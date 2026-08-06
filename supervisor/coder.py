from __future__ import annotations

import asyncio
import inspect
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping, Protocol, TypeAlias

from supervisor.appserver import (
    APP_SERVER_CODER_RPC_TIMEOUT_SECONDS,
    APP_SERVER_CLEANUP_RPC_TIMEOUT_SECONDS,
    APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
    AppServerClient,
    AppServerError,
    AppServerMessage,
    text_input,
)
from supervisor.code_context import code_context_prompt_guidance, dynamic_tool_specs
from supervisor.prompts import build_coder_prompt, build_restart_prompt
from supervisor.state import StateStore


CODER_SANDBOX_ENV = "BELLO_CODER_SANDBOX"
CODER_SANDBOX_READ_ONLY = "read-only"
CODER_SANDBOX_WORKSPACE_WRITE = "workspace-write"
CODER_SANDBOX_DANGER_FULL_ACCESS = "danger-full-access"
CODEX_FAST_SERVICE_TIER = "priority"
DEFAULT_INTELLIGENCE = "xhigh"
MAX_CODER_RECOVERY_CONTEXT_BYTES = 48 * 1024
MAX_CODER_RECOVERY_PROMPT_BYTES = 64 * 1024
MAX_CODER_LIFECYCLE_REASON_BYTES = 2 * 1024


class CoderBindingError(RuntimeError):
    """The requested coder lifecycle operation does not match its binding."""


def _nonempty_text(value: str, field: str, *, maximum_bytes: int | None = None) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CoderBindingError(f"{field} must be a non-empty string")
    if maximum_bytes is not None and len(value.encode("utf-8")) > maximum_bytes:
        raise CoderBindingError(f"{field} exceeds its {maximum_bytes}-byte limit")
    return value


def _lifecycle_counter(value: int, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise CoderBindingError(f"{field} must be an integer >= {minimum}")
    return value


@dataclass(frozen=True, slots=True)
class CoderContextBindingSnapshot:
    """Immutable Context Mode identity/lifecycle view held by ``CoderSession``.

    The authoritative binding remains controller-owned.  This deliberately small
    snapshot is enough for the coder transport to reject accidental workspace,
    generation, or process mixing without gaining write access to that binding.
    """

    run_id: str
    workspace_id: str
    context_session_id: str
    context_state_epoch: int
    binding_version: int
    coder_generation: int
    generation_lease_id: str
    coder_process_epoch: int

    def __post_init__(self) -> None:
        _nonempty_text(self.run_id, "run_id")
        _nonempty_text(self.workspace_id, "workspace_id")
        _nonempty_text(self.context_session_id, "context_session_id")
        _lifecycle_counter(self.context_state_epoch, "context_state_epoch")
        _lifecycle_counter(self.binding_version, "binding_version", minimum=1)
        _lifecycle_counter(self.coder_generation, "coder_generation")
        _nonempty_text(self.generation_lease_id, "generation_lease_id")
        _lifecycle_counter(self.coder_process_epoch, "coder_process_epoch")

    @classmethod
    def from_context_binding(cls, binding: Any) -> "CoderContextBindingSnapshot":
        """Project the full controller/broker binding without retaining it."""

        try:
            stable = binding.stable
            lifecycle = binding.lifecycle
            return cls(
                run_id=stable.run_id,
                workspace_id=stable.workspace_id,
                context_session_id=stable.context_session_id,
                context_state_epoch=lifecycle.context_state_epoch,
                binding_version=lifecycle.binding_version,
                coder_generation=lifecycle.coder_generation,
                generation_lease_id=lifecycle.generation_lease_id,
                coder_process_epoch=lifecycle.coder_process_epoch,
            )
        except (AttributeError, TypeError) as exc:
            raise CoderBindingError("invalid full Context Mode binding") from exc

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "workspace_id": self.workspace_id,
            "context_session_id": self.context_session_id,
            "context_state_epoch": self.context_state_epoch,
            "binding_version": self.binding_version,
            "coder_generation": self.coder_generation,
            "generation_lease_id": self.generation_lease_id,
            "coder_process_epoch": self.coder_process_epoch,
        }

    def validate_logical_handoff(self, candidate: "CoderContextBindingSnapshot") -> None:
        self._validate_stable_context(candidate)
        self._validate_next_version(candidate)
        if candidate.coder_generation != self.coder_generation + 1:
            raise CoderBindingError("logical generation handoff must increment coder_generation exactly once")
        if candidate.generation_lease_id == self.generation_lease_id:
            raise CoderBindingError("logical generation handoff must rotate generation_lease_id")
        if candidate.coder_process_epoch != self.coder_process_epoch:
            raise CoderBindingError("logical generation handoff must not change coder_process_epoch")

    def validate_process_recovery(self, candidate: "CoderContextBindingSnapshot") -> None:
        self._validate_stable_context(candidate)
        self._validate_next_version(candidate)
        if candidate.coder_process_epoch != self.coder_process_epoch + 1:
            raise CoderBindingError("process transport recovery must increment coder_process_epoch exactly once")
        if candidate.coder_generation != self.coder_generation:
            raise CoderBindingError("process transport recovery must not change coder_generation")
        if candidate.generation_lease_id != self.generation_lease_id:
            raise CoderBindingError("process transport recovery must not rotate generation_lease_id")

    def _validate_stable_context(self, candidate: "CoderContextBindingSnapshot") -> None:
        stable_fields = ("run_id", "workspace_id", "context_session_id", "context_state_epoch")
        changed = [name for name in stable_fields if getattr(self, name) != getattr(candidate, name)]
        if changed:
            raise CoderBindingError(f"coder lifecycle transition changed stable Context Mode fields: {changed!r}")

    def _validate_next_version(self, candidate: "CoderContextBindingSnapshot") -> None:
        if candidate.binding_version != self.binding_version + 1:
            raise CoderBindingError("binding_version must increment exactly once per coder lifecycle transition")


@dataclass(frozen=True, slots=True)
class CoderRecoveryContext:
    """Opaque, JSON-object recovery data with a hard model-facing size bound."""

    checkpoint_id: str
    payload_json: str = "{}"

    def __post_init__(self) -> None:
        _nonempty_text(self.checkpoint_id, "checkpoint_id", maximum_bytes=256)
        if not isinstance(self.payload_json, str):
            raise CoderBindingError("recovery payload_json must be a string")
        try:
            payload = json.loads(self.payload_json)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise CoderBindingError("recovery payload_json must contain valid JSON") from exc
        if not isinstance(payload, dict):
            raise CoderBindingError("recovery payload_json must contain a JSON object")
        try:
            canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError, RecursionError) as exc:
            raise CoderBindingError("recovery payload_json is not a canonical JSON object") from exc
        envelope = json.dumps(
            {"checkpoint_id": self.checkpoint_id, "payload": payload},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        if len(envelope.encode("utf-8")) > MAX_CODER_RECOVERY_CONTEXT_BYTES:
            raise CoderBindingError(
                f"recovery context exceeds its {MAX_CODER_RECOVERY_CONTEXT_BYTES}-byte limit"
            )
        object.__setattr__(self, "payload_json", canonical)

    @classmethod
    def from_payload(cls, checkpoint_id: str, payload: Mapping[str, Any]) -> "CoderRecoveryContext":
        if not isinstance(payload, Mapping):
            raise CoderBindingError("recovery payload must be an object")
        try:
            encoded = json.dumps(
                dict(payload),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise CoderBindingError("recovery payload must be JSON serializable") from exc
        return cls(checkpoint_id=checkpoint_id, payload_json=encoded)

    def to_dict(self) -> dict[str, Any]:
        payload = json.loads(self.payload_json)
        return {"checkpoint_id": self.checkpoint_id, "payload": payload}


class CoderLifecycleTransition(str, Enum):
    LOGICAL_GENERATION_HANDOFF = "logical_generation_handoff"
    PROCESS_TRANSPORT_RECOVERY = "process_transport_recovery"


@dataclass(frozen=True, slots=True)
class CoderLifecycleCheckpointRequest:
    transition: CoderLifecycleTransition
    reason: str
    current_binding: CoderContextBindingSnapshot
    next_binding: CoderContextBindingSnapshot
    provider_thread_id: str | None
    active_turn_id: str | None


@dataclass(frozen=True, slots=True)
class CoderTransportRecoveryResult:
    resumed: bool
    thread_id: str
    recovery_context: CoderRecoveryContext


class LifecycleCheckpointWriter(Protocol):
    def checkpoint(
        self,
        request: CoderLifecycleCheckpointRequest,
    ) -> CoderRecoveryContext | Awaitable[CoderRecoveryContext]: ...


LifecycleCheckpointCallback: TypeAlias = Callable[
    [CoderLifecycleCheckpointRequest],
    CoderRecoveryContext | Awaitable[CoderRecoveryContext],
]
LifecycleCheckpointHandler: TypeAlias = LifecycleCheckpointCallback | LifecycleCheckpointWriter


def coder_sandbox_mode() -> str:
    raw = os.environ.get(CODER_SANDBOX_ENV, CODER_SANDBOX_WORKSPACE_WRITE).strip().lower()
    aliases = {
        "read-only": CODER_SANDBOX_READ_ONLY,
        "readonly": CODER_SANDBOX_READ_ONLY,
        "read_only": CODER_SANDBOX_READ_ONLY,
        "workspace-write": CODER_SANDBOX_WORKSPACE_WRITE,
        "workspace_write": CODER_SANDBOX_WORKSPACE_WRITE,
        "workspacewrite": CODER_SANDBOX_WORKSPACE_WRITE,
        "danger-full-access": CODER_SANDBOX_DANGER_FULL_ACCESS,
        "danger_full_access": CODER_SANDBOX_DANGER_FULL_ACCESS,
        "danger": CODER_SANDBOX_DANGER_FULL_ACCESS,
    }
    try:
        return aliases[raw]
    except KeyError as exc:
        supported = f"{CODER_SANDBOX_READ_ONLY}, {CODER_SANDBOX_WORKSPACE_WRITE}, {CODER_SANDBOX_DANGER_FULL_ACCESS}"
        raise RuntimeError(f"unsupported {CODER_SANDBOX_ENV}={raw!r}; expected one of: {supported}") from exc


def coder_turn_sandbox_policy(project_root: Path | None = None) -> dict[str, Any]:
    mode = coder_sandbox_mode()
    if mode == CODER_SANDBOX_DANGER_FULL_ACCESS:
        return {"type": "dangerFullAccess"}
    if mode == CODER_SANDBOX_WORKSPACE_WRITE:
        if project_root is None:
            raise RuntimeError("workspace-write coder sandbox requires a project root")
        return {
            "type": "workspaceWrite",
            "writableRoots": [str(project_root.resolve())],
            "networkAccess": False,
        }
    return {"type": "readOnly", "networkAccess": False}


def codex_service_tier(*, fast: bool) -> str | None:
    return CODEX_FAST_SERVICE_TIER if fast else None


def apply_intelligence(params: dict[str, Any], intelligence: str | None) -> dict[str, Any]:
    if intelligence:
        params["effort"] = intelligence
    return params


def coder_thread_params(
    project_root: Path,
    *,
    model: str | None = None,
    fast: bool = False,
    structured_code_tools: str = "off",
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "cwd": str(project_root),
        "runtimeWorkspaceRoots": [str(project_root)],
        "approvalPolicy": "on-request",
        "approvalsReviewer": "user",
        "sandbox": coder_sandbox_mode(),
        "serviceTier": codex_service_tier(fast=fast),
        "ephemeral": False,
        "experimentalRawEvents": False,
        "persistExtendedHistory": False,
    }
    if model:
        params["model"] = model
    tools = dynamic_tool_specs(structured_code_tools)
    if tools:
        params["dynamicTools"] = tools
    return params


def coder_thread_resume_params(
    thread_id: str,
    project_root: Path,
    *,
    model: str | None = None,
    fast: bool = False,
) -> dict[str, Any]:
    """Build an explicit resume request for the current coder transport."""

    _nonempty_text(thread_id, "thread_id")
    params: dict[str, Any] = {
        "threadId": thread_id,
        "cwd": str(project_root),
        "runtimeWorkspaceRoots": [str(project_root)],
        "approvalPolicy": "on-request",
        "approvalsReviewer": "user",
        "sandbox": coder_sandbox_mode(),
        "serviceTier": codex_service_tier(fast=fast),
    }
    if model:
        params["model"] = model
    return params


def coder_turn_params(
    thread_id: str,
    text: str,
    project_root: Path,
    *,
    model: str | None = None,
    fast: bool = False,
    intelligence: str | None = None,
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "threadId": thread_id,
        "input": [text_input(text)],
        "cwd": str(project_root),
        "runtimeWorkspaceRoots": [str(project_root)],
        "approvalPolicy": "on-request",
        "approvalsReviewer": "user",
        "sandboxPolicy": coder_turn_sandbox_policy(project_root),
        "serviceTier": codex_service_tier(fast=fast),
    }
    if model:
        params["model"] = model
    return apply_intelligence(params, intelligence)


@dataclass
class CoderSession:
    client: AppServerClient
    store: StateStore
    project_root: Path
    task_path: Path
    model: str | None = None
    fast: bool = False
    intelligence: str | None = DEFAULT_INTELLIGENCE
    thread_id: str | None = None
    active_turn_id: str | None = None
    coder_rpc_timeout_seconds: float = APP_SERVER_CODER_RPC_TIMEOUT_SECONDS
    context_binding: CoderContextBindingSnapshot | None = None
    lifecycle_checkpoint: LifecycleCheckpointHandler | None = None
    on_thread_start: Callable[[str], None] | None = None
    structured_code_tools: str = "off"

    def __post_init__(self) -> None:
        self.project_root = Path(self.project_root)
        self.task_path = Path(self.task_path)
        if self.context_binding is not None and not isinstance(
            self.context_binding, CoderContextBindingSnapshot
        ):
            self.context_binding = CoderContextBindingSnapshot.from_context_binding(self.context_binding)
        self._validate_coder_client_role()
        if self.context_binding is not None:
            self._validate_client_process(self.context_binding)

    @property
    def coder_client(self) -> AppServerClient:
        """Role-explicit alias; all coder RPCs go through this passed client."""

        return self.client

    @property
    def binding_snapshot(self) -> CoderContextBindingSnapshot | None:
        return self.context_binding

    def require_context_binding(self) -> CoderContextBindingSnapshot:
        binding = self.context_binding
        if binding is None:
            raise CoderBindingError("CoderSession has no explicit Context Mode binding")
        return binding

    async def start_thread(self) -> str:
        self._validate_active_binding()
        response = await self.coder_client.thread_start(
            coder_thread_params(
                self.project_root,
                model=self.model,
                fast=self.fast,
                structured_code_tools=self.structured_code_tools,
            ),
            timeout=APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
        )
        thread_id = self._response_thread_id(response, operation="thread/start")
        self.thread_id = thread_id
        self.store.update_bello_config(lambda cfg: cfg.model_copy(update={"coder_thread_id": thread_id}))
        if self.on_thread_start is not None:
            self.on_thread_start(thread_id)
        return thread_id

    async def start_initial_turn(self) -> str:
        return await self.start_turn(
            self._with_code_context_guidance(build_coder_prompt(self.task_path))
        )

    async def start_restart_turn(self) -> str:
        return await self.start_turn(
            self._with_code_context_guidance(build_restart_prompt(self.task_path))
        )

    async def start_unbound_recovery_turn(self, message: str) -> str:
        """Start a non-Context recovery turn with the lifecycle-only tool guidance."""

        return await self.start_turn(self._with_code_context_guidance(message))

    async def start_recovery_turn(
        self,
        recovery_context: CoderRecoveryContext,
        *,
        reason: str,
        transition: CoderLifecycleTransition = CoderLifecycleTransition.PROCESS_TRANSPORT_RECOVERY,
    ) -> str:
        """Start the sole model-facing recovery turn with a bounded payload."""

        binding = self.require_context_binding()
        prompt = self._recovery_prompt(
            binding=binding,
            transition=transition,
            reason=reason,
            recovery_context=recovery_context,
        )
        return await self.start_turn(prompt)

    async def start_turn(self, message: str) -> str:
        self._validate_active_binding()
        thread_id = self.thread_id or await self.start_thread()
        response = await self.coder_client.turn_start(
            coder_turn_params(
                thread_id,
                message,
                self.project_root,
                model=self.model,
                fast=self.fast,
                intelligence=self.intelligence,
            ),
            timeout=self.coder_rpc_timeout_seconds,
        )
        turn = response.get("turn", {})
        turn_id = turn.get("id")
        if not isinstance(turn_id, str):
            raise RuntimeError("app-server turn/start did not return a turn id")
        self.active_turn_id = turn_id
        self.store.update_bello_config(lambda cfg: cfg.model_copy(update={"active_coder_turn_id": turn_id}))
        return turn_id

    async def steer_or_start(self, message: str) -> str | None:
        self._validate_active_binding()
        if self.thread_id and self.active_turn_id:
            try:
                await self.coder_client.turn_steer(
                    self.thread_id,
                    self.active_turn_id,
                    message,
                    timeout=self.coder_rpc_timeout_seconds,
                )
                return self.active_turn_id
            except AppServerError:
                raise
            except Exception:
                self.active_turn_id = None
                self.store.update_bello_config(lambda cfg: cfg.model_copy(update={"active_coder_turn_id": None}))
        if self.thread_id:
            return await self.start_turn(message)
        return None

    async def interrupt(self) -> None:
        self._validate_active_binding()
        if not self.thread_id or not self.active_turn_id:
            return
        await self.coder_client.turn_interrupt(
            self.thread_id,
            self.active_turn_id,
            timeout=self.coder_rpc_timeout_seconds,
        )

    async def archive_thread(self) -> None:
        """Require provider-side teardown of the old thread and its MCP session."""

        self._validate_active_binding()
        if not self.thread_id:
            raise CoderBindingError("cannot archive a coder session without a provider thread")
        await self.coder_client.thread_archive(
            self.thread_id,
            timeout=APP_SERVER_CLEANUP_RPC_TIMEOUT_SECONDS,
        )
        self.active_turn_id = None

    async def compact_thread(self) -> AppServerMessage:
        """Run provider compaction and wait for its terminal item notification."""

        self._validate_active_binding()
        thread_id = self.thread_id
        if not thread_id:
            raise CoderBindingError("cannot compact a coder session without a provider thread")
        if self.active_turn_id:
            raise CoderBindingError("cannot compact a coder session with an active turn")

        def item_completed(message: AppServerMessage) -> bool:
            if message.method != "item/completed":
                return False
            params = message.params
            item = params.get("item")
            return (
                params.get("threadId") == thread_id
                and isinstance(item, Mapping)
                and item.get("type") == "contextCompaction"
            )

        def turn_completed(message: AppServerMessage) -> bool:
            return (
                message.method == "turn/completed"
                and message.params.get("threadId") == thread_id
            )

        item_waiter = asyncio.create_task(
            self.coder_client.wait_for_notification(
                item_completed,
                timeout=self.coder_rpc_timeout_seconds,
            )
        )
        turn_waiter = asyncio.create_task(
            self.coder_client.wait_for_notification(
                turn_completed,
                timeout=self.coder_rpc_timeout_seconds,
            )
        )
        # Register both waiters before issuing the RPC; a fast app-server may
        # emit item/completed and turn/completed immediately after the ack.
        await asyncio.sleep(0)
        try:
            await self.coder_client.thread_compact_start(
                thread_id,
                timeout=APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
            )
            item_message, turn_message = await asyncio.gather(item_waiter, turn_waiter)
            item_turn_id = item_message.params.get("turnId")
            terminal_turn_id = turn_message.params.get("turnId")
            if (
                isinstance(item_turn_id, str)
                and isinstance(terminal_turn_id, str)
                and item_turn_id != terminal_turn_id
            ):
                raise CoderBindingError(
                    "contextCompaction item and terminal turn identities do not match"
                )
            return item_message
        except BaseException:
            item_waiter.cancel()
            turn_waiter.cancel()
            await asyncio.gather(item_waiter, turn_waiter, return_exceptions=True)
            raise

    async def checkpoint_lifecycle(
        self,
        next_binding: CoderContextBindingSnapshot,
        *,
        transition: CoderLifecycleTransition,
        reason: str,
        recovery_context: CoderRecoveryContext | None = None,
    ) -> CoderRecoveryContext:
        """Quiesce/checkpoint through the controller-owned lifecycle interface.

        The callback must not return until the checkpoint is durable and Context
        Mode operations for the old lease are quiescent.  Supplying an already
        durable recovery context is the crash-recovery path when no callback can
        run against the failed process.
        """

        current = self.require_context_binding()
        next_binding = self._coerce_binding(next_binding)
        transition = CoderLifecycleTransition(transition)
        if transition is CoderLifecycleTransition.LOGICAL_GENERATION_HANDOFF:
            current.validate_logical_handoff(next_binding)
        else:
            current.validate_process_recovery(next_binding)
        reason = _nonempty_text(
            reason,
            "lifecycle reason",
            maximum_bytes=MAX_CODER_LIFECYCLE_REASON_BYTES,
        )
        request = CoderLifecycleCheckpointRequest(
            transition=transition,
            reason=reason,
            current_binding=current,
            next_binding=next_binding,
            provider_thread_id=self.thread_id,
            active_turn_id=self.active_turn_id,
        )
        if recovery_context is not None:
            if not isinstance(recovery_context, CoderRecoveryContext):
                raise CoderBindingError("invalid coder recovery context")
            return recovery_context

        handler = self.lifecycle_checkpoint
        if handler is None:
            raise CoderBindingError(
                "coder lifecycle transition requires a durable checkpoint callback or recovery context"
            )
        callback = getattr(handler, "checkpoint", None)
        if callback is None:
            callback = handler
        if not callable(callback):
            raise CoderBindingError("lifecycle_checkpoint must be callable or expose checkpoint()")
        result = callback(request)
        if inspect.isawaitable(result):
            result = await result
        selected = self._coerce_recovery_context(result)
        if selected is None:
            raise CoderBindingError("lifecycle checkpoint callback returned no recovery context")
        return selected

    async def handoff_generation(
        self,
        next_binding: CoderContextBindingSnapshot,
        *,
        reason: str,
        recovery_context: CoderRecoveryContext | None = None,
    ) -> str:
        """Checkpoint and start a new logical coder generation.

        This path rotates only generation/lease state.  It never advances the
        app-server process epoch, so a process recycle cannot be hidden in a
        logical restart.
        """

        current = self.require_context_binding()
        next_binding = self._coerce_binding(next_binding)
        current.validate_logical_handoff(next_binding)
        self._validate_client_process(current)
        if self.thread_id and self.active_turn_id:
            await self.interrupt()
        checkpoint = await self.checkpoint_lifecycle(
            next_binding,
            transition=CoderLifecycleTransition.LOGICAL_GENERATION_HANDOFF,
            reason=reason,
            recovery_context=recovery_context,
        )
        prompt = self._recovery_prompt(
            binding=next_binding,
            transition=CoderLifecycleTransition.LOGICAL_GENERATION_HANDOFF,
            reason=reason,
            recovery_context=checkpoint,
        )
        self.context_binding = next_binding
        self.thread_id = None
        self.active_turn_id = None
        self._persist_thread_state(thread_id=None, active_turn_id=None)
        thread_id = await self.start_thread()
        await self.start_turn(prompt)
        return thread_id

    async def recover_transport(
        self,
        next_binding: CoderContextBindingSnapshot,
        *,
        reason: str,
        resume_thread: bool = True,
        recovery_context: CoderRecoveryContext | None = None,
    ) -> CoderTransportRecoveryResult:
        """Recover coder provider transport without changing logical generation.

        ``resume_thread=False`` is the explicit new-thread fallback.  It creates
        no model turn; the controller can call ``start_recovery_turn`` exactly
        once after it has completed the provider-thread claim.
        """

        current = self.require_context_binding()
        next_binding = self._coerce_binding(next_binding)
        current.validate_process_recovery(next_binding)
        old_thread_id = self.thread_id
        if resume_thread and not old_thread_id:
            raise CoderBindingError("transport resume requires an existing provider thread id")
        checkpoint = await self.checkpoint_lifecycle(
            next_binding,
            transition=CoderLifecycleTransition.PROCESS_TRANSPORT_RECOVERY,
            reason=reason,
            recovery_context=recovery_context,
        )
        self._validate_client_process(next_binding)
        self.context_binding = next_binding
        self.active_turn_id = None
        self._persist_thread_state(thread_id=old_thread_id, active_turn_id=None)
        if resume_thread:
            assert old_thread_id is not None
            response = await self.coder_client.thread_resume(
                coder_thread_resume_params(
                    old_thread_id,
                    self.project_root,
                    model=self.model,
                    fast=self.fast,
                ),
                timeout=APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
            )
            thread_id = self._response_thread_id(response, operation="thread/resume")
            if thread_id != old_thread_id:
                raise CoderBindingError(
                    f"thread/resume returned {thread_id!r}, expected bound thread {old_thread_id!r}"
                )
            self.thread_id = thread_id
            self._persist_thread_state(thread_id=thread_id, active_turn_id=None)
            return CoderTransportRecoveryResult(
                resumed=True,
                thread_id=thread_id,
                recovery_context=checkpoint,
            )

        self.thread_id = None
        self._persist_thread_state(thread_id=None, active_turn_id=None)
        thread_id = await self.start_thread()
        return CoderTransportRecoveryResult(
            resumed=False,
            thread_id=thread_id,
            recovery_context=checkpoint,
        )

    def mark_turn_completed(self, turn_id: str) -> None:
        if self.active_turn_id == turn_id:
            self.active_turn_id = None
            self.store.update_bello_config(lambda cfg: cfg.model_copy(update={"active_coder_turn_id": None}))

    def _validate_coder_client_role(self) -> None:
        if self.context_binding is None:
            return
        role = getattr(self.coder_client, "role", None)
        if role is None:
            return
        role_value = getattr(role, "value", role)
        if role_value != "coder":
            raise CoderBindingError("bound CoderSession requires a coder-role AppServerClient")

    def _validate_client_process(self, binding: CoderContextBindingSnapshot) -> None:
        self._validate_coder_client_role()
        client_epoch = getattr(self.coder_client, "process_epoch", None)
        if client_epoch is None:
            return
        if isinstance(client_epoch, bool) or not isinstance(client_epoch, int):
            raise CoderBindingError("coder client process_epoch is invalid")
        if client_epoch != binding.coder_process_epoch:
            raise CoderBindingError(
                "coder client process_epoch does not match the explicit Context Mode binding "
                f"({client_epoch} != {binding.coder_process_epoch})"
            )

    def _validate_active_binding(self) -> None:
        if self.context_binding is not None:
            self._validate_client_process(self.context_binding)

    @staticmethod
    def _coerce_binding(value: Any) -> CoderContextBindingSnapshot:
        if isinstance(value, CoderContextBindingSnapshot):
            return value
        return CoderContextBindingSnapshot.from_context_binding(value)

    @staticmethod
    def _coerce_recovery_context(value: Any) -> CoderRecoveryContext | None:
        if value is None or isinstance(value, CoderRecoveryContext):
            return value
        checkpoint_id = getattr(value, "checkpoint_id", None)
        to_dict = getattr(value, "to_dict", None)
        if isinstance(checkpoint_id, str) and callable(to_dict):
            payload = to_dict()
            if isinstance(payload, Mapping):
                return CoderRecoveryContext.from_payload(checkpoint_id, payload)
        raise CoderBindingError("lifecycle checkpoint callback returned an invalid recovery context")

    @staticmethod
    def _response_thread_id(response: Mapping[str, Any], *, operation: str) -> str:
        thread = response.get("thread", {})
        thread_id = thread.get("id") if isinstance(thread, Mapping) else None
        if not isinstance(thread_id, str) or not thread_id:
            raise RuntimeError(f"app-server {operation} did not return a thread id")
        return thread_id

    def _persist_thread_state(self, *, thread_id: str | None, active_turn_id: str | None) -> None:
        self.store.update_bello_config(
            lambda cfg: cfg.model_copy(
                update={"coder_thread_id": thread_id, "active_coder_turn_id": active_turn_id}
            )
        )

    def _recovery_prompt(
        self,
        *,
        binding: CoderContextBindingSnapshot,
        transition: CoderLifecycleTransition,
        reason: str,
        recovery_context: CoderRecoveryContext,
    ) -> str:
        reason = _nonempty_text(
            reason,
            "lifecycle reason",
            maximum_bytes=MAX_CODER_LIFECYCLE_REASON_BYTES,
        )
        envelope = {
            "schema_version": 1,
            "transition": transition.value,
            "reason": reason,
            "binding": binding.to_dict(),
            "recovery": recovery_context.to_dict(),
        }
        encoded = json.dumps(envelope, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        restart_prompt = self._with_code_context_guidance(
            build_restart_prompt(self.task_path)
        )
        prompt = (
            f"{restart_prompt}\n\n"
            "Bello lifecycle recovery context (controller-bounded JSON):\n"
            f"{encoded}"
        )
        if len(prompt.encode("utf-8")) > MAX_CODER_RECOVERY_PROMPT_BYTES:
            raise CoderBindingError(
                f"coder recovery prompt exceeds its {MAX_CODER_RECOVERY_PROMPT_BYTES}-byte limit"
            )
        return prompt

    def _with_code_context_guidance(self, prompt: str) -> str:
        """Add the optional code-navigation contract to lifecycle prompts only."""

        guidance = code_context_prompt_guidance(self.structured_code_tools)
        if not guidance:
            return prompt
        return f"{prompt}\n\n{guidance}"
