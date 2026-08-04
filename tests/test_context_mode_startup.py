from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from supervisor.controller import BelloController
from supervisor.context_mode._util import canonical_json_bytes
from supervisor.context_mode.approvals import OneShotCapabilityStore
from supervisor.context_mode.config import (
    ALLOWED_TOOLS,
    PINNED_APPROVAL_CORRELATION_FIELDS,
    PINNED_CODEX_APP_SERVER_SCHEMA_SHA256,
    PINNED_CODEX_CLI_VERSION,
    REQUIRED_HOOKS,
)
from supervisor.context_mode.epochs import ContextEpochLayout, EpochStateError
from supervisor.context_mode.runtime import (
    ContextRuntimeCoordinator,
    ExclusiveWorkspaceLease,
    ExclusiveWorkspaceLeasePhase,
    ExclusiveWorkspaceLeasePurpose,
    RuntimeState,
)
from supervisor.context_mode.sandbox import (
    ProfileKind,
    SandboxPathLayout,
    SandboxPolicy,
    build_clean_environment,
    generate_sandbox_policies,
)
from supervisor.context_mode.session import (
    BindingStore,
    CheckpointCursor,
    CheckpointRecoveryKind,
    CheckpointRecoveryTracker,
    ContextBinding,
    LifecycleSnapshot,
    StableBindingIdentity,
    TransitionReason,
)
from supervisor.context_mode.startup import (
    CHECKPOINT_LIFECYCLE_ATTESTATION,
    CheckpointRecoveryAcknowledgement,
    CheckpointRecoveryResult,
    ContextModeStartupError,
    NativeRuntimeEndpoint,
    PURGE_LIFECYCLE_ATTESTATION,
    PreparedContextMode,
    _write_bootstraps,
)
from supervisor.context_mode.telemetry import AuthoritySeparatedCounters
from supervisor.schemas import BelloConfig, BelloStatus


def _environment(tmp_path: Path) -> dict[str, str]:
    return build_clean_environment(
        home=tmp_path / "home",
        temp=tmp_path / "tmp",
        context_mode_dir=tmp_path / "state",
        toolchain_bins=(tmp_path / "runtime" / "bin",),
        platform_tag="linux-x86_64",
        run_id="run-1",
        workspace_id="workspace-1",
        context_session_id="session-1",
    )


def _binding(workspace: Path, *, policy_digest: str) -> ContextBinding:
    return ContextBinding(
        StableBindingIdentity(
            run_id="run-1",
            workspace_id="workspace-1",
            context_session_id="session-1",
            workspace_path=os.fspath(workspace),
            base_config_digest="a" * 64,
        ),
        LifecycleSnapshot(
            binding_version=1,
            context_state_epoch=0,
            coder_generation=1,
            generation_lease_id="lease-1",
            coder_process_epoch=1,
            app_server_instance_id="app-1",
            sandbox_policy_digest=policy_digest,
            provider_thread_id=None,
        ),
    )


class _FakeNativeRuntime:
    def __init__(self, *, reject_updates: bool = False) -> None:
        self.reject_updates = reject_updates
        self.updates: list[tuple[ContextBinding, ContextBinding, str]] = []
        self.boundary_report: dict[str, object] | None = None
        self.authority_key = b"native-checkpoint-authority-key!"
        self.checkpoint_number = 0
        self.checkpoint_envelope_mutator = None
        self.recovery_ack_mutator = None
        self.purge_lease_acquisitions: list[dict[str, object]] = []
        self.purge_lease_releases: list[dict[str, object]] = []

    async def update_binding(
        self,
        *,
        previous_binding: ContextBinding,
        binding: ContextBinding,
        reason: str,
    ) -> None:
        self.updates.append((previous_binding, binding, reason))
        if self.reject_updates:
            raise RuntimeError("broker rejected candidate")

    async def activate_state_epoch(self, **kwargs: object) -> dict[str, object]:
        previous = kwargs["previous_binding"]
        binding = kwargs["binding"]
        assert isinstance(previous, ContextBinding)
        assert isinstance(binding, ContextBinding)
        if self.reject_updates:
            raise RuntimeError("broker rejected epoch activation")
        return {
            "schema_version": 1,
            "runtime_instance_id": "runtime-1",
            "exclusive_lease_id": kwargs["exclusive_lease_id"],
            "run_id": previous.stable.run_id,
            "workspace_id": previous.stable.workspace_id,
            "context_session_id": previous.stable.context_session_id,
            "previous_binding_version": previous.binding_version,
            "binding_version": binding.binding_version,
            "previous_epoch": previous.lifecycle.context_state_epoch,
            "active_epoch": binding.lifecycle.context_state_epoch,
            "previous_epoch_root": os.fspath(kwargs["previous_epoch_root"]),
            "active_epoch_root": os.fspath(kwargs["active_epoch_root"]),
            "active_policy_digest": binding.lifecycle.sandbox_policy_digest,
            "new_epoch_empty": True,
            "active_epoch_switched": True,
            "old_epoch_unmounted": True,
            "process_tree_reaped": True,
            "descendants_reaped": True,
            "writer_handles_closed": True,
            "old_epoch_retained": True,
        }

    async def acquire_purge_lease(self, **kwargs: object) -> dict[str, object]:
        binding = kwargs["binding"]
        assert isinstance(binding, ContextBinding)
        self.purge_lease_acquisitions.append(dict(kwargs))
        return {
            "schema_version": 1,
            "runtime_instance_id": "runtime-1",
            "exclusive_lease_id": kwargs["exclusive_lease_id"],
            "owner": kwargs["owner"],
            "binding_version": binding.binding_version,
            "workspace_id": binding.stable.workspace_id,
            "context_session_id": binding.stable.context_session_id,
            "context_state_epoch": binding.lifecycle.context_state_epoch,
            "active_operations": 0,
            "exclusive": True,
            "quiesced": True,
            "purge_only_bypass": True,
        }

    async def release_purge_lease(self, **kwargs: object) -> None:
        self.purge_lease_releases.append(dict(kwargs))

    async def verify_app_server_boundary(self, **_: object) -> dict[str, object] | None:
        return self.boundary_report

    async def checkpoint(self, **kwargs: object) -> dict[str, object]:
        binding = kwargs["binding"]
        assert isinstance(binding, ContextBinding)
        self.checkpoint_number += 1
        cursor = CheckpointCursor.create(
            authority_key=self.authority_key,
            binding=binding,
            checkpoint_id=f"native-checkpoint-{self.checkpoint_number}",
            reason=str(kwargs["reason"]),
            context_event_seq=17 + self.checkpoint_number,
            last_committed_operation_id="operation-before-checkpoint",
            created_at="2026-08-02T00:00:00Z",
        )
        envelope: dict[str, object] = {
            "schema_version": 1,
            "cursor": cursor.to_dict(),
            "acknowledgement": {
                "schema_version": 1,
                "runtime_instance_id": "runtime-1",
                "checkpoint_id": cursor.checkpoint_id,
                "reason": cursor.reason,
                "transition": str(kwargs["transition"]),
                "binding_version": binding.binding_version,
                "cursor_hmac": cursor.cursor_hmac,
                "cursor_hmac_verified": True,
                "wal_committed": True,
                "state_integrity_verified": True,
            },
        }
        if self.checkpoint_envelope_mutator is not None:
            self.checkpoint_envelope_mutator(envelope)
        return envelope

    async def recover_checkpoint(self, **kwargs: object) -> dict[str, object]:
        cursor_value = kwargs["cursor"]
        checkpoint_binding = kwargs["checkpoint_binding"]
        active_binding = kwargs["binding"]
        assert isinstance(cursor_value, dict)
        assert isinstance(checkpoint_binding, ContextBinding)
        assert isinstance(active_binding, ContextBinding)
        cursor = CheckpointCursor.from_dict(cursor_value)
        acknowledgement: dict[str, object] = {
            "schema_version": 1,
            "runtime_instance_id": "runtime-1",
            "checkpoint_id": cursor.checkpoint_id,
            "recovery_kind": str(kwargs["recovery_kind"]),
            "cursor_hmac": cursor.cursor_hmac,
            "context_event_seq": cursor.context_event_seq,
            "last_committed_operation_id": cursor.last_committed_operation_id,
            "replayed_through_context_event_seq": cursor.context_event_seq + 2,
            "stable": {
                "run_id": cursor.run_id,
                "workspace_id": cursor.workspace_id,
                "context_session_id": cursor.context_session_id,
                "context_state_epoch": cursor.context_state_epoch,
            },
            "recovered_from": checkpoint_binding.lifecycle.to_dict(),
            "active": active_binding.lifecycle.to_dict(),
            "cursor_hmac_verified": True,
            "wal_integrity_verified": True,
            "session_start_verified": True,
        }
        if self.recovery_ack_mutator is not None:
            self.recovery_ack_mutator(acknowledgement)
        return acknowledgement

    async def quiesce(self, **_: object) -> None:
        return None

    async def resume(self, **_: object) -> None:
        return None


class _CoordinatorProbe:
    def __init__(self, store: BindingStore) -> None:
        self.store = store
        self.failed = False
        self.state = RuntimeState.QUIESCED
        self.exclusive_workspace_lease = None

    def mark_failed(self) -> None:
        self.failed = True
        self.state = RuntimeState.FAILED

    def resume_accepting(self) -> None:
        self.state = RuntimeState.ACCEPTING

    def acquire_exclusive_workspace_lease(self, **kwargs: object) -> ExclusiveWorkspaceLease:
        assert self.state is RuntimeState.ACCEPTING
        binding = self.store.load()
        lease = ExclusiveWorkspaceLease(
            lease_id="2" * 64,
            owner=str(kwargs["owner"]),
            binding_version=binding.binding_version,
            workspace_id=binding.stable.workspace_id,
            context_session_id=binding.stable.context_session_id,
            context_state_epoch=binding.lifecycle.context_state_epoch,
            coder_generation=binding.lifecycle.coder_generation,
            generation_lease_id=binding.lifecycle.generation_lease_id,
        )
        self.exclusive_workspace_lease = lease
        self.state = RuntimeState.QUIESCED
        return lease

    def acquire_logical_restart_bootstrap_lease(
        self,
        **kwargs: object,
    ) -> ExclusiveWorkspaceLease:
        assert self.state is RuntimeState.ACCEPTING
        binding = self.store.load()
        lease = ExclusiveWorkspaceLease(
            lease_id="3" * 64,
            owner=str(kwargs["owner"]),
            binding_version=binding.binding_version,
            workspace_id=binding.stable.workspace_id,
            context_session_id=binding.stable.context_session_id,
            context_state_epoch=binding.lifecycle.context_state_epoch,
            coder_generation=binding.lifecycle.coder_generation,
            generation_lease_id=binding.lifecycle.generation_lease_id,
            purpose=ExclusiveWorkspaceLeasePurpose.LOGICAL_RESTART_BOOTSTRAP,
            phase=ExclusiveWorkspaceLeasePhase.LOGICAL_RESTART_ACQUIRED,
        )
        self.exclusive_workspace_lease = lease
        self.state = RuntimeState.QUIESCED
        return lease

    def checkpoint_logical_restart_bootstrap_lease(
        self,
        lease: ExclusiveWorkspaceLease,
        *,
        binding: ContextBinding,
        checkpoint_id: str,
    ) -> ExclusiveWorkspaceLease:
        advanced = ExclusiveWorkspaceLease(
            **{
                **lease.__dict__,
                "phase": ExclusiveWorkspaceLeasePhase.LOGICAL_RESTART_CHECKPOINTED,
                "checkpoint_id": checkpoint_id,
            }
        )
        self.exclusive_workspace_lease = advanced
        return advanced

    def recover_logical_restart_bootstrap_lease(
        self,
        lease: ExclusiveWorkspaceLease,
        *,
        binding: ContextBinding,
        checkpoint_id: str,
    ) -> ExclusiveWorkspaceLease:
        advanced = ExclusiveWorkspaceLease(
            **{
                **lease.__dict__,
                "phase": ExclusiveWorkspaceLeasePhase.LOGICAL_RECOVERED,
            }
        )
        self.exclusive_workspace_lease = advanced
        return advanced

    def validate_exclusive_workspace_transition(self, *_: object, **__: object) -> None:
        return None

    def require_exclusive_workspace_lease(self, lease: ExclusiveWorkspaceLease) -> ContextBinding:
        assert self.exclusive_workspace_lease is not None
        assert lease.lease_id == self.exclusive_workspace_lease.lease_id
        return self.store.load()

    def advance_exclusive_workspace_lease(
        self,
        lease: ExclusiveWorkspaceLease,
        *,
        previous_binding: ContextBinding,
        binding: ContextBinding,
        reason: TransitionReason,
    ) -> ExclusiveWorkspaceLease:
        phase = lease.phase
        if reason is TransitionReason.LOGICAL_GENERATION_RESTART:
            phase = ExclusiveWorkspaceLeasePhase.LOGICAL_GENERATION_ROTATED
        elif (
            lease.purpose is ExclusiveWorkspaceLeasePurpose.LOGICAL_RESTART_BOOTSTRAP
            and reason is TransitionReason.THREAD_CLAIM
        ):
            phase = ExclusiveWorkspaceLeasePhase.LOGICAL_THREAD_CLAIMED
        advanced = ExclusiveWorkspaceLease(
            lease_id=lease.lease_id,
            owner=lease.owner,
            binding_version=binding.binding_version,
            workspace_id=binding.stable.workspace_id,
            context_session_id=binding.stable.context_session_id,
            context_state_epoch=binding.lifecycle.context_state_epoch,
            coder_generation=binding.lifecycle.coder_generation,
            generation_lease_id=binding.lifecycle.generation_lease_id,
            purpose=lease.purpose,
            phase=phase,
            checkpoint_id=lease.checkpoint_id,
        )
        self.exclusive_workspace_lease = advanced
        return advanced

    def replace_policies_for_exclusive_workspace_lease(self, *_: object) -> None:
        return None

    def release_exclusive_workspace_lease(self, lease: ExclusiveWorkspaceLease) -> None:
        assert self.exclusive_workspace_lease is not None
        assert lease.lease_id == self.exclusive_workspace_lease.lease_id
        self.exclusive_workspace_lease = None
        self.state = RuntimeState.ACCEPTING


class _ControllerRuntimeProbe:
    def __init__(self, binding: ContextBinding) -> None:
        self.binding = binding
        self.calls: list[dict[str, object]] = []

    async def transition_binding(self, **kwargs: object) -> ContextBinding:
        self.calls.append(dict(kwargs))
        reason = TransitionReason(kwargs.pop("reason"))
        kwargs.pop("expected_version")
        self.binding = self.binding.transition(reason, **kwargs)
        return self.binding


class _ConfigUpdateProbe:
    def __init__(self) -> None:
        self.updates: list[dict[str, object]] = []

    def update_bello_config(self, callback: object) -> None:
        probe = self

        class _Config:
            def model_copy(self, *, update: dict[str, object]) -> object:
                probe.updates.append(update)
                return self

        callback(_Config())  # type: ignore[operator]


class _RestartStore:
    def __init__(self, tmp_path: Path, *, binding: ContextBinding) -> None:
        self.config = BelloConfig(
            project_root=os.fspath(tmp_path),
            task_path=os.fspath(tmp_path / "TASK.md"),
            status=BelloStatus.RUNNING,
            coder_thread_id=binding.lifecycle.provider_thread_id,
            context_state_epoch=binding.lifecycle.context_state_epoch,
            context_binding_version=binding.binding_version,
            coder_process_epoch=binding.lifecycle.coder_process_epoch,
        )
        self.runtime_metrics: dict[str, object] = {}
        self.handoff = ""

    def get_bello_config(self) -> BelloConfig:
        return self.config

    def update_bello_config(self, callback: object) -> BelloConfig:
        self.config = callback(self.config)  # type: ignore[operator]
        return self.config

    def update_runtime_metrics(self, callback: object) -> dict[str, object]:
        self.runtime_metrics = callback(self.runtime_metrics)  # type: ignore[operator]
        return self.runtime_metrics

    def append_raw_log(self, _: object) -> None:
        return None

    def read_recent_actions(self, _: int) -> list[object]:
        return []

    def write_handoff(self, value: str) -> None:
        self.handoff = value


class _RestartCoordinator:
    def __init__(self) -> None:
        self.failed = False
        self.state = RuntimeState.QUIESCED
        self.exclusive_workspace_lease: ExclusiveWorkspaceLease | None = None

    def mark_failed(self) -> None:
        self.failed = True
        self.state = RuntimeState.FAILED


class _RestartRuntime:
    def __init__(
        self,
        binding: ContextBinding,
        events: list[str],
        *,
        purge_protocol_attested: bool,
    ) -> None:
        self.binding = binding
        self.events = events
        self.purge_protocol_attested = purge_protocol_attested
        self.transitions: list[tuple[TransitionReason, ContextBinding, ContextBinding]] = []
        self.coordinator = _RestartCoordinator()
        self.binding_store = SimpleNamespace(load=lambda: self.binding)
        self.stopped = False
        self.checkpoint_number = 0
        self.last_cursor: CheckpointCursor | None = None
        self.last_checkpoint_binding: ContextBinding | None = None

    async def quiesce(self, *, timeout_seconds: float) -> ContextBinding:
        self.events.append("runtime:quiesce")
        self.coordinator.state = RuntimeState.QUIESCED
        return self.binding

    async def acquire_logical_restart_bootstrap_lease(
        self,
        *,
        owner: str,
        timeout_seconds: float,
    ) -> ExclusiveWorkspaceLease:
        self.events.append("runtime:bootstrap_lease")
        lifecycle = self.binding.lifecycle
        lease = ExclusiveWorkspaceLease(
            lease_id="4" * 64,
            owner=owner,
            binding_version=self.binding.binding_version,
            workspace_id=self.binding.stable.workspace_id,
            context_session_id=self.binding.stable.context_session_id,
            context_state_epoch=lifecycle.context_state_epoch,
            coder_generation=lifecycle.coder_generation,
            generation_lease_id=lifecycle.generation_lease_id,
            purpose=ExclusiveWorkspaceLeasePurpose.LOGICAL_RESTART_BOOTSTRAP,
            phase=ExclusiveWorkspaceLeasePhase.LOGICAL_RESTART_ACQUIRED,
        )
        self.coordinator.exclusive_workspace_lease = lease
        self.coordinator.state = RuntimeState.QUIESCED
        return lease

    async def checkpoint(self, **kwargs: object) -> CheckpointCursor:
        self.events.append("runtime:checkpoint")
        self.checkpoint_number += 1
        self.last_checkpoint_binding = self.binding
        self.last_cursor = CheckpointCursor.create(
            authority_key=b"checkpoint-test-key" * 2,
            binding=self.binding,
            checkpoint_id=f"checkpoint-{self.checkpoint_number}",
            reason=str(kwargs["reason"]),
            context_event_seq=self.checkpoint_number,
            last_committed_operation_id=None,
            created_at="2026-08-02T00:00:00Z",
        )
        lease = self.coordinator.exclusive_workspace_lease
        if kwargs.get("recovery_kind") is CheckpointRecoveryKind.LOGICAL_RESTART:
            assert lease is not None
            self.coordinator.exclusive_workspace_lease = ExclusiveWorkspaceLease(
                **{
                    **lease.__dict__,
                    "phase": ExclusiveWorkspaceLeasePhase.LOGICAL_RESTART_CHECKPOINTED,
                    "checkpoint_id": self.last_cursor.checkpoint_id,
                }
            )
        return self.last_cursor

    async def recover_checkpoint(self, **kwargs: object) -> CheckpointRecoveryResult:
        self.events.append("runtime:recover_checkpoint")
        recovery_kind = CheckpointRecoveryKind(kwargs["recovery_kind"])
        assert self.last_cursor is not None
        assert self.last_checkpoint_binding is not None
        cursor = self.last_cursor
        acknowledgement = CheckpointRecoveryAcknowledgement(
            runtime_instance_id="runtime-1",
            checkpoint_id=cursor.checkpoint_id,
            recovery_kind=recovery_kind.value,
            cursor_hmac=cursor.cursor_hmac,
            context_event_seq=cursor.context_event_seq,
            last_committed_operation_id=cursor.last_committed_operation_id,
            replayed_through_context_event_seq=cursor.context_event_seq,
            stable={
                "run_id": cursor.run_id,
                "workspace_id": cursor.workspace_id,
                "context_session_id": cursor.context_session_id,
                "context_state_epoch": cursor.context_state_epoch,
            },
            recovered_from=self.last_checkpoint_binding.lifecycle.to_dict(),
            active=self.binding.lifecycle.to_dict(),
            cursor_hmac_verified=True,
            wal_integrity_verified=True,
            session_start_verified=True,
        )
        if recovery_kind is CheckpointRecoveryKind.LOGICAL_RESTART:
            lease = self.coordinator.exclusive_workspace_lease
            assert lease is not None
            self.coordinator.exclusive_workspace_lease = ExclusiveWorkspaceLease(
                **{
                    **lease.__dict__,
                    "phase": ExclusiveWorkspaceLeasePhase.LOGICAL_RECOVERED,
                }
            )
        return CheckpointRecoveryResult(cursor, acknowledgement, True)

    async def transition_binding(
        self,
        *,
        expected_version: int,
        reason: TransitionReason,
        **changes: object,
    ) -> ContextBinding:
        assert expected_version == self.binding.binding_version
        transition_reason = TransitionReason(reason)
        previous = self.binding
        self.binding = previous.transition(transition_reason, **changes)
        self.transitions.append((transition_reason, previous, self.binding))
        self.events.append(f"transition:{transition_reason.value}")
        lease = self.coordinator.exclusive_workspace_lease
        if lease is not None:
            phase = lease.phase
            if transition_reason is TransitionReason.LOGICAL_GENERATION_RESTART:
                phase = ExclusiveWorkspaceLeasePhase.LOGICAL_GENERATION_ROTATED
            elif transition_reason is TransitionReason.THREAD_CLAIM:
                phase = ExclusiveWorkspaceLeasePhase.LOGICAL_THREAD_CLAIMED
            self.coordinator.exclusive_workspace_lease = ExclusiveWorkspaceLease(
                lease_id=lease.lease_id,
                owner=lease.owner,
                binding_version=self.binding.binding_version,
                workspace_id=lease.workspace_id,
                context_session_id=lease.context_session_id,
                context_state_epoch=self.binding.lifecycle.context_state_epoch,
                coder_generation=self.binding.lifecycle.coder_generation,
                generation_lease_id=self.binding.lifecycle.generation_lease_id,
                purpose=lease.purpose,
                phase=phase,
                checkpoint_id=lease.checkpoint_id,
            )
        return self.binding

    async def rotate_state_epoch(
        self,
        *,
        exclusive_workspace_lease: ExclusiveWorkspaceLease,
        timeout_seconds: float,
    ) -> tuple[ContextBinding, ExclusiveWorkspaceLease]:
        binding = await self.transition_binding(
            expected_version=self.binding.binding_version,
            reason=TransitionReason.STATE_EPOCH_ROTATION,
            context_state_epoch=self.binding.lifecycle.context_state_epoch + 1,
        )
        advanced = ExclusiveWorkspaceLease(
            lease_id=exclusive_workspace_lease.lease_id,
            owner=exclusive_workspace_lease.owner,
            binding_version=binding.binding_version,
            workspace_id=binding.stable.workspace_id,
            context_session_id=binding.stable.context_session_id,
            context_state_epoch=binding.lifecycle.context_state_epoch,
            coder_generation=binding.lifecycle.coder_generation,
            generation_lease_id=binding.lifecycle.generation_lease_id,
        )
        return binding, advanced

    async def resume(self, **kwargs: object) -> ContextBinding:
        self.events.append("runtime:resume")
        if kwargs.get("exclusive_workspace_lease") is not None:
            lease = self.coordinator.exclusive_workspace_lease
            if (
                lease is not None
                and lease.purpose
                is ExclusiveWorkspaceLeasePurpose.LOGICAL_RESTART_BOOTSTRAP
            ):
                assert lease.phase is ExclusiveWorkspaceLeasePhase.LOGICAL_RECOVERED
            self.coordinator.exclusive_workspace_lease = None
        self.coordinator.state = RuntimeState.ACCEPTING
        return self.binding

    async def stop(self, *, timeout_seconds: float) -> None:
        self.events.append("runtime:stop")
        self.stopped = True


class _RestartClient:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.process_epoch = 1
        self.app_server_instance_id = "app-1"
        self._reserved: tuple[int, str] | None = None

    async def stop(self) -> None:
        self.events.append("client:stop")

    def reserve_next_identity(self) -> tuple[int, str]:
        self.events.append("client:reserve")
        self._reserved = (self.process_epoch + 1, "app-2")
        return self._reserved

    async def start(self) -> None:
        self.events.append("client:start")
        assert self._reserved is not None
        self.process_epoch, self.app_server_instance_id = self._reserved

    async def initialize(self) -> None:
        self.events.append("client:initialize")


class _RestartCoder:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.thread_id = "thread-1"
        self.active_turn_id = None

    async def interrupt(self) -> None:
        self.events.append("coder:interrupt")

    async def archive_thread(self) -> None:
        self.events.append("coder:archive")

    async def recover_transport(self, _: object, **kwargs: object) -> object:
        self.events.append("coder:recover_transport")
        return SimpleNamespace(recovery_context=kwargs["recovery_context"])

    async def start_recovery_turn(self, _: object, *, reason: str) -> None:
        self.events.append("coder:start_recovery_turn")


class _RestartTUI:
    def render(self, *_: object) -> None:
        return None


def _restart_controller(
    tmp_path: Path,
    *,
    purge_protocol_attested: bool,
) -> tuple[BelloController, _RestartRuntime, _RestartClient, _RestartStore, list[str]]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    binding = _binding(workspace, policy_digest="b" * 64).transition(
        TransitionReason.THREAD_CLAIM,
        provider_thread_id="thread-1",
    )
    events: list[str] = []
    runtime = _RestartRuntime(
        binding,
        events,
        purge_protocol_attested=purge_protocol_attested,
    )
    client = _RestartClient(events)
    store = _RestartStore(tmp_path, binding=binding)
    controller = object.__new__(BelloController)
    controller.project_root = workspace
    controller.workspace_root = workspace
    controller.task_path = task
    controller.workspace_task_path = task
    controller._canonical_task_contents = "# Task\n"
    controller.store = store  # type: ignore[assignment]
    controller.coder = _RestartCoder(events)  # type: ignore[assignment]
    controller.coder_client = client  # type: ignore[assignment]
    controller.supervisor_client = object()
    controller.context_runtime = runtime  # type: ignore[assignment]
    controller.context_binding_store = runtime.binding_store
    controller.context_capability_store = None
    controller.pending_approvals = {}
    controller._terminal_cleanup_started = False
    controller._coder_process_restart_lock = None
    controller._context_call_start_revision = {("thread-1", "turn-old", "call-old"): 3}
    controller._context_pending_approval_calls = {("thread-1", "turn-old", "call-old"): object()}
    controller._active_workspace_mutations = {("thread-1", "turn-old", "write-old"): 7}
    controller._overlapped_workspace_mutations = {("thread-1", "turn-old", "write-old")}
    controller._workspace_mutation_terminals = {("thread-1", "turn-old", "done-old"): (7, False)}
    controller._workspace_revision = 7
    controller._context_approval_capabilities = {}
    controller._context_capability_by_item = {}
    controller._context_approval_item_by_request = {}
    controller._context_approval_correlation_issues = {}
    controller._context_purge_lease = None
    controller._context_purge_logical_key = None
    controller._context_purge_request_key = None
    if purge_protocol_attested:
        controller._context_purge_lease = ExclusiveWorkspaceLease(
            lease_id="1" * 64,
            owner="coder:thread-1:turn-purge:item-purge",
            binding_version=binding.binding_version,
            workspace_id=binding.stable.workspace_id,
            context_session_id=binding.stable.context_session_id,
            context_state_epoch=binding.lifecycle.context_state_epoch,
            coder_generation=binding.lifecycle.coder_generation,
            generation_lease_id=binding.lifecycle.generation_lease_id,
        )
    controller.tui = _RestartTUI()  # type: ignore[assignment]
    controller.running = True
    controller._coder_snapshot = None
    controller.coder_model = "gpt-5.5"
    controller.coder_intelligence = "xhigh"
    controller.fast = False
    controller._append_event = lambda *_args, **_kwargs: None  # type: ignore[method-assign]
    controller._repair_snapshot_runtime_controls = lambda **_kwargs: ()  # type: ignore[method-assign]
    controller._mark_coder_thread_started = lambda thread_id: events.append(  # type: ignore[method-assign]
        f"controller:thread_started:{thread_id}"
    )

    async def close_completion() -> None:
        events.append("controller:close_completion")

    controller._close_completion_review_session = close_completion  # type: ignore[method-assign]

    async def resolve_pending(_: str, *, best_effort: bool = False) -> None:
        events.append(f"controller:resolve:{best_effort}")

    async def boundary() -> None:
        events.append("controller:boundary")
        runtime.purge_protocol_attested = True

    controller._resolve_pending_approvals = resolve_pending  # type: ignore[method-assign]
    controller._verify_coder_transport_binding = lambda: events.append("controller:verify")  # type: ignore[method-assign]
    controller._preflight_context_app_server_boundary = boundary  # type: ignore[method-assign]
    return controller, runtime, client, store, events


def _prepared_runtime(
    tmp_path: Path,
    *,
    reject_updates: bool = False,
) -> tuple[PreparedContextMode, _FakeNativeRuntime, _CoordinatorProbe]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = tmp_path / "bin" / "bello-context-mode-launcher"
    launcher.parent.mkdir()
    launcher.write_bytes(b"pinned launcher\n")
    launcher.chmod(0o700)
    launcher_digest = hashlib.sha256(launcher.read_bytes()).hexdigest()
    endpoint = NativeRuntimeEndpoint(
        launcher_path=launcher,
        launcher_sha256=launcher_digest,
        public_bootstrap={"channel": "public-controller-channel"},
        runtime_instance_id="runtime-1",
    )
    context_root = tmp_path / "state"
    context_root.mkdir(mode=0o700)
    epoch_layout = ContextEpochLayout(context_root, "workspace-1")
    active_epoch = epoch_layout.create_fresh_epoch(0)
    environment = build_clean_environment(
        home=tmp_path / "home",
        temp=tmp_path / "tmp",
        context_mode_dir=active_epoch,
        toolchain_bins=(tmp_path / "runtime" / "bin",),
        platform_tag="linux-x86_64",
        run_id="run-1",
        workspace_id="workspace-1",
        context_session_id="session-1",
    )
    layout = SandboxPathLayout(
            workspace=workspace,
            runtime=tmp_path / "runtime",
            state=active_epoch,
            mcp_home=tmp_path / "mcp-home",
            mcp_temp=tmp_path / "mcp-temp",
            hook_home=tmp_path / "hook-home",
            hook_temp=tmp_path / "hook-temp",
            command_home=tmp_path / "command-home",
            command_scratch=tmp_path / "command-scratch",
            launcher=launcher,
            bootstrap=tmp_path / "bootstrap",
            proxy_bootstrap_files=(
                tmp_path / "bootstrap" / "mcp.json",
                *(
                    tmp_path / "bootstrap" / f"hook-{event}.json"
                    for event in REQUIRED_HOOKS
                ),
            ),
            workspace_git=workspace / ".git",
        )
    policy_map = generate_sandbox_policies(layout, environment=environment)
    policy = policy_map[ProfileKind.MCP]
    store = BindingStore(tmp_path / "metadata" / "context-binding.json")
    initial = store.initialize(_binding(workspace, policy_digest=policy.digest))
    bootstraps = _write_bootstraps(
        tmp_path / "bootstrap",
        endpoint=endpoint,
        binding=initial,
        policies=policy_map,
    )
    native = _FakeNativeRuntime(reject_updates=reject_updates)
    coordinator = _CoordinatorProbe(store)
    prepared = PreparedContextMode(
        bundle=SimpleNamespace(),  # type: ignore[arg-type]
        backend=SimpleNamespace(),  # type: ignore[arg-type]
        policies=tuple(policy_map.values()),
        binding_store=store,
        capability_store=OneShotCapabilityStore(),
        coordinator=coordinator,  # type: ignore[arg-type]
        native_runtime=native,  # type: ignore[arg-type]
        endpoint=endpoint,
        bootstraps=bootstraps,
        recovery_tracker=CheckpointRecoveryTracker(
            tmp_path / "metadata" / "checkpoint-recoveries.json"
        ),
        epoch_layout=epoch_layout,
        sandbox_layout=layout,
        clean_environment=environment,
    )
    prepared.checkpoint_protocol_attested = True
    return prepared, native, coordinator


def _valid_boundary_report(prepared: PreparedContextMode) -> dict[str, object]:
    schema = {"type": "object", "additionalProperties": False}
    schema_digest = hashlib.sha256(canonical_json_bytes(schema)).hexdigest()
    prepared.bundle = SimpleNamespace(  # type: ignore[assignment]
        tool_schema_digests={name: schema_digest for name in ALLOWED_TOOLS}
    )
    prepared.backend = SimpleNamespace(  # type: ignore[assignment]
        name=SimpleNamespace(value="linux-bwrap-seccomp")
    )
    return {
        "schema_version": 3,
        "codex_version": PINNED_CODEX_CLI_VERSION,
        "appserver_schema_hash": PINNED_CODEX_APP_SERVER_SCHEMA_SHA256,
        "binding_version": prepared.binding.binding_version,
        "role_sandboxes": {"coder": True, "supervisor": True},
        "discovery_disabled": {"coder": True, "supervisor": True},
        "supervisor_context_entries": [],
        "coder_context_tools": [
            {"name": name, "inputSchema": schema}
            for name in ALLOWED_TOOLS
        ],
        "coder_hooks": list(REQUIRED_HOOKS),
        "coder_hook_attestations": prepared.expected_coder_hook_attestations(),
        "unmanifested_extensions": {"coder": [], "supervisor": []},
        "approval_correlation_fields": list(PINNED_APPROVAL_CORRELATION_FIELDS),
        "purge_lifecycle_attestation": dict(PURGE_LIFECYCLE_ATTESTATION),
        "checkpoint_lifecycle_attestation": dict(CHECKPOINT_LIFECYCLE_ATTESTATION),
        "doctor": {
            "schema_version": 1,
            "offline": True,
            "network_allowed": False,
            "sandbox_backend": "linux-bwrap-seccomp",
            "sandbox_policy_digest": prepared.binding.lifecycle.sandbox_policy_digest,
            "database": "ok",
            "fts5": True,
        },
    }


@pytest.mark.asyncio
async def test_controller_logical_restart_archives_then_holds_fence_through_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller, runtime, _, _, events = _restart_controller(
        tmp_path,
        purge_protocol_attested=True,
    )

    class _ReplacementCoder:
        def __init__(self, *_: object, context_binding: object = None, **__: object) -> None:
            self.context_binding = context_binding
            self.thread_id: str | None = None
            self.active_turn_id: str | None = None

        async def start_thread(self) -> str:
            lease = runtime.coordinator.exclusive_workspace_lease
            assert runtime.coordinator.state is RuntimeState.QUIESCED
            assert lease is not None
            assert lease.phase is ExclusiveWorkspaceLeasePhase.LOGICAL_GENERATION_ROTATED
            events.append("coder:new_thread_start")
            self.thread_id = "thread-new"
            return self.thread_id

        async def start_recovery_turn(self, *_: object, **__: object) -> str:
            assert runtime.coordinator.state is RuntimeState.ACCEPTING
            assert runtime.coordinator.exclusive_workspace_lease is None
            events.append("coder:recovery_turn")
            self.active_turn_id = "turn-recovery"
            return self.active_turn_id

    monkeypatch.setattr("supervisor.controller.CoderSession", _ReplacementCoder)
    monkeypatch.setattr("supervisor.controller.patch_health", lambda *_args, **_kwargs: None)

    await controller.restart_coder_generation("rotate a stalled logical generation")

    ordered = [
        "coder:interrupt",
        "controller:resolve:False",
        "coder:archive",
        "runtime:bootstrap_lease",
        "runtime:checkpoint",
        "transition:logical_generation_restart",
        "coder:new_thread_start",
        "transition:thread_claim",
        "controller:boundary",
        "runtime:recover_checkpoint",
        "runtime:resume",
        "coder:recovery_turn",
    ]
    positions = [events.index(event) for event in ordered]
    assert positions == sorted(positions)
    assert runtime.coordinator.state is RuntimeState.ACCEPTING
    assert runtime.coordinator.exclusive_workspace_lease is None


def test_physical_epoch_layout_is_fresh_exact_and_never_reused(tmp_path: Path) -> None:
    root = tmp_path / "context-mode"
    root.mkdir(mode=0o700)
    layout = ContextEpochLayout(root, "workspace-safe")

    epoch = layout.create_fresh_epoch(0)

    assert epoch == root / "workspaces" / "workspace-safe" / "epochs" / "0"
    assert {entry.name for entry in epoch.iterdir()} == {
        "sessions",
        "content",
        "stats",
        "checkpoints",
        "database.sqlite",
    }
    assert (epoch / "database.sqlite").stat().st_size == 0
    with pytest.raises(EpochStateError, match="refusing state reuse"):
        layout.create_fresh_epoch(0)
    with pytest.raises(EpochStateError, match="path-safe"):
        ContextEpochLayout(root, "../other-workspace")


@pytest.mark.asyncio
async def test_purge_lease_switches_exact_mount_after_writer_reap_ack_and_retains_old_epoch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, native, coordinator = _prepared_runtime(tmp_path)
    prepared.purge_protocol_attested = True
    coordinator.state = RuntimeState.ACCEPTING
    old_root = prepared.active_epoch_root()
    old_database = old_root / "database.sqlite"
    old_database.write_bytes(b"old epoch state")

    async def inline_to_thread(function, /, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", inline_to_thread)
    lease = await prepared.acquire_purge_lease(
        owner="coder:thread:turn:purge",
        timeout_seconds=2.0,
    )
    assert native.purge_lease_acquisitions[0]["exclusive_lease_id"] == lease.lease_id
    rotated, advanced = await asyncio.wait_for(
        prepared.rotate_state_epoch(exclusive_workspace_lease=lease),
        timeout=2.0,
    )

    new_root = prepared.active_epoch_root(rotated)
    assert new_root != old_root
    assert new_root == prepared.epoch_layout.epoch_root(1)  # type: ignore[union-attr]
    assert (new_root / "database.sqlite").stat().st_size == 0
    assert old_database.read_bytes() == b"old epoch state"
    assert all(
        mount.source == os.fspath(new_root)
        for policy in prepared.policies
        for mount in policy.mounts
        if mount.path_class == "context_state"
    )
    await asyncio.wait_for(
        prepared.resume(exclusive_workspace_lease=advanced),
        timeout=2.0,
    )
    assert native.purge_lease_releases[0]["exclusive_lease_id"] == lease.lease_id
    assert coordinator.state is RuntimeState.ACCEPTING


@pytest.mark.asyncio
async def test_binding_claim_and_lifecycle_transition_reach_native_and_all_bootstraps(
    tmp_path: Path,
) -> None:
    prepared, native, coordinator = _prepared_runtime(tmp_path)

    claimed = await prepared.transition_binding(
        expected_version=1,
        reason=TransitionReason.THREAD_CLAIM,
        provider_thread_id="thread-1",
    )
    restarted = await prepared.transition_binding(
        expected_version=claimed.binding_version,
        reason=TransitionReason.LOGICAL_GENERATION_RESTART,
        coder_generation=2,
        generation_lease_id="lease-2",
        provider_thread_id=None,
    )

    assert not coordinator.failed
    assert [(old.binding_version, new.binding_version, reason) for old, new, reason in native.updates] == [
        (1, 2, "thread_claim"),
        (2, 3, "logical_generation_restart"),
    ]
    assert prepared.binding == restarted
    paths = (prepared.bootstraps.mcp, *prepared.bootstraps.hooks.values())
    assert len(paths) == 7
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["binding_version"] == 3
        assert payload["coder_generation"] == 2
        assert payload["generation_lease_id"] == "lease-2"
        assert payload["provider_thread_id"] is None
        assert payload["coder_process_epoch"] == 1
        assert payload["app_server_instance_id"] == "app-1"
        assert "lease-1" not in path.read_text(encoding="utf-8")
        assert "thread-1" not in path.read_text(encoding="utf-8")
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.asyncio
async def test_native_binding_rejection_fails_closed_without_publishing_candidate(
    tmp_path: Path,
) -> None:
    prepared, native, coordinator = _prepared_runtime(tmp_path, reject_updates=True)

    with pytest.raises(ContextModeStartupError, match="rejected or could not durably propagate"):
        await prepared.transition_binding(
            expected_version=1,
            reason=TransitionReason.THREAD_CLAIM,
            provider_thread_id="thread-rejected",
        )

    assert len(native.updates) == 1
    assert coordinator.failed
    assert prepared.binding.binding_version == 1
    for path in (prepared.bootstraps.mcp, *prepared.bootstraps.hooks.values()):
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["binding_version"] == 1
        assert payload["provider_thread_id"] is None


@pytest.mark.asyncio
async def test_second_lifecycle_transition_rejection_leaves_no_partial_binding_or_bootstrap(
    tmp_path: Path,
) -> None:
    prepared, native, coordinator = _prepared_runtime(tmp_path)
    claimed = await prepared.transition_binding(
        expected_version=1,
        reason=TransitionReason.THREAD_CLAIM,
        provider_thread_id="thread-1",
    )
    paths = (prepared.bootstraps.mcp, *prepared.bootstraps.hooks.values())
    published = {path: path.read_bytes() for path in paths}
    native.reject_updates = True

    with pytest.raises(ContextModeStartupError, match="rejected or could not durably propagate"):
        await prepared.transition_binding(
            expected_version=claimed.binding_version,
            reason=TransitionReason.PROCESS_RECOVERY,
            coder_process_epoch=2,
            app_server_instance_id="app-2",
            provider_thread_id="thread-1",
        )

    assert coordinator.failed
    assert prepared.binding == claimed
    assert all(path.read_bytes() == published[path] for path in paths)


@pytest.mark.asyncio
async def test_checkpoint_requires_verified_commit_and_real_reason_bound_cursor(
    tmp_path: Path,
) -> None:
    prepared, native, coordinator = _prepared_runtime(tmp_path)
    await prepared.transition_binding(
        expected_version=1,
        reason=TransitionReason.THREAD_CLAIM,
        provider_thread_id="thread-before-checkpoint",
    )

    def deny_hmac_verification(envelope: dict[str, object]) -> None:
        acknowledgement = envelope["acknowledgement"]
        assert isinstance(acknowledgement, dict)
        acknowledgement["cursor_hmac_verified"] = False

    native.checkpoint_envelope_mutator = deny_hmac_verification
    with pytest.raises(ContextModeStartupError, match="cursor_hmac_verified"):
        await prepared.checkpoint(
            reason="compact before restart",
            transition="logical_generation_restart",
            recovery_kind=CheckpointRecoveryKind.LOGICAL_RESTART,
        )

    assert coordinator.failed
    assert prepared._pending_checkpoints == {}


@pytest.mark.asyncio
async def test_logical_checkpoint_recovery_is_acknowledged_once_before_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, _, coordinator = _prepared_runtime(tmp_path)

    async def inline_to_thread(function, /, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", inline_to_thread)
    claimed = await prepared.transition_binding(
        expected_version=1,
        reason=TransitionReason.THREAD_CLAIM,
        provider_thread_id="thread-old",
    )
    prepared.purge_protocol_attested = True
    coordinator.state = RuntimeState.ACCEPTING
    await asyncio.wait_for(
        prepared.acquire_logical_restart_bootstrap_lease(
            owner="controller:logical-restart:2",
        ),
        timeout=2.0,
    )
    cursor = await asyncio.wait_for(
        prepared.checkpoint(
            reason="bounded logical restart",
            transition="logical_generation_restart",
            recovery_kind=CheckpointRecoveryKind.LOGICAL_RESTART,
        ),
        timeout=2.0,
    )
    restarted = await asyncio.wait_for(
        prepared.transition_binding(
            expected_version=claimed.binding_version,
            reason=TransitionReason.LOGICAL_GENERATION_RESTART,
            coder_generation=2,
            generation_lease_id="lease-2",
            provider_thread_id=None,
        ),
        timeout=2.0,
    )
    active = await asyncio.wait_for(
        prepared.transition_binding(
            expected_version=restarted.binding_version,
            reason=TransitionReason.THREAD_CLAIM,
            provider_thread_id="thread-new",
        ),
        timeout=2.0,
    )

    recovery = await asyncio.wait_for(
        prepared.recover_checkpoint(
            checkpoint_id=cursor.checkpoint_id,
            recovery_kind=CheckpointRecoveryKind.LOGICAL_RESTART,
        ),
        timeout=2.0,
    )
    assert recovery.cursor is cursor
    assert recovery.newly_recovered
    assert recovery.acknowledgement.active == active.lifecycle.to_dict()
    assert cursor.checkpoint_id not in prepared._pending_checkpoints
    assert prepared.recovery_tracker is not None
    assert prepared.recovery_tracker.contains(cursor.checkpoint_id)
    reloaded = CheckpointRecoveryTracker(prepared.recovery_tracker.path)
    assert reloaded.contains(cursor.checkpoint_id)

    recovered_lease = coordinator.exclusive_workspace_lease
    assert recovered_lease is not None
    assert recovered_lease.phase is ExclusiveWorkspaceLeasePhase.LOGICAL_RECOVERED
    await asyncio.wait_for(
        prepared.resume(exclusive_workspace_lease=recovered_lease),
        timeout=2.0,
    )
    assert coordinator.state is RuntimeState.ACCEPTING
    replay = await prepared.recover_checkpoint(
        checkpoint_id=cursor.checkpoint_id,
        recovery_kind=CheckpointRecoveryKind.LOGICAL_RESTART,
    )
    assert not replay.newly_recovered


@pytest.mark.asyncio
async def test_logical_bootstrap_fence_rejects_transition_before_native_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, native, _ = _prepared_runtime(tmp_path)
    claimed = await prepared.transition_binding(
        expected_version=1,
        reason=TransitionReason.THREAD_CLAIM,
        provider_thread_id="thread-old",
    )
    native.updates.clear()
    coordinator = ContextRuntimeCoordinator(
        binding_store=prepared.binding_store,
        capability_store=prepared.capability_store,
        bundle=SimpleNamespace(),  # type: ignore[arg-type]
        backend=SimpleNamespace(),  # type: ignore[arg-type]
        policies=(),
    )
    coordinator._state = RuntimeState.ACCEPTING
    prepared.coordinator = coordinator
    prepared.purge_protocol_attested = True

    async def inline_to_thread(function, /, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", inline_to_thread)
    await prepared.acquire_logical_restart_bootstrap_lease(
        owner="controller:logical-restart:2",
    )

    with pytest.raises(
        ContextModeStartupError,
        match="rejected or could not durably propagate",
    ):
        await prepared.transition_binding(
            expected_version=claimed.binding_version,
            reason=TransitionReason.LOGICAL_GENERATION_RESTART,
            coder_generation=2,
            generation_lease_id="lease-2",
            provider_thread_id=None,
        )

    assert native.updates == []
    assert prepared.binding == claimed
    assert coordinator.state is RuntimeState.FAILED


@pytest.mark.asyncio
async def test_resume_before_session_start_recovery_ack_fails_closed(tmp_path: Path) -> None:
    prepared, _, coordinator = _prepared_runtime(tmp_path)
    await prepared.transition_binding(
        expected_version=1,
        reason=TransitionReason.THREAD_CLAIM,
        provider_thread_id="thread-old",
    )
    cursor = await prepared.checkpoint(
        reason="restart must not race recovery",
        transition="process_recovery",
        recovery_kind=CheckpointRecoveryKind.PROCESS_RECOVERY,
    )

    with pytest.raises(ContextModeStartupError, match="cannot resume before verified"):
        await prepared.resume()

    assert coordinator.failed
    assert cursor.checkpoint_id in prepared._pending_checkpoints
    assert prepared.recovery_tracker is not None
    assert not prepared.recovery_tracker.contains(cursor.checkpoint_id)


@pytest.mark.asyncio
async def test_process_recovery_rejects_ack_with_wrong_origin_instance(tmp_path: Path) -> None:
    prepared, native, coordinator = _prepared_runtime(tmp_path)
    claimed = await prepared.transition_binding(
        expected_version=1,
        reason=TransitionReason.THREAD_CLAIM,
        provider_thread_id="thread-1",
    )
    cursor = await prepared.checkpoint(
        reason="transport failed",
        transition="process_recovery",
        recovery_kind=CheckpointRecoveryKind.PROCESS_RECOVERY,
    )
    await prepared.transition_binding(
        expected_version=claimed.binding_version,
        reason=TransitionReason.PROCESS_RECOVERY,
        coder_process_epoch=2,
        app_server_instance_id="app-2",
        provider_thread_id="thread-1",
    )

    def forge_origin(acknowledgement: dict[str, object]) -> None:
        recovered_from = acknowledgement["recovered_from"]
        assert isinstance(recovered_from, dict)
        recovered_from["app_server_instance_id"] = "wrong-old-instance"

    native.recovery_ack_mutator = forge_origin
    with pytest.raises(ContextModeStartupError, match="recovered_from"):
        await prepared.recover_checkpoint(
            checkpoint_id=cursor.checkpoint_id,
            recovery_kind=CheckpointRecoveryKind.PROCESS_RECOVERY,
        )

    assert coordinator.failed
    assert prepared.recovery_tracker is not None
    assert not prepared.recovery_tracker.contains(cursor.checkpoint_id)


@pytest.mark.asyncio
async def test_compaction_is_counted_only_after_commit_and_verified_recovery(
    tmp_path: Path,
) -> None:
    prepared, _, _ = _prepared_runtime(tmp_path)
    await prepared.transition_binding(
        expected_version=1,
        reason=TransitionReason.THREAD_CLAIM,
        provider_thread_id="thread-compacted",
    )
    telemetry = AuthoritySeparatedCounters(
        tmp_path / "metadata" / "context-telemetry.json"
    )
    controller = object.__new__(BelloController)
    controller.context_runtime = prepared  # type: ignore[assignment]
    controller.context_integration = SimpleNamespace(telemetry=telemetry)
    controller.store = _RestartStore(tmp_path, binding=prepared.binding)  # type: ignore[assignment]

    cursor = await controller._checkpoint_context_runtime(
        reason="PreCompact",
        transition="compaction",
        recovery_kind=CheckpointRecoveryKind.COMPACTION,
    )
    assert telemetry.value("context_mode_compactions_attempted") == 1
    assert telemetry.value("context_mode_compactions_recovered") == 0

    first = await controller._recover_context_checkpoint(
        checkpoint_id=cursor.checkpoint_id,
        recovery_kind=CheckpointRecoveryKind.COMPACTION,
    )
    replay = await controller._recover_context_checkpoint(
        checkpoint_id=cursor.checkpoint_id,
        recovery_kind=CheckpointRecoveryKind.COMPACTION,
    )

    assert first.newly_recovered
    assert not replay.newly_recovered
    assert telemetry.value("context_mode_compactions_attempted") == 1
    assert telemetry.value("context_mode_compactions_recovered") == 1


@pytest.mark.asyncio
async def test_controller_provider_thread_claim_awaits_authoritative_runtime_transition(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    initial = _binding(workspace, policy_digest="b" * 64)
    runtime = _ControllerRuntimeProbe(initial)
    config_updates = _ConfigUpdateProbe()
    controller = object.__new__(BelloController)
    controller.context_runtime = runtime  # type: ignore[assignment]
    controller.coder = None
    controller.store = config_updates  # type: ignore[assignment]
    boundary_versions: list[int] = []

    async def boundary() -> None:
        boundary_versions.append(runtime.binding.binding_version)

    controller._preflight_context_app_server_boundary = boundary  # type: ignore[method-assign]

    await controller._claim_context_provider_thread("thread-controller")

    assert runtime.calls == [
        {
            "expected_version": 1,
            "reason": TransitionReason.THREAD_CLAIM,
            "provider_thread_id": "thread-controller",
        }
    ]
    assert runtime.binding.lifecycle.provider_thread_id == "thread-controller"
    assert config_updates.updates == [
        {
            "context_binding_version": 2,
            "coder_thread_id": "thread-controller",
        }
    ]
    assert boundary_versions == [2]


@pytest.mark.asyncio
async def test_boundary_preflight_requires_exact_hooks_and_exclusive_purge_protocol(
    tmp_path: Path,
) -> None:
    prepared, native, coordinator = _prepared_runtime(tmp_path)
    report = _valid_boundary_report(prepared)
    native.boundary_report = report
    controller = object.__new__(BelloController)
    controller.context_runtime = prepared
    controller.coder_client = object()
    controller.supervisor_client = object()

    await controller._preflight_context_app_server_boundary()

    assert prepared.purge_protocol_attested
    assert prepared.checkpoint_protocol_attested
    assert not coordinator.failed
    attestations = report["coder_hook_attestations"]
    assert isinstance(attestations, dict)
    assert tuple(attestations) == REQUIRED_HOOKS
    for event, attestation in attestations.items():
        assert attestation["launcher_path"] == os.fspath(prepared.endpoint.launcher_path)
        assert attestation["bootstrap_path"] == os.fspath(prepared.bootstraps.hooks[event])
        assert attestation["bootstrap_mode"] == 0o600
        assert len(attestation["bootstrap_sha256"]) == 64

    rejected = _valid_boundary_report(prepared)
    rejected["codex_version"] = "codex-cli 0.147.0"
    native.boundary_report = rejected
    coordinator.failed = False
    with pytest.raises(ContextModeStartupError, match="unpinned Codex"):
        await controller._preflight_context_app_server_boundary()
    assert coordinator.failed

    rejected = _valid_boundary_report(prepared)
    correlation = rejected["approval_correlation_fields"]
    assert isinstance(correlation, list)
    correlation.append(correlation[-1])
    native.boundary_report = rejected
    coordinator.failed = False
    with pytest.raises(ContextModeStartupError, match="cannot correlate"):
        await controller._preflight_context_app_server_boundary()
    assert coordinator.failed

    rejected = _valid_boundary_report(prepared)
    rejected["purge_lifecycle_attestation"] = {
        **dict(PURGE_LIFECYCLE_ATTESTATION),
        "exclusive_lifecycle_lease": False,
    }
    native.boundary_report = rejected
    coordinator.failed = False
    with pytest.raises(ContextModeStartupError, match="exclusive/quiesced"):
        await controller._preflight_context_app_server_boundary()
    assert coordinator.failed
    assert not prepared.purge_protocol_attested
    assert not prepared.checkpoint_protocol_attested


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda report: report.update(schema_version=3.0), "schema mismatch"),
        (lambda report: report.update(binding_version=True), "invalid binding version"),
        (
            lambda report: report.update(
                role_sandboxes={"coder": 1, "supervisor": True}
            ),
            "role sandbox preflight failed",
        ),
    ],
)
async def test_boundary_preflight_rejects_json_scalar_aliases(
    tmp_path: Path,
    mutate,
    match: str,
) -> None:
    prepared, native, coordinator = _prepared_runtime(tmp_path)
    report = _valid_boundary_report(prepared)
    mutate(report)
    native.boundary_report = report
    controller = object.__new__(BelloController)
    controller.context_runtime = prepared
    controller.coder_client = object()
    controller.supervisor_client = object()

    with pytest.raises(ContextModeStartupError, match=match):
        await controller._preflight_context_app_server_boundary()

    assert coordinator.failed


@pytest.mark.asyncio
async def test_boundary_preflight_rejects_stale_hook_bootstrap_attestation(tmp_path: Path) -> None:
    prepared, native, coordinator = _prepared_runtime(tmp_path)
    report = _valid_boundary_report(prepared)
    attestations = report["coder_hook_attestations"]
    assert isinstance(attestations, dict)
    attestations["Stop"] = {
        **attestations["Stop"],
        "bootstrap_path": os.fspath(tmp_path / "other-run" / "hook-Stop.json"),
    }
    native.boundary_report = report
    controller = object.__new__(BelloController)
    controller.context_runtime = prepared
    controller.coder_client = object()
    controller.supervisor_client = object()

    with pytest.raises(ContextModeStartupError, match="attestations"):
        await controller._preflight_context_app_server_boundary()

    assert coordinator.failed
    assert not prepared.purge_protocol_attested


@pytest.mark.asyncio
async def test_trusted_purge_rotates_state_before_separate_controlled_process_transition(
    tmp_path: Path,
) -> None:
    controller, runtime, _, store, events = _restart_controller(
        tmp_path,
        purge_protocol_attested=True,
    )

    await controller.recycle_coder_process(
        "trusted ctx_purge",
        rotate_context_state_epoch=True,
    )

    assert [reason for reason, _, _ in runtime.transitions] == [
        TransitionReason.STATE_EPOCH_ROTATION,
        TransitionReason.CONTROLLED_RECYCLE,
    ]
    _, initial, rotated = runtime.transitions[0]
    _, before_process, restarted = runtime.transitions[1]
    assert rotated.lifecycle.context_state_epoch == initial.lifecycle.context_state_epoch + 1
    assert rotated.lifecycle.coder_process_epoch == initial.lifecycle.coder_process_epoch
    assert before_process == rotated
    assert restarted.lifecycle.context_state_epoch == rotated.lifecycle.context_state_epoch
    assert restarted.lifecycle.coder_process_epoch == rotated.lifecycle.coder_process_epoch + 1
    assert events.index("transition:state_epoch_rotation") < events.index("client:reserve")
    assert events.index("client:reserve") < events.index("transition:controlled_recycle")
    assert store.config.context_state_epoch == 1
    assert store.config.coder_process_epoch == 2
    assert store.config.context_binding_version == restarted.binding_version
    assert controller._context_call_start_revision == {}
    assert controller._context_pending_approval_calls == {}
    assert controller._active_workspace_mutations == {}
    assert controller._overlapped_workspace_mutations == set()
    assert controller._workspace_mutation_terminals == {}
    assert controller._workspace_revision == 8


@pytest.mark.asyncio
async def test_purge_post_transition_failure_is_terminal_provider_failure(tmp_path: Path) -> None:
    controller, runtime, _, store, events = _restart_controller(
        tmp_path,
        purge_protocol_attested=True,
    )

    def reject_metrics(_: object) -> dict[str, object]:
        raise RuntimeError("metrics store failed after process transition")

    async def finalize(reason: str, **_: object) -> None:
        events.append(f"controller:finalize:{reason}")

    store.update_runtime_metrics = reject_metrics  # type: ignore[method-assign]
    controller.finalize = finalize  # type: ignore[method-assign]

    await controller.recycle_coder_process(
        "trusted ctx_purge",
        rotate_context_state_epoch=True,
    )

    assert [reason for reason, _, _ in runtime.transitions] == [
        TransitionReason.STATE_EPOCH_ROTATION,
        TransitionReason.CONTROLLED_RECYCLE,
    ]
    assert runtime.coordinator.failed
    assert runtime.stopped
    assert store.config.status is BelloStatus.PROVIDER_FAILURE
    assert any(event.startswith("controller:finalize:") for event in events)


@pytest.mark.asyncio
async def test_purge_process_transition_rejection_preserves_committed_epoch_and_fails_terminally(
    tmp_path: Path,
) -> None:
    controller, runtime, _, store, events = _restart_controller(
        tmp_path,
        purge_protocol_attested=True,
    )
    transition_binding = runtime.transition_binding

    async def reject_process_transition(**kwargs: object) -> ContextBinding:
        if TransitionReason(kwargs["reason"]) is TransitionReason.CONTROLLED_RECYCLE:
            raise RuntimeError("native rejected the process identity transition")
        return await transition_binding(**kwargs)

    async def finalize(reason: str, **_: object) -> None:
        events.append(f"controller:finalize:{reason}")

    runtime.transition_binding = reject_process_transition  # type: ignore[method-assign]
    controller.finalize = finalize  # type: ignore[method-assign]

    await controller.recycle_coder_process(
        "trusted ctx_purge",
        rotate_context_state_epoch=True,
    )

    assert [reason for reason, _, _ in runtime.transitions] == [
        TransitionReason.STATE_EPOCH_ROTATION
    ]
    assert runtime.binding.lifecycle.context_state_epoch == 1
    assert runtime.binding.lifecycle.coder_process_epoch == 1
    assert store.config.context_state_epoch == 1
    assert store.config.coder_process_epoch == 1
    assert store.config.context_binding_version == runtime.binding.binding_version
    assert "client:start" not in events
    assert runtime.coordinator.failed
    assert runtime.stopped
    assert store.config.status is BelloStatus.PROVIDER_FAILURE


@pytest.mark.asyncio
async def test_ordinary_process_recovery_does_not_rotate_context_state_epoch(tmp_path: Path) -> None:
    controller, runtime, _, store, events = _restart_controller(
        tmp_path,
        purge_protocol_attested=False,
    )

    await controller.recover_coder_process("transport crashed")

    assert [reason for reason, _, _ in runtime.transitions] == [TransitionReason.PROCESS_RECOVERY]
    _, previous, recovered = runtime.transitions[0]
    assert recovered.lifecycle.context_state_epoch == previous.lifecycle.context_state_epoch == 0
    assert recovered.lifecycle.coder_process_epoch == previous.lifecycle.coder_process_epoch + 1
    assert store.config.context_state_epoch == 0
    assert store.config.coder_process_epoch == 2
    assert controller._context_call_start_revision == {}
    assert controller._active_workspace_mutations == {}
    assert events.index("coder:recover_transport") < events.index(
        "runtime:recover_checkpoint"
    )
    assert events.index("runtime:recover_checkpoint") < events.index("runtime:resume")
    assert events.index("runtime:resume") < events.index("coder:start_recovery_turn")


@pytest.mark.asyncio
async def test_purge_recycle_without_native_exclusive_attestation_fails_before_transition(
    tmp_path: Path,
) -> None:
    controller, runtime, _, store, events = _restart_controller(
        tmp_path,
        purge_protocol_attested=False,
    )

    async def finalize(reason: str, **_: object) -> None:
        events.append(f"controller:finalize:{reason}")

    controller.finalize = finalize  # type: ignore[method-assign]
    await controller.recycle_coder_process(
        "unattested ctx_purge",
        rotate_context_state_epoch=True,
    )

    assert runtime.transitions == []
    assert "client:reserve" not in events
    assert runtime.coordinator.failed
    assert runtime.stopped
    assert store.config.status is BelloStatus.PROVIDER_FAILURE
    assert any(event.startswith("controller:finalize:") for event in events)


@pytest.mark.asyncio
async def test_purge_recycle_budget_exhaustion_is_terminal_without_epoch_rotation(
    tmp_path: Path,
) -> None:
    controller, runtime, _, store, events = _restart_controller(
        tmp_path,
        purge_protocol_attested=True,
    )
    store.config = store.config.model_copy(update={"coder_process_controlled_recycles": 2})

    async def finalize(reason: str, **_: object) -> None:
        events.append(f"controller:finalize:{reason}")

    controller.finalize = finalize  # type: ignore[method-assign]
    await controller.recycle_coder_process(
        "trusted ctx_purge with exhausted recycle budget",
        rotate_context_state_epoch=True,
    )

    assert runtime.transitions == []
    assert "runtime:quiesce" not in events
    assert "client:reserve" not in events
    assert runtime.coordinator.failed
    assert runtime.stopped
    assert store.config.status is BelloStatus.PROVIDER_FAILURE
    assert store.config.context_state_epoch == 0
    assert any("budget exhausted" in event for event in events if event.startswith("controller:finalize:"))


def test_proxy_policy_allows_exactly_one_public_bootstrap_file_per_launch(tmp_path: Path) -> None:
    bootstrap_root = tmp_path / "bootstrap"
    bootstrap_root.mkdir()
    layout = SandboxPathLayout(
        workspace=tmp_path / "workspace",
        runtime=tmp_path / "runtime",
        state=tmp_path / "state",
        mcp_home=tmp_path / "mcp-home",
        mcp_temp=tmp_path / "mcp-temp",
        hook_home=tmp_path / "hook-home",
        hook_temp=tmp_path / "hook-temp",
        command_home=tmp_path / "command-home",
        command_scratch=tmp_path / "command-scratch",
        launcher=tmp_path / "bin" / "launcher",
        bootstrap=bootstrap_root,
        proxy_bootstrap_files=(
            bootstrap_root / "mcp.json",
            *(bootstrap_root / f"hook-{event}.json" for event in REQUIRED_HOOKS),
        ),
        workspace_git=tmp_path / "workspace" / ".git",
        toolchain_roots=(tmp_path / "toolchain",),
    )
    policies = generate_sandbox_policies(layout, environment=_environment(tmp_path))
    proxy = policies[ProfileKind.PROXY]
    assert [rule.path_class for rule in proxy.mounts] == ["launcher"]
    assert proxy.proxy_bootstrap is not None
    allowed = set(proxy.proxy_bootstrap.allowed_files)
    assert os.fspath(bootstrap_root / "mcp.json") in allowed
    for event in ("PreToolUse", "PostToolUse", "SessionStart", "PreCompact", "UserPromptSubmit", "Stop"):
        assert os.fspath(bootstrap_root / f"hook-{event}.json") in allowed
    assert proxy.proxy_bootstrap.exactly_one_per_launch


def test_native_launcher_integrity_rejects_tamper_and_unsafe_paths(tmp_path: Path) -> None:
    launcher = tmp_path / "runtime" / "launcher"
    launcher.parent.mkdir()
    launcher.write_bytes(b"trusted launcher\n")
    launcher.chmod(0o700)
    expected = hashlib.sha256(launcher.read_bytes()).hexdigest()

    NativeRuntimeEndpoint(
        launcher_path=launcher,
        launcher_sha256=expected,
        public_bootstrap={"channel": "public"},
        runtime_instance_id="runtime-1",
    )
    launcher.write_bytes(b"tampered launcher\n")
    with pytest.raises(ContextModeStartupError, match="SHA-256 mismatch"):
        NativeRuntimeEndpoint(
            launcher_path=launcher,
            launcher_sha256=expected,
            public_bootstrap={"channel": "public"},
            runtime_instance_id="runtime-1",
        )

    launcher.write_bytes(b"trusted launcher\n")
    launcher.chmod(0o722)
    with pytest.raises(ContextModeStartupError, match="group/world writable"):
        NativeRuntimeEndpoint(
            launcher_path=launcher,
            launcher_sha256=expected,
            public_bootstrap={"channel": "public"},
            runtime_instance_id="runtime-1",
        )

    launcher.chmod(0o700)
    alias = tmp_path / "runtime-alias"
    alias.symlink_to(launcher.parent, target_is_directory=True)
    with pytest.raises(ContextModeStartupError, match="canonical"):
        NativeRuntimeEndpoint(
            launcher_path=alias / launcher.name,
            launcher_sha256=expected,
            public_bootstrap={"channel": "public"},
            runtime_instance_id="runtime-1",
        )

    with pytest.raises(ContextModeStartupError, match="schema must contain only channel"):
        NativeRuntimeEndpoint(
            launcher_path=launcher,
            launcher_sha256=expected,
            public_bootstrap={"transport": {"receipt_key": "must-not-be-public"}},
            runtime_instance_id="runtime-1",
        )
    for invalid in (
        {},
        {"channel": "public", "receipt_private_key": "forbidden"},
        {"channel": "../runtime-metadata/authority"},
    ):
        with pytest.raises(ContextModeStartupError):
            NativeRuntimeEndpoint(
                launcher_path=launcher,
                launcher_sha256=expected,
                public_bootstrap=invalid,
                runtime_instance_id="runtime-1",
            )
