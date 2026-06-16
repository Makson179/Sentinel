from __future__ import annotations

import asyncio
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from supervisor.appserver import AppServerClient, AppServerError, AppServerMessage
from supervisor.approvals import ApprovalManager, normalize_approval_request
from supervisor.coder import CODER_SANDBOX_DANGER_FULL_ACCESS, CoderSession, coder_sandbox_mode, coder_thread_params
from supervisor.health import kill_restart_candidate, patch_health
from supervisor.schemas import (
    AppEvent,
    AppEventSource,
    ApprovalContext,
    ApprovalWakeContext,
    ChangedFile,
    ChangedFileContext,
    ChangedFileDiff,
    ChangedTestsSummary,
    CoderMessage,
    CompletionReturnRecord,
    CompletionReviewDecision,
    CompletionReviewDecisionKind,
    DiffPacketLimits,
    FinalReport,
    HealthDelta,
    HumanMessage,
    PriorIntervention,
    RestartHandoff,
    SentinelConfig,
    SentinelStatus,
    SupervisorDecision,
    SupervisorDecisionKind,
    SupervisorWakePacket,
    TriggeringAction,
    ValidationOutput,
    ValidationRun,
)
from supervisor.schemas.models import ensure_relative_to
from supervisor.state import DECISIONS, HANDOFF, PROGRESS, StateStore
from supervisor.supervisor_agent import StatelessSupervisorAgent, SupervisorAgentError
from supervisor.task_select import resolve_task
from supervisor.tui import TerminalTUI, UserCommand
from supervisor.workspace_clean import clean_workspace_except_task


VALIDATION_LEDGER_LIMIT = 50
READINESS_MARKER = "SENTINEL_READY_FOR_REVIEW"
READINESS_MARKER_RE = re.compile(r"^\s*SENTINEL_READY_FOR_REVIEW\s*$", re.MULTILINE)
NO_MARKER_IDLE_NUDGE = (
    "Continue working. If you believe the task is ready, provide Summary, Validation evidence, "
    "and the exact readiness marker on its own line: SENTINEL_READY_FOR_REVIEW."
)
ACCEPT_GATE_REVIEWER_INCOMPLETE = "reviewer-incomplete"
ACCEPT_GATE_CODER_CORRECTABLE = "coder-correctable"
ACCEPT_GATE_AUDIT_FAILURE = "audit-failure"
LARGE_DIFF_CHANGED_LINES_THRESHOLD = 500
LARGE_DIFF_CHANGED_FILES_THRESHOLD = 10


@dataclass(frozen=True)
class ControllerEvent:
    kind: str
    message: AppServerMessage | None = None
    user_command: UserCommand | None = None
    error: BaseException | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class AcceptGateResult:
    passed: bool
    failure_type: str | None = None
    check_name: str | None = None
    reason: str | None = None
    passed_checks: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuntimeTriggerDecision:
    should_wake: bool
    reasons: tuple[str, ...] = ()


class SentinelController:
    def __init__(
        self,
        project_root: Path,
        *,
        task_path: Path | None = None,
        client: AppServerClient | None = None,
        tui: TerminalTUI | None = None,
        model: str | None = None,
        overwrite_state: bool = False,
        clean_workspace: bool = False,
        use_git_diff: bool = True,
    ):
        self.project_root = project_root.resolve()
        self.task_path = resolve_task(self.project_root, task_path)
        if clean_workspace:
            clean_workspace_except_task(self.project_root, self.task_path)
        self.store = StateStore(self.project_root)
        self.model = model
        self.overwrite_state = overwrite_state
        self.use_git_diff = use_git_diff
        self.event_queue: asyncio.Queue[ControllerEvent] = asyncio.Queue()
        self.client = client or AppServerClient(
            cwd=self.project_root,
            notification_handler=self._on_notification,
            server_request_handler=self._on_server_request,
            transport_error_handler=self._on_transport_error,
        )
        self.tui = tui or TerminalTUI()
        self.supervisor: StatelessSupervisorAgent | None = None
        self.approvals: ApprovalManager | None = None
        self.coder: CoderSession | None = None
        self.pending_approvals: dict[int | str, ApprovalContext] = {}
        self.last_coder_message: CoderMessage | None = None
        self.validations: list[ValidationRun] = []
        self.observed_changed_files: dict[str, ChangedFile] = {}
        self._command_output_chunks: dict[str, list[str]] = {}
        self.prior_interventions: list[PriorIntervention] = []
        self.running = False
        self.paused = False
        self._sequence = 0
        self._supervisor_task: asyncio.Task[None] | None = None
        self._supervisor_dirty = False
        self._supervisor_next_summary: str | None = None
        self._supervisor_next_completion_review = False
        self._current_turn_action_count = 0
        self._last_completion_marker_sequence: int | None = None
        self.completion_returns: list[CompletionReturnRecord] = []
        self.completion_attempt_count = 0
        self.completion_restarts = 0
        self.completion_reviewer_rerun_count = 0
        self.no_marker_idle_nudge_count = 0
        self.validation_runtime_state: dict[str, dict[str, Any]] = {}
        self.completion_review_return_sequence: int | None = None
        self.completion_review_return_validation_sequence: int | None = None
        self._terminal_cleanup_started = False

    async def run(self) -> None:
        self.initialize_state()
        try:
            await self.client.start()
            await self.client.initialize()
            await self.tui.start()
            self.running = True
            await self.preflight()
            self.supervisor = StatelessSupervisorAgent(
                self.client,
                self.store,
                self.task_path,
                model=self.model,
            )
            self.approvals = ApprovalManager(self.project_root, supervisor=self)
            self.coder = CoderSession(self.client, self.store, self.project_root, self.task_path, model=self.model)
            await self.coder.start_thread()
            await self.coder.start_initial_turn()
            self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"status": SentinelStatus.RUNNING}))
            self.tui.status("supervised coder started")
            await self.event_loop()
        except (AppServerError, SupervisorAgentError) as exc:
            await self.fail_provider(f"app-server RPC failed: {exc}")
        finally:
            self.running = False
            await self._stop_supervisor_task()
            await self.tui.stop()
            await self.client.stop()

    def initialize_state(self) -> None:
        config = SentinelConfig(
            project_root=str(self.project_root),
            task_path=str(self.task_path),
            task_hash=_hash_file(self.task_path),
            model=self.model,
        )
        self.store.initialize_sentinel(config, overwrite=self.overwrite_state)

    async def preflight(self) -> None:
        self.tui.status("checking Codex version")
        version = _run_probe(["codex", "--version"])[1]
        self.tui.status("checking Codex app-server schema")
        schema_hash = await self._generate_schema_hash_async()
        self.store.update_sentinel_config(
            lambda cfg: cfg.model_copy(update={"codex_version": version, "appserver_schema_hash": schema_hash})
        )
        self.tui.status("checking Codex account")
        account = await self.client.account_read()
        if account.get("requiresOpenaiAuth") and account.get("account") is None:
            raise RuntimeError("Codex auth missing. Run `codex login` before starting Sentinel.")
        self.tui.status("checking Codex rate limits")
        try:
            await self.client.account_rate_limits_read()
        except Exception as exc:
            warning = f"Codex rate limit check unavailable; continuing: {exc}"
            self.tui.render("SYSTEM", warning)
            self.store.append_raw_log(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "preflight_warning",
                    "check": "codex_rate_limits",
                    "error_type": exc.__class__.__name__,
                    "error": str(exc),
                }
            )
        self.tui.status("checking available models")
        models = await self.client.model_list()
        if self.model is None:
            self.model = _default_model(models)
            self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"model": self.model}))
        self.tui.status("checking supervisor structured output")
        await self._structured_output_self_test()
        self.tui.status("checking config requirements")
        await self.client.config_requirements_read()
        self.tui.status("checking coder sandbox and approval settings")
        thread = await self.client.thread_start(coder_thread_params(self.project_root, model=self.model))
        approval_policy = thread.get("approvalPolicy")
        sandbox = thread.get("sandbox")
        thread_id = thread.get("thread", {}).get("id") if isinstance(thread.get("thread"), dict) else None
        if approval_policy != "on-request":
            raise RuntimeError("app-server did not accept on-request coder approval policy")
        expected_sandbox = coder_sandbox_mode()
        if not _sandbox_matches_mode(sandbox, expected_sandbox):
            raise RuntimeError(f"app-server did not accept {expected_sandbox} coder sandbox")
        if isinstance(thread_id, str):
            await self._cleanup_preflight_probe_thread(thread_id)

    async def event_loop(self) -> None:
        assert self.tui is not None
        while self.running:
            event_task = asyncio.create_task(self.event_queue.get())
            input_task = asyncio.create_task(self.tui.input_queue.get())
            done, pending = await asyncio.wait({event_task, input_task}, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            for done_task in done:
                completed = done_task.result()
                if isinstance(completed, ControllerEvent):
                    await self.handle_controller_event(completed)
                elif isinstance(completed, UserCommand):
                    await self.handle_user_command(completed)

    async def handle_controller_event(self, event: ControllerEvent) -> None:
        try:
            if event.kind == "shutdown":
                return
            if event.kind == "transport_error":
                await self.handle_transport_error(event)
                return
            if event.message is None:
                return
            message = event.message
            if event.kind == "server_request":
                await self.handle_server_request(message)
            elif event.kind == "notification":
                await self.handle_notification(message)
        except AppServerError as exc:
            await self.fail_provider(f"app-server RPC failed while handling {event.kind}: {exc}")

    async def handle_transport_error(self, event: ControllerEvent) -> None:
        message = event.error_message or str(event.error) or "app-server transport error"
        self._append_event(AppEventSource.APP_SERVER, "appServer/transportError", reason=message)
        await self.finalize(f"app-server transport error: {message}", status=SentinelStatus.PROVIDER_FAILURE)

    async def fail_provider(self, message: str) -> None:
        if not self.running and self.store.get_sentinel_config().status == SentinelStatus.PROVIDER_FAILURE:
            return
        await self.finalize(message, status=SentinelStatus.PROVIDER_FAILURE)

    async def _cleanup_preflight_probe_thread(self, thread_id: str) -> None:
        try:
            await self.client.thread_unsubscribe(thread_id)
        except Exception as exc:
            self._append_cleanup_error(
                cleanup_kind="preflight_probe_thread",
                thread_id=thread_id,
                turn_id=None,
                error=exc,
            )

    async def handle_user_command(self, command: UserCommand) -> None:
        text = command.text.strip()
        if not text:
            return
        self._append_event(AppEventSource.USER, "user/input", reason=text)
        if text == "/quit":
            await self.finalize("exited by user", status=SentinelStatus.EXITED)
            return
        if text in {"/pause", "\x03"}:
            await self.pause()
            return
        if text == "/resume":
            self.paused = False
            self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"status": SentinelStatus.RUNNING}))
            self.tui.status("resumed")
            return
        if text == "/restart":
            await self.restart("user requested supervised restart")
            return
        if text == "/status":
            cfg = self.store.get_sentinel_config()
            health = self.store.get_health()
            self.tui.render("SYSTEM", f"task={Path(cfg.task_path).name} generation={cfg.generation} active_turn={cfg.active_coder_turn_id} pending_approvals={len(self.pending_approvals)} restarts={health.restart_count}")
            return
        self._schedule_supervisor_check(
            f"Human message to supervisor: {text}",
            human_message=HumanMessage(text=command.text, sequence=self._sequence),
        )

    async def handle_server_request(self, message: AppServerMessage) -> None:
        context = normalize_approval_request(message)
        if getattr(self, "_terminal_cleanup_started", False):
            manager = getattr(self, "approvals", None) or ApprovalManager(self.project_root)
            resolution = manager._deny(context, "terminal state reached")
            await self.client.respond(context.server_request_id, manager.response_payload(context, resolution))
            self.tui.render("DENIED", f"{resolution.decision}: {resolution.reason}")
            return
        self.pending_approvals[context.server_request_id] = context
        self.store.update_sentinel_config(
            lambda cfg: cfg.model_copy(update={"pending_server_request_ids": list(self.pending_approvals)})
        )
        self._append_event(
            AppEventSource.APPROVAL,
            context.server_request_method,
            thread_id=context.thread_id,
            turn_id=context.turn_id,
            item_id=context.item_id,
            reason=context.command or context.grant_root or context.request_type.value,
        )
        if self.approvals is None:
            resolution = ApprovalManager(self.project_root)._deny(context, "approval manager not ready")
            response = ApprovalManager(self.project_root).response_payload(context, resolution)
        else:
            resolution = await self.approvals.decide(context)
            response = self.approvals.response_payload(context, resolution)
        await self.client.respond(context.server_request_id, response)
        is_denial = _approval_resolution_is_denial(resolution.decision)
        self.tui.render("DENIED" if is_denial else "APPROVAL", f"{resolution.decision}: {resolution.reason}")
        if resolution.persistent_decision:
            self.store.append_text_locked(DECISIONS, f"- {resolution.persistent_decision}\n")
        if is_denial:
            if self.coder is not None:
                await self.coder.steer_or_start(resolution.reason)
            patch_health(self.store, HealthDelta(generation=self.store.get_health().generation, denied_requests=1, last_denial=resolution.reason))

    async def decide_approval(self, context: ApprovalContext, reason: str) -> SupervisorDecision:
        if self.supervisor is None:
            raise SupervisorAgentError("supervisor not ready")
        self._reconcile_intervention_accounting()
        cfg = self.store.get_sentinel_config()
        wake_sequence = cfg.last_event_sequence + 1
        approval_context = _approval_wake_context(context, reason)
        packet = self.supervisor.build_packet(
            wake_sequence=wake_sequence,
            current_summary=f"Approval request needs judgment: {reason}",
            diff_summary=await self.diff_summary(),
            triggering_server_request_id=context.server_request_id,
            approval_context=approval_context,
            pending_approvals=[
                _approval_wake_context(pending, reason if pending.server_request_id == context.server_request_id else None)
                for pending in self.pending_approvals.values()
            ],
            last_coder_message=self.last_coder_message,
            validations=list(self.validations),
            prior_interventions=list(self.prior_interventions),
            changed_files=await self.changed_files(),
            patch_summary=_patch_summary_from_approval_context(context) or await self.patch_summary(),
        )
        return await self.supervisor.decide(packet)

    async def handle_notification(self, message: AppServerMessage) -> None:
        params = message.params
        method = message.method or "notification"
        thread_id = params.get("threadId")
        turn_id = _turn_id_from_params(params)
        item_id = _item_id_from_params(params)
        if _is_stream_delta_method(method):
            self._record_command_output_delta(method, params, item_id=item_id)
            return
        self._append_event(AppEventSource.APP_SERVER, method, thread_id=thread_id, turn_id=turn_id, item_id=item_id)
        if getattr(self, "_terminal_cleanup_started", False) and method != "serverRequest/resolved":
            return

        cfg = self.store.get_sentinel_config()
        if method == "serverRequest/resolved":
            request_id = params.get("requestId")
            self.pending_approvals.pop(request_id, None)
            self.store.update_sentinel_config(
                lambda current: current.model_copy(update={"pending_server_request_ids": list(self.pending_approvals)})
            )
            return
        if method == "turn/started" and thread_id == cfg.coder_thread_id and isinstance(turn_id, str):
            if self.coder:
                self.coder.active_turn_id = turn_id
            self._current_turn_action_count = 0
            self.store.update_sentinel_config(lambda current: current.model_copy(update={"active_coder_turn_id": turn_id}))
            self.tui.render("CODER", f"turn started {turn_id}")
            return
        if method == "item/completed" and thread_id == cfg.coder_thread_id:
            summary = _item_summary(params.get("item"))
            item = params.get("item")
            if isinstance(item, dict) and item.get("type") == "agentMessage" and isinstance(item.get("text"), str):
                text = item["text"].strip()
                if text:
                    self.last_coder_message = CoderMessage(text=text, sequence=self._sequence)
                self.tui.render("CODER", text)
                return
            if _is_completed_action(item):
                self._current_turn_action_count = getattr(self, "_current_turn_action_count", 0) + 1
                self.store.append_recent_action(summary)
                triggering_action = _triggering_action_from_item(item, item_id=item_id, summary=summary)
                self._record_changed_files(triggering_action)
                validation_item = _item_with_recorded_output(item, self._pop_command_output(item_id))
                validation = _validation_from_action(
                    triggering_action,
                    sequence=self._sequence,
                    item=validation_item,
                    changed_paths=list(getattr(self, "observed_changed_files", {}) or {}),
                )
                validation_trigger_reasons: tuple[str, ...] = ()
                if validation is not None:
                    self.validations.append(validation)
                    self.validations = self.validations[-VALIDATION_LEDGER_LIMIT:]
                    self._record_validation_progress(validation)
                    validation_trigger_reasons = self._record_validation_runtime_state(validation)
                changed_files = await self.changed_files()
                self._update_relevant_edit_state(changed_files)
                runtime_decision = self.should_wake_runtime_supervisor(
                    action=triggering_action,
                    validation=validation,
                    changed_files=changed_files,
                    validation_trigger_reasons=validation_trigger_reasons,
                )
                self.tui.render("TOOL", summary)
                self._record_runtime_trigger_trace(
                    event_type=method,
                    action=triggering_action,
                    validation=validation,
                    changed_files=changed_files,
                    decision=runtime_decision,
                )
                if runtime_decision.should_wake:
                    self._schedule_supervisor_check(
                        f"Runtime trigger ({', '.join(runtime_decision.reasons)}): {summary}",
                        triggering_item_id=item_id,
                        triggering_action=triggering_action,
                        patch_summary=_patch_summary_from_item(item),
                    )
            return
        if method == "turn/completed" and thread_id == cfg.coder_thread_id:
            if self.coder and isinstance(turn_id, str):
                self.coder.mark_turn_completed(turn_id)
            await self._handle_coder_turn_completed(item_id=item_id)

    def _record_command_output_delta(self, method: str, params: dict[str, Any], *, item_id: str | None) -> None:
        if method not in {"item/commandExecution/outputDelta", "command/exec/outputDelta", "process/outputDelta"}:
            return
        if not item_id:
            return
        text = _output_delta_text(params)
        if not text:
            return
        chunks = getattr(self, "_command_output_chunks", None)
        if chunks is None:
            chunks = {}
            self._command_output_chunks = chunks
        chunks.setdefault(item_id, []).append(text)

    def _pop_command_output(self, item_id: str | None) -> str:
        if not item_id:
            return ""
        chunks = getattr(self, "_command_output_chunks", None)
        if not chunks:
            return ""
        return "".join(chunks.pop(item_id, []))

    async def _handle_coder_turn_completed(self, *, item_id: str | None) -> None:
        message = self.last_coder_message
        if message is not None and _has_readiness_marker(message.text):
            if self._last_completion_marker_sequence != message.sequence:
                self._last_completion_marker_sequence = message.sequence
                self.no_marker_idle_nudge_count = 0
                self.completion_reviewer_rerun_count = 0
                done_gap = await self._done_without_fresh_behavioral_validation()
                if done_gap is not None:
                    self._record_runtime_trigger_trace(
                        event_type="turn/completed",
                        action=TriggeringAction(
                            item_id=item_id,
                            kind="done",
                            status="completed",
                            summary=done_gap,
                        ),
                        validation=None,
                        changed_files=await self.changed_files(),
                        decision=RuntimeTriggerDecision(
                            should_wake=True,
                            reasons=("done_without_fresh_validation",),
                        ),
                    )
                    self._schedule_supervisor_check(
                        f"Runtime trigger (done_without_fresh_validation): {done_gap}",
                        triggering_item_id=item_id,
                    )
                    return
                self._schedule_supervisor_check(
                    "Coder provided exact readiness marker; running completion_review.",
                    triggering_item_id=item_id,
                    completion_review=True,
                )
            return
        if message is not None and _has_malformed_readiness_marker(message.text):
            await self._steer_for_marker(
                "Coder used a malformed readiness marker; require exact marker only after validation.",
                sequence=message.sequence,
            )
            return
        if message is not None and _appears_to_claim_readiness(message.text):
            await self._steer_for_marker(
                "Coder appears to be claiming readiness but did not provide exact readiness marker.",
                sequence=message.sequence,
            )
            return
        if self.pending_approvals:
            self._schedule_supervisor_check("Coder turn completed", triggering_item_id=item_id)
            return
        if getattr(self, "_current_turn_action_count", 0) == 0:
            await self._handle_no_marker_idle()
            return
        self._schedule_supervisor_check("Coder turn completed", triggering_item_id=item_id)

    async def _done_without_fresh_behavioral_validation(self) -> str | None:
        changed_files = await self.changed_files()
        self._update_relevant_edit_state(changed_files)
        cfg = self.store.get_sentinel_config()
        latest_relevant_edit = cfg.last_relevant_edit_sequence
        if latest_relevant_edit is None:
            return None
        if any(_validation_is_fresh_behavioral_pass(validation, latest_relevant_edit) for validation in self.validations):
            return None
        return (
            "coder marked done without a trusted fresh behavioral validation after "
            f"relevant edit sequence {latest_relevant_edit}"
        )

    async def _steer_for_marker(
        self,
        reason: str,
        *,
        sequence: int | None = None,
        message: str = NO_MARKER_IDLE_NUDGE,
    ) -> None:
        cfg = self.store.get_sentinel_config()
        self.prior_interventions.append(
            PriorIntervention(reason=reason, message_to_coder=message, sequence=sequence or cfg.last_event_sequence)
        )
        self.prior_interventions = self.prior_interventions[-20:]
        patch_health(self.store, HealthDelta(generation=cfg.generation, interventions=1))
        self.tui.render("SUPERVISOR", reason)
        if self.coder:
            await self.coder.steer_or_start(message)

    async def _handle_no_marker_idle(self) -> None:
        cfg = self.store.get_sentinel_config()
        max_nudges = getattr(cfg, "max_no_marker_idle_nudges", 2)
        self.no_marker_idle_nudge_count = getattr(self, "no_marker_idle_nudge_count", 0)
        if self.no_marker_idle_nudge_count < max_nudges:
            self.no_marker_idle_nudge_count += 1
            self.prior_interventions.append(
                PriorIntervention(
                    reason="Coder turn ended idle without readiness marker.",
                    message_to_coder=NO_MARKER_IDLE_NUDGE,
                    sequence=cfg.last_event_sequence,
                )
            )
            self.prior_interventions = self.prior_interventions[-20:]
            patch_health(self.store, HealthDelta(generation=cfg.generation, interventions=1))
            self.tui.render("SUPERVISOR", "nudging coder for readiness marker or continued work")
            if self.coder:
                await self.coder.steer_or_start(NO_MARKER_IDLE_NUDGE)
            return
        patch_health(
            self.store,
            HealthDelta(generation=cfg.generation, add_risk_signals=["no_marker_idle_loop"]),
        )
        candidate, candidate_reason = kill_restart_candidate(self.store.get_health())
        if candidate and cfg.restart_count < cfg.max_restarts:
            handoff = _fallback_restart_handoff(
                task_contents=self.task_path.read_text(encoding="utf-8") if self.task_path.exists() else cfg.task_path,
                reason=candidate_reason or "coder repeatedly idled without readiness marker",
                last_actions=self.store.read_recent_actions(10),
            )
            await self.restart(candidate_reason or "coder repeatedly idled without readiness marker", handoff=handoff)
            return
        await self.finalize(
            "escalated: coder repeatedly idled without readiness marker or progress",
            status=SentinelStatus.ESCALATED,
        )

    async def pause(self) -> None:
        self.paused = True
        self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"status": SentinelStatus.PAUSED}))
        if self.coder:
            try:
                await self.coder.interrupt()
            except AppServerError:
                raise
            except Exception:
                pass
        await self._resolve_pending_approvals("paused")
        self.tui.status("paused")

    async def restart(self, reason: str, *, handoff: RestartHandoff | None = None) -> None:
        cfg = self.store.get_sentinel_config()
        if cfg.restart_count >= cfg.max_restarts:
            await self.finalize("restart cap reached", status=SentinelStatus.STUCK)
            return
        await self._close_completion_review_session()
        self.store.update_sentinel_config(lambda current: current.model_copy(update={"status": SentinelStatus.RESTARTING}))
        if self.coder:
            try:
                await self.coder.interrupt()
            except AppServerError:
                raise
            except Exception:
                pass
        await self._resolve_pending_approvals("restart")
        handoff = handoff or _fallback_restart_handoff(
            task_contents=self.task_path.read_text(encoding="utf-8") if self.task_path.exists() else cfg.task_path,
            reason=reason,
            last_actions=self.store.read_recent_actions(10),
        )
        self.store.write_handoff(handoff.model_dump_json(indent=2) + "\n")
        self.prior_interventions = []
        self.no_marker_idle_nudge_count = 0
        self._last_completion_marker_sequence = None
        self.completion_review_return_sequence = None
        self.completion_review_return_validation_sequence = None
        self.validation_runtime_state = {}
        patch_health(
            self.store,
            HealthDelta(
                generation=cfg.generation,
                restart_count=1,
                reset_generation_scoped=True,
                new_generation=cfg.generation + 1,
            ),
        )
        self.store.update_sentinel_config(
            lambda current: current.model_copy(
                update={
                    "generation": current.generation + 1,
                    "restart_count": current.restart_count + 1,
                    "active_coder_turn_id": None,
                    "coder_thread_id": None,
                    "status": SentinelStatus.RUNNING,
                }
            )
        )
        self.coder = CoderSession(self.client, self.store, self.project_root, self.task_path, model=self.model)
        await self.coder.start_thread()
        await self.coder.start_restart_turn()
        self.tui.render("SYSTEM", "restart complete")

    async def finalize(
        self,
        result: str,
        *,
        status: SentinelStatus = SentinelStatus.COMPLETE,
        completion_review_accepted: bool = False,
    ) -> None:
        await self._prepare_terminal_shutdown(result)
        self._reconcile_intervention_accounting()
        diff = await self.diff_summary()
        changed_files = await self.changed_files()
        health = self.store.get_health()
        accepted_completion = getattr(self, "_accepted_completion_decision", None)
        report = FinalReport(
            task_path=str(self.task_path),
            status=status,
            result=result,
            files_changed=[file.path for file in changed_files] or _changed_files_from_diff_summary(diff),
            validations=[_format_validation(validation) for validation in self.validations],
            denied_actions=[],
            interventions=health.interventions,
            restarts=health.restart_count,
            completion_review_accepted=completion_review_accepted,
            completion_returns=len(getattr(self, "completion_returns", [])),
            completion_restarts=getattr(self, "completion_restarts", 0),
            no_marker_idle_nudges=getattr(self, "no_marker_idle_nudge_count", 0),
            behavior_evidence_summary=_behavior_evidence_summary(accepted_completion),
            files_reviewed_summary=_files_reviewed_summary(accepted_completion),
            packet_or_access_limitations=list(accepted_completion.packet_or_access_limitations)
            if isinstance(accepted_completion, CompletionReviewDecision)
            else [],
            remaining_risks=list(accepted_completion.changed_test_risks)
            if isinstance(accepted_completion, CompletionReviewDecision)
            else [],
            diff_summary=diff,
        )
        self.store.write_final_report(report)
        self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"status": status}))
        self.tui.render("SUPERVISOR", result)
        self.tui.status("final report written: .supervisor/FINAL_REPORT.md")
        self.running = False
        self._wake_event_loop_for_shutdown()

    async def _prepare_terminal_shutdown(self, reason: str) -> None:
        if getattr(self, "_terminal_cleanup_started", False):
            return
        self._terminal_cleanup_started = True
        self.running = False
        await self._close_completion_review_session()
        coder = getattr(self, "coder", None)
        if coder:
            try:
                await coder.interrupt()
            except Exception as exc:
                self._append_cleanup_error(
                    cleanup_kind="terminal_coder_interrupt",
                    thread_id=getattr(coder, "thread_id", None) or "unknown",
                    turn_id=getattr(coder, "active_turn_id", None),
                    error=exc,
                )
        if getattr(self, "pending_approvals", None) and getattr(self, "client", None) is not None:
            try:
                await self._resolve_pending_approvals(f"terminal state reached: {reason}")
            except Exception as exc:
                self._append_cleanup_error(
                    cleanup_kind="terminal_pending_approvals",
                    thread_id="unknown",
                    turn_id=None,
                    error=exc,
                )
        task = getattr(self, "_supervisor_task", None)
        if task is not None and task is not asyncio.current_task():
            await self._stop_supervisor_task()
        client = getattr(self, "client", None)
        if client is not None and hasattr(client, "stop"):
            try:
                await client.stop()
            except Exception as exc:
                self._append_cleanup_error(
                    cleanup_kind="terminal_appserver_stop",
                    thread_id="unknown",
                    turn_id=None,
                    error=exc,
                )

    async def _close_completion_review_session(self) -> None:
        supervisor = getattr(self, "supervisor", None)
        if supervisor is None or not hasattr(supervisor, "close_completion_review"):
            return
        thread_id = getattr(supervisor, "completion_thread_id", None) or "unknown"
        try:
            await supervisor.close_completion_review()
        except Exception as exc:
            self._append_cleanup_error(
                cleanup_kind="completion_review_session",
                thread_id=thread_id,
                turn_id=None,
                error=exc,
            )

    def _wake_event_loop_for_shutdown(self) -> None:
        queue = getattr(self, "event_queue", None)
        if queue is None:
            return
        try:
            queue.put_nowait(ControllerEvent(kind="shutdown"))
        except Exception:
            pass

    def _reconcile_intervention_accounting(self) -> None:
        prior = getattr(self, "prior_interventions", None)
        if not prior:
            return
        target = len(prior)

        def patch(current):
            if current.interventions >= target:
                return current
            return current.model_copy(update={"interventions": target})

        self.store.patch_health(patch)

    def _schedule_supervisor_check(
        self,
        summary: str,
        *,
        triggering_item_id: str | None = None,
        triggering_action: TriggeringAction | None = None,
        human_message: HumanMessage | None = None,
        patch_summary: str | None = None,
        completion_review: bool = False,
    ) -> None:
        if (
            not self.running
            or getattr(self, "paused", False)
            or getattr(self, "_terminal_cleanup_started", False)
            or getattr(self, "supervisor", None) is None
        ):
            return
        if self._supervisor_task and not self._supervisor_task.done():
            self._supervisor_dirty = True
            self._supervisor_next_summary = summary
            self._supervisor_next_completion_review = completion_review or getattr(
                self,
                "_supervisor_next_completion_review",
                False,
            )
            return
        self._supervisor_task = asyncio.create_task(
            self._supervisor_check_loop(
                summary,
                triggering_item_id,
                triggering_action,
                human_message,
                patch_summary,
                completion_review,
            )
        )

    def _record_validation_progress(self, validation: ValidationRun) -> None:
        def patch(current: SentinelConfig) -> SentinelConfig:
            updates: dict[str, Any] = {"last_validation_sequence": validation.sequence}
            if validation.type == "behavioral" and validation.trusted_validation_outcome != "masked_or_unknown":
                updates["last_trusted_behavioral_validation_sequence"] = validation.sequence
                if validation.trusted_validation_outcome == "passed":
                    updates["last_trusted_passing_behavioral_validation_sequence"] = validation.sequence
            return current.model_copy(update=updates)

        self.store.update_sentinel_config(patch)

    def _record_validation_runtime_state(self, validation: ValidationRun) -> tuple[str, ...]:
        key = validation.validation_id
        state = getattr(self, "validation_runtime_state", None)
        if state is None:
            state = {}
            self.validation_runtime_state = state
        previous = state.get(key, {})
        previous_outcome = previous.get("trusted_validation_outcome")
        previous_failed_count = int(previous.get("consecutive_failed_count") or 0)
        current_outcome = validation.trusted_validation_outcome
        reasons: list[str] = []
        if current_outcome == "masked_or_unknown":
            reasons.append("masked_validation")
        elif current_outcome == "failed":
            if previous_outcome == "passed":
                reasons.append("validation_regression")
            failed_count = previous_failed_count + 1 if previous_outcome == "failed" else 1
            if failed_count >= 2:
                reasons.append("repeated_same_failing_validation")
            previous_failed_count = failed_count
        else:
            previous_failed_count = 0
        state[key] = {
            "trusted_validation_outcome": current_outcome,
            "consecutive_failed_count": previous_failed_count,
            "sequence": validation.sequence,
            "normalized_command": validation.normalized_command,
            "type": validation.type,
        }
        return tuple(dict.fromkeys(reasons))

    def _update_relevant_edit_state(self, changed_files: list[ChangedFile]) -> None:
        task_contents = _read_task_text(self.task_path)
        relevant_sequences = [
            changed.sequence
            for changed in changed_files
            if changed.sequence is not None and _is_relevant_changed_path(changed.path, task_contents=task_contents)
        ]
        if not relevant_sequences:
            return
        latest = max(relevant_sequences)

        def patch(current: SentinelConfig) -> SentinelConfig:
            existing = current.last_relevant_edit_sequence
            if existing is not None and existing >= latest:
                return current
            return current.model_copy(update={"last_relevant_edit_sequence": latest})

        self.store.update_sentinel_config(patch)

    def should_wake_runtime_supervisor(
        self,
        *,
        action: TriggeringAction,
        validation: ValidationRun | None,
        changed_files: list[ChangedFile],
        validation_trigger_reasons: tuple[str, ...] = (),
    ) -> RuntimeTriggerDecision:
        reasons: list[str] = list(validation_trigger_reasons)
        if action.exit_code is not None and action.exit_code != 0:
            reasons.append("nonzero_exit")
        if _action_timed_out(action):
            reasons.append("timeout")
        if validation is not None and validation.trusted_validation_outcome == "masked_or_unknown":
            reasons.append("masked_validation")
        if _has_large_diff(changed_files):
            reasons.append("large_diff")
        if any(_is_suspicious_changed_path(changed.path) for changed in changed_files):
            reasons.append("suspicious_file_touched")
        restart_candidate, restart_reason = kill_restart_candidate(self.store.get_health())
        if restart_candidate and restart_reason:
            reasons.append("restart_budget")
        reasons = list(dict.fromkeys(reasons))
        return RuntimeTriggerDecision(should_wake=bool(reasons), reasons=tuple(reasons))

    def _record_runtime_trigger_trace(
        self,
        *,
        event_type: str,
        action: TriggeringAction | None,
        validation: ValidationRun | None,
        changed_files: list[ChangedFile],
        decision: RuntimeTriggerDecision,
    ) -> None:
        additions, deletions = _diff_line_counts(changed_files)
        suspicious_paths = [changed.path for changed in changed_files if _is_suspicious_changed_path(changed.path)]
        trace = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_sequence": getattr(self, "_sequence", None),
            "generation": self.store.get_sentinel_config().generation,
            "event_type": event_type,
            "action_kind": action.kind if action is not None else None,
            "tool_name": action.kind if action is not None else None,
            "command": action.command if action is not None else None,
            "cwd": action.cwd if action is not None else None,
            "exit_code": action.exit_code if action is not None else None,
            "status": action.status if action is not None else None,
            "changed_files_count": len(changed_files),
            "changed_files": [changed.path for changed in changed_files[:20]],
            "changed_lines": additions + deletions,
            "diff_additions": additions,
            "diff_deletions": deletions,
            "suspicious_paths": suspicious_paths[:20],
            "validation_id": validation.validation_id if validation is not None else None,
            "validation_type": validation.type if validation is not None else None,
            "trusted_validation_outcome": validation.trusted_validation_outcome if validation is not None else None,
            "masking_reason": validation.masking_reason if validation is not None else None,
            "should_wake_runtime_supervisor": decision.should_wake,
            "trigger_reasons": list(decision.reasons),
            "skipped_noop": not decision.should_wake,
        }
        self.store.append_runtime_trace(trace)
        self._update_runtime_metrics(trace)

    def _update_runtime_metrics(self, trace: dict[str, Any]) -> None:
        reasons = trace.get("trigger_reasons")
        if not isinstance(reasons, list):
            reasons = []

        def patch(current: dict[str, Any]) -> dict[str, Any]:
            current["runtime_events_total"] = int(current.get("runtime_events_total") or 0) + 1
            if trace.get("should_wake_runtime_supervisor"):
                current["runtime_wakes_total"] = int(current.get("runtime_wakes_total") or 0) + 1
            if trace.get("skipped_noop"):
                current["runtime_skipped_noop_total"] = int(current.get("runtime_skipped_noop_total") or 0) + 1
            counts = current.get("runtime_trigger_reason_counts")
            if not isinstance(counts, dict):
                counts = {}
            for reason in reasons:
                counts[str(reason)] = int(counts.get(str(reason)) or 0) + 1
                metric_name = f"runtime_trigger_{reason}_total"
                current[metric_name] = int(current.get(metric_name) or 0) + 1
            current["runtime_trigger_reason_counts"] = counts
            return current

        self.store.update_runtime_metrics(patch)

    async def _supervisor_check_loop(
        self,
        summary: str,
        triggering_item_id: str | None,
        triggering_action: TriggeringAction | None,
        human_message: HumanMessage | None,
        patch_summary: str | None,
        completion_review: bool,
    ) -> None:
        while True:
            self._supervisor_dirty = False
            await self._run_supervisor_check(
                summary,
                triggering_item_id,
                triggering_action,
                human_message,
                patch_summary,
                completion_review,
            )
            if not self._supervisor_dirty:
                return
            if not self.running:
                return
            summary = self._supervisor_next_summary or "Supervisor check was dirty; reviewing latest state"
            completion_review = getattr(self, "_supervisor_next_completion_review", False)
            self._supervisor_next_summary = None
            self._supervisor_next_completion_review = False
            triggering_item_id = None
            triggering_action = None
            human_message = None
            patch_summary = None

    async def _run_supervisor_check(
        self,
        summary: str,
        triggering_item_id: str | None,
        triggering_action: TriggeringAction | None,
        human_message: HumanMessage | None,
        patch_summary: str | None,
        completion_review: bool = False,
    ) -> None:
        if self.supervisor is None:
            return
        self._reconcile_intervention_accounting()
        cfg = self.store.get_sentinel_config()
        wake_sequence = cfg.last_event_sequence + 1
        changed_files = await self.changed_files()
        latest_change_sequence = _latest_relevant_change_sequence(changed_files)
        freshness_summary = _validation_freshness_summary(
            validations=list(self.validations),
            changed_files=changed_files,
        )
        completion_payload_mode: Literal["full", "delta", "full_fallback"] | None = None
        completion_payload_since_sequence: int | None = None
        completion_details: dict[str, Any] = {}
        if completion_review:
            completion_payload_mode, completion_payload_since_sequence = self._completion_payload_window(changed_files)
            completion_details = await self.completion_packet_details(
                changed_files,
                since_sequence=completion_payload_since_sequence,
            )
        packet = self.supervisor.build_packet(
            wake_sequence=wake_sequence,
            current_summary=summary,
            diff_summary=await self.diff_summary(),
            triggering_item_id=triggering_item_id,
            pending_approvals=[_approval_wake_context(pending) for pending in self.pending_approvals.values()],
            triggering_action=triggering_action,
            last_coder_message=self.last_coder_message,
            validations=list(self.validations),
            human_message=human_message,
            prior_interventions=list(self.prior_interventions),
            changed_files=changed_files,
            patch_summary=patch_summary or await self.patch_summary(),
            completion_attempt_count=getattr(self, "completion_attempt_count", 0),
            completion_returns_this_generation=_completion_returns_this_generation(self, cfg.generation),
            previous_completion_returns=list(getattr(self, "completion_returns", []))[-10:],
            last_readiness_marker_sequence=getattr(self, "_last_completion_marker_sequence", None),
            no_marker_idle_nudge_count=getattr(self, "no_marker_idle_nudge_count", 0),
            latest_relevant_change_sequence=latest_change_sequence,
            validation_freshness_summary=freshness_summary,
            completion_payload_mode=completion_payload_mode,
            completion_payload_since_sequence=completion_payload_since_sequence,
            completion_review_thread_id=getattr(self.supervisor, "completion_thread_id", None),
            **completion_details,
        )
        try:
            if completion_review:
                self.completion_attempt_count = getattr(self, "completion_attempt_count", 0) + 1
                decision = await self.supervisor.decide_completion(packet)
            else:
                decision = await self.supervisor.decide(packet)
        except SupervisorAgentError as exc:
            message = f"supervisor check failed: {exc}"
            self.tui.render("SUPERVISOR", message)
            if not completion_review and getattr(self, "_supervisor_dirty", False):
                patch_health(
                    self.store,
                    HealthDelta(
                        generation=cfg.generation,
                        timeout_fallback_count=1,
                        add_risk_signals=["stale_runtime_supervisor_timeout"],
                    ),
                )
                self.store.append_text_locked(
                    PROGRESS,
                    "- Runtime supervisor check timed out after newer coder activity; continuing with the latest queued review.\n",
                )
                return
            await self.finalize(message, status=SentinelStatus.PROVIDER_FAILURE)
            return
        if completion_review:
            await self.apply_completion_decision(decision, packet_thread_id=packet.coder_thread_id, packet=packet)
        else:
            await self.apply_supervisor_decision(decision, packet_thread_id=packet.coder_thread_id)

    def _completion_payload_window(
        self,
        changed_files: list[ChangedFile],
    ) -> tuple[Literal["full", "delta", "full_fallback"], int | None]:
        since_sequence = getattr(self, "completion_review_return_sequence", None)
        if since_sequence is None:
            return "full", None
        task_contents = _read_task_text(self.task_path)
        has_unknown_relevant_sequence = any(
            changed.sequence is None and _is_relevant_changed_path(changed.path, task_contents=task_contents)
            for changed in changed_files
        )
        if has_unknown_relevant_sequence:
            return "full_fallback", None
        return "delta", since_sequence

    async def apply_supervisor_decision(self, decision: SupervisorDecision, *, packet_thread_id: str | None) -> None:
        cfg = self.store.get_sentinel_config()
        if decision.generation is not None and decision.generation != cfg.generation:
            return
        if packet_thread_id != cfg.coder_thread_id:
            return
        if decision.wake_sequence is not None and decision.wake_sequence <= cfg.last_applied_supervisor_sequence:
            return
        self.store.update_sentinel_config(
            lambda current: current.model_copy(update={"last_applied_supervisor_sequence": decision.wake_sequence or current.last_applied_supervisor_sequence})
        )
        if decision.persistent_decision:
            self.store.append_text_locked(DECISIONS, f"- {decision.persistent_decision}\n")
        if decision.progress_update:
            self.store.append_text_locked(PROGRESS, f"- {decision.progress_update}\n")
            patch_health(self.store, HealthDelta(generation=cfg.generation, last_progress_sequence=cfg.last_event_sequence))
        if decision.clear_handoff:
            self.store.write_text_locked(HANDOFF, "")
        if decision.display_message:
            self.tui.render("SUPERVISOR", decision.display_message)
        if decision.decision == SupervisorDecisionKind.NOOP:
            return
        if decision.decision == SupervisorDecisionKind.INTERVENE and decision.message_to_coder and self.coder:
            self.tui.render("SUPERVISOR", f"steering coder: {decision.reason}")
            self.prior_interventions.append(
                PriorIntervention(
                    reason=decision.reason,
                    message_to_coder=decision.message_to_coder,
                    sequence=decision.wake_sequence or cfg.last_event_sequence,
                )
            )
            self.prior_interventions = self.prior_interventions[-20:]
            patch_health(self.store, HealthDelta(generation=cfg.generation, interventions=1))
            await self.coder.steer_or_start(decision.message_to_coder)
            return
        if decision.decision == SupervisorDecisionKind.RESTART:
            candidate, candidate_reason = kill_restart_candidate(self.store.get_health())
            if not candidate:
                message = decision.message_to_coder or (
                    "Continue the current task. Do not restart; use the latest observation to make the next concrete progress step."
                )
                self.tui.render("SUPERVISOR", f"restart rejected without health evidence: {decision.reason}")
                if self.coder:
                    await self.coder.steer_or_start(message)
                return
            if candidate_reason:
                self.tui.render("SUPERVISOR", f"restart candidate: {candidate_reason}")
            await self.restart(decision.reason or "supervisor requested restart", handoff=decision.handoff)
            return
        if decision.decision == SupervisorDecisionKind.PAUSE:
            await self.pause()
            return

    async def apply_completion_decision(
        self,
        decision: CompletionReviewDecision,
        *,
        packet_thread_id: str | None,
        packet: SupervisorWakePacket | None = None,
    ) -> None:
        cfg = self.store.get_sentinel_config()
        if decision.generation != cfg.generation:
            return
        if packet_thread_id != cfg.coder_thread_id:
            return
        if decision.wake_sequence <= cfg.last_applied_supervisor_sequence:
            return
        self.store.update_sentinel_config(
            lambda current: current.model_copy(update={"last_applied_supervisor_sequence": decision.wake_sequence})
        )
        self._append_completion_anchor_log(decision, packet=packet)
        if decision.decision == CompletionReviewDecisionKind.ACCEPT:
            gate_result = await self._completion_accept_gate(decision, packet=packet)
            if not gate_result.passed:
                await self._handle_completion_accept_gate_failure(decision, gate_result)
                return
            self._record_accept_gate_success(gate_result)
        if decision.persistent_decision:
            self.store.append_text_locked(DECISIONS, f"- {decision.persistent_decision}\n")
        if decision.progress_update:
            self.store.append_text_locked(PROGRESS, f"- {decision.progress_update}\n")
            patch_health(self.store, HealthDelta(generation=cfg.generation, last_progress_sequence=cfg.last_event_sequence))
        if decision.clear_handoff:
            self.store.write_text_locked(HANDOFF, "")
        if decision.display_message:
            self.tui.render("SUPERVISOR", decision.display_message)
        self._append_event(
            AppEventSource.SUPERVISOR,
            f"completion/{decision.decision.value}",
            decision=decision.decision.value,
            reason=decision.reason,
        )
        if decision.decision == CompletionReviewDecisionKind.ACCEPT:
            self.completion_reviewer_rerun_count = 0
            self._accepted_completion_decision = decision
            await self.finalize(
                f"accepted by completion_review: {decision.reason or 'task complete'}",
                status=SentinelStatus.COMPLETE,
                completion_review_accepted=True,
            )
            return
        if decision.decision == CompletionReviewDecisionKind.RETURN:
            await self._return_completion_to_coder(decision)
            return
        if decision.decision == CompletionReviewDecisionKind.RESTART:
            self.completion_restarts = getattr(self, "completion_restarts", 0) + 1
            await self.restart(decision.reason or "completion review requested restart", handoff=decision.handoff)
            return

    def _append_completion_anchor_log(
        self,
        decision: CompletionReviewDecision,
        *,
        packet: SupervisorWakePacket | None,
    ) -> None:
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "completion_review_anchor",
                "decision": decision.decision.value,
                "wake_sequence": decision.wake_sequence,
                "generation": decision.generation,
                "reason": decision.reason,
                "packet_mode": packet.completion_payload_mode if packet is not None else None,
                "packet_since_sequence": packet.completion_payload_since_sequence if packet is not None else None,
                "validation_ids": [validation.validation_id for validation in (packet.validations if packet else [])],
                "changed_files": [changed.path for changed in (packet.changed_files if packet else [])],
            }
        )

    async def _completion_accept_gate(
        self,
        decision: CompletionReviewDecision,
        *,
        packet: SupervisorWakePacket | None,
    ) -> AcceptGateResult:
        changed_files = packet.changed_files if packet is not None else await self.changed_files()
        validations = packet.validations if packet is not None else list(self.validations)
        code_review_files = _material_code_review_files(changed_files)
        passed_checks: list[str] = []

        if packet is not None:
            if decision.wake_sequence != packet.wake_sequence:
                return AcceptGateResult(
                    passed=False,
                    failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                    check_name="structural_consistency",
                    reason="completion decision wake_sequence does not match the reviewed packet",
                )
            if decision.generation != packet.generation:
                return AcceptGateResult(
                    passed=False,
                    failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                    check_name="structural_consistency",
                    reason="completion decision generation does not match the reviewed packet",
                )
            passed_checks.append("packet_consistency")

        structural_issue = _accept_structural_issue(decision, code_changing=bool(code_review_files))
        if structural_issue is not None:
            return AcceptGateResult(
                passed=False,
                failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                check_name="structural_consistency",
                reason=structural_issue,
            )
        passed_checks.append("structural_consistency")

        file_issue = _accept_file_review_issue(decision, code_review_files)
        if file_issue is not None:
            return AcceptGateResult(
                passed=False,
                failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                check_name="file_review_coverage",
                reason=file_issue,
            )
        passed_checks.append("file_review_coverage")

        if packet is not None:
            unassessed_test_risks = _changed_test_contract_shift_risks(packet, decision)
            if unassessed_test_risks:
                return AcceptGateResult(
                    passed=False,
                    failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                    check_name="structural_consistency",
                    reason=(
                        "changed tests rewrite existing behavior without changed_test_risks assessment: "
                        + ", ".join(unassessed_test_risks[:5])
                    ),
                )
            passed_checks.append("changed_test_risks_assessment")
            parallel_state_risks = _unassessed_parallel_persistence_risks(packet, decision)
            if parallel_state_risks:
                return AcceptGateResult(
                    passed=False,
                    failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                    check_name="structural_consistency",
                    reason=(
                        "parallel persistence/source-of-truth risk was not explicitly assessed: "
                        + ", ".join(parallel_state_risks[:5])
                    ),
                )
            passed_checks.append("parallel_persistence_assessment")

        latest_change = (
            packet.latest_relevant_change_sequence
            if packet is not None
            else _latest_relevant_change_sequence(changed_files)
        )

        if code_review_files:
            if latest_change is None:
                return AcceptGateResult(
                    passed=False,
                    failure_type=ACCEPT_GATE_CODER_CORRECTABLE,
                    check_name="behavioral_floor",
                    reason="latest relevant source/test change sequence is unknown, so validation freshness is not proven",
                )
            if not any(_validation_is_fresh_behavioral_pass(validation, latest_change) for validation in validations):
                return AcceptGateResult(
                    passed=False,
                    failure_type=ACCEPT_GATE_CODER_CORRECTABLE,
                    check_name="behavioral_floor",
                    reason="no fresh passing behavioral validation after the latest relevant source/test change",
                )
            passed_checks.append("behavioral_floor")

        binding_issue = _accept_evidence_binding_issue(decision, validations, latest_change=latest_change)
        if binding_issue is not None:
            return AcceptGateResult(
                passed=False,
                failure_type=ACCEPT_GATE_CODER_CORRECTABLE,
                check_name="evidence_binding",
                reason=binding_issue,
            )
        passed_checks.append("evidence_binding")

        return AcceptGateResult(passed=True, passed_checks=tuple(passed_checks))

    async def _handle_completion_accept_gate_failure(
        self,
        decision: CompletionReviewDecision,
        gate_result: AcceptGateResult,
    ) -> None:
        reason = gate_result.reason or "accept gate rejected completion accept"
        check_name = gate_result.check_name or "unknown"
        failure_type = gate_result.failure_type or ACCEPT_GATE_CODER_CORRECTABLE
        self._record_accept_gate_failure(gate_result)

        if failure_type == ACCEPT_GATE_REVIEWER_INCOMPLETE:
            reruns = getattr(self, "completion_reviewer_rerun_count", 0)
            if reruns < 1:
                self.completion_reviewer_rerun_count = reruns + 1
                self.store.append_text_locked(
                    PROGRESS,
                    f"- Controller rerunning completion_review: {check_name} failed ({reason})\n",
                )
                self._append_event(
                    AppEventSource.SUPERVISOR,
                    "completion/accept_gate_reviewer_rerun",
                    decision=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                    reason=f"{check_name}: {reason}",
                )
                self._increment_accept_gate_counter("accept_gate_reviewer_reruns")
                self._schedule_supervisor_check(
                    (
                        "Completion-review accept was rejected by the deterministic accept gate "
                        f"because {check_name} failed: {reason}. Rerun completion_review and repair "
                        "the audit output; do not route this reviewer-incomplete issue to the coder."
                    ),
                    completion_review=True,
                )
                return

            audit_reason = f"repeated reviewer-incomplete accept gate failure ({check_name}): {reason}"
            self.store.append_text_locked(PROGRESS, f"- Controller-side audit failure: {audit_reason}\n")
            self._append_event(
                AppEventSource.SUPERVISOR,
                "completion/accept_gate_audit_failure",
                decision=ACCEPT_GATE_AUDIT_FAILURE,
                reason=audit_reason,
            )
            self._increment_accept_gate_counter("accept_gate_audit_failures")
            await self.finalize(
                f"escalated: controller-side audit failure: {audit_reason}",
                status=SentinelStatus.ESCALATED,
            )
            return

        converted = _completion_accept_rejection_decision(decision, reason, check_name=check_name)
        self.store.append_text_locked(
            PROGRESS,
            f"- Controller rejected completion accept: {check_name} failed ({reason})\n",
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "completion/accept_gate_coder_return",
            decision=converted.decision.value,
            reason=f"{check_name}: {reason}",
        )
        self._increment_accept_gate_counter("accept_gate_coder_returns")
        await self._return_completion_to_coder(converted)

    def _record_accept_gate_failure(self, gate_result: AcceptGateResult) -> None:
        self._increment_accept_gate_counter("accept_gate_rejections")
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "completion_accept_gate_rejection",
                "failure_type": gate_result.failure_type,
                "check_name": gate_result.check_name,
                "reason": gate_result.reason,
            }
        )

    def _record_accept_gate_success(self, gate_result: AcceptGateResult) -> None:
        self._increment_accept_gate_counter("accept_gate_accepts")
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "completion_accept_gate_pass",
                "checks": [
                    {"check_name": check_name, "passed": True}
                    for check_name in gate_result.passed_checks
                ],
            }
        )

    def _increment_accept_gate_counter(self, field: str) -> None:
        self.store.update_sentinel_config(
            lambda current: current.model_copy(update={field: getattr(current, field, 0) + 1})
        )

    async def _return_completion_to_coder(self, decision: CompletionReviewDecision) -> None:
        cfg = self.store.get_sentinel_config()
        record = CompletionReturnRecord(
            reason=decision.reason,
            uncovered_behaviors=decision.uncovered_behaviors,
            validation_gaps=decision.validation_gaps,
            claim_evidence_mismatches=decision.claim_evidence_mismatches,
            packet_or_access_limitations=decision.packet_or_access_limitations,
            message_to_coder=decision.message_to_coder,
            sequence=decision.wake_sequence,
            generation=decision.generation,
        )
        self.completion_returns = [*getattr(self, "completion_returns", []), record][-50:]
        self.completion_review_return_sequence = decision.wake_sequence
        validation_sequences = [validation.sequence for validation in self.validations]
        self.completion_review_return_validation_sequence = max(validation_sequences) if validation_sequences else None
        if not decision.progress_update:
            details = _completion_return_summary(decision)
            self.store.append_text_locked(PROGRESS, f"- Completion review returned: {details}\n")
        self.prior_interventions.append(
            PriorIntervention(
                reason=f"Completion review returned: {decision.reason}",
                message_to_coder=decision.message_to_coder or "",
                sequence=decision.wake_sequence,
            )
        )
        self.prior_interventions = self.prior_interventions[-20:]
        returns_this_generation = _completion_returns_this_generation(self, cfg.generation)
        health_delta = HealthDelta(generation=cfg.generation, interventions=1)
        if returns_this_generation >= cfg.max_completion_returns_per_generation:
            health_delta.add_risk_signals.append("completion_non_convergence")
        patch_health(self.store, health_delta)
        if returns_this_generation > cfg.max_completion_returns_per_generation:
            if cfg.restart_count < cfg.max_restarts:
                handoff = _fallback_restart_handoff(
                    task_contents=self.task_path.read_text(encoding="utf-8") if self.task_path.exists() else cfg.task_path,
                    reason="completion return cap reached",
                    last_actions=self.store.read_recent_actions(10),
                )
                self.completion_restarts = getattr(self, "completion_restarts", 0) + 1
                await self.restart("completion return cap reached", handoff=handoff)
                return
            await self.finalize(
                "escalated: completion return cap reached and restart cap exhausted",
                status=SentinelStatus.ESCALATED,
            )
            return
        if self.coder and decision.message_to_coder:
            await self.coder.steer_or_start(decision.message_to_coder)

    async def _resolve_pending_approvals(self, reason: str) -> None:
        approvals = getattr(self, "approvals", None)
        if approvals is None:
            manager = ApprovalManager(self.project_root)
        else:
            manager = approvals
        for request_id, context in list(self.pending_approvals.items()):
            resolution = manager._deny(context, reason)
            await self.client.respond(request_id, manager.response_payload(context, resolution))
            self.pending_approvals.pop(request_id, None)
        self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"pending_server_request_ids": []}))

    async def _stop_supervisor_task(self) -> None:
        task = self._supervisor_task
        if task is None or task.done():
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def diff_summary(self) -> str:
        if not self.use_git_diff:
            return ""
        if not await self._is_git_work_tree():
            return ""
        commands = [["git", "status", "--short"], ["git", "diff", "--stat"], ["git", "diff", "--name-only"]]
        parts: list[str] = []
        for command in commands:
            output = await self._git_output(command)
            if output is not None:
                parts.append(f"$ {' '.join(command)}\n{output}")
        return "\n\n".join(parts)

    async def changed_files(self) -> list[ChangedFile]:
        if not self.use_git_diff:
            return _observed_changed_files(self)
        if not await self._is_git_work_tree():
            return _observed_changed_files(self)
        status_text = await self._git_output(["git", "status", "--short"])
        numstat_text = await self._git_output(["git", "diff", "--numstat", "HEAD", "--"])
        if status_text is None and numstat_text is None:
            return []
        files: dict[str, ChangedFile] = {}
        for line in (status_text or "").splitlines():
            if not line.strip():
                continue
            status = line[:2].strip() or "modified"
            path = _path_from_git_status_line(line)
            if " -> " in path:
                path = path.rsplit(" -> ", 1)[1].strip()
            if path:
                files[path] = ChangedFile(path=path, status=status)
        for line in (numstat_text or "").splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            additions = _parse_numstat(parts[0])
            deletions = _parse_numstat(parts[1])
            path = parts[2].strip()
            if " => " in path:
                path = path.rsplit(" => ", 1)[1].strip("{}")
            if not path:
                continue
            existing = files.get(path)
            status = existing.status if existing else "modified"
            files[path] = ChangedFile(path=path, status=status, additions=additions, deletions=deletions)
        observed = getattr(self, "observed_changed_files", None)
        if isinstance(observed, dict):
            for path, observed_file in observed.items():
                if path in files:
                    files[path].sequence = observed_file.sequence
        return list(files.values())[:200]

    def _record_changed_files(self, action: TriggeringAction) -> None:
        if not action.paths:
            return
        observed = getattr(self, "observed_changed_files", None)
        if observed is None:
            observed = {}
            self.observed_changed_files = observed
        for raw_path in action.paths:
            path = _workspace_display_path(self.project_root, raw_path)
            if path and not path.startswith(".supervisor/"):
                observed[path] = ChangedFile(path=path, status="modified", sequence=getattr(self, "_sequence", None))

    async def _is_git_work_tree(self) -> bool:
        output = await self._git_output(["git", "rev-parse", "--is-inside-work-tree"])
        return output == "true"

    async def _git_output(self, command: list[str]) -> str | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(self.project_root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            if proc.returncode != 0:
                return None
            return stdout.decode("utf-8", errors="replace").strip()
        except Exception:
            return None

    async def patch_summary(self, limit: int = 4000) -> str | None:
        if not self.use_git_diff:
            return None
        parts: list[str] = []
        for command in (["git", "diff", "--unified=2", "--"], ["git", "diff", "--cached", "--unified=2", "--"]):
            output = await self._git_output(command)
            if output:
                parts.append(f"$ {' '.join(command)}\n{output}")
        if not parts:
            return None
        return _bounded_text("\n\n".join(parts), limit=limit)

    async def completion_packet_details(
        self,
        changed_files: list[ChangedFile],
        *,
        since_sequence: int | None = None,
    ) -> dict[str, Any]:
        diff_limit = 12000
        context_limit = 8000
        changed_file_diffs: list[ChangedFileDiff] = []
        changed_file_contexts: list[ChangedFileContext] = []
        changed_tests_summary: list[ChangedTestsSummary] = []
        omitted: list[str] = []
        total_diff_chars = 0
        total_context_chars = 0
        materially_truncated = False
        truncation_reasons: list[str] = []
        is_git = self.use_git_diff and await self._is_git_work_tree()
        detail_changed_files = [
            changed
            for changed in changed_files
            if since_sequence is None or changed.sequence is None or changed.sequence > since_sequence
        ]
        detail_validations = [
            validation for validation in self.validations if since_sequence is None or validation.sequence > since_sequence
        ]

        for changed in detail_changed_files[:200]:
            file_kind = _file_kind(changed.path)
            change_kind = _change_kind(changed.status)
            diff_text = ""
            omitted_reason: str | None = None
            if is_git:
                diff_text = await self._changed_file_diff(changed.path)
            if not diff_text and change_kind == "added":
                file_text = _read_workspace_file(self.project_root, changed.path, limit=diff_limit)
                if file_text is not None:
                    diff_text = f"<new file snapshot>\n{file_text.text}"
            if not diff_text:
                omitted_reason = "No git diff or readable file snapshot was available for this changed file."
                omitted.append(changed.path)
                materially_truncated = True
            bounded_diff = _bounded_text(diff_text, limit=diff_limit) if diff_text else ""
            diff_truncated = bool(diff_text) and len(diff_text) > len(bounded_diff)
            if diff_truncated:
                materially_truncated = True
                truncation_reasons.append(f"{changed.path}: diff exceeded {diff_limit} characters")
            total_diff_chars += len(bounded_diff)
            changed_file_diffs.append(
                ChangedFileDiff(
                    path=changed.path,
                    file_kind=file_kind,
                    change_kind=change_kind,
                    diff=bounded_diff,
                    diff_truncated=diff_truncated,
                    omitted_reason=omitted_reason,
                )
            )

            if change_kind == "deleted":
                continue
            context = _read_workspace_file(self.project_root, changed.path, limit=context_limit)
            if context is None:
                continue
            total_context_chars += len(context.text)
            if context.truncated:
                materially_truncated = True
                truncation_reasons.append(f"{changed.path}: final file context exceeded {context_limit} characters")
            changed_file_contexts.append(
                ChangedFileContext(
                    path=changed.path,
                    final_snippets_around_changed_hunks=context.text,
                    context_truncated=context.truncated,
                )
            )
            if file_kind == "test":
                changed_tests_summary.append(_changed_tests_summary(changed.path, context.text, detail_validations))

        return {
            "changed_file_diffs": changed_file_diffs,
            "changed_file_contexts": changed_file_contexts,
            "changed_tests_summary": changed_tests_summary,
            "validation_outputs": [_validation_output(validation) for validation in detail_validations],
            "diff_packet_limits": DiffPacketLimits(
                total_diff_chars=total_diff_chars,
                total_context_chars=total_context_chars,
                omitted_changed_files=omitted,
                materially_truncated=materially_truncated,
                truncation_reason="; ".join(truncation_reasons) if truncation_reasons else None,
            ),
        }

    async def _changed_file_diff(self, path: str) -> str:
        parts: list[str] = []
        for command in (
            ["git", "diff", "--unified=80", "--", path],
            ["git", "diff", "--cached", "--unified=80", "--", path],
        ):
            output = await self._git_output(command)
            if output:
                parts.append(f"$ {' '.join(command)}\n{output}")
        return "\n\n".join(parts)

    async def _on_notification(self, message: AppServerMessage) -> None:
        await self.event_queue.put(ControllerEvent(kind="notification", message=message))

    async def _on_server_request(self, message: AppServerMessage) -> None:
        await self.event_queue.put(ControllerEvent(kind="server_request", message=message))

    async def _on_transport_error(self, error: BaseException) -> None:
        await self.event_queue.put(ControllerEvent(kind="transport_error", error=error, error_message=str(error)))

    def _append_cleanup_error(
        self,
        *,
        cleanup_kind: str,
        thread_id: str,
        turn_id: str | None,
        error: BaseException,
    ) -> None:
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "cleanup_error",
                "cleanup_kind": cleanup_kind,
                "thread_id": thread_id,
                "turn_id": turn_id,
                "error_type": error.__class__.__name__,
                "error": str(error),
            }
        )

    def _append_event(
        self,
        source: AppEventSource,
        event_type: str,
        *,
        thread_id: Any = None,
        turn_id: Any = None,
        item_id: Any = None,
        decision: Any = None,
        reason: str | None = None,
    ) -> None:
        self._sequence += 1
        cfg = self.store.get_sentinel_config()
        event = AppEvent(
            sequence=self._sequence,
            generation=cfg.generation,
            source=source,
            event_type=event_type,
            thread_id=thread_id if isinstance(thread_id, str) else None,
            turn_id=turn_id if isinstance(turn_id, str) else None,
            item_id=item_id if isinstance(item_id, str) else None,
            decision=decision,
            reason=reason,
        )
        self.store.append_event(event)
        self.store.update_sentinel_config(lambda current: current.model_copy(update={"last_event_sequence": self._sequence}))

    def _generate_schema_hash(self) -> str:
        if shutil.which("codex") is None:
            raise RuntimeError("codex executable not found")
        with tempfile.TemporaryDirectory(prefix="sentinel-appserver-schema-") as tmp_dir:
            out_dir = Path(tmp_dir)
            completed = subprocess.run(
                ["codex", "app-server", "generate-json-schema", "--experimental", "--out", str(out_dir)],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError((completed.stdout + completed.stderr).strip() or "app-server schema generation failed")
            required = ["ClientRequest.json", "ServerRequest.json", "TurnStartParams.json", "CommandExecutionRequestApprovalParams.json"]
            for rel in required:
                if not _schema_file_exists(out_dir, rel):
                    raise RuntimeError(f"app-server schema missing required file: {rel}")
            digest = hashlib.sha256()
            for path in sorted(out_dir.rglob("*.json")):
                digest.update(str(path.relative_to(out_dir)).encode("utf-8"))
                digest.update(path.read_bytes())
            return digest.hexdigest()

    async def _generate_schema_hash_async(self) -> str:
        return await asyncio.to_thread(self._generate_schema_hash)

    async def _structured_output_self_test(self) -> None:
        agent = StatelessSupervisorAgent(
            self.client,
            self.store,
            self.task_path,
            model=self.model,
        )
        cfg = self.store.get_sentinel_config()
        packet = SupervisorWakePacket(
            wake_sequence=1,
            latest_event_sequence=cfg.last_event_sequence,
            generation=cfg.generation,
            restart_count=cfg.restart_count,
            task_path=str(self.task_path),
            task_contents="Structured output self-test. Return noop.",
            progress="",
            decisions="",
            last_actions=[],
            health=self.store.get_health().model_dump(mode="json"),
            recent_events=[],
            current_summary="Startup structured-output self-test. Return decision noop.",
            coder_thread_id=None,
            active_coder_turn_id=None,
        )
        decision = await asyncio.wait_for(agent.decide(packet), timeout=120)
        if decision.decision not in {SupervisorDecisionKind.NOOP, SupervisorDecisionKind.PAUSE}:
            raise RuntimeError("structured-output supervisor self-test returned an unexpected decision")


def _approval_wake_context(context: ApprovalContext, reason: str | None = None) -> ApprovalWakeContext:
    return ApprovalWakeContext(
        request_type=context.request_type.value,
        server_request_id=context.server_request_id,
        method=context.server_request_method,
        available_decisions=context.available_decisions,
        command=context.command,
        file_changes=context.file_changes,
        paths=context.paths,
        cwd=context.cwd,
        grant_root=context.grant_root,
        network_approval_context=context.network_approval_context,
        proposed_execpolicy_amendment=context.proposed_execpolicy_amendment,
        proposed_network_policy_amendments=context.proposed_network_policy_amendments,
        reason=reason,
    )


def _fallback_restart_handoff(*, task_contents: str, reason: str, last_actions: list[str]) -> RestartHandoff:
    objective = " ".join(task_contents.strip().split())[:1000] or "Continue the selected task."
    known_evidence = "; ".join(last_actions[-5:]) or "No completed coder actions are recorded."
    return RestartHandoff(
        objective=objective,
        restart_reason=reason,
        bad_pattern="The previous generation was interrupted or judged unreliable before completing the task.",
        known_evidence=known_evidence,
        next_step="Read the task, progress, decisions, and this handoff, then take the next concrete task step.",
        recovery_signal="The new generation makes task-relevant progress without repeating the prior failure mode.",
    )


def _triggering_action_from_item(item: Any, *, item_id: str | None, summary: str) -> TriggeringAction:
    if not isinstance(item, dict):
        return TriggeringAction(item_id=item_id, kind="item", status="completed", summary=summary)
    kind = str(item.get("type") or "item")
    exit_code = item.get("exitCode")
    return TriggeringAction(
        item_id=item_id,
        kind=kind,
        command=item.get("command") if isinstance(item.get("command"), str) else None,
        cwd=item.get("cwd") if isinstance(item.get("cwd"), str) else None,
        paths=_paths_from_item(item),
        exit_code=exit_code if isinstance(exit_code, int) else None,
        status=item.get("status") if isinstance(item.get("status"), str) else "completed",
        summary=summary,
    )


def _validation_from_action(
    action: TriggeringAction,
    *,
    sequence: int,
    item: Any = None,
    changed_paths: list[str] | None = None,
) -> ValidationRun | None:
    if action.kind != "commandExecution" or not action.command:
        return None
    validation_type = _classify_validation_command(action.command, changed_paths=changed_paths or [])
    if validation_type is None:
        return None
    output = _command_output_from_item(item)
    normalized_command = _normalize_command(action.command)
    raw_selector = _raw_validation_selector(action.command)
    executed_test_names = _executed_test_names(action.command, output)
    outcome = "pass" if action.exit_code == 0 else "fail"
    if validation_type == "behavioral" and outcome == "pass" and not _tests_executed(action.command, output):
        outcome = "fail"
    masking_reason = _validation_masking_reason(action.command)
    trusted_outcome = "passed" if outcome == "pass" else "failed"
    passed = outcome == "pass"
    if masking_reason is not None:
        trusted_outcome = "masked_or_unknown"
        outcome = "fail"
        passed = False
    passed_count, failed_count = _test_count_summary(output)
    summary = _validation_summary(action.summary, output)
    return ValidationRun(
        validation_id=_stable_validation_id(
            normalized_command=normalized_command,
            cwd=action.cwd,
            validation_type=validation_type,
            raw_selector=raw_selector,
            executed_test_names=executed_test_names,
        ),
        command=action.command,
        raw_command=action.command,
        normalized_command=normalized_command,
        cwd=action.cwd,
        exit_code=action.exit_code,
        shell_exit_code=action.exit_code,
        type=validation_type,
        outcome=outcome,
        passed=passed,
        trusted_validation_outcome=trusted_outcome,
        masking_reason=masking_reason,
        summary=summary,
        sequence=sequence,
        was_filtered=_command_was_filtered(action.command),
        raw_selector=raw_selector,
        executed_test_names=executed_test_names,
        passed_count=passed_count,
        failed_count=failed_count,
        target_files_or_test_files=_target_files_or_test_files(action.command),
    )


def _classify_validation_command(command: str, *, changed_paths: list[str]) -> str | None:
    if _is_static_validation_command(command):
        return "static"
    if (
        _is_behavioral_validation_command(command)
        or _is_direct_script_execution_command(command)
        or _command_requires_changed_module(command, changed_paths)
    ):
        return "behavioral"
    return None


def _is_static_validation_command(command: str) -> bool:
    lowered = command.lower()
    executable_prefix = r"(^|[\s;&|()'\"])(?:npx\s+|(?:\.{0,2}/|/)?(?:[\w.-]+/)*)"
    patterns = (
        r"(^|[\s;&|()'\"])(node|nodejs)\s+-c(\s|$)",
        r"(^|[\s;&|()'\"])(node|nodejs)\s+--check(\s|$)",
        r"(^|[\s;&|()'\"])git\s+diff\s+--check(\s|$)",
        executable_prefix + r"eslint(\s|$)",
        r"(^|[\s;&|()'\"])(npm|pnpm|yarn)\s+(run\s+)?lint(\s|$|:)",
        r"(^|[\s;&|()'\"])(npm|pnpm|yarn)\s+(run\s+)?type-?check(\s|$|:)",
        executable_prefix + r"prettier\s+--check(\s|$)",
        executable_prefix + r"tsc(?:\s+[^;&|()]*)?\s+--noemit(\s|$)",
        r"(^|[\s;&|()'\"])(python|python3)\s+-m\s+(py_compile|compileall)(\s|$)",
        r"(^|[\s;&|()'\"])(python|python3)\s+-m\s+json\.tool(\s|$)",
        r"(^|[\s;&|()'\"])jq\s+['\"]?\.['\"]?(\s|$)",
        r"json\.parse\s*\(",
    )
    return any(re.search(pattern, lowered) for pattern in patterns)


def _is_behavioral_validation_command(command: str) -> bool:
    lowered = command.lower()
    executable_prefix = r"(^|[\s;&|()'\"])(?:npx\s+|(?:\.{0,2}/|/)?(?:[\w.-]+/)*)"
    python_flags = r"(?:\s+-(?!m(?:\s|$))[a-z][\w-]*(?:=[^\s;&|()'\"]+)?)"
    patterns = (
        executable_prefix + r"mocha(\s|$)",
        r"(^|[\s;&|()'\"])(npm|pnpm|yarn)\s+(run\s+)?test(\s|$|:)",
        r"(^|[\s;&|()'\"])(node|nodejs)\s+--test(\s|$)",
        r"(^|[\s;&|()'\"])(python|python3)" + python_flags + r"*\s+-m\s+(pytest|unittest|tox|nose2?)($|[\s;&|()'\"])",
        executable_prefix + r"(jest|ava|tap|vitest|playwright|cypress|pytest|tox|rspec)(\s|$)",
        r"(^|[\s;&|()'\"])(go|cargo|mvn|gradle|swift|dotnet|make)\s+test(\s|$)",
    )
    return any(re.search(pattern, lowered) for pattern in patterns)


def _is_direct_script_execution_command(command: str) -> bool:
    lowered = command.lower()
    boundary = r"(?=$|[\s;&|()'\"])"
    python_flags = r"(?:\s+-(?!m(?:\s|$))[a-z][\w-]*(?:=[^\s;&|()'\"]+)?)"
    patterns = (
        r"(^|[\s;&|()'\"])(python|python3)" + python_flags + r"*\s+(?!-)[\w./-]+\.py" + boundary,
        r"(^|[\s;&|()'\"])(node|nodejs|ruby|bash|sh)\s+(?!-)[\w./-]+\.(js|mjs|cjs|rb|sh)" + boundary,
    )
    return any(re.search(pattern, lowered) for pattern in patterns)


def _command_requires_changed_module(command: str, changed_paths: list[str]) -> bool:
    lowered = command.lower()
    if not re.search(r"(^|[\s;&|()'\"])(node|nodejs|python|python3|ruby)\s+(-e|-c|\S+)", lowered):
        return False
    if not re.search(r"\b(require|import|node|nodejs|python|python3|ruby)\b", lowered):
        return False
    normalized_command = lowered.replace("\\", "/")
    for raw_path in changed_paths:
        path = raw_path.replace("\\", "/").lstrip("./").lower()
        if not path or path.startswith(".supervisor/"):
            continue
        candidates = {path}
        if path.endswith((".js", ".ts", ".jsx", ".tsx", ".py", ".rb")):
            candidates.add(path.rsplit(".", 1)[0])
        if any(candidate and candidate in normalized_command for candidate in candidates):
            return True
    return False


def _tests_executed(command: str, output: str) -> bool:
    if not _is_behavioral_validation_command(command):
        return True
    lowered = output.lower()
    zero_test_patterns = (
        r"\b0\s+(passing|failing|pending|tests?|specs?)\b",
        r"\b0\s+tests?\s+(run|executed|passed|failed|total)\b",
        r"\btests?:\s+0\s+total\b",
        r"\btest suites?:\s+0\b",
        r"\bran\s+0\s+tests?\b",
        r"\bno tests?\s+(found|run|executed)\b",
    )
    return not any(re.search(pattern, lowered) for pattern in zero_test_patterns)


def _command_output_from_item(item: Any, *, limit: int = 20000) -> str:
    if not isinstance(item, dict):
        return ""
    parts: list[str] = []
    _collect_output_strings(item, parts, depth=0)
    return _bounded_text("\n".join(parts), limit=limit)


def _item_with_recorded_output(item: Any, output: str) -> Any:
    if not output or not isinstance(item, dict):
        return item
    existing = _command_output_from_item(item)
    merged = output if not existing else f"{existing}\n{output}"
    enriched = dict(item)
    enriched["output"] = merged
    return enriched


def _output_delta_text(params: dict[str, Any], *, limit: int = 20000) -> str:
    parts: list[str] = []
    _collect_output_delta_strings(params, parts, depth=0)
    return _bounded_text("".join(parts), limit=limit)


def _collect_output_delta_strings(value: Any, parts: list[str], *, depth: int) -> None:
    if depth > 5:
        return
    if isinstance(value, str):
        if value:
            parts.append(value)
        return
    if isinstance(value, list):
        for item in value:
            _collect_output_delta_strings(item, parts, depth=depth + 1)
        return
    if not isinstance(value, dict):
        return
    for key, nested in value.items():
        key_text = str(key).lower()
        if key_text in {"delta", "output", "stdout", "stderr", "text", "content", "message", "chunk", "data"}:
            _collect_output_delta_strings(nested, parts, depth=depth + 1)
        elif key_text in {"outputs", "chunks", "lines", "items"}:
            _collect_output_delta_strings(nested, parts, depth=depth + 1)


def _validation_summary(summary: str, output: str, *, limit: int = 4000) -> str:
    stripped = output.strip()
    if not stripped:
        return summary
    if stripped in summary:
        return summary
    return _bounded_text(f"{summary}\nOutput:\n{stripped}", limit=limit)


def _validation_id(sequence: int) -> str:
    return f"validation-{sequence}"


def _normalize_command(command: str) -> str:
    return " ".join(command.strip().split())


def _stable_validation_id(
    *,
    normalized_command: str,
    cwd: str | None,
    validation_type: str,
    raw_selector: str | None,
    executed_test_names: list[str],
) -> str:
    payload = {
        "normalized_command": normalized_command,
        "cwd": cwd or "",
        "validation_type": validation_type,
        "raw_selector": raw_selector or "",
        "executed_test_names": sorted(dict.fromkeys(executed_test_names)),
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    return f"validation-{digest[:16]}"


def _validation_masking_reason(command: str) -> str | None:
    lowered = command.lower()
    pipeline_probe = lowered.replace("||", "")
    if "|" in pipeline_probe and "pipefail" not in lowered:
        return "pipeline_without_pipefail"
    if "$(" in command or "`" in command:
        return "command_substitution_may_mask_failure"
    if "||" in lowered and not re.search(r"\|\|\s*exit\s+1(\s|$)", lowered):
        return "logical_or_may_mask_validation_failure"
    if ";" in lowered:
        return "command_separator_may_mask_validation_failure"
    return None


def _command_was_filtered(command: str) -> bool:
    return _raw_validation_selector(command) is not None


def _raw_validation_selector(command: str) -> str | None:
    selectors: list[str] = []
    patterns = (
        r"(?:^|\s)(-k)\s+([^\s;&|]+)",
        r"(?:^|\s)(-m)\s+([^\s;&|]+)",
        r"(?:^|\s)(--grep|--testNamePattern|--test-name-pattern|--filter|--test)\s+([^\s;&|]+)",
        r"(?:^|\s)(-g)\s+([^\s;&|]+)",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, command):
            if match.group(1) == "-m" and _is_python_module_flag(command, match.start(1)):
                continue
            selector = match.group(2).strip("\"'")
            selectors.append(f"{match.group(1)} {selector}")
    for target in _explicit_test_selectors(command):
        selectors.append(target)
    return "; ".join(dict.fromkeys(selectors)) or None


def _is_python_module_flag(command: str, start: int) -> bool:
    prefix = command[:start].rstrip().lower()
    python_flags = r"(?:\s+-(?!m(?:\s|$))[a-z][\w-]*(?:=[^\s;&|()'\"]+)?)"
    pattern = r"(^|[\s;&|()'\"])(python|python3)" + python_flags + r"*$"
    return bool(re.search(pattern, prefix))


def _explicit_test_selectors(command: str, *, limit: int = 50) -> list[str]:
    selectors: list[str] = []
    for match in re.finditer(
        r"(?<![\w./-])(?:\.?/)?[\w./-]+\.(?:py|js|jsx|ts|tsx|mjs|cjs|rb|go|rs|java|cs|php)(?:::[\w.*\[\]-]+)+",
        command,
    ):
        selectors.append(match.group(0).strip("'\"").lstrip("./"))
        if len(selectors) >= limit:
            break
    return list(dict.fromkeys(selectors))


def _executed_test_names(command: str, output: str, *, limit: int = 50) -> list[str]:
    names: list[str] = []
    names.extend(_explicit_test_selectors(command, limit=limit))
    names.extend(_test_names_from_output(output, limit=limit))
    if not names and _is_behavioral_validation_command(command):
        names.extend(_target_files_or_test_files(command))
    return list(dict.fromkeys(names))[:limit]


def _test_names_from_output(output: str, *, limit: int = 50) -> list[str]:
    names: list[str] = []
    patterns = (
        r"(?m)\b([\w./+\[\]-]+::test_[\w.\[\]-]+)\b",
        r"(?m)\b(test_[A-Za-z0-9_]+)\s+(?:PASSED|FAILED|SKIPPED|XFAIL|XPASS)\b",
        r"(?m)\b(?:✓|PASS|FAIL)\s+([^()\n]{3,160})",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, output):
            name = " ".join(match.group(1).strip().split())
            if name:
                names.append(name)
            if len(names) >= limit:
                return list(dict.fromkeys(names))
    return list(dict.fromkeys(names))


def _test_count_summary(output: str) -> tuple[int | None, int | None]:
    lowered = output.lower()
    passed = _first_int_match(
        lowered,
        (
            r"\b(\d+)\s+passed\b",
            r"\b(\d+)\s+passing\b",
            r"\bpasses:\s*(\d+)\b",
            r"\btests?:\s*(\d+)\s+passed\b",
        ),
    )
    failed = _first_int_match(
        lowered,
        (
            r"\b(\d+)\s+failed\b",
            r"\b(\d+)\s+failing\b",
            r"\bfailures?:\s*(\d+)\b",
            r"\btests?:\s*\d+\s+passed,\s*(\d+)\s+failed\b",
        ),
    )
    if passed is not None and failed is None:
        failed = 0
    return passed, failed


def _first_int_match(text: str, patterns: tuple[str, ...]) -> int | None:
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return int(match.group(1))
    return None


def _collect_output_strings(value: Any, parts: list[str], *, depth: int) -> None:
    if depth > 4:
        return
    if isinstance(value, str):
        if value.strip():
            parts.append(value)
        return
    if isinstance(value, list):
        for item in value:
            _collect_output_strings(item, parts, depth=depth + 1)
        return
    if not isinstance(value, dict):
        return
    for key, nested in value.items():
        key_text = str(key).lower()
        if key_text in {"output", "stdout", "stderr", "text", "content", "message", "summary"}:
            _collect_output_strings(nested, parts, depth=depth + 1)
        elif key_text in {"outputs", "chunks", "lines", "items"}:
            _collect_output_strings(nested, parts, depth=depth + 1)


def _has_passing_behavioral_validation(validations: list[ValidationRun]) -> bool:
    return any(
        validation.type == "behavioral"
        and validation.outcome == "pass"
        and validation.passed
        and validation.trusted_validation_outcome == "passed"
        for validation in validations
    )


def _has_readiness_marker(text: str) -> bool:
    return bool(READINESS_MARKER_RE.search(text.strip()))


def _has_malformed_readiness_marker(text: str) -> bool:
    if _has_readiness_marker(text):
        return False
    lowered = text.lower()
    compact = re.sub(r"[\s_\-]+", "_", lowered)
    return any(
        marker in lowered or marker in compact
        for marker in (
            "sentinel ready for review",
            "sentinel_ready",
            "sentinel_ready_for_review",
            "ready_for_review",
        )
    )


def _appears_to_claim_readiness(text: str) -> bool:
    lowered = " ".join(text.lower().split())
    phrases = (
        "done",
        "complete",
        "completed",
        "finished",
        "implemented",
        "all tests pass",
        "all tests passed",
        "ready for review",
        "task is complete",
        "validation:",
    )
    return any(phrase in lowered for phrase in phrases)


def _completion_returns_this_generation(controller: Any, generation: int) -> int:
    return sum(
        1
        for record in getattr(controller, "completion_returns", []) or []
        if getattr(record, "generation", None) == generation
    )


def _latest_relevant_change_sequence(changed_files: list[ChangedFile]) -> int | None:
    sequences = [
        file.sequence
        for file in changed_files
        if file.sequence is not None and _is_relevant_changed_path(file.path, task_contents="")
    ]
    return max(sequences) if sequences else None


def _validation_freshness_summary(
    *,
    validations: list[ValidationRun],
    changed_files: list[ChangedFile],
) -> str:
    latest_change = _latest_relevant_change_sequence(changed_files)
    passing_behavioral = [
        validation.sequence
        for validation in validations
        if validation.type == "behavioral"
        and validation.outcome == "pass"
        and validation.passed
        and validation.trusted_validation_outcome == "passed"
    ]
    last_behavioral = max(passing_behavioral) if passing_behavioral else None
    if last_behavioral is None:
        if latest_change is None:
            return "No passing behavioral validation recorded; latest relevant change sequence is unknown."
        return f"No passing behavioral validation recorded after latest relevant change sequence {latest_change}."
    if latest_change is None:
        return (
            f"Last passing behavioral validation sequence {last_behavioral}; "
            "latest relevant change sequence is unknown."
        )
    freshness = "fresh" if last_behavioral >= latest_change else "stale"
    return (
        f"Last passing behavioral validation sequence {last_behavioral}; "
        f"latest relevant change sequence {latest_change}; behavioral validation is {freshness}."
    )


def _material_code_review_files(changed_files: list[ChangedFile]) -> list[ChangedFile]:
    return [
        file
        for file in changed_files
        if _file_kind(file.path) in {"source", "test"} and not _is_non_material_changed_path(file.path)
    ]


def _is_non_material_changed_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower().strip("/")
    parts = set(normalized.split("/"))
    if parts & {
        "node_modules",
        "vendor",
        "dist",
        "build",
        "target",
        "coverage",
        "__generated__",
        "generated",
        ".next",
        ".cache",
    }:
        return True
    name = normalized.rsplit("/", 1)[-1]
    return name.endswith((".min.js", ".lock"))


def _accept_structural_issue(decision: CompletionReviewDecision, *, code_changing: bool) -> str | None:
    if not decision.behavior_evidence_matrix:
        suffix = " for a code-changing task" if code_changing else ""
        return f"behavior_evidence_matrix is empty{suffix}"
    incomplete_rows = [
        row.behavior or "<unnamed behavior>"
        for row in decision.behavior_evidence_matrix
        if row.status != "covered"
    ]
    if incomplete_rows:
        return f"behavior_evidence_matrix has non-covered rows: {', '.join(incomplete_rows[:5])}"
    missing_row_fields = [
        row.behavior or "<unnamed behavior>"
        for row in decision.behavior_evidence_matrix
        if not row.behavior.strip() or not row.task_basis.strip()
    ]
    if missing_row_fields:
        return f"behavior_evidence_matrix has rows with missing required text fields: {', '.join(missing_row_fields[:5])}"
    covered_rows_with_gap = [row.behavior for row in decision.behavior_evidence_matrix if row.gap]
    if covered_rows_with_gap:
        return f"covered behavior rows still set gap: {', '.join(covered_rows_with_gap[:5])}"
    empty_evidence_fields = [
        row.behavior
        for row in decision.behavior_evidence_matrix
        for evidence in row.evidence
        if not evidence.command.strip() or not evidence.why_it_covers_behavior.strip()
    ]
    if empty_evidence_fields:
        return f"behavior_evidence_matrix has evidence with missing required text fields: {', '.join(empty_evidence_fields[:5])}"
    if decision.uncovered_behaviors:
        return f"uncovered_behaviors is not empty: {', '.join(decision.uncovered_behaviors[:5])}"
    if decision.validation_gaps:
        return f"validation_gaps is not empty: {', '.join(decision.validation_gaps[:5])}"
    material_limitations = _material_findings(decision.packet_or_access_limitations)
    if material_limitations:
        return f"material packet/access limitations remain: {', '.join(material_limitations[:5])}"
    material_mismatches = _material_findings(decision.claim_evidence_mismatches)
    if material_mismatches:
        return f"claim/evidence mismatches remain: {', '.join(material_mismatches[:5])}"
    material_test_risks = _material_findings(decision.changed_test_risks)
    if material_test_risks:
        return f"changed test risks remain: {', '.join(material_test_risks[:5])}"
    return None


def _accept_file_review_issue(decision: CompletionReviewDecision, files: list[ChangedFile]) -> str | None:
    reviewed_by_path = {_normalize_review_path(file.path): file for file in decision.files_reviewed}
    missing: list[str] = []
    for changed in files:
        reviewed = reviewed_by_path.get(_normalize_review_path(changed.path))
        if reviewed is None:
            missing.append(changed.path)
            continue
        if reviewed.inspected or _review_marks_non_material(reviewed):
            continue
        missing.append(changed.path)
    if missing:
        return f"changed source/test files were not reviewed: {', '.join(missing[:8])}"
    return None


def _review_marks_non_material(file: Any) -> bool:
    text = " ".join(
        str(value or "")
        for value in (
            getattr(file, "reason", None),
            getattr(file, "limitation", None),
        )
    ).lower()
    return any(marker in text for marker in ("non-material", "not material", "immaterial"))


def _validation_is_fresh_behavioral_pass(validation: ValidationRun, latest_change: int) -> bool:
    return (
        validation.type == "behavioral"
        and validation.outcome == "pass"
        and validation.passed
        and validation.trusted_validation_outcome == "passed"
        and validation.sequence > latest_change
    )


def _validation_is_fresh_pass(validation: ValidationRun, latest_change: int | None) -> bool:
    if validation.outcome != "pass" or not validation.passed or validation.trusted_validation_outcome != "passed":
        return False
    if latest_change is None:
        return True
    return validation.sequence > latest_change


def _accept_evidence_binding_issue(
    decision: CompletionReviewDecision,
    validations: list[ValidationRun],
    *,
    latest_change: int | None,
) -> str | None:
    by_id = {validation.validation_id: validation for validation in validations}
    for row in decision.behavior_evidence_matrix:
        if row.status != "covered":
            continue
        fresh_pass_found = False
        linked_evidence_found = False
        for evidence in row.evidence:
            if not evidence.validation_id:
                continue
            linked_evidence_found = True
            validation = by_id.get(evidence.validation_id or "")
            if validation is None:
                continue
            if evidence.validation_type != validation.type:
                continue
            if _validation_is_fresh_pass(validation, latest_change):
                fresh_pass_found = True
                break
        if not fresh_pass_found:
            if not linked_evidence_found:
                return f"behavior '{row.behavior}' is covered but has no evidence linked by validation_id"
            type_mismatch = _evidence_type_mismatch(row.evidence, by_id)
            if type_mismatch:
                return f"behavior '{row.behavior}' evidence type mismatch: {type_mismatch}"
            return (
                f"behavior '{row.behavior}' is covered but has no linked fresh passing validation "
                "record in the ledger"
            )
    return None


def _evidence_type_mismatch(evidence_items: list[Any], validations_by_id: dict[str, ValidationRun]) -> str | None:
    for evidence in evidence_items:
        if not evidence.validation_id:
            continue
        validation = validations_by_id.get(evidence.validation_id)
        if validation is None or evidence.validation_type == validation.type:
            continue
        return (
            f"{evidence.validation_id} declares {evidence.validation_type} "
            f"but ledger has {validation.type}"
        )
    return None


def _completion_accept_rejection_decision(
    decision: CompletionReviewDecision,
    reason: str,
    *,
    check_name: str = "accept_gate",
) -> CompletionReviewDecision:
    validation_gaps = list(decision.validation_gaps)
    validation_gaps.append(f"Controller accept-gate rejection ({check_name}): {reason}")
    return CompletionReviewDecision(
        decision=CompletionReviewDecisionKind.RETURN,
        reason=f"controller accept-gate rejection ({check_name}): {reason}",
        files_reviewed=decision.files_reviewed,
        behavior_evidence_matrix=decision.behavior_evidence_matrix,
        uncovered_behaviors=decision.uncovered_behaviors,
        validation_gaps=validation_gaps,
        claim_evidence_mismatches=decision.claim_evidence_mismatches,
        packet_or_access_limitations=decision.packet_or_access_limitations,
        changed_test_risks=decision.changed_test_risks,
        message_to_coder=(
            "Continue working. Completion accept was rejected by the deterministic accept gate because "
            f"{reason}. Provide the missing fresh validation evidence, then use the exact readiness marker "
            "on its own line."
        ),
        persistent_decision=decision.persistent_decision,
        progress_update=None,
        clear_handoff=decision.clear_handoff,
        display_message=decision.display_message,
        handoff=None,
        wake_sequence=decision.wake_sequence,
        generation=decision.generation,
    )


def _changed_test_contract_shift_risks(packet: SupervisorWakePacket, decision: CompletionReviewDecision) -> list[str]:
    risks: list[str] = []
    for changed in packet.changed_file_diffs:
        if changed.file_kind != "test" or changed.change_kind not in {"modified", "renamed"}:
            continue
        removed_lines = _substantive_removed_test_lines(changed.diff)
        if not removed_lines:
            continue
        if _changed_test_reviewed_with_assessment(decision, changed.path):
            continue
        risks.append(f"{changed.path} removed/rewrote existing test behavior: {removed_lines[0]}")
        if len(risks) >= 10:
            break
    return risks


def _changed_test_reviewed_with_assessment(decision: CompletionReviewDecision, path: str) -> bool:
    reviewed_by_path = {_normalize_review_path(file.path): file for file in decision.files_reviewed}
    reviewed = reviewed_by_path.get(_normalize_review_path(path))
    if reviewed is None or reviewed.kind != "test" or not reviewed.inspected:
        return False
    assessment = " ".join(part for part in (reviewed.reason, reviewed.limitation or "") if part).strip()
    return bool(assessment)


def _unassessed_parallel_persistence_risks(
    packet: SupervisorWakePacket,
    decision: CompletionReviewDecision,
) -> list[str]:
    if _decision_explicitly_assesses_source_of_truth(decision):
        return []
    risks: list[str] = []
    for changed in packet.changed_file_diffs:
        if changed.file_kind != "source" or changed.change_kind not in {"modified", "added", "renamed"}:
            continue
        if not _source_diff_adds_parallel_persistent_state(changed.diff):
            continue
        risks.append(f"{changed.path} adds parallel persisted state without source-of-truth/legacy compatibility evidence")
        if len(risks) >= 10:
            break
    return risks


def _decision_explicitly_assesses_source_of_truth(decision: CompletionReviewDecision) -> bool:
    texts: list[str] = [
        decision.reason or "",
        decision.persistent_decision or "",
        decision.progress_update or "",
    ]
    for row in decision.behavior_evidence_matrix:
        texts.extend([row.behavior, row.task_basis, row.gap or ""])
        texts.extend(row.files_considered)
        for evidence in row.evidence:
            texts.extend([evidence.command, evidence.why_it_covers_behavior])
    combined = " ".join(texts).lower()
    markers = (
        "source-of-truth",
        "source of truth",
        "precedence",
        "legacy compatibility",
        "compatibility with existing",
        "existing state contract",
        "old state contract",
        "old source of truth",
        "new fallback state must not mask",
    )
    return any(marker in combined for marker in markers)


def _source_diff_adds_parallel_persistent_state(diff: str) -> bool:
    added_keys = _persistent_key_families(diff, prefixes=("+",))
    if not added_keys:
        return False
    prior_or_context_keys = _persistent_key_families(diff, prefixes=("-", " "))
    shared_families = {
        family
        for family, keys in added_keys.items()
        if family in prior_or_context_keys and not keys.issubset(prior_or_context_keys[family])
    }
    if not shared_families:
        return False
    lowered = diff.lower()
    contract_terms = (
        "fallback",
        "metadata",
        "durable",
        "expire",
        "expires",
        "expiry",
        "ttl",
        "interval",
        "pending",
        "status",
        "validation",
        "confirm",
        "resend",
        "email",
    )
    return any(term in lowered for term in contract_terms)


def _persistent_key_families(diff: str, *, prefixes: tuple[str, ...]) -> dict[str, set[str]]:
    families: dict[str, set[str]] = {}
    for raw_line in diff.splitlines():
        if not raw_line.startswith(prefixes) or raw_line.startswith(("+++", "---")):
            continue
        line = raw_line[1:]
        if not _line_mentions_persistence(line):
            continue
        for key in _key_like_literals(line):
            family = key.split(":", 1)[0].strip()
            if not family:
                continue
            families.setdefault(family, set()).add(key)
    return families


def _line_mentions_persistence(line: str) -> bool:
    lowered = line.lower()
    storage_markers = (
        "db.",
        "redis",
        "cache",
        "storage",
        "localstorage",
        "sessionstorage",
        "setobject",
        "setobjectfield",
        "getobject",
        "getobjectfield",
        "pexpire",
        "expire",
        "pttl",
        "ttl",
    )
    return any(marker in lowered for marker in storage_markers)


def _key_like_literals(line: str) -> set[str]:
    keys: set[str] = set()
    for match in re.finditer(r"['\"`]([^'\"`]*:[^'\"`]*)['\"`]", line):
        key = re.sub(r"\$\{[^}]+\}", "*", match.group(1)).strip()
        if not key or key.startswith(("http:", "https:")):
            continue
        if re.search(r"\s", key):
            continue
        keys.add(key)
    return keys


def _substantive_removed_test_lines(diff: str, *, limit: int = 5) -> list[str]:
    lines: list[str] = []
    for raw_line in diff.splitlines():
        if not raw_line.startswith("-") or raw_line.startswith("---"):
            continue
        line = raw_line[1:].strip()
        if not _is_substantive_test_line(line):
            continue
        lines.append(_bounded_text(line, limit=180))
        if len(lines) >= limit:
            break
    return lines


def _is_substantive_test_line(line: str) -> bool:
    if not line or line in {"{", "}", "});", "});,", ");"}:
        return False
    if line.startswith(("//", "/*", "*", "import ", "const assert", "const {", "let ", "var ")):
        return False
    lowered = line.lower()
    substantive_tokens = (
        "assert",
        "expect(",
        ".should",
        "equal",
        "throws",
        "rejects",
        "await ",
        "return ",
        "expire",
        "ttl",
        "interval",
        "status",
        "email",
        "uid",
        "fallback",
        "pending",
        "confirm",
        "validation",
    )
    return any(token in lowered for token in substantive_tokens)


def _completion_return_summary(decision: CompletionReviewDecision) -> str:
    parts = [decision.reason]
    if decision.uncovered_behaviors:
        parts.append("uncovered=" + ", ".join(decision.uncovered_behaviors[:5]))
    if decision.validation_gaps:
        parts.append("validation_gaps=" + ", ".join(decision.validation_gaps[:5]))
    if decision.claim_evidence_mismatches:
        parts.append("mismatches=" + ", ".join(decision.claim_evidence_mismatches[:5]))
    if decision.packet_or_access_limitations:
        parts.append("limitations=" + ", ".join(decision.packet_or_access_limitations[:5]))
    return "; ".join(part for part in parts if part)


def _behavior_evidence_summary(decision: Any) -> list[str]:
    if not isinstance(decision, CompletionReviewDecision):
        return []
    return [
        f"{row.status}: {row.behavior}"
        + (f" ({len(row.evidence)} evidence item{'s' if len(row.evidence) != 1 else ''})" if row.evidence else "")
        for row in decision.behavior_evidence_matrix
    ]


def _files_reviewed_summary(decision: Any) -> list[str]:
    if not isinstance(decision, CompletionReviewDecision):
        return []
    return [
        f"{file.kind}: {file.path} ({'inspected' if file.inspected else 'not inspected'})"
        + (f" - {file.limitation}" if file.limitation else "")
        for file in decision.files_reviewed
    ]


def _material_findings(items: list[str]) -> list[str]:
    material: list[str] = []
    for item in items:
        lowered = item.lower()
        if any(marker in lowered for marker in ("non-material", "not material", "immaterial")):
            continue
        material.append(item)
    return material


def _normalize_review_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


@dataclass(frozen=True)
class _BoundedFileText:
    text: str
    truncated: bool


def _read_workspace_file(root: Path, path: str, *, limit: int) -> _BoundedFileText | None:
    candidate = (root / path).resolve()
    if not ensure_relative_to(candidate, root):
        return None
    if not candidate.is_file():
        return None
    try:
        raw = candidate.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    bounded = _bounded_text(raw, limit=limit)
    return _BoundedFileText(text=bounded, truncated=len(raw) > len(bounded))


def _file_kind(path: str) -> str:
    lowered = path.lower().replace("\\", "/")
    name = lowered.rsplit("/", 1)[-1]
    if (
        lowered.startswith("tests/")
        or lowered.startswith("test/")
        or lowered.startswith("fixtures/")
        or lowered.startswith("fixture/")
        or lowered.startswith("golden/")
        or lowered.startswith("goldens/")
        or lowered.startswith("snapshots/")
        or lowered.startswith("__snapshots__/")
        or "/tests/" in lowered
        or "/test/" in lowered
        or "/fixtures/" in lowered
        or "/fixture/" in lowered
        or "/golden/" in lowered
        or "/goldens/" in lowered
        or "/snapshots/" in lowered
        or "/__snapshots__/" in lowered
        or "/__tests__/" in lowered
        or "/spec/" in lowered
        or ".test." in name
        or ".spec." in name
        or ".snap." in name
        or ".snapshot." in name
        or ".golden." in name
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith("_spec.rb")
        or name.endswith((".snap", ".snapshot", ".golden"))
    ):
        return "test"
    if (
        lowered.startswith(".github/workflows/")
        or lowered.startswith(".circleci/")
        or lowered.startswith(".buildkite/")
        or lowered.startswith("ci/")
        or lowered.startswith(".gitlab/")
        or name in {".gitlab-ci.yml", ".travis.yml", "azure-pipelines.yml", "jenkinsfile"}
    ):
        return "config"
    if name in {
        "package.json",
        "pyproject.toml",
        "setup.cfg",
        "tox.ini",
        "pytest.ini",
        "tsconfig.json",
        "vitest.config.js",
        "vitest.config.ts",
        "jest.config.js",
        "jest.config.ts",
        "playwright.config.js",
        "playwright.config.ts",
    }:
        return "config"
    if lowered.endswith((".toml", ".yaml", ".yml", ".json", ".ini", ".cfg")):
        return "config"
    if lowered.endswith((".md", ".rst", ".txt", ".adoc")):
        return "docs"
    if lowered.endswith(
        (
            ".py",
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".mjs",
            ".cjs",
            ".rb",
            ".go",
            ".rs",
            ".java",
            ".kt",
            ".cs",
            ".php",
            ".swift",
            ".c",
            ".cc",
            ".cpp",
            ".h",
            ".hpp",
            ".css",
            ".scss",
            ".html",
            ".vue",
            ".svelte",
        )
    ):
        return "source"
    return "unknown"


def _is_relevant_changed_path(path: str, *, task_contents: str) -> bool:
    kind = _file_kind(path)
    if kind in {"source", "test", "config"}:
        return True
    if _is_suspicious_changed_path(path):
        return True
    if kind == "docs":
        return _task_is_docs_facing(task_contents)
    return False


def _is_suspicious_changed_path(path: str) -> bool:
    normalized = path.lower().replace("\\", "/").strip("/")
    name = normalized.rsplit("/", 1)[-1]
    if _file_kind(path) == "test":
        return True
    suspicious_parts = {
        "fixtures",
        "fixture",
        "golden",
        "goldens",
        "snapshots",
        "__snapshots__",
        "__fixtures__",
        "ci",
    }
    if set(normalized.split("/")) & suspicious_parts:
        return True
    if normalized.startswith((".github/workflows/", ".circleci/", ".buildkite/")):
        return True
    if name in {".gitlab-ci.yml", ".travis.yml", "azure-pipelines.yml", "jenkinsfile"}:
        return True
    if any(marker in name for marker in (".snap", ".snapshot", ".golden")):
        return True
    return False


def _task_is_docs_facing(task_contents: str) -> bool:
    lowered = task_contents.lower()
    return any(token in lowered for token in ("documentation", "docs", "readme", ".md", "markdown", "docstring"))


def _read_task_text(task_path: Path) -> str:
    try:
        return task_path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _diff_line_counts(changed_files: list[ChangedFile]) -> tuple[int, int]:
    additions = sum(changed.additions or 0 for changed in changed_files)
    deletions = sum(changed.deletions or 0 for changed in changed_files)
    return additions, deletions


def _has_large_diff(changed_files: list[ChangedFile]) -> bool:
    additions, deletions = _diff_line_counts(changed_files)
    return (
        len(changed_files) >= LARGE_DIFF_CHANGED_FILES_THRESHOLD
        or additions + deletions >= LARGE_DIFF_CHANGED_LINES_THRESHOLD
    )


def _action_timed_out(action: TriggeringAction) -> bool:
    text = " ".join(part for part in (action.status, action.summary) if part).lower()
    return "timeout" in text or "timed out" in text


def _change_kind(status: str) -> str:
    normalized = status.strip().upper()
    if "D" in normalized:
        return "deleted"
    if "R" in normalized:
        return "renamed"
    if "A" in normalized or "?" in normalized:
        return "added"
    if normalized:
        return "modified"
    return "unknown"


def _changed_tests_summary(path: str, text: str, validations: list[ValidationRun]) -> ChangedTestsSummary:
    return ChangedTestsSummary(
        path=path,
        added_or_modified_test_names=_detect_test_names(text),
        changed_assertion_snippets=_assertion_snippets(text),
        grep_or_test_selection_relevant_to_validations=[
            validation.command
            for validation in validations
            if path in _target_files_or_test_files(validation.command)
        ],
        summary_truncated=text.endswith("...<truncated>"),
    )


def _validation_output(validation: ValidationRun) -> ValidationOutput:
    return ValidationOutput(
        validation_id=validation.validation_id,
        command=validation.command,
        raw_command=validation.raw_command,
        normalized_command=validation.normalized_command,
        cwd=validation.cwd,
        exit_code=validation.exit_code,
        shell_exit_code=validation.shell_exit_code,
        type=validation.type,
        outcome=validation.outcome,
        passed=validation.passed,
        trusted_validation_outcome=validation.trusted_validation_outcome,
        masking_reason=validation.masking_reason,
        sequence=validation.sequence,
        stdout_or_summary=validation.summary,
        stderr_or_summary=None,
        output_truncated=validation.summary.endswith("...<truncated>"),
        detected_test_names=_detect_test_names(validation.summary),
        target_files_or_test_files=validation.target_files_or_test_files
        or _target_files_or_test_files(validation.command),
        was_filtered=validation.was_filtered,
        raw_selector=validation.raw_selector,
        executed_test_names=validation.executed_test_names,
        passed_count=validation.passed_count,
        failed_count=validation.failed_count,
    )


def _detect_test_names(text: str, *, limit: int = 50) -> list[str]:
    names: list[str] = []
    patterns = (
        r"\b(?:it|test|describe)\s*\(\s*['\"]([^'\"]+)['\"]",
        r"\bdef\s+(test_[A-Za-z0-9_]+)\s*\(",
        r"\bclass\s+(Test[A-Za-z0-9_]+)\b",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            names.append(match.group(1).strip())
            if len(names) >= limit:
                return list(dict.fromkeys(names))
    return list(dict.fromkeys(names))


def _assertion_snippets(text: str, *, limit: int = 30) -> list[str]:
    snippets: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        if not stripped:
            continue
        if any(token in lowered for token in ("assert", "expect(", ".should", "equal", "strictEqual".lower())):
            snippets.append(_bounded_text(stripped, limit=240))
            if len(snippets) >= limit:
                break
    return snippets


def _target_files_or_test_files(command: str) -> list[str]:
    targets: list[str] = []
    for match in re.finditer(r"(?<![\w./-])(?:\.?/)?[\w./-]+\.(?:py|js|jsx|ts|tsx|mjs|cjs|rb|go|rs|java|cs|php)(?![\w.-])", command):
        target = match.group(0).strip("'\"")
        if target:
            targets.append(target.lstrip("./"))
    return list(dict.fromkeys(targets))


def _paths_from_item(item: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    raw_paths = item.get("paths")
    if isinstance(raw_paths, list):
        paths.extend(str(path) for path in raw_paths if isinstance(path, str))
    file_changes = item.get("fileChanges")
    if isinstance(file_changes, dict):
        paths.extend(str(path) for path in file_changes)
    changes = item.get("changes")
    if isinstance(changes, list):
        for change in changes:
            if not isinstance(change, dict):
                continue
            for key in ("path", "filePath", "file_path", "filepath"):
                value = change.get(key)
                if isinstance(value, str):
                    paths.append(value)
    return list(dict.fromkeys(paths))


def _patch_summary_from_item(item: Any, limit: int = 4000) -> str | None:
    if not isinstance(item, dict) or item.get("type") != "fileChange":
        return None
    changes = item.get("changes") or item.get("fileChanges")
    if changes is None:
        return None
    return _bounded_json(changes, limit=limit)


def _patch_summary_from_approval_context(context: ApprovalContext, limit: int = 4000) -> str | None:
    if context.diff:
        return _bounded_text(context.diff, limit=limit)
    if context.file_changes:
        return _bounded_json(context.file_changes, limit=limit)
    return None


def _bounded_text(text: str, *, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 20] + "\n...<truncated>"


def _bounded_json(value: Any, *, limit: int) -> str:
    text = json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)
    return _bounded_text(text, limit=limit)


def _parse_numstat(value: str) -> int | None:
    return int(value) if value.isdigit() else None


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _schema_file_exists(out_dir: Path, name: str) -> bool:
    return (out_dir / name).exists() or (out_dir / "v2" / name).exists()


def _run_probe(args: list[str], timeout: float = 5.0) -> tuple[bool, str]:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return completed.returncode == 0, (completed.stdout + completed.stderr).strip()


def _default_model(response: dict[str, Any]) -> str | None:
    data = response.get("data")
    if not isinstance(data, list) or not data:
        return None
    first = data[0]
    if not isinstance(first, dict):
        return None
    for key in ("id", "slug", "name"):
        value = first.get(key)
        if isinstance(value, str):
            return value
    return None


def _sandbox_is_read_only(value: Any) -> bool:
    if value == "read-only":
        return True
    if isinstance(value, dict):
        return value.get("type") == "readOnly"
    return False


def _sandbox_matches_mode(value: Any, mode: str) -> bool:
    if mode == CODER_SANDBOX_DANGER_FULL_ACCESS:
        if value == "danger-full-access":
            return True
        if isinstance(value, dict):
            return value.get("type") == "dangerFullAccess"
        return False
    return _sandbox_is_read_only(value)


def _approval_resolution_is_denial(decision: str | dict[str, Any]) -> bool:
    return isinstance(decision, str) and decision in {"decline", "cancel", "denied", "abort"}


def _observed_changed_files(controller: Any) -> list[ChangedFile]:
    observed = getattr(controller, "observed_changed_files", None)
    if not isinstance(observed, dict):
        return []
    return list(observed.values())[:200]


def _path_from_git_status_line(line: str) -> str:
    if len(line) > 2 and line[2] == " ":
        return line[3:].strip()
    if len(line) > 2:
        return line[2:].strip()
    return line.strip()


def _format_validation(validation: ValidationRun) -> str:
    exit_code = "unknown" if validation.exit_code is None else str(validation.exit_code)
    return f"{validation.command} ({validation.type} {validation.outcome}, exit={exit_code})"


def _workspace_display_path(project_root: Path, raw_path: str) -> str:
    path = Path(raw_path)
    if not path.is_absolute():
        return str(path)
    try:
        return str(path.resolve().relative_to(project_root.resolve()))
    except ValueError:
        return raw_path


def _turn_id_from_params(params: dict[str, Any]) -> str | None:
    if isinstance(params.get("turnId"), str):
        return params["turnId"]
    turn = params.get("turn")
    if isinstance(turn, dict) and isinstance(turn.get("id"), str):
        return turn["id"]
    return None


def _item_id_from_params(params: dict[str, Any]) -> str | None:
    if isinstance(params.get("itemId"), str):
        return params["itemId"]
    item = params.get("item")
    if isinstance(item, dict) and isinstance(item.get("id"), str):
        return item["id"]
    return None


def _item_summary(item: Any) -> str:
    if not isinstance(item, dict):
        return "item completed"
    item_type = item.get("type", "item")
    if item_type == "commandExecution":
        return f"command completed: {item.get('command', '')} exit={item.get('exitCode')}"
    if item_type == "fileChange":
        return f"file change completed: {len(item.get('changes') or [])} changes"
    if item_type == "mcpToolCall":
        return f"mcp tool completed: {item.get('server')}/{item.get('tool')}"
    if item_type == "dynamicToolCall":
        return f"dynamic tool completed: {item.get('tool')}"
    if item_type == "agentMessage":
        return "agent message completed"
    return f"{item_type} completed"


def _is_completed_action(item: Any) -> bool:
    return isinstance(item, dict) and item.get("type") in {"commandExecution", "fileChange", "mcpToolCall", "dynamicToolCall", "webSearch"}


def _is_stream_delta_method(method: str) -> bool:
    return method.endswith("/delta") or method.endswith("/outputDelta") or method in {
        "item/reasoning/summaryTextDelta",
        "item/reasoning/textDelta",
        "command/exec/outputDelta",
        "process/outputDelta",
        "item/commandExecution/outputDelta",
        "item/fileChange/outputDelta",
    }


def _changed_files_from_diff_summary(diff: str | None) -> list[str]:
    if not diff:
        return []
    files: list[str] = []
    status_marker = "$ git status --short"
    if status_marker in diff:
        status_tail = diff.split(status_marker, 1)[1].split("$ git diff --stat", 1)[0]
        for line in status_tail.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("$"):
                continue
            path = stripped[3:] if len(stripped) > 3 else stripped
            path = path.strip()
            if path and not path.startswith(".supervisor/") and path not in files:
                files.append(path)
    marker = "$ git diff --name-only"
    if marker in diff:
        tail = diff.split(marker, 1)[1]
        for line in tail.splitlines():
            path = line.strip()
            if path and not path.startswith("$") and path not in files:
                files.append(path)
    return files
