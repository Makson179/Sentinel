from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from supervisor.approval_triage import (
    CheapApprovalReviewer,
    CheapApprovalReviewerError,
    CheapApprovalTriageConfig,
    CheapRuntimeReviewer,
    CheapRuntimeReviewerError,
    CheapRuntimeTriageConfig,
    cheap_approval_triage_config_from_env,
    runtime_triage_config_from_env,
)
from supervisor.adversary_agent import AdversaryAgent, AdversaryAgentError
from supervisor.appserver import AppServerClient, AppServerError, AppServerMessage
from supervisor.approvals import ApprovalManager, normalize_approval_request
from supervisor.coder import (
    CODER_SANDBOX_DANGER_FULL_ACCESS,
    DEFAULT_INTELLIGENCE,
    CoderSession,
    coder_sandbox_mode,
    coder_thread_params,
)
from supervisor.health import kill_restart_candidate, patch_health
from supervisor.policy import deterministic_task_command_reason
from supervisor.schemas import (
    AppEvent,
    AppEventSource,
    ApprovalContext,
    ApprovalRequestType,
    AdversaryReport,
    ApprovalWakeContext,
    BreadthRiskSummary,
    CheapApprovalDecision,
    CheapRuntimeDecision,
    ChangedFile,
    ChangedFileContext,
    ChangedFileDiff,
    ChangedTestsSummary,
    CoderMessage,
    CompletionReturnRecord,
    CompletionReviewDecision,
    CompletionReviewDecisionKind,
    DiffPacketLimits,
    EvidenceProvenanceSummary,
    FinalReport,
    HealthDelta,
    HumanMessage,
    InspectionOutput,
    InspectionRun,
    PriorIntervention,
    PolicyDecision,
    RestartHandoff,
    SentinelConfig,
    SentinelStatus,
    SupervisorDecision,
    SupervisorDecisionKind,
    SupervisorWakePacket,
    TriggeringAction,
    ValidationOutput,
    ValidationProvenance,
    ValidationRun,
)
from supervisor.schemas.models import ensure_relative_to
from supervisor.state import DECISIONS, HANDOFF, PROGRESS, StateStore
from supervisor.supervisor_agent import StatelessSupervisorAgent, SupervisorAgentError
from supervisor.task_select import resolve_task
from supervisor.tui import TerminalTUI, UserCommand
from supervisor.workspace_clean import clean_workspace_except_task


VALIDATION_LEDGER_LIMIT = 50
INSPECTION_LEDGER_LIMIT = 50
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
PROTECTED_RUNTIME_WAKE_REASONS = {
    "done_without_fresh_validation",
    "masked_validation",
    "repeated_same_failing_validation",
    "restart_budget",
    "suspicious_file_touched",
    "validation_regression",
}
CONTROLLER_IDLE_GUARD_INTERVAL_SECONDS = 60.0
CONTROLLER_IDLE_GUARD_STALL_SECONDS = 300.0
# Provider no_message (empty-completion) recovery for the completion review. A transient
# backend blip can return empty "completed" turns for a couple of minutes; ride it out with
# backed-off retries before declaring the run infra-invalid. The budget is CONSECUTIVE
# (reset on any successful supervisor decision), so a recovered provider keeps working.
COMPLETION_NO_MESSAGE_MAX_RETRIES = 6
NO_MESSAGE_RETRY_BACKOFF_SECONDS = (15.0, 30.0, 60.0, 120.0, 120.0, 120.0)
# Observation-only breadth-risk hints for reviewer context. These terms must
# never drive an accept gate, mandatory demo, or forced code change; required
# behavior is derived from task_contents and repository contract instead.
BREADTH_FEATURE_TERMS = (
    "api",
    "abi",
    "array",
    "auth",
    "cache",
    "case",
    "cli",
    "compatibility",
    "concurrency",
    "config",
    "constraint",
    "database",
    "delete",
    "enum",
    "error",
    "expression",
    "fallback",
    "function",
    "group",
    "index",
    "insert",
    "join",
    "limit",
    "migration",
    "null",
    "parser",
    "permission",
    "persistence",
    "pointer",
    "preprocessor",
    "query",
    "routing",
    "select",
    "snapshot",
    "sort",
    "storage",
    "struct",
    "transaction",
    "type",
    "update",
    "validation",
)
DEFAULT_MODEL = "gpt-5.5"
ADVERSARY_MODEL = "gpt-5.5"


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
    details: dict[str, Any] | None = None
    passed_checks: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuntimeTriggerDecision:
    should_wake: bool
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class ModelAvailabilityResult:
    missing_roles: tuple[str, ...]
    available_models: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.missing_roles


@dataclass(frozen=True)
class EvidenceBindingIssue:
    reason: str
    kind: str
    behavior: str | None = None
    validation_id: str | None = None
    validation_type: str | None = None
    command: str | None = None
    artifact_evidence_required: bool = False
    coder_correctable: bool = False
    bounded_coder_return_key: str | None = None
    inspection_id: str | None = None


class SentinelController:
    def __init__(
        self,
        project_root: Path,
        *,
        task_path: Path | None = None,
        client: AppServerClient | None = None,
        tui: TerminalTUI | None = None,
        model: str | None = None,
        coder_model: str | None = None,
        supervisor_model: str | None = None,
        coder_intelligence: str | None = DEFAULT_INTELLIGENCE,
        supervisor_intelligence: str | None = DEFAULT_INTELLIGENCE,
        fast: bool = False,
        overwrite_state: bool = False,
        clean_workspace: bool = False,
        use_git_diff: bool = True,
        adversary_enabled: bool | None = None,
        declared_grading_roots: list[str | Path] | tuple[str | Path, ...] | None = None,
    ):
        self.project_root = project_root.resolve()
        self.task_path = resolve_task(self.project_root, task_path)
        if clean_workspace:
            clean_workspace_except_task(self.project_root, self.task_path)
        self.store = StateStore(self.project_root)
        self.coder_model, self.supervisor_model = _resolve_controller_models(
            model=model,
            coder_model=coder_model,
            supervisor_model=supervisor_model,
        )
        self.model = self.coder_model if self.coder_model == self.supervisor_model else None
        self.coder_intelligence = coder_intelligence
        self.supervisor_intelligence = supervisor_intelligence
        self.fast = fast
        self.overwrite_state = overwrite_state
        self.clean_workspace = clean_workspace
        self.use_git_diff = use_git_diff
        self.adversary_enabled = _adversary_enabled_from_env() if adversary_enabled is None else adversary_enabled
        self.declared_grading_roots = tuple(str(Path(root).expanduser()) for root in declared_grading_roots or ())
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
        self.approval_triage_config: CheapApprovalTriageConfig = cheap_approval_triage_config_from_env()
        self.approval_triage_reviewer: CheapApprovalReviewer | None = None
        self.runtime_triage_config: CheapRuntimeTriageConfig = runtime_triage_config_from_env()
        self.runtime_triage_reviewer: CheapRuntimeReviewer | None = None
        self.coder: CoderSession | None = None
        self.pending_approvals: dict[int | str, ApprovalContext] = {}
        self.last_coder_message: CoderMessage | None = None
        self.validations: list[ValidationRun] = []
        self.inspections: list[InspectionRun] = []
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
        self.completion_decision_staleness_rerun_count = 0
        self.completion_return_freshness_rerun_count = 0
        self.provider_failure_recovery_counts: dict[str, int] = {}
        self.no_marker_idle_nudge_count = 0
        self.validation_runtime_state: dict[str, dict[str, Any]] = {}
        self.completion_review_return_sequence: int | None = None
        self.completion_review_return_validation_sequence: int | None = None
        self._pending_completion_gate_rejection: dict[str, Any] | None = None
        self._current_accept_gate_rejection: dict[str, Any] | None = None
        self._terminal_cleanup_started = False
        self._last_controller_activity_monotonic = time.monotonic()
        self._idle_guard_fired_for_sequence: int | None = None
        self._no_marker_completion_review_key: str | None = None
        self._last_large_diff_signature: str | None = None
        self._pending_adversary_report: AdversaryReport | None = None
        self._active_adversary_thread_id: str | None = None
        self._active_adversary_workspace_root: Path | None = None
        self._final_report_archived = False

    async def run(self) -> None:
        self.initialize_state()
        try:
            await self.client.start()
            await self.client.initialize()
            await self.tui.start()
            self.running = True
            await self.preflight()
            if not self.running:
                return
            self.supervisor = StatelessSupervisorAgent(
                self.client,
                self.store,
                self.task_path,
                model=self._supervisor_model(),
                fast=self._fast_mode(),
                intelligence=self._supervisor_intelligence(),
            )
            self.approval_triage_reviewer = self._build_cheap_approval_reviewer()
            self.approvals = ApprovalManager(
                self.project_root,
                supervisor=self,
                cheap_reviewer=self.approval_triage_reviewer,
                declared_grading_roots=self.declared_grading_roots,
                cheap_review_timeout_seconds=self.approval_triage_config.timeout_seconds,
            )
            self.coder = CoderSession(
                self.client,
                self.store,
                self.project_root,
                self.task_path,
                model=self._coder_model(),
                fast=self._fast_mode(),
                intelligence=self._coder_intelligence(),
            )
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
        adversary_enabled = self._adversary_enabled_for_config()
        config = SentinelConfig(
            project_root=str(self.project_root),
            task_path=str(self.task_path),
            task_hash=_hash_file(self.task_path),
            model=self.model,
            coder_model=self.coder_model,
            supervisor_model=self.supervisor_model,
            coder_intelligence=self._coder_intelligence(),
            supervisor_intelligence=self._supervisor_intelligence(),
            fast=self._fast_mode(),
            start_over=self.overwrite_state,
            clean=self.clean_workspace,
            protected_paths=list(self.declared_grading_roots),
            adversary=adversary_enabled,
            max_adversary_runs=1 if adversary_enabled else 0,
        )
        mode = "fresh" if self.overwrite_state else "resume"
        self.store.initialize_sentinel(config, mode=mode)
        self._sequence = self.store.max_event_sequence()
        _ensure_internal_runtime_git_excluded(self.project_root)

    def _persist_model_config(self) -> None:
        adversary_enabled = self._adversary_enabled_for_config()
        self.store.update_sentinel_config(
            lambda cfg: cfg.model_copy(
                update={
                    "model": self.model,
                    "coder_model": self.coder_model,
                    "supervisor_model": self.supervisor_model,
                    "coder_intelligence": self._coder_intelligence(),
                    "supervisor_intelligence": self._supervisor_intelligence(),
                    "fast": self._fast_mode(),
                    "start_over": self.overwrite_state,
                    "clean": self.clean_workspace,
                    "protected_paths": list(self.declared_grading_roots),
                    "adversary": adversary_enabled,
                    "max_adversary_runs": 1 if adversary_enabled else 0,
                }
            )
        )

    def _coder_model(self) -> str | None:
        return getattr(self, "coder_model", getattr(self, "model", DEFAULT_MODEL))

    def _supervisor_model(self) -> str | None:
        return getattr(self, "supervisor_model", getattr(self, "model", DEFAULT_MODEL))

    def _fast_mode(self) -> bool:
        return bool(getattr(self, "fast", False))

    def _adversary_enabled_for_config(self) -> bool:
        enabled = getattr(self, "adversary_enabled", None)
        if enabled is False:
            return False
        return True

    def _coder_intelligence(self) -> str | None:
        return getattr(self, "coder_intelligence", DEFAULT_INTELLIGENCE)

    def _supervisor_intelligence(self) -> str | None:
        return getattr(self, "supervisor_intelligence", DEFAULT_INTELLIGENCE)

    def _adversary_model(self) -> str:
        return ADVERSARY_MODEL

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
        models_response = await self.client.model_list()
        self._persist_model_config()
        await self._ensure_selected_models_available(models_response)
        if self.store.get_sentinel_config().status == SentinelStatus.PROVIDER_FAILURE:
            return
        self.tui.status("checking supervisor structured output")
        await self._structured_output_self_test()
        await self._configure_approval_triage()
        await self._configure_runtime_triage()
        self.tui.status("checking config requirements")
        await self.client.config_requirements_read()
        self.tui.status("checking coder sandbox and approval settings")
        thread = await self.client.thread_start(
            coder_thread_params(self.project_root, model=self._coder_model(), fast=self._fast_mode())
        )
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

    async def _ensure_selected_models_available(self, models_response: dict[str, Any]) -> None:
        result = _selected_model_availability(
            models_response,
            coder_model=self._coder_model(),
            supervisor_model=self._supervisor_model(),
            adversary_model=self._adversary_model() if self._adversary_model_required_for_preflight() else None,
        )
        if result.ok:
            return
        available = ", ".join(result.available_models) if result.available_models else "none reported"
        missing = ", ".join(result.missing_roles)
        message = (
            "model availability preflight failed before coder start: "
            f"selected model(s) are not available from Codex app-server model/list: {missing}. "
            f"Available models: {available}. "
            "The interruption is recorded in .supervisor/FINAL_REPORT.md."
        )
        self.store.append_text_locked(PROGRESS, f"- {message}\n")
        await self.finalize(message, status=SentinelStatus.PROVIDER_FAILURE)

    def _adversary_model_required_for_preflight(self) -> bool:
        enabled = getattr(self, "adversary_enabled", None)
        if enabled is False:
            return False
        if enabled is True:
            return True
        return self.store.get_sentinel_config().max_adversary_runs > 0

    async def event_loop(self) -> None:
        assert self.tui is not None
        while self.running:
            event_task = asyncio.create_task(self.event_queue.get())
            input_task = asyncio.create_task(self.tui.input_queue.get())
            done, pending = await asyncio.wait(
                {event_task, input_task},
                timeout=CONTROLLER_IDLE_GUARD_INTERVAL_SECONDS,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            if not done:
                await self._handle_controller_idle_guard()
                continue
            for done_task in done:
                completed = done_task.result()
                self._mark_controller_activity()
                if isinstance(completed, ControllerEvent):
                    await self.handle_controller_event(completed)
                elif isinstance(completed, UserCommand):
                    await self.handle_user_command(completed)

    def _mark_controller_activity(self) -> None:
        self._last_controller_activity_monotonic = time.monotonic()
        self._idle_guard_fired_for_sequence = None

    async def _handle_controller_idle_guard(self, *, now: float | None = None, force: bool = False) -> None:
        if not self.running or getattr(self, "paused", False) or getattr(self, "_terminal_cleanup_started", False):
            return
        cfg = self.store.get_sentinel_config()
        if cfg.active_coder_turn_id:
            return
        coder = getattr(self, "coder", None)
        if coder is None:
            await self.finalize(
                "controller idle guard: no active coder session, no pending approvals, and no supervisor check",
                status=SentinelStatus.PROVIDER_FAILURE,
            )
            return
        if getattr(coder, "active_turn_id", None):
            return
        if getattr(self, "pending_approvals", None):
            return
        task = getattr(self, "_supervisor_task", None)
        if task is not None and not task.done():
            return
        current_time = time.monotonic() if now is None else now
        last_activity = getattr(self, "_last_controller_activity_monotonic", current_time)
        if not force and current_time - last_activity < CONTROLLER_IDLE_GUARD_STALL_SECONDS:
            return
        sequence = cfg.last_event_sequence
        if getattr(self, "_idle_guard_fired_for_sequence", None) == sequence:
            return
        self._idle_guard_fired_for_sequence = sequence
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "controller_idle_guard",
                "sequence": sequence,
                "reason": "running with no active coder turn, pending approval, or supervisor check",
            }
        )
        await self._handle_no_marker_idle()

    async def handle_controller_event(self, event: ControllerEvent) -> None:
        try:
            if event.kind == "shutdown":
                self.running = False
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
            manager = getattr(self, "approvals", None) or ApprovalManager(
                self.project_root,
                declared_grading_roots=getattr(self, "declared_grading_roots", ()),
            )
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
        is_adversary_request = self._is_adversary_approval_context(context)
        if is_adversary_request:
            adversary_workspace_root = getattr(self, "_active_adversary_workspace_root", None)
            fallback_manager = ApprovalManager(
                adversary_workspace_root or self.project_root,
                declared_grading_roots=getattr(self, "declared_grading_roots", ()),
            )
            if adversary_workspace_root is None:
                resolution = fallback_manager._deny(context, "adversary snapshot workspace is not active")
            else:
                resolution = await fallback_manager.decide(context)
            response = fallback_manager.response_payload(context, resolution)
        elif self.approvals is None:
            fallback_manager = ApprovalManager(
                self.project_root,
                declared_grading_roots=getattr(self, "declared_grading_roots", ()),
            )
            resolution = fallback_manager._deny(context, "approval manager not ready")
            response = fallback_manager.response_payload(context, resolution)
        else:
            resolution = await self.approvals.decide(context)
            response = self.approvals.response_payload(context, resolution)
            self._record_cheap_approval_attempt(context, self.approvals)
        await self.client.respond(context.server_request_id, response)
        is_denial = _approval_resolution_is_denial(resolution.decision)
        decision_key = _approval_resolution_metric_key(resolution.decision)
        self._record_approval_metric(decision=decision_key, from_supervisor=resolution.from_supervisor)
        self.tui.render("DENIED" if is_denial else "APPROVAL", f"{resolution.decision}: {resolution.reason}")
        if resolution.persistent_decision:
            self.store.append_text_locked(DECISIONS, f"- {resolution.persistent_decision}\n")
        if is_denial:
            if is_adversary_request:
                self.store.append_text_locked(
                    PROGRESS,
                    f"- Adversary approval denied without steering coder: {resolution.reason}\n",
                )
            elif self.coder is not None:
                try:
                    await self.coder.steer_or_start(resolution.reason)
                except AppServerError as exc:
                    if not _is_no_active_turn_to_steer_error(exc):
                        raise
                    self.tui.render("SUPERVISOR", f"denial delivered as approval response; starting a new coder turn: {exc}")
                    if hasattr(self.coder, "active_turn_id"):
                        self.coder.active_turn_id = None
                    self.store.update_sentinel_config(
                        lambda cfg: cfg.model_copy(update={"active_coder_turn_id": None})
                    )
                    turn_id = await self.coder.start_turn(resolution.reason)
                    if isinstance(turn_id, str):
                        self.store.update_sentinel_config(
                            lambda cfg: cfg.model_copy(update={"active_coder_turn_id": turn_id})
                        )
                    self.store.append_text_locked(
                        PROGRESS,
                        "- Approval denial was returned to app-server after the original turn ended; "
                        "started a new coder turn with the denial reason.\n",
                    )
            patch_health(self.store, HealthDelta(generation=self.store.get_health().generation, denied_requests=1, last_denial=resolution.reason))

    def _is_adversary_approval_context(self, context: ApprovalContext) -> bool:
        thread_id = getattr(self, "_active_adversary_thread_id", None)
        return bool(thread_id and context.thread_id == thread_id)

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
            inspections=list(getattr(self, "inspections", [])),
            prior_interventions=list(self.prior_interventions),
            changed_files=await self.changed_files(),
            patch_summary=_patch_summary_from_approval_context(context) or await self.patch_summary(),
        )
        return await self.supervisor.decide(packet)

    async def decide_cheap_approval(self, context: ApprovalContext, evaluation: PolicyDecision) -> CheapApprovalDecision:
        if self.approval_triage_reviewer is None:
            raise CheapApprovalReviewerError("cheap approval triage not configured")
        return await self.approval_triage_reviewer.review(context, evaluation)

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
                declared_grading_issue = self._declared_grading_access_issue(triggering_action)
                if declared_grading_issue is not None:
                    self.tui.render("INTEGRITY", declared_grading_issue)
                    self.store.append_text_locked(PROGRESS, f"- Integrity failure: {declared_grading_issue}\n")
                    self._append_event(
                        AppEventSource.SUPERVISOR,
                        "integrity/declared_grading_path_access",
                        reason=declared_grading_issue,
                    )
                    await self.finalize(
                        f"escalated: {declared_grading_issue}",
                        status=SentinelStatus.ESCALATED,
                    )
                    return
                validation_item = _item_with_recorded_output(item, self._pop_command_output(item_id))
                validation = _validation_from_action(
                    triggering_action,
                    sequence=self._sequence,
                    item=validation_item,
                    changed_paths=list(getattr(self, "observed_changed_files", {}) or {}),
                )
                inspection = _inspection_from_action(
                    triggering_action,
                    sequence=self._sequence,
                    item=validation_item,
                )
                validation_trigger_reasons: tuple[str, ...] = ()
                if validation is not None:
                    self.validations.append(validation)
                    self.validations = self.validations[-VALIDATION_LEDGER_LIMIT:]
                    self._record_validation_progress(validation)
                    validation_trigger_reasons = self._record_validation_runtime_state(validation)
                if inspection is not None:
                    self.inspections.append(inspection)
                    self.inspections = self.inspections[-INSPECTION_LEDGER_LIMIT:]
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
        if not _is_command_output_delta_method(method):
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
                self.completion_return_freshness_rerun_count = 0
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
                summary = "Coder provided exact readiness marker; running completion_review."
                pending_gate = getattr(self, "_pending_completion_gate_rejection", None)
                if pending_gate:
                    summary = _completion_gate_followup_summary(pending_gate)
                self._schedule_supervisor_check(
                    summary,
                    triggering_item_id=item_id,
                    completion_review=True,
                )
            return
        if message is not None and _reports_material_limitation(message.text):
            await self._handle_coder_material_limitation(message)
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

    async def _handle_coder_material_limitation(self, message: CoderMessage) -> None:
        cfg = self.store.get_sentinel_config()
        summary = _material_limitation_summary(message.text)
        self.store.append_text_locked(
            PROGRESS,
            f"- Coder reported material limitation without readiness marker: {summary}\n",
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "coder/material_limitation",
            reason=summary,
        )
        patch_health(
            self.store,
            HealthDelta(generation=cfg.generation, add_risk_signals=["coder_material_limitation"]),
        )
        await self.finalize(
            f"escalated: coder reported material validation limitation without readiness marker: {summary}",
            status=SentinelStatus.ESCALATED,
        )

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
        if cfg.active_coder_turn_id:
            return
        latest_validation_sequence = max((validation.sequence for validation in self.validations), default=None)
        last_message_sequence = self.last_coder_message.sequence if self.last_coder_message is not None else None
        review_key = f"{cfg.generation}:{last_message_sequence}:{latest_validation_sequence}"
        if getattr(self, "_no_marker_completion_review_key", None) == review_key:
            return
        self._no_marker_completion_review_key = review_key
        self.store.append_text_locked(
            PROGRESS,
            "- Controller forcing completion_review: coder is idle with no active turn and no readiness marker.\n",
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "completion/no_marker_idle_review",
            reason="coder idle with no active turn and no readiness marker",
        )
        self._schedule_supervisor_check(
            "Coder is idle with no active turn and no readiness marker. Run completion_review on the current state.",
            completion_review=True,
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
        self._append_event(AppEventSource.SUPERVISOR, "controller/restart", reason=reason)
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
        self._pending_adversary_report = None
        self._active_adversary_thread_id = None
        self._active_adversary_workspace_root = None
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
        self.coder = CoderSession(
            self.client,
            self.store,
            self.project_root,
            self.task_path,
            model=self._coder_model(),
            fast=self._fast_mode(),
        )
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
        self._reconcile_intervention_accounting()
        diff = await self.diff_summary()
        changed_files = await self.changed_files()
        health = self.store.get_health()
        accepted_completion = getattr(self, "_accepted_completion_decision", None)
        report = FinalReport(
            task_path=str(self.task_path),
            status=status,
            result=result,
            files_changed=[file.path for file in changed_files]
            or _changed_files_from_diff_summary(diff, project_root=self.project_root, task_path=self.task_path),
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
            adversary_reports=_final_adversary_report_summary(
                getattr(self, "_accepted_adversary_report", None)
                or getattr(self, "_pending_adversary_report", None)
            ),
            remaining_risks=list(accepted_completion.changed_test_risks)
            if isinstance(accepted_completion, CompletionReviewDecision)
            else [],
            diff_summary=diff,
        )
        self.store.write_final_report(report)
        self._archive_final_report_once()
        self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"status": status}))
        self.tui.render("SUPERVISOR", result)
        self.tui.status("final report written: .supervisor/FINAL_REPORT.md")
        await self._prepare_terminal_shutdown(result)
        self.running = False
        self._wake_event_loop_for_shutdown()

    def _archive_final_report_once(self) -> None:
        if getattr(self, "_final_report_archived", False):
            return
        self.store.archive_completed_run(self.task_path)
        self._final_report_archived = True

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
        target = sum(1 for record in prior if _prior_record_counts_as_health_intervention(record))

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
            if _is_behavior_proving_validation(validation) and validation.trusted_validation_outcome != "masked_or_unknown":
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

    def _has_unresolved_runtime_validation_risk(self) -> bool:
        state = getattr(self, "validation_runtime_state", None) or {}
        for entry in state.values():
            if not isinstance(entry, dict):
                continue
            if entry.get("trusted_validation_outcome") == "masked_or_unknown":
                return True
            try:
                failed_count = int(entry.get("consecutive_failed_count") or 0)
            except (TypeError, ValueError):
                failed_count = 0
            if failed_count >= 2:
                return True
        return False

    def _deterministic_runtime_noop_reason(
        self,
        *,
        action: TriggeringAction,
        validation: ValidationRun | None,
        reasons: list[str],
    ) -> str | None:
        if not reasons:
            return None
        reason_set = set(reasons)
        if reason_set & PROTECTED_RUNTIME_WAKE_REASONS:
            return None
        if self._has_unresolved_runtime_validation_risk():
            return None
        if reason_set == {"large_diff"} and _is_file_change_activity(action):
            return "routine file-change large diff"
        command = action.command or ""
        if not command:
            return None
        task_command_reason = deterministic_task_command_reason(self.project_root, command, cwd=action.cwd)
        if task_command_reason is None:
            return None
        if reason_set == {"large_diff"} and action.exit_code == 0:
            return task_command_reason
        if reason_set <= {"nonzero_exit", "timeout", "large_diff"} and (
            action.exit_code is None or action.exit_code != 0 or _action_timed_out(action)
        ):
            if validation is not None and validation.trusted_validation_outcome == "masked_or_unknown":
                return None
            return task_command_reason
        return None

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
        read_only_action = bool(action.command and _is_read_only_inspection_command(action.command))
        if (
            action.exit_code is not None
            and action.exit_code != 0
            and not (
                action.command
                and _is_read_only_inspection_command(action.command)
                and _inspection_exit_is_usable(action.command, action.exit_code)
            )
        ):
            reasons.append("nonzero_exit")
        if _action_timed_out(action):
            reasons.append("timeout")
        if validation is not None and validation.trusted_validation_outcome == "masked_or_unknown":
            reasons.append("masked_validation")
        large_diff_signature = _large_diff_signature(changed_files) if _has_large_diff(changed_files) else None
        if large_diff_signature is not None and not read_only_action:
            reasons.append("large_diff")
        if any(_is_suspicious_changed_path(changed.path) for changed in changed_files):
            reasons.append("suspicious_file_touched")
        restart_candidate, restart_reason = kill_restart_candidate(self.store.get_health())
        if restart_candidate and restart_reason and not read_only_action:
            reasons.append("restart_budget")
        reasons = list(dict.fromkeys(reasons))
        if self._deterministic_runtime_noop_reason(
            action=action,
            validation=validation,
            reasons=reasons,
        ):
            return RuntimeTriggerDecision(should_wake=False, reasons=())
        if (
            reasons == ["large_diff"]
            and large_diff_signature is not None
            and getattr(self, "_last_large_diff_signature", None) == large_diff_signature
        ):
            reasons = []
        elif large_diff_signature is not None and "large_diff" in reasons:
            self._last_large_diff_signature = large_diff_signature
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

    def _declared_grading_access_issue(self, action: TriggeringAction) -> str | None:
        roots = getattr(self, "declared_grading_roots", ())
        if not roots:
            return None
        payload: dict[str, Any] = {}
        if action.command:
            payload["command"] = action.command
        if action.cwd:
            payload["cwd"] = action.cwd
        if action.paths:
            payload["paths"] = action.paths
        if not payload:
            return None
        manager = getattr(self, "approvals", None)
        if manager is None:
            manager = ApprovalManager(self.project_root, declared_grading_roots=roots)
        decision = manager.policy.evaluate(payload)
        if decision.kind.value != "deny" or "declared grading/hidden path access denied" not in decision.reason:
            return None
        command = f" command `{action.command}`" if action.command else ""
        return f"coder accessed declared grading/hidden path via{command}: {decision.reason}"

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

    def _record_supervisor_decision_metric(self, *, use_case: str, decision: str) -> None:
        def patch(current: dict[str, Any]) -> dict[str, Any]:
            counts = current.get("supervisor_decision_counts")
            if not isinstance(counts, dict):
                counts = {}
            scope_counts = counts.get(use_case)
            if not isinstance(scope_counts, dict):
                scope_counts = {}
            scope_counts[decision] = int(scope_counts.get(decision) or 0) + 1
            counts[use_case] = scope_counts
            current["supervisor_decision_counts"] = counts
            current[f"{use_case}_{decision}_total"] = int(current.get(f"{use_case}_{decision}_total") or 0) + 1
            return current

        self.store.update_runtime_metrics(patch)

    def _record_approval_metric(self, *, decision: str, from_supervisor: bool) -> None:
        def patch(current: dict[str, Any]) -> dict[str, Any]:
            counts = current.get("approval_decision_counts")
            if not isinstance(counts, dict):
                counts = {}
            counts[decision] = int(counts.get(decision) or 0) + 1
            current["approval_decision_counts"] = counts
            current["approval_requests_total"] = int(current.get("approval_requests_total") or 0) + 1
            current[f"approval_{decision}_total"] = int(current.get(f"approval_{decision}_total") or 0) + 1
            if from_supervisor:
                current["approval_from_supervisor_total"] = int(current.get("approval_from_supervisor_total") or 0) + 1
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
            self._mark_controller_activity()
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
            completion_details["evidence_provenance_summary"] = _evidence_provenance_summary(
                validations=list(self.validations),
                changed_files=changed_files,
                latest_change_sequence=latest_change_sequence,
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
            inspections=list(getattr(self, "inspections", [])),
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
            pending_accept_gate_rejection=(
                getattr(self, "_pending_completion_gate_rejection", None) if completion_review else None
            ),
            adversary_report=(
                self._fresh_adversary_report(
                    generation=cfg.generation,
                    latest_relevant_change_sequence=latest_change_sequence,
                )
                if completion_review
                else None
            ),
            **completion_details,
        )
        try:
            if completion_review:
                self.completion_attempt_count = getattr(self, "completion_attempt_count", 0) + 1
                decision = await self.supervisor.decide_completion(packet)
            else:
                # Cheap-model triage: let a lightweight model route clear non-events to noop
                # before paying for the full supervisor. Never short-circuit human messages or
                # pending approvals (those always need the full supervisor); on any cheap-side
                # error or escalate, fall through to the full supervisor.
                if (
                    getattr(self, "runtime_triage_reviewer", None) is not None
                    and human_message is None
                    and not packet.pending_approvals
                    and not _runtime_packet_has_protected_reason(packet)
                ):
                    cheap = await self._cheap_runtime_route(packet)
                    if cheap is not None and cheap.decision == "noop":
                        return
                decision = await self.supervisor.decide(packet)
        except SupervisorAgentError as exc:
            failure_kind = _classify_supervisor_agent_error(exc)
            message = f"supervisor check failed ({failure_kind}): {exc}"
            self.tui.render("SUPERVISOR", message)
            if failure_kind == "no_message":
                recovered = await self._handle_supervisor_no_message_failure(
                    message=message,
                    summary=summary,
                    completion_review=completion_review,
                )
                if recovered:
                    return
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
        # Successful supervisor decision: reset the transient provider no_message budget so it
        # counts CONSECUTIVE empty-completion failures, not lifetime ones (a recovered provider
        # should not inherit earlier blips toward an infra-invalid).
        if getattr(self, "provider_failure_recovery_counts", None):
            self.provider_failure_recovery_counts = {}
        if completion_review:
            await self.apply_completion_decision(decision, packet_thread_id=packet.coder_thread_id, packet=packet)
        else:
            await self.apply_supervisor_decision(decision, packet_thread_id=packet.coder_thread_id)

    async def _handle_supervisor_no_message_failure(
        self,
        *,
        message: str,
        summary: str,
        completion_review: bool,
    ) -> bool:
        counts = getattr(self, "provider_failure_recovery_counts", None)
        if counts is None:
            counts = {}
            self.provider_failure_recovery_counts = counts
        scope = "completion_review" if completion_review else "runtime_monitor"
        count_key = f"{scope}_no_message"
        attempts = int(counts.get(count_key) or 0)
        counts["no_message"] = int(counts.get("no_message") or 0) + 1
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "provider_failure_recovery",
                "kind": "no_message",
                "scope": scope,
                "attempts_before": attempts,
                "completion_review": completion_review,
                "message": message,
            }
        )
        budget = (
            getattr(self, "_completion_no_message_max_retries", COMPLETION_NO_MESSAGE_MAX_RETRIES)
            if completion_review
            else 1
        )
        if attempts < budget:
            counts[count_key] = attempts + 1
            if completion_review and self.supervisor is not None and hasattr(self.supervisor, "close_completion_review"):
                await self.supervisor.close_completion_review()
            backoff = 0.0
            if completion_review:
                schedule = getattr(self, "_no_message_backoff_seconds", NO_MESSAGE_RETRY_BACKOFF_SECONDS)
                if schedule:
                    backoff = float(schedule[min(attempts, len(schedule) - 1)])
            self.store.append_text_locked(
                PROGRESS,
                f"- Provider recovery: supervisor produced no agent message; retrying review from latest "
                f"stable state (attempt {attempts + 1}/{budget}, backoff {backoff:.0f}s).\n",
            )
            self._append_event(
                AppEventSource.SUPERVISOR,
                "provider/no_message_retry",
                decision="retry",
                reason=message,
            )
            if backoff > 0:
                await asyncio.sleep(backoff)
            self._supervisor_dirty = True
            self._supervisor_next_summary = (
                "Retry supervisor review from the latest stable controller state after provider no_message. "
                f"Previous review summary: {summary}"
            )
            self._supervisor_next_completion_review = completion_review or getattr(
                self,
                "_supervisor_next_completion_review",
                False,
            )
            return True
        counts[count_key] = attempts + 1
        if not completion_review:
            self.store.append_text_locked(
                PROGRESS,
                "- Provider recovery: runtime supervisor produced no agent message after retry; skipping this runtime-only review.\n",
            )
            self._append_event(
                AppEventSource.SUPERVISOR,
                "provider/runtime_no_message_skipped",
                decision="continue",
                reason=message,
            )
            return True
        self.store.append_text_locked(
            PROGRESS,
            "- Provider recovery failed: repeated supervisor no_message; marking run infra-invalid before scoring.\n",
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "provider/no_message_infra_invalid",
            decision="infra-invalid",
            reason=message,
        )
        await self.finalize(
            f"infra-invalid: supervisor no_message provider failure after retry/resume: {message}",
            status=SentinelStatus.PROVIDER_FAILURE,
        )
        return True

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
        self._record_supervisor_decision_metric(use_case="runtime", decision=decision.decision.value)
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
        stale_issue = self._completion_decision_staleness_issue(decision, packet=packet)
        if stale_issue is not None:
            await self._handle_completion_decision_staleness_failure(stale_issue)
            return
        self.store.update_sentinel_config(
            lambda current: current.model_copy(update={"last_applied_supervisor_sequence": decision.wake_sequence})
        )
        self._append_completion_anchor_log(decision, packet=packet)
        self._record_supervisor_decision_metric(use_case="completion", decision=decision.decision.value)
        if decision.decision == CompletionReviewDecisionKind.ACCEPT:
            gate_result = await self._completion_accept_gate(decision, packet=packet)
            if not gate_result.passed:
                await self._handle_completion_accept_gate_failure(decision, gate_result)
                return
            self._record_accept_gate_success(gate_result)
            if self._should_run_adversary_before_complete(packet):
                if packet is None or self._adversary_runs_remaining():
                    await self._run_adversary_before_complete(decision, packet=packet)
                    return
                self._record_adversary_limit_reached(packet)
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
            self.completion_decision_staleness_rerun_count = 0
            self.completion_return_freshness_rerun_count = 0
            self._pending_completion_gate_rejection = None
            self._accepted_completion_decision = decision
            self._accepted_adversary_report = packet.adversary_report if packet is not None else None
            await self.finalize(
                f"accepted by completion_review: {decision.reason or 'task complete'}",
                status=SentinelStatus.COMPLETE,
                completion_review_accepted=True,
            )
            return
        if decision.decision == CompletionReviewDecisionKind.RETURN:
            self._pending_completion_gate_rejection = None
            decision = self._attach_adversary_report_to_return(decision, packet=packet)
            await self._return_completion_to_coder(decision)
            return
        if decision.decision == CompletionReviewDecisionKind.RESTART:
            self._pending_completion_gate_rejection = None
            self.completion_restarts = getattr(self, "completion_restarts", 0) + 1
            await self.restart(decision.reason or "completion review requested restart", handoff=decision.handoff)
            return

    async def _run_adversary_before_complete(
        self,
        decision: CompletionReviewDecision,
        *,
        packet: SupervisorWakePacket | None,
    ) -> None:
        cfg = self.store.get_sentinel_config()
        if packet is None:
            await self.finalize(
                "infra-invalid: adversary requires a completion packet before final complete",
                status=SentinelStatus.PROVIDER_FAILURE,
            )
            return
        adversary_run_count, max_adversary_runs = self._reserve_adversary_run()
        self.tui.render(
            "ADVERSARY",
            f"running pre-complete adversarial tester ({adversary_run_count}/{max_adversary_runs})",
        )
        self.store.append_text_locked(
            PROGRESS,
            f"- Adversarial tester starting before final complete ({adversary_run_count}/{max_adversary_runs}).\n",
        )
        workspace_state_id = _workspace_state_id(self.project_root)
        snapshot_root: Path | None = None
        previous_report = getattr(self, "_pending_adversary_report", None)
        previous_report_payload = previous_report.model_dump(mode="json") if previous_report is not None else None
        try:
            snapshot_root = _create_adversary_snapshot(self.project_root)
        except Exception as exc:
            await self.finalize(
                f"infra-invalid: adversary snapshot setup failed before complete: {exc.__class__.__name__}: {exc}",
                status=SentinelStatus.PROVIDER_FAILURE,
            )
            return
        self._active_adversary_workspace_root = snapshot_root
        agent = AdversaryAgent(
            self.client,
            snapshot_root,
            model=self._adversary_model(),
            on_thread_start=self._mark_adversary_thread_started,
            on_thread_done=self._mark_adversary_thread_done,
        )
        try:
            result = await agent.run(packet, previous_adversary_report=previous_report_payload)
        except AdversaryAgentError as exc:
            self.store.append_raw_log(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "adversary_error",
                    "generation": packet.generation,
                    "completion_wake_sequence": decision.wake_sequence,
                    "adversary_run_count": adversary_run_count,
                    "max_adversary_runs": max_adversary_runs,
                    "error": str(exc),
                }
            )
            await self.finalize(
                f"infra-invalid: adversary provider/tool failure before complete: {exc}",
                status=SentinelStatus.PROVIDER_FAILURE,
            )
            return
        finally:
            self._active_adversary_workspace_root = None
            if snapshot_root is not None:
                shutil.rmtree(snapshot_root.parent, ignore_errors=True)

        report = AdversaryReport(
            candidate_finding=result.candidate_finding,
            report_text=result.report_text,
            thread_id=result.thread_id,
            turn_id=result.turn_id,
            generation=packet.generation,
            completion_wake_sequence=decision.wake_sequence,
            latest_relevant_change_sequence=packet.latest_relevant_change_sequence,
            validation_sequence=_latest_validation_sequence(packet.validations),
            workspace_state_id=workspace_state_id,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._pending_adversary_report = report
        self.store.append_raw_log(
            {
                "timestamp": report.created_at,
                "type": "adversary_report",
                "generation": report.generation,
                "completion_wake_sequence": report.completion_wake_sequence,
                "latest_relevant_change_sequence": report.latest_relevant_change_sequence,
                "validation_sequence": report.validation_sequence,
                "workspace_state_id": report.workspace_state_id,
                "candidate_finding": report.candidate_finding,
                "thread_id": report.thread_id,
                "turn_id": report.turn_id,
                "adversary_run_count": adversary_run_count,
                "max_adversary_runs": max_adversary_runs,
                "report_text": report.report_text,
            }
        )
        if not report.candidate_finding:
            self.store.append_text_locked(
                PROGRESS,
                "- Adversarial tester completed without a candidate finding; finalizing prior completion accept.\n",
            )
            if decision.persistent_decision:
                self.store.append_text_locked(DECISIONS, f"- {decision.persistent_decision}\n")
            if decision.progress_update:
                self.store.append_text_locked(PROGRESS, f"- {decision.progress_update}\n")
                patch_health(
                    self.store,
                    HealthDelta(generation=cfg.generation, last_progress_sequence=cfg.last_event_sequence),
                )
            if decision.clear_handoff:
                self.store.write_text_locked(HANDOFF, "")
            if decision.display_message:
                self.tui.render("SUPERVISOR", decision.display_message)
            self._append_event(
                AppEventSource.SUPERVISOR,
                "completion/accept",
                decision="accept",
                reason=decision.reason,
            )
            self.completion_reviewer_rerun_count = 0
            self.completion_decision_staleness_rerun_count = 0
            self.completion_return_freshness_rerun_count = 0
            self._pending_completion_gate_rejection = None
            self._accepted_completion_decision = decision
            self._accepted_adversary_report = report
            await self.finalize(
                f"accepted by completion_review after clean adversary report: {decision.reason or 'task complete'}",
                status=SentinelStatus.COMPLETE,
                completion_review_accepted=True,
            )
            return
        self.store.append_text_locked(
            PROGRESS,
            "- Adversarial tester completed with a candidate finding; rerunning completion_review with its report before complete.\n",
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "adversary/report_ready",
            decision="review",
            reason="pre-complete adversarial report available",
        )
        self._schedule_supervisor_check(
            "Adversarial tester report is available. Rerun completion_review; weigh the report as input, "
            "return only for a real reproduced required-behavior defect, otherwise accept.",
            completion_review=True,
        )

    def _adversary_runs_remaining(self) -> bool:
        cfg = self.store.get_sentinel_config()
        return cfg.adversary_run_count < cfg.max_adversary_runs

    def _should_run_adversary_before_complete(self, packet: SupervisorWakePacket | None) -> bool:
        if self._packet_has_fresh_adversary_report(packet):
            return False
        enabled = getattr(self, "adversary_enabled", None)
        if enabled is False:
            return False
        if enabled is True:
            return True
        return self.store.get_sentinel_config().max_adversary_runs > 0

    def _reserve_adversary_run(self) -> tuple[int, int]:
        updated = self.store.update_sentinel_config(
            lambda current: current.model_copy(update={"adversary_run_count": current.adversary_run_count + 1})
        )
        return updated.adversary_run_count, updated.max_adversary_runs

    def _record_adversary_limit_reached(self, packet: SupervisorWakePacket | None) -> None:
        cfg = self.store.get_sentinel_config()
        reason = f"adversary run limit reached ({cfg.adversary_run_count}/{cfg.max_adversary_runs})"
        self.tui.render("ADVERSARY", f"{reason}; finalizing completion accept")
        self.store.append_text_locked(
            PROGRESS,
            f"- Skipping adversarial tester before complete: {reason}.\n",
        )
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "adversary_limit_reached",
                "generation": packet.generation if packet is not None else None,
                "wake_sequence": packet.wake_sequence if packet is not None else None,
                "adversary_run_count": cfg.adversary_run_count,
                "max_adversary_runs": cfg.max_adversary_runs,
            }
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "adversary/limit_reached",
            reason=reason,
        )

    def _fresh_adversary_report(
        self,
        *,
        generation: int,
        latest_relevant_change_sequence: int | None,
    ) -> AdversaryReport | None:
        report = getattr(self, "_pending_adversary_report", None)
        if report is None:
            return None
        if report.status != "completed" or report.generation != generation:
            return None
        if report.latest_relevant_change_sequence != latest_relevant_change_sequence:
            return None
        if report.workspace_state_id and report.workspace_state_id != _workspace_state_id(self.project_root):
            return None
        return report

    def _packet_has_fresh_adversary_report(self, packet: SupervisorWakePacket | None) -> bool:
        if packet is None:
            return False
        report = packet.adversary_report
        if report is None:
            return False
        if report.status != "completed" or report.generation != packet.generation:
            return False
        if report.latest_relevant_change_sequence != packet.latest_relevant_change_sequence:
            return False
        if report.workspace_state_id and report.workspace_state_id != _workspace_state_id(self.project_root):
            return False
        return True

    def _attach_adversary_report_to_return(
        self,
        decision: CompletionReviewDecision,
        *,
        packet: SupervisorWakePacket | None,
    ) -> CompletionReviewDecision:
        report = packet.adversary_report if packet is not None else None
        if report is None or not report.report_text.strip():
            return decision
        marker = "Adversarial tester report:"
        if decision.message_to_coder and marker in decision.message_to_coder:
            return decision
        report_text = _bounded_adversary_report_text(report.report_text)
        message = (decision.message_to_coder or "").rstrip()
        message = f"{message}\n\n{marker}\n{report_text}".strip()
        return decision.model_copy(update={"message_to_coder": message})

    def _mark_adversary_thread_started(self, thread_id: str) -> None:
        self._active_adversary_thread_id = thread_id

    def _mark_adversary_thread_done(self, thread_id: str) -> None:
        if getattr(self, "_active_adversary_thread_id", None) == thread_id:
            self._active_adversary_thread_id = None

    def _completion_decision_staleness_issue(
        self,
        decision: CompletionReviewDecision,
        *,
        packet: SupervisorWakePacket | None,
    ) -> dict[str, Any] | None:
        if packet is None:
            return None
        stale_fields: list[str] = []
        if decision.basis_event_seq is not None and packet.latest_event_sequence > decision.basis_event_seq:
            stale_fields.append(
                f"basis_event_seq={decision.basis_event_seq} < latest_event_sequence={packet.latest_event_sequence}"
            )
        if (
            decision.last_relevant_edit_seq is not None
            and packet.latest_relevant_change_sequence is not None
            and packet.latest_relevant_change_sequence > decision.last_relevant_edit_seq
        ):
            stale_fields.append(
                "last_relevant_edit_seq="
                f"{decision.last_relevant_edit_seq} < latest_relevant_change_sequence={packet.latest_relevant_change_sequence}"
            )
        latest_validation_seq = max((validation.sequence for validation in packet.validations), default=None)
        if (
            decision.last_validation_seq is not None
            and latest_validation_seq is not None
            and latest_validation_seq > decision.last_validation_seq
        ):
            stale_fields.append(
                f"last_validation_seq={decision.last_validation_seq} < latest_validation_sequence={latest_validation_seq}"
            )
        if not stale_fields:
            return None
        return {
            "decision": decision.decision.value,
            "wake_sequence": decision.wake_sequence,
            "generation": decision.generation,
            "stale_fields": stale_fields,
            "packet_latest_event_sequence": packet.latest_event_sequence,
            "packet_latest_relevant_change_sequence": packet.latest_relevant_change_sequence,
            "packet_latest_validation_sequence": latest_validation_seq,
        }

    async def _handle_completion_decision_staleness_failure(self, issue: dict[str, Any]) -> None:
        reruns = getattr(self, "completion_decision_staleness_rerun_count", 0)
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "completion_decision_staleness_failure",
                **issue,
                "reruns_before": reruns,
            }
        )
        stale_fields = _format_issue_list(issue.get("stale_fields"))
        if reruns < 1:
            self.completion_decision_staleness_rerun_count = reruns + 1
            self.store.append_text_locked(
                PROGRESS,
                f"- Controller rerunning completion_review: stale decision anchors ({stale_fields})\n",
            )
            self._schedule_supervisor_check(
                (
                    "Completion-review decision was rejected by the deterministic freshness gate because "
                    f"its anchor sequences are stale: {stale_fields}. Rerun completion_review against the "
                    "current packet and set basis_event_seq, last_relevant_edit_seq, and last_validation_seq "
                    "from the latest current ledgers."
                ),
                completion_review=True,
            )
            return
        self.completion_decision_staleness_rerun_count = reruns + 1
        if self.supervisor is not None:
            await self.supervisor.close_completion_review()
        self.store.append_text_locked(
            PROGRESS,
            f"- Controller starting fresh completion_review: repeated stale decision anchors ({stale_fields})\n",
        )
        self._schedule_supervisor_check(
            (
                "Completion-review repeated stale anchor sequences after a freshness retry. "
                "Start a fresh full completion_review on the current workspace state."
            ),
            completion_review=True,
        )

    def _repair_completion_accept_evidence_ids(
        self,
        decision: CompletionReviewDecision,
        *,
        packet: SupervisorWakePacket | None,
    ) -> CompletionReviewDecision:
        validations = packet.validations if packet is not None else list(self.validations)
        inspections = packet.inspections if packet is not None else list(getattr(self, "inspections", []))
        repaired, repairs = _repair_completion_evidence_ids(
            decision,
            validations=validations,
            inspections=inspections,
        )
        if not repairs:
            return decision
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "completion_evidence_id_repair",
                "wake_sequence": decision.wake_sequence,
                "generation": decision.generation,
                "repairs": repairs,
            }
        )
        self.store.append_text_locked(
            PROGRESS,
            "- Controller repaired completion evidence IDs from the validation/inspection ledger: "
            + "; ".join(repairs[:6])
            + "\n",
        )
        return repaired

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

        if packet is not None:
            masking_issues = _changed_test_masking_issues(packet)
            if masking_issues:
                return AcceptGateResult(
                    passed=False,
                    failure_type=ACCEPT_GATE_CODER_CORRECTABLE,
                    check_name="changed_test_masking",
                    reason="changed test diff appears to mask validation rather than check behavior: "
                    + "; ".join(masking_issues[:5]),
                    details={"issues": masking_issues[:10]},
                )
            passed_checks.append("changed_test_masking")

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

            if _accept_gate_failure_is_proof_format(gate_result):
                infra_reason = f"repeated proof-format accept gate failure ({check_name}): {reason}"
                self.store.append_text_locked(PROGRESS, f"- Controller-side proof-format failure: {infra_reason}\n")
                self._append_event(
                    AppEventSource.SUPERVISOR,
                    "completion/accept_gate_proof_format_failure",
                    decision=ACCEPT_GATE_AUDIT_FAILURE,
                    reason=infra_reason,
                )
                self._increment_accept_gate_counter("accept_gate_audit_failures")
                await self.finalize(
                    f"infra-invalid: controller-side proof-format repair failed: {infra_reason}",
                    status=SentinelStatus.PROVIDER_FAILURE,
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

        gate_context = _accept_gate_rejection_context(gate_result)
        self._pending_completion_gate_rejection = gate_context
        self._current_accept_gate_rejection = gate_context
        converted = _completion_accept_rejection_decision(
            decision,
            reason,
            check_name=check_name,
            details=gate_result.details,
        )
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
        try:
            await self._return_completion_to_coder(converted)
        finally:
            self._current_accept_gate_rejection = None

    def _record_accept_gate_failure(self, gate_result: AcceptGateResult) -> None:
        self._increment_accept_gate_counter("accept_gate_rejections")
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "completion_accept_gate_rejection",
                "failure_type": gate_result.failure_type,
                "check_name": gate_result.check_name,
                "reason": gate_result.reason,
                "details": gate_result.details,
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

    def _completion_return_freshness_issue(
        self,
        decision: CompletionReviewDecision,
        *,
        packet: SupervisorWakePacket | None,
    ) -> dict[str, Any] | None:
        if packet is None:
            return None
        since_sequence = packet.completion_payload_since_sequence
        if packet.completion_payload_mode != "delta" or since_sequence is None:
            return None
        fresh_validation_ids = [
            validation.validation_id
            for validation in packet.validations
            if validation.sequence > since_sequence
            and _is_behavior_proving_validation(validation)
            and validation.outcome == "pass"
            and validation.passed
            and validation.trusted_validation_outcome == "passed"
        ]
        fresh_inspection_ids = [
            inspection.inspection_id
            for inspection in packet.inspections
            if inspection.sequence > since_sequence and inspection.outcome == "pass" and inspection.passed
        ]
        if not fresh_validation_ids and not fresh_inspection_ids:
            return None
        if not _completion_return_has_evidence_related_gap(decision):
            return None
        if _completion_decision_cites_evidence_after(decision, since_sequence=since_sequence):
            return None
        return {
            "since_sequence": since_sequence,
            "fresh_validation_ids": fresh_validation_ids[:12],
            "fresh_inspection_ids": fresh_inspection_ids[:12],
            "fresh_evidence_summary": _fresh_delta_evidence_detail(
                packet,
                since_sequence=since_sequence,
                validation_ids=set(fresh_validation_ids),
                inspection_ids=set(fresh_inspection_ids),
            ),
            "previous_return_summary": _previous_completion_return_summary(
                getattr(self, "completion_returns", []),
                generation=packet.generation,
            ),
            "reason": (
                "completion_review returned an evidence/validation gap without citing any fresh "
                f"validation_id or inspection_id after return baseline sequence {since_sequence}"
            ),
        }

    async def _handle_completion_return_freshness_failure(self, issue: dict[str, Any]) -> None:
        reason = str(issue.get("reason") or "completion_review ignored fresh delta evidence")
        reruns = getattr(self, "completion_return_freshness_rerun_count", 0)
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "completion_return_freshness_failure",
                **issue,
                "reruns_before": reruns,
            }
        )
        if reruns < 1:
            self.completion_return_freshness_rerun_count = reruns + 1
            self.store.append_text_locked(
                PROGRESS,
                f"- Controller rerunning completion_review: stale return ignored fresh delta evidence ({reason})\n",
            )
            self._schedule_supervisor_check(
                (
                    "Completion-review return was rejected by the deterministic freshness gate: "
                    f"{reason}. Rerun completion_review, update the retained behavior_evidence_matrix "
                    "with all fresh validation_outputs/inspection_outputs after the return baseline, "
                    "and explicitly bind any fresh validation_id/inspection_id that closes a prior returned gap. "
                    "Do not repeat a prior return finding that is now closed by fresh passing independent evidence; "
                    "if no current material task-derived gap remains after reconciliation, accept. "
                    f"Fresh evidence to reconcile: {_format_issue_list(issue.get('fresh_evidence_summary'))}. "
                    f"Prior returned gaps: {_format_issue_list(issue.get('previous_return_summary'))}."
                ),
                completion_review=True,
            )
            return
        self.completion_return_freshness_rerun_count = reruns + 1
        self.completion_review_return_sequence = None
        if self.supervisor is not None:
            await self.supervisor.close_completion_review()
        self.store.append_text_locked(
            PROGRESS,
            f"- Controller starting fresh completion_review: repeated stale delta return ({reason})\n",
        )
        self._schedule_supervisor_check(
            (
                "Completion-review delta recovery repeated a stale return after fresh evidence. "
                "Start a fresh full completion_review on the current workspace state, rebuild the "
                "behavior_evidence_matrix from task_contents and current ledgers, and do not rely on "
                "the stale retained return unless current evidence still proves that material gap."
            ),
            completion_review=True,
        )

    def _increment_accept_gate_counter(self, field: str) -> None:
        self.store.update_sentinel_config(
            lambda current: current.model_copy(update={field: getattr(current, field, 0) + 1})
        )

    def _bounded_accept_gate_coder_return_used(self, check_name: str, details: dict[str, Any]) -> bool:
        key = details.get("bounded_coder_return_key")
        if not key:
            return False
        for record in getattr(self, "completion_returns", []):
            if isinstance(record, CompletionReturnRecord):
                gate_context = record.accept_gate_details
            elif isinstance(record, dict):
                gate_context = record.get("accept_gate_details") or {}
            else:
                continue
            if not isinstance(gate_context, dict) or gate_context.get("check_name") != check_name:
                continue
            previous_details = gate_context.get("details") if isinstance(gate_context.get("details"), dict) else {}
            if previous_details.get("bounded_coder_return_key") == key:
                return True
        return False

    async def _return_completion_to_coder(self, decision: CompletionReviewDecision) -> None:
        cfg = self.store.get_sentinel_config()
        record = CompletionReturnRecord(
            reason=decision.reason,
            uncovered_behaviors=decision.uncovered_behaviors,
            validation_gaps=decision.validation_gaps,
            claim_evidence_mismatches=decision.claim_evidence_mismatches,
            packet_or_access_limitations=decision.packet_or_access_limitations,
            message_to_coder=decision.message_to_coder,
            accept_gate_check_name=(
                getattr(self, "_current_accept_gate_rejection", None) or {}
            ).get("check_name"),
            accept_gate_details=getattr(self, "_current_accept_gate_rejection", None) or {},
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
        health_delta = HealthDelta(generation=cfg.generation)
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
        # Fresh completion-review thread per review: close the session after each return so
        # the next readiness review starts a new thread instead of accumulating prior turns.
        # The persistent thread otherwise grows ~55-85k tokens per return and crossed the
        # model context window within a generation, forcing lossy auto-compaction. Prior
        # returns are still carried into the next review via previous_completion_returns,
        # and the reviewer re-reads the workspace live, so no context is lost.
        supervisor = getattr(self, "supervisor", None)
        if supervisor is not None and hasattr(supervisor, "close_completion_review"):
            await supervisor.close_completion_review()

    async def _resolve_pending_approvals(self, reason: str) -> None:
        approvals = getattr(self, "approvals", None)
        if approvals is None:
            manager = ApprovalManager(
                self.project_root,
                declared_grading_roots=getattr(self, "declared_grading_roots", ()),
            )
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
                output = _filter_internal_git_output(
                    output,
                    command=command,
                    project_root=self.project_root,
                    task_path=self.task_path,
                )
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
            if path and not _is_ignored_changed_path(path, project_root=self.project_root, task_path=self.task_path):
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
            if not path or _is_ignored_changed_path(path, project_root=self.project_root, task_path=self.task_path):
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
            if path and not _is_ignored_changed_path(path, project_root=self.project_root, task_path=self.task_path):
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
        detail_inspections = [
            inspection
            for inspection in getattr(self, "inspections", [])
            if since_sequence is None or inspection.sequence > since_sequence
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
            "inspection_outputs": [_inspection_output(inspection) for inspection in detail_inspections],
            "completion_delta_evidence_summary": _completion_delta_evidence_summary(
                detail_validations,
                detail_inspections,
                since_sequence=since_sequence,
            ),
            "breadth_risk_summary": _breadth_risk_summary(
                task_contents=_read_task_text(self.task_path),
                changed_files=changed_files,
            ),
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
            if not _turn_start_schema_supports_effort(out_dir):
                raise RuntimeError("app-server schema missing required turn effort field for Sentinel intelligence settings")
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
            model=self._supervisor_model(),
            fast=self._fast_mode(),
            intelligence=self._supervisor_intelligence(),
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

    async def _configure_approval_triage(self) -> None:
        config = cheap_approval_triage_config_from_env()
        self.approval_triage_config = config
        self.approval_triage_reviewer = None
        if not config.enabled:
            self.tui.render("SYSTEM", "cheap approval triage disabled by configuration")
            return
        if config.model is None:
            self.tui.render(
                "SYSTEM",
                "cheap approval triage disabled: SENTINEL_APPROVAL_TRIAGE_MODEL is not configured",
            )
            self.approval_triage_config = CheapApprovalTriageConfig(
                enabled=False,
                model=None,
                timeout_seconds=config.timeout_seconds,
            )
            return
        reviewer = CheapApprovalReviewer(
            self.client,
            self.project_root,
            model=config.model,
            timeout_seconds=config.timeout_seconds,
        )
        try:
            await self._cheap_approval_structured_output_self_test(reviewer)
        except Exception as exc:
            self.tui.render(
                "SYSTEM",
                f"cheap approval triage unavailable; falling back to full supervisor ({exc.__class__.__name__})",
            )
            self.approval_triage_config = CheapApprovalTriageConfig(
                enabled=False,
                model=config.model,
                timeout_seconds=config.timeout_seconds,
            )
            return
        self.approval_triage_reviewer = reviewer
        self.tui.render("SYSTEM", f"cheap approval triage enabled with model {config.model}")

    async def _cheap_approval_structured_output_self_test(self, reviewer: CheapApprovalReviewer) -> None:
        command = "git status --short && git diff --stat"
        context = ApprovalContext(
            server_request_id="cheap-approval-self-test",
            server_request_method="item/commandExecution/requestApproval",
            request_type=ApprovalRequestType.COMMAND,
            command=command,
            cwd=str(self.project_root),
            available_decisions=["accept", "decline", "cancel"],
        )
        evaluation = ApprovalManager(
            self.project_root,
            declared_grading_roots=getattr(self, "declared_grading_roots", ()),
        ).policy.evaluate({"command": command, "cwd": str(self.project_root)})
        decision = await asyncio.wait_for(reviewer.review(context, evaluation), timeout=reviewer.timeout_seconds)
        if decision.decision not in {"approve_low_impact", "escalate"}:
            raise RuntimeError("cheap approval structured-output self-test returned an unexpected decision")

    def _build_cheap_approval_reviewer(self) -> CheapApprovalReviewer | None:
        if self.approval_triage_reviewer is not None:
            return self.approval_triage_reviewer
        config = self.approval_triage_config
        if not config.enabled or config.model is None:
            return None
        return CheapApprovalReviewer(
            self.client,
            self.project_root,
            model=config.model,
            timeout_seconds=config.timeout_seconds,
        )

    def _record_cheap_approval_attempt(self, context: ApprovalContext, manager: ApprovalManager) -> None:
        attempt = manager.last_cheap_review_attempt
        if attempt is None:
            return
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "cheap_approval_review",
                "server_request_id": context.server_request_id,
                "request_type": context.request_type.value,
                "eligible": attempt.eligible,
                "attempted": attempt.attempted,
                "outcome": attempt.outcome,
                "reason_code": attempt.reason_code,
                "latency_seconds": attempt.latency_seconds,
                "model": attempt.model,
                "full_supervisor_fallback": attempt.full_supervisor_fallback,
            }
        )

    async def _configure_runtime_triage(self) -> None:
        config = runtime_triage_config_from_env()
        self.runtime_triage_config = config
        self.runtime_triage_reviewer = None
        if not config.enabled:
            self.tui.render("SYSTEM", "cheap runtime triage disabled by configuration")
            return
        if config.model is None:
            self.tui.render("SYSTEM", "cheap runtime triage disabled: no model configured")
            self.runtime_triage_config = CheapRuntimeTriageConfig(
                enabled=False, model=None, timeout_seconds=config.timeout_seconds
            )
            return
        reviewer = CheapRuntimeReviewer(
            self.client,
            self.project_root,
            model=config.model,
            timeout_seconds=config.timeout_seconds,
        )
        try:
            await self._cheap_runtime_structured_output_self_test(reviewer)
        except Exception as exc:
            self.tui.render(
                "SYSTEM",
                f"cheap runtime triage unavailable; full supervisor on every wake ({exc.__class__.__name__})",
            )
            self.runtime_triage_config = CheapRuntimeTriageConfig(
                enabled=False, model=config.model, timeout_seconds=config.timeout_seconds
            )
            return
        self.runtime_triage_reviewer = reviewer
        self.tui.render("SYSTEM", f"cheap runtime triage enabled with model {config.model}")

    async def _cheap_runtime_structured_output_self_test(self, reviewer: CheapRuntimeReviewer) -> None:
        packet = SupervisorWakePacket(
            wake_sequence=1,
            latest_event_sequence=0,
            generation=0,
            restart_count=0,
            task_path=str(self.task_path),
            task_contents="",
            current_summary="Startup runtime-triage self-test: routine read-only progress, no failing checks.",
        )
        decision = await asyncio.wait_for(reviewer.review(packet), timeout=reviewer.timeout_seconds)
        if decision.decision not in {"noop", "escalate"}:
            raise RuntimeError("cheap runtime structured-output self-test returned an unexpected decision")

    async def _cheap_runtime_route(self, packet: SupervisorWakePacket) -> CheapRuntimeDecision | None:
        reviewer = self.runtime_triage_reviewer
        if reviewer is None:
            return None
        started = time.monotonic()
        try:
            decision = await reviewer.review(packet)
        except CheapRuntimeReviewerError as exc:
            self._record_cheap_runtime_attempt(
                packet, decision=None, outcome=f"error:{exc.__class__.__name__}", started=started, fallback=True
            )
            return None
        self._record_cheap_runtime_attempt(
            packet,
            decision=decision,
            outcome=decision.decision,
            started=started,
            fallback=(decision.decision == "escalate"),
        )
        if decision.decision == "noop":
            self.tui.render("SUPERVISOR", f"cheap runtime triage: noop ({decision.reason_code})")
        return decision

    def _record_cheap_runtime_attempt(
        self,
        packet: SupervisorWakePacket,
        *,
        decision: CheapRuntimeDecision | None,
        outcome: str,
        started: float,
        fallback: bool,
    ) -> None:
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "cheap_runtime_review",
                "wake_sequence": packet.wake_sequence,
                "generation": packet.generation,
                "current_summary": (packet.current_summary or "")[:160],
                "decision": decision.decision if decision is not None else None,
                "reason_code": decision.reason_code if decision is not None else None,
                "outcome": outcome,
                "latency_seconds": time.monotonic() - started,
                "model": self.runtime_triage_config.model,
                "full_supervisor_fallback": fallback,
            }
        )


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


def _runtime_packet_has_protected_reason(packet: SupervisorWakePacket) -> bool:
    return bool(set(_runtime_trigger_reasons_from_summary(packet.current_summary)) & PROTECTED_RUNTIME_WAKE_REASONS)


def _runtime_trigger_reasons_from_summary(summary: str | None) -> tuple[str, ...]:
    if not summary:
        return ()
    match = re.match(r"\s*Runtime trigger \(([^)]*)\):", summary)
    if not match:
        return ()
    return tuple(reason.strip() for reason in match.group(1).split(",") if reason.strip())


def _is_no_active_turn_to_steer_error(exc: AppServerError) -> bool:
    return "no active turn to steer" in str(exc).lower()


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
    executed_test_files = _test_files_from_output(output)
    outcome = "pass" if action.exit_code == 0 else "fail"
    if validation_type == "behavioral" and outcome == "pass" and not _tests_executed(action.command, output):
        outcome = "fail"
    masking_reason = _validation_masking_reason(
        action.command,
        validation_type=validation_type,
        changed_paths=changed_paths or [],
    )
    if masking_reason is None and validation_type == "behavior_demo" and outcome == "pass":
        if not output.strip():
            masking_reason = "behavior_demo_missing_output"
        else:
            masking_reason = _behavior_demo_output_masking_reason(output)
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
        captured_output=output,
        captured_output_truncated=output.endswith("...<truncated>"),
        sequence=sequence,
        was_filtered=_command_was_filtered(action.command),
        raw_selector=raw_selector,
        executed_test_names=executed_test_names,
        executed_test_files=executed_test_files,
        passed_count=passed_count,
        failed_count=failed_count,
        target_files_or_test_files=_target_files_or_test_files(action.command),
    )


def _inspection_from_action(
    action: TriggeringAction,
    *,
    sequence: int,
    item: Any = None,
) -> InspectionRun | None:
    if action.kind != "commandExecution" or not action.command:
        return None
    if not _is_read_only_inspection_command(action.command):
        return None
    output = _command_output_from_item(item)
    normalized_command = _normalize_command(action.command)
    inspected_paths = _inspected_paths_from_command(action.command)
    outcome = "pass" if _inspection_exit_is_usable(action.command, action.exit_code) else "fail"
    summary = _validation_summary(action.summary, output)
    return InspectionRun(
        inspection_id=_stable_inspection_id(
            normalized_command=normalized_command,
            cwd=action.cwd,
            inspected_paths=inspected_paths,
        ),
        command=action.command,
        raw_command=action.command,
        normalized_command=normalized_command,
        cwd=action.cwd,
        exit_code=action.exit_code,
        shell_exit_code=action.exit_code,
        outcome=outcome,
        passed=outcome == "pass",
        summary=summary,
        captured_output=output,
        captured_output_truncated=output.endswith("...<truncated>"),
        sequence=sequence,
        inspected_paths=inspected_paths,
    )


def _classify_validation_command(command: str, *, changed_paths: list[str]) -> str | None:
    if _is_git_inspection_command(command):
        return "static" if _is_git_diff_check_command(command) else None
    if _is_read_only_inspection_command(command):
        return None
    if _is_static_validation_command(command):
        return "static"
    if _is_behavioral_validation_command(command):
        return "behavioral"
    if _is_behavior_demo_command(command, changed_paths=changed_paths):
        return "behavior_demo"
    return None


def _is_static_validation_command(command: str) -> bool:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _is_static_validation_command(inner)
    lowered = command.lower()
    executable_prefix = r"(^|[\s;&|()'\"])(?:npx\s+|(?:\.{0,2}/|/)?(?:[\w.-]+/)*)"
    node_exec = r"(?:\.{0,2}/|/)?(?:[\w.-]+/)*node(?:js)?"
    python_exec = r"(?:\.{0,2}/|/)?(?:[\w.-]+/)*python(?:3(?:\.\d+)?)?"
    patterns = (
        r"(^|[\s;&|()'\"])" + node_exec + r"\s+-c(\s|$)",
        r"(^|[\s;&|()'\"])" + node_exec + r"\s+--check(\s|$)",
        r"(^|[\s;&|()'\"])git\s+diff\s+--check(\s|$)",
        executable_prefix + r"eslint(\s|$)",
        r"(^|[\s;&|()'\"])(npm|pnpm|yarn)\s+(run\s+)?lint(\s|$|:)",
        r"(^|[\s;&|()'\"])(npm|pnpm|yarn)\s+(run\s+)?type-?check(\s|$|:)",
        executable_prefix + r"prettier\s+--check(\s|$)",
        executable_prefix + r"tsc(?:\s+[^;&|()]*)?\s+--noemit(\s|$)",
        r"(^|[\s;&|()'\"])" + python_exec + r"\s+-m\s+(py_compile|compileall)(\s|$)",
        r"(^|[\s;&|()'\"])" + python_exec + r"\s+-m\s+json\.tool(\s|$)",
        r"(^|[\s;&|()'\"])jq\s+['\"]?\.['\"]?(\s|$)",
        r"json\.parse\s*\(",
    )
    return any(re.search(pattern, lowered) for pattern in patterns)


def _is_git_inspection_command(command: str) -> bool:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _is_git_inspection_command(inner)
    lowered = command.lower()
    pattern = r"(^|[\s;&|()'\"])(?:\.{0,2}/|/)?(?:[\w.-]+/)*git\s+(diff|status|log|show|branch|remote|rev-parse|for-each-ref)\b"
    return bool(re.search(pattern, lowered))


def _is_git_diff_check_command(command: str) -> bool:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _is_git_diff_check_command(inner)
    lowered = command.lower()
    pattern = r"(^|[\s;&|()'\"])(?:\.{0,2}/|/)?(?:[\w.-]+/)*git\s+diff(?:\s+[^;&|()'\"]+)*\s+--check(\s|$)"
    return bool(re.search(pattern, lowered))


def _is_read_only_inspection_command(command: str) -> bool:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _is_read_only_inspection_command(inner)
    lowered = command.lower()
    if any(marker in lowered for marker in ("<<", "$(", "`")):
        return False
    if re.search(r"(?<![12])>(?!&)", command) or re.search(r"(^|[^<])<(?!<)", command):
        return False
    segments = _inspection_command_segments(command)
    if segments is None:
        return False
    if not segments:
        return False
    return all(_is_read_only_inspection_tokens(segment) for segment in segments)


def _inspection_command_segments(command: str) -> list[list[str]] | None:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars="|;&<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = [token for token in lexer if token]
    except ValueError:
        return None
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in {"&&", ";", "|"}:
            if not current:
                return None
            segments.append(current)
            current = []
            continue
        if token in {"&"} or any(char in token for char in "<>"):
            return None
        current.append(token)
    if current:
        segments.append(current)
    return segments


def _shell_command_payload(command: str) -> str | None:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    tokens = _strip_env_command_prefix(tokens)
    if len(tokens) < 3:
        return None
    executable = tokens[0].rsplit("/", 1)[-1].lower()
    if executable not in {"bash", "sh", "zsh"}:
        return None
    for index, token in enumerate(tokens[1:], start=1):
        if not token.startswith("-"):
            continue
        if "c" not in token[1:]:
            continue
        if index + 1 < len(tokens):
            return tokens[index + 1]
    return None


def _strip_env_command_prefix(tokens: list[str]) -> list[str]:
    remaining = list(tokens)
    while remaining and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*", remaining[0]):
        remaining = remaining[1:]
    if not remaining:
        return remaining
    executable = remaining[0].rsplit("/", 1)[-1].lower()
    if executable != "env":
        return remaining
    remaining = remaining[1:]
    while remaining:
        token = remaining[0]
        if token == "--":
            remaining = remaining[1:]
            break
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*", token):
            remaining = remaining[1:]
            continue
        if token.startswith("-"):
            remaining = remaining[1:]
            continue
        break
    return remaining


def _is_read_only_inspection_segment(segment: str) -> bool:
    try:
        tokens = shlex.split(segment)
    except ValueError:
        return False
    return _is_read_only_inspection_tokens([token for token in tokens if token])


def _is_read_only_inspection_tokens(tokens: list[str]) -> bool:
    while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
        tokens = tokens[1:]
    if not tokens:
        return False
    executable = tokens[0].rsplit("/", 1)[-1].lower()
    args = [token.lower() for token in tokens[1:]]
    if executable == "git":
        return bool(args) and args[0] in {"diff", "status", "log", "show", "branch", "remote", "rev-parse", "for-each-ref"}
    if executable in {"cat", "sed", "grep", "egrep", "fgrep", "rg", "head", "tail", "nl", "ls", "wc", "pwd", "stat", "file", "find"}:
        if executable == "find" and any(arg in {"-delete", "-exec", "-execdir"} for arg in args):
            return False
        return True
    return False


def _is_behavioral_validation_command(command: str) -> bool:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _is_behavioral_validation_command(inner)
    lowered = command.lower()
    executable_prefix = r"(^|[\s;&|()'\"])(?:npx\s+|(?:\.{0,2}/|/)?(?:[\w.-]+/)*)"
    python_flags = r"(?:\s+-(?!m(?:\s|$))[a-z][\w-]*(?:=[^\s;&|()'\"]+)?)"
    node_exec = r"(?:\.{0,2}/|/)?(?:[\w.-]+/)*node(?:js)?"
    python_exec = r"(?:\.{0,2}/|/)?(?:[\w.-]+/)*python(?:3(?:\.\d+)?)?"
    patterns = (
        executable_prefix + r"mocha(\s|$)",
        r"(^|[\s;&|()'\"])(npm|pnpm|yarn)\s+(run\s+)?test(\s|$|:)",
        r"(^|[\s;&|()'\"])" + node_exec + r"\s+--test(\s|$)",
        r"(^|[\s;&|()'\"])" + python_exec + python_flags + r"*\s+-m\s+(pytest|unittest|tox|nose2?)($|[\s;&|()'\"])",
        executable_prefix + r"(jest|ava|tap|vitest|playwright|cypress|pytest|tox|rspec)(\s|$)",
        executable_prefix + r"(go|cargo|mvn|gradle|swift|dotnet|make)\s+test(\s|$)",
    )
    return any(re.search(pattern, lowered) for pattern in patterns) or _is_test_wrapper_script_command(command)


def _is_test_wrapper_script_command(command: str) -> bool:
    lowered = command.lower()
    boundary = r"(?=$|[\s;&|()'\"])"
    test_script_basename = r"(?:tests?(?:[._-][\w.-]+)*|[\w.-]+[._-]tests?(?:[._-][\w.-]+)*)"
    script_with_test_token = (
        r"(?:\.{1,2}/|/)?(?:[\w.-]+/)*" + test_script_basename + r"\.(py|js|mjs|cjs|rb|sh)"
    )
    interpreter_exec = r"(?:\.{0,2}/|/)?(?:[\w.-]+/)*(?:python(?:3(?:\.\d+)?)?|node(?:js)?|ruby|bash|sh)"
    shell_prefix = r"(^|[\s;&|()'\"])(?:\.{0,2}/|/)?(?:[\w.-]+/)*(?:bash|sh|zsh)"
    patterns = (
        r"(^|[\s;&|()'\"])" + interpreter_exec + r"\s+(?!-)" + script_with_test_token + boundary,
        r"(^|[\s;&|()'\"])" + script_with_test_token + boundary,
        shell_prefix + r"\s+-[a-z]*c\s+['\"]?" + script_with_test_token + boundary,
    )
    return any(re.search(pattern, lowered) for pattern in patterns)


def _is_direct_script_execution_command(command: str) -> bool:
    lowered = command.lower()
    boundary = r"(?=$|[\s;&|()'\"])"
    python_flags = r"(?:\s+-(?!m(?:\s|$))[a-z][\w-]*(?:=[^\s;&|()'\"]+)?)"
    python_exec = r"(?:\.{0,2}/|/)?(?:[\w.-]+/)*python(?:3(?:\.\d+)?)?"
    interpreter_exec = r"(?:\.{0,2}/|/)?(?:[\w.-]+/)*(?:node(?:js)?|ruby|bash|sh)"
    shell_prefix = r"(^|[\s;&|()'\"])(?:\.{0,2}/|/)?(?:[\w.-]+/)*(?:bash|sh|zsh)"
    patterns = (
        r"(^|[\s;&|()'\"])" + python_exec + python_flags + r"*\s+(?!-)[\w./-]+\.py" + boundary,
        r"(^|[\s;&|()'\"])" + interpreter_exec + r"\s+(?!-)[\w./-]+\.(js|mjs|cjs|rb|sh)" + boundary,
        r"(^|[\s;&|()'\"])(?:\.{1,2}/|/)[\w./-]+\.(py|js|mjs|cjs|rb|sh)" + boundary,
        shell_prefix + r"\s+-[a-z]*c\s+['\"]?(?!-)[\w./-]+\.(py|js|mjs|cjs|rb|sh)" + boundary,
    )
    return any(re.search(pattern, lowered) for pattern in patterns)


def _is_behavior_demo_command(command: str, *, changed_paths: list[str]) -> bool:
    lowered = command.lower()
    python_flags = r"(?:\s+-(?!m(?:\s|$))[a-z][\w-]*(?:=[^\s;&|()'\"]+)?)"
    node_exec = r"(?:\.{0,2}/|/)?(?:[\w.-]+/)*node(?:js)?"
    python_exec = r"(?:\.{0,2}/|/)?(?:[\w.-]+/)*python(?:3(?:\.\d+)?)?"
    ruby_exec = r"(?:\.{0,2}/|/)?(?:[\w.-]+/)*ruby"
    inline_patterns = (
        r"(^|[\s;&|()'\"])" + node_exec + r"\s+-e(\s|$)",
        r"(^|[\s;&|()'\"])" + python_exec + python_flags + r"*\s+-c(\s|$)",
        r"(^|[\s;&|()'\"])" + ruby_exec + r"\s+-e(\s|$)",
    )
    http_patterns = (
        r"(^|[\s;&|()'\"])(curl|wget|http|https)\s+",
        r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)",
    )
    return (
        (_has_behavior_demo_marker(command) and _marked_behavior_demo_command_is_plausible(command, changed_paths))
        or _is_direct_script_execution_command(command)
        or _is_stdin_script_demo_command(command)
        or _command_requires_changed_module(command, changed_paths)
        or any(re.search(pattern, lowered) for pattern in inline_patterns)
        or any(re.search(pattern, lowered) for pattern in http_patterns)
    )


def _has_behavior_demo_marker(command: str) -> bool:
    return bool(re.search(r"\bSENTINEL_BEHAVIOR_DEMO\s*=\s*(?:1|true|yes)\b", command, re.IGNORECASE))


def _marked_behavior_demo_command_is_plausible(command: str, changed_paths: list[str]) -> bool:
    if _is_read_only_inspection_command(command):
        return False
    if _is_observationless_output_command(command):
        return False
    if _is_direct_script_execution_command(command) or _is_stdin_script_demo_command(command):
        return True
    if _command_requires_changed_module(command, changed_paths):
        return True
    lowered = command.lower()
    if re.search(r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)", lowered):
        return True
    normalized_command = lowered.replace("\\", "/")
    for raw_path in changed_paths:
        path = raw_path.replace("\\", "/").lstrip("./").lower()
        if not path or _is_internal_runtime_path(path, project_root=None, task_path=None):
            continue
        name = path.rsplit("/", 1)[-1]
        stem = name.rsplit(".", 1)[0] if "." in name else name
        if path in normalized_command or (stem and len(stem) >= 3 and stem in normalized_command):
            return True
    return bool(re.search(r"(^|[\s;&|()'\"])(?:\.{1,2}/|/)[\w./-]+(?:\s|$)", lowered))


def _is_observationless_output_command(command: str) -> bool:
    segments = [segment.strip() for segment in re.split(r"\s*(?:&&|;|\|)\s*", command) if segment.strip()]
    if not segments:
        return False
    output_only = {"echo", "printf", "true", "false", "yes"}
    read_only_excerpt = {"cat", "sed", "grep", "egrep", "fgrep", "rg", "head", "tail", "nl", "ls", "wc", "pwd"}
    seen_executable = False
    for segment in segments:
        try:
            tokens = shlex.split(segment)
        except ValueError:
            return False
        while tokens and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*", tokens[0]):
            tokens = tokens[1:]
        if not tokens:
            continue
        executable = tokens[0].rsplit("/", 1)[-1].lower()
        seen_executable = True
        if executable not in output_only and executable not in read_only_excerpt:
            return False
    return seen_executable


def _is_stdin_script_demo_command(command: str) -> bool:
    lowered = command.lower()
    if "<<" not in lowered:
        return False
    python_flags = r"(?:\s+-(?!m(?:\s|$))[a-z][\w-]*(?:=[^\s;&|()'\"]+)?)"
    python_exec = r"(?:\.{0,2}/|/)?(?:[\w.-]+/)*python(?:3(?:\.\d+)?)?"
    interpreter_exec = r"(?:\.{0,2}/|/)?(?:[\w.-]+/)*(?:node(?:js)?|ruby|bash|sh|zsh)"
    patterns = (
        r"(^|[\s;&|()'\"])" + python_exec + python_flags + r"*\s+-?\s*<<",
        r"(^|[\s;&|()'\"])" + interpreter_exec + r"\s+-?\s*<<",
    )
    return any(re.search(pattern, lowered) for pattern in patterns)


def _command_requires_changed_module(command: str, changed_paths: list[str]) -> bool:
    lowered = command.lower()
    interpreter_exec = r"(?:\.{0,2}/|/)?(?:[\w.-]+/)*(?:node(?:js)?|python(?:3(?:\.\d+)?)?|ruby)"
    if not re.search(r"(^|[\s;&|()'\"])" + interpreter_exec + r"\s+(-e|-c|\S+)", lowered):
        return False
    if not re.search(r"\b(require|import|node|nodejs|python|python3|ruby)\b", lowered):
        return False
    normalized_command = lowered.replace("\\", "/")
    for raw_path in changed_paths:
        path = raw_path.replace("\\", "/").lstrip("./").lower()
        if not path or _is_internal_runtime_path(path, project_root=None, task_path=None):
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
    if existing.strip() == output.strip():
        merged = existing
    else:
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
        if key_text in {
            "delta",
            "output",
            "outputtext",
            "aggregatedoutput",
            "aggregated_output",
            "combinedoutput",
            "combined_output",
            "stdout",
            "stdouttext",
            "stdout_text",
            "stderr",
            "stderrtext",
            "stderr_text",
            "text",
            "content",
            "message",
            "chunk",
            "data",
        }:
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


def _stable_inspection_id(
    *,
    normalized_command: str,
    cwd: str | None,
    inspected_paths: list[str],
) -> str:
    payload = {
        "normalized_command": normalized_command,
        "cwd": cwd or "",
        "inspected_paths": sorted(dict.fromkeys(inspected_paths)),
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    return f"inspection-{digest[:16]}"


def _inspection_exit_is_usable(command: str, exit_code: int | None) -> bool:
    if exit_code == 0:
        return True
    if exit_code == 1 and re.search(r"(^|[\s;&|()'\"])(?:rg|grep|egrep|fgrep)\b", command.lower()):
        return True
    return False


def _validation_masking_reason(
    command: str,
    *,
    validation_type: str | None = None,
    changed_paths: list[str] | None = None,
) -> str | None:
    if (
        validation_type == "behavior_demo"
        and _has_behavior_demo_marker(command)
        and _marked_behavior_demo_command_is_plausible(command, changed_paths or [])
    ):
        return _marked_behavior_demo_masking_reason(command)
    return _generic_validation_masking_reason(command)


def _marked_behavior_demo_masking_reason(command: str) -> str | None:
    lowered = command.lower()
    pipeline_probe = lowered.replace("||", "")
    if "|" in pipeline_probe and "pipefail" not in lowered:
        return "pipeline_without_pipefail"
    if "||" in lowered and not re.search(r"\|\|\s*exit\s+1(\s|$)", lowered):
        return "logical_or_may_mask_validation_failure"
    if ("$(" in command or "`" in command) and not _shell_errexit_is_enabled(command):
        return "command_substitution_may_mask_failure"
    return None


def _generic_validation_masking_reason(command: str) -> str | None:
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


def _behavior_demo_output_masking_reason(output: str) -> str | None:
    if _captured_output_is_self_verdict_only(output):
        return "behavior_demo_self_verdict_only"
    if _captured_output_looks_like_test_runner(output):
        return "behavior_demo_looks_like_test_runner_output"
    return None


def _shell_errexit_is_enabled(command: str) -> bool:
    return bool(re.search(r"(^|[\s;&|()'\"])(?:set\s+-[a-z]*e[a-z]*|set\s+-o\s+errexit)\b", command.lower()))


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


def _test_files_from_output(output: str, *, limit: int = 100) -> list[str]:
    files: list[str] = []
    runner_patterns = (
        # Jest/Vitest style suite lines. Prefer these over the broad fallback so stack traces
        # through test helpers do not look like independently executed test files.
        r"(?m)^\s*(?:PASS|FAIL)\s+((?:\.{0,2}/)?[\w@+./-]+\.(?:py|js|jsx|ts|tsx|mjs|cjs|rb|go|rs|java|cs|php|vue|svelte|snap|snapshot|golden))\b",
        # Pytest verbose output.
        r"(?m)^\s*((?:\.{0,2}/)?[\w@+./-]+\.py)::[^\s]+\s+(?:PASSED|FAILED|SKIPPED|XFAIL|XPASS|ERROR)\b",
    )
    for pattern in runner_patterns:
        for match in re.finditer(pattern, output):
            path = _normalize_output_test_path(match.group(1))
            if path and _file_kind(path) == "test":
                files.append(path)
            if len(files) >= limit:
                return list(dict.fromkeys(files))[:limit]
    if files:
        return list(dict.fromkeys(files))[:limit]

    path_pattern = re.compile(
        r"(?<![\w./-])((?:\.{0,2}/)?[\w@+./-]*(?:test|spec|tests|__tests__|snapshots|__snapshots__|golden|goldens)"
        r"[\w@+./-]*\.(?:py|js|jsx|ts|tsx|mjs|cjs|rb|go|rs|java|cs|php|snap|snapshot|golden))"
        r"(?:::[\w.*\[\]-]+)?",
        re.IGNORECASE,
    )
    for match in path_pattern.finditer(output):
        path = _normalize_output_test_path(match.group(1))
        if path and _file_kind(path) == "test":
            files.append(path)
        if len(files) >= limit:
            break
    return list(dict.fromkeys(files))[:limit]


def _normalize_output_test_path(path: str) -> str:
    normalized = path.strip().strip("'\"`.,;:()[]{}<>")
    if "::" in normalized:
        normalized = normalized.split("::", 1)[0]
    return normalized.replace("\\", "/").lstrip("./")


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
        if key_text in {
            "output",
            "outputtext",
            "aggregatedoutput",
            "aggregated_output",
            "combinedoutput",
            "combined_output",
            "stdout",
            "stdouttext",
            "stdout_text",
            "stderr",
            "stderrtext",
            "stderr_text",
            "text",
            "content",
            "message",
            "summary",
        }:
            _collect_output_strings(nested, parts, depth=depth + 1)
        elif key_text in {"outputs", "chunks", "lines", "items", "result", "results"}:
            _collect_output_strings(nested, parts, depth=depth + 1)


def _has_passing_behavioral_validation(validations: list[ValidationRun]) -> bool:
    return any(
        _is_behavior_proving_validation(validation)
        and validation.outcome == "pass"
        and validation.passed
        and validation.trusted_validation_outcome == "passed"
        for validation in validations
    )


def _is_behavior_proving_validation(validation: ValidationRun) -> bool:
    return validation.type in {"behavioral", "behavior_demo"}


def _has_readiness_marker(text: str) -> bool:
    return bool(READINESS_MARKER_RE.search(text.strip()))


def _has_malformed_readiness_marker(text: str) -> bool:
    if _has_readiness_marker(text):
        return False
    if _readiness_reference_is_negated(text):
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


def _readiness_reference_is_negated(text: str) -> bool:
    lowered = " ".join(text.lower().split())
    marker = r"(?:sentinel[\s_`'\-]*ready[\s_`'\-]*for[\s_`'\-]*review|ready[\s_`'\-]*for[\s_`'\-]*review|readiness marker)"
    negator = r"(?:do not|don't|not|cannot|can't|will not|won't|without|no)"
    return bool(re.search(rf"\b{negator}\b.{{0,120}}\b{marker}\b", lowered))


def _reports_material_limitation(text: str) -> bool:
    lowered = " ".join(text.lower().split())
    markers = (
        "material limitation",
        "validation limitation",
        "independent behavioral evidence is still missing",
        "independent behavioral evidence is missing",
        "independent evidence is still missing",
        "independent evidence is missing",
        "no untouched output-identified",
        "no compliant next validation step",
        "no compliant validation step",
        "cannot provide independent",
        "can't provide independent",
        "not ready under the independent-evidence requirement",
    )
    return any(marker in lowered for marker in markers)


def _material_limitation_summary(text: str) -> str:
    lines = [line.strip(" `\t\r\n-*") for line in text.splitlines()]
    candidates = [line for line in lines if line]
    preferred_prefixes = ("material limitation", "validation limitation")
    for line in candidates:
        if line.lower().startswith(preferred_prefixes):
            return _truncate_summary(line)
    for line in candidates:
        lowered = line.lower()
        if (
            "independent" in lowered
            or "no untouched" in lowered
            or "no compliant" in lowered
            or "not ready" in lowered
        ):
            return _truncate_summary(line)
    return _truncate_summary(candidates[0] if candidates else "coder reported a material limitation")


def _truncate_summary(text: str, *, limit: int = 280) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1].rstrip() + "..."


def _appears_to_claim_readiness(text: str) -> bool:
    if _reports_material_limitation(text) or _readiness_reference_is_negated(text):
        return False
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


def _prior_record_counts_as_health_intervention(record: Any) -> bool:
    reason = str(getattr(record, "reason", "") or "")
    return not reason.startswith("Completion review returned:")


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
        if validation.type in {"behavioral", "behavior_demo"}
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
    if _is_generated_or_cache_artifact_path(path, project_root=None):
        return True
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
    missing_evidence_ids = [
        row.behavior
        for row in decision.behavior_evidence_matrix
        for evidence in row.evidence
        if (
            evidence.validation_type == "inspection"
            and (not evidence.inspection_id or evidence.validation_id)
        )
        or (
            evidence.validation_type != "inspection"
            and not evidence.validation_id
        )
        or (
            evidence.validation_id
            and evidence.inspection_id
        )
    ]
    if missing_evidence_ids:
        return (
            "behavior_evidence_matrix has evidence with missing or ambiguous validation_id/inspection_id: "
            + ", ".join(missing_evidence_ids[:5])
        )
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


def _is_evidence_id_structural_issue(reason: str | None) -> bool:
    return bool(reason and "missing or ambiguous validation_id/inspection_id" in reason)


def _accept_gate_failure_is_proof_format(gate_result: AcceptGateResult) -> bool:
    details = gate_result.details or {}
    return (
        gate_result.check_name == "evidence_id_repair"
        or details.get("kind") == "proof_format_evidence_id"
        or _is_evidence_id_structural_issue(gate_result.reason)
    )


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


def _completion_return_has_evidence_related_gap(decision: CompletionReviewDecision) -> bool:
    if decision.validation_gaps or decision.uncovered_behaviors or decision.claim_evidence_mismatches:
        return True
    return any(row.status != "covered" or row.gap for row in decision.behavior_evidence_matrix)


def _completion_decision_cites_evidence_after(
    decision: CompletionReviewDecision,
    *,
    since_sequence: int,
) -> bool:
    for row in decision.behavior_evidence_matrix:
        for evidence in row.evidence:
            if evidence.sequence is not None and evidence.sequence > since_sequence:
                return True
            for value in (evidence.validation_id, evidence.inspection_id):
                sequence = _ledger_id_sequence(value)
                if sequence is not None and sequence > since_sequence:
                    return True
    return False


def _fresh_delta_evidence_detail(
    packet: SupervisorWakePacket,
    *,
    since_sequence: int,
    validation_ids: set[str],
    inspection_ids: set[str],
) -> list[str]:
    details: list[str] = []
    for validation in packet.validations:
        if validation.sequence <= since_sequence or validation.validation_id not in validation_ids:
            continue
        output = _bounded_text(" ".join((validation.captured_output or validation.summary).split()), limit=220)
        details.append(
            (
                f"{validation.validation_id} seq={validation.sequence} type={validation.type} "
                f"command={_bounded_text(validation.command, limit=180)}"
                + (f" output={output}" if output else "")
            )
        )
    for inspection in packet.inspections:
        if inspection.sequence <= since_sequence or inspection.inspection_id not in inspection_ids:
            continue
        output = _bounded_text(" ".join((inspection.captured_output or inspection.summary).split()), limit=220)
        details.append(
            (
                f"{inspection.inspection_id} seq={inspection.sequence} type=inspection "
                f"command={_bounded_text(inspection.command, limit=180)}"
                + (f" output={output}" if output else "")
            )
        )
    return details[:20]


def _previous_completion_return_summary(records: list[Any], *, generation: int) -> list[str]:
    summaries: list[str] = []
    for record in records:
        if getattr(record, "generation", None) != generation:
            continue
        parts = [str(getattr(record, "reason", "") or "").strip()]
        for attr in ("uncovered_behaviors", "validation_gaps", "claim_evidence_mismatches"):
            values = getattr(record, attr, None) or []
            if values:
                parts.append(f"{attr}=" + "; ".join(str(value) for value in values[:5]))
        text = " | ".join(part for part in parts if part)
        if text:
            summaries.append(_bounded_text(text, limit=360))
    return summaries[-5:]


def _format_issue_list(value: Any) -> str:
    if not isinstance(value, list) or not value:
        return "none"
    return " || ".join(str(item) for item in value[:10])


def _classify_supervisor_agent_error(error: BaseException) -> str:
    text = str(error).lower()
    if "did not produce an agent message" in text or "no agent message" in text:
        return "no_message"
    if "rate limit" in text or "rate_limit" in text or "429" in text:
        return "rate"
    if "auth" in text or "unauthorized" in text or "forbidden" in text or "api key" in text:
        return "auth"
    if "timed out" in text or "timeout" in text:
        return "tool_timeout"
    return "unknown"


def _repair_completion_evidence_ids(
    decision: CompletionReviewDecision,
    *,
    validations: list[ValidationRun],
    inspections: list[InspectionRun],
) -> tuple[CompletionReviewDecision, list[str]]:
    data = decision.model_dump(mode="json")
    repairs: list[str] = []
    validation_ids = {validation.validation_id for validation in validations}
    inspection_ids = {inspection.inspection_id for inspection in inspections}
    for row in data.get("behavior_evidence_matrix") or []:
        behavior = str(row.get("behavior") or "<unnamed behavior>")
        for evidence in row.get("evidence") or []:
            validation_type = evidence.get("validation_type")
            if validation_type == "inspection":
                repaired = _repair_inspection_evidence_id(
                    evidence,
                    behavior=behavior,
                    inspections=inspections,
                    inspection_ids=inspection_ids,
                )
            else:
                repaired = _repair_validation_evidence_id(
                    evidence,
                    behavior=behavior,
                    validations=validations,
                    validation_ids=validation_ids,
                )
            if repaired:
                repairs.append(repaired)
    if not repairs:
        return decision, []
    return CompletionReviewDecision.model_validate(data), repairs


def _repair_inspection_evidence_id(
    evidence: dict[str, Any],
    *,
    behavior: str,
    inspections: list[InspectionRun],
    inspection_ids: set[str],
) -> str | None:
    validation_id = evidence.get("validation_id")
    inspection_id = evidence.get("inspection_id")
    if isinstance(inspection_id, str) and inspection_id in inspection_ids:
        if validation_id:
            evidence["validation_id"] = None
            return f"{behavior}: removed ambiguous validation_id from inspection evidence {inspection_id}"
        return None
    match = _unique_matching_inspection(evidence, inspections)
    if match is None:
        return None
    evidence["inspection_id"] = match.inspection_id
    evidence["validation_id"] = None
    return f"{behavior}: inspection_id={match.inspection_id}"


def _repair_validation_evidence_id(
    evidence: dict[str, Any],
    *,
    behavior: str,
    validations: list[ValidationRun],
    validation_ids: set[str],
) -> str | None:
    validation_id = evidence.get("validation_id")
    inspection_id = evidence.get("inspection_id")
    if isinstance(validation_id, str) and validation_id in validation_ids:
        if inspection_id:
            evidence["inspection_id"] = None
            return f"{behavior}: removed ambiguous inspection_id from validation evidence {validation_id}"
        return None
    match = _unique_matching_validation(evidence, validations)
    if match is None:
        return None
    evidence["validation_id"] = match.validation_id
    evidence["inspection_id"] = None
    return f"{behavior}: validation_id={match.validation_id}"


def _unique_matching_validation(evidence: dict[str, Any], validations: list[ValidationRun]) -> ValidationRun | None:
    command = str(evidence.get("command") or "")
    sequence = evidence.get("sequence")
    validation_type = evidence.get("validation_type")
    candidates: list[ValidationRun] = []
    for validation in validations:
        if isinstance(sequence, int) and validation.sequence != sequence:
            continue
        if validation_type in {"static", "behavioral", "behavior_demo"} and validation.type != validation_type:
            continue
        if command and _normalize_command(validation.command) != _normalize_command(command):
            continue
        candidates.append(validation)
    return candidates[0] if len(candidates) == 1 else None


def _unique_matching_inspection(evidence: dict[str, Any], inspections: list[InspectionRun]) -> InspectionRun | None:
    command = str(evidence.get("command") or "")
    sequence = evidence.get("sequence")
    candidates: list[InspectionRun] = []
    for inspection in inspections:
        if isinstance(sequence, int) and inspection.sequence != sequence:
            continue
        if command and _normalize_command(inspection.command) != _normalize_command(command):
            continue
        candidates.append(inspection)
    return candidates[0] if len(candidates) == 1 else None


def _ledger_id_sequence(value: str | None) -> int | None:
    if not value:
        return None
    match = re.fullmatch(r"(?:validation|inspection)-(\d+)", value)
    if not match:
        return None
    return int(match.group(1))


def _validation_is_fresh_behavioral_pass(validation: ValidationRun, latest_change: int) -> bool:
    return (
        validation.type in {"behavioral", "behavior_demo"}
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


def _inspection_is_fresh_pass(inspection: InspectionRun, latest_change: int | None) -> bool:
    if inspection.outcome != "pass" or not inspection.passed:
        return False
    if latest_change is None:
        return True
    return inspection.sequence > latest_change


def _row_allows_inspection_evidence(row: Any) -> bool:
    text_parts = [
        getattr(row, "behavior", "") or "",
        getattr(row, "task_basis", "") or "",
        getattr(row, "gap", "") or "",
    ]
    for evidence in getattr(row, "evidence", []) or []:
        text_parts.extend(
            [
                getattr(evidence, "command", "") or "",
                getattr(evidence, "why_it_covers_behavior", "") or "",
            ]
        )
    lowered = " ".join(text_parts).lower()
    static_markers = (
        "anti-hack",
        "anti hack",
        "anti-hacking",
        "source inspection",
        "static",
        "source constraint",
        "implementation constraint",
        "must not",
        "does not",
        "do not",
        "forbid",
        "forbidden",
        "no shell",
        "shell out",
        "subprocess",
        "system(",
        "exec",
        "network",
        "external service",
        "hidden",
        "private",
        "hardcod",
        "benchmark",
        "verifier",
        "harness",
        "fixture",
        "golden",
        "snapshot",
        "lockfile",
        "no sqlite",
    )
    behavior_markers = (
        "renders",
        "returns",
        "responds",
        "executes",
        "parses",
        "compiles",
        "handles",
        "persists",
        "updates",
        "calculates",
        "selects",
        "joins",
    )
    if any(marker in lowered for marker in static_markers):
        return True
    return "inspection" in lowered and not any(marker in lowered for marker in behavior_markers)


def _inspection_for_evidence(
    evidence: Any,
    *,
    inspections_by_id: dict[str, InspectionRun],
) -> InspectionRun | None:
    inspection_id = getattr(evidence, "inspection_id", None)
    if inspection_id:
        return inspections_by_id.get(inspection_id)
    return None


def _accept_evidence_binding_issue(
    decision: CompletionReviewDecision,
    validations: list[ValidationRun],
    inspections: list[InspectionRun],
    *,
    latest_change: int | None,
) -> EvidenceBindingIssue | None:
    by_id = {validation.validation_id: validation for validation in validations}
    inspections_by_id = {inspection.inspection_id: inspection for inspection in inspections}
    for row in decision.behavior_evidence_matrix:
        if row.status != "covered":
            continue
        fresh_pass_found = False
        linked_evidence_found = False
        ledger_record_found = False
        demo_quality_issue: EvidenceBindingIssue | None = None
        for evidence in row.evidence:
            if evidence.inspection_id or evidence.validation_type == "inspection":
                linked_evidence_found = True
                inspection = _inspection_for_evidence(
                    evidence,
                    inspections_by_id=inspections_by_id,
                )
                if inspection is None:
                    continue
                ledger_record_found = True
                inspection_id = evidence.inspection_id or inspection.inspection_id
                if evidence.validation_type != "inspection":
                    continue
                if not _row_allows_inspection_evidence(row):
                    return EvidenceBindingIssue(
                        reason=(
                            f"behavior '{row.behavior}' is covered by inspection_id {inspection_id}, "
                            "but inspection evidence only covers static/source constraints"
                        ),
                        kind="inspection_not_static_source",
                        behavior=row.behavior,
                        inspection_id=inspection_id,
                    )
                if _inspection_is_fresh_pass(inspection, latest_change):
                    fresh_pass_found = True
                    break
                continue
            if not evidence.validation_id:
                continue
            linked_evidence_found = True
            validation = by_id.get(evidence.validation_id or "")
            if validation is None:
                continue
            ledger_record_found = True
            if evidence.validation_type != validation.type:
                continue
            if validation.type == "behavior_demo":
                demo_issue = _behavior_demo_quality_issue(
                    validation,
                    latest_change=latest_change,
                    behavior=row.behavior,
                    evidence=evidence,
                )
                if demo_issue is not None:
                    demo_quality_issue = demo_issue
                    continue
            if _validation_is_fresh_pass(validation, latest_change):
                fresh_pass_found = True
                break
        if not fresh_pass_found:
            if not linked_evidence_found:
                return EvidenceBindingIssue(
                    reason=f"behavior '{row.behavior}' is covered but has no evidence linked by validation_id or inspection_id",
                    kind="missing_linked_evidence",
                    behavior=row.behavior,
                )
            type_mismatch = _evidence_type_mismatch(row.evidence, by_id, inspections_by_id)
            if type_mismatch:
                return EvidenceBindingIssue(
                    reason=f"behavior '{row.behavior}' evidence type mismatch: {type_mismatch}",
                    kind="type_mismatch",
                    behavior=row.behavior,
                )
            if demo_quality_issue:
                return demo_quality_issue
            demo_output_issue = _behavior_demo_output_issue(
                row.evidence,
                by_id,
                latest_change=latest_change,
                behavior=row.behavior,
            )
            if demo_output_issue:
                return demo_output_issue
            return EvidenceBindingIssue(
                reason=(
                    f"behavior '{row.behavior}' is covered but has no linked fresh passing validation "
                    "or allowed inspection record in the ledger"
                ),
                kind="no_fresh_linked_validation",
                behavior=row.behavior,
                coder_correctable=ledger_record_found,
            )
    return None


def _evidence_binding_issue_details(issue: EvidenceBindingIssue) -> dict[str, Any]:
    return {
        "kind": issue.kind,
        "behavior": issue.behavior,
        "validation_id": issue.validation_id,
        "inspection_id": issue.inspection_id,
        "validation_type": issue.validation_type,
        "command": issue.command,
        "artifact_evidence_required": issue.artifact_evidence_required,
        "coder_correctable": issue.coder_correctable,
        "bounded_coder_return_key": issue.bounded_coder_return_key,
    }


def _validation_has_captured_output(validation: ValidationRun) -> bool:
    return bool((validation.captured_output or "").strip())


def _behavior_demo_quality_issue(
    validation: ValidationRun,
    *,
    latest_change: int | None,
    behavior: str,
    evidence: Any,
) -> EvidenceBindingIssue | None:
    if not _validation_is_fresh_pass(validation, latest_change):
        return None
    if not _validation_has_captured_output(validation):
        artifact_required = _looks_like_artifact_generator_evidence(
            behavior=behavior,
            command=validation.command,
            evidence=evidence,
        )
        return EvidenceBindingIssue(
            reason=f"behavior '{behavior}' behavior_demo evidence {validation.validation_id} has no captured output",
            kind="behavior_demo_missing_output",
            behavior=behavior,
            validation_id=validation.validation_id,
            validation_type="behavior_demo",
            command=validation.command,
            artifact_evidence_required=artifact_required,
            coder_correctable=True,
            bounded_coder_return_key=f"behavior_demo_missing_output:{behavior}:{validation.validation_id}",
        )
    output_kind = _validation_output_kind(validation, captured_output_present=True)
    if output_kind == "factual_observation_candidate":
        return None
    if output_kind == "self_verdict_only":
        reason = (
            f"behavior '{behavior}' behavior_demo evidence {validation.validation_id} is only a "
            "self-verdict, not factual observed output/state"
        )
        kind = "behavior_demo_self_verdict_only"
    elif output_kind == "test_runner_output":
        reason = (
            f"behavior '{behavior}' behavior_demo evidence {validation.validation_id} looks like "
            "test-runner output, not a separate factual behavior observation"
        )
        kind = "behavior_demo_test_runner_output"
    else:
        reason = (
            f"behavior '{behavior}' behavior_demo evidence {validation.validation_id} has output "
            "that the controller cannot classify as factual observed output/state"
        )
        kind = "behavior_demo_unknown_output"
    return EvidenceBindingIssue(
        reason=reason,
        kind=kind,
        behavior=behavior,
        validation_id=validation.validation_id,
        validation_type="behavior_demo",
        command=validation.command,
        coder_correctable=True,
        bounded_coder_return_key=f"{kind}:{behavior}:{validation.validation_id}",
    )


def _behavior_demo_output_issue(
    evidence_items: list[Any],
    validations_by_id: dict[str, ValidationRun],
    *,
    latest_change: int | None,
    behavior: str,
) -> EvidenceBindingIssue | None:
    for evidence in evidence_items:
        if not evidence.validation_id:
            continue
        validation = validations_by_id.get(evidence.validation_id)
        if validation is None or evidence.validation_type != "behavior_demo" or validation.type != "behavior_demo":
            continue
        if not _validation_is_fresh_pass(validation, latest_change):
            continue
        if not _validation_has_captured_output(validation):
            artifact_required = _looks_like_artifact_generator_evidence(
                behavior=behavior,
                command=validation.command,
                evidence=evidence,
            )
            return EvidenceBindingIssue(
                reason=f"behavior '{behavior}' behavior_demo evidence {evidence.validation_id} has no captured output",
                kind="behavior_demo_missing_output",
                behavior=behavior,
                validation_id=evidence.validation_id,
                validation_type="behavior_demo",
                command=validation.command,
                artifact_evidence_required=artifact_required,
                coder_correctable=True,
                bounded_coder_return_key=f"behavior_demo_missing_output:{behavior}:{evidence.validation_id}",
            )
    return None


def _looks_like_artifact_generator_evidence(*, behavior: str, command: str | None, evidence: Any) -> bool:
    text_parts = [
        behavior or "",
        command or "",
        str(getattr(evidence, "command", "") or ""),
        str(getattr(evidence, "why_it_covers_behavior", "") or ""),
    ]
    lowered = " ".join(text_parts).lower()
    tokens = (
        "artifact",
        "generated",
        "generator",
        "generate",
        "regen",
        "transform",
        "docs",
        "doc/",
        "doc\\",
        "documentation",
        "asciidoc",
        "markdown",
        "snapshot",
        "golden",
    )
    return any(token in lowered for token in tokens)


def _evidence_type_mismatch(
    evidence_items: list[Any],
    validations_by_id: dict[str, ValidationRun],
    inspections_by_id: dict[str, InspectionRun],
) -> str | None:
    for evidence in evidence_items:
        if evidence.inspection_id:
            inspection = inspections_by_id.get(evidence.inspection_id)
            if inspection is None or evidence.validation_type == "inspection":
                continue
            return (
                f"{evidence.inspection_id} declares {evidence.validation_type} "
                "but inspection ledger requires inspection"
            )
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


def _self_confirming_test_evidence_issue(
    decision: CompletionReviewDecision,
    validations: list[ValidationRun],
    *,
    packet: SupervisorWakePacket | None,
    latest_change: int | None,
) -> dict[str, Any] | None:
    if packet is None:
        return None
    changed_test_files = _changed_test_files(packet.changed_files)
    if not changed_test_files:
        return None
    changed_test_identities = _changed_test_file_identity_map(changed_test_files)
    validations_by_id = {validation.validation_id: validation for validation in validations}
    behavior_issues: list[dict[str, Any]] = []
    for row in decision.behavior_evidence_matrix:
        if row.status != "covered":
            continue
        independent_found = False
        self_confirming_validations: list[dict[str, Any]] = []
        for evidence in row.evidence:
            validation = validations_by_id.get(evidence.validation_id or "")
            if validation is None or evidence.validation_type != validation.type:
                continue
            if not _validation_is_fresh_pass(validation, latest_change):
                continue
            if validation.type == "behavior_demo":
                output_kind = _validation_output_kind(
                    validation,
                    captured_output_present=_validation_has_captured_output(validation),
                )
                if output_kind == "factual_observation_candidate":
                    independent_found = True
                    break
                reason = {
                    "missing": "behavior_demo_missing_captured_output",
                    "self_verdict_only": "behavior_demo_self_verdict_only",
                    "test_runner_output": "behavior_demo_looks_like_test_runner_output",
                }.get(output_kind, "behavior_demo_output_not_factual")
                self_confirming_validations.append(
                    _self_confirming_validation_detail(
                        validation,
                        reason=reason,
                        test_files=[],
                        coder_authored_test_files=[],
                    )
                )
                continue
            if validation.type != "behavioral":
                continue
            executed_files = [_normalize_review_path(path) for path in validation.executed_test_files]
            if not executed_files:
                self_confirming_validations.append(
                    _self_confirming_validation_detail(
                        validation,
                        reason="unknown_test_file_provenance",
                        test_files=[],
                        coder_authored_test_files=[],
                    )
                )
                continue
            coder_authored_files, untouched_files = _partition_executed_test_files(
                executed_files,
                changed_test_identities=changed_test_identities,
            )
            if untouched_files:
                independent_found = True
                break
            self_confirming_validations.append(
                _self_confirming_validation_detail(
                    validation,
                    reason="only_coder_authored_tests",
                    test_files=executed_files,
                    coder_authored_test_files=coder_authored_files,
                )
            )
        if independent_found or not self_confirming_validations:
            continue
        behavior_issues.append(
            {
                "behavior": row.behavior,
                "requirement": "independent_evidence_binding",
                "coder_authored_test_files": changed_test_files,
                "self_confirming_validations": self_confirming_validations,
            }
        )
    if not behavior_issues:
        return None
    behaviors = ", ".join(issue["behavior"] for issue in behavior_issues[:5])
    return {
        "check_name": "self_confirming_test_evidence",
        "requirement": "independent_evidence_binding",
        "reason": (
            "covered behaviors have no linked fresh passing validation independent of coder-authored tests: "
            f"{behaviors}"
        ),
        "behaviors": behavior_issues,
        "required_evidence": (
            "Provide a linked fresh passing validation_id for an untouched pre-existing test whose output explicitly "
            "names the test file and exercises this behavior, or a behavior_demo validation with captured factual "
            "observed output/state for the task scenario."
        ),
    }


def _self_confirming_validation_detail(
    validation: ValidationRun,
    *,
    reason: str,
    test_files: list[str],
    coder_authored_test_files: list[str],
) -> dict[str, Any]:
    return {
        "validation_id": validation.validation_id,
        "command": validation.command,
        "sequence": validation.sequence,
        "reason": reason,
        "test_files": list(dict.fromkeys(test_files)),
        "coder_authored_test_files": list(dict.fromkeys(coder_authored_test_files)),
    }


def _coder_authored_test_surfaces(packet: SupervisorWakePacket) -> list[dict[str, Any]]:
    surfaces: dict[str, dict[str, Any]] = {}

    def add(path: str, reason: str) -> None:
        normalized = _normalize_review_path(path)
        if not normalized or _file_kind(normalized) != "test":
            return
        current = surfaces.setdefault(normalized, {"path": normalized, "reasons": []})
        if reason not in current["reasons"]:
            current["reasons"].append(reason)

    for changed in packet.changed_file_diffs:
        if changed.file_kind != "test":
            continue
        if changed.change_kind == "added":
            add(changed.path, "added test file or snapshot")
            continue
        if _is_snapshot_path(changed.path) and changed.change_kind in {"modified", "renamed"}:
            add(changed.path, "modified snapshot/golden")
            continue
        if changed.change_kind in {"modified", "renamed"}:
            added_assertions = _substantive_added_test_assertion_lines(changed.diff)
            if added_assertions:
                add(changed.path, f"added substantive test assertion: {added_assertions[0]}")

    diff_paths = {_normalize_review_path(changed.path) for changed in packet.changed_file_diffs}
    for changed in packet.changed_files:
        path = _normalize_review_path(changed.path)
        if path in diff_paths or _file_kind(path) != "test":
            continue
        change_kind = _change_kind(changed.status)
        if change_kind == "added":
            add(path, "added test file or snapshot")
        elif _is_snapshot_path(path) and change_kind in {"modified", "renamed"}:
            add(path, "modified snapshot/golden")

    return list(surfaces.values())


def _relevant_coder_authored_test_surfaces(
    row: Any,
    surfaces: list[dict[str, Any]],
    changed_files: list[ChangedFile],
) -> list[dict[str, Any]]:
    source_paths = _source_paths_for_behavior(row, changed_files)
    relevant: list[dict[str, Any]] = []
    for surface in surfaces:
        path = surface.get("path")
        if isinstance(path, str) and _test_surface_matches_source_paths(path, source_paths):
            relevant.append(surface)
    return relevant


def _source_paths_for_behavior(row: Any, changed_files: list[ChangedFile]) -> list[str]:
    source_paths = [
        _normalize_review_path(path)
        for path in getattr(row, "files_considered", []) or []
        if _file_kind(path) == "source"
    ]
    if not source_paths:
        source_paths = [
            _normalize_review_path(changed.path)
            for changed in changed_files
            if _file_kind(changed.path) == "source"
        ]
    return list(dict.fromkeys(source_paths))


def _test_surface_matches_source_paths(test_path: str, source_paths: list[str]) -> bool:
    if not source_paths:
        return False
    test_tokens = _path_match_tokens(test_path, include_parent_for_generic=True)
    for source_path in source_paths:
        source_tokens = _path_match_tokens(source_path, include_parent_for_generic=True)
        if _token_sets_match(test_tokens, source_tokens):
            return True
    return False


def _test_file_is_coder_authored_for_behavior(test_file: str, relevant_surfaces: list[dict[str, Any]]) -> bool:
    normalized = _normalize_review_path(test_file)
    test_tokens = _path_match_tokens(normalized, include_parent_for_generic=True)
    for surface in relevant_surfaces:
        surface_path = surface.get("path")
        if not isinstance(surface_path, str):
            continue
        if normalized == _normalize_review_path(surface_path):
            return True
        if _is_snapshot_path(surface_path) and _token_sets_match(
            test_tokens,
            _path_match_tokens(surface_path, include_parent_for_generic=True),
        ):
            return True
    return False


def _token_sets_match(left: set[str], right: set[str]) -> bool:
    if left & right:
        return True
    for left_token in left:
        for right_token in right:
            if len(left_token) >= 5 and len(right_token) >= 5 and (
                left_token in right_token or right_token in left_token
            ):
                return True
    return False


def _path_match_tokens(path: str, *, include_parent_for_generic: bool) -> set[str]:
    normalized = _normalize_review_path(path).lower()
    parts = [part for part in normalized.split("/") if part]
    if not parts:
        return set()
    name = parts[-1]
    stem = _strip_test_path_extensions(name)
    raw_parts = [part for part in re.split(r"[^a-z0-9]+", stem) if part]
    generic = {"test", "tests", "spec", "specs", "case", "cases", "snapshot", "snap", "golden", "goldens"}
    semantic_parts = [part for part in raw_parts if part not in generic]
    tokens = {_compact_identifier("".join(semantic_parts))} if semantic_parts else set()
    tokens.update(_compact_identifier(part) for part in semantic_parts if len(part) >= 2)
    if include_parent_for_generic and (not semantic_parts or semantic_parts in (["index"], ["main"])):
        for parent in reversed(parts[:-1]):
            parent_token = _compact_identifier(parent)
            if parent_token and parent_token not in generic:
                tokens.add(parent_token)
                break
    return {token for token in tokens if token}


def _strip_test_path_extensions(name: str) -> str:
    stem = name
    suffixes = (
        ".snapshot",
        ".golden",
        ".snap",
        ".tsx",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".js",
        ".py",
        ".rb",
        ".go",
        ".rs",
        ".java",
        ".cs",
        ".php",
        ".vue",
        ".svelte",
        ".html",
        ".css",
        ".scss",
    )
    changed = True
    while changed:
        changed = False
        lowered = stem.lower()
        for suffix in suffixes:
            if lowered.endswith(suffix):
                stem = stem[: -len(suffix)]
                changed = True
                break
    return re.sub(r"(?i)(?:^|[._-])(test|tests|spec|specs|case|cases|snapshot|snap|golden|goldens)$", "", stem)


def _compact_identifier(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _is_snapshot_path(path: str) -> bool:
    normalized = _normalize_review_path(path).lower()
    name = normalized.rsplit("/", 1)[-1]
    return (
        "/snapshots/" in normalized
        or "/__snapshots__/" in normalized
        or "/goldens/" in normalized
        or name.endswith((".snap", ".snapshot", ".golden"))
        or ".snap." in name
        or ".snapshot." in name
        or ".golden." in name
    )


def _substantive_added_test_assertion_lines(diff: str, *, limit: int = 5) -> list[str]:
    lines: list[str] = []
    for raw in diff.splitlines():
        if not raw.startswith("+") or raw.startswith("+++"):
            continue
        line = raw[1:].strip()
        if not _is_added_test_assertion_line(line):
            continue
        lines.append(_bounded_text(line, limit=180))
        if len(lines) >= limit:
            break
    return lines


def _is_added_test_assertion_line(line: str) -> bool:
    if not line or line.startswith(("//", "/*", "*", "import ")):
        return False
    lowered = line.lower()
    tokens = (
        "assert",
        "expect(",
        ".tobe",
        ".toequal",
        ".tocontain",
        ".tomatch",
        "tomatchsnapshot",
        "it(",
        "it.each",
        "test(",
        "test.each",
        "case(",
        "cases",
        "parametrize",
    )
    return any(token in lowered for token in tokens)


def _completion_accept_rejection_decision(
    decision: CompletionReviewDecision,
    reason: str,
    *,
    check_name: str = "accept_gate",
    details: dict[str, Any] | None = None,
) -> CompletionReviewDecision:
    validation_gaps = list(decision.validation_gaps)
    if check_name == "self_confirming_test_evidence" and details:
        validation_gaps.extend(_self_confirming_validation_gaps(details, fallback_reason=reason))
        message_to_coder = _self_confirming_message_to_coder(details, fallback_reason=reason)
    elif (
        check_name == "evidence_binding"
        and details
        and str(details.get("kind") or "").startswith("behavior_demo_")
    ):
        validation_gaps.extend(_evidence_binding_validation_gaps(details, fallback_reason=reason))
        message_to_coder = _evidence_binding_message_to_coder(details, fallback_reason=reason)
    elif check_name == "changed_test_masking":
        validation_gaps.append(f"Controller accept-gate rejection (changed_test_masking): {reason}")
        issues = []
        if isinstance(details, dict):
            issues = [str(issue) for issue in details.get("issues", []) if issue]
        lines = [
            "Continue working. Completion accept was rejected because a changed test appears to mask validation.",
        ]
        if issues:
            lines.append("Masked changed-test diff signals:")
            lines.extend(f"- {issue}" for issue in issues[:6])
        else:
            lines.append(f"Gate reason: {reason}")
        lines.append(
            "Restore a meaningful test check or remove the skip/trivial/no-op change, rerun trusted validation, "
            "then use the exact readiness marker on its own line."
        )
        message_to_coder = _bounded_text("\n".join(lines), limit=3000)
    else:
        validation_gaps.append(f"Controller accept-gate rejection ({check_name}): {reason}")
        message_to_coder = (
            "Continue working. Completion accept was rejected by the deterministic accept gate because "
            f"{reason}. Provide the missing fresh validation evidence, then use the exact readiness marker "
            "on its own line."
        )
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
        message_to_coder=message_to_coder,
        persistent_decision=decision.persistent_decision,
        progress_update=None,
        clear_handoff=decision.clear_handoff,
        display_message=decision.display_message,
        handoff=None,
        wake_sequence=decision.wake_sequence,
        generation=decision.generation,
    )


def _accept_gate_rejection_context(gate_result: AcceptGateResult) -> dict[str, Any]:
    return {
        "check_name": gate_result.check_name,
        "failure_type": gate_result.failure_type,
        "reason": gate_result.reason,
        "details": gate_result.details or {},
    }


def _completion_gate_followup_summary(context: dict[str, Any]) -> str:
    check_name = str(context.get("check_name") or "accept_gate")
    reason = str(context.get("reason") or "completion accept was rejected by deterministic accept gate")
    if check_name == "self_confirming_test_evidence":
        details = context.get("details") if isinstance(context.get("details"), dict) else {}
        behaviors = [
            str(item.get("behavior"))
            for item in details.get("behaviors", [])
            if isinstance(item, dict) and item.get("behavior")
        ]
        behavior_text = "; ".join(behaviors[:5]) or "covered behavior"
        return (
            "Coder provided exact readiness marker after deterministic accept-gate return. "
            f"Previous gate rejection: self_confirming_test_evidence failed for {behavior_text}. "
            "Find an independent validation in the ledger: an untouched test explicitly named in output, "
            "or a behavior_demo with factual captured output/state; compare that output to task_contents "
            "and bind accepted behavior_evidence_matrix rows to its validation_id before accepting."
        )
    if check_name == "evidence_binding":
        return (
            "Coder provided exact readiness marker after deterministic accept-gate return. "
            f"Previous gate rejection: evidence_binding failed: {reason}. Repair the "
            "behavior_evidence_matrix: each covered behavior must cite a validation_id present in the "
            "ledger with matching validation_type and a fresh passing trusted outcome. If no ledger "
            "validation actually covers the behavior, return to the coder with the concrete validation gap."
        )
    return (
        "Coder provided exact readiness marker after deterministic accept-gate return. "
        f"Previous gate rejection: {check_name} failed: {reason}."
    )


def _evidence_binding_validation_gaps(details: dict[str, Any], *, fallback_reason: str) -> list[str]:
    behavior = str(details.get("behavior") or "<unnamed behavior>")
    validation_id = str(details.get("validation_id") or "<unknown validation>")
    kind = str(details.get("kind") or "")
    if details.get("artifact_evidence_required"):
        return [
            (
                f"behavior '{behavior}' is bound to {validation_id}, but that behavior_demo has no captured "
                "produced-artifact output; provide full artifact diff or all objective changed hunks"
            )
        ]
    if kind == "behavior_demo_self_verdict_only":
        return [
            (
                f"behavior '{behavior}' is bound to {validation_id}, but that behavior_demo is only "
                "PASS/OK/self-verdict output instead of factual observed output/state"
            )
        ]
    if kind == "behavior_demo_test_runner_output":
        return [
            (
                f"behavior '{behavior}' is bound to {validation_id}, but that behavior_demo looks like "
                "test-runner output instead of a separate factual behavior observation"
            )
        ]
    return [
        (
            f"behavior '{behavior}' is bound to {validation_id}, but that behavior_demo has no captured "
            f"factual output/state: {fallback_reason}"
        )
    ]


def _evidence_binding_message_to_coder(details: dict[str, Any], *, fallback_reason: str) -> str:
    behavior = str(details.get("behavior") or "<unnamed behavior>")
    validation_id = str(details.get("validation_id") or "<unknown validation>")
    command = str(details.get("command") or "<unknown command>")
    lines = [
        "Continue working. Completion accept was rejected by the deterministic accept gate evidence_binding.",
        f"Behavior missing usable evidence: {behavior}",
        f"Invalid evidence: {validation_id} from command `{command}` is not a usable behavior_demo.",
    ]
    if details.get("artifact_evidence_required"):
        lines.append(
            "For generated/docs/static artifact behavior, produce raw artifact evidence by rerunning the "
            "generator/transform step and capturing the produced artifact as a full diff. If the full diff is "
            "too large, capture all changed hunks selected by the diff itself. Do not provide a hand-picked "
            "grep/sed snippet, PASS/OK, or a narrative conclusion as the evidence."
        )
    else:
        lines.append(
            "Provide a behavior_demo with raw factual observed output/state for this behavior, such as rendered "
            "DOM, a function return value, CLI output for scenario inputs, or an HTTP response body. Do not use "
            "a bare PASS/OK/self-verdict or a wrapper around changed tests as the demo."
        )
    lines.append(f"Gate reason: {fallback_reason}")
    lines.append("Then use the exact readiness marker on its own line.")
    return _bounded_text("\n".join(lines), limit=3000)


def _self_confirming_validation_gaps(details: dict[str, Any], *, fallback_reason: str) -> list[str]:
    behaviors = details.get("behaviors")
    if not isinstance(behaviors, list) or not behaviors:
        return [f"Controller accept-gate rejection (self_confirming_test_evidence): {fallback_reason}"]
    gaps: list[str] = []
    for behavior in behaviors:
        if not isinstance(behavior, dict):
            continue
        name = str(behavior.get("behavior") or "<unnamed behavior>")
        validation_ids = _validation_ids_from_self_confirming_behavior(behavior)
        files = _test_files_from_self_confirming_behavior(behavior)
        detail = f"behavior '{name}' lacks independent_evidence_binding"
        if validation_ids:
            detail += f"; self-confirming validation_ids: {', '.join(validation_ids[:8])}"
        if files:
            detail += f"; coder-authored/unknown-provenance test files: {', '.join(files[:8])}"
        gaps.append(detail)
    return gaps or [f"Controller accept-gate rejection (self_confirming_test_evidence): {fallback_reason}"]


def _self_confirming_message_to_coder(details: dict[str, Any], *, fallback_reason: str) -> str:
    lines = [
        "Continue working. Completion accept was rejected by the deterministic accept gate "
        "self_confirming_test_evidence.",
    ]
    behaviors = details.get("behaviors")
    if isinstance(behaviors, list) and behaviors:
        lines.append("Behaviors without independent evidence:")
        for behavior in behaviors[:8]:
            if not isinstance(behavior, dict):
                continue
            name = str(behavior.get("behavior") or "<unnamed behavior>")
            validation_ids = _validation_ids_from_self_confirming_behavior(behavior)
            commands = _commands_from_self_confirming_behavior(behavior)
            files = _test_files_from_self_confirming_behavior(behavior)
            parts = [name]
            if validation_ids:
                parts.append(f"validation_ids={', '.join(validation_ids[:5])}")
            if files:
                parts.append(f"test_files={', '.join(files[:5])}")
            if commands:
                parts.append(f"commands={'; '.join(commands[:3])}")
            lines.append("- " + " | ".join(parts))
    else:
        lines.append(f"Reason: {fallback_reason}")
    lines.append(
        "Provide independent confirmation for each behavior: either an untouched pre-existing test whose output "
        "explicitly names the test file and exercises this code, or a behavior_demo command that prints factual "
        "observed output/state for the task scenario. Do not use a bare PASS/OK/self-verdict or a wrapper around "
        "your changed tests as the demo. Then use the exact readiness marker on its own line."
    )
    return _bounded_text("\n".join(lines), limit=3000)


def _validation_ids_from_self_confirming_behavior(behavior: dict[str, Any]) -> list[str]:
    return list(
        dict.fromkeys(
            str(item.get("validation_id"))
            for item in behavior.get("self_confirming_validations", [])
            if isinstance(item, dict) and item.get("validation_id")
        )
    )


def _commands_from_self_confirming_behavior(behavior: dict[str, Any]) -> list[str]:
    return list(
        dict.fromkeys(
            str(item.get("command"))
            for item in behavior.get("self_confirming_validations", [])
            if isinstance(item, dict) and item.get("command")
        )
    )


def _test_files_from_self_confirming_behavior(behavior: dict[str, Any]) -> list[str]:
    files: list[str] = []
    for item in behavior.get("self_confirming_validations", []):
        if not isinstance(item, dict):
            continue
        for key in ("coder_authored_test_files", "test_files"):
            value = item.get(key)
            if isinstance(value, list):
                files.extend(str(path) for path in value if path)
    for surface in behavior.get("coder_authored_test_surfaces", []):
        if isinstance(surface, dict) and surface.get("path"):
            files.append(str(surface["path"]))
    return list(dict.fromkeys(files))


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


def _changed_test_masking_issues(packet: SupervisorWakePacket) -> list[str]:
    issues: list[str] = []
    for changed in packet.changed_file_diffs:
        if changed.file_kind != "test" or changed.change_kind not in {"added", "modified", "renamed"}:
            continue
        for line, reason in _added_test_masking_lines(changed.diff):
            issues.append(f"{changed.path}: {reason}: {line}")
            if len(issues) >= 10:
                return issues
        removed_assertions = _removed_test_assertion_lines(changed.diff)
        added_assertions = [
            line
            for line in _substantive_added_test_assertion_lines(changed.diff)
            if not _is_trivially_true_test_assertion(line)
        ]
        if removed_assertions and not added_assertions:
            issues.append(f"{changed.path}: removed assertion without meaningful replacement: {removed_assertions[0]}")
            if len(issues) >= 10:
                return issues
    return issues


def _added_test_masking_lines(diff: str) -> list[tuple[str, str]]:
    lines: list[tuple[str, str]] = []
    for raw_line in diff.splitlines():
        if not raw_line.startswith("+") or raw_line.startswith("+++"):
            continue
        line = raw_line[1:].strip()
        if not line:
            continue
        if _is_test_skip_line(line):
            lines.append((_bounded_text(line, limit=180), "added skipped/todo test marker"))
        elif _is_trivially_true_test_assertion(line):
            lines.append((_bounded_text(line, limit=180), "added trivially true assertion"))
        elif _is_noop_test_body_line(line):
            lines.append((_bounded_text(line, limit=180), "added no-op test body"))
    return lines


def _removed_test_assertion_lines(diff: str, *, limit: int = 5) -> list[str]:
    lines: list[str] = []
    for raw_line in diff.splitlines():
        if not raw_line.startswith("-") or raw_line.startswith("---"):
            continue
        line = raw_line[1:].strip()
        if not _is_test_assertion_like(line):
            continue
        lines.append(_bounded_text(line, limit=180))
        if len(lines) >= limit:
            break
    return lines


def _is_test_assertion_like(line: str) -> bool:
    lowered = line.lower()
    return any(
        token in lowered
        for token in (
            "assert",
            "expect(",
            ".should",
            ".tobe",
            ".toequal",
            ".tocontain",
            ".tomatch",
            "equal(",
            "strictequal",
            "throws",
            "rejects",
        )
    )


def _is_test_skip_line(line: str) -> bool:
    lowered = line.lower()
    return bool(
        re.search(r"\b(?:it|test|describe|context)\.skip\s*\(", lowered)
        or re.search(r"\bx(?:it|test|describe|context)\s*\(", lowered)
        or re.search(r"\btest\.todo\s*\(", lowered)
        or "pytest.mark.skip" in lowered
        or lowered.startswith("@unittest.skip")
    )


def _is_trivially_true_test_assertion(line: str) -> bool:
    compact = re.sub(r"[\s;]+", "", line.lower())
    trivial_patterns = (
        r"^asserttrue$",
        r"^assert\(true\)$",
        r"^assert1==1$",
        r"^assert\(1==1\)$",
        r"^assert\.equal\(1,1\)$",
        r"^assert\.strictequal\(1,1\)$",
        r"^expect\(true\)\.tobe\(true\)$",
        r"^expect\(true\)\.toequal\(true\)$",
        r"^expect\(1\)\.tobe\(1\)$",
        r"^expect\(1\)\.toequal\(1\)$",
    )
    return any(re.search(pattern, compact) for pattern in trivial_patterns)


def _is_noop_test_body_line(line: str) -> bool:
    compact = re.sub(r"\s+", "", line.lower().rstrip(";"))
    return compact in {"pass", "return", "returntrue"}


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
        or re.search(r"(?:^|[._-])(test|tests|spec|specs|case|cases)(?:\.[^.]+)+$", name)
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
    if _is_generated_or_cache_artifact_path(path, project_root=None):
        return False
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


def _ensure_internal_runtime_git_excluded(project_root: Path) -> None:
    git_dir = project_root / ".git"
    if not git_dir.is_dir():
        return
    info_dir = git_dir / "info"
    exclude_path = info_dir / "exclude"
    try:
        info_dir.mkdir(parents=True, exist_ok=True)
        current = exclude_path.read_text(encoding="utf-8") if exclude_path.exists() else ""
        entries = {line.strip() for line in current.splitlines()}
        additions = [entry for entry in (".supervisor/", ".supervisor") if entry not in entries]
        if additions:
            suffix = "" if current.endswith("\n") or not current else "\n"
            exclude_path.write_text(current + suffix + "\n".join(additions) + "\n", encoding="utf-8")
    except OSError:
        return


def _diff_line_counts(changed_files: list[ChangedFile]) -> tuple[int, int]:
    additions = sum(changed.additions or 0 for changed in changed_files)
    deletions = sum(changed.deletions or 0 for changed in changed_files)
    return additions, deletions


def _breadth_risk_summary(*, task_contents: str, changed_files: list[ChangedFile]) -> BreadthRiskSummary:
    task_lines = [line for line in task_contents.splitlines() if line.strip()]
    lowered = task_contents.lower()
    requirement_hint_count = sum(
        1
        for line in task_lines
        if re.search(
            r"\b(must|should|support|implement|handle|include|including|ensure|preserve|compatib|require|allow|prevent)\b",
            line,
            re.IGNORECASE,
        )
        or re.match(r"\s*[-*]\s+", line)
    )
    feature_terms = [
        term
        for term in BREADTH_FEATURE_TERMS
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(term)}s?(?![A-Za-z0-9_])", lowered)
    ]
    additions, deletions = _diff_line_counts(changed_files)
    changed_source_files = [changed for changed in changed_files if _file_kind(changed.path) == "source"]
    changed_lines = additions + deletions
    flags: list[str] = []
    if len(task_contents) >= 2500 or len(task_lines) >= 45 or requirement_hint_count >= 10 or len(feature_terms) >= 10:
        flags.append("task_spec_appears_broad")
    if len(changed_source_files) >= 4 or changed_lines >= LARGE_DIFF_CHANGED_LINES_THRESHOLD:
        flags.append("implementation_diff_is_broad")
    if len(feature_terms) >= 8:
        flags.append("many_task_feature_terms")
    suggested_min = 0
    if flags:
        suggested_min = 6
        if len(task_contents) >= 6000 or requirement_hint_count >= 18 or len(feature_terms) >= 16:
            suggested_min = 8
    return BreadthRiskSummary(
        flags=flags,
        task_line_count=len(task_lines),
        requirement_hint_count=requirement_hint_count,
        task_feature_terms=feature_terms,
        changed_source_files_count=len(changed_source_files),
        changed_lines=changed_lines,
        suggested_min_behavior_rows=suggested_min,
    )


def _has_large_diff(changed_files: list[ChangedFile]) -> bool:
    additions, deletions = _diff_line_counts(changed_files)
    return (
        len(changed_files) >= LARGE_DIFF_CHANGED_FILES_THRESHOLD
        or additions + deletions >= LARGE_DIFF_CHANGED_LINES_THRESHOLD
    )


def _large_diff_signature(changed_files: list[ChangedFile]) -> str:
    payload = [
        {
            "path": changed.path,
            "status": changed.status,
            "additions": changed.additions,
            "deletions": changed.deletions,
        }
        for changed in sorted(changed_files, key=lambda item: item.path)
    ]
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    return digest[:16]


def _action_timed_out(action: TriggeringAction) -> bool:
    text = " ".join(part for part in (action.status, action.summary) if part).lower()
    return "timeout" in text or "timed out" in text


def _is_file_change_activity(action: TriggeringAction) -> bool:
    if action.command:
        return False
    kind = action.kind.lower()
    summary = action.summary.lower()
    return kind in {"filechange", "file_change", "file-change"} or (
        bool(action.paths) and "file" in summary and "change" in summary
    )


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
        captured_output=validation.captured_output,
        output_truncated=validation.summary.endswith("...<truncated>") or validation.captured_output_truncated,
        detected_test_names=_detect_test_names(validation.summary),
        target_files_or_test_files=validation.target_files_or_test_files
        or _target_files_or_test_files(validation.command),
        was_filtered=validation.was_filtered,
        raw_selector=validation.raw_selector,
        executed_test_names=validation.executed_test_names,
        executed_test_files=validation.executed_test_files,
        passed_count=validation.passed_count,
        failed_count=validation.failed_count,
    )


def _completion_delta_evidence_summary(
    validations: list[ValidationRun],
    inspections: list[InspectionRun],
    *,
    since_sequence: int | None,
) -> list[str]:
    if since_sequence is None:
        return []
    items: list[str] = []
    for validation in validations:
        items.append(
            (
                f"validation {validation.validation_id} seq={validation.sequence} "
                f"type={validation.type} outcome={validation.trusted_validation_outcome} "
                f"command={_bounded_text(validation.command, limit=160)}"
            )
        )
    for inspection in inspections:
        outcome = "passed" if inspection.passed and inspection.outcome == "pass" else "failed"
        items.append(
            (
                f"inspection {inspection.inspection_id} seq={inspection.sequence} "
                f"outcome={outcome} command={_bounded_text(inspection.command, limit=160)}"
            )
        )
    if not items:
        return [f"No validation or inspection records after return baseline sequence {since_sequence}."]
    return items[:30]


def _inspection_output(inspection: InspectionRun) -> InspectionOutput:
    return InspectionOutput(
        inspection_id=inspection.inspection_id,
        command=inspection.command,
        raw_command=inspection.raw_command,
        normalized_command=inspection.normalized_command,
        cwd=inspection.cwd,
        exit_code=inspection.exit_code,
        shell_exit_code=inspection.shell_exit_code,
        outcome=inspection.outcome,
        passed=inspection.passed,
        sequence=inspection.sequence,
        stdout_or_summary=inspection.summary,
        captured_output=inspection.captured_output,
        output_truncated=inspection.summary.endswith("...<truncated>") or inspection.captured_output_truncated,
        inspected_paths=inspection.inspected_paths,
    )


def _evidence_provenance_summary(
    *,
    validations: list[ValidationRun],
    changed_files: list[ChangedFile],
    latest_change_sequence: int | None,
) -> EvidenceProvenanceSummary:
    changed_test_files = _changed_test_files(changed_files)
    return EvidenceProvenanceSummary(
        latest_relevant_change_sequence=latest_change_sequence,
        changed_test_files=changed_test_files,
        validations=[
            _validation_provenance(
                validation,
                changed_test_files=changed_test_files,
                latest_change_sequence=latest_change_sequence,
            )
            for validation in validations[-VALIDATION_LEDGER_LIMIT:]
        ],
    )


def _changed_test_files(changed_files: list[ChangedFile]) -> list[str]:
    files = [
        _normalize_review_path(changed.path)
        for changed in changed_files
        if _file_kind(changed.path) == "test"
    ]
    return list(dict.fromkeys(path for path in files if path))


def _changed_test_file_identity_map(changed_test_files: list[str]) -> dict[str, str]:
    identities: dict[str, str] = {}
    for path in changed_test_files:
        identity = _canonical_test_file_identity(path)
        if identity and identity not in identities:
            identities[identity] = path
    return identities


def _partition_executed_test_files(
    executed_files: list[str],
    *,
    changed_test_identities: dict[str, str],
) -> tuple[list[str], list[str]]:
    coder_authored_files: list[str] = []
    untouched_files: list[str] = []
    for path in executed_files:
        identity = _canonical_test_file_identity(path)
        changed_path = changed_test_identities.get(identity)
        if changed_path:
            coder_authored_files.append(changed_path)
        else:
            untouched_files.append(path)
    return list(dict.fromkeys(coder_authored_files)), list(dict.fromkeys(untouched_files))


def _canonical_test_file_identity(path: str) -> str:
    normalized = _normalize_review_path(path)
    if not normalized:
        return ""
    parts = [part for part in normalized.split("/") if part]
    if not parts:
        return ""
    name = parts[-1]
    stem = _strip_test_path_extensions(name)
    if not stem:
        stem = name
    prefix = "/".join(parts[:-1])
    identity = f"{prefix}/{stem}" if prefix else stem
    return identity.lower()


def _validation_provenance(
    validation: ValidationRun,
    *,
    changed_test_files: list[str],
    latest_change_sequence: int | None,
) -> ValidationProvenance:
    executed_files = list(dict.fromkeys(_normalize_review_path(path) for path in validation.executed_test_files if path))
    coder_authored_files, untouched_files = _partition_executed_test_files(
        executed_files,
        changed_test_identities=_changed_test_file_identity_map(changed_test_files),
    )
    captured_output = validation.captured_output or ""
    captured_output_present = bool(captured_output.strip())
    fresh = None if latest_change_sequence is None else validation.sequence > latest_change_sequence
    output_kind = _validation_output_kind(validation, captured_output_present=captured_output_present)
    independence_class, risk_reasons = _validation_independence(
        validation,
        fresh_after_latest_relevant_change=fresh,
        captured_output_present=captured_output_present,
        output_kind=output_kind,
        executed_test_files=executed_files,
        coder_authored_test_files=coder_authored_files,
        untouched_executed_test_files=untouched_files,
    )
    return ValidationProvenance(
        validation_id=validation.validation_id,
        command=validation.command,
        type=validation.type,
        passed=validation.outcome == "pass" and validation.passed,
        trusted_validation_outcome=validation.trusted_validation_outcome,
        sequence=validation.sequence,
        fresh_after_latest_relevant_change=fresh,
        captured_output_present=captured_output_present,
        output_identifies_test_files=bool(executed_files),
        executed_test_files=executed_files,
        coder_authored_test_files=coder_authored_files,
        untouched_executed_test_files=untouched_files,
        target_files_or_test_files=validation.target_files_or_test_files
        or _target_files_or_test_files(validation.command),
        output_kind=output_kind,
        independence_class=independence_class,
        risk_reasons=risk_reasons,
    )


def _validation_output_kind(
    validation: ValidationRun,
    *,
    captured_output_present: bool,
) -> str:
    if validation.type == "static":
        return "not_applicable"
    if not captured_output_present:
        return "missing"
    if validation.type == "behavioral":
        if validation.executed_test_files or validation.passed_count is not None or validation.failed_count is not None:
            return "test_runner_output"
        return "unknown"
    if validation.type == "behavior_demo":
        if _captured_output_looks_like_test_runner(validation.captured_output):
            return "test_runner_output"
        if _captured_output_is_self_verdict_only(validation.captured_output):
            return "self_verdict_only"
        return "factual_observation_candidate"
    return "unknown"


def _validation_independence(
    validation: ValidationRun,
    *,
    fresh_after_latest_relevant_change: bool | None,
    captured_output_present: bool,
    output_kind: str,
    executed_test_files: list[str],
    coder_authored_test_files: list[str],
    untouched_executed_test_files: list[str],
) -> tuple[str, list[str]]:
    risk_reasons: list[str] = []
    if validation.trusted_validation_outcome == "masked_or_unknown":
        risk_reasons.append(validation.masking_reason or "masked_or_unknown_validation")
        return "masked_or_unknown", risk_reasons
    if validation.outcome != "pass" or not validation.passed or validation.trusted_validation_outcome != "passed":
        risk_reasons.append("failed_validation")
        return "failed", risk_reasons
    if fresh_after_latest_relevant_change is False:
        risk_reasons.append("stale_after_latest_relevant_change")
        return "stale", risk_reasons
    if validation.type == "static":
        risk_reasons.append("static_validation_not_behavioral_evidence")
        return "not_independent", risk_reasons
    if validation.type == "behavior_demo":
        if not captured_output_present:
            risk_reasons.append("behavior_demo_missing_captured_output")
            return "not_independent", risk_reasons
        if output_kind == "self_verdict_only":
            risk_reasons.append("behavior_demo_self_verdict_only")
            return "not_independent", risk_reasons
        if output_kind == "test_runner_output":
            risk_reasons.append("behavior_demo_looks_like_test_runner_output")
            return "not_independent", risk_reasons
        return "independent_candidate", risk_reasons
    if validation.type == "behavioral":
        if not executed_test_files:
            risk_reasons.append("unknown_test_file_provenance")
            return "unknown", risk_reasons
        if untouched_executed_test_files:
            return "independent", risk_reasons
        if coder_authored_test_files and len(coder_authored_test_files) == len(executed_test_files):
            risk_reasons.append("all_output_identified_tests_were_coder_authored")
            return "self_confirming", risk_reasons
        risk_reasons.append("unknown_test_file_provenance")
        return "unknown", risk_reasons
    return "unknown", risk_reasons


def _captured_output_is_self_verdict_only(output: str) -> bool:
    lines = [line.strip().strip(".!").lower() for line in output.splitlines() if line.strip()]
    if not lines:
        return False
    verdict_pattern = re.compile(
        r"^(?:pass(?:ed)?|ok|success(?:ful)?|works?|correct|done|green|valid|all good)$"
    )
    return all(verdict_pattern.fullmatch(line) for line in lines)


def _captured_output_looks_like_test_runner(output: str) -> bool:
    text = output.strip()
    if not text:
        return False
    patterns = (
        r"(?m)^\s*(?:PASS|FAIL)\s+[\w@+./-]+",
        r"(?m)\b[\w@+./-]+::test_[\w.\[\]-]+\s+(?:PASSED|FAILED|SKIPPED|XFAIL|XPASS)\b",
        r"(?i)\b\d+\s+(?:passed|passing|failed|failing|skipped)\b",
        r"(?i)\btest result:\s+(?:ok|failed)\b",
    )
    return any(re.search(pattern, text) for pattern in patterns)


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


def _inspected_paths_from_command(command: str, *, limit: int = 50) -> list[str]:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _inspected_paths_from_command(inner, limit=limit)
    targets: list[str] = []
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    option_value_flags = {"-f", "--file", "--config", "-C"}
    skip_next = False
    commands = {
        "cat",
        "sed",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "head",
        "tail",
        "nl",
        "ls",
        "wc",
        "pwd",
        "stat",
        "file",
        "find",
        "git",
        "diff",
        "status",
        "log",
        "show",
        "branch",
        "remote",
        "rev-parse",
        "for-each-ref",
    }
    common_target_dirs = {"src", "lib", "app", "tests", "test", "include", "public", "packages", "pkg"}
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token in option_value_flags:
            skip_next = True
            continue
        stripped = token.strip("'\"").lstrip("./")
        if not stripped or stripped.startswith("-") or stripped in commands:
            continue
        if stripped == ".":
            targets.append(".")
        elif stripped in common_target_dirs:
            targets.append(stripped)
        elif "/" in stripped or re.search(r"\.[A-Za-z0-9_-]{1,12}$", stripped):
            targets.append(stripped)
        if len(targets) >= limit:
            break
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


def _turn_start_schema_supports_effort(out_dir: Path) -> bool:
    for path in (out_dir / "TurnStartParams.json", out_dir / "v2" / "TurnStartParams.json"):
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        properties = payload.get("properties")
        if isinstance(properties, dict) and "effort" in properties:
            return True
    return False


def _run_probe(args: list[str], timeout: float = 5.0) -> tuple[bool, str]:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return completed.returncode == 0, (completed.stdout + completed.stderr).strip()


def _resolve_controller_models(
    *,
    model: str | None,
    coder_model: str | None,
    supervisor_model: str | None,
) -> tuple[str, str]:
    if model and (coder_model or supervisor_model):
        raise RuntimeError("model cannot be combined with coder_model or supervisor_model")
    if bool(coder_model) != bool(supervisor_model):
        raise RuntimeError("coder_model and supervisor_model must be used together")
    if model:
        return model, model
    if coder_model and supervisor_model:
        return coder_model, supervisor_model
    return DEFAULT_MODEL, DEFAULT_MODEL


def _selected_model_availability(
    models_response: dict[str, Any],
    *,
    coder_model: str | None,
    supervisor_model: str | None,
    adversary_model: str | None = None,
) -> ModelAvailabilityResult:
    available_models = tuple(sorted(_extract_model_ids(models_response)))
    available = set(available_models)
    missing: list[str] = []
    if coder_model and coder_model not in available:
        missing.append(f"coder={coder_model}")
    if supervisor_model and supervisor_model not in available:
        missing.append(f"supervisor={supervisor_model}")
    if adversary_model and adversary_model not in available:
        missing.append(f"adversary={adversary_model}")
    return ModelAvailabilityResult(missing_roles=tuple(missing), available_models=available_models)


def _extract_model_ids(value: Any) -> set[str]:
    ids: set[str] = set()
    if isinstance(value, dict):
        for key in ("id", "model", "slug", "name"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                ids.add(candidate.strip())
        for key in ("data", "models", "items"):
            if key in value:
                ids.update(_extract_model_ids(value[key]))
        return ids
    if isinstance(value, list):
        for item in value:
            ids.update(_extract_model_ids(item))
        return ids
    if isinstance(value, str) and value.strip():
        ids.add(value.strip())
    return ids


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


def _approval_resolution_metric_key(decision: str | dict[str, Any]) -> str:
    if isinstance(decision, str):
        return decision
    if isinstance(decision, dict) and decision:
        return str(next(iter(decision)))
    return "unknown"


def _observed_changed_files(controller: Any) -> list[ChangedFile]:
    observed = getattr(controller, "observed_changed_files", None)
    if not isinstance(observed, dict):
        return []
    project_root = getattr(controller, "project_root", None)
    task_path = getattr(controller, "task_path", None)
    return [
        changed
        for changed in observed.values()
        if not _is_ignored_changed_path(changed.path, project_root=project_root, task_path=task_path)
    ][:200]


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


def _is_internal_runtime_path(path: str, *, project_root: Path | None, task_path: Path | str | None) -> bool:
    normalized = _normalize_internal_workspace_path(str(path).strip().strip("'\""))
    if not normalized:
        return False
    if normalized == ".git-init.log":
        return True
    if normalized == ".supervisor" or normalized.startswith(".supervisor/"):
        return True
    task_relative = _task_relative_workspace_path(project_root=project_root, task_path=task_path)
    return bool(task_relative and normalized == task_relative)


def _is_ignored_changed_path(path: str, *, project_root: Path | None, task_path: Path | str | None) -> bool:
    return _is_internal_runtime_path(
        path,
        project_root=project_root,
        task_path=task_path,
    ) or _is_generated_or_cache_artifact_path(path, project_root=project_root)


def _is_generated_or_cache_artifact_path(path: str, *, project_root: Path | None) -> bool:
    normalized = _normalize_internal_workspace_path(str(path).strip().strip("'\""))
    if not normalized:
        return False
    parts = set(normalized.lower().split("/"))
    if parts & {
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".cache",
        ".next",
        ".parcel-cache",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "target",
        "coverage",
    }:
        return True
    name = normalized.rsplit("/", 1)[-1].lower()
    if name.endswith(
        (
            ".o",
            ".obj",
            ".lo",
            ".pyc",
            ".pyo",
            ".class",
            ".so",
            ".dylib",
            ".dll",
            ".exe",
            ".a",
            ".lib",
            ".rlib",
            ".wasm",
            ".gcda",
            ".gcno",
        )
    ):
        return True
    return _is_probably_compiled_binary_artifact(normalized, project_root=project_root)


def _is_probably_compiled_binary_artifact(normalized_path: str, *, project_root: Path | None) -> bool:
    if project_root is None:
        return False
    name = normalized_path.rsplit("/", 1)[-1]
    if "." in name:
        return False
    workspace_path = Path(normalized_path)
    candidate = workspace_path if workspace_path.is_absolute() else Path(project_root) / workspace_path
    try:
        resolved = candidate.resolve()
        resolved.relative_to(Path(project_root).resolve())
        if not resolved.is_file():
            return False
        head = resolved.read_bytes()[:4096]
    except (OSError, ValueError):
        return False
    if not head:
        return False
    binary_magic = (
        b"\x7fELF",
        b"MZ",
        b"\x00asm",
        b"\xca\xfe\xba\xbe",
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xbe\xba\xfe\xca",
        b"BC\xc0\xde",
    )
    return head.startswith(binary_magic) or b"\0" in head


def _task_relative_workspace_path(*, project_root: Path | None, task_path: Path | str | None) -> str | None:
    if task_path is None:
        return None
    task = Path(task_path)
    if project_root is not None:
        try:
            task = task.resolve()
            return _normalize_internal_workspace_path(str(task.relative_to(Path(project_root).resolve())))
        except (OSError, ValueError):
            pass
    if task.is_absolute():
        return _normalize_internal_workspace_path(task.name)
    return _normalize_internal_workspace_path(str(task))


def _normalize_internal_workspace_path(path: str) -> str:
    normalized = path.replace("\\", "/").strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.strip("/")


def _filter_internal_git_output(
    output: str,
    *,
    command: list[str],
    project_root: Path,
    task_path: Path,
) -> str:
    if not output:
        return output
    if command[:2] == ["git", "status"]:
        lines = [
            line
            for line in output.splitlines()
            if not _is_ignored_changed_path(
                _git_status_changed_path(line),
                project_root=project_root,
                task_path=task_path,
            )
        ]
        return "\n".join(lines)
    if command[:2] == ["git", "diff"] and "--name-only" in command:
        lines = [
            line
            for line in output.splitlines()
            if not _is_ignored_changed_path(line.strip(), project_root=project_root, task_path=task_path)
        ]
        return "\n".join(lines)
    if command[:2] == ["git", "diff"] and "--stat" in command:
        lines: list[str] = []
        for line in output.splitlines():
            if "|" not in line:
                continue
            path = line.split("|", 1)[0].strip()
            if not _is_ignored_changed_path(path, project_root=project_root, task_path=task_path):
                lines.append(line)
        return "\n".join(lines)
    return output


def _git_status_changed_path(line: str) -> str:
    path = _path_from_git_status_line(line)
    if " -> " in path:
        path = path.rsplit(" -> ", 1)[1].strip()
    return path


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


def _adversary_enabled_from_env() -> bool | None:
    raw = os.environ.get("SENTINEL_ADVERSARY_ENABLED", "").strip().lower()
    if not raw:
        return None
    if raw in {"1", "true", "yes", "on", "enabled"}:
        return True
    if raw in {"0", "false", "no", "off", "disabled"}:
        return False
    return None


def _create_adversary_snapshot(project_root: Path) -> Path:
    temp_root = Path(tempfile.mkdtemp(prefix="sentinel-adversary-")).resolve()
    snapshot_root = temp_root / "workspace"
    try:
        shutil.copytree(
            project_root,
            snapshot_root,
            symlinks=True,
            ignore=_adversary_snapshot_ignore,
        )
    except Exception:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise
    return snapshot_root


def _adversary_snapshot_ignore(directory: str, names: list[str]) -> set[str]:
    ignored = {
        ".git",
        ".supervisor",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }
    return {name for name in names if name in ignored}


def _workspace_state_id(project_root: Path) -> str:
    root = project_root.resolve()
    digest = hashlib.sha256()
    skip_dirs = {
        ".git",
        ".supervisor",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "node_modules",
        ".venv",
        "venv",
    }
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(name for name in dirs if name not in skip_dirs)
        rel_dir = Path(current).resolve().relative_to(root)
        for name in sorted(files):
            path = Path(current) / name
            rel = (rel_dir / name).as_posix()
            try:
                digest.update(rel.encode("utf-8", errors="surrogateescape"))
                digest.update(b"\0")
                if path.is_symlink():
                    digest.update(b"symlink\0")
                    digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
                else:
                    digest.update(b"file\0")
                    with path.open("rb") as handle:
                        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                            digest.update(chunk)
                digest.update(b"\0")
            except OSError:
                digest.update(b"unreadable\0")
                digest.update(rel.encode("utf-8", errors="surrogateescape"))
                digest.update(b"\0")
    return digest.hexdigest()


def _latest_validation_sequence(validations: list[ValidationRun]) -> int | None:
    return max((validation.sequence for validation in validations), default=None)


def _bounded_adversary_report_text(text: str, *, limit: int = 20_000) -> str:
    stripped = text.strip()
    if len(stripped) <= limit:
        return stripped
    return stripped[:limit].rstrip() + "\n\n[adversary report truncated by controller for coder message]"


def _final_adversary_report_summary(report: AdversaryReport | None) -> list[str]:
    if report is None:
        return []
    first_line = next((line.strip() for line in report.report_text.splitlines() if line.strip()), "")
    if len(first_line) > 240:
        first_line = first_line[:237].rstrip() + "..."
    details = [
        f"status={report.status}",
        f"candidate_finding={str(report.candidate_finding).lower()}",
        f"completion_wake_sequence={report.completion_wake_sequence}",
        f"latest_relevant_change_sequence={report.latest_relevant_change_sequence}",
    ]
    if first_line:
        details.append(f"summary={first_line}")
    return ["; ".join(details)]


def _is_stream_delta_method(method: str) -> bool:
    lowered = method.lower()
    return lowered.endswith("delta") or method in {
        "item/reasoning/summaryTextDelta",
        "item/reasoning/textDelta",
        "command/exec/outputDelta",
        "process/outputDelta",
        "item/commandExecution/outputDelta",
        "item/fileChange/outputDelta",
    }


def _is_command_output_delta_method(method: str) -> bool:
    lowered = method.lower()
    if method in {
        "item/commandExecution/outputDelta",
        "command/exec/outputDelta",
        "process/outputDelta",
    }:
        return True
    return any(token in lowered for token in ("command", "exec", "process")) and (
        lowered.endswith("outputdelta")
        or lowered.endswith("stdoutdelta")
        or lowered.endswith("stderrdelta")
    )


def _changed_files_from_diff_summary(
    diff: str | None,
    *,
    project_root: Path | None = None,
    task_path: Path | str | None = None,
) -> list[str]:
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
            path = _git_status_changed_path(stripped)
            if path and not _is_ignored_changed_path(path, project_root=project_root, task_path=task_path) and path not in files:
                files.append(path)
    marker = "$ git diff --name-only"
    if marker in diff:
        tail = diff.split(marker, 1)[1]
        for line in tail.splitlines():
            path = line.strip()
            if (
                path
                and not path.startswith("$")
                and not _is_ignored_changed_path(path, project_root=project_root, task_path=task_path)
                and path not in files
            ):
                files.append(path)
    return files
