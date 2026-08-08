from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from supervisor.approval_triage import (
    CheapRuntimeReviewer,
    CheapRuntimeReviewerError,
    CheapRuntimeTriageConfig,
    runtime_triage_config_from_env,
)
from supervisor.adversary_agent import AdversaryAgent, AdversaryAgentError
from supervisor.appserver import AppServerClient, AppServerError, AppServerMessage
from supervisor.approvals import ApprovalManager, normalize_approval_request
from supervisor.coder import (
    CODER_SANDBOX_DANGER_FULL_ACCESS,
    CODER_SANDBOX_WORKSPACE_WRITE,
    DEFAULT_INTELLIGENCE,
    CoderSession,
    coder_sandbox_mode,
    coder_thread_params,
)
from supervisor.health import (
    clear_restart_issue_for_validation,
    kill_restart_candidate,
    patch_health,
    record_restart_issue_intervention,
)
from supervisor.project_config import DEFAULT_MODEL, ProjectConfig
from supervisor.review_limits import review_limit_reached
from supervisor.schemas import (
    AppEvent,
    AppEventSource,
    AdvReportControllerDecision,
    ApprovalContext,
    AdversaryReport,
    ApprovalWakeContext,
    BehaviorSurfaceItem,
    BreadthRiskSummary,
    CheapRuntimeDecision,
    ChangedFile,
    ChangedFileContext,
    ChangedFileDiff,
    ChangedTestsSummary,
    CoderMessage,
    CompletionReturnRecord,
    CompletionReviewDecision,
    CompletionReviewDecisionKind,
    completion_review_accept_blocker_fields,
    DiffPacketLimits,
    EvidenceProvenanceSummary,
    FinalReport,
    HealthDelta,
    HumanMessage,
    InspectionOutput,
    InspectionRun,
    PriorIntervention,
    RestartHandoff,
    BelloConfig,
    BelloStatus,
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
from supervisor.markdown_fences import advance_markdown_fence
from supervisor.supervisor_agent import StatelessSupervisorAgent, SupervisorAgentError
from supervisor.task_select import resolve_task
from supervisor.tui import TerminalTUI, UserCommand
from supervisor.workspace_snapshot import (
    _sanitize_copied_workspace_symlinks,
    SNAPSHOT_READ_ONLY_DEPENDENCY_NAMES,
    SnapshotPatchError,
    WorkspaceSnapshot,
    WorkspaceSnapshotError,
    apply_snapshot_patch,
    create_workspace_snapshot,
    snapshot_git_environment,
)
from supervisor.workspace_clean import clean_workspace_except_task


VALIDATION_LEDGER_LIMIT = 50
INSPECTION_LEDGER_LIMIT = 50
READINESS_MARKER = "BELLO_READY_FOR_REVIEW"
READINESS_MARKER_RE = re.compile(r"^\s*BELLO_READY_FOR_REVIEW\s*$", re.MULTILINE)
NO_MARKER_IDLE_NUDGE = (
    "Continue working. If you believe the task is ready, provide Summary, Validation evidence, "
    "and the exact readiness marker on its own line: BELLO_READY_FOR_REVIEW."
)
POST_RESTART_CONTINUE_NUDGE = (
    "You are a fresh generation after a restart. Read HANDOFF.md and continue the task from there. "
    "Do not declare readiness until you have done new work and validated it."
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
MANDATORY_FULL_RUNTIME_WAKE_REASONS = {
    "done_without_fresh_validation",
    "runtime_control_replacement",
}
CONTROLLER_IDLE_GUARD_INTERVAL_SECONDS = 60.0
CONTROLLER_IDLE_GUARD_STALL_SECONDS = 300.0
# Provider no_message (empty-completion) recovery for the completion review. A transient
# backend blip can return empty "completed" turns for a couple of minutes; ride it out with
# backed-off retries before declaring the run infra-invalid. The budget is CONSECUTIVE
# (reset on any successful supervisor decision), so a recovered provider keeps working.
COMPLETION_NO_MESSAGE_MAX_RETRIES = 6
NO_MESSAGE_RETRY_BACKOFF_SECONDS = (15.0, 30.0, 60.0, 120.0, 120.0, 120.0)
# A completion-review turn that times out must not kill the whole run: retry once on a fresh
# review thread (the timed-out turn is abandoned with the closed session) before the existing
# fatal provider_failure path. Consecutive semantics: reset on any successful decision.
COMPLETION_TIMEOUT_MAX_RETRIES = 1
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
ADVERSARY_MODEL = DEFAULT_MODEL


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
class CompletionReviewerEvidence:
    workspace_state_id: str
    kind: Literal["command", "image_view"]
    command: str | None
    paths: tuple[str, ...]
    passed: bool
    summary: str
    path_commands: tuple[tuple[str, str], ...] = ()
    resource_paths: tuple[str, ...] = ()
    observed_output: bool = False
    empty_paths: tuple[str, ...] = ()
    patch_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuntimeDecisionToken:
    product_revision: int
    notification_revision: int
    generation: int
    coder_thread_id: str | None
    active_coder_turn_id: str | None
    controller_status: str
    paused: bool
    running: bool


@dataclass(frozen=True)
class _AdversaryReadonlyDependencyMount:
    relative_path: str
    target: Path


@dataclass(frozen=True)
class CompletionReviewToken:
    workspace_state_id: str
    git_state_id: str
    task_state_id: str
    generation: int
    coder_thread_id: str | None
    active_coder_turn_id: str | None
    controller_status: str
    paused: bool
    pending_approvals_fingerprint: str
    product_revision: int
    latest_relevant_edit_sequence: int | None
    validation_fingerprint: str
    inspection_fingerprint: str
    changed_files_fingerprint: str
    last_coder_message_sequence: int | None


@dataclass(frozen=True)
class RuntimeRestartIssue:
    key: str
    sequence: int
    validation_id: str | None = None


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


class BelloController:
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
        runtime_model: str | None = None,
        completion_model: str | None = None,
        adversary_model: str | None = None,
        coder_intelligence: str | None = DEFAULT_INTELLIGENCE,
        supervisor_intelligence: str | None = None,
        runtime_intelligence: str | None = None,
        completion_intelligence: str | None = None,
        adversary_intelligence: str | None = DEFAULT_INTELLIGENCE,
        fast: bool = False,
        overwrite_state: bool = False,
        clean_workspace: bool = False,
        use_git_diff: bool = True,
        adversary_enabled: bool | None = None,
        adversary_runs: int | None = None,
        completion_review: bool | None = None,
        declared_grading_roots: list[str | Path] | tuple[str | Path, ...] | None = None,
        project_config: ProjectConfig | None = None,
    ):
        self.project_root = project_root.resolve()
        self.task_path = resolve_task(self.project_root, task_path)
        self._canonical_task_contents = self.task_path.read_text(encoding="utf-8")
        self._canonical_task_hash = _hash_file(self.task_path)
        self.workspace_root = self.project_root
        self.workspace_task_path = self.task_path
        self._coder_snapshot: WorkspaceSnapshot | None = None
        self._snapshot_patch_applied = False
        self._coder_started = False
        self.declared_grading_roots = tuple(
            str(Path(root).expanduser()) for root in declared_grading_roots or ()
        )
        if clean_workspace:
            clean_workspace_except_task(
                self.project_root,
                self.task_path,
                protected_paths=self.declared_grading_roots,
            )
        self.store = StateStore(self.project_root)
        (
            self.coder_model,
            self.runtime_model,
            self.completion_model,
            self.adversary_model,
        ) = _resolve_controller_models(
            model=model,
            coder_model=coder_model,
            supervisor_model=supervisor_model,
            runtime_model=runtime_model,
            completion_model=completion_model,
            adversary_model=adversary_model,
        )
        self.supervisor_model = self.runtime_model
        shared_models = {self.coder_model, self.runtime_model, self.completion_model}
        self.model = self.coder_model if len(shared_models) == 1 else None
        self.coder_intelligence = coder_intelligence
        legacy_supervisor_intelligence = supervisor_intelligence or DEFAULT_INTELLIGENCE
        self.runtime_intelligence = (
            runtime_intelligence or legacy_supervisor_intelligence
        )
        self.completion_intelligence = (
            completion_intelligence or legacy_supervisor_intelligence
        )
        self.adversary_intelligence = adversary_intelligence or DEFAULT_INTELLIGENCE
        self.supervisor_intelligence = self.runtime_intelligence
        self.fast = fast
        self.overwrite_state = overwrite_state
        self.clean_workspace = clean_workspace
        self.use_git_diff = use_git_diff
        self.adversary_enabled = (
            _adversary_enabled_from_env()
            if adversary_enabled is None
            else adversary_enabled
        )
        self.adversary_runs = adversary_runs
        # CLI override for the completion-review toggle; stays runtime-scoped and never
        # rewrites the persisted project config, matching the other run settings.
        self.completion_review = completion_review
        self.project_config = project_config
        self.event_queue: asyncio.Queue[ControllerEvent] = asyncio.Queue()
        self.client = client or AppServerClient(
            cwd=self.project_root,
            notification_handler=self._on_notification,
            server_request_handler=self._on_server_request,
            transport_error_handler=self._on_transport_error,
        )
        self.tui = tui or TerminalTUI()
        self.supervisor: StatelessSupervisorAgent | None = None
        self.completion_supervisor: StatelessSupervisorAgent | None = None
        self.adv_report_controller: StatelessSupervisorAgent | None = None
        self.approvals: ApprovalManager | None = None
        self.runtime_triage_config: CheapRuntimeTriageConfig = (
            runtime_triage_config_from_env(
                enabled=project_config.cheap_runtime
                if project_config is not None
                else True
            )
        )
        self.runtime_triage_reviewer: CheapRuntimeReviewer | None = None
        self.coder: CoderSession | None = None
        self.pending_approvals: dict[int | str, ApprovalContext] = {}
        self.last_coder_message: CoderMessage | None = None
        self.validations: list[ValidationRun] = []
        self.inspections: list[InspectionRun] = []
        self.completion_reviewer_evidence: list[CompletionReviewerEvidence] = []
        self._completion_review_workspace_state_id: str | None = None
        self._completion_review_token: CompletionReviewToken | None = None
        self._accepted_completion_review_token: CompletionReviewToken | None = None
        self._completion_product_revision = 0
        self._runtime_notification_revision = 0
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
        # True at run start (the initial generation begins working immediately); reset to False by
        # restart() until the new generation's first coder turn starts.
        self._generation_has_coder_turn = True
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
        # Cross-review knowledge: the behavior surface accumulated by completion reviews of
        # this run plus the previous reviewer's unverified suspicions. Kept in memory on the
        # controller (not on disk in the coder-writable workspace): an in-run restart keeps this
        # same object, which is the only survival we need, and an in-memory store cannot be
        # forged by coder-authored test code or corrupted into a parse/type crash.
        self._completion_knowledge_state: dict[str, list[Any]] = {
            "behavior_surface": [],
            "uncovered_edge_candidates": [],
        }
        self.completion_review_return_sequence: int | None = None
        self.completion_review_return_validation_sequence: int | None = None
        self._pending_completion_gate_rejection: dict[str, Any] | None = None
        self._current_accept_gate_rejection: dict[str, Any] | None = None
        self._terminal_cleanup_started = False
        self._terminal_cleanup_owner_task: asyncio.Task[Any] | None = None
        self._last_controller_activity_monotonic = time.monotonic()
        self._idle_guard_fired_for_sequence: int | None = None
        self._no_marker_completion_review_key: str | None = None
        self._last_large_diff_signature: str | None = None
        self._last_suspicious_file_signature: str | None = None
        self._suspicious_file_hash_cache: dict[str, tuple[tuple[Any, ...], str]] = {}
        self._pending_adversary_report: AdversaryReport | None = None
        self._adversary_stale_limitations: list[str] = []
        self._active_adversary_thread_id: str | None = None
        self._active_adversary_workspace_root: Path | None = None
        self._configured_mcp_server_names: tuple[str, ...] = ()
        self._configured_plugin_names: tuple[str, ...] = ()
        self._final_report_archived = False

    async def run(self) -> None:
        self.initialize_state()
        try:
            await self.client.start()
            await self.client.initialize()
            await self.tui.start()
            self.running = True
            self.tui.render("SYSTEM", self._runtime_settings_summary())
            self._prepare_coder_workspace()
            if (
                self._adversary_enabled_for_config()
                and not self._effective_completion_review()
            ):
                self.tui.render(
                    "SYSTEM",
                    "adversary requires completion review; disabled for this run",
                )
            await self.preflight()
            if not self.running:
                return
            self.supervisor = StatelessSupervisorAgent(
                self.client,
                self.store,
                self.task_path,
                workspace_root=self._active_workspace_root(),
                task_contents=self._canonical_task_contents,
                model=self._runtime_model(),
                fast=self._fast_mode(),
                intelligence=self._runtime_intelligence(),
                configured_mcp_server_names=self._configured_mcp_server_names,
                configured_plugin_names=self._configured_plugin_names,
            )
            self.completion_supervisor = StatelessSupervisorAgent(
                self.client,
                self.store,
                self.task_path,
                workspace_root=self._active_workspace_root(),
                task_contents=self._canonical_task_contents,
                model=self._completion_model(),
                fast=self._fast_mode(),
                intelligence=self._completion_intelligence(),
                denied_workspace_read_paths=(".supervisor/coder/CHECKLIST.md",),
                configured_mcp_server_names=self._configured_mcp_server_names,
                configured_plugin_names=self._configured_plugin_names,
            )
            self.adv_report_controller = StatelessSupervisorAgent(
                self.client,
                self.store,
                self.task_path,
                workspace_root=self._active_workspace_root(),
                task_contents=self._canonical_task_contents,
                model=self._completion_model(),
                fast=self._fast_mode(),
                intelligence=self._completion_intelligence(),
                denied_workspace_read_paths=(".supervisor/coder/CHECKLIST.md",),
                configured_mcp_server_names=self._configured_mcp_server_names,
                configured_plugin_names=self._configured_plugin_names,
            )
            self.approvals = ApprovalManager(
                self._active_workspace_root(),
                supervisor=self,
                declared_grading_roots=self.declared_grading_roots,
                immutable_paths=self._immutable_approval_paths(),
                coder_checklist_path=self.store.coder_checklist_path(),
            )
            self.coder = CoderSession(
                self.client,
                self.store,
                self._active_workspace_root(),
                self._active_task_path(),
                model=self._coder_model(),
                fast=self._fast_mode(),
                intelligence=self._coder_intelligence(),
            )
            await self.coder.start_thread()
            self._coder_started = True
            await self.coder.start_initial_turn()
            self.store.update_bello_config(
                lambda cfg: cfg.model_copy(update={"status": BelloStatus.RUNNING})
            )
            self.tui.status("supervised coder started")
            await self.event_loop()
        except (AppServerError, SupervisorAgentError) as exc:
            await self.fail_provider(f"app-server RPC failed: {exc}")
        except WorkspaceSnapshotError as exc:
            await self.fail_provider(f"run infrastructure failed: {exc}")
        finally:
            self.running = False
            await self._settle_supervisor_task_for_run_shutdown()
            snapshot = getattr(self, "_coder_snapshot", None)
            if snapshot is not None and not getattr(
                self, "_snapshot_patch_applied", False
            ):
                if getattr(self, "_coder_started", False):
                    await self._preserve_snapshot_for_recovery(
                        snapshot, reason="unhandled_shutdown"
                    )
                else:
                    snapshot.cleanup()
                    self._coder_snapshot = None
            await self.tui.stop()
            await self.client.stop()

    def initialize_state(self) -> None:
        project_config = self._project_config_for_persistence()
        config = BelloConfig(
            project_root=str(self.project_root),
            task=project_config.task,
            task_path=str(self.task_path),
            task_hash=_hash_file(self.task_path),
            coder_mod=project_config.coder_mod,
            super_mod=project_config.runtime_mod,
            runtime_mod=project_config.runtime_mod,
            completion_mod=project_config.completion_mod,
            adversary_mod=project_config.adversary_mod,
            coder_intelligence=project_config.coder_intelligence,
            super_intelligence=project_config.runtime_intelligence,
            runtime_intelligence=project_config.runtime_intelligence,
            completion_intelligence=project_config.completion_intelligence,
            adversary_intelligence=project_config.adversary_intelligence,
            speed=project_config.speed,
            start_over=project_config.start_over,
            adversary=project_config.adversary,
            clean=project_config.clean,
            protected_path=list(project_config.protected_path),
            model=_shared_primary_model(project_config),
            coder_model=project_config.coder_mod,
            supervisor_model=project_config.runtime_mod,
            runtime_model=project_config.runtime_mod,
            completion_model=project_config.completion_mod,
            adversary_model=project_config.adversary_mod,
            supervisor_intelligence=project_config.runtime_intelligence,
            fast=project_config.fast,
            protected_paths=list(project_config.protected_path),
            max_adversary_runs=self._configured_adversary_runs(project_config),
            max_completion_returns_before_adversary=project_config.completion_returns_before_adversary,
            max_completion_returns_after_adversary=project_config.completion_returns_after_adversary,
            completion_review_enabled=project_config.completion_review,
            cheap_runtime=project_config.cheap_runtime,
        )
        mode = "fresh" if self.overwrite_state else "resume"
        self.store.initialize_bello(config, mode=mode)
        self._sequence = self.store.max_event_sequence()
        _ensure_internal_runtime_git_excluded(self.project_root)

    def _persist_model_config(self) -> None:
        project_config = self._project_config_for_persistence()
        self.store.update_bello_config(
            lambda cfg: cfg.model_copy(
                update={
                    "model": _shared_primary_model(project_config),
                    "coder_model": project_config.coder_mod,
                    "supervisor_model": project_config.runtime_mod,
                    "runtime_model": project_config.runtime_mod,
                    "completion_model": project_config.completion_mod,
                    "adversary_model": project_config.adversary_mod,
                    "runtime_intelligence": project_config.runtime_intelligence,
                    "completion_intelligence": project_config.completion_intelligence,
                    "adversary_intelligence": project_config.adversary_intelligence,
                    "supervisor_intelligence": project_config.runtime_intelligence,
                    "fast": project_config.fast,
                    "protected_paths": list(project_config.protected_path),
                    "max_adversary_runs": self._configured_adversary_runs(
                        project_config
                    ),
                    "max_completion_returns_before_adversary": project_config.completion_returns_before_adversary,
                    "max_completion_returns_after_adversary": project_config.completion_returns_after_adversary,
                    "completion_review_enabled": project_config.completion_review,
                    "cheap_runtime": project_config.cheap_runtime,
                }
            )
        )

    def _active_workspace_root(self) -> Path:
        return Path(getattr(self, "workspace_root", self.project_root)).resolve()

    def _active_task_path(self) -> Path:
        return Path(getattr(self, "workspace_task_path", self.task_path)).resolve()

    def _canonical_task_text(self) -> str:
        return getattr(
            self, "_canonical_task_contents", _read_task_text(self.task_path)
        )

    def _immutable_approval_paths(self) -> tuple[Path, ...]:
        snapshot = getattr(self, "_coder_snapshot", None)
        if snapshot is not None:
            return (snapshot.original_root, self.task_path)
        task_path = getattr(self, "task_path", None)
        return (Path(task_path),) if task_path is not None else ()

    def _task_integrity_issue(self) -> str | None:
        expected_hash = getattr(self, "_canonical_task_hash", None)
        if expected_hash:
            try:
                current_hash = _hash_file(self.task_path)
            except OSError:
                return "the original task file is missing or unreadable"
            if current_hash != expected_hash:
                return "the original task file changed after the run started"
        snapshot = getattr(self, "_coder_snapshot", None)
        if snapshot is None:
            return None
        snapshot_task = snapshot.snapshot_root / snapshot.task_relative_path
        if not snapshot_task.is_symlink():
            return "the coder workspace replaced or removed the read-only task link"
        try:
            if snapshot_task.resolve(strict=True) != self.task_path.resolve(
                strict=True
            ):
                return "the coder workspace redirected the read-only task link"
        except OSError:
            return "the coder workspace task link is broken"
        return None

    def _repair_snapshot_runtime_controls(self, *, source: str) -> tuple[str, ...]:
        snapshot = getattr(self, "_coder_snapshot", None)
        if snapshot is None:
            return ()
        repaired = list(snapshot.restore_runtime_links())
        if snapshot.restore_git_control():
            repaired.append("git_config")
        if not repaired:
            return ()
        detail = ", ".join(repaired)
        message = (
            f"restored replaced coder workspace runtime control(s): {detail} ({source})"
        )
        self.store.append_text_locked(PROGRESS, f"- Integrity guard: {message}.\n")
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "coder_workspace_runtime_controls_restored",
                "source": source,
                "repaired": list(repaired),
            }
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "integrity/runtime_controls_restored",
            reason=message,
        )
        cfg = self.store.get_bello_config()
        patch_health(
            self.store,
            HealthDelta(
                generation=cfg.generation,
                add_risk_signals=["runtime_control_replacement"],
            ),
        )
        self.tui.render("INTEGRITY", message)
        return tuple(repaired)

    def _uses_coder_snapshot(self) -> bool:
        return coder_sandbox_mode() == CODER_SANDBOX_WORKSPACE_WRITE

    def _prepare_coder_workspace(self) -> None:
        if not self._uses_coder_snapshot():
            self.workspace_root = self.project_root
            self.workspace_task_path = self.task_path
            self._coder_snapshot = None
            return
        snapshot = create_workspace_snapshot(
            self.project_root,
            self.task_path,
            declared_grading_roots=getattr(self, "declared_grading_roots", ()),
        )
        self._coder_snapshot = snapshot
        self.workspace_root = snapshot.snapshot_root
        self.workspace_task_path = snapshot.task_path
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "coder_workspace_snapshot_created",
                "snapshot_root": str(snapshot.snapshot_root),
                "original_root": str(snapshot.original_root),
                "rewritten_symlinks": [
                    rewrite.path for rewrite in snapshot.rewritten_symlinks
                ],
                "excluded_external_symlinks": list(
                    snapshot.excluded_external_symlink_paths
                ),
            }
        )

    def _coder_model(self) -> str | None:
        return getattr(self, "coder_model", getattr(self, "model", DEFAULT_MODEL))

    def _runtime_model(self) -> str | None:
        return getattr(
            self,
            "runtime_model",
            getattr(self, "supervisor_model", getattr(self, "model", DEFAULT_MODEL)),
        )

    def _supervisor_model(self) -> str | None:
        return self._runtime_model()

    def _completion_model(self) -> str | None:
        return getattr(
            self,
            "completion_model",
            getattr(self, "supervisor_model", getattr(self, "model", DEFAULT_MODEL)),
        )

    def _adversary_model(self) -> str:
        return getattr(self, "adversary_model", ADVERSARY_MODEL)

    def _fast_mode(self) -> bool:
        return bool(getattr(self, "fast", False))

    def _cheap_runtime_enabled(self) -> bool:
        try:
            return bool(self.store.get_bello_config().cheap_runtime)
        except Exception:
            project_config = getattr(self, "project_config", None)
            return (
                bool(project_config.cheap_runtime)
                if project_config is not None
                else True
            )

    def _effective_completion_review(self) -> bool:
        """Whether the completion review gate is active for this run.

        CLI override wins; otherwise the persisted project-config mirror. With the gate
        off, the coder's readiness marker finalizes the run directly and the adversary
        (which runs inside the review-accept path) is inactive.
        """
        override = getattr(self, "completion_review", None)
        if override is not None:
            return bool(override)
        try:
            return bool(self.store.get_bello_config().completion_review_enabled)
        except Exception:
            project_config = getattr(self, "project_config", None)
            if project_config is not None:
                return bool(project_config.completion_review)
            return True

    def _adversary_enabled_for_config(self) -> bool:
        enabled = getattr(self, "adversary_enabled", None)
        if enabled is False:
            return False
        return True

    def _configured_adversary_runs(self, project_config: ProjectConfig) -> int:
        """Adversary pass budget persisted to the run config. Mirrors the project file only —
        CLI overrides (adversary_enabled / adversary_runs) stay runtime-scoped and are applied
        in _effective_max_adversary_runs, matching how the other run settings behave."""
        return max(0, project_config.adversary_runs) if project_config.adversary else 0

    def _project_config_for_persistence(self) -> ProjectConfig:
        config = getattr(self, "project_config", None)
        if config is not None:
            return config
        return ProjectConfig(
            task=_workspace_display_path(self.project_root, str(self.task_path)),
            coder_mod=self._coder_model() or DEFAULT_MODEL,
            runtime_mod=self._runtime_model() or DEFAULT_MODEL,
            completion_mod=self._completion_model() or DEFAULT_MODEL,
            adversary_mod=self._adversary_model(),
            coder_intelligence=self._coder_intelligence() or DEFAULT_INTELLIGENCE,
            runtime_intelligence=self._runtime_intelligence() or DEFAULT_INTELLIGENCE,
            completion_intelligence=self._completion_intelligence()
            or DEFAULT_INTELLIGENCE,
            adversary_intelligence=self._adversary_intelligence()
            or DEFAULT_INTELLIGENCE,
            speed="fast" if self._fast_mode() else "usual",
            start_over=self.overwrite_state,
            adversary=self._adversary_enabled_for_config(),
            clean=self.clean_workspace,
            protected_path=tuple(
                _workspace_display_path(self.project_root, path)
                for path in self.declared_grading_roots
            ),
        )

    def _runtime_settings_summary(self) -> str:
        protected_paths = (
            ", ".join(
                _workspace_display_path(self.project_root, path)
                for path in self.declared_grading_roots
            )
            if self.declared_grading_roots
            else "absent"
        )
        speed = "fast" if self._fast_mode() else "usual"
        return (
            "settings: "
            f"task={_workspace_display_path(self.project_root, str(self.task_path))} "
            f"coder-mod={self._coder_model()} "
            f"runtime-mod={self._runtime_model()} "
            f"completion-mod={self._completion_model()} "
            f"adversary-mod={self._adversary_model()} "
            f"coder-intelligence={self._coder_intelligence()} "
            f"runtime-intelligence={self._runtime_intelligence()} "
            f"completion-intelligence={self._completion_intelligence()} "
            f"adversary-intelligence={self._adversary_intelligence()} "
            f"speed={speed} "
            f"cheap-runtime={_format_bool(self._cheap_runtime_enabled())} "
            f"start-over={_format_bool(self.overwrite_state)} "
            f"clean={_format_bool(self.clean_workspace)} "
            f"completion-review={_format_bool(self._effective_completion_review())} "
            f"adversary={_format_bool(self._adversary_enabled_for_config() and self._effective_completion_review())} "
            f"protected-path={protected_paths}"
        )

    def _coder_intelligence(self) -> str | None:
        return getattr(self, "coder_intelligence", DEFAULT_INTELLIGENCE)

    def _runtime_intelligence(self) -> str | None:
        return getattr(
            self,
            "runtime_intelligence",
            getattr(self, "supervisor_intelligence", DEFAULT_INTELLIGENCE),
        )

    def _supervisor_intelligence(self) -> str | None:
        return self._runtime_intelligence()

    def _completion_intelligence(self) -> str | None:
        return getattr(
            self,
            "completion_intelligence",
            getattr(self, "supervisor_intelligence", DEFAULT_INTELLIGENCE),
        )

    def _adversary_intelligence(self) -> str | None:
        return getattr(self, "adversary_intelligence", DEFAULT_INTELLIGENCE)

    def _completion_supervisor_agent(self) -> StatelessSupervisorAgent | None:
        return getattr(self, "completion_supervisor", None) or getattr(
            self, "supervisor", None
        )

    def _adv_report_controller_agent(self) -> StatelessSupervisorAgent | None:
        return getattr(self, "adv_report_controller", None)

    async def preflight(self) -> None:
        self.tui.status("checking Codex version")
        version = _run_probe(["codex", "--version"])[1]
        self.tui.status("checking Codex app-server schema")
        schema_hash = await self._generate_schema_hash_async()
        self.store.update_bello_config(
            lambda cfg: cfg.model_copy(
                update={"codex_version": version, "appserver_schema_hash": schema_hash}
            )
        )
        self.tui.status("checking Codex account")
        account = await self.client.account_read()
        if account.get("requiresOpenaiAuth") and account.get("account") is None:
            raise RuntimeError(
                "Codex auth missing. Run `codex login` before starting Bello."
            )
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
        if self.store.get_bello_config().status == BelloStatus.PROVIDER_FAILURE:
            return
        self.tui.status("checking config requirements")
        await self.client.config_requirements_read()
        self._configured_mcp_server_names = ()
        self._configured_plugin_names = ()
        config_reader = getattr(self.client, "config_read", None)
        if callable(config_reader):
            try:
                effective_config = await config_reader()
            except AppServerError as exc:
                if not _is_unsupported_appserver_method_error(exc):
                    raise
                warning = (
                    "Codex config/read is unsupported by this app-server; "
                    "continuing with an empty reviewer capability inventory."
                )
                self.tui.render("SYSTEM", warning)
                self.store.append_raw_log(
                    {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": "preflight_warning",
                        "check": "config_read",
                        "fallback": "empty_capability_inventory",
                        "error_type": exc.__class__.__name__,
                        "error": str(exc),
                    }
                )
                effective_config = {}
            (
                self._configured_mcp_server_names,
                self._configured_plugin_names,
            ) = _configured_capability_inventory(effective_config)
        self.tui.status("checking supervisor structured output")
        await self._structured_output_self_test()
        await self._configure_runtime_triage()
        self.tui.status("checking coder sandbox and approval settings")
        thread = await self.client.thread_start(
            coder_thread_params(
                self._active_workspace_root(),
                model=self._coder_model(),
                fast=self._fast_mode(),
            )
        )
        approval_policy = thread.get("approvalPolicy")
        sandbox = thread.get("sandbox")
        thread_id = (
            thread.get("thread", {}).get("id")
            if isinstance(thread.get("thread"), dict)
            else None
        )
        if approval_policy != "on-request":
            raise RuntimeError(
                "app-server did not accept on-request coder approval policy"
            )
        expected_sandbox = coder_sandbox_mode()
        if not _sandbox_matches_mode(
            sandbox,
            expected_sandbox,
            workspace_root=self._active_workspace_root(),
        ):
            raise RuntimeError(
                f"app-server did not accept {expected_sandbox} coder sandbox"
            )
        if isinstance(thread_id, str):
            await self._cleanup_preflight_probe_thread(thread_id)

    async def _ensure_selected_models_available(
        self, models_response: dict[str, Any]
    ) -> None:
        result = _selected_model_availability(
            models_response,
            coder_model=self._coder_model(),
            runtime_model=self._runtime_model(),
            completion_model=self._completion_model()
            if self._effective_completion_review()
            else None,
            adversary_model=self._adversary_model()
            if self._adversary_model_required_for_preflight()
            else None,
        )
        if result.ok:
            return
        available = (
            ", ".join(result.available_models)
            if result.available_models
            else "none reported"
        )
        missing = ", ".join(result.missing_roles)
        message = (
            "model availability preflight failed before coder start: "
            f"selected model(s) are not available from Codex app-server model/list: {missing}. "
            f"Available models: {available}. "
            "The interruption is recorded in .supervisor/FINAL_REPORT.md."
        )
        self.store.append_text_locked(PROGRESS, f"- {message}\n")
        await self.finalize(message, status=BelloStatus.PROVIDER_FAILURE)

    def _adversary_model_required_for_preflight(self) -> bool:
        if not self._effective_completion_review():
            return False
        enabled = getattr(self, "adversary_enabled", None)
        if enabled is False:
            return False
        if enabled is True:
            return True
        return self.store.get_bello_config().max_adversary_runs > 0

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

    def _bump_completion_product_revision(self) -> None:
        self._completion_product_revision = (
            getattr(self, "_completion_product_revision", 0) + 1
        )

    def _capture_runtime_transport_activity(
        self, message: AppServerMessage
    ) -> None:
        """Synchronously invalidate in-flight runtime verdicts on coder activity.

        App Server resolves turn waiters before the queued notification reaches the
        controller event loop.  Tracking the raw coder notification here closes that
        window without treating reviewer/token-usage traffic as product changes.
        """

        thread_id = message.params.get("threadId")
        try:
            coder_thread_id = self.store.get_bello_config().coder_thread_id
        except (AttributeError, OSError, ValueError):
            return
        if thread_id != coder_thread_id:
            return
        method = message.method or ""
        if message.is_server_request:
            self._runtime_notification_revision = (
                getattr(self, "_runtime_notification_revision", 0) + 1
            )
            return
        if method not in {
            "turn/started",
            "turn/completed",
            "item/started",
            "item/completed",
            "thread/status/changed",
            "thread/archived",
        }:
            return
        self._runtime_notification_revision = (
            getattr(self, "_runtime_notification_revision", 0) + 1
        )

    async def _handle_controller_idle_guard(
        self, *, now: float | None = None, force: bool = False
    ) -> None:
        if (
            not self.running
            or getattr(self, "paused", False)
            or getattr(self, "_terminal_cleanup_started", False)
        ):
            return
        cfg = self.store.get_bello_config()
        if cfg.active_coder_turn_id:
            return
        coder = getattr(self, "coder", None)
        if coder is None:
            await self.finalize(
                "controller idle guard: no active coder session, no pending approvals, and no supervisor check",
                status=BelloStatus.PROVIDER_FAILURE,
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
        last_activity = getattr(
            self, "_last_controller_activity_monotonic", current_time
        )
        if (
            not force
            and current_time - last_activity < CONTROLLER_IDLE_GUARD_STALL_SECONDS
        ):
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
            await self.fail_provider(
                f"app-server RPC failed while handling {event.kind}: {exc}"
            )

    async def handle_transport_error(self, event: ControllerEvent) -> None:
        message = (
            event.error_message or str(event.error) or "app-server transport error"
        )
        self._append_event(
            AppEventSource.APP_SERVER, "appServer/transportError", reason=message
        )
        await self.finalize(
            f"app-server transport error: {message}",
            status=BelloStatus.PROVIDER_FAILURE,
        )

    async def fail_provider(self, message: str) -> None:
        if (
            not self.running
            and self.store.get_bello_config().status == BelloStatus.PROVIDER_FAILURE
        ):
            return
        await self.finalize(message, status=BelloStatus.PROVIDER_FAILURE)

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
            await self.finalize("exited by user", status=BelloStatus.EXITED)
            return
        if text in {"/pause", "\x03"}:
            await self.pause()
            return
        if text == "/resume":
            self._bump_completion_product_revision()
            self.paused = False
            self.store.update_bello_config(
                lambda cfg: cfg.model_copy(update={"status": BelloStatus.RUNNING})
            )
            self.tui.status("resumed")
            return
        if text == "/restart":
            await self.restart("user requested supervised restart")
            return
        if text == "/status":
            cfg = self.store.get_bello_config()
            health = self.store.get_health()
            self.tui.render(
                "SYSTEM",
                f"task={Path(cfg.task_path).name} generation={cfg.generation} active_turn={cfg.active_coder_turn_id} pending_approvals={len(self.pending_approvals)} restarts={health.restart_count}",
            )
            return
        self._bump_completion_product_revision()
        self._schedule_supervisor_check(
            f"Human message to supervisor: {text}",
            human_message=HumanMessage(text=command.text, sequence=self._sequence),
        )

    async def handle_server_request(self, message: AppServerMessage) -> None:
        context = normalize_approval_request(message)
        if getattr(self, "_terminal_cleanup_started", False):
            manager = getattr(self, "approvals", None) or ApprovalManager(
                self._active_workspace_root(),
                declared_grading_roots=getattr(self, "declared_grading_roots", ()),
                immutable_paths=self._immutable_approval_paths(),
            )
            resolution = manager._deny(context, "terminal state reached")
            await self.client.respond(
                context.server_request_id, manager.response_payload(context, resolution)
            )
            self.tui.render("DENIED", f"{resolution.decision}: {resolution.reason}")
            return
        self.pending_approvals[context.server_request_id] = context
        self.store.update_bello_config(
            lambda cfg: cfg.model_copy(
                update={"pending_server_request_ids": list(self.pending_approvals)}
            )
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
        if not is_adversary_request:
            self._bump_completion_product_revision()
        if is_adversary_request:
            adversary_workspace_root = getattr(
                self, "_active_adversary_workspace_root", None
            )
            fallback_manager = ApprovalManager(
                adversary_workspace_root or self._active_workspace_root(),
                supervisor=self,
                declared_grading_roots=getattr(self, "declared_grading_roots", ()),
                immutable_paths=self._immutable_approval_paths(),
                adversary_mode=adversary_workspace_root is not None,
            )
            if adversary_workspace_root is None:
                resolution = fallback_manager._deny(
                    context, "adversary snapshot workspace is not active"
                )
            else:
                resolution = await fallback_manager.decide(context)
            response = fallback_manager.response_payload(context, resolution)
        elif self.approvals is None:
            fallback_manager = ApprovalManager(
                self._active_workspace_root(),
                declared_grading_roots=getattr(self, "declared_grading_roots", ()),
                immutable_paths=self._immutable_approval_paths(),
            )
            resolution = fallback_manager._deny(context, "approval manager not ready")
            response = fallback_manager.response_payload(context, resolution)
        else:
            resolution = await self.approvals.decide(context)
            response = self.approvals.response_payload(context, resolution)
        await self.client.respond(context.server_request_id, response)
        is_denial = _approval_resolution_is_denial(resolution.decision)
        decision_key = _approval_resolution_metric_key(resolution.decision)
        self._record_approval_metric(
            decision=decision_key, from_supervisor=resolution.from_supervisor
        )
        self.tui.render(
            "DENIED" if is_denial else "APPROVAL",
            f"{resolution.decision}: {resolution.reason}",
        )
        if resolution.persistent_decision:
            self.store.append_text_locked(
                DECISIONS, f"- {resolution.persistent_decision}\n"
            )
        if is_denial:
            if is_adversary_request:
                denied_command = (
                    context.command
                    or context.grant_root
                    or context.request_type.value
                    or ""
                ).strip()
                if len(denied_command) > 200:
                    denied_command = denied_command[:197] + "..."
                denied_list = getattr(self, "_adversary_denied_commands", None)
                if denied_list is None:
                    denied_list = self._adversary_denied_commands = []
                denied_list.append(f"{denied_command} (denied: {resolution.reason})")
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
                    self.tui.render(
                        "SUPERVISOR",
                        f"denial delivered as approval response; starting a new coder turn: {exc}",
                    )
                    if hasattr(self.coder, "active_turn_id"):
                        self.coder.active_turn_id = None
                    self.store.update_bello_config(
                        lambda cfg: cfg.model_copy(
                            update={"active_coder_turn_id": None}
                        )
                    )
                    turn_id = await self.coder.start_turn(resolution.reason)
                    if isinstance(turn_id, str):
                        self.store.update_bello_config(
                            lambda cfg: cfg.model_copy(
                                update={"active_coder_turn_id": turn_id}
                            )
                        )
                    self.store.append_text_locked(
                        PROGRESS,
                        "- Approval denial was returned to app-server after the original turn ended; "
                        "started a new coder turn with the denial reason.\n",
                    )
            patch_health(
                self.store,
                HealthDelta(
                    generation=self.store.get_health().generation,
                    denied_requests=1,
                    last_denial=resolution.reason,
                ),
            )

    def _is_adversary_approval_context(self, context: ApprovalContext) -> bool:
        thread_id = getattr(self, "_active_adversary_thread_id", None)
        return bool(thread_id and context.thread_id == thread_id)

    async def decide_approval(
        self, context: ApprovalContext, reason: str
    ) -> SupervisorDecision:
        if self.supervisor is None:
            raise SupervisorAgentError("supervisor not ready")
        self._reconcile_intervention_accounting()
        cfg = self.store.get_bello_config()
        wake_sequence = cfg.last_event_sequence + 1
        origin = (
            "adversary_snapshot"
            if self._is_adversary_approval_context(context)
            else "coder"
        )
        approval_context = _approval_wake_context(context, reason, origin=origin)
        packet = self.supervisor.build_packet(
            wake_sequence=wake_sequence,
            current_summary=f"Approval request needs judgment: {reason}",
            diff_summary=await self.diff_summary(),
            triggering_server_request_id=context.server_request_id,
            approval_context=approval_context,
            pending_approvals=[
                _approval_wake_context(
                    pending,
                    reason
                    if pending.server_request_id == context.server_request_id
                    else None,
                    origin="adversary_snapshot"
                    if self._is_adversary_approval_context(pending)
                    else "coder",
                )
                for pending in self.pending_approvals.values()
            ],
            last_coder_message=self.last_coder_message,
            validations=list(self.validations),
            inspections=list(getattr(self, "inspections", [])),
            prior_interventions=list(self.prior_interventions),
            changed_files=await self.changed_files(),
            patch_summary=_patch_summary_from_approval_context(context)
            or await self.patch_summary(),
        )
        return await self.supervisor.decide(packet)

    async def handle_notification(self, message: AppServerMessage) -> None:
        params = message.params
        method = message.method or "notification"
        thread_id = params.get("threadId")
        turn_id = _turn_id_from_params(params)
        item_id = _item_id_from_params(params)
        if not message.raw.get("_bello_completion_capture_done"):
            self._capture_completion_review_notification(message)
        if _is_stream_delta_method(method):
            if not message.raw.get("_bello_output_delta_captured"):
                self._record_command_output_delta(method, params, item_id=item_id)
            return
        self._append_event(
            AppEventSource.APP_SERVER,
            method,
            thread_id=thread_id,
            turn_id=turn_id,
            item_id=item_id,
        )
        if (
            getattr(self, "_terminal_cleanup_started", False)
            and method != "serverRequest/resolved"
        ):
            return

        cfg = self.store.get_bello_config()
        if method == "serverRequest/resolved":
            request_id = params.get("requestId")
            resolved_context = self.pending_approvals.pop(request_id, None)
            if resolved_context is not None and not self._is_adversary_approval_context(
                resolved_context
            ):
                self._bump_completion_product_revision()
            self.store.update_bello_config(
                lambda current: current.model_copy(
                    update={"pending_server_request_ids": list(self.pending_approvals)}
                )
            )
            return
        if (
            method == "turn/started"
            and thread_id == cfg.coder_thread_id
            and isinstance(turn_id, str)
        ):
            self._bump_completion_product_revision()
            if self.coder:
                self.coder.active_turn_id = turn_id
            self._current_turn_action_count = 0
            self._generation_has_coder_turn = True
            self.store.update_bello_config(
                lambda current: current.model_copy(
                    update={"active_coder_turn_id": turn_id}
                )
            )
            self.tui.render("CODER", f"turn started {turn_id}")
            return
        if method == "item/completed" and thread_id == cfg.coder_thread_id:
            self._bump_completion_product_revision()
            summary = _item_summary(params.get("item"))
            item = params.get("item")
            if (
                isinstance(item, dict)
                and item.get("type") == "agentMessage"
                and isinstance(item.get("text"), str)
            ):
                text = item["text"].strip()
                if text:
                    self.last_coder_message = CoderMessage(
                        text=text, sequence=self._sequence
                    )
                self.tui.render("CODER", text)
                return
            if _is_completed_action(item):
                self._current_turn_action_count = (
                    getattr(self, "_current_turn_action_count", 0) + 1
                )
                self.store.append_recent_action(summary)
                triggering_action = _triggering_action_from_item(
                    item, item_id=item_id, summary=summary
                )
                repaired_runtime_controls = self._repair_snapshot_runtime_controls(
                    source="coder_action"
                )
                self._record_changed_files(triggering_action)
                declared_grading_issue = self._declared_grading_access_issue(
                    triggering_action
                )
                if declared_grading_issue is not None:
                    self.tui.render("INTEGRITY", declared_grading_issue)
                    self.store.append_text_locked(
                        PROGRESS, f"- Integrity failure: {declared_grading_issue}\n"
                    )
                    self._append_event(
                        AppEventSource.SUPERVISOR,
                        "integrity/declared_grading_path_access",
                        reason=declared_grading_issue,
                    )
                    await self.finalize(
                        f"escalated: {declared_grading_issue}",
                        status=BelloStatus.ESCALATED,
                    )
                    return
                validation_item = _item_with_recorded_output(
                    item, self._pop_command_output(item_id)
                )
                validation = _validation_from_action(
                    triggering_action,
                    sequence=self._sequence,
                    item=validation_item,
                    changed_paths=list(
                        getattr(self, "observed_changed_files", {}) or {}
                    ),
                )
                inspection = _inspection_from_action(
                    triggering_action,
                    sequence=self._sequence,
                    item=validation_item,
                )
                validation_trigger_reasons: tuple[str, ...] = ()
                changed_files = await self.changed_files()
                product_state_id = _review_product_state_id(
                    self._active_workspace_root(),
                    changed_files,
                    task_contents=self._canonical_task_text(),
                )
                behavior_state_id = _review_behavioral_product_state_id(
                    self._active_workspace_root(),
                    changed_files,
                    task_contents=self._canonical_task_text(),
                )
                self.validations = _validations_for_product_state(
                    list(self.validations),
                    product_state_id,
                    current_behavior_state_id=behavior_state_id,
                )[-VALIDATION_LEDGER_LIMIT:]
                self.inspections = _inspections_for_product_state(
                    list(getattr(self, "inspections", [])), product_state_id
                )[-INSPECTION_LEDGER_LIMIT:]
                if validation is not None:
                    validation = validation.model_copy(
                        update={
                            # Behavioral checks are invalidated only by controller-
                            # classified behavioral inputs. Static checks and direct
                            # demos stay conservatively bound to the full material state.
                            "product_state_id": behavior_state_id
                            if validation.type == "behavioral"
                            else product_state_id,
                        }
                    )
                    self.validations.append(validation)
                    self.validations = self.validations[-VALIDATION_LEDGER_LIMIT:]
                    self._record_validation_progress(validation)
                    validation_trigger_reasons = self._record_validation_runtime_state(
                        validation
                    )
                if inspection is not None:
                    inspection = inspection.model_copy(
                        update={"product_state_id": product_state_id}
                    )
                    self.inspections.append(inspection)
                    self.inspections = self.inspections[-INSPECTION_LEDGER_LIMIT:]
                self._update_relevant_edit_state(changed_files)
                runtime_decision = self.should_wake_runtime_supervisor(
                    action=triggering_action,
                    validation=validation,
                    changed_files=changed_files,
                    validation_trigger_reasons=validation_trigger_reasons,
                )
                if repaired_runtime_controls:
                    runtime_decision = RuntimeTriggerDecision(
                        should_wake=True,
                        reasons=tuple(
                            dict.fromkeys(
                                (
                                    *runtime_decision.reasons,
                                    "runtime_control_replacement",
                                )
                            )
                        ),
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
            self._bump_completion_product_revision()
            if self.coder and isinstance(turn_id, str):
                self.coder.mark_turn_completed(turn_id)
            await self._handle_coder_turn_completed(item_id=item_id)

    def _record_command_output_delta(
        self, method: str, params: dict[str, Any], *, item_id: str | None
    ) -> None:
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
        repaired_runtime_controls = self._repair_snapshot_runtime_controls(
            source="coder_turn_completed"
        )
        if repaired_runtime_controls:
            self._schedule_supervisor_check(
                "Runtime integrity trigger: coder workspace runtime links were replaced and restored.",
                triggering_item_id=item_id,
            )
            return
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
                if not self._effective_completion_review():
                    await self._finalize_completion_review_disabled()
                    return
                summary = (
                    "Coder provided exact readiness marker; running completion_review."
                )
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
            self._schedule_supervisor_check(
                "Coder turn completed", triggering_item_id=item_id
            )
            return
        if getattr(self, "_current_turn_action_count", 0) == 0:
            await self._handle_no_marker_idle()
            return
        self._schedule_supervisor_check(
            "Coder turn completed", triggering_item_id=item_id
        )

    async def _handle_coder_material_limitation(self, message: CoderMessage) -> None:
        cfg = self.store.get_bello_config()
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
            HealthDelta(
                generation=cfg.generation,
                add_risk_signals=["coder_material_limitation"],
            ),
        )
        await self.finalize(
            f"escalated: coder reported material validation limitation without readiness marker: {summary}",
            status=BelloStatus.ESCALATED,
        )

    async def _done_without_fresh_behavioral_validation(self) -> str | None:
        changed_files = await self.changed_files()
        self._update_relevant_edit_state(changed_files)
        task_contents = self._canonical_task_text()
        behavior_affecting_files = [
            file
            for file in changed_files
            if _changed_file_is_behavior_affecting(file, task_contents=task_contents)
        ]
        latest_relevant_edit = (
            None
            if any(file.sequence is None for file in behavior_affecting_files)
            else _latest_behavioral_change_sequence(
                behavior_affecting_files,
                task_contents=task_contents,
            )
        )
        if not behavior_affecting_files:
            # Completion review owns direct document/artifact/render inspection. Do
            # not demand a runtime-style validation merely to let a static deliverable
            # reach the reviewer; the accept gate still requires capable direct evidence.
            return None
        current_product_state_id = _review_product_state_id(
            self._active_workspace_root(),
            changed_files,
            task_contents=task_contents,
        )
        current_behavior_state_id = _review_behavioral_product_state_id(
            self._active_workspace_root(),
            changed_files,
            task_contents=task_contents,
        )
        current_validations = _validations_for_product_state(
            list(self.validations),
            current_product_state_id,
            current_behavior_state_id=current_behavior_state_id,
        )
        if latest_relevant_edit is None:
            # Git can discover a pathless/codemod mutation without an event sequence.
            # In that case ordering cannot prove freshness; require evidence explicitly
            # fingerprinted against the current material product state.
            if any(
                _validation_matches_current_product_state(
                    validation,
                    current_product_state_id=current_product_state_id,
                    current_behavior_state_id=current_behavior_state_id,
                )
                and validation.type in {"behavioral", "behavior_demo"}
                and validation.outcome == "pass"
                and validation.passed
                and validation.trusted_validation_outcome == "passed"
                for validation in current_validations
            ):
                return None
            if _task_is_intrinsically_static_contract(task_contents) and any(
                _validation_matches_current_product_state(
                    validation,
                    current_product_state_id=current_product_state_id,
                    current_behavior_state_id=current_behavior_state_id,
                )
                and _validation_is_fresh_static_pass(validation, -1)
                and _static_validation_matches_task_contract(
                    validation.command, task_contents
                )
                for validation in current_validations
            ):
                return None
            return (
                "coder marked done after a behavior-affecting workspace change whose edit "
                "sequence is unknown, without trusted task-appropriate validation bound to "
                "the current product state"
            )
        if any(
            _validation_is_fresh_behavioral_pass(validation, latest_relevant_edit)
            for validation in current_validations
        ):
            return None
        if _task_is_intrinsically_static_contract(task_contents) and any(
            _validation_is_fresh_static_pass(validation, latest_relevant_edit)
            and _static_validation_matches_task_contract(
                validation.command, task_contents
            )
            for validation in current_validations
        ):
            return None
        return (
            "coder marked done without trusted fresh task-appropriate validation after "
            f"relevant edit sequence {latest_relevant_edit}"
        )

    async def _steer_for_marker(
        self,
        reason: str,
        *,
        sequence: int | None = None,
        message: str = NO_MARKER_IDLE_NUDGE,
    ) -> None:
        cfg = self.store.get_bello_config()
        self.prior_interventions.append(
            PriorIntervention(
                reason=reason,
                message_to_coder=message,
                sequence=sequence or cfg.last_event_sequence,
            )
        )
        self.prior_interventions = self.prior_interventions[-20:]
        patch_health(
            self.store, HealthDelta(generation=cfg.generation, interventions=1)
        )
        self.tui.render("SUPERVISOR", reason)
        if self.coder:
            await self.coder.steer_or_start(message)

    async def _handle_no_marker_idle(self) -> None:
        cfg = self.store.get_bello_config()
        if cfg.active_coder_turn_id:
            return
        if not getattr(self, "_generation_has_coder_turn", True):
            # A freshly restarted generation has produced no coder work yet: forcing a completion
            # review here would judge the previous generation's leftover state (observed killing a
            # run via restart-with-exhausted-budget). Kick the coder instead; steer_or_start starts
            # a turn if the restart kickoff died.
            if self.coder:
                await self.coder.steer_or_start(POST_RESTART_CONTINUE_NUDGE)
            return
        latest_validation_sequence = max(
            (validation.sequence for validation in self.validations), default=None
        )
        last_message_sequence = (
            self.last_coder_message.sequence
            if self.last_coder_message is not None
            else None
        )
        review_key = (
            f"{cfg.generation}:{last_message_sequence}:{latest_validation_sequence}"
        )
        if getattr(self, "_no_marker_completion_review_key", None) == review_key:
            return
        self._no_marker_completion_review_key = review_key
        if not self._effective_completion_review():
            # No review gate to force: nudge the coder to finish and emit the marker,
            # which is the only terminal signal in this mode.
            await self._steer_for_marker(
                "Coder is idle with no active turn and no readiness marker; completion review is disabled, nudging coder to finish.",
            )
            return
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
        self._bump_completion_product_revision()
        self.paused = True
        self.store.update_bello_config(
            lambda cfg: cfg.model_copy(update={"status": BelloStatus.PAUSED})
        )
        if self.coder:
            try:
                await self.coder.interrupt()
            except AppServerError:
                raise
            except Exception:
                pass
        await self._resolve_pending_approvals("paused")
        self.tui.status("paused")

    async def restart(
        self, reason: str, *, handoff: RestartHandoff | None = None
    ) -> None:
        cfg = self.store.get_bello_config()
        if cfg.restart_count >= cfg.max_restarts:
            await self.finalize("restart cap reached", status=BelloStatus.STUCK)
            return
        self._append_event(
            AppEventSource.SUPERVISOR, "controller/restart", reason=reason
        )
        await self._close_completion_review_session()
        self.store.update_bello_config(
            lambda current: current.model_copy(
                update={"status": BelloStatus.RESTARTING}
            )
        )
        if self.coder:
            try:
                await self.coder.interrupt()
            except AppServerError:
                raise
            except Exception:
                pass
        await self._resolve_pending_approvals("restart")
        handoff = handoff or _fallback_restart_handoff(
            task_contents=self._canonical_task_text(),
            reason=reason,
            last_actions=self.store.read_recent_actions(10),
        )
        self.store.write_handoff(handoff.model_dump_json(indent=2) + "\n")
        self._repair_snapshot_runtime_controls(source="restart")
        self.prior_interventions = []
        self.no_marker_idle_nudge_count = 0
        self._last_completion_marker_sequence = None
        # The new generation has produced no coder work yet; until its first turn starts,
        # completion machinery must not judge (or restart over) the previous generation's state.
        self._generation_has_coder_turn = False
        self.completion_review_return_sequence = None
        self.completion_review_return_validation_sequence = None
        self._pending_adversary_report = None
        self._active_adversary_thread_id = None
        self._active_adversary_workspace_root = None
        self._adversary_denied_commands: list[str] = []
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
        self.store.update_bello_config(
            lambda current: current.model_copy(
                update={
                    "generation": current.generation + 1,
                    "restart_count": current.restart_count + 1,
                    "active_coder_turn_id": None,
                    "coder_thread_id": None,
                    "status": BelloStatus.RUNNING,
                }
            )
        )
        if self.store.ensure_coder_checklist():
            self._append_event(
                AppEventSource.SUPERVISOR,
                "controller/coder_checklist_reset",
                reason="coder checklist was missing, invalid, or exceeded its storage bound",
            )
        self.coder = CoderSession(
            self.client,
            self.store,
            self._active_workspace_root(),
            self._active_task_path(),
            model=self._coder_model(),
            fast=self._fast_mode(),
            intelligence=self._coder_intelligence(),
        )
        await self.coder.start_thread()
        await self.coder.start_restart_turn()
        self.tui.render("SYSTEM", "restart complete")

    async def finalize(
        self,
        result: str,
        *,
        status: BelloStatus = BelloStatus.COMPLETE,
        completion_review_accepted: bool = False,
    ) -> None:
        self._reconcile_intervention_accounting()
        final_adversary_report = getattr(
            self, "_accepted_adversary_report", None
        ) or getattr(self, "_pending_adversary_report", None)
        await self._prepare_terminal_shutdown(f"finalizing: {result}")
        if status == BelloStatus.COMPLETE:
            task_integrity_issue = self._task_integrity_issue()
            expected_token = getattr(self, "_accepted_completion_review_token", None)
            precommit_issue = (
                self._completion_precommit_issue(final_adversary_report)
                if expected_token is not None
                else task_integrity_issue
            )
            if precommit_issue is not None:
                status = BelloStatus.ESCALATED
                completion_review_accepted = False
                result = f"escalated: completion commit barrier rejected stale state: {precommit_issue}"
        diff = await self.diff_summary()
        changed_files = await self.changed_files()
        if status == BelloStatus.COMPLETE and expected_token is not None:
            prepatch_issue = self._completion_precommit_issue(final_adversary_report)
            if prepatch_issue is not None:
                status = BelloStatus.ESCALATED
                completion_review_accepted = False
                result = f"escalated: completion pre-patch check rejected stale state: {prepatch_issue}"
        final_adversary_staleness = _adversary_report_staleness_reason(
            final_adversary_report,
            workspace_state_id=(
                _workspace_state_id(self._active_workspace_root())
                if final_adversary_report is not None
                else None
            ),
            generation=self.store.get_bello_config().generation,
        )
        patch_error, recovery_path = await self._apply_final_snapshot_patch_if_needed(
            status
        )
        if patch_error is not None:
            status = BelloStatus.ESCALATED
            completion_review_accepted = False
            result = patch_error
        elif recovery_path is not None:
            result = (
                f"{result}; unaccepted coder workspace preserved at {recovery_path}"
            )
        health = self.store.get_health()
        accepted_completion = getattr(self, "_accepted_completion_decision", None)
        adversary_coverage_limitations = (
            list(final_adversary_report.material_coverage_limitations)
            if final_adversary_report is not None
            else []
        )
        for limitation in getattr(self, "_adversary_stale_limitations", []):
            if limitation not in adversary_coverage_limitations:
                adversary_coverage_limitations.append(limitation)
        if final_adversary_staleness is not None:
            adversary_coverage_limitations.append(final_adversary_staleness)
        report = FinalReport(
            task_path=str(self.task_path),
            status=status,
            result=result,
            files_changed=[file.path for file in changed_files]
            or _changed_files_from_diff_summary(
                diff,
                project_root=self._active_workspace_root(),
                task_path=self._active_task_path(),
            ),
            validations=[
                _format_validation(validation) for validation in self.validations
            ],
            denied_actions=[],
            interventions=health.interventions,
            restarts=health.restart_count,
            completion_review_accepted=completion_review_accepted,
            completion_returns=self.store.get_bello_config().completion_return_count,
            completion_restarts=getattr(self, "completion_restarts", 0),
            no_marker_idle_nudges=getattr(self, "no_marker_idle_nudge_count", 0),
            behavior_evidence_summary=_behavior_evidence_summary(accepted_completion),
            files_reviewed_summary=_files_reviewed_summary(accepted_completion),
            packet_or_access_limitations=list(
                accepted_completion.packet_or_access_limitations
            )
            if isinstance(accepted_completion, CompletionReviewDecision)
            else [],
            adversary_reports=_final_adversary_report_summary(
                final_adversary_report,
                stale=final_adversary_staleness is not None,
            ),
            adversary_coverage_limitations=adversary_coverage_limitations,
            remaining_risks=list(accepted_completion.changed_test_risks)
            if isinstance(accepted_completion, CompletionReviewDecision)
            else [],
            diff_summary=diff,
        )
        self.store.write_final_report(report)
        self._archive_final_report_once()
        self.store.update_bello_config(
            lambda cfg: cfg.model_copy(update={"status": status})
        )
        self.tui.render("SUPERVISOR", result)
        self.tui.status("final report written: .supervisor/FINAL_REPORT.md")
        self.running = False
        self._wake_event_loop_for_shutdown()

    async def _apply_final_snapshot_patch_if_needed(
        self,
        status: BelloStatus,
    ) -> tuple[str | None, str | None]:
        snapshot = getattr(self, "_coder_snapshot", None)
        if snapshot is None or getattr(self, "_snapshot_patch_applied", False):
            return None, getattr(self, "_snapshot_recovery_path", None)
        if status != BelloStatus.COMPLETE:
            if not getattr(self, "_coder_started", False):
                snapshot.cleanup()
                self._coder_snapshot = None
                return None, None
            recovery_path = await self._preserve_snapshot_for_recovery(
                snapshot, reason=status.value
            )
            return None, recovery_path
        task_integrity_issue = self._task_integrity_issue()
        if task_integrity_issue is not None:
            recovery_path = await self._preserve_snapshot_for_recovery(
                snapshot, reason="task_integrity"
            )
            return (
                "escalated: accepted snapshot failed task integrity validation; "
                f"workspace preserved at {recovery_path}: {task_integrity_issue}",
                recovery_path,
            )
        try:
            result = await asyncio.to_thread(apply_snapshot_patch, snapshot)
        except (SnapshotPatchError, WorkspaceSnapshotError) as exc:
            recovery_path = await self._preserve_snapshot_for_recovery(
                snapshot, reason="patch_failed"
            )
            message = (
                "escalated: accepted snapshot could not be applied to the real workspace; "
                f"snapshot preserved at {recovery_path}: {exc}"
            )
            self.tui.render("PATCH", message)
            self.store.append_text_locked(PROGRESS, f"- {message}\n")
            self.store.append_raw_log(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "coder_snapshot_patch_failed",
                    "snapshot_root": recovery_path,
                    "original_root": str(snapshot.original_root),
                    "error_type": exc.__class__.__name__,
                    "error": str(exc),
                }
            )
            return message, recovery_path
        self._snapshot_patch_applied = True
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "coder_snapshot_patch_applied",
                "snapshot_root": str(snapshot.snapshot_root),
                "original_root": str(snapshot.original_root),
                "applied": result.applied,
                "changed_paths": list(result.changed_paths),
                "ignored_paths": list(result.ignored_paths),
                "patch_bytes": result.patch_bytes,
            }
        )
        if result.applied:
            ignored_suffix = (
                f"; ignored {len(result.ignored_paths)} generated artifact paths"
                if result.ignored_paths
                else ""
            )
            self.store.append_text_locked(
                PROGRESS,
                f"- Applied accepted coder snapshot patch to real workspace ({len(result.changed_paths)} paths{ignored_suffix}).\n",
            )
        else:
            if result.ignored_paths:
                self.store.append_text_locked(
                    PROGRESS,
                    "- Accepted coder snapshot produced no workspace patch after generated artifacts were ignored.\n",
                )
            else:
                self.store.append_text_locked(
                    PROGRESS, "- Accepted coder snapshot produced no workspace patch.\n"
                )
        snapshot.cleanup()
        self._coder_snapshot = None
        return None, None

    async def _preserve_snapshot_for_recovery(
        self, snapshot: WorkspaceSnapshot, *, reason: str
    ) -> str:
        existing = getattr(self, "_snapshot_recovery_path", None)
        if existing:
            return str(existing)
        destination = self.store.next_recovery_dir()
        try:
            workspace = await asyncio.to_thread(snapshot.preserve, destination)
            recovery_path = str(workspace)
        except WorkspaceSnapshotError:
            recovery_path = str(snapshot.snapshot_root)
        self._snapshot_recovery_path = recovery_path
        self._coder_snapshot = None
        self.store.append_text_locked(
            PROGRESS,
            f"- Preserved coder workspace for recovery at {recovery_path} ({reason}).\n",
        )
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "coder_workspace_preserved",
                "reason": reason,
                "workspace": recovery_path,
            }
        )
        return recovery_path

    def _archive_final_report_once(self) -> None:
        if getattr(self, "_final_report_archived", False):
            return
        self.store.archive_completed_run(self.task_path)
        self._final_report_archived = True

    async def _prepare_terminal_shutdown(self, reason: str) -> None:
        if getattr(self, "_terminal_cleanup_started", False):
            return
        self._terminal_cleanup_started = True
        self._terminal_cleanup_owner_task = asyncio.current_task()
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
        if (
            getattr(self, "pending_approvals", None)
            and getattr(self, "client", None) is not None
        ):
            try:
                await self._resolve_pending_approvals(
                    f"terminal state reached: {reason}"
                )
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
        supervisor = self._completion_supervisor_agent()
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
        target = sum(
            1 for record in prior if _prior_record_counts_as_health_intervention(record)
        )

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
        def patch(current: BelloConfig) -> BelloConfig:
            updates: dict[str, Any] = {"last_validation_sequence": validation.sequence}
            if (
                _is_behavior_proving_validation(validation)
                and validation.trusted_validation_outcome != "masked_or_unknown"
            ):
                updates["last_trusted_behavioral_validation_sequence"] = (
                    validation.sequence
                )
                if validation.trusted_validation_outcome == "passed":
                    updates["last_trusted_passing_behavioral_validation_sequence"] = (
                        validation.sequence
                    )
            return current.model_copy(update=updates)

        self.store.update_bello_config(patch)

    def _record_validation_runtime_state(
        self, validation: ValidationRun
    ) -> tuple[str, ...]:
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
            failed_count = (
                previous_failed_count + 1 if previous_outcome == "failed" else 1
            )
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
        if current_outcome == "passed":
            clear_restart_issue_for_validation(
                self.store,
                generation=self.store.get_bello_config().generation,
                validation_id=validation.validation_id,
                sequence=validation.sequence,
                matching_issue_keys=(
                    _runtime_unresolved_execution_key(
                        validation.command, validation.cwd
                    ),
                ),
            )
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
        return None

    def _update_relevant_edit_state(self, changed_files: list[ChangedFile]) -> None:
        latest = _latest_relevant_change_sequence(
            changed_files,
            task_contents=self._canonical_task_text(),
        )
        if latest is None:
            return

        def patch(current: BelloConfig) -> BelloConfig:
            existing = current.last_relevant_edit_sequence
            if existing is not None and existing >= latest:
                return current
            return current.model_copy(update={"last_relevant_edit_sequence": latest})

        self.store.update_bello_config(patch)

    def should_wake_runtime_supervisor(
        self,
        *,
        action: TriggeringAction,
        validation: ValidationRun | None,
        changed_files: list[ChangedFile],
        validation_trigger_reasons: tuple[str, ...] = (),
    ) -> RuntimeTriggerDecision:
        reasons: list[str] = list(validation_trigger_reasons)
        read_only_action = bool(
            action.command and _is_read_only_inspection_command(action.command)
        )
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
        if (
            validation is not None
            and validation.trusted_validation_outcome == "masked_or_unknown"
        ):
            reasons.append("masked_validation")
        large_diff_signature = (
            _large_diff_signature(changed_files)
            if _has_large_diff(changed_files)
            else None
        )
        if large_diff_signature is not None and not read_only_action:
            reasons.append("large_diff")
        suspicious_file_hash_cache = getattr(self, "_suspicious_file_hash_cache", None)
        if suspicious_file_hash_cache is None:
            suspicious_file_hash_cache = self._suspicious_file_hash_cache = {}
        suspicious_file_signature = _suspicious_changed_file_signature(
            self._active_workspace_root(),
            changed_files,
            cache=suspicious_file_hash_cache,
        )
        if suspicious_file_signature is None:
            self._last_suspicious_file_signature = None
        elif suspicious_file_signature != getattr(
            self, "_last_suspicious_file_signature", None
        ):
            reasons.append("suspicious_file_touched")
            self._last_suspicious_file_signature = suspicious_file_signature
        restart_candidate, restart_reason = kill_restart_candidate(
            self.store.get_health()
        )
        if restart_candidate and restart_reason and not read_only_action:
            reasons.append("restart_budget")
        reasons = list(dict.fromkeys(reasons))
        if self._deterministic_runtime_noop_reason(
            action=action,
            reasons=reasons,
        ):
            return RuntimeTriggerDecision(should_wake=False, reasons=())
        if (
            reasons == ["large_diff"]
            and large_diff_signature is not None
            and getattr(self, "_last_large_diff_signature", None)
            == large_diff_signature
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
        suspicious_paths = [
            changed.path
            for changed in changed_files
            if _is_suspicious_changed_path(changed.path)
        ]
        trace = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_sequence": getattr(self, "_sequence", None),
            "generation": self.store.get_bello_config().generation,
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
            "validation_id": validation.validation_id
            if validation is not None
            else None,
            "validation_type": validation.type if validation is not None else None,
            "trusted_validation_outcome": validation.trusted_validation_outcome
            if validation is not None
            else None,
            "masking_reason": validation.masking_reason
            if validation is not None
            else None,
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
            manager = ApprovalManager(
                self._active_workspace_root(),
                declared_grading_roots=roots,
                immutable_paths=self._immutable_approval_paths(),
            )
        decision = manager.policy.evaluate(payload)
        if (
            decision.kind.value != "deny"
            or "declared grading/hidden path access denied" not in decision.reason
        ):
            return None
        command = f" command `{action.command}`" if action.command else ""
        return f"coder accessed declared grading/hidden path via{command}: {decision.reason}"

    def _update_runtime_metrics(self, trace: dict[str, Any]) -> None:
        reasons = trace.get("trigger_reasons")
        if not isinstance(reasons, list):
            reasons = []

        def patch(current: dict[str, Any]) -> dict[str, Any]:
            current["runtime_events_total"] = (
                int(current.get("runtime_events_total") or 0) + 1
            )
            if trace.get("should_wake_runtime_supervisor"):
                current["runtime_wakes_total"] = (
                    int(current.get("runtime_wakes_total") or 0) + 1
                )
            if trace.get("skipped_noop"):
                current["runtime_skipped_noop_total"] = (
                    int(current.get("runtime_skipped_noop_total") or 0) + 1
                )
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

    def _record_supervisor_decision_metric(
        self, *, use_case: str, decision: str
    ) -> None:
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
            current[f"{use_case}_{decision}_total"] = (
                int(current.get(f"{use_case}_{decision}_total") or 0) + 1
            )
            return current

        self.store.update_runtime_metrics(patch)

    def _record_approval_metric(self, *, decision: str, from_supervisor: bool) -> None:
        def patch(current: dict[str, Any]) -> dict[str, Any]:
            counts = current.get("approval_decision_counts")
            if not isinstance(counts, dict):
                counts = {}
            counts[decision] = int(counts.get(decision) or 0) + 1
            current["approval_decision_counts"] = counts
            current["approval_requests_total"] = (
                int(current.get("approval_requests_total") or 0) + 1
            )
            current[f"approval_{decision}_total"] = (
                int(current.get(f"approval_{decision}_total") or 0) + 1
            )
            if from_supervisor:
                current["approval_from_supervisor_total"] = (
                    int(current.get("approval_from_supervisor_total") or 0) + 1
                )
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
            summary = (
                self._supervisor_next_summary
                or "Supervisor check was dirty; reviewing latest state"
            )
            completion_review = getattr(
                self, "_supervisor_next_completion_review", False
            )
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
        agent = (
            self._completion_supervisor_agent()
            if completion_review
            else self.supervisor
        )
        if agent is None:
            return
        if (
            not getattr(self, "running", True)
            or getattr(self, "paused", False)
            or getattr(self, "_terminal_cleanup_started", False)
        ):
            return
        review_build_token = (
            self._capture_completion_review_token() if completion_review else None
        )
        runtime_build_token = (
            None if completion_review else self._capture_runtime_decision_token()
        )
        self._reconcile_intervention_accounting()
        cfg = self.store.get_bello_config()
        wake_sequence = cfg.last_event_sequence + 1
        changed_files = await self.changed_files()
        task_contents = self._canonical_task_text()
        current_product_state_id = _review_product_state_id(
            self._active_workspace_root(),
            changed_files,
            task_contents=task_contents,
        )
        current_behavior_state_id = _review_behavioral_product_state_id(
            self._active_workspace_root(),
            changed_files,
            task_contents=task_contents,
        )
        review_validations = _validations_for_product_state(
            list(self.validations),
            current_product_state_id,
            current_behavior_state_id=current_behavior_state_id,
        )
        review_inspections = _inspections_for_product_state(
            list(getattr(self, "inspections", [])), current_product_state_id
        )
        latest_change_sequence = _latest_relevant_change_sequence(
            changed_files,
            task_contents=task_contents,
        )
        latest_behavioral_change_sequence = _latest_behavioral_change_sequence(
            changed_files,
            task_contents=task_contents,
        )
        freshness_summary = _validation_freshness_summary(
            validations=review_validations,
            changed_files=changed_files,
            task_contents=task_contents,
        )
        completion_payload_mode: Literal["full", "delta", "full_fallback"] | None = None
        completion_payload_since_sequence: int | None = None
        completion_details: dict[str, Any] = {}
        if completion_review:
            completion_payload_mode, completion_payload_since_sequence = (
                self._completion_payload_window(changed_files)
            )
            completion_details = await self.completion_packet_details(
                changed_files,
                since_sequence=completion_payload_since_sequence,
                validations=review_validations,
                inspections=review_inspections,
            )
            completion_details["evidence_provenance_summary"] = (
                _evidence_provenance_summary(
                    validations=review_validations,
                    changed_files=changed_files,
                    latest_change_sequence=latest_behavioral_change_sequence,
                )
            )
            completion_details["behavior_surface"] = self._behavior_surface_items()
            completion_details["prior_uncovered_edge_candidates"] = list(
                self._completion_knowledge()["uncovered_edge_candidates"]
            )
        packet = agent.build_packet(
            wake_sequence=wake_sequence,
            current_summary=summary,
            diff_summary=await self.diff_summary(),
            triggering_item_id=triggering_item_id,
            pending_approvals=[
                _approval_wake_context(pending)
                for pending in self.pending_approvals.values()
            ],
            triggering_action=triggering_action,
            last_coder_message=self.last_coder_message,
            validations=review_validations,
            inspections=review_inspections,
            human_message=human_message,
            prior_interventions=list(self.prior_interventions),
            changed_files=changed_files,
            patch_summary=patch_summary or await self.patch_summary(),
            completion_attempt_count=getattr(self, "completion_attempt_count", 0),
            completion_returns_this_generation=_completion_returns_this_generation(
                self, cfg.generation
            ),
            previous_completion_returns=list(getattr(self, "completion_returns", []))[
                -10:
            ],
            last_readiness_marker_sequence=getattr(
                self, "_last_completion_marker_sequence", None
            ),
            no_marker_idle_nudge_count=getattr(self, "no_marker_idle_nudge_count", 0),
            latest_relevant_change_sequence=latest_change_sequence,
            validation_freshness_summary=freshness_summary,
            completion_payload_mode=completion_payload_mode,
            completion_payload_since_sequence=completion_payload_since_sequence,
            completion_review_thread_id=getattr(agent, "completion_thread_id", None),
            pending_accept_gate_rejection=(
                getattr(self, "_pending_completion_gate_rejection", None)
                if completion_review
                else None
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
        runtime_ready_token: RuntimeDecisionToken | None = None
        if completion_review:
            review_ready_token = self._capture_completion_review_token()
            if review_build_token != review_ready_token:
                self._rerun_stale_completion_review(
                    "product state changed while the completion packet was being assembled"
                )
                return
            self._completion_review_token = review_ready_token
            self._completion_review_workspace_state_id = (
                review_ready_token.workspace_state_id
            )
            budget_action = self._completion_review_budget_action(packet=packet)
            if budget_action is not None:
                self._accepted_completion_review_token = review_ready_token
            if budget_action == "adversary":
                await self._run_adversary_before_complete(None, packet=packet)
                return
            if budget_action == "complete":
                reason = (
                    "completion review budget exhausted"
                    if self._effective_max_adversary_runs() <= 0
                    else "post-adversary completion review budget exhausted"
                )
                await self._finalize_bounded_completion(
                    reason=reason,
                )
                return
        else:
            runtime_build_issue = self._runtime_decision_token_issue(
                runtime_build_token
            )
            if runtime_build_issue is not None:
                self._discard_stale_runtime_check(
                    runtime_build_issue, stage="packet_build"
                )
                return
            runtime_ready_token = self._capture_runtime_decision_token()
        try:
            if completion_review:
                self.completion_attempt_count = (
                    getattr(self, "completion_attempt_count", 0) + 1
                )
                self.completion_reviewer_evidence = [
                    record
                    for record in getattr(self, "completion_reviewer_evidence", [])
                    if record.workspace_state_id
                    == review_ready_token.workspace_state_id
                ]
                decision = await agent.decide_completion(packet)
                self._record_completion_reviewer_evidence(
                    getattr(agent, "last_completion_review_items", []),
                    workspace_state_id=review_ready_token.workspace_state_id,
                )
            else:
                # Cheap-model triage: let a lightweight model route clear non-events to noop
                # before paying for the full supervisor. Never short-circuit human messages or
                # pending approvals (those always need the full supervisor); on any cheap-side
                # error or escalate, fall through to the full supervisor.
                if (
                    getattr(self, "runtime_triage_reviewer", None) is not None
                    and human_message is None
                    and not packet.pending_approvals
                    and not _runtime_packet_requires_full_supervisor(packet)
                ):
                    cheap = await self._cheap_runtime_route(packet)
                    if cheap is not None and cheap.decision == "noop":
                        return
                decision = await agent.decide(packet)
        except SupervisorAgentError as exc:
            failure_kind = _classify_supervisor_agent_error(exc)
            message = f"supervisor check failed ({failure_kind}): {exc}"
            self.tui.render("SUPERVISOR", message)
            if not completion_review:
                runtime_issue = self._runtime_decision_token_issue(
                    runtime_ready_token
                )
                if runtime_issue is not None or getattr(
                    self, "_supervisor_dirty", False
                ):
                    if failure_kind == "tool_timeout":
                        patch_health(
                            self.store,
                            HealthDelta(
                                generation=cfg.generation,
                                timeout_fallback_count=1,
                                add_risk_signals=[
                                    "stale_runtime_supervisor_timeout"
                                ],
                            ),
                        )
                        self.store.append_text_locked(
                            PROGRESS,
                            "- Runtime supervisor check timed out after newer coder activity; "
                            "continuing with the latest queued review.\n",
                        )
                    self._discard_stale_runtime_check(
                        runtime_issue or "a newer runtime wake was queued",
                        stage="decision_error",
                    )
                    return
            if failure_kind == "no_message":
                recovered = await self._handle_supervisor_no_message_failure(
                    message=message,
                    summary=summary,
                    completion_review=completion_review,
                )
                if recovered:
                    return
            if completion_review and failure_kind == "tool_timeout":
                recovered = await self._handle_completion_review_timeout_failure(
                    message=message,
                    summary=summary,
                )
                if recovered:
                    return
            await self.finalize(message, status=BelloStatus.PROVIDER_FAILURE)
            return
        if completion_review:
            token_issue = self._completion_review_token_issue(
                getattr(self, "_completion_review_token", None)
            )
            if token_issue is not None:
                self._rerun_stale_completion_review(token_issue)
                return
            access_issue = self._completion_review_access_issue(
                decision,
                packet=packet,
                workspace_state_id=review_ready_token.workspace_state_id,
            )
            if access_issue is not None:
                recovered = await self._handle_completion_review_access_failure(
                    message=access_issue,
                    summary=summary,
                )
                if recovered:
                    return
                await self.finalize(
                    f"infra-invalid: completion reviewer source access failed after retry: {access_issue}",
                    status=BelloStatus.PROVIDER_FAILURE,
                )
                return
        else:
            runtime_issue = self._runtime_decision_token_issue(runtime_ready_token)
            if runtime_issue is not None or getattr(self, "_supervisor_dirty", False):
                self._discard_stale_runtime_check(
                    runtime_issue or "a newer runtime wake was queued",
                    stage="decision",
                    decision=decision,
                )
                return
        # A semantically usable decision resets transient provider recovery state.
        # Infrastructure-invalid structured answers above deliberately do not.
        if getattr(self, "provider_failure_recovery_counts", None):
            self.provider_failure_recovery_counts = {}
        if completion_review:
            await self.apply_completion_decision(
                decision, packet_thread_id=packet.coder_thread_id, packet=packet
            )
        else:
            await self.apply_supervisor_decision(
                decision,
                packet_thread_id=packet.coder_thread_id,
                packet=packet,
            )

    def _capture_runtime_decision_token(self) -> RuntimeDecisionToken:
        cfg = self.store.get_bello_config()
        return RuntimeDecisionToken(
            product_revision=int(
                getattr(self, "_completion_product_revision", 0)
            ),
            notification_revision=int(
                getattr(self, "_runtime_notification_revision", 0)
            ),
            generation=cfg.generation,
            coder_thread_id=cfg.coder_thread_id,
            active_coder_turn_id=cfg.active_coder_turn_id,
            controller_status=cfg.status.value,
            paused=bool(getattr(self, "paused", False)),
            running=bool(getattr(self, "running", True)),
        )

    def _runtime_decision_token_issue(
        self, expected: RuntimeDecisionToken | None
    ) -> str | None:
        if expected is None:
            return "runtime check has no immutable state token"
        current = self._capture_runtime_decision_token()
        changed_fields = [
            field_name
            for field_name in (
                "product_revision",
                "notification_revision",
                "generation",
                "coder_thread_id",
                "active_coder_turn_id",
                "controller_status",
                "paused",
                "running",
            )
            if getattr(current, field_name) != getattr(expected, field_name)
        ]
        if not changed_fields:
            return None
        return "runtime state changed in: " + ", ".join(changed_fields)

    def _discard_stale_runtime_check(
        self,
        reason: str,
        *,
        stage: str,
        decision: SupervisorDecision | None = None,
    ) -> None:
        active = (
            bool(getattr(self, "running", True))
            and not bool(getattr(self, "paused", False))
            and not bool(getattr(self, "_terminal_cleanup_started", False))
        )
        if active:
            self._supervisor_dirty = True
            if not getattr(self, "_supervisor_next_summary", None):
                self._supervisor_next_summary = (
                    "Runtime state changed while it was being reviewed; inspect the latest "
                    "coder state and validation evidence."
                )
            # Never downgrade an already queued completion transition to a runtime
            # pass.  The completion flag is intentionally sticky until the outer
            # supervisor loop consumes it.
            self._supervisor_next_completion_review = bool(
                getattr(self, "_supervisor_next_completion_review", False)
            )
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "stale_runtime_decision_discarded",
                "stage": stage,
                "reason": reason,
                "decision_wake_sequence": (
                    decision.wake_sequence if decision is not None else None
                ),
                "latest_event_sequence": self.store.get_bello_config().last_event_sequence,
                "decision": decision.decision.value if decision is not None else None,
                "rerun_queued": active,
            }
        )

    async def _handle_completion_review_timeout_failure(
        self, *, message: str, summary: str
    ) -> bool:
        """One fresh-thread retry when a completion-review turn times out.

        A timed-out review turn used to finalize the whole run as provider_failure, discarding
        hours of coder work over a single slow review. Close the review session (abandoning the
        hung turn) and re-enter the review loop once; on a consecutive second timeout, fall
        through to the existing fatal path. The counter resets on any successful decision.
        """
        counts = getattr(self, "provider_failure_recovery_counts", None)
        if counts is None:
            counts = {}
            self.provider_failure_recovery_counts = counts
        key = "completion_review_tool_timeout"
        attempts = int(counts.get(key) or 0)
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "provider_failure_recovery",
                "kind": "tool_timeout",
                "scope": "completion_review",
                "attempts_before": attempts,
                "message": message,
            }
        )
        budget = getattr(
            self, "_completion_timeout_max_retries", COMPLETION_TIMEOUT_MAX_RETRIES
        )
        if attempts >= budget:
            return False
        counts[key] = attempts + 1
        completion_supervisor = self._completion_supervisor_agent()
        if completion_supervisor is not None and hasattr(
            completion_supervisor, "close_completion_review"
        ):
            await completion_supervisor.close_completion_review()
        self.store.append_text_locked(
            PROGRESS,
            f"- Provider recovery: completion review turn timed out; retrying once on a fresh review "
            f"thread (attempt {attempts + 1}/{budget}).\n",
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "provider/completion_timeout_retry",
            decision="retry",
            reason=message,
        )
        self._supervisor_dirty = True
        self._supervisor_next_summary = (
            "Retry completion review on a fresh thread after the previous review turn timed out. "
            f"Previous review summary: {summary}"
        )
        self._supervisor_next_completion_review = True
        return True

    async def _handle_completion_review_access_failure(
        self, *, message: str, summary: str
    ) -> bool:
        """Retry one infrastructure-invalid completion review on a fresh thread."""

        counts = getattr(self, "provider_failure_recovery_counts", None)
        if counts is None:
            counts = {}
            self.provider_failure_recovery_counts = counts
        key = "completion_review_source_access"
        attempts = int(counts.get(key) or 0)
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "provider_failure_recovery",
                "kind": "source_access",
                "scope": "completion_review",
                "attempts_before": attempts,
                "message": message,
            }
        )
        if attempts >= 1:
            return False
        counts[key] = attempts + 1
        completion_supervisor = self._completion_supervisor_agent()
        if completion_supervisor is not None and hasattr(
            completion_supervisor, "close_completion_review"
        ):
            await completion_supervisor.close_completion_review()
        self.completion_reviewer_evidence = []
        self.store.append_text_locked(
            PROGRESS,
            "- Provider recovery: completion reviewer did not obtain source access; "
            "retrying once on a fresh review thread without consuming a completion return.\n",
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "provider/completion_source_access_retry",
            decision="retry",
            reason=message,
        )
        self._supervisor_dirty = True
        self._supervisor_next_summary = (
            "Retry completion review on a fresh thread because the previous reviewer did not "
            "demonstrate source access. Inspect the current implementation with read-only commands. "
            f"Previous review summary: {summary}"
        )
        self._supervisor_next_completion_review = True
        return True

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
            getattr(
                self,
                "_completion_no_message_max_retries",
                COMPLETION_NO_MESSAGE_MAX_RETRIES,
            )
            if completion_review
            else 1
        )
        if attempts < budget:
            counts[count_key] = attempts + 1
            completion_supervisor = self._completion_supervisor_agent()
            if (
                completion_review
                and completion_supervisor is not None
                and hasattr(
                    completion_supervisor,
                    "close_completion_review",
                )
            ):
                await completion_supervisor.close_completion_review()
            backoff = 0.0
            if completion_review:
                schedule = getattr(
                    self,
                    "_no_message_backoff_seconds",
                    NO_MESSAGE_RETRY_BACKOFF_SECONDS,
                )
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
            status=BelloStatus.PROVIDER_FAILURE,
        )
        return True

    def _completion_payload_window(
        self,
        changed_files: list[ChangedFile],
    ) -> tuple[Literal["full", "delta", "full_fallback"], int | None]:
        since_sequence = getattr(self, "completion_review_return_sequence", None)
        if since_sequence is None:
            return "full", None
        task_contents = self._canonical_task_text()
        has_unknown_relevant_sequence = any(
            changed.sequence is None
            and _is_relevant_changed_path(changed.path, task_contents=task_contents)
            for changed in changed_files
        )
        if has_unknown_relevant_sequence:
            return "full_fallback", None
        return "delta", since_sequence

    def _record_runtime_intervention(
        self,
        *,
        reason: str,
        message: str,
        sequence: int,
        generation: int,
        issue: RuntimeRestartIssue | None,
    ) -> None:
        self.prior_interventions.append(
            PriorIntervention(
                reason=reason, message_to_coder=message, sequence=sequence
            )
        )
        self.prior_interventions = self.prior_interventions[-20:]
        patch_health(self.store, HealthDelta(generation=generation, interventions=1))
        if issue is not None:
            record_restart_issue_intervention(
                self.store,
                generation=generation,
                issue_key=issue.key,
                sequence=issue.sequence,
                validation_id=issue.validation_id,
            )

    async def apply_supervisor_decision(
        self,
        decision: SupervisorDecision,
        *,
        packet_thread_id: str | None,
        packet: SupervisorWakePacket | None = None,
    ) -> None:
        if (
            not getattr(self, "running", True)
            or getattr(self, "paused", False)
            or getattr(self, "_terminal_cleanup_started", False)
        ):
            return
        cfg = self.store.get_bello_config()
        if decision.generation is not None and decision.generation != cfg.generation:
            return
        if packet_thread_id != cfg.coder_thread_id:
            return
        if (
            decision.wake_sequence is not None
            and decision.wake_sequence <= cfg.last_applied_supervisor_sequence
        ):
            return
        self.store.update_bello_config(
            lambda current: current.model_copy(
                update={
                    "last_applied_supervisor_sequence": decision.wake_sequence
                    or current.last_applied_supervisor_sequence
                }
            )
        )
        self._record_supervisor_decision_metric(
            use_case="runtime", decision=decision.decision.value
        )
        health = self.store.get_health()
        issue = (
            _runtime_restart_issue(
                packet,
                active_issue_key=health.restart_issue_key,
                active_issue_last_sequence=health.restart_issue_last_sequence,
            )
            if packet is not None
            else None
        )
        restart_candidate = False
        restart_candidate_reason: str | None = None
        if decision.decision == SupervisorDecisionKind.RESTART:
            restart_candidate, restart_candidate_reason = kill_restart_candidate(
                health,
                issue_key=issue.key if issue is not None else None,
                issue_sequence=issue.sequence if issue is not None else None,
            )
        if decision.persistent_decision:
            self.store.append_text_locked(
                DECISIONS, f"- {decision.persistent_decision}\n"
            )
        apply_restart_metadata = (
            decision.decision != SupervisorDecisionKind.RESTART or restart_candidate
        )
        if decision.progress_update and apply_restart_metadata:
            self.store.append_text_locked(PROGRESS, f"- {decision.progress_update}\n")
            if decision.decision != SupervisorDecisionKind.RESTART:
                patch_health(
                    self.store,
                    HealthDelta(
                        generation=cfg.generation,
                        last_progress_sequence=cfg.last_event_sequence,
                    ),
                )
        if decision.clear_handoff and apply_restart_metadata:
            self.store.write_text_locked(HANDOFF, "")
        if decision.display_message and apply_restart_metadata:
            self.tui.render("SUPERVISOR", decision.display_message)
        if decision.decision == SupervisorDecisionKind.NOOP:
            return
        if (
            decision.decision == SupervisorDecisionKind.INTERVENE
            and decision.message_to_coder
            and self.coder
        ):
            self.tui.render("SUPERVISOR", f"steering coder: {decision.reason}")
            self._record_runtime_intervention(
                reason=decision.reason,
                message=decision.message_to_coder,
                sequence=decision.wake_sequence or cfg.last_event_sequence,
                generation=cfg.generation,
                issue=issue,
            )
            await self.coder.steer_or_start(decision.message_to_coder)
            return
        if decision.decision == SupervisorDecisionKind.RESTART:
            if not restart_candidate:
                message = decision.message_to_coder or _restart_rejection_steering(
                    decision.handoff
                )
                self.tui.render(
                    "SUPERVISOR",
                    f"restart rejected without health evidence: {decision.reason}",
                )
                self._record_runtime_intervention(
                    reason=decision.reason,
                    message=message,
                    sequence=decision.wake_sequence or cfg.last_event_sequence,
                    generation=cfg.generation,
                    issue=issue,
                )
                if self.coder:
                    await self.coder.steer_or_start(message)
                return
            if restart_candidate_reason:
                self.tui.render(
                    "SUPERVISOR", f"restart candidate: {restart_candidate_reason}"
                )
            await self.restart(
                decision.reason or "supervisor requested restart",
                handoff=decision.handoff,
            )
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
        cfg = self.store.get_bello_config()
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
        self.store.update_bello_config(
            lambda current: current.model_copy(
                update={"last_applied_supervisor_sequence": decision.wake_sequence}
            )
        )
        self._append_completion_anchor_log(decision, packet=packet)
        self._record_supervisor_decision_metric(
            use_case="completion", decision=decision.decision.value
        )
        if decision.decision == CompletionReviewDecisionKind.ACCEPT:
            gate_result = await self._completion_accept_gate(decision, packet=packet)
            if not gate_result.passed:
                await self._handle_completion_accept_gate_failure(decision, gate_result)
                return
            self._record_completion_knowledge(decision)
            self._record_accept_gate_success(gate_result)
            # Preserve the exact edit-sequence boundary certified by this accept.  The
            # workspace bytes can later return to the same hash after an edit/revert,
            # so adversary freshness cannot be inferred from bytes alone.
            self._accepted_completion_latest_relevant_change_sequence = (
                packet.latest_relevant_change_sequence if packet is not None else None
            )
            if hasattr(self, "_completion_review_token"):
                self._accepted_completion_review_token = self._completion_review_token
            if self._should_run_adversary_before_complete(packet):
                if packet is None or self._adversary_runs_remaining():
                    await self._run_adversary_before_complete(decision, packet=packet)
                    return
                self._record_adversary_limit_reached(packet)
            precommit_issue = self._completion_precommit_issue(
                packet.adversary_report if packet is not None else None
            )
            if precommit_issue is not None:
                self._rerun_stale_completion_review(precommit_issue)
                return
        else:
            self._record_completion_knowledge(decision)
        if decision.persistent_decision:
            self.store.append_text_locked(
                DECISIONS, f"- {decision.persistent_decision}\n"
            )
        if decision.progress_update:
            self.store.append_text_locked(PROGRESS, f"- {decision.progress_update}\n")
            patch_health(
                self.store,
                HealthDelta(
                    generation=cfg.generation,
                    last_progress_sequence=cfg.last_event_sequence,
                ),
            )
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
            self._accepted_adversary_report = (
                packet.adversary_report if packet is not None else None
            )
            await self.finalize(
                f"accepted by completion_review: {decision.reason or 'task complete'}",
                status=BelloStatus.COMPLETE,
                completion_review_accepted=True,
            )
            return
        if decision.decision == CompletionReviewDecisionKind.RETURN:
            await self._return_completion_to_coder(decision)
            return
        if decision.decision == CompletionReviewDecisionKind.RESTART:
            if not getattr(self, "_generation_has_coder_turn", True):
                # Nothing to restart: the current generation has not run a single coder turn, so
                # this verdict can only be judging the previous generation's leftover state. With
                # the restart budget exhausted it would finalize the run as STUCK for no reason.
                self.store.append_text_locked(
                    PROGRESS,
                    "- Discarded completion restart issued before any coder work in the current generation.\n",
                )
                self._append_event(
                    AppEventSource.SUPERVISOR,
                    "completion/restart_discarded_virgin_generation",
                    reason=decision.reason,
                )
                if self.coder:
                    await self.coder.steer_or_start(POST_RESTART_CONTINUE_NUDGE)
                return
            self.completion_restarts = getattr(self, "completion_restarts", 0) + 1
            await self.restart(
                decision.reason or "completion review requested restart",
                handoff=decision.handoff,
            )
            return

    async def _run_adversary_before_complete(
        self,
        decision: CompletionReviewDecision | None,
        *,
        packet: SupervisorWakePacket | None,
    ) -> None:
        if packet is None:
            error_summary = "completion packet missing for the adversary run"
            if decision is None:
                await self._fail_required_adversary(
                    packet=None, error_summary=error_summary
                )
            else:
                await self._complete_after_adversary_unavailable(
                    decision,
                    packet=None,
                    error_summary=error_summary,
                )
            return
        adversary_run_count, max_adversary_runs = self._reserve_adversary_run()
        forced_by_budget = decision is None
        run_reason = (
            "completion review budget" if forced_by_budget else "completion accept"
        )
        self.tui.render(
            "ADVERSARY",
            f"running pre-complete adversarial tester ({adversary_run_count}/{max_adversary_runs}; {run_reason})",
        )
        self.store.append_text_locked(
            PROGRESS,
            f"- Adversarial tester starting before final complete ({adversary_run_count}/{max_adversary_runs}; "
            f"trigger: {run_reason}).\n",
        )
        workspace_state_id = _workspace_state_id(self._active_workspace_root())
        snapshot_root: Path | None = None
        previous_report = getattr(self, "_pending_adversary_report", None)
        previous_report_payload = (
            previous_report.report_text.replace(
                str(self.task_path.resolve()),
                _task_relative_workspace_path(
                    project_root=self.project_root,
                    task_path=self.task_path,
                )
                or self.task_path.name,
            ).replace(str(self.project_root.resolve()), ".")
            if previous_report is not None
            else None
        )
        try:
            dependency_mounts: tuple[_AdversaryReadonlyDependencyMount, ...] = ()
            coder_snapshot = getattr(self, "_coder_snapshot", None)
            if coder_snapshot is not None:
                dependency_mounts = _approved_adversary_dependency_mounts(
                    coder_snapshot,
                    active_workspace_root=self._active_workspace_root(),
                )
            snapshot_root = _create_adversary_snapshot(
                self._active_workspace_root(),
                task_relative_path=_task_relative_workspace_path(
                    project_root=self.project_root,
                    task_path=self.task_path,
                ),
                task_contents=self._canonical_task_text(),
                approved_readonly_dependency_mounts=dependency_mounts,
            )
        except Exception as exc:
            error_summary = f"snapshot setup failed: {exc.__class__.__name__}: {exc}"
            if decision is None:
                await self._fail_required_adversary(
                    packet=packet, error_summary=error_summary
                )
            else:
                await self._complete_after_adversary_unavailable(
                    decision,
                    packet=packet,
                    error_summary=error_summary,
                )
            return
        self._active_adversary_workspace_root = snapshot_root
        self._adversary_denied_commands = []
        agent = AdversaryAgent(
            self.client,
            snapshot_root,
            model=self._adversary_model(),
            intelligence=self._adversary_intelligence(),
            on_thread_start=self._mark_adversary_thread_started,
            on_thread_done=self._mark_adversary_thread_done,
            denied_probes=lambda: list(getattr(self, "_adversary_denied_commands", [])),
            configured_mcp_server_names=getattr(
                self, "_configured_mcp_server_names", ()
            ),
            configured_plugin_names=getattr(self, "_configured_plugin_names", ()),
        )
        try:
            result = await agent.run(
                packet, previous_adversary_report=previous_report_payload
            )
        except AdversaryAgentError as exc:
            self.store.append_raw_log(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "adversary_error",
                    "generation": packet.generation,
                    "completion_wake_sequence": (
                        decision.wake_sequence
                        if decision is not None
                        else packet.wake_sequence
                    ),
                    "adversary_run_count": adversary_run_count,
                    "max_adversary_runs": max_adversary_runs,
                    "error": str(exc),
                }
            )
            if decision is None:
                await self._fail_required_adversary(
                    packet=packet, error_summary=str(exc)
                )
            else:
                await self._complete_after_adversary_unavailable(
                    decision,
                    packet=packet,
                    error_summary=str(exc),
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
            completion_wake_sequence=decision.wake_sequence
            if decision is not None
            else packet.wake_sequence,
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
        self.store.append_text_locked(
            PROGRESS,
            "- Adversarial tester completed; adv_report_controller is normalizing findings and observations.\n",
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "adversary/report_ready",
            decision="normalize",
            reason="pre-complete adversarial report is ready for findings-and-observations normalization",
        )
        await self._run_adv_report_controller(
            report,
            packet=packet,
            accepted_completion_decision=decision,
        )

    async def _run_adv_report_controller(
        self,
        report: AdversaryReport,
        *,
        packet: SupervisorWakePacket,
        accepted_completion_decision: CompletionReviewDecision | None,
    ) -> None:
        agent = self._adv_report_controller_agent()
        if agent is None:
            await self._fail_adv_report_controller(
                "adv_report_controller agent is unavailable"
            )
            return
        review_packet = packet.model_copy(
            update={
                "current_summary": "Normalize the completed adversary report for the coder.",
                "adversary_report": report,
            }
        )
        self.tui.render("ADVERSARY", "normalizing adversary findings and observations")
        normalized: AdvReportControllerDecision | None = None
        for attempt in range(2):
            try:
                candidate = await agent.decide_adv_report(review_packet)
            except SupervisorAgentError as exc:
                await self._fail_adv_report_controller(str(exc))
                return
            contract_issue = _adv_report_normalization_contract_issue(
                report.report_text, candidate
            )
            if contract_issue is None:
                normalized = candidate
                break
            self.store.append_raw_log(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "adv_report_controller_contract_rejection",
                    "generation": packet.generation,
                    "completion_wake_sequence": report.completion_wake_sequence,
                    "attempt": attempt + 1,
                    "issue": contract_issue,
                }
            )
            if attempt == 0:
                review_packet = review_packet.model_copy(
                    update={
                        "current_summary": (
                            "The previous normalization violated the routing contract: "
                            f"{contract_issue}. Re-normalize the same raw report without losing raw observations "
                            "or inventing coverage limitations."
                        )
                    }
                )
        if normalized is None:
            await self._fail_adv_report_controller(
                "normalization violated the findings/observations routing contract twice"
            )
            return
        report = report.model_copy(
            update={
                "material_coverage_limitations": list(
                    normalized.material_coverage_limitations
                ),
            }
        )
        self._pending_adversary_report = report
        provenance_issue = self._completion_precommit_issue(report)
        if provenance_issue is not None:
            task_integrity_issue = self._task_integrity_issue()
            if task_integrity_issue is not None:
                await self.finalize(
                    f"escalated: adversary normalization detected task integrity failure: {task_integrity_issue}",
                    status=BelloStatus.ESCALATED,
                    completion_review_accepted=False,
                )
                return
            self._rerun_stale_completion_review(
                f"adversary normalization is stale: {provenance_issue}"
            )
            return
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "adv_report_controller_decision",
                "generation": packet.generation,
                "completion_wake_sequence": report.completion_wake_sequence,
                "forward_to_coder": normalized.forward_to_coder,
                "reason": normalized.reason,
                "report_to_coder": normalized.report_to_coder,
                "material_coverage_limitations": normalized.material_coverage_limitations,
            }
        )
        if normalized.forward_to_coder:
            self._append_event(
                AppEventSource.SUPERVISOR,
                "adversary/report_normalized",
                decision="return",
                reason=normalized.reason,
            )
            return_decision = CompletionReviewDecision(
                decision=CompletionReviewDecisionKind.RETURN,
                reason=normalized.reason,
                uncovered_behaviors=[
                    "Adversary findings or observations require coder follow-up."
                ],
                message_to_coder=normalized.report_to_coder,
                persistent_decision=None,
                progress_update=None,
                clear_handoff=False,
                display_message=None,
                handoff=None,
                wake_sequence=packet.wake_sequence,
                generation=packet.generation,
            )
            await self._return_completion_to_coder(
                return_decision,
                source_label="Adversary report controller",
            )
            return

        self.store.append_text_locked(
            PROGRESS,
            "- adv_report_controller found no findings or observations to send to the coder; finalizing.\n",
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "adversary/report_normalized",
            decision="complete",
            reason=normalized.reason,
        )
        if accepted_completion_decision is None:
            self._accepted_adversary_report = report
            await self._finalize_bounded_completion(
                reason="completion review budget reached and the normalized adversary report had nothing for the coder",
            )
            return
        await self._finalize_accepted_completion(
            accepted_completion_decision,
            adversary_report=report,
            result=(
                "accepted by completion_review after adversary report normalization: "
                f"{accepted_completion_decision.reason or 'task complete'}"
            ),
        )

    async def _fail_adv_report_controller(self, error_summary: str) -> None:
        self.tui.render("ADVERSARY", f"adv_report_controller failed: {error_summary}")
        self.store.append_text_locked(
            PROGRESS,
            f"- adv_report_controller failed ({error_summary}); the raw adversary report was not sent to the coder.\n",
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "adversary/report_controller_failed",
            reason=error_summary,
        )
        await self.finalize(
            f"adv_report_controller failed: {error_summary}",
            status=BelloStatus.PROVIDER_FAILURE,
            completion_review_accepted=False,
        )

    def _completion_review_budget_action(
        self,
        *,
        packet: SupervisorWakePacket | None = None,
    ) -> Literal["adversary", "complete"] | None:
        # A deterministic coder-correctable rejection remains an open correctness
        # condition.  Recheck it after the coder's next readiness claim even when the
        # ordinary semantic-review budget is exhausted.
        if getattr(self, "_pending_completion_gate_rejection", None) is not None:
            return None
        cfg = self.store.get_bello_config()
        if self._effective_max_adversary_runs() <= 0:
            limit = cfg.max_completion_returns_before_adversary
            if review_limit_reached(limit, cfg.completion_return_count):
                return "complete"
            return None
        if cfg.adversary_run_count == 0:
            limit = cfg.max_completion_returns_before_adversary
            if review_limit_reached(limit, cfg.completion_return_count):
                return "adversary"
            return None
        limit = cfg.max_completion_returns_after_adversary
        if not review_limit_reached(limit, cfg.completion_returns_since_adversary):
            return None
        if self._adversary_runs_remaining():
            return "adversary"
        return "complete"

    async def _finalize_bounded_completion(self, *, reason: str) -> None:
        precommit_issue = self._completion_precommit_issue(
            getattr(self, "_pending_adversary_report", None)
        )
        if precommit_issue is not None:
            self._rerun_stale_completion_review(precommit_issue)
            return
        validation_issue = await self._done_without_fresh_behavioral_validation()
        if validation_issue is not None:
            self.store.append_text_locked(
                PROGRESS,
                "- Bounded review budget did not finalize because current task-appropriate "
                f"validation is missing: {validation_issue}.\n",
            )
            await self._steer_for_marker(
                validation_issue,
                message=(
                    "The final review budget does not waive the evidence floor. Run one trusted "
                    "task-appropriate validation against the current product state after the last "
                    "affecting edit, address any failure, update the checklist evidence, and only "
                    "then emit BELLO_READY_FOR_REVIEW on its own line."
                ),
            )
            return
        cfg = self.store.get_bello_config()
        self.store.append_text_locked(
            PROGRESS,
            "- Bounded completion policy reached its final review budget after the coder applied the last return; "
            "finalizing without fabricating a completion-review accept.\n",
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "completion/budget_finalize",
            decision={
                "kind": "complete",
                "completion_return_count": cfg.completion_return_count,
                "completion_returns_since_adversary": cfg.completion_returns_since_adversary,
                "adversary_run_count": cfg.adversary_run_count,
                "max_adversary_runs": self._effective_max_adversary_runs(),
            },
            reason=reason,
        )
        self._accepted_completion_decision = None
        await self.finalize(
            f"completed by bounded review policy: {reason}",
            status=BelloStatus.COMPLETE,
            completion_review_accepted=False,
        )

    async def _fail_required_adversary(
        self,
        *,
        packet: SupervisorWakePacket | None,
        error_summary: str,
    ) -> None:
        cfg = self.store.get_bello_config()
        report = AdversaryReport(
            status="error",
            candidate_finding=False,
            report_text=f"required adversary did not run: {error_summary}",
            material_coverage_limitations=[
                f"Required adversary coverage unavailable: {error_summary}"
            ],
            generation=packet.generation if packet is not None else cfg.generation,
            completion_wake_sequence=packet.wake_sequence
            if packet is not None
            else cfg.last_event_sequence + 1,
            latest_relevant_change_sequence=packet.latest_relevant_change_sequence
            if packet is not None
            else None,
            validation_sequence=_latest_validation_sequence(packet.validations)
            if packet is not None
            else None,
            workspace_state_id=_workspace_state_id(self._active_workspace_root()),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._pending_adversary_report = report
        self.tui.render(
            "ADVERSARY", f"required adversarial tester could not run: {error_summary}"
        )
        self.store.append_text_locked(
            PROGRESS,
            f"- Required adversarial tester could not run ({error_summary}); failing the run instead of treating it as accepted.\n",
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "adversary/required_unavailable",
            reason=error_summary,
        )
        await self.finalize(
            f"required adversary failed under bounded review policy: {error_summary}",
            status=BelloStatus.PROVIDER_FAILURE,
            completion_review_accepted=False,
        )

    async def _finalize_completion_review_disabled(self) -> None:
        """Completion review is disabled: the coder's readiness marker is the finish line.

        Runtime supervision (approvals, steering, restarts) already ran its course; the
        final report carries the validation ledger and states plainly that no completion
        review or adversary pass certified the result.
        """
        self.store.append_text_locked(
            PROGRESS,
            "- Coder declared readiness; completion review is disabled by config, finalizing without review.\n",
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "completion/review_disabled_finalize",
            reason="coder readiness marker with completion review disabled",
        )
        await self.finalize(
            "coder declared readiness; completion review disabled by config (no review or adversary certification)",
            status=BelloStatus.COMPLETE,
            completion_review_accepted=False,
        )

    async def _finalize_accepted_completion(
        self,
        decision: CompletionReviewDecision,
        *,
        adversary_report: AdversaryReport | None,
        result: str,
    ) -> None:
        precommit_issue = self._completion_precommit_issue(adversary_report)
        if precommit_issue is not None:
            self._rerun_stale_completion_review(precommit_issue)
            return
        cfg = self.store.get_bello_config()
        if decision.persistent_decision:
            self.store.append_text_locked(
                DECISIONS, f"- {decision.persistent_decision}\n"
            )
        if decision.progress_update:
            self.store.append_text_locked(PROGRESS, f"- {decision.progress_update}\n")
            patch_health(
                self.store,
                HealthDelta(
                    generation=cfg.generation,
                    last_progress_sequence=cfg.last_event_sequence,
                ),
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
        self._accepted_adversary_report = adversary_report
        await self.finalize(
            result,
            status=BelloStatus.COMPLETE,
            completion_review_accepted=True,
        )

    async def _complete_after_adversary_unavailable(
        self,
        decision: CompletionReviewDecision,
        *,
        packet: SupervisorWakePacket | None,
        error_summary: str,
    ) -> None:
        """The completion review accepted and only the adversary could not run.

        That is a tester-availability problem, not evidence against the accepted work:
        finalize the accept with the missing adversary coverage recorded loudly (same
        terminal shape as adversary-disabled or limit-reached) instead of declaring the
        whole run infrastructure-invalid and discarding a reviewed, accepted solution.
        """
        cfg = self.store.get_bello_config()
        report = AdversaryReport(
            status="error",
            candidate_finding=False,
            report_text=f"adversary did not run: {error_summary}",
            material_coverage_limitations=[
                f"Adversary coverage unavailable: {error_summary}"
            ],
            generation=packet.generation if packet is not None else cfg.generation,
            completion_wake_sequence=decision.wake_sequence,
            latest_relevant_change_sequence=packet.latest_relevant_change_sequence
            if packet is not None
            else None,
            validation_sequence=_latest_validation_sequence(packet.validations)
            if packet is not None
            else None,
            workspace_state_id=_workspace_state_id(self._active_workspace_root()),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.tui.render(
            "ADVERSARY",
            f"adversarial tester could not run ({error_summary}); finalizing completion accept",
        )
        self.store.append_text_locked(
            PROGRESS,
            f"- Adversarial tester could not run ({error_summary}); finalizing prior completion accept "
            "with adversary coverage recorded as missing.\n",
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "adversary/unavailable",
            reason=error_summary,
        )
        await self._finalize_accepted_completion(
            decision,
            adversary_report=report,
            result=f"accepted by completion_review; adversary tester could not run: {error_summary}",
        )

    def _adversary_runs_remaining(self) -> bool:
        cfg = self.store.get_bello_config()
        return cfg.adversary_run_count < self._effective_max_adversary_runs()

    def _should_run_adversary_before_complete(
        self, packet: SupervisorWakePacket | None
    ) -> bool:
        if self._packet_has_fresh_adversary_report(packet):
            return False
        enabled = getattr(self, "adversary_enabled", None)
        if enabled is False:
            return False
        if enabled is True:
            return True
        return self.store.get_bello_config().max_adversary_runs > 0

    def _reserve_adversary_run(self) -> tuple[int, int]:
        max_adversary_runs = self._effective_max_adversary_runs()
        updated = self.store.update_bello_config(
            lambda current: current.model_copy(
                update={
                    "adversary_run_count": current.adversary_run_count + 1,
                    "completion_returns_since_adversary": 0,
                }
            )
        )
        return updated.adversary_run_count, max_adversary_runs

    def _record_adversary_limit_reached(
        self, packet: SupervisorWakePacket | None
    ) -> None:
        cfg = self.store.get_bello_config()
        max_adversary_runs = self._effective_max_adversary_runs()
        reason = f"adversary run limit reached ({cfg.adversary_run_count}/{max_adversary_runs})"
        pending_report = getattr(self, "_pending_adversary_report", None)
        if pending_report is not None and not self._packet_has_fresh_adversary_report(
            packet
        ):
            self._quarantine_pending_adversary_report(
                f"{reason}; the previous adversary report does not cover the accepted workspace"
            )
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
                "max_adversary_runs": max_adversary_runs,
            }
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "adversary/limit_reached",
            reason=reason,
        )

    def _effective_max_adversary_runs(self) -> int:
        if not self._effective_completion_review():
            # The adversary runs inside the completion-review accept path; without the
            # review gate there is no point where it could fire.
            return 0
        enabled = getattr(self, "adversary_enabled", None)
        if enabled is False:
            return 0
        override = getattr(self, "adversary_runs", None)
        configured_runs = (
            self.store.get_bello_config().max_adversary_runs
            if override is None
            else override
        )
        if enabled is True:
            return max(1, configured_runs)
        return configured_runs

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
        if not report.workspace_state_id:
            return None
        if report.latest_relevant_change_sequence != latest_relevant_change_sequence:
            return None
        if report.workspace_state_id != _workspace_state_id(
            self._active_workspace_root()
        ):
            return None
        return report

    def _packet_has_fresh_adversary_report(
        self, packet: SupervisorWakePacket | None
    ) -> bool:
        if packet is None:
            return False
        report = packet.adversary_report
        if report is None:
            return False
        if report.status != "completed" or report.generation != packet.generation:
            return False
        if not report.workspace_state_id:
            return False
        if (
            report.latest_relevant_change_sequence
            != packet.latest_relevant_change_sequence
        ):
            return False
        if report.workspace_state_id != _workspace_state_id(
            self._active_workspace_root()
        ):
            return False
        return True

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
        if (
            decision.basis_event_seq is not None
            and packet.latest_event_sequence > decision.basis_event_seq
        ):
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
        latest_validation_seq = max(
            (validation.sequence for validation in packet.validations), default=None
        )
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

    async def _handle_completion_decision_staleness_failure(
        self, issue: dict[str, Any]
    ) -> None:
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
        completion_supervisor = self._completion_supervisor_agent()
        if completion_supervisor is not None:
            await completion_supervisor.close_completion_review()
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
        validations = (
            packet.validations if packet is not None else list(self.validations)
        )
        inspections = (
            packet.inspections
            if packet is not None
            else list(getattr(self, "inspections", []))
        )
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
                "packet_mode": packet.completion_payload_mode
                if packet is not None
                else None,
                "packet_since_sequence": packet.completion_payload_since_sequence
                if packet is not None
                else None,
                "validation_ids": [
                    validation.validation_id
                    for validation in (packet.validations if packet else [])
                ],
                "changed_files": [
                    changed.path for changed in (packet.changed_files if packet else [])
                ],
            }
        )

    def _capture_completion_review_token(self) -> CompletionReviewToken:
        cfg = self.store.get_bello_config()
        last_message = getattr(self, "last_coder_message", None)
        return CompletionReviewToken(
            workspace_state_id=_workspace_state_id(self._active_workspace_root()),
            git_state_id=_git_review_state_id(self._active_workspace_root()),
            task_state_id=_task_review_state_id(
                Path(getattr(self, "task_path", self._active_task_path()))
            ),
            generation=cfg.generation,
            coder_thread_id=cfg.coder_thread_id,
            active_coder_turn_id=cfg.active_coder_turn_id,
            controller_status=cfg.status.value,
            paused=bool(getattr(self, "paused", False)),
            pending_approvals_fingerprint=_pending_approvals_fingerprint(
                getattr(self, "pending_approvals", {})
            ),
            product_revision=int(getattr(self, "_completion_product_revision", 0)),
            latest_relevant_edit_sequence=cfg.last_relevant_edit_sequence,
            validation_fingerprint=_review_ledger_fingerprint(
                list(getattr(self, "validations", []))
            ),
            inspection_fingerprint=_review_ledger_fingerprint(
                list(getattr(self, "inspections", []))
            ),
            changed_files_fingerprint=_changed_file_revision_fingerprint(
                list(getattr(self, "observed_changed_files", {}).values())
                if isinstance(getattr(self, "observed_changed_files", None), dict)
                else []
            ),
            last_coder_message_sequence=(
                last_message.sequence
                if isinstance(last_message, CoderMessage)
                else None
            ),
        )

    def _completion_review_token_issue(
        self, expected: CompletionReviewToken | None
    ) -> str | None:
        if expected is None:
            return "completion review has no immutable state token"
        current = self._capture_completion_review_token()
        changed_fields = [
            field_name
            for field_name in (
                "workspace_state_id",
                "git_state_id",
                "task_state_id",
                "generation",
                "coder_thread_id",
                "active_coder_turn_id",
                "controller_status",
                "paused",
                "pending_approvals_fingerprint",
                "product_revision",
                "latest_relevant_edit_sequence",
                "validation_fingerprint",
                "inspection_fingerprint",
                "changed_files_fingerprint",
                "last_coder_message_sequence",
            )
            if getattr(current, field_name) != getattr(expected, field_name)
        ]
        if not changed_fields:
            return None
        return "reviewed product state changed in: " + ", ".join(changed_fields)

    def _completion_precommit_issue(
        self, adversary_report: AdversaryReport | None = None
    ) -> str | None:
        task_integrity_issue = self._task_integrity_issue()
        if task_integrity_issue is not None:
            return task_integrity_issue
        cfg = self.store.get_bello_config()
        if cfg.active_coder_turn_id:
            return "a coder turn is active during completion commit"
        if getattr(self, "pending_approvals", None):
            return "a coder approval request is pending during completion commit"
        expected_token: CompletionReviewToken | None = None
        if hasattr(self, "_completion_review_token"):
            expected_token = getattr(self, "_accepted_completion_review_token", None)
            issue = self._completion_review_token_issue(expected_token)
            if issue is not None:
                return issue
        if adversary_report is not None:
            expected_generation = (
                expected_token.generation
                if expected_token is not None
                else cfg.generation
            )
            if hasattr(self, "_accepted_completion_latest_relevant_change_sequence"):
                expected_latest_edit = (
                    self._accepted_completion_latest_relevant_change_sequence
                )
            else:
                expected_latest_edit = (
                    expected_token.latest_relevant_edit_sequence
                    if expected_token is not None
                    else cfg.last_relevant_edit_sequence
                )
            if adversary_report.generation != expected_generation:
                return (
                    "adversary report generation does not cover the completion state: "
                    f"{adversary_report.generation} != {expected_generation}"
                )
            if adversary_report.latest_relevant_change_sequence != expected_latest_edit:
                return (
                    "adversary report edit sequence does not cover the completion state: "
                    f"{adversary_report.latest_relevant_change_sequence} != {expected_latest_edit}"
                )
            if not adversary_report.workspace_state_id:
                return "adversary report is not bound to a workspace state"
            current_workspace_state = _workspace_state_id(self._active_workspace_root())
            if adversary_report.workspace_state_id != current_workspace_state:
                return "latest workspace state is not covered by the adversary report"
        return None

    def _rerun_stale_completion_review(self, reason: str) -> None:
        self.store.append_text_locked(
            PROGRESS,
            f"- Controller discarded a stale completion result and scheduled a fresh review: {reason}.\n",
        )
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "completion_review_product_state_stale",
                "reason": reason,
            }
        )
        self._append_event(
            AppEventSource.SUPERVISOR,
            "completion/product_state_stale",
            decision="rerun",
            reason=reason,
        )
        self._accepted_completion_decision = None
        self._accepted_adversary_report = None
        self._accepted_completion_review_token = None
        if hasattr(self, "_accepted_completion_latest_relevant_change_sequence"):
            del self._accepted_completion_latest_relevant_change_sequence
        self.completion_reviewer_evidence = []
        self._quarantine_pending_adversary_report(reason)
        self._schedule_supervisor_check(
            "The product state changed while completion was being reviewed. Discard the stale verdict and run "
            f"completion_review again against the current workspace and ledgers ({reason}).",
            completion_review=True,
        )

    def _quarantine_pending_adversary_report(self, reason: str) -> None:
        stale_report = getattr(self, "_pending_adversary_report", None)
        if stale_report is None:
            return
        limitation = (
            f"Stale adversary report was quarantined before completion: {reason}."
        )
        stale_limitations = getattr(self, "_adversary_stale_limitations", None)
        if stale_limitations is None:
            stale_limitations = self._adversary_stale_limitations = []
        if limitation not in stale_limitations:
            stale_limitations.append(limitation)
        self._pending_adversary_report = None
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "adversary_report_quarantined",
                "reason": reason,
                "report_generation": stale_report.generation,
                "report_workspace_state_id": stale_report.workspace_state_id,
            }
        )

    def _record_completion_reviewer_evidence(
        self,
        items: list[dict[str, Any]],
        *,
        workspace_state_id: str,
    ) -> None:
        records = [
            record
            for item in items
            if (
                record := _completion_reviewer_evidence_from_item(
                    item,
                    workspace_state_id=workspace_state_id,
                    workspace_root=self._active_workspace_root(),
                )
            )
            is not None
        ]
        existing = [
            record
            for record in getattr(self, "completion_reviewer_evidence", [])
            if record.workspace_state_id == workspace_state_id
        ]
        self.completion_reviewer_evidence = list(dict.fromkeys((*existing, *records)))[
            -50:
        ]
        if not records:
            return
        self.store.append_raw_log(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "completion_reviewer_evidence",
                "workspace_state_id": workspace_state_id,
                "records": [
                    {
                        "kind": record.kind,
                        "command": record.command,
                        "paths": list(record.paths),
                        "passed": record.passed,
                        "summary": record.summary,
                        "path_commands": [
                            list(binding) for binding in record.path_commands
                        ],
                        "resource_paths": list(record.resource_paths),
                        "observed_output": record.observed_output,
                        "empty_paths": list(record.empty_paths),
                        "patch_paths": list(record.patch_paths),
                    }
                    for record in records
                ],
            }
        )

    def _completion_review_access_issue(
        self,
        decision: CompletionReviewDecision,
        *,
        packet: SupervisorWakePacket,
        workspace_state_id: str,
    ) -> str | None:
        """Detect an infrastructure-invalid review before it consumes C-budget.

        Completion packets intentionally omit inline source/diffs.  For any
        material change, a review with no successful workspace-bound read
        therefore did not actually see the submitted implementation or artifact,
        regardless of how plausible its structured verdict looks.
        """
        for limitation in decision.packet_or_access_limitations:
            lowered = limitation.lower()
            if "checklist" in lowered:
                continue
            unavailable = any(
                marker in lowered
                for marker in (
                    "access denied",
                    "permission denied",
                    "cannot access",
                    "could not access",
                    "unable to access",
                    "cannot read",
                    "could not read",
                    "unable to read",
                    "unavailable",
                    "no access",
                )
            )
            review_surface = any(
                marker in lowered
                for marker in (
                    "workspace",
                    "repository",
                    "source",
                    "implementation",
                    "shell",
                    "command",
                    "tool",
                )
            )
            if unavailable and review_surface:
                return f"completion reviewer reported material source access failure: {limitation}"

        evidence = list(getattr(self, "completion_reviewer_evidence", []))
        if not _reviewer_evidence_has_capable_workspace_read(
            evidence, workspace_state_id=workspace_state_id
        ):
            return (
                "completion reviewer produced no successful capable workspace-bound "
                "read on the current workspace state"
            )

        review_files = list(
            {
                changed.path: changed
                for changed in (
                    *_material_code_review_files(
                        packet.changed_files,
                        task_contents=packet.task_contents,
                    ),
                    *_material_static_review_files(
                        packet.changed_files,
                        task_contents=packet.task_contents,
                    ),
                )
            }.values()
        )
        if not review_files:
            return None
        covered = [
            changed.path
            for changed in review_files
            if _reviewer_evidence_covers_path(
                evidence,
                changed.path,
                workspace_state_id=workspace_state_id,
            )
        ]
        if not covered:
            return (
                "completion reviewer produced no successful workspace-bound read of "
                "any material changed file"
            )
        return None

    async def _completion_accept_gate(
        self,
        decision: CompletionReviewDecision,
        *,
        packet: SupervisorWakePacket | None,
    ) -> AcceptGateResult:
        try:
            blocker_fields = completion_review_accept_blocker_fields(decision)
        except (AttributeError, TypeError, ValueError) as exc:
            return AcceptGateResult(
                passed=False,
                failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                check_name="typed_structure",
                reason=f"completion accept contains malformed typed evidence: {exc}",
            )
        if blocker_fields:
            return AcceptGateResult(
                passed=False,
                failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                check_name="typed_blockers",
                reason=(
                    "completion accept contains actionable blockers or unclosed requirements: "
                    + ", ".join(blocker_fields)
                ),
                details={"blocker_fields": blocker_fields},
            )

        changed_files = (
            packet.changed_files if packet is not None else await self.changed_files()
        )
        validations = (
            packet.validations if packet is not None else list(self.validations)
        )
        inspections = (
            packet.inspections
            if packet is not None
            else list(getattr(self, "inspections", []))
        )
        task_contents = (
            packet.task_contents if packet is not None else self._canonical_task_text()
        )
        behavior_affecting_files = [
            file
            for file in changed_files
            if _changed_file_is_behavior_affecting(file, task_contents=task_contents)
        ]
        code_review_files = _material_code_review_files(
            changed_files, task_contents=task_contents
        )
        static_review_files = _material_static_review_files(
            changed_files,
            task_contents=task_contents,
        )
        passed_checks: list[str] = []

        reviewed_workspace_state = getattr(
            self, "_completion_review_workspace_state_id", None
        )
        if hasattr(self, "_completion_review_token"):
            token_issue = self._completion_review_token_issue(
                getattr(self, "_completion_review_token", None)
            )
            if token_issue is not None:
                return AcceptGateResult(
                    passed=False,
                    failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                    check_name="review_product_state",
                    reason=token_issue,
                )
            passed_checks.append("review_product_state")
        if (
            reviewed_workspace_state is not None
            and reviewed_workspace_state
            != _workspace_state_id(self._active_workspace_root())
        ):
            return AcceptGateResult(
                passed=False,
                failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                check_name="review_workspace_state",
                reason="workspace changed after the completion review began; rerun review on the current state",
            )
        if reviewed_workspace_state is not None:
            passed_checks.append("review_workspace_state")

        task_integrity_issue = self._task_integrity_issue()
        if task_integrity_issue is not None:
            original_changed = task_integrity_issue.startswith("the original task file")
            return AcceptGateResult(
                passed=False,
                failure_type=ACCEPT_GATE_AUDIT_FAILURE
                if original_changed
                else ACCEPT_GATE_CODER_CORRECTABLE,
                check_name="task_integrity",
                reason=task_integrity_issue,
            )
        passed_checks.append("task_integrity")

        if packet is not None:
            if packet.pending_approvals:
                return AcceptGateResult(
                    passed=False,
                    failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                    check_name="structural_consistency",
                    reason="completion cannot be accepted while a coder approval request is pending",
                )
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

        if getattr(self, "_completion_review_token", None) is not None:
            structural_issue = _accept_structural_issue(
                decision,
                code_changing=bool(behavior_affecting_files),
                expected_surface_categories=tuple(
                    item.category
                    for item in (packet.behavior_surface if packet else [])
                ),
            )
            if structural_issue is not None:
                return AcceptGateResult(
                    passed=False,
                    failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                    check_name="review_structure",
                    reason=structural_issue,
                )
            passed_checks.append("review_structure")

        latest_change = max(
            (
                file.sequence
                for file in behavior_affecting_files
                if file.sequence is not None
            ),
            default=None,
        )

        try:
            evidence_issue = _behavior_evidence_binding_issue(
                decision,
                validations=validations,
                inspections=inspections,
                latest_change=latest_change,
                task_contents=task_contents,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            evidence_issue = f"malformed behavior evidence: {exc}"
        if evidence_issue is not None:
            return AcceptGateResult(
                passed=False,
                failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                check_name="evidence_binding",
                reason=evidence_issue,
            )
        if decision.behavior_evidence_matrix:
            passed_checks.append("evidence_binding")

        if behavior_affecting_files:
            if latest_change is None:
                return AcceptGateResult(
                    passed=False,
                    failure_type=ACCEPT_GATE_CODER_CORRECTABLE,
                    check_name="behavioral_floor",
                    reason="latest behavior-affecting source/test/config change sequence is unknown, so validation freshness is not proven",
                )
            fresh_behavioral = any(
                _validation_is_fresh_behavioral_pass(validation, latest_change)
                for validation in validations
            )
            fresh_static_contract = _task_is_intrinsically_static_contract(
                task_contents
            ) and _decision_has_fresh_static_contract_evidence(
                decision,
                validations=validations,
                latest_change=latest_change,
                task_contents=task_contents,
            )
            if not fresh_behavioral and not fresh_static_contract:
                return AcceptGateResult(
                    passed=False,
                    failure_type=ACCEPT_GATE_CODER_CORRECTABLE,
                    check_name="behavioral_floor",
                    reason=(
                        "no fresh passing behavioral validation after the latest behavior-affecting change, "
                        "and no fully bound fresh evidence for an intrinsically static task contract"
                    ),
                )
            passed_checks.append(
                "behavioral_floor"
                if fresh_behavioral
                else "intrinsic_static_contract_floor"
            )

        if code_review_files:
            code_review_issue = _accept_file_review_issue(
                decision,
                code_review_files,
                reviewer_evidence=(
                    list(getattr(self, "completion_reviewer_evidence", []))
                    if reviewed_workspace_state is not None
                    else None
                ),
                workspace_state_id=reviewed_workspace_state,
            )
            if code_review_issue is not None:
                return AcceptGateResult(
                    passed=False,
                    failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                    check_name="code_review_coverage",
                    reason=code_review_issue,
                    details={"files": [file.path for file in code_review_files[:20]]},
                )
            passed_checks.append("code_review_coverage")

        if static_review_files:
            if (
                hasattr(self, "_completion_review_workspace_state_id")
                and reviewed_workspace_state is None
            ):
                return AcceptGateResult(
                    passed=False,
                    failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                    check_name="static_artifact_review",
                    reason="completion review has no workspace-bound reviewer evidence token",
                    details={"files": [file.path for file in static_review_files[:20]]},
                )
            review_issue = _accept_static_review_issue(
                decision,
                static_review_files,
                reviewer_evidence=(
                    list(getattr(self, "completion_reviewer_evidence", []))
                    if reviewed_workspace_state is not None
                    else None
                ),
                workspace_state_id=reviewed_workspace_state,
                task_contents=task_contents,
            )
            if review_issue is not None:
                return AcceptGateResult(
                    passed=False,
                    failure_type=ACCEPT_GATE_REVIEWER_INCOMPLETE,
                    check_name="static_artifact_review",
                    reason=review_issue,
                    details={"files": [file.path for file in static_review_files[:20]]},
                )
            passed_checks.append("static_artifact_review")

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

        if failure_type == ACCEPT_GATE_AUDIT_FAILURE:
            self._append_event(
                AppEventSource.SUPERVISOR,
                "completion/accept_gate_audit_failure",
                decision=ACCEPT_GATE_AUDIT_FAILURE,
                reason=f"{check_name}: {reason}",
            )
            self._increment_accept_gate_counter("accept_gate_audit_failures")
            await self.finalize(
                f"escalated: controller-side integrity failure: {check_name}: {reason}",
                status=BelloStatus.ESCALATED,
            )
            return

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
                self.store.append_text_locked(
                    PROGRESS,
                    f"- Controller-side proof-format failure: {infra_reason}\n",
                )
                self._append_event(
                    AppEventSource.SUPERVISOR,
                    "completion/accept_gate_proof_format_failure",
                    decision=ACCEPT_GATE_AUDIT_FAILURE,
                    reason=infra_reason,
                )
                self._increment_accept_gate_counter("accept_gate_audit_failures")
                await self.finalize(
                    f"infra-invalid: controller-side proof-format repair failed: {infra_reason}",
                    status=BelloStatus.PROVIDER_FAILURE,
                )
                return

            audit_reason = f"repeated reviewer-incomplete accept gate failure ({check_name}): {reason}"
            self.store.append_text_locked(
                PROGRESS, f"- Controller-side audit failure: {audit_reason}\n"
            )
            self._append_event(
                AppEventSource.SUPERVISOR,
                "completion/accept_gate_audit_failure",
                decision=ACCEPT_GATE_AUDIT_FAILURE,
                reason=audit_reason,
            )
            self._increment_accept_gate_counter("accept_gate_audit_failures")
            await self.finalize(
                f"escalated: controller-side audit failure: {audit_reason}",
                status=BelloStatus.ESCALATED,
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
            if inspection.sequence > since_sequence
            and inspection.outcome == "pass"
            and inspection.passed
        ]
        if not fresh_validation_ids and not fresh_inspection_ids:
            return None
        if not _completion_return_has_evidence_related_gap(decision):
            return None
        if _completion_decision_cites_evidence_after(
            decision, since_sequence=since_sequence
        ):
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

    async def _handle_completion_return_freshness_failure(
        self, issue: dict[str, Any]
    ) -> None:
        reason = str(
            issue.get("reason") or "completion_review ignored fresh delta evidence"
        )
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
        completion_supervisor = self._completion_supervisor_agent()
        if completion_supervisor is not None:
            await completion_supervisor.close_completion_review()
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
        self.store.update_bello_config(
            lambda current: current.model_copy(
                update={field: getattr(current, field, 0) + 1}
            )
        )

    def _bounded_accept_gate_coder_return_used(
        self, check_name: str, details: dict[str, Any]
    ) -> bool:
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
            if (
                not isinstance(gate_context, dict)
                or gate_context.get("check_name") != check_name
            ):
                continue
            previous_details = (
                gate_context.get("details")
                if isinstance(gate_context.get("details"), dict)
                else {}
            )
            if previous_details.get("bounded_coder_return_key") == key:
                return True
        return False

    async def _return_completion_to_coder(
        self,
        decision: CompletionReviewDecision,
        *,
        source_label: str = "Completion review",
    ) -> None:
        self._accepted_completion_review_token = None
        if hasattr(self, "_accepted_completion_latest_relevant_change_sequence"):
            del self._accepted_completion_latest_relevant_change_sequence
        if source_label == "Adversary report controller":
            return_source: Literal[
                "completion_review", "accept_gate", "adversary_report_controller"
            ] = "adversary_report_controller"
        elif getattr(self, "_current_accept_gate_rejection", None):
            return_source = "accept_gate"
        else:
            return_source = "completion_review"
        record = CompletionReturnRecord(
            source=return_source,
            reason=decision.reason,
            uncovered_behaviors=decision.uncovered_behaviors,
            validation_gaps=decision.validation_gaps,
            claim_evidence_mismatches=decision.claim_evidence_mismatches,
            packet_or_access_limitations=decision.packet_or_access_limitations,
            message_to_coder=decision.message_to_coder,
            accept_gate_check_name=(
                getattr(self, "_current_accept_gate_rejection", None) or {}
            ).get("check_name"),
            accept_gate_details=getattr(self, "_current_accept_gate_rejection", None)
            or {},
            sequence=decision.wake_sequence,
            generation=decision.generation,
        )
        self.completion_returns = [*getattr(self, "completion_returns", []), record][
            -50:
        ]
        self.completion_review_return_sequence = decision.wake_sequence
        validation_sequences = [validation.sequence for validation in self.validations]
        self.completion_review_return_validation_sequence = (
            max(validation_sequences) if validation_sequences else None
        )
        if not decision.progress_update:
            details = _completion_return_summary(decision)
            self.store.append_text_locked(
                PROGRESS, f"- {source_label} returned: {details}\n"
            )
        self.prior_interventions.append(
            PriorIntervention(
                reason=f"{source_label} returned: {decision.reason}",
                # Runtime triage uses this exact text to notice that the coder
                # violated a recent return. Completion-prompt compaction removes
                # the duplicate copy when the typed CompletionReturnRecord is also
                # present; do not weaken the frequent runtime path here.
                message_to_coder=decision.message_to_coder or "",
                sequence=decision.wake_sequence,
            )
        )
        self.prior_interventions = self.prior_interventions[-20:]
        if return_source != "adversary_report_controller":
            self.store.update_bello_config(
                lambda current: current.model_copy(
                    update={
                        "completion_return_count": current.completion_return_count
                        + 1,
                        "completion_returns_since_adversary": (
                            current.completion_returns_since_adversary + 1
                            if current.adversary_run_count > 0
                            else 0
                        ),
                    }
                )
            )
        if self.coder and decision.message_to_coder:
            await self.coder.steer_or_start(decision.message_to_coder)
        # Fresh completion-review thread per review: close the session after each return so
        # the next readiness review starts a new thread instead of accumulating prior turns.
        # The persistent thread otherwise grows ~55-85k tokens per return and crossed the
        # model context window within a generation, forcing lossy auto-compaction. Prior
        # returns are still carried into the next review via previous_completion_returns,
        # and the reviewer re-reads the workspace live, so no context is lost.
        supervisor = self._completion_supervisor_agent()
        if supervisor is not None and hasattr(supervisor, "close_completion_review"):
            await supervisor.close_completion_review()

    async def _resolve_pending_approvals(self, reason: str) -> None:
        approvals = getattr(self, "approvals", None)
        if approvals is None:
            manager = ApprovalManager(
                self._active_workspace_root(),
                declared_grading_roots=getattr(self, "declared_grading_roots", ()),
                immutable_paths=self._immutable_approval_paths(),
            )
        else:
            manager = approvals
        for request_id, context in list(self.pending_approvals.items()):
            resolution = manager._deny(context, reason)
            await self.client.respond(
                request_id, manager.response_payload(context, resolution)
            )
            self.pending_approvals.pop(request_id, None)
        self.store.update_bello_config(
            lambda cfg: cfg.model_copy(update={"pending_server_request_ids": []})
        )

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

    async def _settle_supervisor_task_for_run_shutdown(self) -> None:
        """Let an in-flight terminal commit finish; cancel ordinary checks.

        Completion decisions run in ``_supervisor_task``.  Their terminal path sets
        ``running`` false before applying the accepted snapshot and writing the final
        report.  The controller event loop may therefore return while that commit is
        still in progress.  Cancelling it here would leave the run marked running and
        preserve the accepted snapshot as an unhandled shutdown.

        Outside terminal cleanup, the old cancellation behavior is still required so
        provider failures and external shutdowns do not wait on a stale model turn.
        """

        task = self._supervisor_task
        if task is None or task.done() or task is asyncio.current_task():
            return
        terminal_owner = getattr(self, "_terminal_cleanup_owner_task", None)
        if (
            not getattr(self, "_terminal_cleanup_started", False)
            or task is not terminal_owner
        ):
            await self._stop_supervisor_task()
            return
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            self._append_cleanup_error(
                cleanup_kind="terminal_supervisor_task",
                thread_id="unknown",
                turn_id=None,
                error=exc,
            )

    async def diff_summary(self) -> str:
        if not self.use_git_diff:
            return ""
        if not await self._is_git_work_tree():
            return ""
        commands = [
            ["git", "status", "--short"],
            ["git", "diff", "--stat"],
            ["git", "diff", "--name-only"],
        ]
        parts: list[str] = []
        for command in commands:
            output = await self._git_output(command)
            if output is not None:
                output = _filter_internal_git_output(
                    output,
                    command=command,
                    project_root=self._active_workspace_root(),
                    task_path=self._active_task_path(),
                )
                parts.append(f"$ {' '.join(command)}\n{output}")
        return "\n\n".join(parts)

    async def changed_files(self) -> list[ChangedFile]:
        if not self.use_git_diff:
            return _observed_changed_files(self)
        if not await self._is_git_work_tree():
            return _observed_changed_files(self)
        status_text = await self._git_output(
            ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"]
        )
        numstat_text = await self._git_output(
            ["git", "diff", "--numstat", "HEAD", "--"]
        )
        if status_text is None and numstat_text is None:
            return []
        files: dict[str, ChangedFile] = {}
        for path, status in _git_status_entries_from_porcelain_v1_z(status_text or ""):
            if path and not _is_ignored_changed_path(
                path,
                project_root=self._active_workspace_root(),
                task_path=self._active_task_path(),
            ):
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
            if not path or _is_ignored_changed_path(
                path,
                project_root=self._active_workspace_root(),
                task_path=self._active_task_path(),
            ):
                continue
            existing = files.get(path)
            status = existing.status if existing else "modified"
            files[path] = ChangedFile(
                path=path, status=status, additions=additions, deletions=deletions
            )
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
            if self.store.is_coder_checklist_path(
                raw_path, cwd=self._active_workspace_root()
            ):
                # Ignore only the exact state-file path while its final component is
                # still the expected regular single-link file. Resolving that final
                # component would let a substituted symlink hide a product edit.
                if self.store.read_coder_checklist() is not None:
                    continue
                if self.store.ensure_coder_checklist():
                    self.store.append_text_locked(
                        PROGRESS,
                        "- Integrity guard: reset an invalid or oversized coder checklist after its file change.\n",
                    )
                    self.store.append_raw_log(
                        {
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "type": "coder_checklist_repaired_after_file_change",
                            "path": str(self.store.coder_checklist_path()),
                        }
                    )
                continue
            path = _workspace_display_path(self._active_workspace_root(), raw_path)
            if path and not _is_ignored_changed_path(
                path,
                project_root=self._active_workspace_root(),
                task_path=self._active_task_path(),
            ):
                observed[path] = ChangedFile(
                    path=path,
                    status="modified",
                    sequence=getattr(self, "_sequence", None),
                )

    async def _is_git_work_tree(self) -> bool:
        output = await self._git_output(["git", "rev-parse", "--is-inside-work-tree"])
        return output == "true"

    async def _git_output(self, command: list[str]) -> str | None:
        try:
            exec_command = command
            env = None
            snapshot = getattr(self, "_coder_snapshot", None)
            if command and command[0] == "git":
                if snapshot is not None and not snapshot.git_control_is_trusted():
                    return None
                exec_command = ["git", "-c", "core.fsmonitor=false", *command[1:]]
                if len(command) > 1 and command[1] == "diff":
                    safe_diff_flags = [
                        flag
                        for flag in ("--no-ext-diff", "--no-textconv")
                        if flag not in exec_command
                    ]
                    exec_command = [
                        *exec_command[:4],
                        *safe_diff_flags,
                        *exec_command[4:],
                    ]
                if snapshot is not None:
                    env = snapshot_git_environment()
                else:
                    env = os.environ.copy()
                    env.update(
                        {
                            "GIT_OPTIONAL_LOCKS": "0",
                            "GIT_PAGER": "cat",
                            "GIT_TERMINAL_PROMPT": "0",
                        }
                    )
            proc = await asyncio.create_subprocess_exec(
                *exec_command,
                cwd=str(self._active_workspace_root()),
                env=env,
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
        for command in (
            ["git", "diff", "--unified=2", "--"],
            ["git", "diff", "--cached", "--unified=2", "--"],
        ):
            output = await self._git_output(command)
            if output:
                parts.append(f"$ {' '.join(command)}\n{output}")
        if not parts:
            return None
        return _bounded_text("\n\n".join(parts), limit=limit)

    # --- cross-review knowledge: accumulated behavior surface + carried suspicions ---

    def _completion_knowledge(self) -> dict[str, list[Any]]:
        # In-memory only (see __init__): survives in-run restarts because the controller object
        # is reused, and is never sourced from the coder-writable workspace. Lazily initialized
        # so controllers built via __new__ in tests still work.
        state = getattr(self, "_completion_knowledge_state", None)
        if state is None:
            state = {"behavior_surface": [], "uncovered_edge_candidates": []}
            self._completion_knowledge_state = state
        return state

    def _behavior_surface_items(self) -> list[BehaviorSurfaceItem]:
        items: list[BehaviorSurfaceItem] = []
        for entry in self._completion_knowledge()["behavior_surface"]:
            try:
                items.append(BehaviorSurfaceItem.model_validate(entry))
            except Exception:
                continue
        return items

    def _record_completion_knowledge(self, decision: CompletionReviewDecision) -> None:
        """Merge the reviewer-returned surface (merge-only: entries are never removed) into the
        in-memory knowledge and carry its unverified suspicions to the next review."""
        knowledge = self._completion_knowledge()
        merged, changed = _merge_behavior_surface_items(
            knowledge["behavior_surface"], decision.behavior_surface
        )
        if changed:
            knowledge["behavior_surface"] = merged
        artifact = decision.decision_artifact
        if artifact is not None:
            candidates = [
                item
                for item in artifact.uncovered_edge_candidates
                if isinstance(item, str) and item.strip()
            ]
            if candidates != knowledge["uncovered_edge_candidates"]:
                knowledge["uncovered_edge_candidates"] = candidates

    async def completion_packet_details(
        self,
        changed_files: list[ChangedFile],
        *,
        since_sequence: int | None = None,
        validations: list[ValidationRun] | None = None,
        inspections: list[InspectionRun] | None = None,
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
            if since_sequence is None
            or changed.sequence is None
            or changed.sequence > since_sequence
        ]
        source_validations = self.validations if validations is None else validations
        source_inspections = (
            list(getattr(self, "inspections", []))
            if inspections is None
            else inspections
        )
        detail_validations = [
            validation
            for validation in source_validations
            if since_sequence is None or validation.sequence > since_sequence
        ]
        detail_inspections = [
            inspection
            for inspection in source_inspections
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
                file_text = _read_workspace_file(
                    self._active_workspace_root(), changed.path, limit=diff_limit
                )
                if file_text is not None:
                    diff_text = f"<new file snapshot>\n{file_text.text}"
            if not diff_text:
                omitted_reason = "No git diff or readable file snapshot was available for this changed file."
                omitted.append(changed.path)
                materially_truncated = True
            bounded_diff = (
                _bounded_text(diff_text, limit=diff_limit) if diff_text else ""
            )
            diff_truncated = bool(diff_text) and len(diff_text) > len(bounded_diff)
            if diff_truncated:
                materially_truncated = True
                truncation_reasons.append(
                    f"{changed.path}: diff exceeded {diff_limit} characters"
                )
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
            context = _read_workspace_file(
                self._active_workspace_root(), changed.path, limit=context_limit
            )
            if context is None:
                continue
            total_context_chars += len(context.text)
            if context.truncated:
                materially_truncated = True
                truncation_reasons.append(
                    f"{changed.path}: final file context exceeded {context_limit} characters"
                )
            changed_file_contexts.append(
                ChangedFileContext(
                    path=changed.path,
                    final_snippets_around_changed_hunks=context.text,
                    context_truncated=context.truncated,
                )
            )
            if file_kind == "test":
                changed_tests_summary.append(
                    _changed_tests_summary(
                        changed.path, context.text, detail_validations
                    )
                )

        return {
            "changed_file_diffs": changed_file_diffs,
            "changed_file_contexts": changed_file_contexts,
            "changed_tests_summary": changed_tests_summary,
            "validation_outputs": [
                _validation_output(validation) for validation in detail_validations
            ],
            "inspection_outputs": [
                _inspection_output(inspection) for inspection in detail_inspections
            ],
            "completion_delta_evidence_summary": _completion_delta_evidence_summary(
                detail_validations,
                detail_inspections,
                since_sequence=since_sequence,
            ),
            "breadth_risk_summary": _breadth_risk_summary(
                task_contents=self._canonical_task_text(),
                changed_files=changed_files,
            ),
            "diff_packet_limits": DiffPacketLimits(
                total_diff_chars=total_diff_chars,
                total_context_chars=total_context_chars,
                omitted_changed_files=omitted,
                materially_truncated=materially_truncated,
                truncation_reason="; ".join(truncation_reasons)
                if truncation_reasons
                else None,
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
        self._capture_runtime_transport_activity(message)
        method = message.method or ""
        if _is_stream_delta_method(method):
            self._record_command_output_delta(
                method,
                message.params,
                item_id=_item_id_from_params(message.params),
            )
            message.raw["_bello_output_delta_captured"] = True
        # Capture reviewer tool evidence before yielding to the controller queue.
        # App Server resolves the turn waiter independently, so waiting for the
        # queued notification could otherwise race with decide_completion().
        self._capture_completion_review_notification(message)
        message.raw["_bello_completion_capture_done"] = True
        await self.event_queue.put(
            ControllerEvent(kind="notification", message=message)
        )

    def _capture_completion_review_notification(
        self, message: AppServerMessage
    ) -> None:
        if message.method != "item/completed":
            return
        agent = self._completion_supervisor_agent()
        if agent is None or not hasattr(agent, "record_completion_review_item"):
            return
        params = message.params
        thread_id = params.get("threadId")
        if not isinstance(thread_id, str) or thread_id != getattr(
            agent, "completion_thread_id", None
        ):
            return
        item = params.get("item")
        if not isinstance(item, dict):
            return
        output = self._pop_command_output(_item_id_from_params(params))
        agent.record_completion_review_item(
            _item_with_recorded_output(item, output)
        )

    async def _on_server_request(self, message: AppServerMessage) -> None:
        self._capture_runtime_transport_activity(message)
        await self.event_queue.put(
            ControllerEvent(kind="server_request", message=message)
        )

    async def _on_transport_error(self, error: BaseException) -> None:
        await self.event_queue.put(
            ControllerEvent(
                kind="transport_error", error=error, error_message=str(error)
            )
        )

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
        cfg = self.store.get_bello_config()
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
        self.store.update_bello_config(
            lambda current: current.model_copy(
                update={"last_event_sequence": self._sequence}
            )
        )

    def _generate_schema_hash(self) -> str:
        if shutil.which("codex") is None:
            raise RuntimeError("codex executable not found")
        with tempfile.TemporaryDirectory(prefix="bello-appserver-schema-") as tmp_dir:
            out_dir = Path(tmp_dir)
            completed = subprocess.run(
                [
                    "codex",
                    "app-server",
                    "generate-json-schema",
                    "--experimental",
                    "--out",
                    str(out_dir),
                ],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError(
                    (completed.stdout + completed.stderr).strip()
                    or "app-server schema generation failed"
                )
            required = [
                "ClientRequest.json",
                "ServerRequest.json",
                "TurnStartParams.json",
                "CommandExecutionRequestApprovalParams.json",
            ]
            for rel in required:
                if not _schema_file_exists(out_dir, rel):
                    raise RuntimeError(
                        f"app-server schema missing required file: {rel}"
                    )
            if not _turn_start_schema_supports_effort(out_dir):
                raise RuntimeError(
                    "app-server schema missing required turn effort field for Bello intelligence settings"
                )
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
            workspace_root=self._active_workspace_root(),
            task_contents=self._canonical_task_text(),
            model=self._runtime_model(),
            fast=self._fast_mode(),
            intelligence=self._runtime_intelligence(),
            configured_mcp_server_names=self._configured_mcp_server_names,
            configured_plugin_names=self._configured_plugin_names,
        )
        cfg = self.store.get_bello_config()
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
        decision = await asyncio.wait_for(agent.decide(packet), timeout=240)
        if decision.decision not in {
            SupervisorDecisionKind.NOOP,
            SupervisorDecisionKind.PAUSE,
        }:
            raise RuntimeError(
                "structured-output supervisor self-test returned an unexpected decision"
            )

    async def _configure_runtime_triage(self) -> None:
        config = runtime_triage_config_from_env(enabled=self._cheap_runtime_enabled())
        self.runtime_triage_config = config
        self.runtime_triage_reviewer = None
        if not config.enabled:
            self.tui.render("SYSTEM", "cheap runtime triage disabled by configuration")
            return
        if config.model is None:
            self.tui.render(
                "SYSTEM", "cheap runtime triage disabled: no model configured"
            )
            self.runtime_triage_config = CheapRuntimeTriageConfig(
                enabled=False, model=None, timeout_seconds=config.timeout_seconds
            )
            return
        reviewer = CheapRuntimeReviewer(
            self.client,
            self._active_workspace_root(),
            model=config.model,
            timeout_seconds=config.timeout_seconds,
            configured_mcp_server_names=self._configured_mcp_server_names,
            configured_plugin_names=self._configured_plugin_names,
        )
        try:
            await self._cheap_runtime_structured_output_self_test(reviewer)
        except Exception as exc:
            self.tui.render(
                "SYSTEM",
                f"cheap runtime triage unavailable; full supervisor on every wake ({exc.__class__.__name__})",
            )
            self.runtime_triage_config = CheapRuntimeTriageConfig(
                enabled=False,
                model=config.model,
                timeout_seconds=config.timeout_seconds,
            )
            return
        self.runtime_triage_reviewer = reviewer
        self.tui.render(
            "SYSTEM", f"cheap runtime triage enabled with model {config.model}"
        )

    async def _cheap_runtime_structured_output_self_test(
        self, reviewer: CheapRuntimeReviewer
    ) -> None:
        packet = SupervisorWakePacket(
            wake_sequence=1,
            latest_event_sequence=0,
            generation=0,
            restart_count=0,
            task_path=str(self.task_path),
            task_contents="",
            current_summary="Startup runtime-triage self-test: routine read-only progress, no failing checks.",
        )
        decision = await asyncio.wait_for(
            reviewer.review(packet), timeout=reviewer.timeout_seconds
        )
        if decision.decision not in {"noop", "escalate"}:
            raise RuntimeError(
                "cheap runtime structured-output self-test returned an unexpected decision"
            )

    async def _cheap_runtime_route(
        self, packet: SupervisorWakePacket
    ) -> CheapRuntimeDecision | None:
        reviewer = self.runtime_triage_reviewer
        if reviewer is None:
            return None
        started = time.monotonic()
        try:
            decision = await reviewer.review(packet)
        except CheapRuntimeReviewerError as exc:
            self._record_cheap_runtime_attempt(
                packet,
                decision=None,
                outcome=f"error:{exc.__class__.__name__}",
                started=started,
                fallback=True,
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
            self.tui.render(
                "SUPERVISOR", f"cheap runtime triage: noop ({decision.reason_code})"
            )
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
                "trigger_reasons": list(
                    _runtime_trigger_reasons_from_summary(packet.current_summary)
                ),
                "decision": decision.decision if decision is not None else None,
                "reason_code": decision.reason_code if decision is not None else None,
                "outcome": outcome,
                "latency_seconds": time.monotonic() - started,
                "model": self.runtime_triage_config.model,
                "full_supervisor_fallback": fallback,
            }
        )


def _approval_wake_context(
    context: ApprovalContext,
    reason: str | None = None,
    *,
    origin: str = "coder",
) -> ApprovalWakeContext:
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
        origin=origin,
    )


def _runtime_packet_requires_full_supervisor(packet: SupervisorWakePacket) -> bool:
    reasons = set(_runtime_trigger_reasons_from_summary(packet.current_summary))
    if reasons & MANDATORY_FULL_RUNTIME_WAKE_REASONS:
        return True
    return (
        (packet.current_summary or "").lstrip().startswith("Runtime integrity trigger:")
    )


def _runtime_trigger_reasons_from_summary(summary: str | None) -> tuple[str, ...]:
    if not summary:
        return ()
    match = re.match(r"\s*Runtime trigger \(([^)]*)\):", summary)
    if not match:
        return ()
    return tuple(
        reason.strip() for reason in match.group(1).split(",") if reason.strip()
    )


_RESTART_SHELL_NAMES = frozenset({"bash", "dash", "ksh", "sh", "zsh"})


def _canonical_restart_command(command: str) -> str:
    current = _normalize_command(command)
    for _ in range(6):
        try:
            parts = shlex.split(current)
        except ValueError:
            break
        if len(parts) < 3 or Path(parts[0]).name not in _RESTART_SHELL_NAMES:
            break
        command_index = next(
            (
                index + 1
                for index, token in enumerate(parts[1:-1], start=1)
                if token.startswith("-")
                and not token.startswith("--")
                and "c" in token[1:]
            ),
            None,
        )
        if command_index is None or command_index != len(parts) - 1:
            break
        nested = _normalize_command(parts[command_index])
        if not nested or nested == current:
            break
        current = nested
    return current


def _runtime_unresolved_execution_key(command: str, cwd: str | None) -> str:
    payload = {
        "command": _canonical_restart_command(command),
        "cwd": cwd or "",
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return f"unresolved-execution:{digest[:16]}"


def _runtime_validation_restart_issue(
    validation: ValidationRun,
) -> RuntimeRestartIssue | None:
    if validation.trusted_validation_outcome == "passed":
        return None
    if validation.exit_code is None or validation.shell_exit_code is None:
        return RuntimeRestartIssue(
            key=_runtime_unresolved_execution_key(validation.command, validation.cwd),
            sequence=validation.sequence,
            validation_id=validation.validation_id,
        )
    if validation.trusted_validation_outcome == "masked_or_unknown":
        masking_reason = validation.masking_reason or "unknown"
        return RuntimeRestartIssue(
            key=f"masked-validation:{masking_reason}",
            sequence=validation.sequence,
            validation_id=validation.validation_id,
        )
    if validation.trusted_validation_outcome != "failed":
        return None
    evidence = validation.captured_output or validation.summary
    normalized_evidence = " ".join(evidence.split())
    payload = {
        "validation_id": validation.validation_id,
        "exit_code": validation.exit_code,
        "shell_exit_code": validation.shell_exit_code,
        "executed_test_names": sorted(validation.executed_test_names),
        "executed_test_files": sorted(validation.executed_test_files),
        "failed_count": validation.failed_count,
        "evidence_sha256": hashlib.sha256(
            normalized_evidence.encode("utf-8")
        ).hexdigest(),
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    return RuntimeRestartIssue(
        key=f"failed-validation:{validation.validation_id}:{digest}",
        sequence=validation.sequence,
        validation_id=validation.validation_id,
    )


def _matching_active_validation_issue(
    packet: SupervisorWakePacket,
    *,
    active_issue_key: str | None,
    active_issue_last_sequence: int,
) -> RuntimeRestartIssue | None:
    if active_issue_key is None:
        return None
    issues = [
        issue
        for validation in packet.validations
        if validation.sequence > active_issue_last_sequence
        if (issue := _runtime_validation_restart_issue(validation)) is not None
    ]
    if not issues:
        return None
    latest = max(issues, key=lambda issue: issue.sequence)
    return latest if latest.key == active_issue_key else None


def _runtime_event_issue_payload(
    packet: SupervisorWakePacket,
    *,
    reasons: tuple[str, ...],
) -> dict[str, Any]:
    action = packet.triggering_action
    approval = packet.approval_context
    payload: dict[str, Any] = {"reasons": reasons}
    if approval is not None:
        payload["approval"] = {
            "request_type": str(approval.request_type),
            "command": (
                _canonical_restart_command(approval.command)
                if approval.command
                else None
            ),
            "cwd": approval.cwd,
            "paths": sorted(approval.paths),
        }
        return payload
    if action is not None and action.command:
        payload["command"] = {
            "kind": action.kind,
            "command": _canonical_restart_command(action.command),
            "cwd": action.cwd,
            "exit_code": action.exit_code,
        }
        return payload
    changed_paths = sorted({changed.path for changed in packet.changed_files})
    if not changed_paths and action is not None:
        changed_paths = sorted(action.paths)
    payload["paths"] = changed_paths
    if not reasons and action is not None:
        payload["kind"] = action.kind
    return payload


def _runtime_restart_issue(
    packet: SupervisorWakePacket,
    *,
    active_issue_key: str | None = None,
    active_issue_last_sequence: int = 0,
) -> RuntimeRestartIssue | None:
    validation = _runtime_triggering_validation(packet)
    if validation is not None:
        issue = _runtime_validation_restart_issue(validation)
        if issue is not None:
            return issue

    reasons = tuple(
        sorted(_runtime_trigger_reasons_from_summary(packet.current_summary))
    )
    action = packet.triggering_action
    approval = packet.approval_context
    if action is None and approval is None and not reasons:
        if packet.current_summary.strip() != "Coder turn completed":
            return None
        return _matching_active_validation_issue(
            packet,
            active_issue_key=active_issue_key,
            active_issue_last_sequence=active_issue_last_sequence,
        )
    payload = _runtime_event_issue_payload(packet, reasons=reasons)
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]
    return RuntimeRestartIssue(
        key=f"runtime-event:{digest}", sequence=packet.latest_event_sequence
    )


def _runtime_triggering_validation(
    packet: SupervisorWakePacket,
) -> ValidationRun | None:
    if not packet.validations:
        return None
    action = packet.triggering_action
    if action is not None and action.command:
        normalized_command = _normalize_command(action.command)
        matches = [
            validation
            for validation in packet.validations
            if validation.normalized_command == normalized_command
        ]
        if matches:
            return max(matches, key=lambda validation: validation.sequence)
    validation_reasons = {
        "masked_validation",
        "repeated_same_failing_validation",
        "validation_regression",
    }
    if validation_reasons & set(
        _runtime_trigger_reasons_from_summary(packet.current_summary)
    ):
        return max(packet.validations, key=lambda validation: validation.sequence)
    return None


def _is_no_active_turn_to_steer_error(exc: AppServerError) -> bool:
    return "no active turn to steer" in str(exc).lower()


def _fallback_restart_handoff(
    *, task_contents: str, reason: str, last_actions: list[str]
) -> RestartHandoff:
    objective = (
        " ".join(task_contents.strip().split())[:1000] or "Continue the selected task."
    )
    known_evidence = (
        "; ".join(last_actions[-5:]) or "No completed coder actions are recorded."
    )
    return RestartHandoff(
        objective=objective,
        restart_reason=reason,
        bad_pattern="The previous generation was interrupted or judged unreliable before completing the task.",
        known_evidence=known_evidence,
        next_step="Read the task, progress, decisions, and this handoff, then take the next concrete task step.",
        recovery_signal="The new generation makes task-relevant progress without repeating the prior failure mode.",
    )


def _restart_rejection_steering(handoff: RestartHandoff | None) -> str:
    if handoff is None:
        return "Continue the current task. Use the latest observation to make the next concrete progress step."
    return (
        f"Correct the current non-converging pattern before continuing. Avoid: {handoff.bad_pattern} "
        f"Next step: {handoff.next_step} Recovery signal: {handoff.recovery_signal}"
    )


def _triggering_action_from_item(
    item: Any, *, item_id: str | None, summary: str
) -> TriggeringAction:
    if not isinstance(item, dict):
        return TriggeringAction(
            item_id=item_id, kind="item", status="completed", summary=summary
        )
    kind = str(item.get("type") or "item")
    exit_code = item.get("exitCode")
    return TriggeringAction(
        item_id=item_id,
        kind=kind,
        command=item.get("command") if isinstance(item.get("command"), str) else None,
        cwd=item.get("cwd") if isinstance(item.get("cwd"), str) else None,
        paths=_paths_from_item(item),
        exit_code=exit_code if isinstance(exit_code, int) else None,
        status=item.get("status")
        if isinstance(item.get("status"), str)
        else "completed",
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
    validation_type = _classify_validation_command(
        action.command, changed_paths=changed_paths or []
    )
    if validation_type is None:
        return None
    output = _command_output_from_item(item)
    if (
        validation_type == "behavioral"
        and _behavioral_lifecycle_needs_positive_test_output(action.command)
        and not _output_confirms_test_execution(output)
    ):
        # Aggregate Maven/Gradle lifecycle goals can succeed even when the
        # project has no test task. Preserve their build result as static evidence
        # without pretending runtime behavior executed.
        validation_type = "static"
    normalized_command = _normalize_command(action.command)
    raw_selector = _raw_validation_selector(action.command)
    executed_test_names = _executed_test_names(action.command, output)
    executed_test_files = _test_files_from_output(output)
    passed_count, failed_count = _test_count_summary(output)
    outcome = "pass" if action.exit_code == 0 else "fail"
    if validation_type == "behavioral" and _test_output_reports_failure(output):
        outcome = "fail"
    if (
        validation_type == "behavioral"
        and outcome == "pass"
        and not _tests_executed(action.command, output)
    ):
        outcome = "fail"
    masking_reason = _validation_masking_reason(
        action.command,
        validation_type=validation_type,
        changed_paths=changed_paths or [],
    )
    if (
        masking_reason is None
        and validation_type == "behavioral"
        and _optional_package_test_may_not_exist(action.command)
        and not _output_confirms_test_execution(output)
    ):
        masking_reason = "optional_test_script_has_no_execution_evidence"
    if (
        masking_reason is None
        and validation_type == "behavior_demo"
        and outcome == "pass"
    ):
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
        covers_same_action_mutations=_logical_and_chain_validates_after_mutation(
            action.command,
            changed_paths=changed_paths or [],
        ),
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
    outcome = (
        "pass"
        if _inspection_exit_is_usable(action.command, action.exit_code)
        else "fail"
    )
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


def _classify_validation_command(
    command: str, *, changed_paths: list[str]
) -> str | None:
    chained_type = _logical_and_validation_chain_type(
        command, changed_paths=changed_paths
    )
    if chained_type is not None:
        return chained_type
    return _classify_single_validation_command(
        command, changed_paths=changed_paths
    )


def _classify_single_validation_command(
    command: str, *, changed_paths: list[str]
) -> str | None:
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


def _logical_and_validation_chain_type(
    command: str, *, changed_paths: list[str]
) -> str | None:
    segments = _logical_and_command_segments(command)
    if segments is None:
        return None
    validation_types: list[str] = []
    segment_details: list[tuple[str | None, bool]] = []
    for segment in segments:
        validation_type = _classify_single_validation_command(
            segment, changed_paths=changed_paths
        )
        if validation_type is not None:
            validation_types.append(validation_type)
            segment_details.append(
                (validation_type, _validation_segment_may_mutate_product(segment))
            )
            continue
        if _is_read_only_inspection_command(segment):
            segment_details.append((None, False))
            continue
        if _validation_segment_may_mutate_product(segment):
            segment_details.append((None, True))
            continue
        return None
    if not validation_types:
        return None
    behavioral_indexes = [
        index
        for index, (validation_type, _) in enumerate(segment_details)
        if validation_type in {"behavioral", "behavior_demo"}
    ]
    if behavioral_indexes:
        final_behavioral_index = behavioral_indexes[-1]
        if any(
            mutates
            for _, mutates in segment_details[final_behavioral_index + 1 :]
        ):
            return None
    for strongest in ("behavioral", "behavior_demo", "static"):
        if strongest in validation_types:
            return strongest
    return None


def _logical_and_chain_validates_after_mutation(
    command: str,
    *,
    changed_paths: list[str],
) -> bool:
    segments = _logical_and_command_segments(command)
    if segments is None:
        return False
    mutation_indexes = [
        index
        for index, segment in enumerate(segments)
        if _validation_segment_may_mutate_product(segment)
    ]
    behavioral_indexes = [
        index
        for index, segment in enumerate(segments)
        if _classify_single_validation_command(
            segment, changed_paths=changed_paths
        )
        in {"behavioral", "behavior_demo"}
    ]
    return bool(
        mutation_indexes
        and behavioral_indexes
        and max(mutation_indexes) < max(behavioral_indexes)
        and _logical_and_validation_chain_type(
            command, changed_paths=changed_paths
        )
        in {"behavioral", "behavior_demo"}
    )


def _validation_segment_may_mutate_product(command: str) -> bool:
    parsed = _validation_executable_and_args(command)
    if parsed is None:
        return False
    executable, args = parsed
    lowered_args = [arg.lower() for arg in args]
    runner, runner_args = _npx_runner_and_args(executable, lowered_args)
    if runner == "ruff":
        return any(arg in {"--fix", "--fix-only"} for arg in runner_args) or (
            bool(runner_args)
            and runner_args[0] == "format"
            and "--check" not in runner_args
        )
    if runner == "eslint":
        return "--fix" in runner_args
    if runner in {"prettier", "black"}:
        return "--write" in runner_args or "--check" not in runner_args
    if executable in {"npm", "pnpm", "yarn"}:
        script = _package_script_name(lowered_args)
        if script and any(
            arg in {"--fix", "--fix-only", "--write"} for arg in lowered_args
        ):
            return True
        return bool(script and (script == "build" or script.startswith("build:")))
    if executable in {"mvn", "mvnw"}:
        return bool(
            set(_build_tool_tasks(executable, lowered_args))
            & {"package", "install", "deploy"}
        )
    if executable in {"gradle", "gradlew"}:
        return bool(
            set(_build_tool_tasks(executable, lowered_args))
            & {"assemble", "build"}
        )
    return (
        executable == "cargo"
        and _runner_subcommand(executable, lowered_args) == "build"
    ) or (
        executable == "go"
        and _runner_subcommand(executable, lowered_args) == "build"
    )


def _logical_and_command_segments(command: str) -> list[str] | None:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _logical_and_command_segments(inner)
    cleaned = _strip_shell_comments(command)
    if _unquoted_shell_controls(cleaned):
        return None
    if "$(" in cleaned or "`" in cleaned or "<<" in cleaned:
        return None
    try:
        lexer = shlex.shlex(cleaned, posix=True, punctuation_chars="|;&<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = [token for token in lexer if token]
    except ValueError:
        return None
    segments: list[str] = []
    current: list[str] = []
    saw_logical_and = False
    for token in tokens:
        if token == "&&":
            if not current:
                return None
            segments.append(shlex.join(current))
            current = []
            saw_logical_and = True
            continue
        if token in {"&", "||", ";", "|", "!"} or any(
            char in token for char in "<>"
        ):
            return None
        current.append(token)
    if not current or not saw_logical_and:
        return None
    segments.append(shlex.join(current))
    return segments


def _is_static_validation_command(command: str) -> bool:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _is_static_validation_command(inner)
    parsed = _validation_executable_and_args(command)
    if parsed is None:
        return False
    executable, args = parsed
    lowered_args = [arg.lower() for arg in args]
    runner, runner_args = _npx_runner_and_args(executable, lowered_args)
    if executable in {"node", "nodejs"}:
        return bool(lowered_args) and lowered_args[0] in {"-c", "--check"}
    if executable == "git":
        git_args = _git_subcommand_and_args(lowered_args)
        return bool(git_args) and git_args[0] == "diff" and "--check" in git_args[1:]
    if runner == "eslint":
        return bool(runner_args) and "--fix" not in runner_args
    if runner in {"flake8", "mypy", "pyright"}:
        return True
    if runner == "ruff":
        return bool(runner_args) and (
            (
                runner_args[0] == "check"
                and not any(arg in {"--fix", "--fix-only"} for arg in runner_args)
            )
            or (runner_args[0] == "format" and "--check" in runner_args)
        )
    if runner == "black":
        return "--check" in runner_args
    if runner == "prettier":
        return "--check" in runner_args
    if runner == "tsc":
        return "--noemit" in runner_args or "--noemit" in lowered_args
    if executable in {"npm", "pnpm", "yarn"}:
        script = _package_script_name(lowered_args)
        if any(
            arg in {"--fix", "--fix-only", "--write"} for arg in lowered_args
        ):
            return False
        return bool(
            script
            and (
                script == "build"
                or script.startswith("build:")
                or script == "lint"
                or script.startswith("lint:")
                or script in {"type-check", "typecheck"}
                or script.startswith(("type-check:", "typecheck:"))
            )
        )
    if executable == "cargo":
        return _runner_subcommand(executable, lowered_args) == "check"
    if executable == "go":
        return _runner_subcommand(executable, lowered_args) == "build"
    if executable in {"mvn", "mvnw"}:
        return bool(
            set(_build_tool_tasks(executable, lowered_args))
            & {"compile", "generate-sources", "process-sources"}
        )
    if executable in {"gradle", "gradlew"}:
        return "assemble" in _build_tool_tasks(executable, lowered_args)
    if executable.startswith("python"):
        module = _python_module_name(lowered_args)
        return module in {"compileall", "json.tool", "py_compile"}
    if executable == "jq":
        return bool(lowered_args) and lowered_args[0] == "."
    return False


def _is_git_inspection_command(command: str) -> bool:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _is_git_inspection_command(inner)
    parsed = _validation_executable_and_args(command)
    if parsed is None or parsed[0] != "git":
        return False
    git_args = _git_subcommand_and_args([arg.lower() for arg in parsed[1]])
    return bool(git_args) and git_args[0] in {
        "branch",
        "diff",
        "for-each-ref",
        "log",
        "remote",
        "rev-parse",
        "show",
        "status",
    }


def _is_git_diff_check_command(command: str) -> bool:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _is_git_diff_check_command(inner)
    parsed = _validation_executable_and_args(command)
    if parsed is None or parsed[0] != "git":
        return False
    git_args = _git_subcommand_and_args([arg.lower() for arg in parsed[1]])
    return bool(git_args) and git_args[0] == "diff" and "--check" in git_args[1:]


def _npx_runner_and_args(
    executable: str, args: list[str]
) -> tuple[str, list[str]]:
    if executable != "npx":
        return executable, args
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"-p", "--package"}:
            index += 2
            continue
        if arg.startswith("--package=") or arg in {"-y", "--yes", "--no-install"}:
            index += 1
            continue
        if arg.startswith("-"):
            return "", []
        return Path(arg).name.lower(), args[index + 1 :]
    return "", []


def _git_subcommand_and_args(args: list[str]) -> list[str]:
    index = 0
    options_with_values = {"-c", "--config-env", "--git-dir", "--work-tree"}
    while index < len(args):
        arg = args[index]
        if arg in options_with_values:
            index += 2
            continue
        if any(arg.startswith(f"{option}=") for option in options_with_values):
            index += 1
            continue
        if arg in {"--no-pager", "--paginate", "-p"}:
            index += 1
            continue
        if arg.startswith("-"):
            return []
        return args[index:]
    return []


def _first_non_option_arg(args: list[str]) -> str | None:
    return next((arg for arg in args if not arg.startswith("-")), None)


def _validation_executable_and_args(command: str) -> tuple[str, list[str]] | None:
    parsed = _inspection_executable_and_args(command)
    if parsed is None:
        return None
    executable, args = parsed
    for _ in range(4):
        lowered_args = [arg.lower() for arg in args]
        if executable in {"timeout", "gtimeout"}:
            index = 0
            value_options = {"-k", "--kill-after", "-s", "--signal"}
            while index < len(args):
                lowered = lowered_args[index]
                if lowered in value_options:
                    index += 2
                    continue
                if any(lowered.startswith(f"{option}=") for option in value_options):
                    index += 1
                    continue
                if lowered in {"--foreground", "--preserve-status", "-v", "--verbose"}:
                    index += 1
                    continue
                break
            if index + 1 >= len(args) or args[index].startswith("-"):
                return None
            index += 1  # duration
            executable = Path(args[index]).name.lower()
            args = args[index + 1 :]
            continue
        if executable in {"poetry", "pipenv"}:
            if not lowered_args or lowered_args[0] != "run" or len(args) < 2:
                return executable, args
            executable = Path(args[1]).name.lower()
            args = args[2:]
            continue
        if executable == "bundle":
            if not lowered_args or lowered_args[0] != "exec" or len(args) < 2:
                return executable, args
            if args[1].startswith("-"):
                return None
            executable = Path(args[1]).name.lower()
            args = args[2:]
            continue
        if executable == "uv":
            if not lowered_args or lowered_args[0] != "run":
                return executable, args
            index = 1
            value_options = {
                "--directory",
                "--project",
                "--python",
                "--with",
                "--with-editable",
            }
            flag_options = {"--frozen", "--isolated", "--locked", "--no-project"}
            while index < len(args):
                lowered = lowered_args[index]
                if lowered in value_options:
                    index += 2
                    continue
                if any(lowered.startswith(f"{option}=") for option in value_options):
                    index += 1
                    continue
                if lowered in flag_options:
                    index += 1
                    continue
                break
            if index >= len(args) or args[index].startswith("-"):
                return None
            executable = Path(args[index]).name.lower()
            args = args[index + 1 :]
            continue
        if executable in {"pnpm", "yarn"} and lowered_args[:1] == ["exec"]:
            if len(args) < 2 or args[1].startswith("-"):
                return None
            executable = Path(args[1]).name.lower()
            args = args[2:]
            continue
        break
    return executable, args


def _runner_subcommand(executable: str, args: list[str]) -> str | None:
    value_options: dict[str, set[str]] = {
        "cargo": {"--color", "--config", "--manifest-path", "--target-dir", "-z"},
        "go": {"-c"},
        "gradle": {
            "--build-file",
            "--gradle-user-home",
            "--project-dir",
            "--settings-file",
            "-b",
            "-c",
            "-g",
            "-p",
        },
        "gradlew": {
            "--build-file",
            "--gradle-user-home",
            "--project-dir",
            "--settings-file",
            "-b",
            "-c",
            "-g",
            "-p",
        },
        "make": {"--directory", "--file", "--include-dir", "-c", "-f", "-i"},
        "mvn": {
            "--file",
            "--global-settings",
            "--projects",
            "--resume-from",
            "--settings",
            "--threads",
            "-t",
            "-f",
            "-gs",
            "-pl",
            "-rf",
            "-s",
        },
        "mvnw": {
            "--file",
            "--global-settings",
            "--projects",
            "--resume-from",
            "--settings",
            "--threads",
            "-t",
            "-f",
            "-gs",
            "-pl",
            "-rf",
            "-s",
        },
    }
    flag_options: dict[str, set[str]] = {
        "cargo": {"--frozen", "--locked", "--offline", "--quiet", "-q"},
        "go": {"-n", "-v", "-x"},
        "gradle": {"--no-daemon", "--offline", "--quiet", "-i", "-q"},
        "gradlew": {"--no-daemon", "--offline", "--quiet", "-i", "-q"},
        "make": {"--dry-run", "--just-print", "--silent", "-n", "-s"},
        "mvn": {"--batch-mode", "--errors", "--offline", "--quiet", "-b", "-e", "-n", "-o", "-q", "-u", "-v"},
        "mvnw": {"--batch-mode", "--errors", "--offline", "--quiet", "-b", "-e", "-n", "-o", "-q", "-u", "-v"},
    }
    values = value_options.get(executable, set())
    flags = flag_options.get(executable, set())
    index = 0
    while index < len(args):
        arg = args[index]
        if executable == "cargo" and arg.startswith("+"):
            index += 1
            continue
        if arg in values:
            index += 2
            continue
        if any(arg.startswith(f"{option}=") for option in values):
            index += 1
            continue
        if arg in flags or (executable in {"mvn", "mvnw"} and arg.startswith("-D")):
            index += 1
            continue
        if arg.startswith("-"):
            return None
        return arg
    return None


def _build_tool_tasks(executable: str, args: list[str]) -> list[str]:
    """Return Maven/Gradle lifecycle tasks while skipping global option values."""

    value_options = {
        "--build-file",
        "--file",
        "--global-settings",
        "--gradle-user-home",
        "--project-dir",
        "--projects",
        "--resume-from",
        "--settings",
        "--settings-file",
        "--threads",
        "-b",
        "-c",
        "-f",
        "-g",
        "-gs",
        "-p",
        "-pl",
        "-rf",
        "-s",
        "-t",
    }
    tasks: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in value_options:
            index += 2
            continue
        if any(arg.startswith(f"{option}=") for option in value_options):
            index += 1
            continue
        if arg.startswith("-"):
            index += 1
            continue
        task = arg.rsplit(":", 1)[-1] if executable in {"gradle", "gradlew"} else arg
        tasks.append(task)
        index += 1
    return tasks


def _package_script_name(args: list[str]) -> str | None:
    if not args:
        return None
    value_options = {
        "--filter",
        "--workspace",
        "--workspace-root",
        "--cwd",
        "--dir",
        "-c",
        "-f",
        "-w",
    }
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in value_options:
            index += 2
            continue
        if any(arg.startswith(f"{option}=") for option in value_options):
            index += 1
            continue
        break
    remaining = args[index:]
    if not remaining:
        return None
    if remaining[0] == "workspace":
        return (
            remaining[2]
            if len(remaining) > 2 and not remaining[2].startswith("-")
            else None
        )
    if remaining[0] in {"run", "run-script"}:
        return (
            remaining[1]
            if len(remaining) > 1 and not remaining[1].startswith("-")
            else None
        )
    return remaining[0] if not remaining[0].startswith("-") else None


def _first_positional_after_runner_options(
    args: list[str],
    *,
    value_options: set[str],
) -> str | None:
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return None
        if arg in value_options:
            index += 2
            continue
        if any(arg.startswith(f"{option}=") for option in value_options):
            index += 1
            continue
        if arg.startswith("-"):
            index += 1
            continue
        return arg
    return None


def _tox_execution_subcommand(args: list[str]) -> str | None:
    return _first_positional_after_runner_options(
        args,
        value_options={
            "-c",
            "--conf",
            "--configfile",
            "-e",
            "--env",
            "--root",
            "--workdir",
            "--result-json",
        },
    )


def _vitest_subcommand(args: list[str]) -> str | None:
    return _first_positional_after_runner_options(
        args,
        value_options={
            "-c",
            "--config",
            "--dir",
            "--project",
            "-r",
            "--root",
        },
    )


def _python_module_name(args: list[str]) -> str | None:
    options_with_values = {"-W", "-X", "--check-hash-based-pycs"}
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "-c":
            return None
        if arg == "-m":
            return args[index + 1] if index + 1 < len(args) else None
        if arg in options_with_values:
            index += 2
            continue
        if any(arg.startswith(option) and arg != option for option in ("-W", "-X")):
            index += 1
            continue
        if arg.startswith("-"):
            index += 1
            continue
        return None
    return None
    return None


def _is_read_only_inspection_command(command: str) -> bool:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _is_read_only_inspection_command(inner)
    cleaned = _strip_shell_comments(command)
    if _has_unsafe_inspection_shell_control(cleaned):
        return False
    lowered = cleaned.lower()
    if any(marker in lowered for marker in ("<<", "$(", "`")):
        return False
    if re.search(r"(?<![12])>(?!&)", cleaned) or re.search(r"(^|[^<])<(?!<)", cleaned):
        return False
    segments = _inspection_command_segments(cleaned)
    if segments is None:
        return False
    if not segments:
        return False
    return all(_is_read_only_inspection_tokens(segment) for segment in segments)


def _inspection_command_segments(command: str) -> list[list[str]] | None:
    cleaned = _strip_shell_comments(command)
    if _has_unsafe_inspection_shell_control(cleaned):
        return None
    try:
        lexer = shlex.shlex(cleaned, posix=True, punctuation_chars="|;&<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = [token for token in lexer if token]
    except ValueError:
        return None
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token == "&&":
            if not current:
                return None
            segments.append(current)
            current = []
            continue
        if token in {"&", "||", ";", "|", "!"} or any(char in token for char in "<>"):
            return None
        current.append(token)
    if current:
        segments.append(current)
    return segments


def _strip_shell_comments(command: str) -> str:
    """Remove real shell comments without treating a mid-word ``#`` as one."""

    output: list[str] = []
    in_single = False
    in_double = False
    at_word_start = True
    index = 0
    while index < len(command):
        char = command[index]
        if in_single:
            output.append(char)
            if char == "'":
                in_single = False
            index += 1
            continue
        if in_double:
            if char == "\\" and index + 1 < len(command):
                next_char = command[index + 1]
                if next_char == "\n":
                    output.append(" ")
                    index += 2
                    continue
                if next_char == "\r" and command[index + 1 : index + 3] == "\r\n":
                    output.append(" ")
                    index += 3
                    continue
                output.extend((char, next_char))
                index += 2
                continue
            output.append(char)
            if char == '"':
                in_double = False
            index += 1
            continue
        if char == "\\" and index + 1 < len(command):
            next_char = command[index + 1]
            if next_char == "\n":
                output.append(" ")
                index += 2
                continue
            if next_char == "\r" and command[index + 1 : index + 3] == "\r\n":
                output.append(" ")
                index += 3
                continue
            output.extend((char, next_char))
            at_word_start = False
            index += 2
            continue
        if char == "'":
            output.append(char)
            in_single = True
            at_word_start = False
            index += 1
            continue
        if char == '"':
            output.append(char)
            in_double = True
            at_word_start = False
            index += 1
            continue
        if char == "#" and at_word_start:
            while index < len(command) and command[index] not in "\r\n":
                index += 1
            continue
        output.append(char)
        at_word_start = char.isspace() or char in ";|&()<>"
        index += 1
    return "".join(output)


def _has_unsafe_inspection_shell_control(command: str) -> bool:
    """Reject control flow whose final exit code can mask an inspection failure."""

    return bool(_unquoted_shell_controls(command))


def _unquoted_shell_controls(command: str) -> set[str]:
    """Return status-affecting shell controls outside quotes and escapes."""

    controls: set[str] = set()
    in_single = False
    in_double = False
    index = 0
    while index < len(command):
        char = command[index]
        if in_single:
            if char == "'":
                in_single = False
            index += 1
            continue
        if in_double:
            if char == "\\" and index + 1 < len(command):
                index += 2
                continue
            if char == '"':
                in_double = False
            index += 1
            continue
        if char == "\\" and index + 1 < len(command):
            index += 2
            continue
        if char == "'":
            in_single = True
            index += 1
            continue
        if char == '"':
            in_double = True
            index += 1
            continue
        if char in "\r\n":
            newline_width = 2 if command[index : index + 2] == "\r\n" else 1
            if command[index + newline_width :].strip():
                controls.add("newline")
            index += newline_width
            continue
        if char == ";":
            controls.add("semicolon")
            index += 1
            continue
        if char == "!":
            controls.add("bang")
            index += 1
            continue
        if char == "|":
            if command[index : index + 2] == "||":
                controls.add("logical_or")
                index += 2
            else:
                controls.add("pipeline")
                index += 1
            continue
        if char == "&":
            if command[index : index + 2] == "&&":
                index += 2
                continue
            controls.add("background")
            index += 1
            continue
        index += 1
    return controls


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
    saw_modifier = False
    while remaining and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*", remaining[0]):
        remaining = remaining[1:]
        saw_modifier = True
    if not remaining:
        return remaining
    executable = remaining[0].rsplit("/", 1)[-1].lower()
    if executable != "env":
        return remaining
    env_invocation = list(remaining)
    remaining = remaining[1:]
    while remaining:
        token = remaining[0]
        if token == "--":
            remaining = remaining[1:]
            saw_modifier = True
            break
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*", token):
            remaining = remaining[1:]
            saw_modifier = True
            continue
        if token.startswith("-"):
            remaining = remaining[1:]
            saw_modifier = True
            continue
        break
    return remaining if saw_modifier else env_invocation


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
        return bool(args) and args[0] in {
            "diff",
            "status",
            "log",
            "show",
            "branch",
            "remote",
            "rev-parse",
            "for-each-ref",
        }
    if executable in {
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
    }:
        if executable == "find" and any(
            arg in {"-delete", "-exec", "-execdir"} for arg in args
        ):
            return False
        return True
    return False


def _is_behavioral_validation_command(command: str) -> bool:
    chained_type = _logical_and_validation_chain_type(command, changed_paths=[])
    if chained_type is not None:
        return chained_type == "behavioral"
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _is_behavioral_validation_command(inner)
    parsed = _validation_executable_and_args(command)
    if parsed is None:
        return False
    executable, args = parsed
    lowered_args = [arg.lower() for arg in args]
    runner, runner_args = _npx_runner_and_args(executable, lowered_args)
    if runner in {"ava", "jest", "mocha", "pytest", "rspec", "tap", "vitest"}:
        return True
    if runner == "tox":
        return _tox_execution_subcommand(runner_args) in {
            None,
            "run",
            "r",
            "run-parallel",
            "p",
        }
    if runner == "playwright":
        return _first_non_option_arg(runner_args) == "test"
    if runner == "cypress":
        return _first_non_option_arg(runner_args) == "run"
    if executable in {"npm", "pnpm", "yarn"}:
        script = _package_script_name(lowered_args)
        return bool(script and (script == "test" or script.startswith("test:")))
    if executable in {"node", "nodejs"}:
        for arg in lowered_args:
            if arg == "--test":
                return True
            if not arg.startswith("-"):
                return False
        return False
    if executable in {"bun", "deno"}:
        return _runner_subcommand(executable, lowered_args) == "test"
    if executable.startswith("python"):
        return _python_module_name(lowered_args) in {
            "nose",
            "nose2",
            "pytest",
            "tox",
            "unittest",
        }
    if executable in {"mvn", "mvnw"}:
        return bool(
            set(_build_tool_tasks(executable, lowered_args))
            & {"test", "integration-test", "verify", "package", "install", "deploy"}
        )
    if executable in {"gradle", "gradlew"}:
        tasks = _build_tool_tasks(executable, lowered_args)
        return bool(set(tasks) & {"test", "check", "build"}) or any(
            _gradle_task_is_test_task(task) for task in tasks
        )
    if executable in {"cargo", "go", "swift"}:
        return _runner_subcommand(executable, lowered_args) == "test"
    if executable == "dotnet":
        return _runner_subcommand(executable, lowered_args) == "test"
    if executable == "make":
        target = _runner_subcommand(executable, lowered_args)
        return bool(target and re.search(r"(?:^|[-_:])tests?(?:$|[-_:])", target))
    return _is_test_wrapper_script_command(command)


def _is_test_wrapper_script_command(command: str) -> bool:
    parsed = _inspection_executable_and_args(command)
    if parsed is None:
        return False
    executable, args = parsed

    def is_test_script(value: str) -> bool:
        name = Path(value).name.lower()
        return bool(
            re.search(r"(?:^|[._-])tests?(?:[._-]|$)", name)
            and Path(name).suffix in {".cjs", ".js", ".mjs", ".py", ".rb", ".sh"}
        )

    if is_test_script(executable):
        return True
    if executable in {"bash", "node", "nodejs", "ruby", "sh", "zsh"} or executable.startswith(
        "python"
    ):
        for arg in args:
            if arg in {"-c", "-e", "--eval", "-m"}:
                return False
            if arg.startswith("-"):
                continue
            return is_test_script(arg)
    return False


def _is_direct_script_execution_command(command: str) -> bool:
    lowered = command.lower()
    boundary = r"(?=$|[\s;&|()'\"])"
    python_flags = r"(?:\s+-(?!m(?:\s|$))[a-z][\w-]*(?:=[^\s;&|()'\"]+)?)"
    python_exec = r"(?:\.{0,2}/|/)?(?:[\w.-]+/)*python(?:3(?:\.\d+)?)?"
    interpreter_exec = r"(?:\.{0,2}/|/)?(?:[\w.-]+/)*(?:node(?:js)?|ruby|bash|sh)"
    shell_prefix = r"(^|[\s;&|()'\"])(?:\.{0,2}/|/)?(?:[\w.-]+/)*(?:bash|sh|zsh)"
    patterns = (
        r"(^|[\s;&|()'\"])"
        + python_exec
        + python_flags
        + r"*\s+(?!-)[\w./-]+\.py"
        + boundary,
        r"(^|[\s;&|()'\"])"
        + interpreter_exec
        + r"\s+(?!-)[\w./-]+\.(js|mjs|cjs|rb|sh)"
        + boundary,
        r"(^|[\s;&|()'\"])(?:\.{1,2}/|/)[\w./-]+\.(py|js|mjs|cjs|rb|sh)" + boundary,
        shell_prefix
        + r"\s+-[a-z]*c\s+['\"]?(?!-)[\w./-]+\.(py|js|mjs|cjs|rb|sh)"
        + boundary,
    )
    return any(re.search(pattern, lowered) for pattern in patterns)


def _is_behavior_demo_command(command: str, *, changed_paths: list[str]) -> bool:
    return (
        (
            _has_behavior_demo_marker(command)
            and _marked_behavior_demo_command_is_plausible(command, changed_paths)
        )
        or _command_requires_changed_module(command, changed_paths)
        or _is_local_http_demo_command(command)
    )


def _interpreter_terminal_mode_precedes_execution(
    executable: str, args: list[str]
) -> bool:
    """Return true when an interpreter exits before reaching a script/module.

    Product flags after the script operand remain valid behavior (for example,
    ``python app.py --help``).  Only interpreter-owned terminal modes before the
    execution boundary are excluded.
    """

    if executable.startswith("python"):
        execution_selectors = {"-c", "-m"}
        attached_selectors: tuple[str, ...] = ()
        terminal_short = {"-h", "-?", "-V", "-VV"}
        terminal_long = {"--help", "--version"}
    elif executable in {"node", "nodejs"}:
        execution_selectors = {"-e", "--eval", "-p", "--print"}
        attached_selectors = ("--eval=", "--print=")
        terminal_short = {"-h", "-v"}
        terminal_long = {"--help", "--version", "--v8-options"}
    elif executable == "ruby":
        execution_selectors = {"-e"}
        attached_selectors = ("-e",)
        terminal_short = {"-h"}
        terminal_long = {"--copyright", "--help", "--version"}
    elif executable in {"bash", "sh", "zsh"}:
        execution_selectors = {"-c"}
        attached_selectors = ()
        terminal_short = set()
        terminal_long = {"--help", "--version"}
    else:
        return False

    for arg in args:
        if arg == "--":
            return False
        if arg in execution_selectors or any(
            arg.startswith(prefix) and arg != prefix
            for prefix in attached_selectors
        ):
            return False
        if arg in terminal_short or arg.lower() in terminal_long:
            return True
        if not arg.startswith("-"):
            return False
    return False


def _has_behavior_demo_marker(command: str) -> bool:
    return bool(
        re.search(
            r"\bBELLO_BEHAVIOR_DEMO\s*=\s*(?:1|true|yes)\b", command, re.IGNORECASE
        )
    )


def _marked_behavior_demo_command_is_plausible(
    command: str, changed_paths: list[str]
) -> bool:
    if _is_read_only_inspection_command(command):
        return False
    if _is_observationless_output_command(command):
        return False
    if _command_requires_changed_module(command, changed_paths):
        return True
    if _is_local_http_demo_command(command):
        return True
    if _is_external_service_demo_command(command):
        return True
    return False


def _is_observationless_output_command(command: str) -> bool:
    segments = [
        segment.strip()
        for segment in re.split(r"\s*(?:&&|;|\|)\s*", command)
        if segment.strip()
    ]
    if not segments:
        return False
    output_only = {"echo", "printf", "true", "false", "yes"}
    read_only_excerpt = {
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
    }
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


def _changed_module_candidates(raw_path: str) -> set[str]:
    path = raw_path.replace("\\", "/").lstrip("./").lower()
    if not path:
        return set()
    name = path.rsplit("/", 1)[-1]
    module_path = path.rsplit(".", 1)[0]
    candidates = {
        module_path,
        module_path.replace("/", "."),
        name.rsplit(".", 1)[0],
    }
    for prefix in ("src/", "lib/", "app/"):
        if module_path.startswith(prefix):
            shortened = module_path[len(prefix) :]
            candidates.update({shortened, shortened.replace("/", ".")})
    return {candidate for candidate in candidates if candidate}


def _module_reference_matches(candidate: str, modules: set[str]) -> bool:
    normalized = candidate.replace("\\", "/").lstrip("./").lower()
    without_extension = normalized.rsplit(".", 1)[0]
    dotted = without_extension.replace("/", ".")
    return any(
        value in modules
        for value in {normalized, without_extension, dotted}
    )


def _python_script_exercises_modules(script: str, modules: set[str]) -> bool:
    try:
        tree = ast.parse(script)
    except (SyntaxError, ValueError):
        return False
    bound_modules: set[str] = set()
    imported_members: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _module_reference_matches(alias.name, modules):
                    bound_modules.add(alias.asname or alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            if _module_reference_matches(node.module, modules):
                imported_members.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name != "*"
                )
    if not bound_modules and not imported_members:
        return False

    def attribute_root_name(node: ast.AST) -> str | None:
        current = node
        while isinstance(current, ast.Attribute):
            current = current.value
        return current.id if isinstance(current, ast.Name) else None

    def is_observable_output_call(node: ast.Call) -> bool:
        if isinstance(node.func, ast.Name):
            return node.func.id in {"print", "repr", "str", "pprint"}
        if isinstance(node.func, ast.Attribute):
            return node.func.attr in {"debug", "error", "info", "warning", "write"}
        return False

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id in imported_members:
            return True
        if (
            isinstance(node.func, ast.Attribute)
            and attribute_root_name(node.func) in bound_modules
        ):
            return True
        if not is_observable_output_call(node):
            continue
        for argument in [*node.args, *[keyword.value for keyword in node.keywords]]:
            for value in ast.walk(argument):
                if (
                    isinstance(value, ast.Attribute)
                    and not value.attr.startswith("__")
                    and attribute_root_name(value) in bound_modules
                ):
                    return True
                if (
                    isinstance(value, ast.Name)
                    and isinstance(value.ctx, ast.Load)
                    and value.id in imported_members
                ):
                    return True
    return False


def _javascript_script_requires_modules(script: str, modules: set[str]) -> bool:
    matching_requires: list[tuple[int, int]] = []
    index = 0
    in_quote: str | None = None
    in_line_comment = False
    in_block_comment = False
    while index < len(script):
        char = script[index]
        pair = script[index : index + 2]
        if in_line_comment:
            if char in "\r\n":
                in_line_comment = False
            index += 1
            continue
        if in_block_comment:
            if pair == "*/":
                in_block_comment = False
                index += 2
            else:
                index += 1
            continue
        if in_quote is not None:
            if char == "\\":
                index += 2
            elif char == in_quote:
                in_quote = None
                index += 1
            else:
                index += 1
            continue
        if pair == "//":
            in_line_comment = True
            index += 2
            continue
        if pair == "/*":
            in_block_comment = True
            index += 2
            continue
        if char in {"'", '"', "`"}:
            in_quote = char
            index += 1
            continue
        if script.startswith("require", index) and (
            index == 0 or not (script[index - 1].isalnum() or script[index - 1] in "_$")
        ):
            match = re.match(
                r"require\s*\(\s*(['\"])([^'\"]+)\1\s*\)", script[index:]
            )
            if match and _module_reference_matches(match.group(2), modules):
                matching_requires.append((index, index + match.end()))
                index += match.end()
                continue
        index += 1
    if not matching_requires:
        return False

    code_view = _javascript_code_view(script)
    observable_call = (
        r"(?:console\s*\.\s*(?:debug|error|info|log|warn)|"
        r"process\s*\.\s*stdout\s*\.\s*write)\s*\("
    )
    for start, end in matching_requires:
        tail = code_view[end:]
        if re.match(r"\s*(?:\.|\?\.)\s*[A-Za-z_$][\w$]*", tail):
            return True
        statement_start = max(
            code_view.rfind(";", 0, start),
            code_view.rfind("\n", 0, start),
        )
        prefix = code_view[statement_start + 1 : start]
        binding = re.search(
            r"(?:^|\s)(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*$",
            prefix,
        )
        if binding:
            name = re.escape(binding.group(1))
            if re.search(
                rf"\b{name}\s*(?:\.|\?\.)\s*[A-Za-z_$][\w$]*\s*\(",
                tail,
            ):
                return True
            if re.search(
                rf"{observable_call}[^;\n)]*\b{name}\s*(?:\.|\?\.)\s*"
                r"[A-Za-z_$][\w$]*",
                tail,
            ):
                return True
        destructured = re.search(
            r"(?:^|\s)(?:const|let|var)\s*\{([^}]*)\}\s*=\s*$", prefix
        )
        if destructured:
            names = {
                part.split(":", 1)[-1].strip()
                for part in destructured.group(1).split(",")
                if re.fullmatch(
                    r"[A-Za-z_$][\w$]*(?:\s*:\s*[A-Za-z_$][\w$]*)?",
                    part.strip(),
                )
            }
            for name_value in names:
                name = re.escape(name_value)
                if re.search(rf"\b{name}\s*\(", tail):
                    return True
                if re.search(
                    rf"{observable_call}[^;\n)]*\b{name}\b", tail
                ):
                    return True
    return False


def _javascript_code_view(script: str) -> str:
    """Mask JS strings/comments while preserving offsets and executable syntax."""

    output = list(script)
    index = 0
    in_quote: str | None = None
    in_line_comment = False
    in_block_comment = False
    while index < len(script):
        char = script[index]
        pair = script[index : index + 2]
        if in_line_comment:
            if char in "\r\n":
                in_line_comment = False
            else:
                output[index] = " "
            index += 1
            continue
        if in_block_comment:
            output[index] = " "
            if pair == "*/":
                if index + 1 < len(output):
                    output[index + 1] = " "
                in_block_comment = False
                index += 2
            else:
                index += 1
            continue
        if in_quote is not None:
            output[index] = " "
            if char == "\\" and index + 1 < len(script):
                output[index + 1] = " "
                index += 2
            elif char == in_quote:
                in_quote = None
                index += 1
            else:
                index += 1
            continue
        if pair == "//":
            output[index] = output[index + 1] = " "
            in_line_comment = True
            index += 2
            continue
        if pair == "/*":
            output[index] = output[index + 1] = " "
            in_block_comment = True
            index += 2
            continue
        if char in {"'", '"', "`"}:
            output[index] = " "
            in_quote = char
        index += 1
    return "".join(output)


def _ruby_script_requires_modules(script: str, modules: set[str]) -> bool:
    statements = re.split(r"[;\r\n]+", script)
    for index, statement in enumerate(statements):
        match = re.match(r"^\s*require\s+(['\"])([^'\"]+)\1", statement)
        if not match or not _module_reference_matches(match.group(2), modules):
            continue
        stem = Path(match.group(2).replace("\\", "/")).stem
        constant = "".join(part[:1].upper() + part[1:] for part in stem.split("_") if part)
        if not constant:
            continue
        remaining = ";".join(statements[index + 1 :])
        if re.search(
            rf"\b{re.escape(constant)}(?:\s*::\s*[A-Z][A-Za-z0-9_]*)*\s*\.\s*"
            r"[A-Za-z_][A-Za-z0-9_]*",
            remaining,
        ):
            return True
    return False


def _heredoc_script_body(command: str) -> str | None:
    opening = re.search(
        r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1[^\r\n]*(?:\r?\n)",
        command,
    )
    if opening is None:
        return None
    delimiter = opening.group(2)
    body_start = opening.end()
    closing = re.search(
        rf"(?m)^[\t ]*{re.escape(delimiter)}[\t ]*(?:\r?$)", command[body_start:]
    )
    if closing is None:
        return None
    return command[body_start : body_start + closing.start()]


def _shell_invocation_segments(command: str) -> list[list[str]]:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _shell_invocation_segments(inner)
    try:
        lexer = shlex.shlex(
            _strip_shell_comments(command), posix=True, punctuation_chars="|;&<>"
        )
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = [token for token in lexer if token]
    except ValueError:
        return []
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in {"&&", "||", ";", "|", "&"}:
            if current:
                segments.append(current)
                current = []
            continue
        if any(char in token for char in "<>"):
            continue
        current.append(token)
    if current:
        segments.append(current)
    return segments


def _command_requires_changed_module(command: str, changed_paths: list[str]) -> bool:
    paths = [
        raw_path.replace("\\", "/").lstrip("./").lower()
        for raw_path in changed_paths
        if raw_path
        and not _is_internal_runtime_path(
            raw_path, project_root=None, task_path=None
        )
    ]
    modules = {
        module
        for raw_path in paths
        for module in _changed_module_candidates(raw_path)
    }
    body = _heredoc_script_body(command)
    heredoc_invocation = _inspection_executable_and_args(command)
    if (
        body is not None
        and heredoc_invocation is not None
        and heredoc_invocation[0].startswith("python")
        and _is_stdin_script_demo_command(command)
        and _python_script_exercises_modules(body, modules)
    ):
        return True
    for raw_segment in _shell_invocation_segments(command):
        segment = _strip_env_command_prefix(raw_segment)
        if not segment:
            continue
        executable_token = segment[0].replace("\\", "/").lstrip("./").lower()
        executable = Path(executable_token).name
        args = segment[1:]
        if executable_token in paths:
            return True
        if _interpreter_terminal_mode_precedes_execution(executable, args):
            continue
        if executable.startswith("python"):
            lowered_args = [arg.lower() for arg in args]
            if "-c" in lowered_args:
                index = lowered_args.index("-c")
                if index + 1 < len(args) and _python_script_exercises_modules(
                    args[index + 1], modules
                ):
                    return True
                continue
            module = _python_module_name(lowered_args)
            if module and _module_reference_matches(module, modules):
                return True
            script = next((arg for arg in args if not arg.startswith("-")), None)
            if script and script.replace("\\", "/").lstrip("./").lower() in paths:
                return True
            continue
        if executable in {"node", "nodejs"}:
            lowered_args = [arg.lower() for arg in args]
            eval_flag = next(
                (flag for flag in ("-e", "--eval") if flag in lowered_args), None
            )
            if eval_flag:
                index = lowered_args.index(eval_flag)
                if index + 1 < len(args) and _javascript_script_requires_modules(
                    args[index + 1], modules
                ):
                    return True
                continue
            script = next((arg for arg in args if not arg.startswith("-")), None)
            if script and script.replace("\\", "/").lstrip("./").lower() in paths:
                return True
            continue
        if executable == "ruby" and "-e" in args:
            index = args.index("-e")
            if index + 1 < len(args) and _ruby_script_requires_modules(
                args[index + 1], modules
            ):
                return True
            continue
        if executable in {"bash", "ruby", "sh", "zsh"}:
            script = next((arg for arg in args if not arg.startswith("-")), None)
            if script and script.replace("\\", "/").lstrip("./").lower() in paths:
                return True
            continue
        if executable == "go" and _runner_subcommand(
            executable, [arg.lower() for arg in args]
        ) == "run":
            if any(
                arg.replace("\\", "/").lstrip("./").lower() in paths for arg in args
            ):
                return True
        if _has_behavior_demo_marker(command) and re.search(
            r"(?:^|[._-])(?:demo|exercise|probe|scenario|smoke|verify)(?:[._-]|$)",
            executable,
        ):
            if any(
                arg.replace("\\", "/").lstrip("./").lower() in paths for arg in args
            ):
                return True
    return False


def _is_local_http_demo_command(command: str) -> bool:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _is_local_http_demo_command(inner)
    parsed = _inspection_executable_and_args(command)
    if parsed is None:
        return False
    executable, args = parsed
    if executable not in {"curl", "http", "https", "wget"}:
        return False
    lowered_args = [arg.lower() for arg in args]
    if _external_cli_uses_non_observing_mode(executable, args):
        return False
    if executable in {"http", "https"} and "--offline" in lowered_args:
        return False
    return any(
        re.match(
            r"^https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)(?::\d+)?(?:/|$)",
            arg,
            flags=re.IGNORECASE,
        )
        for arg in args
    )


def _external_cli_uses_non_observing_mode(
    executable: str, args: list[str]
) -> bool:
    """Reject help/version/dry-run modes without confusing host flags.

    Short options are executable-specific and case-sensitive: for example,
    ``psql -h`` selects a host while ``psql -V`` exits after printing a version;
    Docker likewise uses ``-H`` for a daemon and ``-v`` for its version.
    """

    lowered_args = [arg.lower() for arg in args]
    if any(
        arg in {"--help", "--manual", "--version", "--dry-run"}
        or arg.startswith(("--help=", "--version=", "--dry-run="))
        for arg in lowered_args
    ):
        return True

    short_exit_options = {
        "curl": {"-h", "-M", "-V"},
        "http": {"-h"},
        "https": {"-h"},
        "wget": {"-h", "-V"},
        "psql": {"-?", "-V"},
        "mysql": {"-?", "-V"},
        "mongosh": {"-h"},
        "redis-cli": {"-v"},
        "docker": {"-h", "-v", "-V"},
        "podman": {"-h", "-v", "-V"},
        "gcloud": {"-h"},
        "az": {"-h", "-v"},
        "kubectl": {"-h"},
    }
    if any(arg in short_exit_options.get(executable, set()) for arg in args):
        return True

    command_path = _external_cli_command_path(executable, lowered_args)
    root_command = command_path[0] if command_path else None
    if executable in {"aws", "gcloud", "az", "kubectl", "docker", "podman"} and root_command == "help":
        return True
    if executable in {"docker", "podman", "gcloud", "az", "kubectl"} and root_command in {
        "completion",
        "version",
    }:
        return True
    if executable == "aws" and root_command in {"configure", "history"}:
        return True
    if executable == "gcloud" and root_command in {
        "auth",
        "components",
        "config",
        "info",
        "meta",
        "topic",
    }:
        return True
    if executable == "az" and root_command in {
        "account",
        "cloud",
        "config",
        "extension",
        "feedback",
        "find",
        "interactive",
        "upgrade",
    }:
        return True
    if executable == "kubectl" and root_command in {
        "config",
        "kustomize",
        "options",
    }:
        return True
    if executable in {"docker", "podman"} and command_path == (
        "compose",
        "config",
    ):
        return True
    if executable == "mysql" and "--print-defaults" in lowered_args:
        return True
    if executable == "mongosh" and "--nodb" in lowered_args:
        return True
    if executable in {"http", "https"} and "--offline" in lowered_args:
        return True
    return False


def _external_cli_command_path(
    executable: str, lowered_args: list[str]
) -> tuple[str, ...]:
    """Extract the semantic top-level (and Compose nested) CLI command."""

    global_value_options = {
        "aws": {
            "--ca-bundle",
            "--cli-connect-timeout",
            "--cli-read-timeout",
            "--color",
            "--endpoint-url",
            "--output",
            "--profile",
            "--query",
            "--region",
        },
        "gcloud": {
            "--account",
            "--billing-project",
            "--configuration",
            "--flags-file",
            "--format",
            "--project",
            "--trace-token",
            "--user-output-enabled",
            "--verbosity",
        },
        "az": {"--output", "-o", "--query", "--subscription"},
        "kubectl": {
            "--as",
            "--as-group",
            "--as-uid",
            "--cache-dir",
            "--certificate-authority",
            "--client-certificate",
            "--client-key",
            "--cluster",
            "--context",
            "--kubeconfig",
            "--namespace",
            "-n",
            "--password",
            "--profile",
            "--profile-output",
            "--request-timeout",
            "--server",
            "-s",
            "--tls-server-name",
            "--token",
            "--user",
            "--username",
            "--v",
        },
        "docker": {"--config", "--context", "--host", "-h", "--log-level", "-l"},
        "podman": {
            "--connection",
            "-c",
            "--events-backend",
            "--identity",
            "--log-level",
            "--network-cmd-path",
            "--root",
            "--runroot",
            "--runtime",
            "--storage-driver",
            "--tmpdir",
            "--url",
        },
    }

    def positional_index(start: int, value_options: set[str]) -> int | None:
        index = start
        while index < len(lowered_args):
            value = lowered_args[index]
            if value == "--":
                index += 1
                return index if index < len(lowered_args) else None
            if value in value_options:
                index += 2
                continue
            if any(value.startswith(f"{option}=") for option in value_options):
                index += 1
                continue
            if value.startswith("-"):
                index += 1
                continue
            return index
        return None

    root_index = positional_index(0, global_value_options.get(executable, set()))
    if root_index is None:
        return ()
    root = lowered_args[root_index]
    if executable not in {"docker", "podman"} or root != "compose":
        return (root,)
    compose_index = positional_index(
        root_index + 1,
        {
            "--ansi",
            "--env-file",
            "-f",
            "--file",
            "--parallel",
            "--profile",
            "--progress",
            "--project-directory",
            "--project-name",
            "-p",
        },
    )
    return (root,) if compose_index is None else (root, lowered_args[compose_index])


def _is_external_service_demo_command(command: str) -> bool:
    """Recognize explicit, observable checks against non-local dependencies."""

    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _is_external_service_demo_command(inner)
    parsed = _inspection_executable_and_args(command)
    if parsed is None:
        return False
    executable, args = parsed
    lowered_args = [arg.lower() for arg in args]
    if _external_cli_uses_non_observing_mode(executable, args):
        return False

    if executable in {"curl", "http", "https", "wget"}:
        return any(
            re.match(
                r"^https?://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)(?::\d+)?(?:/|$))",
                arg,
                flags=re.IGNORECASE,
            )
            for arg in args
        )

    if executable == "psql":
        return any(
            arg in {"-c", "--command", "-f", "--file"}
            or arg.startswith(("--command=", "--file=", "postgres://", "postgresql://"))
            for arg in lowered_args
        )
    if executable == "mysql":
        return any(
            arg in {"-e", "--execute"} or arg.startswith("--execute=")
            for arg in lowered_args
        )
    if executable == "mongosh":
        return any(
            arg == "--eval"
            or arg.startswith(("--eval=", "mongodb://", "mongodb+srv://"))
            for arg in lowered_args
        )
    if executable == "redis-cli":
        return any(arg.startswith("redis://") for arg in lowered_args) or any(
            arg in {"ping", "get", "mget", "exists", "ttl", "pttl", "scan", "hget", "hgetall"}
            for arg in lowered_args
        )
    if executable in {"docker", "podman"}:
        command_path = _external_cli_command_path(executable, lowered_args)
        if "--no-start" in lowered_args:
            return False
        if command_path[:1] in {("build",), ("buildx",), ("bake",)} or command_path == (
            "compose",
            "build",
        ):
            return False
        daemon_commands = {
            "attach",
            "commit",
            "compose",
            "config",
            "container",
            "cp",
            "create",
            "diff",
            "events",
            "exec",
            "export",
            "history",
            "image",
            "images",
            "import",
            "info",
            "inspect",
            "kill",
            "load",
            "login",
            "logs",
            "network",
            "node",
            "pause",
            "plugin",
            "port",
            "ps",
            "pull",
            "push",
            "rename",
            "restart",
            "rm",
            "rmi",
            "run",
            "save",
            "search",
            "secret",
            "service",
            "stack",
            "start",
            "stats",
            "stop",
            "swarm",
            "system",
            "tag",
            "top",
            "trust",
            "unpause",
            "update",
            "volume",
            "wait",
        }
        if not command_path or command_path[0] not in daemon_commands:
            return False
        if command_path[0] != "compose":
            return True
        return len(command_path) == 2 and command_path[1] in {
            "attach",
            "cp",
            "create",
            "down",
            "events",
            "exec",
            "images",
            "kill",
            "logs",
            "ls",
            "pause",
            "port",
            "ps",
            "pull",
            "push",
            "restart",
            "rm",
            "run",
            "scale",
            "start",
            "stats",
            "stop",
            "top",
            "unpause",
            "up",
            "wait",
            "watch",
        }
    if executable == "kubectl":
        command_path = _external_cli_command_path(executable, lowered_args)
        return bool(command_path) and command_path[0] in {
            "annotate",
            "api-resources",
            "api-versions",
            "apply",
            "attach",
            "auth",
            "cluster-info",
            "cordon",
            "cp",
            "create",
            "delete",
            "describe",
            "diff",
            "drain",
            "edit",
            "exec",
            "expose",
            "get",
            "label",
            "logs",
            "patch",
            "port-forward",
            "replace",
            "rollout",
            "run",
            "scale",
            "set",
            "taint",
            "top",
            "uncordon",
            "wait",
        }
    if executable in {"aws", "gcloud", "az"}:
        command_path = _external_cli_command_path(executable, lowered_args)
        return bool(command_path) and not _external_cli_uses_non_observing_mode(
            executable, args
        )
    return False


def _tests_executed(command: str, output: str) -> bool:
    if not _is_behavioral_validation_command(command):
        return True
    if _validation_no_execution_reason(command, validation_type="behavioral") is not None:
        return False
    if not output.strip():
        return False
    lowered = output.lower()
    passed_count, failed_count = _test_count_summary(output)
    if (passed_count or 0) > 0 or (failed_count or 0) > 0:
        return True
    skipped_count = _skipped_test_count(output)
    total_count = _test_total_count(output)
    if (
        total_count is not None
        and skipped_count is not None
        and total_count > skipped_count
    ):
        return True
    zero_test_patterns = (
        r"\b0\s+(passing|failing|pending|tests?|specs?)\b",
        r"\b0\s+tests?\s+(run|executed|passed|failed|total)\b",
        r"\btests?:\s+0\s+total\b",
        r"\btest suites?:\s+0\b",
        r"\bran\s+0\s+tests?\b",
        r"\bno tests?\s+(found|ran|run|executed)\b",
        r"\[no tests? to run\]",
        r"\[no test files\]",
        r"\bno test files? found\b",
        r"\btests? run:\s*0\b",
        r"\b0\s+examples?\b",
        r"\bno test is available\b",
        r"(?m)^\s*[^\r\n]*\bno-source\b",
    )
    if any(re.search(pattern, lowered) for pattern in zero_test_patterns):
        return False
    if (
        skipped_count is not None
        and skipped_count > 0
        and (
            (total_count is not None and total_count <= skipped_count)
            or re.search(
                r"(?m)^\s*[1-9]\d*\s+(?:ignored|pending|skipped|xfailed)\b",
                lowered,
            )
            is not None
        )
        and (passed_count or 0) == 0
        and (failed_count or 0) == 0
    ):
        return False
    positive_execution = re.search(
        r"\b(?:[1-9]\d*\s+(?:passed|failed|errors?|xfailed|xpassed)|"
        r"(?:passed|failed|errors?|tests?)\s*:\s*[1-9]\d*)\b",
        lowered,
    )
    no_execution_output = (
        r"\bcollected\s+\d+\s+(?:items?|tests?)\b",
        r"\b\d+\s+deselected\b",
        r"\btests? are skipped\b",
        r"\bwarning:\s*no tests? to run\b",
        r"\bno matching tests?\b",
    )
    if positive_execution is None and any(
        re.search(pattern, lowered) for pattern in no_execution_output
    ):
        return False
    return True


def _behavioral_lifecycle_needs_positive_test_output(command: str) -> bool:
    parsed = _validation_executable_and_args(command)
    if parsed is None:
        return False
    executable, args = parsed
    lowered_args = [arg.lower() for arg in args]
    if executable in {"mvn", "mvnw"}:
        tasks = set(_build_tool_tasks(executable, lowered_args))
        return bool(tasks & {"package", "verify", "install", "deploy"}) and not bool(
            tasks & {"test", "integration-test"}
        )
    if executable in {"gradle", "gradlew"}:
        tasks = _build_tool_tasks(executable, lowered_args)
        explicit_test = any(_gradle_task_is_test_task(task) for task in tasks)
        return bool(set(tasks) & {"build", "check"}) and not explicit_test
    return False


def _optional_package_test_may_not_exist(command: str) -> bool:
    parsed = _validation_executable_and_args(command)
    if parsed is None:
        return False
    executable, args = parsed
    if executable not in {"npm", "pnpm", "yarn"}:
        return False
    lowered_args = [arg.lower() for arg in args]
    before_separator = (
        lowered_args[: lowered_args.index("--")]
        if "--" in lowered_args
        else lowered_args
    )
    script = _package_script_name(before_separator)
    return bool(
        script
        and (script == "test" or script.startswith("test:"))
        and "--if-present" in before_separator
    )


def _gradle_task_is_test_task(task: str) -> bool:
    """Recognize Gradle/JVM and Android test task names, not option values."""

    name = task.rsplit(":", 1)[-1]
    return name.lower() == "test" or bool(
        re.fullmatch(r"test[A-Za-z0-9_.-]*UnitTest", name, flags=re.IGNORECASE)
    )


def _output_confirms_test_execution(output: str) -> bool:
    passed, failed = _test_count_summary(output)
    if (passed or 0) > 0 or (failed or 0) > 0:
        return True
    total = _test_total_count(output)
    skipped = _skipped_test_count(output) or 0
    return total is not None and total > skipped


def _command_output_from_item(item: Any, *, limit: int = 20000) -> str:
    if not isinstance(item, dict):
        return ""
    parts: list[str] = []
    _collect_output_strings(item, parts, depth=0)
    return _bounded_head_tail_text("\n".join(parts), limit=limit)


def _bounded_head_tail_text(text: str, *, limit: int) -> str:
    if len(text) <= limit:
        return text
    marker = "\n...<middle truncated; terminal output preserved>...\n"
    available = max(0, limit - len(marker))
    head = available // 3
    tail = available - head
    return text[:head] + marker + (text[-tail:] if tail else "")


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
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()
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
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return f"inspection-{digest[:16]}"


def _inspection_exit_is_usable(command: str, exit_code: int | None) -> bool:
    if exit_code == 0:
        return True
    if exit_code == 1 and re.search(
        r"(^|[\s;&|()'\"])(?:rg|grep|egrep|fgrep)\b", command.lower()
    ):
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
    return _generic_validation_masking_reason(
        command,
        validation_type=validation_type,
        changed_paths=changed_paths or [],
    )


def _marked_behavior_demo_masking_reason(command: str) -> str | None:
    no_execution_reason = _validation_no_execution_reason(
        command, validation_type="behavior_demo"
    )
    if no_execution_reason is not None:
        return no_execution_reason
    control_command = _validation_shell_control_envelope(command)
    cleaned = _strip_shell_comments(control_command)
    controls = _unquoted_shell_controls(cleaned)
    if _has_unquoted_logical_and(command):
        return "logical_and_chain_not_atomic"
    if _shell_mode_is_disabled(command):
        return "shell_failure_mode_disabled_during_behavior_demo"
    if "newline" in controls:
        return "command_newline_may_mask_validation_failure"
    if "background" in controls:
        return "background_command_may_mask_validation_failure"
    if "bang" in controls:
        return "negated_command_inverts_validation_status"
    if "pipeline" in controls:
        return "behavior_demo_pipeline_may_transform_output"
    if "logical_or" in controls and not _logical_or_is_fail_closed(command):
        return "logical_or_may_mask_validation_failure"
    if "$(" in command or "`" in command:
        return "command_substitution_may_mask_failure"
    if "semicolon" in controls:
        return "command_separator_may_mask_validation_failure"
    return None


def _generic_validation_masking_reason(
    command: str,
    *,
    validation_type: str | None = None,
    changed_paths: list[str] | None = None,
) -> str | None:
    no_execution_reason = _validation_no_execution_reason(
        command, validation_type=validation_type
    )
    if no_execution_reason is not None:
        return no_execution_reason
    control_command = _validation_shell_control_envelope(command)
    cleaned = _strip_shell_comments(control_command)
    controls = _unquoted_shell_controls(cleaned)
    if _has_unquoted_logical_and(command) and _logical_and_validation_chain_type(
        command, changed_paths=changed_paths or []
    ) is None:
        return "logical_and_chain_not_atomic"
    if "newline" in controls:
        return "command_newline_may_mask_validation_failure"
    if "background" in controls:
        return "background_command_may_mask_validation_failure"
    if "bang" in controls:
        return "negated_command_inverts_validation_status"
    if "pipeline" in controls and not _shell_pipefail_precedes_pipeline(command):
        return "pipeline_without_pipefail"
    if "$(" in command or "`" in command:
        return "command_substitution_may_mask_failure"
    if "logical_or" in controls and not _logical_or_is_fail_closed(command):
        return "logical_or_may_mask_validation_failure"
    if "semicolon" in controls:
        return "command_separator_may_mask_validation_failure"
    return None


def _validation_no_execution_reason(
    command: str, *, validation_type: str | None = None
) -> str | None:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _validation_no_execution_reason(
            inner, validation_type=validation_type
        )
    if validation_type == "behavior_demo":
        return None
    chained = _logical_and_command_segments(command)
    if chained is not None:
        for segment in chained:
            reason = _validation_no_execution_reason(
                segment, validation_type=validation_type
            )
            if reason is not None:
                return reason
        return None
    behavioral_flags = (
        "--collect-only",
        "--collectonly",
        "--fixtures",
        "--fixtures-per-test",
        "--list",
        "--list-tests",
        "--listtests",
        "--listtest",
        "--markers",
        "--cache-show",
        "--clear-cache",
        "--clearcache",
        "--setup-plan",
        "--setup-only",
        "--showconfig",
        "--listfilesonly",
    )
    static_flags = ("--help", "--version", "--dry-run")
    applicable_flags = (
        (*behavioral_flags, *static_flags)
        if validation_type == "behavioral"
        else static_flags
        if validation_type == "static"
        else (*behavioral_flags, *static_flags)
    )
    parsed = _validation_executable_and_args(command)
    if parsed is not None:
        executable, raw_args = parsed
        args = [arg.lower() for arg in raw_args]
        runner, runner_args = _npx_runner_and_args(executable, args)
        raw_runner, raw_runner_args = _npx_runner_and_args(executable, raw_args)
        control_args = runner_args if executable == "npx" else args
        raw_control_args = raw_runner_args if executable == "npx" else raw_args
        before_separator = (
            control_args[: control_args.index("--")]
            if "--" in control_args
            else control_args
        )
        raw_before_separator = (
            raw_control_args[: raw_control_args.index("--")]
            if "--" in raw_control_args
            else raw_control_args
        )

        def has_flag(values: list[str], flag: str) -> bool:
            return any(value == flag or value.startswith(f"{flag}=") for value in values)

        if any(has_flag(before_separator, flag) for flag in applicable_flags):
            return "validation_command_does_not_execute_contract"
        if "-h" in before_separator:
            return "validation_command_does_not_execute_contract"
        if runner == "pytest" and any(
            re.fullmatch(r"-[qvshxl]*h[qvshxl]*", value) is not None
            for value in before_separator
        ):
            return "validation_command_does_not_execute_contract"
        if raw_runner == "mocha" and (
            "-V" in raw_before_separator
            or any(
                value.lower() in {"--list-reporters", "--list-interfaces"}
                for value in raw_before_separator
            )
        ):
            return "validation_command_does_not_execute_contract"
        if raw_runner == "rspec" and "-v" in raw_before_separator:
            return "validation_command_does_not_execute_contract"
        if validation_type in {None, "behavioral"} and "--co" in before_separator:
            return "validation_command_does_not_execute_contract"

        if runner == "vitest" and (
            _vitest_subcommand(before_separator) in {"init", "list"}
            or any(
                value in {"--listtags", "--clearcache"}
                for value in before_separator
            )
        ):
            return "validation_command_does_not_execute_contract"

        if runner == "tox" and (
            _tox_execution_subcommand(before_separator) in {"list", "l", "config"}
            or any(
                value
                in {
                    "-l",
                    "--listenvs",
                    "-a",
                    "--listenvs-all",
                    "-n",
                    "--notest",
                }
                for value in before_separator
            )
        ):
            return "validation_command_does_not_execute_contract"

        if executable in {"npm", "pnpm", "yarn"} and "--" in control_args:
            forwarded = control_args[control_args.index("--") + 1 :]
            if (
                any(has_flag(forwarded, flag) for flag in applicable_flags)
                or "-h" in forwarded
                or (
                    validation_type in {None, "behavioral"}
                    and "--co" in forwarded
                )
            ):
                return "validation_command_does_not_execute_contract"

        if runner == "cargo" and _runner_subcommand(runner, args) == "test":
            if "--no-run" in before_separator:
                return "validation_command_does_not_execute_contract"
            # Cargo forwards arguments after `--` to the test harness; `--list`
            # there lists tests instead of executing them.
            if "--" in control_args and any(
                has_flag(control_args[control_args.index("--") + 1 :], flag)
                for flag in ("--list", "--list-tests", "--help")
            ):
                return "validation_command_does_not_execute_contract"
            if "--" in control_args and "-h" in control_args[
                control_args.index("--") + 1 :
            ]:
                return "validation_command_does_not_execute_contract"

        if executable == "go" and _runner_subcommand(executable, args) == "test":
            if (
                "-c" in before_separator
                or "-n" in before_separator
                or has_flag(before_separator, "-list")
                or has_flag(before_separator, "-exec")
            ):
                return "validation_command_does_not_execute_contract"
            for index, value in enumerate(before_separator):
                if value == "-run" and index + 1 < len(before_separator) and before_separator[index + 1] == "^$":
                    return "validation_command_does_not_execute_contract"
                if value == "-run=^$":
                    return "validation_command_does_not_execute_contract"
                if value == "-count=0" or (
                    value == "-count"
                    and index + 1 < len(before_separator)
                    and before_separator[index + 1] == "0"
                ):
                    return "validation_command_does_not_execute_contract"

        if executable in {"mvn", "mvnw"}:
            if any(
                value in {"-dskiptests", "-dmaven.test.skip"}
                or value in {"-dskiptests=true", "-dmaven.test.skip=true"}
                for value in before_separator
            ):
                return "validation_command_does_not_execute_contract"

        if executable in {"gradle", "gradlew"}:
            if any(value in {"-m", "--task-graph"} for value in before_separator):
                return "validation_command_does_not_execute_contract"
            excluded_tasks: list[str] = []
            for index, value in enumerate(before_separator):
                if value in {"-x", "--exclude-task"} and index + 1 < len(before_separator):
                    excluded_tasks.append(before_separator[index + 1])
                elif value.startswith("--exclude-task="):
                    excluded_tasks.append(value.split("=", 1)[1])
            if any(
                re.fullmatch(
                    r":?(?:[\w.-]+:)*test[\w.-]*",
                    task,
                    flags=re.IGNORECASE,
                )
                for task in excluded_tasks
            ):
                return "validation_command_does_not_execute_contract"

        if executable == "dotnet" and _runner_subcommand(executable, args) == "test":
            test_index = before_separator.index("test")
            if "-t" in before_separator[test_index + 1 :]:
                return "validation_command_does_not_execute_contract"

        if executable == "swift" and _runner_subcommand(executable, args) == "test":
            test_index = before_separator.index("test")
            if any(
                value
                in {
                    "-l",
                    "-help",
                    "list",
                    "--list-tests",
                    "--show-codecov-path",
                }
                for value in before_separator[test_index + 1 :]
            ):
                return "validation_command_does_not_execute_contract"

        if executable == "deno" and _runner_subcommand(executable, args) == "test":
            if "--no-run" in before_separator:
                return "validation_command_does_not_execute_contract"

        if executable == "make" and any(
            value == "--just-print"
            or (
                value.startswith("-")
                and not value.startswith("--")
                and "n" in value[1:]
            )
            for value in before_separator
        ):
            return "validation_command_does_not_execute_contract"
        return None

    # Fail closed for a complex invocation that could not be tokenized into a
    # canonical executable. Direct commands use the exact argv checks above so
    # quoted selector text cannot spoof a runner control flag.
    lowered = _strip_shell_comments(command).lower()
    if any(
        re.search(rf"(^|\s){re.escape(flag)}(?:=|\s|$)", lowered)
        for flag in applicable_flags
    ) or re.search(r"(^|\s)(?:-h|--co)(?:\s|$)", lowered):
        return "validation_command_does_not_execute_contract"
    return None


def _validation_shell_control_envelope(command: str) -> str:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _validation_shell_control_envelope(inner)
    opening = re.search(
        r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1[^\r\n]*(?:\r?\n)", command
    )
    if opening is None:
        return command
    delimiter = opening.group(2)
    body_start = opening.end()
    closing = re.search(
        rf"(?m)^[\t ]*{re.escape(delimiter)}[\t ]*(?:\r?$)",
        command[body_start:],
    )
    if closing is None:
        return command
    trailing = command[body_start + closing.end() :]
    if trailing.strip():
        return command
    return command[: opening.start()] + command[opening.start() : opening.end()].rstrip(
        "\r\n"
    )


def _behavior_demo_output_masking_reason(output: str) -> str | None:
    if _captured_output_is_self_verdict_only(output):
        return "behavior_demo_self_verdict_only"
    if _captured_output_looks_like_test_runner(output):
        return "behavior_demo_looks_like_test_runner_output"
    return None


def _unquoted_shell_view(command: str) -> str:
    output: list[str] = []
    in_quote: str | None = None
    index = 0
    while index < len(command):
        char = command[index]
        if in_quote is not None:
            if char == "\\" and in_quote == '"' and index + 1 < len(command):
                output.extend((" ", " "))
                index += 2
                continue
            if char == in_quote:
                in_quote = None
            output.append(" ")
            index += 1
            continue
        if char in {"'", '"'}:
            in_quote = char
            output.append(" ")
            index += 1
            continue
        if char == "\\" and index + 1 < len(command):
            output.extend((" ", " "))
            index += 2
            continue
        output.append(char)
        index += 1
    return "".join(output)


def _has_unquoted_logical_and(command: str) -> bool:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _has_unquoted_logical_and(inner)
    return "&&" in _unquoted_shell_view(_strip_shell_comments(command))


def _shell_invocation_has_option(
    command: str, *, short_option: str | None, long_option: str
) -> bool:
    try:
        tokens = _strip_env_command_prefix(shlex.split(command))
    except ValueError:
        return False
    if not tokens or Path(tokens[0]).name.lower() not in {"bash", "sh", "zsh"}:
        return False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "-o" and index + 1 < len(tokens):
            if tokens[index + 1].lower() == long_option:
                return True
            index += 2
            continue
        if token.startswith("-") and not token.startswith("--"):
            if short_option and short_option in token[1:]:
                return True
            if "c" in token[1:]:
                break
            index += 1
            continue
        break
    return False


def _shell_mode_activation(
    command: str, *, short_option: str | None, long_option: str
) -> tuple[str, re.Match[str] | None]:
    if _shell_invocation_has_option(
        command, short_option=short_option, long_option=long_option
    ):
        return "", re.match(r"", "")
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _shell_mode_activation(
            inner, short_option=short_option, long_option=long_option
        )
    view = _unquoted_shell_view(_strip_shell_comments(command)).lower()
    patterns = [
        rf"(?:^|[;&|\r\n])\s*set\s+-o\s+{re.escape(long_option)}(?:\s|;|$)",
        rf"(?:^|[;&|\r\n])\s*set\s+-[a-z]*o[a-z]*\s+{re.escape(long_option)}(?:\s|;|$)",
    ]
    if short_option:
        patterns.append(
            rf"(?:^|[;&|\r\n])\s*set\s+-[a-z]*{re.escape(short_option)}[a-z]*(?:\s|;|$)"
        )
    matches = [
        match
        for pattern in patterns
        if (match := re.search(pattern, view)) is not None
    ]
    return view, min(matches, key=lambda match: match.start()) if matches else None


def _shell_errexit_precedes_commands(command: str) -> bool:
    if _shell_invocation_has_option(
        command, short_option="e", long_option="errexit"
    ):
        return True
    view, activation = _shell_mode_activation(
        command, short_option="e", long_option="errexit"
    )
    return activation is not None and not view[: activation.start()].strip()


def _shell_mode_is_disabled(command: str) -> bool:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _shell_mode_is_disabled(inner)
    view = _unquoted_shell_view(_strip_shell_comments(command)).lower()
    return bool(
        re.search(
            r"(?:^|[;&|\r\n])\s*set\s+(?:\+[a-z]*e[a-z]*|\+o\s+(?:errexit|pipefail))"
            r"(?:\s|;|$)",
            view,
        )
    )


def _shell_pipefail_precedes_pipeline(command: str) -> bool:
    if _shell_invocation_has_option(
        command, short_option=None, long_option="pipefail"
    ):
        return True
    view, activation = _shell_mode_activation(
        command, short_option=None, long_option="pipefail"
    )
    if activation is None:
        return False
    pipeline = re.search(r"(?<!\|)\|(?!\|)", view)
    return pipeline is not None and activation.end() <= pipeline.start()


def _logical_or_is_fail_closed(command: str) -> bool:
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _logical_or_is_fail_closed(inner)
    view = _unquoted_shell_view(_strip_shell_comments(command))
    matches = list(re.finditer(r"\|\|", view))
    if len(matches) != 1:
        return False
    return re.fullmatch(r"\s*exit\s+1\s*", view[matches[0].end() :]) is not None


def _command_was_filtered(command: str) -> bool:
    return _raw_validation_selector(command) is not None


def _raw_validation_selector(command: str) -> str | None:
    selectors: list[str] = []
    patterns = (
        r"(?:^|\s)(-k)\s+([^\s;&|]+)",
        r"(?:^|\s)(-m)\s+([^\s;&|]+)",
        r"(?:^|\s)(--grep|--testNamePattern|--test-name-pattern|--filter|--test)\s+([^\s;&|]+)",
        r"(?:^|\s)(-g)\s+([^\s;&|]+)",
        r"(?:^|\s)(--workspace|-w|--filter|-F|workspace)\s+([^\s;&|]+)",
        r"(?:^|\s)(--workspace|--filter)=([^\s;&|]+)",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, command):
            if match.group(1) == "-m" and _is_python_module_flag(
                command, match.start(1)
            ):
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
    passed_patterns = (
        r"\b(\d+)\s+passed\b",
        r"\b(\d+)\s+passing\b",
        r"\bpasses:\s*(\d+)\b",
        r"\bpassed:\s*(\d+)\b",
        r"(?m)^\s*#\s*pass\s+(\d+)\b",
        r"\btests?:\s*(\d+)\s+passed\b",
        r"\b(\d+)\s+tests?\s+passed\b",
        r"\btests?:[^\r\n]*?\b(\d+)\s+passed\b",
    )
    failed_patterns = (
        r"\b(\d+)\s+failed\b",
        r"\b(\d+)\s+failing\b",
        r"\bfailures?:\s*(\d+)\b",
        r"\bfailures?\s*=\s*(\d+)\b",
        r"\bfailed:\s*(\d+)\b",
        r"\berrors?:\s*(\d+)\b",
        r"\berrors?\s*=\s*(\d+)\b",
        r"(?m)^\s*#\s*fail\s+(\d+)\b",
        r"\btests?:\s*\d+\s+passed,\s*(\d+)\s+failed\b",
        r"\b(\d+)\s+tests?\s+failed\b",
        r"\btests?:[^\r\n]*?\b(\d+)\s+failed\b",
    )
    lines = lowered.splitlines()
    # RSpec and pytest error-only terminal summaries do not use the generic
    # "passed"/"failed" wording above. Resolve them from the end of the output so
    # application text printed by the suite cannot override the runner verdict.
    for line in reversed(lines):
        rspec = re.fullmatch(
            r"\s*(\d+)\s+examples?,\s*(\d+)\s+failures?"
            r"(?:,\s*(\d+)\s+pending)?(?:\s+.*)?",
            line,
        )
        if rspec:
            total = int(rspec.group(1))
            failed = int(rspec.group(2))
            pending = int(rspec.group(3) or 0)
            return max(0, total - failed - pending), failed
        pytest_body = line.strip().strip("=").strip()
        pytest_summary = re.fullmatch(
            r"\d+\s+(?:passed|failed|errors?|warnings?|skipped|deselected|xfailed|xpassed)"
            r"(?:,\s*\d+\s+(?:passed|failed|errors?|warnings?|skipped|deselected|xfailed|xpassed))*"
            r"\s+in\s+\S+(?:\s+.*)?",
            pytest_body,
        )
        if pytest_summary:
            passed = _max_int_match(pytest_body, (r"\b(\d+)\s+passed\b",)) or 0
            failed = _max_int_match(
                pytest_body,
                (r"\b(\d+)\s+failed\b", r"\b(\d+)\s+errors?\b"),
            ) or 0
            return passed, failed
        pytest_error = re.fullmatch(
            r"\s*(\d+)\s+errors?(?:\s+in\s+.+)?\s*",
            line,
        )
        if pytest_error:
            return 0, int(pytest_error.group(1))
    # Prefer the terminal runner summary over application text captured earlier by
    # `pytest -s` or an equivalent runner. A genuine mixed summary still carries its
    # failure count on the same line or in the following summary lines.
    for index in range(len(lines) - 1, -1, -1):
        passed = _first_int_match(lines[index], passed_patterns)
        if passed is None:
            continue
        summary_tail = "\n".join(lines[index:])
        failed = _max_int_match(summary_tail, failed_patterns)
        return passed, 0 if failed is None else failed
    passed = _first_int_match(lowered, passed_patterns)
    failed = _max_int_match(lowered, failed_patterns)
    if passed is not None and failed is None:
        failed = 0
    return passed, failed


def _skipped_test_count(output: str) -> int | None:
    return _first_int_match(
        output.lower(),
        (
            r"\b(\d+)\s+(?:ignored|pending|skipped|xfailed)\b",
            r"\b(?:ignored|pending|skipped):\s*(\d+)\b",
            r"(?m)^\s*#\s*skipped\s+(\d+)\b",
        ),
    )


def _test_total_count(output: str) -> int | None:
    lowered = output.lower()
    rust_summary = re.search(
        r"\btest result:\s*(?:ok|failed)\.\s*(\d+)\s+passed;\s*"
        r"(\d+)\s+failed;\s*(\d+)\s+(?:ignored|skipped)",
        lowered,
    )
    if rust_summary:
        return sum(int(value) for value in rust_summary.groups())
    return _first_int_match(
        lowered,
        (
            r"\btests?\s+run:\s*(\d+)\b",
            r"\b(\d+)\s+tests?\s+completed\b",
            r"\b(\d+)\s+examples?\b",
            r"(?m)^\s*#\s*tests?\s+(\d+)\b",
            r"\btotal:\s*(\d+)\b",
            r"\btests?:[^\r\n]*?\b(\d+)\s+total\b",
        ),
    )


def _first_int_match(text: str, patterns: tuple[str, ...]) -> int | None:
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return int(match.group(1))
    return None


def _max_int_match(text: str, patterns: tuple[str, ...]) -> int | None:
    values = [
        int(match.group(1))
        for pattern in patterns
        for match in re.finditer(pattern, text)
    ]
    return max(values) if values else None


def _test_output_reports_failure(output: str) -> bool:
    passed, failed = _test_count_summary(output)
    if (failed or 0) > 0:
        return True
    # A recognized runner summary with executed passing tests and an explicit
    # zero-failure count outranks incidental application text such as an expected
    # rendered "FAIL" label or "handled 1 errors successfully".
    if (passed or 0) > 0 and failed == 0:
        return False
    return any(
        re.search(pattern, output, flags=re.IGNORECASE | re.MULTILINE)
        for pattern in (
            r"^\s*FAIL(?:\s|$)",
            r"^\s*not ok\b",
            r"\bBUILD FAILURE\b",
            r"\bFAILED\s*\(",
            r"\btest result:\s*failed\b",
        )
    )


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
            "bello ready for review",
            "bello_ready",
            "bello_ready_for_review",
            "ready_for_review",
        )
    )


def _readiness_reference_is_negated(text: str) -> bool:
    lowered = " ".join(text.lower().split())
    marker = r"(?:bello[\s_`'\-]*ready[\s_`'\-]*for[\s_`'\-]*review|ready[\s_`'\-]*for[\s_`'\-]*review|readiness marker)"
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
    return _truncate_summary(
        candidates[0] if candidates else "coder reported a material limitation"
    )


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


def _normalized_surface_key(category: str) -> str:
    return re.sub(r"\s+", " ", category).strip().lower()


def _merge_behavior_surface_items(
    existing: list[dict[str, Any]],
    updates: list[BehaviorSurfaceItem],
) -> tuple[list[dict[str, Any]], bool]:
    """Upsert reviewer-returned surface entries into the stored list.

    Entries are never removed: a reviewer that judges an entry not actually required marks it
    status=out_of_scope with a note instead, so the audit trail of what was considered stays
    visible to later reviews.
    """
    merged: list[dict[str, Any]] = [
        dict(item)
        for item in existing
        if isinstance(item, dict) and str(item.get("category") or "").strip()
    ]
    index = {
        _normalized_surface_key(str(item.get("category") or "")): pos
        for pos, item in enumerate(merged)
    }
    changed = False
    for item in updates:
        category = (item.category or "").strip()
        if not category:
            continue
        key = _normalized_surface_key(category)
        pos = index.get(key)
        if pos is None:
            merged.append(
                {"category": category, "status": item.status, "note": item.note}
            )
            index[key] = len(merged) - 1
            changed = True
        elif (
            merged[pos].get("status") != item.status
            or merged[pos].get("note") != item.note
        ):
            merged[pos] = {**merged[pos], "status": item.status, "note": item.note}
            changed = True
    return merged, changed


def _completion_returns_this_generation(controller: Any, generation: int) -> int:
    return sum(
        1
        for record in getattr(controller, "completion_returns", []) or []
        if getattr(record, "generation", None) == generation
    )


def _prior_record_counts_as_health_intervention(record: Any) -> bool:
    reason = str(getattr(record, "reason", "") or "")
    return not reason.startswith("Completion review returned:")


def _latest_relevant_change_sequence(
    changed_files: list[ChangedFile],
    *,
    task_contents: str = "",
) -> int | None:
    static_review_paths = {
        _normalize_review_path(file.path)
        for file in _material_static_review_files(
            changed_files,
            task_contents=task_contents,
        )
    }
    sequences = [
        file.sequence
        for file in changed_files
        if file.sequence is not None
        and (
            _is_relevant_changed_path(file.path, task_contents=task_contents)
            or _normalize_review_path(file.path) in static_review_paths
        )
    ]
    return max(sequences) if sequences else None


def _latest_behavioral_change_sequence(
    changed_files: list[ChangedFile], *, task_contents: str = ""
) -> int | None:
    sequences = [
        file.sequence
        for file in changed_files
        if file.sequence is not None
        and _changed_file_is_behavior_affecting(file, task_contents=task_contents)
    ]
    return max(sequences) if sequences else None


def _validation_freshness_summary(
    *,
    validations: list[ValidationRun],
    changed_files: list[ChangedFile],
    task_contents: str = "",
) -> str:
    latest_change = _latest_behavioral_change_sequence(
        changed_files, task_contents=task_contents
    )
    has_behavioral_change = any(
        _changed_file_is_behavior_affecting(file, task_contents=task_contents)
        for file in changed_files
    )
    passing_behavioral = [
        validation
        for validation in validations
        if validation.type in {"behavioral", "behavior_demo"}
        and validation.outcome == "pass"
        and validation.passed
        and validation.trusted_validation_outcome == "passed"
    ]
    last_behavioral = (
        max(passing_behavioral, key=lambda validation: validation.sequence)
        if passing_behavioral
        else None
    )
    if last_behavioral is None:
        if latest_change is None:
            if has_behavioral_change:
                return (
                    "No passing behavioral validation recorded; a behavioral source/test change exists "
                    "but its sequence is unknown."
                )
            return "No behavioral source/test change is present; behavioral freshness is not applicable."
        return f"No passing behavioral validation recorded after latest relevant change sequence {latest_change}."
    if latest_change is None:
        if not has_behavioral_change:
            return (
                f"Last passing behavioral validation sequence {last_behavioral.sequence}; "
                "no behavioral source/test change is present."
            )
        return (
            f"Last passing behavioral validation sequence {last_behavioral.sequence}; "
            "a behavioral source/test change exists but its sequence is unknown."
        )
    freshness = (
        "fresh"
        if _validation_is_after_change(last_behavioral, latest_change)
        else "stale"
    )
    return (
        f"Last passing behavioral validation sequence {last_behavioral.sequence}; "
        f"latest relevant change sequence {latest_change}; behavioral validation is {freshness}."
    )


def _material_code_review_files(
    changed_files: list[ChangedFile], *, task_contents: str = ""
) -> list[ChangedFile]:
    return [
        file
        for file in changed_files
        if _file_kind(file.path) in {"source", "test", "unknown"}
        and not _is_non_material_changed_path(file.path)
        and not _unknown_path_is_static_task_output(
            file.path, task_contents=task_contents
        )
    ]


def _material_static_review_files(
    changed_files: list[ChangedFile],
    *,
    task_contents: str,
) -> list[ChangedFile]:
    material = [
        file
        for file in changed_files
        if not _is_non_material_changed_path(file.path)
        or _changed_path_is_explicit_task_output(file.path, task_contents=task_contents)
        or _artifact_is_task_relevant(file.path, task_contents=task_contents)
        or _is_static_web_deliverable_path(file.path, task_contents=task_contents)
    ]
    has_behavioral_change = any(
        _changed_file_is_behavior_affecting(file, task_contents=task_contents)
        for file in material
    )
    static_is_primary_output = bool(material) and not has_behavioral_change
    selected: list[ChangedFile] = []
    for file in material:
        kind = _file_kind(file.path)
        if kind == "config":
            selected.append(file)
        elif kind == "docs" and (
            _task_is_docs_facing(task_contents)
            or static_is_primary_output
            or _changed_path_is_explicit_task_output(
                file.path, task_contents=task_contents
            )
        ):
            selected.append(file)
        elif kind == "artifact" and (
            static_is_primary_output
            or _artifact_is_task_relevant(file.path, task_contents=task_contents)
        ):
            selected.append(file)
        elif kind == "unknown" and _unknown_path_is_static_task_output(
            file.path, task_contents=task_contents
        ):
            selected.append(file)
        elif (
            kind in {"source", "test"}
            and _is_non_material_changed_path(file.path)
            and _changed_path_is_explicit_task_output(
                file.path, task_contents=task_contents
            )
        ):
            selected.append(file)
        elif _is_static_web_deliverable_path(file.path, task_contents=task_contents):
            selected.append(file)
    return selected


def _accept_static_review_issue(
    decision: CompletionReviewDecision,
    files: list[ChangedFile],
    *,
    reviewer_evidence: list[CompletionReviewerEvidence] | None = None,
    workspace_state_id: str | None = None,
    task_contents: str = "",
) -> str | None:
    reviewed_by_path = {
        _normalize_review_path(file.path): file for file in decision.files_reviewed
    }
    missing: list[str] = []
    limited: list[str] = []
    unaudited_artifacts: list[str] = []
    for changed in files:
        reviewed = reviewed_by_path.get(_normalize_review_path(changed.path))
        if reviewed is None or not reviewed.inspected:
            missing.append(changed.path)
            continue
        if reviewed.limitation:
            limited.append(f"{changed.path}: {reviewed.limitation}")
            continue
        if reviewer_evidence is not None and not _reviewer_evidence_covers_static_file(
            reviewer_evidence,
            changed.path,
            workspace_state_id=workspace_state_id,
            task_contents=task_contents,
        ):
            unaudited_artifacts.append(changed.path)
    if missing:
        return "task-relevant config/document/artifact was not inspected: " + ", ".join(
            missing[:8]
        )
    if limited:
        return (
            "task-relevant config/document/artifact review remains limited: "
            + "; ".join(limited[:5])
        )
    if unaudited_artifacts:
        return (
            "task-relevant static file was declared inspected without a capable successful reviewer-lane "
            "inspection on this workspace state: " + ", ".join(unaudited_artifacts[:8])
        )
    return None


def _reviewer_evidence_covers_path(
    records: list[CompletionReviewerEvidence],
    path: str,
    *,
    workspace_state_id: str | None,
) -> bool:
    target = _normalize_review_path(path)
    for record in records:
        if not record.passed:
            continue
        if (
            workspace_state_id is not None
            and record.workspace_state_id != workspace_state_id
        ):
            continue
        if target not in {
            _normalize_review_path(raw_path) for raw_path in record.paths
        }:
            continue
        if _reviewer_command_capably_inspects_path(
            record, target, _file_kind(target)
        ):
            return True
    return False


def _reviewer_evidence_has_capable_workspace_read(
    records: list[CompletionReviewerEvidence],
    *,
    workspace_state_id: str,
) -> bool:
    for record in records:
        if not record.passed or record.workspace_state_id != workspace_state_id:
            continue
        for raw_path in record.paths:
            target = _normalize_review_path(raw_path)
            if not target or target == ".":
                continue
            if record.kind == "image_view":
                return True
            if _reviewer_command_capably_inspects_path(
                record, target, _file_kind(target)
            ):
                return True
    return False


def _reviewer_evidence_covers_static_file(
    records: list[CompletionReviewerEvidence],
    path: str,
    *,
    workspace_state_id: str | None,
    task_contents: str,
) -> bool:
    target = _normalize_review_path(path)
    current_records = [
        record
        for record in records
        if record.passed
        and (
            workspace_state_id is None
            or record.workspace_state_id == workspace_state_id
        )
    ]
    matching = [record for record in current_records if target in record.paths]
    kind = _file_kind(path)
    if kind == "artifact":
        if _artifact_requires_visual_inspection(path, task_contents=task_contents):
            if any(record.kind == "image_view" for record in matching):
                return True
            return _reviewer_render_view_chain_covers(current_records, target)
        return any(
            record.kind == "image_view"
            or _reviewer_command_capably_inspects_path(record, target, kind)
            for record in matching
        )
    return any(
        _reviewer_command_capably_inspects_path(record, target, kind)
        for record in matching
    )


def _reviewer_command_capably_inspects_path(
    record: CompletionReviewerEvidence,
    target: str,
    kind: str,
) -> bool:
    if record.kind != "command" or not record.command:
        return False
    segments = _reviewer_command_segments(record.command)
    if len(segments) != 1:
        return False
    if not _is_capable_static_inspection_command(
        segments[0], kind, path=target
    ):
        return False
    parsed = _inspection_executable_and_args(segments[0])
    if parsed is not None and parsed[0] == "git" and "diff" in [
        arg.lower() for arg in parsed[1][:4]
    ]:
        patch_paths = {
            _normalize_review_path(path) for path in record.patch_paths
        }
        if target not in patch_paths:
            return False
    return record.observed_output or target in {
        _normalize_review_path(path) for path in record.empty_paths
    }


def _reviewer_render_view_chain_covers(
    records: list[CompletionReviewerEvidence],
    target: str,
) -> bool:
    for index, render_record in enumerate(records):
        if (
            render_record.kind != "command"
            or not render_record.command
            or len(_reviewer_command_segments(render_record.command)) != 1
        ):
            continue
        render_segments = [
            segment
            for bound_path, segment in render_record.path_commands
            if bound_path == target and _is_visual_render_command(segment)
        ]
        if not render_segments:
            continue
        outputs = [
            resource
            for resource in render_record.resource_paths
            if not _reviewer_resource_matches_workspace_path(resource, target)
        ]
        if not outputs:
            continue
        for view_record in records[index + 1 :]:
            if view_record.kind != "image_view" or not view_record.passed:
                continue
            if any(
                _render_output_matches_view(output, viewed)
                for output in outputs
                for viewed in view_record.resource_paths
            ):
                return True
    return False


def _reviewer_resource_matches_workspace_path(
    resource: str, workspace_path: str
) -> bool:
    normalized_resource = resource.replace("\\", "/").rstrip("/")
    normalized_path = _normalize_review_path(workspace_path)
    return normalized_resource == normalized_path or normalized_resource.endswith(
        f"/{normalized_path}"
    )


def _render_output_matches_view(output: str, viewed: str) -> bool:
    normalized_output = output.replace("\\", "/").rstrip("/")
    normalized_view = viewed.replace("\\", "/").rstrip("/")
    if not normalized_output or not normalized_view:
        return False
    if normalized_output == normalized_view:
        return True
    if normalized_view.startswith(normalized_output + "/"):
        return True
    if Path(normalized_output).suffix:
        return False
    if normalized_view.startswith(normalized_output):
        suffix = normalized_view[len(normalized_output) :]
        return bool(suffix and suffix[0] in {"-", "_", "."})
    return False


def _artifact_requires_visual_inspection(path: str, *, task_contents: str) -> bool:
    suffix = Path(path).suffix.lower()
    if suffix in {
        ".pdf",
        ".png",
        ".jpg",
        ".jpeg",
        ".webp",
        ".gif",
        ".tif",
        ".tiff",
        ".bmp",
        ".ico",
        ".avif",
        ".svg",
    }:
        return True
    if suffix in {".docx", ".pptx", ".odt", ".odp"}:
        return True
    return False


def _inspection_executable_and_args(command: str) -> tuple[str, list[str]] | None:
    try:
        tokens = _strip_env_command_prefix(shlex.split(command))
    except ValueError:
        return None
    if not tokens:
        return None
    executable = tokens[0].rsplit("/", 1)[-1].lower()
    return executable, tokens[1:]


def _command_arg_matches_review_path(token: str, path: str | None) -> bool:
    if not path:
        return False
    candidate = token.replace("\\", "/")
    target = _normalize_review_path(path)
    while candidate.startswith("./"):
        candidate = candidate[2:]
    return candidate == target or candidate.endswith(f"/{target}")


def _command_has_review_path_arg(args: list[str], path: str | None) -> bool:
    return any(_command_arg_matches_review_path(arg, path) for arg in args)


def _cat_input_args(args: list[str]) -> list[str]:
    safe_short = set("AbeEnstTuv")
    safe_long = {
        "--number",
        "--number-nonblank",
        "--show-all",
        "--show-ends",
        "--show-nonprinting",
        "--show-tabs",
        "--squeeze-blank",
    }
    inputs: list[str] = []
    options_done = False
    for arg in args:
        if not options_done and arg == "--":
            options_done = True
            continue
        if not options_done and arg.startswith("--"):
            if arg not in safe_long:
                return []
            continue
        if not options_done and arg.startswith("-") and arg != "-":
            if not set(arg[1:]) <= safe_short:
                return []
            continue
        inputs.append(arg)
    return inputs


def _nl_input_args(args: list[str]) -> list[str]:
    inputs: list[str] = []
    options_done = False
    for arg in args:
        if not options_done and arg == "--":
            options_done = True
            continue
        if not options_done and arg == "-ba":
            continue
        if not options_done and arg.startswith("-"):
            return []
        inputs.append(arg)
    return inputs


def _sed_input_args(args: list[str]) -> list[str]:
    """Return sed input files for a narrow, non-in-place command form."""

    inputs: list[str] = []
    expression_seen = False
    options_done = False
    index = 0
    value_free_options = {
        "-n",
        "--quiet",
        "--silent",
        "-E",
        "-r",
        "--regexp-extended",
        "-s",
        "--separate",
        "-u",
        "--unbuffered",
    }
    while index < len(args):
        arg = args[index]
        if not options_done and arg == "--":
            options_done = True
            index += 1
            continue
        if not options_done and arg in value_free_options:
            index += 1
            continue
        if not options_done and arg in {"-e", "--expression"}:
            if index + 1 >= len(args):
                return []
            expression_seen = True
            index += 2
            continue
        if not options_done and (
            arg.startswith("-e") and arg != "-e"
            or arg.startswith("--expression=")
        ):
            expression_seen = True
            index += 1
            continue
        if not options_done and (
            arg.startswith("-i")
            or arg.startswith("--in-place")
            or arg in {"-f", "--file"}
            or arg.startswith("--file=")
        ):
            return []
        if not options_done and arg.startswith("-"):
            return []
        if not expression_seen:
            expression_seen = True
        else:
            inputs.append(arg)
        index += 1
    return inputs if expression_seen else []


def _head_tail_reads_nonzero_content(
    args: list[str], *, path: str | None
) -> bool:
    """Reject zero-count modes that can emit only multi-file headers."""

    index = 0
    while index < len(args):
        arg = args[index]
        value: str | None = None
        if arg in {"-n", "--lines", "-c", "--bytes"}:
            if index + 1 >= len(args):
                return False
            value = args[index + 1]
            index += 2
        else:
            for prefix in ("-n", "-c", "--lines=", "--bytes="):
                if arg.startswith(prefix) and arg != prefix:
                    value = arg[len(prefix) :]
                    break
            if value is None and re.fullmatch(r"-0+", arg):
                value = arg[1:]
            index += 1
        if value is not None and re.fullmatch(
            r"[+-]?0+(?:[bBkKmMgGtTpPeEzZyY]|[kKmMgGtTpPeE][bB])?",
            value,
        ):
            return False
    return _command_has_review_path_arg(args, path)


def _grep_like_input_args(executable: str, args: list[str]) -> list[str]:
    """Return explicit grep/rg input paths for a narrow content-emitting form."""

    rejected_long = {
        "--count",
        "--count-matches",
        "--files",
        "--files-with-matches",
        "--files-without-match",
        "--json",
        "--quiet",
        "--stats",
        "--type-list",
    }
    allowed_long = {
        "--fixed-strings",
        "--hidden",
        "--ignore-case",
        "--line-number",
        "--line-regexp",
        "--multiline",
        "--no-filename",
        "--no-ignore",
        "--no-messages",
        "--perl-regexp",
        "--smart-case",
        "--with-filename",
        "--word-regexp",
    }
    allowed_short = set("nHhiswxiFEPGSU")
    rejected_short = set("lLcq")
    inputs: list[str] = []
    pattern_seen = False
    options_done = False
    index = 0
    while index < len(args):
        arg = args[index]
        if not options_done and arg == "--":
            options_done = True
            index += 1
            continue
        if not options_done and arg in {"-e", "--regexp"}:
            if index + 1 >= len(args):
                return []
            pattern_seen = True
            index += 2
            continue
        if not options_done and (
            arg.startswith("-e") and arg != "-e"
            or arg.startswith("--regexp=")
        ):
            pattern_seen = True
            index += 1
            continue
        if not options_done and arg in {
            "-A",
            "-B",
            "-C",
            "--after-context",
            "--before-context",
            "--context",
        }:
            if index + 1 >= len(args) or not args[index + 1].isdigit():
                return []
            index += 2
            continue
        if not options_done and (
            re.fullmatch(r"-[ABC]\d+", arg)
            or re.fullmatch(
                r"--(?:after-context|before-context|context)=\d+", arg
            )
        ):
            index += 1
            continue
        if not options_done and arg.startswith("--"):
            name = arg.split("=", 1)[0]
            if name in rejected_long or name not in allowed_long:
                return []
            index += 1
            continue
        if not options_done and arg.startswith("-") and arg != "-":
            flags = set(arg[1:])
            if flags & rejected_short or not flags <= allowed_short:
                return []
            index += 1
            continue
        if not pattern_seen:
            pattern_seen = True
        else:
            inputs.append(arg)
        index += 1
    # `rg` and grep both require a pattern; without an explicit input path they
    # may recurse or consume stdin, neither of which binds this evidence to a file.
    return inputs if pattern_seen else []


def _git_diff_content_form(
    command: str, args: list[str], *, path: str | None
) -> bool:
    try:
        raw_tokens = shlex.split(command)
    except ValueError:
        return False
    if any(
        token.upper().startswith(("GIT_EXTERNAL_DIFF=", "GIT_DIFF_OPTS="))
        for token in raw_tokens
    ):
        return False
    lowered = [arg.lower() for arg in args]
    rejected = {
        "--check",
        "--compact-summary",
        "--dirstat",
        "--name-only",
        "--name-status",
        "--no-patch",
        "--numstat",
        "--quiet",
        "--raw",
        "--shortstat",
        "--stat",
        "--summary",
        "--textconv",
        "--ext-diff",
        "-s",
    }
    if any(
        arg in rejected
        or any(
            arg.startswith(prefix)
            for prefix in (
                "--dirstat=",
                "--numstat=",
                "--output=",
                "--stat=",
            )
        )
        for arg in lowered
    ):
        return False
    if any("diff.external" in arg for arg in lowered):
        return False
    return (
        "diff" in lowered[:4]
        and "--" in args
        and any(
            _command_arg_matches_review_path(arg, path)
            for arg in args[args.index("--") + 1 :]
        )
    )


def _libreoffice_input_args(args: list[str]) -> list[str]:
    options_with_values = {"--convert-to", "--outdir", "--infilter"}
    flag_options = {"--headless", "--invisible", "--nodefault", "--nologo"}
    inputs: list[str] = []
    skip_next = False
    for arg in args:
        lowered = arg.lower()
        if skip_next:
            skip_next = False
            continue
        if lowered in options_with_values:
            skip_next = True
            continue
        if any(lowered.startswith(f"{option}=") for option in options_with_values):
            continue
        if lowered in flag_options:
            continue
        if arg.startswith("-"):
            return []
        inputs.append(arg)
    return [] if skip_next else inputs


def _unzip_archive_arg(args: list[str]) -> str | None:
    saw_pipe_output = False
    for arg in args:
        if arg.startswith("-") and arg != "-":
            option_chars = arg.lstrip("-")
            if not option_chars or not set(option_chars) <= set("pqcCLj"):
                return None
            saw_pipe_output = saw_pipe_output or "p" in option_chars
            continue
        return arg if saw_pipe_output else None
    return None


def _archive_listing_input_arg(executable: str, args: list[str]) -> str | None:
    if executable in {"unzip", "zipinfo"}:
        saw_listing = executable == "zipinfo"
        for arg in args:
            if arg.startswith("-") and arg != "-":
                option_chars = arg.lstrip("-")
                if not option_chars or not set(option_chars) <= set("ltvqcCLj"):
                    return None
                saw_listing = saw_listing or bool(set(option_chars) & set("ltv"))
                continue
            return arg if saw_listing else None
        return None
    if executable == "tar":
        saw_list = False
        expect_archive = False
        for arg in args:
            if expect_archive:
                return arg if saw_list else None
            option_chars = arg.lstrip("-") if arg.startswith("-") else arg
            if option_chars and set(option_chars) <= set("tfvzJj"):
                saw_list = saw_list or "t" in option_chars
                expect_archive = "f" in option_chars
                continue
            return None
        return None
    return None


def _gzip_input_arg(args: list[str]) -> str | None:
    saw_capable_mode = False
    for arg in args:
        if arg.startswith("-") and arg != "-":
            option_chars = arg.lstrip("-")
            if not option_chars or not set(option_chars) <= set("tcdqv"):
                return None
            saw_capable_mode = saw_capable_mode or bool(set(option_chars) & set("tcd"))
            continue
        return arg if saw_capable_mode else None
    return None


def _structured_data_cli_input_args(args: list[str]) -> list[str]:
    """Return jq/yq data-file positionals for a deliberately narrow safe form."""

    lowered = [arg.lower() for arg in args]
    banned_prefixes = (
        "--arg",
        "--from-file",
        "--jsonargs",
        "--null-input",
        "--rawfile",
        "--slurpfile",
    )
    if any(
        arg == "-n" or any(arg.startswith(prefix) for prefix in banned_prefixes)
        for arg in lowered
    ):
        return []
    value_free_options = {
        "-c",
        "--compact-output",
        "-e",
        "--exit-status",
        "-m",
        "--monochrome-output",
        "-r",
        "--raw-output",
        "-s",
        "--slurp",
        "-s",
        "--sort-keys",
    }
    positionals = [arg for arg in args if arg.lower() not in value_free_options]
    if any(arg.startswith("-") for arg in positionals):
        return []
    # The first positional is the filter/expression; only later positionals are
    # input documents.  Requiring it avoids `jq -n --arg ...`-style path decoys.
    return positionals[1:] if len(positionals) >= 2 else []


def _is_visual_render_command(command: str) -> bool:
    parsed = _inspection_executable_and_args(command)
    if parsed is None:
        return False
    executable, args = parsed
    lowered_args = [arg.lower() for arg in args]
    if any(arg in {"--help", "--version", "-h", "-v"} for arg in lowered_args):
        return False
    if executable in {"pdftoppm", "pdftocairo", "magick", "convert"}:
        return bool(args)
    if executable == "mutool":
        return bool(lowered_args) and lowered_args[0] == "draw"
    if executable in {"libreoffice", "soffice"}:
        return "--convert-to" in lowered_args
    renderer_names = {"render_docx", "render_pdf", "render_slides"}
    if Path(executable).stem in renderer_names:
        return True
    if executable.startswith("python"):
        script_names = {
            Path(arg).stem.lower()
            for arg in args
            if not arg.startswith("-") and Path(arg).suffix.lower() == ".py"
        }
        return bool(script_names & renderer_names)
    return False


def _is_capable_static_inspection_command(
    command: str, kind: str, *, path: str | None = None
) -> bool:
    parsed = _inspection_executable_and_args(command)
    if parsed is None:
        return False
    executable, args = parsed
    lowered_args = [arg.lower() for arg in args]
    if any(arg in {"--help", "--version", "-h", "-v"} for arg in lowered_args):
        return False
    has_target_arg = _command_has_review_path_arg(args, path)
    text_capable = kind in {"config", "docs", "source", "test"} or (
        kind == "unknown"
        and Path(path or "").suffix.lower()
        in {
            ".conf",
            ".csv",
            ".env",
            ".log",
            ".md",
            ".properties",
            ".rst",
            ".adoc",
            ".tex",
            ".txt",
            ".tsv",
            ".xml",
        }
    )
    if text_capable and executable == "cat":
        return any(
            _command_arg_matches_review_path(arg, path) for arg in _cat_input_args(args)
        )
    if text_capable and executable == "nl":
        return any(
            _command_arg_matches_review_path(arg, path) for arg in _nl_input_args(args)
        )
    if text_capable and executable == "sed":
        return any(
            _command_arg_matches_review_path(arg, path)
            for arg in _sed_input_args(args)
        )
    if text_capable and executable in {"head", "tail"}:
        return _head_tail_reads_nonzero_content(args, path=path)
    if text_capable and executable in {"grep", "egrep", "fgrep", "rg"}:
        return any(
            _command_arg_matches_review_path(arg, path)
            for arg in _grep_like_input_args(executable, args)
        )
    if (
        text_capable
        and executable == "git"
        and _git_diff_content_form(command, args, path=path)
    ):
        return True
    if kind == "config" and executable in {"jq", "yq"}:
        return any(
            _command_arg_matches_review_path(arg, path)
            for arg in _structured_data_cli_input_args(args)
        )
    if (
        kind == "config"
        and executable.startswith("python")
        and len(lowered_args) >= 2
        and lowered_args[:2] == ["-m", "json.tool"]
        and any(_command_arg_matches_review_path(arg, path) for arg in args[2:])
    ):
        return True
    if kind == "artifact":
        suffix = Path(path or "").suffix.lower()
        if suffix in {".xlsx", ".ods"}:
            if not has_target_arg:
                return False
            if executable == "xlsx2csv":
                # Only the stdout form is content evidence.  Converting to a
                # file (or a LibreOffice/ssconvert success log) must be followed
                # by a separately observed read of that derived output.
                return len(args) == 1 and _command_arg_matches_review_path(
                    args[0], path
                )
            if executable == "unzip":
                archive = _unzip_archive_arg(args)
                return archive is not None and _command_arg_matches_review_path(
                    archive, path
                )
            # Arbitrary inline Python is not accepted as mechanical workbook
            # evidence.  Merely naming a loader and the target is not enough to
            # prove that observed stdout was derived from that workbook.
            return False
        return (
            executable
            in {
                "pdftotext",
                "pdfinfo",
                "qpdf",
                "mutool",
                "identify",
            }
            and has_target_arg
        )
    if kind == "unknown":
        suffix = Path(path or "").suffix.lower()
        if suffix == ".zip":
            archive = _archive_listing_input_arg(executable, args)
            return archive is not None and _command_arg_matches_review_path(
                archive, path
            )
        if suffix == ".tar":
            archive = _archive_listing_input_arg(executable, args)
            return archive is not None and _command_arg_matches_review_path(
                archive, path
            )
        if suffix == ".gz" and executable in {"gzip", "gunzip"}:
            compressed = _gzip_input_arg(args)
            return compressed is not None and _command_arg_matches_review_path(
                compressed, path
            )
        if suffix == ".parquet" and executable in {
            "parquet-tools",
            "parquet_tools",
        }:
            return (
                bool(args)
                and args[0].lower() in {"cat", "head", "inspect", "schema"}
                and _command_arg_matches_review_path(args[-1], path)
            )
        if suffix == ".bundle" and executable == "file":
            return bool(args) and _command_arg_matches_review_path(args[-1], path)
    return False


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


def _accept_minimal_review_structure_issue(
    decision: CompletionReviewDecision,
) -> str | None:
    if decision.decision_artifact is None:
        return "decision_artifact is missing"
    if not decision.decision_artifact.current_state.strip():
        return "decision_artifact.current_state is empty"
    if not decision.reason.strip():
        return "completion decision reason is empty"
    if not decision.behavior_surface:
        return "behavior_surface is empty"
    if any(not item.category.strip() for item in decision.behavior_surface):
        return "behavior_surface contains an empty category"
    if not any(item.status == "required" for item in decision.behavior_surface):
        return "behavior_surface contains no required behavior"
    return None


def _accept_structural_issue(
    decision: CompletionReviewDecision,
    *,
    code_changing: bool,
    expected_surface_categories: tuple[str, ...] = (),
) -> str | None:
    minimal_issue = _accept_minimal_review_structure_issue(decision)
    if minimal_issue is not None:
        return minimal_issue
    surface_by_key: dict[str, str] = {}
    for item in decision.behavior_surface:
        category = item.category.strip()
        key = _normalized_surface_key(category)
        if key in surface_by_key:
            return f"behavior_surface repeats category: {category}"
        surface_by_key[key] = category
    missing_accumulated = [
        category.strip()
        for category in expected_surface_categories
        if _normalized_surface_key(category) not in surface_by_key
    ]
    if missing_accumulated:
        return "behavior_surface omitted accumulated categories: " + ", ".join(
            missing_accumulated[:5]
        )
    if code_changing and not decision.behavior_evidence_matrix:
        return "behavior_evidence_matrix is empty for a behavior-affecting change"
    if not decision.behavior_evidence_matrix:
        return None
    if code_changing:
        required_by_key = {
            _normalized_surface_key(item.category): item.category.strip()
            for item in decision.behavior_surface
            if item.status == "required"
        }
        row_counts: dict[str, int] = {}
        row_text_by_key: dict[str, str] = {}
        for row in decision.behavior_evidence_matrix:
            behavior = row.behavior.strip()
            key = _normalized_surface_key(behavior)
            row_counts[key] = row_counts.get(key, 0) + 1
            row_text_by_key[key] = behavior
        missing_rows = [
            category
            for key, category in required_by_key.items()
            if key not in row_counts
        ]
        duplicate_rows = [
            row_text_by_key[key] for key, count in row_counts.items() if count > 1
        ]
        extra_rows = [
            row_text_by_key[key] for key in row_counts if key not in required_by_key
        ]
        renamed_rows = [
            row_text_by_key[key]
            for key in row_counts.keys() & required_by_key.keys()
            if row_text_by_key[key] != required_by_key[key]
        ]
        if missing_rows:
            return (
                "behavior_evidence_matrix omits required behavior_surface categories: "
                + ", ".join(missing_rows[:5])
            )
        if duplicate_rows:
            return (
                "behavior_evidence_matrix repeats required behavior_surface categories: "
                + ", ".join(duplicate_rows[:5])
            )
        if extra_rows:
            return (
                "behavior_evidence_matrix contains rows outside required behavior_surface categories: "
                + ", ".join(extra_rows[:5])
            )
        if renamed_rows:
            return (
                "behavior_evidence_matrix row.behavior must exactly copy its behavior_surface.category: "
                + ", ".join(renamed_rows[:5])
            )
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
    covered_rows_with_gap = [
        row.behavior for row in decision.behavior_evidence_matrix if row.gap
    ]
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
        or (evidence.validation_type != "inspection" and not evidence.validation_id)
        or (evidence.validation_id and evidence.inspection_id)
    ]
    if missing_evidence_ids:
        return (
            "behavior_evidence_matrix has evidence with missing or ambiguous validation_id/inspection_id: "
            + ", ".join(missing_evidence_ids[:5])
        )
    if decision.uncovered_behaviors:
        return f"uncovered_behaviors is not empty: {', '.join(decision.uncovered_behaviors[:5])}"
    if decision.validation_gaps:
        return (
            f"validation_gaps is not empty: {', '.join(decision.validation_gaps[:5])}"
        )
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


def _accept_file_review_issue(
    decision: CompletionReviewDecision,
    files: list[ChangedFile],
    *,
    reviewer_evidence: list[CompletionReviewerEvidence] | None = None,
    workspace_state_id: str | None = None,
) -> str | None:
    reviewed_by_path = {
        _normalize_review_path(file.path): file for file in decision.files_reviewed
    }
    missing: list[str] = []
    limited: list[str] = []
    unaudited: list[str] = []
    for changed in files:
        reviewed = reviewed_by_path.get(_normalize_review_path(changed.path))
        if reviewed is None:
            missing.append(changed.path)
            continue
        if not reviewed.inspected:
            missing.append(changed.path)
            continue
        if reviewed.limitation:
            limited.append(f"{changed.path}: {reviewed.limitation}")
            continue
        if reviewer_evidence is not None and not _reviewer_evidence_covers_path(
            reviewer_evidence,
            changed.path,
            workspace_state_id=workspace_state_id,
        ):
            unaudited.append(changed.path)
    if missing:
        return f"changed source/test files were not reviewed: {', '.join(missing[:8])}"
    if limited:
        return "changed source/test review remains limited: " + "; ".join(
            limited[:5]
        )
    if unaudited:
        return (
            "changed source/test file was declared inspected without a successful "
            "reviewer-lane read on this workspace state: "
            + ", ".join(unaudited[:8])
        )
    return None


def _review_marks_non_material(file: Any) -> bool:
    text = " ".join(
        str(value or "")
        for value in (
            getattr(file, "reason", None),
            getattr(file, "limitation", None),
        )
    ).lower()
    return any(
        marker in text for marker in ("non-material", "not material", "immaterial")
    )


def _completion_return_has_evidence_related_gap(
    decision: CompletionReviewDecision,
) -> bool:
    if (
        decision.validation_gaps
        or decision.uncovered_behaviors
        or decision.claim_evidence_mismatches
    ):
        return True
    return any(
        row.status != "covered" or row.gap for row in decision.behavior_evidence_matrix
    )


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
        if (
            validation.sequence <= since_sequence
            or validation.validation_id not in validation_ids
        ):
            continue
        output = _bounded_text(
            " ".join((validation.captured_output or validation.summary).split()),
            limit=220,
        )
        details.append(
            (
                f"{validation.validation_id} seq={validation.sequence} type={validation.type} "
                f"command={_bounded_text(validation.command, limit=180)}"
                + (f" output={output}" if output else "")
            )
        )
    for inspection in packet.inspections:
        if (
            inspection.sequence <= since_sequence
            or inspection.inspection_id not in inspection_ids
        ):
            continue
        output = _bounded_text(
            " ".join((inspection.captured_output or inspection.summary).split()),
            limit=220,
        )
        details.append(
            (
                f"{inspection.inspection_id} seq={inspection.sequence} type=inspection "
                f"command={_bounded_text(inspection.command, limit=180)}"
                + (f" output={output}" if output else "")
            )
        )
    return details[:20]


def _previous_completion_return_summary(
    records: list[Any], *, generation: int
) -> list[str]:
    summaries: list[str] = []
    for record in records:
        if getattr(record, "generation", None) != generation:
            continue
        parts = [str(getattr(record, "reason", "") or "").strip()]
        for attr in (
            "uncovered_behaviors",
            "validation_gaps",
            "claim_evidence_mismatches",
        ):
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
    if (
        "auth" in text
        or "unauthorized" in text
        or "forbidden" in text
        or "api key" in text
    ):
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


def _unique_matching_validation(
    evidence: dict[str, Any], validations: list[ValidationRun]
) -> ValidationRun | None:
    command = str(evidence.get("command") or "")
    sequence = evidence.get("sequence")
    validation_type = evidence.get("validation_type")
    candidates: list[ValidationRun] = []
    for validation in validations:
        if isinstance(sequence, int) and validation.sequence != sequence:
            continue
        if (
            validation_type in {"static", "behavioral", "behavior_demo"}
            and validation.type != validation_type
        ):
            continue
        if command and _normalize_command(validation.command) != _normalize_command(
            command
        ):
            continue
        candidates.append(validation)
    return candidates[0] if len(candidates) == 1 else None


def _unique_matching_inspection(
    evidence: dict[str, Any], inspections: list[InspectionRun]
) -> InspectionRun | None:
    command = str(evidence.get("command") or "")
    sequence = evidence.get("sequence")
    candidates: list[InspectionRun] = []
    for inspection in inspections:
        if isinstance(sequence, int) and inspection.sequence != sequence:
            continue
        if command and _normalize_command(inspection.command) != _normalize_command(
            command
        ):
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


def _validation_is_fresh_behavioral_pass(
    validation: ValidationRun, latest_change: int
) -> bool:
    return (
        validation.type in {"behavioral", "behavior_demo"}
        and validation.outcome == "pass"
        and validation.passed
        and validation.trusted_validation_outcome == "passed"
        and _validation_is_after_change(validation, latest_change)
    )


def _validation_is_fresh_static_pass(
    validation: ValidationRun, latest_change: int
) -> bool:
    return (
        validation.type == "static"
        and validation.outcome == "pass"
        and validation.passed
        and validation.trusted_validation_outcome == "passed"
        and _validation_is_after_change(validation, latest_change)
    )


def _validation_is_after_change(
    validation: ValidationRun,
    latest_change: int,
) -> bool:
    return validation.sequence > latest_change or (
        validation.covers_same_action_mutations
        and validation.sequence == latest_change
    )


def _behavior_evidence_binding_issue(
    decision: CompletionReviewDecision,
    *,
    validations: list[ValidationRun],
    inspections: list[InspectionRun],
    latest_change: int | None,
    task_contents: str,
) -> str | None:
    validations_by_id = {
        validation.validation_id: validation for validation in validations
    }
    inspections_by_id = {
        inspection.inspection_id: inspection for inspection in inspections
    }
    for row in decision.behavior_evidence_matrix:
        if not row.evidence:
            return f"covered behavior row has no ledger-bound evidence: {row.behavior}"
        row_has_fresh_pass = False
        for evidence in row.evidence:
            if evidence.validation_type == "inspection":
                if not evidence.inspection_id or evidence.validation_id:
                    return f"inspection evidence has an ambiguous or missing id: {row.behavior}"
                inspection = inspections_by_id.get(evidence.inspection_id)
                if inspection is None:
                    return f"inspection evidence id is absent from the reviewed ledger: {evidence.inspection_id}"
                if _normalize_command(evidence.command) != _normalize_command(
                    inspection.command
                ):
                    return f"inspection evidence command does not match {evidence.inspection_id}"
                if evidence.sequence != inspection.sequence:
                    return f"inspection evidence sequence does not match {evidence.inspection_id}"
                actual_pass = _inspection_is_fresh_pass(inspection, latest_change)
                expected_outcome = (
                    "pass"
                    if inspection.outcome == "pass" and inspection.passed
                    else "fail"
                )
                if evidence.outcome != expected_outcome:
                    return f"inspection evidence outcome does not match {evidence.inspection_id}"
                expected_freshness = (
                    "fresh"
                    if latest_change is None or inspection.sequence > latest_change
                    else "stale"
                )
                if evidence.freshness != expected_freshness:
                    return f"inspection evidence freshness does not match {evidence.inspection_id}"
                if actual_pass and _row_allows_inspection_evidence(row):
                    row_has_fresh_pass = True
                continue

            if not evidence.validation_id or evidence.inspection_id:
                return f"validation evidence has an ambiguous or missing id: {row.behavior}"
            validation = validations_by_id.get(evidence.validation_id)
            if validation is None:
                return f"validation evidence id is absent from the reviewed ledger: {evidence.validation_id}"
            if evidence.validation_type != validation.type:
                return (
                    f"validation evidence type does not match {evidence.validation_id}"
                )
            if _normalize_command(evidence.command) != _normalize_command(
                validation.command
            ):
                return f"validation evidence command does not match {evidence.validation_id}"
            if evidence.sequence != validation.sequence:
                return f"validation evidence sequence does not match {evidence.validation_id}"
            actual_pass = _validation_is_fresh_pass(validation, latest_change)
            expected_outcome = (
                "pass"
                if validation.outcome == "pass"
                and validation.passed
                and validation.trusted_validation_outcome == "passed"
                else "fail"
            )
            if evidence.outcome != expected_outcome:
                return f"validation evidence outcome does not match {evidence.validation_id}"
            expected_freshness = (
                "fresh"
                if latest_change is None
                or _validation_is_after_change(validation, latest_change)
                else "stale"
            )
            if evidence.freshness != expected_freshness:
                return f"validation evidence freshness does not match {evidence.validation_id}"
            if actual_pass and (
                validation.type in {"behavioral", "behavior_demo"}
                or (
                    validation.type == "static"
                    and _task_is_intrinsically_static_contract(task_contents)
                    and _static_validation_matches_task_contract(
                        validation.command, task_contents
                    )
                )
            ):
                row_has_fresh_pass = True
        if not row_has_fresh_pass:
            return f"covered behavior row has no fresh passing task-appropriate evidence: {row.behavior}"
    return None


def _intrinsic_static_contract_kind(task_contents: str) -> str | None:
    lowered = task_contents.lower()
    runtime_signal = re.search(
        r"\b(?:api|behavior|cli|concurr|database|effect|execute|fallback|feature|"
        r"function|install|interaction|load|logic|migrat|network|persist|request|"
        r"response|restart|return|runtime|save|sequence|service|state|reload)\w*\b",
        lowered,
    )
    if runtime_signal is not None or re.search(
        r"\b(?:takes? effect|without restart|existing installs?)\b", lowered
    ):
        return None
    if re.search(
        r"\b(?:type[- ]?check|type errors?|typing|declaration file|type declarations?|"
        r"typescript interface|\.d\.ts)\b",
        lowered,
    ):
        return "type"
    if re.search(r"\b(?:lint|linting|format|formatting|formatter)\b", lowered):
        return "lint_format"
    if re.search(
        r"\b(?:fix|repair|restore|verify|make|ensure)\b[^.\n]{0,80}"
        r"\b(?:build|compile|compilation)\b|"
        r"\b(?:build|compile|compilation)\b[^.\n]{0,80}\b(?:pass|succeed|error|failure)\w*\b",
        lowered,
    ):
        return "build_compile"
    if re.search(r"\b(?:schema|configuration|config)\b", lowered) and re.search(
        r"\b(?:declaration|parseable|parser-valid|schema-valid|syntax|well-formed)\b",
        lowered,
    ):
        return "schema_syntax"
    return None


def _task_is_intrinsically_static_contract(task_contents: str) -> bool:
    return _intrinsic_static_contract_kind(task_contents) is not None


def _decision_has_fresh_static_contract_evidence(
    decision: CompletionReviewDecision,
    *,
    validations: list[ValidationRun],
    latest_change: int,
    task_contents: str,
) -> bool:
    rows = decision.behavior_evidence_matrix
    if not rows:
        return False
    contract_kind = _intrinsic_static_contract_kind(task_contents)
    if contract_kind is None:
        return False
    validations_by_id = {
        validation.validation_id: validation for validation in validations
    }
    for row in rows:
        description = f"{row.behavior} {row.task_basis}"
        if (
            row.status != "covered"
            or row.gap is not None
            or not _description_matches_static_contract_kind(description, contract_kind)
        ):
            return False
        row_has_fresh_static_pass = False
        for evidence in row.evidence:
            if evidence.validation_type != "static" or not evidence.validation_id:
                continue
            validation = validations_by_id.get(evidence.validation_id)
            if validation is None:
                continue
            if (
                validation.type == "static"
                and _validation_is_after_change(validation, latest_change)
                and validation.outcome == "pass"
                and validation.passed
                and validation.trusted_validation_outcome == "passed"
                and evidence.freshness == "fresh"
                and evidence.outcome == "pass"
                and evidence.sequence == validation.sequence
                and _normalize_command(evidence.command)
                == _normalize_command(validation.command)
                and _static_validation_matches_task_contract(
                    validation.command, task_contents
                )
            ):
                row_has_fresh_static_pass = True
                break
        if not row_has_fresh_static_pass:
            return False
    return True


def _static_validation_matches_task_contract(command: str, task_contents: str) -> bool:
    if _validation_no_execution_reason(command, validation_type="static") is not None:
        return False
    inner = _shell_command_payload(command)
    if inner is not None and inner != command:
        return _static_validation_matches_task_contract(inner, task_contents)
    parsed = _inspection_executable_and_args(command)
    if parsed is None:
        return False
    executable, args = parsed
    lowered_args = [arg.lower() for arg in args]
    runner, _runner_args = _npx_runner_and_args(executable, lowered_args)
    contract_kind = _intrinsic_static_contract_kind(task_contents)
    if contract_kind == "type":
        if runner in {"tsc", "mypy", "pyright", "flow"}:
            return True
        if executable.startswith("python"):
            return len(lowered_args) >= 2 and lowered_args[:2] in (
                ["-m", "mypy"],
                ["-m", "pyright"],
            )
        return executable in {"npm", "pnpm", "yarn"} and any(
            arg in {"typecheck", "type-check"} for arg in lowered_args[:3]
        )
    if contract_kind == "lint_format":
        if runner in {"ruff", "eslint", "prettier", "black"}:
            return True
        if executable.startswith("python"):
            return len(lowered_args) >= 2 and lowered_args[:2] in (
                ["-m", "ruff"],
                ["-m", "black"],
            )
        return executable in {"npm", "pnpm", "yarn"} and any(
            arg in {"lint", "format", "formatting"} for arg in lowered_args[:3]
        )
    if contract_kind == "schema_syntax":
        if executable in {"jq", "yq"}:
            return bool(_structured_data_cli_input_args(args))
        if executable == "ajv":
            return any(arg in {"-s", "--schema"} for arg in lowered_args)
        return (
            executable.startswith("python")
            and len(lowered_args) >= 2
            and (
                lowered_args[:2]
                in (
                    ["-m", "json.tool"],
                    ["-m", "check_jsonschema"],
                )
            )
        )
    if contract_kind == "build_compile":
        if runner == "tsc":
            return True
        if executable in {"npm", "pnpm", "yarn"}:
            return any(arg == "build" for arg in lowered_args[:3])
        if executable == "cargo":
            return _runner_subcommand(executable, lowered_args) in {"build", "check"}
        if executable == "go":
            return _runner_subcommand(executable, lowered_args) == "build"
        if executable in {"mvn", "mvnw"}:
            return _runner_subcommand(executable, lowered_args) in {
                "compile",
                "package",
            }
        if executable in {"gradle", "gradlew"}:
            return _runner_subcommand(executable, lowered_args) in {
                "assemble",
                "build",
            }
        if executable.startswith("python"):
            return len(lowered_args) >= 2 and lowered_args[:2] in (
                ["-m", "compileall"],
                ["-m", "py_compile"],
            )
        return False
    return False


def _description_matches_static_contract_kind(
    description: str, contract_kind: str
) -> bool:
    lowered = description.lower()
    if re.search(
        r"\b(?:behavior|effect|execute|fallback|interaction|load|migrat|persist|"
        r"reload|request|response|restart|return|runtime|save|state)\w*\b",
        lowered,
    ):
        return False
    terms_by_kind = {
        "type": r"\b(?:declaration|interface|type|types|typing)\b",
        "lint_format": r"\b(?:format|formatting|lint|linting)\b",
        "build_compile": r"\b(?:build|compile|compilation|compiler)\b",
        "schema_syntax": r"\b(?:config|configuration|declaration|schema|syntax|well-formed)\b",
    }
    pattern = terms_by_kind.get(contract_kind)
    return bool(pattern and re.search(pattern, lowered))


def _validation_is_fresh_pass(
    validation: ValidationRun, latest_change: int | None
) -> bool:
    if (
        validation.outcome != "pass"
        or not validation.passed
        or validation.trusted_validation_outcome != "passed"
    ):
        return False
    if latest_change is None:
        return True
    return _validation_is_after_change(validation, latest_change)


def _inspection_is_fresh_pass(
    inspection: InspectionRun, latest_change: int | None
) -> bool:
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
    return "inspection" in lowered and not any(
        marker in lowered for marker in behavior_markers
    )


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
    inspections_by_id = {
        inspection.inspection_id: inspection for inspection in inspections
    }
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
            type_mismatch = _evidence_type_mismatch(
                row.evidence, by_id, inspections_by_id
            )
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
        if (
            validation is None
            or evidence.validation_type != "behavior_demo"
            or validation.type != "behavior_demo"
        ):
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


def _looks_like_artifact_generator_evidence(
    *, behavior: str, command: str | None, evidence: Any
) -> bool:
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
    validations_by_id = {
        validation.validation_id: validation for validation in validations
    }
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
            executed_files = [
                _normalize_review_path(path) for path in validation.executed_test_files
            ]
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
        if _is_snapshot_path(changed.path) and changed.change_kind in {
            "modified",
            "renamed",
        }:
            add(changed.path, "modified snapshot/golden")
            continue
        if changed.change_kind in {"modified", "renamed"}:
            added_assertions = _substantive_added_test_assertion_lines(changed.diff)
            if added_assertions:
                add(
                    changed.path,
                    f"added substantive test assertion: {added_assertions[0]}",
                )

    diff_paths = {
        _normalize_review_path(changed.path) for changed in packet.changed_file_diffs
    }
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
        if isinstance(path, str) and _test_surface_matches_source_paths(
            path, source_paths
        ):
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


def _test_file_is_coder_authored_for_behavior(
    test_file: str, relevant_surfaces: list[dict[str, Any]]
) -> bool:
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
            if (
                len(left_token) >= 5
                and len(right_token) >= 5
                and (left_token in right_token or right_token in left_token)
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
    generic = {
        "test",
        "tests",
        "spec",
        "specs",
        "case",
        "cases",
        "snapshot",
        "snap",
        "golden",
        "goldens",
    }
    semantic_parts = [part for part in raw_parts if part not in generic]
    tokens = {_compact_identifier("".join(semantic_parts))} if semantic_parts else set()
    tokens.update(
        _compact_identifier(part) for part in semantic_parts if len(part) >= 2
    )
    if include_parent_for_generic and (
        not semantic_parts or semantic_parts in (["index"], ["main"])
    ):
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
    return re.sub(
        r"(?i)(?:^|[._-])(test|tests|spec|specs|case|cases|snapshot|snap|golden|goldens)$",
        "",
        stem,
    )


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
        validation_gaps.extend(
            _self_confirming_validation_gaps(details, fallback_reason=reason)
        )
        message_to_coder = _self_confirming_message_to_coder(
            details, fallback_reason=reason
        )
    elif (
        check_name == "evidence_binding"
        and details
        and str(details.get("kind") or "").startswith("behavior_demo_")
    ):
        validation_gaps.extend(
            _evidence_binding_validation_gaps(details, fallback_reason=reason)
        )
        message_to_coder = _evidence_binding_message_to_coder(
            details, fallback_reason=reason
        )
    elif check_name == "changed_test_masking":
        validation_gaps.append(
            f"Controller accept-gate rejection (changed_test_masking): {reason}"
        )
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
        validation_gaps.append(
            f"Controller accept-gate rejection ({check_name}): {reason}"
        )
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
    reason = str(
        context.get("reason")
        or "completion accept was rejected by deterministic accept gate"
    )
    if check_name == "self_confirming_test_evidence":
        details = (
            context.get("details") if isinstance(context.get("details"), dict) else {}
        )
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


def _evidence_binding_validation_gaps(
    details: dict[str, Any], *, fallback_reason: str
) -> list[str]:
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


def _evidence_binding_message_to_coder(
    details: dict[str, Any], *, fallback_reason: str
) -> str:
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


def _self_confirming_validation_gaps(
    details: dict[str, Any], *, fallback_reason: str
) -> list[str]:
    behaviors = details.get("behaviors")
    if not isinstance(behaviors, list) or not behaviors:
        return [
            f"Controller accept-gate rejection (self_confirming_test_evidence): {fallback_reason}"
        ]
    gaps: list[str] = []
    for behavior in behaviors:
        if not isinstance(behavior, dict):
            continue
        name = str(behavior.get("behavior") or "<unnamed behavior>")
        validation_ids = _validation_ids_from_self_confirming_behavior(behavior)
        files = _test_files_from_self_confirming_behavior(behavior)
        detail = f"behavior '{name}' lacks independent_evidence_binding"
        if validation_ids:
            detail += (
                f"; self-confirming validation_ids: {', '.join(validation_ids[:8])}"
            )
        if files:
            detail += f"; coder-authored/unknown-provenance test files: {', '.join(files[:8])}"
        gaps.append(detail)
    return gaps or [
        f"Controller accept-gate rejection (self_confirming_test_evidence): {fallback_reason}"
    ]


def _self_confirming_message_to_coder(
    details: dict[str, Any], *, fallback_reason: str
) -> str:
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


def _validation_ids_from_self_confirming_behavior(
    behavior: dict[str, Any],
) -> list[str]:
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


def _changed_test_contract_shift_risks(
    packet: SupervisorWakePacket, decision: CompletionReviewDecision
) -> list[str]:
    risks: list[str] = []
    for changed in packet.changed_file_diffs:
        if changed.file_kind != "test" or changed.change_kind not in {
            "modified",
            "renamed",
        }:
            continue
        removed_lines = _substantive_removed_test_lines(changed.diff)
        if not removed_lines:
            continue
        if _changed_test_reviewed_with_assessment(decision, changed.path):
            continue
        risks.append(
            f"{changed.path} removed/rewrote existing test behavior: {removed_lines[0]}"
        )
        if len(risks) >= 10:
            break
    return risks


def _changed_test_masking_issues(packet: SupervisorWakePacket) -> list[str]:
    issues: list[str] = []
    for changed in packet.changed_file_diffs:
        if changed.file_kind != "test" or changed.change_kind not in {
            "added",
            "modified",
            "renamed",
        }:
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
            issues.append(
                f"{changed.path}: removed assertion without meaningful replacement: {removed_assertions[0]}"
            )
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
            lines.append(
                (_bounded_text(line, limit=180), "added skipped/todo test marker")
            )
        elif _is_trivially_true_test_assertion(line):
            lines.append(
                (_bounded_text(line, limit=180), "added trivially true assertion")
            )
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


def _changed_test_reviewed_with_assessment(
    decision: CompletionReviewDecision, path: str
) -> bool:
    reviewed_by_path = {
        _normalize_review_path(file.path): file for file in decision.files_reviewed
    }
    reviewed = reviewed_by_path.get(_normalize_review_path(path))
    if reviewed is None or reviewed.kind != "test" or not reviewed.inspected:
        return False
    assessment = " ".join(
        part for part in (reviewed.reason, reviewed.limitation or "") if part
    ).strip()
    return bool(assessment)


def _unassessed_parallel_persistence_risks(
    packet: SupervisorWakePacket,
    decision: CompletionReviewDecision,
) -> list[str]:
    if _decision_explicitly_assesses_source_of_truth(decision):
        return []
    risks: list[str] = []
    for changed in packet.changed_file_diffs:
        if changed.file_kind != "source" or changed.change_kind not in {
            "modified",
            "added",
            "renamed",
        }:
            continue
        if not _source_diff_adds_parallel_persistent_state(changed.diff):
            continue
        risks.append(
            f"{changed.path} adds parallel persisted state without source-of-truth/legacy compatibility evidence"
        )
        if len(risks) >= 10:
            break
    return risks


def _decision_explicitly_assesses_source_of_truth(
    decision: CompletionReviewDecision,
) -> bool:
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
        if family in prior_or_context_keys
        and not keys.issubset(prior_or_context_keys[family])
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


def _persistent_key_families(
    diff: str, *, prefixes: tuple[str, ...]
) -> dict[str, set[str]]:
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
    if line.startswith(
        ("//", "/*", "*", "import ", "const assert", "const {", "let ", "var ")
    ):
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
        parts.append(
            "limitations=" + ", ".join(decision.packet_or_access_limitations[:5])
        )
    return "; ".join(part for part in parts if part)


def _behavior_evidence_summary(decision: Any) -> list[str]:
    if not isinstance(decision, CompletionReviewDecision):
        return []
    return [
        f"{row.status}: {row.behavior}"
        + (
            f" ({len(row.evidence)} evidence item{'s' if len(row.evidence) != 1 else ''})"
            if row.evidence
            else ""
        )
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
        if any(
            marker in lowered
            for marker in ("non-material", "not material", "immaterial")
        ):
            continue
        material.append(item)
    return material


def _normalize_review_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.rstrip("/")


def _is_conventionally_static_document_path(path: str) -> bool:
    """Identify text files whose conventional role is documentation.

    Text extensions alone are not enough: prompts, templates, fixtures, and other
    runtime resources commonly use Markdown or plain text.  Only paths with a
    mechanically strong documentation signal are safe to exclude from the
    behavioral product fingerprint.
    """

    normalized = _normalize_review_path(path).lower().strip("/")
    if not normalized:
        return False
    parts = normalized.split("/")
    name = parts[-1]
    if any(part in {"doc", "docs", "documentation"} for part in parts[:-1]):
        return True
    document_stem = name.split(".", 1)[0].replace("-", "_")
    return document_stem in {
        "authors",
        "changelog",
        "code_of_conduct",
        "contributing",
        "license",
        "notice",
        "readme",
        "security",
    }


@dataclass(frozen=True)
class _BoundedFileText:
    text: str
    truncated: bool


def _read_workspace_file(
    root: Path, path: str, *, limit: int
) -> _BoundedFileText | None:
    try:
        candidate = (root / path).resolve()
    except OSError:
        return None
    if not ensure_relative_to(candidate, root):
        return None
    descriptor: int | None = None
    try:
        descriptor = _open_regular_file_no_follow(candidate)
        byte_limit = max(4, (limit + 1) * 4)
        data = bytearray()
        while len(data) < byte_limit:
            chunk = os.read(descriptor, min(1024 * 1024, byte_limit - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        bytes_truncated = os.fstat(descriptor).st_size > len(data)
    except OSError:
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    raw = bytes(data).decode("utf-8", errors="replace")
    bounded = _bounded_text(raw, limit=limit)
    return _BoundedFileText(
        text=bounded, truncated=bytes_truncated or len(raw) > len(bounded)
    )


def _open_regular_file_no_follow(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(f"not a regular file: {path}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


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
        or re.search(
            r"(?:^|[._-])(test|tests|spec|specs|case|cases)(?:\.[^.]+)+$", name
        )
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
        or name
        in {".gitlab-ci.yml", ".travis.yml", "azure-pipelines.yml", "jenkinsfile"}
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
        # Runtime prompts and templates often use these same extensions.  Keep
        # the docs-only freshness optimization narrow and fail closed otherwise.
        return "docs" if _is_conventionally_static_document_path(path) else "unknown"
    if (
        name in {"makefile", "gnumakefile", "dockerfile", "containerfile"}
        or name.endswith(".mk")
        or lowered.endswith((".sh", ".bash", ".zsh", ".fish", ".sql"))
    ):
        return "source"
    if lowered.endswith(
        (
            ".pdf",
            ".png",
            ".jpg",
            ".jpeg",
            ".webp",
            ".gif",
            ".tif",
            ".tiff",
            ".bmp",
            ".ico",
            ".avif",
            ".svg",
            ".docx",
            ".xlsx",
            ".pptx",
            ".odt",
            ".ods",
            ".odp",
        )
    ):
        return "artifact"
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
            ".proto",
            ".graphql",
            ".gql",
        )
    ):
        return "source"
    return "unknown"


def _is_behavioral_changed_path(path: str) -> bool:
    return _file_kind(path) in {
        "source",
        "test",
        "config",
        "unknown",
    } and not _is_non_material_changed_path(path)


def _changed_file_is_behavior_affecting(
    file: ChangedFile, *, task_contents: str
) -> bool:
    if (
        _file_kind(file.path) in {"source", "test"}
        and _is_non_material_changed_path(file.path)
        and _changed_path_is_explicit_task_output(
            file.path, task_contents=task_contents
        )
    ):
        return not _generated_source_is_static_task_output(
            file.path, task_contents=task_contents
        )
    if not _is_behavioral_changed_path(file.path):
        return False
    if _is_static_web_deliverable_path(file.path, task_contents=task_contents):
        return False
    return not _unknown_path_is_static_task_output(
        file.path, task_contents=task_contents
    )


def _generated_source_is_static_task_output(path: str, *, task_contents: str) -> bool:
    suffix = Path(path).suffix.lower()
    if suffix not in {".css", ".scss"}:
        return False
    lowered = task_contents.lower()
    if re.search(
        r"\b(?:animat|click|hover|interact|javascript|runtime|script|toggle)\w*\b",
        lowered,
    ):
        return False
    return re.search(r"\b(?:css|layout|style|stylesheet)\b", lowered) is not None


def _is_relevant_changed_path(path: str, *, task_contents: str) -> bool:
    if _is_generated_or_cache_artifact_path(path, project_root=None):
        return False
    kind = _file_kind(path)
    if kind in {"source", "test", "config", "unknown"}:
        return True
    if _is_suspicious_changed_path(path):
        return True
    if kind == "docs":
        return _task_is_docs_facing(task_contents)
    if kind == "artifact":
        return _artifact_is_task_relevant(path, task_contents=task_contents)
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
    return any(
        token in lowered
        for token in (
            "documentation",
            "docs",
            "readme",
            ".md",
            "markdown",
            "docstring",
            "guide",
            "manual",
            "changelog",
        )
    )


def _changed_path_is_explicit_task_output(path: str, *, task_contents: str) -> bool:
    lowered_task = task_contents.lower().replace("\\", "/")
    normalized_path = _normalize_review_path(path).lower()
    name = normalized_path.rsplit("/", 1)[-1]
    if normalized_path and normalized_path in lowered_task:
        return True
    return bool(
        name and re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w.-])", lowered_task)
    )


def _unknown_path_is_static_task_output(path: str, *, task_contents: str) -> bool:
    """Recognize a narrow set of task-grounded data/package outputs.

    Unknown extensions remain behavior-affecting by default.  This exception exists
    only for formats whose ordinary role is a produced deliverable, avoiding the
    opposite error of treating an uncommon source language as a static artifact.
    """

    if _file_kind(path) != "unknown":
        return False
    suffix = Path(path).suffix.lower()
    if suffix not in {
        ".bundle",
        ".csv",
        ".gz",
        ".parquet",
        ".tar",
        ".tsv",
        ".xml",
        ".zip",
    }:
        return False
    lowered = task_contents.lower()
    runtime_signal = re.search(
        r"\b(?:execute|function|implement|interaction|logic|loader|plugin|runtime|script)\b",
        lowered,
    )
    if runtime_signal is not None:
        return False
    output_signal = re.search(
        r"\b(?:archive|artifact|bundle|data(?:set)?|deliverable|export|output|package|report|release)\b",
        lowered,
    )
    production_signal = re.search(
        r"\b(?:build|create|deliver|export|generate|produce|render|write)\b",
        lowered,
    )
    if _changed_path_is_explicit_task_output(path, task_contents=task_contents):
        return output_signal is not None and production_signal is not None
    return output_signal is not None and production_signal is not None


def _is_static_web_deliverable_path(path: str, *, task_contents: str) -> bool:
    suffix = Path(path).suffix.lower()
    if suffix not in {".html", ".htm", ".css", ".scss"}:
        return False
    lowered = task_contents.lower()
    explicit_static_signal = any(
        term in lowered
        for term in (
            "css-only",
            "css only",
            "html-only",
            "html only",
            "no javascript",
            "without javascript",
            "non-interactive",
            "noninteractive",
            "static page",
            "static site",
        )
    ) or (
        re.search(r"\bstatic\b", lowered) is not None
        and re.search(r"\b(?:css|html|landing|layout|page|site|website)\b", lowered)
        is not None
    )
    interaction_text = lowered
    for negated_phrase in (
        "non-interactive",
        "noninteractive",
        "no javascript",
        "without javascript",
    ):
        interaction_text = interaction_text.replace(negated_phrase, " ")
    interaction_signal = re.search(
        r"\b(?:animat|api|backend|button|carousel|click|details|dialog|disclosure|drag|dropdown|event|"
        r"expand|filter|focus|form|hover|input|interact|javascript|keyboard|menu|modal|summary|"
        r"navigat|open|press|request|response|runtime|script|search|select|sort|submit|"
        r"tab|toggle|tooltip|update)\w*\b",
        interaction_text,
    )
    return explicit_static_signal and interaction_signal is None


def _artifact_is_task_relevant(path: str, *, task_contents: str) -> bool:
    lowered_task = task_contents.lower().replace("\\", "/")
    normalized_path = path.lower().replace("\\", "/").lstrip("./")
    name = normalized_path.rsplit("/", 1)[-1]
    if normalized_path and normalized_path in lowered_task:
        return True
    if name and re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w.-])", lowered_task):
        return True
    suffix = Path(name).suffix
    family_terms: tuple[str, ...]
    if suffix == ".pdf":
        family_terms = ("pdf", "portable document")
    elif suffix == ".svg":
        family_terms = ("svg", "vector image", "vector graphic", "logo", "icon")
    elif suffix in {
        ".png",
        ".jpg",
        ".jpeg",
        ".webp",
        ".gif",
        ".tif",
        ".tiff",
        ".bmp",
        ".ico",
        ".avif",
    }:
        family_terms = (
            "image",
            "screenshot",
            "icon",
            "logo",
            "illustration",
            "graphic",
            "photo",
        )
    elif suffix in {".docx", ".odt"}:
        family_terms = ("docx", "word document", "office document")
    elif suffix in {".xlsx", ".ods"}:
        family_terms = ("xlsx", "spreadsheet", "workbook")
    elif suffix in {".pptx", ".odp"}:
        family_terms = ("pptx", "presentation", "slide deck", "slides")
    else:
        family_terms = ()
    return any(term in lowered_task for term in family_terms)


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
        current = (
            exclude_path.read_text(encoding="utf-8") if exclude_path.exists() else ""
        )
        entries = {line.strip() for line in current.splitlines()}
        additions = [
            entry for entry in (".supervisor/", ".supervisor") if entry not in entries
        ]
        if additions:
            suffix = "" if current.endswith("\n") or not current else "\n"
            exclude_path.write_text(
                current + suffix + "\n".join(additions) + "\n", encoding="utf-8"
            )
    except OSError:
        return


def _diff_line_counts(changed_files: list[ChangedFile]) -> tuple[int, int]:
    additions = sum(changed.additions or 0 for changed in changed_files)
    deletions = sum(changed.deletions or 0 for changed in changed_files)
    return additions, deletions


def _breadth_risk_summary(
    *, task_contents: str, changed_files: list[ChangedFile]
) -> BreadthRiskSummary:
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
    changed_source_files = [
        changed for changed in changed_files if _file_kind(changed.path) == "source"
    ]
    changed_lines = additions + deletions
    flags: list[str] = []
    if (
        len(task_contents) >= 2500
        or len(task_lines) >= 45
        or requirement_hint_count >= 10
        or len(feature_terms) >= 10
    ):
        flags.append("task_spec_appears_broad")
    if (
        len(changed_source_files) >= 4
        or changed_lines >= LARGE_DIFF_CHANGED_LINES_THRESHOLD
    ):
        flags.append("implementation_diff_is_broad")
    if len(feature_terms) >= 8:
        flags.append("many_task_feature_terms")
    suggested_min = 0
    if flags:
        suggested_min = 6
        if (
            len(task_contents) >= 6000
            or requirement_hint_count >= 18
            or len(feature_terms) >= 16
        ):
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
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return digest[:16]


def _suspicious_changed_file_signature(
    workspace_root: Path,
    changed_files: list[ChangedFile],
    *,
    cache: dict[str, tuple[tuple[Any, ...], str]] | None = None,
) -> str | None:
    suspicious = sorted(
        (
            changed
            for changed in changed_files
            if _is_suspicious_changed_path(changed.path)
        ),
        key=lambda item: item.path,
    )
    if not suspicious:
        return None
    cache = cache if cache is not None else {}
    payload = [
        {
            "path": changed.path,
            "status": changed.status,
            "additions": changed.additions,
            "deletions": changed.deletions,
            "content": _workspace_path_fingerprint(
                workspace_root, changed.path, cache=cache
            ),
        }
        for changed in suspicious
    ]
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]


def _workspace_path_fingerprint(
    workspace_root: Path,
    relative_path: str,
    *,
    cache: dict[str, tuple[tuple[Any, ...], str]],
) -> str:
    raw_path = Path(relative_path)
    if raw_path.is_absolute() or ".." in raw_path.parts:
        return "invalid-path"
    path = workspace_root / raw_path
    try:
        lexical_stat = path.lstat()
    except OSError as exc:
        cache.pop(relative_path, None)
        return f"unavailable:{type(exc).__name__}"
    if stat.S_ISLNK(lexical_stat.st_mode):
        try:
            target = os.readlink(path)
        except OSError as exc:
            target = f"unreadable:{type(exc).__name__}"
        cache.pop(relative_path, None)
        return (
            "symlink:"
            + hashlib.sha256(target.encode("utf-8", errors="replace")).hexdigest()
        )
    try:
        resolved = path.resolve()
    except OSError as exc:
        cache.pop(relative_path, None)
        return f"unresolved:{type(exc).__name__}"
    if not ensure_relative_to(resolved, workspace_root):
        cache.pop(relative_path, None)
        return "outside-workspace"
    try:
        file_stat = resolved.stat()
    except OSError as exc:
        cache.pop(relative_path, None)
        return f"unavailable:{type(exc).__name__}"
    stat_key = (
        file_stat.st_mode,
        file_stat.st_size,
        file_stat.st_mtime_ns,
        file_stat.st_ctime_ns,
        file_stat.st_ino,
    )
    cached = cache.get(relative_path)
    if cached is not None and cached[0] == stat_key:
        return cached[1]
    if not stat.S_ISREG(file_stat.st_mode):
        fingerprint = hashlib.sha256(repr(stat_key).encode("ascii")).hexdigest()
    else:
        try:
            digest = _hash_file(resolved)
            fingerprint = f"regular:{stat.S_IMODE(file_stat.st_mode):o}:{digest}"
        except OSError as exc:
            fingerprint = (
                f"unreadable:{stat.S_IMODE(file_stat.st_mode):o}:{type(exc).__name__}"
            )
    cache[relative_path] = (stat_key, fingerprint)
    return fingerprint


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


def _changed_tests_summary(
    path: str, text: str, validations: list[ValidationRun]
) -> ChangedTestsSummary:
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
        output_truncated=validation.summary.endswith("...<truncated>")
        or validation.captured_output_truncated,
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
        outcome = (
            "passed" if inspection.passed and inspection.outcome == "pass" else "failed"
        )
        items.append(
            (
                f"inspection {inspection.inspection_id} seq={inspection.sequence} "
                f"outcome={outcome} command={_bounded_text(inspection.command, limit=160)}"
            )
        )
    if not items:
        return [
            f"No validation or inspection records after return baseline sequence {since_sequence}."
        ]
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
        output_truncated=inspection.summary.endswith("...<truncated>")
        or inspection.captured_output_truncated,
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
    return list(dict.fromkeys(coder_authored_files)), list(
        dict.fromkeys(untouched_files)
    )


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
    executed_files = list(
        dict.fromkeys(
            _normalize_review_path(path)
            for path in validation.executed_test_files
            if path
        )
    )
    coder_authored_files, untouched_files = _partition_executed_test_files(
        executed_files,
        changed_test_identities=_changed_test_file_identity_map(changed_test_files),
    )
    captured_output = validation.captured_output or ""
    captured_output_present = bool(captured_output.strip())
    fresh = (
        None
        if latest_change_sequence is None
        else _validation_is_after_change(validation, latest_change_sequence)
    )
    output_kind = _validation_output_kind(
        validation, captured_output_present=captured_output_present
    )
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
        if (
            validation.executed_test_files
            or validation.passed_count is not None
            or validation.failed_count is not None
        ):
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
    if (
        validation.outcome != "pass"
        or not validation.passed
        or validation.trusted_validation_outcome != "passed"
    ):
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
        if coder_authored_test_files and len(coder_authored_test_files) == len(
            executed_test_files
        ):
            risk_reasons.append("all_output_identified_tests_were_coder_authored")
            return "self_confirming", risk_reasons
        risk_reasons.append("unknown_test_file_provenance")
        return "unknown", risk_reasons
    return "unknown", risk_reasons


def _captured_output_is_self_verdict_only(output: str) -> bool:
    lines = [
        line.strip().strip(".!").lower() for line in output.splitlines() if line.strip()
    ]
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
        if any(
            token in lowered
            for token in (
                "assert",
                "expect(",
                ".should",
                "equal",
                "strictEqual".lower(),
            )
        ):
            snippets.append(_bounded_text(stripped, limit=240))
            if len(snippets) >= limit:
                break
    return snippets


def _target_files_or_test_files(command: str) -> list[str]:
    targets: list[str] = []
    for match in re.finditer(
        r"(?<![\w./-])(?:\.?/)?[\w./-]+\.(?:py|js|jsx|ts|tsx|mjs|cjs|rb|go|rs|java|cs|php)(?![\w.-])",
        command,
    ):
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
    common_target_dirs = {
        "src",
        "lib",
        "app",
        "tests",
        "test",
        "include",
        "public",
        "packages",
        "pkg",
    }
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token in option_value_flags:
            skip_next = True
            continue
        stripped = token.strip("'\"")
        while stripped.startswith("./"):
            stripped = stripped[2:]
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
    command_actions = item.get("commandActions")
    if isinstance(command_actions, list):
        for action in command_actions:
            if not isinstance(action, dict):
                continue
            for key in ("path", "filePath", "file_path", "filepath"):
                value = action.get(key)
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


def _patch_summary_from_approval_context(
    context: ApprovalContext, limit: int = 4000
) -> str | None:
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
    descriptor = _open_regular_file_no_follow(path)
    digest = hashlib.sha256()
    try:
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _schema_file_exists(out_dir: Path, name: str) -> bool:
    return (out_dir / name).exists() or (out_dir / "v2" / name).exists()


def _turn_start_schema_supports_effort(out_dir: Path) -> bool:
    for path in (
        out_dir / "TurnStartParams.json",
        out_dir / "v2" / "TurnStartParams.json",
    ):
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
        completed = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return completed.returncode == 0, (completed.stdout + completed.stderr).strip()


def _resolve_controller_models(
    *,
    model: str | None,
    coder_model: str | None,
    supervisor_model: str | None,
    runtime_model: str | None,
    completion_model: str | None,
    adversary_model: str | None,
) -> tuple[str, str, str, str]:
    if model and (coder_model or supervisor_model or runtime_model or completion_model):
        raise RuntimeError(
            "model cannot be combined with coder_model, supervisor_model, runtime_model, or completion_model"
        )
    if supervisor_model and (runtime_model or completion_model):
        raise RuntimeError(
            "supervisor_model cannot be combined with runtime_model or completion_model"
        )
    if model:
        return model, model, model, adversary_model or DEFAULT_MODEL
    legacy_supervisor_model = supervisor_model or DEFAULT_MODEL
    return (
        coder_model or DEFAULT_MODEL,
        runtime_model or legacy_supervisor_model,
        completion_model or legacy_supervisor_model,
        adversary_model or DEFAULT_MODEL,
    )


def _shared_primary_model(config: ProjectConfig) -> str | None:
    models = {config.coder_mod, config.runtime_mod, config.completion_mod}
    return config.coder_mod if len(models) == 1 else None


def _selected_model_availability(
    models_response: dict[str, Any],
    *,
    coder_model: str | None,
    runtime_model: str | None,
    completion_model: str | None,
    adversary_model: str | None = None,
) -> ModelAvailabilityResult:
    available_models = tuple(sorted(_extract_model_ids(models_response)))
    available = set(available_models)
    missing: list[str] = []
    if coder_model and coder_model not in available:
        missing.append(f"coder={coder_model}")
    if runtime_model and runtime_model not in available:
        missing.append(f"runtime={runtime_model}")
    if completion_model and completion_model not in available:
        missing.append(f"completion={completion_model}")
    if adversary_model and adversary_model not in available:
        missing.append(f"adversary={adversary_model}")
    return ModelAvailabilityResult(
        missing_roles=tuple(missing), available_models=available_models
    )


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
        return value.get("type") == "readOnly" and value.get("networkAccess") is False
    return False


def _sandbox_matches_mode(
    value: Any, mode: str, *, workspace_root: Path | None = None
) -> bool:
    if mode == CODER_SANDBOX_DANGER_FULL_ACCESS:
        if value == "danger-full-access":
            return True
        if isinstance(value, dict):
            return value.get("type") == "dangerFullAccess"
        return False
    if mode == CODER_SANDBOX_WORKSPACE_WRITE:
        if not isinstance(value, dict) or value.get("type") != "workspaceWrite":
            return False
        if value.get("networkAccess") is not False:
            return False
        roots = value.get("writableRoots")
        if not isinstance(roots, list) or any(
            not isinstance(root, str) for root in roots
        ):
            return False
        if workspace_root is None:
            return not roots
        expected = workspace_root.resolve()
        for raw in roots:
            try:
                if Path(raw).expanduser().resolve(strict=False) != expected:
                    return False
            except OSError:
                return False
        return True
    return _sandbox_is_read_only(value)


def _approval_resolution_is_denial(decision: str | dict[str, Any]) -> bool:
    return isinstance(decision, str) and decision in {
        "decline",
        "cancel",
        "denied",
        "abort",
    }


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
        if not _is_ignored_changed_path(
            changed.path, project_root=project_root, task_path=task_path
        )
    ][:200]


def _path_from_git_status_line(line: str) -> str:
    if len(line) > 2 and line[2] == " ":
        return line[3:].strip()
    if len(line) > 2:
        return line[2:].strip()
    return line.strip()


def _git_status_entries_from_porcelain_v1_z(output: str) -> list[tuple[str, str]]:
    records = output.split("\0")
    entries: list[tuple[str, str]] = []
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record or len(record) < 4 or record[2] != " ":
            continue
        raw_status = record[:2]
        path = record[3:]
        if path:
            entries.append((path, raw_status.strip() or "modified"))
        if "R" in raw_status or "C" in raw_status:
            # In -z mode Git emits the destination in this record and the
            # source path as the following NUL-delimited record.
            index += 1
    return entries


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


def _format_bool(value: bool) -> str:
    return "true" if value else "false"


def _is_internal_runtime_path(
    path: str, *, project_root: Path | None, task_path: Path | str | None
) -> bool:
    normalized = _normalize_internal_workspace_path(str(path).strip().strip("'\""))
    if not normalized:
        return False
    if normalized == ".git-init.log":
        return True
    if normalized == ".supervisor" or normalized.startswith(".supervisor/"):
        return True
    task_relative = _task_relative_workspace_path(
        project_root=project_root, task_path=task_path
    )
    return bool(task_relative and normalized == task_relative)


def _is_ignored_changed_path(
    path: str, *, project_root: Path | None, task_path: Path | str | None
) -> bool:
    return _is_internal_runtime_path(
        path,
        project_root=project_root,
        task_path=task_path,
    ) or _is_generated_or_cache_artifact_path(path, project_root=project_root)


def _is_generated_or_cache_artifact_path(
    path: str, *, project_root: Path | None
) -> bool:
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
        ".parcel-cache",
        "node_modules",
    }:
        return True
    name = normalized.rsplit("/", 1)[-1].lower()
    if name.endswith(
        (
            ".pyc",
            ".pyo",
            ".gcda",
            ".gcno",
            ".tsbuildinfo",
        )
    ):
        return True
    return False


def _task_relative_workspace_path(
    *, project_root: Path | None, task_path: Path | str | None
) -> str | None:
    if task_path is None:
        return None
    task = Path(task_path)
    if project_root is not None:
        try:
            task = task.resolve()
            return _normalize_internal_workspace_path(
                str(task.relative_to(Path(project_root).resolve()))
            )
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
            if not _is_ignored_changed_path(
                line.strip(), project_root=project_root, task_path=task_path
            )
        ]
        return "\n".join(lines)
    if command[:2] == ["git", "diff"] and "--stat" in command:
        lines: list[str] = []
        for line in output.splitlines():
            if "|" not in line:
                continue
            path = line.split("|", 1)[0].strip()
            if not _is_ignored_changed_path(
                path, project_root=project_root, task_path=task_path
            ):
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
        return (
            f"command completed: {item.get('command', '')} exit={item.get('exitCode')}"
        )
    if item_type == "fileChange":
        return f"file change completed: {len(item.get('changes') or [])} changes"
    if item_type == "mcpToolCall":
        return f"mcp tool completed: {item.get('server')}/{item.get('tool')}"
    if item_type == "dynamicToolCall":
        return f"dynamic tool completed: {item.get('tool')}"
    if item_type == "agentMessage":
        return "agent message completed"
    return f"{item_type} completed"


def _completion_reviewer_evidence_from_item(
    item: dict[str, Any],
    *,
    workspace_state_id: str,
    workspace_root: Path,
) -> CompletionReviewerEvidence | None:
    item_type = item.get("type")
    if item_type == "commandExecution":
        command = item.get("command")
        if not isinstance(command, str) or not command.strip():
            return None
        command_output = _command_output_from_item(item)
        raw_patch_paths = _paths_from_git_patch_output(command, command_output)
        explicit_paths = list(_paths_from_item(item))
        explicit_paths.extend(
            _paths_from_git_diff_output(command, command_output)
        )
        command_segments = _reviewer_command_segments(command)
        command_paths = [
            path
            for segment in command_segments
            for path in _inspected_paths_from_command(segment)
        ]
        paths = [*explicit_paths, *command_paths]
        cwd = item.get("cwd") if isinstance(item.get("cwd"), str) else None
        canonical_paths = [
            canonical
            for path in paths
            if (
                canonical := _canonical_reviewer_evidence_path(
                    path, workspace_root=workspace_root, cwd=cwd
                )
            )
            is not None
        ]
        canonical_patch_paths = [
            canonical
            for path in raw_patch_paths
            if (
                canonical := _canonical_reviewer_evidence_path(
                    path, workspace_root=workspace_root, cwd=cwd
                )
            )
            is not None
        ]
        path_commands: list[tuple[str, str]] = []
        for segment in command_segments:
            for path in _inspected_paths_from_command(segment):
                canonical = _canonical_reviewer_evidence_path(
                    path,
                    workspace_root=workspace_root,
                    cwd=cwd,
                )
                if canonical is not None:
                    path_commands.append((canonical, segment))
        if len(command_segments) == 1:
            for path in explicit_paths:
                canonical = _canonical_reviewer_evidence_path(
                    path,
                    workspace_root=workspace_root,
                    cwd=cwd,
                )
                if canonical is not None:
                    path_commands.append((canonical, command_segments[0]))
        resource_paths = [
            resource
            for path in paths
            if (
                resource := _reviewer_resource_path(
                    path,
                    workspace_root=workspace_root,
                    cwd=cwd,
                )
            )
            is not None
        ]
        exit_code = item.get("exitCode")
        observed_output = bool(command_output.strip())
        empty_paths: list[str] = []
        for canonical in dict.fromkeys(canonical_paths):
            if canonical == ".":
                continue
            try:
                metadata = (workspace_root / canonical).stat()
            except OSError:
                continue
            if stat.S_ISREG(metadata.st_mode) and metadata.st_size == 0:
                empty_paths.append(canonical)
        return CompletionReviewerEvidence(
            workspace_state_id=workspace_state_id,
            kind="command",
            command=command,
            paths=tuple(dict.fromkeys(canonical_paths)),
            passed=isinstance(exit_code, int) and exit_code == 0,
            summary=_bounded_text(
                _validation_summary(
                    _item_summary(item), command_output
                ),
                limit=2000,
            ),
            path_commands=tuple(dict.fromkeys(path_commands)),
            resource_paths=tuple(dict.fromkeys(resource_paths)),
            observed_output=observed_output,
            empty_paths=tuple(empty_paths),
            patch_paths=tuple(dict.fromkeys(canonical_patch_paths)),
        )
    if item_type == "imageView":
        raw_paths = list(_paths_from_item(item))
        for key in ("path", "filePath", "file_path"):
            value = item.get(key)
            if isinstance(value, str):
                raw_paths.append(value)
        canonical_paths = [
            canonical
            for path in raw_paths
            if (
                canonical := _canonical_reviewer_evidence_path(
                    path,
                    workspace_root=workspace_root,
                    cwd=None,
                )
            )
            is not None
        ]
        resource_paths = [
            resource
            for path in raw_paths
            if (
                resource := _reviewer_resource_path(
                    path,
                    workspace_root=workspace_root,
                    cwd=None,
                )
            )
            is not None
        ]
        status = str(item.get("status") or "completed").lower()
        return CompletionReviewerEvidence(
            workspace_state_id=workspace_state_id,
            kind="image_view",
            command=None,
            paths=tuple(dict.fromkeys(canonical_paths)),
            passed=status not in {"failed", "error", "cancelled"},
            summary=_bounded_text(_item_summary(item), limit=500),
            resource_paths=tuple(dict.fromkeys(resource_paths)),
            observed_output=True,
        )
    return None


def _paths_from_git_diff_output(command: str, output: str) -> list[str]:
    if not output:
        return []
    segments = _reviewer_command_segments(command)
    if not any(re.search(r"(?:^|\s)git\s+(?:\S+\s+)*diff(?:\s|$)", segment) for segment in segments):
        return []
    paths: list[str] = []
    for line in output.splitlines():
        candidates: list[str] = []
        if line.startswith("diff --git "):
            try:
                fields = shlex.split(line)
            except ValueError:
                fields = line.split()
            if len(fields) >= 4:
                candidates.extend(fields[-2:])
        elif line.startswith(("--- ", "+++ ")):
            candidates.append(line[4:].split("\t", 1)[0])
        for candidate in candidates:
            candidate = candidate.strip("'\"")
            if candidate == "/dev/null":
                continue
            if candidate.startswith(("a/", "b/")):
                candidate = candidate[2:]
            if candidate:
                paths.append(candidate)
    return list(dict.fromkeys(paths))


def _paths_from_git_patch_output(command: str, output: str) -> list[str]:
    """Paths whose unified patch content, not only metadata, was displayed."""

    if not output:
        return []
    segments = _reviewer_command_segments(command)
    if not any(
        re.search(r"(?:^|\s)git\s+(?:\S+\s+)*diff(?:\s|$)", segment)
        for segment in segments
    ):
        return []
    paths: list[str] = []
    for line in output.splitlines():
        if not line.startswith(("--- ", "+++ ")):
            continue
        candidate = line[4:].split("\t", 1)[0].strip("'\"")
        if candidate == "/dev/null":
            continue
        if candidate.startswith(("a/", "b/")):
            candidate = candidate[2:]
        if candidate:
            paths.append(candidate)
    return list(dict.fromkeys(paths))


def _canonical_reviewer_evidence_path(
    raw_path: str,
    *,
    workspace_root: Path,
    cwd: str | None,
) -> str | None:
    value = _unquote_path_value(raw_path)
    if not value or value.startswith("~"):
        return None
    root = workspace_root.resolve()
    path = Path(value)
    try:
        if path.is_absolute():
            candidate = path.resolve(strict=False)
        else:
            base = root
            if cwd:
                cwd_path = Path(cwd)
                base = (
                    cwd_path.resolve(strict=False)
                    if cwd_path.is_absolute()
                    else (root / cwd_path).resolve(strict=False)
                )
                if not ensure_relative_to(base, root):
                    return None
            candidate = (base / path).resolve(strict=False)
    except OSError:
        return None
    if not ensure_relative_to(candidate, root):
        return None
    relative = candidate.relative_to(root).as_posix()
    return relative or "."


def _reviewer_command_segments(command: str) -> list[str]:
    payload = _shell_command_payload(command)
    candidate = payload if payload is not None else command
    segments = _inspection_command_segments(candidate)
    if not segments:
        return []
    return [shlex.join(segment) for segment in segments]


def _reviewer_resource_path(
    raw_path: str,
    *,
    workspace_root: Path,
    cwd: str | None,
) -> str | None:
    value = _unquote_path_value(raw_path)
    if not value or value.startswith("~"):
        return None
    root = workspace_root.resolve()
    path = Path(value)
    try:
        if path.is_absolute():
            candidate = path.resolve(strict=False)
        else:
            base = root
            if cwd:
                cwd_path = Path(cwd)
                base = (
                    cwd_path.resolve(strict=False)
                    if cwd_path.is_absolute()
                    else (root / cwd_path).resolve(strict=False)
                )
            candidate = (base / path).resolve(strict=False)
    except OSError:
        return None
    return candidate.as_posix()


def _unquote_path_value(value: str) -> str:
    if len(value) >= 2 and value[0] in {"'", '"'} and value[-1] == value[0]:
        return value[1:-1]
    return value


def _is_completed_action(item: Any) -> bool:
    return isinstance(item, dict) and item.get("type") in {
        "commandExecution",
        "fileChange",
        "mcpToolCall",
        "dynamicToolCall",
        "webSearch",
    }


def _adversary_enabled_from_env() -> bool | None:
    raw = os.environ.get("BELLO_ADVERSARY_ENABLED", "").strip().lower()
    if not raw:
        return None
    if raw in {"1", "true", "yes", "on", "enabled"}:
        return True
    if raw in {"0", "false", "no", "off", "disabled"}:
        return False
    return None


def _configured_capability_inventory(
    response: dict[str, Any],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    config = response.get("config")
    if not isinstance(config, dict):
        return (), ()
    mcp_servers = config.get("mcp_servers")
    plugins = config.get("plugins")
    mcp_names = (
        tuple(
            sorted(
                name.strip()
                for name in mcp_servers
                if isinstance(name, str) and name.strip()
            )
        )
        if isinstance(mcp_servers, dict)
        else ()
    )
    plugin_names = (
        tuple(
            sorted(
                name.strip()
                for name in plugins
                if isinstance(name, str) and name.strip()
            )
        )
        if isinstance(plugins, dict)
        else ()
    )
    return mcp_names, plugin_names


def _is_unsupported_appserver_method_error(error: AppServerError) -> bool:
    # AppServerClient preserves the JSON-RPC error mapping in the exception
    # string.  Only the standard endpoint-missing code is safe to downgrade;
    # config/parser failures can legitimately contain phrases such as
    # "unknown method" and must remain fatal.
    return re.search(r"(?<!\d)-32601(?!\d)", str(error)) is not None


def _approved_adversary_dependency_mounts(
    snapshot: WorkspaceSnapshot,
    *,
    active_workspace_root: Path,
) -> tuple[_AdversaryReadonlyDependencyMount, ...]:
    if active_workspace_root.resolve() != snapshot.snapshot_root.resolve():
        raise ValueError("coder snapshot metadata does not match the active workspace")
    original_root = snapshot.original_root.resolve()
    grading_roots: list[Path] = []
    for raw in snapshot.declared_grading_roots:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = original_root / path
        grading_roots.append(path.resolve(strict=False))
    mounts: list[_AdversaryReadonlyDependencyMount] = []
    for raw_relative in snapshot.readonly_dependency_paths:
        relative = Path(raw_relative)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError(f"invalid coder dependency mount path: {raw_relative}")
        if relative.name not in SNAPSHOT_READ_ONLY_DEPENDENCY_NAMES:
            raise ValueError(f"unapproved coder dependency mount path: {raw_relative}")
        target = (original_root / relative).resolve(strict=True)
        if not target.is_dir() or not ensure_relative_to(target, original_root):
            raise ValueError(
                f"coder dependency mount target escapes the original workspace: {raw_relative}"
            )
        target_relative = target.relative_to(original_root)
        if target_relative.parts and target_relative.parts[0] == ".supervisor":
            raise ValueError(f"coder dependency mount targets private runtime: {raw_relative}")
        if any(
            ensure_relative_to(target, grading_root)
            or ensure_relative_to(grading_root, target)
            for grading_root in grading_roots
        ):
            raise ValueError(f"coder dependency mount overlaps grading material: {raw_relative}")
        mounts.append(
            _AdversaryReadonlyDependencyMount(
                relative_path=relative.as_posix(),
                target=target,
            )
        )
    return tuple(mounts)


def _create_adversary_snapshot(
    project_root: Path,
    *,
    task_relative_path: str | None = None,
    task_contents: str | None = None,
    approved_readonly_dependency_mounts: tuple[
        _AdversaryReadonlyDependencyMount, ...
    ] = (),
) -> Path:
    original_root = project_root.resolve()
    temp_root = Path(tempfile.mkdtemp(prefix="bello-adversary-")).resolve()
    snapshot_root = temp_root / "workspace"
    try:
        shutil.copytree(
            original_root,
            snapshot_root,
            symlinks=True,
            ignore=_adversary_snapshot_ignore,
        )
        # copytree preserves symlinks.  Rewrite links whose targets are inside the
        # submitted workspace and drop links that would escape back to the canonical
        # workspace or elsewhere on the host before any adversary process starts.
        _sanitize_copied_workspace_symlinks(original_root, snapshot_root)
        _remove_adversary_private_symlinks(snapshot_root)
        if task_relative_path is not None:
            relative_task = Path(task_relative_path)
            if relative_task.is_absolute() or ".." in relative_task.parts:
                raise ValueError("adversary task path must stay inside the snapshot")
            if task_contents is None:
                raise ValueError("adversary task contents are required with a task path")
            snapshot_task = snapshot_root / relative_task
            if snapshot_task.is_symlink() or snapshot_task.is_file():
                snapshot_task.unlink()
            elif snapshot_task.exists():
                raise ValueError("adversary task path is not a regular file")
            snapshot_task.parent.mkdir(parents=True, exist_ok=True)
            snapshot_task.write_text(task_contents, encoding="utf-8")
        _install_adversary_readonly_dependency_mounts(
            snapshot_root,
            approved_readonly_dependency_mounts,
        )
        _assert_adversary_snapshot_symlink_boundary(
            snapshot_root,
            approved_readonly_dependency_mounts=approved_readonly_dependency_mounts,
        )
    except Exception:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise
    _init_snapshot_git(snapshot_root)
    return snapshot_root


def _install_adversary_readonly_dependency_mounts(
    snapshot_root: Path,
    mounts: tuple[_AdversaryReadonlyDependencyMount, ...],
) -> None:
    root = snapshot_root.resolve()
    for mount in mounts:
        relative = Path(mount.relative_path)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError(f"invalid adversary dependency mount path: {mount.relative_path}")
        if relative.name not in SNAPSHOT_READ_ONLY_DEPENDENCY_NAMES:
            raise ValueError(f"unapproved adversary dependency mount path: {mount.relative_path}")
        destination = root / relative
        current = root
        for part in relative.parts[:-1]:
            current /= part
            if current.is_symlink():
                raise ValueError(
                    f"adversary dependency mount parent is a symlink: {mount.relative_path}"
                )
        parent = destination.parent.resolve(strict=True)
        if not ensure_relative_to(parent, root):
            raise ValueError(f"adversary dependency mount escapes snapshot: {mount.relative_path}")
        target = mount.target.resolve(strict=True)
        if not target.is_dir():
            raise ValueError(f"adversary dependency target is not a directory: {mount.relative_path}")
        if destination.is_symlink() or destination.is_file():
            destination.unlink()
        elif destination.exists():
            shutil.rmtree(destination)
        destination.symlink_to(target, target_is_directory=True)


def _remove_adversary_private_symlinks(snapshot_root: Path) -> None:
    """Remove links into runtime history even when their targets were excluded."""

    root = snapshot_root.resolve()
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        retained_dirs: list[str] = []
        for name in dirs:
            candidate = Path(current) / name
            if _adversary_symlink_targets_private_runtime(candidate, root):
                candidate.unlink()
            else:
                retained_dirs.append(name)
        dirs[:] = retained_dirs
        for name in files:
            candidate = Path(current) / name
            if _adversary_symlink_targets_private_runtime(candidate, root):
                candidate.unlink()


def _adversary_symlink_targets_private_runtime(candidate: Path, root: Path) -> bool:
    if not candidate.is_symlink():
        return False
    try:
        relative_target = candidate.resolve(strict=False).relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return False
    return bool(relative_target.parts and relative_target.parts[0] == ".supervisor")


def _assert_adversary_snapshot_symlink_boundary(
    snapshot_root: Path,
    *,
    approved_readonly_dependency_mounts: tuple[
        _AdversaryReadonlyDependencyMount, ...
    ] = (),
) -> None:
    root = snapshot_root.resolve()
    approved = {
        mount.relative_path: mount.target.resolve(strict=True)
        for mount in approved_readonly_dependency_mounts
    }
    seen_approved: set[str] = set()
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in sorted([*dirs, *files]):
            candidate = Path(current) / name
            if not candidate.is_symlink():
                continue
            relative = candidate.relative_to(root).as_posix()
            approved_target = approved.get(relative)
            if approved_target is not None:
                try:
                    resolved = candidate.resolve(strict=True)
                except (OSError, RuntimeError) as exc:
                    raise ValueError(
                        f"adversary dependency mount is unresolved: {relative}"
                    ) from exc
                if resolved != approved_target or not resolved.is_dir():
                    raise ValueError(
                        f"adversary dependency mount target mismatch: {relative}"
                    )
                seen_approved.add(relative)
                continue
            raw_target = os.readlink(candidate)
            if Path(raw_target).is_absolute():
                raise ValueError(
                    f"adversary snapshot retained an absolute symlink: {candidate.relative_to(root)}"
                )
            try:
                resolved = candidate.resolve(strict=False)
            except (OSError, RuntimeError) as exc:
                raise ValueError(
                    f"adversary snapshot retained an unresolved symlink: {candidate.relative_to(root)}"
                ) from exc
            if not ensure_relative_to(resolved, root):
                raise ValueError(
                    f"adversary snapshot symlink escapes the snapshot: {candidate.relative_to(root)}"
                )
    missing = sorted(set(approved) - seen_approved)
    if missing:
        raise ValueError(
            "adversary snapshot is missing approved dependency mount(s): "
            + ", ".join(missing)
        )


def _init_snapshot_git(snapshot_root: Path) -> None:
    """Give the snapshot a functional git repo so tests/tools that shell out to git work.

    Best-effort: an empty initial commit makes HEAD/status/diff usable while keeping every
    file untracked, so recursive deletes inside the snapshot stay policy-approvable.
    """
    git = shutil.which("git")
    if git is None:
        return
    identity = [
        "-c",
        "user.email=bello@localhost",
        "-c",
        "user.name=Bello Snapshot",
        "-c",
        "commit.gpgsign=false",
    ]
    git_env = snapshot_git_environment()
    try:
        initialized = subprocess.run(
            [git, "-c", "init.templateDir=", "init", "-q"],
            cwd=snapshot_root,
            env=git_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if initialized.returncode != 0:
            return
        subprocess.run(
            [git, "config", "--local", "core.hooksPath", os.devnull],
            cwd=snapshot_root,
            env=git_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        subprocess.run(
            [
                git,
                "-c",
                "core.fsmonitor=false",
                *identity,
                "commit",
                "-q",
                "--no-verify",
                "--allow-empty",
                "-m",
                "bello adversary snapshot baseline",
            ],
            cwd=snapshot_root,
            env=git_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
    except Exception:
        return


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
    for current, dirs, files in os.walk(root, followlinks=False):
        rel_dir = Path(current).relative_to(root)
        traversable_dirs: list[str] = []
        for name in sorted(dirs):
            if name in skip_dirs:
                continue
            path = Path(current) / name
            try:
                mode = path.lstat().st_mode
            except OSError:
                _update_workspace_entry_digest(
                    digest, path, (rel_dir / name).as_posix()
                )
                continue
            if stat.S_ISDIR(mode):
                _update_workspace_entry_digest(
                    digest, path, (rel_dir / name).as_posix()
                )
                traversable_dirs.append(name)
            else:
                _update_workspace_entry_digest(
                    digest, path, (rel_dir / name).as_posix()
                )
        dirs[:] = traversable_dirs
        for name in sorted(files):
            path = Path(current) / name
            rel = (rel_dir / name).as_posix()
            _update_workspace_entry_digest(digest, path, rel)
    return digest.hexdigest()


def _review_product_state_id(
    project_root: Path,
    changed_files: list[ChangedFile],
    *,
    task_contents: str,
) -> str:
    """Fingerprint material review inputs independently of event path metadata."""

    material_paths = {
        _normalize_review_path(file.path)
        for file in (
            *_material_code_review_files(changed_files, task_contents=task_contents),
            *_material_static_review_files(
                changed_files, task_contents=task_contents
            ),
        )
    }
    material_paths.update(
        _normalize_review_path(file.path)
        for file in changed_files
        if _changed_file_is_behavior_affecting(
            file, task_contents=task_contents
        )
    )
    return _review_paths_state_id(project_root, changed_files, material_paths)


def _review_behavioral_product_state_id(
    project_root: Path,
    changed_files: list[ChangedFile],
    *,
    task_contents: str,
) -> str:
    """Fingerprint only inputs whose edits can invalidate behavioral execution."""

    material_paths = {
        _normalize_review_path(file.path)
        for file in changed_files
        if _changed_file_is_behavior_affecting(
            file, task_contents=task_contents
        )
    }
    return _review_paths_state_id(project_root, changed_files, material_paths)


def _review_paths_state_id(
    project_root: Path,
    changed_files: list[ChangedFile],
    material_paths: set[str],
) -> str:
    by_path = {
        _normalize_review_path(file.path): file
        for file in changed_files
        if _normalize_review_path(file.path) in material_paths
    }
    cache: dict[str, tuple[tuple[Any, ...], str]] = {}
    payload = [
        {
            "path": path,
            "status": by_path[path].status,
            "content": _workspace_path_fingerprint(
                project_root, path, cache=cache
            ),
        }
        for path in sorted(material_paths)
    ]
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _validations_for_product_state(
    validations: list[ValidationRun],
    current_product_state_id: str,
    *,
    current_behavior_state_id: str | None = None,
) -> list[ValidationRun]:
    return [
        (
            validation.model_copy(
                update={
                    "outcome": "fail",
                    "passed": False,
                    "trusted_validation_outcome": "masked_or_unknown",
                    "masking_reason": "stale_product_state",
                }
            )
            if not _validation_matches_current_product_state(
                validation,
                current_product_state_id=current_product_state_id,
                current_behavior_state_id=current_behavior_state_id,
            )
            else validation
        )
        for validation in validations
    ]


def _validation_matches_current_product_state(
    validation: ValidationRun,
    *,
    current_product_state_id: str,
    current_behavior_state_id: str | None,
) -> bool:
    expected_state_id = (
        current_behavior_state_id
        if validation.type == "behavioral"
        and current_behavior_state_id is not None
        else current_product_state_id
    )
    return validation.product_state_id == expected_state_id


def _inspections_for_product_state(
    inspections: list[InspectionRun], current_product_state_id: str
) -> list[InspectionRun]:
    return [
        (
            inspection.model_copy(update={"outcome": "fail", "passed": False})
            if inspection.product_state_id != current_product_state_id
            else inspection
        )
        for inspection in inspections
    ]


def _update_workspace_entry_digest(digest: Any, path: Path, relative_path: str) -> None:
    encoded_path = relative_path.encode("utf-8", errors="surrogateescape")
    digest.update(encoded_path)
    digest.update(b"\0")
    try:
        initial_stat = path.lstat()
        mode = initial_stat.st_mode
        digest.update(f"mode:{stat.S_IMODE(mode):o}".encode("ascii"))
        digest.update(b"\0")
        if stat.S_ISLNK(mode):
            digest.update(b"symlink\0")
            digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
        elif stat.S_ISREG(mode):
            flags = (
                os.O_RDONLY
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(path, flags)
            try:
                opened_before = os.fstat(descriptor)
                opened_mode = opened_before.st_mode
                if not stat.S_ISREG(opened_mode):
                    digest.update(
                        f"special:{stat.S_IFMT(opened_mode):o}".encode("ascii")
                    )
                else:
                    digest.update(b"file\0")
                    while chunk := os.read(descriptor, 1024 * 1024):
                        digest.update(chunk)
                    opened_after = os.fstat(descriptor)
                    try:
                        path_after = path.lstat()
                    except OSError:
                        digest.update(b"changed-during-read\0")
                    else:
                        identity_before = (opened_before.st_dev, opened_before.st_ino)
                        identity_after = (opened_after.st_dev, opened_after.st_ino)
                        path_identity_after = (path_after.st_dev, path_after.st_ino)
                        if (
                            identity_before != identity_after
                            or identity_before != path_identity_after
                        ):
                            digest.update(b"changed-during-read\0")
                        if (
                            opened_before.st_size != opened_after.st_size
                            or opened_before.st_mtime_ns != opened_after.st_mtime_ns
                            or stat.S_IMODE(opened_before.st_mode)
                            != stat.S_IMODE(opened_after.st_mode)
                        ):
                            digest.update(b"changed-during-read\0")
            finally:
                os.close(descriptor)
        else:
            digest.update(f"special:{stat.S_IFMT(mode):o}".encode("ascii"))
    except OSError:
        digest.update(b"unreadable\0")
    digest.update(b"\0")


def _latest_validation_sequence(validations: list[ValidationRun]) -> int | None:
    return max((validation.sequence for validation in validations), default=None)


def _review_ledger_fingerprint(records: list[Any]) -> str:
    payload: list[Any] = []
    for record in records:
        if hasattr(record, "model_dump"):
            payload.append(record.model_dump(mode="json"))
        elif hasattr(record, "__dict__"):
            payload.append(dict(vars(record)))
        else:
            payload.append(str(record))
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _pending_approvals_fingerprint(pending: Any) -> str:
    if not isinstance(pending, dict):
        pending = {}
    payload: list[dict[str, Any]] = []
    for request_id, context in pending.items():
        request_type = getattr(context, "request_type", None)
        payload.append(
            {
                "request_id": str(request_id),
                "request_type": getattr(request_type, "value", request_type),
                "thread_id": getattr(context, "thread_id", None),
                "turn_id": getattr(context, "turn_id", None),
                "item_id": getattr(context, "item_id", None),
                "command": getattr(context, "command", None),
                "grant_root": getattr(context, "grant_root", None),
            }
        )
    payload.sort(key=lambda item: item["request_id"])
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _task_review_state_id(task_path: Path) -> str:
    try:
        return _hash_file(task_path)
    except OSError as exc:
        return f"unavailable:{exc.__class__.__name__}"


def _git_review_state_id(project_root: Path) -> str:
    """Hash Git metadata that changes review packet status without changing file bytes."""

    root = project_root.resolve()
    digest = hashlib.sha256()
    marker = root / ".git"
    _update_workspace_entry_digest(digest, marker, ".git")
    git_dir: Path | None = None
    try:
        marker_mode = marker.lstat().st_mode
    except OSError:
        marker_mode = 0
    if stat.S_ISDIR(marker_mode):
        git_dir = marker
    elif stat.S_ISLNK(marker_mode):
        try:
            candidate = marker.resolve(strict=False)
        except OSError:
            candidate = marker
        if candidate.is_dir():
            git_dir = candidate
        elif candidate.is_file():
            marker_bytes = _read_git_metadata_bytes(marker, limit=4096)
            if marker_bytes is not None:
                marker_text = marker_bytes.decode("utf-8", errors="replace").strip()
                if marker_text.lower().startswith("gitdir:"):
                    raw_git_dir = marker_text.split(":", 1)[1].strip()
                    nested = Path(raw_git_dir)
                    git_dir = (
                        nested.resolve(strict=False)
                        if nested.is_absolute()
                        else (root / nested).resolve(strict=False)
                    )
    elif stat.S_ISREG(marker_mode):
        marker_bytes = _read_regular_bytes_no_follow(marker, limit=4096)
        if marker_bytes is not None:
            marker_text = marker_bytes.decode("utf-8", errors="replace").strip()
            if marker_text.lower().startswith("gitdir:"):
                raw_git_dir = marker_text.split(":", 1)[1].strip()
                candidate = Path(raw_git_dir)
                git_dir = (
                    candidate.resolve(strict=False)
                    if candidate.is_absolute()
                    else (root / candidate).resolve(strict=False)
                )
    if git_dir is None:
        return digest.hexdigest()

    common_git_dir = git_dir
    commondir_bytes = _read_git_metadata_bytes(git_dir / "commondir", limit=4096)
    _update_git_metadata_digest(
        digest, git_dir / "commondir", ".git/worktree/commondir"
    )
    if commondir_bytes is not None:
        raw_common_dir = commondir_bytes.decode("utf-8", errors="replace").strip()
        if raw_common_dir:
            candidate = Path(raw_common_dir)
            common_git_dir = (
                candidate.resolve(strict=False)
                if candidate.is_absolute()
                else (git_dir / candidate).resolve(strict=False)
            )

    for relative in ("HEAD", "index", "config.worktree", "info/sparse-checkout"):
        _update_git_metadata_digest(
            digest,
            git_dir / relative,
            f".git/worktree/{relative}",
        )
    for relative in ("packed-refs", "config", "info/exclude", "info/attributes"):
        _update_git_metadata_digest(
            digest,
            common_git_dir / relative,
            f".git/common/{relative}",
        )
    head_bytes = _read_git_metadata_bytes(git_dir / "HEAD", limit=4096)
    if head_bytes is not None:
        head_text = head_bytes.decode("utf-8", errors="replace").strip()
        if head_text.startswith("ref:"):
            raw_ref = head_text.split(":", 1)[1].strip().replace("\\", "/")
            _update_git_symbolic_ref_chain(
                digest,
                git_dir=git_dir,
                common_git_dir=common_git_dir,
                initial_ref=raw_ref,
            )
    _update_git_observable_state_digest(digest, root)
    return digest.hexdigest()


def _update_git_symbolic_ref_chain(
    digest: Any,
    *,
    git_dir: Path,
    common_git_dir: Path,
    initial_ref: str,
) -> None:
    current_ref = initial_ref
    seen: set[str] = set()
    for _ in range(16):
        ref_path = Path(current_ref)
        if (
            not current_ref
            or ref_path.is_absolute()
            or ".." in ref_path.parts
            or current_ref in seen
        ):
            digest.update(f"invalid-or-cyclic-ref:{current_ref}".encode("utf-8"))
            return
        seen.add(current_ref)
        worktree_path = git_dir / ref_path
        common_path = common_git_dir / ref_path
        _update_git_metadata_digest(
            digest,
            worktree_path,
            f".git/worktree/{current_ref}",
        )
        _update_git_metadata_digest(
            digest,
            common_path,
            f".git/common/{current_ref}",
        )
        ref_bytes = _read_git_metadata_bytes(worktree_path, limit=4096)
        if ref_bytes is None:
            ref_bytes = _read_git_metadata_bytes(common_path, limit=4096)
        if ref_bytes is None:
            return
        ref_text = ref_bytes.decode("utf-8", errors="replace").strip()
        if not ref_text.startswith("ref:"):
            return
        current_ref = ref_text.split(":", 1)[1].strip().replace("\\", "/")
    digest.update(b"symbolic-ref-depth-exceeded")


def _update_git_observable_state_digest(digest: Any, root: Path) -> None:
    """Bind the token to the Git outputs consumed by review packet construction."""

    commands = (
        (
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ),
        (
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--unified=0",
            "--",
        ),
        (
            "diff",
            "--cached",
            "--no-ext-diff",
            "--no-textconv",
            "--unified=0",
            "--",
        ),
    )
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    for command in commands:
        digest.update(b"git-observable\0")
        digest.update("\0".join(command).encode("utf-8"))
        digest.update(b"\0")
        try:
            completed = subprocess.run(
                ["git", "-c", "core.fsmonitor=false", *command],
                cwd=root,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            digest.update(f"unavailable:{exc.__class__.__name__}".encode("ascii"))
            continue
        digest.update(f"exit:{completed.returncode}".encode("ascii"))
        digest.update(b"\0stdout\0")
        digest.update(completed.stdout)
        digest.update(b"\0stderr\0")
        digest.update(completed.stderr)


def _update_git_metadata_digest(digest: Any, path: Path, relative_path: str) -> None:
    """Bind both a Git metadata symlink and the regular file Git reads through it."""

    _update_workspace_entry_digest(digest, path, relative_path)
    try:
        if not stat.S_ISLNK(path.lstat().st_mode):
            return
        resolved = path.resolve(strict=False)
    except OSError:
        return
    _update_workspace_entry_digest(digest, resolved, f"{relative_path}:resolved")


def _read_git_metadata_bytes(path: Path, *, limit: int) -> bytes | None:
    try:
        if stat.S_ISLNK(path.lstat().st_mode):
            path = path.resolve(strict=False)
    except OSError:
        return None
    return _read_regular_bytes_no_follow(path, limit=limit)


def _read_regular_bytes_no_follow(path: Path, *, limit: int) -> bytes | None:
    descriptor: int | None = None
    try:
        descriptor = _open_regular_file_no_follow(path)
        return os.read(descriptor, max(0, limit))
    except OSError:
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _changed_file_revision_fingerprint(changed_files: list[ChangedFile]) -> str:
    payload = sorted(
        (
            file.path,
            file.status,
            file.sequence,
            file.additions,
            file.deletions,
        )
        for file in changed_files
    )
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


_RAW_ADVERSARY_SECTION_RE = re.compile(
    r"^(?:#{1,6}\s*)?"
    r"(candidate_finding|attacked|previous_findings_checked|findings|observations|held|not_reached|overall)"
    r"\s*:\s*(.*)$",
    re.IGNORECASE,
)
_EMPTY_ADVERSARY_SECTION_SENTINELS = {
    "",
    "n/a",
    "no",
    "none",
    "nothing",
    "not applicable",
    "no observations",
    "no findings",
}


def _raw_adversary_section_content(report_text: str, section_name: str) -> str | None:
    collected: list[str] = []
    in_section = False
    fence_state = None
    for line in report_text.splitlines():
        before_fence = fence_state
        fence_state, is_fence_marker = advance_markdown_fence(line, fence_state)
        if is_fence_marker:
            if in_section:
                collected.append(line)
            continue
        if before_fence is not None:
            if in_section:
                collected.append(line)
            continue
        match = _RAW_ADVERSARY_SECTION_RE.match(line)
        if match is not None:
            current_name = match.group(1).lower()
            if in_section and current_name != section_name:
                break
            in_section = current_name == section_name
            if in_section and match.group(2).strip():
                collected.append(match.group(2).strip())
            continue
        if in_section:
            collected.append(line)
    if not in_section and not collected:
        return None
    return "\n".join(collected).strip()


def _raw_adversary_section_has_items(report_text: str, section_name: str) -> bool:
    content = _raw_adversary_section_content(report_text, section_name)
    if content is None:
        return False
    meaningful_lines: list[str] = []
    for line in content.splitlines():
        normalized = (
            re.sub(r"^[-*\d.)\s]+", "", line.strip()).strip().lower().rstrip(".")
        )
        if normalized and normalized not in _EMPTY_ADVERSARY_SECTION_SENTINELS:
            meaningful_lines.append(normalized)
    return bool(meaningful_lines)


def _normalized_report_has_observation_section(report_to_coder: str | None) -> bool:
    found, _ = _normalized_report_observation_section(report_to_coder)
    return found


def _normalized_report_observation_section(
    report_to_coder: str | None,
) -> tuple[bool, str]:
    return _normalized_report_named_section(
        report_to_coder, "Observations requiring investigation"
    )


def _normalized_report_findings_section(
    report_to_coder: str | None,
) -> tuple[bool, str]:
    return _normalized_report_named_section(
        report_to_coder, "Findings requiring correction"
    )


def _normalized_report_named_section(
    report_to_coder: str | None,
    heading: str,
) -> tuple[bool, str]:
    if not report_to_coder:
        return False, ""
    collected: list[str] = []
    in_section = False
    found = False
    fence_state = None
    for line in report_to_coder.splitlines():
        stripped = line.strip()
        before_fence = fence_state
        fence_state, is_fence_marker = advance_markdown_fence(line, fence_state)
        if is_fence_marker:
            if in_section:
                collected.append(line)
            continue
        if before_fence is not None:
            if in_section:
                collected.append(line)
            continue
        if line == line.lstrip() and re.match(
            rf"^##\s+{re.escape(heading)}\s*$",
            stripped,
            flags=re.IGNORECASE,
        ):
            in_section = True
            found = True
            continue
        if (
            in_section
            and line == line.lstrip()
            and re.match(r"^##\s+", stripped)
        ):
            break
        if in_section:
            collected.append(line)
    return found, "\n".join(collected).strip()


def _normalized_report_observation_content(report_to_coder: str | None) -> str:
    _, content = _normalized_report_observation_section(report_to_coder)
    return content


def _adversary_section_items(content: str) -> list[str]:
    """Split report bullets while preserving factual indentation inside each item."""

    items: list[str] = []
    current: list[str] = []
    continuation_indent = 0
    item_indent: int | None = None
    bullet_mode: bool | None = None
    fence_state = None

    def flush() -> None:
        if current:
            while current and not current[-1].strip():
                current.pop()
            item = "\n".join(current).strip("\r\n")
            if item:
                items.append(item)
            current.clear()

    for raw_line in content.splitlines():
        before_fence = fence_state
        fence_state, is_fence_marker = advance_markdown_fence(raw_line, fence_state)
        bullet = re.match(r"^(\s*)(?:[-*+]|\d+[.)])\s+(.*)$", raw_line)
        bullet_indent = len(bullet.group(1)) if bullet is not None else None
        if (
            before_fence is None
            and not is_fence_marker
            and bullet is not None
            and bullet_mode is not False
            and (item_indent is None or bullet_indent == item_indent)
        ):
            flush()
            current.append(bullet.group(2))
            continuation_indent = bullet.start(2)
            item_indent = bullet_indent
            bullet_mode = True
            continue
        if not current:
            if not raw_line.strip():
                continue
            current.append(raw_line.strip())
            continuation_indent = 0
            bullet_mode = False
            continue
        line = raw_line
        removable = min(continuation_indent, len(line) - len(line.lstrip(" ")))
        current.append(line[removable:])
    flush()
    return items


def _canonical_adversary_item_text(value: str) -> str:
    return value.strip("\r\n")


def _adv_report_normalization_contract_issue(
    raw_report: str,
    normalized: AdvReportControllerDecision,
) -> str | None:
    raw_finding_items = [
        canonical
        for item in _adversary_section_items(
            _raw_adversary_section_content(raw_report, "findings") or ""
        )
        if (canonical := _canonical_adversary_item_text(item))
        and canonical.lower().rstrip(".") not in _EMPTY_ADVERSARY_SECTION_SENTINELS
    ]
    normalized_has_findings, normalized_findings_content = (
        _normalized_report_findings_section(normalized.report_to_coder)
    )
    kept_findings: list[str] = []
    if normalized_has_findings:
        normalized_finding_items = [
            canonical
            for item in _adversary_section_items(normalized_findings_content)
            if (canonical := _canonical_adversary_item_text(item))
        ]
        if not normalized_finding_items:
            return "coder-facing findings section is empty"
        available_raw_findings = list(raw_finding_items)
        for finding in normalized_finding_items:
            if finding not in available_raw_findings:
                return (
                    "coder-facing finding was rewritten or added without an exact raw "
                    "finding item"
                )
            available_raw_findings.remove(finding)
            kept_findings.append(finding)
    raw_has_observations = _raw_adversary_section_has_items(raw_report, "observations")
    normalized_has_observations = _normalized_report_has_observation_section(
        normalized.report_to_coder
    )
    if raw_has_observations:
        if not normalized.forward_to_coder:
            return "raw observations were dropped by forward_to_coder=false"
        if not normalized_has_observations:
            return "raw observations were omitted from the coder-facing observation section"
    if normalized_has_observations:
        raw_content = _raw_adversary_section_content(raw_report, "observations") or ""
        normalized_content = _normalized_report_observation_content(
            normalized.report_to_coder
        )
        normalized_items = [
            canonical
            for item in _adversary_section_items(normalized_content)
            if (canonical := _canonical_adversary_item_text(item))
        ]
        if not normalized_items:
            return "coder-facing observation section is empty"
        raw_items = (
            [
                canonical
                for item in _adversary_section_items(raw_content)
                if (canonical := _canonical_adversary_item_text(item))
            ]
            if raw_has_observations
            else []
        )
        if normalized_items[: len(raw_items)] != raw_items:
            return (
                "raw observations were not preserved one-to-one: omitted, reordered, "
                "rewritten, or duplicated"
            )
        normalized_downgrades = normalized_items[len(raw_items) :]
        available_raw_findings = [
            finding for finding in raw_finding_items if finding not in kept_findings
        ]
        for canonical_item in normalized_downgrades:
            downgraded = re.match(
                r"^Downgraded finding:\s*(.+)$",
                canonical_item,
                flags=re.DOTALL,
            )
            if downgraded is not None:
                downgraded_fact = downgraded.group(1).strip()
                if not downgraded_fact or downgraded_fact not in available_raw_findings:
                    return "downgraded observation contains facts not copied from a raw finding"
                available_raw_findings.remove(downgraded_fact)
                continue
            return (
                "raw observations were not preserved one-to-one: coder-facing section "
                "contains an invented observation"
            )
    if normalized.material_coverage_limitations:
        if not _raw_adversary_section_has_items(raw_report, "not_reached"):
            return "material coverage limitations were added without a raw not_reached fact"
        available_not_reached = [
            canonical
            for item in _adversary_section_items(
                _raw_adversary_section_content(raw_report, "not_reached") or ""
            )
            if (canonical := _canonical_adversary_item_text(item))
        ]
        for limitation in normalized.material_coverage_limitations:
            canonical_limitation = _canonical_adversary_item_text(limitation)
            if canonical_limitation not in available_not_reached:
                return (
                    "material coverage limitation was rewritten or added without a matching "
                    "raw not_reached item"
                )
            available_not_reached.remove(canonical_limitation)
    return None


def _adversary_report_staleness_reason(
    report: AdversaryReport | None,
    *,
    workspace_state_id: str | None,
    generation: int,
) -> str | None:
    if report is None:
        return None
    if report.generation != generation:
        return (
            "Adversary report is stale: it covers generation "
            f"{report.generation}, while the final workspace is generation {generation}."
        )
    if not report.workspace_state_id:
        return "Adversary report is stale: it is not bound to a workspace state."
    if (
        report.workspace_state_id
        and workspace_state_id
        and report.workspace_state_id != workspace_state_id
    ):
        return "Adversary report is stale: the workspace changed after the report was produced."
    return None


def _final_adversary_report_summary(
    report: AdversaryReport | None,
    *,
    stale: bool = False,
) -> list[str]:
    if report is None:
        return []
    first_line = next(
        (line.strip() for line in report.report_text.splitlines() if line.strip()), ""
    )
    if len(first_line) > 240:
        first_line = first_line[:237].rstrip() + "..."
    details = [
        f"status={report.status}",
        f"candidate_finding={str(report.candidate_finding).lower()}",
        f"completion_wake_sequence={report.completion_wake_sequence}",
        f"latest_relevant_change_sequence={report.latest_relevant_change_sequence}",
        f"workspace_state={'stale' if stale else 'current'}",
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
            if (
                path
                and not _is_ignored_changed_path(
                    path, project_root=project_root, task_path=task_path
                )
                and path not in files
            ):
                files.append(path)
    marker = "$ git diff --name-only"
    if marker in diff:
        tail = diff.split(marker, 1)[1]
        for line in tail.splitlines():
            path = line.strip()
            if (
                path
                and not path.startswith("$")
                and not _is_ignored_changed_path(
                    path, project_root=project_root, task_path=task_path
                )
                and path not in files
            ):
                files.append(path)
    return files
