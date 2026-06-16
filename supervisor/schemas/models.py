from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from copy import deepcopy
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class PolicyDecisionKind(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ROUTE_LLM = "route_llm"


class SentinelStatus(str, Enum):
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    RESTARTING = "restarting"
    COMPLETE = "complete"
    ESCALATED = "escalated"
    STUCK = "stuck"
    PROVIDER_FAILURE = "provider_failure"
    EXITED = "exited"


class AppEventSource(str, Enum):
    SYSTEM = "system"
    APP_SERVER = "app_server"
    CODER = "coder"
    SUPERVISOR = "supervisor"
    APPROVAL = "approval"
    USER = "user"
    TOOL = "tool"


class ApprovalRequestType(str, Enum):
    COMMAND = "command"
    FILE_CHANGE = "file_change"
    PERMISSIONS = "permissions"
    TOOL_USER_INPUT = "tool_user_input"
    DYNAMIC_TOOL_CALL = "dynamic_tool_call"
    MCP_ELICITATION = "mcp_elicitation"
    UNKNOWN = "unknown"


class SupervisorDecisionKind(str, Enum):
    NOOP = "noop"
    APPROVE = "approve"
    DENY = "deny"
    INTERVENE = "intervene"
    RESTART = "restart"
    PAUSE = "pause"


class CompletionReviewDecisionKind(str, Enum):
    ACCEPT = "accept"
    RETURN = "return"
    RESTART = "restart"


class ApprovalDecisionKind(str, Enum):
    ACCEPT = "accept"
    ACCEPT_FOR_SESSION = "acceptForSession"
    DECLINE = "decline"
    CANCEL = "cancel"


class PolicyDecision(BaseModel):
    kind: PolicyDecisionKind
    reason: str
    payload: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def allow(cls, reason: str, **payload: Any) -> "PolicyDecision":
        return cls(kind=PolicyDecisionKind.ALLOW, reason=reason, payload=payload)

    @classmethod
    def deny(cls, reason: str, **payload: Any) -> "PolicyDecision":
        return cls(kind=PolicyDecisionKind.DENY, reason=reason, payload=payload)

    @classmethod
    def route_llm(cls, reason: str, **payload: Any) -> "PolicyDecision":
        return cls(kind=PolicyDecisionKind.ROUTE_LLM, reason=reason, payload=payload)


class SentinelConfig(BaseModel):
    project_root: str
    task_path: str
    task_hash: str | None = None
    codex_version: str | None = None
    appserver_schema_hash: str | None = None
    coder_thread_id: str | None = None
    active_coder_turn_id: str | None = None
    generation: int = 0
    restart_count: int = 0
    max_restarts: int = 3
    last_event_sequence: int = 0
    last_applied_supervisor_sequence: int = 0
    pending_server_request_ids: list[int | str] = Field(default_factory=list)
    status: SentinelStatus = SentinelStatus.STARTING
    model: str | None = None
    max_no_marker_idle_nudges: int = 2
    max_completion_returns_per_generation: int = 2
    accept_gate_accepts: int = 0
    accept_gate_rejections: int = 0
    accept_gate_reviewer_reruns: int = 0
    accept_gate_coder_returns: int = 0
    accept_gate_audit_failures: int = 0
    last_relevant_edit_sequence: int | None = None
    last_validation_sequence: int | None = None
    last_trusted_behavioral_validation_sequence: int | None = None
    last_trusted_passing_behavioral_validation_sequence: int | None = None


class AppEvent(BaseModel):
    sequence: int
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    generation: int = 0
    source: AppEventSource | str
    event_type: str
    thread_id: str | None = None
    turn_id: str | None = None
    item_id: str | None = None
    decision: str | dict[str, Any] | None = None
    reason: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class NetworkApprovalContext(BaseModel):
    host: str
    protocol: str
    port: int | None = None


class ApprovalContext(BaseModel):
    server_request_id: int | str
    server_request_method: str
    request_type: ApprovalRequestType = ApprovalRequestType.UNKNOWN
    thread_id: str | None = None
    turn_id: str | None = None
    item_id: str | None = None
    approval_id: str | None = None
    command: str | None = None
    cwd: str | None = None
    paths: list[str] = Field(default_factory=list)
    file_changes: list[dict[str, Any]] = Field(default_factory=list)
    diff: str | None = None
    grant_root: str | None = None
    network_approval_context: NetworkApprovalContext | None = None
    proposed_execpolicy_amendment: list[str] | None = None
    proposed_network_policy_amendments: list[Any] | None = None
    available_decisions: list[Any] | None = None
    raw_params: dict[str, Any] = Field(default_factory=dict)

    @property
    def available_decision_keys(self) -> set[str] | None:
        if self.available_decisions is None:
            return None
        keys: set[str] = set()
        for decision in self.available_decisions:
            if isinstance(decision, str):
                keys.add(decision)
            elif isinstance(decision, dict):
                keys.update(decision.keys())
        return keys


class ApprovalResolution(BaseModel):
    decision: str | dict[str, Any]
    reason: str
    persistent_decision: str | None = None
    from_supervisor: bool = False


class RestartHandoff(BaseModel):
    model_config = ConfigDict(extra="forbid")

    objective: str
    restart_reason: str
    bad_pattern: str
    known_evidence: str
    next_step: str
    recovery_signal: str


class SupervisorDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: SupervisorDecisionKind
    approval_decision: ApprovalDecisionKind | None = None
    execpolicy_amendment: list[str] | None = None
    reason: str = ""
    message_to_coder: str | None = None
    persistent_decision: str | None = None
    progress_update: str | None = None
    health_delta: dict[str, Any] | None = None
    clear_handoff: bool = False
    display_message: str | None = None
    handoff: RestartHandoff | None = None
    wake_sequence: int | None = None
    generation: int | None = None


class ReviewedFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    reason: str
    kind: Literal["source", "test", "config", "docs", "other"]
    inspected: bool
    limitation: str | None = None


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    validation_id: str | None = None
    command: str
    sequence: int | None = None
    validation_type: Literal["static", "behavioral", "unknown"]
    outcome: Literal["pass", "fail", "unknown"]
    freshness: Literal["fresh", "stale", "unknown"]
    why_it_covers_behavior: str


class BehaviorEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    behavior: str
    task_basis: str
    files_considered: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    status: Literal["covered", "partial", "uncovered"]
    gap: str | None = None


class CompletionReviewDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: CompletionReviewDecisionKind
    reason: str
    files_reviewed: list[ReviewedFile] = Field(default_factory=list)
    behavior_evidence_matrix: list[BehaviorEvidence] = Field(default_factory=list)
    uncovered_behaviors: list[str] = Field(default_factory=list)
    validation_gaps: list[str] = Field(default_factory=list)
    claim_evidence_mismatches: list[str] = Field(default_factory=list)
    packet_or_access_limitations: list[str] = Field(default_factory=list)
    changed_test_risks: list[str] = Field(default_factory=list)
    message_to_coder: str | None
    persistent_decision: str | None
    progress_update: str | None
    clear_handoff: bool
    display_message: str | None
    handoff: RestartHandoff | None
    wake_sequence: int
    generation: int

    @model_validator(mode="after")
    def validate_decision_shape(self) -> "CompletionReviewDecision":
        if self.decision == CompletionReviewDecisionKind.ACCEPT:
            if self.message_to_coder is not None:
                raise ValueError("accept must not set message_to_coder")
            if self.handoff is not None:
                raise ValueError("accept must not set handoff")
            if self.uncovered_behaviors or self.validation_gaps:
                raise ValueError("accept must use empty uncovered_behaviors and validation_gaps")
        elif self.decision == CompletionReviewDecisionKind.RETURN:
            if not self.message_to_coder or not self.message_to_coder.strip():
                raise ValueError("return requires message_to_coder")
            if self.handoff is not None:
                raise ValueError("return must not set handoff")
            if not _completion_review_has_return_issue(self):
                raise ValueError("return requires an uncovered behavior, validation gap, mismatch, risk, or access limitation")
        elif self.decision == CompletionReviewDecisionKind.RESTART:
            if self.handoff is None:
                raise ValueError("restart requires handoff")
            if self.message_to_coder is not None:
                raise ValueError("restart must not set message_to_coder")
        return self


def _completion_review_has_return_issue(decision: CompletionReviewDecision) -> bool:
    if (
        decision.uncovered_behaviors
        or decision.validation_gaps
        or decision.claim_evidence_mismatches
        or decision.packet_or_access_limitations
        or decision.changed_test_risks
    ):
        return True
    return any(row.status != "covered" for row in decision.behavior_evidence_matrix)


class ApprovalWakeContext(BaseModel):
    request_type: str
    server_request_id: int | str
    method: str
    available_decisions: list[Any] | None = None
    command: str | None = None
    file_changes: list[dict[str, Any]] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)
    cwd: str | None = None
    grant_root: str | None = None
    network_approval_context: NetworkApprovalContext | None = None
    proposed_execpolicy_amendment: list[str] | None = None
    proposed_network_policy_amendments: list[Any] | None = None
    reason: str | None = None


class TriggeringAction(BaseModel):
    item_id: str | None = None
    kind: str
    command: str | None = None
    cwd: str | None = None
    paths: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    status: str | None = None
    summary: str


class CoderMessage(BaseModel):
    text: str
    sequence: int


class ValidationRun(BaseModel):
    validation_id: str
    command: str
    raw_command: str | None = None
    normalized_command: str | None = None
    cwd: str | None = None
    exit_code: int | None = None
    shell_exit_code: int | None = None
    type: Literal["static", "behavioral"] = "behavioral"
    outcome: Literal["pass", "fail"] = "fail"
    passed: bool
    trusted_validation_outcome: Literal["passed", "failed", "masked_or_unknown"] = "failed"
    masking_reason: str | None = None
    summary: str
    sequence: int
    was_filtered: bool = False
    raw_selector: str | None = None
    executed_test_names: list[str] = Field(default_factory=list)
    passed_count: int | None = None
    failed_count: int | None = None
    target_files_or_test_files: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def fill_legacy_validation_fields(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        data = dict(value)
        if "outcome" not in data:
            if "passed" in data:
                data["outcome"] = "pass" if data["passed"] else "fail"
            elif data.get("exit_code") == 0:
                data["outcome"] = "pass"
            else:
                data["outcome"] = "fail"
        if "passed" not in data:
            data["passed"] = data.get("outcome") == "pass"
        if "type" not in data:
            data["type"] = "behavioral"
        command = data.get("command")
        if "raw_command" not in data and isinstance(command, str):
            data["raw_command"] = command
        if "normalized_command" not in data and isinstance(command, str):
            data["normalized_command"] = " ".join(command.strip().split())
        if "shell_exit_code" not in data:
            data["shell_exit_code"] = data.get("exit_code")
        if "trusted_validation_outcome" not in data:
            data["trusted_validation_outcome"] = "passed" if data.get("outcome") == "pass" and data.get("passed") else "failed"
        if "validation_id" not in data:
            sequence = data.get("sequence")
            if isinstance(sequence, int) and isinstance(command, str):
                data["validation_id"] = f"validation-{sequence}"
        return data


class HumanMessage(BaseModel):
    text: str
    sequence: int


class PriorIntervention(BaseModel):
    reason: str
    message_to_coder: str
    sequence: int


class CompletionReturnRecord(BaseModel):
    reason: str
    uncovered_behaviors: list[str] = Field(default_factory=list)
    validation_gaps: list[str] = Field(default_factory=list)
    claim_evidence_mismatches: list[str] = Field(default_factory=list)
    packet_or_access_limitations: list[str] = Field(default_factory=list)
    message_to_coder: str | None = None
    sequence: int
    generation: int


class ChangedFile(BaseModel):
    path: str
    status: str
    additions: int | None = None
    deletions: int | None = None
    sequence: int | None = None


class ChangedFileDiff(BaseModel):
    path: str
    file_kind: Literal["source", "test", "config", "docs", "unknown"]
    change_kind: Literal["modified", "added", "deleted", "renamed", "unknown"]
    diff: str
    diff_truncated: bool = False
    omitted_reason: str | None = None


class ChangedFileContext(BaseModel):
    path: str
    final_snippets_around_changed_hunks: str
    context_truncated: bool = False


class ChangedTestsSummary(BaseModel):
    path: str
    added_or_modified_test_names: list[str] = Field(default_factory=list)
    changed_assertion_snippets: list[str] = Field(default_factory=list)
    grep_or_test_selection_relevant_to_validations: list[str] = Field(default_factory=list)
    summary_truncated: bool = False


class ValidationOutput(BaseModel):
    validation_id: str
    command: str
    raw_command: str | None = None
    normalized_command: str | None = None
    cwd: str | None = None
    exit_code: int | None = None
    shell_exit_code: int | None = None
    type: Literal["static", "behavioral"]
    outcome: Literal["pass", "fail"]
    passed: bool
    trusted_validation_outcome: Literal["passed", "failed", "masked_or_unknown"] = "failed"
    masking_reason: str | None = None
    sequence: int
    stdout_or_summary: str
    stderr_or_summary: str | None = None
    output_truncated: bool = False
    detected_test_names: list[str] = Field(default_factory=list)
    target_files_or_test_files: list[str] = Field(default_factory=list)
    was_filtered: bool = False
    raw_selector: str | None = None
    executed_test_names: list[str] = Field(default_factory=list)
    passed_count: int | None = None
    failed_count: int | None = None


class DiffPacketLimits(BaseModel):
    total_diff_chars: int = 0
    total_context_chars: int = 0
    omitted_changed_files: list[str] = Field(default_factory=list)
    materially_truncated: bool = False
    truncation_reason: str | None = None


class SupervisorWakePacket(BaseModel):
    wake_sequence: int
    latest_event_sequence: int
    generation: int
    restart_count: int
    task_path: str
    task_contents: str
    progress: str = ""
    decisions: str = ""
    last_actions: list[str] = Field(default_factory=list)
    health: dict[str, Any] = Field(default_factory=dict)
    handoff: RestartHandoff | None = None
    recent_events: list[dict[str, Any]] = Field(default_factory=list)
    current_summary: str = ""
    diff_summary: str | None = None
    coder_thread_id: str | None = None
    active_coder_turn_id: str | None = None
    triggering_item_id: str | None = None
    triggering_server_request_id: int | str | None = None
    approval_context: ApprovalWakeContext | None = None
    pending_approvals: list[ApprovalWakeContext] = Field(default_factory=list)
    triggering_action: TriggeringAction | None = None
    last_coder_message: CoderMessage | None = None
    validations: list[ValidationRun] = Field(default_factory=list)
    human_message: HumanMessage | None = None
    prior_interventions: list[PriorIntervention] = Field(default_factory=list)
    changed_files: list[ChangedFile] = Field(default_factory=list)
    patch_summary: str | None = None
    completion_attempt_count: int = 0
    completion_returns_this_generation: int = 0
    previous_completion_returns: list[CompletionReturnRecord] = Field(default_factory=list)
    last_readiness_marker_sequence: int | None = None
    no_marker_idle_nudge_count: int = 0
    latest_relevant_change_sequence: int | None = None
    validation_freshness_summary: str | None = None
    changed_file_diffs: list[ChangedFileDiff] = Field(default_factory=list)
    changed_file_contexts: list[ChangedFileContext] = Field(default_factory=list)
    changed_tests_summary: list[ChangedTestsSummary] = Field(default_factory=list)
    validation_outputs: list[ValidationOutput] = Field(default_factory=list)
    diff_packet_limits: DiffPacketLimits = Field(default_factory=DiffPacketLimits)
    completion_payload_mode: Literal["full", "delta", "full_fallback"] | None = None
    completion_payload_since_sequence: int | None = None
    completion_review_thread_id: str | None = None


class FinalReport(BaseModel):
    task_path: str
    status: SentinelStatus | str
    result: str
    files_changed: list[str] = Field(default_factory=list)
    validations: list[str] = Field(default_factory=list)
    denied_actions: list[str] = Field(default_factory=list)
    interventions: int = 0
    restarts: int = 0
    completion_review_accepted: bool = False
    completion_returns: int = 0
    completion_restarts: int = 0
    no_marker_idle_nudges: int = 0
    remaining_risks: list[str] = Field(default_factory=list)
    behavior_evidence_summary: list[str] = Field(default_factory=list)
    files_reviewed_summary: list[str] = Field(default_factory=list)
    packet_or_access_limitations: list[str] = Field(default_factory=list)
    diff_summary: str | None = None


class HealthState(BaseModel):
    generation: int = 0
    restart_count: int = 0
    denied_requests: int = 0
    consecutive_failed_tests: int = 0
    repeated_command_count: int = 0
    interventions: int = 0
    minutes_without_progress: int = 0
    risk_signals: list[str] = Field(default_factory=list)
    last_progress_sequence: int = 0
    last_denial: str | None = None
    timeout_fallback_count: int = 0
    parse_failure_count: int = 0


class HealthDelta(BaseModel):
    generation: int
    denied_requests: int = 0
    consecutive_failed_tests: int = 0
    repeated_command_count: int = 0
    interventions: int = 0
    minutes_without_progress: int = 0
    timeout_fallback_count: int = 0
    parse_failure_count: int = 0
    restart_count: int = 0
    last_denial: str | None = None
    last_progress_sequence: int | None = None
    add_risk_signals: list[str] = Field(default_factory=list)
    clear_risk_signals: bool = False
    reset_generation_scoped: bool = False
    new_generation: int | None = None


def json_schema_for_supervisor_decision() -> dict[str, Any]:
    return SupervisorDecision.model_json_schema()


def openai_strict_json_schema_for_supervisor_decision() -> dict[str, Any]:
    return openai_strict_json_schema(json_schema_for_supervisor_decision())


def json_schema_for_completion_review_decision() -> dict[str, Any]:
    return CompletionReviewDecision.model_json_schema()


def openai_strict_json_schema_for_completion_review_decision() -> dict[str, Any]:
    return openai_strict_json_schema(json_schema_for_completion_review_decision())


def openai_strict_json_schema(schema: dict[str, Any]) -> dict[str, Any]:
    strict_schema = deepcopy(schema)
    _apply_openai_strict_json_schema(strict_schema)
    return strict_schema


def _apply_openai_strict_json_schema(node: Any) -> None:
    if isinstance(node, dict):
        node.pop("default", None)
        properties = node.get("properties")
        if node.get("type") == "object" or isinstance(properties, dict):
            node["additionalProperties"] = False
            if isinstance(properties, dict):
                node["required"] = list(properties)
        for value in node.values():
            _apply_openai_strict_json_schema(value)
    elif isinstance(node, list):
        for item in node:
            _apply_openai_strict_json_schema(item)


def ensure_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
