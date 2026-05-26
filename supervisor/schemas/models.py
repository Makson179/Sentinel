from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from copy import deepcopy
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventType(str, Enum):
    PERMISSION_REQUEST = "PermissionRequest"
    PRE_TOOL_USE = "PreToolUse"
    POST_TOOL_USE = "PostToolUse"
    POST_TOOL_BATCH = "PostToolBatch"
    STOP = "Stop"
    SUBAGENT_STOP = "SubagentStop"
    PRE_COMPACT = "PreCompact"
    POST_COMPACT = "PostCompact"
    SESSION_END = "SessionEnd"
    TIMER = "Timer"
    KILL_CANDIDATE = "KillCandidate"


class DecisionType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    NOOP = "noop"
    INTERVENE = "intervene"
    KILL_RESTART = "kill_restart"
    TASK_COMPLETE = "task_complete"
    KEEP_ALIVE = "keep_alive"


class PermissionDecisionKind(str, Enum):
    ALLOW_ONCE = "allow_once"
    ALLOW_CLASS = "allow_class"
    DENY = "deny"


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
    LEGACY_EXEC_COMMAND = "legacy_exec_command"
    LEGACY_APPLY_PATCH = "legacy_apply_patch"
    UNKNOWN = "unknown"


class SupervisorDecisionKind(str, Enum):
    NOOP = "noop"
    APPROVE = "approve"
    DENY = "deny"
    INTERVENE = "intervene"
    RESTART = "restart"
    COMPLETE = "complete"
    PAUSE = "pause"


class ApprovalDecisionKind(str, Enum):
    ACCEPT = "accept"
    ACCEPT_FOR_SESSION = "acceptForSession"
    DECLINE = "decline"
    CANCEL = "cancel"


class HookEvent(BaseModel):
    event_type: EventType
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    source_hook: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    generation: int = 0


class IPCRequest(BaseModel):
    event_type: EventType
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    auth_token: str
    source_hook: str | None = None


class IPCResponse(BaseModel):
    decision_type: DecisionType
    payload: dict[str, Any] = Field(default_factory=dict)
    deferred_intervention_attached: bool = False
    sequence: int


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
    diff: str | None = None
    grant_root: str | None = None
    network_approval_context: NetworkApprovalContext | None = None
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
    display_message: str | None = None
    wake_sequence: int | None = None
    generation: int | None = None


class SupervisorWakePacket(BaseModel):
    wake_sequence: int
    latest_event_sequence: int
    generation: int
    restart_count: int
    task_path: str
    task_contents: str
    progress: str = ""
    decisions: str = ""
    last_action: str = ""
    health: dict[str, Any] = Field(default_factory=dict)
    handoff: str | None = None
    recent_events: list[dict[str, Any]] = Field(default_factory=list)
    current_summary: str = ""
    diff_summary: str | None = None
    coder_thread_id: str | None = None
    active_coder_turn_id: str | None = None
    triggering_item_id: str | None = None
    triggering_server_request_id: int | str | None = None


class FinalReport(BaseModel):
    task_path: str
    status: SentinelStatus | str
    result: str
    files_changed: list[str] = Field(default_factory=list)
    validations: list[str] = Field(default_factory=list)
    denied_actions: list[str] = Field(default_factory=list)
    interventions: int = 0
    restarts: int = 0
    remaining_risks: list[str] = Field(default_factory=list)
    diff_summary: str | None = None


class AllowRulePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: str | None = None
    command: str | None = None
    path: str | None = None
    file_path: str | None = None
    filepath: str | None = None
    cwd: str | None = None
    directory: str | None = None
    paths: list[str] | None = None
    files: list[str] | None = None
    operation: str | None = None


class LLMDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_type: DecisionType
    permission_kind: PermissionDecisionKind | None = None
    reason: str = ""
    intervention: str | None = None
    decision_entry: str | None = None
    completed_step: str | None = None
    last_action: str | None = None
    handoff: str | None = None
    risk_signals: list[str] = Field(default_factory=list)
    allow_rule: AllowRulePayload | None = None
    sequence: int | None = None
    generation: int | None = None


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


class PendingIntervention(BaseModel):
    generation: int
    sequence: int
    message: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RunConfig(BaseModel):
    platform: Literal["claude", "codex", "fake"]
    mode: Literal["subscription", "api"] = "subscription"
    supervisor_model: str | None = None
    timer_interval_seconds: int = 120
    kill_restart_thresholds: dict[str, int] = Field(default_factory=dict)
    plan_file_path: str
    ipc_socket_path: str | None = None
    codex_hook_manifest: dict[str, Any] | None = None
    generation: int = 0
    restart_count: int = 0
    hook_timeout_seconds: float = 10.0

    @field_validator("plan_file_path")
    @classmethod
    def plan_must_not_be_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("plan_file_path is required")
        return value


class StateSnapshot(BaseModel):
    config: RunConfig
    health: HealthState
    progress: str = ""
    decisions: str = ""
    last_action: str = ""
    pending_intervention: PendingIntervention | None = None


class DecisionLogEntry(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    sequence: int
    hook_event_id: str | None = None
    generation: int
    source_hook: str | None = None
    handling_path: str
    latency_ms: float
    decision: dict[str, Any]
    fallback_reason: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def json_schema_for_decision() -> dict[str, Any]:
    return LLMDecision.model_json_schema()


def openai_strict_json_schema_for_decision() -> dict[str, Any]:
    return openai_strict_json_schema(json_schema_for_decision())


def json_schema_for_supervisor_decision() -> dict[str, Any]:
    return SupervisorDecision.model_json_schema()


def openai_strict_json_schema_for_supervisor_decision() -> dict[str, Any]:
    return openai_strict_json_schema(json_schema_for_supervisor_decision())


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
