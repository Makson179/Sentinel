"""Role-aware Context Mode event identity and idempotent transitions."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal, Mapping

from ._util import ContextModeDataError, require_int, require_nonempty, require_sha256
from .config import CONTEXT_SERVER_NAME, assert_tool_name


class EventError(ContextModeDataError):
    """An app-server event cannot be safely correlated."""


class ClientRole(str, Enum):
    CODER = "coder"
    SUPERVISOR = "supervisor"


@dataclass(frozen=True)
class PendingRequestKey:
    role: ClientRole
    process_epoch: int
    request_id: int | str

    def __post_init__(self) -> None:
        if not isinstance(self.role, ClientRole):
            object.__setattr__(self, "role", ClientRole(self.role))
        require_int(self.process_epoch, "process_epoch")
        if isinstance(self.request_id, bool) or not isinstance(self.request_id, (int, str)):
            raise EventError("JSON-RPC request_id must be an integer or string")
        if isinstance(self.request_id, str):
            require_nonempty(self.request_id, "request_id")


@dataclass(frozen=True)
class LogicalContextCallKey:
    role: Literal[ClientRole.CODER]
    thread_id: str
    turn_id: str
    item_id: str

    def __post_init__(self) -> None:
        role = ClientRole(self.role)
        if role is not ClientRole.CODER:
            raise EventError("Context Mode logical calls are coder-only")
        object.__setattr__(self, "role", ClientRole.CODER)
        require_nonempty(self.thread_id, "thread_id")
        require_nonempty(self.turn_id, "turn_id")
        require_nonempty(self.item_id, "item_id")

    @property
    def stable_id(self) -> str:
        return f"coder:{self.thread_id}:{self.turn_id}:{self.item_id}"


@dataclass(frozen=True)
class ContextObservationKey:
    app_server_instance_id: str
    process_epoch: int
    broker_receipt_seq: int | None

    def __post_init__(self) -> None:
        require_nonempty(self.app_server_instance_id, "app_server_instance_id")
        require_int(self.process_epoch, "process_epoch")
        if self.broker_receipt_seq is not None:
            require_int(self.broker_receipt_seq, "broker_receipt_seq", minimum=1)


class ContextCallStatus(str, Enum):
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class ContextModeCallEvent:
    logical_key: LogicalContextCallKey
    observation: ContextObservationKey
    operation_id: str | None
    status: ContextCallStatus
    tool_name: str
    run_id: str
    workspace_id: str
    context_session_id: str
    context_state_epoch: int
    binding_version: int
    coder_generation: int
    generation_lease_id: str
    sandbox_policy_digest: str
    provider_thread_id: str
    workspace_revision_started: int
    workspace_revision_completed: int | None = None
    overlapping_mutation: bool = False
    duration_ms: int | None = None
    source_bytes: int | None = None
    returned_bytes: int | None = None
    indexed_bytes: int | None = None
    provenance: Any | None = None
    redacted_summary: Mapping[str, Any] | None = None
    protocol_issues: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.status, ContextCallStatus):
            object.__setattr__(self, "status", ContextCallStatus(self.status))
        assert_tool_name(self.tool_name)
        for name in ("run_id", "workspace_id", "context_session_id", "generation_lease_id"):
            require_nonempty(getattr(self, name), name)
        require_sha256(self.sandbox_policy_digest, "sandbox_policy_digest")
        require_nonempty(self.provider_thread_id, "provider_thread_id")
        if self.provider_thread_id != self.logical_key.thread_id:
            raise EventError("event provider thread differs from its logical call key")
        require_int(self.context_state_epoch, "context_state_epoch")
        require_int(self.binding_version, "binding_version", minimum=1)
        require_int(self.coder_generation, "coder_generation")
        require_int(self.workspace_revision_started, "workspace_revision_started")
        if self.workspace_revision_completed is not None:
            require_int(self.workspace_revision_completed, "workspace_revision_completed")
            if self.workspace_revision_completed < self.workspace_revision_started:
                raise EventError("completed workspace revision precedes started revision")
        for name in ("duration_ms", "source_bytes", "returned_bytes", "indexed_bytes"):
            value = getattr(self, name)
            if value is not None:
                require_int(value, name)
        if self.status is ContextCallStatus.STARTED:
            if self.operation_id is not None or self.workspace_revision_completed is not None:
                raise EventError("started event cannot contain terminal operation/revision fields")
        elif self.workspace_revision_completed is None:
            raise EventError("terminal event requires workspace_revision_completed")
        if self.operation_id is not None:
            require_nonempty(self.operation_id, "operation_id")
        if self.redacted_summary is None:
            object.__setattr__(self, "redacted_summary", {})
        if any(not isinstance(issue, str) or not issue for issue in self.protocol_issues):
            raise EventError("protocol issues must be non-empty strings")


class EventDisposition(str, Enum):
    ACCEPTED_STARTED = "accepted_started"
    ACCEPTED_TERMINAL = "accepted_terminal"
    DUPLICATE_OBSERVATION = "duplicate_observation"
    DUPLICATE_LOGICAL_TERMINAL = "duplicate_logical_terminal"


@dataclass
class _CallRecord:
    started: ContextModeCallEvent
    terminal: ContextModeCallEvent | None
    observations: set[ContextObservationKey]


class ContextEventLedger:
    """Deduplicate logical calls independently of transport observations."""

    def __init__(self) -> None:
        self._calls: dict[LogicalContextCallKey, _CallRecord] = {}
        self._operation_owners: dict[str, LogicalContextCallKey] = {}
        self._lock = threading.RLock()

    def record(self, event: ContextModeCallEvent) -> EventDisposition:
        with self._lock:
            record = self._calls.get(event.logical_key)
            if event.status is ContextCallStatus.STARTED:
                if record is None:
                    self._calls[event.logical_key] = _CallRecord(event, None, {event.observation})
                    return EventDisposition.ACCEPTED_STARTED
                if not _same_logical_scope(record.started, event):
                    raise EventError("conflicting started observations for one logical Context Mode call")
                if event.observation in record.observations:
                    return EventDisposition.DUPLICATE_OBSERVATION
                record.observations.add(event.observation)
                return EventDisposition.DUPLICATE_OBSERVATION

            if record is None:
                raise EventError("terminal Context Mode event arrived before its logical started event")
            if not _same_logical_scope(record.started, event):
                raise EventError("terminal observation does not match the logical call generation/scope")
            if record.terminal is not None:
                # A process recovery may produce another observation, but never a
                # second terminal action/counter.  Conflicting terminal semantics
                # are kept out of the trusted ledger.
                if event.observation in record.observations:
                    return EventDisposition.DUPLICATE_OBSERVATION
                previous = record.terminal
                if previous.status != event.status or previous.operation_id != event.operation_id:
                    raise EventError("conflicting terminal observations for one logical Context Mode call")
                if event.operation_id is not None:
                    owner = self._operation_owners.get(event.operation_id)
                    if owner != event.logical_key:
                        raise EventError("broker operation_id owner changed across terminal observations")
                record.observations.add(event.observation)
                return EventDisposition.DUPLICATE_LOGICAL_TERMINAL
            # An untrusted terminal has no broker receipt sequence, so its
            # transport observation is intentionally identical to the started
            # observation.  The first terminal transition must still count as
            # the ordinary coder action; observation deduplication applies only
            # after a logical terminal has been committed.
            record.observations.add(event.observation)
            if event.operation_id is not None:
                owner = self._operation_owners.get(event.operation_id)
                if owner is not None and owner != event.logical_key:
                    raise EventError("broker operation_id was replayed for another logical call")
                self._operation_owners[event.operation_id] = event.logical_key
            record.terminal = event
            return EventDisposition.ACCEPTED_TERMINAL

    def get_terminal(self, key: LogicalContextCallKey) -> ContextModeCallEvent | None:
        with self._lock:
            record = self._calls.get(key)
            return record.terminal if record else None

    def observation_count(self, key: LogicalContextCallKey) -> int:
        with self._lock:
            record = self._calls.get(key)
            return len(record.observations) if record else 0


@dataclass(frozen=True)
class ActiveEventContext:
    role: ClientRole
    app_server_instance_id: str
    process_epoch: int
    thread_id: str
    run_id: str
    workspace_id: str
    context_session_id: str
    context_state_epoch: int
    binding_version: int
    coder_generation: int
    generation_lease_id: str

    def __post_init__(self) -> None:
        for name in (
            "app_server_instance_id",
            "thread_id",
            "run_id",
            "workspace_id",
            "context_session_id",
            "generation_lease_id",
        ):
            require_nonempty(getattr(self, name), name)
        for name, minimum in (
            ("process_epoch", 0),
            ("context_state_epoch", 0),
            ("binding_version", 1),
            ("coder_generation", 0),
        ):
            require_int(getattr(self, name), name, minimum=minimum)


def _same_logical_scope(left: ContextModeCallEvent, right: ContextModeCallEvent) -> bool:
    return all(
        getattr(left, name) == getattr(right, name)
        for name in (
            "logical_key",
            "tool_name",
            "run_id",
            "workspace_id",
            "context_session_id",
            "context_state_epoch",
            "binding_version",
            "coder_generation",
            "generation_lease_id",
            "sandbox_policy_digest",
            "provider_thread_id",
            "workspace_revision_started",
        )
    )


def identify_context_call(
    item: Mapping[str, Any],
    *,
    active: ActiveEventContext,
    params: Mapping[str, Any] | None = None,
) -> tuple[LogicalContextCallKey, str]:
    """Identify only the pinned coder/server/tool item shape.

    This function intentionally returns identity, not provenance.  Terminal
    semantics still require an independently delivered broker receipt.
    """

    if active.role is not ClientRole.CODER:
        raise EventError("Context Mode item observed on the supervisor transport")
    if item.get("type") != "mcpToolCall":
        raise EventError("item is not an mcpToolCall")
    if item.get("server") != CONTEXT_SERVER_NAME:
        raise EventError("MCP item is not from Bello Context Mode")
    tool_name = item.get("tool")
    if not isinstance(tool_name, str):
        raise EventError("MCP item has no string tool name")
    assert_tool_name(tool_name)
    outer = params or {}

    def identity(outer_key: str, inner_key: str) -> str | None:
        outer_value = outer.get(outer_key)
        inner_value = item.get(inner_key)
        if outer_value is not None and inner_value is not None and outer_value != inner_value:
            raise EventError(f"conflicting outer/item {outer_key} identity")
        value = outer_value if outer_value is not None else inner_value
        return value if isinstance(value, str) and value else None

    thread_id = identity("threadId", "threadId")
    turn_id = identity("turnId", "turnId")
    item_id = identity("itemId", "id")
    if thread_id != active.thread_id:
        raise EventError("MCP item belongs to an inactive provider thread")
    if not all(isinstance(value, str) and value for value in (thread_id, turn_id, item_id)):
        raise EventError("MCP item is missing thread/turn/item identity")
    return LogicalContextCallKey(ClientRole.CODER, thread_id, turn_id, item_id), tool_name


EventCorrelator = ContextEventLedger
