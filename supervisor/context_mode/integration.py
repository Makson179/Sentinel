"""Controller-facing normalization facade for Context Mode notifications.

The facade has no process-launching authority.  It consumes app-server
notifications plus receipts that the Controller received over the broker's
separate authority channel.  Text in an MCP result can never manufacture a
receipt: a terminal result is trusted only after an atomic inbox claim and full
``ProvenanceValidator`` validation against the original started binding and
broker origin.  A later terminal transport is accepted only when the active
binding structurally proves an otherwise unchanged monotonic process recovery.

Typical Controller wiring::

    integration.publish_receipt(receipt)  # broker authority channel
    outcome = integration.normalize_notification(
        method=message.method,
        params=message.params,
        origin=ContextNotificationOrigin(...),
        active_binding=binding_store.load(),
        workspace_revision=current_revision,
        approval_capability_id=capability_id,
    )

``outcome.evidence`` is empty unless ``outcome.trusted`` is true.  Supervisor
Context Mode items are returned as explicit role-isolation health violations.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Mapping

from ._util import (
    ContextModeDataError,
    canonical_json_bytes,
    digest_json,
    require_int,
    require_nonempty,
    require_sha256,
    sha256_bytes,
)
from .config import CAPABILITY_REQUIRED_TOOLS, CONTEXT_SERVER_NAME, EXECUTION_TOOLS, assert_tool_name
from .events import (
    ClientRole,
    ContextCallStatus,
    ContextEventLedger,
    ContextModeCallEvent,
    ContextObservationKey,
    EventDisposition,
    EventError,
    LogicalContextCallKey,
)
from .provenance import (
    MAX_EVENT_BYTES,
    MAX_MODEL_RESULT_BYTES,
    BrokerReceipt,
    ExpectedProvenance,
    ProvenanceError,
    ProvenanceValidator,
    RedactedSummary,
    ResultEnvelope,
    RetrievalRecord,
    ValidatedProvenance,
    ValidationEvidence,
    bounded_redacted_summary,
    evidence_from_provenance,
    validate_model_result_limits,
)
from .session import ContextBinding
from .telemetry import AuthoritySeparatedCounters, MetricAuthority


MAX_ARGUMENT_BYTES = 1024 * 1024
DEFAULT_MAX_PENDING_RECEIPTS = 4096
DEFAULT_MAX_RECEIPTS_PER_RUN = 100_000
DEFAULT_MAX_TRACKED_CALLS = 100_000


class IntegrationError(ContextModeDataError):
    """A notification or receipt cannot be normalized safely."""


class ReceiptInboxError(IntegrationError):
    """Out-of-band receipt inbox invariant failed."""


class ReceiptInboxFull(ReceiptInboxError):
    """A bounded inbox reached capacity and refused fail-open eviction."""


class ReceiptNotFound(ReceiptInboxError):
    """No unclaimed out-of-band receipt exactly matches the envelope."""


class ReceiptAlreadySeen(ReceiptInboxError):
    """A receipt sequence, operation, or digest was published more than once."""


@dataclass(frozen=True)
class ContextNotificationOrigin:
    role: ClientRole
    process_epoch: int
    app_server_instance_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.role, ClientRole):
            object.__setattr__(self, "role", ClientRole(self.role))
        require_int(self.process_epoch, "process_epoch")
        require_nonempty(self.app_server_instance_id, "app_server_instance_id")


class OutOfBandReceiptInbox:
    """Bounded one-publish/one-claim storage for canonical broker receipts.

    Claimed identities remain in a bounded seen-set.  Once the total run capacity
    is reached, publishing stops rather than evicting replay protection.
    """

    def __init__(
        self,
        *,
        maximum_pending: int = DEFAULT_MAX_PENDING_RECEIPTS,
        maximum_total: int = DEFAULT_MAX_RECEIPTS_PER_RUN,
    ) -> None:
        require_int(maximum_pending, "maximum_pending", minimum=1)
        require_int(maximum_total, "maximum_total", minimum=1)
        if maximum_pending > maximum_total:
            raise ReceiptInboxError("maximum_pending cannot exceed maximum_total")
        self.maximum_pending = maximum_pending
        self.maximum_total = maximum_total
        self._pending: dict[str, BrokerReceipt] = {}
        self._seen_sequences: set[tuple[str, int, int]] = set()
        self._seen_operations: set[str] = set()
        self._seen_digests: set[str] = set()
        self._claimed_digests: set[str] = set()
        self._lock = threading.RLock()

    def publish(self, receipt: BrokerReceipt) -> None:
        """Publish only data received over the Controller's authority channel."""

        if not isinstance(receipt, BrokerReceipt):
            raise ReceiptInboxError("receipt inbox accepts only parsed BrokerReceipt objects")
        digest = receipt.digest
        sequence_key = (receipt.app_server_instance_id, receipt.process_epoch, receipt.receipt_seq)
        with self._lock:
            if (
                digest in self._seen_digests
                or receipt.operation_id in self._seen_operations
                or sequence_key in self._seen_sequences
            ):
                raise ReceiptAlreadySeen("broker receipt identity was already published")
            if len(self._seen_digests) >= self.maximum_total:
                raise ReceiptInboxFull("receipt run capacity reached; replay state is not evicted")
            if len(self._pending) >= self.maximum_pending:
                raise ReceiptInboxFull("pending receipt inbox capacity reached")
            self._pending[digest] = receipt
            self._seen_digests.add(digest)
            self._seen_operations.add(receipt.operation_id)
            self._seen_sequences.add(sequence_key)

    def has_seen(self, digest: str) -> bool:
        """Report whether one exact authority-channel receipt was delivered.

        Claimed digests deliberately remain in the seen set so replayed
        terminals do not spend a delivery timeout before ``claim`` rejects
        them as already consumed.
        """

        require_sha256(digest, "receipt_digest")
        with self._lock:
            return digest in self._seen_digests

    def claim(
        self,
        envelope: ResultEnvelope,
        *,
        origin: ContextNotificationOrigin,
    ) -> BrokerReceipt:
        """Atomically remove exactly one receipt matching envelope and origin."""

        digest = envelope.broker_receipt_digest
        with self._lock:
            if digest in self._claimed_digests:
                raise ReceiptAlreadySeen("matching broker receipt was already claimed")
            candidates = [
                receipt
                for receipt in self._pending.values()
                if receipt.digest == digest
                and receipt.receipt_seq == envelope.broker_receipt_seq
                and receipt.operation_id == envelope.operation_id
                and receipt.app_server_instance_id == origin.app_server_instance_id
                and receipt.process_epoch == origin.process_epoch
                and receipt.tool_name == envelope.tool_name
                and receipt.run_id == envelope.run_id
                and receipt.workspace_id == envelope.workspace_id
                and receipt.context_session_id == envelope.context_session_id
                and receipt.context_state_epoch == envelope.context_state_epoch
                and receipt.binding_version == envelope.binding_version
                and receipt.coder_generation == envelope.coder_generation
                and receipt.generation_lease_id == envelope.generation_lease_id
                and receipt.mcp_request_id == envelope.mcp_request_id
                and receipt.arguments_digest == envelope.arguments_digest
                and receipt.capability_id == envelope.capability_id
                and receipt.result_digest == envelope.result_digest
                and receipt.sandbox_backend == envelope.sandbox_backend
                and receipt.sandbox_policy_digest == envelope.sandbox_policy_digest
            ]
            if len(candidates) != 1:
                # A digest collision or internal duplicate is treated as an
                # authority failure, never resolved by choosing one candidate.
                if len(candidates) > 1:
                    raise ReceiptInboxError("multiple out-of-band receipts match one result envelope")
                raise ReceiptNotFound("no matching out-of-band broker receipt is pending")
            receipt = candidates[0]
            del self._pending[receipt.digest]
            self._claimed_digests.add(receipt.digest)
            return receipt

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    @property
    def total_published(self) -> int:
        with self._lock:
            return len(self._seen_digests)


class ContextCallClassification(str, Enum):
    EXECUTION = "execution"
    RETRIEVAL = "retrieval"
    INDEXING = "indexing"
    INSPECTION = "inspection"
    PURGE = "purge"


class ContextOutcomeStatus(str, Enum):
    IGNORED = "ignored"
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"
    HEALTH_VIOLATION = "health_violation"


@dataclass(frozen=True)
class ContextIntegrationOutcome:
    recognized: bool
    status: ContextOutcomeStatus
    classification: ContextCallClassification | None = None
    logical_key: LogicalContextCallKey | None = None
    event: ContextModeCallEvent | None = None
    ledger_disposition: EventDisposition | None = None
    trusted: bool = False
    provenance: ValidatedProvenance | None = None
    evidence: tuple[ValidationEvidence, ...] = ()
    retrieval: tuple[RetrievalRecord, ...] = ()
    indexed_bytes: int | None = None
    protocol_issues: tuple[str, ...] = ()
    redacted_summary: Mapping[str, Any] | None = None
    action_counted: bool = False
    health_violation: bool = False
    controller_denied: bool = False

    @property
    def protocol_issue(self) -> str | None:
        return self.protocol_issues[0] if self.protocol_issues else None


@dataclass
class _CallState:
    logical_key: LogicalContextCallKey
    tool_name: str
    arguments_digest: str | None
    mcp_request_id: int | str | None
    approval_capability_id: str | None
    run_id: str
    workspace_id: str
    context_session_id: str
    binding_version: int
    context_state_epoch: int
    coder_generation: int
    generation_lease_id: str
    started_binding: ContextBinding
    started_origin: ContextNotificationOrigin
    workspace_revision_started: int
    start_protocol_issues: tuple[str, ...]
    approval_denied: bool = False
    terminal_notification_digest: str | None = None
    terminal_outcome: ContextIntegrationOutcome | None = None


def _active_binding_proves_call_scope(
    state: _CallState,
    *,
    active_binding: ContextBinding,
    origin: ContextNotificationOrigin,
) -> bool:
    """Accept the started scope or a chain containing only process recoveries.

    A binding snapshot has no free-form transition label.  Equality of the
    binding/process deltas proves that every intervening binding version was a
    process restart: any policy, state, generation, or thread transition would
    consume an additional binding version and fail this check.
    """

    current = active_binding.lifecycle
    started_binding = state.started_binding
    started = started_binding.lifecycle
    if (
        origin.role is not ClientRole.CODER
        or origin.process_epoch != current.coder_process_epoch
        or origin.app_server_instance_id != current.app_server_instance_id
    ):
        return False
    if active_binding == started_binding:
        return (
            origin.process_epoch == state.started_origin.process_epoch
            and origin.app_server_instance_id == state.started_origin.app_server_instance_id
        )
    if active_binding.stable != started_binding.stable:
        return False
    if (
        current.context_state_epoch != started.context_state_epoch
        or current.coder_generation != started.coder_generation
        or current.generation_lease_id != started.generation_lease_id
        or current.sandbox_policy_digest != started.sandbox_policy_digest
        or current.provider_thread_id != started.provider_thread_id
        or current.provider_thread_id != state.logical_key.thread_id
        or current.app_server_instance_id == started.app_server_instance_id
    ):
        return False
    binding_delta = current.binding_version - started.binding_version
    process_delta = current.coder_process_epoch - started.coder_process_epoch
    return binding_delta > 0 and binding_delta == process_delta


def _call_is_recovered(state: _CallState, active_binding: ContextBinding) -> bool:
    return active_binding != state.started_binding


def _classification(tool_name: str) -> ContextCallClassification:
    if tool_name in EXECUTION_TOOLS:
        return ContextCallClassification.EXECUTION
    if tool_name == "ctx_search":
        return ContextCallClassification.RETRIEVAL
    if tool_name == "ctx_index":
        return ContextCallClassification.INDEXING
    if tool_name == "ctx_purge":
        return ContextCallClassification.PURGE
    return ContextCallClassification.INSPECTION


def _coalesce_string(
    params: Mapping[str, Any],
    item: Mapping[str, Any],
    *,
    params_key: str,
    item_key: str,
    issue_name: str,
    issues: list[str],
) -> str | None:
    outer = params.get(params_key)
    inner = item.get(item_key)
    if outer is not None and (not isinstance(outer, str) or not outer):
        issues.append(f"invalid_{issue_name}")
        outer = None
    if inner is not None and (not isinstance(inner, str) or not inner):
        issues.append(f"invalid_item_{issue_name}")
        inner = None
    if outer is not None and inner is not None and outer != inner:
        issues.append(f"conflicting_{issue_name}")
        return None
    value = outer if isinstance(outer, str) else inner if isinstance(inner, str) else None
    if value is None:
        issues.append(f"missing_{issue_name}")
    return value


def _request_id(params: Mapping[str, Any], item: Mapping[str, Any], issues: list[str]) -> int | str | None:
    values = [
        value
        for value in (params.get("mcpRequestId"), params.get("requestId"), item.get("requestId"))
        if value is not None
    ]
    if any(isinstance(value, bool) or not isinstance(value, (int, str)) or value == "" for value in values):
        issues.append("invalid_mcp_request_id")
        return None
    if len(set((type(value), value) for value in values)) > 1:
        issues.append("conflicting_mcp_request_id")
        return None
    # Codex' public ``mcpToolCall`` item schema does not expose the internal
    # MCP request id.  Bello therefore treats this field as an optional hint;
    # the authoritative id is recovered from the independently attested result
    # envelope/receipt at terminal time.  Invalid or conflicting exposed ids
    # remain protocol errors.
    return values[0] if values else None


def _request_ids_conflict(left: int | str | None, right: int | str | None) -> bool:
    if left is None or right is None:
        return False
    return type(left) is not type(right) or left != right


def _bounded_json_digest(value: Any, *, maximum_bytes: int, issue: str, issues: list[str]) -> str | None:
    try:
        encoded = canonical_json_bytes(value)
    except ContextModeDataError:
        issues.append(f"invalid_{issue}_json")
        return None
    if len(encoded) > maximum_bytes:
        issues.append(f"{issue}_too_large")
        return None
    return sha256_bytes(encoded)


def normalized_mcp_result_digest(
    result: Mapping[str, Any],
    *,
    terminal_failed: bool = False,
) -> str:
    """Digest a terminal result after normalizing the public app-server form.

    The pinned fork and Controller must use this exact normalization.  The
    attestation envelope is removed; other structured content remains part of
    the result digest.
    """

    normalized = dict(result)
    # Codex app-server 0.146 represents an absent MCP `_meta` as null in the
    # public item notification. The signed broker hashes the original MCP
    # result, where that field is absent, so normalize the wire placeholder.
    if normalized.get("_meta") is None:
        normalized.pop("_meta", None)
    # Codex app-server 0.146 also omits the MCP SDK's top-level
    # ``isError: true`` marker from the public result while exposing the item
    # itself with status ``failed``.  The broker signs the original MCP result,
    # so reconstruct only that one implied value.  Keeping an explicit value
    # untouched preserves fail-closed mismatch detection.
    if terminal_failed and "isError" not in normalized:
        normalized["isError"] = True
    structured = normalized.get("structuredContent")
    if isinstance(structured, Mapping):
        normalized_structured = dict(structured)
        normalized_structured.pop("belloContextMode", None)
        normalized["structuredContent"] = normalized_structured
    return digest_json(normalized)


def _protocol_notification_id(
    method: str,
    params: Mapping[str, Any],
    origin: ContextNotificationOrigin,
) -> str:
    """Stable controller idempotency key when logical identity is unusable."""

    try:
        digest = digest_json(
            {
                "method": method,
                "params": dict(params),
                "role": origin.role.value,
                "process_epoch": origin.process_epoch,
                "app_server_instance_id": origin.app_server_instance_id,
            }
        )
    except ContextModeDataError:
        item = params.get("item")
        digest = digest_json(
            {
                "method": method,
                "role": origin.role.value,
                "process_epoch": origin.process_epoch,
                "app_server_instance_id": origin.app_server_instance_id,
                "item_type": item.get("type") if isinstance(item, Mapping) else None,
                "item_id": item.get("id") if isinstance(item, Mapping) else None,
            }
        )
    return f"protocol:{digest}"


class ContextModeIntegration:
    """Stateful per-run facade used by the Controller notification handler."""

    def __init__(
        self,
        *,
        redaction_authority_key: bytes,
        receipt_inbox: OutOfBandReceiptInbox | None = None,
        event_ledger: ContextEventLedger | None = None,
        telemetry: AuthoritySeparatedCounters | None = None,
        provenance_validator: ProvenanceValidator | None = None,
        maximum_tracked_calls: int = DEFAULT_MAX_TRACKED_CALLS,
    ) -> None:
        if len(redaction_authority_key) < 32:
            raise IntegrationError("redaction authority key must contain at least 256 bits")
        require_int(maximum_tracked_calls, "maximum_tracked_calls", minimum=1)
        self._redaction_key = bytes(redaction_authority_key)
        self.receipt_inbox = receipt_inbox or OutOfBandReceiptInbox()
        self.event_ledger = event_ledger or ContextEventLedger()
        self.telemetry = telemetry or AuthoritySeparatedCounters()
        self.provenance_validator = provenance_validator or ProvenanceValidator()
        self.maximum_tracked_calls = maximum_tracked_calls
        self._calls: dict[LogicalContextCallKey, _CallState] = {}
        self._lock = threading.RLock()

    def publish_receipt(self, receipt: BrokerReceipt) -> None:
        self.receipt_inbox.publish(receipt)

    def terminal_receipt_delivery_digest(
        self,
        params: Mapping[str, Any],
    ) -> str | None:
        """Return the receipt digest worth awaiting for one terminal.

        Malformed/no-result terminals, calls without an accepted start, and
        calls which the Controller already denied must go directly through
        normal fail-closed terminal normalization without delaying the event
        loop.
        """

        item = params.get("item")
        if not isinstance(item, Mapping):
            return None
        result = item.get("result")
        if not isinstance(result, Mapping):
            return None
        try:
            envelope = ResultEnvelope.from_result(result)
        except ProvenanceError:
            return None

        thread_id = params.get("threadId", item.get("threadId"))
        turn_id = params.get("turnId", item.get("turnId"))
        item_id = params.get("itemId", item.get("id"))
        if not all(isinstance(value, str) and value for value in (thread_id, turn_id, item_id)):
            return None
        logical_key = LogicalContextCallKey(
            ClientRole.CODER,
            thread_id,
            turn_id,
            item_id,
        )
        with self._lock:
            state = self._calls.get(logical_key)
            if state is None or state.approval_denied:
                return None
        return envelope.broker_receipt_digest

    def bounded_evidence_summary(
        self,
        value: Mapping[str, Any],
        *,
        maximum_bytes: int = MAX_EVENT_BYTES,
    ) -> RedactedSummary:
        """Create a run-keyed, redacted packet without exposing the HMAC key.

        This is used for transient supervisor approval context as well as
        persisted normalized events.  Callers may choose a smaller ceiling but
        may never exceed the event-log contract.
        """

        require_int(maximum_bytes, "maximum_bytes", minimum=512)
        if maximum_bytes > MAX_EVENT_BYTES:
            raise IntegrationError("bounded evidence summary exceeds the event byte ceiling")
        return bounded_redacted_summary(
            value,
            authority_key=self._redaction_key,
            maximum_event_bytes=maximum_bytes,
        )

    def attach_approval_capability(
        self,
        *,
        logical_key: LogicalContextCallKey,
        capability_id: str,
        tool_name: str,
        arguments_digest: str,
        active_binding: ContextBinding,
    ) -> None:
        """Attach a controller-minted capability after ``item/started``.

        Codex emits the canonical MCP started item before it asks the client to
        approve the call.  Consequently a capability cannot be present while
        the started notification is normalized.  The Controller calls this
        method only after correlating a real ``mcpServer/elicitation/request``
        to exactly one pending logical item.  Every field is rechecked here so
        a stale or ambiguous controller-side correlation cannot mutate another
        call's state.
        """

        require_nonempty(capability_id, "capability_id")
        assert_tool_name(tool_name)
        if tool_name not in CAPABILITY_REQUIRED_TOOLS:
            raise IntegrationError(f"{tool_name!r} does not accept an approval capability")
        require_sha256(arguments_digest, "arguments_digest")
        lifecycle = active_binding.lifecycle
        with self._lock:
            state = self._calls.get(logical_key)
            if state is None:
                raise IntegrationError("approval capability has no pending Context call")
            if state.terminal_outcome is not None:
                raise IntegrationError("approval capability arrived after the Context call became terminal")
            mismatches = []
            if state.tool_name != tool_name:
                mismatches.append("tool_name")
            if state.arguments_digest != arguments_digest:
                mismatches.append("arguments_digest")
            if state.run_id != active_binding.stable.run_id:
                mismatches.append("run_id")
            if state.workspace_id != active_binding.stable.workspace_id:
                mismatches.append("workspace_id")
            if state.context_session_id != active_binding.stable.context_session_id:
                mismatches.append("context_session_id")
            if state.binding_version != lifecycle.binding_version:
                mismatches.append("binding_version")
            if state.context_state_epoch != lifecycle.context_state_epoch:
                mismatches.append("context_state_epoch")
            if state.coder_generation != lifecycle.coder_generation:
                mismatches.append("coder_generation")
            if state.generation_lease_id != lifecycle.generation_lease_id:
                mismatches.append("generation_lease_id")
            if mismatches:
                raise IntegrationError(
                    f"approval capability does not match pending Context call: {mismatches!r}"
                )
            if state.approval_capability_id is not None:
                if state.approval_capability_id == capability_id:
                    return
                raise IntegrationError("pending Context call already has another approval capability")
            if state.approval_denied:
                raise IntegrationError("pending Context call was already denied by the controller")
            state.approval_capability_id = capability_id
            # Older persisted/in-memory candidates may have been created by a
            # pre-fix normalizer which treated pre-approval started items as an
            # error.  Capability attachment is the authoritative resolution.
            state.start_protocol_issues = tuple(
                issue
                for issue in state.start_protocol_issues
                if issue != "missing_controller_approval_capability"
            )

    def mark_approval_denied(
        self,
        *,
        logical_key: LogicalContextCallKey,
        tool_name: str,
        arguments_digest: str,
        active_binding: ContextBinding,
    ) -> None:
        """Record a deliberate controller denial before Codex emits terminal failure.

        A declined MCP elicitation normally produces an ``item/completed`` event
        with ``status=failed`` and no broker result: the tool never executed, so
        there is intentionally no capability, result envelope, or receipt.  That
        is a policy outcome, not a Context protocol failure.  Bind the denial to
        the exact already-started logical call so only that expected terminal can
        take the non-fatal path.
        """

        assert_tool_name(tool_name)
        if tool_name not in CAPABILITY_REQUIRED_TOOLS:
            raise IntegrationError(f"{tool_name!r} does not require controller approval")
        require_sha256(arguments_digest, "arguments_digest")
        lifecycle = active_binding.lifecycle
        with self._lock:
            state = self._calls.get(logical_key)
            if state is None:
                raise IntegrationError("approval denial has no pending Context call")
            if state.terminal_outcome is not None:
                raise IntegrationError("approval denial arrived after the Context call became terminal")
            mismatches = []
            if state.tool_name != tool_name:
                mismatches.append("tool_name")
            if state.arguments_digest != arguments_digest:
                mismatches.append("arguments_digest")
            if state.run_id != active_binding.stable.run_id:
                mismatches.append("run_id")
            if state.workspace_id != active_binding.stable.workspace_id:
                mismatches.append("workspace_id")
            if state.context_session_id != active_binding.stable.context_session_id:
                mismatches.append("context_session_id")
            if state.binding_version != lifecycle.binding_version:
                mismatches.append("binding_version")
            if state.context_state_epoch != lifecycle.context_state_epoch:
                mismatches.append("context_state_epoch")
            if state.coder_generation != lifecycle.coder_generation:
                mismatches.append("coder_generation")
            if state.generation_lease_id != lifecycle.generation_lease_id:
                mismatches.append("generation_lease_id")
            if mismatches:
                raise IntegrationError(
                    f"approval denial does not match pending Context call: {mismatches!r}"
                )
            if state.approval_capability_id is not None:
                raise IntegrationError("approved Context call cannot also be denied")
            state.approval_denied = True

    def normalize_notification(
        self,
        *,
        method: str,
        params: Mapping[str, Any],
        origin: ContextNotificationOrigin,
        active_binding: ContextBinding,
        workspace_revision: int,
        overlapping_mutation: bool = False,
        approval_capability_id: str | None = None,
    ) -> ContextIntegrationOutcome:
        """Normalize one ItemStarted/ItemCompleted notification.

        ``approval_capability_id`` comes from Controller approval state, never
        from the MCP result.  It is required for execution tools and ``ctx_purge``
        to become trusted.
        """

        require_int(workspace_revision, "workspace_revision")
        if not isinstance(params, Mapping):
            raise IntegrationError("notification params must be an object")
        item = params.get("item")
        if not isinstance(item, Mapping) or item.get("type") != "mcpToolCall":
            return ContextIntegrationOutcome(False, ContextOutcomeStatus.IGNORED)
        if item.get("server") != CONTEXT_SERVER_NAME:
            return ContextIntegrationOutcome(False, ContextOutcomeStatus.IGNORED)
        notification_id = _protocol_notification_id(method, params, origin)
        if origin.role is ClientRole.SUPERVISOR:
            if method == "item/completed":
                return self._protocol_only_terminal_outcome(
                    notification_id=notification_id,
                    issues=["context_mode_item_on_supervisor_transport"],
                    classification=None,
                    logical_key=None,
                    failed=item.get("status") != "completed",
                    health_violation=True,
                )
            return ContextIntegrationOutcome(
                True,
                ContextOutcomeStatus.HEALTH_VIOLATION,
                protocol_issues=("context_mode_item_on_supervisor_transport",),
                health_violation=True,
                action_counted=method == "item/completed",
            )
        if method not in {"item/started", "item/completed"}:
            return ContextIntegrationOutcome(
                True,
                ContextOutcomeStatus.HEALTH_VIOLATION,
                protocol_issues=("unexpected_context_item_notification_method",),
                health_violation=True,
            )

        issues: list[str] = []
        tool_name = item.get("tool")
        if not isinstance(tool_name, str):
            issues.append("missing_tool_name")
            tool_name = ""
        try:
            assert_tool_name(tool_name)
        except ContextModeDataError:
            issues.append("unknown_or_forbidden_tool")
            if method == "item/completed":
                return self._protocol_only_terminal_outcome(
                    notification_id=notification_id,
                    issues=issues,
                    classification=None,
                    logical_key=None,
                    failed=item.get("status") != "completed",
                    health_violation=True,
                )
            return self._protocol_only_outcome(
                method,
                issues,
                health_violation=True,
                action_counted=method == "item/completed",
            )

        thread_id = _coalesce_string(
            params, item, params_key="threadId", item_key="threadId", issue_name="thread_id", issues=issues
        )
        turn_id = _coalesce_string(
            params, item, params_key="turnId", item_key="turnId", issue_name="turn_id", issues=issues
        )
        item_id = _coalesce_string(
            params, item, params_key="itemId", item_key="id", issue_name="item_id", issues=issues
        )
        request_id = _request_id(params, item, issues)
        logical_key = (
            LogicalContextCallKey(ClientRole.CODER, thread_id, turn_id, item_id)
            if thread_id is not None and turn_id is not None and item_id is not None
            else None
        )
        lifecycle = active_binding.lifecycle
        if lifecycle.provider_thread_id is None or thread_id != lifecycle.provider_thread_id:
            issues.append("inactive_provider_thread")
        if (
            origin.process_epoch != lifecycle.coder_process_epoch
            or origin.app_server_instance_id != lifecycle.app_server_instance_id
        ):
            issues.append("stale_transport_origin")

        arguments = item.get("arguments")
        if not isinstance(arguments, Mapping):
            issues.append("missing_or_invalid_arguments")
            arguments_digest = None
        else:
            arguments_digest = _bounded_json_digest(
                dict(arguments), maximum_bytes=MAX_ARGUMENT_BYTES, issue="arguments", issues=issues
            )
        if method == "item/started":
            if item.get("status") != "inProgress":
                issues.append("invalid_started_status")
            return self._normalize_started(
                item=item,
                logical_key=logical_key,
                tool_name=tool_name,
                request_id=request_id,
                arguments=arguments,
                arguments_digest=arguments_digest,
                issues=issues,
                origin=origin,
                binding=active_binding,
                workspace_revision=workspace_revision,
                approval_capability_id=approval_capability_id,
            )
        return self._normalize_terminal(
            item=item,
            logical_key=logical_key,
            tool_name=tool_name,
            request_id=request_id,
            arguments=arguments,
            arguments_digest=arguments_digest,
            issues=issues,
            origin=origin,
            binding=active_binding,
            workspace_revision=workspace_revision,
            overlapping_mutation=overlapping_mutation,
            approval_capability_id=approval_capability_id,
            notification_id=notification_id,
        )

    def _normalize_started(
        self,
        *,
        item: Mapping[str, Any],
        logical_key: LogicalContextCallKey | None,
        tool_name: str,
        request_id: int | str | None,
        arguments: Any,
        arguments_digest: str | None,
        issues: list[str],
        origin: ContextNotificationOrigin,
        binding: ContextBinding,
        workspace_revision: int,
        approval_capability_id: str | None,
    ) -> ContextIntegrationOutcome:
        classification = _classification(tool_name)
        if tool_name not in CAPABILITY_REQUIRED_TOOLS and approval_capability_id is not None:
            issues.append("unexpected_controller_approval_capability")
        if issues:
            return ContextIntegrationOutcome(
                True,
                ContextOutcomeStatus.HEALTH_VIOLATION,
                classification=classification,
                logical_key=logical_key,
                protocol_issues=tuple(dict.fromkeys(issues)),
                health_violation=True,
            )
        with self._lock:
            state = self._calls.get(logical_key)
            if state is None:
                if len(self._calls) >= self.maximum_tracked_calls:
                    return self._protocol_only_outcome(
                        "item/started",
                        [*issues, "logical_call_capacity_exceeded"],
                        classification=classification,
                        health_violation=True,
                    )
                lifecycle = binding.lifecycle
                state = _CallState(
                    logical_key=logical_key,
                    tool_name=tool_name,
                    arguments_digest=arguments_digest,
                    mcp_request_id=request_id,
                    approval_capability_id=approval_capability_id,
                    run_id=binding.stable.run_id,
                    workspace_id=binding.stable.workspace_id,
                    context_session_id=binding.stable.context_session_id,
                    binding_version=lifecycle.binding_version,
                    context_state_epoch=lifecycle.context_state_epoch,
                    coder_generation=lifecycle.coder_generation,
                    generation_lease_id=lifecycle.generation_lease_id,
                    started_binding=binding,
                    started_origin=origin,
                    workspace_revision_started=workspace_revision,
                    start_protocol_issues=tuple(dict.fromkeys(issues)),
                )
                self._calls[logical_key] = state
            else:
                scope_valid = _active_binding_proves_call_scope(
                    state,
                    active_binding=binding,
                    origin=origin,
                )
                recovered = scope_valid and _call_is_recovered(state, binding)
                capability_conflict = (
                    approval_capability_id != state.approval_capability_id
                    and not (recovered and approval_capability_id is None)
                )
                if not scope_valid:
                    issues.append("binding_changed_since_started")
                if (
                    state.tool_name != tool_name
                    or state.arguments_digest != arguments_digest
                    or _request_ids_conflict(state.mcp_request_id, request_id)
                    or capability_conflict
                ):
                    issues.append("conflicting_logical_call_start")
                if "binding_changed_since_started" in issues or "conflicting_logical_call_start" in issues:
                    return ContextIntegrationOutcome(
                        True,
                        ContextOutcomeStatus.HEALTH_VIOLATION,
                        classification=classification,
                        logical_key=logical_key,
                        protocol_issues=tuple(dict.fromkeys(issues)),
                        health_violation=True,
                    )
                if state.mcp_request_id is None and request_id is not None:
                    state.mcp_request_id = request_id
        summary = self._summary(
            {
                "tool": tool_name,
                "status": "started",
                "arguments": arguments if arguments_digest is not None else "[OMITTED_INVALID_OR_OVERSIZED]",
            },
            issues,
        )
        event_binding = state.started_binding
        lifecycle = event_binding.lifecycle
        event = ContextModeCallEvent(
            logical_key=logical_key,
            observation=ContextObservationKey(origin.app_server_instance_id, origin.process_epoch, None),
            operation_id=None,
            status=ContextCallStatus.STARTED,
            tool_name=tool_name,
            run_id=event_binding.stable.run_id,
            workspace_id=event_binding.stable.workspace_id,
            context_session_id=event_binding.stable.context_session_id,
            context_state_epoch=lifecycle.context_state_epoch,
            binding_version=lifecycle.binding_version,
            coder_generation=lifecycle.coder_generation,
            generation_lease_id=lifecycle.generation_lease_id,
            sandbox_policy_digest=lifecycle.sandbox_policy_digest,
            provider_thread_id=state.logical_key.thread_id,
            workspace_revision_started=state.workspace_revision_started,
            redacted_summary=summary.value,
            protocol_issues=tuple(dict.fromkeys(issues)),
        )
        try:
            disposition = self.event_ledger.record(event)
        except EventError:
            issues.append("event_ledger_start_conflict")
            disposition = None
        self.telemetry.increment(
            "context_mode_calls_started",
            authority=MetricAuthority.CONTROLLER_OBSERVED,
            idempotency_key=logical_key.stable_id,
        )
        return ContextIntegrationOutcome(
            True,
            ContextOutcomeStatus.STARTED,
            classification=classification,
            logical_key=logical_key,
            event=replace(event, protocol_issues=tuple(dict.fromkeys(issues))),
            ledger_disposition=disposition,
            protocol_issues=tuple(dict.fromkeys(issues)),
            redacted_summary=summary.value,
        )

    def _normalize_terminal(
        self,
        *,
        item: Mapping[str, Any],
        logical_key: LogicalContextCallKey | None,
        tool_name: str,
        request_id: int | str | None,
        arguments: Any,
        arguments_digest: str | None,
        issues: list[str],
        origin: ContextNotificationOrigin,
        binding: ContextBinding,
        workspace_revision: int,
        overlapping_mutation: bool,
        approval_capability_id: str | None,
        notification_id: str,
    ) -> ContextIntegrationOutcome:
        classification = _classification(tool_name)
        status_value = item.get("status")
        if status_value not in {"completed", "failed"}:
            issues.append("invalid_terminal_status")
        failed = status_value != "completed"
        outcome_status = ContextOutcomeStatus.FAILED if failed else ContextOutcomeStatus.COMPLETED
        if logical_key is None:
            return self._protocol_only_terminal_outcome(
                notification_id=notification_id,
                issues=issues,
                classification=classification,
                logical_key=None,
                failed=failed,
                health_violation=True,
            )
        with self._lock:
            state = self._calls.get(logical_key)
            terminal_notification_digest = _bounded_json_digest(
                dict(item),
                maximum_bytes=MAX_ARGUMENT_BYTES + MAX_MODEL_RESULT_BYTES,
                issue="terminal_item",
                issues=issues,
            )
            if state is not None:
                scope_valid = _active_binding_proves_call_scope(
                    state,
                    active_binding=binding,
                    origin=origin,
                )
                recovered = scope_valid and _call_is_recovered(state, binding)
                capability_conflict = (
                    approval_capability_id != state.approval_capability_id
                    and not (recovered and approval_capability_id is None)
                )
                if not scope_valid:
                    issues.append("binding_changed_since_started")
                if (
                    state.tool_name != tool_name
                    or state.arguments_digest != arguments_digest
                    or _request_ids_conflict(state.mcp_request_id, request_id)
                    or capability_conflict
                ):
                    issues.append("terminal_call_identity_mismatch")
                if issues:
                    return ContextIntegrationOutcome(
                        True,
                        ContextOutcomeStatus.HEALTH_VIOLATION,
                        classification=classification,
                        logical_key=logical_key,
                        protocol_issues=tuple(dict.fromkeys(issues)),
                        action_counted=False,
                        health_violation=True,
                    )

            if state is not None and state.terminal_outcome is not None:
                duplicate_matches = (
                    state.terminal_notification_digest == terminal_notification_digest
                    and state.tool_name == tool_name
                    and state.arguments_digest == arguments_digest
                    and not _request_ids_conflict(state.mcp_request_id, request_id)
                )
                if not duplicate_matches:
                    return ContextIntegrationOutcome(
                        True,
                        outcome_status,
                        classification=classification,
                        logical_key=logical_key,
                        protocol_issues=tuple(dict.fromkeys((*issues, "conflicting_duplicate_terminal"))),
                        action_counted=False,
                        health_violation=True,
                    )
                previous = state.terminal_outcome
                previous_event = previous.event
                if previous_event is None:
                    return ContextIntegrationOutcome(
                        True,
                        outcome_status,
                        classification=classification,
                        logical_key=logical_key,
                        protocol_issues=("conflicting_duplicate_terminal",),
                        action_counted=False,
                        health_violation=True,
                    )
                duplicate_event = replace(
                    previous_event,
                    observation=ContextObservationKey(
                        origin.app_server_instance_id,
                        origin.process_epoch,
                        previous_event.observation.broker_receipt_seq,
                    ),
                    workspace_revision_completed=workspace_revision,
                    overlapping_mutation=overlapping_mutation,
                )
                try:
                    duplicate_disposition = self.event_ledger.record(duplicate_event)
                except EventError:
                    return ContextIntegrationOutcome(
                        True,
                        outcome_status,
                        classification=classification,
                        logical_key=logical_key,
                        protocol_issues=("conflicting_duplicate_terminal",),
                        action_counted=False,
                        health_violation=True,
                    )
                return replace(
                    previous,
                    event=duplicate_event,
                    ledger_disposition=duplicate_disposition,
                    action_counted=False,
                    evidence=(),
                    retrieval=(),
                    indexed_bytes=None,
                    protocol_issues=tuple(
                        dict.fromkeys((*previous.protocol_issues, "duplicate_logical_terminal"))
                    ),
                )
        if state is None:
            return self._protocol_only_terminal_outcome(
                notification_id=notification_id,
                issues=[*issues, "terminal_without_started_call"],
                classification=classification,
                logical_key=logical_key,
                failed=failed,
                health_violation=True,
            )
        else:
            issues.extend(state.start_protocol_issues)
            if (
                tool_name in CAPABILITY_REQUIRED_TOOLS
                and state.approval_capability_id is None
                and not state.approval_denied
            ):
                issues.append("missing_controller_approval_capability")

        result = item.get("result")
        controller_denied = bool(state is not None and state.approval_denied)
        expected_denial_terminal = controller_denied and failed and result is None
        if controller_denied and not expected_denial_terminal:
            issues.append("controller_denial_terminal_mismatch")
        result_digest: str | None = None
        envelope: ResultEnvelope | None = None
        if expected_denial_terminal:
            pass
        elif not isinstance(result, Mapping):
            issues.append("missing_or_invalid_terminal_result")
        else:
            try:
                encoded_result = canonical_json_bytes(dict(result))
                validate_model_result_limits(
                    encoded_bytes=len(encoded_result),
                    estimated_tokens=(len(encoded_result) + 3) // 4,
                )
                result_digest = normalized_mcp_result_digest(
                    result,
                    terminal_failed=failed,
                )
            except ContextModeDataError:
                issues.append("invalid_or_oversized_terminal_result")
            try:
                envelope = ResultEnvelope.from_result(result)
            except ProvenanceError:
                issues.append("missing_or_malformed_result_envelope")

        effective_request_id = state.mcp_request_id if state is not None else None
        if effective_request_id is None:
            effective_request_id = request_id
        if effective_request_id is None and envelope is not None:
            effective_request_id = envelope.mcp_request_id
        if envelope is not None and _request_ids_conflict(effective_request_id, envelope.mcp_request_id):
            issues.append("terminal_envelope_request_id_mismatch")

        validated: ValidatedProvenance | None = None
        if (
            state is not None
            and state.arguments_digest is not None
            and effective_request_id is not None
            and result_digest is not None
            and envelope is not None
            and not issues
        ):
            try:
                # The broker operation and receipt were created in the original
                # started-call process.  A recovered app-server may replay the
                # terminal notification, but it cannot rewrite receipt origin.
                receipt = self.receipt_inbox.claim(envelope, origin=state.started_origin)
                validated = self.provenance_validator.validate(
                    envelope,
                    receipt,
                    ExpectedProvenance.for_started_call(
                        binding=state.started_binding,
                        app_server_instance_id=state.started_origin.app_server_instance_id,
                        process_epoch=state.started_origin.process_epoch,
                        mcp_request_id=effective_request_id,
                        tool_name=tool_name,
                        arguments_digest=state.arguments_digest,
                        result_digest=result_digest,
                        capability_id=state.approval_capability_id,
                    ),
                )
            except (ReceiptInboxError, ProvenanceError):
                issues.append("missing_or_invalid_out_of_band_receipt")

        trusted = validated is not None
        receipt = validated.receipt if validated is not None else None
        summary = self._summary(
            {
                "tool": tool_name,
                "status": outcome_status.value,
                "arguments": arguments if arguments_digest is not None else "[OMITTED_INVALID_OR_OVERSIZED]",
                "result": result if result_digest is not None else "[OMITTED_INVALID_OR_OVERSIZED]",
                "trusted": trusted,
            },
            issues,
        )
        event_binding = state.started_binding if state is not None else binding
        lifecycle = event_binding.lifecycle
        event = ContextModeCallEvent(
            logical_key=logical_key,
            observation=ContextObservationKey(
                origin.app_server_instance_id,
                origin.process_epoch,
                receipt.receipt_seq if receipt is not None else None,
            ),
            operation_id=receipt.operation_id if receipt is not None else None,
            status=ContextCallStatus.FAILED if failed else ContextCallStatus.COMPLETED,
            tool_name=tool_name,
            run_id=event_binding.stable.run_id,
            workspace_id=event_binding.stable.workspace_id,
            context_session_id=event_binding.stable.context_session_id,
            context_state_epoch=lifecycle.context_state_epoch,
            binding_version=lifecycle.binding_version,
            coder_generation=lifecycle.coder_generation,
            generation_lease_id=lifecycle.generation_lease_id,
            sandbox_policy_digest=lifecycle.sandbox_policy_digest,
            provider_thread_id=logical_key.thread_id,
            workspace_revision_started=(state.workspace_revision_started if state else workspace_revision),
            workspace_revision_completed=workspace_revision,
            overlapping_mutation=overlapping_mutation,
            duration_ms=receipt.duration_ms if receipt is not None else None,
            source_bytes=receipt.source_bytes if receipt is not None else None,
            returned_bytes=receipt.returned_bytes if receipt is not None else None,
            indexed_bytes=receipt.indexed_bytes if receipt is not None else None,
            provenance=validated,
            redacted_summary=summary.value,
            protocol_issues=tuple(dict.fromkeys(issues)),
        )
        try:
            disposition = self.event_ledger.record(event)
        except EventError:
            issues.append("event_ledger_terminal_conflict")
            disposition = None
            trusted = False
            validated = None
            receipt = None
            event = replace(
                event,
                operation_id=None,
                provenance=None,
                duration_ms=None,
                source_bytes=None,
                returned_bytes=None,
                indexed_bytes=None,
                protocol_issues=tuple(dict.fromkeys(issues)),
            )
        # A controller denial is a terminal policy observation, not an executed
        # repository action.  Keep the failed-call telemetry, but do not let it
        # advance coder action accounting or execution-specific controller paths.
        action_counted = (
            disposition in {None, EventDisposition.ACCEPTED_TERMINAL}
            and not expected_denial_terminal
        )
        self._record_terminal_telemetry(
            logical_key=logical_key,
            tool_name=tool_name,
            failed=failed,
            trusted=trusted,
            receipt=receipt,
            controller_denied=expected_denial_terminal,
        )
        evidence = (
            evidence_from_provenance(
                validated,
                overlapping_mutation=overlapping_mutation,
                workspace_revision_started=state.workspace_revision_started if state else workspace_revision,
                workspace_revision_completed=workspace_revision,
            )
            if trusted and validated is not None
            else ()
        )
        retrieval = receipt.retrieval if trusted and receipt is not None and tool_name == "ctx_search" else ()
        indexed_bytes = receipt.indexed_bytes if trusted and receipt is not None and tool_name == "ctx_index" else None
        outcome = ContextIntegrationOutcome(
            True,
            outcome_status,
            classification=classification,
            logical_key=logical_key,
            event=event,
            ledger_disposition=disposition,
            trusted=trusted,
            provenance=validated if trusted else None,
            evidence=evidence,
            retrieval=retrieval,
            indexed_bytes=indexed_bytes,
            protocol_issues=tuple(dict.fromkeys(issues)),
            redacted_summary=summary.value,
            action_counted=action_counted,
            controller_denied=expected_denial_terminal,
            health_violation=bool(
                frozenset(issues)
                & {
                    "invalid_terminal_status",
                    "terminal_without_started_call",
                    "terminal_call_identity_mismatch",
                    "binding_changed_since_started",
                    "missing_or_invalid_terminal_result",
                    "invalid_or_oversized_terminal_result",
                    "missing_or_malformed_result_envelope",
                    "terminal_envelope_request_id_mismatch",
                    "missing_controller_approval_capability",
                    "controller_approval_capability_changed",
                    "controller_denial_terminal_mismatch",
                    "event_summary_redaction_failed",
                    "event_ledger_terminal_conflict",
                }
            ),
        )
        if state is not None:
            with self._lock:
                if state.mcp_request_id is None and effective_request_id is not None:
                    state.mcp_request_id = effective_request_id
                state.terminal_notification_digest = terminal_notification_digest
                state.terminal_outcome = outcome
        return outcome

    def _summary(self, value: Mapping[str, Any], issues: list[str]) -> RedactedSummary:
        try:
            return bounded_redacted_summary(value, authority_key=self._redaction_key)
        except ContextModeDataError:
            issues.append("event_summary_redaction_failed")
            return bounded_redacted_summary(
                {"summary": "unavailable", "reason": "redaction_failed"},
                authority_key=self._redaction_key,
            )

    def _record_terminal_telemetry(
        self,
        *,
        logical_key: LogicalContextCallKey,
        tool_name: str,
        failed: bool,
        trusted: bool,
        receipt: BrokerReceipt | None,
        controller_denied: bool = False,
    ) -> None:
        authority = MetricAuthority.CONTROLLER_OBSERVED
        self.telemetry.increment(
            "context_mode_calls_failed" if failed else "context_mode_calls_completed",
            authority=authority,
            idempotency_key=logical_key.stable_id,
        )
        if tool_name == "ctx_search":
            self.telemetry.increment(
                "context_mode_search_calls", authority=authority, idempotency_key=logical_key.stable_id
            )
        if tool_name in EXECUTION_TOOLS:
            self.telemetry.increment(
                "context_mode_execute_calls", authority=authority, idempotency_key=logical_key.stable_id
            )
        if not trusted and not controller_denied:
            self.telemetry.increment(
                "context_mode_untrusted_results", authority=authority, idempotency_key=logical_key.stable_id
            )
            self.telemetry.increment(
                "context_mode_provenance_failures", authority=authority, idempotency_key=logical_key.stable_id
            )
        elif receipt is not None:
            self.telemetry.record_receipt_bytes(
                operation_id=receipt.operation_id,
                source_bytes=receipt.source_bytes,
                returned_bytes=receipt.returned_bytes,
                indexed_bytes=receipt.indexed_bytes,
            )
            if tool_name == "ctx_purge":
                self.telemetry.increment(
                    "context_mode_purges", authority=authority, idempotency_key=logical_key.stable_id
                )

    def _protocol_only_terminal_outcome(
        self,
        *,
        notification_id: str,
        issues: list[str],
        classification: ContextCallClassification | None,
        logical_key: LogicalContextCallKey | None,
        failed: bool,
        health_violation: bool,
    ) -> ContextIntegrationOutcome:
        """Count an uncorrelatable terminal once by transport observation.

        These are controller-observed counters only.  No receipt-derived byte
        or operation counter is admitted without a trusted logical call.
        """

        authority = MetricAuthority.CONTROLLER_OBSERVED
        counted = self.telemetry.increment(
            "context_mode_calls_failed" if failed else "context_mode_calls_completed",
            authority=authority,
            idempotency_key=notification_id,
        )
        if classification is ContextCallClassification.RETRIEVAL:
            self.telemetry.increment(
                "context_mode_search_calls",
                authority=authority,
                idempotency_key=notification_id,
            )
        if classification is ContextCallClassification.EXECUTION:
            self.telemetry.increment(
                "context_mode_execute_calls",
                authority=authority,
                idempotency_key=notification_id,
            )
        self.telemetry.increment(
            "context_mode_untrusted_results",
            authority=authority,
            idempotency_key=notification_id,
        )
        self.telemetry.increment(
            "context_mode_provenance_failures",
            authority=authority,
            idempotency_key=notification_id,
        )
        return ContextIntegrationOutcome(
            True,
            ContextOutcomeStatus.HEALTH_VIOLATION
            if health_violation
            else (ContextOutcomeStatus.FAILED if failed else ContextOutcomeStatus.COMPLETED),
            classification=classification,
            logical_key=logical_key,
            trusted=False,
            protocol_issues=tuple(dict.fromkeys(issues)),
            action_counted=counted,
            health_violation=health_violation,
        )

    def _protocol_only_outcome(
        self,
        method: str,
        issues: list[str],
        *,
        classification: ContextCallClassification | None = None,
        action_counted: bool = False,
        health_violation: bool = False,
    ) -> ContextIntegrationOutcome:
        return ContextIntegrationOutcome(
            True,
            ContextOutcomeStatus.HEALTH_VIOLATION if health_violation else (
                ContextOutcomeStatus.STARTED if method == "item/started" else ContextOutcomeStatus.COMPLETED
            ),
            classification=classification,
            protocol_issues=tuple(dict.fromkeys(issues)),
            action_counted=action_counted,
            health_violation=health_violation,
        )


ContextIntegrationFacade = ContextModeIntegration
