"""Pure-Python broker authority/state core.

Process spawning is intentionally outside this module.  A trusted native adapter
must return a verified ``SandboxExecutionAttestation``; without one, the core
cannot create receipts and Context Mode remains fail-closed.
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ._util import (
    ContextModeDataError,
    atomic_write_json,
    canonical_json_bytes,
    load_json_object,
    require_int,
    require_nonempty,
    require_sha256,
)
from .approvals import (
    CapabilityExpectation,
    OneShotCapabilityStore,
    canonical_cwd,
    normalized_arguments_digest,
    ordered_children_digest,
)
from .config import CAPABILITY_REQUIRED_TOOLS, assert_tool_name
from .events import ClientRole
from .provenance import (
    ARGV_DIGEST_KIND,
    MAX_ARG_BYTES,
    MAX_EXCERPT_BYTES,
    MAX_PATH_BYTES,
    BrokerReceipt,
    CommandRecord,
    ResultEnvelope,
    RetrievalRecord,
    redact_text,
)
from .sandbox import SandboxBackend, SandboxLaunchAuthorization, SandboxPolicy, authorize_sandbox_launch
from .session import BindingStore, ContextBinding


BROKER_JOURNAL_SCHEMA_VERSION = 1
MAX_BROKER_JOURNAL_BYTES = 128 * 1024 * 1024


class BrokerError(ContextModeDataError):
    """The broker cannot safely authorize or attest an operation."""


@dataclass(frozen=True)
class BrokerJournalEntry:
    logical_request_digest: str
    arguments_digest: str
    operation_id: str
    receipt_seq: int
    receipt: BrokerReceipt
    result_reference: str

    def __post_init__(self) -> None:
        require_sha256(self.logical_request_digest, "logical_request_digest")
        require_sha256(self.arguments_digest, "arguments_digest")
        require_nonempty(self.operation_id, "operation_id")
        require_int(self.receipt_seq, "receipt_seq", minimum=1)
        require_nonempty(self.result_reference, "result_reference")
        try:
            result_reference_bytes = len(self.result_reference.encode("utf-8"))
        except UnicodeError as exc:
            raise BrokerError("result_reference must be valid UTF-8 text") from exc
        sanitized_reference, changed = redact_text(
            self.result_reference,
            maximum_bytes=MAX_PATH_BYTES,
        )
        if changed or sanitized_reference != self.result_reference or result_reference_bytes > MAX_PATH_BYTES:
            raise BrokerError("result_reference contains unredacted or oversized sensitive data")
        if self.receipt_seq != self.receipt.receipt_seq or self.operation_id != self.receipt.operation_id:
            raise BrokerError("journal entry identity does not match embedded receipt")

    def to_dict(self) -> dict[str, Any]:
        return {
            "logical_request_digest": self.logical_request_digest,
            "arguments_digest": self.arguments_digest,
            "operation_id": self.operation_id,
            "receipt_seq": self.receipt_seq,
            "receipt": self.receipt.to_dict(),
            "result_reference": self.result_reference,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BrokerJournalEntry":
        if frozenset(value) != {
            "logical_request_digest",
            "arguments_digest",
            "operation_id",
            "receipt_seq",
            "receipt",
            "result_reference",
        }:
            raise BrokerError("broker journal entry fields mismatch")
        if not isinstance(value["receipt"], Mapping):
            raise BrokerError("broker journal receipt must be an object")
        try:
            return cls(
                logical_request_digest=value["logical_request_digest"],
                arguments_digest=value["arguments_digest"],
                operation_id=value["operation_id"],
                receipt_seq=value["receipt_seq"],
                receipt=BrokerReceipt.from_dict(value["receipt"]),
                result_reference=value["result_reference"],
            )
        except (TypeError, ContextModeDataError) as exc:
            raise BrokerError(str(exc)) from exc


class BrokerReceiptJournal:
    """Bounded, raw-payload-free terminal receipt journal."""

    def __init__(self, path: Path, *, maximum_entries: int = 100_000):
        self.path = Path(path)
        self.maximum_entries = maximum_entries
        self._entries: dict[str, BrokerJournalEntry] = {}
        self._operation_ids: set[str] = set()
        self._highest_seq = 0
        self._highest_context_event_seq: dict[tuple[str, int], int] = {}
        self._context_event_owners: dict[tuple[str, int, int], str] = {}
        self._lock = threading.RLock()
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        value = load_json_object(self.path, max_bytes=128 * 1024 * 1024)
        if frozenset(value) != {"schema_version", "highest_receipt_seq", "entries"}:
            raise BrokerError("broker receipt journal fields mismatch")
        require_int(value["schema_version"], "schema_version", minimum=1)
        if value["schema_version"] != BROKER_JOURNAL_SCHEMA_VERSION:
            raise BrokerError("unsupported broker receipt journal schema")
        require_int(value["highest_receipt_seq"], "highest_receipt_seq")
        entries = value["entries"]
        if not isinstance(entries, list) or len(entries) > self.maximum_entries:
            raise BrokerError("broker receipt journal entries are invalid or over capacity")
        for raw_entry in entries:
            if not isinstance(raw_entry, Mapping):
                raise BrokerError("broker receipt journal entry must be an object")
            entry = BrokerJournalEntry.from_dict(raw_entry)
            if (
                entry.logical_request_digest in self._entries
                or entry.operation_id in self._operation_ids
                or entry.receipt_seq != self._highest_seq + 1
            ):
                raise BrokerError("broker receipt journal has replayed/out-of-order identity")
            self._require_next_context_event(entry)
            self._entries[entry.logical_request_digest] = entry
            self._operation_ids.add(entry.operation_id)
            self._highest_seq = entry.receipt_seq
            self._record_context_event(entry)
        if self._highest_seq != value["highest_receipt_seq"]:
            raise BrokerError("broker receipt journal high-water mark mismatch")

    def _persist(self) -> None:
        entries = sorted(self._entries.values(), key=lambda item: item.receipt_seq)
        payload = {
            "schema_version": BROKER_JOURNAL_SCHEMA_VERSION,
            "highest_receipt_seq": self._highest_seq,
            "entries": [entry.to_dict() for entry in entries],
        }
        if len(canonical_json_bytes(payload)) > MAX_BROKER_JOURNAL_BYTES:
            raise BrokerError("broker receipt journal exceeds its canonical byte limit")
        atomic_write_json(self.path, payload, mode=0o600)

    def lookup(self, logical_request_digest: str, arguments_digest: str) -> BrokerJournalEntry | None:
        with self._lock:
            entry = self._entries.get(logical_request_digest)
            if entry is not None and entry.arguments_digest != arguments_digest:
                raise BrokerError("transport retry reused logical request identity with different arguments")
            return entry

    def next_sequence(self) -> int:
        with self._lock:
            return self._highest_seq + 1

    @staticmethod
    def _context_event_scope(entry: BrokerJournalEntry) -> tuple[str, int]:
        receipt = entry.receipt
        return receipt.context_session_id, receipt.context_state_epoch

    def _require_next_context_event(self, entry: BrokerJournalEntry) -> None:
        receipt = entry.receipt
        scope = self._context_event_scope(entry)
        event_seq = receipt.context_event_seq
        expected = self._highest_context_event_seq.get(scope, 0) + 1
        owner_key = (*scope, event_seq)
        owner = self._context_event_owners.get(owner_key)
        if owner is not None and owner != entry.operation_id:
            raise BrokerError("Context event sequence is already owned by another operation")
        if event_seq != expected:
            raise BrokerError(
                "Context event sequence must be contiguous within its session/state epoch"
            )

    def _record_context_event(self, entry: BrokerJournalEntry) -> None:
        receipt = entry.receipt
        scope = self._context_event_scope(entry)
        self._highest_context_event_seq[scope] = receipt.context_event_seq
        self._context_event_owners[(*scope, receipt.context_event_seq)] = entry.operation_id

    def commit(self, entry: BrokerJournalEntry) -> None:
        """Durably consume terminal identity before response is made visible."""

        with self._lock:
            existing = self._entries.get(entry.logical_request_digest)
            if existing is not None:
                if existing != entry:
                    raise BrokerError("conflicting terminal result for logical request")
                return
            if len(self._entries) >= self.maximum_entries:
                raise BrokerError("broker receipt journal capacity exceeded; refusing fail-open eviction")
            if entry.operation_id in self._operation_ids:
                raise BrokerError("broker operation_id already committed")
            if entry.receipt_seq != self._highest_seq + 1:
                raise BrokerError("broker receipt sequence must be contiguous")
            self._require_next_context_event(entry)
            self._entries[entry.logical_request_digest] = entry
            self._operation_ids.add(entry.operation_id)
            self._highest_seq = entry.receipt_seq
            self._record_context_event(entry)
            try:
                self._persist()
            except BaseException:
                del self._entries[entry.logical_request_digest]
                self._operation_ids.remove(entry.operation_id)
                self._highest_seq -= 1
                receipt = entry.receipt
                scope = self._context_event_scope(entry)
                self._context_event_owners.pop((*scope, receipt.context_event_seq), None)
                previous = receipt.context_event_seq - 1
                if previous:
                    self._highest_context_event_seq[scope] = previous
                else:
                    self._highest_context_event_seq.pop(scope, None)
                raise


@dataclass(frozen=True)
class PendingBrokerCall:
    operation_id: str
    logical_request_digest: str
    mcp_request_id: int | str
    tool_name: str
    arguments_digest: str
    canonical_cwd: str
    binding: ContextBinding
    process_epoch: int
    capability_id: str | None
    launch_authorization: SandboxLaunchAuthorization


@dataclass(frozen=True)
class TerminalReplay:
    entry: BrokerJournalEntry


@dataclass(frozen=True)
class SandboxExecutionAttestation:
    """Terminal facts returned only by the trusted native process-tree adapter."""

    operation_id: str
    backend_verification_id: str
    policy_digest: str
    process_tree_reaped: bool
    result_digest: str
    result_reference: str
    context_event_seq: int
    duration_ms: int
    source_bytes: int | None = None
    returned_bytes: int | None = None
    indexed_bytes: int | None = None
    commands: tuple[CommandRecord, ...] = ()
    retrieval: tuple[RetrievalRecord, ...] = ()
    changed_paths: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        require_nonempty(self.operation_id, "operation_id")
        require_nonempty(self.backend_verification_id, "backend_verification_id")
        require_sha256(self.policy_digest, "policy_digest")
        require_sha256(self.result_digest, "result_digest")
        require_nonempty(self.result_reference, "result_reference")
        if not isinstance(self.process_tree_reaped, bool):
            raise BrokerError("process_tree_reaped must be boolean")
        require_int(self.context_event_seq, "context_event_seq", minimum=1)
        require_int(self.duration_ms, "duration_ms")
        for name in ("source_bytes", "returned_bytes", "indexed_bytes"):
            value = getattr(self, name)
            if value is not None:
                require_int(value, name)
        if any(not isinstance(command, CommandRecord) for command in self.commands):
            raise BrokerError("sandbox attestation commands must be parsed CommandRecord values")
        if any(not isinstance(record, RetrievalRecord) for record in self.retrieval):
            raise BrokerError("sandbox attestation retrieval must be parsed RetrievalRecord values")
        if self.changed_paths is not None and not isinstance(self.changed_paths, Mapping):
            raise BrokerError("sandbox attestation changed_paths must be an object")


@dataclass(frozen=True)
class BrokerTerminal:
    receipt: BrokerReceipt
    envelope: ResultEnvelope
    result_reference: str


class BrokerCore:
    """Approval + binding + durable-receipt core; it never invokes subprocesses."""

    def __init__(
        self,
        *,
        backend: SandboxBackend,
        policy: SandboxPolicy,
        capability_store: OneShotCapabilityStore,
        receipt_journal: BrokerReceiptJournal,
        binding_store: BindingStore,
    ) -> None:
        backend.assert_verified()
        self.backend = backend
        self.policy = policy
        self.launch_authorization = authorize_sandbox_launch(policy, backend)
        self.capability_store = capability_store
        self.receipt_journal = receipt_journal
        if not isinstance(binding_store, BindingStore):
            raise BrokerError("broker requires the authoritative Context BindingStore")
        self.binding_store = binding_store
        self._active_operations: set[str] = set()
        self._tainted_epochs: set[tuple[str, str, int]] = set()
        self._lock = threading.RLock()

    @staticmethod
    def _epoch_identity(binding: ContextBinding) -> tuple[str, str, int]:
        return (
            binding.stable.workspace_id,
            binding.stable.context_session_id,
            binding.lifecycle.context_state_epoch,
        )

    def _require_authoritative_binding(self, supplied: ContextBinding) -> ContextBinding:
        authoritative = self.binding_store.load()
        if supplied != authoritative:
            raise BrokerError("broker call binding is stale or not controller-authoritative")
        if self._epoch_identity(authoritative) in self._tainted_epochs:
            raise BrokerError("active Context Mode epoch is tainted and requires rebuild")
        return authoritative

    def begin_call(
        self,
        *,
        binding: ContextBinding,
        process_epoch: int,
        mcp_request_id: int | str,
        logical_request_digest: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        cwd: Path | str,
        capability_id: str | None = None,
        ordered_batch_children: Sequence[Mapping[str, Any]] | None = None,
    ) -> PendingBrokerCall | TerminalReplay:
        assert_tool_name(tool_name)
        require_sha256(logical_request_digest, "logical_request_digest")
        binding = self._require_authoritative_binding(binding)
        lifecycle = binding.lifecycle
        if lifecycle.sandbox_policy_digest != self.policy.digest:
            raise BrokerError("active binding sandbox policy digest mismatch")
        if process_epoch != lifecycle.coder_process_epoch:
            raise BrokerError("broker call belongs to a stale coder process epoch")
        if lifecycle.provider_thread_id is None:
            raise BrokerError("ordinary MCP calls are forbidden before SessionStart thread claim")
        arguments_digest = normalized_arguments_digest(arguments)
        replay = self.receipt_journal.lookup(logical_request_digest, arguments_digest)
        if replay is not None:
            return TerminalReplay(replay)
        cwd_value = canonical_cwd(cwd, binding.stable.workspace_path)
        if tool_name in CAPABILITY_REQUIRED_TOOLS:
            if capability_id is None:
                raise BrokerError(f"{tool_name} requires a one-shot approval capability")
            children_digest = None
            if tool_name == "ctx_batch_execute":
                argument_children = arguments.get("commands")
                if not isinstance(argument_children, list) or not all(
                    isinstance(child, Mapping) for child in argument_children
                ):
                    raise BrokerError("ctx_batch_execute arguments require an ordered commands array")
                children_digest = ordered_children_digest(argument_children)
                if (
                    ordered_batch_children is not None
                    and ordered_children_digest(ordered_batch_children) != children_digest
                ):
                    raise BrokerError(
                        "ctx_batch_execute caller-supplied children differ from exact approved arguments"
                    )
            self.capability_store.consume(
                CapabilityExpectation(
                    capability_id=capability_id,
                    process_epoch=process_epoch,
                    tool_name=tool_name,
                    arguments_digest=arguments_digest,
                    canonical_cwd=cwd_value,
                    request_digest=logical_request_digest,
                    ordered_children_digest=children_digest,
                ),
                active_binding=binding,
            )
        elif capability_id is not None:
            raise BrokerError("auto-approved tool call must not carry an execution capability")
        operation_id = secrets.token_urlsafe(24)
        with self._lock:
            while operation_id in self._active_operations:
                operation_id = secrets.token_urlsafe(24)
            self._active_operations.add(operation_id)
        return PendingBrokerCall(
            operation_id=operation_id,
            logical_request_digest=logical_request_digest,
            mcp_request_id=mcp_request_id,
            tool_name=tool_name,
            arguments_digest=arguments_digest,
            canonical_cwd=cwd_value,
            binding=binding,
            process_epoch=process_epoch,
            capability_id=capability_id,
            launch_authorization=self.launch_authorization,
        )

    def complete_call(
        self,
        call: PendingBrokerCall,
        attestation: SandboxExecutionAttestation,
    ) -> BrokerTerminal:
        """Create a receipt only after verified terminal reap and durable commit."""

        with self._lock:
            if call.operation_id not in self._active_operations:
                raise BrokerError("broker operation is not active or already terminal")
            if attestation.operation_id != call.operation_id:
                raise BrokerError("sandbox attestation operation mismatch")
            if attestation.backend_verification_id != self.launch_authorization.backend_verification_id:
                raise BrokerError("sandbox attestation backend verification mismatch")
            if attestation.policy_digest != self.launch_authorization.policy_digest:
                raise BrokerError("sandbox attestation policy mismatch")
            if not attestation.process_tree_reaped:
                raise BrokerError("cannot receipt operation before command tree is reaped")
            authoritative = self.binding_store.load()
            if call.binding != authoritative:
                # The signed adapter says the late tree is terminal/reaped, but
                # its mutations can no longer be attributed to the active
                # binding.  Quarantine that physical epoch and refuse a receipt.
                self._tainted_epochs.add(self._epoch_identity(call.binding))
                self._active_operations.remove(call.operation_id)
                raise BrokerError(
                    "late Context Mode operation crossed a binding transition; epoch tainted"
                )
            if self._epoch_identity(authoritative) in self._tainted_epochs:
                self._active_operations.remove(call.operation_id)
                raise BrokerError("active Context Mode epoch is tainted and requires rebuild")
            for command in attestation.commands:
                if command.argv_digest_kind != ARGV_DIGEST_KIND:
                    raise BrokerError("native attestation argv digest is not run-keyed")
                for argument in command.redacted_argv:
                    sanitized, changed = redact_text(argument, maximum_bytes=MAX_ARG_BYTES)
                    if changed or sanitized != argument:
                        raise BrokerError("native attestation contains unredacted or oversized argv")
                for excerpt in (command.stdout_excerpt, command.stderr_excerpt):
                    sanitized, changed = redact_text(excerpt, maximum_bytes=MAX_EXCERPT_BYTES)
                    if changed or sanitized != excerpt:
                        raise BrokerError("native attestation contains an unredacted or oversized excerpt")
                if command.relative_cwd != ".":
                    sanitized, changed = redact_text(
                        command.relative_cwd,
                        maximum_bytes=MAX_PATH_BYTES,
                    )
                    if changed or sanitized != command.relative_cwd:
                        raise BrokerError("native attestation contains an unsafe command cwd")
            for record in attestation.retrieval:
                sanitized, changed = redact_text(record.relative_path, maximum_bytes=MAX_PATH_BYTES)
                if changed or sanitized != record.relative_path:
                    raise BrokerError("native attestation contains an unsafe retrieval path")
            for path in (attestation.changed_paths or {}):
                sanitized, changed = redact_text(path, maximum_bytes=MAX_PATH_BYTES)
                if changed or sanitized != path:
                    raise BrokerError("native attestation contains an unsafe changed path")
            require_sha256(attestation.result_digest, "result_digest")
            stable, lifecycle = call.binding.stable, call.binding.lifecycle
            receipt = BrokerReceipt(
                receipt_seq=self.receipt_journal.next_sequence(),
                role=ClientRole.CODER,
                app_server_instance_id=lifecycle.app_server_instance_id,
                process_epoch=call.process_epoch,
                run_id=stable.run_id,
                workspace_id=stable.workspace_id,
                context_session_id=stable.context_session_id,
                context_state_epoch=lifecycle.context_state_epoch,
                binding_version=lifecycle.binding_version,
                coder_generation=lifecycle.coder_generation,
                generation_lease_id=lifecycle.generation_lease_id,
                mcp_request_id=call.mcp_request_id,
                tool_name=call.tool_name,
                arguments_digest=call.arguments_digest,
                operation_id=call.operation_id,
                result_digest=attestation.result_digest,
                sandbox_backend=self.backend.name.value,
                sandbox_policy_digest=self.policy.digest,
                capability_id=call.capability_id,
                context_event_seq=attestation.context_event_seq,
                duration_ms=attestation.duration_ms,
                source_bytes=attestation.source_bytes,
                returned_bytes=attestation.returned_bytes,
                indexed_bytes=attestation.indexed_bytes,
                commands=attestation.commands,
                retrieval=attestation.retrieval,
                changed_paths=attestation.changed_paths,
            )
            entry = BrokerJournalEntry(
                logical_request_digest=call.logical_request_digest,
                arguments_digest=call.arguments_digest,
                operation_id=call.operation_id,
                receipt_seq=receipt.receipt_seq,
                receipt=receipt,
                result_reference=require_nonempty(attestation.result_reference, "result_reference"),
            )
            # atomic write + fsync happens here, before a terminal envelope exists.
            self.receipt_journal.commit(entry)
            envelope = ResultEnvelope(
                broker_receipt_seq=receipt.receipt_seq,
                broker_receipt_digest=receipt.digest,
                operation_id=receipt.operation_id,
                tool_name=receipt.tool_name,
                run_id=receipt.run_id,
                workspace_id=receipt.workspace_id,
                context_session_id=receipt.context_session_id,
                context_state_epoch=receipt.context_state_epoch,
                binding_version=receipt.binding_version,
                coder_generation=receipt.coder_generation,
                generation_lease_id=receipt.generation_lease_id,
                mcp_request_id=receipt.mcp_request_id,
                arguments_digest=receipt.arguments_digest,
                capability_id=receipt.capability_id,
                result_digest=receipt.result_digest,
                sandbox_backend=receipt.sandbox_backend,
                sandbox_policy_digest=receipt.sandbox_policy_digest,
            )
            self._active_operations.remove(call.operation_id)
            return BrokerTerminal(receipt, envelope, entry.result_reference)

    def fail_call(self, call: PendingBrokerCall) -> None:
        """Release an active operation after the native adapter reports no mutation."""

        with self._lock:
            self._active_operations.discard(call.operation_id)

    @property
    def active_operation_count(self) -> int:
        with self._lock:
            return len(self._active_operations)

    @property
    def tainted_epochs(self) -> frozenset[tuple[str, str, int]]:
        with self._lock:
            return frozenset(self._tainted_epochs)
