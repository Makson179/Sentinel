"""Broker receipt matching, replay protection, redaction, and evidence shaping."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from ._util import (
    ContextModeDataError,
    atomic_write_json,
    canonical_json_bytes,
    digest_json,
    load_json_object,
    require_int,
    require_nonempty,
    require_sha256,
    strict_object,
)
from .config import ALLOWED_TOOL_SET, CONTEXT_SERVER_NAME, EXECUTION_TOOLS, assert_tool_name
from .events import ClientRole
from .session import ContextBinding


PROVENANCE_SCHEMA_VERSION = 1
REPLAY_STATE_SCHEMA_VERSION = 1
MAX_EXCERPT_BYTES = 4 * 1024
MAX_EVENT_BYTES = 32 * 1024
MAX_MODEL_RESULT_BYTES = 64 * 1024
MAX_MODEL_RESULT_ESTIMATED_TOKENS = 8_000
MAX_STREAM_SPOOL_BYTES = 8 * 1024 * 1024
MAX_ARG_BYTES = 8 * 1024
MAX_ARGV_BYTES = 64 * 1024
MAX_ARGV_ITEMS = 256
MAX_PATH_BYTES = 4 * 1024
MAX_RETRIEVAL_RANGES = 4 * 1024
MAX_COMMAND_RECORDS = 256
MAX_RETRIEVAL_RECORDS = 2 * 1024
MAX_CHANGED_PATHS = 4 * 1024
MAX_RECEIPT_BYTES = 4 * 1024 * 1024
NATIVE_RUNNER_IDENTITY = "bello-native-runner-v1"
ARGV_DIGEST_KIND = "run-hmac-sha256-v1"


class ProvenanceError(ContextModeDataError):
    """A result cannot be trusted as broker-attested provenance."""


class ReceiptReplayError(ProvenanceError):
    """Receipt sequence or operation identity has already been observed."""


def _request_id(value: Any, field: str = "mcp_request_id") -> int | str:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ProvenanceError(f"{field} must be a JSON-RPC integer or string")
    if isinstance(value, str):
        require_nonempty(value, field)
    return value


def _utf8_size(value: str, field: str) -> int:
    if not isinstance(value, str):
        raise ProvenanceError(f"{field} must be a string")
    try:
        return len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise ProvenanceError(f"{field} must be valid UTF-8 text") from exc


def _require_redacted_text(value: str, field: str, *, maximum_bytes: int) -> None:
    size = _utf8_size(value, field)
    if size > maximum_bytes:
        raise ProvenanceError(f"{field} exceeds the {maximum_bytes}-byte limit")
    sanitized, changed = redact_text(value, maximum_bytes=maximum_bytes)
    if changed or sanitized != value:
        raise ProvenanceError(f"{field} contains unredacted or oversized sensitive data")


def _relative_path(value: str, field: str) -> str:
    require_nonempty(value, field)
    _require_redacted_text(value, field, maximum_bytes=MAX_PATH_BYTES)
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ProvenanceError(f"{field} must be a canonical workspace-relative path")
    return value


def _relative_cwd(value: str) -> str:
    if value == ".":
        return value
    return _relative_path(value, "relative_cwd")


@dataclass(frozen=True)
class CommandRecord:
    runner_identity: str
    redacted_argv: tuple[str, ...]
    argv_digest: str
    relative_cwd: str
    start_order: int
    duration_ms: int
    exit_code: int | None
    signal: int | None
    timed_out: bool
    stdout_bytes: int
    stderr_bytes: int
    stdout_digest: str
    stderr_digest: str
    stdout_complete: bool
    stderr_complete: bool
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    argv_digest_kind: str = ARGV_DIGEST_KIND

    def __post_init__(self) -> None:
        if self.runner_identity != NATIVE_RUNNER_IDENTITY:
            raise ProvenanceError("runner_identity is not the authenticated native runner")
        if not self.redacted_argv or any(not isinstance(arg, str) for arg in self.redacted_argv):
            raise ProvenanceError("redacted_argv must be a non-empty string tuple")
        if len(self.redacted_argv) > MAX_ARGV_ITEMS:
            raise ProvenanceError("redacted_argv exceeds the item-count limit")
        argv_bytes = 0
        for index, arg in enumerate(self.redacted_argv):
            field = f"redacted_argv[{index}]"
            _require_redacted_text(arg, field, maximum_bytes=MAX_ARG_BYTES)
            argv_bytes += _utf8_size(arg, field)
        if argv_bytes > MAX_ARGV_BYTES:
            raise ProvenanceError("redacted_argv exceeds the aggregate byte limit")
        require_sha256(self.argv_digest, "argv_digest")
        if self.argv_digest_kind != ARGV_DIGEST_KIND:
            raise ProvenanceError("argv_digest_kind must identify the run-keyed HMAC scheme")
        _relative_cwd(self.relative_cwd)
        require_int(self.start_order, "start_order")
        require_int(self.duration_ms, "duration_ms")
        for name in ("stdout_bytes", "stderr_bytes"):
            require_int(getattr(self, name), name)
            if getattr(self, name) > MAX_STREAM_SPOOL_BYTES:
                raise ProvenanceError(f"{name} exceeds the broker hard spool ceiling")
        for name in ("stdout_digest", "stderr_digest"):
            require_sha256(getattr(self, name), name)
        for name in ("timed_out", "stdout_complete", "stderr_complete"):
            if not isinstance(getattr(self, name), bool):
                raise ProvenanceError(f"{name} must be boolean")
        terminal_count = int(self.exit_code is not None) + int(self.signal is not None) + int(self.timed_out)
        if terminal_count != 1:
            raise ProvenanceError("command requires exactly one terminal outcome: exit, signal, or timeout")
        if self.exit_code is not None and (isinstance(self.exit_code, bool) or not isinstance(self.exit_code, int)):
            raise ProvenanceError("exit_code must be an integer or null")
        if self.signal is not None:
            require_int(self.signal, "signal", minimum=1)
        for name in ("stdout_excerpt", "stderr_excerpt"):
            excerpt = getattr(self, name)
            _require_redacted_text(excerpt, name, maximum_bytes=MAX_EXCERPT_BYTES)

    def to_dict(self) -> dict[str, Any]:
        return {
            "runner_identity": self.runner_identity,
            "redacted_argv": list(self.redacted_argv),
            "argv_digest": self.argv_digest,
            "argv_digest_kind": self.argv_digest_kind,
            "relative_cwd": self.relative_cwd,
            "start_order": self.start_order,
            "duration_ms": self.duration_ms,
            "exit_code": self.exit_code,
            "signal": self.signal,
            "timed_out": self.timed_out,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "stdout_digest": self.stdout_digest,
            "stderr_digest": self.stderr_digest,
            "stdout_complete": self.stdout_complete,
            "stderr_complete": self.stderr_complete,
            "stdout_excerpt": self.stdout_excerpt,
            "stderr_excerpt": self.stderr_excerpt,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CommandRecord":
        fields = frozenset(cls.__dataclass_fields__)
        strict_object(value, required=fields, name="command provenance record")
        data = dict(value)
        argv = data["redacted_argv"]
        if not isinstance(argv, list):
            raise ProvenanceError("redacted_argv must be an array")
        data["redacted_argv"] = tuple(argv)
        try:
            return cls(**data)
        except (TypeError, ContextModeDataError) as exc:
            raise ProvenanceError(str(exc)) from exc


@dataclass(frozen=True)
class RetrievalRecord:
    source_kind: str
    relative_path: str
    content_hash: str
    indexed_revision: int
    current_revision: int
    ranges: tuple[tuple[int, int], ...]
    source_bytes: int
    returned_bytes: int
    stale: bool

    def __post_init__(self) -> None:
        require_nonempty(self.source_kind, "source_kind")
        _require_redacted_text(self.source_kind, "source_kind", maximum_bytes=256)
        _relative_path(self.relative_path, "relative_path")
        require_sha256(self.content_hash, "content_hash")
        require_int(self.indexed_revision, "indexed_revision")
        require_int(self.current_revision, "current_revision")
        require_int(self.source_bytes, "source_bytes")
        require_int(self.returned_bytes, "returned_bytes")
        if not isinstance(self.stale, bool):
            raise ProvenanceError("stale must be boolean")
        if not self.ranges:
            raise ProvenanceError("retrieval provenance requires at least one returned range")
        if len(self.ranges) > MAX_RETRIEVAL_RANGES:
            raise ProvenanceError("retrieval provenance exceeds the range-count limit")
        if self.returned_bytes <= 0:
            raise ProvenanceError("retrieval provenance returned_bytes must be positive")
        if self.returned_bytes > self.source_bytes:
            raise ProvenanceError("retrieval returned_bytes exceeds source_bytes")
        for start, end in self.ranges:
            require_int(start, "range start")
            require_int(end, "range end", minimum=1)
            if end <= start:
                raise ProvenanceError("retrieval range end must exceed start")
            if end > self.source_bytes:
                raise ProvenanceError("retrieval range exceeds source_bytes")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_kind": self.source_kind,
            "relative_path": self.relative_path,
            "content_hash": self.content_hash,
            "indexed_revision": self.indexed_revision,
            "current_revision": self.current_revision,
            "ranges": [list(item) for item in self.ranges],
            "source_bytes": self.source_bytes,
            "returned_bytes": self.returned_bytes,
            "stale": self.stale,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RetrievalRecord":
        strict_object(value, required=frozenset(cls.__dataclass_fields__), name="retrieval provenance record")
        data = dict(value)
        raw_ranges = data["ranges"]
        if not isinstance(raw_ranges, list) or any(
            not isinstance(item, list) or len(item) != 2 for item in raw_ranges
        ):
            raise ProvenanceError("retrieval ranges must be pairs")
        data["ranges"] = tuple((item[0], item[1]) for item in raw_ranges)
        try:
            return cls(**data)
        except (TypeError, ContextModeDataError) as exc:
            raise ProvenanceError(str(exc)) from exc


@dataclass(frozen=True)
class BrokerReceipt:
    receipt_seq: int
    role: ClientRole
    app_server_instance_id: str
    process_epoch: int
    run_id: str
    workspace_id: str
    context_session_id: str
    context_state_epoch: int
    binding_version: int
    coder_generation: int
    generation_lease_id: str
    mcp_request_id: int | str
    tool_name: str
    arguments_digest: str
    operation_id: str
    result_digest: str
    sandbox_backend: str
    sandbox_policy_digest: str
    capability_id: str | None
    context_event_seq: int
    duration_ms: int
    source_bytes: int | None
    returned_bytes: int | None
    indexed_bytes: int | None
    commands: tuple[CommandRecord, ...] = ()
    retrieval: tuple[RetrievalRecord, ...] = ()
    changed_paths: Mapping[str, str] | None = None
    schema_version: int = PROVENANCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        require_int(self.schema_version, "schema_version", minimum=1)
        if self.schema_version != PROVENANCE_SCHEMA_VERSION:
            raise ProvenanceError("unsupported broker receipt schema")
        require_int(self.receipt_seq, "receipt_seq", minimum=1)
        if ClientRole(self.role) is not ClientRole.CODER:
            raise ProvenanceError("Context Mode receipt role must be coder")
        for name in (
            "app_server_instance_id",
            "run_id",
            "workspace_id",
            "context_session_id",
            "generation_lease_id",
            "operation_id",
            "sandbox_backend",
        ):
            require_nonempty(getattr(self, name), name)
        for name, minimum in (
            ("process_epoch", 0),
            ("context_state_epoch", 0),
            ("binding_version", 1),
            ("coder_generation", 0),
            ("context_event_seq", 1),
            ("duration_ms", 0),
        ):
            require_int(getattr(self, name), name, minimum=minimum)
        _request_id(self.mcp_request_id)
        assert_tool_name(self.tool_name)
        for name in ("arguments_digest", "result_digest", "sandbox_policy_digest"):
            require_sha256(getattr(self, name), name)
        if self.capability_id is not None:
            require_nonempty(self.capability_id, "capability_id")
        if self.tool_name in EXECUTION_TOOLS | {"ctx_purge"} and self.capability_id is None:
            raise ProvenanceError(f"receipt for {self.tool_name} lacks one-shot capability identity")
        if self.tool_name not in EXECUTION_TOOLS and self.commands:
            raise ProvenanceError("non-execution tool receipt contains command provenance")
        if self.tool_name != "ctx_search" and self.retrieval:
            raise ProvenanceError("non-search receipt contains retrieval provenance")
        if any(not isinstance(command, CommandRecord) for command in self.commands):
            raise ProvenanceError("receipt commands must contain parsed command records")
        if any(not isinstance(record, RetrievalRecord) for record in self.retrieval):
            raise ProvenanceError("receipt retrieval must contain parsed retrieval records")
        if len(self.commands) > MAX_COMMAND_RECORDS:
            raise ProvenanceError("receipt exceeds the command-record count limit")
        if len(self.retrieval) > MAX_RETRIEVAL_RECORDS:
            raise ProvenanceError("receipt exceeds the retrieval-record count limit")
        for name in ("source_bytes", "returned_bytes", "indexed_bytes"):
            value = getattr(self, name)
            if value is not None:
                require_int(value, name)
        orders = [command.start_order for command in self.commands]
        if orders != list(range(len(orders))):
            raise ProvenanceError("command records require contiguous ordered start_order values")
        changed = self.changed_paths or {}
        if not isinstance(changed, Mapping):
            raise ProvenanceError("changed_paths must be an object")
        if len(changed) > MAX_CHANGED_PATHS:
            raise ProvenanceError("receipt exceeds the changed-path count limit")
        for path, content_hash in changed.items():
            if not isinstance(path, str):
                raise ProvenanceError("changed path keys must be strings")
            _relative_path(path, "changed path")
            require_sha256(content_hash, f"changed_paths[{path!r}]")
        object.__setattr__(self, "changed_paths", dict(sorted(changed.items())))
        try:
            encoded_bytes = len(canonical_json_bytes(self.to_dict()))
        except (TypeError, UnicodeError, ContextModeDataError) as exc:
            raise ProvenanceError("receipt is not strict canonical UTF-8 JSON") from exc
        if encoded_bytes > MAX_RECEIPT_BYTES:
            raise ProvenanceError("receipt exceeds the canonical byte limit")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "receipt_seq": self.receipt_seq,
            "role": ClientRole(self.role).value,
            "app_server_instance_id": self.app_server_instance_id,
            "process_epoch": self.process_epoch,
            "run_id": self.run_id,
            "workspace_id": self.workspace_id,
            "context_session_id": self.context_session_id,
            "context_state_epoch": self.context_state_epoch,
            "binding_version": self.binding_version,
            "coder_generation": self.coder_generation,
            "generation_lease_id": self.generation_lease_id,
            "mcp_request_id": self.mcp_request_id,
            "tool_name": self.tool_name,
            "arguments_digest": self.arguments_digest,
            "operation_id": self.operation_id,
            "result_digest": self.result_digest,
            "sandbox_backend": self.sandbox_backend,
            "sandbox_policy_digest": self.sandbox_policy_digest,
            "capability_id": self.capability_id,
            "context_event_seq": self.context_event_seq,
            "duration_ms": self.duration_ms,
            "source_bytes": self.source_bytes,
            "returned_bytes": self.returned_bytes,
            "indexed_bytes": self.indexed_bytes,
            "commands": [command.to_dict() for command in self.commands],
            "retrieval": [record.to_dict() for record in self.retrieval],
            "changed_paths": dict(self.changed_paths or {}),
        }

    @property
    def digest(self) -> str:
        return digest_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BrokerReceipt":
        required = frozenset(cls.__dataclass_fields__)
        strict_object(value, required=required, name="broker receipt")
        data = dict(value)
        require_int(data["schema_version"], "schema_version", minimum=1)
        if data["schema_version"] != PROVENANCE_SCHEMA_VERSION:
            raise ProvenanceError("unsupported broker receipt schema")
        data.pop("schema_version")
        if not isinstance(data["commands"], list) or not isinstance(data["retrieval"], list):
            raise ProvenanceError("receipt commands/retrieval must be arrays")
        if not isinstance(data["changed_paths"], Mapping):
            raise ProvenanceError("receipt changed_paths must be an object")
        try:
            data["role"] = ClientRole(data["role"])
            data["commands"] = tuple(CommandRecord.from_dict(item) for item in data["commands"])
            data["retrieval"] = tuple(RetrievalRecord.from_dict(item) for item in data["retrieval"])
            return cls(**data)
        except (TypeError, ValueError, ContextModeDataError) as exc:
            raise ProvenanceError(str(exc)) from exc


@dataclass(frozen=True)
class ResultEnvelope:
    broker_receipt_seq: int
    broker_receipt_digest: str
    operation_id: str
    tool_name: str
    run_id: str
    workspace_id: str
    context_session_id: str
    context_state_epoch: int
    binding_version: int
    coder_generation: int
    generation_lease_id: str
    mcp_request_id: int | str
    arguments_digest: str
    capability_id: str | None
    result_digest: str
    sandbox_backend: str
    sandbox_policy_digest: str
    schema_version: int = PROVENANCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        require_int(self.schema_version, "schema_version", minimum=1)
        if self.schema_version != PROVENANCE_SCHEMA_VERSION:
            raise ProvenanceError("unsupported result envelope schema")
        require_int(self.broker_receipt_seq, "broker_receipt_seq", minimum=1)
        require_sha256(self.broker_receipt_digest, "broker_receipt_digest")
        for name in (
            "operation_id",
            "run_id",
            "workspace_id",
            "context_session_id",
            "generation_lease_id",
            "sandbox_backend",
        ):
            require_nonempty(getattr(self, name), name)
        assert_tool_name(self.tool_name)
        for name in ("context_state_epoch", "coder_generation"):
            require_int(getattr(self, name), name)
        require_int(self.binding_version, "binding_version", minimum=1)
        _request_id(self.mcp_request_id)
        for name in ("arguments_digest", "result_digest", "sandbox_policy_digest"):
            require_sha256(getattr(self, name), name)
        if self.capability_id is not None:
            require_nonempty(self.capability_id, "capability_id")

    def to_dict(self) -> dict[str, Any]:
        return {field: getattr(self, field) for field in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResultEnvelope":
        strict_object(value, required=frozenset(cls.__dataclass_fields__), name="Context Mode result envelope")
        try:
            return cls(**value)  # type: ignore[arg-type]
        except (TypeError, ContextModeDataError) as exc:
            raise ProvenanceError(str(exc)) from exc

    @classmethod
    def from_result(cls, result: Mapping[str, Any]) -> "ResultEnvelope":
        if frozenset(result) - {"content", "structuredContent", "isError", "_meta"}:
            raise ProvenanceError("MCP result contains fields outside the pinned CallToolResult schema")
        if "isError" in result and not isinstance(result["isError"], bool):
            raise ProvenanceError("MCP result isError must be boolean")
        # Codex app-server 0.146 materializes an absent CallToolResult `_meta`
        # as JSON null in item/completed notifications. Treat null exactly as
        # absence while still rejecting every non-object, non-null value.
        if (
            "_meta" in result
            and result["_meta"] is not None
            and not isinstance(result["_meta"], Mapping)
        ):
            raise ProvenanceError("MCP result _meta must be an object")
        content = result.get("content")
        if not isinstance(content, list) or not content or len(content) > 256:
            raise ProvenanceError("MCP result content must be a bounded non-empty array")
        for block in content:
            if not isinstance(block, Mapping) or frozenset(block) != {"type", "text"}:
                raise ProvenanceError(
                    "Context Mode MCP content must contain exact text blocks"
                )
            if block.get("type") != "text" or not isinstance(block.get("text"), str):
                raise ProvenanceError(
                    "Context Mode MCP text blocks require string text"
                )
            try:
                block["text"].encode("utf-8")
            except UnicodeError as exc:
                raise ProvenanceError("Context Mode MCP text must be valid UTF-8") from exc
        structured = result.get("structuredContent")
        if not isinstance(structured, Mapping):
            raise ProvenanceError("MCP result has no structuredContent object")
        envelope = structured.get("belloContextMode")
        if not isinstance(envelope, Mapping):
            raise ProvenanceError("MCP result has no belloContextMode envelope")
        return cls.from_dict(envelope)


@dataclass(frozen=True)
class ExpectedProvenance:
    """Receipt creation scope for one logical call.

    ``binding`` and the transport fields identify the process in which the
    broker began the call.  They intentionally do not describe a later
    app-server transport that merely replays the terminal notification after a
    proven process recovery.
    """

    binding: ContextBinding
    app_server_instance_id: str
    process_epoch: int
    mcp_request_id: int | str
    tool_name: str
    arguments_digest: str
    result_digest: str
    capability_id: str | None = None

    def __post_init__(self) -> None:
        require_nonempty(self.app_server_instance_id, "app_server_instance_id")
        require_int(self.process_epoch, "process_epoch")
        _request_id(self.mcp_request_id)
        assert_tool_name(self.tool_name)
        require_sha256(self.arguments_digest, "arguments_digest")
        require_sha256(self.result_digest, "result_digest")

    @classmethod
    def for_started_call(
        cls,
        *,
        binding: ContextBinding,
        app_server_instance_id: str,
        process_epoch: int,
        mcp_request_id: int | str,
        tool_name: str,
        arguments_digest: str,
        result_digest: str,
        capability_id: str | None = None,
    ) -> "ExpectedProvenance":
        """Make the original broker scope explicit at recovery call sites."""

        return cls(
            binding=binding,
            app_server_instance_id=app_server_instance_id,
            process_epoch=process_epoch,
            mcp_request_id=mcp_request_id,
            tool_name=tool_name,
            arguments_digest=arguments_digest,
            result_digest=result_digest,
            capability_id=capability_id,
        )


@dataclass(frozen=True)
class ValidatedProvenance:
    envelope: ResultEnvelope
    receipt: BrokerReceipt


class ReceiptReplayGuard:
    """High-water/operation replay state, optionally persisted restart-safely."""

    def __init__(self, state_path: Path | None = None, *, maximum_operations: int = 1_000_000):
        self.state_path = Path(state_path) if state_path is not None else None
        self.maximum_operations = maximum_operations
        self._highest_seq = 0
        self._operations: set[str] = set()
        self._lock = threading.RLock()
        if self.state_path is not None and self.state_path.exists():
            self._load()

    def _load(self) -> None:
        assert self.state_path is not None
        value = load_json_object(self.state_path, max_bytes=64 * 1024 * 1024)
        strict_object(
            value,
            required=frozenset({"schema_version", "highest_receipt_seq", "seen_operation_ids"}),
            name="receipt replay state",
        )
        if value["schema_version"] != REPLAY_STATE_SCHEMA_VERSION:
            raise ReceiptReplayError("unsupported receipt replay state schema")
        require_int(value["highest_receipt_seq"], "highest_receipt_seq")
        operations = value["seen_operation_ids"]
        if not isinstance(operations, list) or any(not isinstance(item, str) or not item for item in operations):
            raise ReceiptReplayError("seen_operation_ids must be a string array")
        if len(operations) != len(set(operations)) or len(operations) > self.maximum_operations:
            raise ReceiptReplayError("receipt replay operation state is duplicated or exceeds its limit")
        self._highest_seq = value["highest_receipt_seq"]
        self._operations = set(operations)

    def _persist(self) -> None:
        if self.state_path is None:
            return
        atomic_write_json(
            self.state_path,
            {
                "schema_version": REPLAY_STATE_SCHEMA_VERSION,
                "highest_receipt_seq": self._highest_seq,
                "seen_operation_ids": sorted(self._operations),
            },
            mode=0o600,
        )

    def accept(self, receipt_seq: int, operation_id: str) -> None:
        require_int(receipt_seq, "receipt_seq", minimum=1)
        require_nonempty(operation_id, "operation_id")
        with self._lock:
            if receipt_seq <= self._highest_seq:
                raise ReceiptReplayError("broker receipt sequence is replayed or out of order")
            if operation_id in self._operations:
                raise ReceiptReplayError("broker operation_id was replayed")
            if len(self._operations) >= self.maximum_operations:
                raise ReceiptReplayError("receipt replay state capacity exceeded; refusing fail-open eviction")
            previous_highest = self._highest_seq
            self._highest_seq = receipt_seq
            self._operations.add(operation_id)
            try:
                self._persist()
            except BaseException:
                self._highest_seq = previous_highest
                self._operations.remove(operation_id)
                raise

    @property
    def highest_sequence(self) -> int:
        with self._lock:
            return self._highest_seq


class ProvenanceValidator:
    def __init__(self, replay_guard: ReceiptReplayGuard | None = None):
        self.replay_guard = replay_guard or ReceiptReplayGuard()

    def validate(
        self,
        envelope: ResultEnvelope,
        receipt: BrokerReceipt | None,
        expected: ExpectedProvenance,
    ) -> ValidatedProvenance:
        if receipt is None:
            raise ProvenanceError("result envelope has no matching out-of-band broker receipt")
        binding = expected.binding
        stable, lifecycle = binding.stable, binding.lifecycle
        expected_values = {
            "run_id": stable.run_id,
            "workspace_id": stable.workspace_id,
            "context_session_id": stable.context_session_id,
            "context_state_epoch": lifecycle.context_state_epoch,
            "binding_version": lifecycle.binding_version,
            "coder_generation": lifecycle.coder_generation,
            "generation_lease_id": lifecycle.generation_lease_id,
            "app_server_instance_id": expected.app_server_instance_id,
            "process_epoch": expected.process_epoch,
            "mcp_request_id": expected.mcp_request_id,
            "tool_name": expected.tool_name,
            "arguments_digest": expected.arguments_digest,
            "result_digest": expected.result_digest,
            "sandbox_policy_digest": lifecycle.sandbox_policy_digest,
            "capability_id": expected.capability_id,
        }
        receipt_mismatch = [
            name for name, wanted in expected_values.items() if getattr(receipt, name) != wanted
        ]
        if receipt_mismatch:
            raise ProvenanceError(f"broker receipt does not match active call: {receipt_mismatch!r}")

        envelope_values = {
            "broker_receipt_seq": receipt.receipt_seq,
            "broker_receipt_digest": receipt.digest,
            "operation_id": receipt.operation_id,
            "tool_name": receipt.tool_name,
            "run_id": receipt.run_id,
            "workspace_id": receipt.workspace_id,
            "context_session_id": receipt.context_session_id,
            "context_state_epoch": receipt.context_state_epoch,
            "binding_version": receipt.binding_version,
            "coder_generation": receipt.coder_generation,
            "generation_lease_id": receipt.generation_lease_id,
            "mcp_request_id": receipt.mcp_request_id,
            "arguments_digest": receipt.arguments_digest,
            "capability_id": receipt.capability_id,
            "result_digest": receipt.result_digest,
            "sandbox_backend": receipt.sandbox_backend,
            "sandbox_policy_digest": receipt.sandbox_policy_digest,
        }
        envelope_mismatch = [
            name for name, wanted in envelope_values.items() if getattr(envelope, name) != wanted
        ]
        if envelope_mismatch:
            raise ProvenanceError(f"result envelope does not match broker receipt: {envelope_mismatch!r}")
        if any(
            record.stale or record.indexed_revision != record.current_revision
            for record in receipt.retrieval
        ):
            raise ProvenanceError("broker receipt contains stale retrieval provenance")
        self.replay_guard.accept(receipt.receipt_seq, receipt.operation_id)
        return ValidatedProvenance(envelope, receipt)


_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|secret|token|api[_-]?key|authorization|credential|private[_-]?key|cookie)",
    re.IGNORECASE,
)
_TEXT_PATTERNS = (
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
)


def _truncate_utf8(text: str, maximum_bytes: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return text, False
    suffix = b"...[truncated]"
    available = max(0, maximum_bytes - len(suffix))
    prefix = encoded[:available]
    while prefix:
        try:
            decoded = prefix.decode("utf-8")
            return decoded + suffix.decode("ascii"), True
        except UnicodeDecodeError:
            prefix = prefix[:-1]
    return suffix[:maximum_bytes].decode("ascii", errors="ignore"), True


def redact_text(text: str, *, maximum_bytes: int = MAX_EXCERPT_BYTES) -> tuple[str, bool]:
    redacted = text
    changed = False
    for pattern in _TEXT_PATTERNS:
        replacement = "[REDACTED]"
        updated, count = pattern.subn(replacement, redacted)
        if count:
            changed = True
            redacted = updated
    bounded, truncated = _truncate_utf8(redacted, maximum_bytes)
    return bounded, changed or truncated


def correlation_hmac(authority_key: bytes, payload: Any) -> str:
    if len(authority_key) < 32:
        raise ProvenanceError("redaction correlation key must contain at least 256 bits")
    return hmac.new(authority_key, canonical_json_bytes(payload), hashlib.sha256).hexdigest()


def _redact_value(value: Any, *, depth: int = 0) -> tuple[Any, bool]:
    if depth > 32:
        return "[TRUNCATED_DEPTH]", True
    if isinstance(value, str):
        return redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value, False
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        changed = False
        for key in sorted(value):
            if not isinstance(key, str):
                return "[INVALID_NON_STRING_KEY]", True
            if _SENSITIVE_KEY.search(key):
                result[key] = "[REDACTED]"
                changed = True
            else:
                result[key], item_changed = _redact_value(value[key], depth=depth + 1)
                changed = changed or item_changed
        return result, changed
    if isinstance(value, (list, tuple)):
        result_list: list[Any] = []
        changed = False
        for item in value[:256]:
            redacted, item_changed = _redact_value(item, depth=depth + 1)
            result_list.append(redacted)
            changed = changed or item_changed
        if len(value) > 256:
            result_list.append("[TRUNCATED_ITEMS]")
            changed = True
        return result_list, changed
    return f"[UNSUPPORTED_{type(value).__name__}]", True


@dataclass(frozen=True)
class RedactedSummary:
    value: Mapping[str, Any]
    correlation_digest: str
    redacted_or_truncated: bool
    encoded_bytes: int


def bounded_redacted_summary(
    value: Mapping[str, Any],
    *,
    authority_key: bytes,
    maximum_event_bytes: int = MAX_EVENT_BYTES,
) -> RedactedSummary:
    """Redact before persistence and enforce a hard event-size ceiling."""

    digest = correlation_hmac(authority_key, dict(value))
    redacted, changed = _redact_value(value)
    if not isinstance(redacted, Mapping):  # input contract makes this defensive.
        redacted = {"summary": redacted}
        changed = True
    payload = canonical_json_bytes(redacted)
    if len(payload) > maximum_event_bytes:
        preview, _ = _truncate_utf8(payload.decode("utf-8"), max(0, maximum_event_bytes - 256))
        redacted = {
            "truncated": True,
            "correlation_digest": digest,
            "redacted_preview": preview,
        }
        changed = True
        payload = canonical_json_bytes(redacted)
        if len(payload) > maximum_event_bytes:
            # Very small custom ceilings still fail closed without leaking input.
            redacted = {"truncated": True, "correlation_digest": digest}
            payload = canonical_json_bytes(redacted)
            if len(payload) > maximum_event_bytes:
                raise ProvenanceError("event byte ceiling is too small for a safe redaction marker")
    return RedactedSummary(dict(redacted), digest, changed, len(payload))


@dataclass(frozen=True)
class ValidationEvidence:
    operation_id: str
    command_index: int
    runner_identity: str
    redacted_argv: tuple[str, ...]
    argv_digest: str
    relative_cwd: str
    duration_ms: int
    exit_code: int | None
    signal: int | None
    timed_out: bool
    terminal_complete: bool


def evidence_from_provenance(
    provenance: ValidatedProvenance,
    *,
    overlapping_mutation: bool,
    workspace_revision_started: int,
    workspace_revision_completed: int,
) -> tuple[ValidationEvidence, ...]:
    """Convert only broker runner records with an unambiguous revision range."""

    receipt = provenance.receipt
    if receipt.tool_name not in EXECUTION_TOOLS or overlapping_mutation:
        return ()
    if workspace_revision_completed < workspace_revision_started:
        return ()
    evidence: list[ValidationEvidence] = []
    for index, command in enumerate(receipt.commands):
        complete = command.stdout_complete and command.stderr_complete and not command.timed_out
        evidence.append(
            ValidationEvidence(
                operation_id=receipt.operation_id,
                command_index=index,
                runner_identity=command.runner_identity,
                redacted_argv=command.redacted_argv,
                argv_digest=command.argv_digest,
                relative_cwd=command.relative_cwd,
                duration_ms=command.duration_ms,
                exit_code=command.exit_code,
                signal=command.signal,
                timed_out=command.timed_out,
                terminal_complete=complete,
            )
        )
    return tuple(evidence)


def result_payload_digest(result_payload_without_envelope: Any) -> str:
    """Digest the exact normalized terminal payload selected by the pinned schema."""

    return digest_json(result_payload_without_envelope)


def validate_model_result_limits(*, encoded_bytes: int, estimated_tokens: int | None) -> None:
    require_int(encoded_bytes, "encoded_bytes")
    if encoded_bytes > MAX_MODEL_RESULT_BYTES:
        raise ProvenanceError("model-facing Context Mode result exceeds 64 KiB")
    if estimated_tokens is not None:
        require_int(estimated_tokens, "estimated_tokens")
        if estimated_tokens > MAX_MODEL_RESULT_ESTIMATED_TOKENS:
            raise ProvenanceError("model-facing Context Mode result exceeds 8,000 estimated tokens")


ReceiptValidator = ProvenanceValidator
