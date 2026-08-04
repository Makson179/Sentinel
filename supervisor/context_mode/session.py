"""Authoritative Context Mode binding and checkpoint primitives."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import hmac
import os
import secrets
import stat
import threading
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any, Iterator, Mapping

from ._util import (
    ContextModeDataError,
    atomic_write_json,
    canonical_json_bytes,
    ensure_private_directory,
    load_json_object,
    require_int,
    require_nonempty,
    require_sha256,
    strict_object,
)


BINDING_SCHEMA_VERSION = 1
CHECKPOINT_SCHEMA_VERSION = 1


class BindingError(ContextModeDataError):
    """Binding data is corrupt or a lifecycle transition is not permitted."""


class BindingConflict(BindingError):
    """The persisted binding version differs from the caller's expected version."""


def _require_schema_version(value: Any, *, expected: int, name: str) -> None:
    try:
        require_int(value, f"{name} schema_version", minimum=1)
    except ContextModeDataError as exc:
        raise BindingError(str(exc)) from exc
    if value != expected:
        raise BindingError(f"unsupported {name} schema version: {value!r}")


class TransitionReason(str, Enum):
    THREAD_CLAIM = "thread_claim"
    CLEAR_THREAD_CLAIM = "clear_thread_claim"
    LOGICAL_GENERATION_RESTART = "logical_generation_restart"
    PROCESS_RECOVERY = "process_recovery"
    CONTROLLED_RECYCLE = "controlled_recycle"
    STATE_EPOCH_ROTATION = "state_epoch_rotation"
    POLICY_CHANGE = "policy_change"


class CheckpointRecoveryKind(str, Enum):
    COMPACTION = "compaction"
    LOGICAL_RESTART = "logical_restart"
    PROCESS_RECOVERY = "process_recovery"


def new_generation_lease_id() -> str:
    return secrets.token_urlsafe(32)


def _canonical_absolute_path(value: str, field: str) -> str:
    require_nonempty(value, field)
    path = Path(value)
    if not path.is_absolute() or os.path.normpath(value) != value:
        raise BindingError(f"{field} must be a normalized absolute path")
    if os.path.realpath(value) != value:
        raise BindingError(f"{field} must be canonical and contain no symlink components")
    return value


@dataclass(frozen=True)
class StableBindingIdentity:
    run_id: str
    workspace_id: str
    context_session_id: str
    workspace_path: str
    base_config_digest: str

    def __post_init__(self) -> None:
        require_nonempty(self.run_id, "run_id")
        require_nonempty(self.workspace_id, "workspace_id")
        require_nonempty(self.context_session_id, "context_session_id")
        _canonical_absolute_path(self.workspace_path, "workspace_path")
        require_sha256(self.base_config_digest, "base_config_digest")

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "workspace_id": self.workspace_id,
            "context_session_id": self.context_session_id,
            "workspace_path": self.workspace_path,
            "base_config_digest": self.base_config_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "StableBindingIdentity":
        strict_object(
            value,
            required=frozenset(
                {"run_id", "workspace_id", "context_session_id", "workspace_path", "base_config_digest"}
            ),
            name="stable binding identity",
        )
        try:
            return cls(**value)  # type: ignore[arg-type]
        except (TypeError, ContextModeDataError) as exc:
            raise BindingError(str(exc)) from exc


@dataclass(frozen=True)
class LifecycleSnapshot:
    binding_version: int
    context_state_epoch: int
    coder_generation: int
    generation_lease_id: str
    coder_process_epoch: int
    app_server_instance_id: str
    sandbox_policy_digest: str
    provider_thread_id: str | None = None

    def __post_init__(self) -> None:
        require_int(self.binding_version, "binding_version", minimum=1)
        require_int(self.context_state_epoch, "context_state_epoch")
        require_int(self.coder_generation, "coder_generation")
        require_nonempty(self.generation_lease_id, "generation_lease_id")
        require_int(self.coder_process_epoch, "coder_process_epoch")
        require_nonempty(self.app_server_instance_id, "app_server_instance_id")
        require_sha256(self.sandbox_policy_digest, "sandbox_policy_digest")
        if self.provider_thread_id is not None:
            require_nonempty(self.provider_thread_id, "provider_thread_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_version": self.binding_version,
            "context_state_epoch": self.context_state_epoch,
            "coder_generation": self.coder_generation,
            "generation_lease_id": self.generation_lease_id,
            "coder_process_epoch": self.coder_process_epoch,
            "app_server_instance_id": self.app_server_instance_id,
            "sandbox_policy_digest": self.sandbox_policy_digest,
            "provider_thread_id": self.provider_thread_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LifecycleSnapshot":
        strict_object(
            value,
            required=frozenset(
                {
                    "binding_version",
                    "context_state_epoch",
                    "coder_generation",
                    "generation_lease_id",
                    "coder_process_epoch",
                    "app_server_instance_id",
                    "sandbox_policy_digest",
                    "provider_thread_id",
                }
            ),
            name="binding lifecycle snapshot",
        )
        try:
            return cls(**value)  # type: ignore[arg-type]
        except (TypeError, ContextModeDataError) as exc:
            raise BindingError(str(exc)) from exc


@dataclass(frozen=True)
class ContextBinding:
    stable: StableBindingIdentity
    lifecycle: LifecycleSnapshot
    schema_version: int = BINDING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_schema_version(
            self.schema_version,
            expected=BINDING_SCHEMA_VERSION,
            name="binding",
        )

    @property
    def binding_version(self) -> int:
        return self.lifecycle.binding_version

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "stable": self.stable.to_dict(),
            "lifecycle": self.lifecycle.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ContextBinding":
        strict_object(
            value,
            required=frozenset({"schema_version", "stable", "lifecycle"}),
            name="Context Mode binding",
        )
        _require_schema_version(
            value["schema_version"],
            expected=BINDING_SCHEMA_VERSION,
            name="binding",
        )
        if not isinstance(value["stable"], Mapping) or not isinstance(value["lifecycle"], Mapping):
            raise BindingError("binding stable and lifecycle fields must be objects")
        return cls(
            stable=StableBindingIdentity.from_dict(value["stable"]),
            lifecycle=LifecycleSnapshot.from_dict(value["lifecycle"]),
        )

    def transition(self, reason: TransitionReason | str, **changes: Any) -> "ContextBinding":
        """Construct and validate the next exact lifecycle version."""

        reason = TransitionReason(reason)
        if "binding_version" in changes:
            raise BindingError("binding_version is controlled by the binding store")
        allowed_fields = frozenset(LifecycleSnapshot.__dataclass_fields__) - {"binding_version"}
        unknown = frozenset(changes) - allowed_fields
        if unknown:
            raise BindingError(f"unknown lifecycle fields: {sorted(unknown)!r}")
        lifecycle = replace(self.lifecycle, binding_version=self.binding_version + 1, **changes)
        candidate = replace(self, lifecycle=lifecycle)
        validate_binding_transition(self, candidate, reason)
        return candidate


_LIFECYCLE_FIELDS = frozenset(LifecycleSnapshot.__dataclass_fields__)


def validate_binding_transition(
    previous: ContextBinding,
    candidate: ContextBinding,
    reason: TransitionReason | str,
) -> None:
    reason = TransitionReason(reason)
    if previous.stable != candidate.stable:
        raise BindingError("stable binding identity is immutable")
    old = previous.lifecycle
    new = candidate.lifecycle
    if new.binding_version != old.binding_version + 1:
        raise BindingError("binding_version must increase by exactly one")

    changed = {
        field
        for field in _LIFECYCLE_FIELDS
        if field != "binding_version" and getattr(old, field) != getattr(new, field)
    }
    if reason is TransitionReason.THREAD_CLAIM:
        if old.provider_thread_id is not None or new.provider_thread_id is None:
            raise BindingError("thread claim requires provider_thread_id null -> non-null")
        allowed, required = {"provider_thread_id"}, {"provider_thread_id"}
    elif reason is TransitionReason.CLEAR_THREAD_CLAIM:
        if old.provider_thread_id is None or new.provider_thread_id is not None:
            raise BindingError("clear thread claim requires provider_thread_id non-null -> null")
        allowed, required = {"provider_thread_id"}, {"provider_thread_id"}
    elif reason is TransitionReason.LOGICAL_GENERATION_RESTART:
        if new.coder_generation != old.coder_generation + 1:
            raise BindingError("logical restart must increment coder_generation exactly once")
        if new.generation_lease_id == old.generation_lease_id:
            raise BindingError("logical restart must rotate generation_lease_id")
        if new.provider_thread_id is not None:
            raise BindingError("new logical generation must begin with no provider thread claim")
        allowed = {"coder_generation", "generation_lease_id", "provider_thread_id"}
        required = {"coder_generation", "generation_lease_id"}
    elif reason in {TransitionReason.PROCESS_RECOVERY, TransitionReason.CONTROLLED_RECYCLE}:
        if new.coder_process_epoch != old.coder_process_epoch + 1:
            raise BindingError("process restart must increment coder_process_epoch exactly once")
        if new.app_server_instance_id == old.app_server_instance_id:
            raise BindingError("process restart must change app_server_instance_id")
        if (
            old.provider_thread_id is not None
            and new.provider_thread_id is not None
            and new.provider_thread_id != old.provider_thread_id
        ):
            raise BindingError("process restart cannot silently bind a different provider thread")
        allowed = {"coder_process_epoch", "app_server_instance_id", "provider_thread_id"}
        required = {"coder_process_epoch", "app_server_instance_id"}
    elif reason is TransitionReason.STATE_EPOCH_ROTATION:
        if new.context_state_epoch != old.context_state_epoch + 1:
            raise BindingError("state rotation must increment context_state_epoch exactly once")
        allowed = {"context_state_epoch", "sandbox_policy_digest"}
        required = {"context_state_epoch"}
    elif reason is TransitionReason.POLICY_CHANGE:
        allowed = {"sandbox_policy_digest"}
        required = {"sandbox_policy_digest"}
    else:  # pragma: no cover - Enum conversion above is exhaustive.
        raise BindingError(f"unsupported transition reason: {reason}")
    if not required.issubset(changed) or not changed.issubset(allowed):
        raise BindingError(
            f"transition {reason.value!r} changed invalid fields: {sorted(changed)!r}; "
            f"required={sorted(required)!r}, allowed={sorted(allowed)!r}"
        )

    # These monotonic fields cannot silently move under any reason.
    if new.context_state_epoch < old.context_state_epoch:
        raise BindingError("context_state_epoch must not decrease")
    if new.coder_generation < old.coder_generation:
        raise BindingError("coder_generation must not decrease")
    if new.coder_process_epoch < old.coder_process_epoch:
        raise BindingError("coder_process_epoch must not decrease")


class BindingStore:
    """Single-authority, atomic, monotonic persistence for ``ContextBinding``."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock_path = self.path.with_name(f".{self.path.name}.lock")
        self._thread_lock = threading.RLock()

    @contextlib.contextmanager
    def _exclusive(self) -> Iterator[None]:
        with self._thread_lock:
            ensure_private_directory(self.path.parent)
            descriptor = os.open(self._lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            try:
                os.fchmod(descriptor, 0o600)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> ContextBinding:
        try:
            info = self.path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise BindingError("binding path must be a regular non-symlink file")
            if stat.S_IMODE(info.st_mode) != 0o600:
                raise BindingError("binding file mode must be 0600")
            if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
                raise BindingError("binding file owner does not match the controller")
            value = load_json_object(self.path, max_bytes=256 * 1024)
            return ContextBinding.from_dict(value)
        except FileNotFoundError as exc:
            raise BindingError(f"binding does not exist: {self.path}") from exc
        except ContextModeDataError as exc:
            if isinstance(exc, BindingError):
                raise
            raise BindingError(str(exc)) from exc

    def initialize(self, binding: ContextBinding) -> ContextBinding:
        if binding.binding_version != 1:
            raise BindingError("initial binding_version must be 1")
        with self._exclusive():
            if self.path.exists():
                raise BindingConflict("binding is already initialized")
            atomic_write_json(self.path, binding.to_dict(), mode=0o600)
        return binding

    def compare_and_swap(
        self,
        *,
        expected_version: int,
        candidate: ContextBinding,
        reason: TransitionReason | str,
    ) -> ContextBinding:
        with self._exclusive():
            current = self.load()
            if current.binding_version != expected_version:
                raise BindingConflict(
                    f"binding version conflict: expected {expected_version}, found {current.binding_version}"
                )
            validate_binding_transition(current, candidate, reason)
            atomic_write_json(self.path, candidate.to_dict(), mode=0o600)
        return candidate

    def transition(
        self,
        *,
        expected_version: int,
        reason: TransitionReason | str,
        **changes: Any,
    ) -> ContextBinding:
        with self._exclusive():
            current = self.load()
            if current.binding_version != expected_version:
                raise BindingConflict(
                    f"binding version conflict: expected {expected_version}, found {current.binding_version}"
                )
            candidate = current.transition(reason, **changes)
            atomic_write_json(self.path, candidate.to_dict(), mode=0o600)
            return candidate

    def claim_provider_thread(
        self,
        *,
        expected_version: int,
        coder_generation: int,
        generation_lease_id: str,
        coder_process_epoch: int,
        provider_thread_id: str,
    ) -> ContextBinding:
        with self._exclusive():
            current = self.load()
            lifecycle = current.lifecycle
            if current.binding_version != expected_version:
                raise BindingConflict(
                    f"binding version conflict: expected {expected_version}, found {current.binding_version}"
                )
            if (
                lifecycle.coder_generation != coder_generation
                or lifecycle.generation_lease_id != generation_lease_id
                or lifecycle.coder_process_epoch != coder_process_epoch
            ):
                raise BindingConflict("thread claim does not match the active generation/process lease")
            candidate = current.transition(
                TransitionReason.THREAD_CLAIM,
                provider_thread_id=require_nonempty(provider_thread_id, "provider_thread_id"),
            )
            atomic_write_json(self.path, candidate.to_dict(), mode=0o600)
            return candidate


@dataclass(frozen=True)
class CheckpointCursor:
    checkpoint_id: str
    reason: str
    run_id: str
    workspace_id: str
    context_session_id: str
    context_state_epoch: int
    coder_generation: int
    generation_lease_id: str
    coder_process_epoch: int
    provider_thread_id: str
    binding_version: int
    context_event_seq: int
    last_committed_operation_id: str | None
    created_at: str
    cursor_hmac: str
    schema_version: int = CHECKPOINT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _require_schema_version(
            self.schema_version,
            expected=CHECKPOINT_SCHEMA_VERSION,
            name="checkpoint",
        )

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "checkpoint_id": self.checkpoint_id,
            "reason": self.reason,
            "run_id": self.run_id,
            "workspace_id": self.workspace_id,
            "context_session_id": self.context_session_id,
            "context_state_epoch": self.context_state_epoch,
            "coder_generation": self.coder_generation,
            "generation_lease_id": self.generation_lease_id,
            "coder_process_epoch": self.coder_process_epoch,
            "provider_thread_id": self.provider_thread_id,
            "binding_version": self.binding_version,
            "context_event_seq": self.context_event_seq,
            "last_committed_operation_id": self.last_committed_operation_id,
            "created_at": self.created_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "cursor_hmac": self.cursor_hmac}

    def verify(self, authority_key: bytes, binding: ContextBinding) -> None:
        if self.schema_version != CHECKPOINT_SCHEMA_VERSION:
            raise BindingError("unsupported checkpoint schema version")
        expected = hmac.new(authority_key, canonical_json_bytes(self.unsigned_dict()), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, self.cursor_hmac):
            raise BindingError("checkpoint cursor HMAC mismatch")
        self.validate_binding(binding)

    def validate_binding(
        self,
        binding: ContextBinding,
        *,
        expected_reason: str | None = None,
        exact_lifecycle: bool = False,
    ) -> None:
        """Validate cursor identity without claiming to verify its HMAC.

        Only the native broker owns the cursor-HMAC authority.  Controller-side
        callers use this method *after* an explicit broker verification
        acknowledgement so they can independently reject identity, reason, or
        lifecycle mixing without acquiring the signing key.
        """

        if expected_reason is not None and self.reason != expected_reason:
            raise BindingError("checkpoint reason does not match the lifecycle request")
        lifecycle = binding.lifecycle
        stable = binding.stable
        comparisons = {
            "run_id": (self.run_id, stable.run_id),
            "workspace_id": (self.workspace_id, stable.workspace_id),
            "context_session_id": (self.context_session_id, stable.context_session_id),
            "context_state_epoch": (self.context_state_epoch, lifecycle.context_state_epoch),
        }
        mismatches = [name for name, (actual, wanted) in comparisons.items() if actual != wanted]
        if mismatches:
            raise BindingError(f"checkpoint does not match active binding: {mismatches!r}")
        if exact_lifecycle:
            lifecycle_comparisons = {
                "coder_generation": (self.coder_generation, lifecycle.coder_generation),
                "generation_lease_id": (
                    self.generation_lease_id,
                    lifecycle.generation_lease_id,
                ),
                "coder_process_epoch": (
                    self.coder_process_epoch,
                    lifecycle.coder_process_epoch,
                ),
                "provider_thread_id": (
                    self.provider_thread_id,
                    lifecycle.provider_thread_id,
                ),
                "binding_version": (self.binding_version, lifecycle.binding_version),
            }
            lifecycle_mismatches = [
                name
                for name, (actual, wanted) in lifecycle_comparisons.items()
                if actual != wanted
            ]
            if lifecycle_mismatches:
                raise BindingError(
                    "checkpoint does not match the checkpoint lifecycle: "
                    f"{lifecycle_mismatches!r}"
                )

    def verify_recovery(
        self,
        authority_key: bytes,
        binding: ContextBinding,
        *,
        kind: CheckpointRecoveryKind | str,
        expected_checkpoint_id: str,
    ) -> None:
        """Apply the reason-specific lifecycle rules for one recovery acknowledgement."""

        self.verify(authority_key, binding)
        self.validate_recovery_binding(
            binding,
            kind=kind,
            expected_checkpoint_id=expected_checkpoint_id,
        )

    def validate_recovery_binding(
        self,
        binding: ContextBinding,
        *,
        kind: CheckpointRecoveryKind | str,
        expected_checkpoint_id: str,
    ) -> None:
        """Validate a broker-verified recovery against its active binding."""

        self.validate_binding(binding)
        if self.checkpoint_id != expected_checkpoint_id:
            raise BindingError("recovery acknowledgement uses a different checkpoint_id")
        kind = CheckpointRecoveryKind(kind)
        lifecycle = binding.lifecycle
        if lifecycle.binding_version < self.binding_version:
            raise BindingError("active binding predates checkpoint cursor")
        if kind is CheckpointRecoveryKind.COMPACTION:
            comparisons = (
                lifecycle.binding_version == self.binding_version,
                lifecycle.coder_generation == self.coder_generation,
                lifecycle.generation_lease_id == self.generation_lease_id,
                lifecycle.coder_process_epoch == self.coder_process_epoch,
                lifecycle.provider_thread_id == self.provider_thread_id,
            )
            if not all(comparisons):
                raise BindingError("compaction recovery changed generation/process/thread identity")
        elif kind is CheckpointRecoveryKind.LOGICAL_RESTART:
            if not (
                lifecycle.binding_version > self.binding_version
                and lifecycle.coder_generation == self.coder_generation + 1
                and lifecycle.generation_lease_id != self.generation_lease_id
                and lifecycle.coder_process_epoch == self.coder_process_epoch
                and lifecycle.provider_thread_id is not None
            ):
                raise BindingError("logical restart recovery transition does not match checkpoint")
        elif kind is CheckpointRecoveryKind.PROCESS_RECOVERY:
            if not (
                lifecycle.binding_version > self.binding_version
                and lifecycle.coder_generation == self.coder_generation
                and lifecycle.generation_lease_id == self.generation_lease_id
                and lifecycle.coder_process_epoch == self.coder_process_epoch + 1
                and lifecycle.provider_thread_id == self.provider_thread_id
            ):
                raise BindingError("process recovery transition does not match checkpoint")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CheckpointCursor":
        strict_object(value, required=frozenset(cls.__dataclass_fields__), name="checkpoint cursor")
        _require_schema_version(
            value["schema_version"],
            expected=CHECKPOINT_SCHEMA_VERSION,
            name="checkpoint",
        )
        data = dict(value)
        data.pop("schema_version")
        try:
            cursor = cls(**data)
        except TypeError as exc:
            raise BindingError(str(exc)) from exc
        for name in (
            "checkpoint_id",
            "reason",
            "run_id",
            "workspace_id",
            "context_session_id",
            "generation_lease_id",
            "provider_thread_id",
            "created_at",
        ):
            require_nonempty(getattr(cursor, name), name)
        for name, minimum in (
            ("context_state_epoch", 0),
            ("coder_generation", 0),
            ("coder_process_epoch", 0),
            ("binding_version", 1),
            ("context_event_seq", 0),
        ):
            require_int(getattr(cursor, name), name, minimum=minimum)
        if cursor.last_committed_operation_id is not None:
            require_nonempty(cursor.last_committed_operation_id, "last_committed_operation_id")
        require_sha256(cursor.cursor_hmac, "cursor_hmac")
        return cursor

    @classmethod
    def create(
        cls,
        *,
        authority_key: bytes,
        binding: ContextBinding,
        checkpoint_id: str,
        reason: str,
        context_event_seq: int,
        last_committed_operation_id: str | None,
        created_at: str,
    ) -> "CheckpointCursor":
        if len(authority_key) < 32:
            raise BindingError("checkpoint authority key must contain at least 256 bits")
        stable, lifecycle = binding.stable, binding.lifecycle
        if lifecycle.provider_thread_id is None:
            raise BindingError("cannot checkpoint before provider thread claim")
        if last_committed_operation_id is not None:
            require_nonempty(last_committed_operation_id, "last_committed_operation_id")
        unsigned = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "checkpoint_id": require_nonempty(checkpoint_id, "checkpoint_id"),
            "reason": require_nonempty(reason, "reason"),
            "run_id": stable.run_id,
            "workspace_id": stable.workspace_id,
            "context_session_id": stable.context_session_id,
            "context_state_epoch": lifecycle.context_state_epoch,
            "coder_generation": lifecycle.coder_generation,
            "generation_lease_id": lifecycle.generation_lease_id,
            "coder_process_epoch": lifecycle.coder_process_epoch,
            "provider_thread_id": lifecycle.provider_thread_id,
            "binding_version": lifecycle.binding_version,
            "context_event_seq": require_int(context_event_seq, "context_event_seq"),
            "last_committed_operation_id": last_committed_operation_id,
            "created_at": require_nonempty(created_at, "created_at"),
        }
        signature = hmac.new(authority_key, canonical_json_bytes(unsigned), hashlib.sha256).hexdigest()
        return cls(**{key: value for key, value in unsigned.items() if key != "schema_version"}, cursor_hmac=signature)


class CheckpointRecoveryTracker:
    """Persist checkpoint acknowledgements so recovery is counted exactly once."""

    def __init__(self, path: Path, *, maximum_checkpoints: int = 100_000):
        self.path = Path(path)
        self.maximum_checkpoints = maximum_checkpoints
        self._recovered: set[str] = set()
        self._lock = threading.RLock()
        if self.path.exists():
            value = load_json_object(self.path, max_bytes=16 * 1024 * 1024)
            strict_object(
                value,
                required=frozenset({"schema_version", "recovered_checkpoint_ids"}),
                name="checkpoint recovery state",
            )
            _require_schema_version(
                value["schema_version"],
                expected=CHECKPOINT_SCHEMA_VERSION,
                name="checkpoint recovery state",
            )
            identifiers = value["recovered_checkpoint_ids"]
            if not isinstance(identifiers, list) or any(
                not isinstance(item, str) or not item for item in identifiers
            ):
                raise BindingError("recovered checkpoint IDs must be a string array")
            if len(identifiers) != len(set(identifiers)) or len(identifiers) > maximum_checkpoints:
                raise BindingError("checkpoint recovery state is duplicated or over capacity")
            self._recovered = set(identifiers)

    def acknowledge(
        self,
        cursor: CheckpointCursor,
        *,
        authority_key: bytes,
        binding: ContextBinding,
        kind: CheckpointRecoveryKind | str,
    ) -> bool:
        cursor.verify_recovery(
            authority_key,
            binding,
            kind=kind,
            expected_checkpoint_id=cursor.checkpoint_id,
        )
        return self._commit(cursor.checkpoint_id)

    def acknowledge_native_verified(
        self,
        cursor: CheckpointCursor,
        *,
        binding: ContextBinding,
        kind: CheckpointRecoveryKind | str,
    ) -> bool:
        """Persist an acknowledgement already verified by the native broker.

        This deliberately performs no HMAC operation: the controller never
        receives the native authority key.  The caller must first validate an
        explicit broker acknowledgement; the remaining binding checks are
        repeated here before the exactly-once state is committed.
        """

        cursor.validate_recovery_binding(
            binding,
            kind=kind,
            expected_checkpoint_id=cursor.checkpoint_id,
        )
        return self._commit(cursor.checkpoint_id)

    def contains(self, checkpoint_id: str) -> bool:
        require_nonempty(checkpoint_id, "checkpoint_id")
        with self._lock:
            return checkpoint_id in self._recovered

    def _commit(self, checkpoint_id: str) -> bool:
        with self._lock:
            if checkpoint_id in self._recovered:
                return False
            if len(self._recovered) >= self.maximum_checkpoints:
                raise BindingError("checkpoint recovery tracker capacity exceeded")
            self._recovered.add(checkpoint_id)
            try:
                atomic_write_json(
                    self.path,
                    {
                        "schema_version": CHECKPOINT_SCHEMA_VERSION,
                        "recovered_checkpoint_ids": sorted(self._recovered),
                    },
                    mode=0o600,
                )
            except BaseException:
                self._recovered.remove(checkpoint_id)
                raise
            return True
