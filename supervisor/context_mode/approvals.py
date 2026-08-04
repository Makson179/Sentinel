"""Generation-scoped, one-shot broker approval capabilities."""

from __future__ import annotations

import math
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ._util import (
    ContextModeDataError,
    digest_json,
    require_int,
    require_nonempty,
    require_sha256,
    strict_object,
)
from .config import CAPABILITY_REQUIRED_TOOLS, EXECUTION_TOOLS, Role, assert_tool_name
from .session import ContextBinding


CAPABILITY_SCHEMA_VERSION = 1
DEFAULT_CAPABILITY_TTL_SECONDS = 60.0
MAX_CAPABILITY_TTL_SECONDS = 300.0


class CapabilityError(ContextModeDataError):
    """A capability is absent, expired, consumed, or does not match a call."""


class CapabilityReplay(CapabilityError):
    """A one-shot capability was presented after it had been consumed."""


def normalized_arguments_digest(arguments: Mapping[str, Any]) -> str:
    if not isinstance(arguments, Mapping):
        raise CapabilityError("tool arguments must be a JSON object")
    return digest_json(dict(arguments))


def ordered_children_digest(children: Sequence[Mapping[str, Any]]) -> str:
    if not isinstance(children, Sequence) or isinstance(children, (str, bytes, bytearray)):
        raise CapabilityError("batch children must be an ordered sequence")
    return digest_json([dict(child) for child in children])


def canonical_cwd(cwd: Path | str, workspace: Path | str) -> str:
    """Validate an already-resolved controller cwd against the workspace.

    The native broker must still resolve and mount paths fd-relative immediately
    before spawn.  This function only prevents approval payload widening.
    """

    cwd_text = os.fspath(cwd)
    workspace_text = os.fspath(workspace)
    if not os.path.isabs(cwd_text) or os.path.normpath(cwd_text) != cwd_text:
        raise CapabilityError("cwd must be a normalized absolute path")
    if not os.path.isabs(workspace_text) or os.path.normpath(workspace_text) != workspace_text:
        raise CapabilityError("workspace must be a normalized absolute path")
    if workspace_text == os.path.sep:
        raise CapabilityError("workspace root must not be the host filesystem root")
    try:
        common = os.path.commonpath((cwd_text, workspace_text))
    except ValueError as exc:
        raise CapabilityError("cwd and workspace are not comparable") from exc
    if common != workspace_text:
        raise CapabilityError("cwd lies outside the active workspace")
    return cwd_text


@dataclass(frozen=True)
class ApprovalCapability:
    capability_id: str
    role: Role
    process_epoch: int
    binding_version: int
    coder_generation: int
    generation_lease_id: str
    tool_name: str
    arguments_digest: str
    canonical_cwd: str
    request_digest: str
    issued_at: float
    expires_at: float
    ordered_children_digest: str | None = None
    schema_version: int = CAPABILITY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        require_int(self.schema_version, "schema_version", minimum=1)
        if self.schema_version != CAPABILITY_SCHEMA_VERSION:
            raise CapabilityError("unsupported approval capability schema")
        require_nonempty(self.capability_id, "capability_id")
        if self.role is not Role.CODER:
            raise CapabilityError("Context Mode capabilities are coder-only")
        require_int(self.process_epoch, "process_epoch")
        require_int(self.binding_version, "binding_version", minimum=1)
        require_int(self.coder_generation, "coder_generation")
        require_nonempty(self.generation_lease_id, "generation_lease_id")
        assert_tool_name(self.tool_name)
        if self.tool_name not in CAPABILITY_REQUIRED_TOOLS:
            raise CapabilityError(f"tool {self.tool_name!r} does not use execution/purge capabilities")
        require_sha256(self.arguments_digest, "arguments_digest")
        require_sha256(self.request_digest, "request_digest")
        if not os.path.isabs(self.canonical_cwd) or os.path.normpath(self.canonical_cwd) != self.canonical_cwd:
            raise CapabilityError("canonical_cwd must be a normalized absolute path")
        if (
            isinstance(self.issued_at, bool)
            or isinstance(self.expires_at, bool)
            or not isinstance(self.issued_at, (int, float))
            or not isinstance(self.expires_at, (int, float))
            or not math.isfinite(self.issued_at)
            or not math.isfinite(self.expires_at)
        ):
            raise CapabilityError("capability timestamps must be finite numbers")
        if self.expires_at <= self.issued_at:
            raise CapabilityError("capability expiration must follow issuance")
        if self.tool_name == "ctx_batch_execute":
            if self.ordered_children_digest is None:
                raise CapabilityError("batch capability requires ordered_children_digest")
            require_sha256(self.ordered_children_digest, "ordered_children_digest")
        elif self.ordered_children_digest is not None:
            raise CapabilityError("ordered_children_digest is valid only for ctx_batch_execute")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "capability_id": self.capability_id,
            "role": self.role.value,
            "process_epoch": self.process_epoch,
            "binding_version": self.binding_version,
            "coder_generation": self.coder_generation,
            "generation_lease_id": self.generation_lease_id,
            "tool_name": self.tool_name,
            "arguments_digest": self.arguments_digest,
            "canonical_cwd": self.canonical_cwd,
            "request_digest": self.request_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "ordered_children_digest": self.ordered_children_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ApprovalCapability":
        strict_object(
            value,
            required=frozenset(
                {
                    "schema_version",
                    "capability_id",
                    "role",
                    "process_epoch",
                    "binding_version",
                    "coder_generation",
                    "generation_lease_id",
                    "tool_name",
                    "arguments_digest",
                    "canonical_cwd",
                    "request_digest",
                    "issued_at",
                    "expires_at",
                    "ordered_children_digest",
                }
            ),
            name="approval capability",
        )
        require_int(value["schema_version"], "schema_version", minimum=1)
        if value["schema_version"] != CAPABILITY_SCHEMA_VERSION:
            raise CapabilityError("unsupported approval capability schema")
        fields = dict(value)
        fields.pop("schema_version")
        try:
            fields["role"] = Role(fields["role"])
            return cls(**fields)
        except (TypeError, ValueError, ContextModeDataError) as exc:
            raise CapabilityError(str(exc)) from exc


@dataclass(frozen=True)
class CapabilityExpectation:
    capability_id: str
    process_epoch: int
    tool_name: str
    arguments_digest: str
    canonical_cwd: str
    request_digest: str
    ordered_children_digest: str | None = None


class OneShotCapabilityStore:
    """Controller-to-broker capability store with atomic in-process consumption."""

    def __init__(self, *, clock: Any = time.monotonic, wall_clock: Any = time.time):
        self._clock = clock
        self._wall_clock = wall_clock
        self._active: dict[str, tuple[ApprovalCapability, float]] = {}
        self._consumed: set[str] = set()
        self._lock = threading.RLock()

    def grant(
        self,
        *,
        binding: ContextBinding,
        process_epoch: int,
        tool_name: str,
        arguments: Mapping[str, Any],
        cwd: Path | str,
        request_key: Mapping[str, Any],
        batch_children: Sequence[Mapping[str, Any]] | None = None,
        ttl_seconds: float = DEFAULT_CAPABILITY_TTL_SECONDS,
    ) -> ApprovalCapability:
        assert_tool_name(tool_name)
        if tool_name not in CAPABILITY_REQUIRED_TOOLS:
            raise CapabilityError(f"{tool_name!r} is not capability-gated")
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(ttl_seconds)
            or not 0 < ttl_seconds <= MAX_CAPABILITY_TTL_SECONDS
        ):
            raise CapabilityError(f"capability TTL must be in (0, {MAX_CAPABILITY_TTL_SECONDS}]")
        lifecycle = binding.lifecycle
        if process_epoch != lifecycle.coder_process_epoch:
            raise CapabilityError("approval process epoch is not active")
        if lifecycle.provider_thread_id is None:
            raise CapabilityError("approval cannot be granted before the one-time provider thread claim")
        children_digest: str | None = None
        if tool_name == "ctx_batch_execute":
            if batch_children is None:
                raise CapabilityError("batch approval requires ordered children")
            children_digest = ordered_children_digest(batch_children)
        elif batch_children is not None:
            raise CapabilityError("batch children supplied for a non-batch tool")
        issued_wall = float(self._wall_clock())
        issued_monotonic = float(self._clock())
        capability = ApprovalCapability(
            capability_id=secrets.token_urlsafe(32),
            role=Role.CODER,
            process_epoch=process_epoch,
            binding_version=lifecycle.binding_version,
            coder_generation=lifecycle.coder_generation,
            generation_lease_id=lifecycle.generation_lease_id,
            tool_name=tool_name,
            arguments_digest=normalized_arguments_digest(arguments),
            canonical_cwd=canonical_cwd(cwd, binding.stable.workspace_path),
            request_digest=digest_json(dict(request_key)),
            issued_at=issued_wall,
            expires_at=issued_wall + ttl_seconds,
            ordered_children_digest=children_digest,
        )
        with self._lock:
            self._active[capability.capability_id] = (capability, issued_monotonic + ttl_seconds)
        return capability

    def consume(
        self,
        expectation: CapabilityExpectation,
        *,
        active_binding: ContextBinding,
    ) -> ApprovalCapability:
        """Match all call fields and consume the grant before execution begins."""

        with self._lock:
            if expectation.capability_id in self._consumed:
                raise CapabilityReplay("approval capability has already been consumed")
            stored = self._active.get(expectation.capability_id)
            if stored is None:
                raise CapabilityError("unknown or revoked approval capability")
            capability, deadline = stored
            if float(self._clock()) > deadline:
                del self._active[expectation.capability_id]
                raise CapabilityError("approval capability expired")
            lifecycle = active_binding.lifecycle
            active_fields = (
                capability.binding_version == lifecycle.binding_version,
                capability.coder_generation == lifecycle.coder_generation,
                capability.generation_lease_id == lifecycle.generation_lease_id,
                capability.process_epoch == lifecycle.coder_process_epoch,
            )
            if not all(active_fields):
                raise CapabilityError("approval capability belongs to a stale binding/generation lease")
            comparisons = {
                "process_epoch": (expectation.process_epoch, capability.process_epoch),
                "tool_name": (expectation.tool_name, capability.tool_name),
                "arguments_digest": (expectation.arguments_digest, capability.arguments_digest),
                "canonical_cwd": (expectation.canonical_cwd, capability.canonical_cwd),
                "request_digest": (expectation.request_digest, capability.request_digest),
                "ordered_children_digest": (
                    expectation.ordered_children_digest,
                    capability.ordered_children_digest,
                ),
            }
            mismatch = [name for name, (actual, wanted) in comparisons.items() if actual != wanted]
            if mismatch:
                raise CapabilityError(f"approval capability call mismatch: {mismatch!r}")
            del self._active[expectation.capability_id]
            self._consumed.add(expectation.capability_id)
            return capability

    def revoke_generation(self, *, coder_generation: int, generation_lease_id: str) -> int:
        with self._lock:
            revoked = [
                capability_id
                for capability_id, (capability, _) in self._active.items()
                if capability.coder_generation == coder_generation
                and capability.generation_lease_id == generation_lease_id
            ]
            for capability_id in revoked:
                del self._active[capability_id]
            return len(revoked)

    def revoke_all(self) -> int:
        with self._lock:
            count = len(self._active)
            self._active.clear()
            return count

    def revoke(self, capability_id: str) -> bool:
        """Revoke one unconsumed grant (for a failed approval response)."""

        with self._lock:
            return self._active.pop(capability_id, None) is not None

    def is_consumed(self, capability_id: str) -> bool:
        with self._lock:
            return capability_id in self._consumed


CapabilityStore = OneShotCapabilityStore
