"""Fail-closed controller startup for the offline Context Mode runtime.

The policy/data model lives in the sibling modules.  This module is the narrow
bridge to a *native* process owner supplied by a platform Bello package.  It
never substitutes environment filtering or Python path checks for an OS
sandbox: without a verified backend and a native adapter, preparation fails
before an app-server is started.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import os
import re
import stat
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from ._util import (
    ContextModeDataError,
    atomic_write_json,
    canonical_json_bytes,
    ensure_private_directory,
    require_int,
    require_nonempty,
    require_sha256,
    strict_object,
)
from .approvals import OneShotCapabilityStore
from .config import REQUIRED_HOOKS
from .epochs import ContextEpochLayout, EpochStateError
from .hook_payloads import HOOK_PAYLOAD_CONTRACT_DIGEST, HOOK_PAYLOAD_SCHEMA_VERSION
from .packaging import VerifiedRuntimeBundle, current_platform_tag, select_bundled_runtime
from .runtime import (
    ContextRuntimeCoordinator,
    ExclusiveWorkspaceLease,
    ExclusiveWorkspaceLeasePurpose,
    RuntimeState,
)
from .sandbox import (
    ProfileKind,
    SandboxBackend,
    SandboxPathLayout,
    SandboxPolicy,
    build_clean_environment,
    generate_sandbox_policies,
)
from .session import (
    BindingStore,
    CheckpointCursor,
    CheckpointRecoveryKind,
    CheckpointRecoveryTracker,
    ContextBinding,
    LifecycleSnapshot,
    StableBindingIdentity,
    TransitionReason,
)


class ContextModeStartupError(ContextModeDataError):
    """The native runtime cannot be prepared without weakening isolation."""


PURGE_LIFECYCLE_ATTESTATION: Mapping[str, bool] = {
    "exclusive_lifecycle_lease": True,
    "quiesce_before_epoch_rotation": True,
    "receipt_committed_before_terminal": True,
    "physical_epoch_isolation": True,
    "active_epoch_mount_only": True,
    "atomic_epoch_switch": True,
    "writer_reap_before_epoch_retirement": True,
    "old_epoch_retained_until_recycle": True,
    "lease_bound_purge_capability": True,
}

CHECKPOINT_LIFECYCLE_ATTESTATION: Mapping[str, bool] = {
    "cursor_hmac_authority_is_broker_only": True,
    "wal_commit_before_checkpoint_ack": True,
    "session_start_before_recovery_ack": True,
    "reason_specific_binding_validation": True,
    "bounded_replay_acknowledgement": True,
    "checkpoint_idempotency_persisted": True,
}

CHECKPOINT_ENVELOPE_SCHEMA_VERSION = 1
MAX_CHECKPOINT_ENVELOPE_BYTES = 48 * 1024
MAX_PENDING_CHECKPOINTS = 1024
EPOCH_ACTIVATION_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class CheckpointCommitAcknowledgement:
    """Broker-authenticated proof that a cursor and its WAL commit agree."""

    runtime_instance_id: str
    checkpoint_id: str
    reason: str
    transition: str
    binding_version: int
    cursor_hmac: str
    cursor_hmac_verified: bool
    wal_committed: bool
    state_integrity_verified: bool
    schema_version: int = CHECKPOINT_ENVELOPE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        require_int(
            self.schema_version,
            "native checkpoint acknowledgement schema_version",
            minimum=1,
        )
        if self.schema_version != CHECKPOINT_ENVELOPE_SCHEMA_VERSION:
            raise ContextModeStartupError("unsupported native checkpoint acknowledgement schema")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CheckpointCommitAcknowledgement":
        strict_object(
            value,
            required=frozenset(cls.__dataclass_fields__),
            name="native checkpoint commit acknowledgement",
        )
        require_int(
            value["schema_version"],
            "native checkpoint acknowledgement schema_version",
            minimum=1,
        )
        if value["schema_version"] != CHECKPOINT_ENVELOPE_SCHEMA_VERSION:
            raise ContextModeStartupError("unsupported native checkpoint acknowledgement schema")
        data = dict(value)
        data.pop("schema_version")
        try:
            acknowledgement = cls(**data)
        except TypeError as exc:
            raise ContextModeStartupError("malformed native checkpoint acknowledgement") from exc
        for field_name in ("runtime_instance_id", "checkpoint_id", "reason", "transition"):
            require_nonempty(getattr(acknowledgement, field_name), field_name)
        require_int(acknowledgement.binding_version, "binding_version", minimum=1)
        require_sha256(acknowledgement.cursor_hmac, "cursor_hmac")
        for field_name in (
            "cursor_hmac_verified",
            "wal_committed",
            "state_integrity_verified",
        ):
            if getattr(acknowledgement, field_name) is not True:
                raise ContextModeStartupError(
                    f"native checkpoint did not attest {field_name}"
                )
        return acknowledgement

    def validate(
        self,
        *,
        cursor: CheckpointCursor,
        binding: ContextBinding,
        runtime_instance_id: str,
        reason: str,
        transition: str,
    ) -> None:
        expected = {
            "runtime_instance_id": runtime_instance_id,
            "checkpoint_id": cursor.checkpoint_id,
            "reason": reason,
            "transition": transition,
            "binding_version": binding.binding_version,
            "cursor_hmac": cursor.cursor_hmac,
        }
        mismatches = [
            name for name, wanted in expected.items() if getattr(self, name) != wanted
        ]
        if mismatches:
            raise ContextModeStartupError(
                "native checkpoint acknowledgement does not match the request: "
                f"{mismatches!r}"
            )


@dataclass(frozen=True)
class CheckpointRecoveryAcknowledgement:
    """Bounded SessionStart recovery proof returned on the private channel."""

    runtime_instance_id: str
    checkpoint_id: str
    recovery_kind: str
    cursor_hmac: str
    context_event_seq: int
    last_committed_operation_id: str | None
    replayed_through_context_event_seq: int
    stable: Mapping[str, Any]
    recovered_from: Mapping[str, Any]
    active: Mapping[str, Any]
    cursor_hmac_verified: bool
    wal_integrity_verified: bool
    session_start_verified: bool
    schema_version: int = CHECKPOINT_ENVELOPE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        require_int(
            self.schema_version,
            "SessionStart recovery acknowledgement schema_version",
            minimum=1,
        )
        if self.schema_version != CHECKPOINT_ENVELOPE_SCHEMA_VERSION:
            raise ContextModeStartupError("unsupported SessionStart recovery acknowledgement schema")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CheckpointRecoveryAcknowledgement":
        strict_object(
            value,
            required=frozenset(cls.__dataclass_fields__),
            name="native SessionStart recovery acknowledgement",
        )
        require_int(
            value["schema_version"],
            "SessionStart recovery acknowledgement schema_version",
            minimum=1,
        )
        if value["schema_version"] != CHECKPOINT_ENVELOPE_SCHEMA_VERSION:
            raise ContextModeStartupError("unsupported SessionStart recovery acknowledgement schema")
        data = dict(value)
        data.pop("schema_version")
        for field_name in ("stable", "recovered_from", "active"):
            field_value = data.get(field_name)
            if not isinstance(field_value, Mapping):
                raise ContextModeStartupError(
                    f"SessionStart recovery acknowledgement {field_name} must be an object"
                )
            data[field_name] = dict(field_value)
        try:
            acknowledgement = cls(**data)
        except TypeError as exc:
            raise ContextModeStartupError("malformed SessionStart recovery acknowledgement") from exc
        for field_name in ("runtime_instance_id", "checkpoint_id", "recovery_kind"):
            require_nonempty(getattr(acknowledgement, field_name), field_name)
        require_sha256(acknowledgement.cursor_hmac, "cursor_hmac")
        require_int(acknowledgement.context_event_seq, "context_event_seq")
        require_int(
            acknowledgement.replayed_through_context_event_seq,
            "replayed_through_context_event_seq",
        )
        if acknowledgement.last_committed_operation_id is not None:
            require_nonempty(
                acknowledgement.last_committed_operation_id,
                "last_committed_operation_id",
            )
        for field_name in ("stable", "recovered_from", "active"):
            if not isinstance(getattr(acknowledgement, field_name), Mapping):
                raise ContextModeStartupError(
                    f"SessionStart recovery acknowledgement {field_name} must be an object"
                )
        for field_name in (
            "cursor_hmac_verified",
            "wal_integrity_verified",
            "session_start_verified",
        ):
            if getattr(acknowledgement, field_name) is not True:
                raise ContextModeStartupError(
                    f"SessionStart recovery did not attest {field_name}"
                )
        return acknowledgement

    def validate(
        self,
        *,
        cursor: CheckpointCursor,
        checkpoint_binding: ContextBinding,
        active_binding: ContextBinding,
        kind: CheckpointRecoveryKind,
        runtime_instance_id: str,
    ) -> None:
        strict_object(
            self.stable,
            required=frozenset(
                {"run_id", "workspace_id", "context_session_id", "context_state_epoch"}
            ),
            name="SessionStart recovery stable identity",
        )
        expected_stable = {
            "run_id": cursor.run_id,
            "workspace_id": cursor.workspace_id,
            "context_session_id": cursor.context_session_id,
            "context_state_epoch": cursor.context_state_epoch,
        }
        recovered_from = LifecycleSnapshot.from_dict(self.recovered_from)
        active = LifecycleSnapshot.from_dict(self.active)
        checks = {
            "runtime_instance_id": self.runtime_instance_id == runtime_instance_id,
            "checkpoint_id": self.checkpoint_id == cursor.checkpoint_id,
            "recovery_kind": self.recovery_kind == kind.value,
            "cursor_hmac": self.cursor_hmac == cursor.cursor_hmac,
            "context_event_seq": self.context_event_seq == cursor.context_event_seq,
            "last_committed_operation_id": (
                self.last_committed_operation_id == cursor.last_committed_operation_id
            ),
            "stable": dict(self.stable) == expected_stable,
            "recovered_from": recovered_from == checkpoint_binding.lifecycle,
            "active": active == active_binding.lifecycle,
            "replay_cursor": (
                self.replayed_through_context_event_seq >= cursor.context_event_seq
            ),
        }
        mismatches = [name for name, valid in checks.items() if not valid]
        if mismatches:
            raise ContextModeStartupError(
                "SessionStart recovery acknowledgement does not match the checkpoint/binding: "
                f"{mismatches!r}"
            )
        cursor.validate_recovery_binding(
            active_binding,
            kind=kind,
            expected_checkpoint_id=cursor.checkpoint_id,
        )


@dataclass(frozen=True)
class CheckpointRecoveryResult:
    cursor: CheckpointCursor
    acknowledgement: CheckpointRecoveryAcknowledgement
    newly_recovered: bool


@dataclass(frozen=True)
class _PendingCheckpoint:
    cursor: CheckpointCursor
    binding: ContextBinding
    transition: str
    recovery_kind: CheckpointRecoveryKind | None


@dataclass(frozen=True)
class NativeRuntimeEndpoint:
    """Public proxy material returned by the controller-owned native broker.

    The mapping is intentionally model/coder-readable and therefore may not
    contain an attestation or receipt signing secret.  Authority remains on the
    broker's pre-opened controller channel.
    """

    launcher_path: Path
    launcher_sha256: str
    public_bootstrap: Mapping[str, Any]
    runtime_instance_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.launcher_sha256, str):
            raise ContextModeStartupError("launcher_sha256 must be a lowercase SHA-256 hex digest")
        try:
            expected_digest = require_sha256(self.launcher_sha256, "launcher_sha256")
        except ContextModeDataError as exc:
            raise ContextModeStartupError(str(exc)) from exc
        _verify_launcher_file(Path(self.launcher_path), expected_sha256=expected_digest)
        if not isinstance(self.runtime_instance_id, str) or not self.runtime_instance_id:
            raise ContextModeStartupError("native runtime instance id is missing")
        if not isinstance(self.public_bootstrap, Mapping):
            raise ContextModeStartupError("native runtime public bootstrap must be an object")
        if frozenset(self.public_bootstrap) != {"channel"}:
            raise ContextModeStartupError(
                "native runtime public bootstrap schema must contain only channel"
            )
        channel = self.public_bootstrap["channel"]
        try:
            require_nonempty(channel, "public bootstrap channel")
        except ContextModeDataError as exc:
            raise ContextModeStartupError(str(exc)) from exc
        if len(channel.encode("utf-8")) > 256 or not re.fullmatch(
            r"[A-Za-z0-9._:-]+",
            channel,
        ):
            raise ContextModeStartupError(
                "public bootstrap channel must be a bounded opaque identifier"
            )
        encoded = canonical_json_bytes(dict(self.public_bootstrap))
        if len(encoded) > 64 * 1024:
            raise ContextModeStartupError("native runtime public bootstrap exceeds 64 KiB")
        if _public_bootstrap_has_authority_material(self.public_bootstrap):
            raise ContextModeStartupError("public bootstrap contains authority material")


class NativeContextRuntime(Protocol):
    """Platform package boundary for broker/process-tree ownership."""

    launcher_path: Path
    launcher_sha256: str

    async def start(
        self,
        *,
        bundle: VerifiedRuntimeBundle,
        backend: SandboxBackend,
        policies: tuple[SandboxPolicy, ...],
        binding: ContextBinding,
        run_root: Path,
        receipt_handler: Callable[[Any], None],
    ) -> NativeRuntimeEndpoint: ...

    async def launch_app_server(
        self,
        *,
        command: tuple[str, ...],
        cwd: Path | None,
        environment: Mapping[str, str],
        role: Any,
        stdout_limit: int,
    ) -> Any:
        """Spawn inside the role filesystem/process sandbox with provider network."""
        ...

    async def verify_app_server_boundary(
        self,
        *,
        supervisor_client: Any,
        coder_client: Any,
        binding: ContextBinding,
    ) -> Mapping[str, Any]: ...

    async def register_approval_capability(
        self,
        *,
        capability: Any,
        request_key: Mapping[str, Any],
    ) -> None: ...

    async def revoke_approval_capability(self, *, capability_id: str) -> None: ...

    async def update_binding(
        self,
        *,
        previous_binding: ContextBinding,
        binding: ContextBinding,
        reason: str,
    ) -> None:
        """Accept exactly the next controller-authoritative binding snapshot.

        Returning normally is the native broker's acknowledgement that the
        previous snapshot was current and the candidate was installed.  A
        rejection or an indeterminate transport failure must raise; the Python
        controller then permanently fails this prepared runtime.
        """
        ...

    async def activate_state_epoch(
        self,
        *,
        previous_binding: ContextBinding,
        binding: ContextBinding,
        exclusive_lease_id: str,
        previous_epoch_root: Path,
        active_epoch_root: Path,
        policies: tuple[SandboxPolicy, ...],
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        """Atomically switch the broker to a fresh exact epoch mount.

        The acknowledgement must prove that every writer using the previous
        epoch is terminal/reaped.  Python retains the old directory; only the
        signed broker or retention manager may retire it after coder recycle.
        """
        ...

    async def acquire_purge_lease(
        self,
        *,
        binding: ContextBinding,
        exclusive_lease_id: str,
        owner: str,
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        """Fence all calls except the one purge capability bound to this lease."""
        ...

    async def release_purge_lease(
        self,
        *,
        binding: ContextBinding,
        exclusive_lease_id: str,
    ) -> None:
        """Atomically release the broker fence and resume ordinary calls."""
        ...

    async def quiesce(self, *, binding: ContextBinding, timeout_seconds: float) -> None: ...

    async def checkpoint(
        self,
        *,
        binding: ContextBinding,
        reason: str,
        transition: str,
        timeout_seconds: float,
    ) -> Mapping[str, Any]: ...

    async def recover_checkpoint(
        self,
        *,
        cursor: Mapping[str, Any],
        checkpoint_binding: ContextBinding,
        binding: ContextBinding,
        recovery_kind: str,
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        """Return a broker-verified acknowledgement of the SessionStart recovery."""
        ...

    async def resume(self, *, binding: ContextBinding) -> None: ...

    async def stop(self, *, timeout_seconds: float) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class ContextBootstrapPaths:
    mcp: Path
    hooks: Mapping[str, Path]


@dataclass
class PreparedContextMode:
    bundle: VerifiedRuntimeBundle
    backend: SandboxBackend
    policies: tuple[SandboxPolicy, ...]
    binding_store: BindingStore
    capability_store: OneShotCapabilityStore
    coordinator: ContextRuntimeCoordinator
    native_runtime: NativeContextRuntime
    endpoint: NativeRuntimeEndpoint
    bootstraps: ContextBootstrapPaths
    recovery_tracker: CheckpointRecoveryTracker | None = None
    epoch_layout: ContextEpochLayout | None = None
    sandbox_layout: SandboxPathLayout | None = None
    clean_environment: Mapping[str, str] | None = None
    purge_protocol_attested: bool = field(default=False, init=False)
    checkpoint_protocol_attested: bool = field(default=False, init=False)
    _binding_update_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    _pending_checkpoints: dict[str, _PendingCheckpoint] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )
    _issued_checkpoint_ids: set[str] = field(default_factory=set, init=False, repr=False)
    _recovered_checkpoints: dict[str, CheckpointRecoveryResult] = field(
        default_factory=dict,
        init=False,
        repr=False,
    )

    @property
    def binding(self) -> ContextBinding:
        return self.binding_store.load()

    def active_epoch_root(self, binding: ContextBinding | None = None) -> Path:
        """Return and verify the only state directory visible to MCP/hooks."""

        selected = binding or self.binding_store.load()
        if self.epoch_layout is None or self.sandbox_layout is None or self.clean_environment is None:
            raise ContextModeStartupError("physical Context Mode epoch contract is not configured")
        if self.epoch_layout.workspace_id != selected.stable.workspace_id:
            raise ContextModeStartupError("physical Context Mode workspace identity mismatch")
        expected = self.epoch_layout.validate_epoch(selected.lifecycle.context_state_epoch)
        if Path(self.sandbox_layout.state) != expected:
            raise ContextModeStartupError("sandbox state layout does not select the active epoch")
        if self.clean_environment.get("CONTEXT_MODE_DIR") != os.fspath(expected):
            raise ContextModeStartupError("Context Mode environment selects a stale epoch")
        policy_map = {policy.profile: policy for policy in self.policies}
        mcp_policy = policy_map.get(ProfileKind.MCP)
        if mcp_policy is None or mcp_policy.digest != selected.lifecycle.sandbox_policy_digest:
            raise ContextModeStartupError("active epoch MCP policy digest mismatches binding")
        for profile in (ProfileKind.MCP, ProfileKind.HOOK):
            policy = policy_map.get(profile)
            if policy is None:
                raise ContextModeStartupError(f"active epoch policy is missing {profile.value}")
            state_mounts = [mount for mount in policy.mounts if mount.path_class == "context_state"]
            if (
                len(state_mounts) != 1
                or state_mounts[0].source != os.fspath(expected)
                or state_mounts[0].target != os.fspath(expected)
                or policy.environment.get("CONTEXT_MODE_DIR") != os.fspath(expected)
            ):
                raise ContextModeStartupError(
                    f"{profile.value} policy does not mount only the active physical epoch"
                )
        for profile in (ProfileKind.COMMAND, ProfileKind.PROXY):
            policy = policy_map.get(profile)
            if policy is None:
                raise ContextModeStartupError(f"active epoch policy is missing {profile.value}")
            if any(mount.path_class == "context_state" for mount in policy.mounts):
                raise ContextModeStartupError(
                    f"{profile.value} policy unexpectedly exposes Context Mode state"
                )
        return expected

    def _require_active_epoch(self, binding: ContextBinding | None = None) -> Path:
        try:
            return self.active_epoch_root(binding)
        except (ContextModeDataError, OSError, RuntimeError) as exc:
            self.coordinator.mark_failed()
            if isinstance(exc, ContextModeStartupError):
                raise
            raise ContextModeStartupError(
                "physical Context Mode epoch validation failed closed"
            ) from exc

    async def acquire_purge_lease(
        self,
        *,
        owner: str,
        timeout_seconds: float = 30.0,
    ) -> ExclusiveWorkspaceLease:
        """Fence Context calls while one exact ``ctx_purge`` awaits approval."""

        if not self.purge_protocol_attested:
            self.coordinator.mark_failed()
            raise ContextModeStartupError(
                "ctx_purge requires the attested exclusive physical-epoch protocol"
            )
        binding = self.binding_store.load()
        self._require_active_epoch(binding)
        try:
            lease = await asyncio.to_thread(
                self.coordinator.acquire_exclusive_workspace_lease,
                owner=owner,
                binding_version=binding.binding_version,
                generation_lease_id=binding.lifecycle.generation_lease_id,
                timeout_seconds=timeout_seconds,
            )
            acknowledgement = await _await_result(
                self.native_runtime.acquire_purge_lease(
                    binding=binding,
                    exclusive_lease_id=lease.lease_id,
                    owner=lease.owner,
                    timeout_seconds=timeout_seconds,
                )
            )
            _validate_purge_lease_acknowledgement(
                acknowledgement,
                runtime_instance_id=self.endpoint.runtime_instance_id,
                binding=binding,
                lease=lease,
            )
            return lease
        except BaseException as exc:
            self.coordinator.mark_failed()
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise ContextModeStartupError(
                "native broker could not establish the exclusive ctx_purge lease"
            ) from exc

    async def acquire_logical_restart_bootstrap_lease(
        self,
        *,
        owner: str,
        timeout_seconds: float = 30.0,
    ) -> ExclusiveWorkspaceLease:
        """Use the attested native purge fence only to bootstrap a new MCP session."""

        if not self.purge_protocol_attested:
            self.coordinator.mark_failed()
            raise ContextModeStartupError(
                "logical restart MCP bootstrap requires the attested exclusive fence"
            )
        binding = self.binding_store.load()
        self._require_active_epoch(binding)
        try:
            lease = await asyncio.to_thread(
                self.coordinator.acquire_logical_restart_bootstrap_lease,
                owner=owner,
                binding_version=binding.binding_version,
                generation_lease_id=binding.lifecycle.generation_lease_id,
                timeout_seconds=timeout_seconds,
            )
            acknowledgement = await _await_result(
                self.native_runtime.acquire_purge_lease(
                    binding=binding,
                    exclusive_lease_id=lease.lease_id,
                    owner=lease.owner,
                    timeout_seconds=timeout_seconds,
                )
            )
            _validate_purge_lease_acknowledgement(
                acknowledgement,
                runtime_instance_id=self.endpoint.runtime_instance_id,
                binding=binding,
                lease=lease,
            )
            return lease
        except BaseException as exc:
            self.coordinator.mark_failed()
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise ContextModeStartupError(
                "native broker could not establish the logical restart bootstrap fence"
            ) from exc

    async def rotate_state_epoch(
        self,
        *,
        exclusive_workspace_lease: ExclusiveWorkspaceLease,
        timeout_seconds: float = 30.0,
    ) -> tuple[ContextBinding, ExclusiveWorkspaceLease]:
        """Create and activate a fresh physical epoch under the purge fence."""

        if not self.purge_protocol_attested:
            self.coordinator.mark_failed()
            raise ContextModeStartupError("physical state epoch rotation was not attested")
        if self.epoch_layout is None or self.sandbox_layout is None or self.clean_environment is None:
            self.coordinator.mark_failed()
            raise ContextModeStartupError("physical Context Mode epoch contract is unavailable")
        async with self._binding_update_lock:
            try:
                previous = self.coordinator.require_exclusive_workspace_lease(
                    exclusive_workspace_lease
                )
                previous_root = self._require_active_epoch(previous)
                next_epoch = previous.lifecycle.context_state_epoch + 1
                active_root = self.epoch_layout.create_fresh_epoch(next_epoch)
                next_environment = dict(self.clean_environment)
                next_environment["CONTEXT_MODE_DIR"] = os.fspath(active_root)
                next_layout = replace(self.sandbox_layout, state=active_root)
                policy_map = generate_sandbox_policies(
                    next_layout,
                    environment=next_environment,
                )
                next_policies = tuple(policy_map.values())
                next_mcp_policy = policy_map[ProfileKind.MCP]
                candidate = previous.transition(
                    TransitionReason.STATE_EPOCH_ROTATION,
                    context_state_epoch=next_epoch,
                    sandbox_policy_digest=next_mcp_policy.digest,
                )
                self.coordinator.validate_exclusive_workspace_transition(
                    exclusive_workspace_lease,
                    previous_binding=previous,
                    binding=candidate,
                    reason=TransitionReason.STATE_EPOCH_ROTATION,
                )
                payloads = _bootstrap_payloads(
                    self.bootstraps,
                    endpoint=self.endpoint,
                    binding=candidate,
                    policies=policy_map,
                )
                for payload in payloads.values():
                    canonical_json_bytes(payload)
                acknowledgement = await _await_result(
                    self.native_runtime.activate_state_epoch(
                        previous_binding=previous,
                        binding=candidate,
                        exclusive_lease_id=exclusive_workspace_lease.lease_id,
                        previous_epoch_root=previous_root,
                        active_epoch_root=active_root,
                        policies=next_policies,
                        timeout_seconds=timeout_seconds,
                    )
                )
                _validate_epoch_activation_acknowledgement(
                    acknowledgement,
                    runtime_instance_id=self.endpoint.runtime_instance_id,
                    previous=previous,
                    candidate=candidate,
                    lease=exclusive_workspace_lease,
                    previous_epoch_root=previous_root,
                    active_epoch_root=active_root,
                    active_policy_digest=next_mcp_policy.digest,
                )
                # The Python side never deletes the old epoch.  Its continued
                # presence is verified after the broker attests writer reap;
                # retirement is left to the post-recycle retention authority.
                self.epoch_layout.validate_epoch(previous.lifecycle.context_state_epoch)
                self.epoch_layout.validate_epoch(next_epoch)
                committed = self.binding_store.compare_and_swap(
                    expected_version=previous.binding_version,
                    candidate=candidate,
                    reason=TransitionReason.STATE_EPOCH_ROTATION,
                )
                self.policies = next_policies
                self.sandbox_layout = next_layout
                self.clean_environment = next_environment
                advanced_lease = self.coordinator.advance_exclusive_workspace_lease(
                    exclusive_workspace_lease,
                    previous_binding=previous,
                    binding=committed,
                    reason=TransitionReason.STATE_EPOCH_ROTATION,
                )
                self.coordinator.replace_policies_for_exclusive_workspace_lease(
                    advanced_lease,
                    next_policies,
                )
                _install_bootstrap_payloads(payloads)
                self._require_active_epoch(committed)
                return committed, advanced_lease
            except BaseException as exc:
                self.coordinator.mark_failed()
                if isinstance(exc, asyncio.CancelledError):
                    raise
                if isinstance(exc, ContextModeStartupError):
                    raise
                raise ContextModeStartupError(
                    "native physical Context Mode epoch activation failed closed"
                ) from exc

    def expected_coder_hook_attestations(self) -> dict[str, dict[str, Any]]:
        """Return exact public file identities the native boundary must attest."""

        if frozenset(self.bootstraps.hooks) != frozenset(REQUIRED_HOOKS):
            raise ContextModeStartupError("generated hook bootstrap paths do not cover the exact hook catalogue")
        launcher = Path(self.endpoint.launcher_path)
        _verify_launcher_file(launcher, expected_sha256=self.endpoint.launcher_sha256)
        launcher_info = launcher.lstat()
        payloads = _bootstrap_payloads(
            self.bootstraps,
            endpoint=self.endpoint,
            binding=self.binding,
            policies={policy.profile: policy for policy in self.policies},
        )
        attestations: dict[str, dict[str, Any]] = {}
        for event in REQUIRED_HOOKS:
            bootstrap = Path(self.bootstraps.hooks[event])
            expected_payload = canonical_json_bytes(payloads[bootstrap]) + b"\n"
            bootstrap_attestation = _attest_public_bootstrap_file(
                bootstrap,
                expected_sha256=hashlib.sha256(expected_payload).hexdigest(),
            )
            attestations[event] = {
                "launcher_path": os.fspath(launcher),
                "launcher_uid": launcher_info.st_uid,
                "launcher_mode": stat.S_IMODE(launcher_info.st_mode),
                "launcher_sha256": self.endpoint.launcher_sha256,
                "bootstrap_path": bootstrap_attestation["path"],
                "bootstrap_uid": bootstrap_attestation["uid"],
                "bootstrap_mode": bootstrap_attestation["mode"],
                "bootstrap_sha256": bootstrap_attestation["sha256"],
            }
        return attestations

    async def transition_binding(
        self,
        *,
        expected_version: int,
        reason: TransitionReason | str,
        **changes: Any,
    ) -> ContextBinding:
        """Commit one binding transition across broker, store, and bootstraps.

        There is no safe rollback after a native transport failure: the broker
        may have received the candidate even when its acknowledgement was lost.
        Consequently every failure marks the runtime unusable.  On success the
        method returns only after the controller CAS and every public launcher
        bootstrap contain the same next binding version.
        """

        transition_reason = TransitionReason(reason)
        if transition_reason is TransitionReason.STATE_EPOCH_ROTATION:
            self.coordinator.mark_failed()
            raise ContextModeStartupError(
                "logical-only state epoch rotation is forbidden; use rotate_state_epoch"
            )
        async with self._binding_update_lock:
            previous = self.binding_store.load()
            if previous.binding_version != expected_version:
                self.coordinator.mark_failed()
                raise ContextModeStartupError(
                    "binding transition uses a stale expected version: "
                    f"expected {expected_version}, found {previous.binding_version}"
                )
            try:
                self._require_active_epoch(previous)
                candidate = previous.transition(transition_reason, **changes)
                active_lease = self.coordinator.exclusive_workspace_lease
                if active_lease is not None:
                    self.coordinator.validate_exclusive_workspace_transition(
                        active_lease,
                        previous_binding=previous,
                        binding=candidate,
                        reason=transition_reason,
                    )
                # Render and validate all public JSON before changing either
                # authority.  Individual files are installed with atomic
                # rename; callers hold the lifecycle boundary while a
                # multi-file set is replaced, so no launcher invocation can
                # observe a mixed set.
                payloads = _bootstrap_payloads(
                    self.bootstraps,
                    endpoint=self.endpoint,
                    binding=candidate,
                    policies={policy.profile: policy for policy in self.policies},
                )
                for payload in payloads.values():
                    canonical_json_bytes(payload)
                acknowledgement = await _await_result(
                    self.native_runtime.update_binding(
                        previous_binding=previous,
                        binding=candidate,
                        reason=transition_reason.value,
                    )
                )
                if acknowledgement is not None:
                    raise ContextModeStartupError(
                        "native binding update returned an ambiguous acknowledgement"
                    )
                committed = self.binding_store.compare_and_swap(
                    expected_version=previous.binding_version,
                    candidate=candidate,
                    reason=transition_reason,
                )
                if active_lease is not None:
                    self.coordinator.advance_exclusive_workspace_lease(
                        active_lease,
                        previous_binding=previous,
                        binding=committed,
                        reason=transition_reason,
                    )
                _install_bootstrap_payloads(payloads)
            except BaseException as exc:
                self.coordinator.mark_failed()
                if isinstance(exc, asyncio.CancelledError):
                    raise
                raise ContextModeStartupError(
                    "native broker rejected or could not durably propagate "
                    f"binding transition {transition_reason.value!r}"
                ) from exc
            return committed

    async def quiesce(self, *, timeout_seconds: float = 30.0) -> ContextBinding:
        # The coordinator uses a condition variable and may wait for active
        # operations; keep that bounded wait off the controller event loop.
        binding = await asyncio.to_thread(
            self.coordinator.quiesce,
            timeout_seconds=timeout_seconds,
        )
        try:
            self._require_active_epoch(binding)
            await _await_result(
                self.native_runtime.quiesce(binding=binding, timeout_seconds=timeout_seconds)
            )
            return binding
        except BaseException as exc:
            self.coordinator.mark_failed()
            if isinstance(exc, asyncio.CancelledError):
                raise
            if isinstance(exc, ContextModeStartupError):
                raise
            raise ContextModeStartupError("native Context Mode quiesce failed closed") from exc

    async def resume(
        self,
        *,
        exclusive_workspace_lease: ExclusiveWorkspaceLease | None = None,
    ) -> ContextBinding:
        tracker = self.recovery_tracker
        blocking = [
            checkpoint_id
            for checkpoint_id, checkpoint in self._pending_checkpoints.items()
            if checkpoint.recovery_kind is not None
            and (tracker is None or not tracker.contains(checkpoint_id))
        ]
        if blocking:
            self.coordinator.mark_failed()
            raise ContextModeStartupError(
                "Context Mode cannot resume before verified checkpoint recovery: "
                f"{blocking[:4]!r}"
            )
        binding = self.binding_store.load()
        self._require_active_epoch(binding)
        try:
            if exclusive_workspace_lease is not None:
                self.coordinator.require_exclusive_workspace_lease(
                    exclusive_workspace_lease
                )
            if exclusive_workspace_lease is None:
                await _await_result(self.native_runtime.resume(binding=binding))
                self.coordinator.resume_accepting()
            else:
                acknowledgement = await _await_result(
                    self.native_runtime.release_purge_lease(
                        binding=binding,
                        exclusive_lease_id=exclusive_workspace_lease.lease_id,
                    )
                )
                if acknowledgement is not None:
                    raise ContextModeStartupError(
                        "native purge lease release returned an ambiguous acknowledgement"
                    )
                self.coordinator.release_exclusive_workspace_lease(
                    exclusive_workspace_lease
                )
            return binding
        except BaseException as exc:
            self.coordinator.mark_failed()
            if isinstance(exc, asyncio.CancelledError):
                raise
            if isinstance(exc, ContextModeStartupError):
                raise
            raise ContextModeStartupError("native Context Mode resume failed closed") from exc

    async def checkpoint(
        self,
        *,
        reason: str,
        transition: str,
        recovery_kind: CheckpointRecoveryKind | str | None = None,
        timeout_seconds: float = 30.0,
    ) -> CheckpointCursor:
        if not self.checkpoint_protocol_attested:
            self.coordinator.mark_failed()
            raise ContextModeStartupError(
                "native checkpoint protocol was not attested at the app-server boundary"
            )
        if self.coordinator.state is not RuntimeState.QUIESCED:
            raise ContextModeStartupError("Context Mode checkpoint requires a quiesced runtime")
        require_nonempty(reason, "checkpoint reason")
        require_nonempty(transition, "checkpoint transition")
        if len(reason.encode("utf-8")) > 2 * 1024:
            raise ContextModeStartupError("checkpoint reason exceeds 2 KiB")
        if len(transition.encode("utf-8")) > 256:
            raise ContextModeStartupError("checkpoint transition exceeds 256 bytes")
        selected_kind = (
            CheckpointRecoveryKind(recovery_kind)
            if recovery_kind is not None
            else None
        )
        checkpoint_binding = self.binding_store.load()
        self._require_active_epoch(checkpoint_binding)
        try:
            payload = await _await_result(
                self.native_runtime.checkpoint(
                    binding=checkpoint_binding,
                    reason=reason,
                    transition=transition,
                    timeout_seconds=timeout_seconds,
                )
            )
            if not isinstance(payload, Mapping):
                raise ContextModeStartupError(
                    "native checkpoint did not return a structured commit envelope"
                )
            if len(canonical_json_bytes(dict(payload))) > MAX_CHECKPOINT_ENVELOPE_BYTES:
                raise ContextModeStartupError("native checkpoint envelope exceeds 48 KiB")
            strict_object(
                payload,
                required=frozenset({"schema_version", "cursor", "acknowledgement"}),
                name="native checkpoint envelope",
            )
            require_int(
                payload["schema_version"],
                "native checkpoint envelope schema_version",
                minimum=1,
            )
            if payload["schema_version"] != CHECKPOINT_ENVELOPE_SCHEMA_VERSION:
                raise ContextModeStartupError("unsupported native checkpoint envelope schema")
            cursor_payload = payload["cursor"]
            acknowledgement_payload = payload["acknowledgement"]
            if not isinstance(cursor_payload, Mapping) or not isinstance(
                acknowledgement_payload,
                Mapping,
            ):
                raise ContextModeStartupError(
                    "native checkpoint cursor and acknowledgement must be objects"
                )
            cursor = CheckpointCursor.from_dict(cursor_payload)
            cursor.validate_binding(
                checkpoint_binding,
                expected_reason=reason,
                exact_lifecycle=True,
            )
            acknowledgement = CheckpointCommitAcknowledgement.from_dict(
                acknowledgement_payload
            )
            acknowledgement.validate(
                cursor=cursor,
                binding=checkpoint_binding,
                runtime_instance_id=self.endpoint.runtime_instance_id,
                reason=reason,
                transition=transition,
            )
            tracker = self.recovery_tracker
            if tracker is None:
                raise ContextModeStartupError(
                    "native checkpoint recovery tracker is not configured"
                )
            if tracker.contains(cursor.checkpoint_id):
                raise ContextModeStartupError("native broker reused a recovered checkpoint_id")
            if cursor.checkpoint_id in self._issued_checkpoint_ids:
                raise ContextModeStartupError("native broker reused a checkpoint_id")
            if len(self._issued_checkpoint_ids) >= self.recovery_tracker.maximum_checkpoints:
                raise ContextModeStartupError(
                    "native checkpoint identity capacity exceeded; refusing fail-open eviction"
                )
            if selected_kind is not None and len(self._pending_checkpoints) >= MAX_PENDING_CHECKPOINTS:
                raise ContextModeStartupError(
                    "pending native checkpoint capacity exceeded; refusing fail-open eviction"
                )
            self._issued_checkpoint_ids.add(cursor.checkpoint_id)
            if selected_kind is not None:
                self._pending_checkpoints[cursor.checkpoint_id] = _PendingCheckpoint(
                    cursor=cursor,
                    binding=checkpoint_binding,
                    transition=transition,
                    recovery_kind=selected_kind,
                )
            active_lease = self.coordinator.exclusive_workspace_lease
            if selected_kind is CheckpointRecoveryKind.LOGICAL_RESTART:
                if (
                    active_lease is None
                    or active_lease.purpose
                    is not ExclusiveWorkspaceLeasePurpose.LOGICAL_RESTART_BOOTSTRAP
                ):
                    raise ContextModeStartupError(
                        "logical restart checkpoint requires its exclusive bootstrap fence"
                    )
                self.coordinator.checkpoint_logical_restart_bootstrap_lease(
                    active_lease,
                    binding=checkpoint_binding,
                    checkpoint_id=cursor.checkpoint_id,
                )
            elif (
                active_lease is not None
                and active_lease.purpose
                is ExclusiveWorkspaceLeasePurpose.LOGICAL_RESTART_BOOTSTRAP
            ):
                raise ContextModeStartupError(
                    "logical restart bootstrap fence received another checkpoint kind"
                )
            return cursor
        except BaseException as exc:
            self.coordinator.mark_failed()
            if isinstance(exc, asyncio.CancelledError):
                raise
            if isinstance(exc, ContextModeStartupError):
                raise
            raise ContextModeStartupError(
                "native checkpoint commit could not be verified"
            ) from exc

    async def recover_checkpoint(
        self,
        *,
        checkpoint_id: str,
        recovery_kind: CheckpointRecoveryKind | str,
        timeout_seconds: float = 30.0,
    ) -> CheckpointRecoveryResult:
        """Verify and persist one reason-specific SessionStart recovery."""

        require_nonempty(checkpoint_id, "checkpoint_id")
        if not self.checkpoint_protocol_attested:
            self.coordinator.mark_failed()
            raise ContextModeStartupError(
                "native recovery protocol was not attested at the app-server boundary"
            )
        kind = CheckpointRecoveryKind(recovery_kind)
        recovered = self._recovered_checkpoints.get(checkpoint_id)
        if recovered is not None:
            if recovered.acknowledgement.recovery_kind != kind.value:
                self.coordinator.mark_failed()
                raise ContextModeStartupError(
                    "replayed SessionStart recovery changed its recovery kind"
                )
            return CheckpointRecoveryResult(
                cursor=recovered.cursor,
                acknowledgement=recovered.acknowledgement,
                newly_recovered=False,
            )
        if self.coordinator.state is not RuntimeState.QUIESCED:
            raise ContextModeStartupError(
                "checkpoint recovery acknowledgement requires a quiesced runtime"
            )
        pending = self._pending_checkpoints.get(checkpoint_id)
        if pending is None:
            self.coordinator.mark_failed()
            raise ContextModeStartupError("SessionStart acknowledged an unknown checkpoint_id")
        if pending.recovery_kind is not kind:
            self.coordinator.mark_failed()
            raise ContextModeStartupError(
                "SessionStart recovery kind does not match the checkpoint request"
            )
        tracker = self.recovery_tracker
        if tracker is None:
            self.coordinator.mark_failed()
            raise ContextModeStartupError("native checkpoint recovery tracker is not configured")
        active_binding = self.binding_store.load()
        self._require_active_epoch(active_binding)
        try:
            payload = await _await_result(
                self.native_runtime.recover_checkpoint(
                    cursor=pending.cursor.to_dict(),
                    checkpoint_binding=pending.binding,
                    binding=active_binding,
                    recovery_kind=kind.value,
                    timeout_seconds=timeout_seconds,
                )
            )
            if not isinstance(payload, Mapping):
                raise ContextModeStartupError(
                    "native SessionStart recovery did not return a structured acknowledgement"
                )
            if len(canonical_json_bytes(dict(payload))) > MAX_CHECKPOINT_ENVELOPE_BYTES:
                raise ContextModeStartupError(
                    "native SessionStart recovery acknowledgement exceeds 48 KiB"
                )
            acknowledgement = CheckpointRecoveryAcknowledgement.from_dict(payload)
            acknowledgement.validate(
                cursor=pending.cursor,
                checkpoint_binding=pending.binding,
                active_binding=active_binding,
                kind=kind,
                runtime_instance_id=self.endpoint.runtime_instance_id,
            )
            newly_recovered = tracker.acknowledge_native_verified(
                pending.cursor,
                binding=active_binding,
                kind=kind,
            )
            result = CheckpointRecoveryResult(
                cursor=pending.cursor,
                acknowledgement=acknowledgement,
                newly_recovered=newly_recovered,
            )
            self._pending_checkpoints.pop(checkpoint_id, None)
            if len(self._recovered_checkpoints) >= MAX_PENDING_CHECKPOINTS:
                oldest = next(iter(self._recovered_checkpoints))
                self._recovered_checkpoints.pop(oldest)
            self._recovered_checkpoints[checkpoint_id] = result
            active_lease = self.coordinator.exclusive_workspace_lease
            if kind is CheckpointRecoveryKind.LOGICAL_RESTART:
                if (
                    active_lease is None
                    or active_lease.purpose
                    is not ExclusiveWorkspaceLeasePurpose.LOGICAL_RESTART_BOOTSTRAP
                ):
                    raise ContextModeStartupError(
                        "logical restart recovery lost its exclusive bootstrap fence"
                    )
                self.coordinator.recover_logical_restart_bootstrap_lease(
                    active_lease,
                    binding=active_binding,
                    checkpoint_id=checkpoint_id,
                )
            elif (
                active_lease is not None
                and active_lease.purpose
                is ExclusiveWorkspaceLeasePurpose.LOGICAL_RESTART_BOOTSTRAP
            ):
                raise ContextModeStartupError(
                    "logical restart bootstrap fence received another recovery kind"
                )
            return result
        except BaseException as exc:
            self.coordinator.mark_failed()
            if isinstance(exc, asyncio.CancelledError):
                raise
            if isinstance(exc, ContextModeStartupError):
                raise
            raise ContextModeStartupError(
                "native SessionStart checkpoint recovery could not be verified"
            ) from exc

    async def stop(self, *, timeout_seconds: float = 30.0) -> None:
        if self.coordinator.state is RuntimeState.ACCEPTING:
            await self.quiesce(timeout_seconds=timeout_seconds)
        attestation = await _await_result(
            self.native_runtime.stop(timeout_seconds=timeout_seconds)
        )
        if not isinstance(attestation, Mapping):
            self.coordinator.mark_failed()
            raise ContextModeStartupError(
                "native runtime stop returned no process-tree reap attestation"
            )
        try:
            strict_object(
                attestation,
                required=frozenset(
                    {
                        "schema_version",
                        "runtime_instance_id",
                        "process_tree_reaped",
                        "descendants_reaped",
                        "writer_handles_closed",
                    }
                ),
                name="native runtime stop attestation",
            )
            require_int(
                attestation["schema_version"],
                "native runtime stop schema_version",
                minimum=1,
            )
            if (
                attestation["schema_version"] != 1
                or attestation["runtime_instance_id"] != self.endpoint.runtime_instance_id
                or attestation["process_tree_reaped"] is not True
                or attestation["descendants_reaped"] is not True
                or attestation["writer_handles_closed"] is not True
            ):
                raise ContextModeStartupError(
                    "native runtime stop did not attest every writer as reaped"
                )
        except (ContextModeDataError, KeyError) as exc:
            self.coordinator.mark_failed()
            if isinstance(exc, ContextModeStartupError):
                raise
            raise ContextModeStartupError(
                "native runtime stop attestation schema mismatch"
            ) from exc
        self.coordinator.stop(timeout_seconds=timeout_seconds)


def _validate_purge_lease_acknowledgement(
    value: Any,
    *,
    runtime_instance_id: str,
    binding: ContextBinding,
    lease: ExclusiveWorkspaceLease,
) -> None:
    if not isinstance(value, Mapping):
        raise ContextModeStartupError("native purge lease returned no acknowledgement")
    required = frozenset(
        {
            "schema_version",
            "runtime_instance_id",
            "exclusive_lease_id",
            "owner",
            "binding_version",
            "workspace_id",
            "context_session_id",
            "context_state_epoch",
            "active_operations",
            "exclusive",
            "quiesced",
            "purge_only_bypass",
        }
    )
    try:
        strict_object(value, required=required, name="native purge lease acknowledgement")
        require_int(value["schema_version"], "purge lease schema_version", minimum=1)
        require_int(value["binding_version"], "purge lease binding_version", minimum=1)
        require_int(value["context_state_epoch"], "purge lease context_state_epoch")
        require_int(value["active_operations"], "purge lease active_operations")
    except (ContextModeDataError, KeyError) as exc:
        raise ContextModeStartupError("native purge lease acknowledgement schema mismatch") from exc
    expected = {
        "schema_version": 1,
        "runtime_instance_id": runtime_instance_id,
        "exclusive_lease_id": lease.lease_id,
        "owner": lease.owner,
        "binding_version": binding.binding_version,
        "workspace_id": binding.stable.workspace_id,
        "context_session_id": binding.stable.context_session_id,
        "context_state_epoch": binding.lifecycle.context_state_epoch,
        "active_operations": 0,
        "exclusive": True,
        "quiesced": True,
        "purge_only_bypass": True,
    }
    truth_fields = {"exclusive", "quiesced", "purge_only_bypass"}
    mismatches = [
        name
        for name, expected_value in expected.items()
        if (value[name] is not True if name in truth_fields else value[name] != expected_value)
    ]
    if mismatches:
        raise ContextModeStartupError(
            "native purge lease acknowledgement does not bind the exclusive fence: "
            f"{mismatches!r}"
        )


def _validate_epoch_activation_acknowledgement(
    value: Any,
    *,
    runtime_instance_id: str,
    previous: ContextBinding,
    candidate: ContextBinding,
    lease: ExclusiveWorkspaceLease,
    previous_epoch_root: Path,
    active_epoch_root: Path,
    active_policy_digest: str,
) -> None:
    """Verify the native switch/reap proof before committing the binding CAS."""

    if not isinstance(value, Mapping):
        raise ContextModeStartupError(
            "native epoch activation returned no structured acknowledgement"
        )
    required = frozenset(
        {
            "schema_version",
            "runtime_instance_id",
            "exclusive_lease_id",
            "run_id",
            "workspace_id",
            "context_session_id",
            "previous_binding_version",
            "binding_version",
            "previous_epoch",
            "active_epoch",
            "previous_epoch_root",
            "active_epoch_root",
            "active_policy_digest",
            "new_epoch_empty",
            "active_epoch_switched",
            "old_epoch_unmounted",
            "process_tree_reaped",
            "descendants_reaped",
            "writer_handles_closed",
            "old_epoch_retained",
        }
    )
    try:
        strict_object(value, required=required, name="native epoch activation acknowledgement")
        require_int(value["schema_version"], "epoch activation schema_version", minimum=1)
        require_int(value["previous_binding_version"], "previous_binding_version", minimum=1)
        require_int(value["binding_version"], "binding_version", minimum=1)
        require_int(value["previous_epoch"], "previous_epoch")
        require_int(value["active_epoch"], "active_epoch")
        require_sha256(value["active_policy_digest"], "active_policy_digest")
    except (ContextModeDataError, KeyError) as exc:
        raise ContextModeStartupError(
            "native epoch activation acknowledgement schema mismatch"
        ) from exc
    expected = {
        "schema_version": EPOCH_ACTIVATION_SCHEMA_VERSION,
        "runtime_instance_id": runtime_instance_id,
        "exclusive_lease_id": lease.lease_id,
        "run_id": previous.stable.run_id,
        "workspace_id": previous.stable.workspace_id,
        "context_session_id": previous.stable.context_session_id,
        "previous_binding_version": previous.binding_version,
        "binding_version": candidate.binding_version,
        "previous_epoch": previous.lifecycle.context_state_epoch,
        "active_epoch": candidate.lifecycle.context_state_epoch,
        "previous_epoch_root": os.fspath(previous_epoch_root),
        "active_epoch_root": os.fspath(active_epoch_root),
        "active_policy_digest": active_policy_digest,
    }
    mismatches = [name for name, expected_value in expected.items() if value[name] != expected_value]
    truth_fields = (
        "new_epoch_empty",
        "active_epoch_switched",
        "old_epoch_unmounted",
        "process_tree_reaped",
        "descendants_reaped",
        "writer_handles_closed",
        "old_epoch_retained",
    )
    missing_truth = [name for name in truth_fields if value[name] is not True]
    if mismatches or missing_truth:
        raise ContextModeStartupError(
            "native epoch activation acknowledgement does not prove the exact "
            f"switch/reap contract: mismatches={mismatches!r}, false={missing_truth!r}"
        )


async def prepare_context_mode(
    *,
    run_root: Path,
    workspace: Path,
    run_id: str,
    workspace_id: str,
    context_session_id: str,
    base_config_digest: str,
    coder_generation: int,
    coder_process_epoch: int,
    app_server_instance_id: str,
    generation_lease_id: str,
    vendor_root: Path,
    backend: SandboxBackend,
    native_runtime: NativeContextRuntime | None,
    protected_roots: Sequence[Path] = (),
    toolchain_roots: Sequence[Path] = (),
    immutable_workspace_paths: Sequence[Path] = (),
    readonly_dependency_roots: Sequence[Path] = (),
    workspace_masked_paths: Sequence[Path] = (),
    receipt_handler: Callable[[Any], None] | None = None,
) -> PreparedContextMode:
    """Verify, bind and start Context Mode before either app-server starts."""

    if native_runtime is None:
        raise ContextModeStartupError(
            "Context Mode requires the platform Bello native broker adapter; no reduced-security fallback exists"
        )
    if receipt_handler is None or not callable(receipt_handler):
        raise ContextModeStartupError("Context Mode requires a controller-owned out-of-band receipt handler")
    required_adapter_methods = (
        "launch_app_server",
        "verify_app_server_boundary",
        "register_approval_capability",
        "revoke_approval_capability",
        "update_binding",
        "activate_state_epoch",
        "acquire_purge_lease",
        "release_purge_lease",
        "start",
        "quiesce",
        "checkpoint",
        "recover_checkpoint",
        "resume",
        "stop",
    )
    missing_adapter_methods = [
        name for name in required_adapter_methods if not callable(getattr(native_runtime, name, None))
    ]
    if missing_adapter_methods:
        raise ContextModeStartupError(
            "native broker adapter is missing required security/lifecycle methods: "
            f"{missing_adapter_methods!r}"
        )
    backend.assert_verified()
    run_root = Path(run_root).resolve(strict=True)
    workspace = Path(workspace).resolve(strict=True)
    if not immutable_workspace_paths:
        raise ContextModeStartupError(
            "Context Mode requires at least one exact immutable task/spec workspace path"
        )

    def workspace_policy_path(path: Path, *, must_exist: bool) -> Path:
        try:
            resolved = Path(path).resolve(strict=must_exist)
            resolved.relative_to(workspace)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ContextModeStartupError(
                f"sandbox workspace policy path escapes the filtered workspace: {path}"
            ) from exc
        if resolved == workspace:
            raise ContextModeStartupError("sandbox workspace policy path cannot be the workspace root")
        return resolved

    workspace_git = workspace_policy_path(workspace / ".git", must_exist=True)
    immutable_paths = tuple(
        workspace_policy_path(Path(path), must_exist=True)
        for path in immutable_workspace_paths
    )
    dependency_roots = tuple(
        workspace_policy_path(Path(path), must_exist=True)
        for path in readonly_dependency_roots
    )
    masked_paths = tuple(
        workspace_policy_path(Path(path), must_exist=False)
        for path in workspace_masked_paths
    )
    bundle = select_bundled_runtime(Path(vendor_root))

    context_root = ensure_private_directory(run_root / "context-mode")
    try:
        epoch_layout = ContextEpochLayout(context_root, workspace_id)
        initial_epoch_root = epoch_layout.create_fresh_epoch(0)
    except EpochStateError as exc:
        raise ContextModeStartupError(
            "cannot create a fresh physical Context Mode state epoch"
        ) from exc
    context_home = ensure_private_directory(run_root / "context-mode-home")
    mcp_home = ensure_private_directory(context_home / "mcp")
    hook_home = ensure_private_directory(context_home / "hooks")
    command_home = ensure_private_directory(context_home / "commands")
    for profile_home in (mcp_home, hook_home, command_home):
        ensure_private_directory(profile_home / ".config")
        ensure_private_directory(profile_home / ".cache")
    context_temp = ensure_private_directory(run_root / "context-mode-tmp")
    mcp_temp = ensure_private_directory(context_temp / "mcp")
    hook_temp = ensure_private_directory(context_temp / "hooks")
    command_scratch = ensure_private_directory(context_temp / "commands")
    bootstrap_root = ensure_private_directory(run_root / "bootstrap")
    metadata_root = ensure_private_directory(run_root / "runtime-metadata")

    environment = build_clean_environment(
        home=context_home,
        temp=context_temp,
        context_mode_dir=initial_epoch_root,
        toolchain_bins=(bundle.node_path.parent, *(Path(path) for path in toolchain_roots)),
        platform_tag=current_platform_tag(),
        run_id=run_id,
        workspace_id=workspace_id,
        context_session_id=context_session_id,
    )
    # The launcher is returned only after the native broker is started, while
    # policy generation needs an immutable planned path.  The adapter owns this
    # package-local path and must return the exact same one below.
    planned_launcher = getattr(native_runtime, "launcher_path", None)
    if planned_launcher is None:
        raise ContextModeStartupError("native broker adapter exposes no immutable launcher_path")
    planned_launcher_sha256 = getattr(native_runtime, "launcher_sha256", None)
    if not isinstance(planned_launcher_sha256, str):
        raise ContextModeStartupError(
            "native broker adapter exposes no pinned launcher_sha256"
        )
    try:
        planned_launcher_sha256 = require_sha256(
            planned_launcher_sha256,
            "native broker launcher_sha256",
        )
    except ContextModeDataError as exc:
        raise ContextModeStartupError(str(exc)) from exc
    planned_launcher = Path(planned_launcher)
    _verify_launcher_file(planned_launcher, expected_sha256=planned_launcher_sha256)
    layout = SandboxPathLayout(
        workspace=workspace,
        runtime=bundle.root.resolve(strict=True),
        state=initial_epoch_root,
        mcp_home=mcp_home,
        mcp_temp=mcp_temp,
        hook_home=hook_home,
        hook_temp=hook_temp,
        command_home=command_home,
        command_scratch=command_scratch,
        launcher=planned_launcher,
        # This controller-owned directory is only an allow-list root.  The
        # native proxy profile mounts exactly one selected bootstrap file per
        # MCP/hook invocation and never exposes the directory itself.
        bootstrap=bootstrap_root,
        proxy_bootstrap_files=(
            bootstrap_root / "mcp.json",
            *(bootstrap_root / f"hook-{event}.json" for event in REQUIRED_HOOKS),
        ),
        workspace_git=workspace_git,
        immutable_workspace_paths=immutable_paths,
        readonly_dependency_roots=dependency_roots,
        workspace_masked_paths=masked_paths,
        toolchain_roots=tuple(Path(path).resolve(strict=True) for path in toolchain_roots),
        protected_roots=tuple(Path(path).resolve(strict=False) for path in protected_roots),
    )
    policy_map = generate_sandbox_policies(layout, environment=environment)
    policies = tuple(policy_map.values())
    # MCP is the authoritative policy attached to each ordinary call binding;
    # child command/hook launches additionally require their own exact digest.
    mcp_policy = policy_map[next(profile for profile in policy_map if profile.value == "mcp")]
    binding_store = BindingStore(metadata_root / "context-binding.json")
    binding = binding_store.initialize(
        ContextBinding(
            StableBindingIdentity(
                run_id=run_id,
                workspace_id=workspace_id,
                context_session_id=context_session_id,
                workspace_path=os.fspath(workspace),
                base_config_digest=base_config_digest,
            ),
            LifecycleSnapshot(
                binding_version=1,
                context_state_epoch=0,
                coder_generation=coder_generation,
                generation_lease_id=generation_lease_id,
                coder_process_epoch=coder_process_epoch,
                app_server_instance_id=app_server_instance_id,
                sandbox_policy_digest=mcp_policy.digest,
                provider_thread_id=None,
            ),
        )
    )
    capabilities = OneShotCapabilityStore()
    coordinator = ContextRuntimeCoordinator(
        binding_store=binding_store,
        capability_store=capabilities,
        bundle=bundle,
        backend=backend,
        policies=policies,
    )
    coordinator.preflight()
    try:
        endpoint = await _await_result(
            native_runtime.start(
                bundle=bundle,
                backend=backend,
                policies=policies,
                binding=binding,
                run_root=run_root,
                receipt_handler=receipt_handler,
            )
        )
        if not isinstance(endpoint, NativeRuntimeEndpoint):
            raise ContextModeStartupError("native broker returned an invalid endpoint")
        # Re-open and hash after native start so replacement between policy
        # generation and endpoint publication is also rejected.
        _verify_launcher_file(planned_launcher, expected_sha256=planned_launcher_sha256)
        if Path(endpoint.launcher_path) != planned_launcher:
            raise ContextModeStartupError("native broker launcher changed after policy generation")
        if endpoint.launcher_sha256 != planned_launcher_sha256:
            raise ContextModeStartupError("native broker launcher digest changed after policy generation")
        bootstraps = _write_bootstraps(
            bootstrap_root,
            endpoint=endpoint,
            binding=binding,
            policies=policy_map,
        )
        coordinator.start_accepting()
        prepared = PreparedContextMode(
            bundle=bundle,
            backend=backend,
            policies=policies,
            binding_store=binding_store,
            capability_store=capabilities,
            coordinator=coordinator,
            native_runtime=native_runtime,
            endpoint=endpoint,
            bootstraps=bootstraps,
            recovery_tracker=CheckpointRecoveryTracker(
                metadata_root / "checkpoint-recoveries.json"
            ),
            epoch_layout=epoch_layout,
            sandbox_layout=layout,
            clean_environment=environment,
        )
        prepared._require_active_epoch(binding)
        return prepared
    except BaseException:
        coordinator.mark_failed()
        try:
            await _await_result(native_runtime.stop(timeout_seconds=10.0))
        except BaseException:
            pass
        raise


def _write_bootstraps(
    root: Path,
    *,
    endpoint: NativeRuntimeEndpoint,
    binding: ContextBinding,
    policies: Mapping[Any, SandboxPolicy],
) -> ContextBootstrapPaths:
    mcp = root / "mcp.json"
    hooks = {event: root / f"hook-{event}.json" for event in REQUIRED_HOOKS}
    paths = ContextBootstrapPaths(mcp=mcp, hooks=hooks)
    _install_bootstrap_payloads(
        _bootstrap_payloads(
            paths,
            endpoint=endpoint,
            binding=binding,
            policies=policies,
        )
    )
    return paths


def _bootstrap_payloads(
    paths: ContextBootstrapPaths,
    *,
    endpoint: NativeRuntimeEndpoint,
    binding: ContextBinding,
    policies: Mapping[Any, SandboxPolicy],
) -> dict[Path, dict[str, Any]]:
    lifecycle = binding.lifecycle
    stable = binding.stable
    common: dict[str, Any] = {
        "schema_version": 1,
        "runtime_instance_id": endpoint.runtime_instance_id,
        "launcher_sha256": endpoint.launcher_sha256,
        "public_endpoint": dict(endpoint.public_bootstrap),
        "run_id": stable.run_id,
        "workspace_id": stable.workspace_id,
        "context_session_id": stable.context_session_id,
        "binding_version": lifecycle.binding_version,
        "context_state_epoch": lifecycle.context_state_epoch,
        "coder_generation": lifecycle.coder_generation,
        "generation_lease_id": lifecycle.generation_lease_id,
        "coder_process_epoch": lifecycle.coder_process_epoch,
        "app_server_instance_id": lifecycle.app_server_instance_id,
        "sandbox_policy_digest": lifecycle.sandbox_policy_digest,
        "provider_thread_id": lifecycle.provider_thread_id,
        "policy_digests": {profile.value: policy.digest for profile, policy in policies.items()},
    }
    payloads = {paths.mcp: {**common, "kind": "mcp"}}
    for event in REQUIRED_HOOKS:
        payloads[paths.hooks[event]] = {
            **common,
            "kind": "hook",
            "event": event,
            "hook_payload_schema_version": HOOK_PAYLOAD_SCHEMA_VERSION,
            "hook_payload_contract_digest": HOOK_PAYLOAD_CONTRACT_DIGEST,
        }
    return payloads


def _install_bootstrap_payloads(payloads: Mapping[Path, Mapping[str, Any]]) -> None:
    for path, payload in payloads.items():
        atomic_write_json(path, payload, mode=0o600)


def _verify_launcher_file(path: Path, *, expected_sha256: str) -> None:
    """Pin a controller-owned executable without resolving away unsafe paths."""

    path = Path(path)
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ContextModeStartupError(f"native launcher is missing or unresolvable: {path}") from exc
    if not path.is_absolute() or path != resolved:
        raise ContextModeStartupError(
            "native launcher path must be canonical, absolute, and contain no symlink components"
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ContextModeStartupError(f"native launcher cannot be opened without following symlinks: {path}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & stat.S_IXUSR:
            raise ContextModeStartupError(
                "native launcher must be an owner-executable regular non-symlink file"
            )
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise ContextModeStartupError("native launcher owner does not match the controller uid")
        if stat.S_IMODE(info.st_mode) & 0o022:
            raise ContextModeStartupError("native launcher must not be group/world writable")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except ContextModeStartupError:
        raise
    except OSError as exc:
        raise ContextModeStartupError(f"native launcher could not be hashed: {path}") from exc
    finally:
        os.close(descriptor)
    if digest.hexdigest() != expected_sha256:
        raise ContextModeStartupError("native launcher SHA-256 mismatch")


def _attest_public_bootstrap_file(path: Path, *, expected_sha256: str) -> dict[str, Any]:
    path = Path(path)
    try:
        resolved = path.resolve(strict=True)
        info = path.lstat()
    except (OSError, RuntimeError) as exc:
        raise ContextModeStartupError(f"generated hook bootstrap is missing or unresolvable: {path}") from exc
    if not path.is_absolute() or path != resolved or stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ContextModeStartupError(
            "generated hook bootstrap must be a canonical regular non-symlink file"
        )
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise ContextModeStartupError("generated hook bootstrap owner does not match the controller uid")
    mode = stat.S_IMODE(info.st_mode)
    if mode != 0o600:
        raise ContextModeStartupError("generated hook bootstrap mode must be 0600")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ContextModeStartupError(f"generated hook bootstrap cannot be opened safely: {path}") from exc
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != info.st_dev
            or opened.st_ino != info.st_ino
            or opened.st_uid != info.st_uid
            or stat.S_IMODE(opened.st_mode) != mode
        ):
            raise ContextModeStartupError("generated hook bootstrap identity changed while attesting")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except ContextModeStartupError:
        raise
    except OSError as exc:
        raise ContextModeStartupError(f"generated hook bootstrap could not be hashed: {path}") from exc
    finally:
        os.close(descriptor)
    actual_sha256 = digest.hexdigest()
    if actual_sha256 != expected_sha256:
        raise ContextModeStartupError("generated hook bootstrap SHA-256 mismatch")
    return {
        "path": os.fspath(path),
        "uid": info.st_uid,
        "mode": mode,
        "sha256": actual_sha256,
    }


def _public_bootstrap_has_authority_material(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            lowered = key.lower()
            if any(
                fragment in lowered
                for fragment in ("secret", "signing", "attestation_key", "receipt_key")
            ):
                return True
            if _public_bootstrap_has_authority_material(item):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_public_bootstrap_has_authority_material(item) for item in value)
    return False


async def _await_result(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value
