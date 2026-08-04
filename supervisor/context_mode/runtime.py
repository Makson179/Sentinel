"""Controller-owned Context Mode lifecycle coordination.

This is coordination state, not an OS process sandbox.  ``start_accepting`` only
becomes legal after bundle and native-backend preflight have both passed.
"""

from __future__ import annotations

import contextlib
import secrets
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Iterator

from ._util import ContextModeDataError
from .approvals import OneShotCapabilityStore
from .health import HealthReport, check_offline_runtime_preflight
from .packaging import VerifiedRuntimeBundle
from .sandbox import SandboxBackend, SandboxPolicy
from .session import BindingStore, ContextBinding, TransitionReason


class RuntimeError(ContextModeDataError):
    """Context Runtime lifecycle invariant failed."""


class RuntimeState(str, Enum):
    CREATED = "created"
    PREFLIGHTED = "preflighted"
    ACCEPTING = "accepting"
    QUIESCING = "quiescing"
    QUIESCED = "quiesced"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass(frozen=True)
class OperationLease:
    binding_version: int
    coder_generation: int
    generation_lease_id: str
    context_state_epoch: int


class ExclusiveWorkspaceLeasePurpose(str, Enum):
    PURGE = "purge"
    LOGICAL_RESTART_BOOTSTRAP = "logical_restart_bootstrap"


class ExclusiveWorkspaceLeasePhase(str, Enum):
    PURGE_ACTIVE = "purge_active"
    LOGICAL_RESTART_ACQUIRED = "logical_restart_acquired"
    LOGICAL_RESTART_CHECKPOINTED = "logical_restart_checkpointed"
    LOGICAL_GENERATION_ROTATED = "logical_generation_rotated"
    LOGICAL_THREAD_CLAIMED = "logical_thread_claimed"
    LOGICAL_RECOVERED = "logical_recovered"


@dataclass(frozen=True)
class ExclusiveWorkspaceLease:
    """Controller-held fence for one pending destructive lifecycle operation."""

    lease_id: str
    owner: str
    binding_version: int
    workspace_id: str
    context_session_id: str
    context_state_epoch: int
    coder_generation: int
    generation_lease_id: str
    purpose: ExclusiveWorkspaceLeasePurpose = ExclusiveWorkspaceLeasePurpose.PURGE
    phase: ExclusiveWorkspaceLeasePhase = ExclusiveWorkspaceLeasePhase.PURGE_ACTIVE
    checkpoint_id: str | None = None

    def __post_init__(self) -> None:
        purpose = ExclusiveWorkspaceLeasePurpose(self.purpose)
        phase = ExclusiveWorkspaceLeasePhase(self.phase)
        if purpose is ExclusiveWorkspaceLeasePurpose.PURGE:
            valid = phase is ExclusiveWorkspaceLeasePhase.PURGE_ACTIVE
        else:
            valid = phase in {
                ExclusiveWorkspaceLeasePhase.LOGICAL_RESTART_ACQUIRED,
                ExclusiveWorkspaceLeasePhase.LOGICAL_RESTART_CHECKPOINTED,
                ExclusiveWorkspaceLeasePhase.LOGICAL_GENERATION_ROTATED,
                ExclusiveWorkspaceLeasePhase.LOGICAL_THREAD_CLAIMED,
                ExclusiveWorkspaceLeasePhase.LOGICAL_RECOVERED,
            }
        if purpose is ExclusiveWorkspaceLeasePurpose.PURGE:
            valid = valid and self.checkpoint_id is None
        elif phase is ExclusiveWorkspaceLeasePhase.LOGICAL_RESTART_ACQUIRED:
            valid = valid and self.checkpoint_id is None
        else:
            valid = valid and isinstance(self.checkpoint_id, str) and bool(self.checkpoint_id)
        if not valid:
            raise RuntimeError("exclusive workspace lease purpose/phase mismatch")
        object.__setattr__(self, "purpose", purpose)
        object.__setattr__(self, "phase", phase)


class ContextRuntimeCoordinator:
    """Serialize lifecycle changes against active broker operations/hooks."""

    def __init__(
        self,
        *,
        binding_store: BindingStore,
        capability_store: OneShotCapabilityStore,
        bundle: VerifiedRuntimeBundle,
        backend: SandboxBackend,
        policies: tuple[SandboxPolicy, ...],
    ) -> None:
        self.binding_store = binding_store
        self.capability_store = capability_store
        self.bundle = bundle
        self.backend = backend
        self.policies = policies
        self._state = RuntimeState.CREATED
        self._active_operations = 0
        self._condition = threading.Condition(threading.RLock())
        self._health: HealthReport | None = None
        self._exclusive_workspace_lease: ExclusiveWorkspaceLease | None = None

    @property
    def state(self) -> RuntimeState:
        with self._condition:
            return self._state

    @property
    def active_operations(self) -> int:
        with self._condition:
            return self._active_operations

    @property
    def health(self) -> HealthReport | None:
        return self._health

    @property
    def exclusive_workspace_lease(self) -> ExclusiveWorkspaceLease | None:
        with self._condition:
            return self._exclusive_workspace_lease

    def preflight(self) -> HealthReport:
        with self._condition:
            if self._state is not RuntimeState.CREATED:
                raise RuntimeError(f"preflight is not valid from {self._state.value}")
            report = check_offline_runtime_preflight(
                bundle=self.bundle,
                backend=self.backend,
                policies=self.policies,
            )
            self._health = report
            if not report.passed:
                self._state = RuntimeState.FAILED
                report.require_passed()
            self._state = RuntimeState.PREFLIGHTED
            return report

    def start_accepting(self) -> None:
        """Mark the already-started native broker ready for calls.

        The method does not spawn anything.  Controller integration calls it only
        after the native adapter owns a sandboxed broker process tree/channel.
        """

        with self._condition:
            if self._state is not RuntimeState.PREFLIGHTED:
                raise RuntimeError(f"runtime cannot accept calls from {self._state.value}")
            self._state = RuntimeState.ACCEPTING

    @contextlib.contextmanager
    def operation(self, *, binding_version: int, generation_lease_id: str) -> Iterator[OperationLease]:
        with self._condition:
            if self._state is not RuntimeState.ACCEPTING:
                raise RuntimeError(f"Context Mode is not accepting calls ({self._state.value})")
            binding = self.binding_store.load()
            lifecycle = binding.lifecycle
            if (
                lifecycle.binding_version != binding_version
                or lifecycle.generation_lease_id != generation_lease_id
            ):
                raise RuntimeError("operation uses a stale binding/generation lease")
            self._active_operations += 1
            lease = OperationLease(
                lifecycle.binding_version,
                lifecycle.coder_generation,
                lifecycle.generation_lease_id,
                lifecycle.context_state_epoch,
            )
        try:
            yield lease
        finally:
            with self._condition:
                self._active_operations -= 1
                if self._active_operations < 0:  # defensive invariant
                    self._state = RuntimeState.FAILED
                    raise RuntimeError("active operation accounting underflow")
                self._condition.notify_all()

    def quiesce(self, *, timeout_seconds: float) -> ContextBinding:
        if timeout_seconds < 0:
            raise RuntimeError("quiesce timeout must be non-negative")
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            if self._state not in {RuntimeState.ACCEPTING, RuntimeState.QUIESCED}:
                raise RuntimeError(f"cannot quiesce runtime from {self._state.value}")
            if self._state is RuntimeState.QUIESCED:
                return self.binding_store.load()
            self._state = RuntimeState.QUIESCING
            while self._active_operations:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._state = RuntimeState.FAILED
                    self.capability_store.revoke_all()
                    raise RuntimeError("timed out waiting for Context Mode operations to quiesce")
                self._condition.wait(timeout=remaining)
            binding = self.binding_store.load()
            self.capability_store.revoke_generation(
                coder_generation=binding.lifecycle.coder_generation,
                generation_lease_id=binding.lifecycle.generation_lease_id,
            )
            self._state = RuntimeState.QUIESCED
            return binding

    def acquire_exclusive_workspace_lease(
        self,
        *,
        owner: str,
        binding_version: int,
        generation_lease_id: str,
        timeout_seconds: float,
    ) -> ExclusiveWorkspaceLease:
        """Quiesce calls and bind a destructive operation to the active epoch.

        The reservation is made before waiting, so another call cannot enter
        after a purge approval begins.  A timeout or stale binding permanently
        fails this coordinator; callers may not retry against ambiguous state.
        """

        return self._acquire_exclusive_workspace_lease(
            owner=owner,
            binding_version=binding_version,
            generation_lease_id=generation_lease_id,
            timeout_seconds=timeout_seconds,
            purpose=ExclusiveWorkspaceLeasePurpose.PURGE,
            phase=ExclusiveWorkspaceLeasePhase.PURGE_ACTIVE,
        )

    def acquire_logical_restart_bootstrap_lease(
        self,
        *,
        owner: str,
        binding_version: int,
        generation_lease_id: str,
        timeout_seconds: float,
    ) -> ExclusiveWorkspaceLease:
        """Fence a logical restart's replacement-thread MCP bootstrap."""

        return self._acquire_exclusive_workspace_lease(
            owner=owner,
            binding_version=binding_version,
            generation_lease_id=generation_lease_id,
            timeout_seconds=timeout_seconds,
            purpose=ExclusiveWorkspaceLeasePurpose.LOGICAL_RESTART_BOOTSTRAP,
            phase=ExclusiveWorkspaceLeasePhase.LOGICAL_RESTART_ACQUIRED,
        )

    def _acquire_exclusive_workspace_lease(
        self,
        *,
        owner: str,
        binding_version: int,
        generation_lease_id: str,
        timeout_seconds: float,
        purpose: ExclusiveWorkspaceLeasePurpose,
        phase: ExclusiveWorkspaceLeasePhase,
    ) -> ExclusiveWorkspaceLease:
        """Establish one native-backed exclusive lifecycle fence."""

        if not isinstance(owner, str) or not owner or "\x00" in owner:
            raise RuntimeError("exclusive workspace lease owner is invalid")
        if timeout_seconds < 0:
            raise RuntimeError("exclusive workspace lease timeout must be non-negative")
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            if self._exclusive_workspace_lease is not None:
                raise RuntimeError("an exclusive workspace lifecycle lease is already active")
            if self._state is not RuntimeState.ACCEPTING:
                raise RuntimeError(
                    f"cannot acquire an exclusive workspace lease from {self._state.value}"
                )
            binding = self.binding_store.load()
            lifecycle = binding.lifecycle
            if (
                lifecycle.binding_version != binding_version
                or lifecycle.generation_lease_id != generation_lease_id
            ):
                raise RuntimeError("exclusive workspace lease uses a stale binding/generation lease")
            self._state = RuntimeState.QUIESCING
            while self._active_operations:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._state = RuntimeState.FAILED
                    self.capability_store.revoke_all()
                    self._condition.notify_all()
                    raise RuntimeError(
                        "timed out waiting for Context Mode operations before exclusive lease"
                    )
                self._condition.wait(timeout=remaining)
            # The capability for the pending purge is granted only after this
            # fence exists.  Every older capability is revoked first.
            self.capability_store.revoke_generation(
                coder_generation=lifecycle.coder_generation,
                generation_lease_id=lifecycle.generation_lease_id,
            )
            lease = ExclusiveWorkspaceLease(
                lease_id=secrets.token_hex(32),
                owner=owner,
                binding_version=lifecycle.binding_version,
                workspace_id=binding.stable.workspace_id,
                context_session_id=binding.stable.context_session_id,
                context_state_epoch=lifecycle.context_state_epoch,
                coder_generation=lifecycle.coder_generation,
                generation_lease_id=lifecycle.generation_lease_id,
                purpose=purpose,
                phase=phase,
            )
            self._exclusive_workspace_lease = lease
            self._state = RuntimeState.QUIESCED
            return lease

    def require_exclusive_workspace_lease(
        self,
        lease: ExclusiveWorkspaceLease,
    ) -> ContextBinding:
        with self._condition:
            if self._state is not RuntimeState.QUIESCED:
                raise RuntimeError("exclusive workspace lease requires a quiesced runtime")
            active_lease = self._exclusive_workspace_lease
            if (
                active_lease is None
                or active_lease.lease_id != lease.lease_id
                or active_lease.owner != lease.owner
            ):
                raise RuntimeError("exclusive workspace lease is missing, stale, or replaced")
            if (
                active_lease.purpose
                is ExclusiveWorkspaceLeasePurpose.LOGICAL_RESTART_BOOTSTRAP
                and lease != active_lease
            ):
                self._state = RuntimeState.FAILED
                self.capability_store.revoke_all()
                raise RuntimeError("logical restart bootstrap lease is not at its active phase")
            binding = self.binding_store.load()
            lifecycle = binding.lifecycle
            expected = (
                active_lease.binding_version,
                active_lease.workspace_id,
                active_lease.context_session_id,
                active_lease.context_state_epoch,
                active_lease.coder_generation,
                active_lease.generation_lease_id,
            )
            actual = (
                lifecycle.binding_version,
                binding.stable.workspace_id,
                binding.stable.context_session_id,
                lifecycle.context_state_epoch,
                lifecycle.coder_generation,
                lifecycle.generation_lease_id,
            )
            if actual != expected:
                self._state = RuntimeState.FAILED
                self.capability_store.revoke_all()
                raise RuntimeError("exclusive workspace lease no longer matches active binding")
            return binding

    @staticmethod
    def _lease_matches_binding(
        lease: ExclusiveWorkspaceLease,
        binding: ContextBinding,
    ) -> bool:
        lifecycle = binding.lifecycle
        return (
            lease.binding_version == lifecycle.binding_version
            and lease.workspace_id == binding.stable.workspace_id
            and lease.context_session_id == binding.stable.context_session_id
            and lease.context_state_epoch == lifecycle.context_state_epoch
            and lease.coder_generation == lifecycle.coder_generation
            and lease.generation_lease_id == lifecycle.generation_lease_id
        )

    def checkpoint_logical_restart_bootstrap_lease(
        self,
        lease: ExclusiveWorkspaceLease,
        *,
        binding: ContextBinding,
        checkpoint_id: str,
    ) -> ExclusiveWorkspaceLease:
        """Bind the native-verified lifecycle checkpoint to the bootstrap fence."""

        with self._condition:
            active = self._exclusive_workspace_lease
            if (
                self._state is not RuntimeState.QUIESCED
                or active is None
                or active != lease
                or active.purpose
                is not ExclusiveWorkspaceLeasePurpose.LOGICAL_RESTART_BOOTSTRAP
                or active.phase
                is not ExclusiveWorkspaceLeasePhase.LOGICAL_RESTART_ACQUIRED
                or not self._lease_matches_binding(active, binding)
                or not isinstance(checkpoint_id, str)
                or not checkpoint_id
            ):
                self._state = RuntimeState.FAILED
                self.capability_store.revoke_all()
                raise RuntimeError("logical restart checkpoint does not match its bootstrap lease")
            advanced = ExclusiveWorkspaceLease(
                lease_id=active.lease_id,
                owner=active.owner,
                binding_version=active.binding_version,
                workspace_id=active.workspace_id,
                context_session_id=active.context_session_id,
                context_state_epoch=active.context_state_epoch,
                coder_generation=active.coder_generation,
                generation_lease_id=active.generation_lease_id,
                purpose=active.purpose,
                phase=ExclusiveWorkspaceLeasePhase.LOGICAL_RESTART_CHECKPOINTED,
                checkpoint_id=checkpoint_id,
            )
            self._exclusive_workspace_lease = advanced
            return advanced

    def recover_logical_restart_bootstrap_lease(
        self,
        lease: ExclusiveWorkspaceLease,
        *,
        binding: ContextBinding,
        checkpoint_id: str,
    ) -> ExclusiveWorkspaceLease:
        """Mark the fence releasable only after verified SessionStart recovery."""

        with self._condition:
            active = self._exclusive_workspace_lease
            if (
                self._state is not RuntimeState.QUIESCED
                or active is None
                or active != lease
                or active.purpose
                is not ExclusiveWorkspaceLeasePurpose.LOGICAL_RESTART_BOOTSTRAP
                or active.phase
                is not ExclusiveWorkspaceLeasePhase.LOGICAL_THREAD_CLAIMED
                or active.checkpoint_id != checkpoint_id
                or not self._lease_matches_binding(active, binding)
            ):
                self._state = RuntimeState.FAILED
                self.capability_store.revoke_all()
                raise RuntimeError("logical restart recovery does not match its bootstrap lease")
            recovered = ExclusiveWorkspaceLease(
                lease_id=active.lease_id,
                owner=active.owner,
                binding_version=active.binding_version,
                workspace_id=active.workspace_id,
                context_session_id=active.context_session_id,
                context_state_epoch=active.context_state_epoch,
                coder_generation=active.coder_generation,
                generation_lease_id=active.generation_lease_id,
                purpose=active.purpose,
                phase=ExclusiveWorkspaceLeasePhase.LOGICAL_RECOVERED,
                checkpoint_id=active.checkpoint_id,
            )
            self._exclusive_workspace_lease = recovered
            return recovered

    def _validate_exclusive_workspace_transition_locked(
        self,
        lease: ExclusiveWorkspaceLease,
        *,
        previous_binding: ContextBinding,
        binding: ContextBinding,
        reason: TransitionReason,
    ) -> ExclusiveWorkspaceLease:
        active = self._exclusive_workspace_lease

        def reject(message: str) -> None:
            self._state = RuntimeState.FAILED
            self.capability_store.revoke_all()
            self._condition.notify_all()
            raise RuntimeError(message)

        if (
            self._state is not RuntimeState.QUIESCED
            or active is None
            or active.lease_id != lease.lease_id
            or active.owner != lease.owner
            or active != lease
        ):
            reject("cannot transition an inactive or stale exclusive workspace lease")
        previous = previous_binding.lifecycle
        expected_previous = (
            active.binding_version,
            active.workspace_id,
            active.context_session_id,
            active.context_state_epoch,
            active.coder_generation,
            active.generation_lease_id,
        )
        actual_previous = (
            previous.binding_version,
            previous_binding.stable.workspace_id,
            previous_binding.stable.context_session_id,
            previous.context_state_epoch,
            previous.coder_generation,
            previous.generation_lease_id,
        )
        if actual_previous != expected_previous:
            reject("exclusive workspace lease does not match the previous binding")
        candidate = binding.lifecycle
        if (
            binding.stable != previous_binding.stable
            or candidate.binding_version != previous.binding_version + 1
        ):
            reject("exclusive workspace transition changed stable identity or skipped a version")

        next_phase = active.phase
        if active.purpose is ExclusiveWorkspaceLeasePurpose.PURGE:
            if (
                candidate.context_state_epoch
                not in {previous.context_state_epoch, previous.context_state_epoch + 1}
                or candidate.coder_generation != previous.coder_generation
                or candidate.generation_lease_id != previous.generation_lease_id
            ):
                reject("purge lease transition did not preserve its generation identity")
        elif active.phase is ExclusiveWorkspaceLeasePhase.LOGICAL_RESTART_CHECKPOINTED:
            if (
                reason is not TransitionReason.LOGICAL_GENERATION_RESTART
                or candidate.context_state_epoch != previous.context_state_epoch
                or candidate.coder_generation != previous.coder_generation + 1
                or candidate.generation_lease_id == previous.generation_lease_id
                or candidate.provider_thread_id is not None
            ):
                reject("logical bootstrap lease expected one exact generation restart")
            next_phase = ExclusiveWorkspaceLeasePhase.LOGICAL_GENERATION_ROTATED
        elif active.phase is ExclusiveWorkspaceLeasePhase.LOGICAL_GENERATION_ROTATED:
            if (
                reason is not TransitionReason.THREAD_CLAIM
                or candidate.context_state_epoch != previous.context_state_epoch
                or candidate.coder_generation != previous.coder_generation
                or candidate.generation_lease_id != previous.generation_lease_id
                or candidate.provider_thread_id is None
            ):
                reject("logical bootstrap lease expected one exact provider thread claim")
            next_phase = ExclusiveWorkspaceLeasePhase.LOGICAL_THREAD_CLAIMED
        else:
            reject("logical bootstrap lease permits no transition after thread claim")

        return ExclusiveWorkspaceLease(
            lease_id=active.lease_id,
            owner=active.owner,
            binding_version=candidate.binding_version,
            workspace_id=active.workspace_id,
            context_session_id=active.context_session_id,
            context_state_epoch=candidate.context_state_epoch,
            coder_generation=candidate.coder_generation,
            generation_lease_id=candidate.generation_lease_id,
            purpose=active.purpose,
            phase=next_phase,
            checkpoint_id=active.checkpoint_id,
        )

    def validate_exclusive_workspace_transition(
        self,
        lease: ExclusiveWorkspaceLease,
        *,
        previous_binding: ContextBinding,
        binding: ContextBinding,
        reason: TransitionReason,
    ) -> None:
        """Reject an invalid fenced transition before either authority commits it."""

        with self._condition:
            self._validate_exclusive_workspace_transition_locked(
                lease,
                previous_binding=previous_binding,
                binding=binding,
                reason=TransitionReason(reason),
            )

    def advance_exclusive_workspace_lease(
        self,
        lease: ExclusiveWorkspaceLease,
        *,
        previous_binding: ContextBinding,
        binding: ContextBinding,
        reason: TransitionReason,
    ) -> ExclusiveWorkspaceLease:
        """Advance a prevalidated lease after the candidate binding commits."""

        with self._condition:
            advanced = self._validate_exclusive_workspace_transition_locked(
                lease,
                previous_binding=previous_binding,
                binding=binding,
                reason=TransitionReason(reason),
            )
            self._exclusive_workspace_lease = advanced
            return advanced

    def release_exclusive_workspace_lease(self, lease: ExclusiveWorkspaceLease) -> None:
        with self._condition:
            if self._state is not RuntimeState.QUIESCED:
                raise RuntimeError("cannot release exclusive workspace lease unless quiesced")
            active_lease = self._exclusive_workspace_lease
            if (
                active_lease is None
                or active_lease.lease_id != lease.lease_id
                or active_lease.owner != lease.owner
            ):
                raise RuntimeError("cannot release a stale exclusive workspace lease")
            if (
                active_lease.purpose
                is ExclusiveWorkspaceLeasePurpose.LOGICAL_RESTART_BOOTSTRAP
                and (
                    active_lease.phase is not ExclusiveWorkspaceLeasePhase.LOGICAL_RECOVERED
                    or lease != active_lease
                )
            ):
                self._state = RuntimeState.FAILED
                self.capability_store.revoke_all()
                raise RuntimeError(
                    "logical restart bootstrap lease cannot release before verified recovery"
                )
            self._exclusive_workspace_lease = None
            self._state = RuntimeState.ACCEPTING

    def replace_policies_for_exclusive_workspace_lease(
        self,
        lease: ExclusiveWorkspaceLease,
        policies: tuple[SandboxPolicy, ...],
    ) -> None:
        """Install native-accepted policies while the epoch fence is held."""

        with self._condition:
            active_lease = self._exclusive_workspace_lease
            if (
                self._state is not RuntimeState.QUIESCED
                or active_lease is None
                or active_lease.lease_id != lease.lease_id
                or active_lease.owner != lease.owner
            ):
                raise RuntimeError("sandbox policies can change only under the active exclusive lease")
            if not policies:
                raise RuntimeError("rotated sandbox policy set cannot be empty")
            self.policies = policies

    def resume_accepting(self) -> None:
        with self._condition:
            if self._state is not RuntimeState.QUIESCED:
                raise RuntimeError(f"cannot resume runtime from {self._state.value}")
            if self._exclusive_workspace_lease is not None:
                raise RuntimeError("cannot resume while an exclusive workspace lease is active")
            self._state = RuntimeState.ACCEPTING

    def stop(self, *, timeout_seconds: float = 30.0) -> None:
        with self._condition:
            if self._state is RuntimeState.STOPPED:
                return
            if self._state is RuntimeState.CREATED:
                self.capability_store.revoke_all()
                self._state = RuntimeState.STOPPED
                return
        if self.state is RuntimeState.ACCEPTING:
            self.quiesce(timeout_seconds=timeout_seconds)
        with self._condition:
            if self._active_operations:
                self._state = RuntimeState.FAILED
                raise RuntimeError("cannot stop with active Context Mode operations")
            self.capability_store.revoke_all()
            self._state = RuntimeState.STOPPED

    def mark_failed(self) -> None:
        with self._condition:
            self.capability_store.revoke_all()
            self._state = RuntimeState.FAILED
            self._condition.notify_all()


ContextRuntime = ContextRuntimeCoordinator
