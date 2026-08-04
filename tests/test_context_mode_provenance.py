from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from supervisor.context_mode.approvals import normalized_arguments_digest
from supervisor.context_mode.events import (
    ClientRole,
    ContextCallStatus,
    ContextEventLedger,
    ContextModeCallEvent,
    ContextObservationKey,
    EventDisposition,
    LogicalContextCallKey,
    PendingRequestKey,
)
from supervisor.context_mode.provenance import (
    ARGV_DIGEST_KIND,
    MAX_ARGV_ITEMS,
    MAX_COMMAND_RECORDS,
    MAX_EVENT_BYTES,
    MAX_EXCERPT_BYTES,
    BrokerReceipt,
    CommandRecord,
    ExpectedProvenance,
    ProvenanceError,
    ProvenanceValidator,
    ReceiptReplayGuard,
    ReceiptReplayError,
    RetrievalRecord,
    ResultEnvelope,
    bounded_redacted_summary,
)
from supervisor.context_mode.session import ContextBinding, LifecycleSnapshot, StableBindingIdentity


def _binding(workspace: Path) -> ContextBinding:
    return ContextBinding(
        StableBindingIdentity("run", "workspace", "session", os.fspath(workspace), "a" * 64),
        LifecycleSnapshot(4, 2, 3, "lease", 5, "app", "b" * 64, "thread"),
    )


def _receipt(binding: ContextBinding) -> BrokerReceipt:
    command = CommandRecord(
        runner_identity="bello-native-runner-v1",
        redacted_argv=("python", "-m", "pytest"),
        argv_digest="c" * 64,
        relative_cwd=".",
        start_order=0,
        duration_ms=12,
        exit_code=0,
        signal=None,
        timed_out=False,
        stdout_bytes=10,
        stderr_bytes=0,
        stdout_digest="d" * 64,
        stderr_digest="e" * 64,
        stdout_complete=True,
        stderr_complete=True,
        stdout_excerpt="1 passed",
    )
    stable, lifecycle = binding.stable, binding.lifecycle
    return BrokerReceipt(
        receipt_seq=1,
        role=ClientRole.CODER,
        app_server_instance_id=lifecycle.app_server_instance_id,
        process_epoch=lifecycle.coder_process_epoch,
        run_id=stable.run_id,
        workspace_id=stable.workspace_id,
        context_session_id=stable.context_session_id,
        context_state_epoch=lifecycle.context_state_epoch,
        binding_version=lifecycle.binding_version,
        coder_generation=lifecycle.coder_generation,
        generation_lease_id=lifecycle.generation_lease_id,
        mcp_request_id=9,
        tool_name="ctx_execute",
        arguments_digest=normalized_arguments_digest({"code": "run tests"}),
        operation_id="operation-1",
        result_digest="f" * 64,
        sandbox_backend="linux-bwrap-seccomp",
        sandbox_policy_digest=lifecycle.sandbox_policy_digest,
        capability_id="capability-1",
        context_event_seq=7,
        duration_ms=12,
        source_bytes=100,
        returned_bytes=10,
        indexed_bytes=None,
        commands=(command,),
    )


def _envelope(receipt: BrokerReceipt) -> ResultEnvelope:
    return ResultEnvelope(
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


def test_envelope_requires_matching_out_of_band_receipt_and_rejects_replay(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    receipt = _receipt(binding)
    envelope = _envelope(receipt)
    expected = ExpectedProvenance(
        binding=binding,
        app_server_instance_id="app",
        process_epoch=5,
        mcp_request_id=9,
        tool_name="ctx_execute",
        arguments_digest=receipt.arguments_digest,
        result_digest="f" * 64,
        capability_id="capability-1",
    )
    validator = ProvenanceValidator()
    assert validator.validate(envelope, receipt, expected).receipt == receipt
    with pytest.raises(ReceiptReplayError):
        validator.validate(envelope, receipt, expected)

    with pytest.raises(ProvenanceError, match="no matching"):
        ProvenanceValidator().validate(envelope, None, expected)
    with pytest.raises(ProvenanceError, match="envelope"):
        ProvenanceValidator().validate(replace(envelope, generation_lease_id="old"), receipt, expected)


def test_redaction_occurs_before_hard_event_limits() -> None:
    summary = bounded_redacted_summary(
        {
            "authorization": "Bearer should-never-persist",
            "message": "token=abc123456789 " + ("x" * 100_000),
        },
        authority_key=b"k" * 32,
    )
    assert summary.encoded_bytes <= MAX_EVENT_BYTES
    serialized = repr(summary.value)
    assert "should-never-persist" not in serialized
    assert "abc123456789" not in serialized
    assert all(
        len(value.encode("utf-8")) <= MAX_EXCERPT_BYTES
        for value in summary.value.values()
        if isinstance(value, str) and not value.startswith("[REDACTED]")
    )


def test_provenance_boolean_fields_are_strict_and_stale_retrieval_is_untrusted(
    tmp_path: Path,
) -> None:
    command = _receipt(_binding(tmp_path)).commands[0]
    with pytest.raises(ProvenanceError, match="stdout_complete must be boolean"):
        replace(command, stdout_complete="yes")  # type: ignore[arg-type]

    workspace = tmp_path / "workspace-stale"
    workspace.mkdir()
    binding = _binding(workspace)
    base = _receipt(binding)
    retrieval = RetrievalRecord(
        source_kind="file",
        relative_path="module.py",
        content_hash="1" * 64,
        indexed_revision=4,
        current_revision=5,
        ranges=((0, 4),),
        source_bytes=4,
        returned_bytes=4,
        stale=False,
    )
    receipt = replace(
        base,
        tool_name="ctx_search",
        capability_id=None,
        commands=(),
        retrieval=(retrieval,),
    )
    envelope = _envelope(receipt)
    expected = ExpectedProvenance(
        binding=binding,
        app_server_instance_id="app",
        process_epoch=5,
        mcp_request_id=9,
        tool_name="ctx_search",
        arguments_digest=receipt.arguments_digest,
        result_digest=receipt.result_digest,
        capability_id=None,
    )
    with pytest.raises(ProvenanceError, match="stale retrieval"):
        ProvenanceValidator().validate(envelope, receipt, expected)


def test_provenance_schema_and_terminal_event_sequence_are_strict(tmp_path: Path) -> None:
    receipt = _receipt(_binding(tmp_path))
    with pytest.raises(ValueError, match="schema_version must be an integer"):
        replace(receipt, schema_version=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="context_event_seq must be an integer >= 1"):
        replace(receipt, context_event_seq=0)
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        replace(receipt, result_digest=None)  # type: ignore[arg-type]

    with pytest.raises(ProvenanceError, match="at least one returned range"):
        RetrievalRecord(
            source_kind="file",
            relative_path="module.py",
            content_hash="1" * 64,
            indexed_revision=1,
            current_revision=1,
            ranges=(),
            source_bytes=10,
            returned_bytes=1,
            stale=False,
        )
    with pytest.raises(ProvenanceError, match="range exceeds source_bytes"):
        RetrievalRecord(
            source_kind="file",
            relative_path="module.py",
            content_hash="1" * 64,
            indexed_revision=1,
            current_revision=1,
            ranges=((0, 11),),
            source_bytes=10,
            returned_bytes=1,
            stale=False,
        )


def test_command_record_excerpts_require_utf8_strings(tmp_path: Path) -> None:
    command = _receipt(_binding(tmp_path)).commands[0]
    payload = command.to_dict()
    payload["stdout_excerpt"] = 7
    with pytest.raises(ProvenanceError, match="stdout_excerpt must be a string"):
        CommandRecord.from_dict(payload)

    payload = command.to_dict()
    payload["stdout_excerpt"] = "\ud800"
    with pytest.raises(ProvenanceError, match="stdout_excerpt must be valid UTF-8 text"):
        CommandRecord.from_dict(payload)


def test_command_record_requires_bounded_redacted_argv_and_keyed_digest_kind(
    tmp_path: Path,
) -> None:
    command = _receipt(_binding(tmp_path)).commands[0]
    with pytest.raises(ProvenanceError, match="unredacted"):
        replace(command, redacted_argv=("python", "--token=super-secret-value"))
    with pytest.raises(ProvenanceError, match="item-count"):
        replace(command, redacted_argv=tuple("x" for _ in range(MAX_ARGV_ITEMS + 1)))
    with pytest.raises(ProvenanceError, match="run-keyed HMAC"):
        replace(command, argv_digest_kind="sha256-v1")
    assert command.argv_digest_kind == ARGV_DIGEST_KIND


def test_receipt_rejects_unbounded_command_and_path_structures(tmp_path: Path) -> None:
    receipt = _receipt(_binding(tmp_path))
    command = receipt.commands[0]
    commands = tuple(replace(command, start_order=index) for index in range(MAX_COMMAND_RECORDS + 1))
    with pytest.raises(ProvenanceError, match="command-record count"):
        replace(receipt, commands=commands)
    with pytest.raises(ProvenanceError, match="4096-byte"):
        replace(receipt, changed_paths={"x" * 4097: "a" * 64})


def test_receipt_replay_guard_rolls_back_if_durable_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = ReceiptReplayGuard(tmp_path / "replay.json")

    def fail_persist() -> None:
        raise OSError("disk full")

    monkeypatch.setattr(guard, "_persist", fail_persist)
    with pytest.raises(OSError, match="disk full"):
        guard.accept(1, "operation-1")
    assert guard.highest_sequence == 0

    monkeypatch.undo()
    guard.accept(1, "operation-1")
    assert guard.highest_sequence == 1


def _event(status: ContextCallStatus, observation: ContextObservationKey) -> ContextModeCallEvent:
    terminal = status is not ContextCallStatus.STARTED
    return ContextModeCallEvent(
        logical_key=LogicalContextCallKey(ClientRole.CODER, "thread", "turn", "item"),
        observation=observation,
        operation_id="op" if terminal else None,
        status=status,
        tool_name="ctx_search",
        run_id="run",
        workspace_id="workspace",
        context_session_id="session",
        context_state_epoch=1,
        binding_version=2,
        coder_generation=3,
        generation_lease_id="lease",
        sandbox_policy_digest="b" * 64,
        provider_thread_id="thread",
        workspace_revision_started=5,
        workspace_revision_completed=5 if terminal else None,
    )


def test_logical_event_and_transport_observation_are_independent() -> None:
    assert PendingRequestKey(ClientRole.CODER, 2, 1) != PendingRequestKey(ClientRole.SUPERVISOR, 2, 1)
    ledger = ContextEventLedger()
    started_observation = ContextObservationKey("app-a", 1, None)
    assert ledger.record(_event(ContextCallStatus.STARTED, started_observation)) is EventDisposition.ACCEPTED_STARTED
    terminal_observation = ContextObservationKey("app-a", 1, 10)
    assert ledger.record(_event(ContextCallStatus.COMPLETED, terminal_observation)) is EventDisposition.ACCEPTED_TERMINAL
    recovered_observation = ContextObservationKey("app-b", 2, 11)
    assert (
        ledger.record(_event(ContextCallStatus.COMPLETED, recovered_observation))
        is EventDisposition.DUPLICATE_LOGICAL_TERMINAL
    )
    assert ledger.observation_count(LogicalContextCallKey(ClientRole.CODER, "thread", "turn", "item")) == 3
