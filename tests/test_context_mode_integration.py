from __future__ import annotations

import asyncio
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from supervisor.appserver import (
    AppServerMessage,
    AppServerProtocolError,
    ClientRole as AppServerClientRole,
    PendingRequestKey,
)
from supervisor.approvals import normalize_approval_request
from supervisor.context_mode.approvals import OneShotCapabilityStore, normalized_arguments_digest
from supervisor.context_mode.events import (
    ActiveEventContext,
    ClientRole,
    EventError,
    EventDisposition,
    ContextObservationKey,
    LogicalContextCallKey,
    identify_context_call,
)
from supervisor.context_mode.integration import (
    ContextCallClassification,
    IntegrationError,
    ContextModeIntegration,
    ContextNotificationOrigin,
    ContextOutcomeStatus,
    OutOfBandReceiptInbox,
    ReceiptAlreadySeen,
    ReceiptInboxFull,
    ReceiptNotFound,
    normalized_mcp_result_digest,
)
from supervisor.context_mode.provenance import (
    BrokerReceipt,
    CommandRecord,
    ProvenanceError,
    ResultEnvelope,
    RetrievalRecord,
)
from supervisor.context_mode.session import (
    ContextBinding,
    LifecycleSnapshot,
    StableBindingIdentity,
    TransitionReason,
)
from supervisor.context_mode.telemetry import AuthoritySeparatedCounters
from supervisor.controller import BelloController, _approval_wake_context


def _binding(workspace: Path) -> ContextBinding:
    return ContextBinding(
        StableBindingIdentity("run", "workspace", "session", os.fspath(workspace), "a" * 64),
        LifecycleSnapshot(3, 1, 2, "lease", 4, "app", "b" * 64, "thread"),
    )


def _origin(role: ClientRole = ClientRole.CODER) -> ContextNotificationOrigin:
    return ContextNotificationOrigin(role, 4, "app")


def _recovered_binding(
    binding: ContextBinding,
    *,
    process_epoch: int = 5,
    app_server_instance_id: str = "app-recovered",
) -> ContextBinding:
    return binding.transition(
        TransitionReason.PROCESS_RECOVERY,
        coder_process_epoch=process_epoch,
        app_server_instance_id=app_server_instance_id,
        provider_thread_id="thread",
    )


class _ControllerStore:
    def __init__(self) -> None:
        self.config = SimpleNamespace(
            coder_thread_id="thread",
            active_coder_turn_id="turn",
        )
        self.raw_logs: list[dict[str, object]] = []
        self.metrics: dict[str, object] = {}

    def get_bello_config(self):
        return self.config

    def append_raw_log(self, value):
        self.raw_logs.append(value)

    def update_runtime_metrics(self, patch):
        self.metrics = patch(self.metrics)


class _NativeApprovalRuntime:
    def __init__(self) -> None:
        self.registered = []
        self.revoked: list[str] = []

    async def register_approval_capability(self, *, capability, request_key):
        self.registered.append((capability, request_key))

    async def revoke_approval_capability(self, *, capability_id: str):
        self.revoked.append(capability_id)


def _approval_controller(binding: ContextBinding) -> BelloController:
    controller = BelloController.__new__(BelloController)
    native = _NativeApprovalRuntime()
    controller.store = _ControllerStore()
    controller.context_runtime = SimpleNamespace(binding=binding, native_runtime=native)
    controller.context_binding_store = SimpleNamespace(load=lambda: binding)
    controller.context_capability_store = OneShotCapabilityStore()
    controller.context_integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)
    controller._workspace_revision = 0
    controller._context_call_start_revision = {}
    controller._context_capability_by_item = {}
    controller._context_approval_capabilities = {}
    controller._context_pending_approval_calls = {}
    controller._context_approval_item_by_request = {}
    controller._context_approval_correlation_issues = {}
    return controller


def _started_message(
    *,
    arguments: dict[str, object],
    item_id: str = "item",
) -> AppServerMessage:
    return AppServerMessage(
        {
            "method": "item/started",
            "params": _params(
                tool="ctx_execute",
                arguments=arguments,
                item_id=item_id,
                request_id=None,
            ),
        },
        role=AppServerClientRole.CODER,
        process_epoch=4,
        app_server_instance_id="app",
    )


def _approval_message(arguments: dict[str, object], *, request_id: int = 91) -> AppServerMessage:
    return AppServerMessage(
        {
            "id": request_id,
            "method": "mcpServer/elicitation/request",
            "params": {
                "threadId": "thread",
                "turnId": "turn",
                "serverName": "bello_context_mode",
                "mode": "form",
                "message": "forged display asks for another tool",
                "title": "forged title",
                "description": "forged description",
                "toolName": "ctx_purge",
                "arguments": {"forged": True},
                "_meta": {
                    "codex_approval_kind": "mcp_tool_call",
                    "tool_title": "ctx_purge",
                    "tool_description": "untrusted display metadata",
                    "tool_params": arguments,
                },
            },
        },
        role=AppServerClientRole.CODER,
        process_epoch=4,
        app_server_instance_id="app",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_request_id", [True, {"nested": "id"}])
async def test_resolved_notification_rejects_invalid_request_id_without_popping(
    tmp_path: Path,
    bad_request_id: object,
) -> None:
    controller = _approval_controller(_binding(tmp_path))
    pending_key = PendingRequestKey(AppServerClientRole.CODER, 4, 91)
    controller.pending_approvals = {pending_key: object()}  # type: ignore[dict-item]
    controller._context_approval_capabilities = {pending_key: "capability"}
    controller._context_approval_item_by_request = {pending_key: "item"}
    controller._context_approval_correlation_issues = {pending_key: "issue"}
    controller._append_event = lambda *_args, **_kwargs: None  # type: ignore[method-assign]

    message = AppServerMessage(
        {
            "method": "serverRequest/resolved",
            "params": {"requestId": bad_request_id},
        },
        role=AppServerClientRole.CODER,
        process_epoch=4,
        app_server_instance_id="app",
    )
    with pytest.raises(AppServerProtocolError, match="serverRequest/resolved requestId"):
        await controller.handle_notification(message)

    assert pending_key in controller.pending_approvals
    assert pending_key in controller._context_approval_capabilities
    assert pending_key in controller._context_approval_item_by_request
    assert pending_key in controller._context_approval_correlation_issues


def _params(
    *,
    tool: str,
    arguments: dict[str, object],
    result: dict[str, object] | None = None,
    status: str = "inProgress",
    item_id: str = "item",
    request_id: int | None = 7,
) -> dict[str, object]:
    item: dict[str, object] = {
        "id": item_id,
        "type": "mcpToolCall",
        "server": "bello_context_mode",
        "tool": tool,
        "arguments": arguments,
        "status": status,
    }
    if result is not None:
        item["result"] = result
    params: dict[str, object] = {
        "threadId": "thread",
        "turnId": "turn",
        "itemId": item_id,
        "item": item,
    }
    if request_id is not None:
        params["mcpRequestId"] = request_id
    return params


def _receipt_and_result(
    binding: ContextBinding,
    *,
    tool: str,
    arguments: dict[str, object],
    capability_id: str | None,
    operation_id: str = "operation",
    receipt_seq: int = 1,
    retrieval: tuple[RetrievalRecord, ...] = (),
    indexed_bytes: int | None = None,
    broker_is_error: bool = False,
) -> tuple[BrokerReceipt, dict[str, object]]:
    command = CommandRecord(
        runner_identity="bello-native-runner-v1",
        redacted_argv=("python", "-m", "pytest"),
        argv_digest="c" * 64,
        relative_cwd=".",
        start_order=0,
        duration_ms=10,
        exit_code=0,
        signal=None,
        timed_out=False,
        stdout_bytes=8,
        stderr_bytes=0,
        stdout_digest="d" * 64,
        stderr_digest="e" * 64,
        stdout_complete=True,
        stderr_complete=True,
        stdout_excerpt="1 passed",
    )
    bare_result: dict[str, object] = {
        "content": [{"type": "text", "text": "bounded result"}],
        "structuredContent": {"answer": "ok"},
    }
    broker_result = dict(bare_result)
    if broker_is_error:
        broker_result["isError"] = True
    stable, lifecycle = binding.stable, binding.lifecycle
    receipt = BrokerReceipt(
        receipt_seq=receipt_seq,
        role=ClientRole.CODER,
        app_server_instance_id="app",
        process_epoch=4,
        run_id=stable.run_id,
        workspace_id=stable.workspace_id,
        context_session_id=stable.context_session_id,
        context_state_epoch=lifecycle.context_state_epoch,
        binding_version=lifecycle.binding_version,
        coder_generation=lifecycle.coder_generation,
        generation_lease_id=lifecycle.generation_lease_id,
        mcp_request_id=7,
        tool_name=tool,
        arguments_digest=normalized_arguments_digest(arguments),
        operation_id=operation_id,
        result_digest=normalized_mcp_result_digest(broker_result),
        sandbox_backend="linux-bwrap-seccomp",
        sandbox_policy_digest=lifecycle.sandbox_policy_digest,
        capability_id=capability_id,
        context_event_seq=receipt_seq,
        duration_ms=10,
        source_bytes=100,
        returned_bytes=20,
        indexed_bytes=indexed_bytes,
        commands=(command,) if tool in {"ctx_execute", "ctx_execute_file", "ctx_batch_execute"} else (),
        retrieval=retrieval,
    )
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
    result = dict(bare_result)
    result["structuredContent"] = {
        **bare_result["structuredContent"],  # type: ignore[arg-type]
        "belloContextMode": envelope.to_dict(),
    }
    return receipt, result


def test_receipt_inbox_is_one_shot_and_bounded(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    receipt, _result = _receipt_and_result(
        binding,
        tool="ctx_execute",
        arguments={"code": "test"},
        capability_id="cap",
    )
    inbox = OutOfBandReceiptInbox(maximum_pending=1, maximum_total=1)
    inbox.publish(receipt)
    with pytest.raises(ReceiptAlreadySeen):
        inbox.publish(receipt)
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
    with pytest.raises(ReceiptNotFound):
        inbox.claim(
            envelope,
            origin=ContextNotificationOrigin(ClientRole.CODER, 4, "different-app"),
        )
    assert inbox.claim(envelope, origin=_origin()) == receipt
    with pytest.raises(ReceiptAlreadySeen):
        inbox.claim(envelope, origin=_origin())

    second = BrokerReceipt.from_dict({**receipt.to_dict(), "receipt_seq": 2, "operation_id": "op-2"})
    with pytest.raises(ReceiptInboxFull):
        inbox.publish(second)


def test_execution_terminal_requires_out_of_band_receipt_for_evidence(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    arguments = {"code": "run tests", "api_key": "secret-value"}
    receipt, result = _receipt_and_result(
        binding,
        tool="ctx_execute",
        arguments=arguments,
        capability_id="capability",
    )
    integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)
    started = integration.normalize_notification(
        method="item/started",
        params=_params(tool="ctx_execute", arguments=arguments),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=5,
        approval_capability_id="capability",
    )
    assert started.status is ContextOutcomeStatus.STARTED
    assert started.event is not None
    assert "secret-value" not in repr(started.redacted_summary)

    integration.publish_receipt(receipt)
    terminal = integration.normalize_notification(
        method="item/completed",
        params=_params(tool="ctx_execute", arguments=arguments, result=result, status="completed"),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=5,
        approval_capability_id="capability",
    )
    assert terminal.trusted is True
    assert terminal.classification is ContextCallClassification.EXECUTION
    assert len(terminal.evidence) == 1
    assert terminal.evidence[0].exit_code == 0
    assert terminal.action_counted is True
    assert integration.receipt_inbox.pending_count == 0
    assert integration.telemetry.value("context_mode_operations_receipted") == 1

    duplicate = integration.normalize_notification(
        method="item/completed",
        params=_params(tool="ctx_execute", arguments=arguments, result=result, status="completed"),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=5,
        approval_capability_id="capability",
    )
    assert duplicate.trusted is True
    assert duplicate.action_counted is False
    assert "duplicate_logical_terminal" in duplicate.protocol_issues


@pytest.mark.asyncio
async def test_controller_waits_for_delayed_receipt_before_terminal_normalization(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    controller = _approval_controller(binding)
    arguments = {"code": "python3 reviewable-helper.py"}
    capability_id = "capability"

    started = controller._normalize_context_mode_notification(
        _started_message(arguments=arguments),
        origin_role=AppServerClientRole.CODER,
    )
    assert started.status is ContextOutcomeStatus.STARTED
    logical_key = LogicalContextCallKey(ClientRole.CODER, "thread", "turn", "item")
    controller.context_integration.attach_approval_capability(
        logical_key=logical_key,
        capability_id=capability_id,
        tool_name="ctx_execute",
        arguments_digest=normalized_arguments_digest(arguments),
        active_binding=binding,
    )
    controller._context_capability_by_item[("thread", "turn", "item")] = capability_id
    receipt, result = _receipt_and_result(
        binding,
        tool="ctx_execute",
        arguments=arguments,
        capability_id=capability_id,
        broker_is_error=True,
    )
    # Codex app-server exposes a failed item but strips the MCP result's
    # top-level isError marker.  The controller must reconstruct the broker's
    # signed representation from that terminal status.
    assert "isError" not in result
    assert normalized_mcp_result_digest(result) != receipt.result_digest
    assert (
        normalized_mcp_result_digest(result, terminal_failed=True)
        == receipt.result_digest
    )
    terminal_message = AppServerMessage(
        {
            "method": "item/completed",
            "params": _params(
                tool="ctx_execute",
                arguments=arguments,
                result=result,
                status="failed",
                request_id=None,
            ),
        },
        role=AppServerClientRole.CODER,
        process_epoch=4,
        app_server_instance_id="app",
    )

    async def publish_after_terminal_arrives() -> None:
        await asyncio.sleep(0.01)
        controller.context_integration.publish_receipt(receipt)

    publish_task = asyncio.create_task(publish_after_terminal_arrives())
    delivered = await asyncio.wait_for(
        controller._wait_for_context_terminal_receipt_delivery(terminal_message.params),
        timeout=2.0,
    )
    await publish_task
    assert delivered is True

    terminal = controller._normalize_context_mode_notification(
        terminal_message,
        origin_role=AppServerClientRole.CODER,
    )
    assert terminal.status is ContextOutcomeStatus.FAILED
    assert terminal.trusted is True
    assert "missing_or_invalid_out_of_band_receipt" not in terminal.protocol_issues


@pytest.mark.asyncio
async def test_controller_receipt_delivery_timeout_remains_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    controller = _approval_controller(binding)
    arguments = {"query": "receipt ordering"}
    started_message = AppServerMessage(
        {
            "method": "item/started",
            "params": _params(
                tool="ctx_search",
                arguments=arguments,
                request_id=None,
            ),
        },
        role=AppServerClientRole.CODER,
        process_epoch=4,
        app_server_instance_id="app",
    )
    started = controller._normalize_context_mode_notification(
        started_message,
        origin_role=AppServerClientRole.CODER,
    )
    assert started.status is ContextOutcomeStatus.STARTED
    _receipt, result = _receipt_and_result(
        binding,
        tool="ctx_search",
        arguments=arguments,
        capability_id=None,
        broker_is_error=True,
    )
    terminal_message = AppServerMessage(
        {
            "method": "item/completed",
            "params": _params(
                tool="ctx_search",
                arguments=arguments,
                result=result,
                status="failed",
                request_id=None,
            ),
        },
        role=AppServerClientRole.CODER,
        process_epoch=4,
        app_server_instance_id="app",
    )
    monkeypatch.setattr(
        "supervisor.controller.CONTEXT_RECEIPT_DELIVERY_TIMEOUT_SECONDS",
        0.001,
    )

    assert (
        await controller._wait_for_context_terminal_receipt_delivery(terminal_message.params)
        is False
    )
    terminal = controller._normalize_context_mode_notification(
        terminal_message,
        origin_role=AppServerClientRole.CODER,
    )
    assert terminal.trusted is False
    assert terminal.evidence == ()
    assert "missing_or_invalid_out_of_band_receipt" in terminal.protocol_issues


def test_execution_capability_attaches_after_public_item_started(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    arguments = {"code": "pytest -q"}
    integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)

    started = integration.normalize_notification(
        method="item/started",
        params=_params(tool="ctx_execute", arguments=arguments, request_id=None),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=5,
    )
    assert started.status is ContextOutcomeStatus.STARTED
    assert "missing_controller_approval_capability" not in started.protocol_issues

    logical_key = LogicalContextCallKey(ClientRole.CODER, "thread", "turn", "item")
    with pytest.raises(IntegrationError, match="arguments_digest"):
        integration.attach_approval_capability(
            logical_key=logical_key,
            capability_id="wrong-capability",
            tool_name="ctx_execute",
            arguments_digest="f" * 64,
            active_binding=binding,
        )
    integration.attach_approval_capability(
        logical_key=logical_key,
        capability_id="capability",
        tool_name="ctx_execute",
        arguments_digest=normalized_arguments_digest(arguments),
        active_binding=binding,
    )

    receipt, result = _receipt_and_result(
        binding,
        tool="ctx_execute",
        arguments=arguments,
        capability_id="capability",
    )
    integration.publish_receipt(receipt)
    terminal = integration.normalize_notification(
        method="item/completed",
        params=_params(
            tool="ctx_execute",
            arguments=arguments,
            result=result,
            status="completed",
            request_id=None,
        ),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=5,
        approval_capability_id="capability",
    )
    assert terminal.trusted is True
    assert "missing_controller_approval_capability" not in terminal.protocol_issues

    with pytest.raises(IntegrationError, match="terminal"):
        integration.attach_approval_capability(
            logical_key=logical_key,
            capability_id="late-capability",
            tool_name="ctx_execute",
            arguments_digest=normalized_arguments_digest(arguments),
            active_binding=binding,
        )


def test_controller_denial_has_nonfatal_failed_terminal_without_receipt(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    arguments = {"code": "python3 oversized-review-helper.py"}
    logical_key = LogicalContextCallKey(ClientRole.CODER, "thread", "turn", "item")
    integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)

    started = integration.normalize_notification(
        method="item/started",
        params=_params(tool="ctx_execute", arguments=arguments, request_id=None),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=5,
    )
    assert started.status is ContextOutcomeStatus.STARTED

    integration.mark_approval_denied(
        logical_key=logical_key,
        tool_name="ctx_execute",
        arguments_digest=normalized_arguments_digest(arguments),
        active_binding=binding,
    )
    terminal = integration.normalize_notification(
        method="item/completed",
        params=_params(
            tool="ctx_execute",
            arguments=arguments,
            status="failed",
            request_id=None,
        ),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=5,
    )

    assert terminal.status is ContextOutcomeStatus.FAILED
    assert terminal.controller_denied is True
    assert terminal.trusted is False
    assert terminal.health_violation is False
    assert terminal.protocol_issues == ()
    assert terminal.action_counted is False
    assert integration.telemetry.value("context_mode_calls_failed") == 1
    assert integration.telemetry.value("context_mode_untrusted_results") == 0
    assert integration.telemetry.value("context_mode_provenance_failures") == 0


def test_controller_denied_purge_is_not_an_executed_action(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    arguments = {"scope": "workspace"}
    logical_key = LogicalContextCallKey(ClientRole.CODER, "thread", "turn", "item")
    integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)
    integration.normalize_notification(
        method="item/started",
        params=_params(tool="ctx_purge", arguments=arguments, request_id=None),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=5,
    )
    integration.mark_approval_denied(
        logical_key=logical_key,
        tool_name="ctx_purge",
        arguments_digest=normalized_arguments_digest(arguments),
        active_binding=binding,
    )

    terminal = integration.normalize_notification(
        method="item/completed",
        params=_params(
            tool="ctx_purge",
            arguments=arguments,
            status="failed",
            request_id=None,
        ),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=5,
    )

    assert terminal.classification is ContextCallClassification.PURGE
    assert terminal.controller_denied is True
    assert terminal.action_counted is False
    assert terminal.health_violation is False


def test_controller_denial_rejects_an_impossible_success_terminal(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    arguments = {"code": "python3 oversized-review-helper.py"}
    logical_key = LogicalContextCallKey(ClientRole.CODER, "thread", "turn", "item")
    integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)
    integration.normalize_notification(
        method="item/started",
        params=_params(tool="ctx_execute", arguments=arguments, request_id=None),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=5,
    )
    integration.mark_approval_denied(
        logical_key=logical_key,
        tool_name="ctx_execute",
        arguments_digest=normalized_arguments_digest(arguments),
        active_binding=binding,
    )

    terminal = integration.normalize_notification(
        method="item/completed",
        params=_params(
            tool="ctx_execute",
            arguments=arguments,
            status="completed",
            request_id=None,
        ),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=5,
    )

    assert terminal.controller_denied is False
    assert terminal.health_violation is True
    assert "controller_denial_terminal_mismatch" in terminal.protocol_issues


def test_terminal_replay_after_monotonic_process_recovery_is_trusted_once(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    started_binding = _binding(workspace)
    arguments = {"code": "pytest -q"}
    logical_key = LogicalContextCallKey(ClientRole.CODER, "thread", "turn", "item")
    integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)
    started = integration.normalize_notification(
        method="item/started",
        params=_params(tool="ctx_execute", arguments=arguments, request_id=None),
        origin=_origin(),
        active_binding=started_binding,
        workspace_revision=7,
    )
    assert started.ledger_disposition is EventDisposition.ACCEPTED_STARTED
    integration.attach_approval_capability(
        logical_key=logical_key,
        capability_id="capability",
        tool_name="ctx_execute",
        arguments_digest=normalized_arguments_digest(arguments),
        active_binding=started_binding,
    )
    receipt, result = _receipt_and_result(
        started_binding,
        tool="ctx_execute",
        arguments=arguments,
        capability_id="capability",
    )
    integration.publish_receipt(receipt)

    recovered = _recovered_binding(started_binding)
    recovered_origin = ContextNotificationOrigin(ClientRole.CODER, 5, "app-recovered")
    replayed_start = integration.normalize_notification(
        method="item/started",
        params=_params(tool="ctx_execute", arguments=arguments, request_id=None),
        origin=recovered_origin,
        active_binding=recovered,
        workspace_revision=8,
    )
    assert replayed_start.ledger_disposition is EventDisposition.DUPLICATE_OBSERVATION
    assert replayed_start.protocol_issues == ()

    terminal_params = _params(
        tool="ctx_execute",
        arguments=arguments,
        result=result,
        status="completed",
        request_id=None,
    )
    terminal = integration.normalize_notification(
        method="item/completed",
        params=terminal_params,
        origin=recovered_origin,
        active_binding=recovered,
        workspace_revision=8,
    )
    assert terminal.trusted is True
    assert terminal.action_counted is True
    assert len(terminal.evidence) == 1
    assert terminal.event is not None
    assert terminal.event.binding_version == started_binding.binding_version
    assert terminal.event.observation == ContextObservationKey("app-recovered", 5, 1)
    assert terminal.provenance is not None
    assert terminal.provenance.receipt.app_server_instance_id == "app"
    assert terminal.provenance.receipt.process_epoch == 4

    same_transport_duplicate = integration.normalize_notification(
        method="item/completed",
        params=terminal_params,
        origin=recovered_origin,
        active_binding=recovered,
        workspace_revision=8,
    )
    assert same_transport_duplicate.trusted is True
    assert same_transport_duplicate.action_counted is False
    assert same_transport_duplicate.evidence == ()
    assert same_transport_duplicate.ledger_disposition is EventDisposition.DUPLICATE_OBSERVATION

    recovered_again = _recovered_binding(
        recovered,
        process_epoch=6,
        app_server_instance_id="app-recovered-again",
    )
    another_origin_duplicate = integration.normalize_notification(
        method="item/completed",
        params=terminal_params,
        origin=ContextNotificationOrigin(ClientRole.CODER, 6, "app-recovered-again"),
        active_binding=recovered_again,
        workspace_revision=9,
    )
    assert another_origin_duplicate.action_counted is False
    assert another_origin_duplicate.evidence == ()
    assert (
        another_origin_duplicate.ledger_disposition
        is EventDisposition.DUPLICATE_LOGICAL_TERMINAL
    )
    assert integration.telemetry.value("context_mode_calls_completed") == 1
    assert integration.telemetry.value("context_mode_operations_receipted") == 1
    assert integration.event_ledger.observation_count(logical_key) == 4


def test_stale_pre_recovery_terminal_is_rejected_without_poisoning_call(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    started_binding = _binding(workspace)
    arguments = {"query": "parser"}
    integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)
    integration.normalize_notification(
        method="item/started",
        params=_params(tool="ctx_search", arguments=arguments, request_id=None),
        origin=_origin(),
        active_binding=started_binding,
        workspace_revision=1,
    )
    receipt, result = _receipt_and_result(
        started_binding,
        tool="ctx_search",
        arguments=arguments,
        capability_id=None,
    )
    integration.publish_receipt(receipt)
    recovered = _recovered_binding(started_binding)
    terminal_params = _params(
        tool="ctx_search",
        arguments=arguments,
        result=result,
        status="completed",
        request_id=None,
    )

    stale = integration.normalize_notification(
        method="item/completed",
        params=terminal_params,
        origin=_origin(),
        active_binding=recovered,
        workspace_revision=1,
    )
    assert stale.health_violation is True
    assert stale.action_counted is False
    assert "stale_transport_origin" in stale.protocol_issues
    assert integration.receipt_inbox.pending_count == 1
    assert integration.telemetry.value("context_mode_calls_completed") == 0

    recovered_terminal = integration.normalize_notification(
        method="item/completed",
        params=terminal_params,
        origin=ContextNotificationOrigin(ClientRole.CODER, 5, "app-recovered"),
        active_binding=recovered,
        workspace_revision=1,
    )
    assert recovered_terminal.trusted is True
    assert recovered_terminal.action_counted is True
    assert integration.receipt_inbox.pending_count == 0


@pytest.mark.parametrize("change", ["policy", "generation"])
def test_recovery_replay_rejects_policy_or_generation_scope_change(
    tmp_path: Path,
    change: str,
) -> None:
    workspace = tmp_path / change
    workspace.mkdir()
    started_binding = _binding(workspace)
    arguments = {"query": "parser"}
    integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)
    integration.normalize_notification(
        method="item/started",
        params=_params(tool="ctx_search", arguments=arguments, request_id=None),
        origin=_origin(),
        active_binding=started_binding,
        workspace_revision=1,
    )
    receipt, result = _receipt_and_result(
        started_binding,
        tool="ctx_search",
        arguments=arguments,
        capability_id=None,
    )
    integration.publish_receipt(receipt)
    if change == "policy":
        active = started_binding.transition(
            TransitionReason.POLICY_CHANGE,
            sandbox_policy_digest="c" * 64,
        )
    else:
        active = started_binding.transition(
            TransitionReason.LOGICAL_GENERATION_RESTART,
            coder_generation=started_binding.lifecycle.coder_generation + 1,
            generation_lease_id="next-lease",
            provider_thread_id=None,
        ).transition(
            TransitionReason.THREAD_CLAIM,
            provider_thread_id="thread",
        )
    outcome = integration.normalize_notification(
        method="item/completed",
        params=_params(
            tool="ctx_search",
            arguments=arguments,
            result=result,
            status="completed",
            request_id=None,
        ),
        origin=ContextNotificationOrigin(
            ClientRole.CODER,
            active.lifecycle.coder_process_epoch,
            active.lifecycle.app_server_instance_id,
        ),
        active_binding=active,
        workspace_revision=1,
    )
    assert outcome.health_violation is True
    assert outcome.action_counted is False
    assert "binding_changed_since_started" in outcome.protocol_issues
    assert integration.receipt_inbox.pending_count == 1
    assert integration.telemetry.value("context_mode_calls_completed") == 0


def test_protocol_only_terminal_controller_counters_are_idempotent(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)
    params = _params(
        tool="ctx_stats",
        arguments={},
        result={"structuredContent": {}},
        status="completed",
    )

    first = integration.normalize_notification(
        method="item/completed",
        params=params,
        origin=_origin(),
        active_binding=binding,
        workspace_revision=0,
    )
    duplicate = integration.normalize_notification(
        method="item/completed",
        params=params,
        origin=_origin(),
        active_binding=binding,
        workspace_revision=0,
    )

    assert first.health_violation is True
    assert first.action_counted is True
    assert duplicate.action_counted is False
    assert integration.telemetry.value("context_mode_calls_completed") == 1
    assert integration.telemetry.value("context_mode_untrusted_results") == 1
    assert integration.telemetry.value("context_mode_provenance_failures") == 1


@pytest.mark.asyncio
async def test_controller_correlates_real_elicitation_and_attaches_one_shot_capability(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    controller = _approval_controller(binding)
    arguments = {"code": "pytest -q", "timeout_ms": 1000}

    started = controller._normalize_context_mode_notification(
        _started_message(arguments=arguments),
        origin_role=AppServerClientRole.CODER,
    )
    assert started.status is ContextOutcomeStatus.STARTED
    assert set(controller._context_pending_approval_calls) == {("thread", "turn", "item")}

    approval = _approval_message(arguments)
    pending_key = PendingRequestKey(AppServerClientRole.CODER, 4, 91)
    binding_update = controller._active_context_approval_binding(
        approval,
        origin_role=AppServerClientRole.CODER,
        pending_key=pending_key,
    )
    context = normalize_approval_request(approval).model_copy(
        update={
            "client_role": "coder",
            "process_epoch": 4,
            "app_server_instance_id": "app",
            **binding_update,
        }
    )

    assert context.item_id == "item"
    assert context.tool_name == "ctx_execute"
    assert context.command == "bello_context_mode/ctx_execute"
    assert context.cwd == os.fspath(workspace)
    assert context.normalized_arguments_digest == normalized_arguments_digest(arguments)
    assert "message" not in context.raw_params
    assert controller._context_approval_item_by_request[pending_key] == (
        "thread",
        "turn",
        "item",
    )
    assert controller._context_approval_issue(
        context,
        message=approval,
        origin_role=AppServerClientRole.CODER,
    ) is None

    summary = controller._context_approval_wake_summary(context)
    assert summary is not None
    wake = _approval_wake_context(context, context_summary=summary)
    assert wake.context_arguments_summary == {
        "arguments": arguments,
        "tool": "ctx_execute",
    }
    assert len(wake.context_arguments_correlation_digest or "") == 64
    assert wake.context_arguments_redacted_or_truncated is False
    wake_payload = wake.model_dump(mode="json")
    assert "raw_params" not in wake_payload
    assert "binding_version" not in wake_payload
    assert "generation_lease_id" not in wake_payload

    await controller._grant_context_approval_capability(
        context,
        message=approval,
        pending_key=pending_key,
    )
    capability_id = controller._context_capability_by_item[("thread", "turn", "item")]
    assert controller._context_approval_capabilities[pending_key] == capability_id
    logical_key = LogicalContextCallKey(ClientRole.CODER, "thread", "turn", "item")
    assert controller.context_integration._calls[logical_key].approval_capability_id == capability_id
    assert len(controller.context_runtime.native_runtime.registered) == 1


def test_controller_binds_policy_denial_to_exact_pending_context_call(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    controller = _approval_controller(binding)
    arguments = {"code": "python3 reviewable-helper.py"}

    controller._normalize_context_mode_notification(
        _started_message(arguments=arguments),
        origin_role=AppServerClientRole.CODER,
    )
    approval = _approval_message(arguments)
    update = controller._active_context_approval_binding(
        approval,
        origin_role=AppServerClientRole.CODER,
        pending_key=PendingRequestKey(AppServerClientRole.CODER, 4, 91),
    )
    context = normalize_approval_request(approval).model_copy(
        update={
            "client_role": "coder",
            "process_epoch": 4,
            "app_server_instance_id": "app",
            **update,
        }
    )

    controller._mark_context_approval_denied(context)

    logical_key = LogicalContextCallKey(ClientRole.CODER, "thread", "turn", "item")
    state = controller.context_integration._calls[logical_key]
    assert state.approval_denied is True
    assert state.approval_capability_id is None


def test_context_approval_wake_packet_is_bounded_and_redacted(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    controller = _approval_controller(binding)
    secret = "ghp_" + ("s" * 32)
    arguments = {
        "code": f"token={secret}\n" + ("print('x')\n" * 2_000),
        "authorization": f"Bearer {secret}",
    }
    controller._normalize_context_mode_notification(
        _started_message(arguments=arguments),
        origin_role=AppServerClientRole.CODER,
    )
    approval = _approval_message(arguments)
    update = controller._active_context_approval_binding(
        approval,
        origin_role=AppServerClientRole.CODER,
        pending_key=PendingRequestKey(AppServerClientRole.CODER, 4, 91),
    )
    context = normalize_approval_request(approval).model_copy(update=update)

    summary = controller._context_approval_wake_summary(context)
    wake = _approval_wake_context(context, context_summary=summary)
    encoded = repr(wake.context_arguments_summary).encode("utf-8")
    assert len(encoded) <= 8 * 1024
    assert secret.encode() not in encoded
    assert wake.context_arguments_redacted_or_truncated is True


def test_controller_fails_closed_on_ambiguous_or_missing_tool_params(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    arguments = {"code": "pytest -q"}

    ambiguous = _approval_controller(binding)
    ambiguous._normalize_context_mode_notification(
        _started_message(arguments=arguments, item_id="first"),
        origin_role=AppServerClientRole.CODER,
    )
    ambiguous._normalize_context_mode_notification(
        _started_message(arguments=arguments, item_id="second"),
        origin_role=AppServerClientRole.CODER,
    )
    approval = _approval_message(arguments, request_id=92)
    ambiguous_key = PendingRequestKey(AppServerClientRole.CODER, 4, 92)
    update = ambiguous._active_context_approval_binding(
        approval,
        origin_role=AppServerClientRole.CODER,
        pending_key=ambiguous_key,
    )
    assert update["item_id"] is None
    assert "ambiguously" in ambiguous._context_approval_correlation_issues[ambiguous_key]
    assert ambiguous_key not in ambiguous._context_approval_item_by_request

    missing = _approval_controller(binding)
    missing._normalize_context_mode_notification(
        _started_message(arguments=arguments),
        origin_role=AppServerClientRole.CODER,
    )
    malformed = _approval_message(arguments, request_id=93)
    del malformed.raw["params"]["_meta"]["tool_params"]
    missing_key = PendingRequestKey(AppServerClientRole.CODER, 4, 93)
    update = missing._active_context_approval_binding(
        malformed,
        origin_role=AppServerClientRole.CODER,
        pending_key=missing_key,
    )
    assert update["item_id"] is None
    assert "tool_params" in missing._context_approval_correlation_issues[missing_key]
    assert ("thread", "turn", "item") in missing._context_pending_approval_calls

    missing_kind = _approval_controller(binding)
    missing_kind._normalize_context_mode_notification(
        _started_message(arguments=arguments),
        origin_role=AppServerClientRole.CODER,
    )
    malformed_kind = _approval_message(arguments, request_id=94)
    del malformed_kind.raw["params"]["_meta"]["codex_approval_kind"]
    missing_kind_key = PendingRequestKey(AppServerClientRole.CODER, 4, 94)
    update = missing_kind._active_context_approval_binding(
        malformed_kind,
        origin_role=AppServerClientRole.CODER,
        pending_key=missing_kind_key,
    )
    context = normalize_approval_request(malformed_kind).model_copy(update=update)
    assert context.request_type.value == "mcp_tool_call"
    assert "approval kind" in missing_kind._context_approval_issue(
        context,
        message=malformed_kind,
        origin_role=AppServerClientRole.CODER,
    )


def test_result_envelope_without_inbox_receipt_is_untrusted(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    arguments = {"code": "run tests"}
    _receipt, result = _receipt_and_result(
        binding,
        tool="ctx_execute",
        arguments=arguments,
        capability_id="capability",
    )
    integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)
    integration.normalize_notification(
        method="item/started",
        params=_params(tool="ctx_execute", arguments=arguments),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=1,
        approval_capability_id="capability",
    )
    terminal = integration.normalize_notification(
        method="item/completed",
        params=_params(tool="ctx_execute", arguments=arguments, result=result, status="completed"),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=1,
        approval_capability_id="capability",
    )
    assert terminal.trusted is False
    assert terminal.provenance is None
    assert terminal.evidence == ()
    assert terminal.action_counted is True
    assert terminal.ledger_disposition is not None
    assert terminal.ledger_disposition.value == "accepted_terminal"
    assert "missing_or_invalid_out_of_band_receipt" in terminal.protocol_issues
    assert integration.telemetry.value("context_mode_untrusted_results") == 1


def test_public_codex_item_without_request_id_uses_attested_terminal_id(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    arguments = {"query": "parser"}
    receipt, result = _receipt_and_result(
        binding,
        tool="ctx_search",
        arguments=arguments,
        capability_id=None,
    )
    integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)
    started = integration.normalize_notification(
        method="item/started",
        params=_params(tool="ctx_search", arguments=arguments, request_id=None),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=1,
    )
    assert "missing_mcp_request_id" not in started.protocol_issues

    integration.publish_receipt(receipt)
    terminal = integration.normalize_notification(
        method="item/completed",
        params=_params(
            tool="ctx_search",
            arguments=arguments,
            result=result,
            status="completed",
            request_id=None,
        ),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=1,
    )
    assert terminal.trusted is True
    assert terminal.action_counted is True
    assert terminal.protocol_issues == ()


def test_malformed_context_terminal_is_untrusted_action_and_health_violation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    arguments = {"query": "parser"}
    integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)
    integration.normalize_notification(
        method="item/started",
        params=_params(tool="ctx_search", arguments=arguments),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=1,
    )
    terminal = integration.normalize_notification(
        method="item/completed",
        params=_params(
            tool="ctx_search",
            arguments=arguments,
            result={"structuredContent": {"answer": "not attested"}},
            status="completed",
        ),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=1,
    )
    assert terminal.trusted is False
    assert terminal.action_counted is True
    assert terminal.health_violation is True
    assert "missing_or_malformed_result_envelope" in terminal.protocol_issues


def test_invalid_started_status_is_immediate_health_violation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)

    started = integration.normalize_notification(
        method="item/started",
        params=_params(
            tool="ctx_search",
            arguments={"query": "parser"},
            status="completed",
        ),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=1,
    )

    assert started.status is ContextOutcomeStatus.HEALTH_VIOLATION
    assert started.health_violation is True
    assert "invalid_started_status" in started.protocol_issues


def test_result_envelope_requires_pinned_mcp_content_shape(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    receipt, result = _receipt_and_result(
        binding,
        tool="ctx_search",
        arguments={"query": "parser"},
        capability_id=None,
    )
    assert ResultEnvelope.from_result(result).broker_receipt_digest == receipt.digest
    assert ResultEnvelope.from_result({**result, "_meta": None}).broker_receipt_digest == receipt.digest
    assert normalized_mcp_result_digest({**result, "_meta": None}) == normalized_mcp_result_digest(result)

    with pytest.raises(ProvenanceError, match="_meta must be an object"):
        ResultEnvelope.from_result({**result, "_meta": "invalid"})

    without_content = dict(result)
    without_content.pop("content")
    with pytest.raises(ProvenanceError, match="bounded non-empty array"):
        ResultEnvelope.from_result(without_content)

    malformed_content = {**result, "content": [True]}
    with pytest.raises(ProvenanceError, match="exact text blocks"):
        ResultEnvelope.from_result(malformed_content)

    missing_text = {**result, "content": [{"type": "text"}]}
    with pytest.raises(ProvenanceError, match="exact text blocks"):
        ResultEnvelope.from_result(missing_text)

    unexpected_result_field = {**result, "content": result["content"], "extra": True}
    with pytest.raises(ProvenanceError, match="outside the pinned"):
        ResultEnvelope.from_result(unexpected_result_field)


@pytest.mark.parametrize(
    ("tool", "classification", "indexed_bytes"),
    [
        ("ctx_search", ContextCallClassification.RETRIEVAL, None),
        ("ctx_index", ContextCallClassification.INDEXING, 55),
    ],
)
def test_retrieval_and_indexing_are_classified_from_trusted_receipt(
    tmp_path: Path,
    tool: str,
    classification: ContextCallClassification,
    indexed_bytes: int | None,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace)
    arguments = {"query": "parser"} if tool == "ctx_search" else {"paths": ["src"]}
    retrieval = (
        RetrievalRecord(
            "file",
            "src/parser.py",
            "9" * 64,
            3,
            3,
            ((0, 10),),
            100,
            10,
            False,
        ),
    ) if tool == "ctx_search" else ()
    receipt, result = _receipt_and_result(
        binding,
        tool=tool,
        arguments=arguments,
        capability_id=None,
        retrieval=retrieval,
        indexed_bytes=indexed_bytes,
    )
    integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)
    integration.normalize_notification(
        method="item/started",
        params=_params(tool=tool, arguments=arguments),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=2,
    )
    integration.publish_receipt(receipt)
    terminal = integration.normalize_notification(
        method="item/completed",
        params=_params(tool=tool, arguments=arguments, result=result, status="completed"),
        origin=_origin(),
        active_binding=binding,
        workspace_revision=2,
    )
    assert terminal.trusted
    assert terminal.classification is classification
    assert terminal.retrieval == retrieval
    assert terminal.indexed_bytes == indexed_bytes
    assert terminal.evidence == ()
    if tool == "ctx_search":
        controller = BelloController.__new__(BelloController)
        controller.project_root = workspace
        controller._coder_snapshot = None
        controller._sequence = 0
        assert controller._inspection_from_context_outcome(terminal) is not None
        assert controller._inspection_from_context_outcome(
            replace(terminal, retrieval=())
        ) is None


def test_supervisor_context_item_is_role_isolation_health_violation(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    integration = ContextModeIntegration(redaction_authority_key=b"k" * 32)
    outcome = integration.normalize_notification(
        method="item/completed",
        params=_params(tool="ctx_stats", arguments={}, result={"structuredContent": {}}),
        origin=_origin(ClientRole.SUPERVISOR),
        active_binding=binding,
        workspace_revision=0,
    )
    assert outcome.health_violation is True
    assert outcome.status is ContextOutcomeStatus.HEALTH_VIOLATION
    assert outcome.protocol_issue == "context_mode_item_on_supervisor_transport"


def test_workspace_mutation_journal_marks_both_overlapping_writers() -> None:
    controller = BelloController.__new__(BelloController)
    controller._workspace_revision = 0
    controller._active_workspace_mutations = {}
    controller._overlapped_workspace_mutations = set()
    controller._workspace_mutation_terminals = {}
    first = ("thread", "turn", "first")
    second = ("thread", "turn", "second")

    controller._begin_workspace_mutation(first)
    controller._begin_workspace_mutation(second)
    assert controller._complete_workspace_mutation(first) == (1, True)
    assert controller._complete_workspace_mutation(second) == (2, True)
    # A duplicate terminal observes the original journal result and cannot
    # advance the workspace revision a second time.
    assert controller._complete_workspace_mutation(first) == (1, True)
    assert controller._workspace_revision == 2

    serial = ("thread", "turn", "serial")
    controller._begin_workspace_mutation(serial)
    assert controller._complete_workspace_mutation(serial) == (3, False)


def test_authority_counters_survive_restart_without_replay_increment(tmp_path: Path) -> None:
    path = tmp_path / "counter-state.json"
    counters = AuthoritySeparatedCounters(path)
    assert counters.increment(
        "context_mode_calls_started",
        authority="controller_observed",
        idempotency_key="logical-call",
    )
    restored = AuthoritySeparatedCounters(path)
    assert not restored.increment(
        "context_mode_calls_started",
        authority="controller_observed",
        idempotency_key="logical-call",
    )
    assert restored.value("context_mode_calls_started") == 1


def test_event_identity_uses_outer_notification_ids_and_exact_binding_scope(tmp_path: Path) -> None:
    item = {
        "id": "item",
        "type": "mcpToolCall",
        "server": "bello_context_mode",
        "tool": "ctx_stats",
        "arguments": {},
    }
    active = ActiveEventContext(
        ClientRole.CODER,
        "app",
        4,
        "thread",
        "run",
        "workspace",
        "session",
        1,
        3,
        2,
        "lease",
    )
    key, tool = identify_context_call(
        item,
        active=active,
        params={"threadId": "thread", "turnId": "turn", "itemId": "item"},
    )
    assert key.thread_id == "thread" and key.turn_id == "turn" and key.item_id == "item"
    assert tool == "ctx_stats"
    with pytest.raises(EventError):
        identify_context_call(
            item,
            active=active,
            params={"threadId": "other", "turnId": "turn", "itemId": "item"},
        )
