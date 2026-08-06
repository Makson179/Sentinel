from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any

import pytest

from supervisor.appserver import AppServerError, AppServerMessage, ClientRole
from supervisor.coder import coder_thread_params
from supervisor.code_context import (
    CODE_CONTEXT_NAMESPACE,
    CODE_CONTEXT_TOOL_NAMES,
    dynamic_tool_specs,
)
from supervisor.context_mode.config import (
    ALLOWED_TOOLS,
    ALLOWED_TOOL_SET,
    CONTEXT_SERVER_NAME,
)
from supervisor.controller import BelloController, _item_may_mutate_workspace


class _Store:
    def __init__(self) -> None:
        self.config = SimpleNamespace(
            coder_thread_id="coder-thread",
            active_coder_turn_id="coder-turn",
        )
        self.metrics: dict[str, Any] = {}
        self.raw_logs: list[dict[str, Any]] = []
        self.recent_actions: list[str] = []

    def get_bello_config(self) -> SimpleNamespace:
        return self.config

    def update_runtime_metrics(self, patch):
        self.metrics = patch(self.metrics)

    def append_raw_log(self, value: dict[str, Any]) -> None:
        self.raw_logs.append(value)

    def append_recent_action(self, value: str) -> None:
        self.recent_actions.append(value)


class _Client:
    def __init__(self) -> None:
        self.responses: list[tuple[int | str, Any]] = []

    async def respond(self, request_id: int | str, response: Any) -> None:
        self.responses.append((request_id, response))


class _CodeContextService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.response: dict[str, Any] = {
            "success": True,
            "contentItems": [
                {
                    "type": "inputText",
                    "text": json.dumps({"ok": True, "symbols": ["Widget"]}),
                }
            ],
        }

    async def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool, arguments))
        return self.response


class _ForbiddenCollaborator:
    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"structured code call unexpectedly accessed {name}")


def _controller(*, mode: str = "read") -> tuple[BelloController, _CodeContextService, _Client, _Client]:
    controller = BelloController.__new__(BelloController)
    coder_client = _Client()
    supervisor_client = _Client()
    service = _CodeContextService()
    controller.structured_code_tools = mode
    controller.store = _Store()
    controller.coder_client = coder_client
    controller.supervisor_client = supervisor_client
    controller.code_context_service = service
    controller._code_context_tasks = set()
    controller._terminal_cleanup_started = False
    controller.approvals = _ForbiddenCollaborator()
    controller.supervisor = _ForbiddenCollaborator()
    controller.runtime_triage_reviewer = _ForbiddenCollaborator()
    controller.pending_approvals = {}
    return controller, service, coder_client, supervisor_client


def _request(
    *,
    tool: str = "list_symbols",
    thread_id: str = "coder-thread",
    turn_id: str = "coder-turn",
    role: ClientRole = ClientRole.CODER,
) -> AppServerMessage:
    return AppServerMessage(
        {
            "id": 41,
            "method": "item/tool/call",
            "params": {
                "arguments": {"path": "src/widget.py"},
                "callId": "call-1",
                "namespace": CODE_CONTEXT_NAMESPACE,
                "threadId": thread_id,
                "tool": tool,
                "turnId": turn_id,
            },
        },
        role=role,
        process_epoch=3,
        app_server_instance_id=f"{role.value}-instance",
    )


async def _dispatch(
    controller: BelloController,
    message: AppServerMessage,
) -> None:
    await controller.handle_server_request(message)
    tasks = tuple(controller._code_context_tasks)
    assert len(tasks) == 1
    await asyncio.gather(*tasks)


def _error_code(response: dict[str, Any]) -> str:
    assert response["success"] is False
    content_items = response["contentItems"]
    assert len(content_items) == 1
    return json.loads(content_items[0]["text"])["error"]["code"]


def _dynamic_error_response(
    *,
    code: Any,
    reason: Any,
    message: str = "diagnostic text is not persisted",
) -> dict[str, Any]:
    return {
        "success": False,
        "contentItems": [
            {
                "type": "inputText",
                "text": json.dumps(
                    {
                        "ok": False,
                        "error": {"code": code, "message": message, "reason": reason},
                    }
                ),
            }
        ],
    }


@pytest.mark.asyncio
async def test_valid_dynamic_call_bypasses_approval_and_llm_and_responds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller, service, coder_client, _ = _controller()

    def fail_if_normalized(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("dynamic tool call entered the approval path")

    monkeypatch.setattr("supervisor.controller.normalize_approval_request", fail_if_normalized)
    message = _request()

    await _dispatch(controller, message)

    assert service.calls == [("list_symbols", {"path": "src/widget.py"})]
    assert coder_client.responses == [
        (
            41,
            {
                "success": True,
                "contentItems": [
                    {
                        "type": "inputText",
                        "text": json.dumps({"ok": True, "symbols": ["Widget"]}),
                    }
                ],
            },
        )
    ]
    assert controller.pending_approvals == {}
    assert "structured_code_error_code_counts" not in controller.store.metrics
    assert "structured_code_error_detail_counts" not in controller.store.metrics
    assert "structured_code_tool_error_counts" not in controller.store.metrics


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "role", "thread_id", "tool", "expected_code"),
    [
        ("off", ClientRole.CODER, "coder-thread", "list_symbols", "disabled"),
        ("read", ClientRole.SUPERVISOR, "coder-thread", "list_symbols", "wrong_role"),
        ("read", ClientRole.CODER, "retired-thread", "list_symbols", "stale_thread"),
        ("read", ClientRole.CODER, "coder-thread", "not_a_bello_tool", "unknown_tool"),
    ],
)
async def test_invalid_dynamic_calls_fail_closed_without_invoking_service(
    mode: str,
    role: ClientRole,
    thread_id: str,
    tool: str,
    expected_code: str,
) -> None:
    controller, service, coder_client, supervisor_client = _controller(mode=mode)

    await _dispatch(
        controller,
        _request(role=role, thread_id=thread_id, tool=tool),
    )

    client = supervisor_client if role is ClientRole.SUPERVISOR else coder_client
    assert len(client.responses) == 1
    assert _error_code(client.responses[0][1]) == expected_code
    assert service.calls == []
    assert controller.pending_approvals == {}


@pytest.mark.asyncio
async def test_prepare_symbol_edit_is_forbidden_in_read_mode() -> None:
    controller, service, coder_client, _ = _controller(mode="read")

    await _dispatch(controller, _request(tool="prepare_symbol_edit"))

    assert len(coder_client.responses) == 1
    assert _error_code(coder_client.responses[0][1]) == "tool_not_enabled"
    assert service.calls == []


@pytest.mark.asyncio
async def test_rejected_call_does_not_erase_last_service_metric_snapshot() -> None:
    controller, service, coder_client, _ = _controller(mode="off")
    controller.store.metrics["structured_code_service_metrics"] = {
        "calls_total": 7,
        "cache_hits_total": 4,
    }

    await _dispatch(controller, _request())

    assert len(coder_client.responses) == 1
    assert _error_code(coder_client.responses[0][1]) == "disabled"
    assert service.calls == []
    assert controller.store.metrics["structured_code_service_metrics"] == {
        "calls_total": 7,
        "cache_hits_total": 4,
    }
    assert controller.store.metrics["structured_code_error_code_counts"] == {
        "disabled": 1,
    }
    assert controller.store.metrics["structured_code_error_detail_counts"] == {
        "disabled": 1,
    }
    assert controller.store.metrics["structured_code_tool_error_counts"] == {
        "list_symbols": {"disabled": 1},
    }


@pytest.mark.asyncio
async def test_error_metrics_distinguish_safe_machine_reasons() -> None:
    controller, service, coder_client, _ = _controller()

    service.response = _dynamic_error_response(
        code="invalid_arguments",
        reason="max_bytes_out_of_range",
    )
    await _dispatch(controller, _request(tool="read_raw"))
    service.response = _dynamic_error_response(
        code="invalid_arguments",
        reason="end_line_out_of_range",
    )
    await _dispatch(controller, _request(tool="read_raw"))

    assert len(coder_client.responses) == 2
    assert controller.store.metrics["structured_code_error_code_counts"] == {
        "invalid_arguments": 2,
    }
    expected_details = {
        "invalid_arguments:end_line_out_of_range": 1,
        "invalid_arguments:max_bytes_out_of_range": 1,
    }
    assert controller.store.metrics["structured_code_error_detail_counts"] == expected_details
    assert controller.store.metrics["structured_code_tool_error_counts"] == {
        "read_raw": expected_details,
    }


def test_service_metric_snapshots_merge_monotonically() -> None:
    controller, _, _, _ = _controller()

    controller._record_code_context_metric(
        tool="read_raw",
        success=True,
        duration_ms=2,
        output_bytes=10,
        service_metrics={
            "calls_total": 2,
            "calls_read_raw_total": 2,
            "success_total": 2,
            "cache_hits_total": 1,
        },
        error_diagnostic=None,
    )
    controller._record_code_context_metric(
        tool="read_raw",
        success=True,
        duration_ms=1,
        output_bytes=5,
        service_metrics={
            "calls_total": 1,
            "calls_read_raw_total": 1,
            "success_total": 1,
            "untrusted_metric_name": 99,
        },
        error_diagnostic=None,
    )

    assert controller.store.metrics["structured_code_service_metrics"] == {
        "cache_hits_total": 1,
        "calls_read_raw_total": 2,
        "calls_total": 2,
        "success_total": 2,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload_text",
    [
        "not-json",
        "{}",
        json.dumps(
            {
                "ok": True,
                "error": {"code": "timeout", "message": "x", "reason": "timeout"},
            }
        ),
        json.dumps(
            {
                "ok": False,
                "error": {"code": [], "message": "x", "reason": {}},
            }
        ),
        "[" * 3000 + "0" + "]" * 3000,
    ],
)
async def test_malformed_error_payload_uses_fixed_metric_label(payload_text: str) -> None:
    controller, service, _, _ = _controller()
    service.response = {
        "success": False,
        "contentItems": [{"type": "inputText", "text": payload_text}],
    }

    await _dispatch(controller, _request(tool="read_raw"))

    assert controller.store.metrics["structured_code_calls_total"] == 1
    assert controller.store.metrics["structured_code_calls_error_total"] == 1
    assert controller.store.metrics["structured_code_error_code_counts"] == {
        "malformed_error_payload": 1,
    }
    assert controller.store.metrics["structured_code_error_detail_counts"] == {
        "malformed_error_payload": 1,
    }
    assert controller.store.metrics["structured_code_tool_error_counts"] == {
        "read_raw": {"malformed_error_payload": 1},
    }


@pytest.mark.asyncio
async def test_untrusted_error_fields_do_not_reach_metrics() -> None:
    controller, service, _, _ = _controller()
    service.response = _dynamic_error_response(
        code="attacker_code",
        reason="attacker_reason",
        message="SECRET_SENTINEL /private/path",
    )

    await _dispatch(controller, _request(tool="read_raw"))

    assert controller.store.metrics["structured_code_error_code_counts"] == {
        "unknown_error_code": 1,
    }
    assert controller.store.metrics["structured_code_error_detail_counts"] == {
        "unknown_error_code:unclassified": 1,
    }
    serialized = json.dumps(controller.store.metrics, sort_keys=True)
    assert "attacker_code" not in serialized
    assert "attacker_reason" not in serialized
    assert "SECRET_SENTINEL" not in serialized
    assert "/private/path" not in serialized


@pytest.mark.asyncio
async def test_current_origin_response_failure_queues_transport_recovery() -> None:
    controller, service, _, _ = _controller()

    class FailingClient(_Client):
        async def respond(self, request_id: int | str, response: Any) -> None:
            raise AppServerError("broken response pipe")

    controller.coder_client = FailingClient()
    controller.event_queue = asyncio.Queue()

    await _dispatch(controller, _request())

    assert service.calls == [("list_symbols", {"path": "src/widget.py"})]
    event = controller.event_queue.get_nowait()
    assert event.kind == "transport_error"
    assert event.role is ClientRole.CODER
    assert event.process_epoch == 3
    assert event.app_server_instance_id == "coder-instance"
    assert any(
        entry.get("type") == "structured_code_response_transport_error"
        for entry in controller.store.raw_logs
    )


@pytest.mark.asyncio
async def test_structured_completion_skips_generic_workspace_rescan() -> None:
    controller, _, _, _ = _controller()
    controller._current_turn_action_count = 0
    controller._append_event = lambda *_args, **_kwargs: None
    renders: list[tuple[str, str]] = []
    controller.tui = SimpleNamespace(
        render=lambda category, message: renders.append((category, message))
    )

    async def forbidden_changed_files():
        raise AssertionError("structured read completion rescanned Git workspace")

    controller.changed_files = forbidden_changed_files
    message = AppServerMessage(
        {
            "method": "item/completed",
            "params": {
                "threadId": "coder-thread",
                "turnId": "coder-turn",
                "item": {
                    "type": "dynamicToolCall",
                    "namespace": CODE_CONTEXT_NAMESPACE,
                    "tool": "read_symbol",
                    "status": "completed",
                },
            },
        },
        role=ClientRole.CODER,
        process_epoch=3,
        app_server_instance_id="coder-instance",
    )

    await controller.handle_notification(message)

    assert controller._current_turn_action_count == 1
    assert controller.store.recent_actions == [
        "dynamic tool completed: code_context/read_symbol"
    ]
    assert renders == [("TOOL", "dynamic tool completed: code_context/read_symbol")]


def test_only_known_code_context_dynamic_items_are_non_mutating() -> None:
    for tool in CODE_CONTEXT_TOOL_NAMES:
        assert not _item_may_mutate_workspace(
            {
                "type": "dynamicToolCall",
                "namespace": CODE_CONTEXT_NAMESPACE,
                "tool": tool,
            }
        )

    assert _item_may_mutate_workspace(
        {
            "type": "dynamicToolCall",
            "namespace": CODE_CONTEXT_NAMESPACE,
            "tool": "unknown_tool",
        }
    )
    assert _item_may_mutate_workspace(
        {
            "type": "dynamicToolCall",
            "namespace": "untrusted_namespace",
            "tool": "list_symbols",
        }
    )


def test_context_mode_catalogue_is_unchanged_when_dynamic_specs_coexist(tmp_path) -> None:
    expected_context_tools = (
        "ctx_execute",
        "ctx_execute_file",
        "ctx_batch_execute",
        "ctx_index",
        "ctx_search",
        "ctx_stats",
        "ctx_doctor",
        "ctx_purge",
    )

    assert ALLOWED_TOOLS == expected_context_tools
    assert ALLOWED_TOOL_SET == frozenset(expected_context_tools)
    assert CONTEXT_SERVER_NAME != CODE_CONTEXT_NAMESPACE
    assert ALLOWED_TOOL_SET.isdisjoint(CODE_CONTEXT_TOOL_NAMES)

    preview_specs = dynamic_tool_specs("preview")
    assert preview_specs
    params = coder_thread_params(tmp_path, structured_code_tools="preview")
    assert params["dynamicTools"] == preview_specs
    assert ALLOWED_TOOLS == expected_context_tools
    assert ALLOWED_TOOL_SET == frozenset(expected_context_tools)
