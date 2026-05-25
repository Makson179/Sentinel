from __future__ import annotations

import io
import json
import sys

from supervisor.hooks.codex_hook import format_codex_response
from supervisor.hooks.common import run_hook
from supervisor.schemas import DecisionType, EventType, IPCResponse


def response(decision_type: DecisionType, reason: str = "policy") -> IPCResponse:
    return IPCResponse(decision_type=decision_type, payload={"reason": reason}, sequence=1)


def test_codex_permission_request_response_matches_schema() -> None:
    assert format_codex_response(response(DecisionType.ALLOW), EventType.PERMISSION_REQUEST) == {
        "hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "allow"}}
    }
    assert format_codex_response(response(DecisionType.DENY), EventType.PERMISSION_REQUEST) == {
        "hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "deny", "message": "policy"}}
    }
    assert format_codex_response(response(DecisionType.NOOP), EventType.PERMISSION_REQUEST) is None


def test_codex_pre_tool_use_response_matches_schema() -> None:
    assert format_codex_response(response(DecisionType.ALLOW), EventType.PRE_TOOL_USE) is None
    assert format_codex_response(response(DecisionType.DENY), EventType.PRE_TOOL_USE) == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "policy",
        }
    }


def test_codex_observation_hook_responses_match_schema() -> None:
    intervention = IPCResponse(decision_type=DecisionType.INTERVENE, payload={"additionalContext": "try tests"}, sequence=1)
    assert format_codex_response(intervention, EventType.POST_TOOL_USE) == {
        "hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "try tests"}
    }
    assert format_codex_response(response(DecisionType.NOOP), EventType.POST_TOOL_USE) is None


def test_codex_stop_and_compact_responses_match_schema() -> None:
    assert format_codex_response(response(DecisionType.INTERVENE, "continue with tests"), EventType.STOP) == {
        "decision": "block",
        "reason": "continue with tests",
    }
    assert format_codex_response(response(DecisionType.NOOP), EventType.STOP) is None
    assert format_codex_response(response(DecisionType.KILL_RESTART, "restart"), EventType.PRE_COMPACT) == {
        "continue": False,
        "stopReason": "restart",
    }


def test_codex_hook_allow_writes_empty_stdout_and_trace(tmp_path, monkeypatch) -> None:
    trace_path = tmp_path / "hook-trace.log"

    def fake_send_ipc_request(*args, **kwargs):
        return response(DecisionType.ALLOW, "ok")

    monkeypatch.setattr("supervisor.hooks.common.send_ipc_request", fake_send_ipc_request)
    monkeypatch.setenv("SUPERVISOR_IPC_SOCKET", str(tmp_path / "ipc.sock"))
    monkeypatch.setenv("SUPERVISOR_IPC_TOKEN", "token")
    monkeypatch.setenv("SUPERVISOR_HOOK_TRACE_PATH", str(trace_path))
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"hook_event_name":"PreToolUse","event_id":"event-1"}'))
    stdout = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stdout)

    assert run_hook(format_codex_response) == 0

    assert stdout.getvalue() == ""
    trace_entries = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()]
    assert [entry["stage"] for entry in trace_entries] == ["received", "ipc-response", "stdout-empty"]


def test_codex_hook_ipc_setup_failure_denies_permission_and_traces_error(tmp_path, monkeypatch) -> None:
    trace_path = tmp_path / "hook-trace.log"
    monkeypatch.delenv("SUPERVISOR_IPC_SOCKET", raising=False)
    monkeypatch.delenv("SUPERVISOR_IPC_TOKEN", raising=False)
    monkeypatch.setenv("SUPERVISOR_HOOK_TRACE_PATH", str(trace_path))
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"hook_event_name":"PreToolUse","event_id":"event-1"}'))
    stdout = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stdout)

    assert run_hook(format_codex_response) == 0

    output = json.loads(stdout.getvalue())
    hook_output = output["hookSpecificOutput"]
    assert hook_output["hookEventName"] == "PreToolUse"
    assert hook_output["permissionDecision"] == "deny"
    assert "SUPERVISOR_IPC_SOCKET" in hook_output["permissionDecisionReason"]
    trace_entries = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()]
    assert [entry["stage"] for entry in trace_entries] == ["received", "error", "stdout-json"]
