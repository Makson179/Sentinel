from __future__ import annotations

from supervisor.hooks.common import request_from_vendor
from supervisor.schemas import EventType


def test_request_from_vendor_promotes_codex_tool_input_fields() -> None:
    request = request_from_vendor(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "sed -n '1,220p' TASK.md"},
        },
        "token",
    )

    assert request.event_type == EventType.PRE_TOOL_USE
    assert request.payload["tool_name"] == "Bash"
    assert request.payload["command"] == "sed -n '1,220p' TASK.md"
    assert request.payload["tool_input"]["command"] == "sed -n '1,220p' TASK.md"
