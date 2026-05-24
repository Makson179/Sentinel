from __future__ import annotations

from typing import Any

from supervisor.schemas import DecisionType, EventType, IPCResponse
from supervisor.hooks.common import run_hook


def format_codex_response(response: IPCResponse, event_type: EventType | None = None) -> dict[str, Any] | None:
    reason = response.payload.get("reason", "")
    if event_type == EventType.PERMISSION_REQUEST:
        if response.decision_type == DecisionType.ALLOW:
            return {"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "allow"}}}
        if response.decision_type == DecisionType.DENY:
            return {"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": {"behavior": "deny", "message": reason}}}
        return None
    if event_type == EventType.PRE_TOOL_USE:
        if response.decision_type == DecisionType.DENY:
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        return None
    if response.payload.get("additionalContext"):
        hook_event_name = event_type.value if event_type else "PostToolUse"
        return {"hookSpecificOutput": {"hookEventName": hook_event_name, "additionalContext": response.payload["additionalContext"]}}
    if event_type in {EventType.POST_TOOL_USE, EventType.STOP} and reason and response.decision_type == DecisionType.INTERVENE:
        return {"decision": "block", "reason": reason}
    if event_type in {EventType.PRE_COMPACT, EventType.POST_COMPACT} and response.decision_type == DecisionType.KILL_RESTART:
        return {"continue": False, "stopReason": reason or "Supervisor requested restart"}
    return None


if __name__ == "__main__":
    raise SystemExit(run_hook(format_codex_response))
