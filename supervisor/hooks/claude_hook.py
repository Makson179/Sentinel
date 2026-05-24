from __future__ import annotations

from supervisor.schemas import DecisionType, EventType, IPCResponse
from supervisor.hooks.common import run_hook


def format_claude_response(response: IPCResponse, _event_type: EventType | None = None) -> dict:
    reason = response.payload.get("reason", "")
    if response.decision_type == DecisionType.ALLOW:
        return {"hookSpecificOutput": {"permissionDecision": "allow", "decision": {"behavior": "allow", "reason": reason}}}
    if response.decision_type == DecisionType.DENY:
        return {"hookSpecificOutput": {"permissionDecision": "deny", "permissionDecisionReason": reason, "decision": {"behavior": "deny", "reason": reason}}}
    if response.payload.get("additionalContext"):
        return {"hookSpecificOutput": {"additionalContext": response.payload["additionalContext"]}}
    if reason and response.decision_type == DecisionType.INTERVENE:
        return {"decision": "block", "reason": reason}
    return {}


if __name__ == "__main__":
    raise SystemExit(run_hook(format_claude_response))
