from __future__ import annotations

import json
import math
from typing import Any

from supervisor.schemas import SupervisorWakePacket


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return math.ceil(len(text) / 4)


def infer_trigger(packet: SupervisorWakePacket) -> str:
    if packet.triggering_server_request_id is not None:
        return "approval_request"
    if packet.triggering_item_id is not None:
        return "completed_action"
    summary = packet.current_summary.lower()
    if "turn completed" in summary:
        return "turn_completed"
    if "self-test" in summary or "startup" in summary:
        return "startup"
    return "supervisor_check"


def supervisor_context_event(packet: SupervisorWakePacket, *, supervisor_call_id: str) -> dict[str, Any]:
    section_text = {
        "task": packet.task_contents,
        "progress": packet.progress,
        "decisions": packet.decisions,
        "last_action": packet.last_action,
        "health": _json_text(packet.health),
        "handoff": packet.handoff or "",
        "recent_events": _json_text(packet.recent_events),
        "approval_or_action_summary": _summary_text(packet),
        "filesystem_change_summary": packet.diff_summary or "",
        "schema_and_instructions": "stateless supervisor strict JSON schema and benchmark accounting wrapper",
    }
    section_estimates = {name: estimate_tokens(text) for name, text in section_text.items()}
    return {
        "event": "supervisor_context_built",
        "supervisor_call_id": supervisor_call_id,
        "trigger": infer_trigger(packet),
        "estimated_tokens": sum(section_estimates.values()),
        "section_estimated_tokens": section_estimates,
        "truncated_sections": [],
    }


def _summary_text(packet: SupervisorWakePacket) -> str:
    parts = [packet.current_summary]
    if packet.triggering_item_id is not None:
        parts.append(f"triggering_item_id={packet.triggering_item_id}")
    if packet.triggering_server_request_id is not None:
        parts.append(f"triggering_server_request_id={packet.triggering_server_request_id}")
    return "\n".join(part for part in parts if part)


def _json_text(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)
