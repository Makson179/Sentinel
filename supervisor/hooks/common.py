from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from supervisor.ipc import send_ipc_request
from supervisor.schemas import DecisionType, EventType, IPCRequest, IPCResponse


def read_vendor_event() -> dict[str, Any]:
    raw = sys.stdin.read().strip()
    if not raw:
        return {}
    return json.loads(raw)


def infer_event_type(data: dict[str, Any]) -> EventType:
    value = data.get("event_type") or data.get("hook_event_name") or data.get("hook") or data.get("event")
    if isinstance(value, str):
        try:
            return EventType(value)
        except ValueError:
            pass
    return EventType.POST_TOOL_USE


def normalize_vendor_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    tool_input = normalized.get("tool_input")
    if isinstance(tool_input, dict):
        for key, value in tool_input.items():
            normalized.setdefault(key, value)
    return normalized


def request_from_vendor(data: dict[str, Any], token: str) -> IPCRequest:
    event_type = infer_event_type(data)
    event_id = str(data.get("event_id") or data.get("id") or uuid4())
    raw_payload = data.get("payload") if isinstance(data.get("payload"), dict) else data
    payload = normalize_vendor_payload(raw_payload)
    return IPCRequest(
        event_type=event_type,
        event_id=event_id,
        payload=payload,
        timestamp=datetime.now(timezone.utc),
        auth_token=token,
        source_hook=event_type.value,
    )


def fallback(event_type: EventType, reason: str) -> IPCResponse:
    if event_type in {EventType.PERMISSION_REQUEST, EventType.PRE_TOOL_USE}:
        decision = DecisionType.DENY
    else:
        decision = DecisionType.NOOP
    return IPCResponse(decision_type=decision, payload={"reason": reason}, sequence=0)


def _hook_trace_path() -> Path | None:
    explicit = os.environ.get("SUPERVISOR_HOOK_TRACE_PATH")
    if explicit:
        return Path(explicit)
    return None


def trace_hook(stage: str, **fields: Any) -> None:
    path = _hook_trace_path()
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "argv": sys.argv[1:],
            **fields,
        }
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
    except OSError:
        pass


def run_hook(formatter) -> int:
    event_type: EventType | None = None
    response: IPCResponse
    try:
        data = read_vendor_event()
        event_type = infer_event_type(data)
        trace_hook("received", event_type=event_type.value, vendor_event_id=data.get("event_id") or data.get("id"))
        socket_path = os.environ["SUPERVISOR_IPC_SOCKET"]
        token = os.environ["SUPERVISOR_IPC_TOKEN"]
        timeout = float(os.environ.get("SUPERVISOR_HOOK_TIMEOUT", "10"))
        response = send_ipc_request(socket_path, request_from_vendor(data, token), timeout_seconds=timeout)
        trace_hook(
            "ipc-response",
            event_type=event_type.value,
            decision_type=response.decision_type.value,
            sequence=response.sequence,
            reason=response.payload.get("reason"),
        )
    except Exception as exc:
        event_type = event_type or EventType.PERMISSION_REQUEST
        trace_hook("error", event_type=event_type.value, error=str(exc))
        response = fallback(event_type, str(exc))
    output = formatter(response, event_type)
    if output is not None:
        print(json.dumps(output, sort_keys=True))
        trace_hook("stdout-json", event_type=event_type.value if event_type else None, output=output, exit_code=0)
    else:
        trace_hook("stdout-empty", event_type=event_type.value if event_type else None, exit_code=0)
    return 0
