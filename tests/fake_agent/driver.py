from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from supervisor.ipc import send_ipc_request
from supervisor.schemas import DecisionType, EventType, IPCRequest, IPCResponse


@dataclass
class FakeAgentHarness:
    socket_path: Path
    auth_token: str
    responses: list[IPCResponse] = field(default_factory=list)

    async def send_hook(self, event_type: EventType, payload: dict[str, Any], event_id: str) -> IPCResponse:
        request = IPCRequest(event_type=event_type, event_id=event_id, payload=payload, auth_token=self.auth_token)
        response = await asyncio.to_thread(send_ipc_request, self.socket_path, request, 10.0)
        self.responses.append(response)
        return response

    async def send_parallel(self, count: int, event_type: EventType, payload: dict[str, Any]) -> list[IPCResponse]:
        tasks = [self.send_hook(event_type, payload, f"fake-{idx}") for idx in range(count)]
        return await asyncio.gather(*tasks)

    async def run_codex_exec_tool_call(
        self,
        payload: dict[str, Any],
        event_id: str = "fake-codex-tool",
        *,
        requires_approval: bool = False,
    ) -> list[IPCResponse]:
        responses: list[IPCResponse] = []
        pre_response = await self.send_hook(EventType.PRE_TOOL_USE, payload, f"{event_id}-pre")
        responses.append(pre_response)
        if pre_response.decision_type == DecisionType.DENY:
            return responses

        if requires_approval:
            permission_response = await self.send_hook(EventType.PERMISSION_REQUEST, payload, f"{event_id}-permission")
            responses.append(permission_response)
            if permission_response.decision_type == DecisionType.DENY:
                return responses

        post_payload = dict(payload)
        post_payload.setdefault("status", "completed")
        responses.append(await self.send_hook(EventType.POST_TOOL_USE, post_payload, f"{event_id}-post"))
        return responses
