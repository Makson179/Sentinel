from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Awaitable, Callable

from supervisor.schemas import DecisionType, IPCRequest, IPCResponse

Handler = Callable[[IPCRequest], Awaitable[IPCResponse]]


class IPCServer:
    def __init__(self, socket_path: Path, auth_token: str, handler: Handler):
        self.socket_path = socket_path
        self.auth_token = auth_token
        self.handler = handler
        self._server: asyncio.AbstractServer | None = None
        self._sequence = 0
        self._sequence_lock = asyncio.Lock()

    async def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            self.socket_path.unlink()
        self._server = await asyncio.start_unix_server(self._handle_client, path=str(self.socket_path))
        os.chmod(self.socket_path, 0o600)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self.socket_path.exists():
            self.socket_path.unlink()

    async def next_sequence(self) -> int:
        async with self._sequence_lock:
            self._sequence += 1
            return self._sequence

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sequence = await self.next_sequence()
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=5.0)
            request = IPCRequest.model_validate(json.loads(raw.decode("utf-8")))
            if request.auth_token != self.auth_token:
                response = IPCResponse(
                    decision_type=DecisionType.DENY,
                    payload={"reason": "invalid IPC auth token"},
                    sequence=sequence,
                )
            else:
                response = await self.handler_with_sequence(request, sequence)
        except Exception as exc:
            response = IPCResponse(
                decision_type=DecisionType.DENY,
                payload={"reason": f"IPC failure: {exc}"},
                sequence=sequence,
            )
        writer.write(response.model_dump_json().encode("utf-8") + b"\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def handler_with_sequence(self, request: IPCRequest, sequence: int) -> IPCResponse:
        response = await self.handler(request)
        return response.model_copy(update={"sequence": sequence})

