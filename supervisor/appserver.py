from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class AppServerError(RuntimeError):
    pass


class AppServerProtocolError(AppServerError):
    pass


@dataclass(frozen=True)
class AppServerMessage:
    raw: dict[str, Any]

    @property
    def request_id(self) -> int | str | None:
        return self.raw.get("id")

    @property
    def method(self) -> str | None:
        value = self.raw.get("method")
        return value if isinstance(value, str) else None

    @property
    def params(self) -> dict[str, Any]:
        value = self.raw.get("params")
        return value if isinstance(value, dict) else {}

    @property
    def is_response(self) -> bool:
        return "id" in self.raw and ("result" in self.raw or "error" in self.raw) and "method" not in self.raw

    @property
    def is_server_request(self) -> bool:
        return "id" in self.raw and self.method is not None

    @property
    def is_notification(self) -> bool:
        return "id" not in self.raw and self.method is not None


NotificationHandler = Callable[[AppServerMessage], Awaitable[None] | None]
ServerRequestHandler = Callable[[AppServerMessage], Awaitable[None] | None]


class AppServerClient:
    def __init__(
        self,
        *,
        command: list[str] | None = None,
        cwd: Path | None = None,
        notification_handler: NotificationHandler | None = None,
        server_request_handler: ServerRequestHandler | None = None,
    ):
        self.command = command or ["codex", "app-server", "--listen", "stdio://"]
        self.cwd = cwd
        self.notification_handler = notification_handler
        self.server_request_handler = server_request_handler
        self.process: asyncio.subprocess.Process | None = None
        self._next_id = 1
        self._pending: dict[int | str, asyncio.Future[dict[str, Any]]] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._waiters: list[tuple[Callable[[AppServerMessage], bool], asyncio.Future[AppServerMessage]]] = []
        self.incoming: asyncio.Queue[AppServerMessage] = asyncio.Queue()

    async def start(self) -> None:
        if self.process is not None:
            return
        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            cwd=str(self.cwd) if self.cwd else None,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._reader_task = asyncio.create_task(self._read_loop())
        self._stderr_task = asyncio.create_task(self._drain_stderr())

    async def stop(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None
        if self._stderr_task:
            self._stderr_task.cancel()
            try:
                await self._stderr_task
            except asyncio.CancelledError:
                pass
            self._stderr_task = None
        if self.process:
            if self.process.returncode is None:
                self.process.terminate()
                try:
                    await asyncio.wait_for(self.process.wait(), timeout=3)
                except asyncio.TimeoutError:
                    self.process.kill()
                    await self.process.wait()
            self.process = None

    async def initialize(self) -> dict[str, Any]:
        result = await self.request(
            "initialize",
            {
                "clientInfo": {"name": "sentinel", "title": "Sentinel", "version": "0.1.0"},
                "capabilities": {"experimentalApi": True, "requestAttestation": False},
            },
        )
        await self.notify("initialized")
        return result

    async def request(self, method: str, params: Any = None, *, timeout: float | None = None) -> dict[str, Any]:
        await self._ensure_started()
        request_id = self._next_id
        self._next_id += 1
        payload: dict[str, Any] = {"id": request_id, "method": method}
        if params is not None:
            payload["params"] = params
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        await self._send(payload)
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        finally:
            self._pending.pop(request_id, None)

    async def notify(self, method: str, params: Any = None) -> None:
        await self._ensure_started()
        payload: dict[str, Any] = {"method": method}
        if params is not None:
            payload["params"] = params
        await self._send(payload)

    async def respond(self, request_id: int | str, result: Any = None, error: Any = None) -> None:
        await self._ensure_started()
        payload: dict[str, Any] = {"id": request_id}
        if error is not None:
            payload["error"] = error
        else:
            payload["result"] = result if result is not None else {}
        await self._send(payload)

    async def wait_for_notification(
        self,
        predicate: Callable[[AppServerMessage], bool],
        *,
        timeout: float | None = None,
    ) -> AppServerMessage:
        future: asyncio.Future[AppServerMessage] = asyncio.get_running_loop().create_future()
        self._waiters.append((predicate, future))
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        finally:
            self._waiters = [(pred, fut) for pred, fut in self._waiters if fut is not future]

    async def config_requirements_read(self) -> dict[str, Any]:
        return await self.request("configRequirements/read")

    async def account_read(self) -> dict[str, Any]:
        return await self.request("account/read", {"refreshToken": False})

    async def account_rate_limits_read(self) -> dict[str, Any]:
        return await self.request("account/rateLimits/read")

    async def model_list(self) -> dict[str, Any]:
        return await self.request("model/list", {})

    async def thread_start(self, params: dict[str, Any]) -> dict[str, Any]:
        return await self.request("thread/start", params)

    async def thread_resume(self, params: dict[str, Any]) -> dict[str, Any]:
        return await self.request("thread/resume", params)

    async def thread_read(self, thread_id: str, *, include_turns: bool = True) -> dict[str, Any]:
        return await self.request("thread/read", {"threadId": thread_id, "includeTurns": include_turns})

    async def thread_turns_list(self, thread_id: str, *, limit: int = 10, items_view: str = "full") -> dict[str, Any]:
        return await self.request(
            "thread/turns/list",
            {"threadId": thread_id, "limit": limit, "itemsView": items_view},
        )

    async def thread_archive(self, thread_id: str) -> dict[str, Any]:
        return await self.request("thread/archive", {"threadId": thread_id})

    async def thread_unsubscribe(self, thread_id: str) -> dict[str, Any]:
        return await self.request("thread/unsubscribe", {"threadId": thread_id})

    async def turn_start(self, params: dict[str, Any]) -> dict[str, Any]:
        return await self.request("turn/start", params)

    async def turn_steer(self, thread_id: str, expected_turn_id: str, text: str) -> dict[str, Any]:
        return await self.request(
            "turn/steer",
            {"threadId": thread_id, "expectedTurnId": expected_turn_id, "input": [text_input(text)]},
        )

    async def turn_interrupt(self, thread_id: str, turn_id: str) -> dict[str, Any]:
        return await self.request("turn/interrupt", {"threadId": thread_id, "turnId": turn_id})

    async def _ensure_started(self) -> None:
        if self.process is None:
            await self.start()
        if self.process is None or self.process.stdin is None:
            raise AppServerError("app-server process is not writable")

    async def _send(self, payload: dict[str, Any]) -> None:
        if self.process is None or self.process.stdin is None:
            raise AppServerError("app-server process is not writable")
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
        self.process.stdin.write(data)
        await self.process.stdin.drain()

    async def _read_loop(self) -> None:
        assert self.process is not None
        if self.process.stdout is None:
            raise AppServerError("app-server process has no stdout")
        try:
            while True:
                line = await self.process.stdout.readline()
                if not line:
                    break
                try:
                    raw = json.loads(line.decode("utf-8"))
                except json.JSONDecodeError as exc:
                    raise AppServerProtocolError(f"invalid JSON from app-server: {exc}") from exc
                if not isinstance(raw, dict):
                    continue
                message = AppServerMessage(raw)
                await self._dispatch(message)
        finally:
            for future in list(self._pending.values()):
                if not future.done():
                    future.set_exception(AppServerError("app-server stream closed"))

    async def _drain_stderr(self) -> None:
        if self.process is None or self.process.stderr is None:
            return
        while True:
            line = await self.process.stderr.readline()
            if not line:
                return

    async def _dispatch(self, message: AppServerMessage) -> None:
        if message.is_response:
            future = self._pending.get(message.request_id)
            if future and not future.done():
                if "error" in message.raw:
                    future.set_exception(AppServerError(str(message.raw["error"])))
                else:
                    result = message.raw.get("result")
                    future.set_result(result if isinstance(result, dict) else {"value": result})
            return

        await self.incoming.put(message)
        for predicate, future in list(self._waiters):
            if not future.done() and predicate(message):
                future.set_result(message)
        if message.is_server_request and self.server_request_handler:
            result = self.server_request_handler(message)
            if asyncio.iscoroutine(result):
                await result
        elif message.is_notification and self.notification_handler:
            result = self.notification_handler(message)
            if asyncio.iscoroutine(result):
                await result


def text_input(text: str) -> dict[str, Any]:
    return {"type": "text", "text": text, "text_elements": []}


def last_agent_message_text(turn: dict[str, Any]) -> str | None:
    items = turn.get("items")
    if not isinstance(items, list):
        return None
    for item in reversed(items):
        if isinstance(item, dict) and item.get("type") == "agentMessage" and isinstance(item.get("text"), str):
            return item["text"]
    return None
