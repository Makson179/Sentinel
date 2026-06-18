from __future__ import annotations

import asyncio
import json
import os
import signal
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CODEX_NO_WEB_SEARCH_CONFIG_FLAGS = ["-c", 'web_search="disabled"']


class AppServerError(RuntimeError):
    pass


class AppServerProtocolError(AppServerError):
    pass


class AppServerTimeoutError(AppServerError):
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
TransportErrorHandler = Callable[[BaseException], Awaitable[None] | None]

APP_SERVER_STDOUT_LIMIT = 16 * 1024 * 1024
APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS = 30.0
APP_SERVER_PREFLIGHT_RPC_TIMEOUT_SECONDS = 30.0
APP_SERVER_RESPOND_TIMEOUT_SECONDS = 15.0
APP_SERVER_CLEANUP_RPC_TIMEOUT_SECONDS = 10.0
APP_SERVER_CODER_RPC_TIMEOUT_SECONDS = 1800.0


class AppServerClient:
    def __init__(
        self,
        *,
        command: list[str] | None = None,
        cwd: Path | None = None,
        notification_handler: NotificationHandler | None = None,
        server_request_handler: ServerRequestHandler | None = None,
        transport_error_handler: TransportErrorHandler | None = None,
        stdout_limit: int = APP_SERVER_STDOUT_LIMIT,
    ):
        self.command = command or ["codex", "app-server", *CODEX_NO_WEB_SEARCH_CONFIG_FLAGS, "--listen", "stdio://"]
        self.cwd = cwd
        self.notification_handler = notification_handler
        self.server_request_handler = server_request_handler
        self.transport_error_handler = transport_error_handler
        self.stdout_limit = stdout_limit
        self.process: asyncio.subprocess.Process | None = None
        self._next_id = 1
        self._pending: dict[int | str, asyncio.Future[dict[str, Any]]] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._waiters: list[tuple[Callable[[AppServerMessage], bool], asyncio.Future[AppServerMessage]]] = []
        self.incoming: asyncio.Queue[AppServerMessage] = asyncio.Queue()
        self.reader_error: BaseException | None = None

    async def start(self) -> None:
        if self.process is not None:
            return
        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            cwd=str(self.cwd) if self.cwd else None,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=self.stdout_limit,
            start_new_session=True,
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
                self._terminate_process_group(signal.SIGTERM)
                try:
                    await asyncio.wait_for(self.process.wait(), timeout=3)
                except asyncio.TimeoutError:
                    self._terminate_process_group(signal.SIGKILL)
                    await self.process.wait()
            self.process = None

    def _terminate_process_group(self, sig: int) -> None:
        process = self.process
        if process is None or process.returncode is not None:
            return
        try:
            os.killpg(os.getpgid(process.pid), sig)
        except ProcessLookupError:
            return
        except Exception:
            if sig == signal.SIGTERM:
                process.terminate()
            else:
                process.kill()

    async def initialize(self, *, timeout: float = APP_SERVER_PREFLIGHT_RPC_TIMEOUT_SECONDS) -> dict[str, Any]:
        result = await self.request(
            "initialize",
            {
                "clientInfo": {"name": "sentinel", "title": "Sentinel", "version": "0.1.0"},
                "capabilities": {"experimentalApi": True, "requestAttestation": False},
            },
            timeout=timeout,
        )
        await self.notify("initialized", timeout=APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS)
        return result

    async def request(
        self,
        method: str,
        params: Any = None,
        *,
        timeout: float = APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        await self._ensure_started()
        request_id = self._next_id
        self._next_id += 1
        payload: dict[str, Any] = {"id": request_id, "method": method}
        if params is not None:
            payload["params"] = params
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        try:
            await self._send_with_timeout(payload, timeout, stage=f"app-server RPC {method} send")
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise AppServerTimeoutError(f"app-server RPC {method} response timed out after {timeout:g}s") from exc
        finally:
            self._pending.pop(request_id, None)

    async def notify(
        self,
        method: str,
        params: Any = None,
        *,
        timeout: float = APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
    ) -> None:
        await self._ensure_started()
        payload: dict[str, Any] = {"method": method}
        if params is not None:
            payload["params"] = params
        await self._send_with_timeout(payload, timeout, stage=f"app-server notification {method} send")

    async def respond(
        self,
        request_id: int | str,
        result: Any = None,
        error: Any = None,
        *,
        timeout: float = APP_SERVER_RESPOND_TIMEOUT_SECONDS,
    ) -> None:
        await self._ensure_started()
        payload: dict[str, Any] = {"id": request_id}
        if error is not None:
            payload["error"] = error
        else:
            payload["result"] = result if result is not None else {}
        await self._send_with_timeout(payload, timeout, stage=f"app-server respond {request_id} send")

    async def wait_for_notification(
        self,
        predicate: Callable[[AppServerMessage], bool],
        *,
        timeout: float = APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
    ) -> AppServerMessage:
        future: asyncio.Future[AppServerMessage] = asyncio.get_running_loop().create_future()
        self._waiters.append((predicate, future))
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise AppServerTimeoutError(f"app-server notification wait timed out after {timeout:g}s") from exc
        finally:
            self._waiters = [(pred, fut) for pred, fut in self._waiters if fut is not future]

    async def config_requirements_read(self, *, timeout: float = APP_SERVER_PREFLIGHT_RPC_TIMEOUT_SECONDS) -> dict[str, Any]:
        return await self.request("configRequirements/read", timeout=timeout)

    async def account_read(self, *, timeout: float = APP_SERVER_PREFLIGHT_RPC_TIMEOUT_SECONDS) -> dict[str, Any]:
        return await self.request("account/read", {"refreshToken": False}, timeout=timeout)

    async def account_rate_limits_read(self, *, timeout: float = APP_SERVER_PREFLIGHT_RPC_TIMEOUT_SECONDS) -> dict[str, Any]:
        return await self.request("account/rateLimits/read", timeout=timeout)

    async def model_list(self, *, timeout: float = APP_SERVER_PREFLIGHT_RPC_TIMEOUT_SECONDS) -> dict[str, Any]:
        return await self.request("model/list", {}, timeout=timeout)

    async def thread_start(
        self,
        params: dict[str, Any],
        *,
        timeout: float = APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        return await self.request("thread/start", params, timeout=timeout)

    async def thread_resume(
        self,
        params: dict[str, Any],
        *,
        timeout: float = APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        return await self.request("thread/resume", params, timeout=timeout)

    async def thread_read(
        self,
        thread_id: str,
        *,
        include_turns: bool = True,
        timeout: float = APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        return await self.request("thread/read", {"threadId": thread_id, "includeTurns": include_turns}, timeout=timeout)

    async def thread_turns_list(
        self,
        thread_id: str,
        *,
        limit: int = 10,
        items_view: str = "full",
        timeout: float = APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        return await self.request(
            "thread/turns/list",
            {"threadId": thread_id, "limit": limit, "itemsView": items_view},
            timeout=timeout,
        )

    async def thread_archive(
        self,
        thread_id: str,
        *,
        timeout: float = APP_SERVER_CLEANUP_RPC_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        return await self.request("thread/archive", {"threadId": thread_id}, timeout=timeout)

    async def thread_unsubscribe(
        self,
        thread_id: str,
        *,
        timeout: float = APP_SERVER_CLEANUP_RPC_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        return await self.request("thread/unsubscribe", {"threadId": thread_id}, timeout=timeout)

    async def turn_start(
        self,
        params: dict[str, Any],
        *,
        timeout: float = APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        return await self.request("turn/start", params, timeout=timeout)

    async def turn_steer(
        self,
        thread_id: str,
        expected_turn_id: str,
        text: str,
        *,
        timeout: float = APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        return await self.request(
            "turn/steer",
            {"threadId": thread_id, "expectedTurnId": expected_turn_id, "input": [text_input(text)]},
            timeout=timeout,
        )

    async def turn_interrupt(
        self,
        thread_id: str,
        turn_id: str,
        *,
        timeout: float = APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        return await self.request("turn/interrupt", {"threadId": thread_id, "turnId": turn_id}, timeout=timeout)

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

    async def _send_with_timeout(self, payload: dict[str, Any], timeout: float, *, stage: str) -> None:
        try:
            await asyncio.wait_for(self._send(payload), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise AppServerTimeoutError(f"{stage} timed out after {timeout:g}s") from exc

    async def _read_loop(self) -> None:
        assert self.process is not None
        error: BaseException | None = None
        try:
            if self.process.stdout is None:
                raise AppServerError("app-server process has no stdout")
            while True:
                line = await self.process.stdout.readline()
                if not line:
                    error = AppServerError("app-server stream closed")
                    self.reader_error = error
                    await self._notify_transport_error(error)
                    break
                try:
                    raw = json.loads(line.decode("utf-8"))
                except json.JSONDecodeError as exc:
                    raise AppServerProtocolError(f"invalid JSON from app-server: {exc}") from exc
                if not isinstance(raw, dict):
                    continue
                message = AppServerMessage(raw)
                await self._dispatch(message)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error = self._normalize_reader_error(exc)
            self.reader_error = error
            await self._notify_transport_error(error)
        finally:
            pending_error = error or AppServerError("app-server stream closed")
            for future in list(self._pending.values()):
                if not future.done():
                    future.set_exception(pending_error)

    def _normalize_reader_error(self, exc: Exception) -> AppServerError:
        if isinstance(exc, AppServerError):
            return exc
        if isinstance(exc, ValueError) and "chunk is longer than limit" in str(exc):
            return AppServerProtocolError(
                f"app-server stdout line exceeded stream limit ({self.stdout_limit} bytes): {exc}"
            )
        return AppServerError(f"app-server stream reader failed: {exc}")

    async def _notify_transport_error(self, error: BaseException) -> None:
        if self.transport_error_handler is None:
            return
        try:
            result = self.transport_error_handler(error)
            if asyncio.iscoroutine(result):
                await result
        except Exception:
            pass

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
        text = _agent_message_text_from_item(item)
        if text is not None:
            return text
    return None


def _agent_message_text_from_item(item: Any) -> str | None:
    if not isinstance(item, dict):
        return None
    item_type = item.get("type")
    if item_type == "agentMessage" and isinstance(item.get("text"), str):
        return item["text"]
    if item_type in {"message", "assistantMessage"} or item.get("role") in {"assistant", "agent"}:
        text = _message_content_text(item.get("content"))
        if text is not None:
            return text
        if isinstance(item.get("text"), str):
            return item["text"]
        if isinstance(item.get("message"), str):
            return item["message"]
    payload = item.get("payload")
    if isinstance(payload, dict):
        return _agent_message_text_from_item(payload)
    return None


def _message_content_text(content: Any) -> str | None:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return None
    parts: list[str] = []
    for part in content:
        if isinstance(part, str):
            parts.append(part)
        elif isinstance(part, dict) and isinstance(part.get("text"), str):
            parts.append(part["text"])
    text = "".join(parts).strip()
    return text or None
