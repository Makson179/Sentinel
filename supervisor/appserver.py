from __future__ import annotations

import asyncio
import inspect
import json
import os
import shutil
import signal
import tempfile
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

CODEX_NO_WEB_SEARCH_CONFIG_FLAGS = ["-c", 'web_search="disabled"']

APP_SERVER_PARENT_CONTEXT_ENV_VARS = {
    "CODEX_INTERNAL_ORIGINATOR_OVERRIDE",
    "CODEX_NETWORK_ALLOW_LOCAL_BINDING",
    "CODEX_NETWORK_POLICY_VIOLATION",
    "CODEX_NETWORK_PROXY_ACTIVE",
    "CODEX_NETWORK_PROXY_ATTRIBUTION",
    "CODEX_NETWORK_PROXY_BROKERED_CREDENTIALS",
    "CODEX_NETWORK_PROXY_CREDENTIAL_BROKER_ACTIVE",
    "CODEX_PERMISSION_PROFILE",
    "CODEX_SANDBOX",
    "CODEX_SANDBOX_NETWORK_DISABLED",
    "CODEX_SNAPSHOT_OVERRIDE",
    "CODEX_THREAD_ID",
}

# Build role-process environments from a narrow parent allow-list.  Provider
# credentials/proxy settings may be needed by Codex itself, but loader hooks,
# SSH/cloud/package credentials, and arbitrary user variables must not cross
# the app-server boundary.  Context MCP/hooks receive a separate clean
# environment and never inherit even the provider entries below.
APP_SERVER_ALLOWED_PARENT_ENV_VARS = frozenset(
    {
        "PATH",
        "HOME",
        "CODEX_HOME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "TERM",
        "COLORTERM",
        "NO_COLOR",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "OPENAI_API_KEY",
        "CODEX_API_KEY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    }
)


class ClientRole(str, Enum):
    CODER = "coder"
    SUPERVISOR = "supervisor"


class AppServerError(RuntimeError):
    role: ClientRole | None
    process_epoch: int | None
    app_server_instance_id: str | None

    def __init__(
        self,
        *args: object,
        role: ClientRole | None = None,
        process_epoch: int | None = None,
        app_server_instance_id: str | None = None,
    ) -> None:
        super().__init__(*args)
        self.role = role
        self.process_epoch = process_epoch
        self.app_server_instance_id = app_server_instance_id

    def with_origin(
        self,
        *,
        role: ClientRole,
        process_epoch: int,
        app_server_instance_id: str | None,
    ) -> AppServerError:
        self.role = role
        self.process_epoch = process_epoch
        self.app_server_instance_id = app_server_instance_id
        return self


class AppServerProtocolError(AppServerError):
    pass


class AppServerTimeoutError(AppServerError):
    pass


def require_json_rpc_id(value: Any, *, field: str = "JSON-RPC id") -> int | str:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise AppServerProtocolError(f"{field} must be an integer or string")
    if isinstance(value, str) and not value:
        raise AppServerProtocolError(f"{field} must not be empty")
    return value


def _validate_app_server_frame(raw: Any) -> dict[str, Any]:
    """Apply the pinned app-server frame union before any field is consumed."""

    if not isinstance(raw, dict):
        raise AppServerProtocolError("app-server frame must be a JSON object")
    keys = frozenset(raw)
    if "method" in raw:
        if "id" in raw:
            # Server requests do not carry the notification emission stamp in
            # the pinned 0.146.0 schema.
            expected = {"method", "params", "id"}
        else:
            # ServerNotification.json defines one optional top-level field in
            # addition to every method-specific {method, params} branch.
            expected = {"method", "params", "emittedAtMs"} if "emittedAtMs" in raw else {
                "method",
                "params",
            }
        if keys != expected:
            raise AppServerProtocolError("app-server request/notification fields mismatch")
        method = raw["method"]
        params = raw["params"]
        try:
            method_size = len(method.encode("utf-8")) if isinstance(method, str) else 0
        except UnicodeError as exc:
            raise AppServerProtocolError("app-server method must be valid UTF-8") from exc
        if not isinstance(method, str) or not method or method_size > 256:
            raise AppServerProtocolError("app-server method must be a bounded non-empty UTF-8 string")
        if not isinstance(params, dict):
            raise AppServerProtocolError("app-server params must be an object")
        if "emittedAtMs" in raw:
            emitted_at_ms = raw["emittedAtMs"]
            if (
                isinstance(emitted_at_ms, bool)
                or not isinstance(emitted_at_ms, int)
                or emitted_at_ms < 0
            ):
                raise AppServerProtocolError(
                    "app-server notification emittedAtMs must be a non-negative integer"
                )
        if "id" in raw:
            require_json_rpc_id(raw["id"])
        return raw
    response_shapes = ({"id", "result"}, {"id", "error"})
    if keys not in response_shapes:
        raise AppServerProtocolError("app-server response fields mismatch")
    require_json_rpc_id(raw["id"])
    return raw


@dataclass(frozen=True)
class AppServerMessage:
    raw: dict[str, Any]
    role: ClientRole | None = None
    process_epoch: int = 0
    app_server_instance_id: str | None = None

    @property
    def request_id(self) -> int | str | None:
        value = self.raw.get("id")
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            return None
        return value

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


@dataclass(frozen=True)
class PendingRequestKey:
    role: ClientRole
    process_epoch: int
    request_id: int | str

    def __post_init__(self) -> None:
        if not isinstance(self.role, ClientRole):
            raise AppServerProtocolError("pending request role must be a ClientRole")
        if (
            isinstance(self.process_epoch, bool)
            or not isinstance(self.process_epoch, int)
            or self.process_epoch < 0
        ):
            raise AppServerProtocolError("pending request process_epoch must be an integer >= 0")
        require_json_rpc_id(self.request_id, field="pending request JSON-RPC id")


NotificationHandler = Callable[[AppServerMessage], Awaitable[None] | None]
ServerRequestHandler = Callable[[AppServerMessage], Awaitable[None] | None]
TransportErrorHandler = Callable[[BaseException], Awaitable[None] | None]


class AppServerProcessLauncher(Protocol):
    """Native role-sandbox boundary used before app-server code executes."""

    def __call__(
        self,
        *,
        command: tuple[str, ...],
        cwd: Path | None,
        environment: Mapping[str, str],
        role: ClientRole,
        stdout_limit: int,
    ) -> Awaitable[asyncio.subprocess.Process] | asyncio.subprocess.Process: ...

APP_SERVER_STDOUT_LIMIT = 16 * 1024 * 1024
APP_SERVER_STDERR_LIMIT = 64 * 1024
APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS = 30.0
APP_SERVER_PREFLIGHT_RPC_TIMEOUT_SECONDS = 30.0
APP_SERVER_RESPOND_TIMEOUT_SECONDS = 15.0
APP_SERVER_CLEANUP_RPC_TIMEOUT_SECONDS = 10.0
APP_SERVER_CODER_RPC_TIMEOUT_SECONDS = 3600.0


class AppServerClient:
    def __init__(
        self,
        *,
        command: list[str] | None = None,
        role: ClientRole | str = ClientRole.SUPERVISOR,
        codex_home: Path | None = None,
        launch_cwd: Path | None = None,
        environment_overrides: Mapping[str, str | None] | None = None,
        process_launcher: AppServerProcessLauncher | None = None,
        cwd: Path | None = None,
        notification_handler: NotificationHandler | None = None,
        server_request_handler: ServerRequestHandler | None = None,
        transport_error_handler: TransportErrorHandler | None = None,
        stdout_limit: int = APP_SERVER_STDOUT_LIMIT,
        stderr_limit: int = APP_SERVER_STDERR_LIMIT,
    ):
        if launch_cwd is not None and cwd is not None and Path(launch_cwd) != Path(cwd):
            raise ValueError("launch_cwd and the compatibility cwd alias disagree")
        if stdout_limit <= 0:
            raise ValueError("stdout_limit must be positive")
        if stderr_limit < 0:
            raise ValueError("stderr_limit cannot be negative")
        self.command = command or ["codex", "app-server", *CODEX_NO_WEB_SEARCH_CONFIG_FLAGS, "--listen", "stdio://"]
        self.role = ClientRole(role)
        self.codex_home = Path(codex_home).resolve(strict=False) if codex_home is not None else None
        selected_cwd = launch_cwd if launch_cwd is not None else cwd
        self.launch_cwd = Path(selected_cwd).resolve(strict=False) if selected_cwd is not None else None
        # Kept as a read-only compatibility alias for callers predating launch_cwd.
        self.cwd = self.launch_cwd
        self.environment_overrides = dict(environment_overrides or {})
        self.process_launcher = process_launcher
        self.notification_handler = notification_handler
        self.server_request_handler = server_request_handler
        self.transport_error_handler = transport_error_handler
        self.stdout_limit = stdout_limit
        self.stderr_limit = stderr_limit
        self.process: asyncio.subprocess.Process | None = None
        self.process_epoch = 0
        self.app_server_instance_id: str | None = None
        self._reserved_process_epoch: int | None = None
        self._reserved_app_server_instance_id: str | None = None
        self._active_process_epoch: int | None = None
        self._active_app_server_instance_id: str | None = None
        self._process_group_id: int | None = None
        self._next_id = 1
        self._pending: dict[PendingRequestKey | int | str, asyncio.Future[dict[str, Any]]] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._waiters: list[
            tuple[int, Callable[[AppServerMessage], bool], asyncio.Future[AppServerMessage]]
        ] = []
        self.incoming: asyncio.Queue[AppServerMessage] = asyncio.Queue()
        self.reader_error: BaseException | None = None
        self._stderr_capture = bytearray()
        self.stderr_total_bytes = 0
        self.stderr_truncated = False
        self._lifecycle_lock = asyncio.Lock()

    @property
    def active_process_epoch(self) -> int | None:
        return self._active_process_epoch

    @property
    def stderr_output(self) -> bytes:
        return bytes(self._stderr_capture)

    def reserve_next_identity(self) -> tuple[int, str]:
        """Reserve the origin used by the next process start.

        Context Mode has to bind its broker lease before either app-server is
        allowed to execute discovery/startup code.  Reserving an identity keeps
        that ordering possible without weakening the late-event checks: the
        reservation is consumed only by ``start`` and a live process can never
        be re-reserved.
        """

        if self.process is not None and self.process.returncode is None:
            raise AppServerError(
                "cannot reserve an app-server identity while the process is active",
                role=self.role,
                process_epoch=self.process_epoch,
                app_server_instance_id=self.app_server_instance_id,
            )
        if self._reserved_process_epoch is None:
            self._reserved_process_epoch = self.process_epoch + 1
            self._reserved_app_server_instance_id = str(uuid.uuid4())
        assert self._reserved_app_server_instance_id is not None
        return self._reserved_process_epoch, self._reserved_app_server_instance_id

    def clear_reserved_identity(self) -> None:
        """Discard a not-yet-started reservation during startup rollback."""

        if self.process is not None and self.process.returncode is None:
            raise AppServerError("cannot clear the identity of an active app-server", role=self.role)
        self._reserved_process_epoch = None
        self._reserved_app_server_instance_id = None

    @property
    def stderr_text(self) -> str:
        return self.stderr_output.decode("utf-8", errors="replace")

    async def start(self) -> None:
        async with self._lifecycle_lock:
            if (
                self.process is not None
                and self.process.returncode is None
                and self._active_process_epoch is not None
            ):
                return
            if self.process is not None or self._reader_task is not None or self._stderr_task is not None:
                await self._stop_locked()

            self._reset_transport_state(reset_stderr=True)
            next_epoch = self._reserved_process_epoch or (self.process_epoch + 1)
            instance_id = self._reserved_app_server_instance_id or str(uuid.uuid4())
            if next_epoch != self.process_epoch + 1:
                raise AppServerError(
                    "reserved app-server process epoch is stale",
                    role=self.role,
                    process_epoch=next_epoch,
                    app_server_instance_id=instance_id,
                )
            env = _app_server_environment(overrides=self.environment_overrides)
            if self.codex_home is not None:
                env["CODEX_HOME"] = str(self.codex_home)
            env["BELLO_APP_SERVER_ROLE"] = self.role.value
            env["BELLO_APP_SERVER_INSTANCE_ID"] = instance_id
            env["BELLO_APP_SERVER_PROCESS_EPOCH"] = str(next_epoch)

            if self.process_launcher is None:
                process = await asyncio.create_subprocess_exec(
                    *self.command,
                    cwd=str(self.launch_cwd) if self.launch_cwd else None,
                    env=env,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    limit=self.stdout_limit,
                    start_new_session=True,
                )
            else:
                # asyncio's subprocess default is only 64 KiB. Keep the
                # configured JSON-line bound intact across the native launch
                # boundary instead of silently substituting that default.
                launched = self.process_launcher(
                    command=tuple(self.command),
                    cwd=self.launch_cwd,
                    environment=env,
                    role=self.role,
                    stdout_limit=self.stdout_limit,
                )
                process = await launched if inspect.isawaitable(launched) else launched
                if (
                    not isinstance(process, asyncio.subprocess.Process)
                    or process.stdin is None
                    or process.stdout is None
                    or process.stderr is None
                ):
                    raise AppServerError(
                        "native role sandbox launcher returned an invalid app-server transport",
                        role=self.role,
                        process_epoch=next_epoch,
                        app_server_instance_id=instance_id,
                    )
            self.process = process
            self.process_epoch = next_epoch
            self.app_server_instance_id = instance_id
            self._reserved_process_epoch = None
            self._reserved_app_server_instance_id = None
            self._active_process_epoch = next_epoch
            self._active_app_server_instance_id = instance_id
            self._process_group_id = process.pid
            self._reader_task = asyncio.create_task(self._read_loop(process, next_epoch, instance_id))
            self._stderr_task = asyncio.create_task(self._drain_stderr(process, next_epoch))

    async def stop(self) -> None:
        async with self._lifecycle_lock:
            await self._stop_locked()

    async def _stop_locked(self) -> None:
        process = self.process
        process_group_id = self._process_group_id
        reader_task = self._reader_task
        stderr_task = self._stderr_task

        # Invalidate the origin before signalling. Readers continue draining pipes,
        # but neither they nor a delayed callback may touch the next epoch.
        self._active_process_epoch = None
        self._active_app_server_instance_id = None
        stop_error = AppServerError(
            "app-server process stopped",
            role=self.role,
            process_epoch=self.process_epoch,
            app_server_instance_id=self.app_server_instance_id,
        )
        self._fail_all_pending(stop_error)
        self._fail_all_waiters(stop_error)

        try:
            if process is not None:
                self._terminate_process_group(signal.SIGTERM, process=process, process_group_id=process_group_id)
                try:
                    await asyncio.wait_for(process.wait(), timeout=3)
                except asyncio.TimeoutError:
                    self._terminate_process_group(signal.SIGKILL, process=process, process_group_id=process_group_id)
                    await process.wait()
                else:
                    # The session leader can exit before a descendant. Do not leave
                    # such descendants alive after a nominally successful wait.
                    self._terminate_process_group(signal.SIGKILL, process=process, process_group_id=process_group_id)
        finally:
            for task in (reader_task, stderr_task):
                if task is not None and not task.done():
                    task.cancel()
            tasks = [task for task in (reader_task, stderr_task) if task is not None]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self.process = None
            self._process_group_id = None
            self._reader_task = None
            self._stderr_task = None
            self._reset_transport_state(reset_stderr=False)

    def _terminate_process_group(
        self,
        sig: int,
        *,
        process: asyncio.subprocess.Process | None = None,
        process_group_id: int | None = None,
    ) -> None:
        process = process or self.process
        if process is None:
            return
        pgid = process_group_id if process_group_id is not None else self._process_group_id
        try:
            os.killpg(pgid if pgid is not None else os.getpgid(process.pid), sig)
        except ProcessLookupError:
            return
        except Exception:
            if process.returncode is None:
                if sig == signal.SIGTERM:
                    process.terminate()
                else:
                    process.kill()

    async def initialize(self, *, timeout: float = APP_SERVER_PREFLIGHT_RPC_TIMEOUT_SECONDS) -> dict[str, Any]:
        result = await self.request(
            "initialize",
            {
                "clientInfo": {"name": "bello", "title": "Bello", "version": "0.2.0"},
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
        process, process_epoch, instance_id = self._transport_snapshot()
        request_id = self._next_id
        self._next_id += 1
        payload: dict[str, Any] = {"id": request_id, "method": method}
        if params is not None:
            payload["params"] = params
        future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        pending_key = PendingRequestKey(self.role, process_epoch, request_id)
        self._pending[pending_key] = future
        try:
            await self._send_with_timeout(
                payload,
                timeout,
                stage=f"app-server RPC {method} send",
                process=process,
                process_epoch=process_epoch,
                app_server_instance_id=instance_id,
            )
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise AppServerTimeoutError(
                f"app-server RPC {method} response timed out after {timeout:g}s",
                role=self.role,
                process_epoch=process_epoch,
                app_server_instance_id=instance_id,
            ) from exc
        finally:
            self._pending.pop(pending_key, None)

    async def notify(
        self,
        method: str,
        params: Any = None,
        *,
        timeout: float = APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
    ) -> None:
        await self._ensure_started()
        process, process_epoch, instance_id = self._transport_snapshot()
        payload: dict[str, Any] = {"method": method}
        if params is not None:
            payload["params"] = params
        await self._send_with_timeout(
            payload,
            timeout,
            stage=f"app-server notification {method} send",
            process=process,
            process_epoch=process_epoch,
            app_server_instance_id=instance_id,
        )

    async def respond(
        self,
        request_id: int | str,
        result: Any = None,
        error: Any = None,
        *,
        timeout: float = APP_SERVER_RESPOND_TIMEOUT_SECONDS,
        process_epoch: int | None = None,
        app_server_instance_id: str | None = None,
    ) -> None:
        # A response belongs to a request on one concrete transport.  It must
        # never auto-start a replacement process: doing so could create a new
        # epoch before the controller has committed its binding transition.
        process, active_epoch, active_instance_id = self._transport_snapshot()
        expected_epoch = active_epoch if process_epoch is None else process_epoch
        expected_instance_id = active_instance_id if app_server_instance_id is None else app_server_instance_id
        self._require_active_origin(expected_epoch, expected_instance_id, process)
        payload: dict[str, Any] = {"id": request_id}
        if error is not None:
            payload["error"] = error
        else:
            payload["result"] = result if result is not None else {}
        await self._send_with_timeout(
            payload,
            timeout,
            stage=f"app-server respond {request_id} send",
            process=process,
            process_epoch=expected_epoch,
            app_server_instance_id=expected_instance_id,
        )

    async def wait_for_notification(
        self,
        predicate: Callable[[AppServerMessage], bool],
        *,
        timeout: float = APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
    ) -> AppServerMessage:
        await self._ensure_started()
        _, process_epoch, instance_id = self._transport_snapshot()
        future: asyncio.Future[AppServerMessage] = asyncio.get_running_loop().create_future()
        waiter = (process_epoch, predicate, future)
        self._waiters.append(waiter)
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise AppServerTimeoutError(
                f"app-server notification wait timed out after {timeout:g}s",
                role=self.role,
                process_epoch=process_epoch,
                app_server_instance_id=instance_id,
            ) from exc
        finally:
            self._waiters = [candidate for candidate in self._waiters if candidate is not waiter]

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

    async def thread_compact_start(
        self,
        thread_id: str,
        *,
        timeout: float = APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        return await self.request("thread/compact/start", {"threadId": thread_id}, timeout=timeout)

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
        # A subprocess can remain writable after its stdout reader has died.
        # Reusing it would send an RPC whose response can never be dispatched.
        if self.reader_error is not None:
            raise self.reader_error
        if self.process is None or (
            hasattr(self.process, "returncode") and self.process.returncode is not None
        ):
            await self.start()
        if self.reader_error is not None:
            raise self.reader_error
        if self.process is None or self.process.stdin is None:
            raise AppServerError("app-server process is not writable")

    def _transport_snapshot(self) -> tuple[asyncio.subprocess.Process, int, str | None]:
        process = self.process
        if (
            process is None
            or process.stdin is None
            or (hasattr(process, "returncode") and process.returncode is not None)
        ):
            raise AppServerError("app-server process is not writable")
        process_epoch = self._active_process_epoch
        if process_epoch is None:
            # Compatibility for tests and callers which install a transport
            # directly instead of using start(). Such a transport is epoch zero.
            process_epoch = self.process_epoch
        return process, process_epoch, self._active_app_server_instance_id or self.app_server_instance_id

    def _require_active_origin(
        self,
        process_epoch: int,
        app_server_instance_id: str | None,
        process: asyncio.subprocess.Process,
    ) -> None:
        active_epoch = self._active_process_epoch
        active_instance_id = self._active_app_server_instance_id
        direct_transport = active_epoch is None and self.process_epoch == process_epoch == 0
        if (
            process is not self.process
            or (not direct_transport and process_epoch != active_epoch)
            or (
                not direct_transport
                and app_server_instance_id is not None
                and app_server_instance_id != active_instance_id
            )
        ):
            raise AppServerError(
                "app-server transport origin is no longer active",
                role=self.role,
                process_epoch=process_epoch,
                app_server_instance_id=app_server_instance_id,
            )

    async def _send(
        self,
        payload: dict[str, Any],
        *,
        process: asyncio.subprocess.Process | None = None,
        process_epoch: int | None = None,
        app_server_instance_id: str | None = None,
    ) -> None:
        if process is None or process_epoch is None:
            process, process_epoch, current_instance_id = self._transport_snapshot()
            if app_server_instance_id is None:
                app_server_instance_id = current_instance_id
        self._require_active_origin(process_epoch, app_server_instance_id, process)
        if process.stdin is None:
            raise AppServerError("app-server process is not writable")
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
        process.stdin.write(data)
        await process.stdin.drain()

    async def _send_with_timeout(
        self,
        payload: dict[str, Any],
        timeout: float,
        *,
        stage: str,
        process: asyncio.subprocess.Process | None = None,
        process_epoch: int | None = None,
        app_server_instance_id: str | None = None,
    ) -> None:
        try:
            await asyncio.wait_for(
                self._send(
                    payload,
                    process=process,
                    process_epoch=process_epoch,
                    app_server_instance_id=app_server_instance_id,
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError as exc:
            raise AppServerTimeoutError(
                f"{stage} timed out after {timeout:g}s",
                role=self.role,
                process_epoch=process_epoch,
                app_server_instance_id=app_server_instance_id,
            ) from exc

    async def _read_loop(
        self,
        process: asyncio.subprocess.Process | None = None,
        process_epoch: int | None = None,
        app_server_instance_id: str | None = None,
    ) -> None:
        process = process or self.process
        assert process is not None
        if process_epoch is None:
            process_epoch = self._active_process_epoch
            if process_epoch is None:
                process_epoch = self.process_epoch
        if app_server_instance_id is None:
            app_server_instance_id = self._active_app_server_instance_id or self.app_server_instance_id
        error: BaseException | None = None
        try:
            if process.stdout is None:
                raise AppServerError("app-server process has no stdout")
            while True:
                line = await process.stdout.readline()
                if not line:
                    error = AppServerError("app-server stream closed")
                    error = self._error_with_origin(error, process_epoch, app_server_instance_id)
                    if self._origin_is_active(process, process_epoch, app_server_instance_id):
                        self.reader_error = error
                        await self._notify_transport_error(error)
                    break
                try:
                    raw = json.loads(line.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise AppServerProtocolError(f"invalid JSON from app-server: {exc}") from exc
                raw = _validate_app_server_frame(raw)
                message = AppServerMessage(
                    raw,
                    role=self.role,
                    process_epoch=process_epoch,
                    app_server_instance_id=app_server_instance_id,
                )
                await self._dispatch(
                    message,
                    process=process,
                    process_epoch=process_epoch,
                    app_server_instance_id=app_server_instance_id,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error = self._normalize_reader_error(exc)
            error = self._error_with_origin(error, process_epoch, app_server_instance_id)
            if self._origin_is_active(process, process_epoch, app_server_instance_id):
                self.reader_error = error
                await self._notify_transport_error(error)
        finally:
            pending_error = error or self._error_with_origin(
                AppServerError("app-server stream closed"),
                process_epoch,
                app_server_instance_id,
            )
            if self._origin_is_active(process, process_epoch, app_server_instance_id):
                self._fail_pending_for_epoch(process_epoch, pending_error)

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

    async def _drain_stderr(
        self,
        process: asyncio.subprocess.Process | None = None,
        process_epoch: int | None = None,
    ) -> None:
        process = process or self.process
        if process is None or process.stderr is None:
            return
        if process_epoch is None:
            process_epoch = self._active_process_epoch
            if process_epoch is None:
                process_epoch = self.process_epoch
        while True:
            chunk = await process.stderr.read(8192)
            if not chunk:
                return
            if not self._origin_is_active(process, process_epoch, self._active_app_server_instance_id):
                continue
            self.stderr_total_bytes += len(chunk)
            remaining = self.stderr_limit - len(self._stderr_capture)
            if remaining > 0:
                self._stderr_capture.extend(chunk[:remaining])
            if len(chunk) > max(remaining, 0):
                self.stderr_truncated = True

    async def _dispatch(
        self,
        message: AppServerMessage,
        *,
        process: asyncio.subprocess.Process | None = None,
        process_epoch: int | None = None,
        app_server_instance_id: str | None = None,
    ) -> None:
        process = process or self.process
        if process is None:
            return
        if process_epoch is None:
            process_epoch = message.process_epoch if message.role is not None else self.process_epoch
        if app_server_instance_id is None:
            app_server_instance_id = message.app_server_instance_id
        if not self._origin_is_active(process, process_epoch, app_server_instance_id):
            return

        if message.is_response:
            request_id = message.request_id
            if request_id is None:
                return
            key = PendingRequestKey(self.role, process_epoch, request_id)
            future = self._pending.get(key)
            if future is None:
                # Compatibility for tests/callers which populated the old map.
                future = self._pending.get(request_id)
            if future and not future.done():
                if "error" in message.raw:
                    future.set_exception(
                        AppServerError(
                            str(message.raw["error"]),
                            role=self.role,
                            process_epoch=process_epoch,
                            app_server_instance_id=app_server_instance_id,
                        )
                    )
                else:
                    result = message.raw.get("result")
                    future.set_result(result if isinstance(result, dict) else {"value": result})
            return

        await self.incoming.put(message)
        for waiter_epoch, predicate, future in list(self._waiters):
            if waiter_epoch == process_epoch and not future.done() and predicate(message):
                future.set_result(message)
        if message.is_server_request and self.server_request_handler:
            result = self.server_request_handler(message)
            if asyncio.iscoroutine(result):
                await result
        elif message.is_notification and self.notification_handler:
            result = self.notification_handler(message)
            if asyncio.iscoroutine(result):
                await result

    def _origin_is_active(
        self,
        process: asyncio.subprocess.Process,
        process_epoch: int,
        app_server_instance_id: str | None,
    ) -> bool:
        if process is not self.process:
            return False
        if self._active_process_epoch is None:
            return self.process_epoch == process_epoch == 0
        if process_epoch != self._active_process_epoch:
            return False
        return (
            app_server_instance_id is None
            or app_server_instance_id == self._active_app_server_instance_id
        )

    def _error_with_origin(
        self,
        error: AppServerError,
        process_epoch: int,
        app_server_instance_id: str | None,
    ) -> AppServerError:
        return error.with_origin(
            role=self.role,
            process_epoch=process_epoch,
            app_server_instance_id=app_server_instance_id,
        )

    def _fail_pending_for_epoch(self, process_epoch: int, error: BaseException) -> None:
        for key, future in list(self._pending.items()):
            if isinstance(key, PendingRequestKey) and key.process_epoch != process_epoch:
                continue
            if not future.done():
                future.set_exception(error)

    def _fail_all_pending(self, error: BaseException) -> None:
        for future in list(self._pending.values()):
            if not future.done():
                future.set_exception(error)

    def _fail_all_waiters(self, error: BaseException) -> None:
        for _, _, future in list(self._waiters):
            if not future.done():
                future.set_exception(error)

    def _reset_transport_state(self, *, reset_stderr: bool) -> None:
        self._pending.clear()
        self._waiters.clear()
        self._next_id = 1
        self.incoming = asyncio.Queue()
        self.reader_error = None
        if reset_stderr:
            self._stderr_capture.clear()
            self.stderr_total_bytes = 0
            self.stderr_truncated = False


def text_input(text: str) -> dict[str, Any]:
    return {"type": "text", "text": text, "text_elements": []}


def _app_server_environment(
    environ: Mapping[str, str] | None = None,
    *,
    overrides: Mapping[str, str | None] | None = None,
) -> dict[str, str]:
    source = os.environ if environ is None else environ
    env = {
        name: value
        for name, value in source.items()
        if name in APP_SERVER_ALLOWED_PARENT_ENV_VARS
        and isinstance(value, str)
        and "\x00" not in name + value
    }
    for name in APP_SERVER_PARENT_CONTEXT_ENV_VARS:
        env.pop(name, None)
    for name, value in (overrides or {}).items():
        if not isinstance(name, str) or not name or "\x00" in name:
            raise AppServerProtocolError("app-server environment override key is invalid")
        if value is None:
            env.pop(name, None)
        else:
            if not isinstance(value, str) or "\x00" in value:
                raise AppServerProtocolError(
                    f"app-server environment override {name!r} is invalid"
                )
            env[name] = value
    return env


def _codex_home_from_environment(environ: Mapping[str, str]) -> Path:
    configured = environ.get("CODEX_HOME")
    if configured:
        return Path(configured).expanduser().resolve(strict=False)
    home = Path(environ.get("HOME") or Path.home()).expanduser()
    return (home / ".codex").resolve(strict=False)


def _create_isolated_codex_home(source: Path) -> Path:
    source = source.resolve(strict=True)
    isolated = Path(tempfile.mkdtemp(prefix="bello-codex-home-")).resolve()
    try:
        for child in source.iterdir():
            if child.name == "rules":
                continue
            os.symlink(str(child), isolated / child.name, target_is_directory=child.is_dir())
        (isolated / "rules").mkdir(mode=0o700)
        return isolated
    except BaseException:
        shutil.rmtree(isolated, ignore_errors=True)
        raise


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
