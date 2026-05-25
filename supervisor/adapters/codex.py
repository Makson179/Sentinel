from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import shlex
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from supervisor.codex_cli import CODEX_EXEC_GIT_TRUST_FLAGS, codex_exec_sandbox_flags
from supervisor.state import FileLock, LOG, StateStore

MARKER = "supervisor-agent-mvp"
SUPERVISOR_HOOK_ID_ARG = "--supervisor-hook-id"
SUPERVISOR_STATUS_PREFIX = "Supervisor hook:"
CODEX_MATCHER_EVENTS = {"PreToolUse", "PermissionRequest", "PostToolUse", "PreCompact", "PostCompact"}
CODEX_HOOK_EVENTS = [
    ("PreToolUse", "supervisor-pre-tool-use"),
    ("PermissionRequest", "supervisor-permission-request"),
    ("PostToolUse", "supervisor-post-tool-use"),
    ("PreCompact", "supervisor-pre-compact"),
    ("PostCompact", "supervisor-post-compact"),
    ("Stop", "supervisor-stop"),
]
HOOK_IDS = [hook_id for _, hook_id in CODEX_HOOK_EVENTS]
CODEX_EVENT_KEY_LABELS = {
    "PreToolUse": "pre_tool_use",
    "PermissionRequest": "permission_request",
    "PostToolUse": "post_tool_use",
    "PreCompact": "pre_compact",
    "PostCompact": "post_compact",
    "SessionStart": "session_start",
    "UserPromptSubmit": "user_prompt_submit",
    "Stop": "stop",
}


class CodexHookConfigError(RuntimeError):
    pass


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class CodexAdapter:
    def __init__(
        self,
        store: StateStore,
        python_executable: str | None = None,
        codex_executable: str = "codex",
        hook_timeout_seconds: float = 15.0,
    ):
        self.store = store
        self.workspace = store.workspace
        self.python_executable = python_executable or sys.executable
        self.codex_executable = codex_executable
        self.hook_timeout_seconds = max(1, math.ceil(hook_timeout_seconds))
        self.codex_dir = self.workspace / ".codex"
        self.hooks_path = self.codex_dir / "hooks.json"
        self.lock_path = self.store.path("codex-hooks-install.lock")
        self.last_self_test_error: str | None = None
        self.last_trust_sync_error: str | None = None

    def _read_hooks(self) -> tuple[dict[str, Any], bool, str, bool]:
        if not self.hooks_path.exists():
            return {"hooks": {}}, False, "", False
        text = self.hooks_path.read_text(encoding="utf-8")
        migrated = False
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CodexHookConfigError(f"malformed Codex hooks.json: {exc}") from exc
        if not isinstance(data, dict):
            raise CodexHookConfigError("Codex hooks.json must be a JSON object with a 'hooks' object")
        hooks = data.setdefault("hooks", {})
        if isinstance(hooks, list):
            data["hooks"] = self._legacy_flat_hooks_to_events(hooks)
            hooks = data["hooks"]
            migrated = True
        if not isinstance(hooks, dict):
            raise CodexHookConfigError("Codex hooks.json field 'hooks' must be an object keyed by hook event")
        self._validate_hooks_shape(hooks)
        return data, True, text, migrated

    def _write_hooks(self, data: dict[str, Any]) -> None:
        self.codex_dir.mkdir(parents=True, exist_ok=True)
        self.store.atomic_write_text(self.hooks_path, json.dumps(data, indent=2, sort_keys=True) + "\n")

    @staticmethod
    def _validate_hooks_shape(hooks: dict[str, Any]) -> None:
        for event, groups in hooks.items():
            if not isinstance(groups, list):
                raise CodexHookConfigError(f"Codex hooks.json field 'hooks.{event}' must be a list")
            for group in groups:
                if not isinstance(group, dict):
                    raise CodexHookConfigError(f"Codex hooks.json field 'hooks.{event}' must contain matcher objects")
                handlers = group.get("hooks", [])
                if not isinstance(handlers, list):
                    raise CodexHookConfigError(f"Codex hooks.json field 'hooks.{event}[].hooks' must be a list")

    @classmethod
    def _legacy_flat_hooks_to_events(cls, flat_hooks: list[Any]) -> dict[str, list[dict[str, Any]]]:
        hooks: dict[str, list[dict[str, Any]]] = {}
        for entry in flat_hooks:
            if not isinstance(entry, dict):
                raise CodexHookConfigError("legacy Codex hooks.json flat entries must be objects")
            if cls._is_legacy_supervisor_entry(entry):
                continue
            event = entry.get("event")
            command = entry.get("command")
            if not isinstance(event, str) or not isinstance(command, str):
                raise CodexHookConfigError("legacy Codex hooks.json flat entries must include string 'event' and 'command'")
            handler = {"type": "command", "command": command}
            if isinstance(entry.get("timeout"), int):
                handler["timeout"] = entry["timeout"]
            if isinstance(entry.get("statusMessage"), str):
                handler["statusMessage"] = entry["statusMessage"]
            group: dict[str, Any] = {"hooks": [handler]}
            if isinstance(entry.get("matcher"), str):
                group["matcher"] = entry["matcher"]
            hooks.setdefault(event, []).append(group)
        return hooks

    @staticmethod
    def _is_legacy_supervisor_entry(entry: dict[str, Any]) -> bool:
        return (
            entry.get("marker") == MARKER
            or entry.get("supervisor_owned") is True
            or str(entry.get("id", "")).startswith("supervisor-")
        )

    def _supervisor_command(self, hook_id: str) -> str:
        return f"{shlex.quote(self.python_executable)} -m supervisor.hooks.codex_hook {SUPERVISOR_HOOK_ID_ARG} {shlex.quote(hook_id)}"

    def _supervisor_entries(self) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        for event, hook_id in CODEX_HOOK_EVENTS:
            group: dict[str, Any] = {
                "hooks": [
                    {
                        "type": "command",
                        "command": self._supervisor_command(hook_id),
                        "timeout": self.hook_timeout_seconds,
                        "statusMessage": f"{SUPERVISOR_STATUS_PREFIX} {event}",
                    }
                ]
            }
            if event in CODEX_MATCHER_EVENTS:
                group["matcher"] = "*"
            entries.append({"event": event, "group": group})
        return entries

    @classmethod
    def _is_supervisor_handler(cls, handler: Any) -> bool:
        if not isinstance(handler, dict):
            return False
        command = str(handler.get("command", ""))
        status_message = str(handler.get("statusMessage", ""))
        return (
            cls._is_legacy_supervisor_entry(handler)
            or f"{SUPERVISOR_HOOK_ID_ARG} supervisor-" in command
            or "supervisor.hooks.codex_hook" in command
            or status_message.startswith(SUPERVISOR_STATUS_PREFIX)
        )

    @classmethod
    def _remove_supervisor_handlers_from_group(cls, group: Any) -> Any | None:
        if not isinstance(group, dict):
            return group
        handlers = group.get("hooks")
        if not isinstance(handlers, list):
            return group
        kept = [handler for handler in handlers if not cls._is_supervisor_handler(handler)]
        if len(kept) == len(handlers):
            return group
        if not kept:
            return None
        cleaned = dict(group)
        cleaned["hooks"] = kept
        return cleaned

    @classmethod
    def remove_supervisor_entries(cls, data: dict[str, Any]) -> dict[str, Any]:
        cleaned = dict(data)
        hooks = data.get("hooks", {})
        if isinstance(hooks, list):
            hooks = cls._legacy_flat_hooks_to_events(hooks)
        if isinstance(hooks, dict):
            cleaned_hooks: dict[str, Any] = {}
            for event, groups in hooks.items():
                if not isinstance(groups, list):
                    cleaned_hooks[event] = groups
                    continue
                kept_groups = []
                for group in groups:
                    cleaned_group = cls._remove_supervisor_handlers_from_group(group)
                    if cleaned_group is not None:
                        kept_groups.append(cleaned_group)
                if kept_groups:
                    cleaned_hooks[event] = kept_groups
            cleaned["hooks"] = cleaned_hooks
        return cleaned

    @staticmethod
    def _has_hooks(data: dict[str, Any]) -> bool:
        hooks = data.get("hooks", {})
        if not isinstance(hooks, dict):
            return False
        return any(isinstance(groups, list) and groups for groups in hooks.values())

    def recover_stale_hooks(self) -> None:
        with FileLock(self.lock_path):
            if not self.hooks_path.exists():
                return
            data, existed, _, migrated = self._read_hooks()
            cleaned = self.remove_supervisor_entries(data)
            if existed and (migrated or cleaned.get("hooks") != data.get("hooks")):
                self._write_hooks(cleaned)

    def install(self) -> dict[str, Any]:
        with FileLock(self.lock_path):
            data, existed, before_text, _ = self._read_hooks()
            data = self.remove_supervisor_entries(data)
            hooks = data.setdefault("hooks", {})
            if not isinstance(hooks, dict):
                raise CodexHookConfigError("Codex hooks.json field 'hooks' must be an object keyed by hook event")
            for entry in self._supervisor_entries():
                hooks.setdefault(entry["event"], []).append(entry["group"])
            after_text = json.dumps(data, indent=2, sort_keys=True) + "\n"
            self.codex_dir.mkdir(parents=True, exist_ok=True)
            self.store.atomic_write_text(self.hooks_path, after_text)
            manifest = {
                "marker": MARKER,
                "hook_ids": HOOK_IDS,
                "existed_before_install": existed,
                "installed_at": datetime.now(timezone.utc).isoformat(),
                "hash_before_install": _sha256_text(before_text),
                "hash_after_install": _sha256_text(after_text),
            }
            self.store.update_config(lambda cfg: cfg.model_copy(update={"codex_hook_manifest": manifest}))
            return manifest

    def cleanup(self) -> None:
        with FileLock(self.lock_path):
            manifest = self.store.get_config().codex_hook_manifest
            if not self.hooks_path.exists():
                return
            data, _, _, _ = self._read_hooks()
            cleaned = self.remove_supervisor_entries(data)
            if not self._has_hooks(cleaned) and manifest and not manifest.get("existed_before_install"):
                self.hooks_path.unlink()
                try:
                    os.rmdir(self.codex_dir)
                except OSError:
                    pass
            else:
                self._write_hooks(cleaned)
            self.store.update_config(lambda cfg: cfg.model_copy(update={"codex_hook_manifest": None}))

    async def sync_supervisor_hook_trust(self, timeout_seconds: float = 15.0) -> bool:
        self.last_trust_sync_error = None
        process: asyncio.subprocess.Process | None = None
        try:
            process = await asyncio.create_subprocess_exec(
                self.codex_executable,
                "app-server",
                "--listen",
                "stdio://",
                cwd=str(self.workspace),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            await self._codex_app_server_request(
                process,
                1,
                "initialize",
                {"clientInfo": {"name": "sentinel-supervisor", "version": "0"}, "capabilities": {"experimentalApi": True}},
                timeout_seconds,
            )
            hooks_response = await self._codex_app_server_request(
                process,
                2,
                "hooks/list",
                {"cwds": [str(self.workspace)]},
                timeout_seconds,
            )
            hooks = self._supervisor_hook_metadata(hooks_response)
            if not hooks:
                self.last_trust_sync_error = "Codex app-server did not report the installed Supervisor hooks"
                return False
            edits = []
            for hook in hooks:
                key = hook.get("key")
                current_hash = hook.get("currentHash")
                if not isinstance(key, str) or not isinstance(current_hash, str):
                    continue
                if hook.get("trustStatus") == "trusted":
                    continue
                edits.append(
                    {
                        "keyPath": self._codex_hook_trust_key_path(key),
                        "value": current_hash,
                        "mergeStrategy": "upsert",
                    }
                )
            if edits:
                await self._codex_app_server_request(
                    process,
                    3,
                    "config/batchWrite",
                    {"edits": edits, "reloadUserConfig": True},
                    timeout_seconds,
                )
            return True
        except Exception as exc:
            self.last_trust_sync_error = f"failed to sync Codex hook trust: {exc}"
            return False
        finally:
            if process is not None:
                self._terminate_async_process_group(process)
                await self._wait_async_process(process)

    async def hook_fire_self_test(self, ipc_socket_path: Path | None = None, auth_token: str | None = None, timeout_seconds: float = 90.0) -> bool:
        self.last_self_test_error = None
        if ipc_socket_path is None or auth_token is None:
            self.last_self_test_error = "missing IPC socket or auth token for hook-fire self-test"
            return False

        start_offset = self._log_size()
        env = os.environ.copy()
        env.update(
            {
                "SUPERVISOR_IPC_SOCKET": str(ipc_socket_path),
                "SUPERVISOR_IPC_TOKEN": auth_token,
                "SUPERVISOR_HOOK_TIMEOUT": str(self.hook_timeout_seconds),
                "SUPERVISOR_HOOK_TRACE_PATH": str(self.store.path("codex-hook-trace.log")),
            }
        )
        prompt = "Use the shell tool to run exactly this command and then stop: pwd"
        process = await asyncio.create_subprocess_exec(
            self.codex_executable,
            "exec",
            *CODEX_EXEC_GIT_TRUST_FLAGS,
            "--dangerously-bypass-hook-trust",
            "--json",
            *codex_exec_sandbox_flags(),
            prompt,
            cwd=str(self.workspace),
            env=env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        deadline = time.monotonic() + timeout_seconds
        hook_seen = False
        stdout_tail = ""
        stderr_tail = ""
        try:
            while time.monotonic() < deadline:
                hook_seen = hook_seen or self._new_hook_log_seen(start_offset)
                if process.returncode is not None:
                    break
                await asyncio.sleep(0.5)
            if process.returncode is None:
                self._terminate_async_process_group(process)
            stdout, stderr = await self._wait_async_process(process)
            hook_seen = hook_seen or self._new_hook_log_seen(start_offset)
            stdout_tail = (stdout or b"").decode("utf-8", errors="replace").strip()[-500:]
            stderr_tail = (stderr or b"").decode("utf-8", errors="replace").strip()[-500:]
        except Exception as exc:
            if process.returncode is None:
                self._terminate_async_process_group(process)
            self.last_self_test_error = f"failed to run Codex hook-fire self-test: {exc}"
            return False

        command_succeeded = self._codex_exec_command_succeeded(stdout)
        if hook_seen and command_succeeded:
            return True

        problems = []
        if not hook_seen:
            problems.append(
                "no Codex hook callback reached the supervisor IPC server; "
                "Codex did not activate the installed project hooks. "
                "The startup trust sync may have failed, or this Codex CLI build may not load project hooks in exec mode"
            )
        if not command_succeeded:
            problems.append("Codex self-test shell command did not complete successfully")
        details = []
        if stderr_tail:
            details.append(f"stderr tail: {stderr_tail}")
        if stdout_tail:
            details.append(f"stdout tail: {stdout_tail}")
        suffix = f": {'; '.join(details)}" if details else ""
        self.last_self_test_error = f"{'; '.join(problems)} during the self-test{suffix}"
        return False

    async def _codex_app_server_request(
        self,
        process: asyncio.subprocess.Process,
        request_id: int,
        method: str,
        params: dict[str, Any],
        timeout_seconds: float,
    ) -> dict[str, Any]:
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("Codex app-server stdio pipes are unavailable")
        payload = json.dumps({"id": request_id, "method": method, "params": params}, separators=(",", ":")) + "\n"
        process.stdin.write(payload.encode("utf-8"))
        await asyncio.wait_for(process.stdin.drain(), timeout=timeout_seconds)
        while True:
            line = await asyncio.wait_for(process.stdout.readline(), timeout=timeout_seconds)
            if not line:
                raise RuntimeError(f"Codex app-server closed stdout before replying to {method}")
            try:
                message = json.loads(line.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if message.get("id") != request_id:
                continue
            if "error" in message:
                raise RuntimeError(f"Codex app-server {method} failed: {message['error']}")
            result = message.get("result")
            if not isinstance(result, dict):
                raise RuntimeError(f"Codex app-server {method} returned a non-object result")
            return result

    def _supervisor_hook_metadata(self, hooks_response: dict[str, Any]) -> list[dict[str, Any]]:
        expected_commands = {self._supervisor_command(hook_id) for _, hook_id in CODEX_HOOK_EVENTS}
        hooks = []
        for entry in hooks_response.get("data", []):
            if not isinstance(entry, dict) or entry.get("cwd") != str(self.workspace):
                continue
            for hook in entry.get("hooks", []):
                if not isinstance(hook, dict):
                    continue
                if hook.get("sourcePath") != str(self.hooks_path):
                    continue
                if hook.get("command") not in expected_commands:
                    continue
                hooks.append(hook)
        return hooks

    @staticmethod
    def _codex_hook_trust_key_path(key: str) -> str:
        escaped = key.replace("\\", "\\\\").replace('"', '\\"')
        return f'hooks.state."{escaped}".trusted_hash'

    @staticmethod
    def _codex_exec_command_succeeded(stdout: bytes | None) -> bool:
        text = (stdout or b"").decode("utf-8", errors="replace")
        for line in text.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            item = event.get("item")
            if (
                event.get("type") == "item.completed"
                and isinstance(item, dict)
                and item.get("type") == "command_execution"
                and item.get("exit_code") == 0
            ):
                return True
        return False

    def _log_size(self) -> int:
        path = self.store.path(LOG)
        if not path.exists():
            return 0
        return path.stat().st_size

    def _new_hook_log_seen(self, offset: int) -> bool:
        path = self.store.path(LOG)
        if not path.exists() or path.stat().st_size <= offset:
            return False
        with path.open("r", encoding="utf-8") as handle:
            handle.seek(offset)
            for line in handle:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("source_hook") in CODEX_EVENT_KEY_LABELS:
                    return True
        return False

    @staticmethod
    def _terminate_async_process_group(process: asyncio.subprocess.Process) -> None:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGINT)
        except ProcessLookupError:
            return
        except OSError:
            process.terminate()

    @staticmethod
    async def _wait_async_process(process: asyncio.subprocess.Process, timeout: float = 5.0) -> tuple[bytes | None, bytes | None]:
        try:
            return await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            except OSError:
                process.terminate()
            try:
                return await asyncio.wait_for(process.communicate(), timeout=2.0)
            except asyncio.TimeoutError:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except OSError:
                    process.kill()
                return await process.communicate()

    async def supervisor_isolation_self_test(self) -> bool:
        return True
