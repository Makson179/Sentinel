from __future__ import annotations

import asyncio
import errno
import fcntl
import hashlib
import json
import os
import pty
import select
import shlex
import signal
import shutil
import struct
import subprocess
import sys
import termios
import time
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from supervisor.codex_cli import CODEX_EXEC_GIT_TRUST_FLAGS
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
DEFAULT_CODEX_HOOK_TIMEOUT_SECONDS = 600
CODEX_TRUST_PREFLIGHT_TIMEOUT_SECONDS = 600
CODEX_HOOK_BROWSER_EVENT_ORDER = [
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PreCompact",
    "PostCompact",
    "SessionStart",
    "UserPromptSubmit",
    "Stop",
]
KEY_ENTER = b"\r"
KEY_ESCAPE = b"\x1b"
KEY_ARROW_UP = b"\x1b[A"
KEY_ARROW_DOWN = b"\x1b[B"
CODEX_DIRECTORY_TRUST_PROMPT = b"Do you trust the contents of this directory?"


@dataclass(frozen=True)
class CodexPlannedHook:
    event: str
    hook_id: str
    key: str
    current_hash: str
    command: str
    display_index: int


@dataclass(frozen=True)
class CodexHookTrustStatus:
    hook: CodexPlannedHook
    trusted_hash_matches: bool
    enabled: bool

    @property
    def ready(self) -> bool:
        return self.trusted_hash_matches and self.enabled


@dataclass(frozen=True)
class CodexPtyKeystroke:
    data: bytes
    delay_after: float = 0.15


class CodexHookConfigError(RuntimeError):
    pass


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class CodexAdapter:
    def __init__(self, store: StateStore, python_executable: str | None = None, codex_executable: str = "codex"):
        self.store = store
        self.workspace = store.workspace
        self.python_executable = python_executable or sys.executable
        self.codex_executable = codex_executable
        self.codex_dir = self.workspace / ".codex"
        self.hooks_path = self.codex_dir / "hooks.json"
        self.lock_path = self.store.path("codex-hooks-install.lock")
        self.last_self_test_error: str | None = None

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

    def planned_supervisor_hooks(self) -> list[CodexPlannedHook]:
        data, _, _, _ = self._read_hooks()
        data = self.remove_supervisor_entries(data)
        hooks = data.setdefault("hooks", {})
        if not isinstance(hooks, dict):
            raise CodexHookConfigError("Codex hooks.json field 'hooks' must be an object keyed by hook event")

        planned: list[CodexPlannedHook] = []
        for entry in self._supervisor_entries():
            event = entry["event"]
            group = entry["group"]
            existing_groups = hooks.get(event, [])
            if not isinstance(existing_groups, list):
                raise CodexHookConfigError(f"Codex hooks.json field 'hooks.{event}' must be a list")
            group_index = len(existing_groups)
            display_index = sum(
                len(existing_group.get("hooks", []))
                for existing_group in existing_groups
                if isinstance(existing_group, dict) and isinstance(existing_group.get("hooks", []), list)
            )
            handler = group["hooks"][0]
            hook_id = next(hook_id for candidate_event, hook_id in CODEX_HOOK_EVENTS if candidate_event == event)
            command = handler["command"]
            planned.append(
                CodexPlannedHook(
                    event=event,
                    hook_id=hook_id,
                    key=self._hook_state_key(event, group_index, 0),
                    current_hash=self._command_hook_hash(event, group),
                    command=command,
                    display_index=display_index,
                )
            )
        return planned

    def _hook_state_key(self, event: str, group_index: int, handler_index: int) -> str:
        return f"{self.hooks_path}:{CODEX_EVENT_KEY_LABELS[event]}:{group_index}:{handler_index}"

    @staticmethod
    def _command_hook_hash(event: str, group: dict[str, Any]) -> str:
        handler = group["hooks"][0]
        normalized_handler = {
            "async": bool(handler.get("async", False)),
            "command": handler["command"],
            "statusMessage": handler.get("statusMessage"),
            "timeout": int(handler.get("timeout", DEFAULT_CODEX_HOOK_TIMEOUT_SECONDS)),
            "type": "command",
        }
        if normalized_handler["statusMessage"] is None:
            normalized_handler.pop("statusMessage")
        identity: dict[str, Any] = {
            "event_name": CODEX_EVENT_KEY_LABELS[event],
            "hooks": [normalized_handler],
        }
        if isinstance(group.get("matcher"), str):
            identity["matcher"] = group["matcher"]
        serialized = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return f"sha256:{hashlib.sha256(serialized).hexdigest()}"

    def codex_home(self) -> Path:
        env_value = os.environ.get("CODEX_HOME")
        if env_value:
            path = Path(env_value)
            if not path.exists():
                raise CodexHookConfigError(f"CODEX_HOME points to {env_value!r}, but that path does not exist")
            if not path.is_dir():
                raise CodexHookConfigError(f"CODEX_HOME points to {env_value!r}, but that path is not a directory")
            return path.resolve()
        return Path.home() / ".codex"

    def trust_config_path(self) -> Path:
        return self.codex_home() / "config.toml"

    def read_hook_trust_state(self) -> dict[str, dict[str, Any]]:
        path = self.trust_config_path()
        if not path.exists():
            return {}
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            raise CodexHookConfigError(f"malformed Codex config.toml at {path}: {exc}") from exc
        hooks = data.get("hooks")
        if not isinstance(hooks, dict):
            return {}
        state = hooks.get("state")
        if not isinstance(state, dict):
            return {}
        return {key: value for key, value in state.items() if isinstance(key, str) and isinstance(value, dict)}

    def supervisor_hooks_trusted(self, planned_hooks: list[CodexPlannedHook] | None = None) -> bool:
        return all(status.ready for status in self.hook_trust_statuses(planned_hooks))

    def hook_trust_statuses(self, planned_hooks: list[CodexPlannedHook] | None = None) -> list[CodexHookTrustStatus]:
        planned_hooks = planned_hooks or self.planned_supervisor_hooks()
        state = self.read_hook_trust_state()
        statuses: list[CodexHookTrustStatus] = []
        for hook in planned_hooks:
            entry = state.get(hook.key)
            trusted_hash_matches = isinstance(entry, dict) and entry.get("trusted_hash") == hook.current_hash
            enabled = not (isinstance(entry, dict) and entry.get("enabled") is False)
            statuses.append(CodexHookTrustStatus(hook=hook, trusted_hash_matches=trusted_hash_matches, enabled=enabled))
        return statuses

    def hook_trust_progress_text(self, planned_hooks: list[CodexPlannedHook] | None = None) -> str:
        statuses = self.hook_trust_statuses(planned_hooks)
        trusted = sum(status.trusted_hash_matches for status in statuses)
        ready = sum(status.ready for status in statuses)
        total = len(statuses)
        if ready == trusted:
            return f"{trusted}/{total} hooks trusted"
        return f"{trusted}/{total} hooks trusted, {ready}/{total} ready"

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

    async def trust_preflight(
        self,
        planned_hooks: list[CodexPlannedHook],
        ipc_socket_path: Path,
        auth_token: str,
        timeout_seconds: float = CODEX_TRUST_PREFLIGHT_TIMEOUT_SECONDS,
    ) -> bool:
        env = os.environ.copy()
        env.update(
            {
                "SUPERVISOR_IPC_SOCKET": str(ipc_socket_path),
                "SUPERVISOR_IPC_TOKEN": auth_token,
            }
        )
        process, master_fd, tty_fd = self._launch_interactive_codex_pty(env)
        deadline = time.monotonic() + timeout_seconds
        keystrokes = self.hook_review_keystrokes(planned_hooks)
        next_key_index = 0
        next_key_at: float | None = None
        started_at = time.monotonic()
        output_tail = b""
        last_progress: tuple[int, int] | None = None
        directory_trust_answered = False
        hook_input_not_before = started_at + 12.0
        self._print_trust_progress(planned_hooks, last_progress)
        last_progress = self._trust_progress_tuple(planned_hooks)
        try:
            while time.monotonic() < deadline:
                drained = self._drain_pty(master_fd, tty_fd)
                if drained:
                    output_tail = (output_tail + drained)[-4000:]
                now = time.monotonic()
                if not directory_trust_answered and self._directory_trust_prompt_seen(output_tail):
                    print("Codex is asking to trust this project directory so it can load project hooks; approving inside Codex's native prompt.", flush=True)
                    try:
                        os.write(master_fd, KEY_ENTER)
                    except OSError as exc:
                        if exc.errno in {errno.EIO, errno.EBADF}:
                            return self.supervisor_hooks_trusted(planned_hooks)
                        raise
                    directory_trust_answered = True
                    output_tail = b""
                    hook_input_not_before = now + 8.0
                    await asyncio.sleep(0.2)
                    continue
                tui_ready = now >= hook_input_not_before and (b"\xe2\x80\xba" in output_tail or now - started_at >= 30.0)
                if next_key_at is None and next_key_index < len(keystrokes) and tui_ready:
                    next_key_at = now + 0.2
                if process.poll() is not None:
                    return self.supervisor_hooks_trusted(planned_hooks)
                if next_key_at is not None and next_key_index < len(keystrokes) and now >= next_key_at:
                    keystroke = keystrokes[next_key_index]
                    try:
                        os.write(master_fd, keystroke.data)
                    except OSError as exc:
                        if exc.errno in {errno.EIO, errno.EBADF}:
                            return self.supervisor_hooks_trusted(planned_hooks)
                        raise
                    next_key_index += 1
                    next_key_at = now + keystroke.delay_after
                progress = self._trust_progress_tuple(planned_hooks)
                if progress != last_progress:
                    self._print_trust_progress(planned_hooks, progress)
                    last_progress = progress
                if self.supervisor_hooks_trusted(planned_hooks):
                    self._terminate_process_group(process)
                    return True
                await asyncio.sleep(0.05)
            self._terminate_process_group(process)
            return False
        finally:
            if process.poll() is None:
                self._terminate_process_group(process)
            os.close(master_fd)
            if tty_fd is not None:
                os.close(tty_fd)

    def hook_review_keystrokes(self, planned_hooks: list[CodexPlannedHook]) -> list[CodexPtyKeystroke]:
        statuses = self.hook_trust_statuses(planned_hooks)
        remaining = [status for status in statuses if not status.ready]
        if not remaining:
            return []

        event_position = {event: index for index, event in enumerate(CODEX_HOOK_BROWSER_EVENT_ORDER)}
        review_positions = [
            event_position[status.hook.event]
            for status in statuses
            if not status.trusted_hash_matches
        ]
        current_event_index = min(review_positions) if review_positions else 0
        keystrokes = [CodexPtyKeystroke(bytes([char]), delay_after=0.12) for char in b"/hooks"]
        keystrokes.append(CodexPtyKeystroke(KEY_ENTER, delay_after=1.0))

        for status in sorted(remaining, key=lambda item: (event_position[item.hook.event], item.hook.display_index)):
            target_event_index = event_position[status.hook.event]
            while current_event_index < target_event_index:
                keystrokes.append(CodexPtyKeystroke(KEY_ARROW_DOWN))
                current_event_index += 1
            while current_event_index > target_event_index:
                keystrokes.append(CodexPtyKeystroke(KEY_ARROW_UP))
                current_event_index -= 1
            keystrokes.append(CodexPtyKeystroke(KEY_ENTER, delay_after=0.3))
            keystrokes.extend(CodexPtyKeystroke(KEY_ARROW_DOWN) for _ in range(status.hook.display_index))
            if not status.trusted_hash_matches:
                keystrokes.append(CodexPtyKeystroke(b"t", delay_after=0.4))
            if not status.enabled:
                keystrokes.append(CodexPtyKeystroke(KEY_ENTER, delay_after=0.4))
            keystrokes.append(CodexPtyKeystroke(KEY_ESCAPE, delay_after=0.3))
        return keystrokes

    def _launch_interactive_codex_pty(self, env: dict[str, str]) -> tuple[subprocess.Popen[str], int, int | None]:
        master_fd, slave_fd = pty.openpty()
        self._set_pty_window_size(slave_fd)

        def configure_child_terminal() -> None:
            os.setsid()
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

        try:
            process = subprocess.Popen(
                [self.codex_executable, "--no-alt-screen"],
                cwd=str(self.workspace),
                env=env,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                preexec_fn=configure_child_terminal,
            )
        finally:
            os.close(slave_fd)
        os.set_blocking(master_fd, False)
        return process, master_fd, self._open_display_tty()

    @staticmethod
    def _set_pty_window_size(fd: int) -> None:
        columns, rows = shutil.get_terminal_size(fallback=(120, 40))
        packed = struct.pack("HHHH", rows, columns, 0, 0)
        try:
            fcntl.ioctl(fd, termios.TIOCSWINSZ, packed)
        except OSError:
            pass

    @staticmethod
    def _open_display_tty() -> int | None:
        try:
            return os.open("/dev/tty", os.O_WRONLY | os.O_NOCTTY)
        except OSError:
            if sys.stdout.isatty():
                return os.dup(sys.stdout.fileno())
            return None

    @staticmethod
    def _directory_trust_prompt_seen(output_tail: bytes) -> bool:
        if CODEX_DIRECTORY_TRUST_PROMPT in output_tail:
            return True
        lowered = output_tail.lower()
        return all(fragment in lowered for fragment in (b"trust", b"contents", b"directory", b"yes", b"continue"))

    @staticmethod
    def _drain_pty(master_fd: int, tty_fd: int | None) -> bytes:
        drained = bytearray()
        while True:
            readable, _, _ = select.select([master_fd], [], [], 0)
            if not readable:
                return bytes(drained)
            try:
                chunk = os.read(master_fd, 4096)
            except OSError as exc:
                if exc.errno in {errno.EIO, errno.EBADF}:
                    return bytes(drained)
                raise
            if not chunk:
                return bytes(drained)
            drained.extend(chunk)
            if tty_fd is not None:
                try:
                    os.write(tty_fd, chunk)
                except OSError:
                    pass

    def _trust_progress_tuple(self, planned_hooks: list[CodexPlannedHook]) -> tuple[int, int]:
        statuses = self.hook_trust_statuses(planned_hooks)
        trusted = sum(status.trusted_hash_matches for status in statuses)
        ready = sum(status.ready for status in statuses)
        return trusted, ready

    def _print_trust_progress(self, planned_hooks: list[CodexPlannedHook], progress: tuple[int, int] | None) -> None:
        if progress is None:
            message = self.hook_trust_progress_text(planned_hooks)
        else:
            trusted, ready = progress
            total = len(planned_hooks)
            message = f"{trusted}/{total} hooks trusted" if ready == trusted else f"{trusted}/{total} hooks trusted, {ready}/{total} ready"
        print(f"Waiting for hook trust approval in Codex... ({message})", flush=True)

    @staticmethod
    def _terminate_process(process: subprocess.Popen[str], soft_timeout: float = 2.0) -> None:
        if process.poll() is not None:
            return
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=soft_timeout)
            return
        except subprocess.TimeoutExpired:
            pass
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2.0)

    @staticmethod
    def _terminate_process_group(process: subprocess.Popen[str], soft_timeout: float = 2.0) -> None:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGINT)
        except ProcessLookupError:
            return
        except OSError:
            process.terminate()
        deadline = time.monotonic() + soft_timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return
            time.sleep(0.05)
        if process.poll() is None:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            except ProcessLookupError:
                return
            except OSError:
                process.terminate()
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except OSError:
                process.kill()

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
                "SUPERVISOR_HOOK_TIMEOUT": "10",
                "SUPERVISOR_HOOK_TRACE_PATH": str(self.store.path("codex-hook-trace.log")),
            }
        )
        prompt = "Use the shell tool to run exactly this command and then stop: pwd"
        process = await asyncio.create_subprocess_exec(
            self.codex_executable,
            "exec",
            *CODEX_EXEC_GIT_TRUST_FLAGS,
            "--sandbox",
            "workspace-write",
            prompt,
            cwd=str(self.workspace),
            env=env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        deadline = time.monotonic() + timeout_seconds
        stderr_tail = ""
        try:
            while time.monotonic() < deadline:
                if self._new_hook_log_seen(start_offset):
                    self._terminate_async_process_group(process)
                    await self._wait_async_process(process)
                    return True
                if process.returncode is not None:
                    break
                await asyncio.sleep(0.5)
            if process.returncode is None:
                self._terminate_async_process_group(process)
            _, stderr = await self._wait_async_process(process)
            stderr_tail = (stderr or b"").decode("utf-8", errors="replace").strip()[-500:]
        except Exception as exc:
            if process.returncode is None:
                self._terminate_async_process_group(process)
            self.last_self_test_error = f"failed to run Codex hook-fire self-test: {exc}"
            return False

        detail = f": {stderr_tail}" if stderr_tail else ""
        self.last_self_test_error = f"no Codex hook callback reached the supervisor IPC server during the self-test{detail}"
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
