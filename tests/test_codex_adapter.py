from __future__ import annotations

import asyncio
import json
from collections import deque

import pytest

from supervisor.adapters.codex import (
    CODEX_HOOK_EVENTS,
    CodexAdapter,
    CodexHookConfigError,
    MARKER,
)
from supervisor.state import StateStore


CODEX_0130_EVENTS = {
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PreCompact",
    "PostCompact",
    "SessionStart",
    "UserPromptSubmit",
    "Stop",
}


def command_group(command: str, *, matcher: str | None = None, status_message: str | None = None) -> dict:
    handler = {"type": "command", "command": command}
    if status_message is not None:
        handler["statusMessage"] = status_message
    group = {"hooks": [handler]}
    if matcher is not None:
        group["matcher"] = matcher
    return group


def assert_matches_codex_0130_hooks_file_schema(data: dict) -> None:
    assert isinstance(data, dict)
    assert isinstance(data.get("hooks"), dict)
    assert set(data["hooks"]).issubset(CODEX_0130_EVENTS)
    for groups in data["hooks"].values():
        assert isinstance(groups, list)
        for group in groups:
            assert isinstance(group, dict)
            assert set(group).issubset({"matcher", "hooks"})
            if "matcher" in group:
                assert isinstance(group["matcher"], str)
            assert isinstance(group["hooks"], list)
            for handler in group["hooks"]:
                assert isinstance(handler, dict)
                assert set(handler).issubset({"type", "command", "timeout", "async", "statusMessage"})
                assert handler["type"] == "command"
                assert isinstance(handler["command"], str)
                assert "id" not in handler
                assert "event" not in handler
                assert "marker" not in handler
                assert "supervisor_owned" not in handler


def test_codex_hook_merge_cleanup_preserves_user_edits(store: StateStore) -> None:
    adapter = CodexAdapter(store)
    adapter.codex_dir.mkdir()
    adapter.hooks_path.write_text(json.dumps({"hooks": {"Stop": [command_group("echo user")]}, "other": True}), encoding="utf-8")

    adapter.install()
    installed = json.loads(adapter.hooks_path.read_text(encoding="utf-8"))
    assert_matches_codex_0130_hooks_file_schema(installed)
    installed["hooks"].setdefault("PostToolUse", []).append(command_group("echo later", matcher="Bash"))
    adapter.hooks_path.write_text(json.dumps(installed), encoding="utf-8")

    adapter.cleanup()
    cleaned = json.loads(adapter.hooks_path.read_text(encoding="utf-8"))
    assert_matches_codex_0130_hooks_file_schema(cleaned)
    commands = {
        handler["command"]
        for groups in cleaned["hooks"].values()
        for group in groups
        for handler in group["hooks"]
    }
    assert commands == {"echo user", "echo later"}
    assert cleaned["other"] is True


def test_codex_generated_hooks_match_codex_0130_schema(store: StateStore) -> None:
    adapter = CodexAdapter(store, python_executable="/usr/bin/python3")

    adapter.install()

    data = json.loads(adapter.hooks_path.read_text(encoding="utf-8"))
    assert_matches_codex_0130_hooks_file_schema(data)
    assert set(data["hooks"]) == {event for event, _ in CODEX_HOOK_EVENTS}
    for event, hook_id in CODEX_HOOK_EVENTS:
        groups = data["hooks"][event]
        assert len(groups) == 1
        group = groups[0]
        if event != "Stop":
            assert group["matcher"] == "*"
        handler = group["hooks"][0]
        assert handler["type"] == "command"
        assert handler["command"] == f"/usr/bin/python3 -m supervisor.hooks.codex_hook --supervisor-hook-id {hook_id}"
        assert handler["statusMessage"] == f"Supervisor hook: {event}"


def test_codex_hook_install_hashes_and_json_are_stable(store: StateStore) -> None:
    adapter = CodexAdapter(store, python_executable="/usr/bin/python3")
    adapter.codex_dir.mkdir()
    adapter.hooks_path.write_text(json.dumps({"hooks": {"Stop": [command_group("echo user")]}}), encoding="utf-8")

    adapter.install()
    first_text = adapter.hooks_path.read_text(encoding="utf-8")
    adapter.cleanup()
    adapter.install()
    second_text = adapter.hooks_path.read_text(encoding="utf-8")

    assert first_text == second_text


@pytest.mark.asyncio
async def test_codex_hook_fire_self_test_uses_supported_exec_flags(store: StateStore, monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = CodexAdapter(store)
    captured: dict[str, object] = {}

    class FakeProcess:
        returncode = 0

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return FakeProcess()

    async def fake_wait(process):
        stdout = b'{"type":"item.completed","item":{"type":"command_execution","exit_code":0}}\n'
        return stdout, b""

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(adapter, "_new_hook_log_seen", lambda offset: True)
    monkeypatch.setattr(adapter, "_wait_async_process", fake_wait)

    assert await adapter.hook_fire_self_test(store.workspace / "ipc.sock", "token") is True
    args = captured["args"]
    assert args[:7] == (
        "codex",
        "exec",
        "--skip-git-repo-check",
        "--dangerously-bypass-hook-trust",
        "--json",
        "--sandbox",
        "danger-full-access",
    )
    assert "--ask-for-approval" not in args
    assert captured["kwargs"]["stdin"] == asyncio.subprocess.DEVNULL
    assert captured["kwargs"]["stdout"] == asyncio.subprocess.PIPE
    assert captured["kwargs"]["env"]["SUPERVISOR_HOOK_TRACE_PATH"] == str(store.path("codex-hook-trace.log"))


@pytest.mark.asyncio
async def test_codex_hook_fire_self_test_requires_successful_command(store: StateStore, monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = CodexAdapter(store)

    class FakeProcess:
        returncode = 0

    async def fake_create_subprocess_exec(*args, **kwargs):
        return FakeProcess()

    async def fake_wait(process):
        stdout = b'{"type":"item.completed","item":{"type":"agent_message","text":"bwrap failed"}}\n'
        return stdout, b""

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(adapter, "_new_hook_log_seen", lambda offset: True)
    monkeypatch.setattr(adapter, "_wait_async_process", fake_wait)

    assert await adapter.hook_fire_self_test(store.workspace / "ipc.sock", "token") is False
    assert "shell command did not complete successfully" in (adapter.last_self_test_error or "")


@pytest.mark.asyncio
async def test_codex_sync_supervisor_hook_trust_uses_app_server(store: StateStore, monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = CodexAdapter(store)
    key = f"{adapter.hooks_path}:pre_tool_use:0:0"
    current_hash = "sha256:abc123"
    messages = [
        {"id": 1, "result": {"codexHome": "/home/alex/.codex", "platformFamily": "unix", "platformOs": "linux", "userAgent": "codex"}},
        {
            "method": "remoteControl/status/changed",
            "params": {"status": "disabled"},
        },
        {
            "id": 2,
            "result": {
                "data": [
                    {
                        "cwd": str(store.workspace),
                        "hooks": [
                            {
                                "key": key,
                                "sourcePath": str(adapter.hooks_path),
                                "command": adapter._supervisor_command("supervisor-pre-tool-use"),
                                "currentHash": current_hash,
                                "trustStatus": "modified",
                            }
                        ],
                        "warnings": [],
                        "errors": [],
                    }
                ]
            },
        },
        {"id": 3, "result": {"status": "ok", "version": "sha256:config", "filePath": "/home/alex/.codex/config.toml"}},
    ]

    class FakeStdout:
        def __init__(self):
            self.lines = deque((json.dumps(message) + "\n").encode("utf-8") for message in messages)

        async def readline(self):
            if self.lines:
                return self.lines.popleft()
            return b""

    class FakeStdin:
        def __init__(self):
            self.requests = []

        def write(self, data):
            self.requests.append(json.loads(data.decode("utf-8")))

        async def drain(self):
            return None

    class FakeProcess:
        def __init__(self):
            self.stdin = FakeStdin()
            self.stdout = FakeStdout()
            self.stderr = None

    process = FakeProcess()
    captured: dict[str, object] = {}

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return process

    async def fake_wait(_process):
        return b"", b""

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(adapter, "_terminate_async_process_group", lambda _process: None)
    monkeypatch.setattr(adapter, "_wait_async_process", fake_wait)

    assert await adapter.sync_supervisor_hook_trust() is True

    assert captured["args"] == ("codex", "app-server", "--listen", "stdio://")
    assert [request["method"] for request in process.stdin.requests] == ["initialize", "hooks/list", "config/batchWrite"]
    edit = process.stdin.requests[2]["params"]["edits"][0]
    assert edit == {
        "keyPath": f'hooks.state."{key}".trusted_hash',
        "value": current_hash,
        "mergeStrategy": "upsert",
    }


def test_codex_malformed_json_aborts(store: StateStore) -> None:
    adapter = CodexAdapter(store)
    adapter.codex_dir.mkdir()
    adapter.hooks_path.write_text("{bad", encoding="utf-8")
    with pytest.raises(CodexHookConfigError):
        adapter.install()
    assert adapter.hooks_path.read_text(encoding="utf-8") == "{bad"


def test_codex_crash_recovery_without_config(store: StateStore) -> None:
    adapter = CodexAdapter(store)
    adapter.codex_dir.mkdir()
    adapter.hooks_path.write_text(
        json.dumps(
            {
                "hooks": {
                    "Stop": [
                        command_group("echo user"),
                        command_group("python -m supervisor.hooks.codex_hook", status_message="Supervisor hook: Stop"),
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    adapter.recover_stale_hooks()
    data = json.loads(adapter.hooks_path.read_text(encoding="utf-8"))
    assert data["hooks"] == {"Stop": [command_group("echo user")]}


def test_codex_legacy_flat_hooks_are_migrated_and_cleaned(store: StateStore) -> None:
    adapter = CodexAdapter(store, python_executable="/usr/bin/python3")
    adapter.codex_dir.mkdir()
    adapter.hooks_path.write_text(
        json.dumps(
            {
                "hooks": [
                    {"id": "user", "event": "Stop", "command": "echo user"},
                    {"id": "supervisor-old", "event": "Stop", "command": "python -m supervisor.hooks.codex_hook", "marker": MARKER, "supervisor_owned": True},
                ]
            }
        ),
        encoding="utf-8",
    )

    adapter.install()

    data = json.loads(adapter.hooks_path.read_text(encoding="utf-8"))
    assert_matches_codex_0130_hooks_file_schema(data)
    stop_commands = [handler["command"] for group in data["hooks"]["Stop"] for handler in group["hooks"]]
    assert "echo user" in stop_commands
    assert "python -m supervisor.hooks.codex_hook" not in stop_commands


def test_codex_cleanup_deletes_created_empty_file(store: StateStore) -> None:
    adapter = CodexAdapter(store)
    adapter.install()
    assert adapter.hooks_path.exists()
    adapter.cleanup()
    assert not adapter.hooks_path.exists()
