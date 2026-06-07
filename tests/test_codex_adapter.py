from __future__ import annotations

import asyncio
import json

import pytest

from supervisor.adapters.codex import (
    CODEX_HOOK_EVENTS,
    KEY_ARROW_DOWN,
    KEY_ARROW_UP,
    KEY_ENTER,
    KEY_ESCAPE,
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


def toml_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def codex_hook_state_toml(trusted_hashes: dict[str, str], *, disabled_key: str | None = None) -> str:
    parts = []
    for key, trusted_hash in trusted_hashes.items():
        parts.append(f'[hooks.state."{toml_quote(key)}"]')
        parts.append(f'trusted_hash = "{trusted_hash}"')
        if key == disabled_key:
            parts.append("enabled = false")
        parts.append("")
    return "\n".join(parts)


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


def test_codex_planned_hooks_match_codex_0130_trust_keys(store: StateStore) -> None:
    adapter = CodexAdapter(store, python_executable="/usr/bin/python3")
    adapter.codex_dir.mkdir()
    adapter.hooks_path.write_text(
        json.dumps({"hooks": {"Stop": [command_group("echo user")], "PostToolUse": [command_group("echo one"), command_group("echo two")]}}),
        encoding="utf-8",
    )

    planned = adapter.planned_supervisor_hooks()

    assert len(planned) == len(CODEX_HOOK_EVENTS)
    by_event = {hook.event: hook for hook in planned}
    assert by_event["PreToolUse"].key == f"{adapter.hooks_path}:pre_tool_use:0:0"
    assert by_event["PermissionRequest"].key == f"{adapter.hooks_path}:permission_request:0:0"
    assert by_event["PostToolUse"].key == f"{adapter.hooks_path}:post_tool_use:2:0"
    assert by_event["PostToolUse"].display_index == 2
    assert by_event["PreCompact"].key == f"{adapter.hooks_path}:pre_compact:0:0"
    assert by_event["PostCompact"].key == f"{adapter.hooks_path}:post_compact:0:0"
    assert by_event["Stop"].key == f"{adapter.hooks_path}:stop:1:0"
    assert by_event["Stop"].display_index == 1
    assert all(hook.current_hash.startswith("sha256:") and len(hook.current_hash) == 71 for hook in planned)


def test_codex_trust_state_reads_codex_home_config_toml(store: StateStore, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    adapter = CodexAdapter(store, python_executable="/usr/bin/python3")
    planned = adapter.planned_supervisor_hooks()
    trusted_hashes = {hook.key: hook.current_hash for hook in planned}
    config_path = codex_home / "config.toml"
    config_path.write_text(codex_hook_state_toml(trusted_hashes), encoding="utf-8")

    assert adapter.trust_config_path() == config_path
    assert adapter.supervisor_hooks_trusted(planned) is True

    first = planned[0]
    stale_hashes = dict(trusted_hashes)
    stale_hashes[first.key] = "sha256:" + ("0" * 64)
    config_path.write_text(codex_hook_state_toml(stale_hashes), encoding="utf-8")
    assert adapter.supervisor_hooks_trusted(planned) is False

    config_path.write_text(codex_hook_state_toml(trusted_hashes, disabled_key=first.key), encoding="utf-8")
    assert adapter.supervisor_hooks_trusted(planned) is False


def test_codex_hook_review_keystrokes_resume_partial_trust(store: StateStore, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    adapter = CodexAdapter(store, python_executable="/usr/bin/python3")
    adapter.codex_dir.mkdir()
    adapter.hooks_path.write_text(json.dumps({"hooks": {"Stop": [command_group("echo user")]}}), encoding="utf-8")
    planned = adapter.planned_supervisor_hooks()
    by_event = {hook.event: hook for hook in planned}
    config_path = codex_home / "config.toml"
    config_path.write_text(
        codex_hook_state_toml(
            {
                by_event["PreToolUse"].key: by_event["PreToolUse"].current_hash,
                by_event["PermissionRequest"].key: by_event["PermissionRequest"].current_hash,
            },
            disabled_key=by_event["PermissionRequest"].key,
        ),
        encoding="utf-8",
    )

    keystrokes = adapter.hook_review_keystrokes(planned)
    key_data = [keystroke.data for keystroke in keystrokes]

    assert key_data[:7] == [b"/", b"h", b"o", b"o", b"k", b"s", KEY_ENTER]
    assert b"t" in key_data
    assert key_data.count(b"t") == len(CODEX_HOOK_EVENTS) - 2
    assert KEY_ARROW_UP in key_data
    assert KEY_ARROW_DOWN in key_data
    assert key_data.count(KEY_ESCAPE) == len(CODEX_HOOK_EVENTS) - 1


def test_codex_directory_trust_prompt_detection(store: StateStore) -> None:
    adapter = CodexAdapter(store)

    assert adapter._directory_trust_prompt_seen(b"Do you trust the contents of this directory?")
    assert not adapter._directory_trust_prompt_seen(b"Waiting for hook trust approval")


def test_codex_hook_install_hashes_and_json_are_stable(store: StateStore) -> None:
    adapter = CodexAdapter(store, python_executable="/usr/bin/python3")
    adapter.codex_dir.mkdir()
    adapter.hooks_path.write_text(json.dumps({"hooks": {"Stop": [command_group("echo user")]}}), encoding="utf-8")

    first_planned = adapter.planned_supervisor_hooks()
    adapter.install()
    first_text = adapter.hooks_path.read_text(encoding="utf-8")
    adapter.cleanup()
    second_planned = adapter.planned_supervisor_hooks()
    adapter.install()
    second_text = adapter.hooks_path.read_text(encoding="utf-8")

    assert first_text == second_text
    assert [(hook.key, hook.current_hash) for hook in first_planned] == [(hook.key, hook.current_hash) for hook in second_planned]


@pytest.mark.asyncio
async def test_codex_hook_fire_self_test_uses_supported_exec_flags(store: StateStore, monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = CodexAdapter(store)
    captured: dict[str, object] = {}

    class FakeProcess:
        returncode = None

    async def fake_create_subprocess_exec(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return FakeProcess()

    async def fake_wait(process):
        return None, b""

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    monkeypatch.setattr(adapter, "_new_hook_log_seen", lambda offset: True)
    monkeypatch.setattr(adapter, "_terminate_async_process_group", lambda process: None)
    monkeypatch.setattr(adapter, "_wait_async_process", fake_wait)

    assert await adapter.hook_fire_self_test(store.workspace / "ipc.sock", "token") is True
    args = captured["args"]
    assert args[:7] == ("codex", "exec", "--skip-git-repo-check", "-c", 'web_search="disabled"', "--sandbox", "workspace-write")
    assert "--ask-for-approval" not in args
    assert captured["kwargs"]["stdin"] == asyncio.subprocess.DEVNULL
    assert captured["kwargs"]["env"]["SUPERVISOR_HOOK_TRACE_PATH"] == str(store.path("codex-hook-trace.log"))


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
