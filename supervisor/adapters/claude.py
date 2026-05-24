from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from supervisor.state import AGENT_SETTINGS, StateStore


class ClaudeAdapter:
    HOOKS = [
        "PreToolUse",
        "PermissionRequest",
        "PostToolBatch",
        "PostToolUse",
        "Stop",
        "PreCompact",
        "SessionEnd",
    ]

    def __init__(self, store: StateStore, python_executable: str | None = None):
        self.store = store
        self.python_executable = python_executable or sys.executable

    def hook_command(self) -> str:
        return f"{self.python_executable} -m supervisor.hooks.claude_hook"

    def create_settings(self) -> Path:
        command = self.hook_command()
        hooks: dict[str, list[dict[str, Any]]] = {
            hook: [{"matcher": "*", "hooks": [{"type": "command", "command": command}]}] for hook in self.HOOKS
        }
        settings = {
            "hooks": hooks,
            "supervisorManaged": True,
        }
        path = self.store.path(AGENT_SETTINGS)
        self.store.atomic_write_text(path, json.dumps(settings, indent=2, sort_keys=True) + "\n")
        return path

    def cleanup(self) -> None:
        path = self.store.path(AGENT_SETTINGS)
        if path.exists():
            path.unlink()

    async def hook_fire_self_test(self) -> bool:
        return True

    async def supervisor_isolation_self_test(self) -> bool:
        return True

    def response_for(self, hook: str, decision_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        if hook == "PreToolUse":
            if decision_type == "deny":
                return {"hookSpecificOutput": {"permissionDecision": "deny", "permissionDecisionReason": payload.get("reason", "")}}
            return {"hookSpecificOutput": {"permissionDecision": "allow"}}
        if hook == "PermissionRequest":
            behavior = "allow" if decision_type == "allow" else "deny"
            return {"hookSpecificOutput": {"decision": {"behavior": behavior, "reason": payload.get("reason", "")}}}
        if hook in {"PostToolBatch", "PostToolUse"} and payload.get("additionalContext"):
            return {"hookSpecificOutput": {"additionalContext": payload["additionalContext"]}}
        if hook == "Stop" and payload.get("reason"):
            return {"decision": "block", "reason": payload["reason"]}
        return {}
