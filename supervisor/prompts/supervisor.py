from __future__ import annotations

import json
from pathlib import Path

from supervisor.schemas import HookEvent, StateSnapshot, SupervisorWakePacket


def build_supervisor_prompt(event: HookEvent, snapshot: StateSnapshot, sequence: int, objective: str) -> str:
    payload = {
        "objective": objective,
        "sequence": sequence,
        "generation": snapshot.health.generation,
        "event": event.model_dump(mode="json"),
        "state": snapshot.model_dump(mode="json"),
        "instructions": [
            "Return only JSON matching the supervisor decision schema.",
            "Prefer minimum human involvement and robust autonomous supervision.",
            "For gray-zone permissions, choose allow_once, allow_class, or deny.",
            "Confirm kill_restart only when deterministic evidence shows the current generation is stuck.",
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def build_coder_prompt(task_path: Path) -> str:
    return f"""You are the coding agent for this supervised run.

Read the selected task file first:
{task_path.resolve()}

Complete the task autonomously. When a command, file edit, network access, MCP/app action, or other operation requires approval, request permission through Codex's normal approval flow. Do not ask the human in chat.

The supervisor/controller is the approval authority. It may approve, deny, steer, interrupt, or restart you.

Use minimal changes. Prefer project conventions. Validate your work before claiming completion.
"""


def build_restart_prompt(task_path: Path) -> str:
    return f"""You are the coding agent for a restarted supervised run.

Read the selected task file first:
{task_path.resolve()}

Then read these supervisor state files before making changes:
.supervisor/DECISIONS.md
.supervisor/PROGRESS.md
.supervisor/HANDOFF.md

Continue the task from the handoff. Do not ask the human in chat. Request permissions only through Codex's normal approval flow.
"""


def build_stateless_supervisor_prompt(packet: SupervisorWakePacket) -> str:
    payload = packet.model_dump(mode="json")
    payload["instructions"] = [
        "You are a stateless supervisor for an autonomous Codex coder.",
        "Return only JSON matching the provided output schema.",
        "Choose exactly one decision: noop, approve, deny, intervene, restart, complete, or pause.",
        "Human input is advisory context; do not route messages directly to the coder unless you choose intervene/restart/pause.",
        "For approvals, choose only an offered approval_decision. Do not invent app-server decisions.",
        "Do not approve unsafe network, secrets, broad deletes, permission changes, deploy/publish, git force operations, or supervisor state edits.",
        "Use message_to_coder for concise operational steering.",
        "Do not restart just because tests are currently failing, implementation is pending, or the coder has not finished yet.",
        "Choose restart only when health evidence shows the current generation is stuck or unsafe to continue.",
        "Complete only when validation evidence or explicit validation unavailability is present.",
    ]
    return json.dumps(payload, indent=2, sort_keys=True)
