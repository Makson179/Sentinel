from __future__ import annotations

import json
import os
import tomllib
from importlib.resources import files
from pathlib import Path
from typing import Any

from supervisor.schemas import HookEvent, StateSnapshot, SupervisorWakePacket


PROMPTS_ENV_VAR = "SENTINEL_PROMPTS_FILE"
PROMPTS_RESOURCE = "prompts.toml"


def clear_prompt_cache() -> None:
    """Compatibility hook; prompts are loaded fresh on every build."""
    return None


def build_supervisor_prompt(event: HookEvent, snapshot: StateSnapshot, sequence: int, objective: str) -> str:
    payload = {
        "objective": objective,
        "sequence": sequence,
        "generation": snapshot.health.generation,
        "event": event.model_dump(mode="json"),
        "state": snapshot.model_dump(mode="json"),
        "instructions": _instructions("legacy_supervisor"),
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def build_coder_prompt(task_path: Path) -> str:
    return _template("coder_initial").replace("{task_path}", str(task_path.resolve()))


def build_restart_prompt(task_path: Path) -> str:
    return _template("coder_restart").replace("{task_path}", str(task_path.resolve()))


def build_stateless_supervisor_prompt(packet: SupervisorWakePacket) -> str:
    payload = packet.model_dump(mode="json")
    section_names = _stateless_supervisor_section_names(packet)
    payload["prompt_sections"] = section_names
    payload["instructions"] = [_stateless_supervisor_section_text(name) for name in section_names]
    return json.dumps(payload, indent=2, sort_keys=True)


def _load_prompt_config() -> dict[str, Any]:
    override = os.environ.get(PROMPTS_ENV_VAR)
    if override:
        raw = Path(override).read_bytes()
    else:
        raw = files("supervisor.prompts").joinpath(PROMPTS_RESOURCE).read_bytes()
    data = tomllib.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("prompt config must be a TOML table")
    return data


def _section(name: str) -> dict[str, Any]:
    value = _load_prompt_config().get(name)
    if not isinstance(value, dict):
        raise RuntimeError(f"missing prompt section [{name}] in {PROMPTS_RESOURCE}")
    return value


def _template(name: str) -> str:
    value = _section(name).get("template")
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"prompt section [{name}] must define a non-empty template")
    return value


def _instructions(name: str) -> list[str]:
    value = _section(name).get("instructions")
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
        raise RuntimeError(f"prompt section [{name}] must define non-empty string instructions")
    return list(value)


def _stateless_supervisor_section_names(packet: SupervisorWakePacket) -> list[str]:
    root = _section("stateless_supervisor")
    legacy = root.get("instructions")
    if isinstance(legacy, list):
        return ["stateless_supervisor"]
    body_sections = root.get("body_sections")
    if not isinstance(body_sections, list) or not body_sections:
        raise RuntimeError("[stateless_supervisor] must define body_sections")
    names = [str(name) for name in body_sections]
    if packet.handoff is not None:
        names.append("handoff")
    if packet.approval_context is not None or packet.triggering_server_request_id is not None:
        names.append("approval")
    if _include_action_review(packet):
        names.append("action_review")
    if packet.human_message is not None:
        names.append("human_message")
    return names


def _stateless_supervisor_section_text(name: str) -> str:
    if name == "stateless_supervisor":
        return "\n\n".join(_instructions("stateless_supervisor"))
    root = _section("stateless_supervisor")
    sections = root.get("sections")
    if not isinstance(sections, dict):
        raise RuntimeError("[stateless_supervisor] must define [stateless_supervisor.sections.*] tables")
    section = sections.get(name)
    if not isinstance(section, dict):
        raise RuntimeError(f"missing stateless supervisor prompt block: {name}")
    text = section.get("text")
    if not isinstance(text, str) or not text.strip():
        raise RuntimeError(f"stateless supervisor prompt block {name} must define non-empty text")
    return text.strip()


def _include_action_review(packet: SupervisorWakePacket) -> bool:
    if packet.triggering_item_id is not None or packet.triggering_action is not None:
        return True
    summary = packet.current_summary.lower()
    return any(
        marker in summary
        for marker in (
            "progress check",
            "dirty",
            "reviewing latest state",
            "turn completed",
            "coder completed action",
            "supervisor check",
        )
    )
