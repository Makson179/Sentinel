from __future__ import annotations

import json
import os
import tomllib
from importlib.resources import files
from pathlib import Path
from typing import Any

from supervisor.schemas import SupervisorWakePacket


PROMPTS_ENV_VAR = "SENTINEL_PROMPTS_FILE"
PROMPTS_RESOURCE = "prompts.toml"


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


def build_completion_review_prompt(packet: SupervisorWakePacket) -> str:
    payload = packet.model_dump(mode="json")
    section_names = _completion_review_section_names(packet)
    payload["prompt_sections"] = section_names
    payload["instructions"] = [_stateless_supervisor_section_text(name) for name in section_names]
    return json.dumps(payload, indent=2, sort_keys=True)


def build_adversary_prompt(
    packet: SupervisorWakePacket,
    *,
    previous_adversary_report: dict[str, Any] | None = None,
) -> str:
    payload = {
        "instructions": [
            _adversary_prompt_text(),
            (
                "Operational constraints for this run: start from this prompt only. If previous_adversary_report is "
                "present, use it only as regression context before searching for new issues. Web/network use is "
                "disabled. Do not read hidden/private/id_private "
                "grading material or runtime history. You are running in a disposable snapshot of the submitted "
                "workspace, not the canonical workspace. You may create or edit disposable probe files inside this "
                "snapshot and /tmp, but do not request writes outside the snapshot. Return only the report requested "
                "by the report_format."
            ),
        ],
        "task_path": packet.task_path,
        "task_contents": packet.task_contents,
        "current_workspace_summary": packet.current_summary,
        "diff_summary": packet.diff_summary,
        "changed_files": [changed.model_dump(mode="json") for changed in packet.changed_files],
        "validation_freshness_summary": packet.validation_freshness_summary,
        # The adversary's job is to read the submitted solution and find bugs independently.
        # The validation ledger is intentionally NOT inlined: it is bloat the adversary's
        # instructions never use, and it would anchor its search to what was already tested.
        # It reads the code and runs its own probes in the snapshot.
        "previous_adversary_report": previous_adversary_report,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def build_cheap_approval_prompt(packet: dict[str, Any]) -> str:
    payload = dict(packet)
    payload["instructions"] = [_cheap_approval_prompt_text()]
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


def _cheap_approval_prompt_text() -> str:
    value = _section("cheap_approval").get("text")
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError("[cheap_approval] must define non-empty text")
    return value.strip()


def _adversary_prompt_text() -> str:
    value = _section("adversary").get("text")
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError("[adversary] must define non-empty text")
    return value.strip()


def _stateless_supervisor_section_names(packet: SupervisorWakePacket) -> list[str]:
    root = _section("stateless_supervisor")
    body_sections = root.get("body_sections")
    if not isinstance(body_sections, list) or not body_sections:
        raise RuntimeError("[stateless_supervisor] must define body_sections")
    names = _section_name_list(body_sections, key="body_sections")
    if packet.handoff is not None:
        names.append("handoff")
    if packet.approval_context is not None or packet.triggering_server_request_id is not None:
        names.append("approval")
    if _include_action_review(packet):
        names.append("action_review")
    if packet.human_message is not None:
        names.append("human_message")
    return names


def _completion_review_section_names(packet: SupervisorWakePacket) -> list[str]:
    root = _section("stateless_supervisor")
    body_sections = root.get("completion_body_sections")
    if not isinstance(body_sections, list) or not body_sections:
        raise RuntimeError("[stateless_supervisor] must define completion_body_sections")
    return _section_name_list(body_sections, key="completion_body_sections")


def _section_name_list(value: list[Any], *, key: str) -> list[str]:
    names: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise RuntimeError(f"[stateless_supervisor] {key} must contain non-empty section names")
        names.append(item)
    return names


def _stateless_supervisor_section_text(name: str) -> str:
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
