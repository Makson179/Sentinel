from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from supervisor.prompts import (
    PROMPTS_ENV_VAR,
    build_coder_prompt,
    build_restart_prompt,
    build_stateless_supervisor_prompt,
    build_supervisor_prompt,
    clear_prompt_cache,
)
from supervisor.schemas.models import (
    EventType,
    HealthState,
    HookEvent,
    HumanMessage,
    LLMDecision,
    RestartHandoff,
    RunConfig,
    StateSnapshot,
    SupervisorDecision,
    SupervisorWakePacket,
    TriggeringAction,
    openai_strict_json_schema_for_decision,
    openai_strict_json_schema_for_supervisor_decision,
)


def _walk_schema(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_schema(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_schema(item)


def test_openai_strict_decision_schema_marks_all_objects_closed_and_required() -> None:
    schema = openai_strict_json_schema_for_decision()

    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])
    assert schema["properties"]["allow_rule"]["anyOf"][0]["$ref"] == "#/$defs/AllowRulePayload"

    for node in _walk_schema(schema):
        if node.get("type") == "object" or "properties" in node:
            assert node["additionalProperties"] is False
            assert set(node["required"]) == set(node["properties"])
        assert node.get("additionalProperties") is not True
        assert "default" not in node


def test_llm_decision_allow_rule_accepts_structured_payload() -> None:
    decision = LLMDecision.model_validate(
        {
            "decision_type": "allow",
            "permission_kind": "allow_class",
            "reason": "safe repeated command",
            "allow_rule": {"tool_name": "Bash", "command": "pwd"},
        }
    )

    assert decision.allow_rule is not None
    assert decision.allow_rule.model_dump(exclude_none=True) == {"tool_name": "Bash", "command": "pwd"}


def test_supervisor_decision_schema_is_strict() -> None:
    schema = openai_strict_json_schema_for_supervisor_decision()

    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])
    assert "handoff" in schema["properties"]
    handoff_schema = schema["$defs"]["RestartHandoff"]
    assert set(handoff_schema["required"]) == set(handoff_schema["properties"])


def test_supervisor_decision_accepts_expected_shape() -> None:
    decision = SupervisorDecision.model_validate(
        {
            "decision": "approve",
            "approval_decision": "accept",
            "execpolicy_amendment": None,
            "reason": "ok",
            "message_to_coder": None,
            "persistent_decision": None,
            "progress_update": None,
            "health_delta": None,
            "clear_handoff": True,
            "display_message": None,
        }
    )

    assert decision.decision == "approve"
    assert decision.clear_handoff is True


def test_supervisor_decision_accepts_structured_restart_handoff() -> None:
    handoff = {
        "objective": "Fix parser tests",
        "restart_reason": "same loop after steering",
        "bad_pattern": "rerunning tests without reading assertion",
        "known_evidence": "failure is in test_parser",
        "next_step": "read the assertion",
        "recovery_signal": "coder opens the failing test first",
    }

    restart = SupervisorDecision.model_validate(
        {
            "decision": "restart",
            "approval_decision": None,
            "execpolicy_amendment": None,
            "reason": "loop",
            "message_to_coder": None,
            "persistent_decision": None,
            "progress_update": None,
            "health_delta": None,
            "clear_handoff": False,
            "display_message": None,
            "handoff": handoff,
            "wake_sequence": 7,
            "generation": 1,
        }
    )
    noop = SupervisorDecision.model_validate(
        {
            "decision": "noop",
            "approval_decision": None,
            "execpolicy_amendment": None,
            "reason": "ok",
            "message_to_coder": None,
            "persistent_decision": None,
            "progress_update": None,
            "health_delta": None,
            "clear_handoff": False,
            "display_message": None,
            "handoff": None,
            "wake_sequence": 8,
            "generation": 1,
        }
    )

    assert restart.handoff == RestartHandoff.model_validate(handoff)
    assert noop.handoff is None


def test_supervisor_wake_packet_accepts_decision_critical_fields(tmp_path: Path) -> None:
    packet = SupervisorWakePacket(
        wake_sequence=1,
        latest_event_sequence=1,
        generation=0,
        restart_count=0,
        task_path=str(tmp_path / "TASK.md"),
        task_contents="# Task",
        triggering_action=TriggeringAction(
            item_id="i",
            kind="commandExecution",
            command="pytest",
            exit_code=0,
            status="completed",
            summary="command completed: pytest exit=0",
        ),
        human_message=HumanMessage(text="discussion only", sequence=3),
        changed_files=[{"path": "a.py", "status": "M", "additions": 1, "deletions": 0}],
        validations=[{"command": "pytest", "exit_code": 0, "passed": True, "summary": "pytest passed", "sequence": 2}],
    )

    assert packet.triggering_action is not None
    assert packet.human_message is not None
    assert packet.changed_files[0].path == "a.py"
    assert packet.validations[0].passed is True


def test_stateless_prompt_assembles_blocks_from_packet() -> None:
    base = SupervisorWakePacket(
        wake_sequence=1,
        latest_event_sequence=1,
        generation=0,
        restart_count=0,
        task_path="TASK.md",
        task_contents="# Task",
    )
    payload = json.loads(build_stateless_supervisor_prompt(base))
    assert payload["prompt_sections"] == ["role", "output_contract", "decisions", "inputs", "state_writes", "invariants"]

    approval_with_handoff = base.model_copy(
        update={
            "triggering_server_request_id": 10,
            "handoff": RestartHandoff(
                objective="task",
                restart_reason="loop",
                bad_pattern="repeat",
                known_evidence="evidence",
                next_step="step",
                recovery_signal="signal",
            ),
        }
    )
    payload = json.loads(build_stateless_supervisor_prompt(approval_with_handoff))
    assert "approval" in payload["prompt_sections"]
    assert "handoff" in payload["prompt_sections"]
    assert "action_review" not in payload["prompt_sections"]

    action = base.model_copy(update={"triggering_item_id": "item-1"})
    assert "action_review" in json.loads(build_stateless_supervisor_prompt(action))["prompt_sections"]

    human = base.model_copy(update={"human_message": HumanMessage(text="stop", sequence=2)})
    assert "human_message" in json.loads(build_stateless_supervisor_prompt(human))["prompt_sections"]


def test_prompts_are_loaded_from_single_toml_file(monkeypatch, tmp_path: Path) -> None:
    prompt_file = tmp_path / "prompts.toml"
    prompt_file.write_text(
        """
[coder_initial]
template = '''initial {task_path}'''

[coder_restart]
template = '''restart {task_path}'''

[legacy_supervisor]
instructions = ["legacy instruction"]

[stateless_supervisor]
instructions = ["stateless instruction"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")

    monkeypatch.setenv(PROMPTS_ENV_VAR, str(prompt_file))
    clear_prompt_cache()
    try:
        assert build_coder_prompt(task) == f"initial {task.resolve()}"
        assert build_restart_prompt(task) == f"restart {task.resolve()}"

        packet = SupervisorWakePacket(
            wake_sequence=1,
            latest_event_sequence=1,
            generation=0,
            restart_count=0,
            task_path=str(task),
            task_contents="# Task",
            last_actions=["command completed: pytest exit=1", "file change completed: 1 changes"],
        )
        supervisor_payload = json.loads(build_stateless_supervisor_prompt(packet))
        assert supervisor_payload["instructions"] == ["stateless instruction"]
        assert supervisor_payload["last_actions"] == ["command completed: pytest exit=1", "file change completed: 1 changes"]
        assert "last_action" not in supervisor_payload

        legacy_payload = json.loads(
            build_supervisor_prompt(
                HookEvent(event_type=EventType.TIMER),
                StateSnapshot(
                    config=RunConfig(platform="fake", plan_file_path=str(task)),
                    health=HealthState(),
                ),
                sequence=1,
                objective="# Task",
            )
        )
        assert legacy_payload["instructions"] == ["legacy instruction"]
    finally:
        clear_prompt_cache()
