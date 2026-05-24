from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from supervisor.schemas.models import LLMDecision, openai_strict_json_schema_for_decision


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
