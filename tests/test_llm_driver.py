from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from supervisor.llm_driver.base import LLMDriverError
from supervisor.llm_driver.codex import CodexSubscriptionDriver
from supervisor.schemas import DecisionType


class FakeProcess:
    def __init__(self, stdout: bytes, stderr: bytes = b"", returncode: int = 0):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self.killed = False

    async def communicate(self, input: bytes | None = None) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr

    def kill(self) -> None:
        self.killed = True


@pytest.mark.asyncio
async def test_codex_driver_writes_real_output_schema_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    async def fake_create_subprocess_exec(*args: str, **kwargs: Any) -> FakeProcess:
        captured["args"] = args
        captured["kwargs"] = kwargs
        schema_path = Path(args[args.index("--output-schema") + 1])
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        assert schema["properties"]["decision_type"]["$ref"] == "#/$defs/DecisionType"
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])
        assert schema["$defs"]["AllowRulePayload"]["additionalProperties"] is False
        assert set(schema["$defs"]["AllowRulePayload"]["required"]) == set(schema["$defs"]["AllowRulePayload"]["properties"])
        assert "default" not in json.dumps(schema)
        assert len(str(schema_path)) < 255
        assert not str(schema_path).startswith("{")
        return FakeProcess(b'{"decision_type":"allow","reason":"ok"}')

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    driver = CodexSubscriptionDriver(executable="codex", cwd=tmp_path)

    decision = await driver.decide("decide", timeout_seconds=1)

    args = captured["args"]
    assert args[:7] == ("codex", "exec", "--skip-git-repo-check", "-c", 'web_search="disabled"', "--ignore-user-config", "--output-schema")
    assert Path(args[7]) == tmp_path / "supervisor-output-schema.json"
    assert args[-1] == "-"
    assert captured["kwargs"]["cwd"] == str(tmp_path)
    assert decision.decision_type == DecisionType.ALLOW
    assert decision.reason == "ok"


@pytest.mark.asyncio
async def test_codex_driver_schema_validation_failure_is_not_retried(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls = 0

    async def fake_create_subprocess_exec(*args: str, **kwargs: Any) -> FakeProcess:
        nonlocal calls
        calls += 1
        return FakeProcess(b"", b"Invalid schema for response_format 'codex_output_schema'", returncode=1)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    driver = CodexSubscriptionDriver(executable="codex", cwd=tmp_path)

    with pytest.raises(LLMDriverError, match="Invalid schema"):
        await driver.decide("decide", timeout_seconds=1)

    assert calls == 1
