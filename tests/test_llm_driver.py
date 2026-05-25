from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from supervisor.llm_driver.base import LLMDriverError
from supervisor.llm_driver.claude import ClaudeSubscriptionDriver
from supervisor.llm_driver.codex import CodexSubscriptionDriver
from supervisor.llm_driver.openrouter import OpenRouterDriver
from supervisor.schemas import DecisionType, LLMDecision


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
    assert args[:7] == (
        "codex",
        "exec",
        "--skip-git-repo-check",
        "--sandbox",
        "danger-full-access",
        "--ignore-user-config",
        "--output-schema",
    )
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


@pytest.mark.asyncio
async def test_claude_driver_passes_model_settings_and_schema(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, Any] = {}

    async def fake_run_command_json(args: list[str], prompt: str, timeout_seconds: float | None, cwd: Path | None = None) -> LLMDecision:
        captured["args"] = args
        captured["prompt"] = prompt
        captured["timeout_seconds"] = timeout_seconds
        captured["cwd"] = cwd
        schema = json.loads(args[args.index("--json-schema") + 1])
        assert schema["properties"]["decision_type"]["$ref"] == "#/$defs/DecisionType"
        return LLMDecision(decision_type=DecisionType.NOOP, reason="ok")

    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr("supervisor.llm_driver.claude.run_command_json", fake_run_command_json)
    driver = ClaudeSubscriptionDriver(executable="claude", model="opus", settings_path=settings_path)

    decision = await driver.decide("decide", timeout_seconds=3)

    assert captured["args"][:2] == ["claude", "-p"]
    assert captured["args"][2:6] == ["--model", "opus", "--settings", str(settings_path)]
    assert captured["prompt"] == "decide"
    assert captured["timeout_seconds"] == 3
    assert captured["cwd"] is None
    assert decision.decision_type == DecisionType.NOOP


def test_openrouter_driver_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    with pytest.raises(LLMDriverError, match="OPENROUTER_API_KEY"):
        OpenRouterDriver("provider/model")


@pytest.mark.asyncio
async def test_openrouter_driver_sends_schema_and_parses_decision(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return {"choices": [{"message": {"content": '{"decision_type":"allow","reason":"ok"}'}}]}

    class FakeAsyncClient:
        def __init__(self, timeout: float):
            captured["timeout"] = timeout

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

        async def post(self, url: str, *, headers: dict[str, str], json: dict[str, Any]) -> FakeResponse:
            captured["url"] = url
            captured["headers"] = headers
            captured["payload"] = json
            return FakeResponse()

    monkeypatch.setattr("supervisor.llm_driver.openrouter.httpx.AsyncClient", FakeAsyncClient)
    driver = OpenRouterDriver("provider/model", api_key="key", base_url="https://openrouter.test/api/v1/")

    decision = await driver.decide("decide", timeout_seconds=12)

    assert captured["timeout"] == 12
    assert captured["url"] == "https://openrouter.test/api/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer key"
    assert captured["payload"]["model"] == "provider/model"
    assert captured["payload"]["messages"] == [{"role": "user", "content": "decide"}]
    assert captured["payload"]["response_format"]["type"] == "json_schema"
    assert decision.decision_type == DecisionType.ALLOW
    assert decision.reason == "ok"
