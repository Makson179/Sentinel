from __future__ import annotations

import abc
import asyncio
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from supervisor.schemas import LLMDecision


class LLMDriverError(RuntimeError):
    pass


class ParseFailure(LLMDriverError):
    pass


class LLMDriver(abc.ABC):
    @abc.abstractmethod
    async def decide(self, prompt: str, timeout_seconds: float | None = None) -> LLMDecision:
        raise NotImplementedError


def parse_llm_decision(raw: str | dict[str, Any]) -> LLMDecision:
    if isinstance(raw, dict):
        data = raw
    else:
        text = raw.strip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end == -1 or end < start:
                raise ParseFailure("LLM output was not JSON")
            data = json.loads(text[start : end + 1])
    try:
        return LLMDecision.model_validate(data)
    except ValidationError as exc:
        raise ParseFailure(str(exc)) from exc


async def run_command_json(args: list[str], prompt: str, timeout_seconds: float | None, cwd: Path | None = None) -> LLMDecision:
    process = await asyncio.create_subprocess_exec(
        *args,
        cwd=str(cwd) if cwd else None,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(prompt.encode("utf-8")),
            timeout=timeout_seconds,
        )
    except asyncio.TimeoutError as exc:
        process.kill()
        await process.communicate()
        raise LLMDriverError("LLM command timed out") from exc
    if process.returncode != 0:
        raise LLMDriverError(stderr.decode("utf-8", errors="replace").strip())
    return parse_llm_decision(stdout.decode("utf-8", errors="replace"))
