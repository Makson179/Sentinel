from __future__ import annotations

import json
import tempfile
from pathlib import Path

from supervisor.codex_cli import CODEX_EXEC_GIT_TRUST_FLAGS, CODEX_EXEC_NO_WEB_SEARCH_FLAGS
from supervisor.llm_driver.base import LLMDriver, run_command_json
from supervisor.schemas.models import openai_strict_json_schema_for_decision


class CodexSubscriptionDriver(LLMDriver):
    def __init__(self, executable: str = "codex", model: str | None = None, cwd: Path | None = None):
        self.executable = executable
        self.model = model
        self.cwd = cwd or Path(tempfile.mkdtemp(prefix="supervisor-codex-"))
        self.cwd.mkdir(parents=True, exist_ok=True)
        self.output_schema_path = self.cwd / "supervisor-output-schema.json"

    async def decide(self, prompt: str, timeout_seconds: float | None = None):
        self.output_schema_path.write_text(
            json.dumps(openai_strict_json_schema_for_decision(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        args = [
            self.executable,
            "exec",
            *CODEX_EXEC_GIT_TRUST_FLAGS,
            *CODEX_EXEC_NO_WEB_SEARCH_FLAGS,
            "--ignore-user-config",
            "--output-schema",
            str(self.output_schema_path),
        ]
        if self.model:
            args.extend(["--model", self.model])
        args.append("-")
        return await run_command_json(args, prompt, timeout_seconds, cwd=self.cwd)
