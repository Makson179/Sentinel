from __future__ import annotations

import json
from pathlib import Path

from supervisor.llm_driver.base import LLMDriver, run_command_json
from supervisor.schemas.models import json_schema_for_decision


class ClaudeSubscriptionDriver(LLMDriver):
    def __init__(self, executable: str = "claude", model: str | None = None, settings_path: Path | None = None):
        self.executable = executable
        self.model = model
        self.settings_path = settings_path

    async def decide(self, prompt: str, timeout_seconds: float | None = None):
        args = [self.executable, "-p"]
        if self.model:
            args.extend(["--model", self.model])
        if self.settings_path:
            args.extend(["--settings", str(self.settings_path)])
        args.extend(["--json-schema", json.dumps(json_schema_for_decision())])
        return await run_command_json(args, prompt, timeout_seconds)
