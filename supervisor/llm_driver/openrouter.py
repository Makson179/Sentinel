from __future__ import annotations

import os
from typing import Any

import httpx

from supervisor.llm_driver.base import LLMDriver, LLMDriverError, parse_llm_decision
from supervisor.schemas.models import json_schema_for_decision


class OpenRouterDriver(LLMDriver):
    def __init__(self, model: str, api_key: str | None = None, base_url: str = "https://openrouter.ai/api/v1"):
        self.model = model
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
        self.base_url = base_url.rstrip("/")
        if not self.api_key:
            raise LLMDriverError("OPENROUTER_API_KEY is required for API mode")

    async def capability_metadata(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{self.base_url}/models")
            response.raise_for_status()
            for model in response.json().get("data", []):
                if model.get("id") == self.model:
                    return model
        return {}

    async def decide(self, prompt: str, timeout_seconds: float | None = None):
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "supervisor_decision", "schema": json_schema_for_decision()},
            },
        }
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=timeout_seconds or 60.0) as client:
            response = await client.post(f"{self.base_url}/chat/completions", headers=headers, json=payload)
            response.raise_for_status()
        choice = response.json()["choices"][0]["message"]["content"]
        return parse_llm_decision(choice)

