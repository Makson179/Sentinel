from __future__ import annotations

import json

from supervisor.schemas import HookEvent, StateSnapshot


def build_supervisor_prompt(event: HookEvent, snapshot: StateSnapshot, sequence: int, objective: str) -> str:
    payload = {
        "objective": objective,
        "sequence": sequence,
        "generation": snapshot.health.generation,
        "event": event.model_dump(mode="json"),
        "state": snapshot.model_dump(mode="json"),
        "instructions": [
            "Return only JSON matching the supervisor decision schema.",
            "Prefer minimum human involvement and robust autonomous supervision.",
            "For gray-zone permissions, choose allow_once, allow_class, or deny.",
            "Confirm kill_restart only when deterministic evidence shows the current generation is stuck.",
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)

