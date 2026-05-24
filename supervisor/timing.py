from __future__ import annotations

import time
from dataclasses import dataclass

from supervisor.schemas import DecisionType, EventType, IPCResponse


@dataclass(frozen=True)
class HookBudget:
    timeout_seconds: float
    started_at: float
    llm_fraction: float = 0.9

    @classmethod
    def start(cls, timeout_seconds: float) -> "HookBudget":
        return cls(timeout_seconds=timeout_seconds, started_at=time.monotonic())

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    @property
    def remaining(self) -> float:
        return max(0.0, self.timeout_seconds - self.elapsed)

    @property
    def llm_deadline_seconds(self) -> float:
        return max(0.0, self.timeout_seconds * self.llm_fraction - self.elapsed)


def fallback_response(event_type: EventType, sequence: int, reason: str) -> IPCResponse:
    if event_type in {EventType.PERMISSION_REQUEST, EventType.PRE_TOOL_USE}:
        decision = DecisionType.DENY
        payload = {"reason": reason}
    elif event_type == EventType.KILL_CANDIDATE:
        decision = DecisionType.KEEP_ALIVE
        payload = {"reason": reason}
    else:
        decision = DecisionType.NOOP
        payload = {"reason": reason}
    return IPCResponse(decision_type=decision, payload=payload, sequence=sequence)


class DebouncedTimer:
    def __init__(self, interval_seconds: int):
        self.interval_seconds = interval_seconds
        self._last_activity = time.monotonic()
        self._last_signature: str | None = None

    def reset(self) -> None:
        self._last_activity = time.monotonic()

    def due(self) -> bool:
        return time.monotonic() - self._last_activity >= self.interval_seconds

    def should_call_llm(self, signature: str) -> bool:
        if self._last_signature == signature:
            self.reset()
            return False
        self._last_signature = signature
        self.reset()
        return True
