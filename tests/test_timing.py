from __future__ import annotations

from supervisor.schemas import DecisionType, EventType
from supervisor.timing import HookBudget, fallback_response


def test_hook_deadline_fallbacks() -> None:
    assert fallback_response(EventType.PERMISSION_REQUEST, 1, "timeout").decision_type == DecisionType.DENY
    assert fallback_response(EventType.PRE_TOOL_USE, 1, "timeout").decision_type == DecisionType.DENY
    assert fallback_response(EventType.POST_TOOL_USE, 1, "timeout").decision_type == DecisionType.NOOP
    assert fallback_response(EventType.KILL_CANDIDATE, 1, "timeout").decision_type == DecisionType.KEEP_ALIVE


def test_hook_budget_computes_llm_deadline() -> None:
    budget = HookBudget.start(10)
    assert 0 < budget.llm_deadline_seconds <= 9
