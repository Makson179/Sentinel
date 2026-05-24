from __future__ import annotations

from supervisor.schemas import HealthDelta, HealthState
from supervisor.state import StateStore


def apply_delta(state: HealthState, delta: HealthDelta) -> HealthState:
    if state.generation != delta.generation:
        return state
    if delta.reset_generation_scoped:
        state.denied_requests = 0
        state.consecutive_failed_tests = 0
        state.repeated_command_count = 0
        state.interventions = 0
        state.minutes_without_progress = 0
        state.risk_signals = []
        state.last_denial = None
        state.timeout_fallback_count = 0
        state.parse_failure_count = 0
        state.last_progress_sequence = 0
    state.denied_requests += delta.denied_requests
    state.consecutive_failed_tests += delta.consecutive_failed_tests
    state.repeated_command_count += delta.repeated_command_count
    state.interventions += delta.interventions
    state.minutes_without_progress += delta.minutes_without_progress
    state.timeout_fallback_count += delta.timeout_fallback_count
    state.parse_failure_count += delta.parse_failure_count
    state.restart_count += delta.restart_count
    if delta.new_generation is not None:
        state.generation = delta.new_generation
    if delta.last_denial is not None:
        state.last_denial = delta.last_denial
    if delta.last_progress_sequence is not None:
        state.last_progress_sequence = max(state.last_progress_sequence, delta.last_progress_sequence)
        state.minutes_without_progress = 0
        state.interventions = 0
        state.consecutive_failed_tests = 0
        state.repeated_command_count = 0
    if delta.clear_risk_signals:
        state.risk_signals = []
    for signal in delta.add_risk_signals:
        if signal not in state.risk_signals:
            state.risk_signals.append(signal)
    return state


def patch_health(store: StateStore, delta: HealthDelta) -> HealthState:
    return store.patch_health(lambda current: apply_delta(current, delta))


def kill_restart_candidate(state: HealthState) -> tuple[bool, str | None]:
    if state.restart_count >= 3:
        return True, "restart cap reached"
    if state.interventions >= 3 and state.last_progress_sequence == 0:
        return True, "three interventions without progress"
    if state.repeated_command_count >= 4:
        return True, "four substantially similar failing commands"
    if state.minutes_without_progress >= 15:
        return True, "fifteen minutes without progress"
    if "bypass_after_denial" in state.risk_signals:
        return True, "bypass/rephrase attempt after denial"
    if state.timeout_fallback_count >= 3:
        return True, "repeated timeout fallbacks"
    if state.parse_failure_count >= 3:
        return True, "repeated parse failures"
    return False, None

