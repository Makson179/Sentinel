from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from supervisor.bench_tokens import TOKEN_METRIC_FIELDS, compute_token_metrics


PERF = "perf.jsonl"

METRIC_NAMES = (
    "wall_time_ms",
    "startup_time_ms",
    "time_to_first_action_ms",
    "supervisor_wait_time_ms",
    "approval_wait_time_ms",
    "validation_time_ms",
    "restart_recovery_time_ms",
    "supervision_overhead_ratio",
    "completed_coder_action_count",
    "supervisor_call_count",
    "approval_request_count",
    "restart_count",
    "supervisor_context_tokens_total_est",
    "supervisor_context_tokens_mean_est",
    "supervisor_context_tokens_max_est",
    "supervisor_context_truncation_count",
    *TOKEN_METRIC_FIELDS,
)


def compute_bench_metrics(
    state_dir: Path,
    *,
    validation_time_ms: int | None = None,
) -> dict[str, int | float | None]:
    perf_events = read_jsonl(state_dir / PERF)
    events = read_jsonl(state_dir / "events.jsonl")
    health = read_json(state_dir / "HEALTH.json", {})

    run_started = _first_time(perf_events, "run_started")
    run_finished = _last_time(perf_events, "run_finished")
    coder_turn_started = _first_time(perf_events, "coder_turn_started")
    first_action_started = _first_time(perf_events, "first_coder_action_started")
    wall_time_ms = _duration(run_started, run_finished)
    supervisor_wait_time_ms = _paired_duration(perf_events, "supervisor_call_started", "supervisor_call_finished", "supervisor_call_id")
    approval_wait_time_ms = _paired_duration(perf_events, "approval_requested", "approval_decided", "approval_request_id")
    restart_recovery_time_ms = _paired_duration(perf_events, "restart_started", "restart_finished", "restart_id")

    supervisor_contexts = [event for event in perf_events if event.get("event") == "supervisor_context_built"]
    context_tokens = [
        event["estimated_tokens"]
        for event in supervisor_contexts
        if isinstance(event.get("estimated_tokens"), int | float)
    ]
    supervisor_call_count = _count(perf_events, "supervisor_call_started")

    metrics: dict[str, int | float | None] = {
        "wall_time_ms": wall_time_ms,
        "startup_time_ms": _duration(run_started, coder_turn_started),
        "time_to_first_action_ms": _duration(coder_turn_started, first_action_started),
        "supervisor_wait_time_ms": supervisor_wait_time_ms,
        "approval_wait_time_ms": approval_wait_time_ms,
        "validation_time_ms": validation_time_ms if validation_time_ms is not None else _validation_time(perf_events),
        "restart_recovery_time_ms": restart_recovery_time_ms,
        "supervision_overhead_ratio": _ratio(supervisor_wait_time_ms, wall_time_ms),
        "completed_coder_action_count": _count(perf_events, "coder_action_completed") or _completed_action_count(events),
        "supervisor_call_count": supervisor_call_count,
        "approval_request_count": _count(perf_events, "approval_requested"),
        "restart_count": _count(perf_events, "restart_started") or _health_restart_count(health),
        "supervisor_context_tokens_total_est": sum(context_tokens),
        "supervisor_context_tokens_mean_est": (sum(context_tokens) / len(context_tokens)) if context_tokens else None,
        "supervisor_context_tokens_max_est": max(context_tokens) if context_tokens else None,
        "supervisor_context_truncation_count": sum(
            1 for event in supervisor_contexts if event.get("truncated_sections")
        ),
    }
    metrics.update(compute_token_metrics(perf_events, supervisor_call_count=supervisor_call_count))
    return {name: metrics.get(name) for name in METRIC_NAMES}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _first_time(events: list[dict[str, Any]], event_name: str) -> int | None:
    for event in events:
        if event.get("event") == event_name:
            return _monotonic_ms(event)
    return None


def _last_time(events: list[dict[str, Any]], event_name: str) -> int | None:
    for event in reversed(events):
        if event.get("event") == event_name:
            return _monotonic_ms(event)
    return None


def _monotonic_ms(event: dict[str, Any]) -> int | None:
    value = event.get("monotonic_ms")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return None


def _duration(start: int | None, finish: int | None) -> int | None:
    if start is None or finish is None:
        return None
    return max(0, finish - start)


def _paired_duration(events: list[dict[str, Any]], start_event: str, finish_event: str, id_field: str) -> int:
    starts: dict[Any, int] = {}
    total = 0
    anonymous_starts: list[int] = []
    for event in events:
        name = event.get("event")
        event_time = _monotonic_ms(event)
        if event_time is None:
            continue
        pair_id = event.get(id_field)
        if name == start_event:
            if pair_id is None:
                anonymous_starts.append(event_time)
            else:
                starts[pair_id] = event_time
        elif name == finish_event:
            start_time = starts.pop(pair_id, None) if pair_id is not None else None
            if start_time is None and anonymous_starts:
                start_time = anonymous_starts.pop(0)
            if start_time is not None:
                total += max(0, event_time - start_time)
    return total


def _validation_time(events: list[dict[str, Any]]) -> int:
    explicit = [
        event["duration_ms"]
        for event in events
        if event.get("event") == "validation_finished" and isinstance(event.get("duration_ms"), int | float)
    ]
    if explicit:
        return int(sum(explicit))
    return _paired_duration(events, "validation_started", "validation_finished", "validation_id")


def _count(events: list[dict[str, Any]], event_name: str) -> int:
    return sum(1 for event in events if event.get("event") == event_name)


def _completed_action_count(events: list[dict[str, Any]]) -> int:
    return sum(
        1
        for event in events
        if event.get("event_type") == "item/completed"
        and isinstance(event.get("reason"), str)
        and "completed:" in event["reason"]
    )


def _health_restart_count(health: Any) -> int:
    if isinstance(health, dict) and isinstance(health.get("restart_count"), int):
        return health["restart_count"]
    return 0


def _ratio(numerator: int | float | None, denominator: int | float | None) -> float | None:
    if numerator is None or denominator in {None, 0}:
        return None
    return numerator / denominator
