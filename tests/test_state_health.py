from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from supervisor.health import patch_health
from supervisor.schemas import HealthDelta
from supervisor.state import HEALTH, StateStore


def test_health_concurrent_delta_application(store: StateStore) -> None:
    def increment() -> None:
        patch_health(store, HealthDelta(generation=0, denied_requests=1, interventions=1))

    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(lambda _: increment(), range(100)))

    health = store.get_health()
    assert health.denied_requests == 100
    assert health.interventions == 100


def test_progress_update_preserves_active_task_intervention_count(store: StateStore) -> None:
    patch_health(store, HealthDelta(generation=0, interventions=2))
    patch_health(store, HealthDelta(generation=0, last_progress_sequence=1071))

    health = store.get_health()
    assert health.last_progress_sequence == 1071
    assert health.interventions == 2


def test_atomic_write_behavior(store: StateStore) -> None:
    store.write_json_locked(HEALTH, {"generation": 0, "restart_count": 2})
    assert json.loads(store.path(HEALTH).read_text(encoding="utf-8"))["restart_count"] == 2
    assert not list(store.state_dir.glob("*.tmp"))


def test_recent_action_history_is_capped(store: StateStore) -> None:
    for index in range(12):
        store.append_recent_action(f"action {index}")

    assert store.read_recent_actions() == [f"action {index}" for index in range(2, 12)]
