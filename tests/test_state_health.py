from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from supervisor.health import patch_health
from supervisor.schemas import HealthDelta, PendingIntervention
from supervisor.state import HEALTH, StateStore


def test_health_concurrent_delta_application(store: StateStore) -> None:
    def increment() -> None:
        patch_health(store, HealthDelta(generation=0, denied_requests=1, interventions=1))

    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(lambda _: increment(), range(100)))

    health = store.get_health()
    assert health.denied_requests == 100
    assert health.interventions == 100


def test_pending_intervention_claim_clear_is_atomic(store: StateStore) -> None:
    store.write_pending(PendingIntervention(generation=0, sequence=10, message="Fix the approach."))

    def claim() -> str | None:
        pending = store.claim_pending(0)
        return pending.message if pending else None

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda _: claim(), range(20)))

    assert results.count("Fix the approach.") == 1
    assert store.read_pending() is None


def test_pending_replacement_requires_higher_sequence(store: StateStore) -> None:
    store.write_pending(PendingIntervention(generation=0, sequence=10, message="old"))
    store.write_pending(PendingIntervention(generation=0, sequence=9, message="stale"))
    store.write_pending(PendingIntervention(generation=0, sequence=11, message="new"))
    assert store.read_pending().message == "new"


def test_atomic_write_behavior(store: StateStore) -> None:
    store.write_json_locked(HEALTH, {"generation": 0, "restart_count": 2})
    assert json.loads(store.path(HEALTH).read_text(encoding="utf-8"))["restart_count"] == 2
    assert not list(store.state_dir.glob("*.tmp"))

