from __future__ import annotations

from pathlib import Path
from typing import Any

from supervisor.controller import SentinelController, _merge_behavior_surface_items
from supervisor.prompts import build_completion_review_prompt
from supervisor.schemas import (
    BehaviorSurfaceItem,
    CompletionDecisionArtifact,
    CompletionReviewDecision,
    SentinelConfig,
    SupervisorWakePacket,
)
from supervisor.schemas.models import openai_strict_json_schema_for_completion_review_decision
from supervisor.state import StateStore


def _make_decision(**overrides: Any) -> CompletionReviewDecision:
    base: dict[str, Any] = dict(
        decision="return",
        reason="required behavior missing",
        message_to_coder="fix the unsigned comparison; run the failing check first",
        validation_gaps=["unsigned comparison diverges from required semantics"],
        decision_artifact=CompletionDecisionArtifact(
            current_state="implementation present, one required behavior wrong",
            actionable_gap_or_none="unsigned comparison diverges",
            uncovered_edge_candidates=["large-constant switch cases may be unhandled"],
        ),
        persistent_decision=None,
        progress_update="returned for unsigned comparison defect",
        clear_handoff=False,
        display_message=None,
        handoff=None,
        wake_sequence=1,
        generation=0,
    )
    base.update(overrides)
    return CompletionReviewDecision(**base)


def _knowledge_controller() -> SentinelController:
    # Knowledge is in-memory on the controller; no store needed for these paths.
    return SentinelController.__new__(SentinelController)


# --- _merge_behavior_surface_items (pure) ---


def test_merge_dedups_case_and_whitespace_insensitively() -> None:
    existing = [{"category": "Unsigned conversions", "status": "required", "note": None}]
    merged, changed = _merge_behavior_surface_items(
        existing,
        [
            BehaviorSurfaceItem(category="unsigned   CONVERSIONS", status="required", note=None),
            BehaviorSurfaceItem(category="Rejection of invalid input", status="required", note=None),
        ],
    )
    assert changed
    assert [item["category"] for item in merged] == ["Unsigned conversions", "Rejection of invalid input"]


def test_merge_never_deletes_entries_missing_from_update() -> None:
    existing = [
        {"category": "A", "status": "required", "note": None},
        {"category": "B", "status": "required", "note": None},
    ]
    merged, changed = _merge_behavior_surface_items(
        existing,
        [BehaviorSurfaceItem(category="C", status="required", note=None)],
    )
    assert changed
    assert [item["category"] for item in merged] == ["A", "B", "C"]


def test_merge_updates_status_to_out_of_scope_without_removal() -> None:
    existing = [{"category": "A", "status": "required", "note": None}]
    merged, changed = _merge_behavior_surface_items(
        existing,
        [BehaviorSurfaceItem(category="a", status="out_of_scope", note="task does not require it")],
    )
    assert changed
    assert merged == [{"category": "A", "status": "out_of_scope", "note": "task does not require it"}]


def test_merge_reports_no_change_for_identical_update() -> None:
    existing = [{"category": "A", "status": "required", "note": None}]
    merged, changed = _merge_behavior_surface_items(
        existing,
        [BehaviorSurfaceItem(category="A", status="required", note=None)],
    )
    assert not changed
    assert merged == existing


def test_merge_ignores_blank_categories() -> None:
    merged, changed = _merge_behavior_surface_items(
        [],
        [BehaviorSurfaceItem(category="   ", status="required", note=None)],
    )
    assert not changed
    assert merged == []


# --- in-memory knowledge accumulates across successive reviews of one run ---


def test_completion_knowledge_accumulates_across_reviews() -> None:
    # A single controller object stands in for the whole run: successive completion reviews (and
    # any in-run restart, which reuses this object) feed the same in-memory knowledge.
    controller = _knowledge_controller()
    controller._record_completion_knowledge(
        _make_decision(
            behavior_surface=[
                BehaviorSurfaceItem(category="Unsigned conversions", status="required", note=None),
                BehaviorSurfaceItem(category="Rejection of invalid input", status="required", note=None),
            ]
        )
    )
    categories = [item.category for item in controller._behavior_surface_items()]
    assert categories == ["Unsigned conversions", "Rejection of invalid input"]
    assert controller._completion_knowledge()["uncovered_edge_candidates"] == [
        "large-constant switch cases may be unhandled"
    ]

    # A later reviewer adding one category never deletes earlier entries, and its (now empty)
    # suspicion list replaces the carried one.
    controller._record_completion_knowledge(
        _make_decision(
            behavior_surface=[BehaviorSurfaceItem(category="Aggregate initializers", status="required", note=None)],
            decision_artifact=CompletionDecisionArtifact(
                current_state="second pass",
                actionable_gap_or_none="aggregate initializers wrong",
                uncovered_edge_candidates=[],
            ),
        )
    )
    categories = [item.category for item in controller._behavior_surface_items()]
    assert categories == ["Unsigned conversions", "Rejection of invalid input", "Aggregate initializers"]
    assert controller._completion_knowledge()["uncovered_edge_candidates"] == []


def test_completion_knowledge_is_not_backed_by_workspace_file(tmp_path: Path) -> None:
    # The knowledge must never touch the coder-writable workspace/.supervisor dir (forgery and
    # parse-crash vectors); recording writes nothing under the state dir.
    store = StateStore(tmp_path)
    controller = SentinelController.__new__(SentinelController)
    controller.store = store
    before = sorted(p.name for p in store.state_dir.iterdir())
    controller._record_completion_knowledge(
        _make_decision(behavior_surface=[BehaviorSurfaceItem(category="A", status="required", note=None)])
    )
    after = sorted(p.name for p in store.state_dir.iterdir())
    assert before == after
    assert not (store.state_dir / "completion_knowledge.json").exists()


def test_completion_knowledge_ignores_empty_decision() -> None:
    controller = _knowledge_controller()
    controller._record_completion_knowledge(
        _make_decision(
            behavior_surface=[],
            decision_artifact=None,
            # decision_artifact=None is only valid alongside a gap-bearing return per prompt,
            # but the model allows it; knowledge recording must not crash or record anything.
        )
    )
    assert controller._completion_knowledge() == {
        "behavior_surface": [],
        "uncovered_edge_candidates": [],
    }


# --- completion review timeout retry ---


class _StubSupervisor:
    def __init__(self) -> None:
        self.closed = 0
        self.completion_thread_id = "thread-old"

    async def close_completion_review(self) -> None:
        self.closed += 1


async def test_completion_review_timeout_retries_once_then_gives_up(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )
    controller = SentinelController.__new__(SentinelController)
    controller.store = store
    controller.supervisor = _StubSupervisor()
    controller.provider_failure_recovery_counts = {}
    controller._sequence = 0
    controller._supervisor_dirty = False
    controller._supervisor_next_summary = None
    controller._supervisor_next_completion_review = False

    recovered = await controller._handle_completion_review_timeout_failure(
        message="supervisor check failed (tool_timeout): timed out after 2400s",
        summary="Coder provided exact readiness marker; running completion_review.",
    )
    assert recovered is True
    assert controller.supervisor.closed == 1
    assert controller._supervisor_dirty is True
    assert controller._supervisor_next_completion_review is True
    assert "fresh thread" in (controller._supervisor_next_summary or "")

    # Second consecutive timeout exhausts the budget and falls through to the fatal path.
    recovered = await controller._handle_completion_review_timeout_failure(
        message="supervisor check failed (tool_timeout): timed out again",
        summary="retry summary",
    )
    assert recovered is False


# --- schema and packet surface ---


def test_decision_schema_includes_behavior_surface() -> None:
    schema = openai_strict_json_schema_for_completion_review_decision()
    assert "behavior_surface" in schema["properties"]
    decision = _make_decision(
        behavior_surface=[BehaviorSurfaceItem(category="A", status="required", note=None)]
    )
    payload = decision.model_dump(mode="json")
    assert payload["behavior_surface"] == [{"category": "A", "status": "required", "note": None}]


def test_completion_packet_carries_surface_and_prior_candidates() -> None:
    packet = SupervisorWakePacket(
        wake_sequence=1,
        latest_event_sequence=1,
        generation=0,
        restart_count=0,
        task_path="TASK.md",
        task_contents="# Task",
        behavior_surface=[BehaviorSurfaceItem(category="A", status="required", note=None)],
        prior_uncovered_edge_candidates=["maybe B"],
    )
    prompt = build_completion_review_prompt(packet)
    assert '"behavior_surface"' in prompt
    assert "maybe B" in prompt
