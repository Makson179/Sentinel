from __future__ import annotations

import json
import subprocess
from pathlib import Path

from supervisor.controller import (
    ValidationCommandClassification,
    _classify_validation_command_tri_state,
    _validation_from_action,
)
from supervisor.gates.completion_preflight import (
    AcceptanceFacts,
    CompletionAttempt,
    CompletionPreflightDisposition,
    certainly_missing_required_behavioral_validation,
    evaluate_completion_preflight,
    evaluate_final_behavioral_floor,
)
from supervisor.gates.runtime_wake import RuntimeWakeGate, RuntimeWakeGateDecision
from supervisor.schemas import Certainty, ChangedFile, ChangedFileDiff, CoderMessage, SentinelConfig, TriggeringAction, ValidationRun
from supervisor.schemas.models import CompletionReviewDecision, SupervisorWakePacket
from supervisor.state import LOG, StateStore
from supervisor.workspace_state import WorkspaceState, capture_workspace_state
from tests.test_sentinel_state import _covered_accept_decision, _completion_gate_controller, _runtime_controller


def test_runtime_wake_gate_has_no_approval_actions_and_coalesces_large_diff() -> None:
    assert "approve" not in RuntimeWakeGateDecision.model_fields["action"].annotation.__args__
    assert "deny" not in RuntimeWakeGateDecision.model_fields["action"].annotation.__args__

    gate = RuntimeWakeGate()
    action = TriggeringAction(kind="commandExecution", command="python app.py", exit_code=0, status="completed", summary="ok")
    changed = [ChangedFile(path="src/app.py", status="M", additions=700, deletions=0)]

    first = gate.evaluate(
        generation=0,
        turn_id="turn",
        reasons=["large_diff"],
        action=action,
        changed_files=changed,
        validation=None,
        pending_approval_ids=[],
    )
    same_band = gate.evaluate(
        generation=0,
        turn_id="turn",
        reasons=["large_diff"],
        action=action,
        changed_files=[ChangedFile(path="src/app.py", status="M", additions=701, deletions=0)],
        validation=None,
        pending_approval_ids=[],
    )
    flushed = gate.flush_turn_end(generation=0, turn_id="turn")

    assert first.action == "emit_wake"
    assert same_band.action == "coalesce_until_turn_end"
    assert flushed is not None
    assert flushed.action == "emit_wake"
    assert "turn_end_coalesced_flush" in flushed.reason_codes


def test_runtime_wake_gate_suppresses_exact_duplicate() -> None:
    gate = RuntimeWakeGate()
    action = TriggeringAction(kind="commandExecution", command="pytest -q", exit_code=1, status="completed", summary="failed")
    validation = ValidationRun(command="pytest -q", exit_code=1, passed=False, summary="failed", sequence=3)

    first = gate.evaluate(
        generation=1,
        turn_id="turn",
        reasons=["nonzero_exit"],
        action=action,
        changed_files=[],
        validation=validation,
        pending_approval_ids=[],
    )
    second = gate.evaluate(
        generation=1,
        turn_id="turn",
        reasons=["nonzero_exit"],
        action=action,
        changed_files=[],
        validation=validation,
        pending_approval_ids=[],
    )

    assert first.action == "emit_wake"
    assert second.action == "suppress_exact_duplicate"


def test_completion_preflight_certainty_never_hard_returns_unknown() -> None:
    facts = AcceptanceFacts(
        completion_attempt_id="attempt",
        generation=0,
        final_workspace_state=WorkspaceState(certainty=Certainty.UNKNOWN, unknown_reasons=["hash_failed"]),
        changed_files=[ChangedFile(path="src/app.py", status="M", sequence=2)],
        latest_relevant_change_sequence=2,
        validations=[],
    )

    assert certainly_missing_required_behavioral_validation(facts) is Certainty.UNKNOWN
    result = evaluate_completion_preflight(facts)
    assert result.disposition == CompletionPreflightDisposition.REVIEW
    assert result.uncertainty_reasons


def test_completion_preflight_hard_gap_implies_shared_final_floor_failure() -> None:
    facts = AcceptanceFacts(
        completion_attempt_id="attempt",
        generation=0,
        final_workspace_state=WorkspaceState(state_id="workspace-final", certainty=Certainty.TRUE),
        changed_files=[ChangedFile(path="src/app.py", status="M", sequence=2)],
        latest_relevant_change_sequence=2,
        validations=[],
    )

    result = evaluate_completion_preflight(facts)

    assert result.disposition == CompletionPreflightDisposition.CERTAINLY_INADMISSIBLE
    assert evaluate_final_behavioral_floor(facts) is Certainty.FALSE


def test_completion_preflight_accepts_validation_bound_to_final_state() -> None:
    validation = ValidationRun(
        command="pytest tests/test_app.py",
        exit_code=0,
        passed=True,
        summary="1 passed",
        sequence=3,
        workspace_state_after_id="workspace-final",
    )
    facts = AcceptanceFacts(
        completion_attempt_id="attempt",
        generation=0,
        final_workspace_state=WorkspaceState(state_id="workspace-final", certainty=Certainty.TRUE),
        changed_files=[ChangedFile(path="src/app.py", status="M", sequence=2)],
        latest_relevant_change_sequence=2,
        validations=[validation],
    )

    result = evaluate_completion_preflight(facts)

    assert result.disposition == CompletionPreflightDisposition.REVIEW
    assert evaluate_final_behavioral_floor(facts) is Certainty.TRUE


def test_validation_signature_is_stable_but_run_id_changes() -> None:
    action = TriggeringAction(
        item_id="cmd-1",
        kind="commandExecution",
        command="pytest tests/test_app.py -q",
        exit_code=0,
        status="completed",
        summary="command completed",
    )

    first = _validation_from_action(action, sequence=3, item={"stdout": "tests/test_app.py::test_app PASSED\n1 passed\n"}, generation=0)
    second = _validation_from_action(
        action.model_copy(update={"item_id": "cmd-2"}),
        sequence=4,
        item={"stdout": "tests/test_app.py::test_app PASSED\n1 passed\n"},
        generation=0,
    )

    assert first is not None and second is not None
    assert first.validation_id == second.validation_id
    assert first.validation_signature_id == second.validation_signature_id
    assert first.validation_run_id != second.validation_run_id


def test_tri_state_command_classification_keeps_inspection_and_unknown_distinct() -> None:
    assert (
        _classify_validation_command_tri_state("sed -n '1,100p' tests/test_x.py")
        == ValidationCommandClassification.DEFINITE_NON_VALIDATION
    )
    assert _classify_validation_command_tri_state("echo '20 tests passed'") == ValidationCommandClassification.DEFINITE_NON_VALIDATION
    assert _classify_validation_command_tri_state("python -m pytest tests/public -v") == ValidationCommandClassification.DEFINITE_BEHAVIORAL
    assert _classify_validation_command_tri_state("python -m py_compile src/app.py") == ValidationCommandClassification.DEFINITE_STATIC
    assert _classify_validation_command_tri_state("./check.sh") == ValidationCommandClassification.UNCERTAIN
    assert _classify_validation_command_tri_state("make custom-check") == ValidationCommandClassification.UNCERTAIN


def test_workspace_state_fingerprint_changes_for_relevant_edit_and_ignores_cache(tmp_path: Path) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True, text=True)
    (tmp_path / "src.py").write_text("value = 1\n", encoding="utf-8")
    subprocess.run(["git", "add", "src.py"], cwd=tmp_path, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "init"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )

    clean = capture_workspace_state(tmp_path)
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "src.pyc").write_bytes(b"cache")
    ignored_cache = capture_workspace_state(tmp_path)
    (tmp_path / "src.py").write_text("value = 2\n", encoding="utf-8")
    edited = capture_workspace_state(tmp_path)

    assert clean.certainty is Certainty.TRUE
    assert ignored_cache.state_id == clean.state_id
    assert edited.certainty is Certainty.TRUE
    assert edited.state_id != clean.state_id


def test_workspace_state_unknown_for_non_git_and_unsafe_symlink(tmp_path: Path) -> None:
    assert capture_workspace_state(tmp_path).certainty is Certainty.UNKNOWN

    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True, text=True)
    outside = tmp_path.parent / "outside-target"
    outside.write_text("secret", encoding="utf-8")
    (tmp_path / "link").symlink_to(outside)
    state = capture_workspace_state(tmp_path)

    assert state.certainty is Certainty.UNKNOWN
    assert any(reason.startswith("unsafe_symlink") for reason in state.unknown_reasons)


async def test_controller_preflight_evidence_request_does_not_consume_return_budget(tmp_path: Path) -> None:
    controller, store, fake = _runtime_controller(tmp_path)
    store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"completion_preflight_gate_mode": "enforce"}))
    controller.last_coder_message = CoderMessage(text="Summary\nSENTINEL_READY_FOR_REVIEW", sequence=3)
    controller.observed_changed_files = {"src/app.py": ChangedFile(path="src/app.py", status="modified", sequence=2)}

    class FakeCoder:
        def __init__(self) -> None:
            self.messages: list[str] = []

        async def steer_or_start(self, message: str):
            self.messages.append(message)
            return "turn"

    async def known_state(*, boundary: str) -> WorkspaceState:
        return WorkspaceState(state_id="workspace-final", certainty=Certainty.TRUE)

    coder = FakeCoder()
    controller.coder = coder
    controller._capture_workspace_state_safe = known_state  # type: ignore[method-assign]

    await controller._handle_coder_turn_completed(item_id="done-1")

    assert coder.messages
    assert "Completion review was not started" in coder.messages[0]
    assert controller.completion_returns == []
    assert fake.runtime_packets == []
    assert fake.completion_packets == []
    assert store.get_sentinel_config().generation == 0


async def test_workspace_mismatch_discards_completion_decision_without_coder_return(tmp_path: Path) -> None:
    controller, store, task, coder = _completion_gate_controller(
        tmp_path,
        validations=[ValidationRun(command="pytest tests/test_app.py", exit_code=0, passed=True, summary="passed", sequence=3)],
    )

    async def changed_state(*, boundary: str) -> WorkspaceState:
        return WorkspaceState(state_id="workspace-after", certainty=Certainty.TRUE)

    controller._capture_workspace_state_safe = changed_state  # type: ignore[method-assign]
    packet = SupervisorWakePacket(
        wake_sequence=1,
        latest_event_sequence=1,
        generation=0,
        restart_count=0,
        task_path=str(task),
        task_contents="# Task",
        coder_thread_id="thread",
        changed_files=[ChangedFile(path="src/app.py", status="M", sequence=2)],
        validations=controller.validations,
        latest_relevant_change_sequence=2,
        completion_attempt_id="attempt",
        review_workspace_state_id="workspace-before",
    )

    await controller.apply_completion_decision(_covered_accept_decision(wake_sequence=1), packet_thread_id="thread", packet=packet)

    assert store.get_sentinel_config().last_applied_supervisor_sequence == 0
    assert controller.completion_returns == []
    assert coder.messages == []
    assert "discarded" in store.path("PROGRESS.md").read_text(encoding="utf-8")


def test_packet_budget_manifest_writes_artifacts_and_can_fallback(tmp_path: Path) -> None:
    controller, store, _fake = _runtime_controller(tmp_path)
    store.update_sentinel_config(
        lambda cfg: cfg.model_copy(update={"packet_budget_gate_mode": "enforce", "completion_packet_manifest_threshold_chars": 10})
    )
    details = {"changed_file_diffs": [], "changed_file_contexts": [], "validation_outputs": [], "inspection_outputs": []}
    details["changed_file_diffs"] = [
        type("Diff", (), {"path": "src/app.py", "diff": "+" + "x" * 100, "diff_truncated": False})()
    ]

    mode, manifest, reduced = controller._maybe_apply_packet_budget_gate(
        mode="full",
        completion_attempt_id="attempt-1",
        workspace_state_id="workspace-final",
        completion_details=details,
    )

    assert mode == "manifest"
    assert manifest is not None
    assert reduced["changed_file_diffs"] == []
    artifact_path = tmp_path / manifest["artifacts"][0]["storage_path"]
    assert artifact_path.exists()
    assert "x" * 20 in artifact_path.read_text(encoding="utf-8")


def test_synthetic_replay_reports_fewer_runtime_calls_and_smaller_manifest_packet(tmp_path: Path) -> None:
    gate = RuntimeWakeGate()
    action = TriggeringAction(kind="commandExecution", command="python app.py", exit_code=0, status="completed", summary="ok")
    old_runtime_calls = 0
    new_runtime_calls = 0
    for index in range(6):
        old_runtime_calls += 1
        decision = gate.evaluate(
            generation=0,
            turn_id="turn",
            reasons=["large_diff"],
            action=action,
            changed_files=[ChangedFile(path="src/app.py", status="M", additions=700 + index, deletions=0)],
            validation=None,
            pending_approval_ids=[],
        )
        if decision.action == "emit_wake":
            new_runtime_calls += 1
    if gate.flush_turn_end(generation=0, turn_id="turn") is not None:
        new_runtime_calls += 1

    controller, store, _fake = _runtime_controller(tmp_path)
    store.update_sentinel_config(
        lambda cfg: cfg.model_copy(update={"packet_budget_gate_mode": "enforce", "completion_packet_manifest_threshold_chars": 10})
    )
    large_diff = "+" + "x" * 10_000
    details = {
        "changed_file_diffs": [
            ChangedFileDiff(path="src/app.py", file_kind="source", change_kind="modified", diff=large_diff)
        ],
        "changed_file_contexts": [],
        "validation_outputs": [],
        "inspection_outputs": [],
    }
    old_packet_chars = len(json.dumps(details, default=str, sort_keys=True))
    mode, manifest, reduced = controller._maybe_apply_packet_budget_gate(
        mode="full",
        completion_attempt_id="attempt-replay",
        workspace_state_id="workspace-final",
        completion_details=details,
    )
    new_packet_chars = len(json.dumps({"mode": mode, "manifest": manifest, "details": reduced}, default=str, sort_keys=True))

    assert old_runtime_calls == 6
    assert new_runtime_calls == 2
    assert mode == "manifest"
    assert new_packet_chars < old_packet_chars
