from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from supervisor.prompts import (
    PROMPTS_ENV_VAR,
    build_adv_report_controller_prompt,
    build_completion_review_prompt,
    build_coder_prompt,
    build_restart_prompt,
    build_stateless_supervisor_prompt,
)
from supervisor.schemas.models import (
    AdvReportControllerDecision,
    AdversaryReport,
    ApprovalWakeContext,
    HumanMessage,
    CompletionDecisionArtifact,
    CompletionReviewDecision,
    RestartHandoff,
    SupervisorDecision,
    SupervisorWakePacket,
    TriggeringAction,
    openai_strict_json_schema_for_adv_report_controller_decision,
    openai_strict_json_schema_for_completion_review_decision,
    openai_strict_json_schema_for_supervisor_decision,
)


def _walk_schema(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_schema(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_schema(item)


def test_supervisor_decision_schema_is_strict() -> None:
    schema = openai_strict_json_schema_for_supervisor_decision()

    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])
    assert "handoff" in schema["properties"]
    handoff_schema = schema["$defs"]["RestartHandoff"]
    assert set(handoff_schema["required"]) == set(handoff_schema["properties"])
    assert "complete" not in schema["$defs"]["SupervisorDecisionKind"]["enum"]


def test_completion_review_decision_schema_is_strict() -> None:
    schema = openai_strict_json_schema_for_completion_review_decision()

    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])
    assert schema["$defs"]["CompletionReviewDecisionKind"]["enum"] == ["accept", "return", "restart"]
    assert "ReviewedFile" in schema["$defs"]
    assert "BehaviorEvidence" in schema["$defs"]
    assert "EvidenceItem" in schema["$defs"]
    assert "CompletionDecisionArtifact" in schema["$defs"]
    assert "decision_artifact" in schema["properties"]
    assert "basis_event_seq" in schema["properties"]
    assert "last_relevant_edit_seq" in schema["properties"]
    assert "last_validation_seq" in schema["properties"]
    assert "validation_id" in schema["$defs"]["EvidenceItem"]["properties"]


def test_adv_report_controller_decision_schema_and_shapes_are_strict() -> None:
    schema = openai_strict_json_schema_for_adv_report_controller_decision()

    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])

    forwarded = AdvReportControllerDecision.model_validate(
        {
            "forward_to_coder": True,
            "reason": "one finding retained and one observation carried forward",
            "report_to_coder": "## Findings requiring correction\n\nCrash reproduced.",
            "material_coverage_limitations": ["external database path was not reached"],
        }
    )
    clean = AdvReportControllerDecision.model_validate(
        {
            "forward_to_coder": False,
            "reason": "no findings or observations remain",
            "report_to_coder": None,
            "material_coverage_limitations": [],
        }
    )

    assert forwarded.forward_to_coder is True
    assert forwarded.material_coverage_limitations == ["external database path was not reached"]
    assert clean.report_to_coder is None

    normalized = AdvReportControllerDecision(
        forward_to_coder=False,
        reason="no routed items",
        report_to_coder=None,
        material_coverage_limitations=[
            "  external database path was not reached  ",
            "",
            "external database path was not reached",
        ],
    )
    assert normalized.material_coverage_limitations == ["external database path was not reached"]

    with pytest.raises(ValueError, match="requires report_to_coder"):
        AdvReportControllerDecision(
            forward_to_coder=True,
            reason="missing report",
            report_to_coder=None,
        )
    with pytest.raises(ValueError, match="report_to_coder=null"):
        AdvReportControllerDecision(
            forward_to_coder=False,
            reason="unexpected report",
            report_to_coder="should not be present",
        )
    with pytest.raises(ValueError, match="forbidden"):
        AdvReportControllerDecision(
            forward_to_coder=True,
            reason="coverage leaked",
            report_to_coder=(
                "## Findings requiring correction\n\nCrash reproduced.\n\n"
                "not_reached: external database unavailable"
            ),
        )
    with pytest.raises(ValueError, match="forbidden"):
        AdvReportControllerDecision(
            forward_to_coder=True,
            reason="overall leaked",
            report_to_coder="## Overall\n\nDefects remain.",
        )


def test_completion_review_decision_accepts_expected_shapes() -> None:
    accept = CompletionReviewDecision.model_validate(
        {
            "decision": "accept",
            "reason": "validated",
            "decision_artifact": {
                "current_state": "validated current workspace",
                "resolved_concerns": ["basic flow covered"],
                "stale_concerns": [],
                "uncovered_edge_candidates": [],
                "actionable_gap_or_none": None,
            },
            "basis_event_seq": 10,
            "last_relevant_edit_seq": 8,
            "last_validation_seq": 9,
            "files_reviewed": [
                {"path": "src/app.py", "reason": "changed source", "kind": "source", "inspected": True, "limitation": None}
            ],
            "behavior_evidence_matrix": [
                {
                    "behavior": "returns configured value",
                    "task_basis": "TASK.md",
                    "files_considered": ["src/app.py", "tests/test_app.py"],
                    "evidence": [
                        {
                            "validation_id": "validation-9",
                            "command": "pytest tests/test_app.py",
                            "sequence": 9,
                            "validation_type": "behavioral",
                            "outcome": "pass",
                            "freshness": "fresh",
                            "why_it_covers_behavior": "executes the changed code path",
                        }
                    ],
                    "status": "covered",
                    "gap": None,
                }
            ],
            "uncovered_behaviors": [],
            "validation_gaps": [],
            "claim_evidence_mismatches": [],
            "packet_or_access_limitations": [],
            "changed_test_risks": [],
            "message_to_coder": None,
            "persistent_decision": None,
            "progress_update": "Accepted by completion review.",
            "clear_handoff": False,
            "display_message": None,
            "handoff": None,
            "wake_sequence": 10,
            "generation": 0,
        }
    )

    assert accept.decision == "accept"
    assert accept.decision_artifact == CompletionDecisionArtifact(
        current_state="validated current workspace",
        resolved_concerns=["basic flow covered"],
        stale_concerns=[],
        uncovered_edge_candidates=[],
        actionable_gap_or_none=None,
    )


@pytest.mark.parametrize(
    ("updates", "blocker_field"),
    [
        ({"validation_gaps": ["missing behavioral validation"]}, "validation_gaps"),
        ({"uncovered_behaviors": ["required fallback"]}, "uncovered_behaviors"),
        ({"claim_evidence_mismatches": ["readiness claim exceeds evidence"]}, "claim_evidence_mismatches"),
        ({"packet_or_access_limitations": ["required artifact was not inspectable"]}, "packet_or_access_limitations"),
        ({"changed_test_risks": ["required assertion was removed"]}, "changed_test_risks"),
        (
            {
                "decision_artifact": {
                    "current_state": "one required behavior remains open",
                    "resolved_concerns": [],
                    "stale_concerns": [],
                    "uncovered_edge_candidates": [],
                    "actionable_gap_or_none": "implement the required fallback",
                }
            },
            "decision_artifact.actionable_gap_or_none",
        ),
        (
            {
                "behavior_evidence_matrix": [
                    {
                        "behavior": "required fallback",
                        "task_basis": "TASK.md",
                        "status": "partial",
                        "gap": None,
                    }
                ]
            },
            "behavior_evidence_matrix.status",
        ),
        (
            {
                "behavior_evidence_matrix": [
                    {
                        "behavior": "required fallback",
                        "task_basis": "TASK.md",
                        "status": "covered",
                        "gap": "error path remains unverified",
                    }
                ]
            },
            "behavior_evidence_matrix.gap",
        ),
    ],
)
def test_completion_review_accept_rejects_typed_blockers(
    updates: dict[str, object],
    blocker_field: str,
) -> None:
    payload: dict[str, object] = {
        "decision": "accept",
        "reason": "validated",
        "message_to_coder": None,
        "persistent_decision": None,
        "progress_update": "Accepted by completion review.",
        "clear_handoff": False,
        "display_message": None,
        "handoff": None,
        "wake_sequence": 10,
        "generation": 0,
    }
    payload.update(updates)

    with pytest.raises(ValueError, match=blocker_field.replace(".", r"\.")):
        CompletionReviewDecision.model_validate(payload)


def test_completion_review_accept_allows_nonblocking_edge_candidates() -> None:
    decision = CompletionReviewDecision.model_validate(
        {
            "decision": "accept",
            "reason": "all required behavior is correct",
            "decision_artifact": {
                "current_state": "required behavior validated",
                "resolved_concerns": [],
                "stale_concerns": [],
                "uncovered_edge_candidates": ["optional hardening may be worth exploring later"],
                "actionable_gap_or_none": None,
            },
            "message_to_coder": None,
            "persistent_decision": None,
            "progress_update": "Accepted by completion review.",
            "clear_handoff": False,
            "display_message": None,
            "handoff": None,
            "wake_sequence": 10,
            "generation": 0,
        }
    )

    assert decision.decision == "accept"


def test_completion_review_decision_accepts_minimal_return_without_full_review_artifact() -> None:
    decision = CompletionReviewDecision.model_validate(
        {
            "decision": "return",
            "reason": "one real gap blocks acceptance",
            "decision_artifact": {
                "current_state": "implementation needs one targeted regression",
                "resolved_concerns": [],
                "stale_concerns": [],
                "uncovered_edge_candidates": ["stack-passed call arguments"],
                "actionable_gap_or_none": "validate more than six call arguments",
            },
            "basis_event_seq": 12,
            "last_relevant_edit_seq": 10,
            "last_validation_seq": 11,
            "uncovered_behaviors": ["stack-passed call arguments"],
            "validation_gaps": ["no regression covers more than six call arguments"],
            "claim_evidence_mismatches": [],
            "packet_or_access_limitations": [],
            "changed_test_risks": [],
            "message_to_coder": "Add and pass a regression for calls with more than six integer arguments.",
            "persistent_decision": None,
            "progress_update": None,
            "clear_handoff": False,
            "display_message": None,
            "handoff": None,
            "wake_sequence": 12,
            "generation": 0,
        }
    )

    assert decision.decision == "return"
    assert decision.files_reviewed == []
    assert decision.behavior_evidence_matrix == []
    assert decision.decision_artifact is not None
    assert decision.decision_artifact.actionable_gap_or_none == "validate more than six call arguments"


def test_supervisor_decision_accepts_expected_shape() -> None:
    decision = SupervisorDecision.model_validate(
        {
            "decision": "approve",
            "approval_decision": "accept",
            "execpolicy_amendment": None,
            "reason": "ok",
            "message_to_coder": None,
            "persistent_decision": None,
            "progress_update": None,
            "clear_handoff": True,
            "display_message": None,
        }
    )

    assert decision.decision == "approve"
    assert decision.clear_handoff is True


def test_supervisor_decision_accepts_structured_restart_handoff() -> None:
    handoff = {
        "objective": "Fix parser tests",
        "restart_reason": "same loop after steering",
        "bad_pattern": "rerunning tests without reading assertion",
        "known_evidence": "failure is in test_parser",
        "next_step": "read the assertion",
        "recovery_signal": "coder opens the failing test first",
    }

    restart = SupervisorDecision.model_validate(
        {
            "decision": "restart",
            "approval_decision": None,
            "execpolicy_amendment": None,
            "reason": "loop",
            "message_to_coder": None,
            "persistent_decision": None,
            "progress_update": None,
            "clear_handoff": False,
            "display_message": None,
            "handoff": handoff,
            "wake_sequence": 7,
            "generation": 1,
        }
    )
    noop = SupervisorDecision.model_validate(
        {
            "decision": "noop",
            "approval_decision": None,
            "execpolicy_amendment": None,
            "reason": "ok",
            "message_to_coder": None,
            "persistent_decision": None,
            "progress_update": None,
            "clear_handoff": False,
            "display_message": None,
            "handoff": None,
            "wake_sequence": 8,
            "generation": 1,
        }
    )

    assert restart.handoff == RestartHandoff.model_validate(handoff)
    assert noop.handoff is None


def test_supervisor_wake_packet_accepts_decision_critical_fields(tmp_path: Path) -> None:
    packet = SupervisorWakePacket(
        wake_sequence=1,
        latest_event_sequence=1,
        generation=0,
        restart_count=0,
        task_path=str(tmp_path / "TASK.md"),
        task_contents="# Task",
        triggering_action=TriggeringAction(
            item_id="i",
            kind="commandExecution",
            command="pytest",
            exit_code=0,
            status="completed",
            summary="command completed: pytest exit=0",
        ),
        human_message=HumanMessage(text="discussion only", sequence=3),
        changed_files=[{"path": "a.py", "status": "M", "additions": 1, "deletions": 0}],
        validations=[{"command": "pytest", "exit_code": 0, "passed": True, "summary": "pytest passed", "sequence": 2}],
    )

    assert packet.triggering_action is not None
    assert packet.human_message is not None
    assert packet.changed_files[0].path == "a.py"
    assert packet.validations[0].passed is True


def test_stateless_prompt_assembles_blocks_from_packet() -> None:
    base = SupervisorWakePacket(
        wake_sequence=1,
        latest_event_sequence=1,
        generation=0,
        restart_count=0,
        task_path="TASK.md",
        task_contents="# Task",
    )
    payload = json.loads(build_stateless_supervisor_prompt(base))
    assert payload["prompt_sections"] == ["role", "output_contract", "decisions", "inputs", "state_writes", "invariants"]
    assert "completion_review" not in payload["prompt_sections"]
    assert "completion_output_contract" not in payload["prompt_sections"]

    approval_with_handoff = base.model_copy(
        update={
            "triggering_server_request_id": 10,
            "handoff": RestartHandoff(
                objective="task",
                restart_reason="loop",
                bad_pattern="repeat",
                known_evidence="evidence",
                next_step="step",
                recovery_signal="signal",
            ),
        }
    )
    payload = json.loads(build_stateless_supervisor_prompt(approval_with_handoff))
    assert "approval" in payload["prompt_sections"]
    assert "handoff" in payload["prompt_sections"]
    assert "action_review" not in payload["prompt_sections"]

    adversary_approval = base.model_copy(
        update={
            "triggering_server_request_id": 11,
            "approval_context": ApprovalWakeContext(
                request_type="command",
                server_request_id=11,
                method="item/commandExecution/requestApproval",
                command="curl https://example.com",
                origin="adversary_snapshot",
            ),
        }
    )
    payload = json.loads(build_stateless_supervisor_prompt(adversary_approval))
    assert "adversary_approval" in payload["prompt_sections"]
    assert "approval" not in payload["prompt_sections"]
    adversary_section = payload["instructions"][payload["prompt_sections"].index("adversary_approval")]
    assert "valid in one situation and invalid in another" in adversary_section

    action = base.model_copy(update={"triggering_item_id": "item-1"})
    assert "action_review" in json.loads(build_stateless_supervisor_prompt(action))["prompt_sections"]

    human = base.model_copy(update={"human_message": HumanMessage(text="stop", sequence=2)})
    assert "human_message" in json.loads(build_stateless_supervisor_prompt(human))["prompt_sections"]

    completion_payload = json.loads(build_completion_review_prompt(approval_with_handoff))
    assert completion_payload["prompt_sections"] == [
        "completion_role",
        "completion_output_contract",
        "completion_inputs",
        "completion_state_writes",
        "completion_review",
        "completion_invariants",
    ]
    assert "role" not in completion_payload["prompt_sections"]
    assert "inputs" not in completion_payload["prompt_sections"]
    assert "state_writes" not in completion_payload["prompt_sections"]
    assert "invariants" not in completion_payload["prompt_sections"]
    assert "handoff" not in completion_payload["prompt_sections"]
    assert "approval" not in completion_payload["prompt_sections"]
    assert "action_review" not in completion_payload["prompt_sections"]


def test_adv_report_controller_prompt_is_narrow_and_carries_raw_report() -> None:
    raw_report = (
        "candidate_finding: true\n"
        "attacked: parser boundaries\n"
        "findings: parser crashes on an empty record\n"
        "observations: quoted newline handling looked suspicious\n"
        "held: ordinary rows\n"
        "not_reached: none\n"
        "overall: Defects remain in the submitted solution"
    )
    packet = SupervisorWakePacket(
        wake_sequence=4,
        latest_event_sequence=4,
        generation=0,
        restart_count=0,
        task_path="TASK.md",
        task_contents="# Fix the parser",
        adversary_report=AdversaryReport(
            candidate_finding=True,
            report_text=raw_report,
            generation=0,
            completion_wake_sequence=4,
            workspace_state_id="state-4",
            created_at="2026-08-04T00:00:00+00:00",
        ),
    )

    payload = json.loads(build_adv_report_controller_prompt(packet))

    assert payload["raw_adversary_report"] == raw_report
    assert payload["task_contents"] == "# Fix the parser"
    prompt = payload["instructions"][0]
    assert "Carry every item" in prompt
    assert "Unspecified uncertainty is not enough" in prompt
    assert "Do not downgrade when the evidence positively establishes a reject condition" in prompt
    assert "sole factual source" in prompt
    assert "without a how-to-verify instruction" in prompt
    assert "material_coverage_limitations" in prompt
    assert "These limitations are final-report metadata" in prompt

    completion_payload = json.loads(build_completion_review_prompt(packet))
    assert "adversary_report" not in completion_payload
    assert raw_report not in json.dumps(completion_payload)


def test_completed_adversary_report_requires_workspace_binding() -> None:
    with pytest.raises(ValueError, match="workspace_state_id"):
        AdversaryReport(
            candidate_finding=False,
            report_text="findings: none",
            generation=0,
            completion_wake_sequence=1,
            created_at="2026-08-04T00:00:00+00:00",
        )


def test_default_coder_prompts_preserve_quality_while_bounding_redundant_work(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    initial = build_coder_prompt(task)
    restart = build_restart_prompt(task)

    for prompt in (initial, restart):
        assert ".supervisor/coder/CHECKLIST.md" in prompt
        assert "Never omit a required category to meet an item-count target" in prompt
        assert "use one clear line and one sentence whenever the same meaning can be preserved" in prompt
        assert "at or below 12 KiB" in prompt
        assert "64 KiB is an emergency storage ceiling, not a target" in prompt
        assert "do not spend a command measuring it unless the file is plausibly near the bound" in prompt
        assert "never drop required coverage to meet a size target" in prompt
        assert "exactly three item kinds" in prompt
        assert "`B` for a task-grounded behavior obligation" in prompt
        assert "`F` for a confirmed Finding" in prompt
        assert "`O` for an Observation" in prompt
        assert "exactly one Markdown checkbox and no other status" in prompt
        assert "Implementation alone never qualifies a `B` or `F` item for `[x]`" in prompt
        assert "must end `[x]` after one bounded independent investigation" in prompt
        assert "there is no third pending disposition" in prompt
        assert "whose possible outcomes can materially distinguish the reported failure mode" in prompt
        assert "an infrastructure or permission failure with no interpretable product behavior" in prompt
        assert "incapable of exposing the reported failure mode" in prompt
        assert "qualifying evidence even when its command exits nonzero" in prompt
        assert "If no capable direct investigation is available after one bounded search" in prompt
        assert "do not claim that absence of a defect was proved" in prompt
        assert "Every `[x]` item must include a compact evidence reference and observed outcome" in prompt
        assert "both the confirming investigation and fresh post-fix validation" in prompt
        assert "An evidence-free `[x]` item is nonconforming" in prompt
        assert "An `O` remains `[ ]` only while its one bounded investigation is in progress" in prompt
        assert "a material limitation in required `B` or `F` work or final validation" in prompt
        assert "the conclusion that no defect was established" in prompt
        assert "Do not require proof of absence" in prompt
        assert "A bare assertion, an unavailable check" in prompt
        assert "Before beginning a cohesive product edit" in prompt
        assert "one batched checklist update changing every such `[x]` to `[ ]`" in prompt
        assert "Patch only the entries whose content, checkbox, or evidence changed" in prompt
        assert "Read an existing checklist once at generation start" in prompt
        assert "do not reread unchanged content merely to refresh your memory" in prompt
        assert "locate and read only the target IDs or lines" in prompt
        assert "There is no third pending disposition" in prompt
        assert "inconclusive" not in prompt.lower()
        assert "legacy or nonconforming format" in prompt
        assert "Search and filenames locate candidates" in prompt
        assert "names and checklist notes are never substitutes for understanding the code" in prompt
        assert "Never reread merely for reassurance" in prompt
        assert "Preserve unaffected evidence" in prompt
        assert "dependency, interface, configuration, fixture, build or runtime input" in prompt
        assert "do not rerun unrelated green checks" in prompt
        assert "canonical full regression suite once" in prompt
        assert "every normalized adversary Finding as an unchecked `F` item" in prompt
        assert "do not reopen whether it exists" in prompt
        assert "every received `O` item to be `[x]` with current evidence" in prompt
        assert "these classes are not a quota" in prompt
        assert "Do not run a pre-change baseline merely because no prior result exists" in prompt
        assert "Do not start another general audit" in prompt
        assert "intrinsically static contract" in prompt
        assert "a raw binary diff is not visual evidence" in prompt
        assert "Static checks such as" not in prompt
        assert "preferably the full artifact diff" not in prompt
        assert "enumerate the resources the task and repository make available" not in prompt
        assert "re-run the checks that were previously passing for any area" not in prompt
        assert "new evidence could affect it" not in prompt
        assert "spawn_agent" not in prompt
        for removed_status in (
            "TODO",
            "IN_PROGRESS",
            "INVESTIGATE",
            "IMPLEMENTED",
            "VALIDATED",
            "STALE",
            "CLOSED_UNCONFIRMED",
            "BLOCKED",
        ):
            assert removed_status not in prompt

    assert "its contents are not embedded in this prompt" in initial
    assert "If it is missing or empty" in initial
    assert "first derive the required behavior categories from the task and the applicable domain contract" in initial
    assert "actual relevant implementation, existing contracts, direct consumers, and closest tests" in initial
    assert "must never narrow the task-derived target or turn visible tests into the oracle" in initial
    assert "Continue from the unchecked `[ ]` item that corresponds to `next_step`" in restart
    assert "Treat every checked `[x]` item that carries the compact evidence reference" in restart
    assert "as reusable current evidence, not as independent proof" in restart
    assert "An evidence-free `[x]` item is nonconforming and becomes `[ ]`" in restart
    assert "a missing coder transcript, absence of additional chronology" in restart
    assert "do not reopen, reread, or rerun checked work solely to reconstruct or re-prove" in restart
    assert "only when concrete restart or workspace evidence identifies a specific later affecting edit" in restart
    assert "do not require separately re-proving every checked item" in restart
    assert "including the canonical full regression when feasible and applicable" in restart
    assert "without assuming the product work starts from zero" in restart


def test_prompts_are_loaded_from_single_toml_file(monkeypatch, tmp_path: Path) -> None:
    prompt_file = tmp_path / "prompts.toml"
    prompt_file.write_text(
        """
[coder_initial]
template = '''initial {task_path}'''

[coder_restart]
template = '''restart {task_path}'''

[stateless_supervisor]
body_sections = ["role"]
completion_body_sections = ["completion_role"]

[stateless_supervisor.sections.role]
text = '''stateless instruction'''

[stateless_supervisor.sections.completion_role]
text = '''completion instruction'''
""".strip()
        + "\n",
        encoding="utf-8",
    )
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")

    monkeypatch.setenv(PROMPTS_ENV_VAR, str(prompt_file))
    try:
        assert build_coder_prompt(task) == (
            "initial the task path supplied in the final Task context below\n\n"
            f"Task context:\n- task_path: {task.resolve()}"
        )
        assert build_restart_prompt(task) == (
            "restart the task path supplied in the final Task context below\n\n"
            f"Task context:\n- task_path: {task.resolve()}"
        )

        packet = SupervisorWakePacket(
            wake_sequence=1,
            latest_event_sequence=1,
            generation=0,
            restart_count=0,
            task_path=str(task),
            task_contents="# Task",
            last_actions=["command completed: pytest exit=1", "file change completed: 1 changes"],
        )
        supervisor_payload = json.loads(build_stateless_supervisor_prompt(packet))
        assert supervisor_payload["instructions"] == ["stateless instruction"]
        assert supervisor_payload["last_actions"] == ["command completed: pytest exit=1", "file change completed: 1 changes"]
        assert "last_action" not in supervisor_payload
        completion_payload = json.loads(build_completion_review_prompt(packet))
        assert completion_payload["instructions"] == ["completion instruction"]
        completion_prompt = build_completion_review_prompt(packet)
        assert completion_prompt.index('"task_contents"') < completion_prompt.index(
            '"wake_sequence"'
        )
    finally:
        monkeypatch.delenv(PROMPTS_ENV_VAR, raising=False)


def test_missing_stateless_prompt_block_fails_fast(monkeypatch, tmp_path: Path) -> None:
    prompt_file = tmp_path / "prompts.toml"
    prompt_file.write_text(
        """
[coder_initial]
template = '''initial {task_path}'''

[coder_restart]
template = '''restart {task_path}'''

[stateless_supervisor]
body_sections = ["role", "missing_runtime"]
completion_body_sections = ["completion_role"]

[stateless_supervisor.sections.role]
text = '''runtime'''

[stateless_supervisor.sections.completion_role]
text = '''completion'''
""".strip()
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv(PROMPTS_ENV_VAR, str(prompt_file))
    packet = SupervisorWakePacket(
        wake_sequence=1,
        latest_event_sequence=1,
        generation=0,
        restart_count=0,
        task_path="TASK.md",
        task_contents="# Task",
    )

    with pytest.raises(RuntimeError, match="missing_runtime"):
        build_stateless_supervisor_prompt(packet)

    prompt_file.write_text(
        prompt_file.read_text(encoding="utf-8").replace(
            'completion_body_sections = ["completion_role"]',
            'completion_body_sections = ["missing_completion"]',
        ),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="missing_completion"):
        build_completion_review_prompt(packet)
