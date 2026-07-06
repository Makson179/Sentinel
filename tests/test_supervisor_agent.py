from __future__ import annotations

import json
from pathlib import Path

from supervisor.appserver import AppServerError, AppServerMessage
from supervisor.schemas import (
    ChangedFileContext,
    ChangedFileDiff,
    InspectionOutput,
    InspectionRun,
    SentinelConfig,
    SupervisorDecisionKind,
    ValidationOutput,
    ValidationRun,
)
from supervisor.state import LOG, SUPERVISOR_WAKES, StateStore
from supervisor.supervisor_agent import StatelessSupervisorAgent


async def test_stateless_supervisor_persists_wake_packet_and_decision(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class FakeClient:
        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "supervisor-thread"}}

        async def turn_start(self, params, *, timeout):
            return {
                "turn": {
                    "id": "supervisor-turn",
                    "status": "completed",
                    "items": [
                        {
                            "type": "agentMessage",
                            "text": json.dumps(
                                {
                                    "decision": "noop",
                                    "reason": "state is consistent",
                                    "wake_sequence": 7,
                                    "generation": 0,
                                }
                            ),
                        }
                    ],
                }
            }

        async def thread_archive(self, thread_id, *, timeout):
            return {}

    agent = StatelessSupervisorAgent(FakeClient(), store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(wake_sequence=7, current_summary="audit this wake")

    decision = await agent.decide(packet)

    lines = store.path(SUPERVISOR_WAKES).read_text(encoding="utf-8").splitlines()
    audit = json.loads(lines[-1])
    assert decision.decision == SupervisorDecisionKind.NOOP
    assert audit["status"] == "decision"
    assert audit["thread_id"] == "supervisor-thread"
    assert audit["turn_id"] == "supervisor-turn"
    assert audit["packet"]["wake_sequence"] == 7
    assert audit["packet"]["current_summary"] == "audit this wake"
    assert audit["decision"]["decision"] == "noop"
    assert audit["decision"]["reason"] == "state is consistent"


async def test_completion_review_persists_use_case_and_decision(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class FakeClient:
        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "supervisor-thread"}}

        async def turn_start(self, params, *, timeout):
            assert params["outputSchema"]["$defs"]["CompletionReviewDecisionKind"]["enum"] == [
                "accept",
                "return",
                "restart",
            ]
            return {
                "turn": {
                    "id": "supervisor-turn",
                    "status": "completed",
                    "items": [
                        {
                            "type": "agentMessage",
                            "text": json.dumps(
                                {
                                    "decision": "accept",
                                    "reason": "validated",
                                    "files_reviewed": [],
                                    "behavior_evidence_matrix": [],
                                    "uncovered_behaviors": [],
                                    "validation_gaps": [],
                                    "claim_evidence_mismatches": [],
                                    "packet_or_access_limitations": [],
                                    "changed_test_risks": [],
                                    "message_to_coder": None,
                                    "persistent_decision": None,
                                    "progress_update": None,
                                    "clear_handoff": False,
                                    "display_message": None,
                                    "handoff": None,
                                    "wake_sequence": 7,
                                    "generation": 0,
                                }
                            ),
                        }
                    ],
                }
            }

        async def thread_archive(self, thread_id, *, timeout):
            return {}

    agent = StatelessSupervisorAgent(FakeClient(), store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(wake_sequence=7, current_summary="completion review")

    decision = await agent.decide_completion(packet)

    assert decision.decision == "accept"
    audit = json.loads(store.path(SUPERVISOR_WAKES).read_text(encoding="utf-8").splitlines()[-1])
    assert audit["use_case"] == "completion_review"
    assert audit["decision"]["decision"] == "accept"


async def test_completion_review_uses_minimal_retry_after_repair_output_is_invalid(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\nImplement the compiler.\n", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
    valid_decision = {
        "decision": "return",
        "reason": "stack-passed arguments still need validation",
        "decision_artifact": {
            "current_state": "public tests pass but private ABI behavior is not covered",
            "resolved_concerns": [],
            "stale_concerns": [],
            "uncovered_edge_candidates": ["calls with more than six integer arguments"],
            "actionable_gap_or_none": "add and pass a regression for stack-passed arguments",
        },
        "basis_event_seq": 7,
        "last_relevant_edit_seq": None,
        "last_validation_seq": None,
        "files_reviewed": [],
        "behavior_evidence_matrix": [],
        "uncovered_behaviors": ["stack-passed call arguments"],
        "validation_gaps": ["missing regression for more than six call arguments"],
        "claim_evidence_mismatches": [],
        "packet_or_access_limitations": [],
        "changed_test_risks": [],
        "message_to_coder": "Add a regression that calls a function with more than six integer arguments and fix it.",
        "persistent_decision": None,
        "progress_update": None,
        "clear_handoff": False,
        "display_message": None,
        "handoff": None,
        "wake_sequence": 7,
        "generation": 0,
    }

    class FakeClient:
        def __init__(self) -> None:
            self.thread_starts = 0
            self.turn_inputs: list[str] = []
            self.archived: list[str] = []

        async def thread_start(self, params, *, timeout):
            self.thread_starts += 1
            return {"thread": {"id": f"completion-thread-{self.thread_starts}"}}

        async def turn_start(self, params, *, timeout):
            self.turn_inputs.append(params["input"][0]["text"])
            turn_number = len(self.turn_inputs)
            if turn_number <= 2:
                text = '{"decision":"return","reason":"unterminated","behavior_evidence_matrix":['
            else:
                text = json.dumps(valid_decision)
            return {
                "turn": {
                    "id": f"turn-{turn_number}",
                    "status": "completed",
                    "items": [{"type": "agentMessage", "text": text}],
                }
            }

        async def thread_archive(self, thread_id, *, timeout):
            self.archived.append(thread_id)
            return {}

    client = FakeClient()
    agent = StatelessSupervisorAgent(client, store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(wake_sequence=7, current_summary="completion review")

    decision = await agent.decide_completion(packet)

    assert decision.decision == "return"
    assert decision.files_reviewed == []
    assert decision.behavior_evidence_matrix == []
    assert client.thread_starts == 2
    assert client.archived == ["completion-thread-1"]
    assert len(client.turn_inputs) == 3
    assert "compact completion-review JSON object" in client.turn_inputs[1]
    assert "# Emergency compact JSON retry" in client.turn_inputs[2]
    assert "files_reviewed=[]" in client.turn_inputs[2]
    assert "behavior_evidence_matrix=[]" in client.turn_inputs[2]
    audits = [json.loads(line) for line in store.path(SUPERVISOR_WAKES).read_text(encoding="utf-8").splitlines()]
    assert any(audit["use_case"] == "completion_review_parse_retry" for audit in audits)
    assert any(
        audit["use_case"] == "completion_review" and audit["status"] == "error"
        for audit in audits
    )
    assert audits[-1]["use_case"] == "completion_review_minimal_retry"
    assert audits[-1]["status"] == "decision"


async def test_completion_review_compacts_large_packet_under_budget(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\nImplement the compiler.\n", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class FakeClient:
        def __init__(self) -> None:
            self.prompt = ""

        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "supervisor-thread"}}

        async def turn_start(self, params, *, timeout):
            self.prompt = params["input"][0]["text"]
            assert len(self.prompt) < 900_000
            return {
                "turn": {
                    "id": "supervisor-turn",
                    "status": "completed",
                    "items": [
                        {
                            "type": "agentMessage",
                            "text": json.dumps(
                                {
                                    "decision": "accept",
                                    "reason": "validated",
                                    "files_reviewed": [],
                                    "behavior_evidence_matrix": [],
                                    "uncovered_behaviors": [],
                                    "validation_gaps": [],
                                    "claim_evidence_mismatches": [],
                                    "packet_or_access_limitations": [],
                                    "changed_test_risks": [],
                                    "message_to_coder": None,
                                    "persistent_decision": None,
                                    "progress_update": None,
                                    "clear_handoff": False,
                                    "display_message": None,
                                    "handoff": None,
                                    "wake_sequence": 7,
                                    "generation": 0,
                                }
                            ),
                        }
                    ],
                }
            }

        async def thread_archive(self, thread_id, *, timeout):
            return {}

    validations = [
        ValidationRun(
            validation_id=f"validation-{index}",
            command=f"pytest tests/public/test_public.py::test_case_{index}",
            exit_code=0,
            passed=True,
            trusted_validation_outcome="passed",
            summary="public validation passed\n" + ("V" * 6000),
            captured_output=f"VALIDATION-{index}\n" + ("v" * 16000),
            sequence=100 + index,
        )
        for index in range(12)
    ]
    inspections = [
        InspectionRun(
            inspection_id=f"inspection-{index}",
            command=f"sed -n '1,220p' file_{index}.c",
            exit_code=0,
            passed=True,
            summary="source inspection\n" + ("I" * 6000),
            captured_output=f"INSPECTION-{index}\n" + ("i" * 20000),
            sequence=200 + index,
            inspected_paths=[f"file_{index}.c"],
        )
        for index in range(50)
    ]
    validation_outputs = [
        ValidationOutput(
            validation_id=value.validation_id,
            command=value.command,
            exit_code=value.exit_code,
            type=value.type,
            outcome=value.outcome,
            passed=value.passed,
            trusted_validation_outcome=value.trusted_validation_outcome,
            sequence=value.sequence,
            stdout_or_summary=value.summary,
            captured_output=value.captured_output,
        )
        for value in validations
    ]
    inspection_outputs = [
        InspectionOutput(
            inspection_id=value.inspection_id,
            command=value.command,
            exit_code=value.exit_code,
            outcome=value.outcome,
            passed=value.passed,
            sequence=value.sequence,
            stdout_or_summary=value.summary,
            captured_output=value.captured_output,
            inspected_paths=value.inspected_paths,
        )
        for value in inspections
    ]

    client = FakeClient()
    agent = StatelessSupervisorAgent(client, store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(
        wake_sequence=7,
        current_summary="completion review",
        changed_file_diffs=[
            ChangedFileDiff(path="codegen.c", file_kind="source", change_kind="modified", diff="D" * 12000),
            ChangedFileDiff(path="parser.c", file_kind="source", change_kind="modified", diff="P" * 12000),
        ],
        changed_file_contexts=[
            ChangedFileContext(path="codegen.c", final_snippets_around_changed_hunks="C" * 8000),
            ChangedFileContext(path="parser.c", final_snippets_around_changed_hunks="R" * 8000),
        ],
        validations=validations,
        inspections=inspections,
        validation_outputs=validation_outputs,
        inspection_outputs=inspection_outputs,
        completion_payload_mode="full",
    )

    decision = await agent.decide_completion(packet)

    assert decision.decision == "accept"
    # The completion packet is slimmed: the evidence skeleton (ids, outcomes, short
    # command/summary) is kept so the accept gate can bind to it, but full captured
    # output and inlined file diffs are dropped — the supervisor reads the workspace
    # itself. So evidence ids survive; raw captured output and diffs do not.
    assert "inspection-49" in client.prompt  # evidence id (skeleton) kept
    assert "validation-11" in client.prompt
    assert "INSPECTION-49" not in client.prompt  # raw captured output not inlined
    assert "D" * 200 not in client.prompt  # changed_file_diffs dropped
    assert len(client.prompt) < 500_000  # comfortably under the 1 MiB app-server cap
    audit = json.loads(store.path(SUPERVISOR_WAKES).read_text(encoding="utf-8").splitlines()[-1])
    assert audit["packet"]["inspections"][0]["captured_output"] == ""
    # validation_outputs / inspection_outputs are dropped entirely (near-duplicates of
    # the ledgers once captured_output is emptied; the accept gate does not consume them).
    assert audit["packet"]["validation_outputs"] == []
    assert audit["packet"]["inspection_outputs"] == []
    assert audit["packet"]["changed_file_diffs"] == []


async def test_completion_review_uses_dedicated_long_timeout(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class FakeClient:
        def __init__(self) -> None:
            self.timeouts: list[tuple[str, float]] = []

        async def thread_start(self, params, *, timeout):
            self.timeouts.append(("thread_start", timeout))
            return {"thread": {"id": "supervisor-thread"}}

        async def turn_start(self, params, *, timeout):
            self.timeouts.append(("turn_start", timeout))
            return {"turn": {"id": "supervisor-turn", "status": "running"}}

        async def wait_for_notification(self, predicate, *, timeout):
            self.timeouts.append(("wait_for_notification", timeout))
            turn = {
                "id": "supervisor-turn",
                "items": [
                    {
                        "type": "agentMessage",
                        "text": json.dumps(
                            {
                                "decision": "accept",
                                "reason": "validated",
                                "files_reviewed": [],
                                "behavior_evidence_matrix": [],
                                "uncovered_behaviors": [],
                                "validation_gaps": [],
                                "claim_evidence_mismatches": [],
                                "packet_or_access_limitations": [],
                                "changed_test_risks": [],
                                "message_to_coder": None,
                                "persistent_decision": None,
                                "progress_update": None,
                                "clear_handoff": False,
                                "display_message": None,
                                "handoff": None,
                                "wake_sequence": 7,
                                "generation": 0,
                            }
                        ),
                    }
                ],
            }
            message = AppServerMessage(
                {
                    "method": "turn/completed",
                    "params": {"threadId": "supervisor-thread", "turn": turn},
                }
            )
            assert predicate(message)
            return message

        async def thread_archive(self, thread_id, *, timeout):
            self.timeouts.append(("thread_archive", timeout))
            return {}

    client = FakeClient()
    agent = StatelessSupervisorAgent(
        client,
        store,
        task,
        timeout_seconds=123,
        completion_timeout_seconds=456,
    )  # type: ignore[arg-type]
    packet = agent.build_packet(wake_sequence=7, current_summary="completion review")

    decision = await agent.decide_completion(packet)

    assert decision.decision == "accept"
    assert client.timeouts == [
        ("thread_start", 456),
        ("turn_start", 456),
        ("wait_for_notification", 456),
    ]
    await agent.close_completion_review()
    assert client.timeouts[-1] == ("thread_archive", 10.0)


async def test_completion_review_reuses_thread_until_closed(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class FakeClient:
        def __init__(self) -> None:
            self.thread_starts = 0
            self.turn_starts: list[str] = []
            self.archived: list[str] = []

        async def thread_start(self, params, *, timeout):
            self.thread_starts += 1
            return {"thread": {"id": "completion-thread"}}

        async def turn_start(self, params, *, timeout):
            self.turn_starts.append(params["threadId"])
            return {
                "turn": {
                    "id": f"turn-{len(self.turn_starts)}",
                    "status": "completed",
                    "items": [
                        {
                            "type": "agentMessage",
                            "text": json.dumps(
                                {
                                    "decision": "return",
                                    "reason": "needs more validation",
                                    "files_reviewed": [],
                                    "behavior_evidence_matrix": [],
                                    "uncovered_behaviors": ["fallback"],
                                    "validation_gaps": ["missing fallback test"],
                                    "claim_evidence_mismatches": [],
                                    "packet_or_access_limitations": [],
                                    "changed_test_risks": [],
                                    "message_to_coder": "validate fallback",
                                    "persistent_decision": None,
                                    "progress_update": None,
                                    "clear_handoff": False,
                                    "display_message": None,
                                    "handoff": None,
                                    "wake_sequence": 7,
                                    "generation": 0,
                                }
                            ),
                        }
                    ],
                }
            }

        async def thread_archive(self, thread_id, *, timeout):
            self.archived.append(thread_id)
            return {}

    client = FakeClient()
    agent = StatelessSupervisorAgent(client, store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(wake_sequence=7, current_summary="completion review")

    await agent.decide_completion(packet)
    await agent.decide_completion(packet)

    assert client.thread_starts == 1
    assert client.turn_starts == ["completion-thread", "completion-thread"]
    assert client.archived == []

    await agent.close_completion_review()

    assert client.archived == ["completion-thread"]


async def test_stateless_supervisor_cleanup_error_after_decision_is_logged_not_fatal(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class FakeClient:
        def __init__(self) -> None:
            self.unsubscribed: list[str] = []

        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "supervisor-thread"}}

        async def turn_start(self, params, *, timeout):
            return {
                "turn": {
                    "id": "supervisor-turn",
                    "status": "completed",
                    "items": [
                        {
                            "type": "agentMessage",
                            "text": json.dumps(
                                {
                                    "decision": "noop",
                                    "reason": "state is consistent",
                                    "wake_sequence": 7,
                                    "generation": 0,
                                }
                            ),
                        }
                    ],
                }
            }

        async def thread_archive(self, thread_id, *, timeout):
            raise AppServerError("no rollout found for thread id supervisor-thread")

        async def thread_unsubscribe(self, thread_id, *, timeout):
            self.unsubscribed.append(thread_id)
            return {"status": "unsubscribed"}

    client = FakeClient()
    agent = StatelessSupervisorAgent(client, store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(wake_sequence=7, current_summary="audit this wake")

    decision = await agent.decide(packet)

    assert decision.decision == SupervisorDecisionKind.NOOP
    assert client.unsubscribed == ["supervisor-thread"]
    audit = json.loads(store.path(SUPERVISOR_WAKES).read_text(encoding="utf-8").splitlines()[-1])
    assert audit["status"] == "decision"
    log_entry = json.loads(store.path(LOG).read_text(encoding="utf-8").splitlines()[-1])
    assert log_entry["type"] == "supervisor_cleanup_error"
    assert log_entry["thread_id"] == "supervisor-thread"
    assert "no rollout found" in log_entry["archive_error"]
