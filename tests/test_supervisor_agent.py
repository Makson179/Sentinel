from __future__ import annotations

import json
from pathlib import Path

import pytest

from supervisor.appserver import AppServerError, AppServerMessage
from supervisor.approval_triage import CheapRuntimeReviewer
from supervisor.prompts import build_completion_review_prompt
from supervisor.schemas import (
    AdversaryReport,
    ChangedFileContext,
    ChangedFileDiff,
    InspectionOutput,
    InspectionRun,
    PriorIntervention,
    CompletionReturnRecord,
    BelloConfig,
    SupervisorDecisionKind,
    TriggeringAction,
    ValidationOutput,
    ValidationRun,
)
from supervisor.state import DECISIONS, LOG, PROGRESS, SUPERVISOR_WAKES, StateStore
from supervisor.supervisor_agent import (
    COMPLETION_PERMISSION_PROFILE,
    StatelessSupervisorAgent,
    SupervisorAgentError,
    _slim_completion_packet,
)


def test_cheap_runtime_thread_disables_configured_external_capabilities(
    tmp_path: Path,
) -> None:
    reviewer = CheapRuntimeReviewer(
        object(),  # type: ignore[arg-type]
        tmp_path,
        model="gpt-cheap",
        configured_mcp_server_names=(" docs ", "docs", "browser"),
        configured_plugin_names=("sites@openai-bundled",),
    )

    params = reviewer._thread_params()

    assert params["config"] == {
        "apps": {"_default": {"enabled": False}},
        "include_apps_instructions": False,
        "mcp_servers": {
            "browser": {"enabled": False},
            "docs": {"enabled": False},
        },
        "plugins": {"sites@openai-bundled": {"enabled": False}},
    }
    assert params["dynamicTools"] == []
    assert params["environments"] == []


def test_completion_item_merge_preserves_live_delta_output(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True
    )
    agent = StatelessSupervisorAgent(object(), store, task)  # type: ignore[arg-type]
    agent.record_completion_review_item(
        {
            "id": "read-source",
            "type": "commandExecution",
            "command": "cat src/app.py",
            "exitCode": 0,
            "output": "value = 1\n",
        }
    )

    agent.record_completion_review_item(
        {
            "id": "read-source",
            "type": "commandExecution",
            "command": "cat src/app.py",
            "exitCode": 0,
        }
    )

    assert len(agent.last_completion_review_items) == 1
    assert agent.last_completion_review_items[0]["output"] == "value = 1\n"


def test_completion_packet_redacts_private_coder_checklist_history(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
    review_root = tmp_path / "coder-snapshot"
    review_root.mkdir()
    (review_root / ".supervisor").symlink_to(store.state_dir, target_is_directory=True)
    (review_root / "private-checklist-alias").symlink_to(
        store.coder_checklist_path()
    )
    agent = StatelessSupervisorAgent(object(), store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(
        wake_sequence=7,
        current_summary="review",
        inspections=[
            InspectionRun(
                inspection_id="inspection-1",
                command="cat .supervisor/coder/CHECKLIST.md",
                exit_code=0,
                passed=True,
                summary="PRIVATE CODER REASONING",
                captured_output="PRIVATE CODER REASONING",
                sequence=6,
                inspected_paths=[".supervisor/coder/CHECKLIST.md"],
            ),
            InspectionRun(
                inspection_id="inspection-2",
                command="cat docs/CHECKLIST.md",
                exit_code=0,
                passed=True,
                summary="PUBLIC PRODUCT CHECKLIST",
                captured_output="PUBLIC PRODUCT CHECKLIST",
                sequence=6,
                inspected_paths=["docs/CHECKLIST.md"],
            ),
            InspectionRun(
                inspection_id="inspection-3",
                command=f"cat {store.coder_checklist_path().resolve()}",
                cwd=str(review_root),
                exit_code=0,
                passed=True,
                summary="PRIVATE CANONICAL CODER REASONING",
                captured_output="PRIVATE CANONICAL CODER REASONING",
                sequence=6,
                inspected_paths=[str(store.coder_checklist_path().resolve())],
            ),
            InspectionRun(
                inspection_id="inspection-4",
                command="cat CHECKLIST.md",
                cwd=str(store.coder_checklist_path().parent),
                exit_code=0,
                passed=True,
                summary="PRIVATE CWD-RELATIVE CODER REASONING",
                captured_output="PRIVATE CWD-RELATIVE CODER REASONING",
                sequence=6,
                inspected_paths=["CHECKLIST.md"],
            ),
            InspectionRun(
                inspection_id="inspection-5",
                command="cat coder/CHECKLIST.md",
                cwd=str(store.state_dir),
                exit_code=0,
                passed=True,
                summary="PRIVATE PARENT-CWD CODER REASONING",
                captured_output="PRIVATE PARENT-CWD CODER REASONING",
                sequence=6,
                inspected_paths=["coder/CHECKLIST.md"],
            ),
            InspectionRun(
                inspection_id="inspection-6",
                command="cat foo/../.supervisor/coder/CHECKLIST.md",
                cwd=str(review_root),
                exit_code=0,
                passed=True,
                summary="PRIVATE NORMALIZED CODER REASONING",
                captured_output="PRIVATE NORMALIZED CODER REASONING",
                sequence=6,
                inspected_paths=["foo/../.supervisor/coder/CHECKLIST.md"],
            ),
            InspectionRun(
                inspection_id="inspection-7",
                command="cat .supervisor/coder/../coder/CHECKLIST.md",
                cwd=str(review_root),
                exit_code=0,
                passed=True,
                summary="PRIVATE ALIASED-PARENT CODER REASONING",
                captured_output="PRIVATE ALIASED-PARENT CODER REASONING",
                sequence=6,
                inspected_paths=[".supervisor/coder/../coder/CHECKLIST.md"],
            ),
            InspectionRun(
                inspection_id="inspection-8",
                command="cat private-checklist-alias",
                cwd=str(review_root),
                exit_code=0,
                passed=True,
                summary="PRIVATE SYMLINK-ALIASED CODER REASONING",
                captured_output="PRIVATE SYMLINK-ALIASED CODER REASONING",
                sequence=6,
                inspected_paths=["private-checklist-alias"],
            ),
            InspectionRun(
                inspection_id="inspection-9",
                command="cat docs/../CHECKLIST.md",
                cwd=str(review_root),
                exit_code=0,
                passed=True,
                summary="PUBLIC ROOT CHECKLIST",
                captured_output="PUBLIC ROOT CHECKLIST",
                sequence=6,
                inspected_paths=["docs/../CHECKLIST.md"],
            ),
            InspectionRun(
                inspection_id="inspection-10",
                command="cat private-checklist-alias",
                exit_code=0,
                passed=True,
                summary="PRIVATE DEFAULT-CWD ALIAS REASONING",
                captured_output="PRIVATE DEFAULT-CWD ALIAS REASONING",
                sequence=6,
                inspected_paths=["private-checklist-alias"],
            ),
        ],
    )
    packet.last_actions = [
        "command completed: cat .supervisor/coder/CHECKLIST.md exit=0",
        f"command completed: cat {store.coder_checklist_path().resolve()} exit=0",
        "command completed: cat CHECKLIST.md exit=0",
        "command completed: cat docs/.supervisor/coder/CHECKLIST.md exit=0",
        "command completed: cat .supervisor/coder/CHECKLIST.md.bak exit=0",
    ]
    packet.completion_delta_evidence_summary = [
        "inspection private command=cat .supervisor/coder/CHECKLIST.md",
        "inspection public command=cat docs/CHECKLIST.md",
    ]

    slim = _slim_completion_packet(
        packet,
        denied_workspace_read_paths=(".supervisor/coder/CHECKLIST.md",),
        workspace_root=review_root,
    )
    assert [item.inspection_id for item in slim.inspections] == [
        "inspection-2",
        "inspection-9",
    ]
    assert slim.last_actions == [
        "command completed: cat CHECKLIST.md exit=0",
        "command completed: cat docs/.supervisor/coder/CHECKLIST.md exit=0",
        "command completed: cat .supervisor/coder/CHECKLIST.md.bak exit=0",
    ]
    assert slim.completion_delta_evidence_summary == [
        "inspection public command=cat docs/CHECKLIST.md"
    ]
    assert "PRIVATE CODER REASONING" not in slim.model_dump_json()
    assert "PRIVATE CANONICAL CODER REASONING" not in slim.model_dump_json()
    assert "PRIVATE CWD-RELATIVE CODER REASONING" not in slim.model_dump_json()
    assert "PRIVATE PARENT-CWD CODER REASONING" not in slim.model_dump_json()
    assert "PRIVATE NORMALIZED CODER REASONING" not in slim.model_dump_json()
    assert "PRIVATE ALIASED-PARENT CODER REASONING" not in slim.model_dump_json()
    assert "PRIVATE SYMLINK-ALIASED CODER REASONING" not in slim.model_dump_json()
    assert "PRIVATE DEFAULT-CWD ALIAS REASONING" not in slim.model_dump_json()
    assert "PUBLIC PRODUCT CHECKLIST" in slim.model_dump_json()
    assert "PUBLIC ROOT CHECKLIST" in slim.model_dump_json()


def test_completion_packet_redacts_shell_expanded_private_checklist_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True
    )
    private_checklist_content = "FIX JWT"
    store.ensure_coder_checklist(
        private_checklist_content + "\nPUBLIC DOCS GLOB\nPUBLIC DOCS PRIVATE-SHAPED DIRECTORY\n"
    )
    review_root = tmp_path / "coder-snapshot"
    review_root.mkdir()
    review_root_alias = tmp_path / "coder-snapshot-alias"
    review_root_alias.symlink_to(review_root, target_is_directory=True)
    (review_root / ".supervisor").symlink_to(
        store.state_dir, target_is_directory=True
    )
    (review_root / "private-alias.md").symlink_to(store.coder_checklist_path())
    (review_root / "private-dir").symlink_to(
        store.coder_checklist_path().parent, target_is_directory=True
    )
    monkeypatch.setenv("HOME", str(tmp_path.parent))
    private_spellings = [
        "$PWD/.supervisor/coder/CHECKLIST.md",
        "${PWD}/.supervisor/coder/CHECKLIST.md",
        "${PWD%/}/.supervisor/coder/CHECKLIST.md",
        f"$HOME/{tmp_path.name}/.supervisor/coder/CHECKLIST.md",
        f"${{HOME}}/{tmp_path.name}/.supervisor/coder/CHECKLIST.md",
        "~+/.supervisor/coder/CHECKLIST.md",
        f"~/{tmp_path.name}/.supervisor/coder/CHECKLIST.md",
        ".supervisor/coder/CHECKLIST.m?",
        ".supervisor/cod?r/CHECKLIST.md",
        ".supervisor/{coder}/CHECKLIST.md",
        ".supervisor/cod{e..e}r/CHECKLIST.md",
        ".supervisor/{a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,coder}/CHECKLIST.md",
        ".supervisor/code{a..z}/CHECKLIST.md",
        ".supervisor/coder",
        "private-ali?s.md",
        "private-*.md",
        "private-dir/CHECKLIST.m?",
        "private-dir",
    ]
    inspections = [
        InspectionRun(
            inspection_id=f"private-expansion-{index}",
            command=f"cat '{path}'",
            cwd=str(review_root),
            exit_code=0,
            passed=True,
            summary=f"PRIVATE EXPANSION REASONING {index}",
            captured_output=f"PRIVATE EXPANSION REASONING {index}",
            sequence=6,
            inspected_paths=[path],
        )
        for index, path in enumerate(private_spellings)
    ]
    inspections.append(
        InspectionRun(
            inspection_id="public-docs-glob",
            command="cat docs/CHECKLIST.m?",
            cwd=str(review_root),
            exit_code=0,
            passed=True,
            summary="PUBLIC DOCS GLOB",
            captured_output="PUBLIC DOCS GLOB",
            sequence=6,
            inspected_paths=["docs/CHECKLIST.m?"],
        )
    )
    for index, (command, output, inspected_path) in enumerate(
        (
            ("rg --hidden --follow --no-filename '^' .", private_checklist_content, "."),
            ("rg --hidden --follow --no-filename -o '[0-9]{4}' .", "7391", "."),
            (
                "rg --hidden --follow --no-filename --color=always 'boundary' .",
                "\x1b[31mboundary\x1b[0m",
                ".",
            ),
            ("grep -RhoE '[0-9]{4}' .supervisor/", "7391", ".supervisor/"),
        )
    ):
        inspections.append(
            InspectionRun(
                inspection_id=f"private-ancestor-recursive-read-{index}",
                command=command,
                cwd=str(review_root),
                exit_code=0,
                passed=True,
                summary=output,
                captured_output=output,
                sequence=6,
                inspected_paths=[inspected_path],
            )
        )
    inspections.append(
        InspectionRun(
            inspection_id="public-docs-private-shaped-dir",
            command="find docs/.supervisor/coder -type f",
            cwd=str(review_root),
            exit_code=0,
            passed=True,
            summary="PUBLIC DOCS PRIVATE-SHAPED DIRECTORY",
            captured_output="PUBLIC DOCS PRIVATE-SHAPED DIRECTORY",
            sequence=6,
            inspected_paths=["docs/.supervisor/coder"],
        )
    )
    agent = StatelessSupervisorAgent(object(), store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(
        wake_sequence=7,
        current_summary="review",
        inspections=inspections,
    )

    slim = _slim_completion_packet(
        packet,
        denied_workspace_read_paths=(".supervisor/coder/CHECKLIST.md",),
        workspace_root=review_root,
    )
    alias_slim = _slim_completion_packet(
        packet,
        denied_workspace_read_paths=(".supervisor/coder/CHECKLIST.md",),
        workspace_root=review_root_alias,
    )

    assert [item.inspection_id for item in slim.inspections] == [
        "public-docs-glob",
        "public-docs-private-shaped-dir",
    ]
    assert "PRIVATE EXPANSION REASONING" not in slim.model_dump_json()
    assert private_checklist_content not in slim.model_dump_json()
    assert "7391" not in slim.model_dump_json()
    assert "\x1b[31mboundary\x1b[0m" not in slim.model_dump_json()
    assert "PUBLIC DOCS GLOB" in slim.model_dump_json()
    assert "PUBLIC DOCS PRIVATE-SHAPED DIRECTORY" in slim.model_dump_json()
    assert [item.inspection_id for item in alias_slim.inspections] == [
        "public-docs-glob",
        "public-docs-private-shaped-dir",
    ]


def test_completion_packet_deduplicates_typed_return_from_runtime_interventions(
    tmp_path: Path,
) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True
    )
    message = "Fix the complete returned issue list before readiness."
    agent = StatelessSupervisorAgent(object(), store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(
        wake_sequence=8,
        current_summary="review",
        prior_interventions=[
            PriorIntervention(
                reason="Completion review returned: gaps remain",
                message_to_coder=message,
                sequence=7,
            ),
            PriorIntervention(
                reason="Runtime steering",
                message_to_coder="Run the targeted check.",
                sequence=6,
            ),
        ],
        previous_completion_returns=[
            CompletionReturnRecord(
                reason="gaps remain",
                message_to_coder=message,
                sequence=7,
                generation=0,
            )
        ],
    )

    slim = _slim_completion_packet(packet)

    assert [value.message_to_coder for value in slim.prior_interventions] == [
        "Run the targeted check."
    ]
    assert slim.previous_completion_returns[0].message_to_coder == message


def test_completion_packet_preserves_only_bounded_nonreplayable_validation_output(
    tmp_path: Path,
) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True
    )
    agent = StatelessSupervisorAgent(object(), store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(
        wake_sequence=3,
        current_summary="review",
        validations=[
            ValidationRun(
                validation_id="local-tests",
                command="pytest tests/test_app.py",
                type="behavioral",
                outcome="pass",
                passed=True,
                trusted_validation_outcome="passed",
                summary="1 passed",
                captured_output="LOCAL FULL OUTPUT",
                sequence=1,
            ),
            ValidationRun(
                validation_id="external-tests",
                command="DATABASE_URL=postgresql://db.example/app pytest tests/integration",
                type="behavioral",
                outcome="pass",
                passed=True,
                trusted_validation_outcome="passed",
                summary="external integration passed",
                captured_output=("x" * 4000) + "\nexternal-row=ready\n",
                sequence=2,
            ),
            ValidationRun(
                validation_id="long-local-tests",
                command="pytest tests/test_long.py",
                type="behavioral",
                outcome="pass",
                passed=True,
                trusted_validation_outcome="passed",
                summary="1 passed",
                captured_output=("trace\n" * 500) + "1 passed\n",
                sequence=3,
            ),
            ValidationRun(
                validation_id="direct-demo",
                command="./bin/app --scenario smoke",
                type="behavior_demo",
                outcome="pass",
                passed=True,
                trusted_validation_outcome="passed",
                summary="scenario passed",
                captured_output="scenario=smoke state=ready\n",
                sequence=4,
            ),
        ],
    )

    slim = _slim_completion_packet(packet)
    by_id = {value.validation_id: value for value in slim.validations}

    assert by_id["local-tests"].captured_output == "LOCAL FULL OUTPUT"
    assert by_id["external-tests"].captured_output.endswith("external-row=ready\n")
    assert len(by_id["external-tests"].captured_output) <= 2500
    assert by_id["external-tests"].captured_output_truncated is True
    assert by_id["long-local-tests"].captured_output.endswith("1 passed\n")
    assert len(by_id["long-local-tests"].captured_output) <= 400
    assert by_id["direct-demo"].captured_output == "scenario=smoke state=ready\n"


async def test_stateless_supervisor_persists_wake_packet_and_decision(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

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


def test_supervisor_packet_uses_canonical_task_contents_override(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("weakened after start", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
    agent = StatelessSupervisorAgent(
        object(),  # type: ignore[arg-type]
        store,
        task,
        task_contents="strict original task",
    )

    packet = agent.build_packet(wake_sequence=1, current_summary="review")

    assert packet.task_path == str(task)
    assert packet.task_contents == "strict original task"


async def test_runtime_prompt_uses_recent_state_and_relevant_ledgers(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\nImplement the parser.\n", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
    store.write_text_locked(
        PROGRESS,
        "# Progress\n\n" + "".join(f"- progress entry {index}\n" for index in range(40)),
    )
    store.write_text_locked(
        DECISIONS,
        "# Decisions\n\n" + "".join(f"- decision entry {index}\n" for index in range(30)),
    )

    class FakeClient:
        def __init__(self) -> None:
            self.prompt = ""

        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "runtime-thread"}}

        async def turn_start(self, params, *, timeout):
            self.prompt = params["input"][0]["text"]
            return {
                "turn": {
                    "id": "runtime-turn",
                    "status": "completed",
                    "items": [
                        {
                            "type": "agentMessage",
                            "text": json.dumps({"decision": "noop", "reason": "routine progress"}),
                        }
                    ],
                }
            }

        async def thread_archive(self, thread_id, *, timeout):
            return {}

    validations = [
        ValidationRun(
            validation_id=f"validation-{index}",
            command="pytest tests/test_target.py" if index in {2, 8, 19} else f"pytest tests/test_{index}.py",
            exit_code=0 if index % 3 else 1,
            passed=index % 3 != 0,
            trusted_validation_outcome="passed" if index % 3 else "failed",
            summary=f"validation summary {index}\n" + ("V" * 1200),
            captured_output="raw validation output\n" + ("v" * 2000),
            sequence=100 + index,
            executed_test_names=[f"test_{item}" for item in range(30)],
        )
        for index in range(20)
    ]
    validations[5] = validations[5].model_copy(
        update={
            "passed": False,
            "trusted_validation_outcome": "masked_or_unknown",
            "masking_reason": "status was hidden",
        }
    )
    inspections = [
        InspectionRun(
            inspection_id=f"inspection-{index}",
            command="sed -n '1,80p' parser.py" if index in {1, 9, 14} else f"rg symbol_{index} src",
            exit_code=0,
            passed=True,
            summary=f"inspection summary {index}\n" + ("I" * 1000),
            captured_output="raw inspection output\n" + ("i" * 2000),
            sequence=200 + index,
            inspected_paths=[f"src/file_{item}.py" for item in range(30)],
        )
        for index in range(15)
    ]
    interventions = [
        PriorIntervention(
            reason=f"reason {index}",
            message_to_coder=f"message {index}",
            sequence=300 + index,
        )
        for index in range(15)
    ]
    client = FakeClient()
    agent = StatelessSupervisorAgent(client, store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(
        wake_sequence=7,
        current_summary="Runtime trigger (nonzero_exit): targeted test failed",
        triggering_action=TriggeringAction(
            kind="commandExecution",
            command="pytest tests/test_target.py",
            exit_code=1,
            status="completed",
            summary="targeted test failed",
        ),
        validations=validations,
        inspections=inspections,
        prior_interventions=interventions,
    )

    await agent.decide(packet)

    payload = json.loads(client.prompt)
    assert client.prompt.startswith('{"instructions":')
    assert len(client.prompt) < 120_000
    assert payload["progress_path"] == ".supervisor/PROGRESS.md"
    assert payload["progress_total_entries"] == 40
    assert payload["progress_omitted_entries"] == 10
    assert "progress entry 39" in payload["progress"]
    assert "progress entry 0\n" not in payload["progress"]
    assert any("Read the complete progress file" in instruction for instruction in payload["instructions"])
    assert payload["decisions_path"] == ".supervisor/DECISIONS.md"
    assert payload["decisions_total_entries"] == 30
    assert payload["decisions_omitted_entries"] == 10
    assert "decision entry 29" in payload["decisions"]
    assert "decision entry 0\n" not in payload["decisions"]
    assert len(payload["validations"]) <= 12
    assert {"validation-2", "validation-8", "validation-19"} <= {
        value["validation_id"] for value in payload["validations"]
    }
    assert any(value["trusted_validation_outcome"] == "masked_or_unknown" for value in payload["validations"])
    assert all("captured_output" not in value for value in payload["validations"])
    assert len(payload["inspections"]) <= 8
    assert "inspection-14" in {value["inspection_id"] for value in payload["inspections"]}
    assert len(payload["prior_interventions"]) == 10
    assert payload["prior_interventions"][0]["sequence"] == 305
    assert len(packet.validations) == 20
    assert len(packet.inspections) == 15
    assert "progress entry 0" in packet.progress
    assert packet.progress_path is None

    completion_payload = json.loads(build_completion_review_prompt(packet))
    assert "progress_path" not in completion_payload
    assert "progress entry 0" in completion_payload["progress"]
    assert len(completion_payload["validations"]) == 20

    await agent.decide(
        packet.model_copy(
            update={
                "triggering_action": TriggeringAction(
                    kind="commandExecution",
                    command="sed -n '1,80p' parser.py",
                    exit_code=0,
                    status="completed",
                    summary="source inspection",
                )
            }
        )
    )
    inspection_payload = json.loads(client.prompt)
    assert {"inspection-1", "inspection-9", "inspection-14"} <= {
        value["inspection_id"] for value in inspection_payload["inspections"]
    }


async def test_completion_review_persists_use_case_and_decision(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

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


async def test_completion_review_inherits_exact_thread_deny_read_profile(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
    review_root = tmp_path / "coder-snapshot"
    review_root.mkdir()
    (review_root / ".supervisor").symlink_to(store.state_dir, target_is_directory=True)

    class FakeClient:
        def __init__(self) -> None:
            self.thread_params: list[dict[str, object]] = []
            self.turn_params: list[dict[str, object]] = []

        async def thread_start(self, params, *, timeout):
            self.thread_params.append(params)
            return {
                "thread": {"id": "completion-thread"},
                "activePermissionProfile": {
                    "id": COMPLETION_PERMISSION_PROFILE,
                    "extends": ":read-only",
                },
                "sandbox": {"type": "readOnly", "networkAccess": False},
            }

        async def turn_start(self, params, *, timeout):
            self.turn_params.append(params)
            return {
                "turn": {
                    "id": f"completion-turn-{len(self.turn_params)}",
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

    client = FakeClient()
    agent = StatelessSupervisorAgent(
        client,  # type: ignore[arg-type]
        store,
        task,
        workspace_root=review_root,
        denied_workspace_read_paths=(
            "./.supervisor/coder/CHECKLIST.md",
            ".supervisor/coder/CHECKLIST.md",
        ),
        configured_mcp_server_names=("docs",),
        configured_plugin_names=("browser@openai-bundled",),
    )
    packet = agent.build_packet(wake_sequence=7, current_summary="completion review")

    await agent.decide_completion(packet)
    await agent.decide_completion(packet)

    assert len(client.thread_params) == 1
    thread_params = client.thread_params[0]
    assert thread_params["permissions"] == COMPLETION_PERMISSION_PROFILE
    assert "sandbox" not in thread_params
    profile = thread_params["config"]["permissions"][COMPLETION_PERMISSION_PROFILE]  # type: ignore[index]
    assert profile["extends"] == ":read-only"
    assert profile["filesystem"] == {
        str(store.coder_checklist_path().parent.resolve()): "deny"
    }
    assert thread_params["config"]["include_apps_instructions"] is False  # type: ignore[index]
    assert thread_params["config"]["apps"] == {"_default": {"enabled": False}}  # type: ignore[index]
    assert thread_params["config"]["mcp_servers"] == {"docs": {"enabled": False}}  # type: ignore[index]
    assert thread_params["config"]["plugins"] == {  # type: ignore[index]
        "browser@openai-bundled": {"enabled": False}
    }
    assert thread_params["dynamicTools"] == []
    assert thread_params["environments"] == []
    assert ".supervisor/PROGRESS.md" not in json.dumps(profile)
    assert ".supervisor/DECISIONS.md" not in json.dumps(profile)
    assert len(client.turn_params) == 2
    assert all("sandboxPolicy" not in params for params in client.turn_params)
    assert all("permissions" not in params for params in client.turn_params)
    assert all(params["approvalPolicy"] == "never" for params in client.turn_params)
    assert all(params["cwd"] == str(review_root) for params in client.turn_params)
    assert all(
        params["runtimeWorkspaceRoots"] == [str(review_root)]
        for params in client.turn_params
    )


async def test_completion_review_deny_read_profile_mismatch_fails_closed(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class FakeClient:
        def __init__(self) -> None:
            self.turn_started = False
            self.archived: list[str] = []

        async def thread_start(self, params, *, timeout):
            return {
                "thread": {"id": "unsafe-completion-thread"},
                "activePermissionProfile": {"id": ":read-only", "extends": None},
                "sandbox": {"type": "readOnly", "networkAccess": False},
            }

        async def turn_start(self, params, *, timeout):
            self.turn_started = True
            raise AssertionError("turn must not start without the exact deny-read profile")

        async def thread_archive(self, thread_id, *, timeout):
            self.archived.append(thread_id)
            return {}

    client = FakeClient()
    agent = StatelessSupervisorAgent(
        client,  # type: ignore[arg-type]
        store,
        task,
        denied_workspace_read_paths=(".supervisor/coder/CHECKLIST.md",),
    )
    packet = agent.build_packet(wake_sequence=7, current_summary="completion review")

    with pytest.raises(SupervisorAgentError, match="expected read-only deny-read profile"):
        await agent.decide_completion(packet)

    assert client.turn_started is False
    assert client.archived == ["unsafe-completion-thread"]


def test_completion_deny_read_paths_must_be_exact_workspace_relative_files(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    for invalid_path in ("../CHECKLIST.md", str(tmp_path / "CHECKLIST.md"), "**/CHECKLIST.md"):
        with pytest.raises(ValueError):
            StatelessSupervisorAgent(
                object(),  # type: ignore[arg-type]
                store,
                task,
                denied_workspace_read_paths=(invalid_path,),
            )


async def test_adv_report_controller_uses_its_own_prompt_and_decision_schema(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Fix the parser", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
    raw_report = (
        "candidate_finding: true\n"
        "attacked: empty input\n"
        "findings: exact input: ''; raw output: crash\n"
        "observations: quoted newline behavior looked suspicious\n"
        "overall: Defects remain in the submitted solution"
    )

    class FakeClient:
        def __init__(self) -> None:
            self.prompt = ""

        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "adv-report-controller-thread"}}

        async def turn_start(self, params, *, timeout):
            self.prompt = params["input"][0]["text"]
            assert set(params["outputSchema"]["properties"]) == {
                "forward_to_coder",
                "reason",
                "report_to_coder",
                "material_coverage_limitations",
            }
            assert params["sandboxPolicy"] == {"type": "readOnly", "networkAccess": False}
            return {
                "turn": {
                    "id": "adv-report-controller-turn",
                    "status": "completed",
                    "items": [
                        {
                            "type": "agentMessage",
                            "text": json.dumps(
                                {
                                    "forward_to_coder": True,
                                    "reason": "retained report material",
                                    "report_to_coder": (
                                        "Finding: confirmed and requires correction.\n\n"
                                        "Observation: investigate and fix only if confirmed.\n\n"
                                        "## Findings requiring correction\n\n"
                                        "exact input: ''; raw output: crash\n\n"
                                        "## Observations requiring investigation\n\n"
                                        "quoted newline behavior looked suspicious"
                                    ),
                                    "material_coverage_limitations": [],
                                }
                            ),
                        }
                    ],
                }
            }

        async def thread_archive(self, thread_id, *, timeout):
            return {}

    client = FakeClient()
    agent = StatelessSupervisorAgent(client, store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(
        wake_sequence=7,
        current_summary="normalize adversary report",
        adversary_report=AdversaryReport(
            candidate_finding=True,
            report_text=raw_report,
            generation=0,
            completion_wake_sequence=7,
            workspace_state_id="state-7",
            created_at="2026-08-04T00:00:00+00:00",
        ),
    )

    decision = await agent.decide_adv_report(packet)

    assert decision.forward_to_coder is True
    assert "quoted newline behavior looked suspicious" in (decision.report_to_coder or "")
    payload = json.loads(client.prompt)
    assert payload["raw_adversary_report"] == raw_report
    audits = [json.loads(line) for line in store.path(SUPERVISOR_WAKES).read_text(encoding="utf-8").splitlines()]
    assert audits[-1]["use_case"] == "adv_report_controller"
    assert audits[-1]["decision"]["forward_to_coder"] is True


async def test_completion_review_uses_minimal_retry_after_repair_output_is_invalid(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\nImplement the compiler.\n", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
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
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

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
    # command/summary) is kept so the accept gate can bind to it. Only a tiny bounded
    # factual capture survives for trusted behavioral checks; full output and inlined
    # file diffs are dropped because the supervisor reads the workspace itself.
    assert "inspection-49" in client.prompt  # evidence id (skeleton) kept
    assert "validation-11" in client.prompt
    assert "INSPECTION-49" not in client.prompt  # inspection capture not inlined
    assert "v" * 1000 not in client.prompt  # behavioral capture is tightly bounded
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
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

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
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

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
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

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
