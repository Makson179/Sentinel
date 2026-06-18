from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType

import pytest

from supervisor.approvals import ApprovalManager
from supervisor.controller import (
    NO_MARKER_IDLE_NUDGE,
    ControllerEvent,
    SentinelController,
    _has_malformed_readiness_marker,
    _has_passing_behavioral_validation,
    _has_readiness_marker,
    _path_from_git_status_line,
    _evidence_provenance_summary,
    _file_kind,
    _validation_from_action,
    _validation_freshness_summary,
)
from supervisor.approvals import normalize_approval_request
from supervisor.appserver import APP_SERVER_CODER_RPC_TIMEOUT_SECONDS, AppServerError, AppServerMessage, AppServerTimeoutError
from supervisor.coder import CoderSession, coder_thread_params, coder_turn_params
from supervisor.main import _run_async_cleanly
from supervisor.schemas import (
    AppEvent,
    AppEventSource,
    ApprovalDecisionKind,
    ChangedFile,
    ChangedFileDiff,
    CoderMessage,
    CompletionReturnRecord,
    CompletionReviewDecision,
    FinalReport,
    PriorIntervention,
    RestartHandoff,
    SentinelConfig,
    SentinelStatus,
    SupervisorDecision,
    SupervisorDecisionKind,
    SupervisorWakePacket,
    TriggeringAction,
    ValidationRun,
)
from supervisor.state import (
    CONFIG,
    EVENTS,
    FINAL_REPORT,
    HANDOFF,
    LOG,
    PROGRESS,
    RUNTIME_METRICS,
    RUNTIME_TRACE,
    SUPERVISOR_WAKES,
    StateStore,
)
from supervisor.supervisor_agent import StatelessSupervisorAgent


def test_sentinel_state_initializes_required_files(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    assert store.path(EVENTS).exists()
    assert store.path(FINAL_REPORT).exists()
    assert store.get_sentinel_config().task_path == str(task)


def test_coder_sandbox_defaults_to_read_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("SENTINEL_CODER_SANDBOX", raising=False)

    assert coder_thread_params(tmp_path)["sandbox"] == "read-only"
    assert coder_turn_params("thread", "work", tmp_path)["sandboxPolicy"] == {
        "type": "readOnly",
        "networkAccess": False,
    }


def test_git_status_path_parser_handles_missing_second_status_column() -> None:
    assert _path_from_git_status_line(" M public/src/admin/manage/users.js") == "public/src/admin/manage/users.js"
    assert _path_from_git_status_line("M  public/language/en-GB/admin/manage/users.json") == "public/language/en-GB/admin/manage/users.json"
    assert _path_from_git_status_line("M public/language/en-GB/admin/manage/users.json") == "public/language/en-GB/admin/manage/users.json"


async def test_changed_files_and_diff_summary_filter_internal_runtime_paths(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.use_git_diff = True
    controller.observed_changed_files = {
        ".supervisor/CONFIG.json": ChangedFile(path=".supervisor/CONFIG.json", status="modified", sequence=1),
        "TASK.md": ChangedFile(path="TASK.md", status="modified", sequence=2),
        "src/app.py": ChangedFile(path="src/app.py", status="modified", sequence=3),
    }

    async def is_git_work_tree() -> bool:
        return True

    async def git_output(command):
        if command == ["git", "status", "--short"]:
            return " M .supervisor/CONFIG.json\n M TASK.md\n M src/app.py"
        if command == ["git", "diff", "--numstat", "HEAD", "--"]:
            return "1\t1\t.supervisor/CONFIG.json\n1\t0\tTASK.md\n2\t3\tsrc/app.py"
        if command == ["git", "diff", "--stat"]:
            return " .supervisor/CONFIG.json | 2 +-\n TASK.md | 1 +\n src/app.py | 5 ++---\n 3 files changed"
        if command == ["git", "diff", "--name-only"]:
            return ".supervisor/CONFIG.json\nTASK.md\nsrc/app.py"
        return None

    controller._is_git_work_tree = is_git_work_tree
    controller._git_output = git_output

    changed = await controller.changed_files()
    diff = await controller.diff_summary()

    assert [file.path for file in changed] == ["src/app.py"]
    assert ".supervisor" not in diff
    assert "TASK.md" not in diff
    assert "src/app.py" in diff


def test_file_kind_classifies_common_test_roots_before_source_extensions() -> None:
    assert _file_kind("test/user/emails.js") == "test"
    assert _file_kind("tests/test_flow.py") == "test"
    assert _file_kind("src/user/email.js") == "source"


def test_coder_sandbox_can_use_danger_full_access(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_CODER_SANDBOX", "danger-full-access")

    assert coder_thread_params(tmp_path)["sandbox"] == "danger-full-access"
    assert coder_turn_params("thread", "work", tmp_path)["sandboxPolicy"] == {"type": "dangerFullAccess"}


def test_sentinel_events_are_append_only_jsonl(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    store.append_event(AppEvent(sequence=1, source=AppEventSource.SYSTEM, event_type="test"))

    lines = store.path(EVENTS).read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0])["event_type"] == "test"


def test_final_report_rendering(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    store.write_final_report(FinalReport(task_path=str(task), status="complete", result="done", files_changed=["a.py"]))

    text = store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert "# Final Report" in text
    assert "- a.py" in text


async def test_final_report_non_git_omits_git_usage_and_includes_validations(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.use_git_diff = True
    controller.validations = [
        ValidationRun(command="pytest -q", exit_code=0, passed=True, summary="command completed: pytest -q exit=0", sequence=1)
    ]
    controller.observed_changed_files = {"cron.py": ChangedFile(path="cron.py", status="modified")}
    controller.tui = _FakeTUI()
    controller.running = True

    await controller.finalize("task complete")

    text = store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert "usage: git diff" not in text
    assert "fatal: not a git repository" not in text
    assert "## Diff Summary" not in text
    assert "- cron.py" in text
    assert "- pytest -q (behavioral pass, exit=0)" in text


def test_validation_ledger_classifies_static_and_behavioral_commands() -> None:
    static_commands = [
        "/bin/zsh -lc 'node -c src/user/email.js'",
        "/bin/zsh -lc 'node --check src/user/email.js'",
        "npm run type-check",
        "pnpm run type-check",
        "yarn type-check",
        "npx tsc --noemit",
        "./node_modules/.bin/eslint src/user/email.js",
        "git diff --check",
    ]
    static_runs = [
        _validation_from_action(
            TriggeringAction(
                kind="commandExecution",
                command=command,
                exit_code=0,
                status="completed",
                summary=f"command completed: {command} exit=0",
            ),
            sequence=10 + index,
        )
        for index, command in enumerate(static_commands)
    ]
    behavioral = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="/bin/zsh -lc './node_modules/.bin/mocha test/user/emails.js'",
            exit_code=0,
            status="completed",
            summary="command completed: ./node_modules/.bin/mocha test/user/emails.js exit=0",
        ),
        sequence=11,
        item={"output": "  email confirmation\n    1 passing (12ms)\n"},
    )
    zero_tests = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="npm test",
            exit_code=0,
            status="completed",
            summary="command completed: npm test exit=0",
        ),
        sequence=12,
        item={"stdout": "Tests: 0 total\n"},
    )
    filtered = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="pytest tests/test_user.py::test_sends_email -k sends",
            exit_code=0,
            status="completed",
            summary="command completed: pytest tests/test_user.py::test_sends_email -k sends exit=0",
        ),
        sequence=13,
        item={"stdout": "tests/test_user.py::test_sends_email PASSED\n1 passed in 0.01s\n"},
    )
    filtered_same_identity = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="pytest tests/test_user.py::test_sends_email -k sends",
            exit_code=0,
            status="completed",
            summary="command completed: pytest tests/test_user.py::test_sends_email -k sends exit=0",
        ),
        sequence=99,
        item={"stdout": "tests/test_user.py::test_sends_email PASSED\n1 passed in 0.01s\n"},
    )
    broad_pytest = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="ANSIBLE_DEVEL_WARNING=False python -m pytest test/units/cli/test_galaxy.py test/units/galaxy/test_collection_install.py",
            exit_code=0,
            status="completed",
            summary="command completed: pytest broad target exit=0",
        ),
        sequence=15,
        item={"stdout": "============================= 155 passed in 5.45s =============================\n"},
    )
    broad_pytest_without_output = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="ANSIBLE_DEVEL_WARNING=False python -m pytest test/units/cli/test_galaxy.py test/units/galaxy/test_collection_install.py",
            exit_code=0,
            status="completed",
            summary="command completed: pytest broad target exit=0",
        ),
        sequence=16,
    )
    direct_script = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="/bin/bash -lc 'python3 hello.py'",
            exit_code=0,
            status="completed",
            summary="command completed: /bin/bash -lc 'python3 hello.py' exit=0",
        ),
        sequence=14,
        item={"stdout": "hello world\n", "stderr": ""},
    )
    python_unittest = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="/bin/bash -lc 'python3 -B -m unittest -v'",
            exit_code=0,
            status="completed",
            summary="command completed: /bin/bash -lc 'python3 -B -m unittest -v' exit=0",
        ),
        sequence=15,
        item={"stdout": "Ran 1 test in 0.001s\n\nOK\n"},
    )
    shell_visible_script = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="/bin/bash -lc ./run_visible_tests.sh",
            exit_code=0,
            status="completed",
            summary="command completed: /bin/bash -lc ./run_visible_tests.sh exit=0",
        ),
        sequence=16,
        item={"stdout": "============================= 45 passed in 0.06s =============================\n"},
    )
    direct_visible_script = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="./run_visible_tests.sh",
            exit_code=0,
            status="completed",
            summary="command completed: ./run_visible_tests.sh exit=0",
        ),
        sequence=17,
        item={"stdout": "============================= 45 passed in 0.06s =============================\n"},
    )
    absolute_go_test = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="/usr/local/go/bin/go test -count=1 ./...",
            exit_code=0,
            status="completed",
            summary="command completed: /usr/local/go/bin/go test -count=1 ./... exit=0",
        ),
        sequence=18,
        item={"result": {"stdout": "ok github.com/example/project/core 0.02s\n"}},
    )

    assert all(run is not None and run.type == "static" and run.outcome == "pass" for run in static_runs)
    assert behavioral is not None
    assert behavioral.type == "behavioral"
    assert behavioral.outcome == "pass"
    assert zero_tests is not None
    assert zero_tests.type == "behavioral"
    assert zero_tests.outcome == "fail"
    assert not zero_tests.passed
    assert filtered is not None
    assert filtered_same_identity is not None
    assert filtered.validation_id.startswith("validation-")
    assert filtered.validation_id == filtered_same_identity.validation_id
    assert filtered.raw_command == "pytest tests/test_user.py::test_sends_email -k sends"
    assert filtered.normalized_command == "pytest tests/test_user.py::test_sends_email -k sends"
    assert filtered.trusted_validation_outcome == "passed"
    assert filtered.was_filtered is True
    assert "tests/test_user.py::test_sends_email" in filtered.executed_test_names
    assert filtered.executed_test_files == ["tests/test_user.py"]
    assert filtered.passed_count == 1
    assert filtered.failed_count == 0
    assert filtered.target_files_or_test_files == ["tests/test_user.py"]
    assert broad_pytest is not None
    assert broad_pytest.executed_test_names == [
        "test/units/cli/test_galaxy.py",
        "test/units/galaxy/test_collection_install.py",
    ]
    assert broad_pytest.executed_test_files == []
    assert broad_pytest.passed_count == 155
    assert broad_pytest.failed_count == 0
    assert broad_pytest_without_output is not None
    assert broad_pytest_without_output.executed_test_names == [
        "test/units/cli/test_galaxy.py",
        "test/units/galaxy/test_collection_install.py",
    ]
    assert broad_pytest_without_output.executed_test_files == []
    assert broad_pytest_without_output.passed_count is None
    assert broad_pytest_without_output.failed_count is None
    assert direct_script is not None
    assert direct_script.type == "behavior_demo"
    assert direct_script.captured_output == "hello world\n"
    assert direct_script.validation_id.startswith("validation-")
    assert shell_visible_script is not None
    assert shell_visible_script.type == "behavioral"
    assert shell_visible_script.trusted_validation_outcome == "passed"
    assert shell_visible_script.passed_count == 45
    assert shell_visible_script.failed_count == 0
    assert direct_visible_script is not None
    assert direct_visible_script.type == "behavioral"
    assert direct_visible_script.passed_count == 45
    assert direct_visible_script.failed_count == 0
    assert absolute_go_test is not None
    assert absolute_go_test.type == "behavioral"
    assert absolute_go_test.passed is True
    assert "github.com/example/project/core" in absolute_go_test.captured_output
    assert _has_passing_behavioral_validation([*static_runs, behavioral, zero_tests, filtered, direct_script, shell_visible_script, direct_visible_script, absolute_go_test])


async def test_command_output_delta_is_attached_to_validation_ledger(tmp_path: Path) -> None:
    controller, _store, _fake = _runtime_controller(tmp_path)

    await controller.handle_notification(
        AppServerMessage(
            {
                "method": "item/commandExecution/outputDelta",
                "params": {"threadId": "thread", "turnId": "turn", "itemId": "cmd-1", "delta": "hello "},
            }
        )
    )
    await controller.handle_notification(
        AppServerMessage(
            {
                "method": "item/commandExecution/outputDelta",
                "params": {"threadId": "thread", "turnId": "turn", "itemId": "cmd-1", "delta": {"text": "world\n"}},
            }
        )
    )
    await controller.handle_notification(
        AppServerMessage(
            {
                "method": "item/completed",
                "params": {
                    "threadId": "thread",
                    "turnId": "turn",
                    "itemId": "cmd-1",
                    "item": {
                        "type": "commandExecution",
                        "command": "python3 hello.py",
                        "exitCode": 0,
                        "status": "completed",
                    },
                },
            }
        )
    )
    if controller._supervisor_task is not None:
        await controller._supervisor_task

    assert len(controller.validations) == 1
    validation = controller.validations[0]
    assert validation.command == "python3 hello.py"
    assert validation.type == "behavior_demo"
    assert validation.passed is True
    assert "hello world" in validation.summary
    assert validation.captured_output == "hello world\n"
    assert controller._command_output_chunks == {}


async def test_camelcase_stdout_delta_is_attached_to_validation_ledger(tmp_path: Path) -> None:
    controller, _store, _fake = _runtime_controller(tmp_path)

    await controller.handle_notification(
        AppServerMessage(
            {
                "method": "item/commandExecution/stdoutDelta",
                "params": {"threadId": "thread", "turnId": "turn", "itemId": "cmd-1", "stdout": "ok pkg/a 0.01s\n"},
            }
        )
    )
    await controller.handle_notification(
        AppServerMessage(
            {
                "method": "item/completed",
                "params": {
                    "threadId": "thread",
                    "turnId": "turn",
                    "itemId": "cmd-1",
                    "item": {
                        "type": "commandExecution",
                        "command": "/usr/local/go/bin/go test -count=1 ./...",
                        "exitCode": 0,
                        "status": "completed",
                    },
                },
            }
        )
    )

    assert len(controller.validations) == 1
    validation = controller.validations[0]
    assert validation.command == "/usr/local/go/bin/go test -count=1 ./..."
    assert validation.type == "behavioral"
    assert validation.passed is True
    assert validation.captured_output == "ok pkg/a 0.01s\n"
    assert "ok pkg/a" in validation.summary


def test_readiness_marker_detection_requires_own_exact_line() -> None:
    assert _has_readiness_marker("Summary\n  SENTINEL_READY_FOR_REVIEW  \n")
    assert not _has_readiness_marker("Summary SENTINEL_READY_FOR_REVIEW")
    assert not _has_readiness_marker("sentinel_ready_for_review")
    assert _has_malformed_readiness_marker("sentinel_ready_for_review")
    assert _has_malformed_readiness_marker("SENTINEL READY FOR REVIEW")
    assert not _has_malformed_readiness_marker("I am not emitting `SENTINEL_READY_FOR_REVIEW`.")


async def test_exact_marker_triggers_completion_review_accept(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )

    class CompletionSupervisor:
        def __init__(self) -> None:
            self.agent = StatelessSupervisorAgent(None, store, task)  # type: ignore[arg-type]
            self.completion_packets = []

        def build_packet(self, **kwargs):
            packet = self.agent.build_packet(**kwargs)
            return packet

        async def decide(self, packet):
            raise AssertionError("runtime monitor should not handle exact marker")

        async def decide_completion(self, packet):
            self.completion_packets.append(packet)
            return CompletionReviewDecision(
                decision="accept",
                reason="fresh behavioral validation covers the task",
                files_reviewed=[
                    {"path": "TASK.md", "reason": "task contract", "kind": "other", "inspected": True, "limitation": None}
                ],
                behavior_evidence_matrix=[
                    {
                        "behavior": "task is complete",
                        "task_basis": "TASK.md",
                        "files_considered": ["TASK.md"],
                        "evidence": [
                            {
                                "validation_id": "validation-1",
                                "command": "pytest",
                                "sequence": 1,
                                "validation_type": "behavioral",
                                "outcome": "pass",
                                "freshness": "fresh",
                                "why_it_covers_behavior": "passes the submitted validation",
                            }
                        ],
                        "status": "covered",
                        "gap": None,
                    }
                ],
                uncovered_behaviors=[],
                validation_gaps=[],
                claim_evidence_mismatches=[],
                packet_or_access_limitations=[],
                changed_test_risks=[],
                message_to_coder=None,
                persistent_decision=None,
                progress_update="Completion review accepted final readiness.",
                clear_handoff=False,
                display_message=None,
                handoff=None,
                wake_sequence=packet.wake_sequence,
                generation=packet.generation,
            )

    fake = CompletionSupervisor()
    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.supervisor = fake
    controller.pending_approvals = {}
    controller.last_coder_message = CoderMessage(
        text="Summary: done\nValidation: pytest\nSENTINEL_READY_FOR_REVIEW",
        sequence=1,
    )
    controller.validations = [
        ValidationRun(command="pytest", exit_code=0, passed=True, summary="passed", sequence=1)
    ]
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.tui = _FakeTUI()
    controller.running = True
    controller.event_queue = asyncio.Queue()
    controller._sequence = 0
    controller._supervisor_dirty = False
    controller._supervisor_next_summary = None
    controller._supervisor_next_completion_review = False
    controller._supervisor_task = None
    controller._last_completion_marker_sequence = None
    controller.no_marker_idle_nudge_count = 0
    controller.completion_returns = []
    controller.completion_attempt_count = 0
    controller.completion_restarts = 0
    controller.paused = False

    await controller._handle_coder_turn_completed(item_id="message-item")
    await controller._supervisor_task

    assert len(fake.completion_packets) == 1
    assert fake.completion_packets[0].last_coder_message.text.endswith("SENTINEL_READY_FOR_REVIEW")
    assert store.get_sentinel_config().status == SentinelStatus.COMPLETE
    assert "accepted by completion_review" in store.path(FINAL_REPORT).read_text(encoding="utf-8")


async def test_summary_done_without_marker_steers_for_exact_marker_not_completion(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"), overwrite=True)

    class FakeCoder:
        def __init__(self) -> None:
            self.messages = []

        async def steer_or_start(self, message):
            self.messages.append(message)
            return "turn"

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.supervisor = None
    controller.coder = FakeCoder()
    controller.pending_approvals = {}
    controller.last_coder_message = CoderMessage(text="All tests pass. Done.", sequence=1)
    controller.validations = []
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.tui = _FakeTUI()
    controller.running = True
    controller.event_queue = asyncio.Queue()
    controller._sequence = 0
    controller._supervisor_dirty = False
    controller._supervisor_next_summary = None
    controller._supervisor_next_completion_review = False
    controller._supervisor_task = None
    controller.paused = False

    await controller._handle_coder_turn_completed(item_id="message-item")

    assert controller.coder.messages == [NO_MARKER_IDLE_NUDGE]
    assert store.get_sentinel_config().status == SentinelStatus.STARTING


async def test_material_limitation_without_marker_escalates_instead_of_marker_nudge(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"), overwrite=True)

    class FakeCoder:
        def __init__(self) -> None:
            self.messages = []
            self.interrupted = False

        async def steer_or_start(self, message):
            self.messages.append(message)
            return "turn"

        async def interrupt(self):
            self.interrupted = True

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.supervisor = None
    controller.coder = FakeCoder()
    controller.pending_approvals = {}
    controller.last_coder_message = CoderMessage(
        text=(
            "I do not believe the task is ready.\n\n"
            "Validation: changed focused Jest coverage passed earlier.\n\n"
            "Material limitation: Independent behavioral evidence is still missing. "
            "Current instructions prohibit adding a temporary behavior test, so there is "
            "no compliant next validation step. Therefore I am not emitting "
            "`SENTINEL_READY_FOR_REVIEW`."
        ),
        sequence=7,
    )
    controller.validations = []
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.tui = _FakeTUI()
    controller.running = True
    controller.client = None
    controller.event_queue = asyncio.Queue()
    controller._sequence = 0
    controller._supervisor_dirty = False
    controller._supervisor_next_summary = None
    controller._supervisor_next_completion_review = False
    controller._supervisor_task = None
    controller.paused = False
    controller.no_marker_idle_nudge_count = 0
    controller.completion_returns = []
    controller.completion_restarts = 0

    await controller._handle_coder_turn_completed(item_id="message-item")

    assert store.get_sentinel_config().status == SentinelStatus.ESCALATED
    assert controller.coder.messages == []
    assert controller.coder.interrupted is True
    assert "Coder reported material limitation" in store.path(PROGRESS).read_text(encoding="utf-8")
    assert "material validation limitation" in store.path(FINAL_REPORT).read_text(encoding="utf-8")


async def test_no_marker_idle_forces_completion_review_once(tmp_path: Path) -> None:
    controller, store, fake = _runtime_controller(tmp_path)
    store.update_sentinel_config(
        lambda cfg: cfg.model_copy(update={"active_coder_turn_id": None, "last_event_sequence": 17})
    )

    await controller._handle_no_marker_idle()
    await controller._supervisor_task

    assert len(fake.completion_packets) == 1
    assert controller.completion_returns[0].reason == "not used"
    assert "Controller forcing completion_review" in store.path(PROGRESS).read_text(encoding="utf-8")

    await controller._handle_no_marker_idle()

    assert len(fake.completion_packets) == 1


def test_runtime_supervisor_schema_rejects_complete() -> None:
    with pytest.raises(Exception):
        SupervisorDecision.model_validate({"decision": "complete"})


def test_validation_freshness_summary_marks_stale_behavioral_pass() -> None:
    summary = _validation_freshness_summary(
        validations=[
            ValidationRun(command="pytest", exit_code=0, passed=True, summary="passed", sequence=5),
        ],
        changed_files=[ChangedFile(path="app.py", status="modified", sequence=8)],
    )

    assert "behavioral validation is stale" in summary


async def test_runtime_noop_action_skips_supervisor_and_records_trace(tmp_path: Path) -> None:
    controller, store, fake = _runtime_controller(tmp_path)

    await controller.handle_notification(
        AppServerMessage(
            {
                "method": "item/completed",
                "params": {
                    "threadId": "thread",
                    "itemId": "cmd-1",
                    "item": {
                        "type": "commandExecution",
                        "command": "python3 -c 'print(1)'",
                        "exitCode": 0,
                        "status": "completed",
                    },
                },
            }
        )
    )

    assert fake.runtime_packets == []
    trace = json.loads(store.path(RUNTIME_TRACE).read_text(encoding="utf-8").splitlines()[-1])
    assert trace["skipped_noop"] is True
    assert trace["should_wake_runtime_supervisor"] is False
    metrics = json.loads(store.path(RUNTIME_METRICS).read_text(encoding="utf-8"))
    assert metrics["runtime_skipped_noop_total"] == 1


async def test_runtime_nonzero_action_wakes_supervisor(tmp_path: Path) -> None:
    controller, store, fake = _runtime_controller(tmp_path)

    await controller.handle_notification(
        AppServerMessage(
            {
                "method": "item/completed",
                "params": {
                    "threadId": "thread",
                    "itemId": "cmd-1",
                    "item": {
                        "type": "commandExecution",
                        "command": "python3 -c 'raise SystemExit(1)'",
                        "exitCode": 1,
                        "status": "completed",
                    },
                },
            }
        )
    )
    await controller._supervisor_task

    assert len(fake.runtime_packets) == 1
    assert fake.runtime_packets[0].triggering_action.exit_code == 1
    trace = json.loads(store.path(RUNTIME_TRACE).read_text(encoding="utf-8").splitlines()[-1])
    assert trace["should_wake_runtime_supervisor"] is True
    assert "nonzero_exit" in trace["trigger_reasons"]


async def test_runtime_restart_budget_wakes_supervisor(tmp_path: Path) -> None:
    controller, store, fake = _runtime_controller(tmp_path)
    store.patch_health(lambda health: health.model_copy(update={"restart_count": 3}))

    await controller.handle_notification(
        AppServerMessage(
            {
                "method": "item/completed",
                "params": {
                    "threadId": "thread",
                    "itemId": "cmd-1",
                    "item": {
                        "type": "commandExecution",
                        "command": "python3 -c 'print(1)'",
                        "exitCode": 0,
                        "status": "completed",
                    },
                },
            }
        )
    )
    await controller._supervisor_task

    assert len(fake.runtime_packets) == 1
    trace = json.loads(store.path(RUNTIME_TRACE).read_text(encoding="utf-8").splitlines()[-1])
    assert "restart_budget" in trace["trigger_reasons"]


async def test_masked_validation_wakes_and_is_not_trusted(tmp_path: Path) -> None:
    controller, store, fake = _runtime_controller(tmp_path)

    await controller.handle_notification(
        AppServerMessage(
            {
                "method": "item/completed",
                "params": {
                    "threadId": "thread",
                    "itemId": "cmd-1",
                    "item": {
                        "type": "commandExecution",
                        "command": "pytest tests/test_app.py | cat",
                        "exitCode": 0,
                        "status": "completed",
                        "stdout": "tests/test_app.py::test_app PASSED\n1 passed in 0.01s\n",
                    },
                },
            }
        )
    )
    await controller._supervisor_task

    assert len(fake.runtime_packets) == 1
    assert controller.validations[0].trusted_validation_outcome == "masked_or_unknown"
    assert controller.validations[0].masking_reason == "pipeline_without_pipefail"
    trace = json.loads(store.path(RUNTIME_TRACE).read_text(encoding="utf-8").splitlines()[-1])
    assert "masked_validation" in trace["trigger_reasons"]


async def test_repeated_same_failing_validation_uses_command_identity(tmp_path: Path) -> None:
    controller, store, fake = _runtime_controller(tmp_path)
    item = {
        "type": "commandExecution",
        "command": "pytest tests/test_app.py",
        "exitCode": 1,
        "status": "completed",
        "stdout": "tests/test_app.py::test_app FAILED\n1 failed in 0.01s\n",
    }

    await controller.handle_notification(
        AppServerMessage({"method": "item/completed", "params": {"threadId": "thread", "itemId": "cmd-1", "item": item}})
    )
    await controller._supervisor_task
    await controller.handle_notification(
        AppServerMessage({"method": "item/completed", "params": {"threadId": "thread", "itemId": "cmd-2", "item": item}})
    )
    await controller._supervisor_task

    assert len(fake.runtime_packets) == 2
    assert controller.validations[0].validation_id == controller.validations[1].validation_id
    trace = json.loads(store.path(RUNTIME_TRACE).read_text(encoding="utf-8").splitlines()[-1])
    assert "repeated_same_failing_validation" in trace["trigger_reasons"]


async def test_done_without_fresh_validation_wakes_runtime_not_completion(tmp_path: Path) -> None:
    controller, store, fake = _runtime_controller(tmp_path)
    controller.last_coder_message = CoderMessage(text="Summary\nSENTINEL_READY_FOR_REVIEW", sequence=3)
    controller.observed_changed_files = {
        "src/app.py": ChangedFile(path="src/app.py", status="modified", sequence=2)
    }
    controller.validations = [
        ValidationRun(
            command="node --check src/app.js",
            exit_code=0,
            type="static",
            passed=True,
            summary="ok",
            sequence=3,
        )
    ]

    await controller._handle_coder_turn_completed(item_id="done-1")
    await controller._supervisor_task

    assert len(fake.runtime_packets) == 1
    assert fake.completion_packets == []
    assert store.get_sentinel_config().last_relevant_edit_sequence == 2
    trace = json.loads(store.path(RUNTIME_TRACE).read_text(encoding="utf-8").splitlines()[-1])
    assert trace["trigger_reasons"] == ["done_without_fresh_validation"]


async def test_completion_packet_details_can_send_delta_after_return(tmp_path: Path) -> None:
    controller, _, _ = _runtime_controller(tmp_path)
    controller.validations = [
        ValidationRun(command="pytest old.py", exit_code=0, passed=True, summary="old", sequence=1),
        ValidationRun(command="pytest new.py", exit_code=0, passed=True, summary="new", sequence=5),
    ]
    changed_files = [
        ChangedFile(path="src/old.py", status="M", sequence=2),
        ChangedFile(path="src/new.py", status="M", sequence=6),
    ]

    details = await controller.completion_packet_details(changed_files, since_sequence=3)

    assert [diff.path for diff in details["changed_file_diffs"]] == ["src/new.py"]
    assert [validation.validation_id for validation in details["validation_outputs"]] == [
        controller.validations[1].validation_id
    ]


def test_evidence_provenance_marks_changed_test_as_self_confirming() -> None:
    summary = _evidence_provenance_summary(
        validations=[
            ValidationRun(
                command="pytest tests/test_app_new.py",
                exit_code=0,
                passed=True,
                summary="tests/test_app_new.py::test_requested_behavior PASSED\n1 passed",
                captured_output="tests/test_app_new.py::test_requested_behavior PASSED\n1 passed\n",
                executed_test_files=["tests/test_app_new.py"],
                sequence=3,
            )
        ],
        changed_files=[
            ChangedFile(path="src/app.py", status="M", sequence=2),
            ChangedFile(path="tests/test_app_new.py", status="A", sequence=2),
        ],
        latest_change_sequence=2,
    )

    provenance = summary.validations[0]
    assert provenance.independence_class == "self_confirming"
    assert provenance.output_identifies_test_files is True
    assert provenance.coder_authored_test_files == ["tests/test_app_new.py"]
    assert provenance.untouched_executed_test_files == []
    assert provenance.risk_reasons == ["all_output_identified_tests_were_coder_authored"]


def test_evidence_provenance_canonicalizes_changed_tsx_test_reported_as_ts() -> None:
    summary = _evidence_provenance_summary(
        validations=[
            ValidationRun(
                command="npm test -- DeviceDetailHeading",
                exit_code=0,
                passed=True,
                summary="PASS src/components/DeviceDetailHeading-test.ts\n1 passed",
                captured_output="PASS src/components/DeviceDetailHeading-test.ts\n1 passed\n",
                executed_test_files=["src/components/DeviceDetailHeading-test.ts"],
                sequence=3,
            )
        ],
        changed_files=[
            ChangedFile(path="src/components/DeviceDetailHeading.tsx", status="M", sequence=2),
            ChangedFile(path="src/components/DeviceDetailHeading-test.tsx", status="A", sequence=2),
        ],
        latest_change_sequence=2,
    )

    provenance = summary.validations[0]
    assert provenance.independence_class == "self_confirming"
    assert provenance.executed_test_files == ["src/components/DeviceDetailHeading-test.ts"]
    assert provenance.coder_authored_test_files == ["src/components/DeviceDetailHeading-test.tsx"]
    assert provenance.untouched_executed_test_files == []


def test_evidence_provenance_marks_untouched_output_identified_test_as_independent() -> None:
    summary = _evidence_provenance_summary(
        validations=[
            ValidationRun(
                command="pytest tests/test_app_existing.py tests/test_app_new.py",
                exit_code=0,
                passed=True,
                summary=(
                    "tests/test_app_existing.py::test_requested_behavior PASSED\n"
                    "tests/test_app_new.py::test_requested_behavior PASSED\n2 passed"
                ),
                captured_output=(
                    "tests/test_app_existing.py::test_requested_behavior PASSED\n"
                    "tests/test_app_new.py::test_requested_behavior PASSED\n2 passed\n"
                ),
                executed_test_files=["tests/test_app_existing.py", "tests/test_app_new.py"],
                sequence=4,
            )
        ],
        changed_files=[
            ChangedFile(path="src/app.py", status="M", sequence=2),
            ChangedFile(path="tests/test_app_new.py", status="A", sequence=2),
        ],
        latest_change_sequence=2,
    )

    provenance = summary.validations[0]
    assert provenance.independence_class == "independent"
    assert provenance.coder_authored_test_files == ["tests/test_app_new.py"]
    assert provenance.untouched_executed_test_files == ["tests/test_app_existing.py"]
    assert provenance.risk_reasons == []


def test_evidence_provenance_classifies_behavior_demo_output() -> None:
    summary = _evidence_provenance_summary(
        validations=[
            ValidationRun(
                command="node -e \"console.log(render())\"",
                exit_code=0,
                type="behavior_demo",
                passed=True,
                summary="<button>Save</button>",
                captured_output="<button>Save</button>\n",
                sequence=3,
            ),
            ValidationRun(
                command="node -e \"console.log('PASS')\"",
                exit_code=0,
                type="behavior_demo",
                passed=True,
                summary="PASS",
                captured_output="PASS\n",
                sequence=4,
            ),
            ValidationRun(
                command="node -e \"runJest()\"",
                exit_code=0,
                type="behavior_demo",
                passed=True,
                summary="PASS src/App.test.tsx\n1 passed",
                captured_output="PASS src/App.test.tsx\n1 passed\n",
                sequence=5,
            ),
        ],
        changed_files=[ChangedFile(path="src/App.tsx", status="M", sequence=2)],
        latest_change_sequence=2,
    )

    factual, verdict, wrapped_test = summary.validations
    assert factual.independence_class == "independent_candidate"
    assert factual.output_kind == "factual_observation_candidate"
    assert verdict.independence_class == "not_independent"
    assert verdict.output_kind == "self_verdict_only"
    assert verdict.risk_reasons == ["behavior_demo_self_verdict_only"]
    assert wrapped_test.independence_class == "not_independent"
    assert wrapped_test.output_kind == "test_runner_output"
    assert wrapped_test.risk_reasons == ["behavior_demo_looks_like_test_runner_output"]


def test_heredoc_script_command_is_behavior_demo_validation() -> None:
    command = "python - <<'PY'\nfrom app import render\nprint(render())\nPY"
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=7,
        item={"type": "commandExecution", "stdout": "<button>Save</button>\n"},
        changed_paths=["src/app.py"],
    )

    assert validation is not None
    assert validation.type == "behavior_demo"
    assert validation.trusted_validation_outcome == "passed"
    assert validation.captured_output == "<button>Save</button>\n"


def test_validation_output_prefers_test_runner_suite_files_over_stack_trace_paths() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="npm test -- DeviceDetailHeading",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=8,
        item={
            "type": "commandExecution",
            "stdout": (
                "PASS src/components/DeviceDetailHeading-test.ts\n"
                "  at renderWithProviders (test/test-utils/utilities.ts:42:10)\n"
                "1 passed\n"
            ),
        },
        changed_paths=["src/components/DeviceDetailHeading.tsx"],
    )

    assert validation is not None
    assert validation.executed_test_files == ["src/components/DeviceDetailHeading-test.ts"]


def test_git_inspection_commands_are_not_behavioral_validations() -> None:
    diff_validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="git diff -- tests/test_app.py",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=8,
        item={"type": "commandExecution", "stdout": "diff --git a/tests/test_app.py b/tests/test_app.py\n"},
        changed_paths=["tests/test_app.py"],
    )
    check_validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="git diff --check",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=9,
        item={"type": "commandExecution", "stdout": ""},
        changed_paths=["tests/test_app.py"],
    )

    assert diff_validation is None
    assert check_validation is not None
    assert check_validation.type == "static"


def test_evidence_provenance_marks_validation_before_latest_edit_as_stale() -> None:
    summary = _evidence_provenance_summary(
        validations=[
            ValidationRun(
                command="pytest tests/test_app_existing.py",
                exit_code=0,
                passed=True,
                summary="tests/test_app_existing.py::test_requested_behavior PASSED\n1 passed",
                captured_output="tests/test_app_existing.py::test_requested_behavior PASSED\n1 passed\n",
                executed_test_files=["tests/test_app_existing.py"],
                sequence=2,
            )
        ],
        changed_files=[ChangedFile(path="src/app.py", status="M", sequence=5)],
        latest_change_sequence=5,
    )

    provenance = summary.validations[0]
    assert provenance.fresh_after_latest_relevant_change is False
    assert provenance.independence_class == "stale"
    assert provenance.risk_reasons == ["stale_after_latest_relevant_change"]


async def test_completion_review_agent_reuses_thread_until_closed(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class FakeClient:
        def __init__(self) -> None:
            self.thread_starts = 0
            self.turn_starts = []
            self.archived = []

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


async def test_completion_review_agent_overrides_stale_model_wake_sequence(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class FakeClient:
        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "completion-thread"}}

        async def turn_start(self, params, *, timeout):
            return {
                "turn": {
                    "id": "turn-1",
                    "status": "completed",
                    "items": [
                        {
                            "type": "agentMessage",
                            "text": json.dumps(
                                {
                                    "decision": "return",
                                    "reason": "needs independent demo",
                                    "files_reviewed": [],
                                    "behavior_evidence_matrix": [],
                                    "uncovered_behaviors": ["rendered element"],
                                    "validation_gaps": ["missing factual demo output"],
                                    "claim_evidence_mismatches": [],
                                    "packet_or_access_limitations": [],
                                    "changed_test_risks": [],
                                    "message_to_coder": "provide a factual behavior_demo",
                                    "persistent_decision": None,
                                    "progress_update": None,
                                    "clear_handoff": False,
                                    "display_message": None,
                                    "handoff": None,
                                    "wake_sequence": 3,
                                    "generation": 99,
                                }
                            ),
                        }
                    ],
                }
            }

        async def thread_archive(self, thread_id, *, timeout):
            return {}

    agent = StatelessSupervisorAgent(FakeClient(), store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(wake_sequence=11, current_summary="completion review")

    decision = await agent.decide_completion(packet)

    assert decision.wake_sequence == 11
    assert decision.generation == 0
    audit = json.loads(store.path(SUPERVISOR_WAKES).read_text(encoding="utf-8").splitlines()[-1])
    assert audit["decision"]["wake_sequence"] == 11
    assert '"wake_sequence": 3' in audit["raw_text"]


async def test_completion_review_reads_assistant_message_content_from_turns_list(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
    decision_text = json.dumps(
        {
            "decision": "return",
            "reason": "needs captured output",
            "files_reviewed": [],
            "behavior_evidence_matrix": [],
            "uncovered_behaviors": ["demo"],
            "validation_gaps": ["missing captured demo output"],
            "claim_evidence_mismatches": [],
            "packet_or_access_limitations": [],
            "changed_test_risks": [],
            "message_to_coder": "record demo output",
            "persistent_decision": None,
            "progress_update": None,
            "clear_handoff": False,
            "display_message": None,
            "handoff": None,
            "wake_sequence": 7,
            "generation": 0,
        }
    )

    class FakeClient:
        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "completion-thread"}}

        async def turn_start(self, params, *, timeout):
            return {"turn": {"id": "turn-1", "status": "completed", "items": []}}

        async def thread_turns_list(self, thread_id, *, limit, items_view, timeout):
            assert limit == 5
            assert items_view == "full"
            return {
                "data": [
                    {"id": "older-turn", "items": [{"type": "agentMessage", "text": "{}"}]},
                    {
                        "id": "turn-1",
                        "items": [
                            {
                                "type": "message",
                                "role": "assistant",
                                "content": [{"type": "output_text", "text": decision_text}],
                            }
                        ],
                    },
                ]
            }

        async def thread_archive(self, thread_id, *, timeout):
            return {}

    agent = StatelessSupervisorAgent(FakeClient(), store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(wake_sequence=7, current_summary="completion review")

    decision = await agent.decide_completion(packet)

    assert decision.decision == "return"
    audit = json.loads(store.path(SUPERVISOR_WAKES).read_text(encoding="utf-8").splitlines()[-1])
    assert audit["status"] == "decision"
    assert audit["raw_text"] == decision_text


async def test_terminal_state_denies_new_server_request_without_policy_path(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class FakeClient:
        def __init__(self) -> None:
            self.responses = []

        async def respond(self, request_id, response):
            self.responses.append((request_id, response))

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.store = store
    controller.client = FakeClient()
    controller.approvals = ApprovalManager(tmp_path)
    controller.tui = _FakeTUI()
    controller._terminal_cleanup_started = True

    await controller.handle_server_request(
        AppServerMessage(
            {
                "id": 99,
                "method": "item/commandExecution/requestApproval",
                "params": {"command": "echo after terminal", "availableDecisions": ["accept", "decline"]},
            }
        )
    )

    assert controller.client.responses == [(99, {"decision": "decline"})]


async def test_completion_return_sends_message_and_continues_same_generation(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )

    class FakeCoder:
        def __init__(self) -> None:
            self.messages = []

        async def steer_or_start(self, message):
            self.messages.append(message)
            return "turn"

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.coder = FakeCoder()
    controller.pending_approvals = {}
    controller.validations = []
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.tui = _FakeTUI()
    controller.running = True
    controller.event_queue = asyncio.Queue()
    controller._sequence = 0
    controller.completion_returns = []
    controller.completion_restarts = 0
    controller.completion_reviewer_rerun_count = 0
    controller.no_marker_idle_nudge_count = 0

    await controller.apply_completion_decision(
        CompletionReviewDecision(
            decision="return",
            reason="fallback behavior is uncovered",
            uncovered_behaviors=["missing-key fallback"],
            validation_gaps=["only happy path was validated"],
            message_to_coder="Validate missing-key fallback before marking ready again.",
            persistent_decision="Completion review requires fallback coverage.",
            progress_update="Completion review returned missing fallback coverage.",
            clear_handoff=False,
            display_message=None,
            handoff=None,
            wake_sequence=1,
            generation=0,
        ),
        packet_thread_id="thread",
    )

    assert store.get_sentinel_config().generation == 0
    assert controller.coder.messages == ["Validate missing-key fallback before marking ready again."]
    assert len(controller.completion_returns) == 1
    assert "Completion review returned missing fallback coverage" in store.path("PROGRESS.md").read_text(encoding="utf-8")


async def test_completion_accept_gate_rejects_empty_behavior_matrix_for_code_change(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )

    class FakeCoder:
        def __init__(self) -> None:
            self.messages = []

        async def steer_or_start(self, message):
            self.messages.append(message)
            return "turn"

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.coder = FakeCoder()
    controller.pending_approvals = {}
    controller.validations = []
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.tui = _FakeTUI()
    controller.running = True
    controller.event_queue = asyncio.Queue()
    controller._sequence = 0
    controller.completion_returns = []
    controller.completion_restarts = 0
    controller.completion_reviewer_rerun_count = 0
    controller.no_marker_idle_nudge_count = 0

    packet = SupervisorWakePacket(
        wake_sequence=1,
        latest_event_sequence=1,
        generation=0,
        restart_count=0,
        task_path=str(task),
        task_contents="# Task",
        coder_thread_id="thread",
        changed_files=[ChangedFile(path="src/app.py", status="M", sequence=2)],
        validations=[ValidationRun(command="pytest", exit_code=0, passed=True, summary="passed", sequence=3)],
        latest_relevant_change_sequence=2,
    )

    await controller.apply_completion_decision(
        CompletionReviewDecision(
            decision="accept",
            reason="looks done",
            message_to_coder=None,
            persistent_decision=None,
            progress_update="Accepted.",
            clear_handoff=False,
            display_message=None,
            handoff=None,
            wake_sequence=1,
            generation=0,
        ),
        packet_thread_id="thread",
        packet=packet,
    )

    assert store.get_sentinel_config().status == SentinelStatus.STARTING
    assert len(controller.completion_returns) == 0
    assert controller.coder.messages == []
    assert "behavior_evidence_matrix is empty" in store.path("PROGRESS.md").read_text(encoding="utf-8")
    assert store.get_sentinel_config().accept_gate_reviewer_reruns == 1


async def test_completion_accept_gate_allows_assessed_changed_test_contract_shift(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("User-facing flow depends on helper resend semantics.", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )

    class FakeCoder:
        def __init__(self) -> None:
            self.messages = []

        async def steer_or_start(self, message):
            self.messages.append(message)
            return "turn"

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.coder = FakeCoder()
    controller.pending_approvals = {}
    controller.validations = [
        ValidationRun(command="pytest tests/test_flow.py", exit_code=0, passed=True, summary="passed", sequence=5),
        ValidationRun(
            command="python - <<'PY'\nprint(flow_visible_state())\nPY",
            exit_code=0,
            type="behavior_demo",
            passed=True,
            summary="resend_allowed=True",
            captured_output="resend_allowed=True\n",
            sequence=6,
        ),
    ]
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.tui = _FakeTUI()
    controller.running = True
    controller.event_queue = asyncio.Queue()
    controller._sequence = 0
    controller.completion_returns = []
    controller.completion_restarts = 0
    controller.no_marker_idle_nudge_count = 0

    packet = SupervisorWakePacket(
        wake_sequence=1,
        latest_event_sequence=1,
        generation=0,
        restart_count=0,
        task_path=str(task),
        task_contents=task.read_text(encoding="utf-8"),
        coder_thread_id="thread",
        changed_files=[
            ChangedFile(path="src/helper.py", status="M", sequence=2),
            ChangedFile(path="tests/test_flow.py", status="M", sequence=3),
        ],
        changed_file_diffs=[
            ChangedFileDiff(
                path="tests/test_flow.py",
                file_kind="test",
                change_kind="modified",
                diff=(
                    "diff --git a/tests/test_flow.py b/tests/test_flow.py\n"
                    "@@\n"
                    "-    await db.expire('confirm:user', 1)\n"
                    "+    await db.set('helper:last_sent', old_enough)\n"
                    "     assert ok\n"
                ),
            )
        ],
        validations=controller.validations,
        latest_relevant_change_sequence=3,
    )

    await controller.apply_completion_decision(
        CompletionReviewDecision.model_validate(
            {
                "decision": "accept",
                "reason": "flow test passed",
                "files_reviewed": [
                    {"path": "src/helper.py", "reason": "changed source", "kind": "source", "inspected": True, "limitation": None},
                    {
                        "path": "tests/test_flow.py",
                        "reason": "inspected removed expiry assertion and found no unresolved changed-test risk",
                        "kind": "test",
                        "inspected": True,
                        "limitation": None,
                    },
                ],
                "behavior_evidence_matrix": [
                    {
                        "behavior": "user-facing flow and helper resend semantics",
                        "task_basis": "TASK.md",
                        "files_considered": ["src/helper.py", "tests/test_flow.py"],
                        "evidence": [
                            {
                                "validation_id": "validation-5",
                                "command": "pytest tests/test_flow.py",
                                "sequence": 5,
                                "validation_type": "behavioral",
                                "outcome": "pass",
                                "freshness": "fresh",
                                "why_it_covers_behavior": "runs the visible flow",
                            },
                            {
                                "validation_id": "validation-6",
                                "command": "python - <<'PY'\nprint(flow_visible_state())\nPY",
                                "sequence": 6,
                                "validation_type": "behavior_demo",
                                "outcome": "pass",
                                "freshness": "fresh",
                                "why_it_covers_behavior": "captures factual resend state outside the changed test",
                            },
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
                "progress_update": "Accepted.",
                "clear_handoff": False,
                "display_message": None,
                "handoff": None,
                "wake_sequence": 1,
                "generation": 0,
            }
        ),
        packet_thread_id="thread",
        packet=packet,
    )

    assert store.get_sentinel_config().status == SentinelStatus.COMPLETE
    assert len(controller.completion_returns) == 0
    assert controller.coder.messages == []
    assert store.get_sentinel_config().accept_gate_reviewer_reruns == 0


async def test_completion_accept_gate_rejects_changed_test_contract_shift_without_assessment(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("User-facing flow depends on helper resend semantics.", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )

    class FakeCoder:
        def __init__(self) -> None:
            self.messages = []

        async def steer_or_start(self, message):
            self.messages.append(message)
            return "turn"

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.coder = FakeCoder()
    controller.pending_approvals = {}
    controller.validations = [
        ValidationRun(command="pytest tests/test_flow.py", exit_code=0, passed=True, summary="passed", sequence=5)
    ]
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.tui = _FakeTUI()
    controller.running = True
    controller.event_queue = asyncio.Queue()
    controller._sequence = 0
    controller.completion_returns = []
    controller.completion_restarts = 0
    controller.no_marker_idle_nudge_count = 0

    packet = SupervisorWakePacket(
        wake_sequence=1,
        latest_event_sequence=1,
        generation=0,
        restart_count=0,
        task_path=str(task),
        task_contents=task.read_text(encoding="utf-8"),
        coder_thread_id="thread",
        changed_files=[
            ChangedFile(path="src/helper.py", status="M", sequence=2),
            ChangedFile(path="tests/test_flow.py", status="M", sequence=3),
        ],
        changed_file_diffs=[
            ChangedFileDiff(
                path="tests/test_flow.py",
                file_kind="test",
                change_kind="modified",
                diff=(
                    "diff --git a/tests/test_flow.py b/tests/test_flow.py\n"
                    "@@\n"
                    "-    await db.expire('confirm:user', 1)\n"
                    "+    await db.set('helper:last_sent', old_enough)\n"
                    "     assert ok\n"
                ),
            )
        ],
        validations=controller.validations,
        latest_relevant_change_sequence=3,
    )

    await controller.apply_completion_decision(
        CompletionReviewDecision.model_validate(
            {
                "decision": "accept",
                "reason": "flow test passed",
                "files_reviewed": [
                    {"path": "src/helper.py", "reason": "changed source", "kind": "source", "inspected": True, "limitation": None},
                    {"path": "tests/test_flow.py", "reason": "", "kind": "test", "inspected": True, "limitation": None},
                ],
                "behavior_evidence_matrix": [
                    {
                        "behavior": "user-facing flow and helper resend semantics",
                        "task_basis": "TASK.md",
                        "files_considered": ["src/helper.py", "tests/test_flow.py"],
                        "evidence": [
                            {
                                "validation_id": "validation-5",
                                "command": "pytest tests/test_flow.py",
                                "sequence": 5,
                                "validation_type": "behavioral",
                                "outcome": "pass",
                                "freshness": "fresh",
                                "why_it_covers_behavior": "runs the visible flow",
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
                "progress_update": "Accepted.",
                "clear_handoff": False,
                "display_message": None,
                "handoff": None,
                "wake_sequence": 1,
                "generation": 0,
            }
        ),
        packet_thread_id="thread",
        packet=packet,
    )

    assert store.get_sentinel_config().status == SentinelStatus.STARTING
    assert len(controller.completion_returns) == 0
    assert controller.coder.messages == []
    assert "changed tests rewrite existing behavior" in store.path("PROGRESS.md").read_text(encoding="utf-8")
    assert store.get_sentinel_config().accept_gate_reviewer_reruns == 1


async def test_completion_accept_gate_rejects_unassessed_parallel_persistence_state(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("Fix resend fallback without breaking existing confirmation expiry semantics.", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )

    class FakeCoder:
        def __init__(self) -> None:
            self.messages = []

        async def steer_or_start(self, message):
            self.messages.append(message)
            return "turn"

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.coder = FakeCoder()
    controller.pending_approvals = {}
    controller.validations = [
        ValidationRun(command="pytest tests/test_email.py", exit_code=0, passed=True, summary="passed", sequence=5)
    ]
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.tui = _FakeTUI()
    controller.running = True
    controller.event_queue = asyncio.Queue()
    controller._sequence = 0
    controller.completion_returns = []
    controller.completion_restarts = 0
    controller.completion_reviewer_rerun_count = 0
    controller.no_marker_idle_nudge_count = 0

    packet = SupervisorWakePacket(
        wake_sequence=1,
        latest_event_sequence=1,
        generation=0,
        restart_count=0,
        task_path=str(task),
        task_contents=task.read_text(encoding="utf-8"),
        coder_thread_id="thread",
        changed_files=[ChangedFile(path="src/email.js", status="M", sequence=2)],
        changed_file_diffs=[
            ChangedFileDiff(
                path="src/email.js",
                file_kind="source",
                change_kind="modified",
                diff=(
                    "diff --git a/src/email.js b/src/email.js\n"
                    "@@\n"
                    " async function sendValidation(uid, code, ttl) {\n"
                    "-  await db.set(`confirm:byUid:${uid}`, code);\n"
                    "-  await db.pexpire(`confirm:byUid:${uid}`, ttl);\n"
                    "+  await db.setObject(`confirm:pending:${uid}`, { code, expires: Date.now() + ttl });\n"
                    "+  await db.set(`confirm:byUid:${uid}`, code);\n"
                    "+  await db.pexpire(`confirm:byUid:${uid}`, ttl);\n"
                    " }\n"
                    " async function canSendValidation(uid) {\n"
                    "-  const ttl = await db.pttl(`confirm:byUid:${uid}`);\n"
                    "+  const pending = await db.getObject(`confirm:pending:${uid}`);\n"
                    "+  const ttl = pending.expires - Date.now();\n"
                    "   return ttl < 1000;\n"
                    " }\n"
                ),
            )
        ],
        validations=controller.validations,
        latest_relevant_change_sequence=2,
    )

    await controller.apply_completion_decision(
        CompletionReviewDecision.model_validate(
            {
                "decision": "accept",
                "reason": "resend fallback works",
                "files_reviewed": [
                    {"path": "src/email.js", "reason": "changed source", "kind": "source", "inspected": True, "limitation": None},
                    {"path": "tests/test_email.py", "reason": "validation target", "kind": "test", "inspected": True, "limitation": None},
                ],
                "behavior_evidence_matrix": [
                    {
                        "behavior": "resend fallback works",
                        "task_basis": "TASK.md",
                        "files_considered": ["src/email.js", "tests/test_email.py"],
                        "evidence": [
                            {
                                "validation_id": "validation-5",
                                "command": "pytest tests/test_email.py",
                                "sequence": 5,
                                "validation_type": "behavioral",
                                "outcome": "pass",
                                "freshness": "fresh",
                                "why_it_covers_behavior": "runs the recovered resend path",
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
                "progress_update": "Accepted.",
                "clear_handoff": False,
                "display_message": None,
                "handoff": None,
                "wake_sequence": 1,
                "generation": 0,
            }
        ),
        packet_thread_id="thread",
        packet=packet,
    )

    assert store.get_sentinel_config().status == SentinelStatus.STARTING
    assert len(controller.completion_returns) == 0
    assert controller.coder.messages == []
    assert "parallel persistence/source-of-truth risk" in store.path("PROGRESS.md").read_text(encoding="utf-8")
    assert store.get_sentinel_config().accept_gate_reviewer_reruns == 1


async def test_completion_accept_gate_allows_fresh_covered_code_change(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.coder = None
    controller.pending_approvals = {}
    controller.validations = [
        ValidationRun(command="pytest tests/test_app.py", exit_code=0, passed=True, summary="passed", sequence=3),
        ValidationRun(
            command="python - <<'PY'\nprint(app())\nPY",
            exit_code=0,
            type="behavior_demo",
            passed=True,
            summary='{"rendered_text":"requested behavior"}',
            captured_output='{"rendered_text":"requested behavior"}\n',
            sequence=4,
        ),
    ]
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.tui = _FakeTUI()
    controller.running = True
    controller.event_queue = asyncio.Queue()
    controller._sequence = 0
    controller.completion_returns = []
    controller.completion_restarts = 0
    controller.completion_reviewer_rerun_count = 0
    controller.no_marker_idle_nudge_count = 0

    packet = SupervisorWakePacket(
        wake_sequence=1,
        latest_event_sequence=1,
        generation=0,
        restart_count=0,
        task_path=str(task),
        task_contents="# Task",
        coder_thread_id="thread",
        changed_files=[
            ChangedFile(path="src/app.py", status="M", sequence=2),
            ChangedFile(path="tests/test_app.py", status="M", sequence=2),
        ],
        validations=controller.validations,
        latest_relevant_change_sequence=2,
    )

    await controller.apply_completion_decision(
        CompletionReviewDecision.model_validate(
            {
                "decision": "accept",
                "reason": "covered",
                "files_reviewed": [
                    {"path": "src/app.py", "reason": "changed source", "kind": "source", "inspected": True, "limitation": None},
                    {"path": "tests/test_app.py", "reason": "changed test", "kind": "test", "inspected": True, "limitation": None},
                ],
                "behavior_evidence_matrix": [
                    {
                        "behavior": "requested behavior",
                        "task_basis": "TASK.md",
                        "files_considered": ["src/app.py", "tests/test_app.py"],
                            "evidence": [
                                {
                                    "validation_id": "validation-3",
                                    "command": "pytest tests/test_app.py",
                                    "sequence": 3,
                                    "validation_type": "behavioral",
                                    "outcome": "pass",
                                    "freshness": "fresh",
                                    "why_it_covers_behavior": "executes the changed behavior",
                                },
                                {
                                    "validation_id": "validation-4",
                                    "command": "python - <<'PY'\nprint(app())\nPY",
                                    "sequence": 4,
                                    "validation_type": "behavior_demo",
                                    "outcome": "pass",
                                    "freshness": "fresh",
                                    "why_it_covers_behavior": "captures factual behavior outside the changed test",
                                },
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
                "wake_sequence": 1,
                "generation": 0,
            }
        ),
        packet_thread_id="thread",
        packet=packet,
    )

    assert store.get_sentinel_config().status == SentinelStatus.COMPLETE
    assert store.get_sentinel_config().accept_gate_accepts == 1
    log_entry = json.loads(store.path(LOG).read_text(encoding="utf-8").splitlines()[-1])
    assert log_entry["type"] == "completion_accept_gate_pass"
    assert {"check_name": "evidence_binding", "passed": True} in log_entry["checks"]
    assert {"check_name": "behavioral_floor", "passed": True} in log_entry["checks"]
    report = store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert "## Completion Behavior Evidence" in report
    assert "## Completion Files Reviewed" in report


async def test_completion_accept_gate_returns_for_self_confirming_added_test_and_snapshot(tmp_path: Path) -> None:
    validations = [
        ValidationRun(
            command="npm test -- DeviceDetailHeading",
            exit_code=0,
            passed=True,
            summary="PASS src/components/DeviceDetailHeading-test.ts\n1 passed",
            captured_output="PASS src/components/DeviceDetailHeading-test.ts\n1 passed\n",
            executed_test_files=["src/components/DeviceDetailHeading-test.ts"],
            sequence=3,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    packet = SupervisorWakePacket(
        wake_sequence=1,
        latest_event_sequence=1,
        generation=0,
        restart_count=0,
        task_path=str(task),
        task_contents="Render device detail heading from selected element data.",
        coder_thread_id="thread",
        changed_files=[
            ChangedFile(path="src/components/DeviceDetailHeading.tsx", status="M", sequence=2),
            ChangedFile(path="src/components/DeviceDetailHeading-test.tsx", status="A", sequence=2),
            ChangedFile(path="src/components/__snapshots__/DeviceDetailHeading-test.tsx.snap", status="A", sequence=2),
        ],
        changed_file_diffs=[
            ChangedFileDiff(
                path="src/components/DeviceDetailHeading-test.tsx",
                file_kind="test",
                change_kind="added",
                diff="+test('renders heading', () => expect(screen.getByText('Device')).toBeVisible())",
            ),
            ChangedFileDiff(
                path="src/components/__snapshots__/DeviceDetailHeading-test.tsx.snap",
                file_kind="test",
                change_kind="added",
                diff="+<h1>Device</h1>",
            ),
        ],
        validations=validations,
        latest_relevant_change_sequence=2,
    )
    payload = _covered_accept_decision(wake_sequence=1, validation_id="validation-3").model_dump(mode="json")
    payload["files_reviewed"] = [
        {"path": "src/components/DeviceDetailHeading.tsx", "reason": "changed source", "kind": "source", "inspected": True, "limitation": None},
        {"path": "src/components/DeviceDetailHeading-test.tsx", "reason": "assessed added test", "kind": "test", "inspected": True, "limitation": None},
        {
            "path": "src/components/__snapshots__/DeviceDetailHeading-test.tsx.snap",
            "reason": "assessed added snapshot",
            "kind": "test",
            "inspected": True,
            "limitation": None,
        },
    ]
    payload["behavior_evidence_matrix"] = [
        {
            "behavior": "device detail heading renders selected element data",
            "task_basis": "TASK.md",
            "files_considered": [
                "src/components/DeviceDetailHeading.tsx",
                "src/components/DeviceDetailHeading-test.tsx",
            ],
            "evidence": [
                {
                    "validation_id": "validation-3",
                    "command": "npm test -- DeviceDetailHeading",
                    "sequence": 3,
                    "validation_type": "behavioral",
                    "outcome": "pass",
                    "freshness": "fresh",
                    "why_it_covers_behavior": "runs the new heading test",
                }
            ],
            "status": "covered",
            "gap": None,
        }
    ]
    decision = CompletionReviewDecision.model_validate(payload)

    await controller.apply_completion_decision(decision, packet_thread_id="thread", packet=packet)

    assert store.get_sentinel_config().status == SentinelStatus.STARTING
    assert len(controller.completion_returns) == 1
    assert store.get_sentinel_config().accept_gate_coder_returns == 1
    assert store.get_sentinel_config().accept_gate_reviewer_reruns == 0
    assert "self_confirming_test_evidence" in coder.messages[0]
    assert "device detail heading renders selected element data" in coder.messages[0]
    assert "validation-3" in coder.messages[0]
    assert "DeviceDetailHeading-test.tsx" in coder.messages[0]
    assert "behavior_demo" in coder.messages[0]
    pending = controller._pending_completion_gate_rejection
    assert pending is not None
    assert pending["check_name"] == "self_confirming_test_evidence"
    assert pending["details"]["behaviors"][0]["behavior"] == "device detail heading renders selected element data"
    log_entry = json.loads(store.path(LOG).read_text(encoding="utf-8").splitlines()[-1])
    assert log_entry["check_name"] == "self_confirming_test_evidence"
    assert log_entry["details"]["requirement"] == "independent_evidence_binding"


async def test_completion_accept_gate_allows_untouched_output_identified_test_with_added_test(tmp_path: Path) -> None:
    validations = [
        ValidationRun(
            command="pytest tests/test_app_existing.py tests/test_app_new.py",
            exit_code=0,
            passed=True,
            summary="tests/test_app_existing.py::test_requested_behavior PASSED\ntests/test_app_new.py::test_requested_behavior PASSED\n2 passed",
            captured_output=(
                "tests/test_app_existing.py::test_requested_behavior PASSED\n"
                "tests/test_app_new.py::test_requested_behavior PASSED\n2 passed\n"
            ),
            executed_test_files=["tests/test_app_existing.py", "tests/test_app_new.py"],
            sequence=3,
        )
    ]
    controller, store, task, _coder = _completion_gate_controller(tmp_path, validations=validations)
    payload = _covered_accept_decision(wake_sequence=1, validation_id="validation-3").model_dump(mode="json")
    payload["files_reviewed"].append(
        {"path": "tests/test_app_new.py", "reason": "added test", "kind": "test", "inspected": True, "limitation": None}
    )
    packet = _gate_packet(task, validations=validations)
    packet.changed_file_diffs = [
        ChangedFileDiff(
            path="tests/test_app_new.py",
            file_kind="test",
            change_kind="added",
            diff="+def test_requested_behavior():\n+    assert app() == 'ok'",
        )
    ]
    packet.validations = validations

    await controller.apply_completion_decision(
        CompletionReviewDecision.model_validate(payload),
        packet_thread_id="thread",
        packet=packet,
    )

    assert store.get_sentinel_config().status == SentinelStatus.COMPLETE
    assert store.get_sentinel_config().accept_gate_accepts == 1


async def test_completion_accept_gate_allows_behavior_demo_independent_evidence(tmp_path: Path) -> None:
    validations = [
        ValidationRun(
            command="npm test -- DeviceDetailHeading",
            exit_code=0,
            passed=True,
            summary="PASS src/components/DeviceDetailHeading-test.tsx\n1 passed",
            captured_output="PASS src/components/DeviceDetailHeading-test.tsx\n1 passed\n",
            executed_test_files=["src/components/DeviceDetailHeading-test.tsx"],
            sequence=3,
        ),
        ValidationRun(
            command="node -e \"console.log(renderHeading({name:'Device 42'}))\"",
            exit_code=0,
            passed=True,
            type="behavior_demo",
            summary="<h1>Device 42</h1>",
            captured_output="<h1>Device 42</h1>\n",
            sequence=4,
        ),
    ]
    controller, store, task, _coder = _completion_gate_controller(tmp_path, validations=validations)
    packet = SupervisorWakePacket(
        wake_sequence=1,
        latest_event_sequence=1,
        generation=0,
        restart_count=0,
        task_path=str(task),
        task_contents="Render device detail heading from selected element data.",
        coder_thread_id="thread",
        changed_files=[
            ChangedFile(path="src/components/DeviceDetailHeading.tsx", status="M", sequence=2),
            ChangedFile(path="src/components/DeviceDetailHeading-test.tsx", status="A", sequence=2),
        ],
        changed_file_diffs=[
            ChangedFileDiff(
                path="src/components/DeviceDetailHeading-test.tsx",
                file_kind="test",
                change_kind="added",
                diff="+test('renders heading', () => expect(screen.getByText('Device 42')).toBeVisible())",
            )
        ],
        validations=validations,
        latest_relevant_change_sequence=2,
    )
    payload = _covered_accept_decision(wake_sequence=1, validation_id="validation-3").model_dump(mode="json")
    payload["files_reviewed"] = [
        {"path": "src/components/DeviceDetailHeading.tsx", "reason": "changed source", "kind": "source", "inspected": True, "limitation": None},
        {"path": "src/components/DeviceDetailHeading-test.tsx", "reason": "added test", "kind": "test", "inspected": True, "limitation": None},
    ]
    payload["behavior_evidence_matrix"][0]["behavior"] = "device detail heading renders selected element data"
    payload["behavior_evidence_matrix"][0]["files_considered"] = ["src/components/DeviceDetailHeading.tsx"]
    payload["behavior_evidence_matrix"][0]["evidence"] = [
        {
            "validation_id": "validation-4",
            "command": "node -e \"console.log(renderHeading({name:'Device 42'}))\"",
            "sequence": 4,
            "validation_type": "behavior_demo",
            "outcome": "pass",
            "freshness": "fresh",
            "why_it_covers_behavior": "captured rendered DOM output <h1>Device 42</h1> for the task scenario",
        }
    ]

    await controller.apply_completion_decision(
        CompletionReviewDecision.model_validate(payload),
        packet_thread_id="thread",
        packet=packet,
    )

    assert store.get_sentinel_config().status == SentinelStatus.COMPLETE
    assert store.get_sentinel_config().accept_gate_accepts == 1


async def test_completion_accept_gate_returns_for_empty_behavior_demo_output(tmp_path: Path) -> None:
    validations = [
        ValidationRun(
            command="python -m docs.generate_settings",
            exit_code=0,
            passed=True,
            type="behavior_demo",
            summary="command completed",
            captured_output="",
            sequence=3,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    payload = _covered_accept_decision(wake_sequence=1, validation_id="validation-3").model_dump(mode="json")
    payload["behavior_evidence_matrix"][0]["behavior"] = "Generated docs include the new setting"
    payload["behavior_evidence_matrix"][0]["evidence"][0]["command"] = "python -m docs.generate_settings"
    payload["behavior_evidence_matrix"][0]["evidence"][0]["validation_type"] = "behavior_demo"

    await controller.apply_completion_decision(
        CompletionReviewDecision.model_validate(payload),
        packet_thread_id="thread",
        packet=_gate_packet(task, validations=validations),
    )

    assert store.get_sentinel_config().status == SentinelStatus.STARTING
    assert len(controller.completion_returns) == 1
    assert "full diff" in coder.messages[0]
    assert "hand-picked grep/sed" in coder.messages[0]
    assert store.get_sentinel_config().accept_gate_coder_returns == 1
    assert store.get_sentinel_config().accept_gate_reviewer_reruns == 0
    assert "behavior_demo evidence validation-3 has no captured output" in store.path(PROGRESS).read_text(encoding="utf-8")


async def test_completion_accept_gate_does_not_repeat_bounded_empty_demo_return(tmp_path: Path) -> None:
    validations = [
        ValidationRun(
            command="python -m docs.generate_settings",
            exit_code=0,
            passed=True,
            type="behavior_demo",
            summary="command completed",
            captured_output="",
            sequence=3,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    controller.completion_returns = [
        CompletionReturnRecord(
            reason="controller accept-gate rejection (evidence_binding): missing output",
            message_to_coder="capture artifact diff",
            accept_gate_check_name="evidence_binding",
            accept_gate_details={
                "check_name": "evidence_binding",
                "details": {
                    "bounded_coder_return_key": (
                        "behavior_demo_missing_output:Generated docs include the new setting:validation-3"
                    )
                },
            },
            sequence=1,
            generation=0,
        )
    ]
    payload = _covered_accept_decision(wake_sequence=1, validation_id="validation-3").model_dump(mode="json")
    payload["behavior_evidence_matrix"][0]["behavior"] = "Generated docs include the new setting"
    payload["behavior_evidence_matrix"][0]["evidence"][0]["command"] = "python -m docs.generate_settings"
    payload["behavior_evidence_matrix"][0]["evidence"][0]["validation_type"] = "behavior_demo"

    await controller.apply_completion_decision(
        CompletionReviewDecision.model_validate(payload),
        packet_thread_id="thread",
        packet=_gate_packet(task, validations=validations),
    )

    assert store.get_sentinel_config().status == SentinelStatus.STARTING
    assert coder.messages == []
    assert len(controller.completion_returns) == 1
    assert store.get_sentinel_config().accept_gate_coder_returns == 0
    assert store.get_sentinel_config().accept_gate_reviewer_reruns == 1
    log_entries = [json.loads(line) for line in store.path(LOG).read_text(encoding="utf-8").splitlines()]
    log_entry = next(entry for entry in log_entries if entry.get("type") == "completion_accept_gate_rejection")
    assert log_entry["failure_type"] == "reviewer-incomplete"
    assert log_entry["details"]["bounded_coder_return_already_used"] is True


async def test_completion_accept_gate_reruns_reviewer_when_evidence_type_mismatches_ledger(tmp_path: Path) -> None:
    validations = [
        ValidationRun(
            command="pytest tests/test_app.py",
            exit_code=0,
            passed=True,
            summary="passed",
            sequence=3,
            type="behavioral",
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    payload = _covered_accept_decision(wake_sequence=1, validation_id="validation-3").model_dump(mode="json")
    payload["behavior_evidence_matrix"][0]["evidence"][0]["validation_type"] = "static"

    await controller.apply_completion_decision(
        CompletionReviewDecision.model_validate(payload),
        packet_thread_id="thread",
        packet=_gate_packet(task, validations=validations),
    )

    assert store.get_sentinel_config().status == SentinelStatus.STARTING
    assert len(controller.completion_returns) == 0
    assert coder.messages == []
    assert store.get_sentinel_config().accept_gate_reviewer_reruns == 1
    progress = store.path(PROGRESS).read_text(encoding="utf-8")
    assert "evidence type mismatch" in progress
    assert "validation-3 declares static but ledger has behavioral" in progress


async def test_completion_accept_gate_reruns_reviewer_when_behavior_lacks_ledger_record(tmp_path: Path) -> None:
    validations = [
        ValidationRun(command="pytest tests/test_app.py", exit_code=0, passed=True, summary="passed", sequence=3)
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)

    await controller.apply_completion_decision(
        _covered_accept_decision(wake_sequence=1, validation_id="validation-missing"),
        packet_thread_id="thread",
        packet=_gate_packet(task, validations=validations),
    )

    assert store.get_sentinel_config().status == SentinelStatus.STARTING
    assert len(controller.completion_returns) == 0
    assert coder.messages == []
    assert store.get_sentinel_config().accept_gate_reviewer_reruns == 1
    assert "requested behavior" in store.path(PROGRESS).read_text(encoding="utf-8")
    log_entries = [json.loads(line) for line in store.path(LOG).read_text(encoding="utf-8").splitlines()]
    log_entry = next(entry for entry in log_entries if entry.get("type") == "completion_accept_gate_rejection")
    assert log_entry["check_name"] == "evidence_binding"


async def test_completion_accept_gate_returns_to_coder_without_fresh_behavioral_validation(tmp_path: Path) -> None:
    validations = [
        ValidationRun(
            command="python -m py_compile src/app.py",
            exit_code=0,
            type="static",
            passed=True,
            summary="compiled",
            sequence=3,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)

    await controller.apply_completion_decision(
        _covered_accept_decision(wake_sequence=1, validation_id="validation-3"),
        packet_thread_id="thread",
        packet=_gate_packet(task, validations=validations),
    )

    assert store.get_sentinel_config().status == SentinelStatus.STARTING
    assert len(controller.completion_returns) == 1
    assert "no fresh passing behavioral validation" in coder.messages[0]
    assert store.get_sentinel_config().accept_gate_coder_returns == 1


async def test_completion_accept_gate_reruns_reviewer_for_missing_changed_file_review(tmp_path: Path) -> None:
    validations = [
        ValidationRun(command="pytest tests/test_app.py", exit_code=0, passed=True, summary="passed", sequence=3)
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    payload = _covered_accept_decision(wake_sequence=1).model_dump(mode="json")
    payload["files_reviewed"] = [
        {"path": "src/app.py", "reason": "changed source", "kind": "source", "inspected": True, "limitation": None}
    ]
    decision = CompletionReviewDecision.model_validate(payload)

    await controller.apply_completion_decision(
        decision,
        packet_thread_id="thread",
        packet=_gate_packet(task, validations=validations),
    )

    assert store.get_sentinel_config().status == SentinelStatus.STARTING
    assert len(controller.completion_returns) == 0
    assert coder.messages == []
    assert "changed source/test files were not reviewed" in store.path(PROGRESS).read_text(encoding="utf-8")
    assert store.get_sentinel_config().accept_gate_reviewer_reruns == 1


async def test_completion_accept_gate_reruns_reviewer_for_contradictory_accept(tmp_path: Path) -> None:
    validations = [
        ValidationRun(command="pytest tests/test_app.py", exit_code=0, passed=True, summary="passed", sequence=3)
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    decision = _covered_accept_decision(wake_sequence=1).model_copy(update={"uncovered_behaviors": ["missing edge"]})

    await controller.apply_completion_decision(
        decision,
        packet_thread_id="thread",
        packet=_gate_packet(task, validations=validations),
    )

    assert store.get_sentinel_config().status == SentinelStatus.STARTING
    assert len(controller.completion_returns) == 0
    assert coder.messages == []
    assert "uncovered_behaviors is not empty" in store.path(PROGRESS).read_text(encoding="utf-8")
    assert store.get_sentinel_config().accept_gate_reviewer_reruns == 1


async def test_completion_accept_gate_double_reviewer_incomplete_escalates_audit_failure(tmp_path: Path) -> None:
    validations = [
        ValidationRun(command="pytest tests/test_app.py", exit_code=0, passed=True, summary="passed", sequence=3)
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations, reruns=1)
    decision = _covered_accept_decision(wake_sequence=1).model_copy(update={"uncovered_behaviors": ["missing edge"]})

    await controller.apply_completion_decision(
        decision,
        packet_thread_id="thread",
        packet=_gate_packet(task, validations=validations),
    )

    assert store.get_sentinel_config().status == SentinelStatus.ESCALATED
    assert len(controller.completion_returns) == 0
    assert coder.messages == []
    assert store.get_sentinel_config().accept_gate_audit_failures == 1
    assert "controller-side audit failure" in store.path(FINAL_REPORT).read_text(encoding="utf-8")


async def test_completion_restart_writes_handoff_and_starts_new_generation(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )

    class FakeClient:
        def __init__(self) -> None:
            self.started_turns = []

        async def respond(self, request_id, response):
            return None

        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "new-thread"}}

        async def turn_start(self, params, *, timeout):
            self.started_turns.append(params)
            return {"turn": {"id": "new-turn"}}

    handoff = RestartHandoff(
        objective="task",
        restart_reason="repeated completion miss",
        bad_pattern="validated only happy path",
        known_evidence="fallback unvalidated",
        next_step="read task",
        recovery_signal="fallback validated",
    )
    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.model = None
    controller.client = FakeClient()
    controller.approvals = ApprovalManager(tmp_path)
    controller.coder = None
    controller.pending_approvals = {}
    controller.prior_interventions = []
    controller.validations = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.tui = _FakeTUI()
    controller.running = True
    controller.event_queue = asyncio.Queue()
    controller._sequence = 0
    controller.completion_returns = [
        {
            "reason": "fallback missing",
            "uncovered_behaviors": ["fallback"],
            "validation_gaps": [],
            "message_to_coder": "cover fallback",
            "sequence": 1,
            "generation": 0,
        }
    ]
    controller.completion_restarts = 0
    controller.no_marker_idle_nudge_count = 0

    await controller.apply_completion_decision(
        CompletionReviewDecision(
            decision="restart",
            reason="non-converging completion returns",
            uncovered_behaviors=["fallback"],
            validation_gaps=["same stale validation"],
            message_to_coder=None,
            persistent_decision=None,
            progress_update="Restarting from completion review.",
            clear_handoff=False,
            display_message=None,
            handoff=handoff,
            wake_sequence=1,
            generation=0,
        ),
        packet_thread_id="thread",
    )

    assert store.get_sentinel_config().generation == 1
    assert "repeated completion miss" in store.path(HANDOFF).read_text(encoding="utf-8")
    assert controller.completion_restarts == 1
    assert controller.client.started_turns


async def test_transport_error_writes_provider_failure_final_report(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.use_git_diff = False
    controller.validations = []
    controller.observed_changed_files = {}
    controller.tui = _FakeTUI()
    controller.running = True
    controller._sequence = 0

    await controller.handle_controller_event(
        ControllerEvent(
            kind="transport_error",
            error_message="app-server stdout line exceeded stream limit (64 bytes): test payload",
        )
    )

    text = store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert store.get_sentinel_config().status == SentinelStatus.PROVIDER_FAILURE
    assert "- Status: provider_failure" in text
    assert "app-server transport error" in text
    assert controller.running is False


def test_attempt_image_build_includes_private_sentinel_python(tmp_path: Path, monkeypatch) -> None:
    runner = _load_container_runner()
    captured: dict[str, list[str] | Path] = {}

    def fake_copy_sentinel_source(src: Path, dest: Path) -> None:
        captured["copied_from"] = src
        dest.mkdir(parents=True)
        (dest / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")

    def fake_run(cmd: list[str], *, cwd: Path, log_path: Path) -> None:
        captured["cmd"] = cmd
        captured["cwd"] = cwd
        captured["log_path"] = log_path

    monkeypatch.setattr(runner, "copy_sentinel_source", fake_copy_sentinel_source)
    monkeypatch.setattr(runner, "run", fake_run)

    runner.build_attempt_image(
        base_image="example/base:latest",
        attempt_image="attempt:test",
        codex_version="0.0.0",
        sentinel_src=tmp_path / "sentinel-src",
        build_dir=tmp_path / "build",
        platform="linux/amd64",
    )

    dockerfile = (tmp_path / "build" / "context" / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM python:3.11-slim-bullseye AS sentinel-python" in dockerfile
    assert "FROM example/base:latest" in dockerfile
    assert "COPY --from=sentinel-python /usr/local /opt/sentinel-python" in dockerfile
    assert "/opt/sentinel-python/bin/python3.11" in dockerfile
    assert "sys.version_info >= (3, 11)" in dockerfile
    assert "Python >=3.11 required for sentinel venv" in dockerfile
    assert captured["cmd"] == [
        "docker",
        "build",
        "--platform",
        "linux/amd64",
        "-t",
        "attempt:test",
        str(tmp_path / "build" / "context"),
    ]
    assert captured["cwd"] == tmp_path / "build"


def test_collect_rollouts_infers_pre_restart_coder_session_from_prompt(tmp_path: Path) -> None:
    runner = _load_container_runner()
    paths = runner.RunPaths(
        root=tmp_path,
        private=tmp_path / "private",
        build=tmp_path / "build",
        attempt=tmp_path / "attempt",
        attempt_input=tmp_path / "attempt" / "input",
        attempt_output=tmp_path / "attempt" / "output",
        artifacts=tmp_path / "attempt" / "output" / "artifacts",
        rollouts=tmp_path / "rollouts",
        scoring=tmp_path / "scoring",
    )
    for path in paths.__dict__.values():
        path.mkdir(parents=True, exist_ok=True)
    supervisor_dir = paths.artifacts / ".supervisor"
    supervisor_dir.mkdir(parents=True)
    (supervisor_dir / "config.json").write_text(json.dumps({"coder_thread_id": "new-coder"}), encoding="utf-8")
    (supervisor_dir / "supervisor_wakes.jsonl").write_text(
        json.dumps({"thread_id": "supervisor-thread"}) + "\n",
        encoding="utf-8",
    )
    sessions = paths.rollouts / "codex-home" / "sessions" / "2026" / "06" / "17"
    sessions.mkdir(parents=True)

    def write_rollout(thread_id: str, prompt: str) -> None:
        (sessions / f"rollout-{thread_id}.jsonl").write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "timestamp": "2026-06-17T20:00:00.000Z",
                            "type": "session_meta",
                            "payload": {
                                "id": thread_id,
                                "cwd": "/app",
                                "timestamp": "2026-06-17T20:00:00.000Z",
                            },
                        }
                    ),
                    json.dumps(
                        {
                            "timestamp": "2026-06-17T20:00:00.100Z",
                            "type": "event_msg",
                            "payload": {"type": "user_message", "message": prompt},
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )

    write_rollout("old-coder", "You are the coding agent for this task. Read the task file first: /app/TASK.md")
    write_rollout("new-coder", "ordinary follow-up")
    write_rollout("supervisor-thread", '{"current_summary":"check","wake_sequence":1}')
    write_rollout("preflight", "ordinary preflight")

    summary = runner.collect_rollouts(
        paths,
        container_cwd="/app",
        start_utc=datetime(2026, 6, 17, 19, 59, tzinfo=timezone.utc),
        end_utc=datetime(2026, 6, 17, 20, 1, tzinfo=timezone.utc),
    )

    by_id = {item["id"]: item for item in summary["matched"]}
    assert by_id["old-coder"]["bucket"] == "coder"
    assert by_id["old-coder"]["role_hint"] == "coder"
    assert by_id["new-coder"]["bucket"] == "coder"
    assert by_id["supervisor-thread"]["bucket"] == "supervisor"
    assert by_id["preflight"]["bucket"] == "other"
    assert summary["coder_count"] == 2
    assert summary["other_count"] == 1


async def test_supervisor_turn_start_timeout_writes_provider_failure_final_report(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class HangingTurnStartClient:
        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "supervisor-thread"}}

        async def turn_start(self, params, *, timeout):
            await asyncio.Event().wait()

        async def thread_archive(self, thread_id, *, timeout):
            return {}

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.use_git_diff = False
    controller.pending_approvals = {}
    controller.last_coder_message = None
    controller.validations = []
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.tui = _FakeTUI()
    controller.running = True
    controller.supervisor = StatelessSupervisorAgent(
        HangingTurnStartClient(),
        store,
        task,
        timeout_seconds=0.01,
    )  # type: ignore[arg-type]

    await controller._run_supervisor_check("check latest state", None, None, None, None)

    text = store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert store.get_sentinel_config().status == SentinelStatus.PROVIDER_FAILURE
    assert "- Status: provider_failure" in text
    assert "supervisor check failed" in text
    assert "supervisor turn/start response timed out after 0.01s" in text
    assert "thread_id=supervisor-thread" in text
    assert controller.running is False
    audit = json.loads(store.path(SUPERVISOR_WAKES).read_text(encoding="utf-8").splitlines()[-1])
    assert audit["status"] == "error"
    assert audit["thread_id"] == "supervisor-thread"
    assert audit["turn_id"] is None
    assert "supervisor turn/start response timed out after 0.01s" in audit["error"]


async def test_stale_runtime_supervisor_timeout_keeps_queued_completion_review(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class HangingTurnStartClient:
        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "supervisor-thread"}}

        async def turn_start(self, params, *, timeout):
            await asyncio.Event().wait()

        async def thread_archive(self, thread_id, *, timeout):
            return {}

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.use_git_diff = False
    controller.pending_approvals = {}
    controller.last_coder_message = None
    controller.validations = []
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.tui = _FakeTUI()
    controller.running = True
    controller.supervisor = StatelessSupervisorAgent(
        HangingTurnStartClient(),
        store,
        task,
        timeout_seconds=0.01,
    )  # type: ignore[arg-type]
    controller._supervisor_dirty = True
    controller._supervisor_next_completion_review = True

    await controller._run_supervisor_check("stale runtime check", None, None, None, None)

    text = store.path(FINAL_REPORT).read_text(encoding="utf-8")
    health = store.get_health()
    assert store.get_sentinel_config().status == SentinelStatus.STARTING
    assert text == ""
    assert controller.running is True
    assert health.timeout_fallback_count == 1
    assert "stale_runtime_supervisor_timeout" in health.risk_signals
    assert "continuing with the latest queued review" in store.path(PROGRESS).read_text(encoding="utf-8")
    assert any("supervisor check failed" in message for _, message in controller.tui.messages)


async def test_preflight_appserver_timeout_writes_provider_failure_final_report(tmp_path: Path, monkeypatch) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")

    class PreflightTimeoutClient:
        async def start(self):
            return None

        async def initialize(self):
            return {}

        async def stop(self):
            return None

        async def account_read(self):
            raise AppServerTimeoutError("app-server RPC account/read response timed out after 30s")

    monkeypatch.setattr("supervisor.controller._run_probe", lambda args: (True, "codex-cli test"))
    controller = SentinelController(
        tmp_path,
        task_path=task,
        client=PreflightTimeoutClient(),  # type: ignore[arg-type]
        tui=_FakeTUI(),
        overwrite_state=True,
        use_git_diff=False,
    )
    controller._generate_schema_hash_async = _async_schema_hash

    await controller.run()

    text = controller.store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert controller.store.get_sentinel_config().status == SentinelStatus.PROVIDER_FAILURE
    assert "- Status: provider_failure" in text
    assert "app-server RPC failed" in text
    assert "account/read response timed out" in text


async def test_preflight_probe_cleanup_unsubscribes_and_logs_without_failing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")

    class ProbeCleanupClient:
        def __init__(self) -> None:
            self.unsubscribed: list[str] = []

        async def account_read(self):
            return {"requiresOpenaiAuth": False, "account": {"id": "acct"}}

        async def account_rate_limits_read(self):
            return {}

        async def model_list(self):
            return {"data": [{"id": "gpt-test"}]}

        async def config_requirements_read(self):
            return {}

        async def thread_start(self, params):
            return {
                "thread": {"id": "probe-thread"},
                "approvalPolicy": "on-request",
                "sandbox": {"type": "readOnly", "networkAccess": False},
            }

        async def thread_archive(self, thread_id):
            raise AssertionError("preflight probe cleanup should not archive threads without rollouts")

        async def thread_unsubscribe(self, thread_id):
            self.unsubscribed.append(thread_id)
            raise AppServerError("unsubscribe cleanup failed")

    client = ProbeCleanupClient()
    monkeypatch.setattr("supervisor.controller._run_probe", lambda args: (True, "codex-cli test"))
    controller = SentinelController(
        tmp_path,
        task_path=task,
        client=client,  # type: ignore[arg-type]
        tui=_FakeTUI(),
        overwrite_state=True,
        use_git_diff=False,
    )
    controller._generate_schema_hash_async = _async_schema_hash
    controller._structured_output_self_test = _async_noop
    controller.initialize_state()

    await controller.preflight()

    assert client.unsubscribed == ["probe-thread"]
    assert controller.store.get_sentinel_config().model == "gpt-test"
    log_lines = controller.store.path(LOG).read_text(encoding="utf-8").splitlines()
    assert log_lines
    entry = json.loads(log_lines[-1])
    assert entry["type"] == "cleanup_error"
    assert entry["cleanup_kind"] == "preflight_probe_thread"
    assert entry["thread_id"] == "probe-thread"
    assert entry["error_type"] == "AppServerError"


async def test_preflight_rate_limit_probe_failure_warns_and_continues(tmp_path: Path, monkeypatch) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")

    class RateLimitFailureClient:
        def __init__(self) -> None:
            self.unsubscribed: list[str] = []

        async def account_read(self):
            return {"requiresOpenaiAuth": False, "account": {"id": "acct"}}

        async def account_rate_limits_read(self):
            raise AppServerError(
                "{'code': -32603, 'message': 'failed to fetch codex rate limits: error sending request'}"
            )

        async def model_list(self):
            return {"data": [{"id": "gpt-test"}]}

        async def config_requirements_read(self):
            return {}

        async def thread_start(self, params):
            return {
                "thread": {"id": "probe-thread"},
                "approvalPolicy": "on-request",
                "sandbox": {"type": "readOnly", "networkAccess": False},
            }

        async def thread_unsubscribe(self, thread_id):
            self.unsubscribed.append(thread_id)
            return {}

    client = RateLimitFailureClient()
    tui = _FakeTUI()
    monkeypatch.setattr("supervisor.controller._run_probe", lambda args: (True, "codex-cli test"))
    controller = SentinelController(
        tmp_path,
        task_path=task,
        client=client,  # type: ignore[arg-type]
        tui=tui,
        overwrite_state=True,
        use_git_diff=False,
    )
    controller._generate_schema_hash_async = _async_schema_hash
    controller._structured_output_self_test = _async_noop
    controller.initialize_state()

    await controller.preflight()

    assert controller.store.get_sentinel_config().model == "gpt-test"
    assert client.unsubscribed == ["probe-thread"]
    assert any("rate limit check unavailable" in message for _, message in tui.messages)
    log_lines = controller.store.path(LOG).read_text(encoding="utf-8").splitlines()
    assert log_lines
    entry = json.loads(log_lines[-1])
    assert entry["type"] == "preflight_warning"
    assert entry["check"] == "codex_rate_limits"
    assert entry["error_type"] == "AppServerError"


async def test_preflight_accepts_configured_danger_full_access_sandbox(tmp_path: Path, monkeypatch) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")

    class DangerSandboxClient:
        def __init__(self) -> None:
            self.thread_params: dict | None = None
            self.unsubscribed: list[str] = []

        async def account_read(self):
            return {"requiresOpenaiAuth": False, "account": {"id": "acct"}}

        async def account_rate_limits_read(self):
            return {}

        async def model_list(self):
            return {"data": [{"id": "gpt-test"}]}

        async def config_requirements_read(self):
            return {}

        async def thread_start(self, params):
            self.thread_params = params
            return {
                "thread": {"id": "probe-thread"},
                "approvalPolicy": "on-request",
                "sandbox": "danger-full-access",
            }

        async def thread_unsubscribe(self, thread_id):
            self.unsubscribed.append(thread_id)
            return {}

    client = DangerSandboxClient()
    monkeypatch.setenv("SENTINEL_CODER_SANDBOX", "danger-full-access")
    monkeypatch.setattr("supervisor.controller._run_probe", lambda args: (True, "codex-cli test"))
    controller = SentinelController(
        tmp_path,
        task_path=task,
        client=client,  # type: ignore[arg-type]
        tui=_FakeTUI(),
        overwrite_state=True,
        use_git_diff=False,
    )
    controller._generate_schema_hash_async = _async_schema_hash
    controller._structured_output_self_test = _async_noop
    controller.initialize_state()

    await controller.preflight()

    assert client.thread_params is not None
    assert client.thread_params["sandbox"] == "danger-full-access"
    assert client.unsubscribed == ["probe-thread"]


async def test_server_request_respond_timeout_writes_provider_failure_final_report(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread", active_coder_turn_id="turn"),
        overwrite=True,
    )

    class RespondTimeoutClient:
        async def respond(self, request_id, response):
            raise AppServerTimeoutError("app-server respond 61 send timed out after 15s")

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.client = RespondTimeoutClient()
    controller.approvals = ApprovalManager(tmp_path)
    controller.coder = None
    controller.pending_approvals = {}
    controller.tui = _FakeTUI()
    controller._sequence = 0
    controller.use_git_diff = False
    controller.validations = []
    controller.observed_changed_files = {}
    controller.running = True

    await controller.handle_controller_event(
        ControllerEvent(
            kind="server_request",
            message=AppServerMessage(
                {
                    "id": 61,
                    "method": "item/fileChange/requestApproval",
                    "params": {"grantRoot": str(tmp_path / "src.py"), "availableDecisions": ["accept", "decline"]},
                }
            ),
        )
    )

    text = store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert store.get_sentinel_config().status == SentinelStatus.PROVIDER_FAILURE
    assert "- Status: provider_failure" in text
    assert "app-server RPC failed while handling server_request" in text
    assert "respond 61 send timed out" in text
    assert controller.running is False


async def test_coder_turn_start_timeout_writes_provider_failure_final_report(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="coder-thread"),
        overwrite=True,
    )

    class CoderTurnTimeoutClient:
        async def respond(self, request_id, response):
            return None

        async def turn_start(self, params, *, timeout):
            assert timeout == APP_SERVER_CODER_RPC_TIMEOUT_SECONDS
            raise AppServerTimeoutError(f"app-server RPC turn/start response timed out after {timeout:g}s")

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.client = CoderTurnTimeoutClient()
    controller.approvals = ApprovalManager(tmp_path)
    controller.coder = CoderSession(
        controller.client,  # type: ignore[arg-type]
        store,
        tmp_path,
        task,
        thread_id="coder-thread",
    )
    controller.pending_approvals = {}
    controller.tui = _FakeTUI()
    controller._sequence = 0
    controller.use_git_diff = False
    controller.validations = []
    controller.observed_changed_files = {}
    controller.running = True

    await controller.handle_controller_event(
        ControllerEvent(
            kind="server_request",
            message=AppServerMessage(
                {
                    "id": 62,
                    "method": "item/fileChange/requestApproval",
                    "params": {
                        "grantRoot": str(tmp_path / ".supervisor" / CONFIG),
                        "availableDecisions": ["accept", "decline"],
                    },
                }
            ),
        )
    )

    text = store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert store.get_sentinel_config().status == SentinelStatus.PROVIDER_FAILURE
    assert "- Status: provider_failure" in text
    assert "app-server RPC failed while handling server_request" in text
    assert "turn/start response timed out after 1800s" in text
    assert controller.running is False


async def test_supervisor_decision_can_clear_handoff(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
    store.write_handoff("restart context\n")

    controller = SentinelController.__new__(SentinelController)
    controller.store = store

    await controller.apply_supervisor_decision(
        SupervisorDecision(
            decision=SupervisorDecisionKind.NOOP,
            clear_handoff=True,
            wake_sequence=1,
            generation=0,
        ),
        packet_thread_id=None,
    )

    assert store.path(HANDOFF).read_text(encoding="utf-8") == ""


def test_structured_handoff_is_read_back_verbatim(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
    handoff = RestartHandoff(
        objective="task",
        restart_reason="loop",
        bad_pattern="repeat",
        known_evidence="evidence",
        next_step="step",
        recovery_signal="signal",
    )
    store.write_handoff(handoff.model_dump_json(indent=2) + "\n")

    packet = StatelessSupervisorAgent(None, store, task).build_packet(  # type: ignore[arg-type]
        wake_sequence=1,
        current_summary="progress check",
    )

    assert packet.handoff == handoff


async def test_controller_approval_packet_carries_structured_context(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(SentinelConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
    context = normalize_approval_request(
        AppServerMessage(
            {
                "id": 42,
                "method": "item/commandExecution/requestApproval",
                "params": {
                    "threadId": "t",
                    "turnId": "u",
                    "itemId": "i",
                    "command": "pytest",
                    "cwd": str(tmp_path),
                    "availableDecisions": ["accept", "decline"],
                },
            }
        )
    )

    class FakeSupervisor:
        def __init__(self) -> None:
            self.agent = StatelessSupervisorAgent(None, store, task)  # type: ignore[arg-type]
            self.packet = None

        def build_packet(self, **kwargs):
            self.packet = self.agent.build_packet(**kwargs)
            return self.packet

        async def decide(self, packet):
            return SupervisorDecision(
                decision=SupervisorDecisionKind.NOOP,
                reason="ok",
                wake_sequence=packet.wake_sequence,
                generation=packet.generation,
            )

    fake = FakeSupervisor()
    controller = SentinelController.__new__(SentinelController)
    controller.store = store
    controller.project_root = tmp_path
    controller.task_path = task
    controller.supervisor = fake
    controller.pending_approvals = {context.server_request_id: context}
    controller.last_coder_message = CoderMessage(text="ready", sequence=1)
    controller.validations = [ValidationRun(command="pytest", exit_code=1, passed=False, summary="failed", sequence=2)]
    controller.prior_interventions = [PriorIntervention(reason="drift", message_to_coder="focus", sequence=3)]
    controller.use_git_diff = False

    await controller.decide_approval(context, "needs judgment")

    packet = fake.packet
    assert packet.approval_context.command == "pytest"
    assert packet.approval_context.available_decisions == ["accept", "decline"]
    assert len(packet.pending_approvals) == 1
    assert packet.last_coder_message.text == "ready"
    assert packet.validations[0].passed is False
    assert packet.prior_interventions[0].message_to_coder == "focus"


async def test_supervisor_deny_reason_is_steered_to_coder(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread", active_coder_turn_id="turn"),
        overwrite=True,
    )
    context = normalize_approval_request(
        AppServerMessage(
            {
                "id": 51,
                "method": "item/commandExecution/requestApproval",
                "params": {"command": "curl https://example.com", "availableDecisions": ["accept", "decline", "cancel"]},
            }
        )
    )

    class FakeSupervisor:
        async def decide_approval(self, context, reason):
            return SupervisorDecision(
                decision=SupervisorDecisionKind.DENY,
                approval_decision="decline",
                reason="Network access is not required by the task.",
                message_to_coder="do not use this",
            )

    class FakeClient:
        def __init__(self) -> None:
            self.responses = []

        async def respond(self, request_id, response):
            self.responses.append((request_id, response))

    class FakeCoder:
        def __init__(self) -> None:
            self.messages = []

        async def steer_or_start(self, message):
            self.messages.append(message)
            return "turn"

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.store = store
    controller.client = FakeClient()
    controller.approvals = ApprovalManager(tmp_path, supervisor=FakeSupervisor())
    controller.coder = FakeCoder()
    controller.pending_approvals = {}
    controller.tui = _FakeTUI()
    controller._sequence = 0

    await controller.handle_server_request(AppServerMessage({"id": 51, "method": context.server_request_method, "params": context.raw_params}))

    assert controller.client.responses == [(51, {"decision": "decline"})]
    assert controller.coder.messages == ["Network access is not required by the task."]


async def test_policy_deny_reason_is_steered_to_coder(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread", active_coder_turn_id="turn"),
        overwrite=True,
    )

    class FakeClient:
        def __init__(self) -> None:
            self.responses = []

        async def respond(self, request_id, response):
            self.responses.append((request_id, response))

    class FakeCoder:
        def __init__(self) -> None:
            self.messages = []

        async def steer_or_start(self, message):
            self.messages.append(message)
            return "turn"

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.store = store
    controller.client = FakeClient()
    controller.approvals = ApprovalManager(tmp_path)
    controller.coder = FakeCoder()
    controller.pending_approvals = {}
    controller.tui = _FakeTUI()
    controller._sequence = 0

    await controller.handle_server_request(
        AppServerMessage(
            {
                "id": 52,
                "method": "item/fileChange/requestApproval",
                "params": {
                    "grantRoot": str(tmp_path / ".supervisor" / CONFIG),
                    "availableDecisions": ["accept", "decline", "cancel"],
                },
            }
        )
    )

    assert controller.client.responses == [(52, {"decision": "decline"})]
    assert controller.coder.messages == ["writes to supervisor runtime/state files are denied"]


async def test_approval_accept_does_not_steer_coder(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread", active_coder_turn_id="turn"),
        overwrite=True,
    )

    class FakeClient:
        def __init__(self) -> None:
            self.responses = []

        async def respond(self, request_id, response):
            self.responses.append((request_id, response))

    class FakeCoder:
        def __init__(self) -> None:
            self.messages = []

        async def steer_or_start(self, message):
            self.messages.append(message)
            return "turn"

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.store = store
    controller.client = FakeClient()
    controller.approvals = ApprovalManager(tmp_path)
    controller.coder = FakeCoder()
    controller.pending_approvals = {}
    controller.tui = _FakeTUI()
    controller._sequence = 0

    await controller.handle_server_request(
        AppServerMessage(
            {
                "id": 53,
                "method": "item/fileChange/requestApproval",
                "params": {"grantRoot": str(tmp_path / "src.py"), "availableDecisions": ["accept", "decline"]},
            }
        )
    )

    assert controller.client.responses == [(53, {"decision": "accept"})]
    assert controller.coder.messages == []


async def test_execpolicy_amendment_approval_is_not_rendered_as_denied(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread", active_coder_turn_id="turn"),
        overwrite=True,
    )
    amendment = ["/bin/zsh", "-lc", "printf 'hello sentinel\\n' > hello.txt"]
    offered_decision = {"acceptWithExecpolicyAmendment": {"execpolicy_amendment": amendment}}

    class FakeSupervisor:
        async def decide_approval(self, context, reason):
            return SupervisorDecision(
                decision=SupervisorDecisionKind.APPROVE,
                approval_decision=ApprovalDecisionKind.ACCEPT,
                execpolicy_amendment=amendment,
                reason="scoped task file write",
            )

    class FakeClient:
        def __init__(self) -> None:
            self.responses = []

        async def respond(self, request_id, response):
            self.responses.append((request_id, response))

    class FakeCoder:
        def __init__(self) -> None:
            self.messages = []

        async def steer_or_start(self, message):
            self.messages.append(message)
            return "turn"

    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.store = store
    controller.client = FakeClient()
    controller.approvals = ApprovalManager(tmp_path, supervisor=FakeSupervisor())
    controller.coder = FakeCoder()
    controller.pending_approvals = {}
    controller.tui = _FakeTUI()
    controller._sequence = 0

    await controller.handle_server_request(
        AppServerMessage(
            {
                "id": 54,
                "method": "item/commandExecution/requestApproval",
                "params": {
                    "command": "printf 'hello sentinel\\n' > hello.txt",
                    "cwd": str(tmp_path),
                    "availableDecisions": [offered_decision, "decline"],
                },
            }
        )
    )

    assert controller.client.responses == [(54, {"decision": offered_decision})]
    assert controller.tui.messages[0][0] == "APPROVAL"
    assert controller.coder.messages == []


async def test_run_shutdown_after_final_report_stops_stubbed_appserver(tmp_path: Path, monkeypatch) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")

    class ShutdownClient:
        def __init__(self) -> None:
            self.initial_turn_started = asyncio.Event()
            self.stopped = False
            self.thread_count = 0

        async def start(self):
            return None

        async def initialize(self):
            return {}

        async def stop(self):
            self.stopped = True

        async def account_read(self):
            return {"requiresOpenaiAuth": False, "account": {"id": "acct"}}

        async def account_rate_limits_read(self):
            return {}

        async def model_list(self):
            return {"data": [{"id": "gpt-test"}]}

        async def config_requirements_read(self):
            return {}

        async def thread_start(self, params, **kwargs):
            self.thread_count += 1
            return {
                "thread": {"id": f"thread-{self.thread_count}"},
                "approvalPolicy": "on-request",
                "sandbox": {"type": "readOnly", "networkAccess": False},
            }

        async def thread_unsubscribe(self, thread_id, **kwargs):
            return {}

        async def turn_start(self, params, **kwargs):
            self.initial_turn_started.set()
            return {"turn": {"id": "turn-1", "status": "running"}}

    client = ShutdownClient()
    monkeypatch.setattr("supervisor.controller._run_probe", lambda args: (True, "codex-cli test"))
    controller = SentinelController(
        tmp_path,
        task_path=task,
        client=client,  # type: ignore[arg-type]
        tui=_FakeTUI(),
        overwrite_state=True,
        use_git_diff=False,
    )
    controller._generate_schema_hash_async = _async_schema_hash
    controller._structured_output_self_test = _async_noop

    run_task = asyncio.create_task(controller.run())
    await asyncio.wait_for(client.initial_turn_started.wait(), timeout=1)
    await controller.finalize("task complete", status=SentinelStatus.COMPLETE)
    await asyncio.wait_for(run_task, timeout=1)

    assert client.stopped is True
    assert controller.running is False


async def test_finalize_writes_report_and_status_before_terminal_shutdown(tmp_path: Path) -> None:
    controller, store, _ = _runtime_controller(tmp_path)
    shutdown_seen = False

    async def fake_prepare_terminal_shutdown(reason: str) -> None:
        nonlocal shutdown_seen
        shutdown_seen = True
        assert store.get_sentinel_config().status == SentinelStatus.COMPLETE
        report = store.path(FINAL_REPORT).read_text(encoding="utf-8")
        assert "# Final Report" in report
        assert "task complete" in report

    controller._prepare_terminal_shutdown = fake_prepare_terminal_shutdown  # type: ignore[method-assign]

    await controller.finalize("task complete", status=SentinelStatus.COMPLETE)

    assert shutdown_seen is True
    assert store.get_sentinel_config().status == SentinelStatus.COMPLETE
    assert store.path(FINAL_REPORT).read_text(encoding="utf-8").strip()


def test_run_async_cleanly_exits_zero_after_loop_cleanup() -> None:
    with pytest.raises(SystemExit) as exc_info:
        _run_async_cleanly(_async_noop())

    assert exc_info.value.code == 0


async def _async_noop() -> None:
    return None


async def _async_schema_hash() -> str:
    return "schema"


class _GateFakeCoder:
    def __init__(self) -> None:
        self.messages = []

    async def steer_or_start(self, message):
        self.messages.append(message)
        return "turn"


def _completion_gate_controller(
    tmp_path: Path,
    *,
    validations: list[ValidationRun],
    reruns: int = 0,
) -> tuple[SentinelController, StateStore, Path, _GateFakeCoder]:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )
    coder = _GateFakeCoder()
    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.supervisor = None
    controller.coder = coder
    controller.pending_approvals = {}
    controller.validations = validations
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.tui = _FakeTUI()
    controller.running = True
    controller.paused = False
    controller.event_queue = asyncio.Queue()
    controller._sequence = 0
    controller._supervisor_task = None
    controller._supervisor_dirty = False
    controller._supervisor_next_summary = None
    controller._supervisor_next_completion_review = False
    controller.completion_returns = []
    controller.completion_restarts = 0
    controller.completion_reviewer_rerun_count = reruns
    controller.no_marker_idle_nudge_count = 0
    return controller, store, task, coder


class _RuntimeFakeSupervisor:
    def __init__(self, store: StateStore, task: Path) -> None:
        self.agent = StatelessSupervisorAgent(None, store, task)  # type: ignore[arg-type]
        self.runtime_packets = []
        self.completion_packets = []
        self.completion_thread_id = None

    def build_packet(self, **kwargs):
        return self.agent.build_packet(**kwargs)

    async def decide(self, packet):
        self.runtime_packets.append(packet)
        return SupervisorDecision(
            decision=SupervisorDecisionKind.NOOP,
            reason="observed",
            wake_sequence=packet.wake_sequence,
            generation=packet.generation,
        )

    async def decide_completion(self, packet):
        self.completion_packets.append(packet)
        return CompletionReviewDecision(
            decision="return",
            reason="not used",
            uncovered_behaviors=[],
            validation_gaps=["fake completion gap"],
            claim_evidence_mismatches=[],
            packet_or_access_limitations=[],
            changed_test_risks=[],
            message_to_coder="not used",
            persistent_decision=None,
            progress_update=None,
            clear_handoff=False,
            display_message=None,
            handoff=None,
            wake_sequence=packet.wake_sequence,
            generation=packet.generation,
        )

    async def close_completion_review(self):
        return None


def _runtime_controller(tmp_path: Path) -> tuple[SentinelController, StateStore, _RuntimeFakeSupervisor]:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )
    fake = _RuntimeFakeSupervisor(store, task)
    controller = SentinelController.__new__(SentinelController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.supervisor = fake
    controller.coder = None
    controller.pending_approvals = {}
    controller.last_coder_message = None
    controller.validations = []
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.tui = _FakeTUI()
    controller.running = True
    controller.paused = False
    controller.event_queue = asyncio.Queue()
    controller._sequence = 0
    controller._supervisor_task = None
    controller._supervisor_dirty = False
    controller._supervisor_next_summary = None
    controller._supervisor_next_completion_review = False
    controller._current_turn_action_count = 0
    controller._last_completion_marker_sequence = None
    controller.no_marker_idle_nudge_count = 0
    controller.completion_returns = []
    controller.completion_attempt_count = 0
    controller.completion_restarts = 0
    controller.completion_reviewer_rerun_count = 0
    controller.validation_runtime_state = {}
    controller.completion_review_return_sequence = None
    controller.completion_review_return_validation_sequence = None
    controller._terminal_cleanup_started = False
    controller._command_output_chunks = {}
    return controller, store, fake


async def test_controller_idle_guard_forces_completion_review_for_stalled_no_active_turn(tmp_path: Path) -> None:
    controller, store, fake = _runtime_controller(tmp_path)

    class FakeCoder:
        active_turn_id = None

        def __init__(self) -> None:
            self.messages = []

        async def steer_or_start(self, message):
            self.messages.append(message)
            return "turn"

    coder = FakeCoder()
    controller.coder = coder
    controller.running = True
    controller._last_controller_activity_monotonic = 0.0
    store.update_sentinel_config(
        lambda cfg: cfg.model_copy(
            update={
                "status": SentinelStatus.RUNNING,
                "last_event_sequence": 17,
                "active_coder_turn_id": None,
            }
        )
    )

    await controller._handle_controller_idle_guard(now=301.0)
    await controller._supervisor_task

    assert coder.messages == ["not used"]
    assert coder.messages != [NO_MARKER_IDLE_NUDGE]
    assert len(fake.completion_packets) == 1
    log = store.path(LOG).read_text(encoding="utf-8")
    assert '"type": "controller_idle_guard"' in log


def _load_container_runner() -> ModuleType:
    runner_path = Path(__file__).resolve().parents[1] / "scripts" / "run_sentinel_container_attempt.py"
    spec = importlib.util.spec_from_file_location("run_sentinel_container_attempt", runner_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _covered_accept_decision(*, wake_sequence: int, validation_id: str = "validation-3") -> CompletionReviewDecision:
    return CompletionReviewDecision.model_validate(
        {
            "decision": "accept",
            "reason": "covered",
            "files_reviewed": [
                {"path": "src/app.py", "reason": "changed source", "kind": "source", "inspected": True, "limitation": None},
                {"path": "tests/test_app.py", "reason": "changed test", "kind": "test", "inspected": True, "limitation": None},
            ],
            "behavior_evidence_matrix": [
                {
                    "behavior": "requested behavior",
                    "task_basis": "TASK.md",
                    "files_considered": ["src/app.py", "tests/test_app.py"],
                    "evidence": [
                        {
                            "validation_id": validation_id,
                            "command": "pytest tests/test_app.py",
                            "sequence": 3,
                            "validation_type": "behavioral",
                            "outcome": "pass",
                            "freshness": "fresh",
                            "why_it_covers_behavior": "executes the changed behavior",
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
            "wake_sequence": wake_sequence,
            "generation": 0,
        }
    )


def _gate_packet(
    task: Path,
    *,
    validations: list[ValidationRun],
    wake_sequence: int = 1,
    latest_change: int | None = 2,
) -> SupervisorWakePacket:
    return SupervisorWakePacket(
        wake_sequence=wake_sequence,
        latest_event_sequence=wake_sequence,
        generation=0,
        restart_count=0,
        task_path=str(task),
        task_contents=task.read_text(encoding="utf-8"),
        coder_thread_id="thread",
        changed_files=[
            ChangedFile(path="src/app.py", status="M", sequence=2),
            ChangedFile(path="tests/test_app.py", status="M", sequence=2),
        ],
        validations=validations,
        latest_relevant_change_sequence=latest_change,
    )


class _FakeTUI:
    def __init__(self) -> None:
        self.messages = []
        self.input_queue = asyncio.Queue()

    def render(self, title, message):
        self.messages.append((title, message))

    def status(self, message):
        self.messages.append(("STATUS", message))

    async def start(self):
        self.messages.append(("START", ""))

    async def stop(self):
        self.messages.append(("STOP", ""))
