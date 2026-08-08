from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from supervisor.approvals import ApprovalManager
from supervisor.controller import (
    ADVERSARY_MODEL,
    CONTEXT_NATIVE_VALIDATION_NUDGE,
    NO_MARKER_IDLE_NUDGE,
    POST_RESTART_CONTINUE_NUDGE,
    ControllerEvent,
    BelloController,
    _ensure_internal_runtime_git_excluded,
    _has_malformed_readiness_marker,
    _has_passing_behavioral_validation,
    _has_readiness_marker,
    _git_status_entries_from_porcelain_v1_z,
    _generic_validation_masking_reason,
    _inspection_from_action,
    _hash_file,
    _path_from_git_status_line,
    _read_workspace_file,
    _runtime_restart_issue,
    _sandbox_matches_mode,
    _evidence_provenance_summary,
    _file_kind,
    _validation_from_action,
    _validation_freshness_summary,
)
from supervisor.adversary_agent import AdversaryAgentError
from supervisor.approvals import normalize_approval_request
from supervisor.appserver import APP_SERVER_CODER_RPC_TIMEOUT_SECONDS, AppServerError, AppServerMessage, AppServerTimeoutError, ClientRole
from supervisor.coder import CODEX_FAST_SERVICE_TIER, CoderSession, coder_thread_params, coder_turn_params
from supervisor.main import _run_async_cleanly
from supervisor.project_config import DEFAULT_MODEL, MODEL_GPT_5_5, MODEL_GPT_5_6_SOL
from supervisor.schemas import (
    AppEvent,
    AppEventSource,
    AdversaryReport,
    ApprovalDecisionKind,
    ChangedFile,
    ChangedFileDiff,
    CheapRuntimeDecision,
    CoderMessage,
    CompletionReviewDecision,
    FinalReport,
    PriorIntervention,
    RestartHandoff,
    BelloConfig,
    BelloStatus,
    SupervisorDecision,
    SupervisorDecisionKind,
    SupervisorWakePacket,
    TriggeringAction,
    ValidationRun,
)
from supervisor.state import (
    CONFIG,
    DECISIONS,
    EVENTS,
    FINAL_REPORT,
    HANDOFF,
    LOG,
    PREVIOUS_RUNS,
    PROGRESS,
    PROVIDER_TOKEN_USAGE,
    RECOVERY,
    RUNTIME_METRICS,
    RUNTIME_TRACE,
    SUPERVISOR_WAKES,
    StateStore,
)
from supervisor.supervisor_agent import StatelessSupervisorAgent, SupervisorAgentError
from supervisor.workspace_snapshot import create_workspace_snapshot


def test_bello_state_initializes_required_files(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    assert store.path(EVENTS).exists()
    assert store.path(FINAL_REPORT).exists()
    assert store.path(PROVIDER_TOKEN_USAGE).exists()
    assert store.get_bello_config().task_path == str(task)


def test_provider_token_usage_ledger_keeps_every_raw_sample_and_role(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    controller = BelloController(tmp_path, task_path=task)
    controller.initialize_state()
    controller._mark_supervisor_thread_started("completion-thread", "completion")

    first_usage = {
        "total": {
            "inputTokens": 10,
            "cachedInputTokens": 4,
            "outputTokens": 5,
            "reasoningOutputTokens": 2,
            "totalTokens": 15,
        },
        "last": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15},
        "providerExtension": {"preserved": True},
    }
    params = {
        "threadId": "completion-thread",
        "turnId": "turn-1",
        "tokenUsage": first_usage,
    }
    controller._record_provider_token_usage(
        ClientRole.SUPERVISOR,
        params,
        process_epoch=3,
        app_server_instance_id="instance-1",
    )
    controller._record_provider_token_usage(ClientRole.SUPERVISOR, params)

    samples = [
        json.loads(line)
        for line in controller.store.path(PROVIDER_TOKEN_USAGE).read_text(encoding="utf-8").splitlines()
    ]
    assert len(samples) == 2
    assert samples[0]["tokenUsage"] == first_usage
    assert samples[0]["transportRole"] == "supervisor"
    assert samples[0]["role"] == "completion"
    assert samples[0]["threadId"] == "completion-thread"
    assert samples[0]["turnId"] == "turn-1"
    assert samples[0]["processEpoch"] == 3
    assert samples[0]["appServerInstanceId"] == "instance-1"
    assert samples[0]["cumulative"]["authoritativeTotalTokens"] == 15
    assert samples[0]["cumulative"]["liveDeltaTokens"] == 15
    assert samples[1]["tokenUsage"] == first_usage
    assert samples[1]["cumulative"]["liveDeltaTokens"] == 0


def test_internal_supervisor_dir_is_added_to_git_info_exclude(tmp_path: Path) -> None:
    git_info = tmp_path / ".git" / "info"
    git_info.mkdir(parents=True)
    exclude = git_info / "exclude"
    exclude.write_text("# local excludes\n", encoding="utf-8")

    _ensure_internal_runtime_git_excluded(tmp_path)
    _ensure_internal_runtime_git_excluded(tmp_path)

    lines = exclude.read_text(encoding="utf-8").splitlines()
    assert lines.count(".supervisor/") == 1
    assert lines.count(".supervisor") == 1


async def test_git_init_log_is_filtered_from_changed_files_source(tmp_path: Path) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True, text=True)
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    (tmp_path / ".git-init.log").write_text("initial\n", encoding="utf-8")
    (tmp_path / "src.c").write_text("int value(void) { return 1; }\n", encoding="utf-8")
    subprocess.run(["git", "add", "TASK.md", ".git-init.log", "src.c"], cwd=tmp_path, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "init"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    (tmp_path / ".git-init.log").write_text("initial\nmore git init output\n", encoding="utf-8")
    (tmp_path / "src.c").write_text("int value(void) { return 2; }\n", encoding="utf-8")

    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.use_git_diff = True
    controller.observed_changed_files = {}

    paths = {file.path for file in await controller.changed_files()}
    diff_summary = await controller.diff_summary()

    assert paths == {"src.c"}
    assert "src.c" in diff_summary
    assert ".git-init.log" not in diff_summary


async def test_generated_cache_artifacts_are_filtered_from_changed_files_source(tmp_path: Path) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True, text=True)
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.c").write_text("int main(void) { return 1; }\n", encoding="utf-8")
    subprocess.run(["git", "add", "TASK.md", "src/app.c"], cwd=tmp_path, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "init"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )
    (tmp_path / "src" / "app.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (tmp_path / "src" / "app.o").write_bytes(b"\x7fELF\0object")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "app.cpython-312.pyc").write_bytes(b"\0\0\0pyc")
    (tmp_path / "compiler").write_bytes(b"\x7fELF\0compiled")
    script = tmp_path / "run_demo"
    script.write_text("#!/usr/bin/env bash\nprintf 'demo\\n'\n", encoding="utf-8")
    script.chmod(0o755)

    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.use_git_diff = True
    controller.observed_changed_files = {}

    changed = await controller.changed_files()
    paths = {file.path for file in changed}
    diff_summary = await controller.diff_summary()

    assert "src/app.c" in paths
    assert "run_demo" in paths
    assert "src/app.o" in paths
    assert "__pycache__/app.cpython-312.pyc" not in paths
    assert "compiler" in paths
    assert "src/app.c" in diff_summary
    assert "run_demo" in diff_summary
    assert "src/app.o" in diff_summary
    assert "__pycache__" not in diff_summary
    assert "compiler" in diff_summary

    controller.use_git_diff = False
    controller.observed_changed_files = {
        "src/app.c": ChangedFile(path="src/app.c", status="modified", sequence=2),
        "src/app.o": ChangedFile(path="src/app.o", status="modified", sequence=2),
        "__pycache__/app.cpython-312.pyc": ChangedFile(
            path="__pycache__/app.cpython-312.pyc",
            status="modified",
            sequence=2,
        ),
        "compiler": ChangedFile(path="compiler", status="modified", sequence=2),
    }

    observed_paths = {file.path for file in await controller.changed_files()}
    assert observed_paths == {"src/app.c", "src/app.o", "compiler"}


async def test_greenfield_untracked_files_keep_sequences_for_validation_freshness(tmp_path: Path) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True, text=True)
    task = tmp_path / "TASK.md"
    task.write_text("# Build a Python CLI", encoding="utf-8")
    subprocess.run(["git", "add", "TASK.md"], cwd=tmp_path, check=True, capture_output=True, text=True)
    subprocess.run(
        ["git", "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "init"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    )

    source = tmp_path / "src" / "new module.py"
    test_file = tmp_path / "tests" / "test_cli.py"
    source.parent.mkdir()
    test_file.parent.mkdir()
    source.write_text("def main():\n    return 0\n", encoding="utf-8")
    test_file.write_text("def test_main():\n    assert True\n", encoding="utf-8")

    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.use_git_diff = True
    controller.observed_changed_files = {
        "src/new module.py": ChangedFile(path="src/new module.py", status="modified", sequence=7),
        "tests/test_cli.py": ChangedFile(path="tests/test_cli.py", status="modified", sequence=8),
        "src/no-longer-changed.py": ChangedFile(path="src/no-longer-changed.py", status="modified", sequence=99),
    }

    changed = await controller.changed_files()
    by_path = {file.path: file for file in changed}

    assert set(by_path) == {"src/new module.py", "tests/test_cli.py"}
    assert by_path["src/new module.py"].status == "??"
    assert by_path["src/new module.py"].sequence == 7
    assert by_path["tests/test_cli.py"].status == "??"
    assert by_path["tests/test_cli.py"].sequence == 8

    controller.validations = [
        ValidationRun(command="pytest", exit_code=0, passed=True, summary="2 passed", sequence=9)
    ]
    assert await controller._done_without_fresh_behavioral_validation() is None
    assert store.get_bello_config().last_relevant_edit_sequence == 8

    controller.validations = [
        ValidationRun(command="pytest", exit_code=0, passed=True, summary="2 passed", sequence=8)
    ]
    stale_reason = await controller._done_without_fresh_behavioral_validation()
    assert stale_reason is not None
    assert "relevant edit sequence 8" in stale_reason


def test_coder_sandbox_defaults_to_workspace_write(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("BELLO_CODER_SANDBOX", raising=False)

    assert coder_thread_params(tmp_path)["sandbox"] == "workspace-write"
    assert coder_turn_params("thread", "work", tmp_path)["sandboxPolicy"] == {
        "type": "workspaceWrite",
        "writableRoots": [str(tmp_path.resolve())],
        "networkAccess": False,
    }


def test_snapshot_mode_protects_entire_original_workspace_from_approval_commands(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller._coder_snapshot = SimpleNamespace(original_root=tmp_path)

    assert controller._immutable_approval_paths() == (tmp_path, task)


def test_workspace_write_preflight_rejects_network_or_extra_writable_roots(tmp_path: Path) -> None:
    valid = {"type": "workspaceWrite", "writableRoots": [], "networkAccess": False}
    same_root = {
        "type": "workspaceWrite",
        "writableRoots": [str(tmp_path.resolve())],
        "networkAccess": False,
    }
    network_enabled = {"type": "workspaceWrite", "writableRoots": [], "networkAccess": True}
    extra_root = {
        "type": "workspaceWrite",
        "writableRoots": [str(tmp_path.parent.resolve())],
        "networkAccess": False,
    }

    assert _sandbox_matches_mode(valid, "workspace-write", workspace_root=tmp_path) is True
    assert _sandbox_matches_mode(same_root, "workspace-write", workspace_root=tmp_path) is True
    assert _sandbox_matches_mode(network_enabled, "workspace-write", workspace_root=tmp_path) is False
    assert _sandbox_matches_mode(extra_root, "workspace-write", workspace_root=tmp_path) is False


def test_coder_sandbox_can_use_read_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("BELLO_CODER_SANDBOX", "read-only")

    assert coder_thread_params(tmp_path)["sandbox"] == "read-only"
    assert coder_turn_params("thread", "work", tmp_path)["sandboxPolicy"] == {
        "type": "readOnly",
        "networkAccess": False,
    }


def test_coder_fast_mode_sets_codex_service_tier(tmp_path: Path) -> None:
    assert coder_thread_params(tmp_path)["serviceTier"] is None
    assert coder_turn_params("thread", "work", tmp_path)["serviceTier"] is None
    assert coder_thread_params(tmp_path, fast=True)["serviceTier"] == CODEX_FAST_SERVICE_TIER
    assert coder_turn_params("thread", "work", tmp_path, fast=True)["serviceTier"] == CODEX_FAST_SERVICE_TIER


def test_coder_turn_params_include_intelligence_effort(tmp_path: Path) -> None:
    assert coder_turn_params("thread", "work", tmp_path, intelligence="xhigh")["effort"] == "xhigh"


def test_git_status_path_parser_handles_missing_second_status_column() -> None:
    assert _path_from_git_status_line(" M public/src/admin/manage/users.js") == "public/src/admin/manage/users.js"
    assert _path_from_git_status_line("M  public/language/en-GB/admin/manage/users.json") == "public/language/en-GB/admin/manage/users.json"
    assert _path_from_git_status_line("M public/language/en-GB/admin/manage/users.json") == "public/language/en-GB/admin/manage/users.json"


def test_git_porcelain_z_parser_preserves_exact_paths_and_rename_destination() -> None:
    output = "R  src/new name.py\0src/old name.py\0?? new dir/file one.py\0"

    assert _git_status_entries_from_porcelain_v1_z(output) == [
        ("src/new name.py", "R"),
        ("new dir/file one.py", "??"),
    ]


async def test_changed_files_and_diff_summary_filter_internal_runtime_paths(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    controller = BelloController.__new__(BelloController)
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
        if command == ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"]:
            return " M .supervisor/CONFIG.json\0 M TASK.md\0 M src/app.py\0"
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
    monkeypatch.setenv("BELLO_CODER_SANDBOX", "danger-full-access")

    assert coder_thread_params(tmp_path)["sandbox"] == "danger-full-access"
    assert coder_turn_params("thread", "work", tmp_path)["sandboxPolicy"] == {"type": "dangerFullAccess"}


def test_bello_events_are_append_only_jsonl(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    store.append_event(AppEvent(sequence=1, source=AppEventSource.SYSTEM, event_type="test"))

    lines = store.path(EVENTS).read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[0])["event_type"] == "test"



def test_fresh_initialization_creates_empty_previous_runs_without_run_slot(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), mode="fresh")
    previous_runs = store.path(PREVIOUS_RUNS)

    assert previous_runs.is_dir()
    assert list(previous_runs.iterdir()) == []

    store.path(EVENTS).write_text('{"sequence": 9}\n', encoding="utf-8")
    store.path(LOG).write_text("old log\n", encoding="utf-8")
    (previous_runs / "run9").mkdir()
    (previous_runs / "run9" / "FINAL_REPORT.md").write_text("old report", encoding="utf-8")
    recovery = store.path(RECOVERY)
    (recovery / "run9" / "workspace").mkdir(parents=True)
    (recovery / "run9" / "workspace" / "app.py").write_text("recovery", encoding="utf-8")
    (store.state_dir / "scratch.txt").write_text("scratch", encoding="utf-8")

    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), mode="fresh")

    assert store.path(EVENTS).read_text(encoding="utf-8") == ""
    assert store.path(LOG).read_text(encoding="utf-8") == ""
    assert store.path(FINAL_REPORT).read_text(encoding="utf-8") == ""
    assert store.path(PREVIOUS_RUNS).is_dir()
    assert list(store.path(PREVIOUS_RUNS).iterdir()) == []
    assert not store.path(RECOVERY).exists()
    assert not (store.state_dir / "scratch.txt").exists()


def test_resume_initialization_preserves_history_and_resets_runtime_files(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    config = BelloConfig(project_root=str(tmp_path), task_path=str(task))
    store.initialize_bello(config, mode="fresh")
    previous_runs = store.path(PREVIOUS_RUNS)
    run1 = previous_runs / "run1"
    run1.mkdir()
    (run1 / "task.md").write_text("old task", encoding="utf-8")
    (run1 / "FINAL_REPORT.md").write_text("old report", encoding="utf-8")
    store.path(EVENTS).write_text('{"sequence": 42}\n', encoding="utf-8")
    store.path(LOG).write_text("old log\n", encoding="utf-8")
    store.path(FINAL_REPORT).write_text("stale final", encoding="utf-8")
    store.path(PROGRESS).write_text("stale progress", encoding="utf-8")
    store.path(DECISIONS).write_text("stale decisions", encoding="utf-8")
    store.path(SUPERVISOR_WAKES).write_text("stale wake\n", encoding="utf-8")
    store.path(RUNTIME_TRACE).write_text("stale trace\n", encoding="utf-8")
    store.path(RUNTIME_METRICS).write_text('{"old": true}\n', encoding="utf-8")
    recovery_workspace = store.path(RECOVERY) / "run2" / "workspace"
    recovery_workspace.mkdir(parents=True)
    (recovery_workspace / "app.py").write_text("recover me", encoding="utf-8")
    (store.state_dir / "scratch.txt").write_text("scratch", encoding="utf-8")
    (store.state_dir / "scratch_dir").mkdir()

    store.initialize_bello(config, mode="resume")

    assert store.path(EVENTS).read_text(encoding="utf-8") == '{"sequence": 42}\n'
    assert store.path(LOG).read_text(encoding="utf-8") == "old log\n"
    assert (run1 / "task.md").read_text(encoding="utf-8") == "old task"
    assert (run1 / "FINAL_REPORT.md").read_text(encoding="utf-8") == "old report"
    assert store.path(FINAL_REPORT).read_text(encoding="utf-8") == ""
    assert "not started" in store.path(PROGRESS).read_text(encoding="utf-8")
    assert store.path(DECISIONS).read_text(encoding="utf-8") == "# Decisions\n\n"
    assert store.path(SUPERVISOR_WAKES).read_text(encoding="utf-8") == ""
    assert store.path(RUNTIME_TRACE).read_text(encoding="utf-8") == ""
    assert store.path(RUNTIME_METRICS).read_text(encoding="utf-8") == "{}\n"
    assert (recovery_workspace / "app.py").read_text(encoding="utf-8") == "recover me"
    assert not (store.state_dir / "scratch.txt").exists()
    assert not (store.state_dir / "scratch_dir").exists()


def test_archive_completed_run_copies_task_and_report_after_completion(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), mode="fresh")

    store.write_final_report("first report\n")
    run1 = store.archive_completed_run(task)
    store.write_final_report("second report\n")
    run2 = store.archive_completed_run(task)

    assert run1.name == "run1"
    assert run2.name == "run2"
    assert (run1 / "task.md").read_text(encoding="utf-8") == "# Task"
    assert (run1 / "FINAL_REPORT.md").read_text(encoding="utf-8") == "first report\n"
    assert (run2 / "FINAL_REPORT.md").read_text(encoding="utf-8") == "second report\n"


def test_controller_event_sequence_starts_at_one_when_events_are_empty(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")

    controller = BelloController(tmp_path, task_path=task)
    controller.initialize_state()

    assert controller._sequence == 0

    controller._append_event(AppEventSource.SYSTEM, "test/new")

    lines = controller.store.path(EVENTS).read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[-1])["sequence"] == 1
    assert controller.store.get_bello_config().last_event_sequence == 1


def test_controller_event_sequence_continues_existing_events(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
    store.append_event(AppEvent(sequence=7, source=AppEventSource.SYSTEM, event_type="old"))
    store.append_event(AppEvent(sequence=42, source=AppEventSource.SYSTEM, event_type="newer"))

    controller = BelloController(tmp_path, task_path=task)
    controller.initialize_state()

    assert controller._sequence == 42

    controller._append_event(AppEventSource.SYSTEM, "test/new")

    lines = controller.store.path(EVENTS).read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[-1])["sequence"] == 43
    assert controller.store.get_bello_config().last_event_sequence == 43


def test_final_report_rendering(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    store.write_final_report(FinalReport(task_path=str(task), status="complete", result="done", files_changed=["a.py"]))

    text = store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert "# Final Report" in text
    assert "- a.py" in text


async def test_final_report_non_git_omits_git_usage_and_includes_validations(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    controller = BelloController.__new__(BelloController)
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

    run1 = store.path(PREVIOUS_RUNS) / "run1"
    assert (run1 / "task.md").read_text(encoding="utf-8") == "# Task"
    archived_report = (run1 / "FINAL_REPORT.md").read_text(encoding="utf-8")
    assert "# Final Report" in archived_report
    assert "- Result: task complete" in archived_report

    controller._archive_final_report_once()
    assert sorted(path.name for path in store.path(PREVIOUS_RUNS).iterdir()) == ["run1"]


async def test_finalize_applies_accepted_snapshot_patch_to_real_workspace(tmp_path: Path) -> None:
    controller, store, _ = _runtime_controller(tmp_path)
    controller.use_git_diff = True
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    snapshot = create_workspace_snapshot(tmp_path, controller.task_path)
    controller._coder_snapshot = snapshot
    controller._snapshot_patch_applied = False
    controller.workspace_root = snapshot.snapshot_root
    controller.workspace_task_path = snapshot.task_path
    (snapshot.snapshot_root / "app.py").write_text("value = 2\n", encoding="utf-8")

    await controller.finalize("task complete", status=BelloStatus.COMPLETE, completion_review_accepted=True)

    assert source.read_text(encoding="utf-8") == "value = 2\n"
    assert not snapshot.temp_root.exists()
    assert store.get_bello_config().status == BelloStatus.COMPLETE
    assert "- app.py" in store.path(FINAL_REPORT).read_text(encoding="utf-8")


async def test_finalize_preserves_snapshot_and_escalates_when_patch_back_is_rejected(tmp_path: Path) -> None:
    controller, store, _ = _runtime_controller(tmp_path)
    controller.use_git_diff = True
    snapshot = create_workspace_snapshot(tmp_path, controller.task_path)
    controller._coder_snapshot = snapshot
    controller._snapshot_patch_applied = False
    controller.workspace_root = snapshot.snapshot_root
    controller.workspace_task_path = snapshot.task_path
    (snapshot.snapshot_root / ".env").write_text("TOKEN=secret\n", encoding="utf-8")

    await controller.finalize("task complete", status=BelloStatus.COMPLETE, completion_review_accepted=True)

    assert not (tmp_path / ".env").exists()
    assert not snapshot.temp_root.exists()
    recovery_workspace = tmp_path / ".supervisor" / "recovery" / "run1" / "workspace"
    assert recovery_workspace.is_dir()
    assert (recovery_workspace / ".env").read_text(encoding="utf-8") == "TOKEN=secret\n"
    assert not (recovery_workspace / ".git").exists()
    assert not (recovery_workspace / ".supervisor").exists()
    assert not (recovery_workspace / "TASK.md").is_symlink()
    assert (recovery_workspace / "TASK.md").read_text(encoding="utf-8") == "# Task"
    assert store.get_bello_config().status == BelloStatus.ESCALATED
    report = store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert "accepted snapshot could not be applied" in report
    assert "snapshot preserved" in report


async def test_noncomplete_run_preserves_workspace_without_applying_it(tmp_path: Path) -> None:
    controller, store, _ = _runtime_controller(tmp_path)
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    snapshot = create_workspace_snapshot(tmp_path, controller.task_path)
    controller._coder_snapshot = snapshot
    controller._snapshot_patch_applied = False
    controller._coder_started = True
    controller.workspace_root = snapshot.snapshot_root
    controller.workspace_task_path = snapshot.task_path
    (snapshot.snapshot_root / "app.py").write_text("value = 2\n", encoding="utf-8")

    await controller.finalize("exited by user", status=BelloStatus.EXITED)

    recovery_workspace = tmp_path / ".supervisor" / "recovery" / "run1" / "workspace"
    assert source.read_text(encoding="utf-8") == "value = 1\n"
    assert (recovery_workspace / "app.py").read_text(encoding="utf-8") == "value = 2\n"
    assert not (recovery_workspace / ".git").exists()
    assert not (recovery_workspace / ".supervisor").exists()
    assert store.get_bello_config().status == BelloStatus.EXITED
    assert str(recovery_workspace) in store.path(FINAL_REPORT).read_text(encoding="utf-8")


async def test_preflight_failure_cleans_unused_snapshot_without_recovery(tmp_path: Path) -> None:
    controller, store, _ = _runtime_controller(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, controller.task_path)
    controller._coder_snapshot = snapshot
    controller._snapshot_patch_applied = False
    controller._coder_started = False
    controller.workspace_root = snapshot.snapshot_root
    controller.workspace_task_path = snapshot.task_path

    await controller.finalize("preflight failed", status=BelloStatus.PROVIDER_FAILURE)

    assert not snapshot.temp_root.exists()
    assert not (store.state_dir / "recovery").exists()
    assert store.get_bello_config().status == BelloStatus.PROVIDER_FAILURE


def test_task_integrity_detects_replaced_snapshot_link(tmp_path: Path) -> None:
    controller, _store, _ = _runtime_controller(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, controller.task_path)
    controller._coder_snapshot = snapshot
    controller.workspace_root = snapshot.snapshot_root
    controller.workspace_task_path = snapshot.task_path
    try:
        assert controller._task_integrity_issue() is None
        snapshot.task_path.unlink()
        snapshot.task_path.write_text("weakened\n", encoding="utf-8")

        assert controller._task_integrity_issue() == "the coder workspace replaced or modified the immutable task copy"
    finally:
        snapshot.cleanup()


async def test_runtime_git_inspection_waits_for_trusted_snapshot_config(tmp_path: Path) -> None:
    controller, _store, _ = _runtime_controller(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, controller.task_path)
    controller._coder_snapshot = snapshot
    controller.workspace_root = snapshot.snapshot_root
    controller.workspace_task_path = snapshot.task_path
    try:
        subprocess.run(
            ["git", "config", "--local", "filter.untrusted.clean", "false"],
            cwd=snapshot.snapshot_root,
            check=True,
        )

        assert await controller._git_output(["git", "status", "--short"]) is None

        repaired = controller._repair_snapshot_runtime_controls(source="test")

        assert repaired == ("git_config",)
        assert await controller._git_output(["git", "status", "--short"]) == ""
    finally:
        snapshot.cleanup()


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
    shell_node_test = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="/bin/bash -lc 'node --test'",
            exit_code=0,
            status="completed",
            summary="command completed: /bin/bash -lc 'node --test' exit=0",
        ),
        sequence=12,
        item={"stdout": "ok 1 - mounted board\n1..1\n# tests 1\n# pass 1\n# fail 0\n"},
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
    shell_zero_tests = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="/bin/bash -lc 'npm test'",
            exit_code=0,
            status="completed",
            summary="command completed: /bin/bash -lc 'npm test' exit=0",
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
    assert shell_node_test is not None
    assert shell_node_test.type == "behavioral"
    assert shell_node_test.outcome == "pass"
    assert shell_node_test.trusted_validation_outcome == "passed"
    assert zero_tests is not None
    assert zero_tests.type == "behavioral"
    assert zero_tests.outcome == "fail"
    assert not zero_tests.passed
    assert shell_zero_tests is not None
    assert shell_zero_tests.type == "behavioral"
    assert shell_zero_tests.outcome == "fail"
    assert not shell_zero_tests.passed
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
    assert python_unittest is not None
    assert python_unittest.type == "behavioral"
    assert python_unittest.trusted_validation_outcome == "passed"
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


def test_behavioral_validation_rejects_runner_names_embedded_in_echo_output() -> None:
    forged = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="echo pytest",
            exit_code=0,
            status="completed",
            summary="broker-attested Context command",
        ),
        sequence=1,
        item={"stdout": "pytest\n1 passed\n"},
    )

    assert forged is None

    piped_forgery = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="echo pytest | cat",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=2,
        item={"stdout": "pytest\n1 passed\n"},
    )

    assert piped_forgery is None


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


async def test_command_aggregated_output_is_attached_to_validation_ledger(tmp_path: Path) -> None:
    controller, _store, _fake = _runtime_controller(tmp_path)

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
                        "cwd": str(tmp_path),
                        "exitCode": 0,
                        "status": "completed",
                        "aggregatedOutput": "Hello world\n",
                    },
                },
            }
        )
    )

    assert len(controller.validations) == 1
    validation = controller.validations[0]
    assert validation.command == "python3 hello.py"
    assert validation.type == "behavior_demo"
    assert validation.passed is True
    assert validation.captured_output == "Hello world\n"
    assert "Hello world" in validation.summary


def test_readiness_marker_detection_requires_own_exact_line() -> None:
    assert _has_readiness_marker("Summary\n  BELLO_READY_FOR_REVIEW  \n")
    assert not _has_readiness_marker("Summary BELLO_READY_FOR_REVIEW")
    assert not _has_readiness_marker("bello_ready_for_review")
    assert _has_malformed_readiness_marker("bello_ready_for_review")
    assert _has_malformed_readiness_marker("BELLO READY FOR REVIEW")
    assert not _has_malformed_readiness_marker("I am not emitting `BELLO_READY_FOR_REVIEW`.")


async def test_exact_marker_triggers_completion_review_accept(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
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
    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.supervisor = fake
    controller.pending_approvals = {}
    controller.last_coder_message = CoderMessage(
        text="Summary: done\nValidation: pytest\nBELLO_READY_FOR_REVIEW",
        sequence=1,
    )
    controller.validations = [
        ValidationRun(command="pytest", exit_code=0, passed=True, summary="passed", sequence=1)
    ]
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.adversary_enabled = False
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
    assert fake.completion_packets[0].last_coder_message.text.endswith("BELLO_READY_FOR_REVIEW")
    assert store.get_bello_config().status == BelloStatus.COMPLETE
    assert "accepted by completion_review" in store.path(FINAL_REPORT).read_text(encoding="utf-8")


async def test_summary_done_without_marker_steers_for_exact_marker_not_completion(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"), overwrite=True)

    class FakeCoder:
        def __init__(self) -> None:
            self.messages = []

        async def steer_or_start(self, message):
            self.messages.append(message)
            return "turn"

    controller = BelloController.__new__(BelloController)
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
    controller.adversary_enabled = False
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
    assert store.get_bello_config().status == BelloStatus.STARTING


async def test_material_limitation_without_marker_escalates_instead_of_marker_nudge(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"), overwrite=True)

    class FakeCoder:
        def __init__(self) -> None:
            self.messages = []
            self.interrupted = False

        async def steer_or_start(self, message):
            self.messages.append(message)
            return "turn"

        async def interrupt(self):
            self.interrupted = True

    controller = BelloController.__new__(BelloController)
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
            "`BELLO_READY_FOR_REVIEW`."
        ),
        sequence=7,
    )
    controller.validations = []
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.adversary_enabled = False
    controller.tui = _FakeTUI()
    controller.running = True
    controller.coder_client = controller.supervisor_client = None
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

    assert store.get_bello_config().status == BelloStatus.ESCALATED
    assert controller.coder.messages == []
    assert controller.coder.interrupted is True
    assert "Coder reported material limitation" in store.path(PROGRESS).read_text(encoding="utf-8")
    assert "material validation limitation" in store.path(FINAL_REPORT).read_text(encoding="utf-8")


async def test_no_marker_idle_forces_completion_review_once(tmp_path: Path) -> None:
    controller, store, fake = _runtime_controller(tmp_path)
    store.update_bello_config(
        lambda cfg: cfg.model_copy(update={"active_coder_turn_id": None, "last_event_sequence": 17})
    )

    await controller._handle_no_marker_idle()
    await controller._supervisor_task

    assert len(fake.completion_packets) == 1
    assert controller.completion_returns[0].reason == "not used"
    assert "Controller forcing completion_review" in store.path(PROGRESS).read_text(encoding="utf-8")

    await controller._handle_no_marker_idle()

    assert len(fake.completion_packets) == 1


async def test_marker_with_completion_review_disabled_finalizes_without_review(tmp_path: Path) -> None:
    controller, store, fake = _runtime_controller(tmp_path)
    store.update_bello_config(lambda cfg: cfg.model_copy(update={"completion_review_enabled": False}))
    controller.last_coder_message = CoderMessage(
        text="Summary: done\nValidation: pytest\nBELLO_READY_FOR_REVIEW",
        sequence=1,
    )
    controller.validations = [
        ValidationRun(command="pytest", exit_code=0, passed=True, summary="passed", sequence=1)
    ]

    await controller._handle_coder_turn_completed(item_id="message-item")

    assert store.get_bello_config().status == BelloStatus.COMPLETE
    assert fake.completion_packets == []
    report = store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert "completion review disabled by config" in report
    assert "- Completion review accepted: false" in report
    progress = store.path(PROGRESS).read_text(encoding="utf-8")
    assert "completion review is disabled by config" in progress
    events = [json.loads(line) for line in store.path(EVENTS).read_text(encoding="utf-8").splitlines()]
    assert any(event["event_type"] == "completion/review_disabled_finalize" for event in events)


async def test_completion_review_cli_override_beats_persisted_config(tmp_path: Path) -> None:
    controller, store, _ = _runtime_controller(tmp_path)

    controller.completion_review = False
    assert controller._effective_completion_review() is False

    controller.completion_review = True
    store.update_bello_config(lambda cfg: cfg.model_copy(update={"completion_review_enabled": False}))
    assert controller._effective_completion_review() is True

    controller.completion_review = None
    assert controller._effective_completion_review() is False


async def test_completion_review_disabled_suppresses_adversary(tmp_path: Path) -> None:
    controller, store, _ = _runtime_controller(tmp_path)
    controller.adversary_enabled = True
    controller.adversary_runs = None
    store.update_bello_config(
        lambda cfg: cfg.model_copy(update={"max_adversary_runs": 2, "completion_review_enabled": False})
    )

    assert controller._effective_max_adversary_runs() == 0
    assert controller._adversary_model_required_for_preflight() is False


async def test_no_marker_idle_nudges_coder_when_completion_review_disabled(tmp_path: Path) -> None:
    controller, store, fake = _runtime_controller(tmp_path)
    store.update_bello_config(
        lambda cfg: cfg.model_copy(
            update={"active_coder_turn_id": None, "last_event_sequence": 17, "completion_review_enabled": False}
        )
    )

    class FakeCoder:
        def __init__(self) -> None:
            self.messages: list[str] = []

        async def steer_or_start(self, message: str) -> str:
            self.messages.append(message)
            return "turn"

    controller.coder = FakeCoder()

    await controller._handle_no_marker_idle()

    assert fake.completion_packets == []
    assert controller.coder.messages == [NO_MARKER_IDLE_NUDGE]


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
                        "command": "pwd",
                        "exitCode": 0,
                        "status": "completed",
                        "stdout": str(tmp_path) + "\n",
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
    store.patch_health(lambda health: health.model_copy(update={"restart_count": 100}))

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


def _runtime_failure_validation(
    *,
    sequence: int,
    output: str,
    validation_id: str = "validation-repeat",
    trusted_outcome: str = "failed",
    masking_reason: str | None = None,
    command: str = "pytest tests/test_parser.py",
) -> ValidationRun:
    passed = trusted_outcome == "passed"
    return ValidationRun(
        validation_id=validation_id,
        command=command,
        normalized_command=command,
        exit_code=0 if passed else 1,
        shell_exit_code=0 if passed else 1,
        outcome="pass" if passed else "fail",
        passed=passed,
        trusted_validation_outcome=trusted_outcome,
        masking_reason=masking_reason,
        summary=output,
        captured_output=output,
        sequence=sequence,
        executed_test_names=["tests/test_parser.py::test_parse"],
        executed_test_files=["tests/test_parser.py"],
        failed_count=0 if passed else 1,
    )


def _runtime_validation_packet(
    validation: ValidationRun,
    *,
    wake_sequence: int,
    reason: str = "repeated_same_failing_validation",
) -> SupervisorWakePacket:
    return SupervisorWakePacket(
        wake_sequence=wake_sequence,
        latest_event_sequence=wake_sequence,
        generation=0,
        restart_count=0,
        task_path="TASK.md",
        task_contents="# Task",
        current_summary=f"Runtime trigger ({reason}): validation requires review",
        coder_thread_id="thread",
        triggering_action=TriggeringAction(
            kind="commandExecution",
            command=validation.command,
            exit_code=validation.exit_code,
            status="completed",
            summary=validation.summary,
        ),
        validations=[validation],
    )


def _runtime_unresolved_validation(
    *,
    sequence: int,
    command: str,
    validation_id: str,
) -> ValidationRun:
    return ValidationRun(
        validation_id=validation_id,
        command=command,
        normalized_command=command,
        exit_code=None,
        shell_exit_code=None,
        outcome="fail",
        passed=False,
        trusted_validation_outcome="failed",
        summary=f"command completed: {command} exit=None",
        sequence=sequence,
    )


def test_runtime_restart_issue_distinguishes_failures_but_groups_same_masking_reason() -> None:
    first = _runtime_failure_validation(sequence=1, output="AssertionError: expected 1, got 2")
    different = _runtime_failure_validation(sequence=2, output="ValueError: malformed header")

    first_issue = _runtime_restart_issue(_runtime_validation_packet(first, wake_sequence=1))
    different_issue = _runtime_restart_issue(_runtime_validation_packet(different, wake_sequence=2))

    assert first_issue is not None
    assert different_issue is not None
    assert first_issue.key != different_issue.key

    masked_a = _runtime_failure_validation(
        sequence=3,
        output="pipeline exit was masked",
        validation_id="validation-a",
        trusted_outcome="masked_or_unknown",
        masking_reason="shell_pipeline_masks_failure",
        command="bash strict-a.sh | tail",
    )
    masked_b = _runtime_failure_validation(
        sequence=4,
        output="different command masked the same way",
        validation_id="validation-b",
        trusted_outcome="masked_or_unknown",
        masking_reason="shell_pipeline_masks_failure",
        command="bash strict-b.sh | head",
    )

    masked_a_issue = _runtime_restart_issue(
        _runtime_validation_packet(masked_a, wake_sequence=3, reason="masked_validation")
    )
    masked_b_issue = _runtime_restart_issue(
        _runtime_validation_packet(masked_b, wake_sequence=4, reason="masked_validation")
    )

    assert masked_a_issue is not None
    assert masked_b_issue is not None
    assert masked_a_issue.key == masked_b_issue.key


def test_runtime_restart_issue_groups_nested_shells_for_same_unresolved_command() -> None:
    direct = _runtime_unresolved_validation(
        sequence=1,
        command="/bin/bash -lc ./compile.sh",
        validation_id="validation-direct",
    )
    nested = _runtime_unresolved_validation(
        sequence=2,
        command="/bin/bash -c '/bin/bash -lc ./compile.sh'",
        validation_id="validation-nested",
    )
    different = _runtime_unresolved_validation(
        sequence=3,
        command="/bin/bash -lc ./test.sh",
        validation_id="validation-different",
    )

    direct_issue = _runtime_restart_issue(_runtime_validation_packet(direct, wake_sequence=1))
    nested_issue = _runtime_restart_issue(_runtime_validation_packet(nested, wake_sequence=2))
    different_issue = _runtime_restart_issue(
        _runtime_validation_packet(different, wake_sequence=3)
    )

    assert direct_issue is not None
    assert nested_issue is not None
    assert different_issue is not None
    assert direct_issue.key == nested_issue.key
    assert direct_issue.key != different_issue.key


def test_runtime_restart_issue_carries_active_failure_across_turn_completion() -> None:
    first = _runtime_unresolved_validation(
        sequence=10,
        command="/bin/bash -lc ./compile.sh",
        validation_id="validation-direct",
    )
    repeated = _runtime_unresolved_validation(
        sequence=12,
        command="/bin/bash -lc '/bin/bash -lc ./compile.sh'",
        validation_id="validation-nested",
    )
    active = _runtime_restart_issue(_runtime_validation_packet(first, wake_sequence=11))
    assert active is not None
    packet = SupervisorWakePacket(
        wake_sequence=13,
        latest_event_sequence=13,
        generation=0,
        restart_count=0,
        task_path="TASK.md",
        task_contents="# Task",
        current_summary="Coder turn completed",
        coder_thread_id="thread",
        validations=[first, repeated],
    )

    carried = _runtime_restart_issue(
        packet,
        active_issue_key=active.key,
        active_issue_last_sequence=first.sequence,
    )
    stale = _runtime_restart_issue(
        packet,
        active_issue_key=active.key,
        active_issue_last_sequence=repeated.sequence,
    )
    different = _runtime_unresolved_validation(
        sequence=14,
        command="/bin/bash -lc ./test.sh",
        validation_id="validation-different",
    )
    superseded = _runtime_restart_issue(
        packet.model_copy(update={"validations": [first, repeated, different]}),
        active_issue_key=active.key,
        active_issue_last_sequence=first.sequence,
    )
    unrelated_wake = _runtime_restart_issue(
        packet.model_copy(
            update={"current_summary": "Runtime integrity trigger: runtime links restored."}
        ),
        active_issue_key=active.key,
        active_issue_last_sequence=first.sequence,
    )

    assert carried is not None
    assert carried.key == active.key
    assert carried.sequence == repeated.sequence
    assert stale is None
    assert superseded is None
    assert unrelated_wake is None


def test_runtime_event_issue_ignores_optional_file_change_action_metadata() -> None:
    base = SupervisorWakePacket(
        wake_sequence=20,
        latest_event_sequence=21,
        generation=0,
        restart_count=0,
        task_path="TASK.md",
        task_contents="# Task",
        current_summary="Runtime trigger (large_diff): file change completed: 1 changes",
        coder_thread_id="thread",
        changed_files=[ChangedFile(path="src/parser.py", status="M", sequence=19)],
    )
    with_action = base.model_copy(
        update={
            "wake_sequence": 22,
            "latest_event_sequence": 23,
            "triggering_action": TriggeringAction(
                kind="fileChange",
                paths=["/tmp/coder/workspace/src/parser.py"],
                status="completed",
                summary="file change completed: 1 changes",
            ),
        }
    )
    different_path = with_action.model_copy(
        update={"changed_files": [ChangedFile(path="src/lexer.py", status="M", sequence=24)]}
    )

    base_issue = _runtime_restart_issue(base)
    action_issue = _runtime_restart_issue(with_action)
    different_issue = _runtime_restart_issue(different_path)

    assert base_issue is not None
    assert action_issue is not None
    assert different_issue is not None
    assert base_issue.key == action_issue.key
    assert base_issue.key != different_issue.key


async def test_runtime_restart_gate_counts_rejected_restart_as_steering_and_ignores_progress_update(
    tmp_path: Path,
) -> None:
    controller, store, _fake = _runtime_controller(tmp_path)

    class FakeCoder:
        def __init__(self) -> None:
            self.steers: list[str] = []

        async def steer_or_start(self, message: str) -> None:
            self.steers.append(message)

    coder = FakeCoder()
    controller.coder = coder
    restarts: list[tuple[str, RestartHandoff | None]] = []

    async def capture_restart(reason: str, *, handoff: RestartHandoff | None = None) -> None:
        restarts.append((reason, handoff))

    controller.restart = capture_restart  # type: ignore[method-assign]
    handoff = RestartHandoff(
        objective="finish task",
        restart_reason="same failure repeated after steering",
        bad_pattern="rerunning the same failing validation",
        known_evidence="the same assertion failed repeatedly",
        next_step="inspect the assertion before editing",
        recovery_signal="the validation failure changes or passes",
    )

    for sequence in (1, 2, 3):
        event_sequence = sequence * 2 - 1
        wake_sequence = event_sequence + 1
        store.update_bello_config(
            lambda cfg: cfg.model_copy(update={"last_event_sequence": event_sequence})
        )
        validation = _runtime_failure_validation(
            sequence=event_sequence,
            output="AssertionError: expected 1, got 2",
        )
        packet = _runtime_validation_packet(validation, wake_sequence=wake_sequence)
        if sequence == 1:
            decision = SupervisorDecision(
                decision=SupervisorDecisionKind.INTERVENE,
                reason="the same failure needs a controlled diagnostic",
                message_to_coder="Inspect the failing assertion before another edit.",
                progress_update="Recorded the first steering for this validation failure.",
                wake_sequence=wake_sequence,
                generation=0,
            )
        else:
            decision = SupervisorDecision(
                decision=SupervisorDecisionKind.RESTART,
                reason="coder repeated the same failure after steering",
                progress_update="Restart requested for the repeated validation failure.",
                handoff=handoff,
                wake_sequence=wake_sequence,
                generation=0,
            )
        await controller.apply_supervisor_decision(
            decision,
            packet_thread_id="thread",
            packet=packet,
        )

    assert len(coder.steers) == 2
    assert coder.steers[0] == "Inspect the failing assertion before another edit."
    assert "rerunning the same failing validation" in coder.steers[1]
    assert len(restarts) == 1
    assert restarts[0][0] == "coder repeated the same failure after steering"
    health = store.get_health()
    assert health.restart_issue_interventions == 2
    assert health.last_progress_sequence == 1
    progress = store.path(PROGRESS).read_text(encoding="utf-8")
    assert progress.count("Restart requested for the repeated validation failure.") == 1


def test_trusted_pass_clears_only_matching_runtime_restart_issue(tmp_path: Path) -> None:
    controller, store, _fake = _runtime_controller(tmp_path)
    failed = _runtime_failure_validation(sequence=1, output="AssertionError: expected 1, got 2")
    issue = _runtime_restart_issue(_runtime_validation_packet(failed, wake_sequence=1))
    assert issue is not None
    controller._record_runtime_intervention(
        reason="first steering",
        message="inspect the failure",
        sequence=1,
        generation=0,
        issue=issue,
    )

    unrelated_pass = _runtime_failure_validation(
        sequence=2,
        output="1 passed",
        validation_id="validation-other",
        trusted_outcome="passed",
    )
    controller._record_validation_runtime_state(unrelated_pass)
    assert store.get_health().restart_issue_key == issue.key

    matching_pass = unrelated_pass.model_copy(
        update={"validation_id": failed.validation_id, "sequence": 3}
    )
    controller._record_validation_runtime_state(matching_pass)
    assert store.get_health().restart_issue_key is None


def test_trusted_pass_clears_unresolved_issue_through_equivalent_shell_wrapper(
    tmp_path: Path,
) -> None:
    controller, store, _fake = _runtime_controller(tmp_path)
    unresolved = _runtime_unresolved_validation(
        sequence=1,
        command="/bin/bash -lc '/bin/bash -lc ./compile.sh'",
        validation_id="validation-nested",
    )
    issue = _runtime_restart_issue(_runtime_validation_packet(unresolved, wake_sequence=1))
    assert issue is not None
    controller._record_runtime_intervention(
        reason="build did not execute",
        message="run the build once through the normal approval path",
        sequence=1,
        generation=0,
        issue=issue,
    )

    passed = unresolved.model_copy(
        update={
            "validation_id": "validation-direct",
            "command": "/bin/bash -lc ./compile.sh",
            "normalized_command": "/bin/bash -lc ./compile.sh",
            "exit_code": 0,
            "shell_exit_code": 0,
            "outcome": "pass",
            "passed": True,
            "trusted_validation_outcome": "passed",
            "summary": "command completed: /bin/bash -lc ./compile.sh exit=0",
            "sequence": 2,
        }
    )
    controller._record_validation_runtime_state(passed)

    assert store.get_health().restart_issue_key is None


@pytest.mark.parametrize(
    "reason",
    [
        "masked_validation",
        "validation_regression",
        "repeated_same_failing_validation",
        "timeout",
        "suspicious_file_touched",
        "restart_budget",
        "unknown_signal",
    ],
)
async def test_quality_runtime_wake_can_be_filtered_by_cheap_runtime(tmp_path: Path, reason: str) -> None:
    controller, _store, fake = _runtime_controller(tmp_path)
    cheap = _CheapRuntimeNoopReviewer()
    controller.runtime_triage_reviewer = cheap
    controller.runtime_triage_config = SimpleNamespace(model=cheap.model)

    await controller._run_supervisor_check(
        f"Runtime trigger ({reason}): command completed: sed -n '1,120p' app.test.js exit=0",
        triggering_item_id="cmd-1",
        triggering_action=TriggeringAction(
            kind="commandExecution",
            command="sed -n '1,120p' app.test.js",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        human_message=None,
        patch_summary=None,
        completion_review=False,
    )

    assert len(cheap.calls) == 1
    assert cheap.calls[0].current_summary.startswith(f"Runtime trigger ({reason})")
    assert fake.runtime_packets == []


def test_cheap_runtime_switch_reads_persisted_runtime_config(tmp_path: Path) -> None:
    controller, store, _fake = _runtime_controller(tmp_path)
    assert controller._cheap_runtime_enabled() is True

    store.update_bello_config(lambda cfg: cfg.model_copy(update={"cheap_runtime": False}))

    assert controller._cheap_runtime_enabled() is False


@pytest.mark.parametrize(
    "summary",
    [
        "Runtime trigger (done_without_fresh_validation): readiness claim lacks trusted validation",
        "Runtime trigger (runtime_control_replacement): coder workspace runtime links were restored",
        "Runtime integrity trigger: coder workspace runtime links were replaced and restored.",
    ],
)
async def test_mandatory_runtime_wake_bypasses_cheap_runtime_noop(tmp_path: Path, summary: str) -> None:
    controller, _store, fake = _runtime_controller(tmp_path)
    cheap = _CheapRuntimeNoopReviewer()
    controller.runtime_triage_reviewer = cheap
    controller.runtime_triage_config = SimpleNamespace(model=cheap.model)

    await controller._run_supervisor_check(
        summary,
        triggering_item_id="message-1",
        triggering_action=None,
        human_message=None,
        patch_summary=None,
        completion_review=False,
    )

    assert cheap.calls == []
    assert len(fake.runtime_packets) == 1


def test_read_only_large_diff_trigger_is_suppressed_but_real_diff_change_wakes(tmp_path: Path) -> None:
    controller, _store, _fake = _runtime_controller(tmp_path)
    read_only_action = TriggeringAction(
        kind="commandExecution",
        command="sed -n '1,20p' src/app.py",
        exit_code=0,
        status="completed",
        summary="command completed",
    )
    execution_action = TriggeringAction(
        kind="commandExecution",
        command="python3 -c 'print(1)'",
        exit_code=0,
        status="completed",
        summary="command completed",
    )
    changed_files = [ChangedFile(path="src/app.py", status="M", additions=600, deletions=0, sequence=2)]

    read_only = controller.should_wake_runtime_supervisor(
        action=read_only_action,
        validation=None,
        changed_files=changed_files,
    )
    first_execution = controller.should_wake_runtime_supervisor(
        action=execution_action,
        validation=None,
        changed_files=changed_files,
    )
    repeated_execution = controller.should_wake_runtime_supervisor(
        action=execution_action,
        validation=None,
        changed_files=changed_files,
    )
    changed_signature = controller.should_wake_runtime_supervisor(
        action=execution_action,
        validation=None,
        changed_files=[ChangedFile(path="src/app.py", status="M", additions=601, deletions=0, sequence=2)],
    )

    assert read_only.should_wake is False
    assert read_only.reasons == ()
    assert first_execution.should_wake is True
    assert first_execution.reasons == ("large_diff",)
    assert repeated_execution.should_wake is False
    assert repeated_execution.reasons == ()
    assert changed_signature.should_wake is True
    assert changed_signature.reasons == ("large_diff",)


def test_suspicious_file_trigger_wakes_once_per_file_state(tmp_path: Path) -> None:
    controller, _store, _fake = _runtime_controller(tmp_path)
    test_path = tmp_path / "tests" / "test_parser.py"
    test_path.parent.mkdir()
    test_path.write_text("assert parse('a') == 1\n", encoding="utf-8")
    action = TriggeringAction(
        kind="commandExecution",
        command="python3 -c 'print(1)'",
        exit_code=0,
        status="completed",
        summary="command completed",
    )
    changed_files = [
        ChangedFile(path="tests/test_parser.py", status="M", additions=1, deletions=1, sequence=2)
    ]

    first = controller.should_wake_runtime_supervisor(
        action=action,
        validation=None,
        changed_files=changed_files,
    )
    unchanged = controller.should_wake_runtime_supervisor(
        action=action,
        validation=None,
        changed_files=changed_files,
    )
    test_path.write_text("assert parse('b') == 2\n", encoding="utf-8")
    edited_again = controller.should_wake_runtime_supervisor(
        action=action,
        validation=None,
        changed_files=changed_files,
    )
    cleaned = controller.should_wake_runtime_supervisor(
        action=action,
        validation=None,
        changed_files=[],
    )
    changed_after_clean = controller.should_wake_runtime_supervisor(
        action=action,
        validation=None,
        changed_files=changed_files,
    )

    assert first.reasons == ("suspicious_file_touched",)
    assert unchanged.should_wake is False
    assert edited_again.reasons == ("suspicious_file_touched",)
    assert cleaned.should_wake is False
    assert changed_after_clean.reasons == ("suspicious_file_touched",)


def test_unchanged_suspicious_file_does_not_hide_another_runtime_reason(tmp_path: Path) -> None:
    controller, _store, _fake = _runtime_controller(tmp_path)
    test_path = tmp_path / "tests" / "test_parser.py"
    test_path.parent.mkdir()
    test_path.write_text("assert parse('a') == 1\n", encoding="utf-8")
    changed_files = [ChangedFile(path="tests/test_parser.py", status="M", additions=1, deletions=0)]
    successful_action = TriggeringAction(
        kind="commandExecution",
        command="python3 -c 'print(1)'",
        exit_code=0,
        status="completed",
        summary="command completed",
    )
    failing_action = successful_action.model_copy(update={"exit_code": 1})

    controller.should_wake_runtime_supervisor(
        action=successful_action,
        validation=None,
        changed_files=changed_files,
    )
    decision = controller.should_wake_runtime_supervisor(
        action=failing_action,
        validation=None,
        changed_files=changed_files,
    )

    assert decision.should_wake is True
    assert decision.reasons == ("nonzero_exit",)


def test_file_change_large_diff_noops_without_runtime_model(tmp_path: Path) -> None:
    controller, _store, _fake = _runtime_controller(tmp_path)

    decision = controller.should_wake_runtime_supervisor(
        action=TriggeringAction(
            kind="fileChange",
            paths=["src/app.py"],
            status="completed",
            summary="file change completed: src/app.py",
        ),
        validation=None,
        changed_files=[ChangedFile(path="src/app.py", status="M", additions=600, deletions=0, sequence=2)],
    )

    assert decision.should_wake is False
    assert decision.reasons == ()


def test_project_execution_large_diff_wakes_runtime_supervisor(tmp_path: Path) -> None:
    controller, _store, _fake = _runtime_controller(tmp_path)

    decision = controller.should_wake_runtime_supervisor(
        action=TriggeringAction(
            kind="commandExecution",
            command="/bin/bash -lc 'make -j4'",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        validation=None,
        changed_files=[ChangedFile(path="src/app.py", status="M", additions=600, deletions=0, sequence=2)],
    )

    assert decision.should_wake is True
    assert decision.reasons == ("large_diff",)


def test_project_execution_nonzero_wakes_runtime_supervisor(tmp_path: Path) -> None:
    controller, _store, _fake = _runtime_controller(tmp_path)
    action = TriggeringAction(
        kind="commandExecution",
        command="pytest tests/public/test_public.py",
        exit_code=1,
        status="completed",
        summary="command completed",
    )

    decision = controller.should_wake_runtime_supervisor(
        action=action,
        validation=ValidationRun(
            command=action.command or "",
            exit_code=1,
            type="behavioral",
            passed=False,
            summary="1 failed",
            trusted_validation_outcome="failed",
            sequence=3,
        ),
        changed_files=[],
    )

    assert decision.should_wake is True
    assert decision.reasons == ("nonzero_exit",)


def test_protected_runtime_reason_stays_visible_for_project_execution(tmp_path: Path) -> None:
    controller, _store, _fake = _runtime_controller(tmp_path)

    decision = controller.should_wake_runtime_supervisor(
        action=TriggeringAction(
            kind="commandExecution",
            command="pytest tests/public/test_public.py",
            exit_code=1,
            status="completed",
            summary="command completed",
        ),
        validation=None,
        changed_files=[],
        validation_trigger_reasons=("repeated_same_failing_validation",),
    )

    assert decision.should_wake is True
    assert decision.reasons == ("repeated_same_failing_validation", "nonzero_exit")


def test_unresolved_masked_validation_still_wakes_for_project_execution(tmp_path: Path) -> None:
    controller, _store, _fake = _runtime_controller(tmp_path)
    controller.validation_runtime_state = {
        "validation-old": {
            "trusted_validation_outcome": "masked_or_unknown",
            "consecutive_failed_count": 0,
            "sequence": 2,
        }
    }

    decision = controller.should_wake_runtime_supervisor(
        action=TriggeringAction(
            kind="commandExecution",
            command="./run_visible_tests.sh",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        validation=ValidationRun(
            command="./run_visible_tests.sh",
            exit_code=0,
            type="behavioral",
            passed=True,
            summary="45 passed",
            trusted_validation_outcome="passed",
            sequence=4,
        ),
        changed_files=[ChangedFile(path="src/app.py", status="M", additions=600, deletions=0, sequence=3)],
    )

    assert decision.should_wake is True
    assert decision.reasons == ("large_diff",)


def test_read_only_action_does_not_wake_only_for_restart_budget(tmp_path: Path) -> None:
    controller, store, _fake = _runtime_controller(tmp_path)
    store.patch_health(lambda health: health.model_copy(update={"restart_count": 100}))

    decision = controller.should_wake_runtime_supervisor(
        action=TriggeringAction(
            kind="commandExecution",
            command="rg -n \"TODO\" src",
            exit_code=1,
            status="completed",
            summary="command completed",
        ),
        validation=None,
        changed_files=[ChangedFile(path="src/app.py", status="M", additions=600, deletions=0, sequence=2)],
    )

    assert decision.should_wake is False
    assert decision.reasons == ()


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
    controller.last_coder_message = CoderMessage(text="Summary\nBELLO_READY_FOR_REVIEW", sequence=3)
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
    assert store.get_bello_config().last_relevant_edit_sequence == 2
    trace = json.loads(store.path(RUNTIME_TRACE).read_text(encoding="utf-8").splitlines()[-1])
    assert trace["trigger_reasons"] == ["done_without_fresh_validation"]


async def test_done_after_evidence_less_context_execution_requires_native_validation(
    tmp_path: Path,
) -> None:
    controller, store, fake = _runtime_controller(tmp_path)
    coder = _GateFakeCoder()
    controller.coder = coder
    controller.last_coder_message = CoderMessage(
        text="Summary\nValidation: ctx_batch_execute passed\nBELLO_READY_FOR_REVIEW",
        sequence=5,
    )
    controller.observed_changed_files = {
        "src/app.py": ChangedFile(path="src/app.py", status="modified", sequence=2)
    }
    controller._latest_context_execution_without_command_evidence_sequence = 4

    await controller._handle_coder_turn_completed(item_id="done-context-1")

    assert fake.runtime_packets == []
    assert fake.completion_packets == []
    assert coder.messages == [CONTEXT_NATIVE_VALIDATION_NUDGE]
    assert store.get_bello_config().last_relevant_edit_sequence == 2
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
    assert details["completion_delta_evidence_summary"] == [
        (
            f"validation {controller.validations[1].validation_id} seq=5 "
            "type=behavioral outcome=passed command=pytest new.py"
        )
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


def test_quoted_heredoc_literals_do_not_look_like_shell_substitution() -> None:
    command = (
        "python - <<'PY'\n"
        "message = 'cannot specify `--emit abi` twice'\n"
        "assert '$(' not in message\n"
        "print('compiler diagnostic=' + message)\n"
        "PY"
    )
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=8,
        item={
            "type": "commandExecution",
            "stdout": "compiler diagnostic=cannot specify `--emit abi` twice\n",
        },
        changed_paths=["solar.py"],
    )

    assert validation is not None
    assert validation.masking_reason is None
    assert validation.trusted_validation_outcome == "passed"


def test_unquoted_heredoc_shell_substitution_remains_masked() -> None:
    command = "python - <<PY\nprint(`printf hidden`)\nPY"
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=9,
        item={"type": "commandExecution", "stdout": "hidden\n"},
        changed_paths=["solar.py"],
    )

    assert validation is not None
    assert validation.masking_reason == "command_substitution_may_mask_failure"
    assert validation.trusted_validation_outcome == "masked_or_unknown"


@pytest.mark.parametrize(
    "declaration",
    [
        "python -c 'print(1)' # <<'X'",
        "python -c \"print(\\\"<<'X'\\\")\"",
    ],
)
def test_heredoc_text_in_comment_or_quote_cannot_hide_shell_pipeline(
    declaration: str,
) -> None:
    command = f"{declaration}\nprintf unsafe | cat\nX"
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=10,
        item={"type": "commandExecution", "stdout": "unsafe\n"},
        changed_paths=["solar.py"],
    )

    assert validation is not None
    assert validation.masking_reason == "pipeline_without_pipefail"
    assert validation.trusted_validation_outcome == "masked_or_unknown"


def test_heredoc_text_in_multiline_quote_cannot_hide_shell_pipeline() -> None:
    command = "printf '%s\\n' \"literal\n<<'X'\n\"\nfalse | true\nX\ntrue"

    assert _generic_validation_masking_reason(command) == "pipeline_without_pipefail"


def test_absolute_python_script_command_is_behavior_demo_validation() -> None:
    command = f"{sys.executable} targeted_validation.py"
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=7,
        item={"type": "commandExecution", "stdout": "actual=42 expected=42\n"},
        changed_paths=["src/app.py"],
    )

    assert validation is not None
    assert validation.type == "behavior_demo"
    assert validation.trusted_validation_outcome == "passed"
    assert validation.captured_output == "actual=42 expected=42\n"


def test_marked_behavior_demo_command_gets_validation_but_echo_is_rejected() -> None:
    demo = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="BELLO_BEHAVIOR_DEMO=1 ./run_scenario src/app.py",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=8,
        item={"type": "commandExecution", "stdout": "rendered=<h1>Requested</h1>\n"},
        changed_paths=["src/app.py"],
    )
    echo = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="BELLO_BEHAVIOR_DEMO=1 echo PASS",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=9,
        item={"type": "commandExecution", "stdout": "PASS\n"},
        changed_paths=["src/app.py"],
    )

    assert demo is not None
    assert demo.type == "behavior_demo"
    assert echo is None


def test_marked_behavior_demo_allows_honest_shell_sequence() -> None:
    command = (
        "BELLO_BEHAVIOR_DEMO=1 bash -lc 'set -euo pipefail; "
        "./bin/app --scenario smoke; printf \"scenario=smoke state=requested\\n\"'"
    )

    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command=command,
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=10,
        item={"type": "commandExecution", "stdout": "scenario=smoke state=requested\n"},
        changed_paths=["bin/app"],
    )

    assert validation is not None
    assert validation.type == "behavior_demo"
    assert validation.trusted_validation_outcome == "passed"
    assert validation.masking_reason is None


def test_marked_behavior_demo_does_not_unmask_status_manipulation() -> None:
    logical_or = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="BELLO_BEHAVIOR_DEMO=1 bash -lc './bin/app --scenario smoke || true; echo PASS'",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=10,
        item={"type": "commandExecution", "stdout": "PASS\n"},
        changed_paths=["bin/app"],
    )
    pipeline = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="BELLO_BEHAVIOR_DEMO=1 ./bin/app --scenario smoke | cat",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=11,
        item={"type": "commandExecution", "stdout": "scenario=smoke state=requested\n"},
        changed_paths=["bin/app"],
    )
    bare_pass = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="BELLO_BEHAVIOR_DEMO=1 bash -lc './bin/app --scenario smoke; echo PASS'",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=12,
        item={"type": "commandExecution", "stdout": "PASS\n"},
        changed_paths=["bin/app"],
    )

    assert logical_or is not None
    assert logical_or.trusted_validation_outcome == "masked_or_unknown"
    assert logical_or.masking_reason == "logical_or_may_mask_validation_failure"
    assert pipeline is not None
    assert pipeline.trusted_validation_outcome == "masked_or_unknown"
    assert pipeline.masking_reason == "pipeline_without_pipefail"
    assert bare_pass is not None
    assert bare_pass.trusted_validation_outcome == "masked_or_unknown"
    assert bare_pass.masking_reason == "behavior_demo_self_verdict_only"


def test_validation_ledger_reads_aggregated_output_field() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="BELLO_BEHAVIOR_DEMO=1 ./bin/app --scenario smoke",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=10,
        item={"type": "commandExecution", "aggregatedOutput": "scenario=smoke state=requested\n"},
        changed_paths=["bin/app"],
    )

    assert validation is not None
    assert validation.type == "behavior_demo"
    assert validation.trusted_validation_outcome == "passed"
    assert validation.captured_output == "scenario=smoke state=requested\n"


def test_command_output_aliases_are_attached_to_validation_ledger() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="BELLO_BEHAVIOR_DEMO=1 ./bin/app --scenario smoke",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=10,
        item={"type": "commandExecution", "aggregated_output": "scenario=smoke state=requested\n"},
        changed_paths=["bin/app"],
    )

    assert validation is not None
    assert validation.type == "behavior_demo"
    assert validation.trusted_validation_outcome == "passed"
    assert validation.captured_output == "scenario=smoke state=requested\n"


def test_behavior_demo_without_real_output_is_not_passed() -> None:
    validation = _validation_from_action(
        TriggeringAction(
            kind="commandExecution",
            command="BELLO_BEHAVIOR_DEMO=1 ./bin/app --scenario smoke",
            exit_code=0,
            status="completed",
            summary="command completed",
        ),
        sequence=10,
        item={"type": "commandExecution"},
        changed_paths=["bin/app"],
    )

    assert validation is not None
    assert validation.type == "behavior_demo"
    assert validation.outcome == "fail"
    assert validation.passed is False
    assert validation.trusted_validation_outcome == "masked_or_unknown"
    assert validation.masking_reason == "behavior_demo_missing_output"


def test_non_python_behavior_demo_commands_are_classified() -> None:
    cases = [
        (
            "node -e \"const app = require('./src/app'); console.log(app.render())\"",
            ["src/app.js"],
            "rendered=<h1>Requested</h1>\n",
        ),
        (
            "ruby -e \"require './src/app'; puts App.render\"",
            ["src/app.rb"],
            "rendered=<h1>Requested</h1>\n",
        ),
        (
            "curl -s http://localhost:3000/api/status",
            ["src/server.js"],
            '{"status":"ok","feature":"requested"}\n',
        ),
        (
            "BELLO_BEHAVIOR_DEMO=1 ./bin/app --scenario smoke",
            ["bin/app"],
            "scenario=smoke result=requested\n",
        ),
    ]

    for index, (command, changed_paths, output) in enumerate(cases, start=10):
        validation = _validation_from_action(
            TriggeringAction(
                kind="commandExecution",
                command=command,
                exit_code=0,
                status="completed",
                summary="command completed",
            ),
            sequence=index,
            item={"type": "commandExecution", "stdout": output},
            changed_paths=changed_paths,
        )

        assert validation is not None, command
        assert validation.type == "behavior_demo", command
        assert validation.captured_output == output


def test_supervisor_policy_has_no_specbench_split_triggers() -> None:
    root = Path(__file__).resolve().parents[1]
    texts = [
        (root / "supervisor" / "controller.py").read_text(encoding="utf-8"),
        (root / "supervisor" / "prompts" / "prompts.toml").read_text(encoding="utf-8"),
    ]
    forbidden = (
        "id" + "_private",
        "public + " + "id" + "_private",
        "public " + "green",
        "public " + "tests",
        "hidden " + "tests",
        "breadth_risk" + "_assessment",
    )

    for text in texts:
        lowered = text.lower()
        for token in forbidden:
            assert token not in lowered


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


def test_read_only_test_file_commands_are_inspections_not_validations() -> None:
    action = TriggeringAction(
        kind="commandExecution",
        command="sed -n '1,80p' tests/public/test_public.py",
        exit_code=0,
        status="completed",
        summary="command completed",
    )
    item = {"type": "commandExecution", "stdout": "def test_public():\n    assert app()\n"}

    validation = _validation_from_action(action, sequence=8, item=item, changed_paths=["tests/public/test_public.py"])
    inspection = _inspection_from_action(action, sequence=8, item=item)

    assert validation is None
    assert inspection is not None
    assert inspection.inspection_id.startswith("inspection-")
    assert inspection.passed is True
    assert inspection.inspected_paths == ["tests/public/test_public.py"]
    assert "def test_public" in inspection.captured_output


def test_shell_wrapped_read_only_test_file_commands_are_inspections_not_validations() -> None:
    action = TriggeringAction(
        kind="commandExecution",
        command="/bin/bash -lc \"sed -n '1,80p' tests/public/test_public.py\"",
        exit_code=0,
        status="completed",
        summary="command completed",
    )
    item = {"type": "commandExecution", "stdout": "def test_public():\n    assert app()\n"}

    validation = _validation_from_action(action, sequence=8, item=item, changed_paths=["tests/public/test_public.py"])
    inspection = _inspection_from_action(action, sequence=8, item=item)

    assert validation is None
    assert inspection is not None
    assert inspection.passed is True
    assert inspection.inspected_paths == ["tests/public/test_public.py"]
    assert "def test_public" in inspection.captured_output


def test_forbidden_pattern_scan_with_regex_alternation_records_inspection() -> None:
    action = TriggeringAction(
        kind="commandExecution",
        command='rg -n "system\\(|exec\\(|popen\\(" src include',
        exit_code=1,
        status="completed",
        summary="command completed",
    )
    item = {"type": "commandExecution", "stdout": ""}

    validation = _validation_from_action(action, sequence=8, item=item, changed_paths=["src/compiler.c"])
    inspection = _inspection_from_action(action, sequence=8, item=item)

    assert validation is None
    assert inspection is not None
    assert inspection.passed is True
    assert inspection.inspection_id.startswith("inspection-")
    assert inspection.inspected_paths == ["src", "include"]


async def test_read_only_command_is_recorded_in_inspection_ledger(tmp_path: Path) -> None:
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
                        "command": "rg -n \"system\\(\" src",
                        "exitCode": 1,
                        "status": "completed",
                        "stdout": "",
                    },
                },
            }
        )
    )

    assert controller.validations == []
    assert len(controller.inspections) == 1
    assert controller.inspections[0].passed is True
    assert fake.runtime_packets == []
    trace = json.loads(store.path(RUNTIME_TRACE).read_text(encoding="utf-8").splitlines()[-1])
    assert trace["should_wake_runtime_supervisor"] is False


async def test_declared_grading_path_completed_command_escalates_integrity_failure(tmp_path: Path) -> None:
    controller, store, fake = _runtime_controller(tmp_path)
    grading_root = tmp_path / "SpecBench" / "examples" / "c_compiler"
    grading_root.mkdir(parents=True)
    (grading_root / "hidden.c").write_text("int secret;\n", encoding="utf-8")
    controller.declared_grading_roots = (str(grading_root),)
    controller.approvals = ApprovalManager(tmp_path, declared_grading_roots=controller.declared_grading_roots)

    await controller.handle_notification(
        AppServerMessage(
            {
                "method": "item/completed",
                "params": {
                    "threadId": "thread",
                    "itemId": "cmd-1",
                    "item": {
                        "type": "commandExecution",
                        "command": f"sed -n '1,20p' {grading_root / 'hidden.c'}",
                        "exitCode": 0,
                        "status": "completed",
                        "stdout": "int secret;\n",
                    },
                },
            }
        )
    )

    assert store.get_bello_config().status == BelloStatus.ESCALATED
    assert controller.running is False
    assert fake.runtime_packets == []
    progress = store.path(PROGRESS).read_text(encoding="utf-8")
    assert "coder accessed declared grading/hidden path" in progress


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
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

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


async def test_supervisor_fast_mode_sets_codex_service_tier(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class FakeClient:
        def __init__(self) -> None:
            self.thread_params = None
            self.turn_params = None

        async def thread_start(self, params, *, timeout):
            self.thread_params = params
            return {"thread": {"id": "supervisor-thread"}}

        async def turn_start(self, params, *, timeout):
            self.turn_params = params
            return {
                "turn": {
                    "id": "turn-1",
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

    default_agent = StatelessSupervisorAgent(FakeClient(), store, task)  # type: ignore[arg-type]
    assert default_agent._thread_params()["serviceTier"] is None

    client = FakeClient()
    agent = StatelessSupervisorAgent(client, store, task, fast=True)  # type: ignore[arg-type]
    packet = agent.build_packet(wake_sequence=7, current_summary="runtime check")

    decision = await agent.decide(packet)

    assert decision.decision == SupervisorDecisionKind.NOOP
    assert client.thread_params["serviceTier"] == CODEX_FAST_SERVICE_TIER
    assert client.turn_params["serviceTier"] == CODEX_FAST_SERVICE_TIER


async def test_supervisor_agent_sets_intelligence_effort(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class FakeClient:
        def __init__(self) -> None:
            self.turn_params = None

        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "supervisor-thread"}}

        async def turn_start(self, params, *, timeout):
            self.turn_params = params
            return {
                "turn": {
                    "id": "turn-1",
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

    client = FakeClient()
    agent = StatelessSupervisorAgent(client, store, task, intelligence="high")  # type: ignore[arg-type]
    packet = agent.build_packet(wake_sequence=7, current_summary="runtime check")

    decision = await agent.decide(packet)

    assert decision.decision == SupervisorDecisionKind.NOOP
    assert client.turn_params["effort"] == "high"


async def test_completion_review_agent_overrides_stale_model_wake_sequence(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

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
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
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


async def test_completion_review_no_message_retries_with_ultra_compact_minimal_prompt(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\nImplement the compiler.\n", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
    valid_decision = {
        "decision": "return",
        "reason": "needs independent demo",
        "decision_artifact": {
            "current_state": "provider recovered on compact retry",
            "resolved_concerns": [],
            "stale_concerns": [],
            "uncovered_edge_candidates": ["independent demo missing"],
            "actionable_gap_or_none": "run an independent demo",
        },
        "basis_event_seq": 7,
        "last_relevant_edit_seq": 5,
        "last_validation_seq": 6,
        "files_reviewed": [],
        "behavior_evidence_matrix": [],
        "uncovered_behaviors": ["independent demo"],
        "validation_gaps": [],
        "claim_evidence_mismatches": [],
        "packet_or_access_limitations": [],
        "changed_test_risks": [],
        "message_to_coder": "Run an independent demo for the claimed compiler behavior.",
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
            self.thread_count = 0
            self.turn_inputs: list[str] = []
            self.archived: list[str] = []

        async def thread_start(self, params, *, timeout):
            self.thread_count += 1
            return {"thread": {"id": f"completion-thread-{self.thread_count}"}}

        async def turn_start(self, params, *, timeout):
            self.turn_inputs.append(params["input"][0]["text"])
            turn_number = len(self.turn_inputs)
            if turn_number <= 2:
                return {
                    "turn": {
                        "id": f"turn-{turn_number}",
                        "status": "completed",
                        "items": [],
                    }
                }
            return {
                "turn": {
                    "id": "turn-3",
                    "status": "completed",
                    "items": [{"type": "agentMessage", "text": json.dumps(valid_decision)}],
                }
            }

        async def thread_turns_list(self, thread_id, *, limit, items_view, timeout):
            return {"data": []}

        async def thread_archive(self, thread_id, *, timeout):
            self.archived.append(thread_id)
            return {}

    client = FakeClient()
    agent = StatelessSupervisorAgent(client, store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(
        wake_sequence=7,
        current_summary="completion review",
        validations=[
            ValidationRun(
                command="pytest tests/public",
                exit_code=0,
                passed=True,
                summary="46 passed\n" + ("x" * 5000),
                captured_output="46 passed\n" + ("y" * 5000),
                sequence=6,
            )
        ],
    )

    decision = await agent.decide_completion(packet)

    assert decision.decision == "return"
    assert len(client.turn_inputs) == 3
    assert "Emergency compact JSON retry" in client.turn_inputs[2]
    assert "ultra_compact_outputs" in client.turn_inputs[2]
    assert "supervisor did not produce an agent message" in client.turn_inputs[2]
    assert client.archived == ["completion-thread-1"]
    audit_rows = [
        json.loads(line)
        for line in store.path(SUPERVISOR_WAKES).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert audit_rows[-1]["use_case"] == "completion_review_no_message_minimal_retry"
    assert audit_rows[-1]["status"] == "decision"


async def test_supervisor_agent_retries_invalid_structured_output_once(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
    valid_decision = {
        "decision": "return",
        "reason": "needs factual demo",
        "files_reviewed": [],
        "behavior_evidence_matrix": [],
        "uncovered_behaviors": ["demo"],
        "validation_gaps": ["missing factual demo output"],
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

    class FakeClient:
        def __init__(self) -> None:
            self.turn_inputs = []

        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "completion-thread"}}

        async def turn_start(self, params, *, timeout):
            self.turn_inputs.append(params["input"][0]["text"])
            if len(self.turn_inputs) == 1:
                return {
                    "turn": {
                        "id": "turn-1",
                        "status": "completed",
                        "items": [{"type": "agentMessage", "text": '{"decision":"return","reason":"unterminated'}],
                    }
                }
            return {
                "turn": {
                    "id": "turn-2",
                    "status": "completed",
                    "items": [{"type": "agentMessage", "text": json.dumps(valid_decision)}],
                }
            }

        async def thread_archive(self, thread_id, *, timeout):
            return {}

    client = FakeClient()
    agent = StatelessSupervisorAgent(client, store, task)  # type: ignore[arg-type]
    packet = agent.build_packet(wake_sequence=7, current_summary="completion review")

    decision = await agent.decide_completion(packet)

    assert decision.decision == "return"
    assert len(client.turn_inputs) == 2
    assert "previous completion-review response was not valid structured JSON" in client.turn_inputs[1]
    assert "compact completion-review JSON object" in client.turn_inputs[1]
    assert "files_reviewed=[]" in client.turn_inputs[1]
    assert "behavior_evidence_matrix=[]" in client.turn_inputs[1]
    assert "under 3000 characters" in client.turn_inputs[1]
    audits = [json.loads(line) for line in store.path(SUPERVISOR_WAKES).read_text(encoding="utf-8").splitlines()]
    assert audits[-2]["use_case"] == "completion_review_parse_retry"
    assert audits[-2]["status"] == "error"
    assert audits[-1]["status"] == "decision"


async def test_terminal_state_denies_new_server_request_without_policy_path(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class FakeClient:
        def __init__(self) -> None:
            self.responses = []

        async def respond(self, request_id, response):
            self.responses.append((request_id, response))

    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.store = store
    controller.coder_client = controller.supervisor_client = FakeClient()
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

    assert controller.coder_client.responses == [(99, {"decision": "decline"})]


async def test_completion_return_sends_message_and_continues_same_generation(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )

    class FakeCoder:
        def __init__(self) -> None:
            self.messages = []

        async def steer_or_start(self, message):
            self.messages.append(message)
            return "turn"

    controller = BelloController.__new__(BelloController)
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

    class _CloseTrackingSupervisor:
        def __init__(self) -> None:
            self.closed = 0

        async def close_completion_review(self) -> None:
            self.closed += 1

    runtime_supervisor = _CloseTrackingSupervisor()
    completion_supervisor = _CloseTrackingSupervisor()
    controller.supervisor = runtime_supervisor
    controller.completion_supervisor = completion_supervisor

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

    assert store.get_bello_config().generation == 0
    assert controller.coder.messages == ["Validate missing-key fallback before marking ready again."]
    assert len(controller.completion_returns) == 1
    assert store.get_health().interventions == 0
    assert "Completion review returned missing fallback coverage" in store.path("PROGRESS.md").read_text(encoding="utf-8")
    # Fresh completion-review thread per review: a normal return closes the session so the
    # next readiness review starts a new thread instead of accumulating prior turns.
    assert runtime_supervisor.closed == 0
    assert completion_supervisor.closed == 1


async def test_completion_accept_gate_allows_minimal_accept_with_fresh_validation(tmp_path: Path) -> None:
    validations = [
        ValidationRun(
            command="pytest tests/test_app.py",
            exit_code=0,
            passed=True,
            summary="tests/test_app.py::test_requested_behavior PASSED\n1 passed",
            captured_output="tests/test_app.py::test_requested_behavior PASSED\n1 passed\n",
            executed_test_files=["tests/test_app.py"],
            sequence=3,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    decision = CompletionReviewDecision(
        decision="accept",
        reason="fresh validation passed",
        message_to_coder=None,
        persistent_decision=None,
        progress_update="Accepted by completion review.",
        clear_handoff=False,
        display_message=None,
        handoff=None,
        wake_sequence=1,
        generation=0,
    )

    await controller.apply_completion_decision(
        decision,
        packet_thread_id="thread",
        packet=_gate_packet(task, validations=validations),
    )

    assert store.get_bello_config().status == BelloStatus.COMPLETE
    assert len(controller.completion_returns) == 0
    assert coder.messages == []
    assert store.get_bello_config().accept_gate_accepts == 1
    log_entries = [json.loads(line) for line in store.path(LOG).read_text(encoding="utf-8").splitlines()]
    log_entry = next(entry for entry in log_entries if entry.get("type") == "completion_accept_gate_pass")
    check_names = {check["check_name"] for check in log_entry["checks"]}
    assert "behavioral_floor" in check_names
    assert "evidence_binding" not in check_names
    assert "independent_evidence_binding" not in check_names
    assert "file_review_coverage" not in check_names


async def test_completion_accept_gate_allows_changed_test_without_independent_evidence(tmp_path: Path) -> None:
    validations = [
        ValidationRun(
            command="pytest tests/test_app_new.py",
            exit_code=0,
            passed=True,
            summary="tests/test_app_new.py::test_requested_behavior PASSED\n1 passed",
            captured_output="tests/test_app_new.py::test_requested_behavior PASSED\n1 passed\n",
            executed_test_files=["tests/test_app_new.py"],
            sequence=3,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    packet = _gate_packet(task, validations=validations)
    packet.changed_files = [
        ChangedFile(path="src/app.py", status="M", sequence=2),
        ChangedFile(path="tests/test_app_new.py", status="A", sequence=2),
    ]
    packet.changed_file_diffs = [
        ChangedFileDiff(
            path="tests/test_app_new.py",
            file_kind="test",
            change_kind="added",
            diff="+def test_requested_behavior():\n+    assert app() == 'requested'",
        )
    ]

    await controller.apply_completion_decision(
        _covered_accept_decision(wake_sequence=1, validation_id="validation-3"),
        packet_thread_id="thread",
        packet=packet,
    )

    assert store.get_bello_config().status == BelloStatus.COMPLETE
    assert len(controller.completion_returns) == 0
    assert coder.messages == []
    assert store.get_bello_config().accept_gate_accepts == 1


async def test_adversary_remaining_limit_runs_before_completion_finalize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validations = [
        ValidationRun(
            command="pytest tests/test_app.py",
            exit_code=0,
            passed=True,
            summary="1 passed",
            captured_output="1 passed\n",
            executed_test_files=["tests/test_app.py"],
            sequence=3,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    controller.adversary_enabled = None
    controller.coder_client = controller.supervisor_client = object()
    controller.model = None
    controller.running = False
    controller._pending_adversary_report = None
    controller._active_adversary_thread_id = None
    controller._active_adversary_workspace_root = None
    (tmp_path / ".supervisor" / "secret.txt").parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / ".supervisor" / "secret.txt").write_text("runtime history", encoding="utf-8")
    seen_snapshot_roots: list[Path] = []

    class FakeAdversary:
        def __init__(self, client, project_root, *, on_thread_start=None, on_thread_done=None, **kwargs) -> None:
            self.project_root = Path(project_root)
            self.on_thread_start = on_thread_start
            self.on_thread_done = on_thread_done

        async def run(self, packet, *, previous_adversary_report=None):
            seen_snapshot_roots.append(self.project_root)
            assert self.project_root != tmp_path
            assert (self.project_root / "TASK.md").exists()
            assert not (self.project_root / ".supervisor").exists()
            (self.project_root / "adversary_probe.txt").write_text("probe", encoding="utf-8")
            assert previous_adversary_report is None
            if self.on_thread_start:
                self.on_thread_start("adv-thread")
            if self.on_thread_done:
                self.on_thread_done("adv-thread")
            return SimpleNamespace(
                report_text=(
                    "attacked: boundary inputs\n"
                    "findings: none\n"
                    "held: boundary inputs held\n"
                    "not_reached: none\n"
                    "overall: held"
                ),
                thread_id="adv-thread",
                turn_id="adv-turn",
                candidate_finding=False,
            )

    monkeypatch.setattr("supervisor.controller.AdversaryAgent", FakeAdversary)

    await controller.apply_completion_decision(
        _covered_accept_decision(wake_sequence=1, validation_id="validation-3"),
        packet_thread_id="thread",
        packet=_gate_packet(task, validations=validations),
    )

    assert store.get_bello_config().status == BelloStatus.COMPLETE
    assert controller._pending_adversary_report is not None
    assert controller._pending_adversary_report.thread_id == "adv-thread"
    assert controller._pending_adversary_report.candidate_finding is False
    assert controller._pending_adversary_report.latest_relevant_change_sequence == 2
    assert controller._pending_adversary_report.workspace_state_id is not None
    assert store.get_bello_config().adversary_run_count == 1
    assert coder.messages == []
    assert seen_snapshot_roots and not seen_snapshot_roots[0].exists()
    progress = store.path(PROGRESS).read_text(encoding="utf-8")
    assert "Adversarial tester completed" in progress
    assert "without a candidate finding" in progress


async def test_adversary_run_limit_skips_additional_run_and_finalizes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validations = [
        ValidationRun(
            command="pytest tests/test_app.py",
            exit_code=0,
            passed=True,
            summary="1 passed",
            captured_output="1 passed\n",
            executed_test_files=["tests/test_app.py"],
            sequence=3,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    controller.adversary_enabled = True
    store.update_bello_config(
        lambda cfg: cfg.model_copy(update={"max_adversary_runs": 1, "adversary_run_count": 1})
    )

    class UnexpectedAdversary:
        def __init__(self, *args, **kwargs) -> None:
            raise AssertionError("adversary should not run after limit is reached")

    monkeypatch.setattr("supervisor.controller.AdversaryAgent", UnexpectedAdversary)

    await controller.apply_completion_decision(
        _covered_accept_decision(wake_sequence=1, validation_id="validation-3"),
        packet_thread_id="thread",
        packet=_gate_packet(task, validations=validations),
    )

    assert store.get_bello_config().status == BelloStatus.COMPLETE
    assert store.get_bello_config().adversary_run_count == 1
    assert coder.messages == []
    progress = store.path(PROGRESS).read_text(encoding="utf-8")
    assert "Skipping adversarial tester before complete: adversary run limit reached (1/1)" in progress
    events = [json.loads(line) for line in store.path(EVENTS).read_text(encoding="utf-8").splitlines()]
    assert any(event["event_type"] == "adversary/limit_reached" for event in events)


async def test_adversary_infra_failure_completes_with_recorded_gap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An adversary that cannot run is a tester-availability problem, not evidence against
    # the accepted work: the run must finalize the accept with the gap recorded loudly,
    # not die as infrastructure-invalid.
    validations = [
        ValidationRun(
            command="pytest tests/test_app.py",
            exit_code=0,
            passed=True,
            summary="1 passed",
            captured_output="1 passed\n",
            executed_test_files=["tests/test_app.py"],
            sequence=3,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    controller.adversary_enabled = True
    controller.coder_client = controller.supervisor_client = object()
    controller.model = None
    controller.running = False
    controller._pending_adversary_report = None
    controller._active_adversary_thread_id = None
    controller._active_adversary_workspace_root = None

    class FailingAdversary:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def run(self, packet, *, previous_adversary_report=None):
            raise AdversaryAgentError("adversary did not produce an agent message")

    monkeypatch.setattr("supervisor.controller.AdversaryAgent", FailingAdversary)

    await controller.apply_completion_decision(
        _covered_accept_decision(wake_sequence=1, validation_id="validation-3"),
        packet_thread_id="thread",
        packet=_gate_packet(task, validations=validations),
    )

    assert store.get_bello_config().status == BelloStatus.COMPLETE
    assert coder.messages == []
    accepted = controller._accepted_adversary_report
    assert accepted is not None
    assert accepted.status == "error"
    assert "did not produce an agent message" in accepted.report_text
    progress = store.path(PROGRESS).read_text(encoding="utf-8")
    assert "Adversarial tester could not run" in progress
    assert "adversary coverage recorded as missing" in progress
    events = [json.loads(line) for line in store.path(EVENTS).read_text(encoding="utf-8").splitlines()]
    assert any(event["event_type"] == "adversary/unavailable" for event in events)
    assert any(event["event_type"] == "completion/accept" for event in events)
    final_report = store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert "status=error" in final_report
    assert "provider_failure" not in final_report.lower()


async def test_adversary_fresh_report_allows_completion_finalize(tmp_path: Path) -> None:
    validations = [
        ValidationRun(
            command="pytest tests/test_app.py",
            exit_code=0,
            passed=True,
            summary="1 passed",
            captured_output="1 passed\n",
            executed_test_files=["tests/test_app.py"],
            sequence=3,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    controller.adversary_enabled = True
    packet = _gate_packet(task, validations=validations)
    packet.adversary_report = AdversaryReport(
        report_text="attacked: boundary\nfindings: none\noverall: held",
        thread_id="adv-thread",
        turn_id="adv-turn",
        generation=0,
        completion_wake_sequence=1,
        latest_relevant_change_sequence=2,
        validation_sequence=3,
        created_at=datetime.now(timezone.utc).isoformat(),
    )

    await controller.apply_completion_decision(
        _covered_accept_decision(wake_sequence=1, validation_id="validation-3"),
        packet_thread_id="thread",
        packet=packet,
    )

    assert store.get_bello_config().status == BelloStatus.COMPLETE
    assert coder.messages == []
    final_report = store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert "## Adversary Reports" in final_report


async def test_adversary_candidate_finding_reruns_completion_review_with_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validations = [
        ValidationRun(
            command="pytest tests/test_app.py",
            exit_code=0,
            passed=True,
            summary="1 passed",
            captured_output="1 passed\n",
            executed_test_files=["tests/test_app.py"],
            sequence=3,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    fake = _RuntimeFakeSupervisor(store, task)
    controller.supervisor = fake
    controller.adversary_enabled = True
    controller.coder_client = controller.supervisor_client = object()
    controller.model = None
    controller.coder_model = MODEL_GPT_5_5
    controller.supervisor_model = MODEL_GPT_5_5
    controller.adversary_model = "gpt-adversary"
    controller.adversary_intelligence = "ultra"
    controller.running = True
    controller.observed_changed_files = {"src/app.py": ChangedFile(path="src/app.py", status="M", sequence=2)}
    fresh_coder = _GateFakeCoder()
    rollovers: list[tuple[str, bool]] = []

    async def rollover(reason, *, handoff=None, phase_rollover=False):
        rollovers.append((reason, phase_rollover))
        controller.coder = fresh_coder

    monkeypatch.setattr(controller, "restart_coder_generation", rollover)

    class FakeAdversary:
        def __init__(
            self,
            *args,
            model=None,
            intelligence=None,
            on_thread_start=None,
            on_thread_done=None,
            **kwargs,
        ) -> None:
            assert model == "gpt-adversary"
            assert intelligence == "ultra"
            self.on_thread_start = on_thread_start
            self.on_thread_done = on_thread_done

        async def run(self, packet, *, previous_adversary_report=None):
            assert previous_adversary_report is None
            if self.on_thread_start:
                self.on_thread_start("adv-thread")
            if self.on_thread_done:
                self.on_thread_done("adv-thread")
            return SimpleNamespace(
                report_text="attacked: stack args\nfindings: crash on seven args\noverall: broke",
                thread_id="adv-thread",
                turn_id="adv-turn",
                candidate_finding=True,
            )

    monkeypatch.setattr("supervisor.controller.AdversaryAgent", FakeAdversary)

    await controller.apply_completion_decision(
        _covered_accept_decision(wake_sequence=1, validation_id="validation-3"),
        packet_thread_id="thread",
        packet=_gate_packet(task, validations=validations),
    )
    assert controller._supervisor_task is not None
    await controller._supervisor_task

    assert store.get_bello_config().status == BelloStatus.STARTING
    assert fake.completion_packets
    assert fake.completion_packets[0].adversary_report is not None
    assert fake.completion_packets[0].adversary_report.candidate_finding is True
    assert store.get_bello_config().adversary_run_count == 1
    assert coder.messages == []
    assert rollovers and rollovers[0][1] is True
    assert "Adversarial tester report:" in fresh_coder.messages[0]


async def test_completion_return_budget_waits_for_coder_readiness_before_forcing_adversary(
    tmp_path: Path,
) -> None:
    controller, store, _, coder = _completion_gate_controller(tmp_path, validations=[])
    controller.adversary_enabled = True
    store.update_bello_config(
        lambda cfg: cfg.model_copy(
            update={
                "max_adversary_runs": 1,
                "max_completion_returns_before_adversary": 1,
                "max_completion_returns_after_adversary": 2,
            }
        )
    )
    decision = CompletionReviewDecision(
        decision="return",
        reason="one material gap remains",
        validation_gaps=["edge case is not validated"],
        message_to_coder="Fix and validate the edge case, then report readiness again.",
        persistent_decision=None,
        progress_update=None,
        clear_handoff=False,
        display_message=None,
        handoff=None,
        wake_sequence=1,
        generation=0,
    )

    await controller._return_completion_to_coder(decision)

    cfg = store.get_bello_config()
    assert cfg.completion_return_count == 1
    assert cfg.completion_returns_since_adversary == 0
    assert cfg.adversary_run_count == 0
    assert coder.messages == ["Fix and validate the edge case, then report readiness again."]
    assert controller._completion_review_budget_action() == "adversary"


async def test_completion_only_review_budget_finalizes_without_restart_or_extra_review(
    tmp_path: Path,
) -> None:
    controller, store, fake = _runtime_controller(tmp_path)
    controller.adversary_enabled = False
    store.update_bello_config(
        lambda cfg: cfg.model_copy(
            update={
                "max_adversary_runs": 1,
                "max_completion_returns_before_adversary": 4,
                "completion_return_count": 4,
            }
        )
    )
    finalized: list[tuple[str, BelloStatus, bool]] = []

    async def capture_finalize(
        result: str,
        *,
        status: BelloStatus = BelloStatus.COMPLETE,
        completion_review_accepted: bool = False,
    ) -> None:
        finalized.append((result, status, completion_review_accepted))

    controller.finalize = capture_finalize

    await controller._run_supervisor_check("coder ready after final allowed review", None, None, None, None, True)

    assert fake.completion_packets == []
    assert controller.completion_restarts == 0
    assert finalized == [
        (
            "completed by bounded review policy: completion review budget exhausted",
            BelloStatus.COMPLETE,
            False,
        )
    ]


def test_completion_only_zero_review_budget_is_unlimited(tmp_path: Path) -> None:
    controller, store, _ = _runtime_controller(tmp_path)
    controller.adversary_enabled = False
    store.update_bello_config(
        lambda cfg: cfg.model_copy(
            update={
                "max_completion_returns_before_adversary": 0,
                "completion_return_count": 100,
            }
        )
    )

    assert controller._completion_review_budget_action() is None


async def test_pre_adversary_return_budget_runs_adversary_without_an_extra_completion_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller, store, fake = _runtime_controller(tmp_path)
    controller.adversary_enabled = True
    controller.coder_client = controller.supervisor_client = object()
    controller.model = None
    controller.adversary_model = "gpt-adversary"
    controller.adversary_intelligence = "ultra"
    store.update_bello_config(
        lambda cfg: cfg.model_copy(
            update={
                "max_adversary_runs": 1,
                "max_completion_returns_before_adversary": 7,
                "max_completion_returns_after_adversary": 2,
                "completion_return_count": 7,
            }
        )
    )
    finalized: list[tuple[str, BelloStatus, bool]] = []

    async def capture_finalize(
        result: str,
        *,
        status: BelloStatus = BelloStatus.COMPLETE,
        completion_review_accepted: bool = False,
    ) -> None:
        finalized.append((result, status, completion_review_accepted))

    controller.finalize = capture_finalize

    class CleanAdversary:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def run(self, packet, *, previous_adversary_report=None):
            return SimpleNamespace(
                report_text="attacked: boundaries\nfindings: none\noverall: held",
                thread_id="adv-thread",
                turn_id="adv-turn",
                candidate_finding=False,
            )

    monkeypatch.setattr("supervisor.controller.AdversaryAgent", CleanAdversary)

    await controller._run_supervisor_check("coder ready", None, None, None, None, True)

    cfg = store.get_bello_config()
    assert fake.completion_packets == []
    assert cfg.adversary_run_count == 1
    assert cfg.completion_returns_since_adversary == 0
    assert finalized == [
        (
            "completed by bounded review policy: completion review budget reached and adversary reported no candidate finding",
            BelloStatus.COMPLETE,
            False,
        )
    ]


async def test_post_adversary_return_budget_finalizes_on_next_readiness_without_extra_review(
    tmp_path: Path,
) -> None:
    controller, store, fake = _runtime_controller(tmp_path)
    controller.adversary_enabled = True
    store.update_bello_config(
        lambda cfg: cfg.model_copy(
            update={
                "max_adversary_runs": 1,
                "max_completion_returns_before_adversary": 7,
                "max_completion_returns_after_adversary": 2,
                "adversary_run_count": 1,
                "completion_return_count": 9,
                "completion_returns_since_adversary": 2,
            }
        )
    )
    finalized: list[tuple[str, BelloStatus, bool]] = []

    async def capture_finalize(
        result: str,
        *,
        status: BelloStatus = BelloStatus.COMPLETE,
        completion_review_accepted: bool = False,
    ) -> None:
        finalized.append((result, status, completion_review_accepted))

    controller.finalize = capture_finalize

    await controller._run_supervisor_check("coder ready after final return", None, None, None, None, True)

    assert fake.completion_packets == []
    assert finalized == [
        (
            "completed by bounded review policy: post-adversary completion review budget exhausted",
            BelloStatus.COMPLETE,
            False,
        )
    ]
    events = [json.loads(line) for line in store.path(EVENTS).read_text(encoding="utf-8").splitlines()]
    assert events[-1]["event_type"] == "completion/budget_finalize"
    assert events[-1]["decision"]["completion_return_count"] == 9


async def test_required_budget_adversary_failure_is_not_reported_as_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller, store, fake = _runtime_controller(tmp_path)
    controller.adversary_enabled = True
    controller.coder_client = controller.supervisor_client = object()
    store.update_bello_config(
        lambda cfg: cfg.model_copy(
            update={
                "max_adversary_runs": 1,
                "max_completion_returns_before_adversary": 1,
                "completion_return_count": 1,
            }
        )
    )
    finalized: list[tuple[str, BelloStatus, bool]] = []

    async def capture_finalize(
        result: str,
        *,
        status: BelloStatus = BelloStatus.COMPLETE,
        completion_review_accepted: bool = False,
    ) -> None:
        finalized.append((result, status, completion_review_accepted))

    controller.finalize = capture_finalize

    class FailingAdversary:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def run(self, packet, *, previous_adversary_report=None):
            raise AdversaryAgentError("provider unavailable")

    monkeypatch.setattr("supervisor.controller.AdversaryAgent", FailingAdversary)

    await controller._run_supervisor_check("coder ready", None, None, None, None, True)

    assert fake.completion_packets == []
    assert finalized == [
        (
            "required adversary failed under bounded review policy: provider unavailable",
            BelloStatus.PROVIDER_FAILURE,
            False,
        )
    ]
    assert controller._pending_adversary_report.status == "error"


async def test_adversary_receives_previous_report_as_regression_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validations = [
        ValidationRun(
            command="pytest tests/test_app.py",
            exit_code=0,
            passed=True,
            summary="1 passed",
            captured_output="1 passed\n",
            executed_test_files=["tests/test_app.py"],
            sequence=3,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    controller.adversary_enabled = True
    controller.coder_client = controller.supervisor_client = object()
    controller.model = None
    controller.running = False
    store.update_bello_config(
        lambda cfg: cfg.model_copy(update={"max_adversary_runs": 2, "adversary_run_count": 1})
    )
    controller._pending_adversary_report = AdversaryReport(
        candidate_finding=True,
        report_text="attacked: previous edge\nfindings: previous crash\noverall: broke",
        thread_id="old-adv-thread",
        turn_id="old-adv-turn",
        generation=0,
        completion_wake_sequence=1,
        latest_relevant_change_sequence=1,
        validation_sequence=2,
        workspace_state_id="old-state",
        created_at=datetime.now(timezone.utc).isoformat(),
    )

    class FakeAdversary:
        def __init__(self, *args, on_thread_start=None, on_thread_done=None, **kwargs) -> None:
            self.on_thread_start = on_thread_start
            self.on_thread_done = on_thread_done

        async def run(self, packet, *, previous_adversary_report=None):
            assert previous_adversary_report is not None
            assert previous_adversary_report["report_text"].startswith("attacked: previous edge")
            if self.on_thread_start:
                self.on_thread_start("new-adv-thread")
            if self.on_thread_done:
                self.on_thread_done("new-adv-thread")
            return SimpleNamespace(
                report_text="attacked: previous edge, fresh edge\nfindings: none\noverall: held",
                thread_id="new-adv-thread",
                turn_id="new-adv-turn",
                candidate_finding=False,
            )

    monkeypatch.setattr("supervisor.controller.AdversaryAgent", FakeAdversary)

    await controller.apply_completion_decision(
        _covered_accept_decision(wake_sequence=1, validation_id="validation-3"),
        packet_thread_id="thread",
        packet=_gate_packet(task, validations=validations),
    )

    assert store.get_bello_config().status == BelloStatus.COMPLETE
    assert controller._accepted_adversary_report.thread_id == "new-adv-thread"
    assert store.get_bello_config().adversary_run_count == 2
    assert coder.messages == []


async def test_completion_return_after_adversary_includes_report_for_fresh_coder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validations = [
        ValidationRun(
            command="pytest tests/test_app.py",
            exit_code=0,
            passed=True,
            summary="1 passed",
            captured_output="1 passed\n",
            executed_test_files=["tests/test_app.py"],
            sequence=3,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    fresh_coder = _GateFakeCoder()
    rollovers: list[tuple[str, bool]] = []

    async def rollover(reason, *, handoff=None, phase_rollover=False):
        rollovers.append((reason, phase_rollover))
        controller.coder = fresh_coder

    monkeypatch.setattr(controller, "restart_coder_generation", rollover)
    packet = _gate_packet(task, validations=validations)
    packet.adversary_report = AdversaryReport(
        report_text="attacked: stack args\nfindings: crash on seven args\nraw observed output: SIGSEGV\noverall: broke",
        thread_id="adv-thread",
        turn_id="adv-turn",
        generation=0,
        completion_wake_sequence=1,
        latest_relevant_change_sequence=2,
        validation_sequence=3,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    decision = CompletionReviewDecision(
        decision="return",
        reason="adversary reproduced stack arg crash",
        uncovered_behaviors=["stack-passed arguments crash"],
        validation_gaps=[],
        claim_evidence_mismatches=[],
        packet_or_access_limitations=[],
        changed_test_risks=[],
        message_to_coder="Fix the reproduced stack-argument crash.",
        persistent_decision=None,
        progress_update=None,
        clear_handoff=False,
        display_message=None,
        handoff=None,
        wake_sequence=1,
        generation=0,
    )

    await controller.apply_completion_decision(decision, packet_thread_id="thread", packet=packet)

    assert len(controller.completion_returns) == 1
    assert coder.messages == []
    assert rollovers and rollovers[0][1] is True
    assert "Fix the reproduced stack-argument crash." in fresh_coder.messages[0]
    assert "Adversarial tester report:" in fresh_coder.messages[0]
    assert "SIGSEGV" in fresh_coder.messages[0]


async def test_completion_accept_gate_returns_for_vacuous_changed_test_masking(tmp_path: Path) -> None:
    validations = [
        ValidationRun(
            command="pytest tests/test_app.py",
            exit_code=0,
            passed=True,
            summary="tests/test_app.py::test_requested_behavior PASSED\n1 passed",
            captured_output="tests/test_app.py::test_requested_behavior PASSED\n1 passed\n",
            executed_test_files=["tests/test_app.py"],
            sequence=3,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    packet = _gate_packet(task, validations=validations)
    packet.changed_file_diffs = [
        ChangedFileDiff(
            path="tests/test_app.py",
            file_kind="test",
            change_kind="modified",
            diff=(
                "diff --git a/tests/test_app.py b/tests/test_app.py\n"
                "@@\n"
                "-    assert app() == 'requested'\n"
                "+    assert True\n"
            ),
        )
    ]

    await controller.apply_completion_decision(
        _covered_accept_decision(wake_sequence=1, validation_id="validation-3"),
        packet_thread_id="thread",
        packet=packet,
    )

    assert store.get_bello_config().status == BelloStatus.STARTING
    assert len(controller.completion_returns) == 1
    assert store.get_bello_config().accept_gate_coder_returns == 1
    assert "changed test appears to mask validation" in coder.messages[0]
    assert "trivially true assertion" in coder.messages[0]


async def test_completion_accept_gate_returns_for_skipped_changed_test_masking(tmp_path: Path) -> None:
    validations = [
        ValidationRun(
            command="pytest tests/test_app.py",
            exit_code=0,
            passed=True,
            summary="tests/test_app.py::test_requested_behavior PASSED\n1 passed",
            captured_output="tests/test_app.py::test_requested_behavior PASSED\n1 passed\n",
            executed_test_files=["tests/test_app.py"],
            sequence=3,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    packet = _gate_packet(task, validations=validations)
    packet.changed_file_diffs = [
        ChangedFileDiff(
            path="tests/test_app.py",
            file_kind="test",
            change_kind="modified",
            diff="+test.skip('requested behavior', () => expect(app()).toBe('requested'))",
        )
    ]

    await controller.apply_completion_decision(
        _covered_accept_decision(wake_sequence=1, validation_id="validation-3"),
        packet_thread_id="thread",
        packet=packet,
    )

    assert store.get_bello_config().status == BelloStatus.STARTING
    assert len(controller.completion_returns) == 1
    assert store.get_bello_config().accept_gate_coder_returns == 1
    assert "changed test appears to mask validation" in coder.messages[0]
    assert "skipped/todo test marker" in coder.messages[0]


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

    assert store.get_bello_config().status == BelloStatus.STARTING
    assert len(controller.completion_returns) == 1
    assert "no fresh passing behavioral validation" in coder.messages[0]
    assert store.get_bello_config().accept_gate_coder_returns == 1


async def test_completion_decision_with_stale_anchor_sequences_reruns_reviewer(tmp_path: Path) -> None:
    validations = [
        ValidationRun(
            validation_id="validation-new",
            command="BELLO_BEHAVIOR_DEMO=1 ./bin/app --scenario fixed",
            exit_code=0,
            type="behavior_demo",
            passed=True,
            trusted_validation_outcome="passed",
            summary="fixed=1",
            captured_output="fixed=1\n",
            sequence=12,
        )
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    packet = _gate_packet(task, validations=validations, wake_sequence=20, latest_change=11)
    packet.latest_event_sequence = 20
    decision = CompletionReviewDecision.model_validate(
        {
            "decision": "return",
            "reason": "old gap still open",
            "decision_artifact": {
                "current_state": "old state",
                "resolved_concerns": [],
                "stale_concerns": ["old gap"],
                "uncovered_edge_candidates": [],
                "actionable_gap_or_none": "old gap",
            },
            "basis_event_seq": 10,
            "last_relevant_edit_seq": 8,
            "last_validation_seq": 9,
            "files_reviewed": [
                {"path": "src/app.py", "reason": "changed source", "kind": "source", "inspected": True, "limitation": None}
            ],
            "behavior_evidence_matrix": [
                {
                    "behavior": "requested behavior",
                    "task_basis": "TASK.md",
                    "files_considered": ["src/app.py"],
                    "evidence": [],
                    "status": "partial",
                    "gap": "old gap",
                }
            ],
            "uncovered_behaviors": ["requested behavior"],
            "validation_gaps": [],
            "claim_evidence_mismatches": [],
            "packet_or_access_limitations": [],
            "changed_test_risks": [],
            "message_to_coder": "fix old gap",
            "persistent_decision": None,
            "progress_update": None,
            "clear_handoff": False,
            "display_message": None,
            "handoff": None,
            "wake_sequence": 20,
            "generation": 0,
        }
    )

    await controller.apply_completion_decision(decision, packet_thread_id="thread", packet=packet)

    assert store.get_bello_config().status == BelloStatus.STARTING
    assert controller.completion_returns == []
    assert coder.messages == []
    assert controller.completion_decision_staleness_rerun_count == 1
    progress = store.path(PROGRESS).read_text(encoding="utf-8")
    assert "stale decision anchors" in progress
    log = store.path(LOG).read_text(encoding="utf-8")
    assert "completion_decision_staleness_failure" in log
    assert "last_validation_seq=9 < latest_validation_sequence=12" in log


async def test_completion_restart_writes_handoff_and_starts_new_generation(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
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
    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.model = None
    controller.coder_client = controller.supervisor_client = FakeClient()
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

    assert store.get_bello_config().generation == 1
    assert "repeated completion miss" in store.path(HANDOFF).read_text(encoding="utf-8")
    assert controller.completion_restarts == 1
    assert controller.coder_client.started_turns


async def test_transport_error_writes_provider_failure_final_report(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    controller = BelloController.__new__(BelloController)
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
    assert store.get_bello_config().status == BelloStatus.PROVIDER_FAILURE
    assert "- Status: provider_failure" in text
    assert "app-server transport error" in text
    assert controller.running is False


async def test_supervisor_turn_start_timeout_writes_provider_failure_final_report(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class HangingTurnStartClient:
        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "supervisor-thread"}}

        async def turn_start(self, params, *, timeout):
            await asyncio.Event().wait()

        async def thread_archive(self, thread_id, *, timeout):
            return {}

    controller = BelloController.__new__(BelloController)
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
    assert store.get_bello_config().status == BelloStatus.PROVIDER_FAILURE
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
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class HangingTurnStartClient:
        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "supervisor-thread"}}

        async def turn_start(self, params, *, timeout):
            await asyncio.Event().wait()

        async def thread_archive(self, thread_id, *, timeout):
            return {}

    controller = BelloController.__new__(BelloController)
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
    assert store.get_bello_config().status == BelloStatus.STARTING
    assert text == ""
    assert controller.running is True
    assert health.timeout_fallback_count == 1
    assert "stale_runtime_supervisor_timeout" in health.risk_signals
    assert "continuing with the latest queued review" in store.path(PROGRESS).read_text(encoding="utf-8")
    assert any("supervisor check failed" in message for _, message in controller.tui.messages)


async def test_supervisor_no_message_retries_from_latest_stable_state(tmp_path: Path) -> None:
    controller, store, _ = _runtime_controller(tmp_path)

    class NoMessageThenNoopSupervisor:
        def __init__(self, store: StateStore, task: Path) -> None:
            self.agent = StatelessSupervisorAgent(None, store, task)  # type: ignore[arg-type]
            self.calls = 0

        def build_packet(self, **kwargs):
            return self.agent.build_packet(**kwargs)

        async def decide(self, packet):
            self.calls += 1
            if self.calls == 1:
                raise SupervisorAgentError("supervisor did not produce an agent message")
            return SupervisorDecision(
                decision=SupervisorDecisionKind.NOOP,
                reason="recovered",
                wake_sequence=packet.wake_sequence,
                generation=packet.generation,
            )

    supervisor = NoMessageThenNoopSupervisor(store, controller.task_path)
    controller.supervisor = supervisor

    await controller._supervisor_check_loop("runtime check", None, None, None, None, False)

    assert supervisor.calls == 2
    assert store.get_bello_config().status == BelloStatus.STARTING
    assert store.path(FINAL_REPORT).read_text(encoding="utf-8") == ""
    # After a successful recovery the consecutive no_message budget resets, so a recovered
    # provider does not carry earlier blips toward infra-invalid.
    assert controller.provider_failure_recovery_counts == {}
    assert "supervisor produced no agent message" in store.path(PROGRESS).read_text(encoding="utf-8")


async def test_repeated_runtime_supervisor_no_message_skips_current_review(tmp_path: Path) -> None:
    controller, store, _ = _runtime_controller(tmp_path)

    class AlwaysNoMessageRuntimeSupervisor:
        def __init__(self, store: StateStore, task: Path) -> None:
            self.agent = StatelessSupervisorAgent(None, store, task)  # type: ignore[arg-type]
            self.calls = 0

        def build_packet(self, **kwargs):
            return self.agent.build_packet(**kwargs)

        async def decide(self, packet):
            self.calls += 1
            raise SupervisorAgentError("supervisor did not produce an agent message")

    supervisor = AlwaysNoMessageRuntimeSupervisor(store, controller.task_path)
    controller.supervisor = supervisor

    await controller._supervisor_check_loop("runtime check", None, None, None, None, False)

    assert supervisor.calls == 2
    assert store.get_bello_config().status == BelloStatus.STARTING
    assert store.path(FINAL_REPORT).read_text(encoding="utf-8") == ""
    assert controller.running is True
    assert controller._supervisor_dirty is False
    assert controller.provider_failure_recovery_counts["no_message"] == 2
    assert controller.provider_failure_recovery_counts["runtime_monitor_no_message"] == 2
    progress = store.path(PROGRESS).read_text(encoding="utf-8")
    assert "retrying review from latest stable state" in progress
    assert "skipping this runtime-only review" in progress


async def test_repeated_supervisor_no_message_marks_infra_invalid_provider_failure(tmp_path: Path) -> None:
    controller, store, _ = _runtime_controller(tmp_path)

    class AlwaysNoMessageSupervisor:
        def __init__(self, store: StateStore, task: Path) -> None:
            self.agent = StatelessSupervisorAgent(None, store, task)  # type: ignore[arg-type]
            self.calls = 0

        def build_packet(self, **kwargs):
            return self.agent.build_packet(**kwargs)

        async def decide_completion(self, packet):
            self.calls += 1
            raise SupervisorAgentError("supervisor did not produce an agent message")

        async def close_completion_review(self):
            return None

    supervisor = AlwaysNoMessageSupervisor(store, controller.task_path)
    controller.supervisor = supervisor
    # Pin the configurable completion no_message budget low and disable backoff so the test
    # reaches the infra-invalid path fast (default budget rides out a transient blip).
    controller._completion_no_message_max_retries = 1
    controller._no_message_backoff_seconds = ()

    await controller._supervisor_check_loop("completion check", None, None, None, None, True)

    assert supervisor.calls == 2
    assert store.get_bello_config().status == BelloStatus.PROVIDER_FAILURE
    report = store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert "infra-invalid: supervisor no_message provider failure after retry/resume" in report
    assert "- Status: provider_failure" in report
    assert "repeated supervisor no_message" in store.path(PROGRESS).read_text(encoding="utf-8")


async def test_completion_no_message_budget_rides_out_blip_before_infra_invalid(tmp_path: Path) -> None:
    # A transient provider blip (empty completions) must be ridden out with backed-off retries
    # up to the configurable budget; infra-invalid only fires after the full budget is spent.
    controller, store, _ = _runtime_controller(tmp_path)

    class AlwaysNoMessageSupervisor:
        def __init__(self, store: StateStore, task: Path) -> None:
            self.agent = StatelessSupervisorAgent(None, store, task)  # type: ignore[arg-type]
            self.calls = 0

        def build_packet(self, **kwargs):
            return self.agent.build_packet(**kwargs)

        async def decide_completion(self, packet):
            self.calls += 1
            raise SupervisorAgentError("supervisor did not produce an agent message")

        async def close_completion_review(self):
            return None

    supervisor = AlwaysNoMessageSupervisor(store, controller.task_path)
    controller.supervisor = supervisor
    controller._completion_no_message_max_retries = 3
    controller._no_message_backoff_seconds = ()  # no real sleeping in the test

    await controller._supervisor_check_loop("completion check", None, None, None, None, True)

    # 3 retries then the infra-invalid attempt = 4 model calls (old behavior gave up after 1 retry).
    assert supervisor.calls == 4
    assert store.get_bello_config().status == BelloStatus.PROVIDER_FAILURE


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
    controller = BelloController(
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
    assert controller.store.get_bello_config().status == BelloStatus.PROVIDER_FAILURE
    assert "- Status: provider_failure" in text
    assert "app-server RPC failed" in text
    assert "account/read response timed out" in text


async def test_startup_runtime_error_is_recorded_as_provider_failure(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")

    class FailingStartupClient:
        async def start(self):
            raise RuntimeError("native role launcher rejected startup")

        async def stop(self):
            return None

    controller = BelloController(
        tmp_path,
        task_path=task,
        client=FailingStartupClient(),  # type: ignore[arg-type]
        tui=_FakeTUI(),
        overwrite_state=True,
        use_git_diff=False,
    )

    await controller.run()

    report = controller.store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert controller.store.get_bello_config().status == BelloStatus.PROVIDER_FAILURE
    assert "run infrastructure failed: native role launcher rejected startup" in report


async def test_missing_selected_model_interrupts_before_coder_and_writes_final_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")

    class MissingModelClient:
        def __init__(self) -> None:
            self.thread_started = False
            self.stopped = False

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
            return {"data": [{"id": MODEL_GPT_5_6_SOL}, {"id": MODEL_GPT_5_5}]}

        async def thread_start(self, params):
            self.thread_started = True
            raise AssertionError("coder must not start with an unavailable model")

    client = MissingModelClient()
    monkeypatch.setattr("supervisor.controller._run_probe", lambda args: (True, "codex-cli test"))
    controller = BelloController(
        tmp_path,
        task_path=task,
        client=client,  # type: ignore[arg-type]
        tui=_FakeTUI(),
        coder_model="gpt-5.6-unknown",
        supervisor_model=MODEL_GPT_5_6_SOL,
        overwrite_state=True,
        use_git_diff=False,
    )
    controller._generate_schema_hash_async = _async_schema_hash

    await controller.run()

    report = controller.store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert controller.store.get_bello_config().status == BelloStatus.PROVIDER_FAILURE
    assert "- Status: provider_failure" in report
    assert "model availability preflight failed before coder start" in report
    assert "coder=gpt-5.6-unknown" in report
    assert "Available models: gpt-5.5, gpt-5.6-sol" in report
    assert ".supervisor/FINAL_REPORT.md" in report
    assert client.thread_started is False
    assert client.stopped is True


async def test_missing_fixed_adversary_model_interrupts_before_coder_and_writes_final_report(
    tmp_path: Path,
    monkeypatch,
) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")

    class MissingAdversaryModelClient:
        def __init__(self) -> None:
            self.thread_started = False
            self.stopped = False

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
            return {"data": [{"id": MODEL_GPT_5_5}]}

        async def thread_start(self, params):
            self.thread_started = True
            raise AssertionError("coder must not start with an unavailable adversary model")

    client = MissingAdversaryModelClient()
    monkeypatch.setattr("supervisor.controller._run_probe", lambda args: (True, "codex-cli test"))
    controller = BelloController(
        tmp_path,
        task_path=task,
        client=client,  # type: ignore[arg-type]
        tui=_FakeTUI(),
        coder_model=MODEL_GPT_5_5,
        supervisor_model=MODEL_GPT_5_5,
        overwrite_state=True,
        use_git_diff=False,
        completion_review=True,
        adversary_enabled=True,
    )
    controller._generate_schema_hash_async = _async_schema_hash

    await controller.run()

    report = controller.store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert controller.store.get_bello_config().status == BelloStatus.PROVIDER_FAILURE
    assert "- Status: provider_failure" in report
    assert "model availability preflight failed before coder start" in report
    assert f"adversary={ADVERSARY_MODEL}" in report
    assert "Available models: gpt-5.5" in report
    assert client.thread_started is False
    assert client.stopped is True


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
            return {"data": [{"id": DEFAULT_MODEL}, {"id": "gpt-test"}]}

        async def config_requirements_read(self):
            return {}

        async def thread_start(self, params):
                return {
                    "thread": {"id": "probe-thread"},
                    "approvalPolicy": "on-request",
                    "sandbox": {"type": "workspaceWrite", "writableRoots": [], "networkAccess": False},
                }

        async def thread_archive(self, thread_id):
            raise AssertionError("preflight probe cleanup should not archive threads without rollouts")

        async def thread_unsubscribe(self, thread_id):
            self.unsubscribed.append(thread_id)
            raise AppServerError("unsubscribe cleanup failed")

    client = ProbeCleanupClient()
    monkeypatch.setattr("supervisor.controller._run_probe", lambda args: (True, "codex-cli test"))
    controller = BelloController(
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
    config = controller.store.get_bello_config()
    assert config.model == DEFAULT_MODEL
    assert config.coder_model == DEFAULT_MODEL
    assert config.supervisor_model == DEFAULT_MODEL
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
            return {"data": [{"id": DEFAULT_MODEL}, {"id": "gpt-test"}]}

        async def config_requirements_read(self):
            return {}

        async def thread_start(self, params):
                return {
                    "thread": {"id": "probe-thread"},
                    "approvalPolicy": "on-request",
                    "sandbox": {"type": "workspaceWrite", "writableRoots": [], "networkAccess": False},
                }

        async def thread_unsubscribe(self, thread_id):
            self.unsubscribed.append(thread_id)
            return {}

    client = RateLimitFailureClient()
    tui = _FakeTUI()
    monkeypatch.setattr("supervisor.controller._run_probe", lambda args: (True, "codex-cli test"))
    controller = BelloController(
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

    config = controller.store.get_bello_config()
    assert config.model == DEFAULT_MODEL
    assert config.coder_model == DEFAULT_MODEL
    assert config.supervisor_model == DEFAULT_MODEL
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
            return {"data": [{"id": DEFAULT_MODEL}, {"id": "gpt-test"}]}

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
    monkeypatch.setenv("BELLO_CODER_SANDBOX", "danger-full-access")
    monkeypatch.setattr("supervisor.controller._run_probe", lambda args: (True, "codex-cli test"))
    controller = BelloController(
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
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread", active_coder_turn_id="turn"),
        overwrite=True,
    )

    class RespondTimeoutClient:
        async def respond(self, request_id, response):
            raise AppServerTimeoutError("app-server respond 61 send timed out after 15s")

    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.coder_client = controller.supervisor_client = RespondTimeoutClient()
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
    assert store.get_bello_config().status == BelloStatus.PROVIDER_FAILURE
    assert "- Status: provider_failure" in text
    assert "app-server RPC failed while handling server_request" in text
    assert "respond 61 send timed out" in text
    assert controller.running is False


async def test_coder_turn_start_timeout_writes_provider_failure_final_report(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="coder-thread"),
        overwrite=True,
    )

    class CoderTurnTimeoutClient:
        async def respond(self, request_id, response):
            return None

        async def turn_start(self, params, *, timeout):
            assert timeout == APP_SERVER_CODER_RPC_TIMEOUT_SECONDS
            raise AppServerTimeoutError(f"app-server RPC turn/start response timed out after {timeout:g}s")

    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.coder_client = controller.supervisor_client = CoderTurnTimeoutClient()
    controller.approvals = ApprovalManager(tmp_path)
    controller.coder = CoderSession(
        controller.coder_client,  # type: ignore[arg-type]
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
    assert store.get_bello_config().status == BelloStatus.PROVIDER_FAILURE
    assert "- Status: provider_failure" in text
    assert "app-server RPC failed while handling server_request" in text
    assert "turn/start response timed out after 3600s" in text
    assert controller.running is False


async def test_restart_preserves_coder_intelligence(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)

    class FakeClient:
        def __init__(self) -> None:
            self.turn_params = []

        async def thread_start(self, params, *, timeout):
            return {"thread": {"id": "restart-thread"}}

        async def turn_start(self, params, *, timeout):
            self.turn_params.append(params)
            return {"turn": {"id": "restart-turn", "status": "completed"}}

    client = FakeClient()
    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.coder_client = controller.supervisor_client = client
    controller.tui = _FakeTUI()
    controller.supervisor = None
    controller.approvals = None
    controller.coder = None
    controller.pending_approvals = {}
    controller.declared_grading_roots = ()
    controller._sequence = 0
    controller.coder_model = "gpt-coder"
    controller.coder_intelligence = "high"
    controller.fast = False

    await controller.restart("test restart")

    assert controller.coder is not None
    assert controller.coder.intelligence == "high"
    assert client.turn_params[-1]["effort"] == "high"


async def test_supervisor_decision_can_clear_handoff(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
    store.write_handoff("restart context\n")

    controller = BelloController.__new__(BelloController)
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
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
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
    store.initialize_bello(BelloConfig(project_root=str(tmp_path), task_path=str(task)), overwrite=True)
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
    controller = BelloController.__new__(BelloController)
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
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread", active_coder_turn_id="turn"),
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

    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.store = store
    controller.coder_client = controller.supervisor_client = FakeClient()
    controller.approvals = ApprovalManager(tmp_path, supervisor=FakeSupervisor())
    controller.coder = FakeCoder()
    controller.pending_approvals = {}
    controller.tui = _FakeTUI()
    controller._sequence = 0

    await controller.handle_server_request(AppServerMessage({"id": 51, "method": context.server_request_method, "params": context.raw_params}))

    assert controller.coder_client.responses == [(51, {"decision": "decline"})]
    assert controller.coder.messages == ["Network access is not required by the task."]


async def test_policy_deny_reason_is_steered_to_coder(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread", active_coder_turn_id="turn"),
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

    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.store = store
    controller.coder_client = controller.supervisor_client = FakeClient()
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

    assert controller.coder_client.responses == [(52, {"decision": "decline"})]
    assert controller.coder.messages == ["writes to supervisor runtime/state files are denied"]


async def test_adversary_file_change_request_is_denied_without_steering_coder(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="coder-thread"),
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

    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.store = store
    controller.coder_client = controller.supervisor_client = FakeClient()
    controller.approvals = ApprovalManager(tmp_path)
    controller.coder = FakeCoder()
    controller.pending_approvals = {}
    controller.tui = _FakeTUI()
    controller._sequence = 0
    controller._active_adversary_thread_id = "adv-thread"

    await controller.handle_server_request(
        AppServerMessage(
            {
                "id": 53,
                "method": "item/fileChange/requestApproval",
                "params": {
                    "threadId": "adv-thread",
                    "turnId": "adv-turn",
                    "grantRoot": str(tmp_path / "src" / "app.py"),
                    "availableDecisions": ["accept", "decline", "cancel"],
                },
            }
        )
    )

    assert controller.coder_client.responses == [(53, {"decision": "decline"})]
    assert controller.coder.messages == []
    progress = store.path(PROGRESS).read_text(encoding="utf-8")
    assert "Adversary approval denied without steering coder" in progress
    # The denial is remembered so an adversary retry can be told what was refused.
    assert len(controller._adversary_denied_commands) == 1
    assert str(tmp_path / "src" / "app.py") in controller._adversary_denied_commands[0]
    assert "(denied:" in controller._adversary_denied_commands[0]


async def test_policy_deny_no_active_turn_starts_new_coder_turn(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread", active_coder_turn_id="turn"),
        overwrite=True,
    )

    class FakeClient:
        def __init__(self) -> None:
            self.responses = []

        async def respond(self, request_id, response):
            self.responses.append((request_id, response))

    class FakeCoder:
        def __init__(self) -> None:
            self.active_turn_id = "turn"
            self.started_messages = []

        async def steer_or_start(self, message):
            raise AppServerError("{'code': -32600, 'message': 'no active turn to steer'}")

        async def start_turn(self, message):
            self.started_messages.append(message)
            self.active_turn_id = "new-turn"
            return "new-turn"

    coder = FakeCoder()
    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.store = store
    controller.coder_client = controller.supervisor_client = FakeClient()
    controller.approvals = ApprovalManager(tmp_path)
    controller.coder = coder
    controller.pending_approvals = {}
    controller.tui = _FakeTUI()
    controller._sequence = 0

    await controller.handle_server_request(
        AppServerMessage(
            {
                "id": 55,
                "method": "item/fileChange/requestApproval",
                "params": {
                    "grantRoot": str(tmp_path / ".supervisor" / CONFIG),
                    "availableDecisions": ["accept", "decline", "cancel"],
                },
            }
        )
    )

    health = store.get_health()
    assert controller.coder_client.responses == [(55, {"decision": "decline"})]
    assert health.denied_requests == 1
    assert health.last_denial == "writes to supervisor runtime/state files are denied"
    assert coder.started_messages == ["writes to supervisor runtime/state files are denied"]
    assert store.get_bello_config().active_coder_turn_id == "new-turn"
    assert "started a new coder turn with the denial reason" in store.path(PROGRESS).read_text(encoding="utf-8")


async def test_approval_accept_does_not_steer_coder(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread", active_coder_turn_id="turn"),
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

    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.store = store
    controller.coder_client = controller.supervisor_client = FakeClient()
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

    assert controller.coder_client.responses == [(53, {"decision": "accept"})]
    assert controller.coder.messages == []


async def test_execpolicy_amendment_approval_is_not_rendered_as_denied(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread", active_coder_turn_id="turn"),
        overwrite=True,
    )
    amendment = ["/bin/zsh", "-lc", "printf 'hello bello\\n' > hello.txt"]
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

    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.store = store
    controller.coder_client = controller.supervisor_client = FakeClient()
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
                    "command": "printf 'hello bello\\n' > hello.txt",
                    "cwd": str(tmp_path),
                    "availableDecisions": [offered_decision, "decline"],
                },
            }
        )
    )

    assert controller.coder_client.responses == [(54, {"decision": offered_decision})]
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
            return {
                "data": [
                    {"id": DEFAULT_MODEL},
                    {"id": "gpt-coder"},
                    {"id": "gpt-runtime"},
                    {"id": "gpt-completion"},
                ]
            }

        async def config_requirements_read(self):
            return {}

        async def thread_start(self, params, **kwargs):
            self.thread_count += 1
            return {
                "thread": {"id": f"thread-{self.thread_count}"},
                "approvalPolicy": "on-request",
                "sandbox": {"type": "workspaceWrite", "writableRoots": [], "networkAccess": False},
            }

        async def thread_unsubscribe(self, thread_id, **kwargs):
            return {}

        async def turn_start(self, params, **kwargs):
            self.initial_turn_started.set()
            return {"turn": {"id": "turn-1", "status": "running"}}

    client = ShutdownClient()
    monkeypatch.setattr("supervisor.controller._run_probe", lambda args: (True, "codex-cli test"))
    controller = BelloController(
        tmp_path,
        task_path=task,
        client=client,  # type: ignore[arg-type]
        tui=_FakeTUI(),
        coder_model="gpt-coder",
        runtime_model="gpt-runtime",
        completion_model="gpt-completion",
        coder_intelligence="ultra",
        runtime_intelligence="xhigh",
        completion_intelligence="high",
        adversary_enabled=False,
        overwrite_state=True,
        use_git_diff=False,
    )
    controller._generate_schema_hash_async = _async_schema_hash
    controller._structured_output_self_test = _async_noop

    run_task = asyncio.create_task(controller.run())
    await asyncio.wait_for(client.initial_turn_started.wait(), timeout=1)
    await controller.finalize("task complete", status=BelloStatus.COMPLETE)
    await asyncio.wait_for(run_task, timeout=1)

    assert controller.coder is not None
    assert controller.coder.model == "gpt-coder"
    assert controller.coder.intelligence == "ultra"
    assert controller.supervisor is not None
    assert controller.supervisor.model == "gpt-runtime"
    assert controller.supervisor.intelligence == "xhigh"
    assert controller.completion_supervisor is not None
    assert controller.completion_supervisor is not controller.supervisor
    assert controller.completion_supervisor.model == "gpt-completion"
    assert controller.completion_supervisor.intelligence == "high"
    assert client.stopped is True
    assert controller.running is False


async def test_finalize_arms_terminal_shutdown_before_reading_or_writing_report(tmp_path: Path) -> None:
    controller, store, _ = _runtime_controller(tmp_path)
    shutdown_seen = False

    async def fake_prepare_terminal_shutdown(reason: str) -> None:
        nonlocal shutdown_seen
        shutdown_seen = True
        assert controller._terminal_cleanup_started is True
        assert controller.running is False
        assert store.get_bello_config().status != BelloStatus.COMPLETE

    controller._prepare_terminal_shutdown = fake_prepare_terminal_shutdown  # type: ignore[method-assign]

    await controller.finalize("task complete", status=BelloStatus.COMPLETE)

    assert shutdown_seen is True
    assert store.get_bello_config().status == BelloStatus.COMPLETE
    report = store.path(FINAL_REPORT).read_text(encoding="utf-8")
    assert "# Final Report" in report
    assert "task complete" in report
    assert store.get_bello_config().status == BelloStatus.COMPLETE
    assert store.path(FINAL_REPORT).read_text(encoding="utf-8").strip()


async def test_run_exit_joins_background_terminal_cleanup_before_supervisor_cancellation(
    tmp_path: Path,
) -> None:
    controller, store, _ = _runtime_controller(tmp_path)
    controller.running = True
    controller._shutdown_signal = asyncio.Event()
    cleanup_entered = asyncio.Event()
    allow_cleanup_to_finish = asyncio.Event()

    async def background_terminal_cleanup() -> None:
        controller._terminal_cleanup_task = asyncio.current_task()
        controller._terminal_cleanup_started = True
        controller.running = False
        cleanup_entered.set()
        controller.event_queue.put_nowait(ControllerEvent(kind="shutdown"))
        await allow_cleanup_to_finish.wait()
        store.write_text_locked(FINAL_REPORT, "# Final Report\n\ncomplete\n")
        store.update_bello_config(
            lambda cfg: cfg.model_copy(update={"status": BelloStatus.COMPLETE})
        )

    async def main_loop_and_generic_cleanup() -> None:
        await controller.event_loop()
        await controller._await_terminal_cleanup_task()
        await controller._stop_supervisor_task()

    run_exit_task = asyncio.create_task(main_loop_and_generic_cleanup())
    await asyncio.sleep(0)
    terminal_task = asyncio.create_task(background_terminal_cleanup())
    controller._supervisor_task = terminal_task
    await cleanup_entered.wait()

    await asyncio.sleep(0)
    assert not run_exit_task.done()
    assert not terminal_task.cancelled()

    allow_cleanup_to_finish.set()
    await run_exit_task

    assert terminal_task.done()
    assert not terminal_task.cancelled()
    assert store.get_bello_config().status == BelloStatus.COMPLETE
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
) -> tuple[BelloController, StateStore, Path, _GateFakeCoder]:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )
    coder = _GateFakeCoder()
    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.supervisor = None
    controller.coder = coder
    controller.pending_approvals = {}
    controller.last_coder_message = None
    controller.validations = validations
    controller.inspections = []
    controller.prior_interventions = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.adversary_enabled = False
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
    controller.completion_attempt_count = 0
    controller.completion_restarts = 0
    controller.completion_reviewer_rerun_count = reruns
    controller.completion_decision_staleness_rerun_count = 0
    controller.no_marker_idle_nudge_count = 0
    controller.provider_failure_recovery_counts = {}
    controller.validation_runtime_state = {}
    controller.completion_review_return_sequence = None
    controller.completion_review_return_validation_sequence = None
    controller._terminal_cleanup_started = False
    controller._command_output_chunks = {}
    controller._last_large_diff_signature = None
    controller._pending_adversary_report = None
    controller._active_adversary_thread_id = None
    controller._active_adversary_workspace_root = None
    return controller, store, task, coder


class _RuntimeFakeSupervisor:
    def __init__(self, store: StateStore, task: Path) -> None:
        self.agent = StatelessSupervisorAgent(None, store, task)  # type: ignore[arg-type]
        self.runtime_packets = []
        self.completion_packets = []
        self.completion_thread_id = None
        self.closed_completion_reviews = 0

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
        self.closed_completion_reviews += 1
        self.completion_thread_id = None
        return None


class _CheapRuntimeNoopReviewer:
    model = "cheap-runtime-test"

    def __init__(self) -> None:
        self.calls = []

    async def review(self, packet):
        self.calls.append(packet)
        return CheapRuntimeDecision(decision="noop", reason_code="routine_progress")


def _runtime_controller(tmp_path: Path) -> tuple[BelloController, StateStore, _RuntimeFakeSupervisor]:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )
    fake = _RuntimeFakeSupervisor(store, task)
    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.supervisor = fake
    controller.coder = None
    controller.pending_approvals = {}
    controller.last_coder_message = None
    controller.validations = []
    controller.inspections = []
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
    controller.completion_decision_staleness_rerun_count = 0
    controller.validation_runtime_state = {}
    controller.provider_failure_recovery_counts = {}
    controller.completion_review_return_sequence = None
    controller.completion_review_return_validation_sequence = None
    controller._terminal_cleanup_started = False
    controller._command_output_chunks = {}
    controller._last_large_diff_signature = None
    controller._pending_adversary_report = None
    controller._active_adversary_thread_id = None
    controller._active_adversary_workspace_root = None
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
    store.update_bello_config(
        lambda cfg: cfg.model_copy(
            update={
                "status": BelloStatus.RUNNING,
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


async def test_completion_return_with_fresh_delta_evidence_goes_to_coder_without_rerun(tmp_path: Path) -> None:
    validations = [
        ValidationRun(
            validation_id="validation-old",
            command="pytest tests/public",
            exit_code=0,
            passed=True,
            summary="old public pass",
            sequence=5,
        ),
        ValidationRun(
            validation_id="validation-demo",
            command="BELLO_BEHAVIOR_DEMO=1 ./c_compiler sample.c",
            exit_code=0,
            type="behavior_demo",
            passed=True,
            trusted_validation_outcome="passed",
            summary="returns 42",
            captured_output="program exit=42\n",
            sequence=15,
        ),
    ]
    controller, store, task, coder = _completion_gate_controller(tmp_path, validations=validations)
    packet = _gate_packet(task, validations=validations, wake_sequence=20)
    packet.completion_payload_mode = "delta"
    packet.completion_payload_since_sequence = 10
    decision = CompletionReviewDecision.model_validate(
        {
            "decision": "return",
            "reason": "old gap still lacks proof",
            "files_reviewed": [],
            "behavior_evidence_matrix": [],
            "uncovered_behaviors": [],
            "validation_gaps": ["needs direct behavior evidence"],
            "claim_evidence_mismatches": [],
            "packet_or_access_limitations": [],
            "changed_test_risks": [],
            "message_to_coder": "provide direct behavior evidence",
            "persistent_decision": None,
            "progress_update": None,
            "clear_handoff": False,
            "display_message": None,
            "handoff": None,
            "wake_sequence": 20,
            "generation": 0,
        }
    )

    await controller.apply_completion_decision(decision, packet_thread_id="thread", packet=packet)

    assert coder.messages == ["provide direct behavior evidence"]
    assert len(controller.completion_returns) == 1
    assert controller.completion_decision_staleness_rerun_count == 0
    assert getattr(controller, "completion_return_freshness_rerun_count", 0) == 0
    assert "stale return ignored fresh delta evidence" not in store.path(PROGRESS).read_text(encoding="utf-8")
    assert "completion_return_freshness_failure" not in store.path(LOG).read_text(encoding="utf-8")


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


def test_adversary_snapshot_gets_functional_git_repo(tmp_path: Path) -> None:
    import shutil as _shutil
    import subprocess as _subprocess

    from supervisor.controller import _create_adversary_snapshot

    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("print('x')\n", encoding="utf-8")

    snapshot = _create_adversary_snapshot(project)
    try:
        assert (snapshot / "app.py").exists()
        assert (snapshot / ".git").is_dir()
        head = _subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=snapshot, capture_output=True, text=True
        )
        assert head.returncode == 0
        status = _subprocess.run(
            ["git", "status", "--short"], cwd=snapshot, capture_output=True, text=True
        )
        assert status.returncode == 0
        # Files stay untracked on purpose: recursive deletes inside the snapshot must
        # remain approvable for the adversary (tracked paths would be policy-denied).
        assert "?? app.py" in status.stdout
    finally:
        _shutil.rmtree(snapshot.parent, ignore_errors=True)


def test_adversary_snapshot_git_ignores_global_template_hooks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from supervisor.controller import _create_adversary_snapshot

    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("print('x')\n", encoding="utf-8")
    marker = tmp_path / "global-hook-ran"
    template = tmp_path / "git-template"
    hooks = template / "hooks"
    hooks.mkdir(parents=True)
    hook = hooks / "post-commit"
    hook.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    hook.chmod(0o755)
    global_config = tmp_path / "global-gitconfig"
    global_config.write_text(f"[init]\n\ttemplateDir = {template}\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

    snapshot = _create_adversary_snapshot(project)
    try:
        assert not marker.exists()
        assert not (snapshot / ".git" / "hooks" / "post-commit").exists()
        hooks_path = subprocess.check_output(
            ["git", "config", "--local", "--get", "core.hooksPath"],
            cwd=snapshot,
            text=True,
        ).strip()
        assert hooks_path == os.devnull
    finally:
        import shutil as _shutil

        _shutil.rmtree(snapshot.parent, ignore_errors=True)


def test_workspace_state_id_does_not_open_fifo(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO files are not supported on this platform")
    from supervisor.controller import _workspace_state_id

    fifo = tmp_path / "coder-output"
    os.mkfifo(fifo)

    fifo_state = _workspace_state_id(tmp_path)
    fifo.unlink()
    fifo.write_text("regular file\n", encoding="utf-8")
    file_state = _workspace_state_id(tmp_path)

    assert fifo_state != file_state


def test_workspace_context_reader_and_hasher_reject_fifo(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO files are not supported on this platform")
    fifo = tmp_path / "coder-output"
    os.mkfifo(fifo)

    assert _read_workspace_file(tmp_path, "coder-output", limit=1000) is None
    with pytest.raises(OSError, match="not a regular file"):
        _hash_file(fifo)


def test_effective_max_adversary_runs_cli_override(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )
    controller = BelloController.__new__(BelloController)
    controller.store = store

    # No overrides: falls back to the persisted config (default 1).
    controller.adversary_enabled = None
    assert controller._effective_max_adversary_runs() == 1

    # CLI --adversary true --adversary-runs 3: budget honored without touching persisted config.
    controller.adversary_enabled = True
    controller.adversary_runs = 3
    assert controller._effective_max_adversary_runs() == 3
    assert store.get_bello_config().max_adversary_runs == 1

    # CLI --adversary false wins regardless of budget.
    controller.adversary_enabled = False
    assert controller._effective_max_adversary_runs() == 0


class _FakeSteerCoder:
    def __init__(self) -> None:
        self.steers: list[str] = []

    async def steer_or_start(self, message: str) -> None:
        self.steers.append(message)


async def test_no_marker_idle_skips_review_for_virgin_generation(tmp_path: Path) -> None:
    controller, store, fake = _runtime_controller(tmp_path)
    store.update_bello_config(
        lambda cfg: cfg.model_copy(update={"active_coder_turn_id": None, "last_event_sequence": 17})
    )
    controller._generation_has_coder_turn = False
    controller.coder = _FakeSteerCoder()

    await controller._handle_no_marker_idle()

    assert fake.completion_packets == []
    assert "Controller forcing completion_review" not in store.path(PROGRESS).read_text(encoding="utf-8")
    assert controller.coder.steers == [POST_RESTART_CONTINUE_NUDGE]


async def test_completion_restart_discarded_for_virgin_generation(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )
    handoff = RestartHandoff(
        objective="task",
        restart_reason="recovery restart before any coder work",
        bad_pattern="none",
        known_evidence="handoff from prior generation",
        next_step="continue",
        recovery_signal="new coder work",
    )
    controller = BelloController.__new__(BelloController)
    controller.project_root = tmp_path
    controller.task_path = task
    controller.store = store
    controller.coder = _FakeSteerCoder()
    controller.pending_approvals = {}
    controller.prior_interventions = []
    controller.validations = []
    controller.observed_changed_files = {}
    controller.use_git_diff = False
    controller.tui = _FakeTUI()
    controller.running = True
    controller.event_queue = asyncio.Queue()
    controller._sequence = 0
    controller.completion_returns = []
    controller.completion_restarts = 0
    controller.no_marker_idle_nudge_count = 0
    controller._generation_has_coder_turn = False

    await controller.apply_completion_decision(
        CompletionReviewDecision(
            decision="restart",
            reason="generation recovery before any new coder work",
            uncovered_behaviors=[],
            validation_gaps=["stale prior-generation state"],
            message_to_coder=None,
            persistent_decision=None,
            progress_update="Restarting into recovery.",
            clear_handoff=False,
            display_message=None,
            handoff=handoff,
            wake_sequence=1,
            generation=0,
        ),
        packet_thread_id="thread",
    )

    cfg = store.get_bello_config()
    assert cfg.generation == 0
    assert cfg.status not in (BelloStatus.STUCK, BelloStatus.RESTARTING)
    assert controller.completion_restarts == 0
    assert "Discarded completion restart" in store.path(PROGRESS).read_text(encoding="utf-8")
    events = store.path(EVENTS).read_text(encoding="utf-8")
    assert "completion/restart_discarded_virgin_generation" in events
    assert controller.coder.steers == [POST_RESTART_CONTINUE_NUDGE]
