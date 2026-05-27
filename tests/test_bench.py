from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from supervisor.bench_metrics import compute_bench_metrics
from supervisor.bench_results import utc_now, write_aggregate_result
from supervisor.bench_runner import (
    TEST_PROMPTS_FILENAME,
    BenchCase,
    BenchRunner,
    BenchmarkError,
    clear_test_directory,
    discover_bench_tests,
    load_test_prompts,
)
from supervisor.schemas import SentinelConfig, SentinelStatus
from supervisor.state import StateStore


def test_discover_bench_tests_uses_numeric_order(tmp_path: Path) -> None:
    tests_dir = tmp_path / "TESTS"
    for name in ("10", "2", "alpha", "1"):
        (tests_dir / name).mkdir(parents=True)

    cases = discover_bench_tests(tests_dir)

    assert [case.test_id for case in cases] == ["1", "2", "10"]


def test_compute_bench_metrics_from_perf_events(tmp_path: Path) -> None:
    state_dir = tmp_path / ".supervisor"
    state_dir.mkdir()
    _write_jsonl(
        state_dir / "perf.jsonl",
        [
            {"event": "run_started", "monotonic_ms": 0},
            {"event": "coder_turn_started", "monotonic_ms": 100},
            {"event": "first_coder_action_started", "monotonic_ms": 250},
            {"event": "approval_requested", "approval_request_id": "a1", "monotonic_ms": 300},
            {"event": "approval_decided", "approval_request_id": "a1", "monotonic_ms": 330},
            {"event": "supervisor_context_built", "supervisor_call_id": "sup_1", "estimated_tokens": 20, "truncated_sections": []},
            {"event": "supervisor_call_started", "supervisor_call_id": "sup_1", "monotonic_ms": 400},
            {
                "event": "token_usage_updated",
                "role": "supervisor",
                "supervisor_call_id": "sup_1",
                "usage": {"input_tokens": 10, "cached_input_tokens": 0, "output_tokens": 5, "total_tokens": 15},
            },
            {"event": "supervisor_call_finished", "supervisor_call_id": "sup_1", "monotonic_ms": 460},
            {"event": "coder_action_completed", "monotonic_ms": 500},
            {
                "event": "token_usage_updated",
                "role": "coder",
                "usage": {"input_tokens": 2, "cached_input_tokens": 0, "output_tokens": 1, "total_tokens": 3},
            },
            {"event": "run_finished", "monotonic_ms": 1000},
        ],
    )

    metrics = compute_bench_metrics(state_dir, validation_time_ms=7)

    assert metrics["wall_time_ms"] == 1000
    assert metrics["startup_time_ms"] == 100
    assert metrics["time_to_first_action_ms"] == 150
    assert metrics["approval_wait_time_ms"] == 30
    assert metrics["supervisor_wait_time_ms"] == 60
    assert metrics["completed_coder_action_count"] == 1
    assert metrics["supervisor_context_tokens_total_est"] == 20
    assert metrics["total_tokens"] == 18
    assert metrics["supervisor_token_share"] == pytest.approx(15 / 18)


def test_write_aggregate_result_uses_current_run_and_skips_nulls(tmp_path: Path) -> None:
    tests_dir = tmp_path / "TESTS"
    for name in ("1", "2", "10"):
        (tests_dir / name).mkdir(parents=True)
    _write_json(
        tests_dir / "1" / "result.json",
        {"run_id": "run", "success": 1, "metrics": {"wall_time_ms": 10, "coder_total_tokens": None}},
    )
    _write_json(
        tests_dir / "2" / "result.json",
        {"run_id": "run", "success": 0, "metrics": {"wall_time_ms": 30, "coder_total_tokens": 12}},
    )
    _write_json(
        tests_dir / "10" / "result.json",
        {"run_id": "old", "success": 1, "metrics": {"wall_time_ms": 1000}},
    )

    now = utc_now()
    aggregate = write_aggregate_result(tests_dir, run_id="run", started_at=now, finished_at=now, root=tmp_path)

    assert aggregate["test_count"] == 3
    assert aggregate["completed_count"] == 2
    assert aggregate["failed_count"] == 1
    assert aggregate["means"]["success"] == 0.5
    assert aggregate["means"]["wall_time_ms"] == 20
    assert aggregate["means"]["coder_total_tokens"] == 12


def test_clear_test_directory_preserves_only_task(tmp_path: Path) -> None:
    test_dir = tmp_path / "1"
    test_dir.mkdir()
    (test_dir / "TASK.md").write_text("# Task\n", encoding="utf-8")
    (test_dir / "bench.json").write_text("{}", encoding="utf-8")
    (test_dir / "result.json").write_text("{}", encoding="utf-8")
    (test_dir / ".supervisor").mkdir()
    (test_dir / ".supervisor" / "config.json").write_text("{}", encoding="utf-8")
    (test_dir / "output.txt").write_text("generated", encoding="utf-8")

    clear_test_directory(test_dir)

    assert sorted(path.name for path in test_dir.iterdir()) == ["TASK.md"]


def test_load_test_prompts_accepts_string_and_line_lists(tmp_path: Path) -> None:
    prompt_dir = tmp_path / "tests"
    prompt_dir.mkdir()
    _write_json(
        prompt_dir / TEST_PROMPTS_FILENAME,
        {"1": ["# Task", "", "Do it"], "2": "Plain task"},
    )

    assert load_test_prompts(tmp_path) == {"1": "# Task\n\nDo it\n", "2": "Plain task\n"}


@pytest.mark.asyncio
async def test_runner_writes_invalid_test_result_without_task(tmp_path: Path) -> None:
    test_dir = tmp_path / "TESTS" / "1"
    test_dir.mkdir(parents=True)

    result = await BenchRunner(tmp_path).run_case(BenchCase(test_id="1", test_dir=test_dir), run_id="run")

    assert result["status"] == "invalid_test"
    assert result["success"] == 0
    assert result["error"] == "TASK.md is missing"
    assert json.loads((test_dir / "result.json").read_text(encoding="utf-8"))["status"] == "invalid_test"


@pytest.mark.asyncio
async def test_runner_writes_current_result_before_reraising_cancellation(tmp_path: Path) -> None:
    test_dir = tmp_path / "TESTS" / "1"
    test_dir.mkdir(parents=True)
    (test_dir / "TASK.md").write_text("# Task\n", encoding="utf-8")

    runner = BenchRunner(tmp_path, controller_factory=CancelledController)

    with pytest.raises(asyncio.CancelledError):
        await runner.run_case(BenchCase(test_id="1", test_dir=test_dir), run_id="run")

    result = json.loads((test_dir / "result.json").read_text(encoding="utf-8"))
    assert result["run_id"] == "run"
    assert result["status"] == "crashed"
    assert result["success"] == 0
    assert result["error"] == "CancelledError"


@pytest.mark.asyncio
async def test_runner_updates_task_from_test_prompts_before_case(tmp_path: Path) -> None:
    tests_dir = tmp_path / "TESTS"
    test_dir = tests_dir / "1"
    test_dir.mkdir(parents=True)
    (test_dir / "TASK.md").write_text("stale task\n", encoding="utf-8")
    (test_dir / "old_output.txt").write_text("old run\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    _write_json(
        tmp_path / "tests" / TEST_PROMPTS_FILENAME,
        {"1": ["# Task", "", "Fresh task"]},
    )

    aggregate = await BenchRunner(tmp_path, controller_factory=FakeController).run()

    assert (test_dir / "TASK.md").read_text(encoding="utf-8") == "# Task\n\nFresh task\n"
    assert not (test_dir / "old_output.txt").exists()
    assert aggregate["means"]["success"] == 1


@pytest.mark.asyncio
async def test_runner_creates_missing_test_directories_from_prompts(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    _write_json(
        tmp_path / "tests" / TEST_PROMPTS_FILENAME,
        {"1": "# Task 1\n", "2": "# Task 2\n"},
    )

    aggregate = await BenchRunner(tmp_path, controller_factory=FakeController).run()

    assert (tmp_path / "TESTS" / "1" / "TASK.md").read_text(encoding="utf-8") == "# Task 1\n"
    assert (tmp_path / "TESTS" / "2" / "TASK.md").read_text(encoding="utf-8") == "# Task 2\n"
    assert aggregate["completed_count"] == 2


@pytest.mark.asyncio
async def test_runner_writes_all_tasks_before_first_case_runs(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    _write_json(
        tmp_path / "tests" / TEST_PROMPTS_FILENAME,
        {"1": "# Task 1", "2": "# Task 2"},
    )

    aggregate = await BenchRunner(tmp_path, controller_factory=SiblingTaskPreparedController).run()

    assert aggregate["completed_count"] == 2


@pytest.mark.asyncio
async def test_runner_requires_prompt_for_each_existing_numeric_case(tmp_path: Path) -> None:
    tests_dir = tmp_path / "TESTS"
    for test_id in ("1", "2"):
        (tests_dir / test_id).mkdir(parents=True)
    (tmp_path / "tests").mkdir()
    _write_json(
        tmp_path / "tests" / TEST_PROMPTS_FILENAME,
        {"1": "# Task\n"},
    )

    with pytest.raises(BenchmarkError, match="missing prompts for tests: 2"):
        await BenchRunner(tmp_path, controller_factory=FakeController).run()


@pytest.mark.asyncio
async def test_runner_creates_missing_prompt_file_then_requires_prompts(tmp_path: Path) -> None:
    with pytest.raises(BenchmarkError, match="tests/TEST_PROMPTS.json has no prompts"):
        await BenchRunner(tmp_path, controller_factory=FakeController).run()

    assert (tmp_path / "TESTS").is_dir()
    assert json.loads((tmp_path / "tests" / TEST_PROMPTS_FILENAME).read_text(encoding="utf-8")) == {}


@pytest.mark.asyncio
async def test_runner_invokes_controller_inside_test_directory(tmp_path: Path) -> None:
    test_dir = tmp_path / "TESTS" / "1"
    test_dir.mkdir(parents=True)
    (test_dir / "TASK.md").write_text("# Task\n", encoding="utf-8")
    (test_dir / "stale.txt").write_text("old run", encoding="utf-8")
    (test_dir / ".supervisor").mkdir()
    (test_dir / ".supervisor" / "old.json").write_text("{}", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    _write_json(tmp_path / "tests" / TEST_PROMPTS_FILENAME, {"1": "# Task\n"})

    aggregate = await BenchRunner(tmp_path, controller_factory=FakeController).run()
    result = json.loads((test_dir / "result.json").read_text(encoding="utf-8"))

    assert result["status"] == "success"
    assert result["success"] == 1
    assert result["test_dir"] == "TESTS/1"
    assert not (test_dir / "stale.txt").exists()
    assert not (test_dir / ".supervisor" / "old.json").exists()
    assert aggregate["means"]["success"] == 1


class FakeController:
    def __init__(self, project_root: Path, **kwargs: Any):
        self.project_root = project_root.resolve()
        self.task_path = self.project_root / "TASK.md"
        self.bench_recorder = kwargs["bench_recorder"]

    async def run(self) -> None:
        assert Path.cwd().resolve() == self.project_root
        store = StateStore(self.project_root)
        store.initialize_sentinel(
            SentinelConfig(
                project_root=str(self.project_root),
                task_path=str(self.task_path),
                status=SentinelStatus.COMPLETE,
            ),
            overwrite=True,
        )
        self.bench_recorder.record("appserver_started")
        self.bench_recorder.record("appserver_initialized")
        self.bench_recorder.set_coder_thread("coder")
        self.bench_recorder.record("coder_thread_started", thread_id="coder")
        self.bench_recorder.record("coder_turn_started", thread_id="coder", turn_id="turn")
        store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"status": SentinelStatus.COMPLETE}))


class SiblingTaskPreparedController(FakeController):
    async def run(self) -> None:
        if self.project_root.name == "1":
            sibling_task = self.project_root.parent / "2" / "TASK.md"
            assert sibling_task.read_text(encoding="utf-8") == "# Task 2\n"
        await super().run()


class CancelledController:
    def __init__(self, project_root: Path, **kwargs: Any):
        self.project_root = project_root.resolve()

    async def run(self) -> None:
        assert Path.cwd().resolve() == self.project_root
        raise asyncio.CancelledError


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
