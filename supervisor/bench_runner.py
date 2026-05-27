from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from supervisor.appserver import AppServerError, AppServerMessage
from supervisor.bench_context import supervisor_context_event
from supervisor.bench_metrics import PERF, compute_bench_metrics
from supervisor.bench_results import display_path, iso_z, numeric_test_dirs, utc_now, write_aggregate_result, write_per_test_result
from supervisor.bench_tokens import extract_token_usage
from supervisor.controller import SentinelController
from supervisor.schemas import SentinelStatus, SupervisorWakePacket
from supervisor.state import CONFIG, STATE_DIR_NAME
from supervisor.tui import UserCommand


DEFAULT_TIMEOUT_SECONDS = 1800
TEST_PROMPTS_DIR_NAME = "tests"
TEST_PROMPTS_FILENAME = "TEST_PROMPTS.json"


class BenchmarkError(RuntimeError):
    pass


@dataclass(frozen=True)
class BenchCaseConfig:
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    validation: tuple[str, ...] = ()


@dataclass(frozen=True)
class BenchCase:
    test_id: str
    test_dir: Path

    @property
    def task_file(self) -> Path:
        return self.test_dir / "TASK.md"


class BenchTUI:
    def __init__(self, test_id: str):
        self.test_id = test_id
        self.input_queue: asyncio.Queue[UserCommand] = asyncio.Queue()

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    def render(self, lane: str, message: str, *, payload: dict[str, Any] | None = None) -> None:
        prefix = lane if lane.startswith("[") else f"[{lane}]"
        print(f"[BENCH {self.test_id}] {prefix} {message}", flush=True)

    def status(self, message: str) -> None:
        self.render("SYSTEM", message)


class BenchRecorder:
    def __init__(self, test_dir: Path, *, run_id: str):
        self.test_dir = test_dir.resolve()
        self.run_id = run_id
        self.state_dir = self.test_dir / STATE_DIR_NAME
        self.path = self.state_dir / PERF
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        self.origin = time.monotonic()
        self._supervisor_call_count = 0
        self._validation_count = 0
        self._restart_count = 0
        self._first_action_seen = False
        self.coder_thread_id: str | None = None
        self._supervisor_threads: dict[str, str] = {}
        self._thread_calls: dict[str, str] = {}

    def record(self, event: str, **payload: Any) -> None:
        entry = {"event": event, **payload}
        self._write(entry)

    def record_supervisor_context(self, packet: SupervisorWakePacket) -> str:
        self._supervisor_call_count += 1
        call_id = f"sup_{self._supervisor_call_count}"
        self._write(supervisor_context_event(packet, supervisor_call_id=call_id))
        return call_id

    def register_supervisor_thread(self, supervisor_call_id: str, thread_id: str) -> None:
        self._supervisor_threads[supervisor_call_id] = thread_id
        self._thread_calls[thread_id] = supervisor_call_id

    def set_coder_thread(self, thread_id: str) -> None:
        self.coder_thread_id = thread_id

    def record_first_coder_action_started(self, *, thread_id: str | None = None, turn_id: str | None = None, item_id: str | None = None) -> None:
        if self._first_action_seen:
            return
        self._first_action_seen = True
        self.record("first_coder_action_started", thread_id=thread_id, turn_id=turn_id, item_id=item_id)

    def record_token_usage(self, *, role: str, usage_source: Any, thread_id: str | None = None, supervisor_call_id: str | None = None) -> None:
        usage = extract_token_usage(usage_source)
        if usage is None:
            return
        self.record(
            "token_usage_updated",
            role=role,
            thread_id=thread_id,
            supervisor_call_id=supervisor_call_id,
            usage=usage,
        )

    def record_message_token_usage(self, message: AppServerMessage) -> None:
        thread_id = _thread_id_from_message(message)
        if thread_id is None:
            return
        if thread_id == self.coder_thread_id:
            self.record_token_usage(role="coder", usage_source=message.raw, thread_id=thread_id)
            return
        call_id = self._thread_calls.get(thread_id)
        if call_id:
            self.record_token_usage(
                role="supervisor",
                usage_source=message.raw,
                thread_id=thread_id,
                supervisor_call_id=call_id,
            )

    def next_validation_id(self) -> str:
        self._validation_count += 1
        return f"val_{self._validation_count}"

    def next_restart_id(self) -> str:
        self._restart_count += 1
        return f"restart_{self._restart_count}"

    def _write(self, entry: dict[str, Any]) -> None:
        enriched = {
            "timestamp": iso_z(utc_now()),
            "monotonic_ms": int((time.monotonic() - self.origin) * 1000),
            "run_id": self.run_id,
            **entry,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(enriched, sort_keys=True, default=str) + "\n")


ControllerFactory = Callable[..., SentinelController]


class BenchRunner:
    def __init__(
        self,
        project_root: Path,
        *,
        model: str | None = None,
        controller_factory: ControllerFactory = SentinelController,
    ):
        self.project_root = project_root.resolve()
        self.tests_dir = self.project_root / "TESTS"
        self.model = model
        self.controller_factory = controller_factory

    async def run(self) -> dict[str, Any]:
        self.tests_dir.mkdir(parents=True, exist_ok=True)
        test_prompts = load_test_prompts(self.project_root)
        ensure_bench_case_dirs(self.tests_dir, test_prompts)
        cases = discover_bench_tests(self.tests_dir)
        validate_bench_cases(cases, test_prompts)
        prepare_bench_cases(cases, test_prompts)

        run_id = new_run_id()
        started_at = utc_now()
        for case in cases:
            print(f"[BENCH] running TESTS/{case.test_id}", flush=True)
            await self.run_case(case, run_id=run_id)
        finished_at = utc_now()
        return write_aggregate_result(
            self.tests_dir,
            run_id=run_id,
            started_at=started_at,
            finished_at=finished_at,
            root=self.project_root,
        )

    async def run_case(
        self,
        case: BenchCase,
        *,
        run_id: str,
    ) -> dict[str, Any]:
        state_dir = case.test_dir / STATE_DIR_NAME
        clear_test_directory(case.test_dir)
        if state_dir.exists():
            shutil.rmtree(state_dir)
        recorder = BenchRecorder(case.test_dir, run_id=run_id)
        started_at = utc_now()
        recorder.record("run_started", test_id=case.test_id)
        config = BenchCaseConfig()
        validation = {"validation_pass": None, "commands": []}
        validation_time_ms = 0
        status = "crashed"
        error: str | None = None
        result: dict[str, Any] | None = None
        interrupt: BaseException | None = None
        case_started_monotonic = time.monotonic()

        try:
            config = load_case_config(case.test_dir)
            if not case.task_file.exists():
                status = "invalid_test"
                error = "TASK.md is missing"
            else:
                runtime_status, runtime_error = await self._run_sentinel_case(case, config, recorder)
                status = runtime_status
                error = runtime_error
                if status == "success":
                    remaining_timeout = config.timeout_seconds - (time.monotonic() - case_started_monotonic)
                    if remaining_timeout <= 0:
                        status = "timeout"
                        error = f"timed out after {config.timeout_seconds:g} seconds"
                    else:
                        validation, validation_time_ms, validation_timed_out = await run_validation_commands(
                            case.test_dir,
                            config.validation,
                            recorder,
                            timeout_seconds=remaining_timeout,
                        )
                        if validation_timed_out:
                            status = "timeout"
                            error = f"timed out after {config.timeout_seconds:g} seconds"
                    if status == "success" and validation["validation_pass"] is False:
                        status = "failed"
                        error = "validation failed"
        except ValueError as exc:
            status = "invalid_test"
            error = str(exc)
        except Exception as exc:
            status = "crashed"
            error = f"{exc.__class__.__name__}: {exc}"
        except BaseException as exc:
            status = "crashed"
            error = exc.__class__.__name__
            interrupt = exc
        finally:
            finished_at = utc_now()
            recorder.record("run_finished", test_id=case.test_id, status=status)
            metrics = compute_bench_metrics(state_dir, validation_time_ms=validation_time_ms)
            result = {
                "run_id": run_id,
                "test_id": case.test_id,
                "test_dir": display_path(case.test_dir, self.project_root),
                "task_file": display_path(case.task_file, self.project_root),
                "status": status,
                "success": 1 if status == "success" else 0,
                "started_at": iso_z(started_at),
                "finished_at": iso_z(finished_at),
                "metrics": metrics,
                "validation": validation,
                "error": error,
            }
            write_per_test_result(case.test_dir / "result.json", result)

        if interrupt is not None:
            raise interrupt
        assert result is not None
        return result

    async def _run_sentinel_case(
        self,
        case: BenchCase,
        config: BenchCaseConfig,
        recorder: BenchRecorder,
    ) -> tuple[str, str | None]:
        try:
            with chdir(case.test_dir):
                controller = self.controller_factory(
                    case.test_dir,
                    task_path=Path("TASK.md"),
                    model=self.model,
                    overwrite_state=True,
                    clean_workspace=False,
                    tui=BenchTUI(case.test_id),
                    bench_recorder=recorder,
                    use_git_diff=False,
                )
                await asyncio.wait_for(controller.run(), timeout=config.timeout_seconds)
            sentinel_status = _read_sentinel_status(case.test_dir)
            return _benchmark_status_from_sentinel(sentinel_status), None
        except asyncio.TimeoutError:
            return "timeout", f"timed out after {config.timeout_seconds:g} seconds"
        except AppServerError as exc:
            return "provider_failure", str(exc)
        except RuntimeError as exc:
            return "provider_failure", str(exc)


def discover_bench_tests(tests_dir: Path) -> list[BenchCase]:
    return [BenchCase(test_id=path.name, test_dir=path.resolve()) for path in numeric_test_dirs(tests_dir)]


def load_test_prompts(project_root: Path) -> dict[str, str]:
    path = project_root / TEST_PROMPTS_DIR_NAME / TEST_PROMPTS_FILENAME
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BenchmarkError(f"invalid {TEST_PROMPTS_FILENAME}: {exc}") from exc
    if not isinstance(raw, dict):
        raise BenchmarkError(f"{TEST_PROMPTS_FILENAME} must be a JSON object keyed by test id")
    prompts: dict[str, str] = {}
    for test_id, value in raw.items():
        key = str(test_id)
        if not key.isascii() or not key.isdecimal():
            raise BenchmarkError(f"{TEST_PROMPTS_FILENAME} key {key!r} must be a numeric test id")
        prompts[key] = _normalize_task_prompt(value, test_id=key)
    return prompts


def ensure_bench_case_dirs(tests_dir: Path, test_prompts: dict[str, str]) -> None:
    for test_id in _sorted_test_ids(set(test_prompts)):
        (tests_dir / test_id).mkdir(parents=True, exist_ok=True)


def validate_bench_cases(cases: list[BenchCase], test_prompts: dict[str, str]) -> None:
    if not test_prompts:
        raise BenchmarkError(f"{TEST_PROMPTS_DIR_NAME}/{TEST_PROMPTS_FILENAME} has no prompts")
    case_ids = {case.test_id for case in cases}
    prompt_ids = set(test_prompts)
    missing_prompts = _sorted_test_ids(case_ids - prompt_ids)
    if missing_prompts:
        missing_list = ", ".join(missing_prompts)
        raise BenchmarkError(f"{TEST_PROMPTS_FILENAME} is missing prompts for tests: {missing_list}")


def prepare_bench_cases(cases: list[BenchCase], test_prompts: dict[str, str]) -> None:
    for case in cases:
        clear_test_directory(case.test_dir)
        case.task_file.write_text(test_prompts[case.test_id], encoding="utf-8")


def load_case_config(test_dir: Path) -> BenchCaseConfig:
    path = test_dir / "bench.json"
    if not path.exists():
        return BenchCaseConfig()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid bench.json: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("bench.json must be a JSON object")
    timeout = raw.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("bench.json timeout_seconds must be a positive number")
    validation = raw.get("validation", [])
    if not isinstance(validation, list) or not all(isinstance(item, str) for item in validation):
        raise ValueError("bench.json validation must be a list of command strings")
    return BenchCaseConfig(timeout_seconds=float(timeout), validation=tuple(validation))


def clear_test_directory(test_dir: Path) -> None:
    preserved = {"TASK.md"}
    for child in test_dir.iterdir():
        if child.name in preserved:
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def _normalize_task_prompt(value: Any, *, test_id: str) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, list) and all(isinstance(line, str) for line in value):
        text = "\n".join(value)
    else:
        raise BenchmarkError(f"{TEST_PROMPTS_FILENAME} entry {test_id!r} must be a string or a list of strings")
    return text if text.endswith("\n") else text + "\n"


def _sorted_test_ids(test_ids: set[str]) -> list[str]:
    return sorted(test_ids, key=lambda test_id: int(test_id))


async def run_validation_commands(
    test_dir: Path,
    commands: tuple[str, ...],
    recorder: BenchRecorder,
    *,
    timeout_seconds: float | None = None,
) -> tuple[dict[str, Any], int, bool]:
    if not commands:
        return {"validation_pass": None, "commands": []}, 0, False
    results: list[dict[str, Any]] = []
    total_ms = 0
    timed_out = False
    deadline = time.monotonic() + timeout_seconds if timeout_seconds is not None else None
    for command in commands:
        validation_id = recorder.next_validation_id()
        started = time.monotonic()
        recorder.record("validation_started", validation_id=validation_id, command=command)
        exit_code: int | None = None
        error: str | None = None
        process: asyncio.subprocess.Process | None = None
        try:
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            if remaining is not None and remaining <= 0:
                raise asyncio.TimeoutError
            process = await asyncio.create_subprocess_shell(
                command,
                cwd=str(test_dir),
                env=_validation_env(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=remaining)
            exit_code = process.returncode
            if exit_code != 0:
                error = (stdout + stderr).decode("utf-8", errors="replace").strip() or f"exit code {exit_code}"
        except asyncio.TimeoutError:
            timed_out = True
            error = "validation timed out"
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
        except Exception as exc:
            error = f"{exc.__class__.__name__}: {exc}"
        duration_ms = int((time.monotonic() - started) * 1000)
        total_ms += duration_ms
        recorder.record(
            "validation_finished",
            validation_id=validation_id,
            command=command,
            exit_code=exit_code,
            duration_ms=duration_ms,
        )
        entry: dict[str, Any] = {"command": command, "exit_code": exit_code, "duration_ms": duration_ms}
        if error:
            entry["error"] = error
        results.append(entry)
        if timed_out:
            break
    return {"validation_pass": all(result.get("exit_code") == 0 for result in results), "commands": results}, total_ms, timed_out


def new_run_id(now: datetime | None = None) -> str:
    stamp = iso_z(now or utc_now()).replace(":", "-")
    return f"{stamp}_{uuid4().hex[:4]}"


def _validation_env() -> dict[str, str]:
    env = os.environ.copy()
    python_bin_dir = str(Path(sys.executable).resolve().parent)
    env["PATH"] = python_bin_dir + os.pathsep + env.get("PATH", "")
    return env


@contextmanager
def chdir(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _read_sentinel_status(test_dir: Path) -> SentinelStatus | str | None:
    path = test_dir / STATE_DIR_NAME / CONFIG
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return raw.get("status") if isinstance(raw, dict) else None


def _benchmark_status_from_sentinel(status: SentinelStatus | str | None) -> str:
    value = status.value if isinstance(status, SentinelStatus) else status
    if value == SentinelStatus.COMPLETE.value:
        return "success"
    if value == SentinelStatus.STUCK.value:
        return "stuck"
    if value == SentinelStatus.PROVIDER_FAILURE.value:
        return "provider_failure"
    return "failed"


def _thread_id_from_message(message: AppServerMessage) -> str | None:
    params = message.params
    for value in (params.get("threadId"), params.get("conversationId")):
        if isinstance(value, str):
            return value
    for key in ("thread", "turn"):
        value = params.get(key)
        if isinstance(value, dict) and isinstance(value.get("threadId"), str):
            return value["threadId"]
        if isinstance(value, dict) and isinstance(value.get("id"), str) and key == "thread":
            return value["id"]
    return None
