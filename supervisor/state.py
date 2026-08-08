from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, Literal, TypeVar

import fcntl
from pydantic import BaseModel

from supervisor.schemas import AppEvent, FinalReport, HealthState, BelloConfig
from supervisor.review_limits import normalize_review_limit_payload

T = TypeVar("T")

STATE_DIR_NAME = ".supervisor"
CONFIG = "config.json"
PROGRESS = "PROGRESS.md"
DECISIONS = "DECISIONS.md"
LAST_ACTION = "LAST_ACTION.md"
ACTION_HISTORY_LIMIT = 10
HEALTH = "HEALTH.json"
HANDOFF = "HANDOFF.md"
CODER_STATE = "coder"
CODER_CHECKLIST = f"{CODER_STATE}/CHECKLIST.md"
CODER_CHECKLIST_MAX_BYTES = 64 * 1024
FINAL_REPORT = "FINAL_REPORT.md"
LOG = "log.jsonl"
EVENTS = "events.jsonl"
SUPERVISOR_WAKES = "supervisor_wakes.jsonl"
RUNTIME_TRACE = "runtime_trace.jsonl"
RUNTIME_METRICS = "runtime_metrics.json"
AGENT_SETTINGS = "agent-settings.json"
PREVIOUS_RUNS = "previous_runs"
RECOVERY = "recovery"

INITIALIZATION_MODES = Literal["fresh", "resume"]


def require_inside_workspace(workspace: Path, path: Path) -> Path:
    workspace = workspace.resolve()
    resolved = path.resolve() if path.exists() else path.absolute().parent.resolve() / path.name
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"path escapes workspace: {path}") from exc
    return resolved


class FileLock:
    def __init__(self, path: Path):
        self.path = path
        self.fd: int | None = None

    def __enter__(self) -> "FileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None


class StateStore:
    def __init__(self, workspace: Path):
        self.workspace = workspace.resolve()
        self.state_dir = require_inside_workspace(self.workspace, self.workspace / STATE_DIR_NAME)
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def path(self, name: str) -> Path:
        return require_inside_workspace(self.workspace, self.state_dir / name)

    def lock_path(self, name: str) -> Path:
        return self.path(f"{name}.lock")

    @contextmanager
    def locked(self, name: str) -> Iterator[None]:
        with FileLock(self.lock_path(name)):
            yield

    def atomic_write_text(self, path: Path, text: str) -> None:
        require_inside_workspace(self.workspace, path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def atomic_write_json(self, path: Path, data: Any) -> None:
        if isinstance(data, BaseModel):
            text = data.model_dump_json(indent=2)
        else:
            text = json.dumps(data, indent=2, sort_keys=True)
        self.atomic_write_text(path, text + "\n")

    def read_text(self, name: str, default: str = "") -> str:
        path = self.path(name)
        if not path.exists():
            return default
        return path.read_text(encoding="utf-8")

    def write_text_locked(self, name: str, text: str) -> None:
        with self.locked(name):
            self.atomic_write_text(self.path(name), text)

    def append_text_locked(self, name: str, text: str) -> None:
        with self.locked(name):
            current = self.read_text(name, "")
            self.atomic_write_text(self.path(name), current + text)

    def read_recent_actions(self, limit: int = ACTION_HISTORY_LIMIT) -> list[str]:
        return _recent_action_lines(self.read_text(LAST_ACTION, ""), limit=limit)

    def append_recent_action(self, summary: str, limit: int = ACTION_HISTORY_LIMIT) -> None:
        if limit <= 0:
            return
        summary = " ".join(summary.strip().split())[:500]
        if not summary:
            return
        with self.locked(LAST_ACTION):
            actions = _recent_action_lines(self.read_text(LAST_ACTION, ""), limit=limit - 1)
            actions.append(summary)
            self.atomic_write_text(self.path(LAST_ACTION), "\n".join(actions[-limit:]) + "\n")

    def read_json(self, name: str, default: Any) -> Any:
        path = self.path(name)
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))

    def write_json_locked(self, name: str, data: Any) -> None:
        with self.locked(name):
            self.atomic_write_json(self.path(name), data)

    def get_health(self) -> HealthState:
        return HealthState.model_validate(self.read_json(HEALTH, HealthState().model_dump()))

    def patch_health(self, patcher: Callable[[HealthState], HealthState]) -> HealthState:
        with self.locked(HEALTH):
            health = self.get_health()
            updated = patcher(health)
            self.atomic_write_json(self.path(HEALTH), updated)
            return updated

    def write_handoff(self, content: str) -> None:
        self.write_text_locked(HANDOFF, content)

    def coder_checklist_path(self) -> Path:
        # Keep the lexical final component so validation can reject a substituted
        # symlink instead of resolving it into another supervisor state file.
        return self.state_dir / CODER_STATE / "CHECKLIST.md"

    def is_coder_checklist_path(self, raw: str | os.PathLike[str], *, cwd: Path | None = None) -> bool:
        """Match only the canonical or active-workspace-visible checklist path lexically."""
        candidate = Path(os.fspath(raw).strip().strip("'\"")).expanduser()
        if not candidate.is_absolute():
            candidate = (cwd or self.workspace) / candidate
        target = self.coder_checklist_path()
        try:
            candidate = Path(os.path.abspath(os.path.normpath(os.fspath(candidate))))
            canonical = Path(os.path.abspath(os.path.normpath(os.fspath(target))))
            visible = Path(
                os.path.abspath(os.path.normpath(os.fspath((cwd or self.workspace) / STATE_DIR_NAME / CODER_CHECKLIST)))
            )
            return candidate in {canonical, visible}
        except OSError:
            return False

    def read_coder_checklist(self) -> str | None:
        """Read a bounded, regular coder checklist without following a final symlink."""
        path = self.coder_checklist_path()
        try:
            parent_metadata = os.lstat(path.parent)
        except (FileNotFoundError, OSError):
            return None
        if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(parent_metadata.st_mode):
            return None
        try:
            path_metadata = os.lstat(path)
        except (FileNotFoundError, OSError):
            return None
        if (
            not stat.S_ISREG(path_metadata.st_mode)
            or stat.S_ISLNK(path_metadata.st_mode)
            or path_metadata.st_nlink != 1
            or path_metadata.st_size > CODER_CHECKLIST_MAX_BYTES
        ):
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except (FileNotFoundError, OSError):
            return None
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > CODER_CHECKLIST_MAX_BYTES
                or (metadata.st_dev, metadata.st_ino) != (path_metadata.st_dev, path_metadata.st_ino)
            ):
                return None
            data = bytearray()
            while len(data) <= CODER_CHECKLIST_MAX_BYTES:
                chunk = os.read(descriptor, min(16 * 1024, CODER_CHECKLIST_MAX_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > CODER_CHECKLIST_MAX_BYTES:
                return None
            return bytes(data).decode("utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        finally:
            os.close(descriptor)

    def ensure_coder_checklist(self, content: str | None = None) -> bool:
        """Ensure the coder-owned checklist is a bounded regular file.

        Returns true when the file had to be created or repaired. Existing valid
        content is left untouched unless replacement content is supplied.
        """
        path = self.coder_checklist_path()
        current = self.read_coder_checklist()
        if content is None and current is not None:
            return False
        replacement = current if content is None else content
        if replacement is None or len(replacement.encode("utf-8")) > CODER_CHECKLIST_MAX_BYTES:
            replacement = ""
        parent = path.parent
        if parent.is_symlink() or parent.exists() and not parent.is_dir():
            if parent.is_dir() and not parent.is_symlink():
                shutil.rmtree(parent)
            else:
                parent.unlink(missing_ok=True)
        parent.mkdir(parents=True, exist_ok=True)
        os.chmod(parent, 0o700)
        if path.exists() or path.is_symlink():
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
        self.atomic_write_text(path, replacement)
        os.chmod(path, 0o600)
        return True

    def initialize_bello(
        self,
        config: BelloConfig,
        overwrite: bool = False,
        *,
        mode: INITIALIZATION_MODES | None = None,
    ) -> None:
        mode = mode or ("fresh" if overwrite else "resume")
        preserved_checklist = self._same_task_checklist(config) if mode == "resume" else None
        if mode == "fresh":
            self._clear_state_dir(preserve=set())
        elif mode == "resume":
            self._clear_state_dir(preserve={EVENTS, LOG, PREVIOUS_RUNS, RECOVERY})
        else:
            raise ValueError(f"unknown bello initialization mode: {mode}")

        files = self._initial_state_files(config)
        files[CODER_CHECKLIST] = preserved_checklist or ""
        for name, value in files.items():
            if name == CODER_CHECKLIST:
                continue
            path = self.path(name)
            if name in {EVENTS, LOG} and mode == "resume" and path.exists():
                continue
            if isinstance(value, BaseModel):
                self.atomic_write_json(path, value)
            else:
                self.atomic_write_text(path, value)
        self.ensure_coder_checklist(files[CODER_CHECKLIST])
        self.ensure_previous_runs_dir()

    def _same_task_checklist(self, config: BelloConfig) -> str | None:
        try:
            existing = self.read_json(CONFIG, {})
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(existing, dict):
            return None
        if _bello_task_location(existing) != _bello_task_location(config.model_dump()):
            return None
        old_hash = existing.get("task_hash")
        new_hash = config.task_hash
        if old_hash or new_hash:
            if not isinstance(old_hash, str) or not isinstance(new_hash, str) or old_hash != new_hash:
                return None
        elif existing.get("task_path") != config.task_path:
            return None
        return self.read_coder_checklist()

    def _initial_state_files(self, config: BelloConfig) -> dict[str, Any]:
        return {
            CONFIG: config,
            HEALTH: HealthState(generation=config.generation, restart_count=config.restart_count),
            PROGRESS: "# Progress\n\n- Current step: not started\n- Completed steps: none\n- Known issues: none\n",
            DECISIONS: "# Decisions\n\n",
            LAST_ACTION: "",
            HANDOFF: "",
            CODER_CHECKLIST: "",
            FINAL_REPORT: "",
            LOG: "",
            EVENTS: "",
            SUPERVISOR_WAKES: "",
            RUNTIME_TRACE: "",
            RUNTIME_METRICS: "{}\n",
        }

    def _clear_state_dir(self, *, preserve: set[str]) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        for child in self.state_dir.iterdir():
            if child.name in preserve:
                continue
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink(missing_ok=True)

    def ensure_previous_runs_dir(self) -> Path:
        path = self.path(PREVIOUS_RUNS)
        if path.exists() and not path.is_dir():
            path.unlink()
        path.mkdir(parents=True, exist_ok=True)
        return path

    def next_recovery_dir(self) -> Path:
        recovery = self.path(RECOVERY)
        if recovery.exists() and not recovery.is_dir():
            recovery.unlink()
        recovery.mkdir(parents=True, exist_ok=True)
        max_run = 0
        for child in recovery.iterdir():
            if not child.is_dir() or not child.name.startswith("run"):
                continue
            suffix = child.name[3:]
            if suffix.isdigit():
                max_run = max(max_run, int(suffix))
        return recovery / f"run{max_run + 1}"

    def archive_completed_run(self, task_path: Path) -> Path:
        previous_runs = self.ensure_previous_runs_dir()
        run_dir = self._next_previous_run_dir(previous_runs)
        run_dir.mkdir()
        task_source = require_inside_workspace(self.workspace, task_path)
        final_report_source = self.path(FINAL_REPORT)
        shutil.copyfile(task_source, run_dir / "task.md")
        shutil.copyfile(final_report_source, run_dir / FINAL_REPORT)
        return run_dir

    def _next_previous_run_dir(self, previous_runs: Path) -> Path:
        max_run = 0
        for child in previous_runs.iterdir():
            if not child.is_dir() or not child.name.startswith("run"):
                continue
            suffix = child.name[3:]
            if suffix.isdigit():
                max_run = max(max_run, int(suffix))
        return previous_runs / f"run{max_run + 1}"

    def get_bello_config(self) -> BelloConfig:
        return BelloConfig.model_validate(normalize_review_limit_payload(self.read_json(CONFIG, {})))

    def update_bello_config(self, patcher: Callable[[BelloConfig], BelloConfig]) -> BelloConfig:
        with self.locked(CONFIG):
            config = self.get_bello_config()
            updated = patcher(config)
            self.atomic_write_json(self.path(CONFIG), updated)
            return updated

    def append_event(self, event: AppEvent) -> None:
        self.append_text_locked(EVENTS, event.model_dump_json() + "\n")

    def max_event_sequence(self) -> int:
        max_sequence = 0
        for line in self.read_text(EVENTS, "").splitlines():
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            sequence = payload.get("sequence")
            if isinstance(sequence, int) and sequence > max_sequence:
                max_sequence = sequence
        return max_sequence

    def append_raw_log(self, entry: dict[str, Any]) -> None:
        self.append_text_locked(LOG, json.dumps(entry, default=str, sort_keys=True) + "\n")

    def append_supervisor_wake(self, entry: dict[str, Any]) -> None:
        self.append_text_locked(SUPERVISOR_WAKES, json.dumps(entry, default=str, sort_keys=True) + "\n")

    def append_runtime_trace(self, entry: dict[str, Any]) -> None:
        self.append_text_locked(RUNTIME_TRACE, json.dumps(entry, default=str, sort_keys=True) + "\n")

    def update_runtime_metrics(self, patcher: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
        with self.locked(RUNTIME_METRICS):
            current = self.read_json(RUNTIME_METRICS, {})
            if not isinstance(current, dict):
                current = {}
            updated = patcher(dict(current))
            self.atomic_write_json(self.path(RUNTIME_METRICS), updated)
            return updated

    def read_recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        raw = self.read_text(EVENTS, "")
        lines = [line for line in raw.splitlines() if line.strip()]
        selected = lines[-limit:]
        events: list[dict[str, Any]] = []
        for line in selected:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events

    def write_final_report(self, report: FinalReport | str) -> None:
        if isinstance(report, FinalReport):
            status = report.status.value if hasattr(report.status, "value") else str(report.status)
            lines = [
                "# Final Report",
                "",
                f"- Task: {report.task_path}",
                f"- Status: {status}",
                f"- Result: {report.result}",
                f"- Restarts: {report.restarts}",
                f"- Interventions: {report.interventions}",
                f"- Completion review accepted: {str(report.completion_review_accepted).lower()}",
                f"- Completion returns: {report.completion_returns}",
                f"- Completion restarts: {report.completion_restarts}",
                f"- No-marker idle nudges: {report.no_marker_idle_nudges}",
            ]
            if report.files_changed:
                lines.extend(["", "## Files Changed", *[f"- {path}" for path in report.files_changed]])
            if report.validations:
                lines.extend(["", "## Validations", *[f"- {item}" for item in report.validations]])
            if report.behavior_evidence_summary:
                lines.extend(["", "## Completion Behavior Evidence", *[f"- {item}" for item in report.behavior_evidence_summary]])
            if report.files_reviewed_summary:
                lines.extend(["", "## Completion Files Reviewed", *[f"- {item}" for item in report.files_reviewed_summary]])
            if report.packet_or_access_limitations:
                lines.extend(["", "## Packet Or Access Limitations", *[f"- {item}" for item in report.packet_or_access_limitations]])
            if report.adversary_reports:
                lines.extend(["", "## Adversary Reports", *[f"- {item}" for item in report.adversary_reports]])
            if report.adversary_coverage_limitations:
                lines.extend(
                    [
                        "",
                        "## Adversary Coverage Limitations",
                        *[f"- {item}" for item in report.adversary_coverage_limitations],
                    ]
                )
            if report.denied_actions:
                lines.extend(["", "## Denied Actions", *[f"- {item}" for item in report.denied_actions]])
            if report.remaining_risks:
                lines.extend(["", "## Remaining Risks", *[f"- {item}" for item in report.remaining_risks]])
            if report.diff_summary:
                lines.extend(["", "## Diff Summary", "", "```text", report.diff_summary.strip(), "```"])
            self.write_text_locked(FINAL_REPORT, "\n".join(lines).rstrip() + "\n")
        else:
            self.write_text_locked(FINAL_REPORT, report)


def _bello_task_location(config: dict[str, Any]) -> tuple[Path, Path] | None:
    raw_root = config.get("project_root")
    raw_task = config.get("task_path") or config.get("task")
    if not isinstance(raw_root, str) or not raw_root.strip() or not isinstance(raw_task, str) or not raw_task.strip():
        return None
    try:
        root = Path(raw_root).expanduser().resolve(strict=False)
        task = Path(raw_task).expanduser()
        if not task.is_absolute():
            task = root / task
        return root, task.resolve(strict=False)
    except OSError:
        return None


def _recent_action_lines(text: str, *, limit: int) -> list[str]:
    if limit <= 0:
        return []
    return [line.strip() for line in text.splitlines() if line.strip()][-limit:]
