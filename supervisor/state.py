from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, TypeVar

import fcntl
from pydantic import BaseModel

from supervisor.schemas import DecisionLogEntry, HealthState, PendingIntervention, RunConfig

T = TypeVar("T")

STATE_DIR_NAME = ".supervisor"
CONFIG = "config.json"
PROGRESS = "PROGRESS.md"
DECISIONS = "DECISIONS.md"
LAST_ACTION = "LAST_ACTION.md"
PENDING = "PENDING_INTERVENTION.md"
HEALTH = "HEALTH.json"
HANDOFF = "HANDOFF.md"
LOG = "log.jsonl"
AGENT_SETTINGS = "agent-settings.json"


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

    def read_json(self, name: str, default: Any) -> Any:
        path = self.path(name)
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))

    def write_json_locked(self, name: str, data: Any) -> None:
        with self.locked(name):
            self.atomic_write_json(self.path(name), data)

    def initialize(self, config: RunConfig, overwrite: bool = False) -> None:
        files = {
            CONFIG: config,
            HEALTH: HealthState(generation=config.generation, restart_count=config.restart_count),
            PROGRESS: "# Progress\n\n- Current step: not started\n- Completed steps: none\n- Known issues: none\n",
            DECISIONS: "# Decisions\n\n",
            LAST_ACTION: "",
            PENDING: "",
            LOG: "",
        }
        for name, value in files.items():
            path = self.path(name)
            if path.exists() and not overwrite:
                continue
            if isinstance(value, BaseModel):
                self.atomic_write_json(path, value)
            else:
                self.atomic_write_text(path, value)

    def get_config(self) -> RunConfig:
        return RunConfig.model_validate(self.read_json(CONFIG, {}))

    def update_config(self, patcher: Callable[[RunConfig], RunConfig]) -> RunConfig:
        with self.locked(CONFIG):
            config = self.get_config()
            updated = patcher(config)
            self.atomic_write_json(self.path(CONFIG), updated)
            return updated

    def get_health(self) -> HealthState:
        return HealthState.model_validate(self.read_json(HEALTH, HealthState().model_dump()))

    def patch_health(self, patcher: Callable[[HealthState], HealthState]) -> HealthState:
        with self.locked(HEALTH):
            health = self.get_health()
            updated = patcher(health)
            self.atomic_write_json(self.path(HEALTH), updated)
            return updated

    def write_pending(self, pending: PendingIntervention) -> None:
        with self.locked(PENDING):
            existing = self.read_pending_unlocked()
            if existing and existing.generation == pending.generation and existing.sequence >= pending.sequence:
                return
            self.atomic_write_text(self.path(PENDING), pending.model_dump_json(indent=2) + "\n")

    def read_pending_unlocked(self) -> PendingIntervention | None:
        raw = self.read_text(PENDING, "").strip()
        if not raw:
            return None
        return PendingIntervention.model_validate_json(raw)

    def read_pending(self) -> PendingIntervention | None:
        with self.locked(PENDING):
            return self.read_pending_unlocked()

    def claim_pending(self, generation: int) -> PendingIntervention | None:
        with self.locked(PENDING):
            pending = self.read_pending_unlocked()
            if pending is None or pending.generation != generation:
                return None
            self.atomic_write_text(self.path(PENDING), "")
            return pending

    def append_log(self, entry: DecisionLogEntry) -> None:
        line = entry.model_dump_json() + "\n"
        self.append_text_locked(LOG, line)

    def write_handoff(self, content: str) -> None:
        self.write_text_locked(HANDOFF, content)

