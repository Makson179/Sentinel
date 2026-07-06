from __future__ import annotations

from pathlib import Path

import pytest

from supervisor.schemas import SentinelConfig
from supervisor.state import StateStore


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "TASK.md").write_text("# Task\n\nDo the work.\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def store(workspace: Path) -> StateStore:
    config = SentinelConfig(project_root=str(workspace), task_path=str(workspace / "TASK.md"))
    state = StateStore(workspace)
    state.initialize_sentinel(config, overwrite=True)
    return state
