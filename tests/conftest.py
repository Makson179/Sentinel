from __future__ import annotations

from pathlib import Path

import pytest

from supervisor.schemas import RunConfig
from supervisor.state import StateStore


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "TASK.md").write_text("# Task\n\nDo the work.\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def store(workspace: Path) -> StateStore:
    config = RunConfig(platform="fake", plan_file_path=str(workspace / "TASK.md"))
    state = StateStore(workspace)
    state.initialize(config, overwrite=True)
    return state

