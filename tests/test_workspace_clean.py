from __future__ import annotations

from pathlib import Path

import pytest

from supervisor.workspace_clean import WorkspaceCleanError, clean_workspace_except_task


def test_clean_workspace_removes_everything_except_task(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("remove", encoding="utf-8")
    (tmp_path / ".supervisor").mkdir()
    (tmp_path / ".supervisor" / "config.json").write_text("{}", encoding="utf-8")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "artifact.txt").write_text("remove", encoding="utf-8")

    removed = clean_workspace_except_task(tmp_path, task)

    assert task.exists()
    assert sorted(path.name for path in tmp_path.iterdir()) == ["TASK.md"]
    assert {path.name for path in removed} == {"notes.txt", ".supervisor", "build"}


def test_clean_workspace_preserves_nested_task_parents(tmp_path: Path) -> None:
    tasks_dir = tmp_path / "tasks"
    tasks_dir.mkdir()
    task = tasks_dir / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    (tasks_dir / "old.md").write_text("remove", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("remove", encoding="utf-8")

    clean_workspace_except_task(tmp_path, task)

    assert task.exists()
    assert sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*")) == [
        "tasks",
        "tasks/TASK.md",
    ]


def test_clean_workspace_rejects_task_outside_root(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    other = outside / "TASK.md"
    other.write_text("# Task", encoding="utf-8")

    with pytest.raises(WorkspaceCleanError):
        clean_workspace_except_task(workspace, other)
