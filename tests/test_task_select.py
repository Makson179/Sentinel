from __future__ import annotations

from pathlib import Path

import pytest

from supervisor.task_select import TaskSelectionError, resolve_task, scan_markdown_tasks, validate_task_path


def test_task_selection_ranking_and_exclusions(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "notes.md").write_text("notes", encoding="utf-8")
    (tmp_path / "PLAN.md").write_text("plan", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "TASK.md").write_text("ignore", encoding="utf-8")

    candidates = scan_markdown_tasks(tmp_path)

    assert candidates[0] == (tmp_path / "PLAN.md").resolve()
    assert all("node_modules" not in path.parts for path in candidates)


def test_validate_task_requires_markdown_inside_project(tmp_path: Path) -> None:
    task = tmp_path / "TASK.txt"
    task.write_text("no", encoding="utf-8")

    with pytest.raises(TaskSelectionError):
        validate_task_path(task, tmp_path)


def test_resolve_task_uses_selector_for_multiple_candidates(tmp_path: Path) -> None:
    (tmp_path / "TASK.md").write_text("task", encoding="utf-8")
    (tmp_path / "notes.md").write_text("notes", encoding="utf-8")

    selected = resolve_task(tmp_path, None, input_func=lambda _: "2", output_func=lambda _: None)

    assert selected.name == "notes.md"
