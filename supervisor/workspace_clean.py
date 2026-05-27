from __future__ import annotations

import shutil
from pathlib import Path


class WorkspaceCleanError(RuntimeError):
    pass


def clean_workspace_except_task(project_root: Path, task_path: Path) -> list[Path]:
    root = project_root.resolve()
    task = task_path.resolve()
    if not task.is_file():
        raise WorkspaceCleanError(f"task file does not exist: {task_path}")
    try:
        task.relative_to(root)
    except ValueError as exc:
        raise WorkspaceCleanError(f"task file must be inside project root: {task_path}") from exc

    removed: list[Path] = []
    _clean_dir(root, task, removed)
    return removed


def _clean_dir(directory: Path, task: Path, removed: list[Path]) -> None:
    for child in directory.iterdir():
        if _same_path(child, task):
            continue
        if child.is_dir() and not child.is_symlink() and _contains_path(child, task):
            _clean_dir(child, task, removed)
            continue
        _remove_entry(child)
        removed.append(child)


def _contains_path(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return False


def _remove_entry(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()
