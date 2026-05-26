from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


EXCLUDED_DIRS = {".git", ".supervisor", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv"}
PREFERRED_NAMES = ["TASK.md", "task.md", "PLAN.md", "plan.md", "TODO.md"]


class TaskSelectionError(ValueError):
    pass


@dataclass(frozen=True)
class TaskCandidate:
    path: Path
    rank: int


def validate_task_path(path: Path, project_root: Path) -> Path:
    resolved = path.expanduser().resolve()
    root = project_root.resolve()
    if not resolved.exists():
        raise TaskSelectionError(f"task file does not exist: {path}")
    if not resolved.is_file():
        raise TaskSelectionError(f"task path is not a file: {path}")
    if resolved.suffix.lower() != ".md":
        raise TaskSelectionError("task file must end in .md")
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise TaskSelectionError(f"task file must be inside project root: {path}") from exc
    return resolved


def _is_excluded(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    return any(part in EXCLUDED_DIRS for part in rel.parts)


def scan_markdown_tasks(project_root: Path) -> list[Path]:
    root = project_root.resolve()
    candidates: list[TaskCandidate] = []
    for path in root.rglob("*.md"):
        if _is_excluded(path, root):
            continue
        name = path.name
        preferred_rank = PREFERRED_NAMES.index(name) if name in PREFERRED_NAMES else len(PREFERRED_NAMES)
        depth = len(path.relative_to(root).parts)
        candidates.append(TaskCandidate(path=path.resolve(), rank=preferred_rank * 1000 + depth))
    return [candidate.path for candidate in sorted(candidates, key=lambda item: (item.rank, str(item.path)))]


def resolve_task(project_root: Path, task: Path | None, *, input_func=input, output_func=print) -> Path:
    root = project_root.resolve()
    if task is not None:
        return validate_task_path(task if task.is_absolute() else root / task, root)

    candidates = scan_markdown_tasks(root)
    if not candidates:
        raise TaskSelectionError("no markdown task file found")
    if len(candidates) == 1:
        return candidates[0]

    output_func("Select task file:")
    for index, candidate in enumerate(candidates, start=1):
        output_func(f"{index}. {candidate.relative_to(root)}")
    while True:
        raw = input_func("Task number: ").strip()
        try:
            selected = int(raw)
        except ValueError:
            output_func("Enter a number from the list.")
            continue
        if 1 <= selected <= len(candidates):
            return candidates[selected - 1]
        output_func("Enter a number from the list.")
