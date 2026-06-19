from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from supervisor.schemas import Certainty


class WorkspaceFileState(BaseModel):
    path: str
    status: str
    mode: str | None = None
    content_hash: str | None = None
    staged_blob_hash: str | None = None
    symlink_target: str | None = None
    deleted: bool = False
    rename_source: str | None = None


class WorkspaceState(BaseModel):
    state_id: str | None = None
    certainty: Certainty = Certainty.UNKNOWN
    head: str | None = None
    files: list[WorkspaceFileState] = Field(default_factory=list)
    unknown_reasons: list[str] = Field(default_factory=list)

    @property
    def is_known(self) -> bool:
        return self.certainty is Certainty.TRUE and self.state_id is not None


def capture_workspace_state(project_root: Path) -> WorkspaceState:
    root = project_root.resolve()
    if not _is_git_work_tree(root):
        return WorkspaceState(certainty=Certainty.UNKNOWN, unknown_reasons=["not_a_git_work_tree"])

    head = _git_output(root, ["git", "rev-parse", "--verify", "HEAD"])
    if head is None:
        head = "<no-commit>"
    status_before = _git_output(root, ["git", "status", "--porcelain=v2", "--untracked-files=all"])
    if status_before is None:
        return WorkspaceState(certainty=Certainty.UNKNOWN, head=head, unknown_reasons=["git_status_failed"])

    parsed = _parse_porcelain_v2(status_before)
    filtered_status_before = _filtered_status_payload(parsed)
    unknown_reasons: list[str] = []
    files: list[WorkspaceFileState] = []
    for entry in parsed:
        path = entry["path"]
        if _is_ignored_state_path(path):
            continue
        file_state, reason = _file_state(root, path, status=entry["status"], rename_source=entry.get("rename_source"))
        if reason is not None:
            unknown_reasons.append(reason)
        files.append(file_state)

    status_after = _git_output(root, ["git", "status", "--porcelain=v2", "--untracked-files=all"])
    if status_after is None:
        unknown_reasons.append("git_status_verify_failed")
    elif _filtered_status_payload(_parse_porcelain_v2(status_after)) != filtered_status_before:
        unknown_reasons.append("workspace_changed_during_capture")

    files = sorted(files, key=lambda item: (item.path, item.status, item.rename_source or ""))
    if unknown_reasons:
        return WorkspaceState(
            certainty=Certainty.UNKNOWN,
            head=head,
            files=files,
            unknown_reasons=list(dict.fromkeys(unknown_reasons)),
        )

    payload = {
        "head": head,
        "status": filtered_status_before,
        "files": [file.model_dump(mode="json") for file in files],
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return WorkspaceState(state_id=f"workspace-{digest[:32]}", certainty=Certainty.TRUE, head=head, files=files)


async def capture_workspace_state_async(project_root: Path) -> WorkspaceState:
    return await asyncio.to_thread(capture_workspace_state, project_root)


def _is_git_work_tree(root: Path) -> bool:
    return _git_output(root, ["git", "rev-parse", "--is-inside-work-tree"]) == "true"


def _git_output(root: Path, command: list[str]) -> str | None:
    try:
        completed = subprocess.run(command, cwd=root, text=True, capture_output=True, timeout=5, check=False)
    except Exception:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.rstrip("\n")


def _parse_porcelain_v2(text: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for line in text.splitlines():
        if not line or line.startswith("#") or line.startswith("! "):
            continue
        if line.startswith("? "):
            entries.append({"status": "?", "path": line[2:].strip()})
            continue
        if line.startswith("1 "):
            parts = line.split(" ", 8)
            if len(parts) == 9:
                entries.append({"status": parts[1], "path": parts[8].strip()})
            continue
        if line.startswith("2 "):
            parts = line.split(" ", 9)
            if len(parts) == 10:
                path_part = parts[9]
                if "\t" in path_part:
                    path, rename_source = path_part.split("\t", 1)
                else:
                    path, rename_source = path_part, None
                entry = {"status": parts[1], "path": path.strip()}
                if rename_source:
                    entry["rename_source"] = rename_source.strip()
                entries.append(entry)
            continue
        fallback = line[2:].strip() if len(line) > 3 else line.strip()
        if fallback:
            entries.append({"status": line[:2].strip() or "modified", "path": fallback})
    return entries




def _filtered_status_payload(entries: list[dict[str, str]]) -> list[dict[str, str]]:
    return sorted(
        (dict(entry) for entry in entries if not _is_ignored_state_path(entry.get("path", ""))),
        key=lambda item: (item.get("path", ""), item.get("status", ""), item.get("rename_source", "")),
    )

def _file_state(
    root: Path,
    rel_path: str,
    *,
    status: str,
    rename_source: str | None,
) -> tuple[WorkspaceFileState, str | None]:
    normalized = rel_path.replace("\\", "/").lstrip("./")
    base = WorkspaceFileState(path=normalized, status=status, rename_source=rename_source)
    if not normalized or Path(normalized).is_absolute() or any(part == ".." for part in Path(normalized).parts):
        return base, f"unsafe_path:{rel_path}"
    candidate = root / normalized
    try:
        st = candidate.lstat()
    except FileNotFoundError:
        return base.model_copy(update={"deleted": True}), None
    except OSError as exc:
        return base, f"stat_failed:{normalized}:{exc.__class__.__name__}"

    mode = oct(stat.S_IMODE(st.st_mode))
    staged_blob = _staged_blob_hash(root, normalized)
    if stat.S_ISLNK(st.st_mode):
        try:
            target = os.readlink(candidate)
        except OSError as exc:
            return base.model_copy(update={"mode": mode, "staged_blob_hash": staged_blob}), f"readlink_failed:{normalized}:{exc.__class__.__name__}"
        if _symlink_escapes(root, candidate.parent, target):
            return (
                base.model_copy(update={"mode": mode, "symlink_target": target, "staged_blob_hash": staged_blob}),
                f"unsafe_symlink:{normalized}",
            )
        return base.model_copy(update={"mode": mode, "symlink_target": target, "staged_blob_hash": staged_blob}), None
    if stat.S_ISREG(st.st_mode):
        digest, reason = _hash_regular_file(candidate)
        return base.model_copy(update={"mode": mode, "content_hash": digest, "staged_blob_hash": staged_blob}), reason
    if stat.S_ISDIR(st.st_mode):
        return base.model_copy(update={"mode": mode, "staged_blob_hash": staged_blob}), None
    return base.model_copy(update={"mode": mode, "staged_blob_hash": staged_blob}), f"unsupported_file_type:{normalized}"


def _hash_regular_file(path: Path) -> tuple[str | None, str | None]:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        return None, f"hash_failed:{path.name}:{exc.__class__.__name__}"
    return digest.hexdigest(), None


def _staged_blob_hash(root: Path, path: str) -> str | None:
    output = _git_output(root, ["git", "ls-files", "-s", "--", path])
    if not output:
        return None
    first = output.splitlines()[0].split()
    if len(first) >= 2:
        return first[1]
    return None


def _symlink_escapes(root: Path, parent: Path, target: str) -> bool:
    target_path = Path(target)
    if target_path.is_absolute():
        resolved = target_path.resolve(strict=False)
    else:
        resolved = (parent / target_path).resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError:
        return True
    return False


def _is_ignored_state_path(path: str) -> bool:
    normalized = path.replace("\\", "/").strip("/").lower()
    if not normalized:
        return True
    if normalized == ".supervisor" or normalized.startswith(".supervisor/") or normalized == ".git-init.log":
        return True
    parts = set(normalized.split("/"))
    return bool(
        parts
        & {
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            ".tox",
            ".cache",
            ".next",
            ".parcel-cache",
            "node_modules",
            "vendor",
            "dist",
            "build",
            "target",
            "coverage",
        }
    )
