from __future__ import annotations

from collections.abc import Sequence
import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from supervisor.policy import PolicyEngine, is_protected_path, is_supervisor_runtime_path
from supervisor.schemas import PolicyDecisionKind


SNAPSHOT_ALWAYS_IGNORE_NAMES = {
    ".git",
    ".supervisor",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
}

SNAPSHOT_READ_ONLY_DEPENDENCY_NAMES = {
    ".venv",
    "venv",
    "node_modules",
}

SNAPSHOT_RESERVED_TASK_PATH_NAMES = SNAPSHOT_ALWAYS_IGNORE_NAMES | SNAPSHOT_READ_ONLY_DEPENDENCY_NAMES

GENERATED_ARTIFACT_DIR_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
}

GENERATED_ARTIFACT_FILE_NAMES = {
    ".coverage",
    ".ds_store",
    "cmakecache.txt",
    "coverage.xml",
}

GENERATED_ARTIFACT_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".gcda",
    ".gcno",
    ".tsbuildinfo",
}


class WorkspaceSnapshotError(RuntimeError):
    pass


class SnapshotPatchError(WorkspaceSnapshotError):
    pass


@dataclass(frozen=True)
class SnapshotPatchResult:
    applied: bool
    changed_paths: tuple[str, ...] = ()
    patch_bytes: int = 0
    ignored_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class SnapshotPatchSelection:
    changed_paths: tuple[str, ...]
    ignored_paths: tuple[str, ...]


@dataclass(frozen=True)
class SnapshotPathState:
    kind: str
    sha256: str | None = None
    executable: bool = False
    symlink_target: str | None = None


@dataclass(frozen=True)
class SnapshotSymlinkRewrite:
    path: str
    original_target: str
    snapshot_target: str


@dataclass(frozen=True)
class WorkspaceSnapshot:
    original_root: Path
    snapshot_root: Path
    temp_root: Path
    task_path: Path
    task_relative_path: str
    task_bytes: bytes
    task_sha256: str
    baseline_commit: str
    git_config_bytes: bytes
    git_config_mode: int
    git_worktree_config_bytes: bytes | None
    git_worktree_config_mode: int | None
    readonly_dependency_paths: tuple[str, ...] = ()
    declared_grading_roots: tuple[str | Path, ...] = ()
    rewritten_symlinks: tuple[SnapshotSymlinkRewrite, ...] = ()
    excluded_external_symlink_paths: tuple[str, ...] = ()

    def cleanup(self) -> None:
        shutil.rmtree(self.temp_root, ignore_errors=True)

    def restore_runtime_links(self) -> tuple[str, ...]:
        try:
            return _restore_runtime_links(self)
        except OSError as exc:
            raise WorkspaceSnapshotError(f"failed to restore coder workspace runtime links: {exc}") from exc

    def git_control_is_trusted(self) -> bool:
        git_dir = self.snapshot_root / ".git"
        if git_dir.is_symlink() or not git_dir.is_dir():
            return False
        if not _regular_file_matches(git_dir / "config", self.git_config_bytes):
            return False
        worktree_config = git_dir / "config.worktree"
        if self.git_worktree_config_bytes is None:
            return not (worktree_config.exists() or worktree_config.is_symlink())
        return _regular_file_matches(worktree_config, self.git_worktree_config_bytes)

    def restore_git_control(self) -> bool:
        if self.git_control_is_trusted():
            return False
        try:
            _restore_trusted_snapshot_git_config(self)
        except OSError as exc:
            raise WorkspaceSnapshotError(f"failed to restore trusted snapshot Git config: {exc}") from exc
        return True

    def preserve(self, destination: Path) -> Path:
        try:
            _detach_recovery_workspace(self)
            destination = destination.resolve(strict=False)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() or destination.is_symlink():
                raise WorkspaceSnapshotError(f"snapshot recovery destination already exists: {destination}")
            relative_workspace = self.snapshot_root.relative_to(self.temp_root)
            shutil.move(str(self.temp_root), str(destination))
            return destination / relative_workspace
        except WorkspaceSnapshotError:
            raise
        except OSError as exc:
            raise WorkspaceSnapshotError(f"failed to preserve coder workspace for recovery: {exc}") from exc


def create_workspace_snapshot(
    project_root: Path,
    task_path: Path,
    *,
    declared_grading_roots: Iterable[str | Path] = (),
    prefix: str = "sentinel-coder-",
) -> WorkspaceSnapshot:
    if shutil.which("git") is None:
        raise WorkspaceSnapshotError("git executable is required for workspace snapshots")
    try:
        original_root = project_root.resolve()
        original_task = task_path.resolve()
        task_bytes = original_task.read_bytes()
    except OSError as exc:
        raise WorkspaceSnapshotError(f"failed to read project or task path for workspace snapshot: {exc}") from exc
    try:
        task_relative = original_task.relative_to(original_root)
    except ValueError as exc:
        raise WorkspaceSnapshotError(f"task path is outside project root: {original_task}") from exc
    reserved_task_part = next(
        (part for part in task_relative.parts if part in SNAPSHOT_RESERVED_TASK_PATH_NAMES),
        None,
    )
    if reserved_task_part is not None:
        raise WorkspaceSnapshotError(
            f"task path cannot be inside Sentinel runtime, cache, or dependency directory: {reserved_task_part}"
        )

    try:
        temp_root = Path(tempfile.mkdtemp(prefix=prefix)).resolve()
    except OSError as exc:
        raise WorkspaceSnapshotError(f"failed to create temporary workspace snapshot directory: {exc}") from exc
    snapshot_root = temp_root / "workspace"
    declared_roots = tuple(declared_grading_roots)
    resolved_declared_roots = _resolve_declared_roots(original_root, declared_roots)
    readonly_dependencies: list[tuple[Path, str]] = []
    try:
        history_preserved = _clone_git_metadata(original_root, snapshot_root)
        if history_preserved:
            _sync_snapshot_remotes(original_root, snapshot_root)
            _clear_snapshot_worktree(snapshot_root)
        shutil.copytree(
            original_root,
            snapshot_root,
            dirs_exist_ok=history_preserved,
            symlinks=True,
            ignore=_snapshot_ignore(
                original_root,
                resolved_declared_roots,
                original_task=original_task,
                readonly_dependencies=readonly_dependencies,
            ),
        )
        rewritten_symlinks, excluded_external_symlinks = _sanitize_copied_workspace_symlinks(
            original_root,
            snapshot_root,
        )
        snapshot_task = snapshot_root / task_relative
        _create_readonly_link(snapshot_task, original_task)
        state_source = original_root / ".supervisor"
        if state_source.is_dir():
            _create_readonly_link(snapshot_root / ".supervisor", state_source)
        readonly_dependency_paths: list[str] = []
        for source, relative in readonly_dependencies:
            _create_readonly_link(snapshot_root / relative, source)
            readonly_dependency_paths.append(relative)
        baseline_commit = _init_snapshot_git(snapshot_root)
        git_config_bytes, git_config_mode = _read_regular_file(snapshot_root / ".git" / "config")
        worktree_config = snapshot_root / ".git" / "config.worktree"
        if worktree_config.exists() or worktree_config.is_symlink():
            git_worktree_config_bytes, git_worktree_config_mode = _read_regular_file(worktree_config)
        else:
            git_worktree_config_bytes, git_worktree_config_mode = None, None
        return WorkspaceSnapshot(
            original_root=original_root,
            snapshot_root=snapshot_root.resolve(),
            temp_root=temp_root,
            task_path=snapshot_task.absolute(),
            task_relative_path=task_relative.as_posix(),
            task_bytes=task_bytes,
            task_sha256=hashlib.sha256(task_bytes).hexdigest(),
            baseline_commit=baseline_commit,
            git_config_bytes=git_config_bytes,
            git_config_mode=git_config_mode,
            git_worktree_config_bytes=git_worktree_config_bytes,
            git_worktree_config_mode=git_worktree_config_mode,
            readonly_dependency_paths=tuple(sorted(dict.fromkeys(readonly_dependency_paths))),
            declared_grading_roots=declared_roots,
            rewritten_symlinks=rewritten_symlinks,
            excluded_external_symlink_paths=excluded_external_symlinks,
        )
    except WorkspaceSnapshotError:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise
    except Exception as exc:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise WorkspaceSnapshotError(f"failed to create coder workspace snapshot: {exc}") from exc


def apply_snapshot_patch(snapshot: WorkspaceSnapshot) -> SnapshotPatchResult:
    try:
        return _apply_snapshot_patch(snapshot)
    except WorkspaceSnapshotError:
        raise
    except OSError as exc:
        raise SnapshotPatchError(f"snapshot patch filesystem operation failed: {exc}") from exc


def _apply_snapshot_patch(snapshot: WorkspaceSnapshot) -> SnapshotPatchResult:
    _restore_trusted_snapshot_git_config(snapshot)
    selection = _snapshot_patch_selection(snapshot)
    changed_paths = selection.changed_paths
    if not changed_paths:
        return SnapshotPatchResult(applied=False, ignored_paths=selection.ignored_paths)
    _validate_snapshot_patch_paths(
        snapshot.original_root,
        changed_paths,
        task_relative_path=snapshot.task_relative_path,
        declared_grading_roots=snapshot.declared_grading_roots,
    )
    _validate_symlink_targets(snapshot.snapshot_root, changed_paths)
    patch = _snapshot_patch(snapshot, changed_paths)
    if not patch.strip():
        raise SnapshotPatchError("snapshot reported changed paths but produced an empty patch")
    _apply_patch_to_original(snapshot, changed_paths, patch)
    return SnapshotPatchResult(
        applied=True,
        changed_paths=changed_paths,
        patch_bytes=len(patch),
        ignored_paths=selection.ignored_paths,
    )


def _restore_runtime_links(snapshot: WorkspaceSnapshot) -> tuple[str, ...]:
    repaired: list[str] = []
    mounts: list[tuple[Path, Path, str]] = [
        (
            snapshot.snapshot_root / snapshot.task_relative_path,
            snapshot.original_root / snapshot.task_relative_path,
            "task",
        ),
    ]
    state_source = snapshot.original_root / ".supervisor"
    if state_source.is_dir():
        mounts.append((snapshot.snapshot_root / ".supervisor", state_source, "supervisor_state"))
    for relative in snapshot.readonly_dependency_paths:
        source = snapshot.original_root / relative
        if source.exists() or source.is_symlink():
            mounts.append((snapshot.snapshot_root / relative, source, f"dependency:{relative}"))
    for destination, source, label in mounts:
        if _symlink_points_to(destination, source):
            continue
        _create_readonly_link(destination, source)
        repaired.append(label)
    return tuple(repaired)


def _snapshot_patch_selection(snapshot: WorkspaceSnapshot) -> SnapshotPatchSelection:
    snapshot_root = snapshot.snapshot_root
    _run_git(snapshot_root, ["add", "-f", "-A", "--"])
    raw = _run_git(
        snapshot_root,
        [
            "--literal-pathspecs",
            "diff",
            "--cached",
            "--name-only",
            "--no-ext-diff",
            "--no-textconv",
            "-z",
            snapshot.baseline_commit,
            "--",
        ],
        capture_bytes=True,
    )
    assert isinstance(raw, bytes)
    changed_paths = tuple(part.decode("utf-8", errors="surrogateescape") for part in raw.split(b"\0") if part)
    return _filter_snapshot_patch_paths(
        snapshot_root,
        changed_paths,
        readonly_dependency_paths=snapshot.readonly_dependency_paths,
    )


def _filter_snapshot_patch_paths(
    snapshot_root: Path,
    changed_paths: tuple[str, ...],
    *,
    readonly_dependency_paths: tuple[str, ...],
) -> SnapshotPatchSelection:
    kept: list[str] = []
    ignored: list[str] = []
    for path in changed_paths:
        if _is_generated_artifact_path(snapshot_root, path) or any(
            _path_is_at_or_below(path, dependency) for dependency in readonly_dependency_paths
        ):
            ignored.append(path)
        else:
            kept.append(path)
    return SnapshotPatchSelection(tuple(kept), tuple(ignored))


def _snapshot_patch(snapshot: WorkspaceSnapshot, changed_paths: Sequence[str]) -> bytes:
    raw = _run_git(
        snapshot.snapshot_root,
        [
            "--literal-pathspecs",
            "diff",
            "--cached",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            snapshot.baseline_commit,
            "--",
            *changed_paths,
        ],
        capture_bytes=True,
    )
    assert isinstance(raw, bytes)
    return raw


def _validate_snapshot_patch_paths(
    original_root: Path,
    paths: tuple[str, ...],
    *,
    task_relative_path: str,
    declared_grading_roots: tuple[str | Path, ...],
) -> None:
    if any(_path_is_at_or_below(path, task_relative_path) for path in paths):
        raise SnapshotPatchError(f"snapshot patch path rejected: task file is immutable: {task_relative_path}")
    decision = PolicyEngine(original_root, declared_grading_roots=declared_grading_roots).evaluate_patch_paths(list(paths))
    if decision.kind != PolicyDecisionKind.ALLOW:
        raise SnapshotPatchError(f"snapshot patch path rejected: {decision.reason}")


def _validate_symlink_targets(snapshot_root: Path, paths: tuple[str, ...]) -> None:
    root = snapshot_root.resolve()
    for raw in paths:
        path = root / raw
        if not path.is_symlink():
            continue
        target = os.readlink(path)
        target_path = Path(target)
        if target_path.is_absolute():
            raise SnapshotPatchError(f"snapshot patch creates or modifies absolute symlink: {raw} -> {target}")
        candidate = path.parent / target_path
        try:
            resolved = candidate.resolve(strict=False)
            resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            raise SnapshotPatchError(f"snapshot patch creates or modifies escaping symlink: {raw} -> {target}") from exc


def _apply_patch_to_original(
    snapshot: WorkspaceSnapshot,
    changed_paths: tuple[str, ...],
    patch: bytes,
) -> None:
    original_root = snapshot.original_root
    with tempfile.TemporaryDirectory(prefix="sentinel-patch-backup-") as raw_backup:
        backup_root = Path(raw_backup)
        normalized_symlink_paths = _rewritten_symlink_paths_for_changes(snapshot, changed_paths)
        backup_paths = tuple(dict.fromkeys((*changed_paths, *normalized_symlink_paths)))
        backup_entries = _backup_original_paths(original_root, backup_root, backup_paths)
        try:
            _normalize_original_symlink_baselines(snapshot, changed_paths)
            check = _run_git_apply(original_root, ["--check", "--binary", "--whitespace=nowarn"], patch)
            if check.returncode != 0:
                raise SnapshotPatchError(_format_apply_error("snapshot patch does not apply cleanly", check))
            applied = _run_git_apply(original_root, ["--binary", "--whitespace=nowarn"], patch)
            if applied.returncode != 0:
                raise SnapshotPatchError(_format_apply_error("snapshot patch apply failed after clean check", applied))
            _verify_applied_paths(original_root, snapshot.snapshot_root, changed_paths)
        except Exception:
            _restore_original_paths(original_root, backup_root, backup_entries)
            raise


def _normalize_original_symlink_baselines(
    snapshot: WorkspaceSnapshot,
    changed_paths: tuple[str, ...],
) -> None:
    affected_paths = set(_rewritten_symlink_paths_for_changes(snapshot, changed_paths))
    for rewrite in snapshot.rewritten_symlinks:
        if rewrite.path not in affected_paths:
            continue
        path = snapshot.original_root / rewrite.path
        if not path.is_symlink() or os.readlink(path) != rewrite.original_target:
            raise SnapshotPatchError(
                f"real workspace changed at rewritten symlink path during the run: {rewrite.path}"
            )
        path.unlink()
        os.symlink(rewrite.snapshot_target, path)


def _rewritten_symlink_paths_for_changes(
    snapshot: WorkspaceSnapshot,
    changed_paths: tuple[str, ...],
) -> tuple[str, ...]:
    return tuple(
        rewrite.path
        for rewrite in snapshot.rewritten_symlinks
        if any(
            _path_is_at_or_below(changed_path, rewrite.path)
            or _path_is_at_or_below(rewrite.path, changed_path)
            for changed_path in changed_paths
        )
    )


def _init_snapshot_git(snapshot_root: Path) -> str:
    identity = [
        "-c",
        "user.email=sentinel@localhost",
        "-c",
        "user.name=Sentinel Snapshot",
        "-c",
        "commit.gpgsign=false",
    ]
    if not (snapshot_root / ".git").exists():
        _run_git(snapshot_root, ["init", "-q"])
    _run_git(snapshot_root, ["config", "--local", "core.hooksPath", os.devnull])
    _run_git(snapshot_root, ["config", "--local", "commit.gpgsign", "false"])
    _run_git(snapshot_root, ["config", "--local", "tag.gpgsign", "false"])
    _run_git(snapshot_root, ["config", "--local", "user.email", "sentinel@localhost"])
    _run_git(snapshot_root, ["config", "--local", "user.name", "Sentinel Snapshot"])
    _run_git(snapshot_root, ["add", "-f", "-A", "--"])
    _run_git(
        snapshot_root,
        [*identity, "commit", "-q", "--no-verify", "--allow-empty", "-m", "sentinel coder snapshot baseline"],
    )
    baseline_commit = str(_run_git(snapshot_root, ["rev-parse", "HEAD"])).strip()
    _run_git(snapshot_root, ["update-ref", "refs/sentinel/baseline", baseline_commit])
    return baseline_commit


def _restore_trusted_snapshot_git_config(snapshot: WorkspaceSnapshot) -> None:
    git_dir = snapshot.snapshot_root / ".git"
    if git_dir.is_symlink() or not git_dir.is_dir():
        raise SnapshotPatchError("snapshot Git directory was replaced or removed")
    _atomic_replace_bytes(git_dir / "config", snapshot.git_config_bytes, snapshot.git_config_mode)
    worktree_config = git_dir / "config.worktree"
    if snapshot.git_worktree_config_bytes is None:
        _remove_path(worktree_config)
    else:
        _atomic_replace_bytes(
            worktree_config,
            snapshot.git_worktree_config_bytes,
            snapshot.git_worktree_config_mode or 0o644,
        )


def _detach_recovery_workspace(snapshot: WorkspaceSnapshot) -> None:
    _remove_path(snapshot.snapshot_root / ".git")
    _remove_path(snapshot.snapshot_root / ".supervisor")
    for relative in snapshot.readonly_dependency_paths:
        _remove_path(snapshot.snapshot_root / relative)
    task = snapshot.snapshot_root / snapshot.task_relative_path
    _remove_path(task)
    task.parent.mkdir(parents=True, exist_ok=True)
    _atomic_replace_bytes(task, snapshot.task_bytes, 0o644)


def _read_regular_file(path: Path) -> tuple[bytes, int]:
    try:
        descriptor = _open_regular_file_no_follow(path)
    except OSError as exc:
        raise WorkspaceSnapshotError(f"snapshot Git control file is not a regular file: {path}") from exc
    try:
        mode = stat.S_IMODE(os.fstat(descriptor).st_mode)
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks), mode
    finally:
        os.close(descriptor)


def _regular_file_matches(path: Path, expected: bytes) -> bool:
    descriptor: int | None = None
    try:
        descriptor = _open_regular_file_no_follow(path)
        content = bytearray()
        while len(content) <= len(expected):
            chunk = os.read(descriptor, min(1024 * 1024, len(expected) + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        return bytes(content) == expected
    except OSError:
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _atomic_replace_bytes(path: Path, content: bytes, mode: int) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _clone_git_metadata(original_root: Path, snapshot_root: Path) -> bool:
    probe = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=original_root,
        env=_isolated_git_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if probe.returncode != 0:
        return False
    try:
        top_level = Path(probe.stdout.strip()).resolve()
    except OSError:
        return False
    if top_level != original_root:
        return False
    cloned = subprocess.run(
        ["git", "clone", "--quiet", "--no-hardlinks", "--no-checkout", str(original_root), str(snapshot_root)],
        env=_isolated_git_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if cloned.returncode == 0:
        return True
    shutil.rmtree(snapshot_root, ignore_errors=True)
    return False


def _sync_snapshot_remotes(original_root: Path, snapshot_root: Path) -> None:
    for name in _optional_git_lines(snapshot_root, ["remote"]):
        _run_git(snapshot_root, ["remote", "remove", name])
    for name in _optional_git_lines(original_root, ["remote"]):
        fetch_urls = _optional_git_lines(original_root, ["remote", "get-url", "--all", name])
        if not fetch_urls:
            continue
        _run_git(snapshot_root, ["remote", "add", name, fetch_urls[0]])
        for url in fetch_urls[1:]:
            _run_git(snapshot_root, ["remote", "set-url", "--add", name, url])
        push_urls = _optional_git_lines(original_root, ["remote", "get-url", "--push", "--all", name])
        if push_urls and push_urls != fetch_urls:
            _run_git(snapshot_root, ["remote", "set-url", "--push", name, push_urls[0]])
            for url in push_urls[1:]:
                _run_git(snapshot_root, ["remote", "set-url", "--add", "--push", name, url])


def _optional_git_lines(cwd: Path, args: list[str]) -> list[str]:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=_isolated_git_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        return []
    return [line for line in completed.stdout.splitlines() if line]


def _clear_snapshot_worktree(snapshot_root: Path) -> None:
    for child in snapshot_root.iterdir():
        if child.name == ".git":
            continue
        _remove_path(child)


def _sanitize_copied_workspace_symlinks(
    original_root: Path,
    snapshot_root: Path,
) -> tuple[tuple[SnapshotSymlinkRewrite, ...], tuple[str, ...]]:
    rewrites: list[SnapshotSymlinkRewrite] = []
    excluded: list[str] = []
    for current, dirs, files in os.walk(snapshot_root, followlinks=False):
        if Path(current) == snapshot_root:
            dirs[:] = [name for name in dirs if name != ".git"]
        for name in sorted([*dirs, *files]):
            destination = Path(current) / name
            if not destination.is_symlink():
                continue
            relative = destination.relative_to(snapshot_root).as_posix()
            raw_target = os.readlink(destination)
            original_link = original_root / relative
            raw_target_path = Path(raw_target)
            target_candidate = raw_target_path if raw_target_path.is_absolute() else original_link.parent / raw_target_path
            try:
                resolved_target = target_candidate.resolve(strict=False)
                target_relative = resolved_target.relative_to(original_root)
            except (OSError, ValueError):
                destination.unlink()
                excluded.append(relative)
                continue
            if not raw_target_path.is_absolute():
                continue
            snapshot_target = snapshot_root / target_relative
            safe_target = os.path.relpath(snapshot_target, start=destination.parent)
            destination.unlink()
            os.symlink(safe_target, destination, target_is_directory=resolved_target.is_dir())
            rewrites.append(
                SnapshotSymlinkRewrite(
                    path=relative,
                    original_target=raw_target,
                    snapshot_target=safe_target,
                )
            )
    return tuple(rewrites), tuple(excluded)


def _create_readonly_link(destination: Path, source: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        _remove_path(destination)
    os.symlink(str(source.resolve()), destination, target_is_directory=source.is_dir())


def _symlink_points_to(path: Path, target: Path) -> bool:
    if not path.is_symlink():
        return False
    try:
        return path.resolve(strict=True) == target.resolve(strict=True)
    except OSError:
        return False


def _backup_original_paths(
    original_root: Path,
    backup_root: Path,
    changed_paths: tuple[str, ...],
) -> tuple[tuple[str, bool], ...]:
    entries: list[tuple[str, bool]] = []
    for raw in _minimal_changed_paths(changed_paths):
        source = original_root / raw
        exists = source.exists() or source.is_symlink()
        entries.append((raw, exists))
        if not exists:
            continue
        destination = backup_root / raw
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            os.symlink(os.readlink(source), destination)
        elif source.is_dir():
            shutil.copytree(source, destination, symlinks=True)
        elif source.is_file():
            shutil.copy2(source, destination, follow_symlinks=False)
        else:
            raise SnapshotPatchError(f"unsupported original path type during patch backup: {raw}")
    return tuple(entries)


def _restore_original_paths(
    original_root: Path,
    backup_root: Path,
    entries: tuple[tuple[str, bool], ...],
) -> None:
    failures: list[str] = []
    for raw, existed in entries:
        destination = original_root / raw
        try:
            _remove_path(destination)
            if not existed:
                continue
            source = backup_root / raw
            destination.parent.mkdir(parents=True, exist_ok=True)
            if source.is_symlink():
                os.symlink(os.readlink(source), destination)
            elif source.is_dir():
                shutil.copytree(source, destination, symlinks=True)
            else:
                shutil.copy2(source, destination, follow_symlinks=False)
        except OSError as exc:
            failures.append(f"{raw}: {exc}")
    if failures:
        raise SnapshotPatchError("snapshot patch rollback failed: " + "; ".join(failures))


def _verify_applied_paths(original_root: Path, snapshot_root: Path, changed_paths: tuple[str, ...]) -> None:
    mismatches: list[str] = []
    for raw in changed_paths:
        expected = _snapshot_path_state(snapshot_root / raw)
        actual = _snapshot_path_state(original_root / raw)
        if expected != actual:
            mismatches.append(raw)
    if mismatches:
        joined = ", ".join(mismatches[:20])
        raise SnapshotPatchError(f"snapshot patch verification failed for: {joined}")


def _snapshot_path_state(path: Path) -> SnapshotPathState:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return SnapshotPathState(kind="absent")
    if stat.S_ISLNK(mode):
        return SnapshotPathState(kind="symlink", symlink_target=os.readlink(path))
    if stat.S_ISDIR(mode):
        return SnapshotPathState(kind="directory")
    if not stat.S_ISREG(mode):
        return SnapshotPathState(kind="unsupported")
    executable = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    return SnapshotPathState(kind="file", sha256=_sha256_file(path), executable=executable)


def _minimal_changed_paths(paths: tuple[str, ...]) -> tuple[str, ...]:
    selected: list[str] = []
    for raw in sorted(paths, key=lambda value: (len(Path(value).parts), value)):
        if any(_path_is_at_or_below(raw, existing) for existing in selected):
            continue
        selected.append(raw)
    return tuple(selected)


def _remove_path(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if stat.S_ISDIR(mode) and not stat.S_ISLNK(mode):
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def _sha256_file(path: Path) -> str:
    descriptor = _open_regular_file_no_follow(path)
    digest = hashlib.sha256()
    try:
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _open_regular_file_no_follow(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError(f"not a regular file: {path}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _path_is_at_or_below(raw_path: str, raw_parent: str) -> bool:
    path_parts = Path(raw_path).parts
    parent_parts = Path(raw_parent).parts
    return len(path_parts) >= len(parent_parts) and path_parts[: len(parent_parts)] == parent_parts


def _run_git(cwd: Path, args: list[str], *, capture_bytes: bool = False) -> str | bytes:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=_isolated_git_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        stdout = completed.stdout.decode("utf-8", errors="replace").strip()
        detail = stderr or stdout or f"exit {completed.returncode}"
        raise WorkspaceSnapshotError(f"git {' '.join(args)} failed in {cwd}: {detail}")
    if capture_bytes:
        return completed.stdout
    return completed.stdout.decode("utf-8", errors="replace")


def _run_git_apply(cwd: Path, args: list[str], patch: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "apply", *args],
        cwd=cwd,
        env=_isolated_git_env(),
        input=patch,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _isolated_git_env() -> dict[str, str]:
    env = os.environ.copy()
    blocked = {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_DIR",
        "GIT_EXEC_PATH",
        "GIT_EXTERNAL_DIFF",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    }
    for key in list(env):
        if key in blocked or key.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
            env.pop(key, None)
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    return env


def snapshot_git_environment() -> dict[str, str]:
    return _isolated_git_env()


def _format_apply_error(prefix: str, completed: subprocess.CompletedProcess[bytes]) -> str:
    stderr = completed.stderr.decode("utf-8", errors="replace").strip()
    stdout = completed.stdout.decode("utf-8", errors="replace").strip()
    detail = stderr or stdout or f"exit {completed.returncode}"
    return f"{prefix}: {detail}"


def _is_generated_artifact_path(snapshot_root: Path, raw_path: str) -> bool:
    relative = Path(raw_path)
    parts = tuple(part.lower() for part in relative.parts)
    if any(part in GENERATED_ARTIFACT_DIR_NAMES for part in parts):
        return True
    name = relative.name
    lowered_name = name.lower()
    if lowered_name in GENERATED_ARTIFACT_FILE_NAMES:
        return True
    if any(lowered_name.endswith(suffix) for suffix in GENERATED_ARTIFACT_SUFFIXES):
        return True
    return False


def _snapshot_ignore(
    original_root: Path,
    declared_roots: tuple[Path, ...],
    *,
    original_task: Path,
    readonly_dependencies: list[tuple[Path, str]],
):
    root = original_root.resolve()

    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored: set[str] = set()
        current = Path(directory)
        for name in names:
            candidate = current / name
            try:
                candidate_relative = candidate.relative_to(root).as_posix()
            except ValueError:
                candidate_relative = name
            try:
                resolved_candidate = candidate.resolve(strict=False)
            except OSError:
                resolved_candidate = None
            if resolved_candidate == original_task:
                ignored.add(name)
                continue
            if name in SNAPSHOT_READ_ONLY_DEPENDENCY_NAMES:
                readonly_dependencies.append((candidate, candidate_relative))
                ignored.add(name)
                continue
            if name in SNAPSHOT_ALWAYS_IGNORE_NAMES:
                ignored.add(name)
                continue
            if is_protected_path(root, candidate) or is_supervisor_runtime_path(root, candidate):
                ignored.add(name)
                continue
            if _matches_declared_root(candidate, declared_roots):
                ignored.add(name)
        return ignored

    return ignore


def _resolve_declared_roots(project_root: Path, roots: tuple[str | Path, ...]) -> tuple[Path, ...]:
    resolved: list[Path] = []
    for raw in roots:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            path = project_root / path
        try:
            resolved.append(path.resolve(strict=False))
        except OSError:
            continue
    return tuple(dict.fromkeys(resolved))


def _matches_declared_root(path: Path, roots: tuple[Path, ...]) -> bool:
    if not roots:
        return False
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        return False
    for root in roots:
        if resolved == root:
            return True
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            continue
    return False
