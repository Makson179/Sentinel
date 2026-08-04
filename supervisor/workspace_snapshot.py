from __future__ import annotations

from collections.abc import Sequence
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from supervisor.policy import PolicyEngine, is_protected_path, is_supervisor_runtime_path
from supervisor.schemas import PolicyDecisionKind


SNAPSHOT_ALWAYS_IGNORE_NAMES = {
    ".git",
    ".supervisor",
    ".bello",
    ".codex",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
}

# These directories belong to Bello's control plane, not to the task workspace.
# The top-level names mirror the run-root layout from task.md.  Dot-prefixed
# control directories are excluded at any depth because repository-local Codex
# configuration must not become coder/context input.
SNAPSHOT_RUNTIME_STATE_ANYWHERE_NAMES = {
    ".bello",
    ".codex",
    ".context-mode",
    ".context_mode",
    ".supervisor",
}

SNAPSHOT_RUNTIME_STATE_TOP_LEVEL_NAMES = {
    "context-mode",
    "context-mode-home",
    "context-mode-tmp",
    "runtime-metadata",
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

_SNAPSHOT_REMOTE_URL_MAX_BYTES = 4096
_SNAPSHOT_REMOTE_SCHEMES = frozenset({"git", "http", "https", "ssh"})
_SNAPSHOT_REMOTE_CREDENTIAL_PATTERN = re.compile(
    r"(?:"
    r"github_pat_[A-Za-z0-9_]{10,}"
    r"|gh[pousr]_[A-Za-z0-9]{10,}"
    r"|glpat-[A-Za-z0-9_-]{10,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|x-access-token"
    r"|(?:access|auth|private|refresh)[_-]?token(?:$|[/.:=_-])"
    r"|api[_-]?key(?:$|[/.:=_-])"
    r"|authorization(?:$|[/.:=_-])"
    r"|bearer(?:$|[ +:/=_-])"
    r")",
    re.IGNORECASE,
)
_SNAPSHOT_SENSITIVE_GIT_CONFIG_PREFIXES = (
    "credential.",
    "http.",
    "include.",
    "includeif.",
    "url.",
)


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
    readonly_dependency_digests: tuple[tuple[str, str], ...] = ()
    declared_grading_roots: tuple[str | Path, ...] = ()
    protected_path_masks: tuple[str, ...] = ()
    runtime_excluded_paths: tuple[str, ...] = ()
    rewritten_symlinks: tuple[SnapshotSymlinkRewrite, ...] = ()
    excluded_external_symlink_paths: tuple[str, ...] = ()
    owns_temp_root: bool = True
    _quiesced: threading.Event = field(default_factory=threading.Event, repr=False, compare=False)

    @property
    def run_root(self) -> Path:
        """Return the run root while retaining the legacy ``temp_root`` name."""

        return self.temp_root

    def cleanup(self) -> None:
        try:
            if self.owns_temp_root:
                _remove_path(self.temp_root)
            else:
                _remove_path(self.snapshot_root)
        except OSError:
            # Cleanup remains best-effort for compatibility with the previous
            # TemporaryDirectory-style lifecycle.
            pass

    @property
    def is_quiesced(self) -> bool:
        return self._quiesced.is_set()

    def mark_quiesced(self) -> None:
        """Attest that all processes capable of writing the workspace stopped.

        The controller owns this lifecycle assertion.  Consumers that require
        the stronger final-diff contract pass ``require_quiesced=True`` to
        :func:`apply_snapshot_patch`.
        """

        self._quiesced.set()

    def task_control_is_trusted(self) -> bool:
        task = self.snapshot_root / self.task_relative_path
        if not _path_has_only_real_directory_parents(self.snapshot_root, task):
            return False
        try:
            descriptor = _open_regular_file_no_follow(task)
        except OSError:
            return False
        try:
            mode = stat.S_IMODE(os.fstat(descriptor).st_mode)
            if mode & 0o222:
                return False
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 1024 * 1024):
                digest.update(chunk)
            return digest.hexdigest() == self.task_sha256
        finally:
            os.close(descriptor)

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
            destination.mkdir(mode=0o700)
            recovery_workspace = destination / "workspace"
            shutil.move(str(self.snapshot_root), str(recovery_workspace))
            if self.owns_temp_root:
                _remove_path(self.temp_root)
            return recovery_workspace
        except WorkspaceSnapshotError:
            raise
        except OSError as exc:
            raise WorkspaceSnapshotError(f"failed to preserve coder workspace for recovery: {exc}") from exc


def create_workspace_snapshot(
    project_root: Path,
    task_path: Path,
    *,
    declared_grading_roots: Iterable[str | Path] = (),
    protected_path_masks: Iterable[str | Path] = (),
    prefix: str = "bello-coder-",
    run_root: Path | None = None,
    workspace_name: str = "coder-workspace",
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
        (
            part
            for index, part in enumerate(task_relative.parts)
            if part in SNAPSHOT_RESERVED_TASK_PATH_NAMES
            or part in SNAPSHOT_RUNTIME_STATE_ANYWHERE_NAMES
            or (index == 0 and part in SNAPSHOT_RUNTIME_STATE_TOP_LEVEL_NAMES)
        ),
        None,
    )
    if reserved_task_part is not None:
        raise WorkspaceSnapshotError(
            f"task path cannot be inside Bello runtime, cache, or dependency directory: {reserved_task_part}"
        )

    declared_roots = tuple(declared_grading_roots)
    explicit_protected_roots = tuple(protected_path_masks)
    policy_roots = tuple(dict.fromkeys((*declared_roots, *explicit_protected_roots)))
    resolved_declared_roots = _resolve_declared_roots(original_root, policy_roots)
    if is_protected_path(original_root, original_task) or _matches_declared_root(
        original_task,
        resolved_declared_roots,
    ):
        raise WorkspaceSnapshotError("task path cannot be inside a protected or declared grading path")

    owns_temp_root = run_root is None
    temp_root: Path | None = None
    try:
        if run_root is None:
            temp_root = Path(tempfile.mkdtemp(prefix=prefix)).resolve()
            os.chmod(temp_root, 0o700)
            _validate_run_root_separation(original_root, temp_root)
        else:
            temp_root = _prepare_external_run_root(Path(run_root), original_root)
        snapshot_root = _prepare_snapshot_workspace_path(temp_root, workspace_name)
    except WorkspaceSnapshotError:
        if owns_temp_root and temp_root is not None:
            try:
                _remove_path(temp_root)
            except OSError:
                pass
        raise
    except OSError as exc:
        if run_root is None:
            if temp_root is not None:
                try:
                    _remove_path(temp_root)
                except OSError:
                    pass
            raise WorkspaceSnapshotError(f"failed to create temporary workspace snapshot directory: {exc}") from exc
        raise WorkspaceSnapshotError(f"failed to prepare external run workspace: {exc}") from exc

    assert temp_root is not None
    readonly_dependencies: list[tuple[Path, str]] = []
    masked_protected_paths = list(_relative_roots_within(original_root, resolved_declared_roots))
    runtime_excluded_paths: list[str] = []
    try:
        history_preserved = _clone_git_metadata(original_root, snapshot_root)
        if history_preserved:
            _sync_snapshot_remotes(original_root, snapshot_root)
            _clear_snapshot_worktree(snapshot_root)
        shutil.copytree(
            original_root,
            snapshot_root,
            # The run-root workspace leaf is created up front with 0700.  It is
            # therefore always an existing, controller-owned empty directory
            # (or contains only the isolated Git clone prepared above).
            dirs_exist_ok=True,
            symlinks=True,
            ignore=_snapshot_ignore(
                original_root,
                resolved_declared_roots,
                original_task=original_task,
                readonly_dependencies=readonly_dependencies,
                protected_path_masks=masked_protected_paths,
                runtime_excluded_paths=runtime_excluded_paths,
            ),
        )
        rewritten_symlinks, excluded_external_symlinks = _sanitize_copied_workspace_symlinks(
            original_root,
            snapshot_root,
            declared_roots=resolved_declared_roots,
        )
        _make_workspace_tree_owner_writable(snapshot_root)
        snapshot_task = snapshot_root / task_relative
        _copy_immutable_task(snapshot_task, task_bytes)
        readonly_dependency_paths: list[str] = []
        readonly_dependency_digests: list[tuple[str, str]] = []
        for source, relative in readonly_dependencies:
            if source.is_symlink() or not source.is_dir():
                excluded_external_symlinks = (*excluded_external_symlinks, relative)
                continue
            dependency_rewrites, dependency_excluded, dependency_masks, dependency_runtime = (
                _copy_readonly_dependency(
                    source,
                    snapshot_root / relative,
                    relative,
                    declared_roots=resolved_declared_roots,
                )
            )
            rewritten_symlinks = (*rewritten_symlinks, *dependency_rewrites)
            excluded_external_symlinks = (*excluded_external_symlinks, *dependency_excluded)
            masked_protected_paths.extend(dependency_masks)
            runtime_excluded_paths.extend(dependency_runtime)
            readonly_dependency_paths.append(relative)
            readonly_dependency_digests.append((relative, _tree_digest(snapshot_root / relative)))
        baseline_commit = _init_snapshot_git(snapshot_root)
        _sanitize_snapshot_git_metadata(snapshot_root)
        os.chmod(snapshot_root, 0o700)
        _restrict_control_file_permissions(snapshot_root / ".git" / "config")
        git_config_bytes, git_config_mode = _read_regular_file(snapshot_root / ".git" / "config")
        worktree_config = snapshot_root / ".git" / "config.worktree"
        if worktree_config.exists() or worktree_config.is_symlink():
            _restrict_control_file_permissions(worktree_config)
            git_worktree_config_bytes, git_worktree_config_mode = _read_regular_file(worktree_config)
        else:
            git_worktree_config_bytes, git_worktree_config_mode = None, None
        _assert_no_shared_regular_file_inodes(original_root, snapshot_root)
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
            readonly_dependency_digests=tuple(sorted(readonly_dependency_digests)),
            declared_grading_roots=policy_roots,
            protected_path_masks=tuple(sorted(dict.fromkeys(masked_protected_paths))),
            runtime_excluded_paths=tuple(sorted(dict.fromkeys(runtime_excluded_paths))),
            rewritten_symlinks=rewritten_symlinks,
            excluded_external_symlink_paths=tuple(sorted(dict.fromkeys(excluded_external_symlinks))),
            owns_temp_root=owns_temp_root,
        )
    except WorkspaceSnapshotError:
        _cleanup_failed_snapshot(temp_root, snapshot_root, owns_temp_root=owns_temp_root)
        raise
    except Exception as exc:
        _cleanup_failed_snapshot(temp_root, snapshot_root, owns_temp_root=owns_temp_root)
        raise WorkspaceSnapshotError(f"failed to create coder workspace snapshot: {exc}") from exc


def _prepare_external_run_root(run_root: Path, original_root: Path) -> Path:
    raw_root = Path(os.path.abspath(os.fspath(run_root)))
    try:
        resolved = raw_root.resolve(strict=True)
    except FileNotFoundError as exc:
        raise WorkspaceSnapshotError(f"external run root does not exist: {raw_root}") from exc
    if resolved != raw_root:
        raise WorkspaceSnapshotError(
            f"external run root must not contain symlink path components: {raw_root}"
        )
    try:
        metadata = raw_root.lstat()
    except FileNotFoundError as exc:
        raise WorkspaceSnapshotError(f"external run root does not exist: {raw_root}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise WorkspaceSnapshotError(f"external run root must be a real directory, not a symlink: {raw_root}")
    if hasattr(os, "geteuid") and metadata.st_uid != os.geteuid():
        raise WorkspaceSnapshotError(f"external run root is not owned by the current user: {raw_root}")

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(raw_root, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise WorkspaceSnapshotError(f"external run root changed while it was being opened: {raw_root}")
        os.fchmod(descriptor, 0o700)
    finally:
        os.close(descriptor)

    _validate_run_root_separation(original_root, resolved)
    return resolved


def _validate_run_root_separation(original_root: Path, run_root: Path) -> None:
    if _path_is_within(run_root, original_root) or _path_is_within(original_root, run_root):
        raise WorkspaceSnapshotError(
            f"run root must be outside and disjoint from the source project: {run_root}"
        )


def _prepare_snapshot_workspace_path(run_root: Path, workspace_name: str) -> Path:
    if not workspace_name or Path(workspace_name).is_absolute() or Path(workspace_name).parts != (workspace_name,):
        raise WorkspaceSnapshotError(f"invalid coder workspace name: {workspace_name!r}")
    if workspace_name in {".", ".."} or _is_runtime_state_relative(workspace_name):
        raise WorkspaceSnapshotError(f"reserved coder workspace name: {workspace_name!r}")
    workspace = run_root / workspace_name
    if workspace.exists() or workspace.is_symlink():
        metadata = workspace.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise WorkspaceSnapshotError(f"coder workspace path must be a real directory: {workspace}")
        if any(workspace.iterdir()):
            raise WorkspaceSnapshotError(f"coder workspace path is not empty: {workspace}")
        os.chmod(workspace, 0o700)
    else:
        workspace.mkdir(mode=0o700)
    return workspace.absolute()


def _cleanup_failed_snapshot(temp_root: Path, snapshot_root: Path, *, owns_temp_root: bool) -> None:
    if owns_temp_root:
        try:
            _remove_path(temp_root)
        except OSError:
            pass
    else:
        try:
            _remove_path(snapshot_root)
        except OSError:
            pass


def _copy_immutable_task(destination: Path, content: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    _remove_path(destination)
    _atomic_replace_bytes(destination, content, 0o444)


def _copy_readonly_dependency(
    source: Path,
    destination: Path,
    relative_prefix: str,
    *,
    declared_roots: tuple[Path, ...],
) -> tuple[
    tuple[SnapshotSymlinkRewrite, ...],
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
]:
    protected_masks: list[str] = []
    runtime_excluded: list[str] = []

    def ignore(directory: str, names: list[str]) -> set[str]:
        ignored: set[str] = set()
        current = Path(directory)
        for name in names:
            candidate = current / name
            local_relative = candidate.relative_to(source).as_posix()
            workspace_relative = _prefixed_relative(relative_prefix, local_relative)
            if _is_runtime_state_relative(local_relative):
                ignored.add(name)
                runtime_excluded.append(workspace_relative)
            elif is_protected_path(source, candidate) or _matches_declared_root(candidate, declared_roots):
                ignored.add(name)
                protected_masks.append(workspace_relative)
        return ignored

    _remove_path(destination)
    shutil.copytree(source, destination, symlinks=True, ignore=ignore)
    local_rewrites, local_excluded = _sanitize_copied_workspace_symlinks(
        source,
        destination,
        declared_roots=declared_roots,
    )
    rewrites = tuple(
        SnapshotSymlinkRewrite(
            path=_prefixed_relative(relative_prefix, rewrite.path),
            original_target=rewrite.original_target,
            snapshot_target=rewrite.snapshot_target,
        )
        for rewrite in local_rewrites
    )
    excluded = tuple(_prefixed_relative(relative_prefix, path) for path in local_excluded)
    _make_tree_readonly(destination)
    return rewrites, excluded, tuple(protected_masks), tuple(runtime_excluded)


def _prefixed_relative(prefix: str, relative: str) -> str:
    return (Path(prefix) / relative).as_posix() if relative not in {"", "."} else Path(prefix).as_posix()


def _make_tree_readonly(root: Path) -> None:
    for current, directories, files in os.walk(root, topdown=False, followlinks=False):
        for name in [*directories, *files]:
            path = Path(current) / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise WorkspaceSnapshotError(f"unsupported path in read-only dependency: {path}")
            mode = stat.S_IMODE(metadata.st_mode) & ~0o222
            if stat.S_ISDIR(metadata.st_mode):
                mode |= stat.S_IRUSR | stat.S_IXUSR
            else:
                mode |= stat.S_IRUSR
            os.chmod(path, mode, follow_symlinks=False)
    root_mode = stat.S_IMODE(root.lstat().st_mode) & ~0o222
    os.chmod(root, root_mode | stat.S_IRUSR | stat.S_IXUSR, follow_symlinks=False)


def _make_workspace_tree_owner_writable(root: Path) -> None:
    for current, directories, files in os.walk(root, followlinks=False):
        for name in [*directories, *files]:
            path = Path(current) / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                continue
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise WorkspaceSnapshotError(f"unsupported path in coder workspace: {path}")
            mode = stat.S_IMODE(metadata.st_mode) & ~0o022
            if stat.S_ISDIR(metadata.st_mode):
                mode |= stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
            else:
                mode |= stat.S_IRUSR | stat.S_IWUSR
            os.chmod(path, mode, follow_symlinks=False)
    os.chmod(root, 0o700, follow_symlinks=False)


def _tree_digest(root: Path) -> str:
    metadata = root.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OSError(f"not a real directory: {root}")
    digest = hashlib.sha256()
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        files.sort()
        for name in [*directories, *files]:
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            entry = path.lstat()
            mode = stat.S_IMODE(entry.st_mode)
            if stat.S_ISLNK(entry.st_mode):
                kind = b"link"
                payload = os.fsencode(os.readlink(path))
            elif stat.S_ISDIR(entry.st_mode):
                kind = b"dir"
                payload = b""
            elif stat.S_ISREG(entry.st_mode):
                kind = b"file"
                payload = bytes.fromhex(_sha256_file(path))
            else:
                raise OSError(f"unsupported path type in read-only dependency: {path}")
            digest.update(kind + b"\0" + os.fsencode(relative) + b"\0" + f"{mode:o}".encode() + b"\0")
            digest.update(payload + b"\0")
    return digest.hexdigest()


def _restrict_control_file_permissions(path: Path) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise WorkspaceSnapshotError(f"snapshot control file is not a regular file: {path}")
    os.chmod(path, 0o600, follow_symlinks=False)


def _assert_no_shared_regular_file_inodes(original_root: Path, snapshot_root: Path) -> None:
    source_inodes = {
        inode: relative
        for inode, relative in _regular_file_inodes(original_root)
    }
    for inode, relative in _regular_file_inodes(snapshot_root):
        source_relative = source_inodes.get(inode)
        if source_relative is not None:
            raise WorkspaceSnapshotError(
                "coder workspace contains a hardlink to the source project: "
                f"{relative} shares an inode with {source_relative}"
            )


def _regular_file_inodes(root: Path) -> list[tuple[tuple[int, int], str]]:
    inodes: list[tuple[tuple[int, int], str]] = []
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        files.sort()
        for name in [*directories, *files]:
            path = Path(current) / name
            metadata = path.lstat()
            if stat.S_ISREG(metadata.st_mode):
                inodes.append(((metadata.st_dev, metadata.st_ino), path.relative_to(root).as_posix()))
    return inodes


def _validate_snapshot_root(snapshot: WorkspaceSnapshot) -> None:
    try:
        metadata = snapshot.snapshot_root.lstat()
    except FileNotFoundError as exc:
        raise SnapshotPatchError("coder workspace root is missing") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise SnapshotPatchError("coder workspace root was replaced with an unsafe path")
    if not _path_is_within(snapshot.snapshot_root, snapshot.temp_root):
        raise SnapshotPatchError("coder workspace root is outside its run root")


def _path_has_only_real_directory_parents(root: Path, path: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    current = root
    try:
        root_metadata = current.lstat()
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
            return False
        for part in relative.parts[:-1]:
            current = current / part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                return False
    except OSError:
        return False
    return True


def _path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def apply_snapshot_patch(
    snapshot: WorkspaceSnapshot,
    *,
    require_quiesced: bool = False,
) -> SnapshotPatchResult:
    try:
        return _apply_snapshot_patch(snapshot, require_quiesced=require_quiesced)
    except WorkspaceSnapshotError:
        raise
    except OSError as exc:
        raise SnapshotPatchError(f"snapshot patch filesystem operation failed: {exc}") from exc


def _apply_snapshot_patch(
    snapshot: WorkspaceSnapshot,
    *,
    require_quiesced: bool,
) -> SnapshotPatchResult:
    if require_quiesced and not snapshot.is_quiesced:
        raise SnapshotPatchError(
            "coder workspace must be quiesced before computing or applying the final diff"
        )
    _validate_snapshot_root(snapshot)
    if not snapshot.task_control_is_trusted():
        raise SnapshotPatchError(
            f"snapshot patch path rejected: task file is immutable: {snapshot.task_relative_path}"
        )
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
    if not snapshot.task_control_is_trusted():
        task = snapshot.snapshot_root / snapshot.task_relative_path
        if not _path_has_only_real_directory_parents(snapshot.snapshot_root, task):
            raise WorkspaceSnapshotError("cannot restore immutable task through a symlinked parent directory")
        _copy_immutable_task(
            task,
            snapshot.task_bytes,
        )
        repaired.append("task")

    expected_dependency_digests = dict(snapshot.readonly_dependency_digests)
    for relative in snapshot.readonly_dependency_paths:
        destination = snapshot.snapshot_root / relative
        expected_digest = expected_dependency_digests.get(relative)
        try:
            trusted = expected_digest is not None and _tree_digest(destination) == expected_digest
        except OSError:
            trusted = False
        if trusted:
            continue
        if not _path_has_only_real_directory_parents(snapshot.snapshot_root, destination):
            raise WorkspaceSnapshotError(
                f"cannot restore read-only dependency through a symlinked parent: {relative}"
            )
        source = snapshot.original_root / relative
        if source.is_symlink() or not source.is_dir():
            raise WorkspaceSnapshotError(
                f"read-only dependency source is no longer a real directory: {relative}"
            )
        _remove_path(destination)
        _copy_readonly_dependency(
            source,
            destination,
            relative,
            declared_roots=_resolve_declared_roots(
                snapshot.original_root,
                snapshot.declared_grading_roots,
            ),
        )
        if expected_digest is None or _tree_digest(destination) != expected_digest:
            _remove_path(destination)
            raise WorkspaceSnapshotError(
                f"read-only dependency changed at its source during the run: {relative}"
            )
        repaired.append(f"dependency:{relative}")
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
        runtime_excluded_paths=snapshot.runtime_excluded_paths,
    )


def _filter_snapshot_patch_paths(
    snapshot_root: Path,
    changed_paths: tuple[str, ...],
    *,
    readonly_dependency_paths: tuple[str, ...],
    runtime_excluded_paths: tuple[str, ...] = (),
) -> SnapshotPatchSelection:
    kept: list[str] = []
    ignored: list[str] = []
    for path in changed_paths:
        if (
            _is_generated_artifact_path(snapshot_root, path)
            or _is_runtime_state_relative(path)
            or any(_path_is_at_or_below(path, dependency) for dependency in readonly_dependency_paths)
            or any(_path_is_at_or_below(path, runtime) for runtime in runtime_excluded_paths)
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
        except (OSError, RuntimeError, ValueError) as exc:
            raise SnapshotPatchError(f"snapshot patch creates or modifies escaping symlink: {raw} -> {target}") from exc


def _apply_patch_to_original(
    snapshot: WorkspaceSnapshot,
    changed_paths: tuple[str, ...],
    patch: bytes,
) -> None:
    original_root = snapshot.original_root
    with tempfile.TemporaryDirectory(prefix="bello-patch-backup-") as raw_backup:
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
        "user.email=bello@localhost",
        "-c",
        "user.name=Bello Snapshot",
        "-c",
        "commit.gpgsign=false",
    ]
    if not (snapshot_root / ".git").exists():
        _run_git(snapshot_root, ["init", "-q"])
    _run_git(snapshot_root, ["config", "--local", "core.hooksPath", os.devnull])
    _run_git(snapshot_root, ["config", "--local", "commit.gpgsign", "false"])
    _run_git(snapshot_root, ["config", "--local", "tag.gpgsign", "false"])
    _run_git(snapshot_root, ["config", "--local", "user.email", "bello@localhost"])
    _run_git(snapshot_root, ["config", "--local", "user.name", "Bello Snapshot"])
    _run_git(snapshot_root, ["add", "-f", "-A", "--"])
    _run_git(
        snapshot_root,
        [*identity, "commit", "-q", "--no-verify", "--allow-empty", "-m", "bello coder snapshot baseline"],
    )
    baseline_commit = str(_run_git(snapshot_root, ["rev-parse", "HEAD"])).strip()
    _run_git(snapshot_root, ["update-ref", "refs/bello/baseline", baseline_commit])
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
    _validate_snapshot_root(snapshot)
    _remove_workspace_relative_path(snapshot.snapshot_root, ".git")
    for name in SNAPSHOT_RUNTIME_STATE_ANYWHERE_NAMES | SNAPSHOT_RUNTIME_STATE_TOP_LEVEL_NAMES:
        _remove_workspace_relative_path(snapshot.snapshot_root, name)
    for relative in snapshot.runtime_excluded_paths:
        _remove_workspace_relative_path(snapshot.snapshot_root, relative)
    for relative in snapshot.readonly_dependency_paths:
        _remove_workspace_relative_path(snapshot.snapshot_root, relative)
    task = snapshot.snapshot_root / snapshot.task_relative_path
    if not _path_has_only_real_directory_parents(snapshot.snapshot_root, task):
        raise WorkspaceSnapshotError("cannot detach immutable task through a symlinked parent directory")
    _remove_workspace_relative_path(snapshot.snapshot_root, snapshot.task_relative_path)
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
        push_urls = _optional_git_lines(original_root, ["remote", "get-url", "--push", "--all", name])
        all_urls = (*fetch_urls, *push_urls)
        if any(_credential_free_snapshot_remote_url(url) is None for url in all_urls):
            # A remote is copied as one trust unit.  Keeping only its safe fetch
            # half would make an unsafe push URL silently fall back to fetch.
            continue
        safe_fetch_urls = list(fetch_urls)
        safe_push_urls = list(push_urls)
        _run_git(snapshot_root, ["remote", "add", name, safe_fetch_urls[0]])
        for url in safe_fetch_urls[1:]:
            _run_git(snapshot_root, ["remote", "set-url", "--add", name, url])
        if safe_push_urls and safe_push_urls != safe_fetch_urls:
            _run_git(snapshot_root, ["remote", "set-url", "--push", name, safe_push_urls[0]])
            for url in safe_push_urls[1:]:
                _run_git(snapshot_root, ["remote", "set-url", "--add", "--push", name, url])
    _sanitize_snapshot_git_metadata(snapshot_root)


def _credential_free_snapshot_remote_url(raw_url: str) -> str | None:
    if not raw_url or "\\" in raw_url:
        return None
    try:
        encoded = raw_url.encode("utf-8")
    except UnicodeError:
        return None
    if len(encoded) > _SNAPSHOT_REMOTE_URL_MAX_BYTES or any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
        for character in raw_url
    ):
        return None
    try:
        parsed = urllib.parse.urlsplit(raw_url)
        hostname = parsed.hostname
        # Accessing ``port`` also rejects malformed/out-of-range port syntax.
        parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme.lower() not in _SNAPSHOT_REMOTE_SCHEMES
        or not parsed.netloc
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or "@" in urllib.parse.unquote(parsed.netloc)
        or parsed.query
        or parsed.fragment
    ):
        return None
    decoded = raw_url
    for _ in range(3):
        next_decoded = urllib.parse.unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    if _SNAPSHOT_REMOTE_CREDENTIAL_PATTERN.search(decoded):
        return None
    return raw_url


def _sanitize_snapshot_git_metadata(snapshot_root: Path) -> None:
    git_dir = snapshot_root / ".git"
    if git_dir.is_symlink() or not git_dir.is_dir():
        raise WorkspaceSnapshotError("snapshot Git directory was replaced or removed")
    for config_name in ("config", "config.worktree"):
        config_path = git_dir / config_name
        if not (config_path.exists() or config_path.is_symlink()):
            continue
        _remove_sensitive_snapshot_git_config(config_path, snapshot_root=snapshot_root)
    for name in _optional_git_lines(snapshot_root, ["remote"]):
        fetch_urls = _optional_git_lines(snapshot_root, ["remote", "get-url", "--all", name])
        push_urls = _optional_git_lines(snapshot_root, ["remote", "get-url", "--push", "--all", name])
        if not fetch_urls or any(
            _credential_free_snapshot_remote_url(url) is None for url in (*fetch_urls, *push_urls)
        ):
            _run_git(snapshot_root, ["remote", "remove", name])


def _remove_sensitive_snapshot_git_config(config_path: Path, *, snapshot_root: Path) -> None:
    # Validate without following a final symlink before asking Git to parse it.
    _read_regular_file(config_path)
    raw_keys = _run_git(
        snapshot_root,
        ["config", "--file", os.fspath(config_path), "--null", "--name-only", "--list"],
        capture_bytes=True,
    )
    assert isinstance(raw_keys, bytes)
    for raw_key in raw_keys.split(b"\0"):
        if not raw_key:
            continue
        try:
            key = raw_key.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise WorkspaceSnapshotError("snapshot Git config contains a non-UTF-8 key") from exc
        if _snapshot_git_config_key_is_sensitive(key):
            _run_git(
                snapshot_root,
                ["config", "--file", os.fspath(config_path), "--unset-all", key],
            )


def _snapshot_git_config_key_is_sensitive(key: str) -> bool:
    normalized = key.casefold()
    if normalized.startswith(_SNAPSHOT_SENSITIVE_GIT_CONFIG_PREFIXES):
        return True
    if normalized in {"core.askpass", "core.sshcommand"}:
        return True
    parts = normalized.split(".")
    return len(parts) >= 3 and parts[0] == "remote" and parts[-1] in {
        "proxy",
        "proxyauthmethod",
    }


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
    *,
    declared_roots: tuple[Path, ...] = (),
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
            except (OSError, RuntimeError, ValueError):
                destination.unlink()
                excluded.append(relative)
                continue
            if (
                _is_runtime_state_relative(target_relative.as_posix())
                or is_protected_path(original_root, resolved_target)
                or _matches_declared_root(resolved_target, declared_roots)
            ):
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
        _make_tree_owner_removable(path)
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def _make_tree_owner_removable(root: Path) -> None:
    metadata = root.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        return
    os.chmod(root, stat.S_IMODE(metadata.st_mode) | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    for current, directories, _files in os.walk(root, topdown=True, followlinks=False):
        for name in directories:
            path = Path(current) / name
            entry = path.lstat()
            if stat.S_ISLNK(entry.st_mode) or not stat.S_ISDIR(entry.st_mode):
                continue
            os.chmod(
                path,
                stat.S_IMODE(entry.st_mode) | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR,
                follow_symlinks=False,
            )


def _remove_workspace_relative_path(root: Path, raw_relative: str) -> None:
    relative = Path(raw_relative)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise WorkspaceSnapshotError(f"unsafe workspace-relative removal path: {raw_relative}")
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return
        is_last = index == len(relative.parts) - 1
        if is_last:
            _remove_path(current)
            return
        if stat.S_ISLNK(metadata.st_mode):
            current.unlink(missing_ok=True)
            return
        if not stat.S_ISDIR(metadata.st_mode):
            return


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
    protected_path_masks: list[str],
    runtime_excluded_paths: list[str],
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
            if _is_runtime_state_relative(candidate_relative):
                runtime_excluded_paths.append(candidate_relative)
                ignored.add(name)
                continue
            if name in SNAPSHOT_ALWAYS_IGNORE_NAMES:
                ignored.add(name)
                continue
            if is_protected_path(root, candidate) or is_supervisor_runtime_path(root, candidate):
                protected_path_masks.append(candidate_relative)
                ignored.add(name)
                continue
            if _matches_declared_root(candidate, declared_roots):
                protected_path_masks.append(candidate_relative)
                ignored.add(name)
                continue
            if name in SNAPSHOT_READ_ONLY_DEPENDENCY_NAMES:
                readonly_dependencies.append((candidate, candidate_relative))
                ignored.add(name)
        return ignored

    return ignore


def _is_runtime_state_relative(raw_path: str) -> bool:
    parts = tuple(part.lower() for part in Path(raw_path).parts if part not in {"", "."})
    if not parts:
        return False
    if any(part in SNAPSHOT_RUNTIME_STATE_ANYWHERE_NAMES for part in parts):
        return True
    return parts[0] in SNAPSHOT_RUNTIME_STATE_TOP_LEVEL_NAMES


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


def _relative_roots_within(project_root: Path, roots: tuple[Path, ...]) -> tuple[str, ...]:
    relative: list[str] = []
    for root in roots:
        try:
            candidate = root.relative_to(project_root).as_posix()
        except ValueError:
            continue
        if candidate not in {"", "."}:
            relative.append(candidate)
    return tuple(dict.fromkeys(relative))


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
