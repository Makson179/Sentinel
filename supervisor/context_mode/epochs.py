"""Controller-owned physical layout for Context Mode state epochs.

The signed native broker remains responsible for descriptor-relative mounting
and deletion.  This module deliberately does only the controller side of the
contract: create a fresh, private epoch skeleton and verify that a binding can
name exactly one run-local workspace/epoch directory.  Old epochs are retained
until the native broker has attested that every writer tree and handle is gone.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from ._util import ContextModeDataError, require_int, require_nonempty


class EpochStateError(ContextModeDataError):
    """The physical Context Mode epoch layout is missing or unsafe."""


EPOCH_DIRECTORIES = ("sessions", "content", "stats", "checkpoints")
EPOCH_DATABASE = "database.sqlite"
_SAFE_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def _safe_component(value: str, field: str) -> str:
    value = require_nonempty(value, field)
    if value in {".", ".."} or _SAFE_COMPONENT.fullmatch(value) is None:
        raise EpochStateError(
            f"{field} is not a bounded path-safe Context Mode identity"
        )
    return value


def _require_private_directory(path: Path, description: str) -> None:
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise EpochStateError(f"{description} is missing or unresolvable: {path}") from exc
    if path != resolved or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise EpochStateError(f"{description} must be a canonical real directory")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise EpochStateError(f"{description} mode must be 0700")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise EpochStateError(f"{description} owner does not match the controller")


def _require_private_database(path: Path, *, pristine: bool) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise EpochStateError(f"epoch database is missing: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise EpochStateError("epoch database must be a regular non-symlink file")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise EpochStateError("epoch database mode must be 0600")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise EpochStateError("epoch database owner does not match the controller")
    if pristine and info.st_size != 0:
        raise EpochStateError("new Context Mode epoch database is not empty")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class ContextEpochLayout:
    """Exact ``workspaces/<id>/epochs/<n>`` state namespace for one workspace."""

    context_root: Path
    workspace_id: str

    def __post_init__(self) -> None:
        root = Path(self.context_root)
        if not root.is_absolute():
            raise EpochStateError("Context Mode state root must be absolute")
        _require_private_directory(root, "Context Mode state root")
        object.__setattr__(self, "context_root", root)
        object.__setattr__(self, "workspace_id", _safe_component(self.workspace_id, "workspace_id"))

    @property
    def workspaces_root(self) -> Path:
        return self.context_root / "workspaces"

    @property
    def workspace_root(self) -> Path:
        return self.workspaces_root / self.workspace_id

    @property
    def epochs_root(self) -> Path:
        return self.workspace_root / "epochs"

    def epoch_root(self, epoch: int) -> Path:
        require_int(epoch, "context_state_epoch")
        return self.epochs_root / str(epoch)

    def _ensure_namespace(self) -> None:
        parent = self.context_root
        for child in (
            self.workspaces_root,
            self.workspace_root,
            self.epochs_root,
        ):
            try:
                child.mkdir(mode=0o700, exist_ok=False)
            except FileExistsError:
                pass
            _require_private_directory(child, "Context Mode epoch namespace")
            _fsync_directory(parent)
            parent = child

    def create_fresh_epoch(self, epoch: int) -> Path:
        """Create a durable empty epoch and refuse any pre-existing target."""

        require_int(epoch, "context_state_epoch")
        self._ensure_namespace()
        root = self.epoch_root(epoch)
        try:
            root.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError as exc:
            raise EpochStateError(
                f"Context Mode epoch {epoch} already exists; refusing state reuse"
            ) from exc
        try:
            for name in EPOCH_DIRECTORIES:
                directory = root / name
                directory.mkdir(mode=0o700, exist_ok=False)
                _require_private_directory(directory, f"epoch {name} directory")
            database = root / EPOCH_DATABASE
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(database, flags, 0o600)
            try:
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _fsync_directory(root)
            _fsync_directory(self.epochs_root)
            self.validate_epoch(epoch, pristine=True)
            return root
        except BaseException:
            # Never recursively remove an authority-state path here.  A partial
            # epoch is quarantined and a retry must choose a new run root.
            raise

    def validate_epoch(self, epoch: int, *, pristine: bool = False) -> Path:
        """Validate required objects without following a substituted component."""

        root = self.epoch_root(epoch)
        _require_private_directory(self.context_root, "Context Mode state root")
        _require_private_directory(self.workspaces_root, "Context Mode workspaces root")
        _require_private_directory(self.workspace_root, "Context Mode workspace state root")
        _require_private_directory(self.epochs_root, "Context Mode epochs root")
        _require_private_directory(root, "Context Mode active epoch root")
        for name in EPOCH_DIRECTORIES:
            _require_private_directory(root / name, f"epoch {name} directory")
        _require_private_database(root / EPOCH_DATABASE, pristine=pristine)
        return root

