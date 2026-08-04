"""Small, dependency-free helpers shared by the Context Mode foundation.

The helpers in this module deliberately do not try to replace descriptor-relative
path resolution performed by the native runtime broker.  They are suitable for
controller-owned metadata and generated configuration files.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any


class ContextModeDataError(ValueError):
    """Raised when versioned Context Mode data is malformed."""


def canonical_json_bytes(value: Any) -> bytes:
    """Return a deterministic, strict JSON representation.

    ``allow_nan=False`` matters for approval and receipt digests: NaN has several
    spellings and is not JSON.  Mapping keys must be strings so Python's implicit
    key coercion cannot create digest collisions.
    """

    _validate_json_value(value)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return encoded.encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ContextModeDataError(f"value is not strict JSON: {exc}") from exc


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    if depth > 64:
        raise ContextModeDataError("JSON value exceeds maximum nesting depth")
    if value is None or isinstance(value, (str, int, float, bool)):
        return
    if isinstance(value, list) or isinstance(value, tuple):
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContextModeDataError("JSON mapping keys must be strings")
            _validate_json_value(item, depth=depth + 1)
        return
    raise ContextModeDataError(f"unsupported JSON value: {type(value).__name__}")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_json(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def require_sha256(value: str, field: str = "digest") -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ContextModeDataError(f"{field} must be a lowercase SHA-256 hex digest")
    return value


def require_nonempty(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ContextModeDataError(f"{field} must be a non-empty string without NUL")
    return value


def require_int(value: int, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContextModeDataError(f"{field} must be an integer >= {minimum}")
    return value


def ensure_private_directory(path: Path) -> Path:
    """Create a controller-owned directory and reject a symlink at the leaf."""

    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
        info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ContextModeDataError(f"private directory is not a real directory: {path}")
    os.chmod(path, 0o700)
    return path


def atomic_write_bytes(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    """Durably replace a small controller-owned metadata file.

    Native broker policy files additionally need fd-relative owner/device checks;
    those checks belong to the OS adapter and are intentionally not simulated here.
    """

    path = Path(path)
    parent = path.parent
    if not parent.exists():
        ensure_private_directory(parent)
    parent_info = parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise ContextModeDataError(f"metadata parent is not a real directory: {parent}")
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and (stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)):
        raise ContextModeDataError(f"metadata target is not a regular file: {path}")

    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            fd = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def atomic_write_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    atomic_write_bytes(path, canonical_json_bytes(value) + b"\n", mode=mode)


def load_json_object(path: Path, *, max_bytes: int = 1024 * 1024) -> dict[str, Any]:
    path = Path(path)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ContextModeDataError(f"expected a regular JSON file: {path}")
    if info.st_size > max_bytes:
        raise ContextModeDataError(f"JSON file exceeds {max_bytes} bytes: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContextModeDataError(f"cannot read JSON file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ContextModeDataError(f"expected a JSON object: {path}")
    return value


def strict_object(
    value: Mapping[str, Any],
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
    name: str,
) -> None:
    keys = frozenset(value)
    missing = required - keys
    unknown = keys - required - optional
    if missing:
        raise ContextModeDataError(f"{name} is missing fields: {sorted(missing)!r}")
    if unknown:
        raise ContextModeDataError(f"{name} contains unknown fields: {sorted(unknown)!r}")
