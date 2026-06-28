from __future__ import annotations

import importlib.metadata as metadata
import json
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from supervisor import __version__


DISTRIBUTION_NAME = "sentinel"
SKIP_UPDATE_CHECK_ENV = "SENTINEL_SKIP_UPDATE_CHECK"
REMOTE_CHECK_TIMEOUT_SECONDS = 8.0
UPDATE_COMMAND_TIMEOUT_SECONDS = 300.0
NONINTERACTIVE_UPDATE_EXIT_CODE = 17


class UpdateCheckError(RuntimeError):
    pass


class UpdateState(str, Enum):
    CURRENT = "current"
    OUTDATED = "outdated"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class InstallInfo:
    package_name: str
    version: str
    repo_url: str | None
    requested_revision: str | None
    installed_commit: str | None
    install_mode: str
    metadata_available: bool = True
    metadata_location: str | None = None
    warning: str | None = None

    @property
    def source_display(self) -> str:
        if self.repo_url and self.requested_revision:
            return f"{self.repo_url}@{self.requested_revision}"
        if self.repo_url:
            return f"{self.repo_url} (default branch)"
        return "unknown"


@dataclass(frozen=True)
class UpdateStatus:
    state: UpdateState
    install_info: InstallInfo
    latest_commit: str | None = None
    warning: str | None = None

    @property
    def is_current(self) -> bool:
        return self.state == UpdateState.CURRENT

    @property
    def is_outdated(self) -> bool:
        return self.state == UpdateState.OUTDATED


def skip_update_check_enabled(environ: dict[str, str] | None = None) -> bool:
    value = (environ or os.environ).get(SKIP_UPDATE_CHECK_ENV, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def short_sha(value: str | None) -> str:
    if not value:
        return "unknown"
    return value[:7]


def read_install_info(distribution_name: str = DISTRIBUTION_NAME) -> InstallInfo:
    version = __version__
    metadata_location: str | None = None
    direct_url: dict[str, Any] | None = None
    warning: str | None = None

    try:
        dist = metadata.distribution(distribution_name)
    except metadata.PackageNotFoundError:
        dist = None
        warning = f"package metadata for {distribution_name!r} was not found"
    else:
        version = getattr(dist, "version", None) or version
        metadata_location = _distribution_location(dist)
        direct_url = _read_direct_url(dist)

    repo_url: str | None = None
    requested_revision: str | None = None
    installed_commit: str | None = None

    if direct_url:
        repo_url, requested_revision, installed_commit = _pep610_git_info(direct_url)

    build_info = _build_info_fallback()
    repo_url = repo_url or build_info.get("repo_url")
    requested_revision = requested_revision or build_info.get("requested_revision")
    installed_commit = installed_commit or build_info.get("installed_commit")

    git_info = _git_checkout_fallback()
    repo_url = repo_url or git_info.get("repo_url")
    requested_revision = requested_revision or git_info.get("requested_revision")
    installed_commit = installed_commit or git_info.get("installed_commit")

    if warning is None and direct_url is None and not installed_commit:
        warning = "install source metadata does not include a git commit"

    return InstallInfo(
        package_name=distribution_name,
        version=version,
        repo_url=repo_url,
        requested_revision=requested_revision,
        installed_commit=installed_commit,
        install_mode=detect_install_mode(),
        metadata_available=dist is not None,
        metadata_location=metadata_location,
        warning=warning,
    )


def check_for_update(install_info: InstallInfo | None = None) -> UpdateStatus:
    info = install_info or read_install_info()
    if not info.installed_commit:
        return UpdateStatus(UpdateState.UNKNOWN, info, warning="could not determine installed Sentinel commit")
    if not info.repo_url:
        return UpdateStatus(UpdateState.UNKNOWN, info, warning="could not determine Sentinel install source")

    try:
        latest = latest_remote_commit(info.repo_url, info.requested_revision)
    except UpdateCheckError as exc:
        return UpdateStatus(UpdateState.UNKNOWN, info, warning=str(exc))

    if latest.lower() == info.installed_commit.lower():
        return UpdateStatus(UpdateState.CURRENT, info, latest_commit=latest)
    return UpdateStatus(UpdateState.OUTDATED, info, latest_commit=latest)


def latest_remote_commit(repo_url: str, ref: str | None, *, timeout: float = REMOTE_CHECK_TIMEOUT_SECONDS) -> str:
    if _looks_like_full_sha(ref):
        raise UpdateCheckError("could not determine latest commit for a pinned commit ref")
    args = ["git", "ls-remote", repo_url, ref] if ref else ["git", "ls-remote", "--symref", repo_url, "HEAD"]
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise UpdateCheckError("git executable not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise UpdateCheckError("git ls-remote timed out while checking for Sentinel updates") from exc

    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout).strip() or "git ls-remote failed"
        raise UpdateCheckError(message)
    return parse_ls_remote_commit(completed.stdout)


def parse_ls_remote_commit(output: str) -> str:
    rows: list[tuple[str, str]] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        sha, remote_ref = parts[0], parts[1]
        if _looks_like_full_sha(sha):
            rows.append((sha, remote_ref))

    if not rows:
        raise UpdateCheckError("could not determine latest commit for the installed ref")

    peeled = {sha for sha, remote_ref in rows if remote_ref.endswith("^{}")}
    if len(peeled) == 1:
        return next(iter(peeled))
    if len(peeled) > 1:
        raise UpdateCheckError("remote ref matched multiple peeled commits")

    distinct = {sha for sha, _ in rows}
    if len(distinct) != 1:
        raise UpdateCheckError("remote ref is ambiguous")
    return next(iter(distinct))


def install_spec(info: InstallInfo) -> str:
    if not info.repo_url:
        raise UpdateCheckError("could not build a git install spec for this Sentinel install")
    if not info.requested_revision:
        return f"git+{info.repo_url}"
    return f"git+{info.repo_url}@{info.requested_revision}"


def run_update(info: InstallInfo) -> subprocess.CompletedProcess[str]:
    spec = install_spec(info)
    command = update_command(info, spec)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=UPDATE_COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except FileNotFoundError as exc:
        raise UpdateCheckError(str(exc)) from exc
    except subprocess.TimeoutExpired as exc:
        raise UpdateCheckError("Sentinel update command timed out") from exc

    if completed.returncode != 0:
        output = (completed.stdout + completed.stderr).strip()
        detail = f"\n\n{output}" if output else ""
        raise UpdateCheckError(f"Sentinel update command failed.{detail}")
    return completed


def update_command(info: InstallInfo, spec: str) -> list[str]:
    if info.install_mode == "pipx" and shutil.which("pipx"):
        return ["pipx", "install", "--force", spec]
    if _running_inside_venv():
        return [sys.executable, "-m", "pip", "install", "--upgrade", "--force-reinstall", spec]
    raise UpdateCheckError(manual_update_message(info))


def manual_update_message(info: InstallInfo) -> str:
    lines = [
        "Could not update Sentinel automatically.",
        "",
        "Try:",
        f"  pipx reinstall {info.package_name}",
    ]
    if info.repo_url:
        lines.extend(["", "or:", f"  pipx install --force {shlex.quote(install_spec(info))}"])
    return "\n".join(lines)


def detect_install_mode() -> str:
    prefix_parts = {part.lower() for part in Path(sys.prefix).parts}
    if "pipx" in prefix_parts and "venvs" in prefix_parts:
        return "pipx"
    if _running_inside_venv():
        return "venv"
    return "system"


def _running_inside_venv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def _distribution_location(dist: metadata.Distribution) -> str | None:
    try:
        return str(dist.locate_file(""))
    except Exception:
        return None


def _read_direct_url(dist: metadata.Distribution) -> dict[str, Any] | None:
    try:
        text = dist.read_text("direct_url.json")
    except Exception:
        return None
    if not text:
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _pep610_git_info(direct_url: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    repo_url = direct_url.get("url") if isinstance(direct_url.get("url"), str) else None
    vcs_info = direct_url.get("vcs_info")
    if not isinstance(vcs_info, dict) or vcs_info.get("vcs") != "git":
        return repo_url, None, None
    requested_revision = vcs_info.get("requested_revision")
    commit_id = vcs_info.get("commit_id")
    return (
        repo_url,
        requested_revision if isinstance(requested_revision, str) and requested_revision else None,
        commit_id if isinstance(commit_id, str) and commit_id else None,
    )


def _build_info_fallback() -> dict[str, str]:
    try:
        from supervisor import _build
    except Exception:
        return {}
    values = {
        "repo_url": getattr(_build, "SOURCE_URL", None),
        "requested_revision": getattr(_build, "REQUESTED_REVISION", None),
        "installed_commit": getattr(_build, "COMMIT_SHA", None),
    }
    return {key: value for key, value in values.items() if isinstance(value, str) and value}


def _git_checkout_fallback() -> dict[str, str]:
    package_root = Path(__file__).resolve().parents[1]
    git_root = _git_output(["git", "-C", str(package_root), "rev-parse", "--show-toplevel"], timeout=2)
    if not git_root:
        return {}
    root = Path(git_root)
    installed_commit = _git_output(["git", "-C", str(root), "rev-parse", "HEAD"], timeout=2)
    repo_url = _git_output(["git", "-C", str(root), "config", "--get", "remote.origin.url"], timeout=2)
    branch = _git_output(["git", "-C", str(root), "branch", "--show-current"], timeout=2)
    values = {
        "repo_url": repo_url,
        "requested_revision": branch,
        "installed_commit": installed_commit,
    }
    return {key: value for key, value in values.items() if value}


def _git_output(args: list[str], *, timeout: float) -> str | None:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value or None


def _looks_like_full_sha(value: str | None) -> bool:
    if value is None:
        return False
    if len(value) not in {40, 64}:
        return False
    return all(char in "0123456789abcdefABCDEF" for char in value)
