from __future__ import annotations

import importlib.metadata as metadata
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from supervisor import __version__


DISTRIBUTION_NAME = "sentinel-supervisor"
SKIP_UPDATE_CHECK_ENV = "SENTINEL_SKIP_UPDATE_CHECK"
REMOTE_CHECK_TIMEOUT_SECONDS = 8.0
UPDATE_COMMAND_TIMEOUT_SECONDS = 300.0
NONINTERACTIVE_UPDATE_EXIT_CODE = 17
PYPI_JSON_BASE_URL = "https://pypi.org/pypi"


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
    install_mode: str
    metadata_available: bool = True
    metadata_location: str | None = None
    warning: str | None = None


@dataclass(frozen=True)
class UpdateStatus:
    state: UpdateState
    install_info: InstallInfo
    latest_version: str | None = None
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


def read_install_info(distribution_name: str = DISTRIBUTION_NAME) -> InstallInfo:
    version = __version__
    metadata_location: str | None = None
    warning: str | None = None
    metadata_available = True

    try:
        dist = metadata.distribution(distribution_name)
    except metadata.PackageNotFoundError:
        metadata_available = False
        warning = f"package metadata for {distribution_name!r} was not found"
    else:
        version = getattr(dist, "version", None) or version
        metadata_location = _distribution_location(dist)

    return InstallInfo(
        package_name=distribution_name,
        version=version,
        install_mode=detect_install_mode(),
        metadata_available=metadata_available,
        metadata_location=metadata_location,
        warning=warning,
    )


def check_for_update(install_info: InstallInfo | None = None) -> UpdateStatus:
    info = install_info or read_install_info()
    try:
        latest = latest_pypi_version(info.package_name)
        installed_version = Version(info.version)
        latest_version = Version(latest)
    except (UpdateCheckError, InvalidVersion) as exc:
        return UpdateStatus(UpdateState.UNKNOWN, info, warning=str(exc))

    if latest_version > installed_version:
        return UpdateStatus(UpdateState.OUTDATED, info, latest_version=latest)
    return UpdateStatus(UpdateState.CURRENT, info, latest_version=latest)


def latest_pypi_version(
    package_name: str,
    *,
    timeout: float = REMOTE_CHECK_TIMEOUT_SECONDS,
    base_url: str = PYPI_JSON_BASE_URL,
) -> str:
    quoted_name = urllib.parse.quote(package_name, safe="")
    url = f"{base_url.rstrip('/')}/{quoted_name}/json"
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise UpdateCheckError(f"package {package_name!r} was not found on PyPI") from exc
        raise UpdateCheckError(f"PyPI returned HTTP {exc.code} while checking for updates") from exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise UpdateCheckError(f"could not reach PyPI while checking for updates: {reason}") from exc
    except TimeoutError as exc:
        raise UpdateCheckError("PyPI update check timed out") from exc

    try:
        payload: Any = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateCheckError("PyPI returned invalid JSON while checking for updates") from exc

    if not isinstance(payload, dict):
        raise UpdateCheckError("PyPI returned an invalid response while checking for updates")
    info = payload.get("info")
    if not isinstance(info, dict):
        raise UpdateCheckError("PyPI response did not include package info")
    version = info.get("version")
    if not isinstance(version, str) or not version.strip():
        raise UpdateCheckError("PyPI response did not include a latest version")
    return version


def run_update(info: InstallInfo) -> subprocess.CompletedProcess[str]:
    command = update_command(info)
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


def update_command(info: InstallInfo) -> list[str]:
    if info.install_mode == "pipx" and shutil.which("pipx"):
        return ["pipx", "upgrade", info.package_name]
    if _running_inside_venv():
        return [sys.executable, "-m", "pip", "install", "--upgrade", info.package_name]
    raise UpdateCheckError(manual_update_message(info))


def manual_update_message(info: InstallInfo) -> str:
    return "\n".join(
        [
            "Could not update Sentinel automatically.",
            "",
            "Try:",
            f"  pipx upgrade {info.package_name}",
            "",
            "or:",
            f"  pipx install --force {info.package_name}",
        ]
    )


def detect_install_mode() -> str:
    prefix = Path(sys.prefix)
    if (prefix / "pipx_metadata.json").exists():
        return "pipx"
    prefix_parts = {part.lower() for part in prefix.parts}
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
