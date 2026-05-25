from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field


@dataclass
class CapabilityReport:
    executable: str
    available: bool
    version_output: str = ""
    help_output: str = ""
    missing: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.available and not self.missing


def run_probe(args: list[str], timeout: float = 5.0) -> tuple[bool, str]:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    output = (completed.stdout + completed.stderr).strip()
    return completed.returncode == 0, output


def probe_claude(executable: str = "claude") -> CapabilityReport:
    if shutil.which(executable) is None:
        return CapabilityReport(executable=executable, available=False, missing=["claude executable not found"])
    _, version = run_probe([executable, "--version"])
    _, help_text = run_probe([executable, "--help"])
    missing = []
    if "-p" not in help_text and "--print" not in help_text:
        missing.append("headless prompt mode")
    return CapabilityReport(executable=executable, available=True, version_output=version, help_output=help_text, missing=missing)


def probe_codex(executable: str = "codex") -> CapabilityReport:
    if shutil.which(executable) is None:
        return CapabilityReport(executable=executable, available=False, missing=["codex executable not found"])
    _, version = run_probe([executable, "--version"])
    _, exec_help_text = run_probe([executable, "exec", "--help"])
    _, app_server_help_text = run_probe([executable, "app-server", "--help"])
    help_text = f"{exec_help_text}\n{app_server_help_text}"
    missing = []
    if "exec" not in exec_help_text and "Usage" not in exec_help_text:
        missing.append("codex exec")
    if "--ignore-user-config" not in exec_help_text:
        missing.append("codex exec --ignore-user-config")
    if "--skip-git-repo-check" not in exec_help_text:
        missing.append("codex exec --skip-git-repo-check")
    if "--dangerously-bypass-hook-trust" not in exec_help_text:
        missing.append("codex exec --dangerously-bypass-hook-trust")
    if "--sandbox" not in exec_help_text:
        missing.append("codex exec --sandbox")
    if "--json" not in exec_help_text and "--experimental-json" not in exec_help_text:
        missing.append("codex exec --json")
    if "app-server" not in app_server_help_text or "--listen" not in app_server_help_text:
        missing.append("codex app-server --listen stdio://")
    return CapabilityReport(executable=executable, available=True, version_output=version, help_output=help_text, missing=missing)
