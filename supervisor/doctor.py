from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from supervisor.appserver import AppServerClient
from supervisor import update_check


APP_SERVER_REQUIRED_SCHEMA_FILES = (
    "ClientRequest.json",
    "ServerRequest.json",
    "TurnStartParams.json",
    "CommandExecutionRequestApprovalParams.json",
)


DoctorLevel = Literal["ok", "warn", "fail"]


@dataclass(frozen=True)
class DoctorResult:
    level: DoctorLevel
    message: str
    detail: str | None = None


def run_doctor() -> int:
    results = collect_doctor_results()
    print("Sentinel doctor")
    print()
    for result in results:
        print(format_result(result))
        if result.detail:
            print(f"  {result.detail}")
    return 1 if any(result.level == "fail" for result in results) else 0


def collect_doctor_results() -> list[DoctorResult]:
    results: list[DoctorResult] = []
    results.append(_python_version_result())

    git_path = shutil.which("git")
    results.append(
        DoctorResult("ok", f"Git found: {git_path}") if git_path else DoctorResult("fail", "Git not found on PATH")
    )

    codex_path = shutil.which("codex")
    results.append(
        DoctorResult("ok", f"Codex found: {codex_path}") if codex_path else DoctorResult("fail", "Codex not found on PATH")
    )
    if codex_path:
        results.append(_probe_result(["codex", "--version"], "Codex version OK", "codex --version failed"))
        results.append(_probe_result(["codex", "app-server", "--help"], "Codex app-server supported", "codex app-server --help failed"))
        results.append(_schema_generation_result())
        results.append(_codex_auth_result())
    else:
        results.extend(
            [
                DoctorResult("fail", "codex --version failed", "Codex executable not found on PATH"),
                DoctorResult("fail", "Codex app-server support not checked", "Codex executable not found on PATH"),
                DoctorResult("fail", "app-server schema generation not checked", "Codex executable not found on PATH"),
                DoctorResult("fail", "Codex auth check failed", "Codex executable not found on PATH"),
            ]
        )

    info = update_check.read_install_info()
    if not info.metadata_available:
        results.append(DoctorResult("fail", "Sentinel package metadata could not be read", info.warning))
    else:
        results.append(DoctorResult("ok", f"Sentinel package: {info.package_name} {info.version}"))

    executable = shutil.which("sentinel")
    if executable:
        results.append(DoctorResult("ok", f"Sentinel executable: {executable}"))
    else:
        results.append(DoctorResult("warn", "sentinel command not found on PATH"))
    results.append(DoctorResult("ok", f"Sentinel install mode: {info.install_mode}"))

    status = update_check.check_for_update(info)
    if status.state == update_check.UpdateState.CURRENT:
        results.append(DoctorResult("ok", "Sentinel is up to date"))
    elif status.state == update_check.UpdateState.OUTDATED:
        results.append(
            DoctorResult(
                "warn",
                f"Update available: {status.latest_version}",
                "Run: sentinel update",
            )
        )
    else:
        results.append(DoctorResult("warn", "Could not check for Sentinel updates", status.warning))

    return results


def format_result(result: DoctorResult) -> str:
    marker = {"ok": "[OK]", "warn": "[WARN]", "fail": "[FAIL]"}[result.level]
    return f"{marker} {result.message}"


def _python_version_result() -> DoctorResult:
    version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 11):
        return DoctorResult("ok", f"Python {version}")
    return DoctorResult("fail", f"Python {version}", "Python 3.11 or newer is required")


def _probe_result(args: list[str], ok_message: str, fail_message: str, *, timeout: float = 10.0) -> DoctorResult:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        return DoctorResult("fail", fail_message, str(exc))
    except subprocess.TimeoutExpired:
        return DoctorResult("fail", fail_message, f"{args[0]} timed out")
    output = (completed.stdout + completed.stderr).strip()
    if completed.returncode == 0:
        detail = output.splitlines()[0] if output else None
        return DoctorResult("ok", ok_message, detail)
    return DoctorResult("fail", fail_message, output or f"exit code {completed.returncode}")


def _schema_generation_result() -> DoctorResult:
    with tempfile.TemporaryDirectory(prefix="sentinel-doctor-schema-") as tmp_dir:
        out_dir = Path(tmp_dir)
        try:
            completed = subprocess.run(
                ["codex", "app-server", "generate-json-schema", "--experimental", "--out", str(out_dir)],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return DoctorResult("fail", "app-server schema generation failed", str(exc))
        if completed.returncode != 0:
            return DoctorResult("fail", "app-server schema generation failed", (completed.stdout + completed.stderr).strip())

        for name in APP_SERVER_REQUIRED_SCHEMA_FILES:
            path = _schema_file(out_dir, name)
            if path is None:
                return DoctorResult("fail", f"app-server schema missing required file: {name}")
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:
                return DoctorResult("fail", f"app-server schema file unreadable: {name}", str(exc))
    return DoctorResult("ok", "app-server schema generation OK")


def _schema_file(out_dir: Path, name: str) -> Path | None:
    direct = out_dir / name
    if direct.exists():
        return direct
    nested = out_dir / "v2" / name
    if nested.exists():
        return nested
    return None


def _codex_auth_result() -> DoctorResult:
    async def probe() -> DoctorResult:
        client = AppServerClient()
        try:
            await asyncio.wait_for(client.start(), timeout=10)
            await client.initialize(timeout=10)
            account = await client.account_read(timeout=10)
            await client.config_requirements_read(timeout=10)
        except Exception as exc:
            return DoctorResult("fail", "Codex auth check failed", str(exc))
        finally:
            await client.stop()
        if account.get("requiresOpenaiAuth") and account.get("account") is None:
            return DoctorResult("fail", "Codex auth missing", "Run: codex login")
        return DoctorResult("ok", "Codex auth OK")

    return asyncio.run(probe())
