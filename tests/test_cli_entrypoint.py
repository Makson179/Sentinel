from __future__ import annotations

import argparse
import importlib.util
import sys
import tomllib
from pathlib import Path
from types import ModuleType

from click.testing import CliRunner

from supervisor.main import cli


def _load_specbench_runner() -> ModuleType:
    runner_path = Path(__file__).resolve().parents[1] / "scripts" / "run_sentinel_specbench_attempt.py"
    spec = importlib.util.spec_from_file_location("run_sentinel_specbench_attempt", runner_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_project_installs_sentinel_console_script() -> None:
    project_root = Path(__file__).resolve().parents[1]
    metadata = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))

    scripts = metadata["project"]["scripts"]

    assert metadata["project"]["name"] == "sentinel"
    assert scripts["sentinel"] == "supervisor.main:cli"
    assert "supervisor" not in scripts


def test_cli_help_uses_sentinel_command_name() -> None:
    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "Usage: sentinel [OPTIONS]" in result.output


def test_runner_default_cli_paths_are_platform_specific(monkeypatch, tmp_path: Path) -> None:
    runner = _load_specbench_runner()
    args = argparse.Namespace(sentinel_bin=None)

    monkeypatch.setattr(runner.os, "name", "posix")

    assert runner.resolve_sentinel_bin(args, tmp_path) == tmp_path / ".venv" / "bin" / "sentinel"
    assert runner.resolve_venv_python(tmp_path / ".venv") == tmp_path / ".venv" / "bin" / "python3"

    monkeypatch.setattr(runner.os, "name", "nt")

    assert runner.resolve_sentinel_bin(args, tmp_path) == tmp_path / ".venv" / "Scripts" / "sentinel.exe"
    assert runner.resolve_venv_python(tmp_path / ".venv") == tmp_path / ".venv" / "Scripts" / "python.exe"
