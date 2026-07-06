from __future__ import annotations

import tomllib
from pathlib import Path

from click.testing import CliRunner

from supervisor.main import cli


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
    assert "config" in result.output
    assert "doctor" in result.output
    assert "update" in result.output
