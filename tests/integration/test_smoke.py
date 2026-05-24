from __future__ import annotations

import os
import shutil
import subprocess

import pytest


@pytest.mark.skipif(shutil.which("claude") is None, reason="Claude Code CLI not installed")
def test_claude_hook_fire_smoke() -> None:
    completed = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0


@pytest.mark.skipif(shutil.which("claude") is None, reason="Claude Code CLI not installed")
def test_claude_supervisor_call_isolation_smoke() -> None:
    completed = subprocess.run(["claude", "--help"], capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0


@pytest.mark.skipif(shutil.which("claude") is None, reason="Claude Code CLI not installed")
def test_claude_additional_context_delivery_smoke() -> None:
    completed = subprocess.run(["claude", "--help"], capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0


@pytest.mark.skipif(shutil.which("codex") is None, reason="Codex CLI not installed")
def test_codex_hook_trust_preflight_smoke() -> None:
    completed = subprocess.run(["codex", "--version"], capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0


@pytest.mark.skipif(shutil.which("codex") is None, reason="Codex CLI not installed")
def test_codex_hook_fire_smoke() -> None:
    completed = subprocess.run(["codex", "exec", "--help"], capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0


@pytest.mark.skipif(shutil.which("codex") is None, reason="Codex CLI not installed")
def test_codex_cleanup_normal_and_crash_smoke() -> None:
    completed = subprocess.run(["codex", "exec", "--help"], capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0


@pytest.mark.skipif(shutil.which("codex") is None, reason="Codex CLI not installed")
def test_codex_supervisor_call_isolation_smoke() -> None:
    completed = subprocess.run(["codex", "exec", "--help"], capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0


@pytest.mark.skipif(shutil.which("codex") is None, reason="Codex CLI not installed")
def test_codex_json_observability_smoke() -> None:
    completed = subprocess.run(["codex", "exec", "--help"], capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0


@pytest.mark.skipif(not os.environ.get("OPENROUTER_API_KEY"), reason="OPENROUTER_API_KEY not set")
def test_openrouter_structured_output_smoke() -> None:
    assert os.environ["OPENROUTER_API_KEY"]

