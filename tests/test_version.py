from __future__ import annotations

import shutil

from supervisor.version import probe_codex


def test_codex_probe_requires_exec_flags(monkeypatch) -> None:
    def fake_run_probe(args, timeout=5.0):
        if args == ["codex", "--version"]:
            return True, "codex 0.130.0"
        if args == ["codex", "exec", "--help"]:
            return True, "Usage: codex exec\n--ignore-user-config\n--skip-git-repo-check\n--dangerously-bypass-hook-trust\n--sandbox\n--json"
        if args == ["codex", "app-server", "--help"]:
            return True, "Usage: codex app-server\n--listen <URL>"
        raise AssertionError(args)

    monkeypatch.setattr(shutil, "which", lambda executable: "/usr/bin/codex")
    monkeypatch.setattr("supervisor.version.run_probe", fake_run_probe)

    assert probe_codex().ok


def test_codex_probe_reports_missing_exec_flags(monkeypatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda executable: "/usr/bin/codex")
    monkeypatch.setattr("supervisor.version.run_probe", lambda args, timeout=5.0: (True, "Usage: codex exec"))

    report = probe_codex()

    assert "codex exec --ignore-user-config" in report.missing
    assert "codex exec --skip-git-repo-check" in report.missing
    assert "codex exec --dangerously-bypass-hook-trust" in report.missing
    assert "codex exec --sandbox" in report.missing
    assert "codex exec --json" in report.missing
    assert "codex app-server --listen stdio://" in report.missing
