from __future__ import annotations

import asyncio
import io
import json

import click
from click.testing import CliRunner
import pytest

from supervisor import update_check
from supervisor.controller import DEFAULT_MODEL
from supervisor.project_config import DEFAULT_INTELLIGENCE
from supervisor.main import _format_version_report, _startup_update_gate, _update_and_reexec, cli


VERSION_A = "0.1.0"
VERSION_B = "0.1.1"


def _info(version: str = VERSION_A) -> update_check.InstallInfo:
    return update_check.InstallInfo(
        package_name="sentinel-supervisor",
        version=version,
        install_mode="pipx",
    )


def _status(state: update_check.UpdateState, latest: str | None = VERSION_A) -> update_check.UpdateStatus:
    return update_check.UpdateStatus(state, _info(), latest_version=latest)


class NonTty(io.StringIO):
    def isatty(self) -> bool:
        return False


class Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_version_report_shows_update_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        update_check,
        "check_for_update",
        lambda: update_check.UpdateStatus(update_check.UpdateState.OUTDATED, _info(VERSION_A), latest_version=VERSION_B),
    )

    report = _format_version_report()

    assert "Sentinel 0.1.0" in report
    assert "installed: 0.1.0" in report
    assert "latest:    0.1.1" in report
    assert "sentinel update" in report


def test_startup_gate_warns_and_continues_when_outdated_without_tty(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(update_check, "check_for_update", lambda: _status(update_check.UpdateState.OUTDATED, VERSION_B))
    monkeypatch.setattr("supervisor.main.sys.stdin", NonTty())

    _startup_update_gate()

    captured = capsys.readouterr()
    assert "A newer Sentinel version is available." in captured.err
    assert "continuing without prompting" in captured.err
    assert "Set SENTINEL_SKIP_UPDATE_CHECK=1" in captured.err


def test_startup_gate_warns_and_continues_when_update_check_is_unknown(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        update_check,
        "check_for_update",
        lambda: update_check.UpdateStatus(
            update_check.UpdateState.UNKNOWN,
            _info(),
            warning="could not reach PyPI",
        ),
    )

    _startup_update_gate()

    captured = capsys.readouterr()
    assert "Could not check for Sentinel updates" in captured.err
    assert "could not reach PyPI" in captured.err


def test_startup_gate_continues_on_interactive_continue(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_check, "check_for_update", lambda: _status(update_check.UpdateState.OUTDATED, VERSION_B))
    monkeypatch.setattr("supervisor.main.sys.stdin", Tty())
    monkeypatch.setattr("builtins.input", lambda prompt: "c")

    _startup_update_gate()


def test_startup_gate_accepts_case_and_retries_invalid_selection(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    responses = iter(["x", " C\r"])
    monkeypatch.setattr(update_check, "check_for_update", lambda: _status(update_check.UpdateState.OUTDATED, VERSION_B))
    monkeypatch.setattr("supervisor.main.sys.stdin", Tty())
    monkeypatch.setattr("builtins.input", lambda prompt: next(responses))

    _startup_update_gate()

    assert "Please choose u, c, or q." in capsys.readouterr().out


def test_startup_gate_quit_exits_without_running_task(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_check, "check_for_update", lambda: _status(update_check.UpdateState.OUTDATED, VERSION_B))
    monkeypatch.setattr("supervisor.main.sys.stdin", Tty())
    monkeypatch.setattr("builtins.input", lambda prompt: "q")

    with pytest.raises(click.exceptions.Exit) as exc_info:
        _startup_update_gate()

    assert exc_info.value.exit_code == 0


def test_startup_gate_update_choice_updates_and_reexecs(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []
    monkeypatch.setattr(update_check, "check_for_update", lambda: _status(update_check.UpdateState.OUTDATED, VERSION_B))
    monkeypatch.setattr("supervisor.main.sys.stdin", Tty())
    monkeypatch.setattr("builtins.input", lambda prompt: "u")
    monkeypatch.setattr(update_check, "run_update", lambda info: calls.append(info))

    def fake_execvp(program: str, args: list[str]) -> None:
        calls.append((program, list(args)))
        raise RuntimeError("reexec requested")

    monkeypatch.setattr("supervisor.main.os.execvp", fake_execvp)

    with pytest.raises(RuntimeError, match="reexec requested"):
        _startup_update_gate()

    assert calls[0] == _info()
    assert isinstance(calls[1], tuple)


@pytest.mark.parametrize(
    "argv",
    [
        ["sentinel", "--task", "TASK.md"],
        ["/Users/alex/.local/bin/sentinel", "--task", "TASK.md"],
        [r"C:\Users\alex\.local\bin\sentinel.exe", "--task", "TASK.md"],
    ],
)
def test_update_reexec_preserves_original_launcher_and_task_args(
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(update_check, "run_update", lambda info: calls.append(info))
    monkeypatch.setattr("supervisor.main.sys.argv", argv)

    def fake_execvp(program: str, args: list[str]) -> None:
        calls.append((program, args))
        raise RuntimeError("reexec requested")

    monkeypatch.setattr("supervisor.main.os.execvp", fake_execvp)

    with pytest.raises(RuntimeError, match="reexec requested"):
        _update_and_reexec(_status(update_check.UpdateState.OUTDATED, VERSION_B))

    assert calls == [_info(), (argv[0], argv)]


def test_startup_gate_skip_env_bypasses_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(update_check.SKIP_UPDATE_CHECK_ENV, "1")
    monkeypatch.setattr(update_check, "check_for_update", lambda: pytest.fail("update check should be skipped"))

    _startup_update_gate()


def test_update_command_reports_current(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_check, "check_for_update", lambda: _status(update_check.UpdateState.CURRENT, VERSION_A))

    result = CliRunner().invoke(cli, ["update"])

    assert result.exit_code == 0
    assert "Sentinel is up to date." in result.output
    assert "Installed: 0.1.0" in result.output


def test_update_check_reports_outdated_without_installing(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[update_check.InstallInfo] = []
    monkeypatch.setattr(
        update_check,
        "check_for_update",
        lambda: update_check.UpdateStatus(update_check.UpdateState.OUTDATED, _info(VERSION_A), latest_version=VERSION_B),
    )
    monkeypatch.setattr(update_check, "run_update", lambda info: calls.append(info))

    result = CliRunner().invoke(cli, ["update", "--check"])

    assert result.exit_code == 0
    assert calls == []
    assert "status: update available" in result.output
    assert "installed: 0.1.0" in result.output
    assert "latest:    0.1.1" in result.output


def test_update_check_json_reports_unknown_without_failing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        update_check,
        "check_for_update",
        lambda: update_check.UpdateStatus(
            update_check.UpdateState.UNKNOWN,
            _info(VERSION_A),
            warning="PyPI returned invalid JSON",
        ),
    )

    result = CliRunner().invoke(cli, ["update", "--check", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload == {
        "package": "sentinel-supervisor",
        "installed_version": "0.1.0",
        "latest_version": None,
        "state": "unknown",
        "update_available": False,
        "install_mode": "pipx",
        "warning": "PyPI returned invalid JSON",
    }


def test_update_command_runs_update_when_outdated(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[update_check.InstallInfo] = []
    monkeypatch.setattr(
        update_check,
        "check_for_update",
        lambda: update_check.UpdateStatus(update_check.UpdateState.OUTDATED, _info(VERSION_A), latest_version=VERSION_B),
    )
    monkeypatch.setattr(update_check, "run_update", lambda info: calls.append(info))

    result = CliRunner().invoke(cli, ["update"])

    assert result.exit_code == 0
    assert calls == [_info(VERSION_A)]
    assert "Previous: 0.1.0" in result.output
    assert "Current:  0.1.1" in result.output


def test_version_option_bypasses_startup_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        update_check,
        "check_for_update",
        lambda: update_check.UpdateStatus(update_check.UpdateState.CURRENT, _info(VERSION_A), latest_version=VERSION_A),
    )
    monkeypatch.setattr("supervisor.main._startup_update_gate", lambda: pytest.fail("startup gate should not run"))

    result = CliRunner().invoke(cli, ["--version"])

    assert result.exit_code == 0
    assert "Sentinel 0.1.0" in result.output


def test_version_option_reports_unknown_update_status_without_failing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        update_check,
        "check_for_update",
        lambda: update_check.UpdateStatus(
            update_check.UpdateState.UNKNOWN,
            _info(VERSION_A),
            warning="could not reach PyPI",
        ),
    )

    result = CliRunner().invoke(cli, ["--version"])

    assert result.exit_code == 0
    assert "Sentinel 0.1.0" in result.output
    assert "status: unknown" in result.output
    assert "could not reach PyPI" in result.output


@pytest.mark.parametrize("platform_name", ["linux", "darwin", "win32"])
def test_cli_update_continue_runs_original_task_on_supported_platforms(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    platform_name: str,
) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    calls: list[tuple[object, ...]] = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("supervisor.main.sys.platform", platform_name)
    monkeypatch.setattr("supervisor.main.sys.stdin", Tty())
    monkeypatch.setattr("builtins.input", lambda prompt: "c")
    monkeypatch.setattr(update_check, "check_for_update", lambda: _status(update_check.UpdateState.OUTDATED, VERSION_B))

    async def fake_run_sentinel(settings):
        calls.append(
            (
                settings.task_path,
                settings.coder_model,
                settings.runtime_model,
                settings.completion_model,
                settings.adversary_model,
                settings.coder_intelligence,
                settings.runtime_intelligence,
                settings.completion_intelligence,
                settings.adversary_intelligence,
                settings.fast,
                settings.start_over,
                settings.protected_paths,
                settings.clean,
                settings.adversary,
            )
        )
        return 0

    def fake_run_async_cleanly(coro):
        assert asyncio.run(coro) == 0
        calls.append(("runtime-started",))

    monkeypatch.setattr("supervisor.main._run_sentinel", fake_run_sentinel)
    monkeypatch.setattr("supervisor.main._run_async_cleanly", fake_run_async_cleanly)

    result = cli.main(
        args=["--task", str(task), "--start-over"],
        prog_name="sentinel",
        standalone_mode=False,
    )

    assert result is None
    assert calls == [
        (
            task,
            DEFAULT_MODEL,
            DEFAULT_MODEL,
            DEFAULT_MODEL,
            DEFAULT_MODEL,
            DEFAULT_INTELLIGENCE,
            DEFAULT_INTELLIGENCE,
            DEFAULT_INTELLIGENCE,
            DEFAULT_INTELLIGENCE,
            False,
            True,
            (),
            False,
            True,
        ),
        ("runtime-started",),
    ]


def test_cli_fast_flag_reaches_runner(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    calls: list[tuple[object, ...]] = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("supervisor.main._startup_update_gate", lambda: None)

    async def fake_run_sentinel(settings):
        calls.append(
            (
                settings.task_path,
                settings.coder_model,
                settings.runtime_model,
                settings.completion_model,
                settings.adversary_model,
                settings.coder_intelligence,
                settings.runtime_intelligence,
                settings.completion_intelligence,
                settings.adversary_intelligence,
                settings.fast,
                settings.start_over,
                settings.protected_paths,
                settings.clean,
                settings.adversary,
            )
        )
        return 0

    def fake_run_async_cleanly(coro):
        assert asyncio.run(coro) == 0

    monkeypatch.setattr("supervisor.main._run_sentinel", fake_run_sentinel)
    monkeypatch.setattr("supervisor.main._run_async_cleanly", fake_run_async_cleanly)

    result = cli.main(
        args=["--task", str(task), "--fast"],
        prog_name="sentinel",
        standalone_mode=False,
    )

    assert result is None
    assert calls == [
        (
            task,
            DEFAULT_MODEL,
            DEFAULT_MODEL,
            DEFAULT_MODEL,
            DEFAULT_MODEL,
            DEFAULT_INTELLIGENCE,
            DEFAULT_INTELLIGENCE,
            DEFAULT_INTELLIGENCE,
            DEFAULT_INTELLIGENCE,
            True,
            True,
            (),
            False,
            True,
        )
    ]


def test_cli_boolean_false_overrides_project_config(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    calls: list[tuple[object, ...]] = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("supervisor.main._startup_update_gate", lambda: None)

    async def fake_run_sentinel(settings):
        calls.append((settings.fast, settings.start_over, settings.clean, settings.adversary))
        return 0

    def fake_run_async_cleanly(coro):
        assert asyncio.run(coro) == 0

    monkeypatch.setattr("supervisor.main._run_sentinel", fake_run_sentinel)
    monkeypatch.setattr("supervisor.main._run_async_cleanly", fake_run_async_cleanly)

    result = cli.main(
        args=["--task", str(task), "--start-over=false", "--adversary=false", "--clean=false", "--fast=false"],
        prog_name="sentinel",
        standalone_mode=False,
    )

    assert result is None
    assert calls == [(False, False, False, False)]


def test_cli_completion_review_flag_reaches_runner(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    calls: list[bool] = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("supervisor.main._startup_update_gate", lambda: None)

    async def fake_run_sentinel(settings):
        calls.append(settings.completion_review)
        return 0

    def fake_run_async_cleanly(coro):
        assert asyncio.run(coro) == 0

    monkeypatch.setattr("supervisor.main._run_sentinel", fake_run_sentinel)
    monkeypatch.setattr("supervisor.main._run_async_cleanly", fake_run_async_cleanly)

    result = cli.main(
        args=["--task", str(task), "--completion-review=false"],
        prog_name="sentinel",
        standalone_mode=False,
    )

    assert result is None
    assert calls == [False]

    result = cli.main(
        args=["--task", str(task)],
        prog_name="sentinel",
        standalone_mode=False,
    )

    assert result is None
    # No flag: the project-config default (enabled) flows through.
    assert calls == [False, True]
