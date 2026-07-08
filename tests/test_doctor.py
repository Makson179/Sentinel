from __future__ import annotations

import subprocess

import pytest

from supervisor import update_check
from supervisor import doctor
from supervisor.doctor import DoctorResult, format_result


def test_doctor_result_format_is_readable() -> None:
    assert format_result(DoctorResult("ok", "Python 3.11.8")) == "[OK] Python 3.11.8"
    assert format_result(DoctorResult("warn", "Update available: 0.1.1")) == "[WARN] Update available: 0.1.1"
    assert format_result(DoctorResult("fail", "Codex not found on PATH")) == "[FAIL] Codex not found on PATH"


def test_doctor_collects_required_checks_with_update_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    info = update_check.InstallInfo(
        package_name="sentinel-supervisor",
        version="0.1.0",
        install_mode="pipx",
    )
    monkeypatch.setattr(doctor.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        doctor,
        "_probe_result",
        lambda args, ok_message, fail_message, timeout=10.0: DoctorResult("ok", ok_message, "ok"),
    )
    monkeypatch.setattr(doctor, "_schema_generation_result", lambda: DoctorResult("ok", "app-server schema generation OK"))
    monkeypatch.setattr(doctor, "_codex_auth_result", lambda: DoctorResult("ok", "Codex auth OK"))
    monkeypatch.setattr(update_check, "read_install_info", lambda: info)
    monkeypatch.setattr(
        update_check,
        "check_for_update",
        lambda install_info: update_check.UpdateStatus(
            update_check.UpdateState.OUTDATED,
            install_info,
            latest_version="0.1.1",
        ),
    )

    messages = [result.message for result in doctor.collect_doctor_results()]

    assert any(message.startswith("Python ") for message in messages)
    assert "Git found: /usr/bin/git" in messages
    assert "Codex found: /usr/bin/codex" in messages
    assert "Codex version OK" in messages
    assert "Codex app-server supported" in messages
    assert "app-server schema generation OK" in messages
    assert "Codex auth OK" in messages
    assert "Sentinel package: sentinel-supervisor 0.1.0" in messages
    assert "Sentinel executable: /usr/bin/sentinel" in messages
    assert "Sentinel install mode: pipx" in messages
    assert "Update available: 0.1.1" in messages


def test_probe_result_fails_on_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        doctor.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 2, "", "nope"),
    )

    result = doctor._probe_result(["codex", "--version"], "ok", "codex failed")

    assert result.level == "fail"
    assert result.message == "codex failed"
    assert result.detail == "nope"


def test_doctor_reports_dependent_codex_checks_when_codex_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    info = update_check.InstallInfo(
        package_name="sentinel-supervisor",
        version="0.1.0",
        install_mode="system",
        metadata_available=False,
        warning="package metadata missing",
    )
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    monkeypatch.setattr(update_check, "read_install_info", lambda: info)
    monkeypatch.setattr(
        update_check,
        "check_for_update",
        lambda install_info: update_check.UpdateStatus(
            update_check.UpdateState.UNKNOWN,
            install_info,
            warning="package 'sentinel-supervisor' was not found on PyPI",
        ),
    )

    results = doctor.collect_doctor_results()
    by_message = {result.message: result for result in results}

    assert by_message["Codex not found on PATH"].level == "fail"
    assert by_message["codex --version failed"].level == "fail"
    assert by_message["Codex app-server support not checked"].level == "fail"
    assert by_message["app-server schema generation not checked"].level == "fail"
    assert by_message["Codex auth check failed"].level == "fail"
    assert by_message["Sentinel package metadata could not be read"].level == "fail"


def test_doctor_returns_zero_when_update_check_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    info = update_check.InstallInfo(
        package_name="sentinel-supervisor",
        version="0.1.0",
        install_mode="pipx",
    )
    monkeypatch.setattr(doctor.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        doctor,
        "_probe_result",
        lambda args, ok_message, fail_message, timeout=10.0: DoctorResult("ok", ok_message, "ok"),
    )
    monkeypatch.setattr(doctor, "_schema_generation_result", lambda: DoctorResult("ok", "app-server schema generation OK"))
    monkeypatch.setattr(doctor, "_codex_auth_result", lambda: DoctorResult("ok", "Codex auth OK"))
    monkeypatch.setattr(update_check, "read_install_info", lambda: info)
    monkeypatch.setattr(
        update_check,
        "check_for_update",
        lambda install_info: update_check.UpdateStatus(
            update_check.UpdateState.UNKNOWN,
            install_info,
            warning="could not reach PyPI",
        ),
    )

    assert doctor.run_doctor() == 0
    output = capsys.readouterr().out
    assert "[WARN] Could not check for Sentinel updates" in output
    assert "could not reach PyPI" in output
