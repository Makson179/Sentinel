from __future__ import annotations

import json
import urllib.error

import pytest

from supervisor import update_check


class FakeDistribution:
    version = "0.1.2"

    def locate_file(self, name: str) -> str:
        return "/fake/site-packages"


class FakeResponse:
    def __init__(self, payload: object):
        self.payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


def test_read_install_info_uses_distribution_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(update_check.metadata, "distribution", lambda name: FakeDistribution())
    monkeypatch.setattr(update_check, "detect_install_mode", lambda: "pipx")

    info = update_check.read_install_info()

    assert info.package_name == "sentinel-supervisor"
    assert info.version == "0.1.2"
    assert info.install_mode == "pipx"
    assert info.metadata_available is True
    assert info.metadata_location == "/fake/site-packages"


def test_read_install_info_reports_missing_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing_distribution(name: str) -> None:
        raise update_check.metadata.PackageNotFoundError

    monkeypatch.setattr(update_check.metadata, "distribution", missing_distribution)
    monkeypatch.setattr(update_check, "detect_install_mode", lambda: "system")

    info = update_check.read_install_info()

    assert info.package_name == "sentinel-supervisor"
    assert info.version
    assert info.install_mode == "system"
    assert info.metadata_available is False
    assert "package metadata" in (info.warning or "")


def test_latest_pypi_version_reads_json_api(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_urlopen(request: update_check.urllib.request.Request, timeout: float) -> FakeResponse:
        calls.append(request.full_url)
        return FakeResponse({"info": {"version": "0.2.0"}})

    monkeypatch.setattr(update_check.urllib.request, "urlopen", fake_urlopen)

    assert update_check.latest_pypi_version("sentinel-supervisor") == "0.2.0"
    assert calls == ["https://pypi.org/pypi/sentinel-supervisor/json"]


def test_latest_pypi_version_reports_404(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: update_check.urllib.request.Request, timeout: float) -> FakeResponse:
        raise urllib.error.HTTPError(request.full_url, 404, "not found", {}, None)

    monkeypatch.setattr(update_check.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(update_check.UpdateCheckError, match="not found on PyPI"):
        update_check.latest_pypi_version("sentinel-supervisor")


def test_latest_pypi_version_reports_network_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: update_check.urllib.request.Request, timeout: float) -> FakeResponse:
        raise urllib.error.URLError("temporary failure in name resolution")

    monkeypatch.setattr(update_check.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(update_check.UpdateCheckError, match="could not reach PyPI"):
        update_check.latest_pypi_version("sentinel-supervisor")


def test_latest_pypi_version_reports_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: update_check.urllib.request.Request, timeout: float) -> FakeResponse:
        raise TimeoutError

    monkeypatch.setattr(update_check.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(update_check.UpdateCheckError, match="timed out"):
        update_check.latest_pypi_version("sentinel-supervisor")


def test_latest_pypi_version_reports_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    class BadResponse(FakeResponse):
        def read(self) -> bytes:
            return b"<html>not json</html>"

    def fake_urlopen(request: update_check.urllib.request.Request, timeout: float) -> BadResponse:
        return BadResponse({})

    monkeypatch.setattr(update_check.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(update_check.UpdateCheckError, match="invalid JSON"):
        update_check.latest_pypi_version("sentinel-supervisor")


def test_check_for_update_compares_pep440_versions(monkeypatch: pytest.MonkeyPatch) -> None:
    info = update_check.InstallInfo(
        package_name="sentinel-supervisor",
        version="0.1.9",
        install_mode="pipx",
    )
    monkeypatch.setattr(update_check, "latest_pypi_version", lambda package_name: "0.1.10")

    status = update_check.check_for_update(info)

    assert status.state == update_check.UpdateState.OUTDATED
    assert status.latest_version == "0.1.10"


def test_check_for_update_treats_newer_local_version_as_current(monkeypatch: pytest.MonkeyPatch) -> None:
    info = update_check.InstallInfo(
        package_name="sentinel-supervisor",
        version="0.2.0",
        install_mode="pipx",
    )
    monkeypatch.setattr(update_check, "latest_pypi_version", lambda package_name: "0.1.10")

    status = update_check.check_for_update(info)

    assert status.state == update_check.UpdateState.CURRENT
    assert status.latest_version == "0.1.10"


def test_check_for_update_reports_invalid_versions(monkeypatch: pytest.MonkeyPatch) -> None:
    info = update_check.InstallInfo(
        package_name="sentinel-supervisor",
        version="not-a-version",
        install_mode="pipx",
    )
    monkeypatch.setattr(update_check, "latest_pypi_version", lambda package_name: "0.1.10")

    status = update_check.check_for_update(info)

    assert status.state == update_check.UpdateState.UNKNOWN
    assert "Invalid version" in (status.warning or "")


def test_check_for_update_converts_pypi_errors_to_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    info = update_check.InstallInfo(
        package_name="sentinel-supervisor",
        version="0.1.0",
        install_mode="pipx",
    )

    def fail(package_name: str) -> str:
        raise update_check.UpdateCheckError("could not reach PyPI")

    monkeypatch.setattr(update_check, "latest_pypi_version", fail)

    status = update_check.check_for_update(info)

    assert status.state == update_check.UpdateState.UNKNOWN
    assert status.warning == "could not reach PyPI"


def test_update_command_uses_pipx_upgrade_for_pipx_installs(monkeypatch: pytest.MonkeyPatch) -> None:
    info = update_check.InstallInfo(
        package_name="sentinel-supervisor",
        version="0.1.0",
        install_mode="pipx",
    )
    monkeypatch.setattr(update_check.shutil, "which", lambda name: "/usr/bin/pipx" if name == "pipx" else None)

    assert update_check.update_command(info) == ["pipx", "upgrade", "sentinel-supervisor"]


def test_update_command_uses_pip_inside_venv(monkeypatch: pytest.MonkeyPatch) -> None:
    info = update_check.InstallInfo(
        package_name="sentinel-supervisor",
        version="0.1.0",
        install_mode="venv",
    )
    monkeypatch.setattr(update_check, "_running_inside_venv", lambda: True)

    assert update_check.update_command(info) == [
        update_check.sys.executable,
        "-m",
        "pip",
        "install",
        "--upgrade",
        "sentinel-supervisor",
    ]


def test_detect_install_mode_recognizes_custom_pipx_home(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    venv = tmp_path / "custom-home" / "venvs" / "sentinel-supervisor"
    venv.mkdir(parents=True)
    (venv / "pipx_metadata.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(update_check.sys, "prefix", str(venv))
    monkeypatch.setattr(update_check.sys, "base_prefix", str(tmp_path / "python"))

    assert update_check.detect_install_mode() == "pipx"
