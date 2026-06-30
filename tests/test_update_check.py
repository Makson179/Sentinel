from __future__ import annotations

import json
import subprocess

import pytest

from supervisor import update_check


FULL_A = "a" * 40
FULL_B = "b" * 40


class FakeDistribution:
    version = "0.1.2"

    def __init__(self, direct_url: dict[str, object] | None):
        self.direct_url = direct_url

    def read_text(self, name: str) -> str | None:
        if name != "direct_url.json" or self.direct_url is None:
            return None
        return json.dumps(self.direct_url)

    def locate_file(self, name: str) -> str:
        return "/fake/site-packages"


def test_read_install_info_uses_pep610_git_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    direct_url = {
        "url": "https://github.com/Makson179/Sentinel.git",
        "vcs_info": {
            "vcs": "git",
            "commit_id": FULL_A,
        },
    }
    monkeypatch.setattr(update_check.metadata, "distribution", lambda name: FakeDistribution(direct_url))
    monkeypatch.setattr(update_check, "_git_checkout_fallback", lambda: {})

    info = update_check.read_install_info()

    assert info.version == "0.1.2"
    assert info.repo_url == "https://github.com/Makson179/Sentinel.git"
    assert info.requested_revision is None
    assert info.installed_commit == FULL_A
    assert info.source_display == "https://github.com/Makson179/Sentinel.git (default branch)"


def test_parse_ls_remote_commit_rejects_ambiguous_refs() -> None:
    output = f"{FULL_A}\trefs/heads/main\n{FULL_B}\trefs/tags/main\n"

    with pytest.raises(update_check.UpdateCheckError, match="ambiguous"):
        update_check.parse_ls_remote_commit(output)


def test_parse_ls_remote_commit_prefers_peeled_tag_commit() -> None:
    tag_object = "c" * 40
    output = f"{tag_object}\trefs/tags/v1\n{FULL_A}\trefs/tags/v1^{{}}\n"

    assert update_check.parse_ls_remote_commit(output) == FULL_A


def test_check_for_update_compares_full_commit_sha(monkeypatch: pytest.MonkeyPatch) -> None:
    installed = "abcdef0" + "1" * 33
    latest = "abcdef0" + "2" * 33
    info = update_check.InstallInfo(
        package_name="sentinel",
        version="0.1.0",
        repo_url="https://example.test/Sentinel.git",
        requested_revision="main",
        installed_commit=installed,
        install_mode="pipx",
    )
    monkeypatch.setattr(update_check, "latest_remote_commit", lambda repo, ref: latest)

    status = update_check.check_for_update(info)

    assert status.state == update_check.UpdateState.OUTDATED
    assert status.latest_commit == latest


def test_update_command_uses_pipx_for_pipx_installs(monkeypatch: pytest.MonkeyPatch) -> None:
    info = update_check.InstallInfo(
        package_name="sentinel",
        version="0.1.0",
        repo_url="https://example.test/Sentinel.git",
        requested_revision=None,
        installed_commit=FULL_A,
        install_mode="pipx",
    )
    monkeypatch.setattr(update_check.shutil, "which", lambda name: "/usr/bin/pipx" if name == "pipx" else None)

    assert update_check.update_command(info, update_check.install_spec(info)) == [
        "pipx",
        "install",
        "--force",
        "git+https://example.test/Sentinel.git",
    ]


def test_latest_remote_commit_uses_default_branch_head_when_ref_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, f"ref: refs/heads/main\tHEAD\n{FULL_B}\tHEAD\n", "")

    monkeypatch.setattr(update_check.subprocess, "run", fake_run)

    assert update_check.latest_remote_commit("https://example.test/Sentinel.git", None) == FULL_B
    assert calls == [["git", "ls-remote", "--symref", "https://example.test/Sentinel.git", "HEAD"]]


def test_install_spec_includes_ref_only_when_present() -> None:
    default_info = update_check.InstallInfo(
        package_name="sentinel",
        version="0.1.0",
        repo_url="https://example.test/Sentinel.git",
        requested_revision=None,
        installed_commit=FULL_A,
        install_mode="pipx",
    )
    branch_info = update_check.InstallInfo(
        package_name="sentinel",
        version="0.1.0",
        repo_url="https://example.test/Sentinel.git",
        requested_revision="main",
        installed_commit=FULL_A,
        install_mode="pipx",
    )

    assert update_check.install_spec(default_info) == "git+https://example.test/Sentinel.git"
    assert update_check.install_spec(branch_info) == "git+https://example.test/Sentinel.git@main"


def test_latest_remote_commit_reports_git_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args[0], 2, "", "fatal: missing ref")

    monkeypatch.setattr(update_check.subprocess, "run", fake_run)

    with pytest.raises(update_check.UpdateCheckError, match="missing ref"):
        update_check.latest_remote_commit("https://example.test/Sentinel.git", "missing")
