from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import build_context_mode_bundle as bundles
from scripts import build_context_mode_wheel as wheels
from scripts import verify_context_mode_release_readiness as readiness


def _base_wheel(tmp_path: Path, *, include_vendor: bool = False) -> Path:
    root = "bello-0.3.1.dist-info"
    members = {
        "supervisor/__init__.py": wheels.WheelMember(b"__version__ = '0.3.1'\n", 0o644),
        f"{root}/METADATA": wheels.WheelMember(
            b"Metadata-Version: 2.4\nName: Bello\nVersion: 0.3.1\n\n",
            0o644,
        ),
        f"{root}/WHEEL": wheels.WheelMember(
            b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
            0o644,
        ),
    }
    if include_vendor:
        members["supervisor/_vendor/context_mode/stale.txt"] = wheels.WheelMember(b"stale\n", 0o644)
    record_name = f"{root}/RECORD"
    members[record_name] = wheels.WheelMember(wheels._record_bytes(members, record_name), 0o644)
    path = tmp_path / "bello-0.3.1-py3-none-any.whl"
    wheels._write_wheel(path, members, epoch=1_700_000_000)
    return path


def _bundle(tmp_path: Path) -> Path:
    root = tmp_path / "bundle"
    files: dict[str, tuple[bytes, int]] = {
        "manifest.json": (b"{}\n", 0o644),
        "manifest.sha256": (b"fixture  manifest.json\n", 0o644),
        "node/bin/node": (b"#!/bin/sh\nexit 0\n", 0o755),
        "package/server.bundle.mjs": (b"export {};\n", 0o644),
        "authority/bin/bello-context-broker": (b"#!/bin/sh\nexit 0\n", 0o755),
        "authority/bin/bello-context-launcher": (b"#!/bin/sh\nexit 0\n", 0o755),
        "authority/LICENSE": (b"Native authority license\n", 0o644),
        "authority/authority.json": (b'{"schema_version":1}\n', 0o644),
        "authority/authority.sig": (b"signed-native-authority", 0o644),
        "authority/release-public-key.pem": (b"fixture-public-key\n", 0o644),
    }
    for relative, (payload, mode) in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(mode)
    return root


def _fake_bundle_verifier(root: Path, **_kwargs: object) -> SimpleNamespace:
    files = [path for path in Path(root).rglob("*") if path.is_file()]
    assert (Path(root) / "manifest.json").is_file()
    assert (Path(root) / "manifest.sha256").is_file()
    assert os.access(Path(root) / "node" / "bin" / "node", os.X_OK)
    return SimpleNamespace(file_count=len(files) - 2)


@pytest.fixture
def platform_tag() -> str:
    detected = bundles._detected_host_platform()
    if detected not in wheels.PLATFORM_WHEEL_TAGS:
        pytest.skip(f"unsupported wheel-test host: {detected}")
    return detected


@pytest.fixture(autouse=True)
def release_readiness_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    # Mechanical wheel tests isolate the assembler from host provisioning; the
    # dedicated readiness test below checks the real CLI against the audited
    # state of this checkout.
    monkeypatch.setattr(wheels, "require_release_readiness", lambda *_args, **_kwargs: None)


def test_assembler_builds_platform_wheel_and_regenerates_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_tag: str,
) -> None:
    monkeypatch.setattr(wheels, "verify_bundle", _fake_bundle_verifier)
    base = _base_wheel(tmp_path)
    bundle = _bundle(tmp_path)

    verified = wheels.assemble_wheel(
        base_wheel=base,
        bundle=bundle,
        output_dir=tmp_path / "dist",
        platform_tag=platform_tag,
        source_date_epoch=1_700_000_000,
        enforce_host_platform=False,
        run_native_smoke=False,
    )

    expected_tag = wheels.PLATFORM_WHEEL_TAGS[platform_tag]
    assert verified.path.name == f"bello-0.3.1-{expected_tag}.whl"
    assert verified.embedded_files == 10
    with zipfile.ZipFile(verified.path) as archive:
        names = set(archive.namelist())
        wheel_metadata = archive.read("bello-0.3.1.dist-info/WHEEL").decode()
        node_info = archive.getinfo(
            f"supervisor/_vendor/context_mode/{platform_tag}/node/bin/node"
        )
        broker_info = archive.getinfo(
            f"supervisor/_vendor/context_mode/{platform_tag}/authority/bin/bello-context-broker"
        )
        launcher_info = archive.getinfo(
            f"supervisor/_vendor/context_mode/{platform_tag}/authority/bin/bello-context-launcher"
        )
        record_rows = list(
            csv.reader(
                io.StringIO(
                    archive.read("bello-0.3.1.dist-info/RECORD").decode(),
                    newline="",
                )
            )
        )
    assert "Root-Is-Purelib: false" in wheel_metadata
    assert f"Tag: {expected_tag}" in wheel_metadata
    assert "Tag: py3-none-any" not in wheel_metadata
    assert node_info.external_attr >> 16 & 0o111
    assert broker_info.external_attr >> 16 & 0o111
    assert launcher_info.external_attr >> 16 & 0o111
    assert {row[0] for row in record_rows} == names
    assert all(
        name.startswith(f"supervisor/_vendor/context_mode/{platform_tag}/")
        for name in names
        if name.startswith("supervisor/_vendor/context_mode/")
    )


def test_platform_wheel_installs_without_index_or_dependencies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_tag: str,
) -> None:
    monkeypatch.setattr(wheels, "verify_bundle", _fake_bundle_verifier)
    verified = wheels.assemble_wheel(
        base_wheel=_base_wheel(tmp_path),
        bundle=_bundle(tmp_path),
        output_dir=tmp_path / "dist",
        platform_tag=platform_tag,
        enforce_host_platform=False,
        run_native_smoke=False,
    )
    install_root = tmp_path / "installed"
    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-index",
            "--no-deps",
            "--target",
            str(install_root),
            str(verified.path),
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    installed_bundle = install_root / "supervisor" / "_vendor" / "context_mode" / platform_tag
    assert (installed_bundle / "manifest.json").is_file()
    assert (installed_bundle / "package" / "server.bundle.mjs").is_file()
    assert os.access(installed_bundle / "node" / "bin" / "node", os.X_OK)
    assert os.access(
        installed_bundle / "authority" / "bin" / "bello-context-broker",
        os.X_OK,
    )
    assert os.access(
        installed_bundle / "authority" / "bin" / "bello-context-launcher",
        os.X_OK,
    )


def test_assembler_rejects_preexisting_vendor_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_tag: str,
) -> None:
    monkeypatch.setattr(wheels, "verify_bundle", _fake_bundle_verifier)
    with pytest.raises(wheels.WheelBuildError, match="already contains"):
        wheels.assemble_wheel(
            base_wheel=_base_wheel(tmp_path, include_vendor=True),
            bundle=_bundle(tmp_path),
            output_dir=tmp_path / "dist",
            platform_tag=platform_tag,
            enforce_host_platform=False,
            run_native_smoke=False,
        )


def test_verifier_rejects_tampered_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform_tag: str,
) -> None:
    monkeypatch.setattr(wheels, "verify_bundle", _fake_bundle_verifier)
    verified = wheels.assemble_wheel(
        base_wheel=_base_wheel(tmp_path),
        bundle=_bundle(tmp_path),
        output_dir=tmp_path / "dist",
        platform_tag=platform_tag,
        enforce_host_platform=False,
        run_native_smoke=False,
    )
    layout = wheels._load_layout(verified.path)
    members = dict(layout.members)
    server = f"supervisor/_vendor/context_mode/{platform_tag}/package/server.bundle.mjs"
    members[server] = wheels.WheelMember(b"tampered\n", 0o644)
    corrupted_dir = tmp_path / "corrupted"
    corrupted_dir.mkdir()
    corrupted = corrupted_dir / verified.path.name
    wheels._write_wheel(corrupted, members, epoch=1_700_000_000)

    with pytest.raises(wheels.WheelBuildError, match="RECORD mismatch"):
        wheels.verify_wheel(
            wheel=corrupted,
            platform_tag=platform_tag,
            enforce_host_platform=False,
            run_native_smoke=False,
        )


def test_release_workflow_is_gated_then_builds_and_offline_installs_platform_wheel() -> None:
    workflow = Path(".github/workflows/context-mode-bundles.yml").read_text(encoding="utf-8")
    readiness_script = "scripts/verify_context_mode_release_readiness.py"
    assert readiness_script in workflow
    assert workflow.index(readiness_script) < workflow.index("python3 -m build --wheel --no-isolation")
    assert "--authority-root \"$RELEASE_INPUT_ROOT/$PLATFORM_TAG/authority\"" in workflow
    for relative in readiness.REQUIRED_AUTHORITY_FILES:
        assert f"authority/{relative}" in workflow
    assert "python3 -m build --wheel --no-isolation" in workflow
    assert "scripts/build_context_mode_wheel.py assemble" in workflow
    assert "scripts/build_context_mode_wheel.py verify" in workflow
    assert "pip install --no-index --no-deps" in workflow
    assert "supervisor/_vendor/context_mode/$PLATFORM_TAG" in workflow
    assert "retag" not in workflow.lower()


def test_current_repository_release_readiness_matches_audited_provisioning(
    platform_tag: str,
) -> None:
    audited = readiness.audit_release_readiness(Path("."), platforms=(platform_tag,))
    result = subprocess.run(
        (
            sys.executable,
            "scripts/verify_context_mode_release_readiness.py",
            "--project-root",
            ".",
            "--platform",
            platform_tag,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )
    payload = json.loads(result.stdout)
    assert result.returncode == (0 if audited.ready else 2)
    assert payload == {
        "blockers": list(audited.blockers),
        "platforms": [platform_tag],
        "ready": audited.ready,
    }


def test_wheel_cli_cannot_bypass_native_release_readiness(
    tmp_path: Path,
    platform_tag: str,
) -> None:
    audited = readiness.audit_release_readiness(Path("."), platforms=(platform_tag,))
    result = subprocess.run(
        (
            sys.executable,
            "scripts/build_context_mode_wheel.py",
            "assemble",
            "--base-wheel",
            str(tmp_path / "missing-base.whl"),
            "--bundle",
            str(tmp_path / "missing-bundle"),
            "--output-dir",
            str(tmp_path / "dist"),
            "--platform",
            platform_tag,
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 2
    if audited.ready:
        assert "Context Mode bundle verification failed" in result.stderr
        assert "missing-bundle" in result.stderr
    else:
        assert "native release authority is not ready" in result.stderr
        assert "missing-bundle" not in result.stderr
    # The base wheel is opened only after release readiness and bundle
    # verification have both succeeded.
    assert "missing-base.whl" not in result.stderr
