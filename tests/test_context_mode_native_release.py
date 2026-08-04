from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from supervisor.context_mode import native_release
from supervisor.context_mode.native_release import (
    BundledNativeRuntime,
    NativeReleaseError,
    load_bundled_native_runtime,
    verify_signed_native_authority,
)


def _canonical(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def _sign(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    expanded = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(expanded[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    public = native_release._ed_encode(
        native_release._ed_scalarmult(native_release._ED_BASE, scalar)
    )
    nonce = int.from_bytes(hashlib.sha512(expanded[32:] + message).digest(), "little") % native_release._ED_L
    encoded_r = native_release._ed_encode(
        native_release._ed_scalarmult(native_release._ED_BASE, nonce)
    )
    challenge = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") % native_release._ED_L
    signature = encoded_r + ((nonce + challenge * scalar) % native_release._ED_L).to_bytes(32, "little")
    return public, signature


def _authority(tmp_path: Path, *, platform: str = "linux-x86_64") -> tuple[Path, Path]:
    root = tmp_path / "bundle" / "authority"
    (root / "bin").mkdir(parents=True)
    broker = root / "bin" / "bello-context-broker"
    launcher = root / "bin" / "bello-context-launcher"
    broker.write_bytes(b"#!/bin/sh\nexit 2\n")
    launcher.write_bytes(b"#!/bin/sh\nexit 2\n")
    broker.chmod(0o755)
    launcher.chmod(0o755)
    (root / "LICENSE").write_text("Bello native authority test license\n", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "platform": platform,
        "broker_protocol": native_release.NATIVE_CONTROLLER_PROTOCOL,
        "authority_version": "test-authority-1",
        "files": {
            relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()
            for relative in native_release.SIGNED_PAYLOAD_FILES
        },
    }
    manifest_bytes = _canonical(manifest)
    (root / "authority.json").write_bytes(manifest_bytes)
    public, signature = _sign(b"\x07" * 32, manifest_bytes)
    der = bytes.fromhex("302a300506032b6570032100") + public
    public_pem = (
        b"-----BEGIN PUBLIC KEY-----\n"
        + base64.b64encode(der)
        + b"\n-----END PUBLIC KEY-----\n"
    )
    (root / "release-public-key.pem").write_bytes(public_pem)
    (root / "authority.sig").write_bytes(base64.b64encode(signature) + b"\n")
    platform_records = {
        tag: {
            "authority_manifest_sha256": "0" * 64,
            "release_public_key_sha256": "0" * 64,
        }
        for tag in native_release.SUPPORTED_PLATFORMS
    }
    platform_records[platform] = {
        "authority_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "release_public_key_sha256": hashlib.sha256(public_pem).hexdigest(),
    }
    contract = {
        "schema_version": 1,
        "signature_algorithm": "Ed25519",
        "authority_schema_version": 1,
        "broker_protocol": native_release.NATIVE_CONTROLLER_PROTOCOL,
        "platforms": platform_records,
    }
    contract_path = tmp_path / "native-release.json"
    contract_path.write_bytes(_canonical(contract))
    return root, contract_path


def test_embedded_ed25519_verifier_matches_rfc_8032_vector() -> None:
    public = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a"
        "0ee172f3daa62325af021a68f707511a"
    )
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b"
    )
    assert native_release._ed25519_verify(public, b"", signature)
    assert not native_release._ed25519_verify(public, b"tampered", signature)
    assert not native_release._ed25519_verify(public, b"", signature[:-1] + b"\x00")


def test_signed_native_authority_verifies_exact_payload_and_rejects_tampering(
    tmp_path: Path,
) -> None:
    root, contract = _authority(tmp_path)
    verified = verify_signed_native_authority(
        authority_root=root,
        contract_path=contract,
        platform_tag="linux-x86_64",
    )
    assert verified["signature_verified"] is True
    assert verified["broker_protocol"] == native_release.NATIVE_CONTROLLER_PROTOCOL
    assert Path(verified["launcher_path"]) == (root / "bin" / "bello-context-launcher")

    (root / "bin" / "bello-context-broker").write_bytes(b"tampered")
    (root / "bin" / "bello-context-broker").chmod(0o755)
    with pytest.raises(NativeReleaseError, match="payload digest mismatch"):
        verify_signed_native_authority(
            authority_root=root,
            contract_path=contract,
            platform_tag="linux-x86_64",
        )


def test_native_authority_rejects_noncanonical_contract_and_extra_file(tmp_path: Path) -> None:
    root, contract = _authority(tmp_path)
    value = json.loads(contract.read_bytes())
    contract.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(NativeReleaseError, match="not canonical"):
        verify_signed_native_authority(
            authority_root=root,
            contract_path=contract,
            platform_tag="linux-x86_64",
        )

    contract.write_bytes(_canonical(value))
    (root / "unexpected").write_text("no\n", encoding="utf-8")
    with pytest.raises(NativeReleaseError, match="unexpected or missing"):
        verify_signed_native_authority(
            authority_root=root,
            contract_path=contract,
            platform_tag="linux-x86_64",
        )


def test_loader_returns_only_signature_verified_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, contract = _authority(tmp_path)
    bundle = SimpleNamespace(root=root.parent)
    monkeypatch.setattr(
        "supervisor.context_mode.packaging.select_bundled_runtime",
        lambda *_args, **_kwargs: bundle,
    )

    runtime = load_bundled_native_runtime(
        vendor_root=root.parent,
        platform_tag="linux-x86_64",
        contract_path=contract,
        require_executable_node=False,
    )
    assert isinstance(runtime, BundledNativeRuntime)
    assert runtime.launcher_sha256 == hashlib.sha256(runtime.launcher_path.read_bytes()).hexdigest()


async def test_native_app_server_launch_propagates_and_validates_stdout_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    launched = object()

    async def fake_create_subprocess_exec(*command: str, **kwargs: object) -> object:
        captured["command"] = command
        captured.update(kwargs)
        return launched

    runtime = object.__new__(BundledNativeRuntime)
    runtime._process = object()  # type: ignore[assignment]
    runtime._channel = "test-channel"
    runtime._fatal_error = None
    runtime.launcher_path = tmp_path / "bello-context-launcher"
    runtime._verify_executables = lambda: None  # type: ignore[method-assign]
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    result = await runtime.launch_app_server(
        command=("codex", "app-server"),
        cwd=tmp_path,
        environment={"PATH": "/usr/bin"},
        role="coder",
        stdout_limit=16 * 1024 * 1024,
    )

    assert result is launched
    assert captured["limit"] == 16 * 1024 * 1024

    with pytest.raises(NativeReleaseError, match="stdout limit must be a positive integer"):
        await runtime.launch_app_server(
            command=("codex", "app-server"),
            cwd=tmp_path,
            environment={"PATH": "/usr/bin"},
            role="coder",
            stdout_limit=0,
        )
