from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import tarfile
import tomllib
from pathlib import Path

import pytest

from scripts import build_context_mode_bundle as bundles
from supervisor.context_mode.provenance import MAX_MODEL_RESULT_ESTIMATED_TOKENS


FORK_SOURCE_COMMIT = "b" * 40


def test_offline_worker_result_budget_leaves_signed_envelope_headroom() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "release/context_mode_offline_fork/build/worker.mjs"
    ).read_text(encoding="utf-8")
    match = re.search(r"const RESULT_TEXT_BUDGET = (\d+) \* 1024;", source)
    assert match is not None
    text_budget = int(match.group(1)) * 1024
    conservative_result_budget = MAX_MODEL_RESULT_ESTIMATED_TOKENS * 4

    assert text_budget + 4 * 1024 <= conservative_result_budget
    assert (
        "utf8Prefix(value.content[0].text, RESULT_TEXT_BUDGET)" in source
    )


def _write(path: Path, content: str | bytes, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    path.chmod(0o755 if executable else 0o644)


@pytest.fixture
def release_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, Path, str]:
    monkeypatch.setattr(bundles, "PINNED_OFFLINE_FORK_COMMIT", FORK_SOURCE_COMMIT)
    context = tmp_path / "context-mode"
    node = tmp_path / "node"
    authority = tmp_path / "authority"
    package_json = {
        "name": "context-mode",
        "version": bundles.CONTEXT_MODE_VERSION,
        "license": bundles.CONTEXT_MODE_LICENSE,
        "engines": {"node": ">=22.5.0"},
    }
    _write(context / "package.json", json.dumps(package_json))
    _write(context / "LICENSE", "Elastic License 2.0\n")
    _write(context / "server.bundle.mjs", "export const server = true;\n")
    _write(context / "cli.bundle.mjs", "#!/usr/bin/env node\n", executable=True)
    _write(context / "start.mjs", "import './server.bundle.mjs';\n")
    for directory in ("build", "hooks", "skills", "configs"):
        _write(context / directory / "fixture.txt", f"{directory}\n")
    schemas = {
        name: {"type": "object", "properties": {}}
        for name in bundles.ALLOWED_TOOLS
    }
    _write(
        context / bundles.TOOL_SCHEMA_CATALOG,
        bundles._canonical_json(schemas),
    )
    native_root = context / "node_modules" / "better-sqlite3"
    _write(
        native_root / "package.json",
        json.dumps({"name": "better-sqlite3", "version": bundles.BETTER_SQLITE3_VERSION}),
    )
    _write(native_root / "build" / "Release" / "better_sqlite3.node", b"native-fixture")
    _write(context / "node_modules" / "dependency" / "index.js", "module.exports = 1;\n")
    _write(
        context / bundles.OFFLINE_FORK_ATTESTATION,
        bundles._canonical_json(
            bundles.make_offline_fork_attestation(
                context,
                fork_source_commit=FORK_SOURCE_COMMIT,
            )
        ),
    )

    # The fixture executable emulates both release checks.  The production
    # builder passes the real pinned binary and executes the same argv.
    _write(
        node / "bin" / "node",
        "#!/bin/sh\n"
        "if [ \"$1\" = \"--version\" ]; then printf 'v22.5.0\\n'; exit 0; fi\n"
        "exit 0\n",
        executable=True,
    )
    _write(node / "LICENSE", "Node.js fixture license\n")
    monkeypatch.setattr(
        bundles,
        "PINNED_NODE_BINARY_SHA256",
        {
            tag: hashlib.sha256((node / "bin" / "node").read_bytes()).hexdigest()
            for tag in bundles.SUPPORTED_PLATFORMS
        },
    )
    monkeypatch.setattr(
        bundles,
        "PINNED_NODE_LICENSE_SHA256",
        hashlib.sha256((node / "LICENSE").read_bytes()).hexdigest(),
    )
    dependency_digest = bundles._dependency_inventory_digest(context / "node_modules")
    monkeypatch.setattr(
        bundles,
        "PINNED_DEPENDENCY_INVENTORY_SHA256",
        {tag: dependency_digest for tag in bundles.SUPPORTED_PLATFORMS},
    )
    _write(
        authority / "bin" / "bello-context-broker",
        "#!/bin/sh\nexit 0\n",
        executable=True,
    )
    _write(
        authority / "bin" / "bello-context-launcher",
        "#!/bin/sh\nexit 0\n",
        executable=True,
    )
    _write(authority / "LICENSE", "Native authority fixture license\n")
    _write(authority / "authority.json", '{"schema_version":1}\n')
    _write(authority / "authority.sig", b"signed-fixture")
    _write(authority / "release-public-key.pem", "-----BEGIN PUBLIC KEY-----\nfixture\n")
    monkeypatch.setattr(bundles, "_git_head", lambda *_args, **_kwargs: FORK_SOURCE_COMMIT)
    monkeypatch.setattr(bundles, "_git_is_ancestor", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(bundles, "_require_clean_tracked_checkout", lambda *_args, **_kwargs: None)
    return context, node, authority, bundles._detected_host_platform()


def _build(
    tmp_path: Path,
    release_inputs: tuple[Path, Path, Path, str],
    name: str,
) -> bundles.VerifiedBundle:
    context, node, authority, platform_tag = release_inputs
    return bundles.build_bundle(
        context_source=context,
        node_tree=node,
        authority_source=authority,
        output=tmp_path / name,
        platform_tag=platform_tag,
        source_date_epoch=1_700_000_000,
    )


def test_builder_api_and_cli_require_native_authority_source() -> None:
    parameter = inspect.signature(bundles.build_bundle).parameters["authority_source"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty

    with pytest.raises(SystemExit):
        bundles._parser().parse_args(
            [
                "build",
                "--context-source",
                "context-mode",
                "--node-tree",
                "node",
                "--output",
                "bundle",
                "--platform",
                bundles.SUPPORTED_PLATFORMS[0],
            ]
        )


def test_builder_emits_release_layout_and_complete_hash_manifest(
    tmp_path: Path,
    release_inputs: tuple[Path, Path, Path, str],
) -> None:
    verified = _build(tmp_path, release_inputs, "bundle")
    root = verified.root

    assert verified.node_path == root / "node" / "bin" / "node"
    assert verified.server_entrypoint == root / "package" / "server.bundle.mjs"
    assert verified.authority_root == root / "authority"
    assert os.access(verified.node_path, os.X_OK)
    assert all(
        os.access(verified.authority_root / relative, os.X_OK)
        for relative in bundles.AUTHORITY_EXECUTABLES
    )
    assert (root / "package" / "LICENSE").read_text() == "Elastic License 2.0\n"
    manifest = json.loads((root / "manifest.json").read_text())
    assert manifest["context_mode_commit"] == bundles.CONTEXT_MODE_COMMIT
    assert manifest["context_mode_version"] == "1.0.169"
    assert manifest["node_version"] == "22.5.0"
    assert manifest["bello_offline_fork_revision"] == bundles.OFFLINE_FORK_REVISION
    assert manifest["bello_offline_fork_attestation_sha256"] == hashlib.sha256(
        (root / "package" / bundles.OFFLINE_FORK_ATTESTATION).read_bytes()
    ).hexdigest()
    assert manifest["platform"] == release_inputs[3]
    assert manifest["files"]["node"] == hashlib.sha256(verified.node_path.read_bytes()).hexdigest()
    assert manifest["files"]["server.bundle.mjs"] == hashlib.sha256(
        verified.server_entrypoint.read_bytes()
    ).hexdigest()
    for relative in bundles.AUTHORITY_FILES:
        authority_path = verified.authority_root / relative
        assert manifest["files"][f"authority/{relative}"] == hashlib.sha256(
            authority_path.read_bytes()
        ).hexdigest()
    assert "package/node_modules/better-sqlite3/build/Release/better_sqlite3.node" in manifest["files"]
    payload_count = sum(
        1
        for path in root.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "manifest.sha256"}
    )
    assert verified.file_count == payload_count == len(manifest["files"])
    expected_record = f"{hashlib.sha256((root / 'manifest.json').read_bytes()).hexdigest()}  manifest.json\n"
    assert (root / "manifest.sha256").read_text() == expected_record


def test_build_is_byte_reproducible_including_archive(
    tmp_path: Path,
    release_inputs: tuple[Path, Path, Path, str],
) -> None:
    first = _build(tmp_path, release_inputs, "first")
    second = _build(tmp_path, release_inputs, "second")
    first_archive = bundles.create_reproducible_archive(
        first.root, tmp_path / "first.tar.gz", epoch=1_700_000_000
    )
    second_archive = bundles.create_reproducible_archive(
        second.root, tmp_path / "second.tar.gz", epoch=1_700_000_000
    )

    assert (first.root / "manifest.json").read_bytes() == (second.root / "manifest.json").read_bytes()
    assert first_archive.read_bytes() == second_archive.read_bytes()
    with tarfile.open(first_archive, "r:gz") as archive:
        members = archive.getmembers()
    assert members[0].name == "context_mode"
    assert all(member.uid == 0 and member.gid == 0 and member.mtime == 1_700_000_000 for member in members)
    assert not any(member.issym() or member.islnk() for member in members)


def test_verifier_rejects_tamper_and_unlisted_file(
    tmp_path: Path,
    release_inputs: tuple[Path, Path, Path, str],
) -> None:
    verified = _build(tmp_path, release_inputs, "tampered")
    verified.server_entrypoint.write_text("tampered\n")
    with pytest.raises(bundles.BundleBuildError, match="SHA-256 mismatch"):
        bundles.verify_bundle(verified.root, expected_platform=verified.platform)

    complete = _build(tmp_path, release_inputs, "unlisted")
    _write(complete.root / "package" / "build" / "not-in-manifest.txt", "unexpected\n")
    with pytest.raises(bundles.BundleBuildError, match="coverage mismatch"):
        bundles.verify_bundle(complete.root, expected_platform=complete.platform)

    authority_tamper = _build(tmp_path, release_inputs, "authority-tampered")
    (authority_tamper.authority_root / "authority.sig").write_bytes(b"different-signature")
    with pytest.raises(bundles.BundleBuildError, match="SHA-256 mismatch"):
        bundles.verify_bundle(
            authority_tamper.root,
            expected_platform=authority_tamper.platform,
        )


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("missing", "authority root layout mismatch"),
        ("extra-root", "authority root layout mismatch"),
        ("extra-bin", "authority bin layout mismatch"),
        ("symlink", "regular non-symlink file"),
        ("empty", "authority file is empty"),
        ("non-executable", "authority .* is not executable"),
    ),
)
def test_builder_rejects_non_exact_native_authority_source(
    tmp_path: Path,
    release_inputs: tuple[Path, Path, Path, str],
    case: str,
    message: str,
) -> None:
    context, node, authority, platform_tag = release_inputs
    if case == "missing":
        (authority / "authority.sig").unlink()
    elif case == "extra-root":
        _write(authority / "README", "not part of the signed payload\n")
    elif case == "extra-bin":
        _write(authority / "bin" / "helper", "#!/bin/sh\n", executable=True)
    elif case == "symlink":
        signature = authority / "authority.sig"
        signature.unlink()
        signature.symlink_to("LICENSE")
    elif case == "empty":
        (authority / "authority.sig").write_bytes(b"")
    elif case == "non-executable":
        (authority / "bin" / "bello-context-broker").chmod(0o644)
    else:  # pragma: no cover - protects the test table itself
        raise AssertionError(case)

    with pytest.raises(bundles.BundleBuildError, match=message):
        bundles.build_bundle(
            context_source=context,
            node_tree=node,
            authority_source=authority,
            output=tmp_path / "invalid-authority",
            platform_tag=platform_tag,
        )


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("missing", "authority root layout mismatch"),
        ("extra", "authority root layout mismatch"),
        ("symlink", "regular non-symlink file"),
        ("non-executable", "authority .* is not executable"),
    ),
)
def test_bundle_verifier_rejects_non_exact_native_authority_layout(
    tmp_path: Path,
    release_inputs: tuple[Path, Path, Path, str],
    case: str,
    message: str,
) -> None:
    verified = _build(tmp_path, release_inputs, f"invalid-authority-{case}")
    authority = verified.authority_root
    if case == "missing":
        (authority / "authority.sig").unlink()
    elif case == "extra":
        _write(authority / "extra", "unexpected\n")
    elif case == "symlink":
        signature = authority / "authority.sig"
        signature.unlink()
        signature.symlink_to("LICENSE")
    elif case == "non-executable":
        (authority / "bin" / "bello-context-launcher").chmod(0o644)
    else:  # pragma: no cover - protects the test table itself
        raise AssertionError(case)

    with pytest.raises(bundles.BundleBuildError, match=message):
        bundles.verify_bundle(verified.root, expected_platform=verified.platform)


def test_verifier_rejects_noncanonical_or_wrong_manifest_digest(
    tmp_path: Path,
    release_inputs: tuple[Path, Path, Path, str],
) -> None:
    verified = _build(tmp_path, release_inputs, "bundle")
    manifest_path = verified.manifest_path
    manifest = json.loads(manifest_path.read_text())
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(bundles.BundleBuildError, match="not canonical"):
        bundles.verify_bundle(verified.root, expected_platform=verified.platform)

    manifest_path.write_bytes(bundles._canonical_json(manifest))
    verified.manifest_digest_path.write_text(f"{'0' * 64}  manifest.json\n", encoding="ascii")
    with pytest.raises(bundles.BundleBuildError, match="manifest.sha256"):
        bundles.verify_bundle(verified.root, expected_platform=verified.platform)


def test_source_and_node_pins_fail_closed(
    tmp_path: Path,
    release_inputs: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, node, authority, platform_tag = release_inputs
    monkeypatch.setattr(bundles, "_git_head", lambda *_args, **_kwargs: bundles.CONTEXT_MODE_COMMIT)
    with pytest.raises(bundles.BundleBuildError, match="stock Context Mode upstream"):
        bundles.build_bundle(
            context_source=context,
            node_tree=node,
            authority_source=authority,
            output=tmp_path / "wrong-commit",
            platform_tag=platform_tag,
        )

    monkeypatch.setattr(bundles, "_git_head", lambda *_args, **_kwargs: "c" * 40)
    monkeypatch.setattr(bundles, "_git_is_ancestor", lambda *_args, **_kwargs: False)
    with pytest.raises(bundles.BundleBuildError, match="not based on pinned upstream"):
        bundles.build_bundle(
            context_source=context,
            node_tree=node,
            authority_source=authority,
            output=tmp_path / "wrong-base",
            platform_tag=platform_tag,
        )

    monkeypatch.setattr(bundles, "_git_head", lambda *_args, **_kwargs: FORK_SOURCE_COMMIT)
    monkeypatch.setattr(bundles, "_git_is_ancestor", lambda *_args, **_kwargs: True)
    _write(
        node / "bin" / "node",
        "#!/bin/sh\nprintf 'v22.9.0\\n'\n",
        executable=True,
    )
    with pytest.raises(bundles.BundleBuildError, match="requires 'v22.5.0'"):
        bundles.build_bundle(
            context_source=context,
            node_tree=node,
            authority_source=authority,
            output=tmp_path / "wrong-node",
            platform_tag=platform_tag,
        )


def test_builder_refuses_release_without_reviewed_offline_fork_commit_pin(
    tmp_path: Path,
    release_inputs: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, node, authority, platform_tag = release_inputs
    monkeypatch.setattr(bundles, "PINNED_OFFLINE_FORK_COMMIT", "0" * 40)
    with pytest.raises(bundles.BundleBuildError, match="reviewed.*pin is not configured"):
        bundles.build_bundle(
            context_source=context,
            node_tree=node,
            authority_source=authority,
            output=tmp_path / "unreviewed-fork",
            platform_tag=platform_tag,
        )


@pytest.mark.parametrize(
    ("relative", "payload", "message"),
    (
        ("server.bundle.mjs", "register('ctx_upgrade');\n", "forbidden tool name"),
        ("start.mjs", "spawn('npm', ['install', 'x']);\n", "package-manager operation"),
        ("hooks/fixture.txt", "import{lookup}from\"node:dns\";\n", "network module import"),
        ("skills/fixture.txt", "fetch('https://example.invalid');\n", "direct network API"),
        ("configs/fixture.txt", "ensure-deps\n", "mutating dependency/startup helper"),
        ("build/fixture.txt", "['git', 'clone', 'https://example.invalid/repo'];\n", "source update route"),
    ),
)
def test_builder_rejects_forbidden_offline_fork_surfaces(
    tmp_path: Path,
    release_inputs: tuple[Path, Path, Path, str],
    relative: str,
    payload: str,
    message: str,
) -> None:
    context, node, authority, platform_tag = release_inputs
    _write(context / relative, payload)
    _write(
        context / bundles.OFFLINE_FORK_ATTESTATION,
        bundles._canonical_json(
            bundles.make_offline_fork_attestation(
                context,
                fork_source_commit=FORK_SOURCE_COMMIT,
            )
        ),
    )
    with pytest.raises(bundles.BundleBuildError, match=message):
        bundles.build_bundle(
            context_source=context,
            node_tree=node,
            authority_source=authority,
            output=tmp_path / "forbidden-fork",
            platform_tag=platform_tag,
        )


def test_builder_rejects_missing_or_stale_offline_fork_attestation(
    tmp_path: Path,
    release_inputs: tuple[Path, Path, Path, str],
) -> None:
    context, node, authority, platform_tag = release_inputs
    (context / bundles.OFFLINE_FORK_ATTESTATION).unlink()
    with pytest.raises(bundles.BundleBuildError, match="attestation"):
        bundles.build_bundle(
            context_source=context,
            node_tree=node,
            authority_source=authority,
            output=tmp_path / "missing-attestation",
            platform_tag=platform_tag,
        )

    _write(
        context / bundles.OFFLINE_FORK_ATTESTATION,
        bundles._canonical_json(
            bundles.make_offline_fork_attestation(
                context,
                fork_source_commit=FORK_SOURCE_COMMIT,
            )
        ),
    )
    _write(context / "server.bundle.mjs", "export const changed = true;\n")
    with pytest.raises(bundles.BundleBuildError, match="attestation does not match"):
        bundles.build_bundle(
            context_source=context,
            node_tree=node,
            authority_source=authority,
            output=tmp_path / "stale-attestation",
            platform_tag=platform_tag,
        )


def test_builder_requires_native_binding_and_never_overwrites_output(
    tmp_path: Path,
    release_inputs: tuple[Path, Path, Path, str],
) -> None:
    context, node, authority, platform_tag = release_inputs
    output = tmp_path / "existing"
    output.mkdir()
    marker = output / "user-data"
    marker.write_text("keep", encoding="utf-8")
    with pytest.raises(bundles.BundleBuildError, match="refusing to overwrite"):
        bundles.build_bundle(
            context_source=context,
            node_tree=node,
            authority_source=authority,
            output=output,
            platform_tag=platform_tag,
        )
    assert marker.read_text() == "keep"

    (context / "node_modules" / "better-sqlite3" / "build" / "Release" / "better_sqlite3.node").unlink()
    with pytest.raises(bundles.BundleBuildError, match="exactly one native"):
        bundles.build_bundle(
            context_source=context,
            node_tree=node,
            authority_source=authority,
            output=tmp_path / "missing-native",
            platform_tag=platform_tag,
        )


def test_clean_release_environment_drops_credentials_and_npm_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    monkeypatch.setenv("HTTPS_PROXY", "http://credential@example.invalid")
    monkeypatch.setenv("npm_config_registry", "https://example.invalid")
    environment = bundles._release_environment(tmp_path)

    assert environment["HOME"] == str(tmp_path)
    assert environment["CONTEXT_MODE_OFFLINE"] == "1"
    assert "OPENAI_API_KEY" not in environment
    assert "HTTPS_PROXY" not in environment
    assert "npm_config_registry" not in environment


def test_static_cli_verification_reports_machine_readable_success(
    tmp_path: Path,
    release_inputs: tuple[Path, Path, Path, str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    verified = _build(tmp_path, release_inputs, "bundle")
    result = bundles.main(
        [
            "verify",
            "--bundle",
            str(verified.root),
            "--platform",
            verified.platform,
            "--static-only",
        ]
    )
    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert output == {
        "bundle": str(verified.root),
        "files": verified.file_count,
        "platform": verified.platform,
        "release_ready": False,
        "worker_bundle_verified": True,
    }


def test_all_release_platform_tags_are_explicit() -> None:
    assert bundles.SUPPORTED_PLATFORMS == (
        "linux-x86_64",
        "linux-arm64",
        "macos-x86_64",
        "macos-arm64",
    )


def test_release_workflow_has_four_air_gapped_native_jobs() -> None:
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "context-mode-bundles.yml"
    ).read_text(encoding="utf-8")
    for platform_tag in bundles.SUPPORTED_PLATFORMS:
        assert f"platform: {platform_tag}" in workflow
    assert "self-hosted" in workflow
    assert "pre-provisioned" in workflow
    assert "bello-offline-fork.json" in workflow
    assert '--authority-source "$RELEASE_INPUT_ROOT/$PLATFORM_TAG/authority"' in workflow
    assert "npm install" not in workflow
    assert "curl " not in workflow
    assert "wget " not in workflow


def test_platform_bundle_package_data_route_is_declared() -> None:
    pyproject = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    assert "_vendor/context_mode/**/*" in pyproject["tool"]["setuptools"]["package-data"]["supervisor"]
