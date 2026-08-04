from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from supervisor.context_mode._util import ContextModeDataError, canonical_json_bytes
from supervisor.context_mode.approvals import (
    CapabilityError,
    CapabilityExpectation,
    CapabilityReplay,
    OneShotCapabilityStore,
    normalized_arguments_digest,
)
from supervisor.context_mode.config import (
    ALLOWED_TOOLS,
    FORBIDDEN_TOOL_NAMES,
    REQUIRED_HOOKS,
    ConfigError,
    Role,
    generate_coder_home,
    generate_supervisor_home,
    validate_exact_tool_catalogue,
)
from supervisor.context_mode.health import check_generated_role_home
from supervisor.context_mode import packaging as runtime_packaging
from supervisor.context_mode.packaging import (
    PINNED_CONTEXT_MODE_COMMIT,
    PINNED_CONTEXT_MODE_VERSION,
    PINNED_NODE_VERSION,
    PackagingError,
    verify_runtime_bundle,
)
from supervisor.context_mode.session import (
    BindingConflict,
    BindingError,
    BindingStore,
    CheckpointCursor,
    ContextBinding,
    LifecycleSnapshot,
    StableBindingIdentity,
    TransitionReason,
)


@pytest.fixture(autouse=True)
def _reviewed_offline_fork_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime_packaging, "PINNED_OFFLINE_FORK_COMMIT", "c" * 40)


def test_canonical_json_rejects_non_utf8_surrogates_as_data_error() -> None:
    with pytest.raises(ContextModeDataError, match="strict JSON"):
        canonical_json_bytes({"value": "\ud800"})


def _binding(workspace: Path, *, policy_digest: str = "b" * 64) -> ContextBinding:
    return ContextBinding(
        StableBindingIdentity(
            run_id="run-1",
            workspace_id="workspace-1",
            context_session_id="session-1",
            workspace_path=os.fspath(workspace),
            base_config_digest="a" * 64,
        ),
        LifecycleSnapshot(
            binding_version=1,
            context_state_epoch=0,
            coder_generation=1,
            generation_lease_id="lease-1",
            coder_process_epoch=1,
            app_server_instance_id="app-1",
            sandbox_policy_digest=policy_digest,
        ),
    )


def _write_complete_runtime_bundle(root: Path) -> tuple[Path, Path]:
    node = root / "node" / "bin" / "node"
    package = root / "package"
    authority = root / "authority"
    server = package / "server.bundle.mjs"
    node.parent.mkdir(parents=True)
    node.write_bytes(b"node-runtime")
    node.chmod(0o755)
    (root / "node" / "LICENSE").write_text("Node.js license\n", encoding="utf-8")
    package.mkdir()
    server.write_text("export const server = true;\n", encoding="utf-8")
    (package / "cli.bundle.mjs").write_text("export const cli = true;\n", encoding="utf-8")
    (package / "start.mjs").write_text("import './server.bundle.mjs';\n", encoding="utf-8")
    (package / "package.json").write_text(
        json.dumps(
            {
                "name": "context-mode",
                "version": PINNED_CONTEXT_MODE_VERSION,
                "license": runtime_packaging.CONTEXT_MODE_LICENSE,
            }
        ),
        encoding="utf-8",
    )
    (package / "LICENSE").write_text("Elastic License 2.0\n", encoding="utf-8")
    (authority / "bin").mkdir(parents=True)
    for executable in ("bello-context-broker", "bello-context-launcher"):
        path = authority / "bin" / executable
        path.write_bytes(b"#!/bin/sh\nexit 0\n")
        path.chmod(0o755)
    (authority / "LICENSE").write_text("Native authority license\n", encoding="utf-8")
    (authority / "authority.json").write_text('{"schema_version":1}\n', encoding="utf-8")
    (authority / "authority.sig").write_bytes(b"signed-native-authority")
    (authority / "release-public-key.pem").write_text(
        "-----BEGIN PUBLIC KEY-----\nfixture\n",
        encoding="utf-8",
    )
    for directory in runtime_packaging.FORK_CODE_DIRECTORIES:
        target = package / directory
        target.mkdir()
        (target / "fixture.txt").write_text(f"{directory}\n", encoding="utf-8")
    tool_schemas = {
        name: {"type": "object", "properties": {}}
        for name in runtime_packaging.ALLOWED_TOOLS
    }
    (package / "configs" / "bello-tool-schemas.json").write_bytes(
        runtime_packaging._canonical_manifest_bytes(tool_schemas)
    )
    native = package / "node_modules" / "better-sqlite3"
    (native / "build" / "Release").mkdir(parents=True)
    (native / "package.json").write_text(
        json.dumps(
            {
                "name": "better-sqlite3",
                "version": runtime_packaging.BETTER_SQLITE3_VERSION,
            }
        ),
        encoding="utf-8",
    )
    (native / "build" / "Release" / "better_sqlite3.node").write_bytes(b"native-binding")
    runtime_packaging.PINNED_NODE_BINARY_SHA256 = {
        tag: hashlib.sha256(node.read_bytes()).hexdigest()
        for tag in runtime_packaging.SUPPORTED_RELEASE_PLATFORMS
    }
    runtime_packaging.PINNED_NODE_LICENSE_SHA256 = hashlib.sha256(
        (root / "node" / "LICENSE").read_bytes()
    ).hexdigest()
    dependency_digest = runtime_packaging._dependency_inventory_digest(package / "node_modules")
    runtime_packaging.PINNED_DEPENDENCY_INVENTORY_SHA256 = {
        tag: dependency_digest for tag in runtime_packaging.SUPPORTED_RELEASE_PLATFORMS
    }
    attestation = {
        "schema_version": runtime_packaging.OFFLINE_FORK_ATTESTATION_VERSION,
        "attestation_type": runtime_packaging.OFFLINE_FORK_ID,
        "fork_revision": runtime_packaging.OFFLINE_FORK_REVISION,
        "fork_source_commit": "c" * 40,
        "upstream_version": PINNED_CONTEXT_MODE_VERSION,
        "upstream_commit": PINNED_CONTEXT_MODE_COMMIT,
        "catalog_version": 1,
        "allowed_tools": list(runtime_packaging.ALLOWED_TOOLS),
        "tool_schema_digests": {
            name: hashlib.sha256(runtime_packaging._canonical_digest_json(schema)).hexdigest()
            for name, schema in tool_schemas.items()
        },
        "forbidden_tools": list(runtime_packaging.FORBIDDEN_TOOLS),
        "offline": True,
        "runtime_downloads": False,
        "runtime_installs": False,
        "runtime_updates": False,
        "network_routes": False,
        "payload_sha256": runtime_packaging._offline_fork_payload_digest(package),
    }
    attestation_path = package / runtime_packaging.OFFLINE_FORK_ATTESTATION
    attestation_path.write_bytes(runtime_packaging._canonical_manifest_bytes(attestation))
    files = {
        key: runtime_packaging._sha256_file(path)
        for key, path in runtime_packaging._iter_payload_files(root)
    }
    manifest = {
        "schema_version": 1,
        "bello_offline_fork_revision": runtime_packaging.OFFLINE_FORK_REVISION,
        "bello_offline_fork_attestation_sha256": runtime_packaging._sha256_file(attestation_path),
        "context_mode_commit": PINNED_CONTEXT_MODE_COMMIT,
        "context_mode_version": PINNED_CONTEXT_MODE_VERSION,
        "node_version": PINNED_NODE_VERSION,
        "platform": "linux-x86_64",
        "files": files,
    }
    manifest_bytes = runtime_packaging._canonical_manifest_bytes(manifest)
    (root / "manifest.json").write_bytes(manifest_bytes)
    (root / "manifest.sha256").write_text(
        f"{hashlib.sha256(manifest_bytes).hexdigest()}  manifest.json\n",
        encoding="ascii",
    )
    return node, server


def test_exact_catalogue_has_only_eight_offline_tools() -> None:
    assert len(ALLOWED_TOOLS) == 8
    assert not set(ALLOWED_TOOLS) & FORBIDDEN_TOOL_NAMES
    assert validate_exact_tool_catalogue(ALLOWED_TOOLS) == ALLOWED_TOOLS
    with pytest.raises(ConfigError):
        validate_exact_tool_catalogue((*ALLOWED_TOOLS, "ctx_fetch_and_index"))
    with pytest.raises(ConfigError):
        validate_exact_tool_catalogue(ALLOWED_TOOLS[:-1])
    with pytest.raises(ConfigError):
        validate_exact_tool_catalogue((*ALLOWED_TOOLS[:-1], ALLOWED_TOOLS[0]))


def test_binding_store_is_atomic_cas_and_reason_monotonic(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = BindingStore(tmp_path / "metadata" / "context-binding.json")
    initial = store.initialize(_binding(workspace))
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600

    claimed = store.claim_provider_thread(
        expected_version=1,
        coder_generation=1,
        generation_lease_id="lease-1",
        coder_process_epoch=1,
        provider_thread_id="thread-1",
    )
    assert claimed.binding_version == 2
    assert claimed.lifecycle.provider_thread_id == "thread-1"
    with pytest.raises(BindingConflict):
        store.claim_provider_thread(
            expected_version=1,
            coder_generation=1,
            generation_lease_id="lease-1",
            coder_process_epoch=1,
            provider_thread_id="thread-late",
        )

    restarted = store.transition(
        expected_version=2,
        reason=TransitionReason.LOGICAL_GENERATION_RESTART,
        coder_generation=2,
        generation_lease_id="lease-2",
        provider_thread_id=None,
    )
    assert restarted.binding_version == 3
    assert restarted.lifecycle.coder_process_epoch == 1
    with pytest.raises(BindingError):
        restarted.transition(
            TransitionReason.PROCESS_RECOVERY,
            coder_process_epoch=4,
            app_server_instance_id="app-2",
        )

    payload = json.loads(store.path.read_text(encoding="utf-8"))
    payload["stable"]["workspace_id"] = "different"
    forged = ContextBinding.from_dict(payload)
    with pytest.raises(BindingError):
        store.compare_and_swap(
            expected_version=3,
            candidate=forged,
            reason=TransitionReason.POLICY_CHANGE,
        )


def test_binding_and_checkpoint_schema_versions_reject_json_boolean(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace).transition(
        TransitionReason.THREAD_CLAIM,
        provider_thread_id="thread-1",
    )
    binding_payload = binding.to_dict()
    binding_payload["schema_version"] = True
    with pytest.raises(BindingError, match="integer"):
        ContextBinding.from_dict(binding_payload)

    cursor = CheckpointCursor.create(
        authority_key=b"checkpoint-schema-test-authority!",
        binding=binding,
        checkpoint_id="checkpoint-schema",
        reason="schema test",
        context_event_seq=1,
        last_committed_operation_id=None,
        created_at="2026-08-02T00:00:00Z",
    )
    cursor_payload = cursor.to_dict()
    cursor_payload["schema_version"] = True
    with pytest.raises(BindingError, match="integer"):
        CheckpointCursor.from_dict(cursor_payload)


def test_generation_scoped_capability_is_exact_and_one_shot(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binding = _binding(workspace).transition(
        TransitionReason.THREAD_CLAIM,
        provider_thread_id="thread-1",
    )
    store = OneShotCapabilityStore()
    arguments = {"code": "print('local')"}
    request_key = {"role": "coder", "process_epoch": 1, "request_id": 7}
    capability = store.grant(
        binding=binding,
        process_epoch=1,
        tool_name="ctx_execute",
        arguments=arguments,
        cwd=workspace,
        request_key=request_key,
    )
    expectation = CapabilityExpectation(
        capability_id=capability.capability_id,
        process_epoch=1,
        tool_name="ctx_execute",
        arguments_digest=normalized_arguments_digest(arguments),
        canonical_cwd=os.fspath(workspace),
        request_digest=capability.request_digest,
    )
    assert store.consume(expectation, active_binding=binding) == capability
    with pytest.raises(CapabilityReplay):
        store.consume(expectation, active_binding=binding)

    second = store.grant(
        binding=binding,
        process_epoch=1,
        tool_name="ctx_execute",
        arguments=arguments,
        cwd=workspace,
        request_key={**request_key, "request_id": 8},
    )
    wrong = CapabilityExpectation(
        capability_id=second.capability_id,
        process_epoch=1,
        tool_name="ctx_execute",
        arguments_digest=normalized_arguments_digest({"code": "different"}),
        canonical_cwd=os.fspath(workspace),
        request_digest=second.request_digest,
    )
    with pytest.raises(CapabilityError):
        store.consume(wrong, active_binding=binding)


def test_generated_role_homes_do_not_cross_contaminate(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    launcher = tmp_path / "bin" / "bello-context-mode-launcher"
    bootstrap = tmp_path / "bootstrap" / "mcp.json"
    hook_bootstraps = {name: tmp_path / "bootstrap" / f"{name}.json" for name in REQUIRED_HOOKS}
    coder = generate_coder_home(
        tmp_path / "coder-home",
        launcher_path=launcher,
        mcp_bootstrap_path=bootstrap,
        workspace=workspace,
        hook_bootstraps=hook_bootstraps,
        auth_bytes=b"{}\n",
    )
    supervisor = generate_supervisor_home(tmp_path / "supervisor-home", auth_bytes=b"{}\n")

    coder_config = coder.config_path.read_text(encoding="utf-8")
    supervisor_config = supervisor.config_path.read_text(encoding="utf-8")
    assert all(tool in coder_config for tool in ALLOWED_TOOLS)
    assert all(tool in coder_config for tool in FORBIDDEN_TOOL_NAMES)
    assert "bello_context_mode" not in supervisor_config
    assert not (supervisor.root / "hooks.json").exists()
    assert (coder.root / "skills" / "bello-context-mode" / "SKILL.md").is_file()
    assert check_generated_role_home(coder.root, expected_role=Role.CODER).passed
    assert check_generated_role_home(supervisor.root, expected_role=Role.SUPERVISOR).passed


def test_bundle_manifest_hashes_and_release_pins(tmp_path: Path) -> None:
    node, server = _write_complete_runtime_bundle(tmp_path)
    bundle = verify_runtime_bundle(tmp_path, expected_platform="linux-x86_64")
    assert bundle.node_path == node
    assert bundle.authority_root == tmp_path / "authority"
    assert all(
        os.access(bundle.authority_root / relative, os.X_OK)
        for relative in runtime_packaging.AUTHORITY_EXECUTABLES
    )
    server.write_bytes(b"tampered")
    with pytest.raises(PackagingError, match="SHA-256 mismatch"):
        verify_runtime_bundle(tmp_path, expected_platform="linux-x86_64")


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("missing", "authority layout mismatch"),
        ("extra", "authority layout mismatch"),
        ("symlink", "regular non-symlink file"),
        ("empty", "authority file is empty"),
        ("non-executable", "authority executable is not executable"),
        ("tamper", "SHA-256 mismatch"),
    ),
)
def test_runtime_bundle_verifier_requires_exact_signed_native_authority(
    tmp_path: Path,
    case: str,
    message: str,
) -> None:
    _write_complete_runtime_bundle(tmp_path)
    authority = tmp_path / "authority"
    if case == "missing":
        (authority / "authority.sig").unlink()
    elif case == "extra":
        (authority / "unexpected").write_text("extra\n", encoding="utf-8")
    elif case == "symlink":
        signature = authority / "authority.sig"
        signature.unlink()
        signature.symlink_to("LICENSE")
    elif case == "empty":
        (authority / "authority.sig").write_bytes(b"")
    elif case == "non-executable":
        (authority / "bin" / "bello-context-broker").chmod(0o644)
    elif case == "tamper":
        (authority / "authority.sig").write_bytes(b"tampered-native-authority")
    else:  # pragma: no cover - protects the test table itself
        raise AssertionError(case)

    with pytest.raises(PackagingError, match=message):
        verify_runtime_bundle(tmp_path, expected_platform="linux-x86_64")


def test_runtime_bundle_verifier_requires_canonical_full_coverage(tmp_path: Path) -> None:
    _write_complete_runtime_bundle(tmp_path)
    (tmp_path / "package" / "build" / "unlisted.js").write_text("extra\n", encoding="utf-8")
    with pytest.raises(PackagingError, match="coverage mismatch"):
        verify_runtime_bundle(tmp_path, expected_platform="linux-x86_64")

    (tmp_path / "package" / "build" / "unlisted.js").unlink()
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(PackagingError, match="not canonical"):
        verify_runtime_bundle(tmp_path, expected_platform="linux-x86_64")


def test_runtime_bundle_verifier_requires_sidecar_schema_license_and_native_payload(
    tmp_path: Path,
) -> None:
    _write_complete_runtime_bundle(tmp_path)
    (tmp_path / "manifest.sha256").write_text(f"{'0' * 64}  manifest.json\n", encoding="ascii")
    with pytest.raises(PackagingError, match="manifest.sha256"):
        verify_runtime_bundle(tmp_path, expected_platform="linux-x86_64")

    schema_root = tmp_path / "schema-case"
    _write_complete_runtime_bundle(schema_root)
    manifest = json.loads((schema_root / "manifest.json").read_text(encoding="utf-8"))
    del manifest["schema_version"]
    manifest_bytes = runtime_packaging._canonical_manifest_bytes(manifest)
    (schema_root / "manifest.json").write_bytes(manifest_bytes)
    (schema_root / "manifest.sha256").write_text(
        f"{hashlib.sha256(manifest_bytes).hexdigest()}  manifest.json\n",
        encoding="ascii",
    )
    with pytest.raises(PackagingError, match="missing fields.*schema_version"):
        verify_runtime_bundle(schema_root, expected_platform="linux-x86_64")

    # Rebuild a fresh fixture in a sibling so each strict failure is observed
    # before a previous mutation can mask it.
    license_root = tmp_path / "license-case"
    _write_complete_runtime_bundle(license_root)
    license_path = license_root / "package" / "LICENSE"
    license_path.write_text("wrong license\n", encoding="utf-8")
    manifest = json.loads((license_root / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"]["package/LICENSE"] = hashlib.sha256(license_path.read_bytes()).hexdigest()
    manifest_bytes = runtime_packaging._canonical_manifest_bytes(manifest)
    (license_root / "manifest.json").write_bytes(manifest_bytes)
    (license_root / "manifest.sha256").write_text(
        f"{hashlib.sha256(manifest_bytes).hexdigest()}  manifest.json\n",
        encoding="ascii",
    )
    with pytest.raises(PackagingError, match="Elastic License"):
        verify_runtime_bundle(license_root, expected_platform="linux-x86_64")

    native_root = tmp_path / "native-case"
    _write_complete_runtime_bundle(native_root)
    native_path = (
        native_root
        / "package"
        / "node_modules"
        / "better-sqlite3"
        / "build"
        / "Release"
        / "better_sqlite3.node"
    )
    native_path.write_bytes(b"")
    manifest = json.loads((native_root / "manifest.json").read_text(encoding="utf-8"))
    native_key = "package/node_modules/better-sqlite3/build/Release/better_sqlite3.node"
    manifest["files"][native_key] = hashlib.sha256(b"").hexdigest()
    manifest_bytes = runtime_packaging._canonical_manifest_bytes(manifest)
    (native_root / "manifest.json").write_bytes(manifest_bytes)
    (native_root / "manifest.sha256").write_text(
        f"{hashlib.sha256(manifest_bytes).hexdigest()}  manifest.json\n",
        encoding="ascii",
    )
    with pytest.raises(PackagingError, match="non-empty native"):
        verify_runtime_bundle(native_root, expected_platform="linux-x86_64")


def test_runtime_bundle_verifier_requires_bound_offline_fork_attestation(tmp_path: Path) -> None:
    _write_complete_runtime_bundle(tmp_path)
    attestation_path = tmp_path / "package" / runtime_packaging.OFFLINE_FORK_ATTESTATION
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    attestation["runtime_downloads"] = True
    attestation_path.write_bytes(runtime_packaging._canonical_manifest_bytes(attestation))
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"][f"package/{runtime_packaging.OFFLINE_FORK_ATTESTATION}"] = (
        runtime_packaging._sha256_file(attestation_path)
    )
    manifest["bello_offline_fork_attestation_sha256"] = runtime_packaging._sha256_file(
        attestation_path
    )
    manifest_bytes = runtime_packaging._canonical_manifest_bytes(manifest)
    (tmp_path / "manifest.json").write_bytes(manifest_bytes)
    (tmp_path / "manifest.sha256").write_text(
        f"{hashlib.sha256(manifest_bytes).hexdigest()}  manifest.json\n",
        encoding="ascii",
    )
    with pytest.raises(PackagingError, match="attestation policy mismatch"):
        verify_runtime_bundle(tmp_path, expected_platform="linux-x86_64")
