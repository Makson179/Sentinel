from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from supervisor.context_mode._util import digest_json
from supervisor.context_mode.health import check_offline_runtime_preflight
from supervisor.context_mode.manifests import load_manifest_resource
from supervisor.context_mode.sandbox import (
    AUTHENTICATED_RUNNER_IDENTITY,
    BackendStatus,
    LINUX_REQUIRED_BACKEND_CHECKS,
    MACOS_REQUIRED_BACKEND_CHECKS,
    MountAccess,
    PROCESS_CONTROL_BACKEND_CHECKS,
    ProcessControlPolicy,
    ProfileKind,
    ResourceLimits,
    SandboxBackend,
    SandboxBackendName,
    SandboxError,
    SandboxPathLayout,
    build_clean_environment,
    generate_sandbox_policies,
    verified_backend,
)


def _policies(tmp_path: Path, *, extra_mask: str | None = None):
    workspace = tmp_path / "workspace"
    immutable = workspace / "task.md"
    dependency = workspace / ".venv"
    masks = () if extra_mask is None else (workspace / extra_mask,)
    environment = build_clean_environment(
        home=tmp_path / "unused-base-home",
        temp=tmp_path / "unused-base-temp",
        context_mode_dir=tmp_path / "state",
        toolchain_bins=(tmp_path / "runtime" / "bin", tmp_path / "toolchain" / "bin"),
        platform_tag="linux-x86_64",
        run_id="run-1",
        workspace_id="workspace-1",
        context_session_id="session-1",
    )
    return generate_sandbox_policies(
        SandboxPathLayout(
            workspace=workspace,
            runtime=tmp_path / "runtime",
            state=tmp_path / "state",
            mcp_home=tmp_path / "homes" / "mcp",
            mcp_temp=tmp_path / "temps" / "mcp",
            hook_home=tmp_path / "homes" / "hook",
            hook_temp=tmp_path / "temps" / "hook",
            command_home=tmp_path / "homes" / "command",
            command_scratch=tmp_path / "temps" / "command",
            launcher=tmp_path / "bin" / "launcher",
            bootstrap=tmp_path / "bootstrap",
            proxy_bootstrap_files=(
                tmp_path / "bootstrap" / "mcp.json",
                tmp_path / "bootstrap" / "hook-Stop.json",
            ),
            workspace_git=workspace / ".git",
            immutable_workspace_paths=(immutable,),
            readonly_dependency_roots=(dependency,),
            workspace_masked_paths=masks,
            toolchain_roots=(tmp_path / "toolchain",),
            protected_roots=(tmp_path / "runtime-metadata", tmp_path / "codex-home"),
        ),
        environment=environment,
    )


def _mount_covering(policy, path: str):
    candidate = Path(path)
    return next(
        rule
        for rule in policy.mounts
        if candidate == Path(rule.target) or candidate.is_relative_to(Path(rule.target))
    )


def test_each_runtime_profile_mounts_its_generated_home_temp_and_xdg(tmp_path: Path) -> None:
    policies = _policies(tmp_path)
    runtime_profiles = (ProfileKind.MCP, ProfileKind.HOOK, ProfileKind.COMMAND)

    assert len({policies[profile].digest for profile in ProfileKind}) == len(ProfileKind)
    assert len({policies[profile].environment["HOME"] for profile in runtime_profiles}) == 3
    assert len({policies[profile].environment["TMPDIR"] for profile in runtime_profiles}) == 3
    for profile in runtime_profiles:
        policy = policies[profile]
        for key in ("HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"):
            assert _mount_covering(policy, policy.environment[key]).access is MountAccess.READ_WRITE

    hook = policies[ProfileKind.HOOK]
    assert str(tmp_path / "toolchain" / "bin") not in hook.environment["PATH"].split(":")
    assert str(tmp_path / "runtime" / "bin") in hook.environment["PATH"].split(":")


def test_command_has_no_state_authority_and_proxy_is_minimal(tmp_path: Path) -> None:
    policies = _policies(tmp_path)
    command = policies[ProfileKind.COMMAND]
    proxy = policies[ProfileKind.PROXY]

    assert "CONTEXT_MODE_DIR" not in command.environment
    assert not {"context_state", "binding", "receipts"}.intersection(
        rule.path_class for rule in command.mounts
    )
    assert str(tmp_path / "state") in command.protected_roots
    assert proxy.environment == {
        "BELLO_OFFLINE": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
    }
    assert {(rule.path_class, rule.access) for rule in proxy.mounts} == {
        ("launcher", MountAccess.READ_EXECUTE),
    }
    assert proxy.workspace_paths is None
    assert proxy.proxy_bootstrap is not None
    assert proxy.proxy_bootstrap.exactly_one_per_launch
    assert set(proxy.proxy_bootstrap.allowed_files) == {
        str(tmp_path / "bootstrap" / "mcp.json"),
        str(tmp_path / "bootstrap" / "hook-Stop.json"),
    }


def test_nested_workspace_mounts_are_exact_read_only_in_all_runtime_profiles(tmp_path: Path) -> None:
    policies = _policies(tmp_path)
    expected = {
        str(tmp_path / "workspace" / ".git"),
        str(tmp_path / "workspace" / "task.md"),
        str(tmp_path / "workspace" / ".venv"),
    }
    for profile in (ProfileKind.MCP, ProfileKind.HOOK, ProfileKind.COMMAND):
        policy = policies[profile]
        workspace_index = next(
            index for index, rule in enumerate(policy.mounts) if rule.path_class == "workspace"
        )
        nested = {
            rule.target
            for rule in policy.mounts
            if rule.path_class in {"workspace_git", "immutable_task", "readonly_dependency"}
        }
        assert nested == expected
        assert set(policy.workspace_paths.read_only_paths) == expected  # type: ignore[union-attr]
        for index, rule in enumerate(policy.mounts):
            if rule.target in expected:
                assert rule.access is MountAccess.READ_ONLY
                assert index > workspace_index


def test_reserved_and_late_created_workspace_paths_are_digest_bound_denials(tmp_path: Path) -> None:
    policies = _policies(tmp_path, extra_mask="grader-data")
    workspace_paths = policies[ProfileKind.MCP].workspace_paths
    assert workspace_paths is not None
    assert {".codex", ".supervisor", ".bello"}.issubset(workspace_paths.deny_component_names)
    assert {"runtime-metadata", "context-mode"}.issubset(workspace_paths.deny_top_level_names)
    assert {".env", ".env.*", "*.pem", "credentials.json"}.issubset(
        workspace_paths.deny_filename_globs
    )
    assert str(tmp_path / "workspace" / "grader-data") in workspace_paths.masked_paths

    without_extra_mask = _policies(tmp_path)[ProfileKind.MCP]
    assert policies[ProfileKind.MCP].digest != without_extra_mask.digest


def test_unmounted_generated_environment_path_is_rejected(tmp_path: Path) -> None:
    policy = _policies(tmp_path)[ProfileKind.MCP]
    bad_environment = {**policy.environment, "HOME": str(tmp_path / "not-mounted")}
    bad_environment["XDG_CONFIG_HOME"] = str(tmp_path / "not-mounted" / ".config")
    bad_environment["XDG_CACHE_HOME"] = str(tmp_path / "not-mounted" / ".cache")
    with pytest.raises(SandboxError, match="HOME is not covered"):
        replace(policy, environment=bad_environment)


def test_sandbox_boolean_contracts_do_not_accept_integer_aliases(tmp_path: Path) -> None:
    policy = _policies(tmp_path)[ProfileKind.MCP]
    with pytest.raises(SandboxError, match="network_allowed must be boolean"):
        replace(policy, network_allowed=0)  # type: ignore[arg-type]

    proxy = _policies(tmp_path)[ProfileKind.PROXY]
    assert proxy.proxy_bootstrap is not None
    with pytest.raises(SandboxError, match="exactly one file"):
        replace(proxy.proxy_bootstrap, exactly_one_per_launch=1)  # type: ignore[arg-type]


def test_backend_attestation_must_cover_nested_mounts_and_live_path_filter(tmp_path: Path) -> None:
    checks = set(LINUX_REQUIRED_BACKEND_CHECKS)
    for omitted in (
        "nested_readonly_mounts",
        "workspace_path_filter",
        "exact_bootstrap_file_mount",
    ):
        with pytest.raises(SandboxError, match="verification is missing checks"):
            verified_backend(
                name=SandboxBackendName.LINUX_BWRAP_SECCOMP,
                executable=tmp_path / "bwrap",
                verification_id="native-test",
                completed_checks=sorted(checks - {omitted}),
            )


def test_every_profile_digest_binds_the_strict_process_control_contract(tmp_path: Path) -> None:
    expected = {
        "authenticated_runner_identity": AUTHENTICATED_RUNNER_IDENTITY,
        "direct_exec_mediated": True,
        "ptrace_denied": True,
        "process_vm_denied": True,
        "cross_tree_signals_denied": True,
        "non_dumpable": True,
        "core_dumps_denied": True,
        "rlimits_enforced": True,
        "process_tree_enforced": True,
    }
    policies = _policies(tmp_path)
    for profile in ProfileKind:
        policy = policies[profile]
        assert policy.process_control.to_dict() == expected
        assert policy.to_dict()["process_control"] == expected
        assert policy.to_dict()["limits"]["core_dump_bytes"] == 0
        assert policy.digest == digest_json(policy.to_dict())


@pytest.mark.parametrize(
    "field_name",
    (
        "direct_exec_mediated",
        "ptrace_denied",
        "process_vm_denied",
        "cross_tree_signals_denied",
        "non_dumpable",
        "core_dumps_denied",
        "rlimits_enforced",
        "process_tree_enforced",
    ),
)
def test_process_control_policy_has_no_weakened_boolean_mode(field_name: str) -> None:
    with pytest.raises(SandboxError, match=field_name):
        replace(ProcessControlPolicy(), **{field_name: False})
    with pytest.raises(SandboxError, match=field_name):
        replace(ProcessControlPolicy(), **{field_name: 1})


def test_process_control_policy_requires_the_authenticated_native_runner() -> None:
    with pytest.raises(SandboxError, match="authenticated Bello native runner"):
        replace(ProcessControlPolicy(), authenticated_runner_identity="user-controlled-runner")


def test_resource_limits_bind_core_dump_denial() -> None:
    limits = ResourceLimits()
    assert limits.core_dump_bytes == 0
    assert limits.to_dict()["core_dump_bytes"] == 0
    with pytest.raises(SandboxError, match="core_dump_bytes must be zero"):
        replace(limits, core_dump_bytes=1)
    with pytest.raises(SandboxError, match="core_dump_bytes must be an integer"):
        replace(limits, core_dump_bytes=False)


@pytest.mark.parametrize(
    ("backend_name", "required_checks"),
    (
        (SandboxBackendName.LINUX_BWRAP_SECCOMP, LINUX_REQUIRED_BACKEND_CHECKS),
        (SandboxBackendName.MACOS_SEATBELT, MACOS_REQUIRED_BACKEND_CHECKS),
    ),
)
def test_native_backend_attestation_requires_every_platform_and_process_check(
    tmp_path: Path,
    backend_name: SandboxBackendName,
    required_checks: frozenset[str],
) -> None:
    assert PROCESS_CONTROL_BACKEND_CHECKS.issubset(required_checks)
    complete = verified_backend(
        name=backend_name,
        executable=tmp_path / "native-sandbox",
        verification_id="native-process-control-test",
        completed_checks=sorted(required_checks),
    )
    assert frozenset(complete.checks) == required_checks
    for omitted in required_checks:
        with pytest.raises(SandboxError, match="verification is missing checks"):
            verified_backend(
                name=backend_name,
                executable=tmp_path / "native-sandbox",
                verification_id="native-process-control-test",
                completed_checks=sorted(required_checks - {omitted}),
            )


@pytest.mark.parametrize(
    ("backend_name", "required_checks"),
    (
        (SandboxBackendName.LINUX_BWRAP_SECCOMP, LINUX_REQUIRED_BACKEND_CHECKS),
        (SandboxBackendName.MACOS_SEATBELT, MACOS_REQUIRED_BACKEND_CHECKS),
    ),
)
def test_native_backend_attestation_check_catalogue_is_exact(
    tmp_path: Path,
    backend_name: SandboxBackendName,
    required_checks: frozenset[str],
) -> None:
    with pytest.raises(SandboxError, match="unrecognized checks"):
        verified_backend(
            name=backend_name,
            executable=tmp_path / "native-sandbox",
            verification_id="native-process-control-test",
            completed_checks=(*sorted(required_checks), "unversioned-extra-claim"),
        )
    with pytest.raises(SandboxError, match="duplicate checks"):
        check = sorted(required_checks)[0]
        verified_backend(
            name=backend_name,
            executable=tmp_path / "native-sandbox",
            verification_id="native-process-control-test",
            completed_checks=(*sorted(required_checks), check),
        )


def test_sandbox_policy_manifest_requires_exact_process_control_contract() -> None:
    schema = load_manifest_resource("sandbox-policy.schema.json")
    protocol = load_manifest_resource("protocol-schemas-v1.json")
    assert "process_control" in schema["required"]
    process_control = schema["$defs"]["process_control"]
    assert process_control["additionalProperties"] is False
    assert set(process_control["required"]) == set(ProcessControlPolicy().to_dict())
    assert process_control["properties"]["authenticated_runner_identity"] == {
        "const": AUTHENTICATED_RUNNER_IDENTITY
    }
    for name in set(ProcessControlPolicy().to_dict()) - {"authenticated_runner_identity"}:
        assert process_control["properties"][name] == {"const": True}
    limits = schema["properties"]["limits"]
    assert "core_dump_bytes" in limits["required"]
    assert limits["properties"]["core_dump_bytes"] == {
        "type": "integer",
        "const": 0,
    }
    assert protocol["$defs"]["command_record"]["properties"]["runner_identity"] == {
        "const": AUTHENTICATED_RUNNER_IDENTITY
    }


def test_health_preflight_rechecks_native_process_controls(tmp_path: Path) -> None:
    policies = _policies(tmp_path)
    backend = verified_backend(
        name=SandboxBackendName.LINUX_BWRAP_SECCOMP,
        executable=tmp_path / "bwrap",
        verification_id="native-process-control-test",
        completed_checks=sorted(LINUX_REQUIRED_BACKEND_CHECKS),
    )
    bundle = SimpleNamespace(
        manifest=SimpleNamespace(
            platform="linux-x86_64",
            context_mode_version="1.0.169",
        )
    )
    healthy = check_offline_runtime_preflight(
        bundle=bundle,  # type: ignore[arg-type]
        backend=backend,
        policies=policies.values(),
    )
    assert healthy.passed
    assert "sandbox_process_controls_verified" in healthy.checks
    assert healthy.details["sandbox_backend_checks"] == list(backend.checks)

    incomplete_backend = SandboxBackend(
        SandboxBackendName.LINUX_BWRAP_SECCOMP,
        BackendStatus.VERIFIED,
        str(tmp_path / "bwrap"),
        verification_id="incomplete-native-process-control-test",
        checks=tuple(
            sorted(LINUX_REQUIRED_BACKEND_CHECKS - {"process_tree_kill_reap"})
        ),
    )
    incomplete = check_offline_runtime_preflight(
        bundle=bundle,  # type: ignore[arg-type]
        backend=incomplete_backend,
        policies=policies.values(),
    )
    assert not incomplete.passed
    assert any(
        issue.check == "sandbox_backend" and "process_tree_kill_reap" in issue.message
        for issue in incomplete.issues
    )

    object.__setattr__(
        policies[ProfileKind.MCP].process_control,
        "ptrace_denied",
        False,
    )
    unhealthy = check_offline_runtime_preflight(
        bundle=bundle,  # type: ignore[arg-type]
        backend=backend,
        policies=policies.values(),
    )
    assert not unhealthy.passed
    assert any("ptrace_denied" in issue.message for issue in unhealthy.issues)
