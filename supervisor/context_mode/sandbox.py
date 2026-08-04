"""Fail-closed sandbox policy models and external adapter boundary.

This package does **not** claim that Python path checks or environment cleanup
form an OS sandbox.  A native/platform adapter must apply namespaces + seccomp on
Linux or a supported Seatbelt policy on macOS, mediate exec through the
authenticated runner, enforce process/resource controls, and return independent
evidence.  Until that happens, launch authorization is unavailable.
"""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from ._util import ContextModeDataError, digest_json, require_int, require_nonempty, require_sha256


SANDBOX_POLICY_SCHEMA_VERSION = 1
AUTHENTICATED_RUNNER_IDENTITY = "bello-native-runner-v1"

# Native preflight evidence is an exact, versioned contract.  These semantic
# checks are shared by Linux and macOS even though the underlying mechanisms
# differ (seccomp/prctl/namespaces versus Seatbelt plus native process APIs).
PROCESS_CONTROL_BACKEND_CHECKS = frozenset(
    {
        "authenticated_direct_exec_runner",
        "ptrace_denied",
        "process_vm_readv_denied",
        "process_vm_writev_denied",
        "cross_tree_signals_denied",
        "non_dumpable",
        "core_dump_disabled",
        "rlimit_cpu_enforced",
        "rlimit_address_space_enforced",
        "rlimit_processes_enforced",
        "rlimit_open_files_enforced",
        "rlimit_file_size_enforced",
        "wall_time_process_tree_enforced",
        "process_tree_kill_reap",
    }
)
LINUX_REQUIRED_BACKEND_CHECKS = frozenset(
    {
        "network_namespace",
        "loopback_down",
        "mount_namespace",
        "pid_namespace",
        "seccomp_network_deny",
        "descendant_inheritance",
        "fd_isolation",
        "nested_readonly_mounts",
        "workspace_path_filter",
        "exact_bootstrap_file_mount",
    }
) | PROCESS_CONTROL_BACKEND_CHECKS
MACOS_REQUIRED_BACKEND_CHECKS = frozenset(
    {
        "seatbelt_network_deny",
        "seatbelt_path_allowlist",
        "descendant_inheritance",
        "fd_isolation",
        "supported_release",
        "nested_readonly_mounts",
        "workspace_path_filter",
        "exact_bootstrap_file_mount",
    }
) | PROCESS_CONTROL_BACKEND_CHECKS


class SandboxError(ContextModeDataError):
    """A sandbox policy is unsafe or no verified OS backend is available."""


class SandboxBackendName(str, Enum):
    LINUX_BWRAP_SECCOMP = "linux-bwrap-seccomp"
    MACOS_SEATBELT = "macos-seatbelt"


class BackendStatus(str, Enum):
    UNAVAILABLE = "unavailable"
    AVAILABLE_UNVERIFIED = "available_unverified"
    VERIFIED = "verified"


@dataclass(frozen=True)
class SandboxBackend:
    name: SandboxBackendName
    status: BackendStatus
    executable: str | None
    verification_id: str | None = None
    checks: tuple[str, ...] = ()
    issues: tuple[str, ...] = ()

    def assert_verified(self) -> None:
        if not isinstance(self.name, SandboxBackendName):
            raise SandboxError("sandbox backend name is not a recognized native backend")
        if not isinstance(self.status, BackendStatus):
            raise SandboxError("sandbox backend status is not recognized")
        if self.status is not BackendStatus.VERIFIED or not self.verification_id:
            raise SandboxError(
                f"Context Mode sandbox backend {self.name.value} is not verified: "
                f"status={self.status.value}, issues={self.issues!r}"
            )
        require_nonempty(self.verification_id, "verification_id")
        if (
            not isinstance(self.executable, str)
            or not os.path.isabs(self.executable)
            or os.path.normpath(self.executable) != self.executable
        ):
            raise SandboxError("verified sandbox executable must be a normalized absolute path")
        if any(not isinstance(check, str) or not check for check in self.checks):
            raise SandboxError("sandbox verification checks must be non-empty strings")
        if len(self.checks) != len(set(self.checks)):
            raise SandboxError("sandbox verification contains duplicate checks")
        required = _required_backend_checks(self.name)
        completed = frozenset(self.checks)
        missing = required - completed
        if missing:
            raise SandboxError(f"sandbox verification is missing checks: {sorted(missing)!r}")
        unexpected = completed - required
        if unexpected:
            raise SandboxError(
                f"sandbox verification contains unrecognized checks: {sorted(unexpected)!r}"
            )


def _required_backend_checks(name: SandboxBackendName) -> frozenset[str]:
    if name is SandboxBackendName.LINUX_BWRAP_SECCOMP:
        return LINUX_REQUIRED_BACKEND_CHECKS
    return MACOS_REQUIRED_BACKEND_CHECKS


def detect_sandbox_backend(
    *,
    system: str | None = None,
    which: Any = shutil.which,
) -> SandboxBackend:
    """Detect an executable, but deliberately return *unverified* status."""

    system_value = (system or platform.system()).lower()
    if system_value == "linux":
        executable = which("bwrap")
        if executable:
            return SandboxBackend(
                SandboxBackendName.LINUX_BWRAP_SECCOMP,
                BackendStatus.AVAILABLE_UNVERIFIED,
                executable,
                issues=("native namespace/seccomp self-test has not attested this process tree",),
            )
        return SandboxBackend(
            SandboxBackendName.LINUX_BWRAP_SECCOMP,
            BackendStatus.UNAVAILABLE,
            None,
            issues=("bubblewrap is unavailable",),
        )
    if system_value == "darwin":
        executable = "/usr/bin/sandbox-exec" if Path("/usr/bin/sandbox-exec").is_file() else None
        if executable:
            return SandboxBackend(
                SandboxBackendName.MACOS_SEATBELT,
                BackendStatus.AVAILABLE_UNVERIFIED,
                executable,
                issues=("Seatbelt release/path/network semantics have not been attested",),
            )
        return SandboxBackend(
            SandboxBackendName.MACOS_SEATBELT,
            BackendStatus.UNAVAILABLE,
            None,
            issues=("sandbox-exec is unavailable",),
        )
    raise SandboxError(f"Context Mode has no sandbox backend for {system_value!r}")


def verified_backend(
    *,
    name: SandboxBackendName | str,
    executable: Path | str,
    verification_id: str,
    completed_checks: Sequence[str],
) -> SandboxBackend:
    """Construct evidence supplied by a trusted native preflight adapter."""

    name = SandboxBackendName(name)
    executable_text = os.fspath(executable)
    if not os.path.isabs(executable_text):
        raise SandboxError("sandbox executable path must be absolute")
    require_nonempty(verification_id, "verification_id")
    backend = SandboxBackend(
        name,
        BackendStatus.VERIFIED,
        executable_text,
        verification_id=verification_id,
        checks=tuple(completed_checks),
    )
    backend.assert_verified()
    return backend


class ProfileKind(str, Enum):
    MCP = "mcp"
    HOOK = "hook"
    COMMAND = "command"
    PROXY = "proxy"


class MountAccess(str, Enum):
    READ_ONLY = "read_only"
    READ_WRITE = "read_write"
    READ_EXECUTE = "read_execute"


@dataclass(frozen=True)
class MountRule:
    source: str
    target: str
    access: MountAccess
    path_class: str

    def __post_init__(self) -> None:
        for field_name in ("source", "target"):
            value = getattr(self, field_name)
            if not os.path.isabs(value) or os.path.normpath(value) != value or value == os.path.sep:
                raise SandboxError(f"mount {field_name} must be a normalized, non-root absolute path")
        require_nonempty(self.path_class, "path_class")

    def to_dict(self) -> dict[str, str]:
        return {
            "source": self.source,
            "target": self.target,
            "access": self.access.value,
            "path_class": self.path_class,
        }


@dataclass(frozen=True)
class ResourceLimits:
    wall_time_seconds: int = 3600
    cpu_time_seconds: int = 1800
    address_space_bytes: int = 2 * 1024 * 1024 * 1024
    processes: int = 128
    open_files: int = 512
    single_file_bytes: int = 512 * 1024 * 1024
    total_write_bytes: int = 2 * 1024 * 1024 * 1024
    stdout_bytes: int = 8 * 1024 * 1024
    stderr_bytes: int = 8 * 1024 * 1024
    core_dump_bytes: int = 0

    def __post_init__(self) -> None:
        for name in self.__dataclass_fields__:
            minimum = 0 if name == "core_dump_bytes" else 1
            try:
                require_int(getattr(self, name), name, minimum=minimum)
            except ContextModeDataError as exc:
                raise SandboxError(str(exc)) from exc
        if self.core_dump_bytes != 0:
            raise SandboxError("sandbox core_dump_bytes must be zero")

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True)
class ProcessControlPolicy:
    """Digest-bound native process controls required for every profile.

    Numeric limits alone are only configuration.  These fields require the
    native adapter to actively mediate exec and enforce the limits/process tree
    before any untrusted profile code runs.  They are deliberately constants:
    there is no supported weakened Context Mode profile.
    """

    authenticated_runner_identity: str = AUTHENTICATED_RUNNER_IDENTITY
    direct_exec_mediated: bool = True
    ptrace_denied: bool = True
    process_vm_denied: bool = True
    cross_tree_signals_denied: bool = True
    non_dumpable: bool = True
    core_dumps_denied: bool = True
    rlimits_enforced: bool = True
    process_tree_enforced: bool = True

    def __post_init__(self) -> None:
        self.assert_enforced()

    def assert_enforced(self) -> None:
        if self.authenticated_runner_identity != AUTHENTICATED_RUNNER_IDENTITY:
            raise SandboxError(
                "sandbox process control must use the authenticated Bello native runner"
            )
        for field_name in (
            "direct_exec_mediated",
            "ptrace_denied",
            "process_vm_denied",
            "cross_tree_signals_denied",
            "non_dumpable",
            "core_dumps_denied",
            "rlimits_enforced",
            "process_tree_enforced",
        ):
            if getattr(self, field_name) is not True:
                raise SandboxError(
                    f"sandbox process control requires {field_name}=true"
                )

    def to_dict(self) -> dict[str, str | bool]:
        return {
            "authenticated_runner_identity": self.authenticated_runner_identity,
            "direct_exec_mediated": self.direct_exec_mediated,
            "ptrace_denied": self.ptrace_denied,
            "process_vm_denied": self.process_vm_denied,
            "cross_tree_signals_denied": self.cross_tree_signals_denied,
            "non_dumpable": self.non_dumpable,
            "core_dumps_denied": self.core_dumps_denied,
            "rlimits_enforced": self.rlimits_enforced,
            "process_tree_enforced": self.process_tree_enforced,
        }

    @property
    def digest(self) -> str:
        return digest_json(self.to_dict())


_REQUIRED_WORKSPACE_DENY_COMPONENTS = frozenset(
    {".bello", ".codex", ".context-mode", ".context_mode", ".supervisor"}
)
_REQUIRED_WORKSPACE_DENY_TOP_LEVEL = frozenset(
    {"context-mode", "context-mode-home", "context-mode-tmp", "runtime-metadata"}
)
_REQUIRED_WORKSPACE_DENY_GLOBS = frozenset(
    {
        ".env",
        ".env.*",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "*.key",
        "*.p12",
        "*.pem",
        "*.pfx",
        "credentials",
        "credentials.json",
        "id_ed25519*",
        "id_rsa*",
        "service-account*.json",
    }
)


@dataclass(frozen=True)
class WorkspacePathPolicy:
    """Native, digest-bound filtering contract for a writable workspace mount.

    Exact read-only paths are nested mounts applied after the filtered workspace
    root.  Deny names/globs are enforced continuously by the native backend, so
    creating a new ``.codex`` or secret-looking file after startup cannot make it
    visible to MCP/hooks/commands.
    """

    root: str
    read_only_paths: tuple[str, ...]
    masked_paths: tuple[str, ...]
    deny_component_names: tuple[str, ...]
    deny_top_level_names: tuple[str, ...]
    deny_filename_globs: tuple[str, ...]

    def __post_init__(self) -> None:
        root = _normalized_environment_path(self.root, "workspace filter root")
        read_only = _validate_workspace_filter_paths(root, self.read_only_paths, "read-only")
        masked = _validate_workspace_filter_paths(root, self.masked_paths, "masked")
        for left in read_only:
            for right in masked:
                if _paths_overlap(left, right):
                    raise SandboxError("workspace read-only and masked paths must not overlap")
        for label, values in (
            ("deny component", self.deny_component_names),
            ("deny top-level", self.deny_top_level_names),
            ("deny filename glob", self.deny_filename_globs),
        ):
            if len(set(values)) != len(values):
                raise SandboxError(f"duplicate workspace {label} rule")
            if any(not value or value in {".", ".."} or "/" in value or "\\" in value for value in values):
                raise SandboxError(f"workspace {label} rules must be single non-empty path components")
        if not _REQUIRED_WORKSPACE_DENY_COMPONENTS.issubset(self.deny_component_names):
            raise SandboxError("workspace filter omits reserved run-control component names")
        if not _REQUIRED_WORKSPACE_DENY_TOP_LEVEL.issubset(self.deny_top_level_names):
            raise SandboxError("workspace filter omits reserved top-level run-control names")
        if not _REQUIRED_WORKSPACE_DENY_GLOBS.issubset(self.deny_filename_globs):
            raise SandboxError("workspace filter omits mandatory secret filename patterns")

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "read_only_paths": list(self.read_only_paths),
            "masked_paths": list(self.masked_paths),
            "deny_component_names": list(self.deny_component_names),
            "deny_top_level_names": list(self.deny_top_level_names),
            "deny_filename_globs": list(self.deny_filename_globs),
        }


@dataclass(frozen=True)
class ProxyBootstrapPolicy:
    """Allow-list whose selected member is the proxy's sole bootstrap mount."""

    allowed_files: tuple[str, ...]
    exactly_one_per_launch: bool = True

    def __post_init__(self) -> None:
        if self.exactly_one_per_launch is not True:
            raise SandboxError("proxy bootstrap policy must mount exactly one file per launch")
        if not self.allowed_files or len(set(self.allowed_files)) != len(self.allowed_files):
            raise SandboxError("proxy bootstrap policy requires distinct allowed files")
        for path in self.allowed_files:
            _normalized_environment_path(path, "proxy bootstrap file")

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_files": list(self.allowed_files),
            "exactly_one_per_launch": self.exactly_one_per_launch,
        }


@dataclass(frozen=True)
class SandboxPolicy:
    profile: ProfileKind
    mounts: tuple[MountRule, ...]
    protected_roots: tuple[str, ...]
    environment: Mapping[str, str]
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    workspace_paths: WorkspacePathPolicy | None = None
    proxy_bootstrap: ProxyBootstrapPolicy | None = None
    process_control: ProcessControlPolicy = field(default_factory=ProcessControlPolicy)
    network_allowed: bool = False
    loopback_allowed: bool = False
    allow_host_unix_sockets: bool = False
    schema_version: int = SANDBOX_POLICY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        require_int(self.schema_version, "schema_version", minimum=1)
        if self.schema_version != SANDBOX_POLICY_SCHEMA_VERSION:
            raise SandboxError("unsupported sandbox policy schema")
        for field_name in (
            "network_allowed",
            "loopback_allowed",
            "allow_host_unix_sockets",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise SandboxError(f"{field_name} must be boolean")
        if self.network_allowed or self.loopback_allowed or self.allow_host_unix_sockets:
            raise SandboxError("Context Mode policy must deny external, loopback, and host socket access")
        if not isinstance(self.process_control, ProcessControlPolicy):
            raise SandboxError("sandbox policy requires a native process-control contract")
        self.process_control.assert_enforced()
        if not self.mounts:
            raise SandboxError("sandbox policy requires explicit mounts")
        targets: set[str] = set()
        for rule in self.mounts:
            if rule.target in targets:
                raise SandboxError(f"duplicate sandbox mount target: {rule.target}")
            targets.add(rule.target)
        normalized_protected: list[str] = []
        for root in self.protected_roots:
            if not os.path.isabs(root) or os.path.normpath(root) != root or root == os.path.sep:
                raise SandboxError("protected roots must be normalized, non-root absolute paths")
            normalized_protected.append(root)
        for rule in self.mounts:
            for protected in normalized_protected:
                if _paths_overlap(rule.source, protected) or _paths_overlap(rule.target, protected):
                    raise SandboxError(
                        "sandbox mount source/target "
                        f"{rule.source!r}/{rule.target!r} overlaps protected root {protected!r}"
                    )
        _validate_environment(self.environment)
        required_environment = (
            {"BELLO_OFFLINE"}
            if self.profile is ProfileKind.PROXY
            else {
                "HOME",
                "TMPDIR",
                "XDG_CONFIG_HOME",
                "XDG_CACHE_HOME",
                "PATH",
                "BELLO_OFFLINE",
                "BELLO_RUN_ID",
                "BELLO_WORKSPACE_ID",
                "BELLO_CONTEXT_SESSION_ID",
            }
        )
        missing_environment = required_environment - frozenset(self.environment)
        if missing_environment or self.environment.get("BELLO_OFFLINE") != "1":
            raise SandboxError(
                f"sandbox policy lacks the clean offline environment contract: {sorted(missing_environment)!r}"
            )
        if self.profile is ProfileKind.PROXY:
            if self.workspace_paths is not None:
                raise SandboxError("proxy must not receive a workspace path policy")
            if self.proxy_bootstrap is None:
                raise SandboxError("proxy requires an exact per-launch bootstrap file policy")
            allowed_proxy_environment = {"BELLO_OFFLINE", "LANG", "LC_ALL", "TZ"}
            unexpected = frozenset(self.environment) - allowed_proxy_environment
            if unexpected:
                raise SandboxError(
                    "proxy environment is not minimal: "
                    f"unexpected keys {sorted(unexpected)!r}"
                )
            classes = {rule.path_class for rule in self.mounts}
            if classes != {"launcher"} or len(self.mounts) != 1:
                raise SandboxError("proxy persistent mounts may contain only one launcher")
            launcher = self.mounts[0]
            if launcher.access is not MountAccess.READ_EXECUTE:
                raise SandboxError("proxy launcher mount must be read/execute")
        else:
            if self.proxy_bootstrap is not None:
                raise SandboxError(f"{self.profile.value} policy must not receive proxy bootstrap authority")
            if self.workspace_paths is None:
                raise SandboxError(f"{self.profile.value} policy requires a native workspace filter contract")
            workspace_mounts = [rule for rule in self.mounts if rule.path_class == "workspace"]
            if len(workspace_mounts) != 1:
                raise SandboxError(f"{self.profile.value} policy requires exactly one workspace root mount")
            workspace_mount = workspace_mounts[0]
            if (
                workspace_mount.source != self.workspace_paths.root
                or workspace_mount.target != self.workspace_paths.root
            ):
                raise SandboxError("workspace filter root must equal the filtered workspace mount")
            nested_read_only = {
                rule.target
                for rule in self.mounts
                if rule.path_class in {"workspace_git", "immutable_task", "readonly_dependency"}
                and rule.access is MountAccess.READ_ONLY
            }
            if nested_read_only != set(self.workspace_paths.read_only_paths):
                raise SandboxError("workspace filter read-only paths do not match exact nested mounts")
            _validate_environment_mounts(self)
        if self.profile is ProfileKind.HOOK:
            workspace_rules = [rule for rule in self.mounts if rule.path_class == "workspace"]
            if len(workspace_rules) != 1 or any(
                rule.access is not MountAccess.READ_ONLY for rule in workspace_rules
            ):
                raise SandboxError("hook workspace must be read-only")
        if self.profile is ProfileKind.COMMAND:
            if any(rule.path_class in {"context_state", "binding", "receipts"} for rule in self.mounts):
                raise SandboxError("command subtree must not mount Context Mode authority/state")
            if "CONTEXT_MODE_DIR" in self.environment:
                raise SandboxError("command subtree must not receive a Context Mode state path")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "profile": self.profile.value,
            "mounts": [rule.to_dict() for rule in self.mounts],
            "protected_roots": list(self.protected_roots),
            "environment": dict(sorted(self.environment.items())),
            "limits": self.limits.to_dict(),
            "workspace_paths": None if self.workspace_paths is None else self.workspace_paths.to_dict(),
            "proxy_bootstrap": None if self.proxy_bootstrap is None else self.proxy_bootstrap.to_dict(),
            "process_control": self.process_control.to_dict(),
            "network_allowed": self.network_allowed,
            "loopback_allowed": self.loopback_allowed,
            "allow_host_unix_sockets": self.allow_host_unix_sockets,
        }

    @property
    def digest(self) -> str:
        return digest_json(self.to_dict())


def _paths_overlap(left: str, right: str) -> bool:
    try:
        common = os.path.commonpath((left, right))
    except ValueError:
        return False
    return common in {left, right}


def _path_is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def _normalized_environment_path(value: str, field_name: str) -> str:
    if not os.path.isabs(value) or os.path.normpath(value) != value or value == os.path.sep:
        raise SandboxError(f"{field_name} must be a normalized, non-root absolute sandbox path")
    return value


def _validate_workspace_filter_paths(
    root: str,
    values: Sequence[str],
    label: str,
) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        value = _normalized_environment_path(value, f"workspace {label} path")
        if value == root or not _path_is_within(value, root):
            raise SandboxError(f"workspace {label} paths must be strict descendants of the workspace root")
        if value in normalized:
            raise SandboxError(f"duplicate workspace {label} path: {value}")
        normalized.append(value)
    return tuple(normalized)


def _validate_environment_mounts(policy: SandboxPolicy) -> None:
    """Prove that every generated runtime path is reachable through this profile.

    Environment cleanup without a matching mount is both non-functional and
    dangerously easy for a native adapter to "fix" by exposing a parent such as
    the run root.  Requiring exact policy coverage keeps that expansion
    impossible and makes the applied policy digest authoritative.
    """

    environment = policy.environment
    home = _normalized_environment_path(environment["HOME"], "HOME")
    temp = _normalized_environment_path(environment["TMPDIR"], "TMPDIR")
    xdg_config = _normalized_environment_path(environment["XDG_CONFIG_HOME"], "XDG_CONFIG_HOME")
    xdg_cache = _normalized_environment_path(environment["XDG_CACHE_HOME"], "XDG_CACHE_HOME")
    if xdg_config != os.path.join(home, ".config") or xdg_cache != os.path.join(home, ".cache"):
        raise SandboxError("XDG paths must be the generated profile HOME .config/.cache directories")
    if _paths_overlap(home, temp):
        raise SandboxError("profile HOME and TMPDIR must be separate mount roots")

    home_mounts = tuple(
        rule
        for rule in policy.mounts
        if rule.path_class == "profile_home" and rule.access is MountAccess.READ_WRITE
    )
    if len(home_mounts) != 1 or home_mounts[0].target != home:
        raise SandboxError(f"HOME is not covered by the sole profile_home mount in {policy.profile.value} policy")
    if not _path_is_within(xdg_config, home) or not _path_is_within(xdg_cache, home):
        raise SandboxError("XDG paths escape the dedicated profile_home mount")

    temp_class = {
        ProfileKind.MCP: "operation_temp",
        ProfileKind.HOOK: "hook_temp",
        ProfileKind.COMMAND: "operation_scratch",
    }[policy.profile]
    temp_mounts = tuple(
        rule
        for rule in policy.mounts
        if rule.path_class == temp_class and rule.access is MountAccess.READ_WRITE
    )
    if len(temp_mounts) != 1 or temp_mounts[0].target != temp:
        raise SandboxError(
            f"TMPDIR is not covered by the sole {temp_class} mount in {policy.profile.value} policy"
        )
    for key in _PROFILE_CACHE_VARIABLES:
        value = environment.get(key)
        if value is None:
            continue
        value = _normalized_environment_path(value, key)
        if not _path_is_within(value, home):
            raise SandboxError(f"{key} must be redirected beneath the dedicated profile HOME")

    path_value = environment["PATH"]
    if not path_value:
        raise SandboxError("sandbox PATH must name at least one mounted runtime/toolchain directory")
    executable_roots = tuple(
        rule
        for rule in policy.mounts
        if rule.access is MountAccess.READ_EXECUTE
        and rule.path_class in {"runtime", "worker_runtime", "toolchain"}
    )
    for component in path_value.split(os.pathsep):
        component = _normalized_environment_path(component, "PATH component")
        if not any(_path_is_within(component, rule.target) for rule in executable_roots):
            raise SandboxError(
                f"PATH component {component!r} is not covered by a read/execute runtime/toolchain mount"
            )

    context_mode_dir = environment.get("CONTEXT_MODE_DIR")
    if context_mode_dir is not None:
        context_mode_dir = _normalized_environment_path(context_mode_dir, "CONTEXT_MODE_DIR")
        state_mounts = tuple(
            rule
            for rule in policy.mounts
            if rule.path_class == "context_state" and rule.access is MountAccess.READ_WRITE
        )
        if len(state_mounts) != 1 or not _path_is_within(context_mode_dir, state_mounts[0].target):
            raise SandboxError("CONTEXT_MODE_DIR must be covered by the sole read/write state mount")
        if _paths_overlap(context_mode_dir, home) or _paths_overlap(context_mode_dir, temp):
            raise SandboxError("profile HOME/TMPDIR must be disjoint from Context Mode state")


_FORBIDDEN_ENV_EXACT = frozenset(
    {
        "SSH_AUTH_SOCK",
        "GIT_ASKPASS",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "NPM_CONFIG_USERCONFIG",
        "PIP_CONFIG_FILE",
        "NODE_OPTIONS",
        "PYTHONSTARTUP",
        "PYTHONPATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    }
)
_FORBIDDEN_ENV_FRAGMENTS = ("TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "API_KEY", "AUTH_")
_BASE_ENV_KEYS = frozenset(
    {
        "HOME",
        "TMPDIR",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "PATH",
        "LANG",
        "LC_ALL",
        "TZ",
        "CONTEXT_MODE_PLATFORM",
        "CONTEXT_MODE_DIR",
        "BELLO_OFFLINE",
        "BELLO_RUN_ID",
        "BELLO_WORKSPACE_ID",
        "BELLO_CONTEXT_SESSION_ID",
    }
)
_SAFE_BUILD_VARIABLES = frozenset(
    {
        "CC",
        "CXX",
        "AR",
        "RANLIB",
        "CFLAGS",
        "CXXFLAGS",
        "CPPFLAGS",
        "LDFLAGS",
        "MAKEFLAGS",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "GOMODCACHE",
        "GOCACHE",
        "npm_config_cache",
        "PIP_CACHE_DIR",
    }
)
_PROFILE_CACHE_VARIABLES = {
    "CARGO_HOME": (".cache", "cargo"),
    "RUSTUP_HOME": (".cache", "rustup"),
    "GOMODCACHE": (".cache", "go-mod"),
    "GOCACHE": (".cache", "go-build"),
    "npm_config_cache": (".cache", "npm"),
    "PIP_CACHE_DIR": (".cache", "pip"),
}


def _validate_environment(environment: Mapping[str, str]) -> None:
    for key, value in environment.items():
        if not isinstance(key, str) or not isinstance(value, str) or not key or "\x00" in key + value:
            raise SandboxError("sandbox environment keys/values must be NUL-free strings")
        upper = key.upper()
        if upper in _FORBIDDEN_ENV_EXACT or any(fragment in upper for fragment in _FORBIDDEN_ENV_FRAGMENTS):
            raise SandboxError(f"forbidden credential/proxy/loader environment key: {key}")


def build_clean_environment(
    *,
    home: Path,
    temp: Path,
    context_mode_dir: Path,
    toolchain_bins: Sequence[Path],
    platform_tag: str,
    run_id: str,
    workspace_id: str,
    context_session_id: str,
    build_variables: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build an allow-listed environment without consulting ``os.environ``."""

    paths = {
        "HOME": home,
        "TMPDIR": temp,
        "XDG_CONFIG_HOME": home / ".config",
        "XDG_CACHE_HOME": home / ".cache",
        "CONTEXT_MODE_DIR": context_mode_dir,
    }
    for name, path in paths.items():
        if not Path(path).is_absolute():
            raise SandboxError(f"{name} must be an absolute run-local path")
    bin_strings: list[str] = []
    for path in toolchain_bins:
        path_string = os.fspath(path)
        if not os.path.isabs(path_string) or os.path.normpath(path_string) != path_string:
            raise SandboxError("toolchain PATH components must be normalized absolute paths")
        bin_strings.append(path_string)
    environment = {
        "HOME": os.fspath(home),
        "TMPDIR": os.fspath(temp),
        "XDG_CONFIG_HOME": os.fspath(home / ".config"),
        "XDG_CACHE_HOME": os.fspath(home / ".cache"),
        "PATH": os.pathsep.join(bin_strings),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "CONTEXT_MODE_PLATFORM": require_nonempty(platform_tag, "platform_tag"),
        "CONTEXT_MODE_DIR": os.fspath(context_mode_dir),
        "BELLO_OFFLINE": "1",
        "BELLO_RUN_ID": require_nonempty(run_id, "run_id"),
        "BELLO_WORKSPACE_ID": require_nonempty(workspace_id, "workspace_id"),
        "BELLO_CONTEXT_SESSION_ID": require_nonempty(context_session_id, "context_session_id"),
    }
    for key, value in (build_variables or {}).items():
        if key not in _SAFE_BUILD_VARIABLES:
            raise SandboxError(f"build environment key is not allow-listed: {key}")
        environment[key] = value
    _validate_environment(environment)
    unknown = frozenset(environment) - _BASE_ENV_KEYS - _SAFE_BUILD_VARIABLES
    if unknown:  # defensive invariant if the constructor changes.
        raise SandboxError(f"unexpected generated environment keys: {sorted(unknown)!r}")
    return environment


@dataclass(frozen=True)
class SandboxPathLayout:
    """Explicit run-local paths used to derive four immutable mount profiles.

    ``bootstrap`` is the controller-owned public bootstrap directory used only
    to build an exact-file allow-list.  The directory itself is never mounted:
    the native adapter must bind exactly one selected member into each proxy.
    """

    workspace: Path
    runtime: Path
    state: Path
    mcp_home: Path
    mcp_temp: Path
    hook_home: Path
    hook_temp: Path
    command_home: Path
    command_scratch: Path
    launcher: Path
    bootstrap: Path
    proxy_bootstrap_files: tuple[Path, ...] = ()
    workspace_git: Path | None = None
    immutable_workspace_paths: tuple[Path, ...] = ()
    readonly_dependency_roots: tuple[Path, ...] = ()
    workspace_masked_paths: tuple[Path, ...] = ()
    toolchain_roots: tuple[Path, ...] = ()
    bounded_hook_input: Path | None = None
    protected_roots: tuple[Path, ...] = ()


def generate_sandbox_policies(
    layout: SandboxPathLayout,
    *,
    environment: Mapping[str, str],
    limits: ResourceLimits | None = None,
) -> Mapping[ProfileKind, SandboxPolicy]:
    """Generate distinct least-authority MCP/hook/command/proxy policies.

    Component/symlink/device resolution remains the native adapter's job.  The
    generated matrix prevents argument-driven mount expansion in controller code.
    """

    limits = limits or ResourceLimits()
    base_protected = tuple(os.fspath(path) for path in layout.protected_roots)

    def mount(path: Path, access: MountAccess, path_class: str) -> MountRule:
        value = os.fspath(path)
        return MountRule(value, value, access, path_class)

    def profile_environment(
        *,
        home: Path,
        temp: Path,
        include_context_state: bool,
        path_roots: tuple[Path, ...] | None = None,
    ) -> dict[str, str]:
        generated = dict(environment)
        generated.update(
            {
                "HOME": os.fspath(home),
                "TMPDIR": os.fspath(temp),
                "XDG_CONFIG_HOME": os.fspath(home / ".config"),
                "XDG_CACHE_HOME": os.fspath(home / ".cache"),
            }
        )
        for key, parts in _PROFILE_CACHE_VARIABLES.items():
            if key in generated:
                generated[key] = os.fspath(home.joinpath(*parts))
        if include_context_state:
            generated["CONTEXT_MODE_DIR"] = os.fspath(layout.state)
        else:
            generated.pop("CONTEXT_MODE_DIR", None)
        if path_roots is not None:
            generated["PATH"] = os.pathsep.join(
                component
                for component in generated.get("PATH", "").split(os.pathsep)
                if component
                and any(
                    _path_is_within(component, os.fspath(root))
                    for root in path_roots
                )
            )
        return generated

    def protected_with(*paths: Path) -> tuple[str, ...]:
        values: list[str] = []
        for value in (*base_protected, *(os.fspath(path) for path in paths)):
            if value not in values:
                values.append(value)
        return tuple(values)

    workspace_git = layout.workspace_git or layout.workspace / ".git"
    read_only_mounts = (
        mount(workspace_git, MountAccess.READ_ONLY, "workspace_git"),
        *(
            mount(path, MountAccess.READ_ONLY, "immutable_task")
            for path in layout.immutable_workspace_paths
        ),
        *(
            mount(path, MountAccess.READ_ONLY, "readonly_dependency")
            for path in layout.readonly_dependency_roots
        ),
    )
    read_only_paths = tuple(rule.target for rule in read_only_mounts)
    masked_paths = tuple(
        dict.fromkeys(
            (
                *(os.fspath(path) for path in layout.workspace_masked_paths),
                *(
                    os.fspath(layout.workspace / name)
                    for name in sorted(_REQUIRED_WORKSPACE_DENY_TOP_LEVEL)
                ),
            )
        )
    )
    workspace_paths = WorkspacePathPolicy(
        root=os.fspath(layout.workspace),
        read_only_paths=read_only_paths,
        masked_paths=masked_paths,
        deny_component_names=tuple(sorted(_REQUIRED_WORKSPACE_DENY_COMPONENTS)),
        deny_top_level_names=tuple(sorted(_REQUIRED_WORKSPACE_DENY_TOP_LEVEL)),
        deny_filename_globs=tuple(sorted(_REQUIRED_WORKSPACE_DENY_GLOBS)),
    )

    toolchains = tuple(mount(path, MountAccess.READ_EXECUTE, "toolchain") for path in layout.toolchain_roots)
    mcp_mounts = (
        mount(layout.workspace, MountAccess.READ_WRITE, "workspace"),
        mount(layout.runtime, MountAccess.READ_EXECUTE, "runtime"),
        mount(layout.state, MountAccess.READ_WRITE, "context_state"),
        mount(layout.mcp_home, MountAccess.READ_WRITE, "profile_home"),
        mount(layout.mcp_temp, MountAccess.READ_WRITE, "operation_temp"),
        *read_only_mounts,
        *toolchains,
    )
    hook_mounts = [
        mount(layout.workspace, MountAccess.READ_ONLY, "workspace"),
        mount(layout.runtime, MountAccess.READ_EXECUTE, "runtime"),
        mount(layout.state, MountAccess.READ_WRITE, "context_state"),
        mount(layout.hook_home, MountAccess.READ_WRITE, "profile_home"),
        mount(layout.hook_temp, MountAccess.READ_WRITE, "hook_temp"),
        *read_only_mounts,
    ]
    if layout.bounded_hook_input is not None:
        hook_mounts.append(mount(layout.bounded_hook_input, MountAccess.READ_ONLY, "bounded_hook_input"))
    command_mounts = (
        mount(layout.workspace, MountAccess.READ_WRITE, "workspace"),
        mount(layout.runtime, MountAccess.READ_EXECUTE, "worker_runtime"),
        mount(layout.command_home, MountAccess.READ_WRITE, "profile_home"),
        mount(layout.command_scratch, MountAccess.READ_WRITE, "operation_scratch"),
        *read_only_mounts,
        *toolchains,
    )
    proxy_mounts = (mount(layout.launcher, MountAccess.READ_EXECUTE, "launcher"),)
    proxy_bootstrap = ProxyBootstrapPolicy(
        allowed_files=tuple(os.fspath(path) for path in layout.proxy_bootstrap_files)
    )
    return {
        ProfileKind.MCP: SandboxPolicy(
            ProfileKind.MCP,
            tuple(mcp_mounts),
            protected_with(
                layout.hook_home,
                layout.hook_temp,
                layout.command_home,
                layout.command_scratch,
                layout.bootstrap,
            ),
            profile_environment(home=layout.mcp_home, temp=layout.mcp_temp, include_context_state=True),
            limits,
            workspace_paths=workspace_paths,
        ),
        ProfileKind.HOOK: SandboxPolicy(
            ProfileKind.HOOK,
            tuple(hook_mounts),
            protected_with(
                layout.mcp_home,
                layout.mcp_temp,
                layout.command_home,
                layout.command_scratch,
                layout.bootstrap,
            ),
            profile_environment(
                home=layout.hook_home,
                temp=layout.hook_temp,
                include_context_state=True,
                path_roots=(layout.runtime,),
            ),
            limits,
            workspace_paths=workspace_paths,
        ),
        ProfileKind.COMMAND: SandboxPolicy(
            ProfileKind.COMMAND,
            tuple(command_mounts),
            protected_with(
                layout.state,
                layout.mcp_home,
                layout.mcp_temp,
                layout.hook_home,
                layout.hook_temp,
                layout.bootstrap,
            ),
            profile_environment(
                home=layout.command_home,
                temp=layout.command_scratch,
                include_context_state=False,
            ),
            limits,
            workspace_paths=workspace_paths,
        ),
        ProfileKind.PROXY: SandboxPolicy(
            ProfileKind.PROXY,
            tuple(proxy_mounts),
            protected_with(
                layout.workspace,
                layout.state,
                layout.mcp_home,
                layout.mcp_temp,
                layout.hook_home,
                layout.hook_temp,
                layout.command_home,
                layout.command_scratch,
            ),
            {
                key: environment[key]
                for key in ("BELLO_OFFLINE", "LANG", "LC_ALL", "TZ")
                if key in environment
            },
            limits,
            proxy_bootstrap=proxy_bootstrap,
        ),
    }


@dataclass(frozen=True)
class SandboxLaunchAuthorization:
    backend: SandboxBackendName
    backend_verification_id: str
    profile: ProfileKind
    policy_digest: str
    authenticated_runner_identity: str
    process_control_digest: str


def authorize_sandbox_launch(
    policy: SandboxPolicy,
    backend: SandboxBackend,
) -> SandboxLaunchAuthorization:
    backend.assert_verified()
    policy.process_control.assert_enforced()
    assert backend.verification_id is not None
    return SandboxLaunchAuthorization(
        backend=backend.name,
        backend_verification_id=backend.verification_id,
        profile=policy.profile,
        policy_digest=policy.digest,
        authenticated_runner_identity=policy.process_control.authenticated_runner_identity,
        process_control_digest=policy.process_control.digest,
    )


class NativeSandboxAdapter(Protocol):
    """Boundary implemented by Bello's platform-specific privileged broker."""

    def preflight(self) -> SandboxBackend:
        """Run active network/path/descendant tests and return verified evidence."""

    def spawn(self, authorization: SandboxLaunchAuthorization, argv: Sequence[str]) -> Any:
        """Dispatch through the authenticated runner and own/enforce the process tree.

        The adapter must apply the digest-bound policy and active resource
        limits before the runner executes ``argv``.  Direct exec from profile
        code, ptrace/process_vm access, and signals outside the owned tree stay
        denied for the complete descendant lifetime.
        """


class UnimplementedSandboxAdapter:
    """Explicit fail-closed default used by the pure-Python foundation."""

    def preflight(self) -> SandboxBackend:
        return detect_sandbox_backend()

    def spawn(self, authorization: SandboxLaunchAuthorization, argv: Sequence[str]) -> Any:
        raise SandboxError("no native sandbox adapter is installed; Context Mode launch is refused")


require_verified_backend = SandboxBackend.assert_verified
