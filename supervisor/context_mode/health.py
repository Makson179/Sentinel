"""Fail-closed startup health checks for generated config and runtime policy."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from ._util import ContextModeDataError, load_json_object, require_sha256
from .config import (
    CONTEXT_SERVER_NAME,
    FORBIDDEN_TOOL_NAMES,
    REQUIRED_HOOK_SET,
    Role,
    validate_exact_hook_catalogue,
    validate_exact_tool_catalogue,
)
from .routing import CONTEXT_MODE_ROUTING_TEXT
from .packaging import VerifiedRuntimeBundle
from .sandbox import ProfileKind, SandboxBackend, SandboxPolicy


class HealthCheckError(ContextModeDataError):
    """A required startup invariant is not proven."""


@dataclass(frozen=True)
class HealthIssue:
    check: str
    message: str


@dataclass(frozen=True)
class HealthReport:
    passed: bool
    checks: tuple[str, ...] = ()
    issues: tuple[HealthIssue, ...] = ()
    details: Mapping[str, Any] = field(default_factory=dict)

    def require_passed(self) -> "HealthReport":
        if not self.passed:
            summary = "; ".join(f"{issue.check}: {issue.message}" for issue in self.issues)
            raise HealthCheckError(summary or "Context Mode health preflight failed")
        return self


def check_effective_catalogues(
    *,
    role: Role | str,
    mcp_servers: Mapping[str, Iterable[str | Mapping[str, Any]]],
    hooks: Iterable[str],
    plugins: Iterable[str] = (),
    skills: Iterable[str] = (),
    expected_tool_schema_digests: Mapping[str, str] | None = None,
) -> HealthReport:
    role = Role(role)
    checks: list[str] = []
    issues: list[HealthIssue] = []
    servers = dict(mcp_servers)
    hook_names = tuple(hooks)
    plugin_names = tuple(plugins)
    skill_names = tuple(skills)
    if role is Role.SUPERVISOR:
        if servers:
            issues.append(HealthIssue("supervisor_mcp", "supervisor effective MCP catalogue is not empty"))
        else:
            checks.append("supervisor_mcp_empty")
        if hook_names:
            issues.append(HealthIssue("supervisor_hooks", "supervisor effective hook catalogue is not empty"))
        else:
            checks.append("supervisor_hooks_empty")
        if plugin_names or skill_names:
            issues.append(HealthIssue("supervisor_extensions", "supervisor has unmanifested plugins/skills"))
        else:
            checks.append("supervisor_extensions_empty")
    else:
        if frozenset(servers) != {CONTEXT_SERVER_NAME}:
            issues.append(
                HealthIssue(
                    "coder_mcp_servers",
                    f"coder requires only {CONTEXT_SERVER_NAME!r}, got {sorted(servers)!r}",
                )
            )
        else:
            try:
                validate_exact_tool_catalogue(
                    servers[CONTEXT_SERVER_NAME],
                    expected_schema_digests=expected_tool_schema_digests,
                )
                checks.append("coder_exact_tool_catalogue")
            except ContextModeDataError as exc:
                issues.append(HealthIssue("coder_tool_catalogue", str(exc)))
        try:
            validate_exact_hook_catalogue(hook_names)
            checks.append("coder_exact_hook_catalogue")
        except ContextModeDataError as exc:
            issues.append(HealthIssue("coder_hook_catalogue", str(exc)))
        if plugin_names or skill_names:
            issues.append(
                HealthIssue(
                    "coder_extensions",
                    "coder Context Mode uses sticky routing and permits no discoverable plugins/skills",
                )
            )
        else:
            checks.append("coder_extensions_empty")
    return HealthReport(not issues, tuple(checks), tuple(issues), {"role": role.value})


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def check_generated_role_home(
    root: Path,
    *,
    expected_role: Role | str,
    expected_context_mode_enabled: bool | None = None,
) -> HealthReport:
    """Verify the generated-home manifest, modes, and role separation."""

    expected_role = Role(expected_role)
    if expected_context_mode_enabled is None:
        expected_context_mode_enabled = expected_role is Role.CODER
    root = Path(root)
    issues: list[HealthIssue] = []
    checks: list[str] = []
    try:
        root_info = root.lstat()
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            raise HealthCheckError("generated home is not a real directory")
        if stat.S_IMODE(root_info.st_mode) & 0o077:
            raise HealthCheckError("generated home is accessible to group/other")
        manifest = load_json_object(root / "bello-generated-home.json", max_bytes=256 * 1024)
        if frozenset(manifest) != {"schema_version", "role", "context_mode_enabled", "files"}:
            raise HealthCheckError("generated home manifest fields mismatch")
        if (
            isinstance(manifest["schema_version"], bool)
            or not isinstance(manifest["schema_version"], int)
            or manifest["schema_version"] != 1
            or manifest["role"] != expected_role.value
        ):
            raise HealthCheckError("generated home manifest role/schema mismatch")
        if (
            not isinstance(manifest["context_mode_enabled"], bool)
            or manifest["context_mode_enabled"] is not expected_context_mode_enabled
        ):
            raise HealthCheckError("generated home manifest Context Mode setting mismatch")
        files = manifest["files"]
        if not isinstance(files, Mapping):
            raise HealthCheckError("generated home manifest files must be an object")
        for relative, expected_digest in files.items():
            if not isinstance(relative, str):
                raise HealthCheckError("generated home manifest file name must be a string")
            relative_path = Path(relative)
            if relative_path.is_absolute() or any(part in {"", ".", ".."} for part in relative_path.parts):
                raise HealthCheckError("generated home manifest contains an unsafe relative path")
            if not isinstance(expected_digest, str):
                raise HealthCheckError("generated home manifest digest must be a string")
            require_sha256(expected_digest, f"generated file {relative}")
            path = root / relative_path
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise HealthCheckError(f"generated home entry is not a regular file: {relative}")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise HealthCheckError(f"generated home entry is accessible to group/other: {relative}")
            if _file_sha256(path) != expected_digest:
                raise HealthCheckError(f"generated home entry hash mismatch: {relative}")
        config_text = (root / "config.toml").read_text(encoding="utf-8")
        if expected_role is Role.SUPERVISOR or not expected_context_mode_enabled:
            forbidden = (CONTEXT_SERVER_NAME, "ctx_", "context-mode-routing", "hooks.json")
            if any(fragment in config_text for fragment in forbidden):
                raise HealthCheckError(f"{expected_role.value} generated config contains Context Mode material")
            if any(name in files for name in ("hooks.json", "context-mode-routing.md")):
                raise HealthCheckError(f"{expected_role.value} generated home contains Context Mode files")
        else:
            if CONTEXT_SERVER_NAME not in config_text:
                raise HealthCheckError("coder generated config lacks Context Mode server")
            required = {
                "hooks.json",
                "context-mode-routing.md",
            }
            if not required.issubset(files):
                raise HealthCheckError("coder generated home lacks mandatory hooks/routing")
            if (root / "context-mode-routing.md").read_text(encoding="utf-8") != CONTEXT_MODE_ROUTING_TEXT:
                raise HealthCheckError("coder generated home routing differs from Bello's canonical policy")
            if not all(forbidden in config_text for forbidden in FORBIDDEN_TOOL_NAMES):
                raise HealthCheckError("coder config lacks explicit forbidden-tool defense")
        expected_paths = set(files) | {"bello-generated-home.json"}
        actual_paths = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file()
        }
        if actual_paths != expected_paths:
            raise HealthCheckError(
                f"generated home contains missing/unmanifested files: expected={sorted(expected_paths)!r}, "
                f"actual={sorted(actual_paths)!r}"
            )
        for directory in (path for path in root.rglob("*") if path.is_dir()):
            info = directory.lstat()
            if stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
                raise HealthCheckError(f"generated home directory is unsafe: {directory.relative_to(root)}")
        checks.extend(("generated_home_manifest", "generated_home_permissions", "generated_home_hashes"))
    except (OSError, UnicodeError, ContextModeDataError) as exc:
        issues.append(HealthIssue("generated_role_home", str(exc)))
    return HealthReport(not issues, tuple(checks), tuple(issues), {"role": expected_role.value})


def check_offline_runtime_preflight(
    *,
    bundle: VerifiedRuntimeBundle,
    backend: SandboxBackend,
    policies: Iterable[SandboxPolicy],
) -> HealthReport:
    issues: list[HealthIssue] = []
    checks: list[str] = ["bundle_hashes_verified"]
    policy_list = tuple(policies)
    try:
        backend.assert_verified()
        checks.append("sandbox_backend_verified")
    except ContextModeDataError as exc:
        issues.append(HealthIssue("sandbox_backend", str(exc)))
    if not policy_list:
        issues.append(HealthIssue("sandbox_policy", "no sandbox policies were supplied"))
    else:
        profile_counts = {profile: 0 for profile in ProfileKind}
        digests: set[str] = set()
        for policy in policy_list:
            try:
                profile_counts[policy.profile] += 1
                if policy.network_allowed or policy.loopback_allowed:
                    raise HealthCheckError("sandbox policy permits network or loopback")
                policy.process_control.assert_enforced()
                if policy.digest in digests:
                    raise HealthCheckError("MCP/hook/command policies must have distinct digests")
                digests.add(policy.digest)
            except ContextModeDataError as exc:
                issues.append(HealthIssue("sandbox_policy", str(exc)))
        invalid_profiles = [
            profile.value for profile, count in profile_counts.items() if count != 1
        ]
        if invalid_profiles:
            issues.append(
                HealthIssue(
                    "sandbox_profiles",
                    f"startup requires exactly one MCP/hook/command/proxy policy: {invalid_profiles!r}",
                )
            )
        if not issues:
            checks.extend(
                ("offline_policy_digests", "sandbox_process_controls_verified")
            )
    return HealthReport(
        not issues,
        tuple(checks),
        tuple(issues),
        {
            "platform": bundle.manifest.platform,
            "context_mode_version": bundle.manifest.context_mode_version,
            "sandbox_backend": backend.name.value,
            "sandbox_backend_checks": list(backend.checks),
            "policy_digests": [policy.digest for policy in policy_list],
            "process_control_digests": [
                policy.process_control.digest for policy in policy_list
            ],
        },
    )


def check_doctor_result(
    result: Mapping[str, Any],
    *,
    expected_policy_digest: str,
    expected_backend: str,
) -> HealthReport:
    """Cross-check Bello's bounded offline doctor output.

    Doctor output is a health signal, never the proof that an OS sandbox was
    applied; ``check_offline_runtime_preflight`` still requires backend evidence.
    """

    issues: list[HealthIssue] = []
    expected_keys = {
        "schema_version",
        "offline",
        "network_allowed",
        "sandbox_backend",
        "sandbox_policy_digest",
        "database",
        "fts5",
    }
    if frozenset(result) != expected_keys:
        issues.append(HealthIssue("doctor_schema", "ctx_doctor fields mismatch"))
    else:
        if (
            isinstance(result["schema_version"], bool)
            or not isinstance(result["schema_version"], int)
            or result["schema_version"] != 1
        ):
            issues.append(HealthIssue("doctor_schema", "unsupported ctx_doctor schema"))
        if result["offline"] is not True or result["network_allowed"] is not False:
            issues.append(HealthIssue("doctor_offline", "ctx_doctor does not report strict offline mode"))
        if result["sandbox_backend"] != expected_backend:
            issues.append(HealthIssue("doctor_backend", "ctx_doctor backend mismatch"))
        if result["sandbox_policy_digest"] != expected_policy_digest:
            issues.append(HealthIssue("doctor_policy", "ctx_doctor policy digest mismatch"))
        if result["database"] != "ok" or result["fts5"] is not True:
            issues.append(HealthIssue("doctor_database", "ctx_doctor database/FTS5 health failed"))
    return HealthReport(not issues, ("ctx_doctor" if not issues else "",), tuple(issues))


catalogue_preflight = check_effective_catalogues
