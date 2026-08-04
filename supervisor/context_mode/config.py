"""Generated, coder-only Context Mode configuration.

No function in this module reads a user's Codex configuration.  Inputs are
explicit and output is generated from scratch into a run-owned directory.
"""

from __future__ import annotations

import os
import math
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping

from ._util import (
    ContextModeDataError,
    atomic_write_bytes,
    atomic_write_json,
    canonical_json_bytes,
    ensure_private_directory,
    sha256_bytes,
)


CONTEXT_SERVER_NAME = "bello_context_mode"
CONTEXT_SKILL_NAME = "bello-context-mode"
CONTEXT_MODE_SCHEMA_VERSION = 1
PINNED_CODEX_CLI_VERSION = "codex-cli 0.146.0"
PINNED_CODEX_APP_SERVER_SCHEMA_SHA256 = (
    "8b4f3070be27707f5f621196fff0bad967f9b47093737fe1699c859a69d52289"
)
PINNED_APPROVAL_CORRELATION_FIELDS: tuple[str, ...] = (
    "role",
    "process_epoch",
    "request_id",
    "thread_id",
    "turn_id",
    "item_id",
    "server",
    "tool",
    "arguments",
    "cwd",
    "binding_version",
    "generation_lease_id",
)

# Tuple order is release metadata.  Catalogue validation compares sets *and*
# cardinality, so duplicates and aliases are never accepted.
ALLOWED_TOOLS: tuple[str, ...] = (
    "ctx_execute",
    "ctx_execute_file",
    "ctx_batch_execute",
    "ctx_index",
    "ctx_search",
    "ctx_stats",
    "ctx_doctor",
    "ctx_purge",
)
ALLOWED_TOOL_SET = frozenset(ALLOWED_TOOLS)
FORBIDDEN_TOOL_NAMES = frozenset(
    {
        "ctx_fetch_and_index",
        "ctx_upgrade",
        "ctx_insight",
    }
)
EXECUTION_TOOLS = frozenset({"ctx_execute", "ctx_execute_file", "ctx_batch_execute"})
CAPABILITY_REQUIRED_TOOLS = EXECUTION_TOOLS | {"ctx_purge"}
AUTO_APPROVABLE_TOOLS = ALLOWED_TOOL_SET - CAPABILITY_REQUIRED_TOOLS

REQUIRED_HOOKS: tuple[str, ...] = (
    "PreToolUse",
    "PostToolUse",
    "SessionStart",
    "PreCompact",
    "UserPromptSubmit",
    "Stop",
)
REQUIRED_HOOK_SET = frozenset(REQUIRED_HOOKS)


class ConfigError(ContextModeDataError):
    """Generated config or effective catalogue violates the pinned contract."""


class Role(str, Enum):
    CODER = "coder"
    SUPERVISOR = "supervisor"


def _catalogue_names(entries: Iterable[str | Mapping[str, Any]]) -> tuple[str, ...]:
    names: list[str] = []
    for entry in entries:
        if isinstance(entry, str):
            name = entry
        elif isinstance(entry, Mapping) and isinstance(entry.get("name"), str):
            name = entry["name"]
        else:
            raise ConfigError("tool catalogue entries must be names or objects with a string name")
        if not name:
            raise ConfigError("tool name must not be empty")
        names.append(name)
    return tuple(names)


def validate_exact_tool_catalogue(
    entries: Iterable[str | Mapping[str, Any]],
    *,
    expected_schema_digests: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """Require exactly the eight pinned tools, with no duplicate names."""

    materialized = tuple(entries)
    names = _catalogue_names(materialized)
    if len(names) != len(set(names)):
        raise ConfigError("Context Mode tool catalogue contains duplicate names")
    actual = frozenset(names)
    if actual & FORBIDDEN_TOOL_NAMES:
        raise ConfigError(f"forbidden Context Mode tools are registered: {sorted(actual & FORBIDDEN_TOOL_NAMES)!r}")
    missing = ALLOWED_TOOL_SET - actual
    extra = actual - ALLOWED_TOOL_SET
    if missing or extra or len(names) != len(ALLOWED_TOOLS):
        raise ConfigError(
            f"Context Mode tool catalogue mismatch (missing={sorted(missing)!r}, extra={sorted(extra)!r})"
        )
    if expected_schema_digests is not None:
        if frozenset(expected_schema_digests) != ALLOWED_TOOL_SET:
            raise ConfigError("expected schema digest table must cover exactly the pinned tools")
        for entry in materialized:
            if not isinstance(entry, Mapping):
                raise ConfigError("schema validation requires object catalogue entries")
            name = entry.get("name")
            schema = entry.get("inputSchema")
            if not isinstance(name, str) or not isinstance(schema, Mapping):
                raise ConfigError(f"tool {name!r} has no inputSchema object")
            actual_digest = sha256_bytes(canonical_json_bytes(schema))
            if actual_digest != expected_schema_digests[name]:
                raise ConfigError(f"schema digest mismatch for {name}")
    return names


# American spelling is a convenience alias; the strict implementation remains
# a single function.
validate_exact_tool_catalog = validate_exact_tool_catalogue


def validate_exact_hook_catalogue(entries: Iterable[str]) -> tuple[str, ...]:
    names = tuple(entries)
    if len(names) != len(set(names)):
        raise ConfigError("hook catalogue contains duplicate event names")
    missing = REQUIRED_HOOK_SET - frozenset(names)
    extra = frozenset(names) - REQUIRED_HOOK_SET
    if missing or extra or len(names) != len(REQUIRED_HOOKS):
        raise ConfigError(f"hook catalogue mismatch (missing={sorted(missing)!r}, extra={sorted(extra)!r})")
    return names


validate_exact_hook_catalog = validate_exact_hook_catalogue


def assert_tool_name(name: str) -> str:
    if name not in ALLOWED_TOOL_SET:
        if name in FORBIDDEN_TOOL_NAMES:
            raise ConfigError(f"tool {name!r} is forbidden by the offline fork")
        raise ConfigError(f"unknown Context Mode tool: {name!r}")
    return name


def _toml_string(value: str) -> str:
    # JSON string syntax is valid TOML string syntax for these scalar values.
    import json

    return json.dumps(value, ensure_ascii=False)


def _absolute_existing_or_planned(path: Path, field: str) -> Path:
    path = Path(path)
    if not path.is_absolute():
        raise ConfigError(f"{field} must be an absolute path")
    if "\x00" in os.fspath(path):
        raise ConfigError(f"{field} contains NUL")
    return path


def render_supervisor_config(*, model_settings: Mapping[str, str | int | float | bool] | None = None) -> str:
    """Render a minimal config with no MCP, hook, plugin, skill, or memory entries."""

    lines = ["# Generated by Bello; user/project discovery must be disabled by the launcher."]
    for key, value in sorted((model_settings or {}).items()):
        if not key.replace("_", "").isalnum():
            raise ConfigError(f"unsafe model setting name: {key!r}")
        if isinstance(value, bool):
            rendered = "true" if value else "false"
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            if isinstance(value, float) and not math.isfinite(value):
                raise ConfigError(f"non-finite model setting value for {key!r}")
            rendered = repr(value)
        elif isinstance(value, str):
            rendered = _toml_string(value)
        else:
            raise ConfigError(f"unsupported model setting value for {key!r}")
        lines.append(f"{key} = {rendered}")
    lines.extend(("", "[features]", "hooks = false", ""))
    return "\n".join(lines)


def render_coder_config(
    *,
    launcher_path: Path,
    mcp_bootstrap_path: Path,
    workspace: Path,
    model_settings: Mapping[str, str | int | float | bool] | None = None,
) -> str:
    launcher_path = _absolute_existing_or_planned(launcher_path, "launcher_path")
    mcp_bootstrap_path = _absolute_existing_or_planned(mcp_bootstrap_path, "mcp_bootstrap_path")
    workspace = _absolute_existing_or_planned(workspace, "workspace")
    base = render_supervisor_config(model_settings=model_settings).replace("hooks = false", "hooks = true")
    enabled = ",\n".join(f"  {_toml_string(name)}" for name in ALLOWED_TOOLS)
    disabled = ",\n".join(f"  {_toml_string(name)}" for name in sorted(FORBIDDEN_TOOL_NAMES))
    return base + "\n" + "\n".join(
        (
            f"[mcp_servers.{CONTEXT_SERVER_NAME}]",
            f"command = {_toml_string(os.fspath(launcher_path))}",
            f"args = [\"mcp\", \"--bootstrap\", {_toml_string(os.fspath(mcp_bootstrap_path))}]",
            f"cwd = {_toml_string(os.fspath(workspace))}",
            "required = true",
            "startup_timeout_sec = 90",
            "tool_timeout_sec = 3600",
            'default_tools_approval_mode = "prompt"',
            "enabled_tools = [",
            enabled,
            "]",
            "disabled_tools = [",
            disabled,
            "]",
            "",
        )
    )


@dataclass(frozen=True)
class GeneratedRoleHome:
    role: Role
    root: Path
    config_path: Path
    auth_path: Path | None
    manifest_path: Path
    file_digests: Mapping[str, str]


def generate_role_home(
    root: Path,
    *,
    role: Role | str,
    auth_source: Path | None = None,
    auth_bytes: bytes | None = None,
    model_settings: Mapping[str, str | int | float | bool] | None = None,
    launcher_path: Path | None = None,
    mcp_bootstrap_path: Path | None = None,
    workspace: Path | None = None,
    hook_bootstraps: Mapping[str, Path] | None = None,
    routing_text: str | None = None,
    skill_text: str | None = None,
    context_mode_enabled: bool = True,
) -> GeneratedRoleHome:
    """Create a role home from explicit inputs, never by cloning user config.

    Hook definitions are a Bello-owned JSON manifest consumed by the pinned
    launcher integration.  They do not interpolate payload into a shell command.
    """

    role = Role(role)
    if auth_source is not None and auth_bytes is not None:
        raise ConfigError("provide auth_source or auth_bytes, not both")
    root = ensure_private_directory(Path(root))
    if any(root.iterdir()):
        raise ConfigError("generated role home must be a new or empty directory")
    if role is Role.CODER and context_mode_enabled:
        if launcher_path is None or mcp_bootstrap_path is None or workspace is None:
            raise ConfigError("coder home requires launcher, MCP bootstrap, and workspace paths")
        config_text = render_coder_config(
            launcher_path=launcher_path,
            mcp_bootstrap_path=mcp_bootstrap_path,
            workspace=workspace,
            model_settings=model_settings,
        )
    else:
        if role is Role.SUPERVISOR and not context_mode_enabled:
            # This flag is meaningful only for the coder.  Accepting it for the
            # supervisor would create two encodings of the same role manifest.
            raise ConfigError("context_mode_enabled is a coder-only setting")
        if any(
            value is not None
            for value in (launcher_path, mcp_bootstrap_path, workspace, routing_text, skill_text)
        ):
            raise ConfigError(f"{role.value} home must not receive Context Mode paths or routing")
        if hook_bootstraps:
            raise ConfigError(f"{role.value} home must not contain Context Mode hooks")
        config_text = render_supervisor_config(model_settings=model_settings)

    written: dict[str, str] = {}
    config_path = root / "config.toml"
    config_payload = config_text.encode("utf-8")
    atomic_write_bytes(config_path, config_payload, mode=0o600)
    written[config_path.name] = sha256_bytes(config_payload)

    auth_path: Path | None = None
    if auth_source is not None:
        source_info = Path(auth_source).lstat()
        if stat.S_ISLNK(source_info.st_mode) or not stat.S_ISREG(source_info.st_mode):
            raise ConfigError("auth_source must be a regular file, not a symlink")
        auth_bytes = Path(auth_source).read_bytes()
    if auth_bytes is not None:
        auth_path = root / "auth.json"
        atomic_write_bytes(auth_path, bytes(auth_bytes), mode=0o600)
        written[auth_path.name] = sha256_bytes(bytes(auth_bytes))

    if role is Role.CODER and context_mode_enabled:
        provided_hooks = hook_bootstraps or {}
        validate_exact_hook_catalogue(provided_hooks)
        assert launcher_path is not None
        hook_manifest = {
            "schema_version": CONTEXT_MODE_SCHEMA_VERSION,
            "hooks": [
                {
                    "event": event,
                    "command": os.fspath(_absolute_existing_or_planned(launcher_path, "launcher_path")),
                    "args": [
                        "hook",
                        "--event",
                        event,
                        "--bootstrap",
                        os.fspath(_absolute_existing_or_planned(provided_hooks[event], f"hook {event} bootstrap")),
                    ],
                }
                for event in REQUIRED_HOOKS
            ],
        }
        hook_path = root / "hooks.json"
        hook_payload = canonical_json_bytes(hook_manifest) + b"\n"
        atomic_write_bytes(hook_path, hook_payload, mode=0o600)
        written[hook_path.name] = sha256_bytes(hook_payload)

        routing = routing_text or (
            "Bello Context Mode is offline. Use only the eight generated ctx_* tools for local "
            "execution, indexing, retrieval, and recovery. Never fetch, upgrade, use hosted "
            "services, or treat unverified command text as validation evidence.\n"
        )
        lowered = routing.lower()
        forbidden_fragments = ("ctx_fetch_and_index", "ctx_upgrade", "ctx_insight", "http://", "https://")
        if any(fragment in lowered for fragment in forbidden_fragments):
            raise ConfigError("routing text contains forbidden online/update functionality")
        routing_path = root / "context-mode-routing.md"
        routing_payload = routing.encode("utf-8")
        atomic_write_bytes(routing_path, routing_payload, mode=0o600)
        written[routing_path.name] = sha256_bytes(routing_payload)

        skill = skill_text or (
            "---\n"
            "name: bello-context-mode\n"
            "description: Use Bello's verified offline local execution, indexing, retrieval, and compaction recovery.\n"
            "---\n\n"
            "Operate only through the generated Bello Context Mode catalogue and launcher. "
            "Keep local command output bounded, prefer indexed retrieval for large data, and "
            "treat validation as trusted only when Bello accepts broker provenance. Network, "
            "hosted, update, and self-repair behavior is unavailable.\n"
        )
        skill_lowered = skill.lower()
        if any(fragment in skill_lowered for fragment in forbidden_fragments):
            raise ConfigError("skill text contains forbidden online/update functionality")
        skills_root = ensure_private_directory(root / "skills")
        skill_directory = ensure_private_directory(skills_root / CONTEXT_SKILL_NAME)
        skill_path = skill_directory / "SKILL.md"
        skill_payload = skill.encode("utf-8")
        atomic_write_bytes(skill_path, skill_payload, mode=0o600)
        written[f"skills/{CONTEXT_SKILL_NAME}/SKILL.md"] = sha256_bytes(skill_payload)

    manifest_path = root / "bello-generated-home.json"
    manifest = {
        "schema_version": CONTEXT_MODE_SCHEMA_VERSION,
        "role": role.value,
        "context_mode_enabled": role is Role.CODER and context_mode_enabled,
        "files": dict(sorted(written.items())),
    }
    atomic_write_json(manifest_path, manifest, mode=0o600)
    written[manifest_path.name] = sha256_bytes(canonical_json_bytes(manifest) + b"\n")
    return GeneratedRoleHome(role, root, config_path, auth_path, manifest_path, dict(written))


def generate_coder_home(root: Path, **kwargs: Any) -> GeneratedRoleHome:
    return generate_role_home(root, role=Role.CODER, **kwargs)


def generate_plain_coder_home(root: Path, **kwargs: Any) -> GeneratedRoleHome:
    """Generate a clean coder home for ``--no-context-mode`` runs."""

    return generate_role_home(root, role=Role.CODER, context_mode_enabled=False, **kwargs)


def generate_supervisor_home(root: Path, **kwargs: Any) -> GeneratedRoleHome:
    return generate_role_home(root, role=Role.SUPERVISOR, **kwargs)
