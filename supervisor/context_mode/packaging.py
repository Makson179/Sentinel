"""Selection and hash preflight for the bundled Context Mode runtime."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from ._util import (
    ContextModeDataError,
    load_json_object,
    require_int,
    require_nonempty,
    require_sha256,
    strict_object,
)


MANIFEST_SCHEMA_VERSION = 1
PINNED_CONTEXT_MODE_VERSION = "1.0.169"
PINNED_CONTEXT_MODE_COMMIT = "589d8214d56740a28b5f7bf63167743d586b0b40"
PINNED_NODE_VERSION = "22.5.0"
MINIMUM_NODE_VERSION = "22.5.0"
CONTEXT_MODE_LICENSE = "Elastic-2.0"
BETTER_SQLITE3_VERSION = "12.9.0"
OFFLINE_FORK_ATTESTATION_VERSION = 1
OFFLINE_FORK_ID = "bello-context-mode-offline-fork"
OFFLINE_FORK_REVISION = "bello-offline-v1"
PINNED_OFFLINE_FORK_COMMIT = "4fb531520ce7d802f52b8a3389d871b7d13e6c99"
SUPPORTED_RELEASE_PLATFORMS = (
    "linux-x86_64",
    "linux-arm64",
    "macos-x86_64",
    "macos-arm64",
)
PINNED_NODE_BINARY_SHA256 = {
    **{platform_tag: "0" * 64 for platform_tag in SUPPORTED_RELEASE_PLATFORMS},
    "linux-x86_64": "a77b4802a405a4a151623f35c7e6a396fd97766ed7415c1b90b0046b290dc9b7",
}
PINNED_NODE_LICENSE_SHA256 = "3b3f9af857c7ef307fb33ee897ef1af01fb5afd5e28e1f66bfbca809c527ee61"
PINNED_DEPENDENCY_INVENTORY_SHA256 = {
    **{platform_tag: "0" * 64 for platform_tag in SUPPORTED_RELEASE_PLATFORMS},
    "linux-x86_64": "e5dd457d90caa6b3f143db641ba68f6019cbefab146e7224abb9384efc9eb0f0",
}
OFFLINE_FORK_ATTESTATION = "bello-offline-fork.json"
TOOL_SCHEMA_CATALOG = "configs/bello-tool-schemas.json"
ALLOWED_TOOLS = (
    "ctx_execute",
    "ctx_execute_file",
    "ctx_batch_execute",
    "ctx_index",
    "ctx_search",
    "ctx_stats",
    "ctx_doctor",
    "ctx_purge",
)
FORBIDDEN_TOOLS = ("ctx_fetch_and_index", "ctx_insight", "ctx_upgrade")
PACKAGE_FILES = (
    "server.bundle.mjs",
    "cli.bundle.mjs",
    "start.mjs",
    "package.json",
    "LICENSE",
    OFFLINE_FORK_ATTESTATION,
)
PACKAGE_DIRECTORIES = ("build", "hooks", "skills", "configs", "node_modules")
FORK_CODE_FILES = ("server.bundle.mjs", "cli.bundle.mjs", "start.mjs", "package.json")
FORK_CODE_DIRECTORIES = ("build", "hooks", "skills", "configs")
AUTHORITY_FILES = (
    "bin/bello-context-broker",
    "bin/bello-context-launcher",
    "LICENSE",
    "authority.json",
    "authority.sig",
    "release-public-key.pem",
)
AUTHORITY_EXECUTABLES = frozenset(
    {
        "bin/bello-context-broker",
        "bin/bello-context-launcher",
    }
)
REQUIRED_RUNTIME_FILES = frozenset(
    {
        "node",
        "server.bundle.mjs",
        "node/LICENSE",
        "package/cli.bundle.mjs",
        "package/start.mjs",
        "package/package.json",
        "package/LICENSE",
        "package/bello-offline-fork.json",
        "package/node_modules/better-sqlite3/package.json",
        "authority/bin/bello-context-broker",
        "authority/bin/bello-context-launcher",
        "authority/LICENSE",
        "authority/authority.json",
        "authority/authority.sig",
        "authority/release-public-key.pem",
    }
)


class PackagingError(ContextModeDataError):
    """The platform bundle is missing, malformed, or has the wrong digest."""


def current_platform_tag(*, system: str | None = None, machine: str | None = None) -> str:
    system_value = (system or platform.system()).lower()
    machine_value = (machine or platform.machine()).lower().replace(" ", "")
    os_names = {"linux": "linux", "darwin": "macos"}
    machine_names = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    try:
        return f"{os_names[system_value]}-{machine_names[machine_value]}"
    except KeyError as exc:
        raise PackagingError(f"unsupported Context Mode platform: {system_value}/{machine_value}") from exc


def _manifest_path_for_key(key: str) -> PurePosixPath:
    compatibility = {
        "node": PurePosixPath("node/bin/node"),
        "server.bundle.mjs": PurePosixPath("package/server.bundle.mjs"),
    }
    if key in compatibility:
        return compatibility[key]
    path = PurePosixPath(key)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise PackagingError(f"unsafe bundle manifest path: {key!r}")
    if path.parts[0] not in {"node", "package", "authority"}:
        raise PackagingError(f"bundle file lies outside node/package/authority roots: {key!r}")
    return path


@dataclass(frozen=True)
class RuntimeManifest:
    schema_version: int
    bello_offline_fork_revision: str
    bello_offline_fork_attestation_sha256: str
    context_mode_commit: str
    context_mode_version: str
    node_version: str
    platform: str
    files: Mapping[str, str]

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RuntimeManifest":
        required = frozenset(
            {
                "schema_version",
                "bello_offline_fork_revision",
                "bello_offline_fork_attestation_sha256",
                "context_mode_commit",
                "context_mode_version",
                "node_version",
                "platform",
                "files",
            }
        )
        strict_object(
            value,
            required=required,
            name="Context Mode bundle manifest",
        )
        schema_version = value["schema_version"]
        require_int(schema_version, "schema_version", minimum=1)
        if schema_version != MANIFEST_SCHEMA_VERSION:
            raise PackagingError(f"unsupported bundle manifest schema version: {schema_version!r}")
        files = value["files"]
        if not isinstance(files, Mapping) or not files:
            raise PackagingError("bundle manifest files must be a non-empty object")
        normalized_files: dict[str, str] = {}
        resolved_paths: set[PurePosixPath] = set()
        for key, digest in files.items():
            if not isinstance(key, str) or not isinstance(digest, str):
                raise PackagingError("bundle manifest file names and digests must be strings")
            resolved = _manifest_path_for_key(key)
            if resolved in resolved_paths:
                raise PackagingError(f"duplicate canonical bundle path: {resolved}")
            resolved_paths.add(resolved)
            normalized_files[key] = require_sha256(digest, f"files[{key!r}]")
        if not REQUIRED_RUNTIME_FILES.issubset(normalized_files):
            missing = REQUIRED_RUNTIME_FILES - frozenset(normalized_files)
            raise PackagingError(f"bundle manifest is missing required files: {sorted(missing)!r}")
        attestation_digest = value["bello_offline_fork_attestation_sha256"]
        if not isinstance(attestation_digest, str):
            raise PackagingError("bello_offline_fork_attestation_sha256 must be a string")
        return cls(
            schema_version=MANIFEST_SCHEMA_VERSION,
            bello_offline_fork_revision=require_nonempty(
                value["bello_offline_fork_revision"],
                "bello_offline_fork_revision",
            ),
            bello_offline_fork_attestation_sha256=require_sha256(
                attestation_digest,
                "bello_offline_fork_attestation_sha256",
            ),
            context_mode_commit=require_nonempty(value["context_mode_commit"], "context_mode_commit"),
            context_mode_version=require_nonempty(value["context_mode_version"], "context_mode_version"),
            node_version=require_nonempty(value["node_version"], "node_version"),
            platform=require_nonempty(value["platform"], "platform"),
            files=normalized_files,
        )


@dataclass(frozen=True)
class VerifiedRuntimeBundle:
    root: Path
    manifest_path: Path
    manifest: RuntimeManifest
    node_path: Path
    server_entrypoint: Path
    authority_root: Path
    verified_files: Mapping[str, Path]
    tool_schema_digests: Mapping[str, str]


def _sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_manifest_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _canonical_digest_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _dependency_inventory_digest(root: Path) -> str:
    _require_real_directory(root, "bundled dependency inventory")
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        if stat.S_ISLNK(info.st_mode):
            raise PackagingError(f"bundled dependency inventory contains a symlink: {relative}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise PackagingError(
                f"bundled dependency inventory contains an unsupported file: {relative}"
            )
        files[relative] = _sha256_file(path)
    if not files:
        raise PackagingError("bundled dependency inventory is empty")
    return hashlib.sha256(_canonical_digest_json({"files": files})).hexdigest()


def _require_real_directory(path: Path, description: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise PackagingError(f"{description} is missing: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise PackagingError(f"{description} is not a real directory: {path}")


def _require_real_file(path: Path, description: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise PackagingError(f"{description} is missing: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PackagingError(f"{description} is not a regular non-symlink file: {path}")


def _validate_authority_layout(authority_root: Path) -> None:
    _require_real_directory(authority_root, "bundled signed native authority directory")
    expected_root = {
        "bin",
        "LICENSE",
        "authority.json",
        "authority.sig",
        "release-public-key.pem",
    }
    actual_root = {entry.name for entry in authority_root.iterdir()}
    if actual_root != expected_root:
        raise PackagingError(
            "bundled signed native authority layout mismatch: "
            f"expected {sorted(expected_root)!r}, got {sorted(actual_root)!r}"
        )
    bin_root = authority_root / "bin"
    _require_real_directory(bin_root, "bundled signed native authority bin directory")
    expected_bin = {"bello-context-broker", "bello-context-launcher"}
    actual_bin = {entry.name for entry in bin_root.iterdir()}
    if actual_bin != expected_bin:
        raise PackagingError(
            "bundled signed native authority bin layout mismatch: "
            f"expected {sorted(expected_bin)!r}, got {sorted(actual_bin)!r}"
        )
    for relative in AUTHORITY_FILES:
        path = authority_root / relative
        _require_real_file(path, f"bundled signed native authority {relative}")
        if path.lstat().st_size <= 0:
            raise PackagingError(f"bundled signed native authority file is empty: {relative}")
        if relative in AUTHORITY_EXECUTABLES and not os.access(path, os.X_OK):
            raise PackagingError(
                f"bundled signed native authority executable is not executable: {relative}"
            )


def _validate_bundle_layout(root: Path) -> None:
    expected_root = {"node", "package", "authority", "manifest.json", "manifest.sha256"}
    actual_root = {entry.name for entry in root.iterdir()}
    if actual_root != expected_root:
        raise PackagingError(
            f"bundle root layout mismatch: expected {sorted(expected_root)!r}, got {sorted(actual_root)!r}"
        )
    node_root = root / "node"
    package_root = root / "package"
    authority_root = root / "authority"
    _require_real_directory(node_root, "bundled Node directory")
    _require_real_directory(package_root, "bundled Context Mode package directory")
    _validate_authority_layout(authority_root)
    node_entries = {entry.name for entry in node_root.iterdir()}
    if node_entries != {"bin", "LICENSE"}:
        raise PackagingError(f"bundled Node layout mismatch: {sorted(node_entries)!r}")
    _require_real_directory(node_root / "bin", "bundled Node bin directory")
    if {entry.name for entry in (node_root / "bin").iterdir()} != {"node"}:
        raise PackagingError("bundled Node bin directory must contain only node")
    _require_real_file(node_root / "bin" / "node", "bundled Node executable")
    _require_real_file(node_root / "LICENSE", "bundled Node LICENSE")

    expected_package = set(PACKAGE_FILES) | set(PACKAGE_DIRECTORIES)
    actual_package = {entry.name for entry in package_root.iterdir()}
    if actual_package != expected_package:
        raise PackagingError(
            "bundled Context Mode layout mismatch: "
            f"expected {sorted(expected_package)!r}, got {sorted(actual_package)!r}"
        )
    for relative in PACKAGE_FILES:
        _require_real_file(package_root / relative, f"bundled Context Mode {relative}")
    for relative in PACKAGE_DIRECTORIES:
        _require_real_directory(package_root / relative, f"bundled Context Mode {relative}")


def _iter_payload_files(root: Path) -> list[tuple[str, Path]]:
    payload: list[tuple[str, Path]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise PackagingError(f"bundle contains a symlink: {relative.as_posix()}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise PackagingError(f"bundle contains an unsupported file type: {relative.as_posix()}")
        posix = relative.as_posix()
        if posix in {"manifest.json", "manifest.sha256"}:
            continue
        if posix == "node/bin/node":
            key = "node"
        elif posix == "package/server.bundle.mjs":
            key = "server.bundle.mjs"
        else:
            key = posix
        payload.append((key, path))
    return payload


def _iter_fork_code_files(package_root: Path) -> list[Path]:
    files: list[Path] = []
    for relative in FORK_CODE_FILES:
        path = package_root / relative
        _require_real_file(path, f"offline fork {relative}")
        files.append(path)
    for relative in FORK_CODE_DIRECTORIES:
        root = package_root / relative
        _require_real_directory(root, f"offline fork {relative}")
        for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(package_root).as_posix()):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise PackagingError(
                    f"offline fork code surface contains a symlink: {path.relative_to(package_root)}"
                )
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise PackagingError(
                    "offline fork code surface contains an unsupported file type: "
                    f"{path.relative_to(package_root)}"
                )
            files.append(path)
    return files


def _offline_fork_payload_digest(package_root: Path) -> str:
    files = {
        path.relative_to(package_root).as_posix(): _sha256_file(path)
        for path in _iter_fork_code_files(package_root)
    }
    return hashlib.sha256(_canonical_digest_json({"files": files})).hexdigest()


def _verify_offline_fork_attestation(
    package_root: Path,
    *,
    manifest: RuntimeManifest,
    enforce_release_pin: bool,
) -> dict[str, str]:
    attestation_path = package_root / OFFLINE_FORK_ATTESTATION
    try:
        attestation = load_json_object(attestation_path, max_bytes=256 * 1024)
    except ContextModeDataError as exc:
        raise PackagingError(str(exc)) from exc
    if attestation_path.read_bytes() != _canonical_manifest_bytes(attestation):
        raise PackagingError("Bello offline-fork attestation is not canonical deterministic JSON")
    required = frozenset(
        {
            "schema_version",
            "attestation_type",
            "fork_revision",
            "fork_source_commit",
            "upstream_version",
            "upstream_commit",
            "catalog_version",
            "allowed_tools",
            "tool_schema_digests",
            "forbidden_tools",
            "offline",
            "runtime_downloads",
            "runtime_installs",
            "runtime_updates",
            "network_routes",
            "payload_sha256",
        }
    )
    try:
        strict_object(attestation, required=required, name="Bello offline-fork attestation")
        require_int(attestation["schema_version"], "schema_version", minimum=1)
        require_int(attestation["catalog_version"], "catalog_version", minimum=1)
    except ContextModeDataError as exc:
        raise PackagingError(str(exc)) from exc
    for field_name in (
        "offline",
        "runtime_downloads",
        "runtime_installs",
        "runtime_updates",
        "network_routes",
    ):
        if not isinstance(attestation[field_name], bool):
            raise PackagingError(
                f"Bello offline-fork attestation {field_name} must be boolean"
            )
    fixed = {
        "schema_version": OFFLINE_FORK_ATTESTATION_VERSION,
        "attestation_type": OFFLINE_FORK_ID,
        "fork_revision": OFFLINE_FORK_REVISION,
        "upstream_version": PINNED_CONTEXT_MODE_VERSION,
        "upstream_commit": PINNED_CONTEXT_MODE_COMMIT,
        "catalog_version": 1,
        "allowed_tools": list(ALLOWED_TOOLS),
        "forbidden_tools": list(FORBIDDEN_TOOLS),
        "offline": True,
        "runtime_downloads": False,
        "runtime_installs": False,
        "runtime_updates": False,
        "network_routes": False,
    }
    mismatches = {key: attestation.get(key) for key, expected in fixed.items() if attestation.get(key) != expected}
    if mismatches:
        raise PackagingError(f"Bello offline-fork attestation policy mismatch: {sorted(mismatches)!r}")
    schema_digests = attestation.get("tool_schema_digests")
    if not isinstance(schema_digests, Mapping) or frozenset(schema_digests) != frozenset(ALLOWED_TOOLS):
        raise PackagingError("offline-fork tool schema digests must cover exactly eight pinned tools")
    normalized_schema_digests: dict[str, str] = {}
    for name in ALLOWED_TOOLS:
        digest = schema_digests.get(name)
        if not isinstance(digest, str):
            raise PackagingError(f"offline-fork schema digest for {name!r} is not a string")
        try:
            normalized_schema_digests[name] = require_sha256(digest, f"tool_schema_digests[{name!r}]")
        except ContextModeDataError as exc:
            raise PackagingError(str(exc)) from exc
    schema_path = package_root / TOOL_SCHEMA_CATALOG
    try:
        schemas = load_json_object(schema_path, max_bytes=512 * 1024)
    except ContextModeDataError as exc:
        raise PackagingError(str(exc)) from exc
    if schema_path.read_bytes() != _canonical_manifest_bytes(schemas):
        raise PackagingError("bundled tool schema catalogue is not canonical deterministic JSON")
    if frozenset(schemas) != frozenset(ALLOWED_TOOLS):
        raise PackagingError("bundled tool schema catalogue does not cover exactly eight tools")
    for name in ALLOWED_TOOLS:
        schema = schemas.get(name)
        if not isinstance(schema, Mapping):
            raise PackagingError(f"bundled tool schema for {name!r} is not an object")
        if hashlib.sha256(_canonical_digest_json(schema)).hexdigest() != normalized_schema_digests[name]:
            raise PackagingError(f"bundled tool schema digest mismatch for {name!r}")
    fork_source_commit = attestation.get("fork_source_commit")
    if (
        not isinstance(fork_source_commit, str)
        or len(fork_source_commit) != 40
        or any(character not in "0123456789abcdef" for character in fork_source_commit)
        or fork_source_commit == PINNED_CONTEXT_MODE_COMMIT
    ):
        raise PackagingError("Bello offline-fork attestation has an invalid fork source commit")
    if enforce_release_pin:
        if PINNED_OFFLINE_FORK_COMMIT == "0" * 40:
            raise PackagingError(
                "reviewed Bello offline-fork commit pin is not configured for this release"
            )
        if fork_source_commit != PINNED_OFFLINE_FORK_COMMIT:
            raise PackagingError(
                "Bello offline-fork attestation does not match the reviewed source commit"
            )
    payload_digest = attestation.get("payload_sha256")
    if not isinstance(payload_digest, str):
        raise PackagingError("Bello offline-fork attestation payload digest is not a string")
    try:
        expected_payload_digest = require_sha256(payload_digest, "payload_sha256")
    except ContextModeDataError as exc:
        raise PackagingError(str(exc)) from exc
    actual_payload_digest = _offline_fork_payload_digest(package_root)
    if expected_payload_digest != actual_payload_digest:
        raise PackagingError("Bello offline-fork attestation payload digest mismatch")
    if manifest.bello_offline_fork_revision != OFFLINE_FORK_REVISION:
        raise PackagingError("bundle does not match the Bello offline-fork revision")
    if _sha256_file(attestation_path) != manifest.bello_offline_fork_attestation_sha256:
        raise PackagingError("bundle manifest offline-fork attestation digest mismatch")
    return normalized_schema_digests


def verify_runtime_bundle(
    bundle_root: Path,
    *,
    expected_platform: str | None = None,
    require_executable_node: bool = True,
    enforce_release_pin: bool = True,
) -> VerifiedRuntimeBundle:
    """Verify every manifest entry before returning any executable path."""

    root = Path(bundle_root)
    try:
        root_info = root.lstat()
    except FileNotFoundError as exc:
        raise PackagingError(f"bundle root is missing: {root}") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise PackagingError(f"bundle root is not a real directory: {root}")
    _validate_bundle_layout(root)
    manifest_path = root / "manifest.json"
    try:
        raw_manifest = load_json_object(manifest_path, max_bytes=512 * 1024)
    except ContextModeDataError as exc:
        raise PackagingError(str(exc)) from exc
    canonical_manifest = _canonical_manifest_bytes(raw_manifest)
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as exc:
        raise PackagingError(f"cannot read bundle manifest: {exc}") from exc
    if manifest_bytes != canonical_manifest:
        raise PackagingError("bundle manifest.json is not canonical deterministic JSON")
    manifest_digest_path = root / "manifest.sha256"
    _require_real_file(manifest_digest_path, "bundle manifest digest")
    expected_manifest_digest = f"{hashlib.sha256(canonical_manifest).hexdigest()}  manifest.json\n"
    try:
        manifest_digest_record = manifest_digest_path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise PackagingError(f"cannot read bundle manifest digest: {exc}") from exc
    if manifest_digest_record != expected_manifest_digest:
        raise PackagingError("bundle manifest.sha256 does not match canonical manifest.json")
    try:
        manifest = RuntimeManifest.from_dict(raw_manifest)
    except ContextModeDataError as exc:
        raise PackagingError(str(exc)) from exc
    expected = expected_platform or current_platform_tag()
    if manifest.platform != expected:
        raise PackagingError(f"bundle platform {manifest.platform!r} does not match {expected!r}")
    if enforce_release_pin:
        release_mismatches = []
        if manifest.context_mode_version != PINNED_CONTEXT_MODE_VERSION:
            release_mismatches.append("context_mode_version")
        if manifest.context_mode_commit != PINNED_CONTEXT_MODE_COMMIT:
            release_mismatches.append("context_mode_commit")
        if manifest.node_version != PINNED_NODE_VERSION:
            release_mismatches.append("node_version")
        if manifest.bello_offline_fork_revision != OFFLINE_FORK_REVISION:
            release_mismatches.append("bello_offline_fork_revision")
        if release_mismatches:
            raise PackagingError(f"bundle does not match Bello release pins: {release_mismatches!r}")
        if expected not in PINNED_NODE_BINARY_SHA256 or expected not in PINNED_DEPENDENCY_INVENTORY_SHA256:
            raise PackagingError(f"no reviewed dependency pins exist for platform {expected!r}")

    payload_entries = _iter_payload_files(root)
    payload_keys = [key for key, _path in payload_entries]
    if len(payload_keys) != len(set(payload_keys)):
        raise PackagingError("bundle payload contains duplicate canonical manifest paths")
    payload = dict(payload_entries)
    if frozenset(payload) != frozenset(manifest.files):
        unlisted = sorted(frozenset(payload) - frozenset(manifest.files))
        missing = sorted(frozenset(manifest.files) - frozenset(payload))
        raise PackagingError(
            f"bundle manifest coverage mismatch: unlisted={unlisted!r}, missing={missing!r}"
        )

    verified: dict[str, Path] = {}
    root_resolved = root.resolve(strict=True)
    for key, expected_digest in manifest.files.items():
        relative = _manifest_path_for_key(key)
        path = payload[key]
        try:
            info = path.lstat()
        except FileNotFoundError as exc:
            raise PackagingError(f"bundle file is missing: {relative}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise PackagingError(f"bundle file is not a regular non-symlink file: {relative}")
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(root_resolved)
        except ValueError as exc:
            raise PackagingError(f"bundle file escapes bundle root: {relative}") from exc
        actual_digest = _sha256_file(path)
        if actual_digest != expected_digest:
            raise PackagingError(
                f"SHA-256 mismatch for {relative}: expected {expected_digest}, got {actual_digest}"
            )
        verified[key] = path

    node_path = verified["node"]
    server_entrypoint = verified["server.bundle.mjs"]
    authority_root = root / "authority"
    package_root = root / "package"
    node_license = verified["node/LICENSE"].read_bytes()
    if not node_license.strip():
        raise PackagingError("bundled Node LICENSE is empty")
    if enforce_release_pin:
        expected_node = PINNED_NODE_BINARY_SHA256[expected]
        expected_dependencies = PINNED_DEPENDENCY_INVENTORY_SHA256[expected]
        if (
            expected_node == "0" * 64
            or PINNED_NODE_LICENSE_SHA256 == "0" * 64
            or expected_dependencies == "0" * 64
        ):
            raise PackagingError(
                f"reviewed Node/dependency release pins are not configured for {expected}"
            )
        if (
            _sha256_file(node_path) != expected_node
            or _sha256_file(verified["node/LICENSE"]) != PINNED_NODE_LICENSE_SHA256
        ):
            raise PackagingError("bundled Node bytes do not match the reviewed release pins")
    try:
        context_license = verified["package/LICENSE"].read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise PackagingError(f"cannot read bundled Context Mode LICENSE: {exc}") from exc
    if "Elastic License 2.0" not in context_license:
        raise PackagingError("bundled Context Mode LICENSE is not Elastic License 2.0")
    try:
        package_metadata = load_json_object(package_root / "package.json", max_bytes=256 * 1024)
        native_metadata = load_json_object(
            package_root / "node_modules" / "better-sqlite3" / "package.json",
            max_bytes=256 * 1024,
        )
    except ContextModeDataError as exc:
        raise PackagingError(str(exc)) from exc
    if (
        package_metadata.get("name") != "context-mode"
        or package_metadata.get("version") != PINNED_CONTEXT_MODE_VERSION
        or package_metadata.get("license") != CONTEXT_MODE_LICENSE
    ):
        raise PackagingError("bundled Context Mode package metadata does not match release pins")
    if (
        native_metadata.get("name") != "better-sqlite3"
        or native_metadata.get("version") != BETTER_SQLITE3_VERSION
    ):
        raise PackagingError("bundled better-sqlite3 metadata does not match the pinned native payload")
    native_bindings = [
        path
        for key, path in verified.items()
        if key.startswith("package/node_modules/better-sqlite3/") and path.suffix == ".node"
    ]
    if len(native_bindings) != 1 or native_bindings[0].stat().st_size <= 0:
        raise PackagingError(
            "bundled better-sqlite3 must contain exactly one non-empty native .node binding"
        )
    if enforce_release_pin and (
        _dependency_inventory_digest(package_root / "node_modules")
        != PINNED_DEPENDENCY_INVENTORY_SHA256[expected]
    ):
        raise PackagingError(
            "bundled dependency inventory does not match the reviewed platform payload"
        )
    tool_schema_digests = _verify_offline_fork_attestation(
        package_root,
        manifest=manifest,
        enforce_release_pin=enforce_release_pin,
    )
    if require_executable_node and not os.access(node_path, os.X_OK):
        raise PackagingError(f"bundled Node.js is not executable: {node_path}")
    return VerifiedRuntimeBundle(
        root,
        manifest_path,
        manifest,
        node_path,
        server_entrypoint,
        authority_root,
        verified,
        tool_schema_digests,
    )


def select_bundled_runtime(
    vendor_root: Path,
    *,
    platform_tag: str | None = None,
    require_executable_node: bool = True,
    enforce_release_pin: bool = True,
) -> VerifiedRuntimeBundle:
    """Select ``<vendor>/<platform>`` when present, otherwise a direct bundle.

    Release layouts may put ``manifest.json`` directly at
    ``supervisor/_vendor/context_mode`` or one level below per platform.  Both
    forms still require an exact platform match in the signed release manifest.
    """

    vendor_root = Path(vendor_root)
    selected_platform = platform_tag or current_platform_tag()
    candidate = vendor_root if (vendor_root / "manifest.json").is_file() else vendor_root / selected_platform
    try:
        return verify_runtime_bundle(
            candidate,
            expected_platform=selected_platform,
            require_executable_node=require_executable_node,
            enforce_release_pin=enforce_release_pin,
        )
    except FileNotFoundError as exc:
        raise PackagingError(f"no bundled Context Mode runtime for {selected_platform}") from exc


preflight_bundle = verify_runtime_bundle
