#!/usr/bin/env python3
"""Build and verify Bello's pinned, offline Context Mode worker bundle.

The builder deliberately has no dependency installation or download path.  A
release runner must provide a clean, attested Bello offline-fork checkout based
on the pinned Context Mode upstream commit, a populated ``node_modules`` tree
built on the target platform, and an unpacked pinned Node distribution.  Stock
upstream is rejected.  Every regular payload file is covered by
``manifest.json`` and the canonical manifest is itself covered by
``manifest.sha256``.

The signed native broker/launcher authority is a mandatory, opaque release
input and is copied into the hash-covered bundle.  Signature verification and
adapter loading remain a separate fail-closed release-readiness gate.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform as host_platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence


SCHEMA_VERSION = 1
CONTEXT_MODE_VERSION = "1.0.169"
CONTEXT_MODE_COMMIT = "589d8214d56740a28b5f7bf63167743d586b0b40"
NODE_VERSION = "22.5.0"
CONTEXT_MODE_LICENSE = "Elastic-2.0"
BETTER_SQLITE3_VERSION = "12.9.0"
OFFLINE_FORK_ATTESTATION_VERSION = 1
OFFLINE_FORK_ID = "bello-context-mode-offline-fork"
OFFLINE_FORK_REVISION = "bello-offline-v1"
# Release engineering must replace this sentinel with the independently
# reviewed Bello fork commit.  A self-consistent checkout/attestation is not a
# trust root and production bundle construction is intentionally impossible
# while the sentinel remains.
PINNED_OFFLINE_FORK_COMMIT = "4fb531520ce7d802f52b8a3389d871b7d13e6c99"
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
DEFAULT_SOURCE_DATE_EPOCH = 1_720_742_400  # 2024-07-12T00:00:00Z
SUPPORTED_PLATFORMS = (
    "linux-x86_64",
    "linux-arm64",
    "macos-x86_64",
    "macos-arm64",
)
PINNED_NODE_BINARY_SHA256 = {
    **{platform_tag: "0" * 64 for platform_tag in SUPPORTED_PLATFORMS},
    # Official node-v22.5.0-linux-x64 distribution, verified against the
    # upstream SHASUMS256.txt before extraction on the release host.
    "linux-x86_64": "a77b4802a405a4a151623f35c7e6a396fd97766ed7415c1b90b0046b290dc9b7",
}
PINNED_NODE_LICENSE_SHA256 = "3b3f9af857c7ef307fb33ee897ef1af01fb5afd5e28e1f66bfbca809c527ee61"
PINNED_DEPENDENCY_INVENTORY_SHA256 = {
    **{platform_tag: "0" * 64 for platform_tag in SUPPORTED_PLATFORMS},
    # better-sqlite3 12.9.0 and its production npm dependency tree, rebuilt
    # with the pinned Node ABI on Ubuntu 24.04 x86-64. Install-only .bin
    # symlinks are deliberately excluded from the shipped payload.
    "linux-x86_64": "e5dd457d90caa6b3f143db641ba68f6019cbefab146e7224abb9384efc9eb0f0",
}

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
        "authority/bin/bello-context-broker",
        "authority/bin/bello-context-launcher",
        "authority/LICENSE",
        "authority/authority.json",
        "authority/authority.sig",
        "authority/release-public-key.pem",
    }
)
MANIFEST_NAME = "manifest.json"
MANIFEST_DIGEST_NAME = "manifest.sha256"
# Keep the release verifier aligned with supervisor.context_mode.packaging,
# which rejects oversized manifests before touching an executable.
MAX_MANIFEST_BYTES = 512 * 1024

# These checks are intentionally conservative.  The Bello fork must not merely
# hide forbidden tools with MCP configuration: handlers, routes and mutating
# startup helpers must be absent from every shipped runtime/code surface.
OFFLINE_SOURCE_RULES: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    (
        "runtime package-manager operation",
        re.compile(
            rb"\b(?:npm|npx|pnpm|yarn|bun)\s+(?:install|add|rebuild|update|upgrade|dlx)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "split runtime package-manager operation",
        re.compile(
            rb"[\"'](?:npm|npx|pnpm|yarn|bun)(?:\.cmd)?[\"'][\s\S]{0,192}"
            rb"[\"'](?:install|add|rebuild|update|upgrade|dlx)[\"']",
            re.IGNORECASE,
        ),
    ),
    (
        "mutating dependency/startup helper",
        re.compile(
            rb"(?:ensure[-_]deps|postinstall|preinstall|heal[-_](?:better[-_]sqlite3|partial[-_]install)|"
            rb"normalizeHooksOnStartup|NPM_INSTALL|NPM_CLI_JS)",
            re.IGNORECASE,
        ),
    ),
    (
        "direct network API",
        re.compile(rb"\b(?:fetch|WebFetch|XMLHttpRequest|WebSocket)\s*\(", re.IGNORECASE),
    ),
    (
        "network module import",
        re.compile(
            rb"(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*(?:\(\s*)?)[\"']"
            rb"(?:(?:node:)?(?:http|https|net|tls|dns|dgram)|undici|axios)[\"']",
            re.IGNORECASE,
        ),
    ),
    (
        "download command route",
        re.compile(rb"\b(?:curl|wget)\b[^\r\n]{0,160}\bhttps?://", re.IGNORECASE),
    ),
    (
        "source update route",
        re.compile(
            rb"[\"']git[\"'][\s\S]{0,192}[\"'](?:pull|clone|fetch)[\"']",
            re.IGNORECASE,
        ),
    ),
)


class BundleBuildError(RuntimeError):
    """A supplied release input or generated bundle is invalid."""


@dataclass(frozen=True)
class VerifiedBundle:
    root: Path
    platform: str
    manifest_path: Path
    manifest_digest_path: Path
    node_path: Path
    server_entrypoint: Path
    authority_root: Path
    file_count: int


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _canonical_digest_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _dependency_inventory_digest(root: Path) -> str:
    """Hash every dependency byte by canonical relative path, rejecting links."""

    root = Path(root)
    _lstat_directory(root, "Context Mode dependency inventory")
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        if stat.S_ISLNK(info.st_mode):
            raise BundleBuildError(f"dependency inventory contains a symlink: {relative}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise BundleBuildError(f"dependency inventory contains an unsupported file: {relative}")
        files[relative] = _sha256(path)
    if not files:
        raise BundleBuildError("Context Mode dependency inventory is empty")
    return hashlib.sha256(_canonical_digest_json({"files": files})).hexdigest()


def _lstat_directory(path: Path, description: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise BundleBuildError(f"{description} is missing: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise BundleBuildError(f"{description} must be a real directory: {path}")


def _lstat_file(path: Path, description: str, *, executable: bool = False) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise BundleBuildError(f"{description} is missing: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise BundleBuildError(f"{description} must be a regular non-symlink file: {path}")
    if executable and not os.access(path, os.X_OK):
        raise BundleBuildError(f"{description} is not executable: {path}")


def _load_json(path: Path, description: str) -> Mapping[str, object]:
    _lstat_file(path, description)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise BundleBuildError(f"cannot read {description}: {path}: {exc}") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise BundleBuildError(f"{description} is too large: {path}")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleBuildError(f"invalid JSON in {description}: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise BundleBuildError(f"{description} must contain a JSON object: {path}")
    return value


def _release_environment(home: Path) -> dict[str, str]:
    """Return a small environment that cannot inherit npm/proxy credentials."""

    environment = {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
        "CONTEXT_MODE_OFFLINE": "1",
        "NO_COLOR": "1",
    }
    # macOS system tools can require this variable.  Nothing credential-like is
    # copied from the caller, and npm configuration is intentionally absent.
    if "TMPDIR" in os.environ:
        environment["TMPDIR"] = os.environ["TMPDIR"]
    return environment


def _run(
    argv: Sequence[str],
    *,
    cwd: Path,
    home: Path,
    timeout_seconds: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(argv),
            cwd=cwd,
            env=_release_environment(home),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BundleBuildError(f"release check failed to execute {argv[0]!r}: {exc}") from exc


def _git_head(checkout: Path, *, scratch_home: Path) -> str:
    result = _run(
        ("git", "-c", "safe.directory=*", "rev-parse", "--verify", "HEAD^{commit}"),
        cwd=checkout,
        home=scratch_home,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise BundleBuildError(f"Context Mode source is not a Git checkout: {detail}")
    return result.stdout.strip().lower()


def _git_is_ancestor(
    checkout: Path,
    *,
    ancestor: str,
    descendant: str,
    scratch_home: Path,
) -> bool:
    result = _run(
        (
            "git",
            "-c",
            "safe.directory=*",
            "merge-base",
            "--is-ancestor",
            ancestor,
            descendant,
        ),
        cwd=checkout,
        home=scratch_home,
    )
    if result.returncode in {0, 1}:
        return result.returncode == 0
    detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
    raise BundleBuildError(f"cannot verify Context Mode fork ancestry: {detail}")


def _require_clean_tracked_checkout(checkout: Path, *, scratch_home: Path) -> None:
    result = _run(
        ("git", "-c", "safe.directory=*", "status", "--porcelain", "--untracked-files=all"),
        cwd=checkout,
        home=scratch_home,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise BundleBuildError(f"cannot inspect Context Mode checkout: {detail}")
    if result.stdout.strip():
        raise BundleBuildError("Context Mode checkout has modifications or untracked release inputs")


def _iter_fork_code_files(checkout: Path) -> Iterable[Path]:
    checkout = Path(checkout)
    for relative in FORK_CODE_FILES:
        path = checkout / relative
        _lstat_file(path, f"offline fork {relative}")
        yield path
    for relative in FORK_CODE_DIRECTORIES:
        root = checkout / relative
        _lstat_directory(root, f"offline fork {relative}")
        for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(checkout).as_posix()):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise BundleBuildError(
                    f"offline fork code surface contains a symlink: {path.relative_to(checkout).as_posix()}"
                )
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise BundleBuildError(
                    "offline fork code surface contains an unsupported file type: "
                    f"{path.relative_to(checkout).as_posix()}"
                )
            yield path


def offline_fork_payload_digest(checkout: Path) -> str:
    checkout = Path(checkout)
    files = {
        path.relative_to(checkout).as_posix(): _sha256(path)
        for path in _iter_fork_code_files(checkout)
    }
    return hashlib.sha256(_canonical_digest_json({"files": files})).hexdigest()


def tool_schema_digests(checkout: Path) -> dict[str, str]:
    """Load the reviewed fork schemas and bind their exact canonical digests."""

    path = Path(checkout) / TOOL_SCHEMA_CATALOG
    catalogue = _load_json(path, "Bello Context Mode tool schema catalogue")
    if path.read_bytes() != _canonical_json(catalogue):
        raise BundleBuildError("tool schema catalogue is not canonical deterministic JSON")
    if frozenset(catalogue) != frozenset(ALLOWED_TOOLS):
        raise BundleBuildError("tool schema catalogue must cover exactly the eight pinned tools")
    result: dict[str, str] = {}
    for name in ALLOWED_TOOLS:
        schema = catalogue.get(name)
        if not isinstance(schema, dict):
            raise BundleBuildError(f"tool schema for {name!r} must be an object")
        result[name] = hashlib.sha256(_canonical_digest_json(schema)).hexdigest()
    return result


def make_offline_fork_attestation(checkout: Path, *, fork_source_commit: str) -> dict[str, object]:
    """Construct the exact attestation an independently built Bello fork must ship.

    The release builder never writes this file itself.  Fork build/review tooling
    must commit it beside the fork payload, after which this function is useful
    for deterministic generation and tests.
    """

    if (
        len(fork_source_commit) != 40
        or any(character not in "0123456789abcdef" for character in fork_source_commit)
        or fork_source_commit == CONTEXT_MODE_COMMIT
    ):
        raise BundleBuildError("offline fork source commit must be a non-upstream lowercase Git commit")
    return {
        "schema_version": OFFLINE_FORK_ATTESTATION_VERSION,
        "attestation_type": OFFLINE_FORK_ID,
        "fork_revision": OFFLINE_FORK_REVISION,
        "fork_source_commit": fork_source_commit,
        "upstream_version": CONTEXT_MODE_VERSION,
        "upstream_commit": CONTEXT_MODE_COMMIT,
        "catalog_version": 1,
        "allowed_tools": list(ALLOWED_TOOLS),
        "tool_schema_digests": tool_schema_digests(checkout),
        "forbidden_tools": list(FORBIDDEN_TOOLS),
        "offline": True,
        "runtime_downloads": False,
        "runtime_installs": False,
        "runtime_updates": False,
        "network_routes": False,
        "payload_sha256": offline_fork_payload_digest(checkout),
    }


def _validate_offline_source_policy(checkout: Path) -> None:
    for path in _iter_fork_code_files(checkout):
        relative = path.relative_to(checkout).as_posix()
        # package.json is bound into the attestation, but its developer-only
        # build scripts are not a runtime/code surface shipped to a launcher.
        if relative == "package.json":
            continue
        payload = path.read_bytes()
        lowered = payload.lower()
        for forbidden in FORBIDDEN_TOOLS:
            if forbidden.encode("ascii") in lowered:
                raise BundleBuildError(
                    f"offline fork contains forbidden tool name {forbidden!r}: {relative}"
                )
        for rule_name, pattern in OFFLINE_SOURCE_RULES:
            if pattern.search(payload):
                raise BundleBuildError(f"offline fork violates {rule_name}: {relative}")


def _validate_offline_fork_attestation(checkout: Path, *, fork_source_commit: str) -> None:
    path = Path(checkout) / OFFLINE_FORK_ATTESTATION
    attestation = _load_json(path, "Bello offline-fork attestation")
    if path.read_bytes() != _canonical_json(attestation):
        raise BundleBuildError("Bello offline-fork attestation is not canonical deterministic JSON")
    expected = make_offline_fork_attestation(checkout, fork_source_commit=fork_source_commit)
    if attestation != expected:
        differing = sorted(
            key
            for key in set(attestation) | set(expected)
            if attestation.get(key) != expected.get(key)
        )
        raise BundleBuildError(
            "Bello offline-fork attestation does not match the pinned code/policy: "
            f"{differing}"
        )
    _validate_offline_source_policy(checkout)


def validate_context_source(
    checkout: Path,
    *,
    scratch_home: Path,
    platform_tag: str,
) -> None:
    checkout = Path(checkout)
    _lstat_directory(checkout, "Context Mode checkout")
    package = _load_json(checkout / "package.json", "Context Mode package.json")
    expected_metadata = {
        "name": "context-mode",
        "version": CONTEXT_MODE_VERSION,
        "license": CONTEXT_MODE_LICENSE,
    }
    mismatches = {
        key: package.get(key)
        for key, expected in expected_metadata.items()
        if package.get(key) != expected
    }
    if mismatches:
        raise BundleBuildError(f"Context Mode package metadata does not match release pins: {mismatches}")
    engines = package.get("engines")
    if not isinstance(engines, dict) or engines.get("node") != ">=22.5.0":
        raise BundleBuildError("Context Mode package must declare engines.node >=22.5.0")
    fork_source_commit = _git_head(checkout, scratch_home=scratch_home)
    if fork_source_commit == CONTEXT_MODE_COMMIT:
        raise BundleBuildError(
            "stock Context Mode upstream is forbidden; a versioned Bello offline fork is required"
        )
    if not _git_is_ancestor(
        checkout,
        ancestor=CONTEXT_MODE_COMMIT,
        descendant=fork_source_commit,
        scratch_home=scratch_home,
    ):
        raise BundleBuildError(
            f"Bello offline fork is not based on pinned upstream commit {CONTEXT_MODE_COMMIT}"
        )
    if PINNED_OFFLINE_FORK_COMMIT == "0" * 40:
        raise BundleBuildError(
            "reviewed Bello offline-fork commit pin is not configured for this release"
        )
    if fork_source_commit != PINNED_OFFLINE_FORK_COMMIT:
        raise BundleBuildError(
            "Context Mode checkout does not match the reviewed Bello offline-fork commit"
        )
    _require_clean_tracked_checkout(checkout, scratch_home=scratch_home)
    _validate_offline_fork_attestation(checkout, fork_source_commit=fork_source_commit)
    # Keep the native ABI payload check independent from the aggregate inventory
    # digest so a missing/duplicated binding is rejected with the precise release
    # invariant that was violated.
    _validate_native_dependency(checkout)
    expected_dependencies = PINNED_DEPENDENCY_INVENTORY_SHA256[platform_tag]
    if expected_dependencies == "0" * 64:
        raise BundleBuildError(
            f"reviewed dependency inventory pin is not configured for {platform_tag}"
        )
    actual_dependencies = _dependency_inventory_digest(checkout / "node_modules")
    if actual_dependencies != expected_dependencies:
        raise BundleBuildError(
            "Context Mode dependency inventory does not match the reviewed platform payload"
        )

    for relative in PACKAGE_FILES:
        _lstat_file(checkout / relative, f"Context Mode {relative}")
    for relative in PACKAGE_DIRECTORIES:
        _lstat_directory(checkout / relative, f"Context Mode {relative}")
    license_text = (checkout / "LICENSE").read_text(encoding="utf-8", errors="strict")
    if "Elastic License 2.0" not in license_text:
        raise BundleBuildError("Context Mode LICENSE is not Elastic License 2.0")


def _detected_host_platform() -> str:
    systems = {"linux": "linux", "darwin": "macos"}
    machines = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    system = host_platform.system().lower()
    machine = host_platform.machine().lower().replace(" ", "")
    try:
        return f"{systems[system]}-{machines[machine]}"
    except KeyError as exc:
        raise BundleBuildError(f"unsupported release host: {system}/{machine}") from exc


def _validate_platform(platform_tag: str, *, enforce_host_platform: bool) -> None:
    if platform_tag not in SUPPORTED_PLATFORMS:
        raise BundleBuildError(f"unsupported Context Mode bundle platform: {platform_tag!r}")
    if enforce_host_platform:
        detected = _detected_host_platform()
        if platform_tag != detected:
            raise BundleBuildError(
                f"target platform {platform_tag!r} does not match native release host {detected!r}"
            )


def _validate_node_tree(
    node_tree: Path,
    *,
    scratch_home: Path,
    platform_tag: str,
) -> Path:
    node_tree = Path(node_tree)
    _lstat_directory(node_tree, "Node tree")
    node_path = node_tree / "bin" / "node"
    _lstat_file(node_path, "Node executable", executable=True)
    _lstat_file(node_tree / "LICENSE", "Node LICENSE")
    result = _run((str(node_path), "--version"), cwd=node_tree, home=scratch_home)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise BundleBuildError(f"bundled Node version check failed: {detail}")
    if result.stdout.strip() != f"v{NODE_VERSION}":
        raise BundleBuildError(
            f"Node tree is {result.stdout.strip()!r}; Bello release requires 'v{NODE_VERSION}'"
        )
    expected_node = PINNED_NODE_BINARY_SHA256[platform_tag]
    if expected_node == "0" * 64 or PINNED_NODE_LICENSE_SHA256 == "0" * 64:
        raise BundleBuildError(f"reviewed Node distribution pins are not configured for {platform_tag}")
    if _sha256(node_path) != expected_node or _sha256(node_tree / "LICENSE") != PINNED_NODE_LICENSE_SHA256:
        raise BundleBuildError("Node distribution bytes do not match the reviewed release pins")
    return node_path


def _validate_authority_source(authority_source: Path) -> Path:
    """Require the exact signed native-authority input layout.

    Signature semantics belong to the production native verifier.  The bundle
    builder nevertheless refuses partial, extensible, symlinked, empty, or
    non-executable authority payloads before copying their opaque bytes.
    """

    root = Path(authority_source)
    _lstat_directory(root, "signed native authority source")
    expected_root = {
        "bin",
        "LICENSE",
        "authority.json",
        "authority.sig",
        "release-public-key.pem",
    }
    actual_root = {entry.name for entry in root.iterdir()}
    if actual_root != expected_root:
        raise BundleBuildError(
            "signed native authority root layout mismatch: "
            f"expected {sorted(expected_root)}, got {sorted(actual_root)}"
        )
    bin_root = root / "bin"
    _lstat_directory(bin_root, "signed native authority bin directory")
    expected_bin = {"bello-context-broker", "bello-context-launcher"}
    actual_bin = {entry.name for entry in bin_root.iterdir()}
    if actual_bin != expected_bin:
        raise BundleBuildError(
            "signed native authority bin layout mismatch: "
            f"expected {sorted(expected_bin)}, got {sorted(actual_bin)}"
        )
    for relative in AUTHORITY_FILES:
        path = root / relative
        _lstat_file(
            path,
            f"signed native authority {relative}",
            executable=relative in AUTHORITY_EXECUTABLES,
        )
        if path.lstat().st_size <= 0:
            raise BundleBuildError(f"signed native authority file is empty: {relative}")
    return root


def _normalize_path(path: Path, *, mode: int, epoch: int) -> None:
    os.chmod(path, mode, follow_symlinks=False)
    os.utime(path, (epoch, epoch), follow_symlinks=False)


def _copy_file(source: Path, destination: Path, *, epoch: int, force_executable: bool = False) -> None:
    resolved = source.resolve(strict=True)
    info = resolved.stat()
    if not stat.S_ISREG(info.st_mode):
        raise BundleBuildError(f"bundle input is not a regular file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with resolved.open("rb") as reader, destination.open("xb") as writer:
        shutil.copyfileobj(reader, writer, length=1024 * 1024)
    executable = force_executable or bool(info.st_mode & 0o111)
    _normalize_path(destination, mode=0o755 if executable else 0o644, epoch=epoch)


def _copy_tree(
    source: Path,
    destination: Path,
    *,
    source_root: Path,
    epoch: int,
    ancestors: frozenset[Path] = frozenset(),
) -> None:
    """Copy a tree deterministically, dereferencing only in-root symlinks."""

    resolved = source.resolve(strict=True)
    root_resolved = source_root.resolve(strict=True)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise BundleBuildError(f"bundle input symlink escapes source root: {source}") from exc
    if resolved in ancestors:
        raise BundleBuildError(f"bundle input contains a symlink cycle: {source}")
    if not resolved.is_dir():
        raise BundleBuildError(f"bundle input is not a directory: {source}")
    destination.mkdir(parents=True, exist_ok=False)
    next_ancestors = ancestors | {resolved}
    for child in sorted(resolved.iterdir(), key=lambda item: item.name.encode("utf-8")):
        target = child.resolve(strict=True)
        try:
            target.relative_to(root_resolved)
        except ValueError as exc:
            raise BundleBuildError(f"bundle input symlink escapes source root: {child}") from exc
        output = destination / child.name
        info = target.stat()
        if stat.S_ISDIR(info.st_mode):
            _copy_tree(
                child,
                output,
                source_root=source_root,
                epoch=epoch,
                ancestors=next_ancestors,
            )
        elif stat.S_ISREG(info.st_mode):
            _copy_file(child, output, epoch=epoch)
        else:
            raise BundleBuildError(f"unsupported bundle input file type: {child}")
    _normalize_path(destination, mode=0o755, epoch=epoch)


def _iter_payload_files(root: Path) -> Iterable[tuple[Path, str]]:
    """Yield every payload file and its canonical manifest key."""

    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise BundleBuildError(f"bundle must not contain symlinks: {relative.as_posix()}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise BundleBuildError(f"bundle contains unsupported file type: {relative.as_posix()}")
        posix = relative.as_posix()
        if posix in {MANIFEST_NAME, MANIFEST_DIGEST_NAME}:
            continue
        if posix == "node/bin/node":
            key = "node"
        elif posix == "package/server.bundle.mjs":
            key = "server.bundle.mjs"
        else:
            key = posix
        yield path, key


def _native_fts5_smoke(node_path: Path, package_root: Path, *, scratch_home: Path) -> None:
    script = r"""
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
const require = createRequire(pathToFileURL(process.argv[1]));
const DatabaseModule = require('better-sqlite3');
const Database = DatabaseModule.default ?? DatabaseModule;
const db = new Database(':memory:');
db.exec("CREATE VIRTUAL TABLE bello_docs USING fts5(content); INSERT INTO bello_docs(content) VALUES ('offline context');");
const result = db.prepare("SELECT count(*) AS count FROM bello_docs WHERE bello_docs MATCH 'context'").get();
db.close();
if (!result || result.count !== 1) throw new Error('FTS5 smoke result mismatch');
""".strip()
    result = _run(
        (str(node_path), "--input-type=module", "--eval", script, str(package_root / "package.json")),
        cwd=package_root,
        home=scratch_home,
        timeout_seconds=60.0,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise BundleBuildError(f"better-sqlite3/FTS5 native smoke failed: {detail}")


def _validate_native_dependency(package_root: Path) -> None:
    dependency_root = package_root / "node_modules" / "better-sqlite3"
    metadata = _load_json(dependency_root / "package.json", "bundled better-sqlite3 package.json")
    if metadata.get("name") != "better-sqlite3" or metadata.get("version") != BETTER_SQLITE3_VERSION:
        raise BundleBuildError(
            f"bundled better-sqlite3 must be exactly {BETTER_SQLITE3_VERSION} from the pinned lockfile"
        )
    bindings = [
        path
        for path in dependency_root.rglob("*.node")
        if path.is_file() and not path.is_symlink()
    ]
    if len(bindings) != 1:
        raise BundleBuildError(
            "bundled better-sqlite3 must contain exactly one native .node binding "
            f"(found {len(bindings)})"
        )


def _validate_manifest_shape(value: Mapping[str, object], expected_platform: str) -> Mapping[str, str]:
    expected_keys = {
        "schema_version",
        "bello_offline_fork_revision",
        "bello_offline_fork_attestation_sha256",
        "context_mode_commit",
        "context_mode_version",
        "node_version",
        "platform",
        "files",
    }
    if set(value) != expected_keys:
        raise BundleBuildError(
            f"manifest fields differ from schema: expected {sorted(expected_keys)}, got {sorted(value)}"
        )
    pinned = {
        "schema_version": SCHEMA_VERSION,
        "bello_offline_fork_revision": OFFLINE_FORK_REVISION,
        "context_mode_commit": CONTEXT_MODE_COMMIT,
        "context_mode_version": CONTEXT_MODE_VERSION,
        "node_version": NODE_VERSION,
        "platform": expected_platform,
    }
    mismatches = {key: value.get(key) for key, expected in pinned.items() if value.get(key) != expected}
    if mismatches:
        raise BundleBuildError(f"manifest does not match Bello release pins: {mismatches}")
    attestation_digest = value.get("bello_offline_fork_attestation_sha256")
    if (
        not isinstance(attestation_digest, str)
        or len(attestation_digest) != 64
        or any(character not in "0123456789abcdef" for character in attestation_digest)
    ):
        raise BundleBuildError("manifest Bello offline-fork attestation digest is invalid")
    files = value.get("files")
    if not isinstance(files, dict) or not files:
        raise BundleBuildError("manifest files must be a non-empty object")
    normalized: dict[str, str] = {}
    for key, digest in files.items():
        if not isinstance(key, str) or not isinstance(digest, str):
            raise BundleBuildError("manifest file names and digests must be strings")
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise BundleBuildError(f"invalid SHA-256 for manifest entry {key!r}")
        path = PurePosixPath(key)
        if key not in {"node", "server.bundle.mjs"}:
            if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
                raise BundleBuildError(f"unsafe manifest path: {key!r}")
            if not path.parts or path.parts[0] not in {"node", "package", "authority"}:
                raise BundleBuildError(f"manifest path lies outside bundle roots: {key!r}")
        normalized[key] = digest
    missing_required = REQUIRED_RUNTIME_FILES - frozenset(normalized)
    if missing_required:
        raise BundleBuildError(
            "manifest omits required runtime entries: "
            f"{sorted(missing_required)}"
        )
    return normalized


def verify_bundle(
    root: Path,
    *,
    expected_platform: str,
    enforce_host_platform: bool = True,
    run_native_smoke: bool = True,
) -> VerifiedBundle:
    root = Path(root)
    _validate_platform(expected_platform, enforce_host_platform=enforce_host_platform)
    _lstat_directory(root, "Context Mode bundle")
    root_entries = {entry.name for entry in root.iterdir()}
    expected_root_entries = {
        "node",
        "package",
        "authority",
        MANIFEST_NAME,
        MANIFEST_DIGEST_NAME,
    }
    if root_entries != expected_root_entries:
        raise BundleBuildError(
            "bundle root layout mismatch: "
            f"expected {sorted(expected_root_entries)}, got {sorted(root_entries)}"
        )
    _lstat_directory(root / "node", "bundled Node directory")
    _lstat_directory(root / "package", "bundled Context Mode package directory")
    authority_root = _validate_authority_source(root / "authority")
    node_entries = {entry.name for entry in (root / "node").iterdir()}
    if node_entries != {"bin", "LICENSE"}:
        raise BundleBuildError(f"bundled Node layout mismatch: {sorted(node_entries)}")
    _lstat_directory(root / "node" / "bin", "bundled Node bin directory")
    if {entry.name for entry in (root / "node" / "bin").iterdir()} != {"node"}:
        raise BundleBuildError("bundled Node bin directory must contain only the pinned node executable")
    _lstat_file(root / "node" / "LICENSE", "bundled Node LICENSE")
    package_root = root / "package"
    expected_package_entries = set(PACKAGE_FILES) | set(PACKAGE_DIRECTORIES)
    package_entries = {entry.name for entry in package_root.iterdir()}
    if package_entries != expected_package_entries:
        raise BundleBuildError(
            "bundled Context Mode layout mismatch: "
            f"expected {sorted(expected_package_entries)}, got {sorted(package_entries)}"
        )
    for relative in PACKAGE_FILES:
        _lstat_file(package_root / relative, f"bundled Context Mode {relative}")
    for relative in PACKAGE_DIRECTORIES:
        _lstat_directory(package_root / relative, f"bundled Context Mode {relative}")
    manifest_path = root / MANIFEST_NAME
    digest_path = root / MANIFEST_DIGEST_NAME
    manifest = _load_json(manifest_path, "Context Mode manifest")
    canonical = _canonical_json(manifest)
    if manifest_path.read_bytes() != canonical:
        raise BundleBuildError("manifest.json is not canonical deterministic JSON")
    _lstat_file(digest_path, "Context Mode manifest digest")
    expected_digest_record = f"{hashlib.sha256(canonical).hexdigest()}  {MANIFEST_NAME}\n"
    if digest_path.read_text(encoding="ascii", errors="strict") != expected_digest_record:
        raise BundleBuildError("manifest.sha256 does not match canonical manifest.json")
    manifest_files = _validate_manifest_shape(manifest, expected_platform)
    payload = {key: path for path, key in _iter_payload_files(root)}
    if set(payload) != set(manifest_files):
        missing = sorted(set(payload) - set(manifest_files))
        stale = sorted(set(manifest_files) - set(payload))
        raise BundleBuildError(f"manifest coverage mismatch: unlisted={missing}, missing={stale}")
    for key, path in payload.items():
        actual = _sha256(path)
        if actual != manifest_files[key]:
            raise BundleBuildError(
                f"SHA-256 mismatch for {path.relative_to(root).as_posix()}: "
                f"expected {manifest_files[key]}, got {actual}"
            )
    node_path = payload["node"]
    server_entrypoint = payload["server.bundle.mjs"]
    _lstat_file(node_path, "bundled Node executable", executable=True)
    expected_node = PINNED_NODE_BINARY_SHA256[expected_platform]
    expected_dependencies = PINNED_DEPENDENCY_INVENTORY_SHA256[expected_platform]
    if (
        expected_node == "0" * 64
        or PINNED_NODE_LICENSE_SHA256 == "0" * 64
        or expected_dependencies == "0" * 64
    ):
        raise BundleBuildError(
            f"reviewed Node/dependency release pins are not configured for {expected_platform}"
        )
    if (
        _sha256(node_path) != expected_node
        or _sha256(root / "node" / "LICENSE") != PINNED_NODE_LICENSE_SHA256
    ):
        raise BundleBuildError("bundled Node bytes do not match the reviewed release pins")
    if _dependency_inventory_digest(package_root / "node_modules") != expected_dependencies:
        raise BundleBuildError(
            "bundled dependency inventory does not match the reviewed platform payload"
        )
    package = _load_json(package_root / "package.json", "bundled Context Mode package.json")
    if package.get("version") != CONTEXT_MODE_VERSION or package.get("license") != CONTEXT_MODE_LICENSE:
        raise BundleBuildError("bundled package.json does not match Context Mode release pins")
    license_text = (package_root / "LICENSE").read_text(encoding="utf-8", errors="strict")
    if "Elastic License 2.0" not in license_text:
        raise BundleBuildError("bundled Context Mode LICENSE is not Elastic License 2.0")
    attestation = _load_json(
        package_root / OFFLINE_FORK_ATTESTATION,
        "bundled Bello offline-fork attestation",
    )
    fork_source_commit = attestation.get("fork_source_commit")
    if not isinstance(fork_source_commit, str):
        raise BundleBuildError("bundled Bello offline-fork attestation has no source commit")
    _validate_offline_fork_attestation(package_root, fork_source_commit=fork_source_commit)
    if _sha256(package_root / OFFLINE_FORK_ATTESTATION) != manifest[
        "bello_offline_fork_attestation_sha256"
    ]:
        raise BundleBuildError("manifest offline-fork attestation digest does not match payload")
    _validate_native_dependency(package_root)
    if run_native_smoke:
        with tempfile.TemporaryDirectory(prefix="bello-context-verify-") as temp_home:
            home = Path(temp_home)
            version = _run((str(node_path), "--version"), cwd=package_root, home=home)
            if version.returncode != 0 or version.stdout.strip() != f"v{NODE_VERSION}":
                detail = version.stderr.strip() or version.stdout.strip() or f"exit {version.returncode}"
                raise BundleBuildError(f"bundled Node version check failed: {detail}")
            _native_fts5_smoke(node_path, package_root, scratch_home=home)
    return VerifiedBundle(
        root=root,
        platform=expected_platform,
        manifest_path=manifest_path,
        manifest_digest_path=digest_path,
        node_path=node_path,
        server_entrypoint=server_entrypoint,
        authority_root=authority_root,
        file_count=len(payload),
    )


def _write_manifest(bundle_root: Path, *, platform_tag: str, epoch: int) -> None:
    files = {key: _sha256(path) for path, key in _iter_payload_files(bundle_root)}
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "bello_offline_fork_revision": OFFLINE_FORK_REVISION,
        "bello_offline_fork_attestation_sha256": _sha256(
            bundle_root / "package" / OFFLINE_FORK_ATTESTATION
        ),
        "context_mode_commit": CONTEXT_MODE_COMMIT,
        "context_mode_version": CONTEXT_MODE_VERSION,
        "node_version": NODE_VERSION,
        "platform": platform_tag,
        "files": files,
    }
    content = _canonical_json(manifest)
    manifest_path = bundle_root / MANIFEST_NAME
    manifest_path.write_bytes(content)
    _normalize_path(manifest_path, mode=0o644, epoch=epoch)
    digest_path = bundle_root / MANIFEST_DIGEST_NAME
    digest_path.write_text(
        f"{hashlib.sha256(content).hexdigest()}  {MANIFEST_NAME}\n",
        encoding="ascii",
        newline="\n",
    )
    _normalize_path(digest_path, mode=0o644, epoch=epoch)
    _normalize_path(bundle_root, mode=0o755, epoch=epoch)


def build_bundle(
    *,
    context_source: Path,
    node_tree: Path,
    authority_source: Path,
    output: Path,
    platform_tag: str,
    source_date_epoch: int = DEFAULT_SOURCE_DATE_EPOCH,
    enforce_host_platform: bool = True,
    run_native_smoke: bool = True,
) -> VerifiedBundle:
    output = Path(output)
    if source_date_epoch < 0:
        raise BundleBuildError("SOURCE_DATE_EPOCH must be non-negative")
    _validate_platform(platform_tag, enforce_host_platform=enforce_host_platform)
    if output.exists() or output.is_symlink():
        raise BundleBuildError(f"output already exists; refusing to overwrite: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    _lstat_directory(output.parent, "bundle output parent")

    temporary_root = Path(tempfile.mkdtemp(prefix=".bello-context-bundle-", dir=output.parent))
    staging = temporary_root / "bundle"
    scratch_home = temporary_root / "home"
    staging.mkdir(mode=0o755)
    scratch_home.mkdir(mode=0o700)
    published = False
    try:
        validate_context_source(
            Path(context_source),
            scratch_home=scratch_home,
            platform_tag=platform_tag,
        )
        source_node = _validate_node_tree(
            Path(node_tree),
            scratch_home=scratch_home,
            platform_tag=platform_tag,
        )
        source_authority = _validate_authority_source(Path(authority_source))
        node_root = staging / "node"
        package_root = staging / "package"
        authority_root = staging / "authority"
        node_root.mkdir(mode=0o755)
        package_root.mkdir(mode=0o755)
        authority_root.mkdir(mode=0o755)
        (node_root / "bin").mkdir(mode=0o755)
        (authority_root / "bin").mkdir(mode=0o755)
        _copy_file(source_node, node_root / "bin" / "node", epoch=source_date_epoch, force_executable=True)
        _copy_file(Path(node_tree) / "LICENSE", node_root / "LICENSE", epoch=source_date_epoch)
        for relative in PACKAGE_FILES:
            _copy_file(Path(context_source) / relative, package_root / relative, epoch=source_date_epoch)
        for relative in PACKAGE_DIRECTORIES:
            _copy_tree(
                Path(context_source) / relative,
                package_root / relative,
                source_root=Path(context_source),
                epoch=source_date_epoch,
            )
        for relative in AUTHORITY_FILES:
            _copy_file(
                source_authority / relative,
                authority_root / relative,
                epoch=source_date_epoch,
                force_executable=relative in AUTHORITY_EXECUTABLES,
            )
        for directory in (
            node_root / "bin",
            node_root,
            package_root,
            authority_root / "bin",
            authority_root,
        ):
            _normalize_path(directory, mode=0o755, epoch=source_date_epoch)
        _write_manifest(staging, platform_tag=platform_tag, epoch=source_date_epoch)
        verify_bundle(
            staging,
            expected_platform=platform_tag,
            enforce_host_platform=enforce_host_platform,
            run_native_smoke=run_native_smoke,
        )
        staging.rename(output)
        published = True
        return verify_bundle(
            output,
            expected_platform=platform_tag,
            enforce_host_platform=enforce_host_platform,
            run_native_smoke=run_native_smoke,
        )
    except Exception:
        if published and output.exists():
            shutil.rmtree(output)
        raise
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)


def create_reproducible_archive(bundle_root: Path, archive_path: Path, *, epoch: int) -> Path:
    bundle_root = Path(bundle_root)
    archive_path = Path(archive_path)
    _lstat_directory(bundle_root, "Context Mode bundle")
    if archive_path.exists() or archive_path.is_symlink():
        raise BundleBuildError(f"archive already exists; refusing to overwrite: {archive_path}")
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = archive_path.parent / f".{archive_path.name}.tmp"
    if temporary.exists() or temporary.is_symlink():
        raise BundleBuildError(f"temporary archive path already exists: {temporary}")
    try:
        with temporary.open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                    entries = [bundle_root, *sorted(bundle_root.rglob("*"), key=lambda p: p.relative_to(bundle_root).as_posix())]
                    for source in entries:
                        relative = source.relative_to(bundle_root) if source != bundle_root else Path()
                        archive_name = PurePosixPath("context_mode", *relative.parts).as_posix()
                        info = source.lstat()
                        member = tarfile.TarInfo(archive_name)
                        member.uid = 0
                        member.gid = 0
                        member.uname = ""
                        member.gname = ""
                        member.mtime = epoch
                        if stat.S_ISDIR(info.st_mode):
                            member.type = tarfile.DIRTYPE
                            member.mode = 0o755
                            member.size = 0
                            archive.addfile(member)
                        elif stat.S_ISREG(info.st_mode):
                            member.type = tarfile.REGTYPE
                            member.mode = stat.S_IMODE(info.st_mode)
                            member.size = info.st_size
                            with source.open("rb") as stream:
                                archive.addfile(member, stream)
                        else:
                            raise BundleBuildError(f"cannot archive unsupported file type: {source}")
        temporary.rename(archive_path)
        return archive_path
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    build = subcommands.add_parser("build", help="build and verify a platform bundle")
    build.add_argument("--context-source", type=Path, required=True)
    build.add_argument("--node-tree", type=Path, required=True)
    build.add_argument("--authority-source", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--platform", choices=SUPPORTED_PLATFORMS, required=True)
    build.add_argument("--source-date-epoch", type=int, default=DEFAULT_SOURCE_DATE_EPOCH)
    build.add_argument("--archive", type=Path)
    verify = subcommands.add_parser("verify", help="verify hashes, pins, Node, and native FTS5")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--platform", choices=SUPPORTED_PLATFORMS, required=True)
    verify.add_argument(
        "--static-only",
        action="store_true",
        help="verify content without executing a foreign-platform Node binary",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "build":
            verified = build_bundle(
                context_source=args.context_source,
                node_tree=args.node_tree,
                authority_source=args.authority_source,
                output=args.output,
                platform_tag=args.platform,
                source_date_epoch=args.source_date_epoch,
            )
            if args.archive:
                create_reproducible_archive(
                    verified.root,
                    args.archive,
                    epoch=args.source_date_epoch,
                )
        else:
            verified = verify_bundle(
                args.bundle,
                expected_platform=args.platform,
                enforce_host_platform=not args.static_only,
                run_native_smoke=not args.static_only,
            )
    except BundleBuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "bundle": str(verified.root),
                "files": verified.file_count,
                "platform": verified.platform,
                "release_ready": False,
                "worker_bundle_verified": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
