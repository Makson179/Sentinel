#!/usr/bin/env python3
"""Fail-closed audit for Context Mode native release authority.

The Python policy model and the Node worker bundle are not a native sandbox.
A releasable platform wheel additionally needs a signed broker/launcher payload,
an implementation that verifies and loads it, and controller wiring that
constructs that implementation.  This audit intentionally blocks artifact
assembly until those concrete pieces exist; it has no override or "unsafe"
mode.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

# Direct script execution sets ``sys.path[0]`` to ``scripts/`` rather than the
# checkout root.  The release workflow invokes this file directly, so make the
# in-tree ``supervisor`` package importable before loading either the builder or
# the production native adapter.  This is a deterministic local import only;
# no ambient PYTHONPATH or installed Bello package is trusted.
CHECKOUT_ROOT = Path(__file__).resolve().parents[1]
if str(CHECKOUT_ROOT) not in sys.path:
    sys.path.insert(0, str(CHECKOUT_ROOT))

try:
    from scripts.build_context_mode_bundle import (
        PINNED_DEPENDENCY_INVENTORY_SHA256,
        PINNED_NODE_BINARY_SHA256,
        PINNED_NODE_LICENSE_SHA256,
        PINNED_OFFLINE_FORK_COMMIT,
        SUPPORTED_PLATFORMS,
    )
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from build_context_mode_bundle import (  # type: ignore[no-redef]
        PINNED_DEPENDENCY_INVENTORY_SHA256,
        PINNED_NODE_BINARY_SHA256,
        PINNED_NODE_LICENSE_SHA256,
        PINNED_OFFLINE_FORK_COMMIT,
        SUPPORTED_PLATFORMS,
    )


NATIVE_ADAPTER_MODULE = Path("supervisor/context_mode/native_release.py")
SIGNED_AUTHORITY_CONTRACT = Path("supervisor/context_mode/native-release.json")
REQUIRED_ADAPTER_SYMBOLS = (
    "verify_signed_native_authority",
    "load_bundled_native_runtime",
)
REQUIRED_AUTHORITY_FILES = (
    "bin/bello-context-broker",
    "bin/bello-context-launcher",
    "LICENSE",
    "authority.json",
    "authority.sig",
    "release-public-key.pem",
)


class ReleaseReadinessError(RuntimeError):
    """The repository cannot honestly produce a functional Context Mode wheel."""


@dataclass(frozen=True)
class ReleaseReadiness:
    project_root: Path
    platforms: tuple[str, ...]
    blockers: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.blockers

    def require_ready(self) -> None:
        if self.blockers:
            raise ReleaseReadinessError("; ".join(self.blockers))


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _parsed_source(path: Path, description: str, blockers: list[str]) -> ast.Module | None:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        blockers.append(f"{description} cannot be parsed: {type(exc).__name__}")
        return None


def _assigned_literal(module: ast.Module, name: str) -> object | None:
    for statement in module.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in statement.targets
        ):
            try:
                return ast.literal_eval(statement.value)
            except (ValueError, TypeError):
                value = statement.value
                if (
                    isinstance(value, ast.BinOp)
                    and isinstance(value.op, ast.Mult)
                    and isinstance(value.left, ast.Constant)
                    and isinstance(value.left.value, str)
                    and isinstance(value.right, ast.Constant)
                    and isinstance(value.right.value, int)
                ):
                    return value.left.value * value.right.value
                if (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Name)
                    and value.func.id == "frozenset"
                    and len(value.args) == 1
                    and not value.keywords
                ):
                    try:
                        return frozenset(ast.literal_eval(value.args[0]))
                    except (ValueError, TypeError):
                        return None
                return None
    return None


def audit_release_readiness(
    project_root: Path,
    *,
    platforms: Sequence[str] = SUPPORTED_PLATFORMS,
    authority_roots: Mapping[str, Path] | None = None,
) -> ReleaseReadiness:
    root = Path(project_root).resolve(strict=True)
    selected = tuple(platforms)
    unknown = sorted(set(selected) - set(SUPPORTED_PLATFORMS))
    if unknown:
        raise ReleaseReadinessError(f"unsupported release platforms: {unknown}")
    blockers: list[str] = []
    if PINNED_OFFLINE_FORK_COMMIT == "0" * 40:
        blockers.append("reviewed Bello offline-fork commit pin is not configured")
    for platform_tag in selected:
        if (
            PINNED_NODE_BINARY_SHA256.get(platform_tag) == "0" * 64
            or PINNED_DEPENDENCY_INVENTORY_SHA256.get(platform_tag) == "0" * 64
        ):
            blockers.append(f"{platform_tag} reviewed Node/dependency hashes are not configured")
    if PINNED_NODE_LICENSE_SHA256 == "0" * 64:
        blockers.append("reviewed Node license hash is not configured")

    adapter_path = root / NATIVE_ADAPTER_MODULE
    contract_path = root / SIGNED_AUTHORITY_CONTRACT
    adapter_module: object | None = None
    if not adapter_path.is_file() or adapter_path.is_symlink():
        blockers.append(
            "production native broker adapter is absent "
            f"({NATIVE_ADAPTER_MODULE.as_posix()})"
        )
    else:
        spec = importlib.util.spec_from_file_location("_bello_native_release_audit", adapter_path)
        if spec is None or spec.loader is None:
            blockers.append("production native broker adapter cannot be imported")
        else:
            module = importlib.util.module_from_spec(spec)
            try:
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
            except Exception as exc:
                blockers.append(f"production native broker adapter import failed: {type(exc).__name__}")
            else:
                missing = [name for name in REQUIRED_ADAPTER_SYMBOLS if not callable(getattr(module, name, None))]
                if missing:
                    blockers.append(f"production native broker adapter omits required entrypoints: {missing}")
                else:
                    adapter_module = module
            finally:
                sys.modules.pop(spec.name, None)

    contract: object | None = None
    if not contract_path.is_file() or contract_path.is_symlink():
        blockers.append(
            "signed native authority release contract is absent "
            f"({SIGNED_AUTHORITY_CONTRACT.as_posix()})"
        )
    else:
        try:
            raw = contract_path.read_bytes()
            contract = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            blockers.append(f"signed native authority release contract is invalid: {type(exc).__name__}")
        else:
            if not isinstance(contract, dict) or raw != _canonical_json(contract):
                blockers.append("signed native authority release contract is not canonical JSON")
                contract = None

    platform_records: object = contract.get("platforms") if isinstance(contract, dict) else None
    if isinstance(contract, dict):
        if contract.get("schema_version") != 1:
            blockers.append("signed native authority contract schema_version is not 1")
        if contract.get("signature_algorithm") != "Ed25519":
            blockers.append("signed native authority contract is not pinned to Ed25519")
        if not isinstance(platform_records, dict):
            blockers.append("signed native authority contract has no platform map")

    for platform_tag in selected:
        authority_root = Path(
            (authority_roots or {}).get(
                platform_tag,
                root
                / "supervisor"
                / "_vendor"
                / "context_mode"
                / platform_tag
                / "authority",
            )
        )
        missing_files = [relative for relative in REQUIRED_AUTHORITY_FILES if not (authority_root / relative).is_file()]
        if missing_files:
            blockers.append(f"{platform_tag} signed native authority payload is incomplete: {missing_files}")
        if isinstance(platform_records, dict) and platform_tag not in platform_records:
            blockers.append(f"signed native authority contract omits {platform_tag}")
        if isinstance(platform_records, dict) and platform_tag in platform_records:
            record = platform_records[platform_tag]
            if not isinstance(record, dict) or frozenset(record) != {
                "authority_manifest_sha256",
                "release_public_key_sha256",
            }:
                blockers.append(f"{platform_tag} native authority release pins are malformed")
            elif any(
                not isinstance(record[field], str)
                or len(record[field]) != 64
                or record[field] == "0" * 64
                for field in ("authority_manifest_sha256", "release_public_key_sha256")
            ):
                blockers.append(f"{platform_tag} native authority release pins are not configured")
        if not missing_files and adapter_module is not None and contract is not None:
            verifier = getattr(adapter_module, "verify_signed_native_authority")
            try:
                result = verifier(
                    authority_root=authority_root,
                    contract_path=contract_path,
                    platform_tag=platform_tag,
                )
            except Exception as exc:
                blockers.append(
                    f"{platform_tag} native authority signature verification failed: "
                    f"{type(exc).__name__}"
                )
            else:
                if not isinstance(result, Mapping) or result.get("signature_verified") is not True:
                    blockers.append(
                        f"{platform_tag} native authority verifier returned no positive signature proof"
                    )

    builder_tree = _parsed_source(
        root / "scripts" / "build_context_mode_bundle.py",
        "release bundle builder",
        blockers,
    )
    if builder_tree is not None:
        build_function = next(
            (
                node
                for node in builder_tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "build_bundle"
            ),
            None,
        )
        required_kwonly = False
        if build_function is not None:
            for argument, default in zip(
                build_function.args.kwonlyargs,
                build_function.args.kw_defaults,
                strict=True,
            ):
                if argument.arg == "authority_source" and default is None:
                    required_kwonly = True
        if not required_kwonly:
            blockers.append("release bundle builder does not require authority_source")
        authority_files = _assigned_literal(builder_tree, "AUTHORITY_FILES")
        if not isinstance(authority_files, tuple) or tuple(authority_files) != REQUIRED_AUTHORITY_FILES:
            blockers.append("release bundle builder native authority catalogue is not exact")

    packaging_tree = _parsed_source(
        root / "supervisor" / "context_mode" / "packaging.py",
        "runtime bundle loader",
        blockers,
    )
    if packaging_tree is not None:
        required_files = _assigned_literal(packaging_tree, "REQUIRED_RUNTIME_FILES")
        required_authority = {f"authority/{relative}" for relative in REQUIRED_AUTHORITY_FILES}
        if not isinstance(required_files, frozenset) or not required_authority.issubset(required_files):
            blockers.append("runtime bundle loader does not require the exact native authority payload")
        runtime_fork_pin = _assigned_literal(packaging_tree, "PINNED_OFFLINE_FORK_COMMIT")
        if runtime_fork_pin != PINNED_OFFLINE_FORK_COMMIT or runtime_fork_pin == "0" * 40:
            blockers.append("runtime loader reviewed offline-fork commit pin is absent or inconsistent")
        verifier = next(
            (
                node
                for node in packaging_tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "verify_runtime_bundle"
            ),
            None,
        )
        referenced = {
            node.id for node in ast.walk(verifier) if isinstance(node, ast.Name)
        } if verifier is not None else set()
        if not {
            "PINNED_NODE_BINARY_SHA256",
            "PINNED_NODE_LICENSE_SHA256",
            "PINNED_DEPENDENCY_INVENTORY_SHA256",
        }.issubset(referenced):
            blockers.append("runtime loader does not enforce reviewed Node/dependency hashes")

    controller_tree = _parsed_source(
        root / "supervisor" / "controller.py",
        "Controller source",
        blockers,
    )
    if controller_tree is not None and not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "load_bundled_native_runtime"
        for node in ast.walk(controller_tree)
    ):
        blockers.append("Controller does not call the verified bundled native runtime loader")

    return ReleaseReadiness(root, selected, tuple(blockers))


def require_release_readiness(
    project_root: Path,
    *,
    platforms: Sequence[str] = SUPPORTED_PLATFORMS,
    authority_roots: Mapping[str, Path] | None = None,
) -> ReleaseReadiness:
    readiness = audit_release_readiness(
        project_root,
        platforms=platforms,
        authority_roots=authority_roots,
    )
    readiness.require_ready()
    return readiness


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--platform", action="append", choices=SUPPORTED_PLATFORMS)
    parser.add_argument(
        "--authority-root",
        type=Path,
        help="signed authority root for a single selected platform",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        platforms = tuple(args.platform or SUPPORTED_PLATFORMS)
        if args.authority_root is not None and len(platforms) != 1:
            raise ReleaseReadinessError("--authority-root requires exactly one --platform")
        authority_roots = (
            {platforms[0]: args.authority_root}
            if args.authority_root is not None
            else None
        )
        readiness = audit_release_readiness(
            args.project_root,
            platforms=platforms,
            authority_roots=authority_roots,
        )
    except (OSError, ReleaseReadinessError) as exc:
        print(json.dumps({"ready": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(
        json.dumps(
            {
                "blockers": list(readiness.blockers),
                "platforms": list(readiness.platforms),
                "ready": readiness.ready,
            },
            sort_keys=True,
        )
    )
    return 0 if readiness.ready else 2


if __name__ == "__main__":
    raise SystemExit(main())
