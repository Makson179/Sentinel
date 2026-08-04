#!/usr/bin/env python3
"""Assemble and verify Bello wheels containing a native Context Mode bundle.

This is deliberately a wheel assembler, not a filename retagger.  It starts
from Bello's freshly built ``py3-none-any`` wheel, embeds one independently
verified platform bundle, changes the wheel metadata to a platform-specific
tag, and regenerates ``RECORD`` over the complete result.  Verification then
extracts the embedded bundle and re-runs the release bundle verifier.

The script performs no downloads and never invokes npm or a system Node.
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import hashlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence

try:
    from scripts.build_context_mode_bundle import (
        DEFAULT_SOURCE_DATE_EPOCH,
        SUPPORTED_PLATFORMS,
        BundleBuildError,
        verify_bundle,
    )
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from build_context_mode_bundle import (  # type: ignore[no-redef]
        DEFAULT_SOURCE_DATE_EPOCH,
        SUPPORTED_PLATFORMS,
        BundleBuildError,
        verify_bundle,
    )

try:
    from scripts.verify_context_mode_release_readiness import (
        ReleaseReadinessError,
        require_release_readiness,
    )
except ModuleNotFoundError:  # Direct execution from the scripts directory.
    from verify_context_mode_release_readiness import (  # type: ignore[no-redef]
        ReleaseReadinessError,
        require_release_readiness,
    )


PLATFORM_WHEEL_TAGS: Mapping[str, str] = {
    "linux-x86_64": "py3-none-linux_x86_64",
    "linux-arm64": "py3-none-linux_aarch64",
    "macos-x86_64": "py3-none-macosx_10_15_x86_64",
    "macos-arm64": "py3-none-macosx_11_0_arm64",
}
VENDOR_ROOT = PurePosixPath("supervisor/_vendor/context_mode")
RECORD_HASH = "sha256"


class WheelBuildError(RuntimeError):
    """A base wheel, native bundle, or assembled wheel is invalid."""


@dataclass(frozen=True)
class WheelMember:
    data: bytes
    mode: int


@dataclass(frozen=True)
class WheelLayout:
    members: Mapping[str, WheelMember]
    dist_info: str
    distribution: str
    version: str
    filename_distribution: str
    filename_version: str


@dataclass(frozen=True)
class VerifiedWheel:
    path: Path
    platform: str
    wheel_tag: str
    embedded_files: int


def _safe_member_name(name: str) -> str:
    if not name or "\\" in name or "\x00" in name or name.startswith("/"):
        raise WheelBuildError(f"unsafe wheel member path: {name!r}")
    if name.endswith("/") or "//" in name:
        raise WheelBuildError(f"wheel must contain regular files only: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise WheelBuildError(f"unsafe wheel member path: {name!r}")
    if path.as_posix() != name:
        raise WheelBuildError(f"non-canonical wheel member path: {name!r}")
    return name


def _regular_mode(info: zipfile.ZipInfo) -> int:
    raw_mode = info.external_attr >> 16
    file_type = stat.S_IFMT(raw_mode)
    if file_type == stat.S_IFLNK:
        raise WheelBuildError(f"wheel contains a symlink: {info.filename!r}")
    if file_type not in {0, stat.S_IFREG}:
        raise WheelBuildError(f"wheel contains an unsupported member type: {info.filename!r}")
    return 0o755 if raw_mode & 0o111 else 0o644


def _read_members(path: Path) -> dict[str, WheelMember]:
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise WheelBuildError(f"wheel must be a regular non-symlink file: {path}")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            members: dict[str, WheelMember] = {}
            for info in archive.infolist():
                name = _safe_member_name(info.filename)
                if name in members:
                    raise WheelBuildError(f"wheel contains a duplicate member: {name!r}")
                if info.flag_bits & 0x1:
                    raise WheelBuildError(f"wheel contains an encrypted member: {name!r}")
                members[name] = WheelMember(archive.read(info), _regular_mode(info))
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        if isinstance(exc, WheelBuildError):
            raise
        raise WheelBuildError(f"cannot read wheel {path}: {exc}") from exc
    if not members:
        raise WheelBuildError(f"wheel is empty: {path}")
    return members


def _record_digest(payload: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
    return f"{RECORD_HASH}={encoded.decode('ascii')}"


def _verify_record(members: Mapping[str, WheelMember], record_name: str) -> None:
    record = members.get(record_name)
    if record is None:
        raise WheelBuildError(f"wheel omits {record_name}")
    try:
        text = record.data.decode("utf-8", errors="strict")
        rows = list(csv.reader(io.StringIO(text, newline="")))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise WheelBuildError(f"wheel RECORD is invalid: {exc}") from exc
    recorded: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3:
            raise WheelBuildError("wheel RECORD rows must contain exactly three fields")
        name = _safe_member_name(row[0])
        if name in recorded:
            raise WheelBuildError(f"wheel RECORD contains a duplicate path: {name!r}")
        recorded[name] = (row[1], row[2])
    if set(recorded) != set(members):
        unlisted = sorted(set(members) - set(recorded))
        missing = sorted(set(recorded) - set(members))
        raise WheelBuildError(f"wheel RECORD coverage mismatch: unlisted={unlisted}, missing={missing}")
    for name, member in members.items():
        digest, size = recorded[name]
        if name == record_name:
            if digest or size:
                raise WheelBuildError("wheel RECORD must leave its own hash and size empty")
            continue
        if digest != _record_digest(member.data) or size != str(len(member.data)):
            raise WheelBuildError(f"wheel RECORD mismatch for {name!r}")


def _metadata_identity(payload: bytes) -> tuple[str, str]:
    try:
        metadata = BytesParser().parsebytes(payload, headersonly=True)
    except Exception as exc:  # email defects vary between Python patch releases.
        raise WheelBuildError(f"wheel METADATA cannot be parsed: {exc}") from exc
    names = metadata.get_all("Name", [])
    versions = metadata.get_all("Version", [])
    if len(names) != 1 or len(versions) != 1:
        raise WheelBuildError("wheel METADATA must contain one Name and one Version")
    distribution = names[0].strip()
    version = versions[0].strip()
    if not distribution or not version or any(character.isspace() for character in version):
        raise WheelBuildError("wheel METADATA has an invalid Name or Version")
    return distribution, version


def _filename_component(value: str) -> str:
    normalized = re.sub(r"[-_.]+", "_", value).strip("_")
    if not normalized or not re.fullmatch(r"[A-Za-z0-9_]+", normalized):
        raise WheelBuildError(f"cannot form a wheel filename component from {value!r}")
    return normalized


def _version_component(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9.]+", "_", value).strip("_")
    if not normalized or not re.fullmatch(r"[A-Za-z0-9_.]+", normalized):
        raise WheelBuildError(f"cannot form a wheel version component from {value!r}")
    return normalized


def _parse_filename(path: Path) -> tuple[str, str, str]:
    name = path.name
    if not name.endswith(".whl"):
        raise WheelBuildError(f"wheel filename must end in .whl: {name!r}")
    parts = name[:-4].split("-")
    if len(parts) != 5:
        raise WheelBuildError(
            "wheel filename must have no build tag and exactly one compatibility tag: "
            f"{name!r}"
        )
    distribution, version, python_tag, abi_tag, platform_tag = parts
    return distribution, version, f"{python_tag}-{abi_tag}-{platform_tag}"


def _wheel_headers(payload: bytes) -> tuple[list[str], list[str]]:
    try:
        lines = payload.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise WheelBuildError(f"WHEEL metadata is not UTF-8: {exc}") from exc
    roots = [line.partition(":")[2].strip().lower() for line in lines if line.lower().startswith("root-is-purelib:")]
    tags = [line.partition(":")[2].strip() for line in lines if line.lower().startswith("tag:")]
    return roots, tags


def _rewrite_wheel_metadata(payload: bytes, *, tag: str) -> bytes:
    try:
        lines = payload.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as exc:
        raise WheelBuildError(f"base WHEEL metadata is not UTF-8: {exc}") from exc
    roots, tags = _wheel_headers(payload)
    if roots != ["true"] or tags != ["py3-none-any"]:
        raise WheelBuildError(
            "base wheel must declare exactly Root-Is-Purelib: true and Tag: py3-none-any"
        )
    rewritten: list[str] = []
    for line in lines:
        lowered = line.lower()
        if lowered.startswith("root-is-purelib:"):
            rewritten.append("Root-Is-Purelib: false")
        elif not lowered.startswith("tag:"):
            rewritten.append(line)
    rewritten.append(f"Tag: {tag}")
    return ("\n".join(rewritten) + "\n").encode("utf-8")


def _load_layout(path: Path) -> WheelLayout:
    members = _read_members(path)
    wheel_names = sorted(name for name in members if name.endswith(".dist-info/WHEEL"))
    if len(wheel_names) != 1:
        raise WheelBuildError("wheel must contain exactly one .dist-info/WHEEL file")
    dist_info = wheel_names[0].removesuffix("/WHEEL")
    metadata_name = f"{dist_info}/METADATA"
    record_name = f"{dist_info}/RECORD"
    if metadata_name not in members:
        raise WheelBuildError(f"wheel omits {metadata_name}")
    if any(name in members for name in (f"{dist_info}/RECORD.jws", f"{dist_info}/RECORD.p7s")):
        raise WheelBuildError("signed RECORD sidecars cannot survive wheel reconstruction")
    _verify_record(members, record_name)
    distribution, version = _metadata_identity(members[metadata_name].data)
    filename_distribution, filename_version, _ = _parse_filename(path)
    if _filename_component(distribution).lower() != filename_distribution.lower():
        raise WheelBuildError("wheel filename distribution does not match METADATA Name")
    if _version_component(version).lower() != filename_version.lower():
        raise WheelBuildError("wheel filename version does not match METADATA Version")
    expected_dist_info = f"{filename_distribution}-{filename_version}.dist-info"
    if dist_info.lower() != expected_dist_info.lower():
        raise WheelBuildError("wheel .dist-info directory does not match its filename")
    return WheelLayout(
        members=members,
        dist_info=dist_info,
        distribution=distribution,
        version=version,
        filename_distribution=filename_distribution,
        filename_version=filename_version,
    )


def _record_bytes(members: Mapping[str, WheelMember], record_name: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name in sorted(members):
        if name != record_name:
            payload = members[name].data
            writer.writerow((name, _record_digest(payload), str(len(payload))))
    writer.writerow((record_name, "", ""))
    return output.getvalue().encode("utf-8")


def _zip_timestamp(epoch: int) -> tuple[int, int, int, int, int, int]:
    try:
        moment = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise WheelBuildError(f"SOURCE_DATE_EPOCH is invalid: {epoch}") from exc
    if moment.year < 1980 or moment.year > 2107:
        raise WheelBuildError("SOURCE_DATE_EPOCH is outside the ZIP timestamp range (1980-2107)")
    return (moment.year, moment.month, moment.day, moment.hour, moment.minute, moment.second)


def _write_wheel(path: Path, members: Mapping[str, WheelMember], *, epoch: int) -> None:
    timestamp = _zip_timestamp(epoch)
    temporary = path.with_name(f".{path.name}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise WheelBuildError(f"temporary wheel path already exists: {temporary}")
    try:
        with zipfile.ZipFile(temporary, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name in sorted(members):
                member = members[name]
                info = zipfile.ZipInfo(name, date_time=timestamp)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | member.mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, member.data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _bundle_members(bundle: Path, *, prefix: PurePosixPath) -> dict[str, WheelMember]:
    result: dict[str, WheelMember] = {}
    for source in sorted(Path(bundle).rglob("*"), key=lambda item: item.relative_to(bundle).as_posix()):
        info = source.lstat()
        relative = source.relative_to(bundle)
        if stat.S_ISLNK(info.st_mode):
            raise WheelBuildError(f"bundle contains a symlink: {relative.as_posix()}")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise WheelBuildError(f"bundle contains an unsupported file: {relative.as_posix()}")
        name = _safe_member_name((prefix / PurePosixPath(relative.as_posix())).as_posix())
        result[name] = WheelMember(source.read_bytes(), 0o755 if info.st_mode & 0o111 else 0o644)
    if not result:
        raise WheelBuildError("Context Mode bundle contains no files")
    return result


def assemble_wheel(
    *,
    base_wheel: Path,
    bundle: Path,
    output_dir: Path,
    platform_tag: str,
    source_date_epoch: int = DEFAULT_SOURCE_DATE_EPOCH,
    enforce_host_platform: bool = True,
    run_native_smoke: bool = True,
    native_authority_root: Path | None = None,
) -> VerifiedWheel:
    if platform_tag not in PLATFORM_WHEEL_TAGS:
        raise WheelBuildError(f"unsupported Context Mode wheel platform: {platform_tag!r}")
    try:
        require_release_readiness(
            Path(__file__).resolve().parents[1],
            platforms=(platform_tag,),
            authority_roots=(
                {platform_tag: Path(native_authority_root)}
                if native_authority_root is not None
                else None
            ),
        )
    except ReleaseReadinessError as exc:
        raise WheelBuildError(f"native release authority is not ready: {exc}") from exc
    try:
        verify_bundle(
            Path(bundle),
            expected_platform=platform_tag,
            enforce_host_platform=enforce_host_platform,
            run_native_smoke=run_native_smoke,
        )
    except BundleBuildError as exc:
        raise WheelBuildError(f"Context Mode bundle verification failed: {exc}") from exc

    layout = _load_layout(Path(base_wheel))
    _, _, base_tag = _parse_filename(Path(base_wheel))
    if base_tag != "py3-none-any":
        raise WheelBuildError("base Bello wheel must be py3-none-any before native payload assembly")
    roots, tags = _wheel_headers(layout.members[f"{layout.dist_info}/WHEEL"].data)
    if roots != ["true"] or tags != ["py3-none-any"]:
        raise WheelBuildError("base Bello wheel is not a canonical universal pure-Python wheel")
    vendor_prefix = f"{VENDOR_ROOT.as_posix()}/"
    if any(name == VENDOR_ROOT.as_posix() or name.startswith(vendor_prefix) for name in layout.members):
        raise WheelBuildError("base wheel already contains a Context Mode vendor payload")

    wheel_tag = PLATFORM_WHEEL_TAGS[platform_tag]
    members = dict(layout.members)
    wheel_name = f"{layout.dist_info}/WHEEL"
    record_name = f"{layout.dist_info}/RECORD"
    members[wheel_name] = WheelMember(
        _rewrite_wheel_metadata(members[wheel_name].data, tag=wheel_tag),
        0o644,
    )
    prefix = VENDOR_ROOT / platform_tag
    embedded = _bundle_members(Path(bundle), prefix=prefix)
    collision = set(members) & set(embedded)
    if collision:
        raise WheelBuildError(f"native bundle collides with base wheel members: {sorted(collision)}")
    members.update(embedded)
    members.pop(record_name, None)
    members[record_name] = WheelMember(_record_bytes(members, record_name), 0o644)

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if output_dir.is_symlink() or not output_dir.is_dir():
        raise WheelBuildError(f"wheel output directory must be a real directory: {output_dir}")
    output = output_dir / (
        f"{layout.filename_distribution}-{layout.filename_version}-{wheel_tag}.whl"
    )
    if output.exists() or output.is_symlink():
        raise WheelBuildError(f"output wheel already exists; refusing to overwrite: {output}")
    try:
        _write_wheel(output, members, epoch=source_date_epoch)
        return verify_wheel(
            wheel=output,
            platform_tag=platform_tag,
            enforce_host_platform=enforce_host_platform,
            run_native_smoke=run_native_smoke,
            native_authority_root=native_authority_root,
        )
    except Exception:
        output.unlink(missing_ok=True)
        raise


def _extract_embedded_bundle(
    members: Mapping[str, WheelMember],
    *,
    platform_tag: str,
    destination: Path,
) -> int:
    target_prefix = f"{(VENDOR_ROOT / platform_tag).as_posix()}/"
    vendor_prefix = f"{VENDOR_ROOT.as_posix()}/"
    vendor_names = sorted(name for name in members if name.startswith(vendor_prefix))
    if not vendor_names:
        raise WheelBuildError("wheel contains no Context Mode vendor payload")
    foreign = [name for name in vendor_names if not name.startswith(target_prefix)]
    if foreign:
        raise WheelBuildError(f"wheel contains a Context Mode payload outside {platform_tag}: {foreign}")
    count = 0
    for name in vendor_names:
        relative = PurePosixPath(name.removeprefix(target_prefix))
        if not relative.parts:
            raise WheelBuildError("wheel contains an empty Context Mode payload path")
        output = destination.joinpath(*relative.parts)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(members[name].data)
        os.chmod(output, members[name].mode)
        count += 1
    return count


def verify_wheel(
    *,
    wheel: Path,
    platform_tag: str,
    enforce_host_platform: bool = True,
    run_native_smoke: bool = True,
    native_authority_root: Path | None = None,
) -> VerifiedWheel:
    if platform_tag not in PLATFORM_WHEEL_TAGS:
        raise WheelBuildError(f"unsupported Context Mode wheel platform: {platform_tag!r}")
    try:
        require_release_readiness(
            Path(__file__).resolve().parents[1],
            platforms=(platform_tag,),
            authority_roots=(
                {platform_tag: Path(native_authority_root)}
                if native_authority_root is not None
                else None
            ),
        )
    except ReleaseReadinessError as exc:
        raise WheelBuildError(f"native release authority is not ready: {exc}") from exc
    layout = _load_layout(Path(wheel))
    filename_distribution, filename_version, filename_tag = _parse_filename(Path(wheel))
    expected_tag = PLATFORM_WHEEL_TAGS[platform_tag]
    if filename_tag != expected_tag or filename_tag == "py3-none-any":
        raise WheelBuildError(
            f"wheel filename tag must be {expected_tag!r}, got {filename_tag!r}"
        )
    if filename_distribution != layout.filename_distribution or filename_version != layout.filename_version:
        raise WheelBuildError("wheel filename identity changed during verification")
    roots, tags = _wheel_headers(layout.members[f"{layout.dist_info}/WHEEL"].data)
    if roots != ["false"] or tags != [expected_tag]:
        raise WheelBuildError(
            "native wheel must declare exactly Root-Is-Purelib: false and its platform tag"
        )
    node_name = f"{(VENDOR_ROOT / platform_tag / 'node/bin/node').as_posix()}"
    node = layout.members.get(node_name)
    if node is None or not node.mode & 0o111:
        raise WheelBuildError("embedded Node executable is missing its executable mode")

    with tempfile.TemporaryDirectory(prefix="bello-context-wheel-verify-") as temporary:
        extracted = Path(temporary) / "bundle"
        extracted.mkdir(mode=0o700)
        embedded_files = _extract_embedded_bundle(
            layout.members,
            platform_tag=platform_tag,
            destination=extracted,
        )
        try:
            verified = verify_bundle(
                extracted,
                expected_platform=platform_tag,
                enforce_host_platform=enforce_host_platform,
                run_native_smoke=run_native_smoke,
            )
        except BundleBuildError as exc:
            raise WheelBuildError(f"embedded Context Mode bundle verification failed: {exc}") from exc
        if embedded_files != verified.file_count + 2:  # manifest.json and manifest.sha256
            raise WheelBuildError("wheel contains unaccounted Context Mode bundle files")
    return VerifiedWheel(
        path=Path(wheel),
        platform=platform_tag,
        wheel_tag=expected_tag,
        embedded_files=embedded_files,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    assemble = commands.add_parser("assemble", help="embed a verified bundle in a platform wheel")
    assemble.add_argument("--base-wheel", type=Path, required=True)
    assemble.add_argument("--bundle", type=Path, required=True)
    assemble.add_argument("--output-dir", type=Path, required=True)
    assemble.add_argument("--platform", choices=SUPPORTED_PLATFORMS, required=True)
    assemble.add_argument("--authority-root", type=Path)
    assemble.add_argument("--source-date-epoch", type=int, default=DEFAULT_SOURCE_DATE_EPOCH)
    assemble.add_argument(
        "--static-only",
        action="store_true",
        help="skip execution checks only when inspecting a foreign-platform bundle",
    )
    verify = commands.add_parser("verify", help="verify wheel metadata, RECORD, and embedded bundle")
    verify.add_argument("--wheel", type=Path, required=True)
    verify.add_argument("--platform", choices=SUPPORTED_PLATFORMS, required=True)
    verify.add_argument("--authority-root", type=Path)
    verify.add_argument(
        "--static-only",
        action="store_true",
        help="skip execution checks only when inspecting a foreign-platform wheel",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "assemble":
            verified = assemble_wheel(
                base_wheel=args.base_wheel,
                bundle=args.bundle,
                output_dir=args.output_dir,
                platform_tag=args.platform,
                source_date_epoch=args.source_date_epoch,
                enforce_host_platform=not args.static_only,
                run_native_smoke=not args.static_only,
                native_authority_root=args.authority_root,
            )
        else:
            verified = verify_wheel(
                wheel=args.wheel,
                platform_tag=args.platform,
                enforce_host_platform=not args.static_only,
                run_native_smoke=not args.static_only,
                native_authority_root=args.authority_root,
            )
    except (WheelBuildError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "embedded_files": verified.embedded_files,
                "platform": verified.platform,
                "verified": True,
                "wheel": str(verified.path),
                "wheel_tag": verified.wheel_tag,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
