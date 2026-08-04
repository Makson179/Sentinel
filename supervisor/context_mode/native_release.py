"""Signed production boundary for Bello's platform Context Mode authority.

This module deliberately contains no Python sandbox fallback.  It verifies the
release-pinned Ed25519 authority payload before exposing either executable, and
then speaks a small bounded controller protocol to the signed native broker.
The broker/launcher binaries are release inputs; source checkouts without them
remain fail closed.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import signal
import stat
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from supervisor.context_mode._util import (
    ContextModeDataError,
    canonical_json_bytes,
    require_int,
    require_nonempty,
    require_sha256,
    strict_object,
)


AUTHORITY_SCHEMA_VERSION = 1
RELEASE_CONTRACT_SCHEMA_VERSION = 1
NATIVE_CONTROLLER_PROTOCOL = "bello-context-native-v1"
SIGNATURE_ALGORITHM = "Ed25519"
SUPPORTED_PLATFORMS = (
    "linux-x86_64",
    "linux-arm64",
    "macos-x86_64",
    "macos-arm64",
)
AUTHORITY_FILES = (
    "bin/bello-context-broker",
    "bin/bello-context-launcher",
    "LICENSE",
    "authority.json",
    "authority.sig",
    "release-public-key.pem",
)
SIGNED_PAYLOAD_FILES = (
    "bin/bello-context-broker",
    "bin/bello-context-launcher",
    "LICENSE",
)
MAX_AUTHORITY_FILE_BYTES = 128 * 1024 * 1024
MAX_CONTROL_LINE_BYTES = 1024 * 1024
MAX_STDERR_CAPTURE_BYTES = 64 * 1024


class NativeReleaseError(ContextModeDataError):
    """The signed native payload or broker protocol is invalid."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
    except OSError as exc:
        raise NativeReleaseError(f"cannot hash native authority file {path}: {exc}") from exc
    return digest.hexdigest()


def _require_real_directory(path: Path, description: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as exc:
        raise NativeReleaseError(f"{description} is missing: {path}") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise NativeReleaseError(f"{description} must be a real directory: {path}")


def _require_real_file(
    path: Path,
    description: str,
    *,
    executable: bool = False,
    maximum_bytes: int = MAX_AUTHORITY_FILE_BYTES,
) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise NativeReleaseError(f"{description} is missing: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise NativeReleaseError(f"{description} must be a regular non-symlink file: {path}")
    if info.st_size <= 0 or info.st_size > maximum_bytes:
        raise NativeReleaseError(f"{description} has an invalid size: {info.st_size}")
    if executable and not info.st_mode & 0o111:
        raise NativeReleaseError(f"{description} is not marked executable: {path}")


def _load_canonical_object(path: Path, description: str) -> dict[str, Any]:
    _require_real_file(path, description, maximum_bytes=512 * 1024)
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NativeReleaseError(f"{description} is invalid JSON: {type(exc).__name__}") from exc
    if not isinstance(value, dict):
        raise NativeReleaseError(f"{description} must contain an object")
    try:
        canonical = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
            "utf-8"
        )
    except (TypeError, ValueError, UnicodeError) as exc:
        raise NativeReleaseError(f"{description} is not strict JSON") from exc
    if raw != canonical:
        raise NativeReleaseError(f"{description} is not canonical deterministic JSON")
    return value


# Minimal RFC 8032 verifier.  Keeping verification in the wheel avoids an
# ambient openssl binary and does not add a second native dependency before the
# signed broker itself has been authenticated.
_ED_Q = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_Q - 2, _ED_Q)) % _ED_Q
_ED_I = pow(2, (_ED_Q - 1) // 4, _ED_Q)
_ED_IDENTITY = (0, 1)


def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_Q - 2, _ED_Q) % _ED_Q
    x = pow(xx, (_ED_Q + 3) // 8, _ED_Q)
    if (x * x - xx) % _ED_Q:
        x = x * _ED_I % _ED_Q
    if (x * x - xx) % _ED_Q:
        raise NativeReleaseError("Ed25519 point is not on the curve")
    return x


_ED_BY = 4 * pow(5, _ED_Q - 2, _ED_Q) % _ED_Q
_ED_BX = _ed_xrecover(_ED_BY)
if _ED_BX & 1:
    _ED_BX = _ED_Q - _ED_BX
_ED_BASE = (_ED_BX, _ED_BY)


def _ed_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    product = _ED_D * x1 * x2 * y1 * y2 % _ED_Q
    x3 = (x1 * y2 + x2 * y1) * pow(1 + product, _ED_Q - 2, _ED_Q) % _ED_Q
    y3 = (y1 * y2 + x1 * x2) * pow(1 - product, _ED_Q - 2, _ED_Q) % _ED_Q
    return x3, y3


def _ed_scalarmult(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = _ED_IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed_add(result, addend)
        addend = _ed_add(addend, addend)
        scalar >>= 1
    return result


def _ed_decode(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise NativeReleaseError("Ed25519 point must contain 32 bytes")
    value = int.from_bytes(encoded, "little")
    sign_bit = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _ED_Q:
        raise NativeReleaseError("Ed25519 point is not canonically encoded")
    x = _ed_xrecover(y)
    if (x & 1) != sign_bit:
        x = _ED_Q - x
    if x == 0 and sign_bit:
        raise NativeReleaseError("Ed25519 point has an invalid sign bit")
    point = (x, y)
    if _ed_add(point, _ED_IDENTITY) != point:
        raise NativeReleaseError("Ed25519 point decode failed")
    return point


def _ed_encode(point: tuple[int, int]) -> bytes:
    x, y = point
    value = y | ((x & 1) << 255)
    return value.to_bytes(32, "little")


def _ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        public_point = _ed_decode(public_key)
        r_point = _ed_decode(signature[:32])
    except NativeReleaseError:
        return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _ED_L:
        return False
    # Strict subgroup checks avoid accepting small-order encodings.
    if public_point == _ED_IDENTITY or _ed_scalarmult(public_point, _ED_L) != _ED_IDENTITY:
        return False
    if _ed_scalarmult(r_point, _ED_L) != _ED_IDENTITY:
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(),
        "little",
    ) % _ED_L
    left = _ed_scalarmult(_ED_BASE, scalar)
    right = _ed_add(r_point, _ed_scalarmult(public_point, challenge))
    return hmac.compare_digest(_ed_encode(left), _ed_encode(right))


def _public_key_from_pem(raw: bytes) -> bytes:
    prefix = b"-----BEGIN PUBLIC KEY-----\n"
    suffix = b"-----END PUBLIC KEY-----\n"
    if not raw.startswith(prefix) or not raw.endswith(suffix):
        raise NativeReleaseError("release public key is not canonical PEM")
    body_record = raw[len(prefix) : -len(suffix)]
    if not body_record.endswith(b"\n"):
        raise NativeReleaseError("release public key PEM has a noncanonical body")
    body = body_record[:-1]
    if b"\n" in body or b"\r" in body:
        raise NativeReleaseError("release public key PEM has a noncanonical body")
    try:
        der = base64.b64decode(body, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise NativeReleaseError("release public key PEM is invalid base64") from exc
    # SubjectPublicKeyInfo(Ed25519), RFC 8410.
    spki_prefix = bytes.fromhex("302a300506032b6570032100")
    if len(der) != len(spki_prefix) + 32 or not der.startswith(spki_prefix):
        raise NativeReleaseError("release public key is not an Ed25519 SubjectPublicKeyInfo")
    if base64.b64encode(der) != body:
        raise NativeReleaseError("release public key PEM is not canonical base64")
    return der[len(spki_prefix) :]


def verify_signed_native_authority(
    *,
    authority_root: Path,
    contract_path: Path,
    platform_tag: str,
) -> Mapping[str, Any]:
    """Verify exact layout, release pins, file hashes, and Ed25519 signature."""

    if platform_tag not in SUPPORTED_PLATFORMS:
        raise NativeReleaseError(f"unsupported native authority platform: {platform_tag!r}")
    root = Path(authority_root)
    _require_real_directory(root, "native authority root")
    _require_real_directory(root / "bin", "native authority bin directory")
    actual_root = {entry.name for entry in root.iterdir()}
    if actual_root != {"bin", "LICENSE", "authority.json", "authority.sig", "release-public-key.pem"}:
        raise NativeReleaseError("native authority root has unexpected or missing entries")
    if {entry.name for entry in (root / "bin").iterdir()} != {
        "bello-context-broker",
        "bello-context-launcher",
    }:
        raise NativeReleaseError("native authority bin directory has unexpected or missing entries")
    for relative in AUTHORITY_FILES:
        _require_real_file(
            root / relative,
            f"native authority {relative}",
            executable=relative.startswith("bin/"),
            maximum_bytes=(
                512 * 1024
                if relative == "authority.json"
                else 16 * 1024
                if relative in {"authority.sig", "release-public-key.pem", "LICENSE"}
                else MAX_AUTHORITY_FILE_BYTES
            ),
        )

    contract = _load_canonical_object(Path(contract_path), "native release contract")
    strict_object(
        contract,
        required=frozenset(
            {
                "schema_version",
                "signature_algorithm",
                "authority_schema_version",
                "broker_protocol",
                "platforms",
            }
        ),
        name="native release contract",
    )
    require_int(contract["schema_version"], "release contract schema_version", minimum=1)
    require_int(
        contract["authority_schema_version"],
        "release contract authority_schema_version",
        minimum=1,
    )
    if (
        contract["schema_version"] != RELEASE_CONTRACT_SCHEMA_VERSION
        or contract["authority_schema_version"] != AUTHORITY_SCHEMA_VERSION
        or contract["signature_algorithm"] != SIGNATURE_ALGORITHM
        or contract["broker_protocol"] != NATIVE_CONTROLLER_PROTOCOL
    ):
        raise NativeReleaseError("native release contract pins do not match this adapter")
    platform_records = contract["platforms"]
    if not isinstance(platform_records, Mapping) or frozenset(platform_records) != frozenset(
        SUPPORTED_PLATFORMS
    ):
        raise NativeReleaseError("native release contract must cover exactly four platforms")
    record = platform_records.get(platform_tag)
    if not isinstance(record, Mapping):
        raise NativeReleaseError("native release contract has no selected platform record")
    strict_object(
        record,
        required=frozenset({"authority_manifest_sha256", "release_public_key_sha256"}),
        name="native release platform record",
    )
    expected_manifest_digest = require_sha256(
        record["authority_manifest_sha256"],
        "authority_manifest_sha256",
    )
    expected_key_digest = require_sha256(
        record["release_public_key_sha256"],
        "release_public_key_sha256",
    )

    manifest_path = root / "authority.json"
    manifest = _load_canonical_object(manifest_path, "native authority manifest")
    manifest_digest = _sha256_file(manifest_path)
    if manifest_digest != expected_manifest_digest:
        raise NativeReleaseError("native authority manifest does not match the release contract")
    strict_object(
        manifest,
        required=frozenset(
            {"schema_version", "platform", "broker_protocol", "authority_version", "files"}
        ),
        name="native authority manifest",
    )
    require_int(manifest["schema_version"], "authority schema_version", minimum=1)
    if (
        manifest["schema_version"] != AUTHORITY_SCHEMA_VERSION
        or manifest["platform"] != platform_tag
        or manifest["broker_protocol"] != NATIVE_CONTROLLER_PROTOCOL
    ):
        raise NativeReleaseError("native authority manifest identity mismatch")
    require_nonempty(manifest["authority_version"], "authority_version")
    files = manifest["files"]
    if not isinstance(files, Mapping) or frozenset(files) != frozenset(SIGNED_PAYLOAD_FILES):
        raise NativeReleaseError("native authority manifest file catalogue is not exact")
    for relative in SIGNED_PAYLOAD_FILES:
        expected = require_sha256(files[relative], f"authority files[{relative!r}]")
        if _sha256_file(root / relative) != expected:
            raise NativeReleaseError(f"native authority payload digest mismatch: {relative}")

    key_path = root / "release-public-key.pem"
    if _sha256_file(key_path) != expected_key_digest:
        raise NativeReleaseError("native authority public key does not match the release contract")
    try:
        key_bytes = key_path.read_bytes()
        signature_record = (root / "authority.sig").read_bytes()
    except OSError as exc:
        raise NativeReleaseError(f"cannot read native signature material: {exc}") from exc
    public_key = _public_key_from_pem(key_bytes)
    try:
        signature = base64.b64decode(signature_record.strip(), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise NativeReleaseError("native authority signature is invalid base64") from exc
    if signature_record != base64.b64encode(signature) + b"\n" or len(signature) != 64:
        raise NativeReleaseError("native authority signature encoding is not canonical")
    manifest_bytes = manifest_path.read_bytes()
    if not _ed25519_verify(public_key, manifest_bytes, signature):
        raise NativeReleaseError("native authority Ed25519 signature verification failed")

    broker = root / "bin" / "bello-context-broker"
    launcher = root / "bin" / "bello-context-launcher"
    return {
        "schema_version": 1,
        "signature_verified": True,
        "signature_algorithm": SIGNATURE_ALGORITHM,
        "platform": platform_tag,
        "broker_protocol": NATIVE_CONTROLLER_PROTOCOL,
        "authority_manifest_sha256": manifest_digest,
        "broker_path": os.fspath(broker.resolve(strict=True)),
        "broker_sha256": files["bin/bello-context-broker"],
        "launcher_path": os.fspath(launcher.resolve(strict=True)),
        "launcher_sha256": files["bin/bello-context-launcher"],
    }


class BundledNativeRuntime:
    """Bounded adapter for the signed broker/launcher controller protocol."""

    def __init__(self, *, bundle: Any, authority: Mapping[str, Any]) -> None:
        if authority.get("signature_verified") is not True:
            raise NativeReleaseError("native runtime requires a verified authority")
        self.bundle = bundle
        self.authority = dict(authority)
        self.broker_path = Path(require_nonempty(authority.get("broker_path"), "broker_path"))
        self.broker_sha256 = require_sha256(authority.get("broker_sha256"), "broker_sha256")
        self.launcher_path = Path(require_nonempty(authority.get("launcher_path"), "launcher_path"))
        self.launcher_sha256 = require_sha256(authority.get("launcher_sha256"), "launcher_sha256")
        self._process: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._next_request_id = 1
        self._write_lock = asyncio.Lock()
        self._receipt_handler: Callable[[Any], None] | None = None
        self._runtime_instance_id: str | None = None
        self._channel: str | None = None
        self._stderr_capture = bytearray()
        self._fatal_error: BaseException | None = None
        self._last_stop_attestation: dict[str, Any] | None = None

    def _verify_executables(self) -> None:
        for path, digest, label in (
            (self.broker_path, self.broker_sha256, "broker"),
            (self.launcher_path, self.launcher_sha256, "launcher"),
        ):
            _require_real_file(path, f"signed native {label}", executable=True)
            if _sha256_file(path) != digest:
                raise NativeReleaseError(f"signed native {label} changed after verification")

    async def verify_sandbox_backend(self) -> Any:
        """Run the signed broker's one-shot OS isolation self-test."""

        self._verify_executables()
        process: asyncio.subprocess.Process | None = None
        try:
            process = await asyncio.create_subprocess_exec(
                os.fspath(self.broker_path),
                "--verify-sandbox-backend",
                "--protocol",
                NATIVE_CONTROLLER_PROTOCOL,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"BELLO_OFFLINE": "1", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"},
                start_new_session=True,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30.0)
        except (OSError, asyncio.TimeoutError) as exc:
            if process is not None and process.returncode is None and process.pid > 1:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()
            raise NativeReleaseError(f"native sandbox self-test could not run: {exc}") from exc
        if process.returncode != 0 or len(stdout) > MAX_CONTROL_LINE_BYTES or len(stderr) > MAX_STDERR_CAPTURE_BYTES:
            raise NativeReleaseError("native sandbox self-test failed or exceeded output limits")
        try:
            report = json.loads(stdout)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise NativeReleaseError("native sandbox self-test returned invalid JSON") from exc
        if not isinstance(report, Mapping):
            raise NativeReleaseError("native sandbox self-test returned no object")
        strict_object(
            report,
            required=frozenset(
                {
                    "schema_version",
                    "platform",
                    "broker_protocol",
                    "backend",
                    "executable",
                    "verification_id",
                    "completed_checks",
                }
            ),
            name="native sandbox self-test",
        )
        require_int(report["schema_version"], "native sandbox schema_version", minimum=1)
        if (
            report["schema_version"] != 1
            or report["platform"] != self.authority["platform"]
            or report["broker_protocol"] != NATIVE_CONTROLLER_PROTOCOL
            or not isinstance(report["completed_checks"], list)
            or any(not isinstance(value, str) for value in report["completed_checks"])
        ):
            raise NativeReleaseError("native sandbox self-test schema/identity mismatch")
        from supervisor.context_mode.sandbox import verified_backend

        return verified_backend(
            name=report["backend"],
            executable=report["executable"],
            verification_id=report["verification_id"],
            completed_checks=report["completed_checks"],
        )

    async def start(
        self,
        *,
        bundle: Any,
        backend: Any,
        policies: tuple[Any, ...],
        binding: Any,
        run_root: Path,
        receipt_handler: Callable[[Any], None],
    ) -> Any:
        if self._process is not None:
            raise NativeReleaseError("native broker is already started")
        if Path(bundle.root).resolve(strict=True) != Path(self.bundle.root).resolve(strict=True):
            raise NativeReleaseError("native adapter bundle changed between verification and start")
        self._verify_executables()
        run_root = Path(run_root).resolve(strict=True)
        self._receipt_handler = receipt_handler
        try:
            process = await asyncio.create_subprocess_exec(
                os.fspath(self.broker_path),
                "--controller-stdio",
                "--protocol",
                NATIVE_CONTROLLER_PROTOCOL,
                cwd=run_root,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={"BELLO_OFFLINE": "1", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC"},
                start_new_session=True,
                limit=MAX_CONTROL_LINE_BYTES + 1,
            )
        except OSError as exc:
            raise NativeReleaseError(f"signed native broker failed to start: {exc}") from exc
        self._process = process
        self._fatal_error = None
        self._last_stop_attestation = None
        self._stderr_capture.clear()
        self._reader_task = asyncio.create_task(self._read_control_stream())
        self._stderr_task = asyncio.create_task(self._drain_stderr())
        try:
            result = await self._rpc(
                "runtime/start",
                {
                    "schema_version": 1,
                    "bundle_root": os.fspath(Path(bundle.root).resolve(strict=True)),
                    "bundle_manifest_sha256": _sha256_file(Path(bundle.manifest_path)),
                    "authority_manifest_sha256": self.authority["authority_manifest_sha256"],
                    "backend": {
                        "name": backend.name.value,
                        "verification_id": backend.verification_id,
                        "checks": list(backend.checks),
                    },
                    "policies": [policy.to_dict() for policy in policies],
                    "binding": binding.to_dict(),
                    "run_root": os.fspath(run_root),
                },
                timeout=30.0,
            )
            if not isinstance(result, Mapping):
                raise NativeReleaseError("native broker start returned no endpoint")
            strict_object(
                result,
                required=frozenset({"schema_version", "runtime_instance_id", "channel"}),
                name="native broker start endpoint",
            )
            require_int(result["schema_version"], "native endpoint schema_version", minimum=1)
            if result["schema_version"] != 1:
                raise NativeReleaseError("native broker endpoint schema mismatch")
            runtime_instance_id = require_nonempty(result["runtime_instance_id"], "runtime_instance_id")
            channel = require_nonempty(result["channel"], "native public channel")
            self._runtime_instance_id = runtime_instance_id
            self._channel = channel
            from supervisor.context_mode.startup import NativeRuntimeEndpoint

            return NativeRuntimeEndpoint(
                launcher_path=self.launcher_path,
                launcher_sha256=self.launcher_sha256,
                public_bootstrap={"channel": channel},
                runtime_instance_id=runtime_instance_id,
            )
        except BaseException:
            try:
                await self.stop(timeout_seconds=5.0)
            except BaseException:
                # Startup remains failed; the stop path has already killed and
                # waited for the broker leader, but cannot manufacture the
                # missing native descendant-reap attestation.
                pass
            raise

    async def _rpc(self, method: str, params: Mapping[str, Any], *, timeout: float = 30.0) -> Any:
        process = self._process
        if process is None or process.stdin is None or process.returncode is not None:
            raise NativeReleaseError("native broker control channel is unavailable")
        if self._fatal_error is not None:
            raise NativeReleaseError(f"native broker control channel failed: {self._fatal_error}")
        require_nonempty(method, "native broker method")
        loop = asyncio.get_running_loop()
        future: asyncio.Future[Any] = loop.create_future()
        async with self._write_lock:
            request_id = self._next_request_id
            self._next_request_id += 1
            self._pending[request_id] = future
            payload = canonical_json_bytes(
                {"id": request_id, "method": method, "params": dict(params)}
            ) + b"\n"
            if len(payload) > MAX_CONTROL_LINE_BYTES:
                self._pending.pop(request_id, None)
                raise NativeReleaseError("native broker request exceeds the control-line limit")
            try:
                process.stdin.write(payload)
                await process.stdin.drain()
            except (OSError, RuntimeError) as exc:
                self._pending.pop(request_id, None)
                raise NativeReleaseError(f"native broker request send failed: {exc}") from exc
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError as exc:
            self._pending.pop(request_id, None)
            raise NativeReleaseError(f"native broker {method} timed out") from exc

    async def _read_control_stream(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        try:
            while True:
                line = await process.stdout.readline()
                if not line:
                    if process.returncode not in {None, 0}:
                        raise NativeReleaseError("native broker control stream ended unexpectedly")
                    return
                if len(line) > MAX_CONTROL_LINE_BYTES:
                    raise NativeReleaseError("native broker control line exceeds the hard limit")
                try:
                    value = json.loads(line)
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise NativeReleaseError("native broker returned invalid JSON") from exc
                if not isinstance(value, Mapping):
                    raise NativeReleaseError("native broker control message must be an object")
                if "id" in value:
                    if frozenset(value) not in {
                        frozenset({"id", "result"}),
                        frozenset({"id", "error"}),
                    }:
                        raise NativeReleaseError("native broker response schema mismatch")
                    request_id = value["id"]
                    require_int(request_id, "native broker response id", minimum=1)
                    future = self._pending.pop(request_id, None)
                    if future is None or future.done():
                        raise NativeReleaseError("native broker response id is unknown or replayed")
                    if "error" in value:
                        future.set_exception(NativeReleaseError(f"native broker rejected request: {value['error']}"))
                    else:
                        future.set_result(value["result"])
                    continue
                if frozenset(value) != frozenset({"method", "params"}):
                    raise NativeReleaseError("native broker notification schema mismatch")
                if value["method"] != "broker/receipt" or not isinstance(value["params"], Mapping):
                    raise NativeReleaseError("native broker emitted an unauthorized notification")
                from supervisor.context_mode.provenance import BrokerReceipt

                receipt = BrokerReceipt.from_dict(value["params"])
                handler = self._receipt_handler
                if handler is None:
                    raise NativeReleaseError("native broker receipt arrived without a controller handler")
                handler(receipt)
        except BaseException as exc:
            self._fatal_error = exc
            for future in tuple(self._pending.values()):
                if not future.done():
                    future.set_exception(NativeReleaseError(f"native broker control channel failed: {exc}"))
            self._pending.clear()

    async def _drain_stderr(self) -> None:
        process = self._process
        if process is None or process.stderr is None:
            return
        while True:
            chunk = await process.stderr.read(8192)
            if not chunk:
                return
            remaining = MAX_STDERR_CAPTURE_BYTES - len(self._stderr_capture)
            if remaining > 0:
                self._stderr_capture.extend(chunk[:remaining])

    async def launch_app_server(
        self,
        *,
        command: tuple[str, ...],
        cwd: Path | None,
        environment: Mapping[str, str],
        role: Any,
        stdout_limit: int,
    ) -> asyncio.subprocess.Process:
        if self._process is None or self._channel is None or self._fatal_error is not None:
            raise NativeReleaseError("native broker is not healthy for app-server launch")
        self._verify_executables()
        if not command or any(not isinstance(value, str) or not value or "\x00" in value for value in command):
            raise NativeReleaseError("app-server command must be a non-empty NUL-free string tuple")
        role_value = getattr(role, "value", role)
        if role_value not in {"coder", "supervisor"}:
            raise NativeReleaseError("app-server role is invalid")
        if isinstance(stdout_limit, bool) or not isinstance(stdout_limit, int) or stdout_limit <= 0:
            raise NativeReleaseError("app-server stdout limit must be a positive integer")
        if any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or not key
            or "\x00" in key + value
            for key, value in environment.items()
        ):
            raise NativeReleaseError("app-server environment contains an invalid key/value")
        return await asyncio.create_subprocess_exec(
            os.fspath(self.launcher_path),
            "app-server",
            "--channel",
            self._channel,
            "--role",
            role_value,
            "--",
            *command,
            cwd=cwd,
            env=dict(environment),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=stdout_limit,
            start_new_session=True,
        )

    async def verify_app_server_boundary(
        self,
        *,
        supervisor_client: Any,
        coder_client: Any,
        binding: Any,
    ) -> Mapping[str, Any]:
        def identity(client: Any) -> dict[str, Any]:
            process = getattr(client, "process", None)
            pid = getattr(process, "pid", None)
            require_int(pid, "app-server pid", minimum=2)
            return {
                "process_epoch": require_int(client.process_epoch, "app-server process_epoch"),
                "app_server_instance_id": require_nonempty(
                    client.app_server_instance_id,
                    "app_server_instance_id",
                ),
                "pid": pid,
            }

        result = await self._rpc(
            "runtime/verify-app-server-boundary",
            {
                "schema_version": 1,
                "binding": binding.to_dict(),
                "supervisor": identity(supervisor_client),
                "coder": identity(coder_client),
            },
        )
        if not isinstance(result, Mapping):
            raise NativeReleaseError("native app-server boundary returned no report")
        return dict(result)

    async def register_approval_capability(
        self,
        *,
        capability: Any,
        request_key: Mapping[str, Any],
    ) -> None:
        await self._rpc(
            "runtime/register-approval-capability",
            {
                "schema_version": 1,
                "capability": capability.to_dict(),
                "request_key": dict(request_key),
            },
        )

    async def revoke_approval_capability(self, *, capability_id: str) -> None:
        await self._rpc(
            "runtime/revoke-approval-capability",
            {"schema_version": 1, "capability_id": require_nonempty(capability_id, "capability_id")},
        )

    async def update_binding(self, *, previous_binding: Any, binding: Any, reason: str) -> None:
        await self._rpc(
            "runtime/update-binding",
            {
                "schema_version": 1,
                "previous_binding": previous_binding.to_dict(),
                "binding": binding.to_dict(),
                "reason": require_nonempty(reason, "binding transition reason"),
            },
        )

    async def activate_state_epoch(
        self,
        *,
        previous_binding: Any,
        binding: Any,
        exclusive_lease_id: str,
        previous_epoch_root: Path,
        active_epoch_root: Path,
        policies: tuple[Any, ...],
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        result = await self._rpc(
            "runtime/activate-state-epoch",
            {
                "schema_version": 1,
                "previous_binding": previous_binding.to_dict(),
                "binding": binding.to_dict(),
                "exclusive_lease_id": require_nonempty(
                    exclusive_lease_id,
                    "exclusive_lease_id",
                ),
                "previous_epoch_root": os.fspath(Path(previous_epoch_root)),
                "active_epoch_root": os.fspath(Path(active_epoch_root)),
                "policies": [policy.to_dict() for policy in policies],
            },
            timeout=timeout_seconds,
        )
        if not isinstance(result, Mapping):
            raise NativeReleaseError(
                "native epoch activation returned no switch/reap acknowledgement"
            )
        return dict(result)

    async def acquire_purge_lease(
        self,
        *,
        binding: Any,
        exclusive_lease_id: str,
        owner: str,
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        result = await self._rpc(
            "runtime/acquire-purge-lease",
            {
                "schema_version": 1,
                "binding": binding.to_dict(),
                "exclusive_lease_id": require_nonempty(
                    exclusive_lease_id,
                    "exclusive_lease_id",
                ),
                "owner": require_nonempty(owner, "purge lease owner"),
            },
            timeout=timeout_seconds,
        )
        if not isinstance(result, Mapping):
            raise NativeReleaseError("native broker returned no purge lease acknowledgement")
        return dict(result)

    async def release_purge_lease(
        self,
        *,
        binding: Any,
        exclusive_lease_id: str,
    ) -> None:
        result = await self._rpc(
            "runtime/release-purge-lease",
            {
                "schema_version": 1,
                "binding": binding.to_dict(),
                "exclusive_lease_id": require_nonempty(
                    exclusive_lease_id,
                    "exclusive_lease_id",
                ),
            },
        )
        if result is not None:
            raise NativeReleaseError("native broker returned an ambiguous purge lease release")

    async def quiesce(self, *, binding: Any, timeout_seconds: float) -> None:
        await self._rpc(
            "runtime/quiesce",
            {"schema_version": 1, "binding": binding.to_dict()},
            timeout=timeout_seconds,
        )

    async def checkpoint(
        self,
        *,
        binding: Any,
        reason: str,
        transition: str,
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        result = await self._rpc(
            "runtime/checkpoint",
            {
                "schema_version": 1,
                "binding": binding.to_dict(),
                "reason": require_nonempty(reason, "checkpoint reason"),
                "transition": require_nonempty(transition, "checkpoint transition"),
            },
            timeout=timeout_seconds,
        )
        if not isinstance(result, Mapping):
            raise NativeReleaseError("native checkpoint returned no acknowledgement")
        return dict(result)

    async def recover_checkpoint(
        self,
        *,
        cursor: Mapping[str, Any],
        checkpoint_binding: Any,
        binding: Any,
        recovery_kind: str,
        timeout_seconds: float,
    ) -> Mapping[str, Any]:
        result = await self._rpc(
            "runtime/recover-checkpoint",
            {
                "schema_version": 1,
                "cursor": dict(cursor),
                "checkpoint_binding": checkpoint_binding.to_dict(),
                "binding": binding.to_dict(),
                "recovery_kind": require_nonempty(recovery_kind, "recovery_kind"),
            },
            timeout=timeout_seconds,
        )
        if not isinstance(result, Mapping):
            raise NativeReleaseError("native recovery returned no acknowledgement")
        return dict(result)

    async def resume(self, *, binding: Any) -> None:
        await self._rpc(
            "runtime/resume",
            {"schema_version": 1, "binding": binding.to_dict()},
        )

    async def stop(self, *, timeout_seconds: float) -> Mapping[str, Any]:
        process = self._process
        if process is None:
            if self._last_stop_attestation is None:
                raise NativeReleaseError(
                    "native broker has no verified process-tree stop attestation"
                )
            return dict(self._last_stop_attestation)
        stop_error: BaseException | None = None
        stop_attestation: dict[str, Any] | None = None
        try:
            if process.returncode is None and self._fatal_error is None:
                try:
                    result = await self._rpc(
                        "runtime/stop",
                        {"schema_version": 1},
                        timeout=max(0.1, timeout_seconds),
                    )
                    if not isinstance(result, Mapping):
                        raise NativeReleaseError(
                            "native broker stop returned no process-tree attestation"
                        )
                    strict_object(
                        result,
                        required=frozenset(
                            {
                                "schema_version",
                                "runtime_instance_id",
                                "process_tree_reaped",
                                "descendants_reaped",
                                "writer_handles_closed",
                            }
                        ),
                        name="native broker stop attestation",
                    )
                    require_int(
                        result["schema_version"],
                        "native broker stop schema_version",
                        minimum=1,
                    )
                    if (
                        result["schema_version"] != 1
                        or result["runtime_instance_id"] != self._runtime_instance_id
                        or result["process_tree_reaped"] is not True
                        or result["descendants_reaped"] is not True
                        or result["writer_handles_closed"] is not True
                    ):
                        raise NativeReleaseError(
                            "native broker stop did not attest every writer as reaped"
                        )
                    stop_attestation = dict(result)
                except BaseException as exc:
                    stop_error = exc
            if process.stdin is not None:
                process.stdin.close()
            if process.returncode is None:
                try:
                    await asyncio.wait_for(process.wait(), timeout=max(0.1, timeout_seconds))
                except asyncio.TimeoutError:
                    if process.pid and process.pid > 1:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    await process.wait()
        finally:
            for task in (self._reader_task, self._stderr_task):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(
                *(task for task in (self._reader_task, self._stderr_task) if task is not None),
                return_exceptions=True,
            )
            for future in tuple(self._pending.values()):
                if not future.done():
                    future.set_exception(NativeReleaseError("native broker stopped"))
            self._pending.clear()
            self._process = None
            self._reader_task = None
            self._stderr_task = None
            self._runtime_instance_id = None
            self._channel = None
            self._fatal_error = None
        if stop_error is not None:
            raise NativeReleaseError(f"native broker stop was not acknowledged: {stop_error}") from stop_error
        if stop_attestation is None:
            raise NativeReleaseError("native broker exited without a process-tree stop attestation")
        self._last_stop_attestation = stop_attestation
        return dict(stop_attestation)


def load_bundled_native_runtime(
    *,
    vendor_root: Path,
    platform_tag: str | None = None,
    contract_path: Path | None = None,
    require_executable_node: bool = True,
) -> BundledNativeRuntime:
    """Load only a fully verified worker bundle plus signed native authority."""

    from supervisor.context_mode.packaging import current_platform_tag, select_bundled_runtime

    selected_platform = platform_tag or current_platform_tag()
    bundle = select_bundled_runtime(
        Path(vendor_root),
        platform_tag=selected_platform,
        require_executable_node=require_executable_node,
    )
    authority = verify_signed_native_authority(
        authority_root=Path(bundle.root) / "authority",
        contract_path=contract_path or Path(__file__).with_name("native-release.json"),
        platform_tag=selected_platform,
    )
    return BundledNativeRuntime(bundle=bundle, authority=authority)


__all__ = [
    "AUTHORITY_FILES",
    "BundledNativeRuntime",
    "NativeReleaseError",
    "load_bundled_native_runtime",
    "verify_signed_native_authority",
]
