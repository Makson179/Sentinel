"""Strict, non-persistent contract for Bello-owned Context Mode hook input.

The native broker applies this contract before a hook process is spawned.  Raw
stdin, transcript paths, and binding authority never become hook-visible data;
only the bounded redacted envelope and an out-of-band HMAC receipt survive
normalization.  This Python implementation is also the release reference used
to derive the contract digest embedded in hook bootstrap files.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from ._util import (
    ContextModeDataError,
    canonical_json_bytes,
    digest_json,
    require_nonempty,
    require_sha256,
)
from .config import REQUIRED_HOOKS
from .provenance import bounded_redacted_summary, correlation_hmac, redact_text
from .session import ContextBinding


HOOK_PAYLOAD_SCHEMA_VERSION = 1
MAX_RAW_HOOK_BYTES = 256 * 1024
MAX_RAW_TRANSCRIPT_BYTES = 256 * 1024
MAX_VISIBLE_HOOK_BYTES = 32 * 1024
MAX_REDACTED_TRANSCRIPT_BYTES = 16 * 1024
MAX_FIELD_BYTES = 64 * 1024
MAX_ACTIVE_HOOK_INVOCATIONS = 128
MAX_SEEN_HOOK_INVOCATIONS = 4096
HOOK_INVOCATION_TTL_SECONDS = 120

_COMMON_REQUIRED = frozenset({"hook_event_name", "session_id", "cwd"})
_COMMON_OPTIONAL = frozenset({"transcript_path"})
_EVENT_FIELDS: Mapping[str, tuple[frozenset[str], frozenset[str]]] = {
    "PreToolUse": (
        frozenset({"tool_name", "tool_input", "tool_use_id"}),
        frozenset(),
    ),
    "PostToolUse": (
        frozenset({"tool_name", "tool_input", "tool_use_id", "tool_response"}),
        frozenset(),
    ),
    "SessionStart": (frozenset({"source"}), frozenset()),
    "PreCompact": (frozenset({"trigger"}), frozenset({"custom_instructions"})),
    "UserPromptSubmit": (frozenset({"prompt"}), frozenset()),
    "Stop": (frozenset({"stop_hook_active"}), frozenset({"last_assistant_message"})),
}
_SESSION_SOURCES = frozenset({"startup", "resume", "clear", "compact", "recovery"})
_COMPACT_TRIGGERS = frozenset({"manual", "auto"})

HOOK_PAYLOAD_CONTRACT: Mapping[str, Any] = {
    "schema_version": HOOK_PAYLOAD_SCHEMA_VERSION,
    "events": {
        event: {
            "required": sorted(_COMMON_REQUIRED | fields[0]),
            "optional": sorted(_COMMON_OPTIONAL | fields[1]),
        }
        for event, fields in sorted(_EVENT_FIELDS.items())
    },
    "limits": {
        "raw_bytes": MAX_RAW_HOOK_BYTES,
        "raw_transcript_bytes": MAX_RAW_TRANSCRIPT_BYTES,
        "visible_bytes": MAX_VISIBLE_HOOK_BYTES,
        "redacted_transcript_bytes": MAX_REDACTED_TRANSCRIPT_BYTES,
        "field_bytes": MAX_FIELD_BYTES,
        "ttl_seconds": HOOK_INVOCATION_TTL_SECONDS,
    },
    "unknown_fields": "strip-and-count",
    "transcript_path_visible": False,
}
HOOK_PAYLOAD_CONTRACT_DIGEST = digest_json(HOOK_PAYLOAD_CONTRACT)


class HookPayloadError(ContextModeDataError):
    """Hook input or its one-shot lifecycle violates the pinned contract."""


class HookPayloadReplayError(HookPayloadError):
    """A hook invocation was replayed, expired, or claimed under stale authority."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HookPayloadError(f"hook payload contains duplicate field {key!r}")
        result[key] = value
    return result


def _load_raw_payload(raw: bytes | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(raw, (bytes, bytearray)):
        encoded = bytes(raw)
        if len(encoded) > MAX_RAW_HOOK_BYTES:
            raise HookPayloadError("raw hook payload exceeds 256 KiB")
        try:
            value = json.loads(
                encoded.decode("utf-8", errors="strict"),
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    HookPayloadError(f"hook payload contains non-JSON number {value}")
                ),
            )
        except HookPayloadError:
            raise
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise HookPayloadError("hook payload is not strict UTF-8 JSON") from exc
    elif isinstance(raw, Mapping):
        value = dict(raw)
        try:
            encoded = canonical_json_bytes(value)
        except ContextModeDataError as exc:
            raise HookPayloadError(str(exc)) from exc
        if len(encoded) > MAX_RAW_HOOK_BYTES:
            raise HookPayloadError("raw hook payload exceeds 256 KiB")
    else:
        raise HookPayloadError("hook payload must be an object or UTF-8 JSON bytes")
    if not isinstance(value, dict):
        raise HookPayloadError("hook payload must contain an object")
    # Canonicalization enforces string keys, finite numbers, and bounded JSON depth.
    try:
        canonical_json_bytes(value)
    except ContextModeDataError as exc:
        raise HookPayloadError(str(exc)) from exc
    return value


def _bounded_string(value: Any, field: str) -> str:
    value = require_nonempty(value, field)
    if len(value.encode("utf-8")) > MAX_FIELD_BYTES:
        raise HookPayloadError(f"{field} exceeds 64 KiB")
    return value


def _validate_event_fields(event: str, payload: Mapping[str, Any]) -> None:
    required, _optional = _EVENT_FIELDS[event]
    for field in required:
        if field not in payload:
            raise HookPayloadError(f"{event} hook payload is missing {field!r}")
    string_fields = {
        "tool_name",
        "tool_use_id",
        "source",
        "trigger",
        "custom_instructions",
        "prompt",
        "last_assistant_message",
    }
    for field in string_fields & payload.keys():
        _bounded_string(payload[field], field)
    for field in ("tool_input",):
        if field in payload and not isinstance(payload[field], Mapping):
            raise HookPayloadError(f"{field} must be a strict JSON object")
    if event == "SessionStart" and payload["source"] not in _SESSION_SOURCES:
        raise HookPayloadError("SessionStart source is not recognized")
    if event == "PreCompact" and payload["trigger"] not in _COMPACT_TRIGGERS:
        raise HookPayloadError("PreCompact trigger is not recognized")
    if event == "Stop" and not isinstance(payload["stop_hook_active"], bool):
        raise HookPayloadError("Stop stop_hook_active must be boolean")


@dataclass(frozen=True)
class NormalizedHookPayload:
    event: str
    visible: Mapping[str, Any]
    visible_sha256: str
    visible_bytes: int
    redacted_transcript: str | None
    transcript_sha256: str | None
    raw_payload_hmac: str
    redacted_or_truncated: bool
    unknown_fields_removed: int


def validate_hook_payload(
    *,
    event: str,
    raw: bytes | Mapping[str, Any],
    binding: ContextBinding,
    authority_key: bytes,
    transcript_excerpt: bytes | str | None = None,
) -> NormalizedHookPayload:
    """Validate, minimize, and redact one hook input without persisting raw data."""

    if event not in REQUIRED_HOOKS or event not in _EVENT_FIELDS:
        raise HookPayloadError(f"unknown Bello hook event: {event!r}")
    payload = _load_raw_payload(raw)
    required, optional = _EVENT_FIELDS[event]
    allowed = _COMMON_REQUIRED | _COMMON_OPTIONAL | required | optional
    missing = (_COMMON_REQUIRED | required) - payload.keys()
    if missing:
        raise HookPayloadError(f"{event} hook payload is missing fields: {sorted(missing)!r}")
    if payload["hook_event_name"] != event:
        raise HookPayloadError("hook payload event does not match the requested hook")
    if payload["session_id"] != binding.stable.context_session_id:
        raise HookPayloadError("hook payload session does not match active binding")
    if payload["cwd"] != binding.stable.workspace_path:
        raise HookPayloadError("hook payload cwd does not match active workspace")
    for field in _COMMON_REQUIRED:
        _bounded_string(payload[field], field)
    if "transcript_path" in payload:
        _bounded_string(payload["transcript_path"], "transcript_path")
    _validate_event_fields(event, payload)
    unknown_count = len(set(payload) - allowed)
    event_input = {
        key: payload[key]
        for key in sorted(required | optional)
        if key in payload
    }
    summary = bounded_redacted_summary(
        event_input,
        authority_key=authority_key,
        maximum_event_bytes=MAX_VISIBLE_HOOK_BYTES - 512,
    )
    redacted_input = dict(summary.value)
    # Correlation is broker-only; never expose it to the hook process.
    redacted_input.pop("correlation_digest", None)
    visible = {
        "schema_version": HOOK_PAYLOAD_SCHEMA_VERSION,
        "event": event,
        "input": redacted_input,
        "redaction": {
            "redacted_or_truncated": summary.redacted_or_truncated,
            "unknown_fields_removed": unknown_count,
        },
    }
    visible_encoded = canonical_json_bytes(visible)
    if len(visible_encoded) > MAX_VISIBLE_HOOK_BYTES:
        raise HookPayloadError("redacted hook payload exceeds 32 KiB")

    transcript: str | None = None
    transcript_digest: str | None = None
    transcript_changed = False
    if transcript_excerpt is not None:
        if not isinstance(transcript_excerpt, (bytes, bytearray, str)):
            raise HookPayloadError("transcript excerpt must be text or bytes")
        try:
            raw_transcript_bytes = (
                len(transcript_excerpt)
                if isinstance(transcript_excerpt, (bytes, bytearray))
                else len(transcript_excerpt.encode("utf-8"))
            )
        except UnicodeError as exc:
            raise HookPayloadError("transcript excerpt is not valid UTF-8 text") from exc
        if raw_transcript_bytes > MAX_RAW_TRANSCRIPT_BYTES:
            raise HookPayloadError("raw transcript excerpt exceeds 256 KiB")
        try:
            transcript_text = (
                bytes(transcript_excerpt).decode("utf-8", errors="strict")
                if isinstance(transcript_excerpt, (bytes, bytearray))
                else transcript_excerpt
            )
        except UnicodeError as exc:
            raise HookPayloadError("transcript excerpt is not UTF-8") from exc
        if not isinstance(transcript_text, str):
            raise HookPayloadError("transcript excerpt must be text or bytes")
        transcript, transcript_changed = redact_text(
            transcript_text,
            maximum_bytes=MAX_REDACTED_TRANSCRIPT_BYTES,
        )
        transcript_digest = hashlib.sha256(transcript.encode("utf-8")).hexdigest()

    raw_hmac = correlation_hmac(authority_key, payload)
    return NormalizedHookPayload(
        event=event,
        visible=visible,
        visible_sha256=hashlib.sha256(visible_encoded).hexdigest(),
        visible_bytes=len(visible_encoded),
        redacted_transcript=transcript,
        transcript_sha256=transcript_digest,
        raw_payload_hmac=raw_hmac,
        redacted_or_truncated=summary.redacted_or_truncated or transcript_changed,
        unknown_fields_removed=unknown_count,
    )


@dataclass(frozen=True)
class HookPayloadReceipt:
    schema_version: int
    contract_digest: str
    invocation_id: str
    event: str
    run_id: str
    workspace_id: str
    context_session_id: str
    context_state_epoch: int
    binding_digest: str
    binding_version: int
    coder_generation: int
    generation_lease_id: str
    coder_process_epoch: int
    app_server_instance_id: str
    hook_policy_digest: str
    visible_sha256: str
    visible_bytes: int
    transcript_sha256: str | None
    raw_payload_hmac: str
    redacted_or_truncated: bool
    unknown_fields_removed: int
    request_hmac: str
    expires_at: float


class HookInvocationReplayGuard:
    """Bounded in-memory one-shot claims; no raw hook material is retained."""

    def __init__(
        self,
        authority_key: bytes,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if len(authority_key) < 32:
            raise HookPayloadError("hook authority key must contain at least 256 bits")
        self._key = bytes(authority_key)
        self._clock = clock
        self._active: dict[str, tuple[str, HookPayloadReceipt]] = {}
        self._seen: dict[str, float] = {}

    def issue(
        self,
        *,
        invocation_id: str,
        claim_token: str,
        request_id: int | str,
        normalized: NormalizedHookPayload,
        binding: ContextBinding,
        hook_policy_digest: str,
        ttl_seconds: int = HOOK_INVOCATION_TTL_SECONDS,
    ) -> HookPayloadReceipt:
        invocation_id = require_nonempty(invocation_id, "invocation_id")
        claim_token = require_nonempty(claim_token, "claim_token")
        hook_policy_digest = require_sha256(hook_policy_digest, "hook_policy_digest")
        self.cleanup_expired()
        if invocation_id in self._active or invocation_id in self._seen:
            raise HookPayloadReplayError("hook invocation identity was already used")
        if len(self._active) >= MAX_ACTIVE_HOOK_INVOCATIONS:
            raise HookPayloadError("too many active hook invocations")
        if isinstance(request_id, bool) or not isinstance(request_id, (int, str)):
            raise HookPayloadError("hook request_id must be a JSON-RPC string or integer")
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or not 1 <= ttl_seconds <= 300:
            raise HookPayloadError("hook invocation TTL must be between 1 and 300 seconds")
        request_hmac = correlation_hmac(
            self._key,
            {
                "domain": "bello-hook-request-v1",
                "request_id": request_id,
                "event": normalized.event,
                "binding": binding.to_dict(),
                "visible_sha256": normalized.visible_sha256,
                "hook_policy_digest": hook_policy_digest,
            },
        )
        receipt = HookPayloadReceipt(
            HOOK_PAYLOAD_SCHEMA_VERSION,
            HOOK_PAYLOAD_CONTRACT_DIGEST,
            invocation_id,
            normalized.event,
            binding.stable.run_id,
            binding.stable.workspace_id,
            binding.stable.context_session_id,
            binding.lifecycle.context_state_epoch,
            digest_json(binding.to_dict()),
            binding.binding_version,
            binding.lifecycle.coder_generation,
            binding.lifecycle.generation_lease_id,
            binding.lifecycle.coder_process_epoch,
            binding.lifecycle.app_server_instance_id,
            hook_policy_digest,
            normalized.visible_sha256,
            normalized.visible_bytes,
            normalized.transcript_sha256,
            normalized.raw_payload_hmac,
            normalized.redacted_or_truncated,
            normalized.unknown_fields_removed,
            request_hmac,
            self._clock() + ttl_seconds,
        )
        token_hmac = hmac.new(self._key, claim_token.encode("utf-8"), hashlib.sha256).hexdigest()
        self._active[invocation_id] = (token_hmac, receipt)
        return receipt

    def claim(
        self,
        *,
        invocation_id: str,
        claim_token: str,
        active_binding: ContextBinding,
        hook_policy_digest: str,
    ) -> HookPayloadReceipt:
        self.cleanup_expired()
        record = self._active.pop(invocation_id, None)
        if record is None:
            raise HookPayloadReplayError("hook invocation is missing, expired, or already claimed")
        token_hmac, receipt = record
        supplied = hmac.new(self._key, claim_token.encode("utf-8"), hashlib.sha256).hexdigest()
        # A failed claim consumes the one-shot identity as well.
        self._remember(invocation_id, receipt.expires_at)
        if not hmac.compare_digest(token_hmac, supplied):
            raise HookPayloadReplayError("hook invocation claim token mismatch")
        hook_policy_digest = require_sha256(hook_policy_digest, "hook_policy_digest")
        if (
            receipt.binding_digest != digest_json(active_binding.to_dict())
            or receipt.binding_version != active_binding.binding_version
            or receipt.generation_lease_id != active_binding.lifecycle.generation_lease_id
            or receipt.hook_policy_digest != hook_policy_digest
        ):
            raise HookPayloadReplayError("hook invocation authority is stale")
        return receipt

    def cleanup_expired(self) -> None:
        now = self._clock()
        for invocation_id, (_token, receipt) in list(self._active.items()):
            if receipt.expires_at <= now:
                self._active.pop(invocation_id, None)
                self._remember(invocation_id, receipt.expires_at)

    def _remember(self, invocation_id: str, expires_at: float) -> None:
        if len(self._seen) >= MAX_SEEN_HOOK_INVOCATIONS:
            oldest = min(self._seen, key=self._seen.__getitem__)
            self._seen.pop(oldest, None)
        # Keep completed/expired identities replay-blocked for this bounded
        # run-local guard; only capacity eviction can forget an old identity.
        self._seen[invocation_id] = self._clock()
