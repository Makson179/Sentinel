from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, Field

from supervisor.schemas import ChangedFile, TriggeringAction, ValidationRun


class RuntimeWakeGateDecision(BaseModel):
    action: Literal["emit_wake", "coalesce_until_turn_end", "suppress_exact_duplicate"]
    reason_codes: list[str] = Field(default_factory=list)
    risk_fingerprint: str


@dataclass
class _QueuedWake:
    fingerprint: str
    reason_codes: list[str]


@dataclass
class RuntimeWakeGate:
    _last_emitted_fingerprint: str | None = None
    _last_emitted_context: tuple[int, str | None] | None = None
    _last_large_diff_band: tuple[int, str | None, int] | None = None
    _queued: _QueuedWake | None = None
    _seen_suspicious: set[tuple[int, str | None, str, str, str]] = field(default_factory=set)

    def evaluate(
        self,
        *,
        generation: int,
        turn_id: str | None,
        reasons: list[str],
        action: TriggeringAction | None,
        changed_files: list[ChangedFile],
        validation: ValidationRun | None,
        pending_approval_ids: list[int | str],
        large_diff_threshold_lines: int = 500,
    ) -> RuntimeWakeGateDecision:
        fingerprint = runtime_risk_fingerprint(
            generation=generation,
            turn_id=turn_id,
            reasons=reasons,
            action=action,
            changed_files=changed_files,
            validation=validation,
            pending_approval_ids=pending_approval_ids,
            large_diff_threshold_lines=large_diff_threshold_lines,
        )
        context = (generation, turn_id)
        if self._last_emitted_context == context and self._last_emitted_fingerprint == fingerprint:
            return RuntimeWakeGateDecision(
                action="suppress_exact_duplicate",
                reason_codes=["exact_duplicate_runtime_risk"],
                risk_fingerprint=fingerprint,
            )

        material_reasons = set(reasons)
        bypass_reasons = material_reasons & {
            "nonzero_exit",
            "timeout",
            "masked_validation",
            "validation_regression",
            "repeated_same_failing_validation",
            "suspicious_file_touched",
            "restart_budget",
            "readiness_marker",
            "state_corruption",
            "controller_inconsistency",
        }
        if material_reasons == {"large_diff"} and not bypass_reasons:
            band = _large_diff_band(changed_files, threshold=large_diff_threshold_lines)
            band_key = (generation, turn_id, band)
            if self._last_large_diff_band == band_key:
                self._queued = _QueuedWake(
                    fingerprint=fingerprint,
                    reason_codes=["large_diff_same_band"],
                )
                return RuntimeWakeGateDecision(
                    action="coalesce_until_turn_end",
                    reason_codes=["large_diff_same_band"],
                    risk_fingerprint=fingerprint,
                )
            self._last_large_diff_band = band_key

        self.mark_emitted(generation=generation, turn_id=turn_id, fingerprint=fingerprint)
        return RuntimeWakeGateDecision(action="emit_wake", reason_codes=list(reasons), risk_fingerprint=fingerprint)

    def mark_emitted(self, *, generation: int, turn_id: str | None, fingerprint: str) -> None:
        self._last_emitted_context = (generation, turn_id)
        self._last_emitted_fingerprint = fingerprint
        if self._queued and self._queued.fingerprint == fingerprint:
            self._queued = None

    def flush_turn_end(self, *, generation: int, turn_id: str | None) -> RuntimeWakeGateDecision | None:
        queued = self._queued
        if queued is None:
            return None
        self._queued = None
        self.mark_emitted(generation=generation, turn_id=turn_id, fingerprint=queued.fingerprint)
        return RuntimeWakeGateDecision(
            action="emit_wake",
            reason_codes=["turn_end_coalesced_flush", *queued.reason_codes],
            risk_fingerprint=queued.fingerprint,
        )

    def reset(self) -> None:
        self._last_emitted_fingerprint = None
        self._last_emitted_context = None
        self._last_large_diff_band = None
        self._queued = None
        self._seen_suspicious.clear()


def runtime_risk_fingerprint(
    *,
    generation: int,
    turn_id: str | None,
    reasons: list[str],
    action: TriggeringAction | None,
    changed_files: list[ChangedFile],
    validation: ValidationRun | None,
    pending_approval_ids: list[int | str],
    large_diff_threshold_lines: int,
) -> str:
    payload: dict[str, Any] = {
        "generation": generation,
        "turn_id": turn_id,
        "reasons": sorted(dict.fromkeys(reasons)),
        "action": {
            "kind": action.kind if action is not None else None,
            "command": _normalized(action.command) if action is not None else None,
            "cwd": action.cwd if action is not None else None,
            "exit_code": action.exit_code if action is not None else None,
            "status": action.status if action is not None else None,
        },
        "changed_paths": [
            {
                "path": changed.path,
                "status": changed.status,
                "band": _change_size_band(changed),
            }
            for changed in sorted(changed_files, key=lambda item: item.path)
        ],
        "large_diff_band": _large_diff_band(changed_files, threshold=large_diff_threshold_lines),
        "changed_line_total": sum((changed.additions or 0) + (changed.deletions or 0) for changed in changed_files),
        "validation": {
            "run_id": validation.validation_run_id if validation is not None else None,
            "signature_id": validation.validation_signature_id or validation.validation_id if validation is not None else None,
            "outcome": validation.trusted_validation_outcome if validation is not None else None,
            "type": validation.type if validation is not None else None,
        },
        "pending_approval_ids": sorted(str(item) for item in pending_approval_ids),
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return f"runtime-risk-{digest[:24]}"


def _normalized(value: str | None) -> str | None:
    if value is None:
        return None
    return " ".join(value.strip().split())


def _change_size_band(changed: ChangedFile) -> str:
    total = (changed.additions or 0) + (changed.deletions or 0)
    if total >= 4000:
        return "huge"
    if total >= 2000:
        return "xlarge"
    if total >= 1000:
        return "large"
    if total >= 500:
        return "medium"
    return "small"


def _large_diff_band(changed_files: list[ChangedFile], *, threshold: int) -> int:
    changed_lines = sum((changed.additions or 0) + (changed.deletions or 0) for changed in changed_files)
    size = max(changed_lines, len(changed_files) * max(threshold // 10, 1))
    if size < threshold:
        return 0
    band = 1
    current = threshold
    while size >= current * 2 and band < 16:
        current *= 2
        band *= 2
    return band
