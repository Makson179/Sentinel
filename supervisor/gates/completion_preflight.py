from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

from supervisor.schemas import (
    ApprovalContext,
    Certainty,
    ChangedFile,
    CompletionReturnRecord,
    InspectionRun,
    ValidationRun,
)
from supervisor.workspace_state import WorkspaceState


class CompletionPreflightDisposition(str, Enum):
    CERTAINLY_INADMISSIBLE = "certainly_inadmissible"
    REVIEW = "review"
    DEFER = "defer"


class CompletionAttempt(BaseModel):
    completion_attempt_id: str
    generation: int
    marker_sequence: int
    coder_message_sequence: int
    review_state_id: str | None = None
    created_at_sequence: int
    deferred: bool = False
    defer_reasons: list[str] = Field(default_factory=list)


class AcceptanceFacts(BaseModel):
    completion_attempt_id: str
    generation: int
    final_workspace_state: WorkspaceState | None = None
    changed_files: list[ChangedFile] = Field(default_factory=list)
    latest_relevant_change_sequence: int | None = None
    validations: list[ValidationRun] = Field(default_factory=list)
    inspections: list[InspectionRun] = Field(default_factory=list)
    previous_completion_returns: list[CompletionReturnRecord] = Field(default_factory=list)
    pending_approvals: list[ApprovalContext] = Field(default_factory=list)
    task_contents: str = ""
    unsupported_reasons: list[str] = Field(default_factory=list)


class CompletionPreflightResult(BaseModel):
    disposition: CompletionPreflightDisposition
    hard_gap_codes: list[str] = Field(default_factory=list)
    uncertainty_reasons: list[str] = Field(default_factory=list)
    review_risk_flags: list[str] = Field(default_factory=list)
    completion_attempt_id: str
    final_workspace_state_id: str | None = None

    @classmethod
    def review_due_to_unknown(cls, facts: AcceptanceFacts, reason: str) -> "CompletionPreflightResult":
        return cls(
            disposition=CompletionPreflightDisposition.REVIEW,
            uncertainty_reasons=[reason],
            completion_attempt_id=facts.completion_attempt_id,
            final_workspace_state_id=facts.final_workspace_state.state_id if facts.final_workspace_state else None,
        )


def build_completion_attempt_id(*, generation: int, marker_sequence: int, state_id: str | None) -> str:
    payload = {"generation": generation, "marker_sequence": marker_sequence, "state_id": state_id or "unknown"}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()
    return f"completion-{generation}-{marker_sequence}-{digest[:12]}"


def behavioral_floor_required(facts: AcceptanceFacts) -> Certainty:
    if facts.unsupported_reasons:
        return Certainty.UNKNOWN
    material_files = [file for file in facts.changed_files if _material_behavioral_file(file.path)]
    if material_files:
        return Certainty.TRUE
    unknown_files = [file for file in facts.changed_files if _file_kind(file.path) == "unknown"]
    if unknown_files:
        return Certainty.UNKNOWN
    return Certainty.FALSE


def validation_is_behavior_proving(validation: ValidationRun) -> Certainty:
    if validation.type in {"behavioral", "behavior_demo"}:
        return Certainty.TRUE
    if validation.type == "static":
        return Certainty.FALSE
    return Certainty.UNKNOWN


def validation_is_trusted_pass(validation: ValidationRun) -> Certainty:
    if validation.trusted_validation_outcome == "masked_or_unknown":
        return Certainty.FALSE
    if validation.outcome == "pass" and validation.passed and validation.trusted_validation_outcome == "passed":
        return Certainty.TRUE
    if validation.exit_code is None or validation.completion_status == "unknown":
        return Certainty.UNKNOWN
    return Certainty.FALSE


def validation_applies_to_final_state(validation: ValidationRun, facts: AcceptanceFacts) -> Certainty:
    trusted = validation_is_trusted_pass(validation)
    if trusted is not Certainty.TRUE:
        return trusted
    if validation_is_behavior_proving(validation) is Certainty.FALSE:
        return Certainty.FALSE

    state = facts.final_workspace_state
    if state is not None:
        if state.certainty is not Certainty.TRUE or state.state_id is None:
            return Certainty.UNKNOWN
        if validation.workspace_state_after_id is None:
            return Certainty.UNKNOWN
        return Certainty.TRUE if validation.workspace_state_after_id == state.state_id else Certainty.FALSE

    latest = facts.latest_relevant_change_sequence
    if latest is None:
        return Certainty.UNKNOWN
    if validation.sequence is None:
        return Certainty.UNKNOWN
    return Certainty.TRUE if validation.sequence > latest else Certainty.FALSE


def evaluate_final_behavioral_floor(facts: AcceptanceFacts) -> Certainty:
    required = behavioral_floor_required(facts)
    if required is not Certainty.TRUE:
        return required
    applicable: list[Certainty] = []
    for validation in facts.validations:
        if validation_is_behavior_proving(validation) is Certainty.FALSE:
            continue
        applicable.append(validation_applies_to_final_state(validation, facts))
    if any(result is Certainty.TRUE for result in applicable):
        return Certainty.TRUE
    if any(result is Certainty.UNKNOWN for result in applicable):
        return Certainty.UNKNOWN
    return Certainty.FALSE


def certainly_missing_required_behavioral_validation(facts: AcceptanceFacts) -> Certainty:
    required = behavioral_floor_required(facts)
    if required is Certainty.FALSE:
        return Certainty.FALSE
    if required is Certainty.UNKNOWN:
        return Certainty.UNKNOWN
    if facts.final_workspace_state is None:
        return Certainty.UNKNOWN
    if facts.final_workspace_state.certainty is not Certainty.TRUE or facts.final_workspace_state.state_id is None:
        return Certainty.UNKNOWN
    floor = evaluate_final_behavioral_floor(facts)
    if floor is Certainty.FALSE:
        return Certainty.TRUE
    if floor is Certainty.TRUE:
        return Certainty.FALSE
    return Certainty.UNKNOWN


def evaluate_completion_preflight(facts: AcceptanceFacts) -> CompletionPreflightResult:
    try:
        if facts.pending_approvals:
            return CompletionPreflightResult(
                disposition=CompletionPreflightDisposition.DEFER,
                review_risk_flags=["pending_approval"],
                completion_attempt_id=facts.completion_attempt_id,
                final_workspace_state_id=facts.final_workspace_state.state_id if facts.final_workspace_state else None,
            )
        result = certainly_missing_required_behavioral_validation(facts)
    except Exception as exc:
        return CompletionPreflightResult.review_due_to_unknown(facts, f"preflight_exception:{exc.__class__.__name__}")

    state_id = facts.final_workspace_state.state_id if facts.final_workspace_state else None
    if result is Certainty.TRUE:
        return CompletionPreflightResult(
            disposition=CompletionPreflightDisposition.CERTAINLY_INADMISSIBLE,
            hard_gap_codes=["NO_VALIDATION_FOR_FINAL_STATE"],
            completion_attempt_id=facts.completion_attempt_id,
            final_workspace_state_id=state_id,
        )
    if result is Certainty.UNKNOWN:
        return CompletionPreflightResult(
            disposition=CompletionPreflightDisposition.REVIEW,
            uncertainty_reasons=["behavioral_floor_unknown"],
            completion_attempt_id=facts.completion_attempt_id,
            final_workspace_state_id=state_id,
        )
    return CompletionPreflightResult(
        disposition=CompletionPreflightDisposition.REVIEW,
        completion_attempt_id=facts.completion_attempt_id,
        final_workspace_state_id=state_id,
    )


def _material_behavioral_file(path: str) -> bool:
    return _file_kind(path) in {"source", "test"} and not _is_non_material_path(path)


def _file_kind(path: str) -> Literal["source", "test", "config", "docs", "unknown"]:
    lowered = path.lower().replace("\\", "/")
    name = lowered.rsplit("/", 1)[-1]
    if (
        lowered.startswith(("tests/", "test/", "fixtures/", "fixture/"))
        or "/tests/" in lowered
        or "/test/" in lowered
        or "/__tests__/" in lowered
        or ".test." in name
        or ".spec." in name
        or name.startswith("test_")
        or name.endswith(("_test.py", "_spec.rb", ".snap", ".snapshot", ".golden"))
    ):
        return "test"
    if lowered.endswith((".toml", ".yaml", ".yml", ".json", ".ini", ".cfg")) or name in {
        "package.json",
        "pyproject.toml",
        "setup.cfg",
        "tox.ini",
        "pytest.ini",
        "tsconfig.json",
    }:
        return "config"
    if lowered.endswith((".md", ".rst", ".txt", ".adoc")):
        return "docs"
    if lowered.endswith(
        (
            ".py",
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".mjs",
            ".cjs",
            ".rb",
            ".go",
            ".rs",
            ".java",
            ".kt",
            ".cs",
            ".php",
            ".swift",
            ".c",
            ".cc",
            ".cpp",
            ".h",
            ".hpp",
            ".css",
            ".scss",
            ".html",
            ".vue",
            ".svelte",
        )
    ):
        return "source"
    return "unknown"


def _is_non_material_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower().strip("/")
    parts = set(normalized.split("/"))
    if parts & {"node_modules", "vendor", "dist", "build", "target", "coverage", "__generated__", "generated", ".next", ".cache"}:
        return True
    name = normalized.rsplit("/", 1)[-1]
    return name.endswith((".min.js", ".lock"))
