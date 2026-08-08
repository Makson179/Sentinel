from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from supervisor.appserver import AppServerClient, AppServerError, last_agent_message_text, text_input
from supervisor.project_config import MODEL_GPT_5_6_LUNA
from supervisor.prompts import build_cheap_runtime_prompt
from supervisor.schemas import (
    CheapRuntimeDecision,
    PriorIntervention,
    SupervisorWakePacket,
    TriggeringAction,
    ValidationRun,
)
from supervisor.schemas.models import openai_strict_json_schema_for_cheap_runtime_decision
from supervisor.supervisor_agent import _agent_message_text_from_turns, _parse_json_object


# Default cheap-triage model: the efficient GPT-5.6 variant for frequent,
# narrow runtime routing decisions.
DEFAULT_TRIAGE_MODEL = MODEL_GPT_5_6_LUNA

RUNTIME_TRIAGE_MODEL_ENV = "BELLO_RUNTIME_TRIAGE_MODEL"
RUNTIME_TRIAGE_TIMEOUT_ENV = "BELLO_RUNTIME_TRIAGE_TIMEOUT"
DEFAULT_RUNTIME_TRIAGE_TIMEOUT_SECONDS = 25.0

@dataclass(frozen=True)
class CheapRuntimeTriageConfig:
    enabled: bool
    model: str | None
    timeout_seconds: float = DEFAULT_RUNTIME_TRIAGE_TIMEOUT_SECONDS


def runtime_triage_config_from_env(*, enabled: bool = True) -> CheapRuntimeTriageConfig:
    # The project config owns the on/off switch; env remains available for advanced
    # model and timeout overrides.
    model = _env_str(os.environ.get(RUNTIME_TRIAGE_MODEL_ENV)) or DEFAULT_TRIAGE_MODEL
    timeout_seconds = _env_float(os.environ.get(RUNTIME_TRIAGE_TIMEOUT_ENV), DEFAULT_RUNTIME_TRIAGE_TIMEOUT_SECONDS)
    return CheapRuntimeTriageConfig(enabled=enabled, model=model, timeout_seconds=timeout_seconds)


class CheapRuntimeReviewerError(RuntimeError):
    pass


def _bounded(text: str, limit: int) -> str:
    if not text:
        return text or ""
    return text if len(text) <= limit else text[:limit] + "…"


_RUNTIME_TRIGGER_RE = re.compile(r"^\s*Runtime trigger \(([^)]*)\):")
_COMMAND_WAKE_RE = re.compile(r"^command completed: (?P<command>.*) exit=(?P<exit>-?\d+)$", re.DOTALL)
_VALIDATION_REQUEST_RE = re.compile(
    r"\b(?:asserting|audit|behavioral|check|comparator|comparison|differential|exact|probe|rerun|"
    r"test|validate|validation)\b",
    re.IGNORECASE,
)
_STOP_AND_VALIDATE_RE = re.compile(
    r"\b(?:"
    r"before (?:any )?(?:further|another|the next) (?:semantic )?(?:edit|change)|"
    r"before making (?:any )?further (?:semantic )?(?:edit|change)|"
    r"make no further (?:semantic )?(?:edit|change)|"
    r"do not (?:edit|make (?:another|further) (?:semantic )?(?:edit|change))|"
    r"stop editing"
    r")",
    re.IGNORECASE,
)
_BUILD_ONLY_RE = re.compile(
    r"(?:^|[;&|\s])(?:\./)?(?:compile\.sh|build\.sh)(?:\s|$)|"
    r"\b(?:cargo\s+(?:build|check)|go\s+build|npm\s+run\s+build|pnpm\s+build|yarn\s+build|"
    r"python(?:3)?\s+-m\s+py_compile|make(?:\s|$))",
    re.IGNORECASE,
)


def _runtime_trigger_reasons(summary: str | None) -> list[str]:
    match = _RUNTIME_TRIGGER_RE.match(summary or "")
    if not match:
        return []
    return [reason.strip() for reason in match.group(1).split(",") if reason.strip()]


def _trigger_detail(summary: str | None) -> str:
    value = summary or ""
    match = _RUNTIME_TRIGGER_RE.match(value)
    return value[match.end() :].lstrip() if match else value


def _effective_triggering_action(packet: SupervisorWakePacket) -> TriggeringAction | None:
    if packet.triggering_action is not None:
        return packet.triggering_action
    detail = _trigger_detail(packet.current_summary)
    command_match = _COMMAND_WAKE_RE.match(detail)
    if command_match:
        exit_code = int(command_match.group("exit"))
        return TriggeringAction(
            item_id=packet.triggering_item_id,
            kind="commandExecution",
            command=command_match.group("command"),
            exit_code=exit_code,
            status="completed" if exit_code == 0 else "failed",
            summary=detail,
        )
    if detail.startswith("file change completed:"):
        sequenced = [changed for changed in packet.changed_files if changed.sequence is not None]
        latest_sequence = max((changed.sequence for changed in sequenced), default=None)
        paths = [
            changed.path
            for changed in packet.changed_files
            if latest_sequence is None or changed.sequence == latest_sequence
        ]
        return TriggeringAction(
            item_id=packet.triggering_item_id,
            kind="fileChange",
            paths=paths,
            status="completed",
            summary=detail,
        )
    return None


def _validation_snapshot(validation: ValidationRun) -> dict[str, Any]:
    return {
        "validation_id": validation.validation_id,
        "sequence": validation.sequence,
        "type": validation.type,
        "command": _bounded(validation.command or "", 240),
        "shell_exit_code": validation.shell_exit_code,
        "outcome": validation.outcome,
        "trusted_validation_outcome": validation.trusted_validation_outcome,
        "masking_reason": validation.masking_reason,
        "captured_output_present": bool(validation.captured_output.strip()),
        "captured_output_truncated": validation.captured_output_truncated,
        "summary": _bounded(validation.summary or "", 400),
    }


def _triggering_validation_from_ledger(
    action: TriggeringAction | None,
    validations: list[ValidationRun],
) -> ValidationRun | None:
    if action is None:
        return None
    if not action.command:
        return None
    normalized_action = " ".join(action.command.strip().split())
    for validation in reversed(validations):
        normalized_validation = validation.normalized_command or " ".join(validation.command.strip().split())
        if normalized_validation != normalized_action:
            continue
        validation_exit = (
            validation.shell_exit_code if validation.shell_exit_code is not None else validation.exit_code
        )
        if action.exit_code is not None and validation_exit != action.exit_code:
            continue
        return validation
    return None


def _trigger_sequence(
    packet: SupervisorWakePacket,
    action: TriggeringAction | None,
    triggering_validation: ValidationRun | None,
) -> int | None:
    if triggering_validation is not None:
        return triggering_validation.sequence
    if action is not None and action.item_id:
        for event in reversed(packet.recent_events or []):
            if event.get("item_id") != action.item_id:
                continue
            sequence = event.get("sequence")
            if isinstance(sequence, int):
                return sequence
    if action is not None and action.kind == "fileChange":
        return max(
            (changed.sequence for changed in packet.changed_files if changed.sequence is not None),
            default=None,
        )
    return None


def _intervention_snapshot(intervention: PriorIntervention) -> dict[str, Any]:
    return {
        "sequence": intervention.sequence,
        "reason": _bounded(intervention.reason or "", 300),
        "instruction": _bounded(intervention.message_to_coder or "", 300),
    }


def _latest_matching_intervention(
    packet: SupervisorWakePacket,
    pattern: re.Pattern[str],
) -> PriorIntervention | None:
    for intervention in reversed(packet.prior_interventions or []):
        text = f"{intervention.message_to_coder or ''}\n{intervention.reason or ''}"
        if pattern.search(text):
            return intervention
    return None


def cheap_runtime_packet(packet: SupervisorWakePacket) -> dict[str, Any]:
    """Build a trigger-scoped snapshot without presenting stale ledger entries as current risk."""
    action = _effective_triggering_action(packet)
    validations = list(packet.validations or [])
    triggering_validation = _triggering_validation_from_ledger(action, validations)
    trigger_sequence = _trigger_sequence(packet, action, triggering_validation)
    followups = (
        [validation for validation in validations if validation.sequence > trigger_sequence][-2:]
        if trigger_sequence is not None
        else []
    )
    health = packet.health if isinstance(packet.health, dict) else {}
    changed_files = list(packet.changed_files or [])
    additions = sum(changed.additions or 0 for changed in changed_files)
    deletions = sum(changed.deletions or 0 for changed in changed_files)
    latest_behavioral_pass = max(
        (
            validation.sequence
            for validation in validations
            if validation.type in {"behavioral", "behavior_demo"}
            and validation.trusted_validation_outcome == "passed"
        ),
        default=None,
    )
    latest_relevant_change = packet.latest_relevant_change_sequence
    coder_message = packet.last_coder_message
    coder_text = coder_message.text if coder_message is not None else ""
    validation_request = _latest_matching_intervention(packet, _VALIDATION_REQUEST_RE)
    stop_and_validate = _latest_matching_intervention(packet, _STOP_AND_VALIDATE_RE)
    current_masked = (
        triggering_validation is not None
        and triggering_validation.trusted_validation_outcome == "masked_or_unknown"
    )
    trigger_reasons = _runtime_trigger_reasons(packet.current_summary)
    behavioral_validation_is_fresh = bool(
        latest_relevant_change is None
        or (latest_behavioral_pass is not None and latest_behavioral_pass >= latest_relevant_change)
    )
    action_after_stop_instruction = bool(
        action is not None
        and trigger_sequence is not None
        and stop_and_validate is not None
        and trigger_sequence > stop_and_validate.sequence
    )
    return {
        "wake_reason": packet.current_summary,
        "trigger_reasons": trigger_reasons,
        "triggering_action": (
            {
                "sequence": trigger_sequence,
                "kind": action.kind,
                "command": _bounded(action.command or "", 200),
                "summary": _bounded(action.summary or "", 300),
                "cwd": _bounded(action.cwd or "", 160),
                "paths": [_bounded(path, 160) for path in action.paths[:12]],
                "exit_code": action.exit_code,
                "status": action.status,
            }
            if action is not None
            else None
        ),
        "triggering_validation": (
            _validation_snapshot(triggering_validation) if triggering_validation is not None else None
        ),
        "followup_validations": [_validation_snapshot(validation) for validation in followups],
        "context_validations": (
            [_validation_snapshot(validation) for validation in validations[-2:]] if action is None else []
        ),
        "validation_state": {
            "latest_relevant_change_sequence": latest_relevant_change,
            "latest_trusted_behavioral_pass_sequence": latest_behavioral_pass,
            "trusted_behavioral_validation_is_fresh": behavioral_validation_is_fresh,
        },
        "recent_actions": [_bounded(str(value), 240) for value in (packet.last_actions or [])[-5:]],
        "prior_interventions": [
            _intervention_snapshot(intervention) for intervention in (packet.prior_interventions or [])[-6:]
        ],
        "latest_validation_request": (
            _intervention_snapshot(validation_request) if validation_request is not None else None
        ),
        "routing_signals": {
            "turn_boundary": (packet.current_summary or "").strip() == "Coder turn completed",
            "repeated_failure_with_incomplete_output": bool(
                "repeated_same_failing_validation" in trigger_reasons
                and triggering_validation is not None
                and (
                    triggering_validation.captured_output_truncated
                    or not triggering_validation.captured_output.strip()
                )
            ),
            "stale_edit_after_stop_and_validate": bool(
                action_after_stop_instruction
                and action is not None
                and action.kind == "fileChange"
                and not behavioral_validation_is_fresh
            ),
            "masked_result_after_validation_request": bool(
                validation_request is not None and current_masked and not behavioral_validation_is_fresh
            ),
            "masked_nonzero_after_validation_request": bool(
                validation_request is not None
                and "masked_validation" in trigger_reasons
                and "nonzero_exit" in trigger_reasons
                and not behavioral_validation_is_fresh
            ),
            "build_only_after_validation_request": bool(
                validation_request is not None
                and action is not None
                and bool(_BUILD_ONLY_RE.search(action.command or ""))
                and not behavioral_validation_is_fresh
            ),
            "failed_after_validation_request": bool(
                validation_request is not None
                and triggering_validation is not None
                and triggering_validation.trusted_validation_outcome == "failed"
            ),
        },
        "coder_context": {
            "last_message": _bounded(coder_text, 600),
            "message_sequence": coder_message.sequence if coder_message is not None else None,
            "message_after_trigger": bool(
                coder_message is not None
                and trigger_sequence is not None
                and coder_message.sequence > trigger_sequence
            ),
            "readiness_marker_present": any(
                line.strip() == "BELLO_READY_FOR_REVIEW" for line in coder_text.splitlines()
            ),
        },
        "diff": {
            "summary": _bounded(packet.diff_summary or "", 500),
            "changed_files_count": len(changed_files),
            "additions": additions,
            "deletions": deletions,
            "files": [
                {
                    "path": _bounded(changed.path, 160),
                    "status": changed.status,
                    "additions": changed.additions,
                    "deletions": changed.deletions,
                    "sequence": changed.sequence,
                }
                for changed in changed_files[:15]
            ],
        },
        "health_risk": {
            "risk_signals": [_bounded(str(value), 200) for value in (health.get("risk_signals") or [])[:10]],
            "consecutive_failed_tests": health.get("consecutive_failed_tests"),
            "repeated_command_count": health.get("repeated_command_count"),
            "minutes_without_progress": health.get("minutes_without_progress"),
            "restart_count": packet.restart_count,
        },
        "pending_approvals_count": len(packet.pending_approvals or []),
        "has_human_message": packet.human_message is not None,
    }


class CheapRuntimeReviewer:
    def __init__(
        self,
        client: AppServerClient,
        workspace: Path,
        *,
        model: str | None,
        timeout_seconds: float = DEFAULT_RUNTIME_TRIAGE_TIMEOUT_SECONDS,
        configured_mcp_server_names: tuple[str, ...] = (),
        configured_plugin_names: tuple[str, ...] = (),
        disable_apps: bool = True,
    ):
        self.client = client
        self.workspace = workspace.resolve()
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.configured_mcp_server_names = tuple(
            sorted({name.strip() for name in configured_mcp_server_names if name.strip()})
        )
        self.configured_plugin_names = tuple(
            sorted({name.strip() for name in configured_plugin_names if name.strip()})
        )
        self.disable_apps = disable_apps

    async def review(self, packet: SupervisorWakePacket) -> CheapRuntimeDecision:
        if not self.model:
            raise CheapRuntimeReviewerError("cheap runtime triage model is not configured")
        prompt = build_cheap_runtime_prompt(cheap_runtime_packet(packet))
        return await self._decide(prompt)

    async def _decide(self, prompt: str) -> CheapRuntimeDecision:
        thread_id: str | None = None
        turn_id: str | None = None
        try:
            thread_response = await asyncio.wait_for(
                self.client.thread_start(self._thread_params(), timeout=self.timeout_seconds),
                timeout=self.timeout_seconds,
            )
            thread = thread_response.get("thread", {})
            thread_id = thread.get("id") if isinstance(thread, dict) else None
            if not isinstance(thread_id, str):
                raise CheapRuntimeReviewerError("cheap runtime thread/start did not return thread id")
            turn_response = await asyncio.wait_for(
                self.client.turn_start(
                    {
                        "threadId": thread_id,
                        "input": [text_input(prompt)],
                        "approvalPolicy": "never",
                        "sandboxPolicy": {"type": "readOnly", "networkAccess": False},
                        "outputSchema": openai_strict_json_schema_for_cheap_runtime_decision(),
                        "model": self.model,
                    },
                    timeout=self.timeout_seconds,
                ),
                timeout=self.timeout_seconds,
            )
            turn = turn_response.get("turn", {})
            turn_id_value = turn.get("id")
            if not isinstance(turn_id_value, str):
                raise CheapRuntimeReviewerError("cheap runtime turn/start did not return turn id")
            turn_id = turn_id_value
            if turn.get("status") != "completed":
                try:
                    completed = await self.client.wait_for_notification(
                        lambda message: message.method == "turn/completed"
                        and message.params.get("threadId") == thread_id
                        and isinstance(message.params.get("turn"), dict)
                        and message.params["turn"].get("id") == turn_id,
                        timeout=self.timeout_seconds,
                    )
                except (asyncio.TimeoutError, AppServerError) as exc:
                    raise CheapRuntimeReviewerError("cheap runtime turn timed out") from exc
                turn = completed.params.get("turn", {})
            text = last_agent_message_text(turn)
            if text is None:
                turns = await asyncio.wait_for(
                    self.client.thread_turns_list(
                        thread_id,
                        limit=5,
                        items_view="full",
                        timeout=self.timeout_seconds,
                    ),
                    timeout=self.timeout_seconds,
                )
                text = _agent_message_text_from_turns(turns.get("data", []), turn_id=turn_id)
            if text is None:
                raise CheapRuntimeReviewerError("cheap runtime reviewer did not produce an agent message")
            return CheapRuntimeDecision.model_validate(_parse_json_object(text))
        except asyncio.TimeoutError as exc:
            raise CheapRuntimeReviewerError("cheap runtime reviewer timed out") from exc
        except (ValidationError, ValueError) as exc:
            raise CheapRuntimeReviewerError("invalid cheap runtime decision") from exc
        except CheapRuntimeReviewerError:
            raise
        except Exception as exc:
            raise CheapRuntimeReviewerError(f"cheap runtime reviewer failed: {exc.__class__.__name__}") from exc
        finally:
            if thread_id:
                await self._cleanup_thread(thread_id)

    def _thread_params(self) -> dict[str, Any]:
        thread_config: dict[str, Any] = {"include_apps_instructions": False}
        if self.configured_mcp_server_names:
            thread_config["mcp_servers"] = {
                name: {"enabled": False} for name in self.configured_mcp_server_names
            }
        if self.configured_plugin_names:
            thread_config["plugins"] = {
                name: {"enabled": False} for name in self.configured_plugin_names
            }
        if self.disable_apps:
            thread_config["apps"] = {"_default": {"enabled": False}}
        return {
            "cwd": str(self.workspace),
            "runtimeWorkspaceRoots": [str(self.workspace)],
            "approvalPolicy": "never",
            "approvalsReviewer": "user",
            "sandbox": "read-only",
            "ephemeral": False,
            "experimentalRawEvents": False,
            "persistExtendedHistory": False,
            "config": thread_config,
            "dynamicTools": [],
            "environments": [],
            "model": self.model,
        }

    async def _cleanup_thread(self, thread_id: str) -> None:
        cleanup_timeout = min(self.timeout_seconds, 10.0)
        try:
            await asyncio.wait_for(self.client.thread_archive(thread_id, timeout=cleanup_timeout), timeout=cleanup_timeout)
        except Exception:
            try:
                await asyncio.wait_for(self.client.thread_unsubscribe(thread_id, timeout=cleanup_timeout), timeout=cleanup_timeout)
            except Exception:
                return


def _env_str(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _env_float(value: str | None, default: float) -> float:
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError:
        return default
    return parsed if parsed > 0 else default
