from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from supervisor.appserver import AppServerClient, AppServerError, last_agent_message_text, text_input
from supervisor.policy import (
    CHEAP_REVIEW_BLOCK_TAGS,
    CommandAnalysis,
    analyze_command,
)
from supervisor.project_config import MODEL_GPT_5_6_LUNA
from supervisor.prompts import build_cheap_approval_prompt, build_cheap_runtime_prompt
from supervisor.schemas import (
    ApprovalContext,
    ApprovalRequestType,
    ApprovalResolution,
    CheapApprovalDecision,
    CheapRuntimeDecision,
    PolicyDecision,
    PolicyDecisionKind,
    SupervisorWakePacket,
)
from supervisor.schemas.models import (
    openai_strict_json_schema_for_cheap_approval_decision,
    openai_strict_json_schema_for_cheap_runtime_decision,
)
from supervisor.supervisor_agent import _agent_message_text_from_turns, _parse_json_object


# Default cheap-triage model: the efficient GPT-5.6 variant for the frequent,
# narrow approve/noop routing decisions.
DEFAULT_TRIAGE_MODEL = MODEL_GPT_5_6_LUNA

APPROVAL_TRIAGE_ENABLED_ENV = "SENTINEL_APPROVAL_TRIAGE_ENABLED"
APPROVAL_TRIAGE_MODEL_ENV = "SENTINEL_APPROVAL_TRIAGE_MODEL"
APPROVAL_TRIAGE_TIMEOUT_ENV = "SENTINEL_APPROVAL_TRIAGE_TIMEOUT"
DEFAULT_APPROVAL_TRIAGE_TIMEOUT_SECONDS = 20.0
CHEAP_APPROVAL_REASON = "low-impact command approved by cheap review"

RUNTIME_TRIAGE_ENABLED_ENV = "SENTINEL_RUNTIME_TRIAGE_ENABLED"
RUNTIME_TRIAGE_MODEL_ENV = "SENTINEL_RUNTIME_TRIAGE_MODEL"
RUNTIME_TRIAGE_TIMEOUT_ENV = "SENTINEL_RUNTIME_TRIAGE_TIMEOUT"
DEFAULT_RUNTIME_TRIAGE_TIMEOUT_SECONDS = 25.0


class CheapApprovalReviewerError(RuntimeError):
    pass


class CheapApprovalUnavailable(CheapApprovalReviewerError):
    pass


@dataclass(frozen=True)
class CheapApprovalTriageConfig:
    enabled: bool
    model: str | None
    timeout_seconds: float = DEFAULT_APPROVAL_TRIAGE_TIMEOUT_SECONDS


@dataclass(frozen=True)
class CheapApprovalAttempt:
    attempted: bool
    eligible: bool
    outcome: str
    reason_code: str | None = None
    latency_seconds: float | None = None
    model: str | None = None
    full_supervisor_fallback: bool = False


class CheapApprovalReviewer:
    def __init__(
        self,
        client: AppServerClient,
        workspace: Path,
        *,
        model: str | None,
        timeout_seconds: float = DEFAULT_APPROVAL_TRIAGE_TIMEOUT_SECONDS,
    ):
        self.client = client
        self.workspace = workspace.resolve()
        self.model = model
        self.timeout_seconds = timeout_seconds

    async def review(self, context: ApprovalContext, evaluation: PolicyDecision) -> CheapApprovalDecision:
        if not self.model:
            raise CheapApprovalUnavailable("cheap approval triage model is not configured")
        analysis = command_analysis_from_policy_decision(evaluation)
        if analysis is None:
            raise CheapApprovalReviewerError("policy evaluation did not include command analysis")
        packet = cheap_approval_packet(context, evaluation, analysis)
        prompt = build_cheap_approval_prompt(packet)
        return await self._decide(prompt)

    async def _decide(self, prompt: str) -> CheapApprovalDecision:
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
                raise CheapApprovalReviewerError("cheap approval thread/start did not return thread id")
            turn_response = await asyncio.wait_for(
                self.client.turn_start(
                    {
                        "threadId": thread_id,
                        "input": [text_input(prompt)],
                        "approvalPolicy": "never",
                        "sandboxPolicy": {"type": "readOnly", "networkAccess": False},
                        "outputSchema": openai_strict_json_schema_for_cheap_approval_decision(),
                        "model": self.model,
                    },
                    timeout=self.timeout_seconds,
                ),
                timeout=self.timeout_seconds,
            )
            turn = turn_response.get("turn", {})
            turn_id_value = turn.get("id")
            if not isinstance(turn_id_value, str):
                raise CheapApprovalReviewerError("cheap approval turn/start did not return turn id")
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
                    raise CheapApprovalReviewerError("cheap approval turn timed out") from exc
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
                raise CheapApprovalReviewerError("cheap approval reviewer did not produce an agent message")
            return CheapApprovalDecision.model_validate(_parse_json_object(text))
        except asyncio.TimeoutError as exc:
            raise CheapApprovalReviewerError("cheap approval reviewer timed out") from exc
        except (ValidationError, ValueError) as exc:
            raise CheapApprovalReviewerError("invalid cheap approval decision") from exc
        except CheapApprovalReviewerError:
            raise
        except Exception as exc:
            raise CheapApprovalReviewerError(f"cheap approval reviewer failed: {exc.__class__.__name__}") from exc
        finally:
            if thread_id:
                await self._cleanup_thread(thread_id)

    def _thread_params(self) -> dict[str, Any]:
        return {
            "cwd": str(self.workspace),
            "runtimeWorkspaceRoots": [str(self.workspace)],
            "approvalPolicy": "never",
            "approvalsReviewer": "user",
            "sandbox": "read-only",
            "ephemeral": False,
            "experimentalRawEvents": False,
            "persistExtendedHistory": False,
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


def cheap_approval_triage_config_from_env() -> CheapApprovalTriageConfig:
    # Disabled by default: deterministic approval gates should handle the obvious cases.
    enabled = _env_flag(os.environ.get(APPROVAL_TRIAGE_ENABLED_ENV), default=False)
    model = _env_str(os.environ.get(APPROVAL_TRIAGE_MODEL_ENV)) or DEFAULT_TRIAGE_MODEL
    timeout_seconds = _env_float(os.environ.get(APPROVAL_TRIAGE_TIMEOUT_ENV), DEFAULT_APPROVAL_TRIAGE_TIMEOUT_SECONDS)
    return CheapApprovalTriageConfig(enabled=enabled, model=model, timeout_seconds=timeout_seconds)


@dataclass(frozen=True)
class CheapRuntimeTriageConfig:
    enabled: bool
    model: str | None
    timeout_seconds: float = DEFAULT_RUNTIME_TRIAGE_TIMEOUT_SECONDS


def runtime_triage_config_from_env() -> CheapRuntimeTriageConfig:
    # Enabled by default with a cheap default model; env can override or disable.
    enabled = _env_flag(os.environ.get(RUNTIME_TRIAGE_ENABLED_ENV), default=True)
    model = _env_str(os.environ.get(RUNTIME_TRIAGE_MODEL_ENV)) or DEFAULT_TRIAGE_MODEL
    timeout_seconds = _env_float(os.environ.get(RUNTIME_TRIAGE_TIMEOUT_ENV), DEFAULT_RUNTIME_TRIAGE_TIMEOUT_SECONDS)
    return CheapRuntimeTriageConfig(enabled=enabled, model=model, timeout_seconds=timeout_seconds)


class CheapRuntimeReviewerError(RuntimeError):
    pass


def _bounded(text: str, limit: int) -> str:
    if not text:
        return text or ""
    return text if len(text) <= limit else text[:limit] + "…"


def cheap_runtime_packet(packet: SupervisorWakePacket) -> dict[str, Any]:
    """Slim snapshot for the cheap runtime router: only signals needed to route noop/escalate."""
    action = packet.triggering_action

    def vrun(v: Any) -> dict[str, Any]:
        return {
            "type": getattr(v, "type", None),
            "outcome": getattr(v, "outcome", None),
            "trusted_validation_outcome": getattr(v, "trusted_validation_outcome", None),
            "masking_reason": getattr(v, "masking_reason", None),
            "passed": getattr(v, "passed", None),
            "summary": _bounded(getattr(v, "summary", "") or "", 200),
        }

    health = packet.health if isinstance(packet.health, dict) else {}
    return {
        "wake_reason": packet.current_summary,
        "triggering_action": (
            {
                "kind": action.kind,
                "command": _bounded(action.command or "", 200),
                "exit_code": action.exit_code,
                "status": action.status,
            }
            if action is not None
            else None
        ),
        "diff_summary": _bounded(packet.diff_summary or "", 400),
        "changed_files_count": len(packet.changed_files or []),
        "validation_freshness_summary": _bounded(packet.validation_freshness_summary or "", 300),
        "recent_validations": [vrun(v) for v in (packet.validations or [])[-3:]],
        "recent_events": (packet.recent_events or [])[-8:],
        "health_risk": {
            "risk_signals": health.get("risk_signals"),
            "consecutive_failed_tests": health.get("consecutive_failed_tests"),
            "repeated_command_count": health.get("repeated_command_count"),
            "minutes_without_progress": health.get("minutes_without_progress"),
        },
        "pending_approvals_count": len(packet.pending_approvals or []),
        "has_human_message": packet.human_message is not None,
        "last_coder_message_present": packet.last_coder_message is not None,
    }


class CheapRuntimeReviewer:
    def __init__(
        self,
        client: AppServerClient,
        workspace: Path,
        *,
        model: str | None,
        timeout_seconds: float = DEFAULT_RUNTIME_TRIAGE_TIMEOUT_SECONDS,
    ):
        self.client = client
        self.workspace = workspace.resolve()
        self.model = model
        self.timeout_seconds = timeout_seconds

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
        return {
            "cwd": str(self.workspace),
            "runtimeWorkspaceRoots": [str(self.workspace)],
            "approvalPolicy": "never",
            "approvalsReviewer": "user",
            "sandbox": "read-only",
            "ephemeral": False,
            "experimentalRawEvents": False,
            "persistExtendedHistory": False,
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


def command_analysis_from_policy_decision(evaluation: PolicyDecision) -> CommandAnalysis | None:
    raw = evaluation.payload.get("command_analysis")
    if isinstance(raw, CommandAnalysis):
        return raw
    if isinstance(raw, dict):
        try:
            return CommandAnalysis.model_validate(raw)
        except ValidationError:
            return None
    return None


def is_cheap_review_candidate(context: ApprovalContext, evaluation: PolicyDecision, workspace: Path) -> bool:
    if context.request_type != ApprovalRequestType.COMMAND:
        return False
    if evaluation.kind != PolicyDecisionKind.ROUTE_LLM:
        return False
    if not context.command or not context.cwd:
        return False
    if context.network_approval_context is not None:
        return False
    if context.proposed_network_policy_amendments:
        return False
    if not _decision_available(context, "accept"):
        return False
    analysis = command_analysis_from_policy_decision(evaluation)
    if analysis is None:
        analysis = analyze_command(workspace, context.command, context.cwd)
    if analysis.command != context.command:
        return False
    # Expanded eligibility: any command without a hard-block tag may be cheap-reviewed
    # (including in-workspace filesystem writes), not just read-only commands. The cheap
    # model still escalates anything it can't deem safe; hard-block tags (grading-path,
    # destructive, network, escape, secret, interpreter execution, shell composition, ...)
    # are never eligible.
    if analysis.risk_tags & CHEAP_REVIEW_BLOCK_TAGS:
        return False
    return True


def cheap_approval_fingerprint(context: ApprovalContext, evaluation: PolicyDecision, workspace: Path) -> tuple[Any, ...]:
    analysis = command_analysis_from_policy_decision(evaluation) or analyze_command(workspace, context.command or "", context.cwd)
    return (
        context.request_type.value,
        context.server_request_method,
        context.server_request_id,
        context.command,
        context.cwd,
        tuple(context.available_decision_keys or ()),
        tuple(context.proposed_execpolicy_amendment or ()),
        bool(context.proposed_network_policy_amendments),
        evaluation.kind.value,
        evaluation.reason,
        tuple(sorted(analysis.risk_tags)),
        tuple(analysis.operators),
        tuple((segment.executable, tuple(segment.args), tuple(segment.resolved_paths)) for segment in analysis.segments),
        analysis.cheap_review_candidate,
    )


def validate_cheap_approval(
    *,
    context: ApprovalContext,
    evaluation: PolicyDecision,
    cheap_decision: CheapApprovalDecision,
    workspace: Path,
    expected_fingerprint: tuple[Any, ...],
) -> ApprovalResolution | None:
    # The schema guarantees reason_code is an approve code when decision is approve_low_impact.
    if cheap_decision.decision != "approve_low_impact":
        return None
    if cheap_approval_fingerprint(context, evaluation, workspace) != expected_fingerprint:
        return None
    if not is_cheap_review_candidate(context, evaluation, workspace):
        return None
    if context.proposed_network_policy_amendments:
        return None
    if not _decision_available(context, "accept"):
        return None
    return ApprovalResolution(
        decision="accept",
        reason=f"{CHEAP_APPROVAL_REASON} ({cheap_decision.reason_code})",
    )


def cheap_approval_packet(context: ApprovalContext, evaluation: PolicyDecision, analysis: CommandAnalysis) -> dict[str, Any]:
    return {
        "request_type": context.request_type.value,
        "command": context.command,
        "cwd": context.cwd,
        "parsed_command_segments": [segment.model_dump(mode="json") for segment in analysis.segments],
        "shell_composition_operators": analysis.operators,
        "resolved_workspace_relative_paths": analysis.resolved_paths,
        "risk_tags": sorted(analysis.risk_tags),
        "deterministic_routing_reason": evaluation.reason,
        "available_decisions": context.available_decisions,
    }


def _decision_available(context: ApprovalContext, decision: str) -> bool:
    keys = context.available_decision_keys
    return keys is None or decision in keys


def _env_flag(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    return default


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


def cheap_review_attempt_metadata(
    *,
    eligible: bool,
    attempted: bool,
    outcome: str,
    started_at: float | None = None,
    reason_code: str | None = None,
    model: str | None = None,
    full_supervisor_fallback: bool = False,
) -> CheapApprovalAttempt:
    latency = None if started_at is None else time.monotonic() - started_at
    return CheapApprovalAttempt(
        attempted=attempted,
        eligible=eligible,
        outcome=outcome,
        reason_code=reason_code,
        latency_seconds=latency,
        model=model,
        full_supervisor_fallback=full_supervisor_fallback,
    )
