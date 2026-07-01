from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

from pydantic import ValidationError

from supervisor.appserver import AppServerClient, AppServerError, last_agent_message_text, text_input
from supervisor.coder import codex_service_tier
from supervisor.prompts import build_completion_review_prompt, build_stateless_supervisor_prompt
from supervisor.schemas import (
    AdversaryReport,
    ApprovalContext,
    ApprovalWakeContext,
    BreadthRiskSummary,
    ChangedFile,
    ChangedFileContext,
    ChangedFileDiff,
    ChangedTestsSummary,
    CoderMessage,
    CompletionReviewDecision,
    DiffPacketLimits,
    EvidenceProvenanceSummary,
    HumanMessage,
    InspectionOutput,
    InspectionRun,
    PriorIntervention,
    RestartHandoff,
    SupervisorDecision,
    SupervisorDecisionKind,
    SupervisorWakePacket,
    TriggeringAction,
    ValidationOutput,
    ValidationRun,
)
from supervisor.schemas.models import (
    openai_strict_json_schema_for_completion_review_decision,
    openai_strict_json_schema_for_supervisor_decision,
)
from supervisor.state import DECISIONS, HANDOFF, PROGRESS, StateStore


DEFAULT_SUPERVISOR_TIMEOUT_SECONDS = 180.0
DEFAULT_COMPLETION_REVIEW_TIMEOUT_SECONDS = 900.0
# Prompt-size budgets (characters). Compaction triggers above the target so the
# assembled wake packet never approaches the model context window (~4 chars/token).
# Both runtime and completion wakes go through a budget; runtime is kept small so it
# never bloats over a long run, completion keeps real headroom below the context cap.
COMPLETION_PROMPT_TARGET_CHARS = 500_000
COMPLETION_PROMPT_ULTRA_TARGET_CHARS = 380_000
RUNTIME_PROMPT_TARGET_CHARS = 120_000
RUNTIME_PROMPT_ULTRA_TARGET_CHARS = 80_000


class SupervisorAgentError(RuntimeError):
    pass


class StatelessSupervisorAgent:
    def __init__(
        self,
        client: AppServerClient,
        store: StateStore,
        task_path: Path,
        *,
        model: str | None = None,
        fast: bool = False,
        timeout_seconds: float = DEFAULT_SUPERVISOR_TIMEOUT_SECONDS,
        completion_timeout_seconds: float = DEFAULT_COMPLETION_REVIEW_TIMEOUT_SECONDS,
    ):
        self.client = client
        self.store = store
        self.task_path = task_path.resolve()
        self.model = model
        self.fast = fast
        self.timeout_seconds = timeout_seconds
        self.completion_timeout_seconds = completion_timeout_seconds
        self.completion_thread_id: str | None = None

    async def decide(self, packet: SupervisorWakePacket) -> SupervisorDecision:
        prompt_packet, prompt = _stateless_prompt_with_budget(packet)
        return await self._decide(
            prompt_packet,
            prompt=prompt,
            schema=openai_strict_json_schema_for_supervisor_decision(),
            model_cls=SupervisorDecision,
            use_case="runtime_monitor",
            timeout_seconds=self.timeout_seconds,
        )

    async def decide_completion(self, packet: SupervisorWakePacket) -> CompletionReviewDecision:
        packet = _slim_completion_packet(packet)
        prompt_packet, prompt = _completion_prompt_with_budget(packet)
        try:
            return await self._decide_completion_with_prompt(
                prompt_packet,
                prompt=prompt,
                use_case="completion_review",
            )
        except SupervisorAgentError as exc:
            if _is_input_too_large_error(exc):
                prompt_packet, prompt = _completion_prompt_with_budget(packet, ultra=True)
                try:
                    return await self._decide_completion_with_prompt(
                        prompt_packet,
                        prompt=prompt,
                        use_case="completion_review_compact_retry",
                    )
                except SupervisorAgentError as compact_exc:
                    if not _is_invalid_supervisor_decision_error(compact_exc):
                        raise
                    return await self._decide_completion_with_prompt(
                        prompt_packet,
                        prompt=_minimal_completion_review_retry_prompt(
                            context_prompt=prompt,
                            error=str(compact_exc),
                            packet=prompt_packet,
                        ),
                        use_case="completion_review_minimal_retry",
                    )
            if _is_no_message_error(exc):
                prompt_packet, prompt = _completion_prompt_with_budget(packet, ultra=True)
                return await self._decide_completion_with_prompt(
                    prompt_packet,
                    prompt=_minimal_completion_review_retry_prompt(
                        context_prompt=prompt,
                        error=str(exc),
                        packet=prompt_packet,
                    ),
                    use_case="completion_review_no_message_minimal_retry",
                )
            if not _is_invalid_supervisor_decision_error(exc):
                raise
            prompt_packet, prompt = _completion_prompt_with_budget(packet, ultra=True)
            return await self._decide_completion_with_prompt(
                prompt_packet,
                prompt=_minimal_completion_review_retry_prompt(
                    context_prompt=prompt,
                    error=str(exc),
                    packet=prompt_packet,
                ),
                use_case="completion_review_minimal_retry",
            )

    async def _decide_completion_with_prompt(
        self,
        packet: SupervisorWakePacket,
        *,
        prompt: str,
        use_case: str,
    ) -> CompletionReviewDecision:
        decision = await self._decide(
            packet,
            prompt=prompt,
            schema=openai_strict_json_schema_for_completion_review_decision(),
            model_cls=CompletionReviewDecision,
            use_case=use_case,
            timeout_seconds=self.completion_timeout_seconds,
            persistent_completion_thread=True,
        )
        if not isinstance(decision, CompletionReviewDecision):
            raise SupervisorAgentError("completion review returned non-completion decision")
        return decision

    async def _decide(
        self,
        packet: SupervisorWakePacket,
        *,
        prompt: str,
        schema: dict[str, Any],
        model_cls: type[SupervisorDecision] | type[CompletionReviewDecision],
        use_case: str,
        timeout_seconds: float,
        persistent_completion_thread: bool = False,
    ) -> SupervisorDecision | CompletionReviewDecision:
        thread_id: str | None = None
        turn_id: str | None = None
        raw_text: str | None = None
        decision: SupervisorDecision | CompletionReviewDecision | None = None
        audit_error: str | None = None
        try:
            if persistent_completion_thread and self.completion_thread_id:
                thread_id = self.completion_thread_id
            else:
                thread_response = await self._await_rpc(
                    "supervisor thread/start response",
                    self.client.thread_start(self._thread_params(), timeout=timeout_seconds),
                    timeout=timeout_seconds,
                )
                thread = thread_response.get("thread", {})
                thread_id = thread.get("id") if isinstance(thread, dict) else None
                if not isinstance(thread_id, str):
                    raise SupervisorAgentError("supervisor thread/start did not return thread id")
                if persistent_completion_thread:
                    self.completion_thread_id = thread_id
            turn_prompt = prompt
            for attempt in range(2):
                turn_response = await self._await_rpc(
                    "supervisor turn/start response",
                    self.client.turn_start(
                        {
                            "threadId": thread_id,
                            "input": [text_input(turn_prompt)],
                            "approvalPolicy": "never",
                            "sandboxPolicy": {"type": "readOnly", "networkAccess": False},
                            "outputSchema": schema,
                            "serviceTier": codex_service_tier(fast=self.fast),
                            **({"model": self.model} if self.model else {}),
                        },
                        timeout=timeout_seconds,
                    ),
                    thread_id=thread_id,
                    timeout=timeout_seconds,
                )
                turn = turn_response.get("turn", {})
                turn_id_value = turn.get("id")
                if not isinstance(turn_id_value, str):
                    raise SupervisorAgentError("supervisor turn/start did not return turn id")
                turn_id = turn_id_value
                if turn.get("status") != "completed":
                    try:
                        completed = await self.client.wait_for_notification(
                            lambda message: message.method == "turn/completed"
                            and message.params.get("threadId") == thread_id
                            and isinstance(message.params.get("turn"), dict)
                            and message.params["turn"].get("id") == turn_id,
                            timeout=timeout_seconds,
                        )
                    except (asyncio.TimeoutError, AppServerError) as exc:
                        raise SupervisorAgentError(
                            self._stage_error(
                                "supervisor turn/completed notification",
                                thread_id=thread_id,
                                turn_id=turn_id,
                                timeout=timeout_seconds,
                            )
                        ) from exc
                    turn = completed.params.get("turn", {})
                text = last_agent_message_text(turn)
                if text is None:
                    turns = await self._await_rpc(
                        "supervisor thread/turns/list response",
                        self.client.thread_turns_list(
                            thread_id,
                            limit=5,
                            items_view="full",
                            timeout=timeout_seconds,
                        ),
                        thread_id=thread_id,
                        turn_id=turn_id,
                        timeout=timeout_seconds,
                    )
                    data = turns.get("data", [])
                    text = _agent_message_text_from_turns(data, turn_id=turn_id)
                if text is None:
                    audit_error = "supervisor did not produce an agent message"
                    if attempt == 0:
                        self._append_wake_audit(
                            packet,
                            thread_id=thread_id,
                            turn_id=turn_id,
                            decision=None,
                            raw_text=raw_text,
                            error=audit_error,
                            use_case=f"{use_case}_no_message_retry",
                        )
                        continue
                    raise SupervisorAgentError(audit_error)
                raw_text = text
                try:
                    decision = model_cls.model_validate(_parse_json_object(text))
                except (ValidationError, json.JSONDecodeError) as exc:
                    audit_error = f"invalid supervisor decision: {exc}"
                    if attempt == 0:
                        self._append_wake_audit(
                            packet,
                            thread_id=thread_id,
                            turn_id=turn_id,
                            decision=None,
                            raw_text=raw_text,
                            error=audit_error,
                            use_case=f"{use_case}_parse_retry",
                        )
                        turn_prompt = _repair_json_prompt(
                            raw_text=raw_text,
                            error=audit_error,
                            packet=packet,
                            model_cls=model_cls,
                        )
                        continue
                    raise SupervisorAgentError(audit_error) from exc
                if isinstance(decision, (SupervisorDecision, CompletionReviewDecision)):
                    decision.wake_sequence = packet.wake_sequence
                    decision.generation = packet.generation
                audit_error = None
                return decision
            raise SupervisorAgentError("supervisor decision repair loop exhausted")
        except SupervisorAgentError as exc:
            audit_error = str(exc)
            raise
        except Exception as exc:
            audit_error = f"{exc.__class__.__name__}: {exc}"
            raise SupervisorAgentError(audit_error) from exc
        except BaseException as exc:
            audit_error = f"{exc.__class__.__name__}: {exc}"
            raise
        finally:
            self._append_wake_audit(
                packet,
                thread_id=thread_id,
                turn_id=turn_id,
                decision=decision,
                raw_text=raw_text,
                error=audit_error,
                use_case=use_case,
            )
            if thread_id:
                if persistent_completion_thread:
                    if audit_error is not None:
                        await self._cleanup_thread(thread_id, turn_id, timeout_seconds)
                        if self.completion_thread_id == thread_id:
                            self.completion_thread_id = None
                else:
                    await self._cleanup_thread(thread_id, turn_id, timeout_seconds)

    async def close_completion_review(self) -> None:
        thread_id = self.completion_thread_id
        if not thread_id:
            return
        self.completion_thread_id = None
        await self._cleanup_thread(thread_id, None, self.completion_timeout_seconds)

    async def _await_rpc(
        self,
        stage: str,
        awaitable: Any,
        *,
        thread_id: str | None = None,
        turn_id: str | None = None,
        timeout: float,
    ) -> Any:
        try:
            return await asyncio.wait_for(awaitable, timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise SupervisorAgentError(
                self._stage_error(stage, thread_id=thread_id, turn_id=turn_id, timeout=timeout)
            ) from exc
        except SupervisorAgentError:
            raise
        except Exception as exc:
            raise SupervisorAgentError(
                self._stage_error(
                    stage,
                    thread_id=thread_id,
                    turn_id=turn_id,
                    timeout=timeout,
                    detail=f"failed with {exc.__class__.__name__}: {exc}",
                )
            ) from exc

    async def _cleanup_thread(self, thread_id: str, turn_id: str | None, timeout_seconds: float) -> None:
        cleanup_timeout = min(timeout_seconds, 10.0)
        try:
            await self._await_rpc(
                "supervisor thread/archive cleanup",
                self.client.thread_archive(thread_id, timeout=cleanup_timeout),
                thread_id=thread_id,
                turn_id=turn_id,
                timeout=cleanup_timeout,
            )
        except Exception as archive_exc:
            try:
                await self._await_rpc(
                    "supervisor thread/unsubscribe cleanup",
                    self.client.thread_unsubscribe(thread_id, timeout=cleanup_timeout),
                    thread_id=thread_id,
                    turn_id=turn_id,
                    timeout=cleanup_timeout,
                )
            except Exception as unsubscribe_exc:
                self._append_cleanup_error(thread_id, turn_id, archive_exc, unsubscribe_exc)
                return
            self._append_cleanup_error(thread_id, turn_id, archive_exc, None)
            return

    def _append_cleanup_error(
        self,
        thread_id: str,
        turn_id: str | None,
        archive_error: BaseException,
        unsubscribe_error: BaseException | None,
    ) -> None:
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "supervisor_cleanup_error",
            "thread_id": thread_id,
            "turn_id": turn_id,
            "archive_error": str(archive_error),
        }
        if unsubscribe_error is not None:
            entry["unsubscribe_error"] = str(unsubscribe_error)
        self.store.append_raw_log(entry)

    @staticmethod
    def _stage_error(
        stage: str,
        *,
        thread_id: str | None = None,
        turn_id: str | None = None,
        timeout: float,
        detail: str | None = None,
    ) -> str:
        parts = [stage]
        parts.append(f"timed out after {timeout:g}s")
        if detail:
            parts.append(detail)
        parts.append(f"thread_id={thread_id or 'unknown'}")
        parts.append(f"turn_id={turn_id or 'unknown'}")
        return " ".join(parts)

    async def decide_approval(self, context: ApprovalContext, reason: str) -> SupervisorDecision:
        packet = self.build_packet(
            wake_sequence=self.store.get_sentinel_config().last_event_sequence + 1,
            current_summary=f"Approval request needs judgment: {reason}",
            triggering_server_request_id=context.server_request_id,
            approval_context=_approval_wake_context(context, reason),
            pending_approvals=[_approval_wake_context(context, reason)],
        )
        return await self.decide(packet)

    def build_packet(
        self,
        *,
        wake_sequence: int,
        current_summary: str,
        diff_summary: str | None = None,
        triggering_item_id: str | None = None,
        triggering_server_request_id: int | str | None = None,
        approval_context: ApprovalWakeContext | None = None,
        pending_approvals: list[ApprovalWakeContext] | None = None,
        triggering_action: TriggeringAction | None = None,
        last_coder_message: CoderMessage | None = None,
        validations: list[ValidationRun] | None = None,
        inspections: list[InspectionRun] | None = None,
        human_message: HumanMessage | None = None,
        prior_interventions: list[PriorIntervention] | None = None,
        changed_files: list[ChangedFile] | None = None,
        patch_summary: str | None = None,
        completion_attempt_count: int = 0,
        completion_returns_this_generation: int = 0,
        previous_completion_returns: list[Any] | None = None,
        last_readiness_marker_sequence: int | None = None,
        no_marker_idle_nudge_count: int = 0,
        latest_relevant_change_sequence: int | None = None,
        validation_freshness_summary: str | None = None,
        changed_file_diffs: list[ChangedFileDiff] | None = None,
        changed_file_contexts: list[ChangedFileContext] | None = None,
        changed_tests_summary: list[ChangedTestsSummary] | None = None,
        validation_outputs: list[ValidationOutput] | None = None,
        inspection_outputs: list[InspectionOutput] | None = None,
        completion_delta_evidence_summary: list[str] | None = None,
        evidence_provenance_summary: EvidenceProvenanceSummary | None = None,
        diff_packet_limits: DiffPacketLimits | None = None,
        breadth_risk_summary: BreadthRiskSummary | None = None,
        completion_payload_mode: Literal["full", "delta", "full_fallback"] | None = None,
        completion_payload_since_sequence: int | None = None,
        completion_review_thread_id: str | None = None,
        pending_accept_gate_rejection: dict[str, Any] | None = None,
        adversary_report: AdversaryReport | None = None,
    ) -> SupervisorWakePacket:
        cfg = self.store.get_sentinel_config()
        health = self.store.get_health()
        prior_interventions = prior_interventions or []
        health_payload = health.model_dump(mode="json")
        return SupervisorWakePacket(
            wake_sequence=wake_sequence,
            latest_event_sequence=cfg.last_event_sequence,
            generation=cfg.generation,
            restart_count=cfg.restart_count,
            task_path=str(self.task_path),
            task_contents=self.task_path.read_text(encoding="utf-8") if self.task_path.exists() else "",
            progress=self.store.read_text(PROGRESS, ""),
            decisions=self.store.read_text(DECISIONS, ""),
            last_actions=self.store.read_recent_actions(10),
            health=health_payload,
            handoff=_read_handoff(self.store),
            recent_events=self.store.read_recent_events(40),
            current_summary=current_summary,
            diff_summary=diff_summary,
            coder_thread_id=cfg.coder_thread_id,
            active_coder_turn_id=cfg.active_coder_turn_id,
            triggering_item_id=triggering_item_id,
            triggering_server_request_id=triggering_server_request_id,
            approval_context=approval_context,
            pending_approvals=pending_approvals or [],
            triggering_action=triggering_action,
            last_coder_message=last_coder_message,
            validations=validations or [],
            inspections=inspections or [],
            human_message=human_message,
            prior_interventions=prior_interventions,
            changed_files=changed_files or [],
            patch_summary=patch_summary,
            completion_attempt_count=completion_attempt_count,
            completion_returns_this_generation=completion_returns_this_generation,
            previous_completion_returns=previous_completion_returns or [],
            last_readiness_marker_sequence=last_readiness_marker_sequence,
            no_marker_idle_nudge_count=no_marker_idle_nudge_count,
            latest_relevant_change_sequence=latest_relevant_change_sequence,
            validation_freshness_summary=validation_freshness_summary,
            changed_file_diffs=changed_file_diffs or [],
            changed_file_contexts=changed_file_contexts or [],
            changed_tests_summary=changed_tests_summary or [],
            validation_outputs=validation_outputs or [],
            inspection_outputs=inspection_outputs or [],
            completion_delta_evidence_summary=completion_delta_evidence_summary or [],
            evidence_provenance_summary=evidence_provenance_summary,
            diff_packet_limits=diff_packet_limits or DiffPacketLimits(),
            breadth_risk_summary=breadth_risk_summary,
            completion_payload_mode=completion_payload_mode,
            completion_payload_since_sequence=completion_payload_since_sequence,
            completion_review_thread_id=completion_review_thread_id,
            pending_accept_gate_rejection=pending_accept_gate_rejection,
            adversary_report=adversary_report,
        )

    def _thread_params(self) -> dict[str, Any]:
        params: dict[str, Any] = {
            "cwd": str(self.store.workspace),
            "runtimeWorkspaceRoots": [str(self.store.workspace)],
            "approvalPolicy": "never",
            "approvalsReviewer": "user",
            "sandbox": "read-only",
            "serviceTier": codex_service_tier(fast=self.fast),
            "ephemeral": False,
            "experimentalRawEvents": False,
            "persistExtendedHistory": False,
        }
        if self.model:
            params["model"] = self.model
        return params

    def _append_wake_audit(
        self,
        packet: SupervisorWakePacket,
        *,
        thread_id: str | None,
        turn_id: str | None,
        decision: SupervisorDecision | CompletionReviewDecision | None,
        raw_text: str | None,
        error: str | None,
        use_case: str = "runtime_monitor",
    ) -> None:
        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "use_case": use_case,
            "wake_sequence": packet.wake_sequence,
            "generation": packet.generation,
            "restart_count": packet.restart_count,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "packet": packet.model_dump(mode="json"),
        }
        if decision is not None:
            entry["status"] = "decision"
            entry["decision"] = decision.model_dump(mode="json")
        elif error is not None:
            entry["status"] = "error"
            entry["error"] = error
        else:
            entry["status"] = "aborted"
        if raw_text is not None:
            entry["raw_text"] = raw_text
        self.store.append_supervisor_wake(entry)

def _parse_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        candidate = _extract_first_json_object(stripped)
        if candidate and candidate != stripped:
            return json.loads(candidate, strict=False)
        return json.loads(stripped, strict=False)


def _extract_first_json_object(text: str) -> str | None:
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


def _repair_json_prompt(
    *,
    raw_text: str,
    error: str,
    packet: SupervisorWakePacket,
    model_cls: type[SupervisorDecision] | type[CompletionReviewDecision],
) -> str:
    decision_name = "completion-review" if model_cls is CompletionReviewDecision else "runtime supervisor"
    if model_cls is CompletionReviewDecision:
        return _completion_review_repair_json_prompt(raw_text=raw_text, error=error, packet=packet)
    excerpt = raw_text
    if len(excerpt) > 12000:
        excerpt = excerpt[:12000] + "\n...<truncated>"
    return (
        f"Your previous {decision_name} response was not valid structured JSON: {error}\n\n"
        "Return exactly one JSON object matching the required output schema. Do not include markdown, prose, "
        "comments, or extra keys. Keep string fields concise so the JSON is not truncated. Preserve the same "
        f"reviewed packet identity: wake_sequence={packet.wake_sequence}, generation={packet.generation}.\n\n"
        "Previous invalid response excerpt:\n"
        "```text\n"
        f"{excerpt}\n"
        "```"
    )


def _completion_review_repair_json_prompt(
    *,
    raw_text: str,
    error: str,
    packet: SupervisorWakePacket,
) -> str:
    excerpt = raw_text
    if len(excerpt) > 1500:
        excerpt = excerpt[:1500] + "\n...<truncated>"
    return (
        f"Your previous completion-review response was not valid structured JSON: {error}\n\n"
        "Return exactly one compact completion-review JSON object matching the required output schema. "
        "Do not include markdown, prose, comments, or extra keys. Keep the whole JSON under 3000 characters. "
        "Preserve wake_sequence and generation exactly: "
        f"wake_sequence={packet.wake_sequence}, generation={packet.generation}.\n\n"
        "For decision=\"return\" or decision=\"restart\", do not rebuild the full review artifact: set "
        "files_reviewed=[] and behavior_evidence_matrix=[]. For return, include one concrete blocking issue in "
        "uncovered_behaviors, validation_gaps, claim_evidence_mismatches, packet_or_access_limitations, "
        "or changed_test_risks, plus the minimal message_to_coder needed to get that issue fixed. "
        "For restart, include a valid handoff and set message_to_coder=null. "
        "For decision=\"accept\", include only the evidence needed for the accept gates.\n\n"
        "Previous invalid response excerpt, for context only:\n"
        "```text\n"
        f"{excerpt}\n"
        "```"
    )


def _minimal_completion_review_retry_prompt(
    *,
    context_prompt: str,
    error: str,
    packet: SupervisorWakePacket,
) -> str:
    return (
        f"{context_prompt}\n\n"
        "# Emergency compact JSON retry\n"
        f"The previous completion-review attempt failed before a usable decision was parsed: {error}\n"
        "Run the same completion review, but output exactly one compact JSON object matching the required schema. "
        "Do not include markdown, prose, comments, or extra keys. Keep the whole JSON under 3000 characters. "
        "Include all top-level schema fields; use [] or null for empty fields. Preserve "
        f"wake_sequence={packet.wake_sequence} and generation={packet.generation}.\n"
        "If the decision is return or restart, avoid the full evidence matrix: use files_reviewed=[] and "
        "behavior_evidence_matrix=[]. For return, include only the concrete blocker and the minimal message_to_coder "
        "needed to resolve it. For restart, include a valid handoff and set message_to_coder=null. "
        "If the decision is accept, include only evidence required by the accept gates."
    )


def _agent_message_text_from_turns(data: Any, *, turn_id: str | None) -> str | None:
    if not isinstance(data, list):
        return None
    turns = [item for item in data if isinstance(item, dict)]
    if turn_id:
        for turn in turns:
            if turn.get("id") == turn_id:
                text = last_agent_message_text(turn)
                if text is not None:
                    return text
    for turn in turns:
        text = last_agent_message_text(turn)
        if text is not None:
            return text
    return None


def _prompt_with_budget(
    packet: SupervisorWakePacket,
    *,
    builder: Callable[[SupervisorWakePacket], str],
    target: int,
    ultra_target: int,
    ultra: bool = False,
) -> tuple[SupervisorWakePacket, str]:
    prompt = builder(packet)
    effective_target = ultra_target if ultra else target
    if len(prompt) <= effective_target and not ultra:
        return packet, prompt

    levels = _PROMPT_COMPACTION_LEVELS
    selected = levels[-1] if ultra else levels[0]
    compact_packet = _compact_completion_packet(packet, level=selected, original_prompt_chars=len(prompt))
    compact_prompt = builder(compact_packet)
    if ultra:
        return compact_packet, _hard_cap_prompt(compact_prompt)
    for level in levels[1:]:
        if len(compact_prompt) <= effective_target:
            return compact_packet, compact_prompt
        selected = level
        compact_packet = _compact_completion_packet(packet, level=selected, original_prompt_chars=len(prompt))
        compact_prompt = builder(compact_packet)
    return compact_packet, _hard_cap_prompt(compact_prompt)


def _completion_prompt_with_budget(
    packet: SupervisorWakePacket,
    *,
    ultra: bool = False,
) -> tuple[SupervisorWakePacket, str]:
    return _prompt_with_budget(
        packet,
        builder=build_completion_review_prompt,
        target=COMPLETION_PROMPT_TARGET_CHARS,
        ultra_target=COMPLETION_PROMPT_ULTRA_TARGET_CHARS,
        ultra=ultra,
    )


def _stateless_prompt_with_budget(
    packet: SupervisorWakePacket,
    *,
    ultra: bool = False,
) -> tuple[SupervisorWakePacket, str]:
    return _prompt_with_budget(
        packet,
        builder=build_stateless_supervisor_prompt,
        target=RUNTIME_PROMPT_TARGET_CHARS,
        ultra_target=RUNTIME_PROMPT_ULTRA_TARGET_CHARS,
        ultra=ultra,
    )


# Hard ceiling for any supervisor prompt: the Codex app-server rejects a single
# turn input above 1,048,576 chars (input_too_large). Stay strictly below it.
PROMPT_HARD_CAP_CHARS = 1_000_000


def _hard_cap_prompt(prompt: str) -> str:
    if len(prompt) <= PROMPT_HARD_CAP_CHARS:
        return prompt
    keep = PROMPT_HARD_CAP_CHARS - 200
    return (
        prompt[:keep]
        + "\n…<PROMPT HARD-TRUNCATED to fit the app-server input cap; "
        "read source files and re-run commands yourself to recover any missing detail>"
    )


def _slim_command(text: str | None, *, limit: int = 200) -> str:
    if not text:
        return text or ""
    return text if len(text) <= limit else text[:limit] + " …<truncated; run it yourself>"


def _slim_completion_packet(packet: SupervisorWakePacket) -> SupervisorWakePacket:
    """Strip everything the completion supervisor can re-derive by reading the repo.

    The completion-review supervisor reads source and re-runs checks itself (it
    already issues rg/sed/git exec_command calls during review), so we drop from the
    prompt everything redundant or recoverable and keep only the evidence skeleton
    the accept gate / behavior_evidence_matrix bind to:

    - drop inlined file diffs/contexts (changed_file_diffs/changed_file_contexts) — it runs `git diff`;
    - drop validation_outputs/inspection_outputs entirely — after captured_output is
      emptied they are near-duplicates of the validations/inspections ledgers, and the
      accept gate does not consume them (it binds validation_ids from `validations`);
    - in each ledger item: empty captured_output, drop the duplicate raw/normalized
      command, blank the constant cwd, and bound command + summary;
    - in evidence_provenance_summary keep the risk flags but drop the third copy of the
      full command it re-embeds per validation;
    - drop patch_summary/diff_summary — the model reads the diff itself.
    """
    def slim_run(value: Any) -> Any:
        had_output = bool((getattr(value, "captured_output", "") or "").strip())
        return value.model_copy(
            update={
                "command": _slim_command(value.command, limit=120),
                "raw_command": "",
                "normalized_command": "",
                "cwd": "",
                "captured_output": "",
                "captured_output_truncated": value.captured_output_truncated or had_output,
                "summary": _bounded_text(value.summary, limit=200),
            }
        )

    provenance = packet.evidence_provenance_summary
    if provenance is not None:
        provenance = provenance.model_copy(
            update={
                "validations": [
                    entry.model_copy(update={"command": _slim_command(entry.command, limit=120)})
                    for entry in provenance.validations
                ]
            }
        )

    return packet.model_copy(
        update={
            "validations": [slim_run(v) for v in packet.validations],
            "inspections": [slim_run(v) for v in packet.inspections],
            "validation_outputs": [],
            "inspection_outputs": [],
            "changed_file_diffs": [],
            "changed_file_contexts": [],
            "evidence_provenance_summary": provenance,
            "patch_summary": None,
            "diff_summary": None,
        }
    )


class _PromptCompactionLevel:
    def __init__(
        self,
        *,
        name: str,
        ledger_summary_limit: int,
        output_summary_limit: int | None,
        output_capture_limit: int | None,
        diff_limit: int | None,
        context_limit: int | None,
        recent_events_limit: int | None,
        output_item_limit: int | None,
    ) -> None:
        self.name = name
        self.ledger_summary_limit = ledger_summary_limit
        self.output_summary_limit = output_summary_limit
        self.output_capture_limit = output_capture_limit
        self.diff_limit = diff_limit
        self.context_limit = context_limit
        self.recent_events_limit = recent_events_limit
        self.output_item_limit = output_item_limit


# Progressive compaction levels, shared by runtime and completion prompt budgets.
# Each level strips more aggressively: first the raw captured_output of the ledger
# runs, then bounds output/diff/context text, then caps item counts and event count.
_PROMPT_COMPACTION_LEVELS = (
    _PromptCompactionLevel(
        name="metadata_ledger",
        ledger_summary_limit=1000,
        output_summary_limit=None,
        output_capture_limit=None,
        diff_limit=None,
        context_limit=None,
        recent_events_limit=None,
        output_item_limit=None,
    ),
    _PromptCompactionLevel(
        name="bounded_outputs",
        ledger_summary_limit=800,
        output_summary_limit=2200,
        output_capture_limit=8000,
        diff_limit=None,
        context_limit=None,
        recent_events_limit=None,
        output_item_limit=None,
    ),
    _PromptCompactionLevel(
        name="compact_outputs",
        ledger_summary_limit=600,
        output_summary_limit=1400,
        output_capture_limit=4000,
        diff_limit=10000,
        context_limit=6500,
        recent_events_limit=30,
        output_item_limit=100,
    ),
    _PromptCompactionLevel(
        name="ultra_compact_outputs",
        ledger_summary_limit=450,
        output_summary_limit=900,
        output_capture_limit=1800,
        diff_limit=7000,
        context_limit=4000,
        recent_events_limit=20,
        output_item_limit=60,
    ),
)


def _compact_completion_packet(
    packet: SupervisorWakePacket,
    *,
    level: _PromptCompactionLevel,
    original_prompt_chars: int,
) -> SupervisorWakePacket:
    diff_limits = packet.diff_packet_limits
    reasons = [
        reason
        for reason in (diff_limits.truncation_reason or "").split("; ")
        if reason
    ]
    reasons.append(
        f"completion prompt compacted for app-server budget: level={level.name}, "
        f"original_prompt_chars={original_prompt_chars}, target_chars={COMPLETION_PROMPT_TARGET_CHARS}"
    )
    if level.output_item_limit is not None:
        validation_outputs = _most_recent_by_sequence(packet.validation_outputs, limit=level.output_item_limit)
        inspection_outputs = _most_recent_by_sequence(packet.inspection_outputs, limit=level.output_item_limit)
    else:
        validation_outputs = packet.validation_outputs
        inspection_outputs = packet.inspection_outputs
    return packet.model_copy(
        update={
            "validations": [_compact_validation_run(value, level=level) for value in packet.validations],
            "inspections": [_compact_inspection_run(value, level=level) for value in packet.inspections],
            "validation_outputs": [
                _compact_validation_output(value, level=level) for value in validation_outputs
            ],
            "inspection_outputs": [
                _compact_inspection_output(value, level=level) for value in inspection_outputs
            ],
            "changed_file_diffs": [
                _compact_changed_file_diff(value, level=level) for value in packet.changed_file_diffs
            ],
            "changed_file_contexts": [
                _compact_changed_file_context(value, level=level) for value in packet.changed_file_contexts
            ],
            "recent_events": (
                packet.recent_events[-level.recent_events_limit :]
                if level.recent_events_limit is not None
                else packet.recent_events
            ),
            "diff_packet_limits": diff_limits.model_copy(
                update={
                    "materially_truncated": True,
                    "truncation_reason": "; ".join(reasons),
                }
            ),
        }
    )


def _most_recent_by_sequence(items: list[Any], *, limit: int) -> list[Any]:
    if len(items) <= limit:
        return items
    return sorted(items, key=lambda item: getattr(item, "sequence", 0))[-limit:]


def _compact_validation_run(validation: ValidationRun, *, level: _PromptCompactionLevel) -> ValidationRun:
    had_output = bool(validation.captured_output.strip())
    return validation.model_copy(
        update={
            "command": _slim_command(validation.command, limit=200),
            "raw_command": "",
            "normalized_command": "",
            "cwd": "",
            "summary": _bounded_text(validation.summary, limit=level.ledger_summary_limit),
            "captured_output": "",
            "captured_output_truncated": validation.captured_output_truncated or had_output,
        }
    )


def _compact_inspection_run(inspection: InspectionRun, *, level: _PromptCompactionLevel) -> InspectionRun:
    had_output = bool(inspection.captured_output.strip())
    return inspection.model_copy(
        update={
            "command": _slim_command(inspection.command, limit=200),
            "raw_command": "",
            "normalized_command": "",
            "cwd": "",
            "summary": _bounded_text(inspection.summary, limit=level.ledger_summary_limit),
            "captured_output": "",
            "captured_output_truncated": inspection.captured_output_truncated or had_output,
        }
    )


def _compact_validation_output(output: ValidationOutput, *, level: _PromptCompactionLevel) -> ValidationOutput:
    summary = output.stdout_or_summary
    captured = output.captured_output
    if level.output_summary_limit is not None:
        summary = _bounded_text(summary, limit=level.output_summary_limit)
    if level.output_capture_limit is not None:
        captured = _bounded_text(captured, limit=level.output_capture_limit)
    return output.model_copy(
        update={
            "stdout_or_summary": summary,
            "captured_output": captured,
            "output_truncated": output.output_truncated
            or len(summary) < len(output.stdout_or_summary)
            or len(captured) < len(output.captured_output),
        }
    )


def _compact_inspection_output(output: InspectionOutput, *, level: _PromptCompactionLevel) -> InspectionOutput:
    summary = output.stdout_or_summary
    captured = output.captured_output
    if level.output_summary_limit is not None:
        summary = _bounded_text(summary, limit=level.output_summary_limit)
    if level.output_capture_limit is not None:
        captured = _bounded_text(captured, limit=level.output_capture_limit)
    return output.model_copy(
        update={
            "stdout_or_summary": summary,
            "captured_output": captured,
            "output_truncated": output.output_truncated
            or len(summary) < len(output.stdout_or_summary)
            or len(captured) < len(output.captured_output),
        }
    )


def _compact_changed_file_diff(changed: ChangedFileDiff, *, level: _PromptCompactionLevel) -> ChangedFileDiff:
    if level.diff_limit is None:
        return changed
    bounded = _bounded_text(changed.diff, limit=level.diff_limit)
    return changed.model_copy(
        update={
            "diff": bounded,
            "diff_truncated": changed.diff_truncated or len(bounded) < len(changed.diff),
        }
    )


def _compact_changed_file_context(
    context: ChangedFileContext,
    *,
    level: _PromptCompactionLevel,
) -> ChangedFileContext:
    if level.context_limit is None:
        return context
    bounded = _bounded_text(context.final_snippets_around_changed_hunks, limit=level.context_limit)
    return context.model_copy(
        update={
            "final_snippets_around_changed_hunks": bounded,
            "context_truncated": context.context_truncated
            or len(bounded) < len(context.final_snippets_around_changed_hunks),
        }
    )


def _bounded_text(text: str, *, limit: int) -> str:
    if len(text) <= limit:
        return text
    if limit <= 20:
        return text[:limit]
    return text[: limit - 15] + "\n...<truncated>"


def _is_input_too_large_error(exc: BaseException) -> bool:
    text = str(exc)
    return "input_too_large" in text or "Input exceeds the maximum length" in text


def _is_invalid_supervisor_decision_error(exc: BaseException) -> bool:
    return "invalid supervisor decision:" in str(exc)


def _is_no_message_error(exc: BaseException) -> bool:
    return "did not produce an agent message" in str(exc)


def _approval_wake_context(context: ApprovalContext, reason: str | None = None) -> ApprovalWakeContext:
    return ApprovalWakeContext(
        request_type=context.request_type.value,
        server_request_id=context.server_request_id,
        method=context.server_request_method,
        available_decisions=context.available_decisions,
        command=context.command,
        file_changes=context.file_changes,
        paths=context.paths,
        cwd=context.cwd,
        grant_root=context.grant_root,
        network_approval_context=context.network_approval_context,
        proposed_execpolicy_amendment=context.proposed_execpolicy_amendment,
        proposed_network_policy_amendments=context.proposed_network_policy_amendments,
        reason=reason,
    )


def _read_handoff(store: StateStore) -> RestartHandoff | None:
    raw = store.read_text(HANDOFF, "").strip()
    if not raw:
        return None
    try:
        return RestartHandoff.model_validate_json(raw)
    except Exception:
        return None
