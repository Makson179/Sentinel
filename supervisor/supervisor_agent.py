from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from supervisor.appserver import AppServerClient, AppServerError, last_agent_message_text, text_input
from supervisor.prompts import build_completion_review_prompt, build_stateless_supervisor_prompt
from supervisor.schemas import (
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
        timeout_seconds: float = DEFAULT_SUPERVISOR_TIMEOUT_SECONDS,
        completion_timeout_seconds: float = DEFAULT_COMPLETION_REVIEW_TIMEOUT_SECONDS,
    ):
        self.client = client
        self.store = store
        self.task_path = task_path.resolve()
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.completion_timeout_seconds = completion_timeout_seconds
        self.completion_thread_id: str | None = None

    async def decide(self, packet: SupervisorWakePacket) -> SupervisorDecision:
        return await self._decide(
            packet,
            prompt=build_stateless_supervisor_prompt(packet),
            schema=openai_strict_json_schema_for_supervisor_decision(),
            model_cls=SupervisorDecision,
            use_case="runtime_monitor",
            timeout_seconds=self.timeout_seconds,
        )

    async def decide_completion(self, packet: SupervisorWakePacket) -> CompletionReviewDecision:
        return await self._decide(
            packet,
            prompt=build_completion_review_prompt(packet),
            schema=openai_strict_json_schema_for_completion_review_decision(),
            model_cls=CompletionReviewDecision,
            use_case="completion_review",
            timeout_seconds=self.completion_timeout_seconds,
            persistent_completion_thread=True,
        )

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
                    raise SupervisorAgentError("supervisor did not produce an agent message")
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
        evidence_provenance_summary: EvidenceProvenanceSummary | None = None,
        diff_packet_limits: DiffPacketLimits | None = None,
        breadth_risk_summary: BreadthRiskSummary | None = None,
        completion_payload_mode: Literal["full", "manifest", "true_delta", "delta", "full_fallback"] | None = None,
        completion_payload_since_sequence: int | None = None,
        completion_review_thread_id: str | None = None,
        pending_accept_gate_rejection: dict[str, Any] | None = None,
        completion_attempt_id: str | None = None,
        review_workspace_state_id: str | None = None,
        review_artifact_manifest: dict[str, Any] | None = None,
    ) -> SupervisorWakePacket:
        cfg = self.store.get_sentinel_config()
        health = self.store.get_health()
        prior_interventions = prior_interventions or []
        health_payload = health.model_dump(mode="json")
        if prior_interventions:
            health_payload["interventions"] = max(
                int(health_payload.get("interventions") or 0),
                len(prior_interventions),
            )
        task_contents = self.task_path.read_text(encoding="utf-8") if self.task_path.exists() else ""
        if completion_payload_mode == "true_delta":
            task_contents = ""
        return SupervisorWakePacket(
            wake_sequence=wake_sequence,
            latest_event_sequence=cfg.last_event_sequence,
            generation=cfg.generation,
            restart_count=cfg.restart_count,
            task_path=str(self.task_path),
            task_contents=task_contents,
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
            evidence_provenance_summary=evidence_provenance_summary,
            diff_packet_limits=diff_packet_limits or DiffPacketLimits(),
            breadth_risk_summary=breadth_risk_summary,
            completion_payload_mode=completion_payload_mode,
            completion_payload_since_sequence=completion_payload_since_sequence,
            completion_review_thread_id=completion_review_thread_id,
            pending_accept_gate_rejection=pending_accept_gate_rejection,
            completion_attempt_id=completion_attempt_id,
            review_workspace_state_id=review_workspace_state_id,
            review_artifact_manifest=review_artifact_manifest,
        )

    def _thread_params(self) -> dict[str, Any]:
        params: dict[str, Any] = {
            "cwd": str(self.store.workspace),
            "runtimeWorkspaceRoots": [str(self.store.workspace)],
            "approvalPolicy": "never",
            "approvalsReviewer": "user",
            "sandbox": "read-only",
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
