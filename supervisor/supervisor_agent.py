from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from supervisor.appserver import AppServerClient, AppServerError, last_agent_message_text, text_input
from supervisor.prompts import build_completion_review_prompt, build_stateless_supervisor_prompt
from supervisor.schemas import (
    ApprovalContext,
    ApprovalWakeContext,
    ChangedFile,
    ChangedFileContext,
    ChangedFileDiff,
    ChangedTestsSummary,
    CoderMessage,
    CompletionReviewDecision,
    DiffPacketLimits,
    HumanMessage,
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
    ) -> SupervisorDecision | CompletionReviewDecision:
        thread_id: str | None = None
        turn_id: str | None = None
        raw_text: str | None = None
        decision: SupervisorDecision | CompletionReviewDecision | None = None
        audit_error: str | None = None
        try:
            thread_response = await self._await_rpc(
                "supervisor thread/start response",
                self.client.thread_start(self._thread_params(), timeout=timeout_seconds),
                timeout=timeout_seconds,
            )
            thread = thread_response.get("thread", {})
            thread_id = thread.get("id") if isinstance(thread, dict) else None
            if not isinstance(thread_id, str):
                raise SupervisorAgentError("supervisor thread/start did not return thread id")
            turn_response = await self._await_rpc(
                "supervisor turn/start response",
                self.client.turn_start(
                    {
                        "threadId": thread_id,
                        "input": [text_input(prompt)],
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
                        limit=1,
                        items_view="full",
                        timeout=timeout_seconds,
                    ),
                    thread_id=thread_id,
                    turn_id=turn_id,
                    timeout=timeout_seconds,
                )
                data = turns.get("data", [])
                if data and isinstance(data[0], dict):
                    text = last_agent_message_text(data[0])
            if text is None:
                raise SupervisorAgentError("supervisor did not produce an agent message")
            raw_text = text
            decision = model_cls.model_validate(_parse_json_object(text))
            if isinstance(decision, SupervisorDecision):
                decision.wake_sequence = decision.wake_sequence or packet.wake_sequence
                decision.generation = decision.generation if decision.generation is not None else packet.generation
            return decision
        except (ValidationError, json.JSONDecodeError) as exc:
            audit_error = f"invalid supervisor decision: {exc}"
            raise SupervisorAgentError(audit_error) from exc
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
                await self._cleanup_thread(thread_id, turn_id, timeout_seconds)

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
        diff_packet_limits: DiffPacketLimits | None = None,
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
            diff_packet_limits=diff_packet_limits or DiffPacketLimits(),
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
    return json.loads(stripped)


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


def fallback_supervisor_decision(reason: str, *, decision: SupervisorDecisionKind = SupervisorDecisionKind.NOOP) -> SupervisorDecision:
    return SupervisorDecision(decision=decision, reason=reason, display_message=reason)
