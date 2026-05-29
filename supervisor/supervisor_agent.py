from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from supervisor.appserver import AppServerClient, last_agent_message_text, text_input
from supervisor.prompts import build_stateless_supervisor_prompt
from supervisor.schemas import (
    ApprovalContext,
    ApprovalWakeContext,
    ChangedFile,
    CoderMessage,
    HumanMessage,
    PriorIntervention,
    RestartHandoff,
    SupervisorDecision,
    SupervisorDecisionKind,
    SupervisorWakePacket,
    TriggeringAction,
    ValidationRun,
)
from supervisor.schemas.models import openai_strict_json_schema_for_supervisor_decision
from supervisor.state import DECISIONS, HANDOFF, PROGRESS, StateStore


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
        timeout_seconds: float = 180.0,
    ):
        self.client = client
        self.store = store
        self.task_path = task_path.resolve()
        self.model = model
        self.timeout_seconds = timeout_seconds

    async def decide(self, packet: SupervisorWakePacket) -> SupervisorDecision:
        thread_id: str | None = None
        try:
            thread_response = await self.client.thread_start(self._thread_params())
            thread = thread_response.get("thread", {})
            thread_id = thread.get("id") if isinstance(thread, dict) else None
            if not isinstance(thread_id, str):
                raise SupervisorAgentError("supervisor thread/start did not return thread id")
            prompt = build_stateless_supervisor_prompt(packet)
            turn_response = await self.client.turn_start(
                {
                    "threadId": thread_id,
                    "input": [text_input(prompt)],
                    "approvalPolicy": "never",
                    "sandboxPolicy": {"type": "readOnly", "networkAccess": False},
                    "outputSchema": openai_strict_json_schema_for_supervisor_decision(),
                    **({"model": self.model} if self.model else {}),
                }
            )
            turn = turn_response.get("turn", {})
            turn_id = turn.get("id")
            if not isinstance(turn_id, str):
                raise SupervisorAgentError("supervisor turn/start did not return turn id")
            if turn.get("status") != "completed":
                completed = await self.client.wait_for_notification(
                    lambda message: message.method == "turn/completed"
                    and message.params.get("threadId") == thread_id
                    and isinstance(message.params.get("turn"), dict)
                    and message.params["turn"].get("id") == turn_id,
                    timeout=self.timeout_seconds,
                )
                turn = completed.params.get("turn", {})
            text = last_agent_message_text(turn)
            if text is None:
                turns = await self.client.thread_turns_list(thread_id, limit=1, items_view="full")
                data = turns.get("data", [])
                if data and isinstance(data[0], dict):
                    text = last_agent_message_text(data[0])
            if text is None:
                raise SupervisorAgentError("supervisor did not produce an agent message")
            decision = SupervisorDecision.model_validate(_parse_json_object(text))
            decision.wake_sequence = decision.wake_sequence or packet.wake_sequence
            decision.generation = decision.generation if decision.generation is not None else packet.generation
            return decision
        except (ValidationError, json.JSONDecodeError) as exc:
            raise SupervisorAgentError(f"invalid supervisor decision: {exc}") from exc
        finally:
            if thread_id:
                try:
                    await self.client.thread_archive(thread_id)
                except Exception:
                    try:
                        await self.client.thread_unsubscribe(thread_id)
                    except Exception:
                        pass

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
    ) -> SupervisorWakePacket:
        cfg = self.store.get_sentinel_config()
        health = self.store.get_health()
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
            health=health.model_dump(mode="json"),
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
            prior_interventions=prior_interventions or [],
            changed_files=changed_files or [],
            patch_summary=patch_summary,
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
