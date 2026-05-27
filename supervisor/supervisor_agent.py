from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from supervisor.appserver import AppServerClient, last_agent_message_text, text_input
from supervisor.prompts import build_stateless_supervisor_prompt
from supervisor.schemas import (
    ApprovalContext,
    SupervisorDecision,
    SupervisorDecisionKind,
    SupervisorWakePacket,
)
from supervisor.schemas.models import openai_strict_json_schema_for_supervisor_decision
from supervisor.state import DECISIONS, HANDOFF, LAST_ACTION, PROGRESS, StateStore


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
        bench_recorder: Any | None = None,
    ):
        self.client = client
        self.store = store
        self.task_path = task_path.resolve()
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.bench_recorder = bench_recorder

    async def decide(self, packet: SupervisorWakePacket) -> SupervisorDecision:
        thread_id: str | None = None
        supervisor_call_id = self._bench_supervisor_context(packet)
        self._bench_record("supervisor_call_started", supervisor_call_id=supervisor_call_id)
        try:
            thread_response = await self.client.thread_start(self._thread_params())
            thread = thread_response.get("thread", {})
            thread_id = thread.get("id") if isinstance(thread, dict) else None
            if not isinstance(thread_id, str):
                raise SupervisorAgentError("supervisor thread/start did not return thread id")
            self._bench_register_supervisor_thread(supervisor_call_id, thread_id)
            self._bench_record_token_usage(thread_response, thread_id=thread_id, supervisor_call_id=supervisor_call_id)
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
            self._bench_record_token_usage(turn_response, thread_id=thread_id, supervisor_call_id=supervisor_call_id)
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
                self._bench_record_token_usage(completed.raw, thread_id=thread_id, supervisor_call_id=supervisor_call_id)
            text = last_agent_message_text(turn)
            if text is None:
                turns = await self.client.thread_turns_list(thread_id, limit=1, items_view="full")
                self._bench_record_token_usage(turns, thread_id=thread_id, supervisor_call_id=supervisor_call_id)
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
            self._bench_record(
                "supervisor_call_finished",
                supervisor_call_id=supervisor_call_id,
                thread_id=thread_id,
            )
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
            last_action=self.store.read_text(LAST_ACTION, ""),
            health=health.model_dump(mode="json"),
            handoff=self.store.read_text(HANDOFF, "") or None,
            recent_events=self.store.read_recent_events(40),
            current_summary=current_summary,
            diff_summary=diff_summary,
            coder_thread_id=cfg.coder_thread_id,
            active_coder_turn_id=cfg.active_coder_turn_id,
            triggering_item_id=triggering_item_id,
            triggering_server_request_id=triggering_server_request_id,
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

    def _bench_supervisor_context(self, packet: SupervisorWakePacket) -> str | None:
        if self.bench_recorder is None:
            return None
        try:
            return self.bench_recorder.record_supervisor_context(packet)
        except Exception:
            return None

    def _bench_record(self, event: str, **payload: Any) -> None:
        if self.bench_recorder is None:
            return
        try:
            self.bench_recorder.record(event, **payload)
        except Exception:
            pass

    def _bench_register_supervisor_thread(self, supervisor_call_id: str | None, thread_id: str) -> None:
        if self.bench_recorder is None or supervisor_call_id is None:
            return
        try:
            self.bench_recorder.register_supervisor_thread(supervisor_call_id, thread_id)
        except Exception:
            pass

    def _bench_record_token_usage(
        self,
        usage_source: Any,
        *,
        thread_id: str | None,
        supervisor_call_id: str | None,
    ) -> None:
        if self.bench_recorder is None or supervisor_call_id is None:
            return
        try:
            self.bench_recorder.record_token_usage(
                role="supervisor",
                usage_source=usage_source,
                thread_id=thread_id,
                supervisor_call_id=supervisor_call_id,
            )
        except Exception:
            pass


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


def fallback_supervisor_decision(reason: str, *, decision: SupervisorDecisionKind = SupervisorDecisionKind.NOOP) -> SupervisorDecision:
    return SupervisorDecision(decision=decision, reason=reason, display_message=reason)
