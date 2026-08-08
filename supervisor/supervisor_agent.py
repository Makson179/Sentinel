from __future__ import annotations

import asyncio
import fnmatch
import glob
import json
import os
import re
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

from pydantic import ValidationError

from supervisor.appserver import AppServerClient, AppServerError, last_agent_message_text, text_input
from supervisor.coder import DEFAULT_INTELLIGENCE, apply_intelligence, codex_service_tier
from supervisor.prompts import (
    build_adv_report_controller_prompt,
    build_completion_review_prompt,
    build_stateless_supervisor_prompt,
)
from supervisor.schemas import (
    AdvReportControllerDecision,
    AdversaryReport,
    ApprovalContext,
    ApprovalWakeContext,
    BehaviorSurfaceItem,
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
    SupervisorWakePacket,
    TriggeringAction,
    ValidationOutput,
    ValidationRun,
)
from supervisor.schemas.models import (
    openai_strict_json_schema_for_adv_report_controller_decision,
    openai_strict_json_schema_for_completion_review_decision,
    openai_strict_json_schema_for_supervisor_decision,
)
from supervisor.state import DECISIONS, HANDOFF, PROGRESS, STATE_DIR_NAME, StateStore


DEFAULT_SUPERVISOR_TIMEOUT_SECONDS = 360.0
# Completion review reads the whole (growing) workspace at high effort; late-round reviews on
# large tasks were observed needing >900s (a 711k-token read died at the old cap and killed a
# 4.5h run). Keep this above the coder RPC budget, not below it.
DEFAULT_COMPLETION_REVIEW_TIMEOUT_SECONDS = 4800.0
# Prompt-size budgets (characters). Compaction triggers above the target so the
# assembled wake packet never approaches the model context window (~4 chars/token).
# Both runtime and completion wakes go through a budget; runtime is kept small so it
# never bloats over a long run, completion keeps real headroom below the context cap.
COMPLETION_PROMPT_TARGET_CHARS = 500_000
COMPLETION_PROMPT_ULTRA_TARGET_CHARS = 380_000
RUNTIME_PROMPT_TARGET_CHARS = 120_000
RUNTIME_PROMPT_ULTRA_TARGET_CHARS = 80_000
RUNTIME_PROGRESS_ENTRY_LIMIT = 30
RUNTIME_PROGRESS_CHAR_LIMIT = 12_000
RUNTIME_DECISIONS_ENTRY_LIMIT = 20
RUNTIME_DECISIONS_CHAR_LIMIT = 10_000
RUNTIME_VALIDATION_LIMIT = 12
RUNTIME_INSPECTION_LIMIT = 8
RUNTIME_INTERVENTION_LIMIT = 10
COMPLETION_PERMISSION_PROFILE = "bello_completion_review"


class SupervisorAgentError(RuntimeError):
    pass


def _validated_workspace_relative_deny_path(raw: str | Path) -> str:
    value = Path(raw)
    if value.is_absolute() or ".." in value.parts:
        raise ValueError(f"completion deny-read path must stay within the workspace: {raw}")
    normalized = value.as_posix()
    if not normalized or normalized == ".":
        raise ValueError("completion deny-read path must identify a file")
    if any(character in normalized for character in "*?[]"):
        raise ValueError(f"completion deny-read path must identify one exact file: {raw}")
    return normalized


class StatelessSupervisorAgent:
    def __init__(
        self,
        client: AppServerClient,
        store: StateStore,
        task_path: Path,
        *,
        workspace_root: Path | None = None,
        task_contents: str | None = None,
        model: str | None = None,
        fast: bool = False,
        intelligence: str | None = DEFAULT_INTELLIGENCE,
        timeout_seconds: float = DEFAULT_SUPERVISOR_TIMEOUT_SECONDS,
        completion_timeout_seconds: float = DEFAULT_COMPLETION_REVIEW_TIMEOUT_SECONDS,
        denied_workspace_read_paths: tuple[str | Path, ...] = (),
        configured_mcp_server_names: tuple[str, ...] = (),
        configured_plugin_names: tuple[str, ...] = (),
        disable_apps: bool = True,
    ):
        self.client = client
        self.store = store
        self.task_path = task_path.resolve()
        self.workspace_root = (workspace_root or store.workspace).resolve()
        self.task_contents = task_contents
        self.model = model
        self.fast = fast
        self.intelligence = intelligence
        self.timeout_seconds = timeout_seconds
        self.completion_timeout_seconds = completion_timeout_seconds
        self.completion_thread_id: str | None = None
        self.last_completion_review_items: list[dict[str, Any]] = []
        self.denied_workspace_read_paths = tuple(
            dict.fromkeys(
                _validated_workspace_relative_deny_path(path)
                for path in denied_workspace_read_paths
            )
        )
        # Packet redaction uses workspace-relative file names, while the App Server
        # permission profile must deny the canonical ORIGINAL state directory.  A
        # coder snapshot exposes `.supervisor` through an absolute symlink; asking
        # Linux bwrap to mount a deny rule below that lexical snapshot path makes
        # every reviewer command fail before execution.  Keep these two address
        # spaces deliberately separate.
        self.permission_denied_read_paths = tuple(
            dict.fromkeys(
                str(self.store.coder_checklist_path().parent.resolve())
                if path == f"{STATE_DIR_NAME}/coder/CHECKLIST.md"
                else str((self.store.workspace / path).resolve())
                for path in self.denied_workspace_read_paths
            )
        )
        self.configured_mcp_server_names = tuple(
            sorted({name.strip() for name in configured_mcp_server_names if name.strip()})
        )
        self.configured_plugin_names = tuple(
            sorted({name.strip() for name in configured_plugin_names if name.strip()})
        )
        self.disable_apps = disable_apps

    async def decide(self, packet: SupervisorWakePacket) -> SupervisorDecision:
        packet = _prepare_runtime_packet(packet)
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
        self.last_completion_review_items = []
        packet = _slim_completion_packet(
            packet,
            denied_workspace_read_paths=self.denied_workspace_read_paths,
            workspace_root=self.workspace_root,
        )
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

    async def decide_adv_report(self, packet: SupervisorWakePacket) -> AdvReportControllerDecision:
        decision = await self._decide(
            packet,
            prompt=build_adv_report_controller_prompt(packet),
            schema=openai_strict_json_schema_for_adv_report_controller_decision(),
            model_cls=AdvReportControllerDecision,
            use_case="adv_report_controller",
            timeout_seconds=self.completion_timeout_seconds,
        )
        if not isinstance(decision, AdvReportControllerDecision):
            raise SupervisorAgentError("adv_report_controller returned an unexpected decision type")
        return decision

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
        model_cls: type[SupervisorDecision] | type[CompletionReviewDecision] | type[AdvReportControllerDecision],
        use_case: str,
        timeout_seconds: float,
        persistent_completion_thread: bool = False,
    ) -> SupervisorDecision | CompletionReviewDecision | AdvReportControllerDecision:
        thread_id: str | None = None
        turn_id: str | None = None
        raw_text: str | None = None
        decision: SupervisorDecision | CompletionReviewDecision | AdvReportControllerDecision | None = None
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
                if self.permission_denied_read_paths:
                    active_profile = thread_response.get("activePermissionProfile")
                    profile_id = active_profile.get("id") if isinstance(active_profile, dict) else None
                    profile_parent = (
                        active_profile.get("extends") if isinstance(active_profile, dict) else None
                    )
                    sandbox = thread_response.get("sandbox")
                    if (
                        profile_id != COMPLETION_PERMISSION_PROFILE
                        or profile_parent != ":read-only"
                        or not isinstance(sandbox, dict)
                        or sandbox.get("type") != "readOnly"
                        or sandbox.get("networkAccess") is not False
                    ):
                        raise SupervisorAgentError(
                            "completion thread did not activate the expected read-only deny-read profile"
                        )
                if persistent_completion_thread:
                    self.completion_thread_id = thread_id
            turn_prompt = prompt
            for attempt in range(2):
                turn_params: dict[str, Any] = {
                    "threadId": thread_id,
                    "input": [text_input(turn_prompt)],
                    # Codex App Server resolves command execution for a turn from
                    # these turn-local roots.  thread/start also carries them, but
                    # omitting them here leaves a structured-output reviewer able
                    # to answer while silently unable to inspect the workspace.
                    "cwd": str(self.workspace_root),
                    "runtimeWorkspaceRoots": [str(self.workspace_root)],
                    "approvalPolicy": "never",
                    "outputSchema": schema,
                    "serviceTier": codex_service_tier(fast=self.fast),
                    **({"model": self.model} if self.model else {}),
                }
                # A deny-read profile is defined by thread-local config and must be
                # inherited unchanged. Re-selecting it here would reload permissions
                # without the thread/start config that defines the private profile.
                if not self.permission_denied_read_paths:
                    turn_params["sandboxPolicy"] = {"type": "readOnly", "networkAccess": False}
                turn_response = await self._await_rpc(
                    "supervisor turn/start response",
                    self.client.turn_start(
                        apply_intelligence(turn_params, self.intelligence),
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
                if persistent_completion_thread:
                    items = turn.get("items") if isinstance(turn, dict) else None
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict):
                                self.record_completion_review_item(item)
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

    def record_completion_review_item(self, item: dict[str, Any]) -> None:
        """Keep live completion-review items for controller-side evidence binding.

        Current App Server versions emit commandExecution only through live
        item/completed notifications; neither turn/completed.items nor
        thread/turns/list reliably contains those items.  Replace an earlier item
        with the same id so a completed payload (including aggregatedOutput) wins.
        """

        payload = dict(item)
        item_id = payload.get("id")
        if isinstance(item_id, str):
            for index, existing in enumerate(self.last_completion_review_items):
                if existing.get("id") == item_id:
                    merged = {**existing, **payload}
                    for key in (
                        "output",
                        "aggregatedOutput",
                        "aggregated_output",
                        "stdout",
                        "stderr",
                    ):
                        if not payload.get(key) and existing.get(key):
                            merged[key] = existing[key]
                    self.last_completion_review_items[index] = merged
                    break
            else:
                self.last_completion_review_items.append(payload)
        elif payload not in self.last_completion_review_items:
            self.last_completion_review_items.append(payload)
        self.last_completion_review_items = self.last_completion_review_items[-100:]

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
            wake_sequence=self.store.get_bello_config().last_event_sequence + 1,
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
        behavior_surface: list[BehaviorSurfaceItem] | None = None,
        prior_uncovered_edge_candidates: list[str] | None = None,
    ) -> SupervisorWakePacket:
        cfg = self.store.get_bello_config()
        health = self.store.get_health()
        prior_interventions = prior_interventions or []
        health_payload = health.model_dump(mode="json")
        return SupervisorWakePacket(
            wake_sequence=wake_sequence,
            latest_event_sequence=cfg.last_event_sequence,
            generation=cfg.generation,
            restart_count=cfg.restart_count,
            task_path=str(self.task_path),
            task_contents=(
                self.task_contents
                if self.task_contents is not None
                else self.task_path.read_text(encoding="utf-8") if self.task_path.exists() else ""
            ),
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
            behavior_surface=behavior_surface or [],
            prior_uncovered_edge_candidates=prior_uncovered_edge_candidates or [],
        )

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
        params: dict[str, Any] = {
            "cwd": str(self.workspace_root),
            "runtimeWorkspaceRoots": [str(self.workspace_root)],
            "approvalPolicy": "never",
            "approvalsReviewer": "user",
            "serviceTier": codex_service_tier(fast=self.fast),
            "ephemeral": False,
            "experimentalRawEvents": False,
            "persistExtendedHistory": False,
            "config": thread_config,
            "dynamicTools": [],
            "environments": [],
        }
        if self.permission_denied_read_paths:
            params["permissions"] = COMPLETION_PERMISSION_PROFILE
            thread_config["permissions"] = {
                COMPLETION_PERMISSION_PROFILE: {
                    "description": (
                        "Read-only completion audit with coder private working memory denied."
                    ),
                    "extends": ":read-only",
                    "filesystem": {
                        path: "deny" for path in self.permission_denied_read_paths
                    },
                }
            }
        else:
            params["sandbox"] = "read-only"
        if self.model:
            params["model"] = self.model
        return params

    def _append_wake_audit(
        self,
        packet: SupervisorWakePacket,
        *,
        thread_id: str | None,
        turn_id: str | None,
        decision: SupervisorDecision | CompletionReviewDecision | AdvReportControllerDecision | None,
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
    model_cls: type[SupervisorDecision] | type[CompletionReviewDecision] | type[AdvReportControllerDecision],
) -> str:
    if model_cls is CompletionReviewDecision:
        decision_name = "completion-review"
    elif model_cls is AdvReportControllerDecision:
        decision_name = "adversary report controller"
    else:
        decision_name = "runtime supervisor"
    if model_cls is CompletionReviewDecision:
        return _completion_review_repair_json_prompt(raw_text=raw_text, error=error, packet=packet)
    if model_cls is AdvReportControllerDecision:
        excerpt = raw_text
        if len(excerpt) > 4000:
            excerpt = excerpt[:4000] + "\n...<truncated>"
        return (
            f"Your previous adversary report controller response was not valid structured JSON: {error}\n\n"
            "Return exactly one JSON object matching the supplied schema, with only forward_to_coder, reason, "
            "report_to_coder, and material_coverage_limitations. Correct the reported validation error; preserve "
            "the previous normalization only where it satisfies the contract, and do not add facts. The coder-facing "
            "report may contain only the `## Findings requiring correction` and `## Observations requiring "
            "investigation` sections plus their two category definitions. Never copy attacked, held, not_reached, "
            "overall, rejected findings, adjudication details, or coverage metadata into report_to_coder. Use "
            "report_to_coder=null when forward_to_coder=false. Do not include "
            "markdown outside the JSON object, comments, or extra keys.\n\n"
            "Previous invalid response excerpt:\n"
            "```text\n"
            f"{excerpt}\n"
            "```"
        )
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
        "Do not include markdown, prose, comments, or extra keys. Keep free-text fields concise, but do not "
        "truncate, omit, or split required blockers or accept-gate evidence to meet an arbitrary whole-object cap. "
        "Preserve wake_sequence and generation exactly: "
        f"wake_sequence={packet.wake_sequence}, generation={packet.generation}.\n\n"
        "For decision=\"return\" or decision=\"restart\", do not rebuild the full review artifact: set "
        "files_reviewed=[] and behavior_evidence_matrix=[]. For return, include every concrete blocking issue "
        "already established by this review in "
        "uncovered_behaviors, validation_gaps, claim_evidence_mismatches, packet_or_access_limitations, "
        "or changed_test_risks, plus one concise batched message_to_coder covering all of them. "
        "For restart, include a valid handoff and set message_to_coder=null. "
        "For decision=\"accept\", include the complete files, behavior-surface rows, and ledger-bound evidence "
        "required by every accept gate.\n\n"
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
        "Do not include markdown, prose, comments, or extra keys. Keep free-text fields concise without omitting "
        "or splitting required blockers or accept-gate evidence. "
        "Include all top-level schema fields; use [] or null for empty fields. Preserve "
        f"wake_sequence={packet.wake_sequence} and generation={packet.generation}.\n"
        "If the decision is return or restart, avoid the full evidence matrix: use files_reviewed=[] and "
        "behavior_evidence_matrix=[]. For return, include every concrete blocker already established by the "
        "review and one concise batched message_to_coder covering all of them. For restart, include a valid "
        "handoff and set message_to_coder=null. If the decision is accept, include the complete files, "
        "behavior-surface rows, and ledger-bound evidence required by every accept gate."
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


def _slim_completion_packet(
    packet: SupervisorWakePacket,
    *,
    denied_workspace_read_paths: tuple[str, ...] = (),
    workspace_root: Path | None = None,
) -> SupervisorWakePacket:
    """Strip everything the completion supervisor can re-derive by reading the repo.

    The completion-review supervisor reads source and re-runs checks itself (it
    already issues rg/sed/git exec_command calls during review), so we drop from the
    prompt everything redundant or recoverable and keep only the evidence skeleton
    the accept gate / behavior_evidence_matrix bind to:

    - drop inlined file diffs/contexts (changed_file_diffs/changed_file_contexts) — it runs `git diff`;
    - drop validation_outputs/inspection_outputs entirely — they are near-duplicates
      of the validations/inspections ledgers, and the accept gate does not consume
      them (it binds validation_ids from `validations`);
    - in each ledger item: normally empty captured_output, but retain a small bounded
      factual capture for direct behavior demos or checks whose external dependency
      cannot be replayed in the isolated reviewer; drop duplicate raw/normalized
      command, blank the constant cwd, and bound command + summary;
    - in evidence_provenance_summary keep the risk flags but drop the third copy of the
      full command it re-embeds per validation;
    - drop patch_summary/diff_summary — the model reads the diff itself.
    """
    def slim_run(value: Any) -> Any:
        had_output = bool((getattr(value, "captured_output", "") or "").strip())
        captured_output = (
            _completion_validation_capture(value, limit=2500)
            if isinstance(value, ValidationRun)
            else ""
        )
        return value.model_copy(
            update={
                "command": _slim_command(value.command, limit=120),
                "raw_command": "",
                "normalized_command": "",
                "cwd": "",
                "captured_output": captured_output,
                "captured_output_truncated": value.captured_output_truncated
                or (had_output and len(captured_output) < len(value.captured_output)),
                "summary": _bounded_text(value.summary, limit=200),
            }
        )

    validations = [
        value
        for value in packet.validations
        if not _completion_packet_value_references_denied_path(
            value,
            denied_workspace_read_paths,
            workspace_root=workspace_root,
        )
    ]
    inspections = [
        value
        for value in packet.inspections
        if not _completion_packet_value_references_denied_path(
            value,
            denied_workspace_read_paths,
            workspace_root=workspace_root,
        )
    ]
    provenance = packet.evidence_provenance_summary
    if provenance is not None:
        provenance = provenance.model_copy(
            update={
                "validations": [
                    entry.model_copy(update={"command": _slim_command(entry.command, limit=120)})
                    for entry in provenance.validations
                    if not _completion_packet_value_references_denied_path(
                        entry,
                        denied_workspace_read_paths,
                        workspace_root=workspace_root,
                    )
                ]
            }
        )

    return packet.model_copy(
        update={
            "validations": [slim_run(v) for v in validations],
            "inspections": [slim_run(v) for v in inspections],
            "last_actions": [
                action
                for action in packet.last_actions
                if not _text_references_denied_workspace_path(
                    action,
                    denied_workspace_read_paths,
                    workspace_root=workspace_root,
                )
            ],
            "recent_events": [
                event
                for event in packet.recent_events
                if not _completion_packet_value_references_denied_path(
                    event,
                    denied_workspace_read_paths,
                    workspace_root=workspace_root,
                )
            ],
            "prior_interventions": [
                intervention
                for intervention in packet.prior_interventions
                if not _completion_packet_value_references_denied_path(
                    intervention,
                    denied_workspace_read_paths,
                    workspace_root=workspace_root,
                )
                and not _prior_intervention_duplicates_completion_return(
                    intervention,
                    packet.previous_completion_returns,
                )
            ],
            "validation_outputs": [],
            "inspection_outputs": [],
            "completion_delta_evidence_summary": [
                summary
                for summary in packet.completion_delta_evidence_summary
                if not _text_references_denied_workspace_path(
                    summary,
                    denied_workspace_read_paths,
                    workspace_root=workspace_root,
                )
            ],
            "changed_file_diffs": [],
            "changed_file_contexts": [],
            "evidence_provenance_summary": provenance,
            "patch_summary": None,
            "diff_summary": None,
        }
    )


_NON_REPLAYABLE_VALIDATION_COMMAND_RE = re.compile(
    r"(?:"
    r"https?://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)(?::|/|$))|"
    r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://|"
    r"(?:^|[\s;&|])(?:psql|mysql|mongosh|redis-cli|aws|gcloud|az|kubectl|docker|podman)"
    r"(?:\s|$)"
    r")",
    re.IGNORECASE,
)


def _completion_validation_capture(
    validation: ValidationRun,
    *,
    limit: int,
) -> str:
    captured = validation.captured_output or ""
    if not captured:
        return ""
    if validation.type == "behavior_demo" or _NON_REPLAYABLE_VALIDATION_COMMAND_RE.search(
        validation.command
    ):
        capture_limit = limit
    elif (
        validation.type == "behavioral"
        and validation.outcome == "pass"
        and validation.passed
        and validation.trusted_validation_outcome == "passed"
    ):
        # The reviewer is intentionally isolated from network/MCP/apps, and a
        # generic test command can hide an SDK or credential-backed integration.
        # Retain a tiny factual tail for every trusted behavioral pass instead of
        # trying to infer all external systems from executable names.
        capture_limit = min(limit, 400)
    else:
        return ""
    return _bounded_head_tail_text(captured, limit=capture_limit)


def _prior_intervention_duplicates_completion_return(
    intervention: PriorIntervention,
    completion_returns: list[Any],
) -> bool:
    if not intervention.message_to_coder:
        return False
    for record in completion_returns:
        if hasattr(record, "sequence"):
            sequence = getattr(record, "sequence", None)
            message = getattr(record, "message_to_coder", None)
        elif isinstance(record, dict):
            sequence = record.get("sequence")
            message = record.get("message_to_coder")
        else:
            continue
        if (
            sequence == intervention.sequence
            and isinstance(message, str)
            and message == intervention.message_to_coder
        ):
            return True
    return False


def _completion_packet_value_references_denied_path(
    value: Any,
    denied_paths: tuple[str, ...],
    *,
    workspace_root: Path | None = None,
) -> bool:
    if not denied_paths:
        return False
    if hasattr(value, "model_dump"):
        raw = value.model_dump(mode="json")
    else:
        raw = value
    if _structured_value_references_denied_workspace_path(
        raw,
        denied_paths,
        workspace_root=workspace_root,
    ):
        return True
    try:
        text = json.dumps(raw, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        text = str(raw)
    return _text_references_denied_workspace_path(
        text,
        denied_paths,
        workspace_root=workspace_root,
    )


def _structured_value_references_denied_workspace_path(
    value: Any,
    denied_paths: tuple[str, ...],
    *,
    workspace_root: Path | None,
) -> bool:
    """Resolve cwd-relative ledger references without basename-wide redaction.

    Historical command records carry a cwd separately from the command.  Looking
    only at their JSON text misses `cat CHECKLIST.md` executed from the private
    coder-state directory.  Resolve that structured context while retaining exact
    path semantics so a repository-owned `docs/CHECKLIST.md` remains visible.
    """
    if workspace_root is None:
        return False

    canonical_denied = tuple(
        (workspace_root / Path(path)).resolve(strict=False)
        for path in denied_paths
    )
    canonical_private_roots = tuple(path.parent for path in canonical_denied)
    resolved_workspace_root = workspace_root.resolve()
    lexical_denied = tuple(
        Path(
            os.path.abspath(
                os.path.normpath(resolved_workspace_root / Path(path))
            )
        )
        for path in denied_paths
    )
    lexical_private_roots = tuple(path.parent for path in lexical_denied)

    def canonical_path_is_private(candidate: Path) -> bool:
        if candidate in canonical_denied:
            return True
        for private_root in canonical_private_roots:
            try:
                candidate.relative_to(private_root)
            except ValueError:
                pass
            else:
                return True
        return False

    def lexical_path_is_private(candidate: Path) -> bool:
        if candidate in lexical_denied:
            return True
        for private_root in lexical_private_roots:
            try:
                candidate.relative_to(private_root)
            except ValueError:
                pass
            else:
                return True
        return False

    def brace_variants(value: str) -> list[str]:
        variants = [value]
        for _depth in range(4):
            expanded: list[str] = []
            changed = False
            for variant in variants:
                match = re.search(r"\{([^{}]*)\}", variant)
                if match is None:
                    expanded.append(variant)
                    continue
                body = match.group(1)
                choices = body.split(",")
                sequence = body.split("..")
                if len(sequence) in {2, 3}:
                    start, end = sequence[:2]
                    step_text = sequence[2] if len(sequence) == 3 else None
                    try:
                        if len(start) == 1 and len(end) == 1 and not (
                            start.isdigit() and end.isdigit()
                        ):
                            start_value, end_value = ord(start), ord(end)
                            default_step = 1 if start_value <= end_value else -1
                            step = int(step_text) if step_text else default_step
                            stop = end_value + (1 if step > 0 else -1)
                            choices = [chr(value) for value in range(start_value, stop, step)][:64]
                        else:
                            start_value, end_value = int(start), int(end)
                            default_step = 1 if start_value <= end_value else -1
                            step = int(step_text) if step_text else default_step
                            stop = end_value + (1 if step > 0 else -1)
                            choices = [str(value) for value in range(start_value, stop, step)][:64]
                    except (TypeError, ValueError, ZeroDivisionError):
                        choices = body.split(",")
                changed = True
                for choice in choices[:64]:
                    expanded.append(
                        variant[: match.start()] + choice + variant[match.end() :]
                    )
            variants = expanded[:64]
            if not changed:
                break
        return variants

    def expanded_path_variants(raw_path: str, *, cwd: Path) -> list[str]:
        candidate_text = raw_path.strip().strip("'\"")
        if not candidate_text or candidate_text.startswith("-"):
            return []
        candidate_text = candidate_text.replace(
            "${PWD%/}", str(cwd).rstrip("/")
        ).replace("${HOME%/}", os.path.expanduser("~").rstrip("/"))
        candidate_text = candidate_text.replace("${PWD}", str(cwd)).replace(
            "$PWD", str(cwd)
        )
        candidate_text = candidate_text.replace("~+", str(cwd))
        candidate_text = os.path.expandvars(candidate_text)
        try:
            candidate_text = os.path.expanduser(candidate_text)
        except RuntimeError:
            return []
        return brace_variants(candidate_text)

    def resolves_to_denied(raw_path: str, *, cwd: Path) -> bool:
        for variant in expanded_path_variants(raw_path, cwd=cwd):
            candidate_path = Path(variant)
            try:
                unresolved = (
                    candidate_path
                    if candidate_path.is_absolute()
                    else cwd / candidate_path
                )
                lexical_candidate = Path(
                    os.path.abspath(os.path.normpath(unresolved))
                )
                if any(character in variant for character in "*?["):
                    pattern = lexical_candidate.as_posix()
                    if any(
                        fnmatch.fnmatchcase(denied.as_posix(), pattern)
                        for denied in (
                            *lexical_denied,
                            *canonical_denied,
                            *lexical_private_roots,
                            *canonical_private_roots,
                        )
                    ):
                        return True
                    for match_index, matched in enumerate(
                        glob.iglob(pattern, recursive=True, include_hidden=True)
                    ):
                        if match_index >= 256:
                            break
                        try:
                            resolved_match = Path(matched).resolve(strict=False)
                        except (OSError, ValueError):
                            continue
                        if canonical_path_is_private(resolved_match):
                            return True
                    continue
                candidate = unresolved.resolve(strict=False)
            except (OSError, ValueError):
                continue
            if canonical_path_is_private(candidate) or lexical_path_is_private(
                lexical_candidate
            ):
                return True
        return False

    def path_can_reach_private(raw_path: str, *, cwd: Path) -> bool:
        for variant in expanded_path_variants(raw_path, cwd=cwd):
            if any(character in variant for character in "*?["):
                continue
            candidate_path = Path(variant)
            try:
                unresolved = (
                    candidate_path
                    if candidate_path.is_absolute()
                    else cwd / candidate_path
                )
                lexical_candidate = Path(
                    os.path.abspath(os.path.normpath(unresolved))
                )
                canonical_candidate = unresolved.resolve(strict=False)
            except (OSError, ValueError):
                continue
            for private_root in canonical_private_roots:
                try:
                    private_root.relative_to(canonical_candidate)
                except ValueError:
                    pass
                else:
                    return True
            for private_root in lexical_private_roots:
                try:
                    private_root.relative_to(lexical_candidate)
                except ValueError:
                    pass
                else:
                    return True
        return False

    def command_path_candidates(command: str) -> list[str]:
        pending = [command]
        candidates: list[str] = []
        for _depth in range(3):
            next_pending: list[str] = []
            for fragment in pending:
                try:
                    tokens = shlex.split(fragment, posix=True)
                except ValueError:
                    tokens = fragment.split()
                for token in tokens[:200]:
                    if not token or len(token) > 4096:
                        continue
                    candidates.append(token)
                    # Covers shell wrappers and small snippets such as
                    # `/bin/bash -lc 'cat private-alias'` or `open("path")`.
                    pieces = [
                        piece
                        for piece in re.split(r"[\s'\"`()\[\]{},;|&<>:=]+", token)
                        if piece
                    ]
                    candidates.extend(pieces)
                    next_pending.extend(piece for piece in pieces if " " in piece)
            pending = next_pending
            if not pending:
                break
        return list(dict.fromkeys(candidates))

    def string_values(raw: Any) -> list[str]:
        if isinstance(raw, str):
            return [raw]
        if isinstance(raw, (list, tuple, set)):
            return [item for item in raw if isinstance(item, str)]
        return []

    def command_is_recursive_content_reader(command: str) -> bool:
        pending = [command]
        for _depth in range(3):
            nested: list[str] = []
            for fragment in pending:
                try:
                    tokens = shlex.split(fragment, posix=True)
                except ValueError:
                    tokens = fragment.split()
                if not tokens:
                    continue
                executable = Path(tokens[0]).name.lower()
                if executable == "rg":
                    return True
                if executable == "grep":
                    if any(
                        token in {"--recursive", "--dereference-recursive"}
                        or (
                            token.startswith("-")
                            and not token.startswith("--")
                            and any(flag in token[1:] for flag in "rR")
                        )
                        for token in tokens[1:]
                    ):
                        return True
                if executable in {"bash", "fish", "sh", "zsh"}:
                    for index, token in enumerate(tokens[1:], start=1):
                        if token.startswith("-") and "c" in token[1:] and index + 1 < len(tokens):
                            nested.append(tokens[index + 1])
                            break
            pending = nested
            if not pending:
                break
        return False

    def recursively_scans_denied_ancestor(
        command: str,
        node: dict[str, Any],
        *,
        cwd: Path,
    ) -> bool:
        if not command_is_recursive_content_reader(command):
            return False
        search_roots = string_values(node.get("inspected_paths"))
        if not search_roots:
            search_roots = ["."]
        return any(path_can_reach_private(path, cwd=cwd) for path in search_roots)

    def visit(node: Any, *, inherited_cwd: Path) -> bool:
        if isinstance(node, dict):
            cwd = node.get("cwd")
            resolved_cwd = inherited_cwd
            if isinstance(cwd, str) and cwd.strip():
                cwd_path = Path(cwd).expanduser()
                resolved_cwd = (
                    cwd_path.resolve(strict=False)
                    if cwd_path.is_absolute()
                    else (workspace_root / cwd_path).resolve(strict=False)
                )
            # Nothing product-relevant should execute from inside the private
            # coder-state directory.  Dropping the whole record also prevents
            # encoded/indirect checklist reads from leaking captured output.
            for denied in canonical_denied:
                try:
                    resolved_cwd.relative_to(denied.parent)
                except ValueError:
                    pass
                else:
                    return True
            try:
                node_text = json.dumps(node, ensure_ascii=False, sort_keys=True)
            except (TypeError, ValueError):
                node_text = str(node)
            for denied in canonical_denied:
                relative_from_cwd = Path(
                    os.path.relpath(denied, start=resolved_cwd)
                ).as_posix()
                if _text_references_exact_path_token(node_text, relative_from_cwd):
                    return True
            for key in (
                "path",
                "paths",
                "inspected_paths",
                "resource_paths",
                "target_files_or_test_files",
                "executed_test_files",
            ):
                if any(
                    resolves_to_denied(candidate, cwd=resolved_cwd)
                    for candidate in string_values(node.get(key))
                ):
                    return True
            for key in ("command", "raw_command", "normalized_command"):
                command = node.get(key)
                if isinstance(command, str):
                    if recursively_scans_denied_ancestor(
                        command,
                        node,
                        cwd=resolved_cwd,
                    ):
                        return True
                    if any(
                        resolves_to_denied(candidate, cwd=resolved_cwd)
                        for candidate in command_path_candidates(command)
                    ):
                        return True
            return any(
                visit(child, inherited_cwd=resolved_cwd)
                for child in node.values()
            )
        if isinstance(node, (list, tuple)):
            return any(
                visit(child, inherited_cwd=inherited_cwd) for child in node
            )
        return False

    return visit(value, inherited_cwd=resolved_workspace_root)


def _text_references_exact_path_token(text: str, path: str) -> bool:
    normalized_path = path.replace("\\", "/").strip().rstrip("/").lower()
    if not normalized_path:
        return False
    normalized_text = text.replace("\\", "/").lower()
    pattern = re.compile(
        rf"(?<![a-z0-9_./-])(?:\./)?{re.escape(normalized_path)}"
        r"(?![a-z0-9_./-])"
    )
    return pattern.search(normalized_text) is not None


def _text_references_denied_workspace_path(
    text: str,
    denied_paths: tuple[str, ...],
    *,
    workspace_root: Path | None = None,
) -> bool:
    for denied in denied_paths:
        relative_denied = denied.replace("\\", "/").strip("/")
        normalized_denied = relative_denied.lower()
        if not normalized_denied:
            continue
        # Match the exact root-relative private path as a shell/path token.  A
        # basename-only fallback used to erase unrelated CHECKLIST.md files, and
        # a suffix match would also erase docs/.supervisor/coder/CHECKLIST.md.
        if _text_references_exact_path_token(text, normalized_denied):
            return True
        if workspace_root is not None:
            lexical_denied = workspace_root.resolve() / Path(relative_denied)
            canonical_denied = (
                workspace_root / Path(relative_denied)
            ).resolve(strict=False)
            for absolute_denied in {lexical_denied, canonical_denied}:
                if _text_references_exact_path_token(text, absolute_denied.as_posix()):
                    return True
    return False


def _prepare_runtime_packet(packet: SupervisorWakePacket) -> SupervisorWakePacket:
    progress, progress_total, progress_included = _markdown_tail_excerpt(
        packet.progress,
        entry_limit=RUNTIME_PROGRESS_ENTRY_LIMIT,
        char_limit=RUNTIME_PROGRESS_CHAR_LIMIT,
    )
    decisions, decisions_total, decisions_included = _markdown_tail_excerpt(
        packet.decisions,
        entry_limit=RUNTIME_DECISIONS_ENTRY_LIMIT,
        char_limit=RUNTIME_DECISIONS_CHAR_LIMIT,
    )
    return packet.model_copy(
        update={
            "progress": progress,
            "progress_path": f"{STATE_DIR_NAME}/{PROGRESS}",
            "progress_total_entries": progress_total,
            "progress_omitted_entries": max(0, progress_total - progress_included),
            "decisions": decisions,
            "decisions_path": f"{STATE_DIR_NAME}/{DECISIONS}",
            "decisions_total_entries": decisions_total,
            "decisions_omitted_entries": max(0, decisions_total - decisions_included),
            "validations": _select_runtime_validations(
                packet.validations,
                triggering_action=packet.triggering_action,
            ),
            "inspections": _select_runtime_inspections(
                packet.inspections,
                triggering_action=packet.triggering_action,
            ),
            "prior_interventions": [
                _compact_runtime_intervention(value)
                for value in packet.prior_interventions[-RUNTIME_INTERVENTION_LIMIT:]
            ],
        }
    )


def _markdown_tail_excerpt(
    text: str,
    *,
    entry_limit: int,
    char_limit: int,
) -> tuple[str, int, int]:
    lines = text.splitlines()
    heading = next((line for line in lines if line.startswith("#")), "")
    entries: list[str] = []
    current: list[str] = []
    for line in lines:
        if line.startswith("- "):
            if current:
                entries.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        entries.append("\n".join(current))
    if not entries:
        return _bounded_text(text, limit=char_limit), 0, 0

    selected = entries[-entry_limit:]

    def render(values: list[str]) -> str:
        body = "\n".join(values)
        return f"{heading}\n\n{body}".strip() if heading else body

    while len(selected) > 1 and len(render(selected)) > char_limit:
        selected.pop(0)
    excerpt = render(selected)
    if len(excerpt) > char_limit:
        excerpt = _bounded_text(excerpt, limit=char_limit)
    return excerpt, len(entries), len(selected)


def _select_runtime_validations(
    validations: list[ValidationRun],
    *,
    triggering_action: TriggeringAction | None,
) -> list[ValidationRun]:
    if not validations:
        return []
    selected: list[ValidationRun] = []
    selected_keys: set[tuple[str, int]] = set()

    def add(value: ValidationRun) -> None:
        key = (value.validation_id, value.sequence)
        if key in selected_keys or len(selected) >= RUNTIME_VALIDATION_LIMIT:
            return
        selected_keys.add(key)
        selected.append(value)

    command_key = _normalized_command_key(triggering_action.command if triggering_action else None)
    if command_key:
        matching = [
            value
            for value in reversed(validations)
            if _normalized_command_key(value.normalized_command or value.command) == command_key
        ]
        for value in matching[:4]:
            add(value)

    for predicate in (
        lambda value: value.trusted_validation_outcome == "masked_or_unknown",
        lambda value: value.trusted_validation_outcome == "failed",
        lambda value: value.type in {"behavioral", "behavior_demo"}
        and value.trusted_validation_outcome == "passed",
    ):
        match = next((value for value in reversed(validations) if predicate(value)), None)
        if match is not None:
            add(match)

    for value in reversed(validations[-5:]):
        add(value)
    for value in reversed(validations):
        add(value)
        if len(selected) >= RUNTIME_VALIDATION_LIMIT:
            break
    return [
        _compact_runtime_validation(value)
        for value in sorted(selected, key=lambda item: item.sequence)
    ]


def _select_runtime_inspections(
    inspections: list[InspectionRun],
    *,
    triggering_action: TriggeringAction | None,
) -> list[InspectionRun]:
    if not inspections:
        return []
    selected: list[InspectionRun] = []
    selected_keys: set[tuple[str, int]] = set()

    def add(value: InspectionRun) -> None:
        key = (value.inspection_id, value.sequence)
        if key in selected_keys or len(selected) >= RUNTIME_INSPECTION_LIMIT:
            return
        selected_keys.add(key)
        selected.append(value)

    command_key = _normalized_command_key(triggering_action.command if triggering_action else None)
    if command_key:
        matching = [
            value
            for value in reversed(inspections)
            if _normalized_command_key(value.normalized_command or value.command) == command_key
        ]
        for value in matching[:3]:
            add(value)

    seen_commands: set[str] = set()
    for value in reversed(inspections):
        key = _normalized_command_key(value.normalized_command or value.command)
        if key in seen_commands:
            continue
        seen_commands.add(key)
        add(value)
        if len(selected) >= RUNTIME_INSPECTION_LIMIT:
            break
    return [
        _compact_runtime_inspection(value)
        for value in sorted(selected, key=lambda item: item.sequence)
    ]


def _compact_runtime_validation(value: ValidationRun) -> ValidationRun:
    had_output = bool(value.captured_output.strip())
    return value.model_copy(
        update={
            "command": _slim_command(value.command, limit=300),
            "raw_command": None,
            "normalized_command": None,
            "cwd": None,
            "summary": _bounded_text(value.summary, limit=800),
            "captured_output": "",
            "captured_output_truncated": value.captured_output_truncated or had_output,
            "raw_selector": _bounded_text(value.raw_selector, limit=300) if value.raw_selector else None,
            "executed_test_names": _bounded_string_list(value.executed_test_names),
            "executed_test_files": _bounded_string_list(value.executed_test_files),
            "target_files_or_test_files": _bounded_string_list(value.target_files_or_test_files),
        }
    )


def _compact_runtime_inspection(value: InspectionRun) -> InspectionRun:
    had_output = bool(value.captured_output.strip())
    return value.model_copy(
        update={
            "command": _slim_command(value.command, limit=300),
            "raw_command": None,
            "normalized_command": None,
            "cwd": None,
            "summary": _bounded_text(value.summary, limit=600),
            "captured_output": "",
            "captured_output_truncated": value.captured_output_truncated or had_output,
            "inspected_paths": _bounded_string_list(value.inspected_paths),
        }
    )


def _compact_runtime_intervention(value: PriorIntervention) -> PriorIntervention:
    return value.model_copy(
        update={
            "reason": _bounded_text(value.reason, limit=400),
            "message_to_coder": _bounded_text(value.message_to_coder, limit=1000),
        }
    )


def _bounded_string_list(values: list[str], *, limit: int = 20, item_limit: int = 240) -> list[str]:
    bounded = [_bounded_text(value, limit=item_limit) for value in values[:limit]]
    omitted = len(values) - len(bounded)
    if omitted > 0:
        bounded.append(f"...<{omitted} more>")
    return bounded


def _normalized_command_key(command: str | None) -> str:
    return " ".join((command or "").strip().split())


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
    captured_output = _completion_validation_capture(validation, limit=1200)
    return validation.model_copy(
        update={
            "command": _slim_command(validation.command, limit=200),
            "raw_command": "",
            "normalized_command": "",
            "cwd": "",
            "summary": _bounded_text(validation.summary, limit=level.ledger_summary_limit),
            "captured_output": captured_output,
            "captured_output_truncated": validation.captured_output_truncated
            or (had_output and len(captured_output) < len(validation.captured_output)),
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


def _bounded_head_tail_text(text: str, *, limit: int) -> str:
    if len(text) <= limit:
        return text
    marker = "\n...<middle truncated>...\n"
    if limit <= len(marker):
        return text[-limit:]
    available = limit - len(marker)
    head = available // 3
    tail = available - head
    return text[:head] + marker + text[-tail:]


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
