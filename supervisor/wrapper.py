from __future__ import annotations

import asyncio
import json
import os
import shutil
import secrets
import tempfile
import time
from pathlib import Path
from typing import Any

from supervisor.adapters import ClaudeAdapter, CodexAdapter
from supervisor.codex_cli import CODEX_EXEC_GIT_TRUST_FLAGS, CODEX_EXEC_NO_WEB_SEARCH_FLAGS
from supervisor.health import kill_restart_candidate, patch_health
from supervisor.ipc import IPCServer
from supervisor.llm_driver import ClaudeSubscriptionDriver, CodexSubscriptionDriver, LLMDriver, LLMDriverError, OpenRouterDriver, ParseFailure
from supervisor.policy import AllowRule, PolicyEngine, SessionAllowRules
from supervisor.process import ManagedProcess, launch_process
from supervisor.schemas import (
    DecisionLogEntry,
    DecisionType,
    EventType,
    HealthDelta,
    HookEvent,
    IPCRequest,
    IPCResponse,
    LLMDecision,
    PendingIntervention,
    PermissionDecisionKind,
    PolicyDecisionKind,
    RunConfig,
    StateSnapshot,
)
from supervisor.state import DECISIONS, PROGRESS, StateStore
from supervisor.timing import DebouncedTimer, HookBudget, fallback_response


WRAPPER_SUPERVISOR_INSTRUCTIONS = [
    "Return only JSON matching the provided supervisor decision schema.",
    "Prefer minimum human involvement and robust autonomous supervision.",
    "For gray-zone permissions, choose allow_once, allow_class, or deny.",
    "Confirm kill_restart only when deterministic evidence shows the current generation is stuck.",
]


class SupervisorWrapper:
    def __init__(
        self,
        workspace: Path,
        config: RunConfig,
        llm_driver: LLMDriver | None = None,
        supervisee_command: list[str] | None = None,
        runtime_parent: Path | None = None,
    ):
        self.workspace = workspace.resolve()
        self.config = config
        self.store = StateStore(self.workspace)
        self.allow_rules = SessionAllowRules()
        self.policy = PolicyEngine(self.workspace, self.allow_rules)
        self.llm_driver = llm_driver or self._make_llm_driver(config)
        self.supervisee_command = supervisee_command
        runtime_base = runtime_parent or Path(tempfile.gettempdir())
        self.runtime_dir = Path(tempfile.mkdtemp(prefix="supervisor-", dir=runtime_base))
        os.chmod(self.runtime_dir, 0o700)
        self.socket_path = self.runtime_dir / "ipc.sock"
        self.auth_token = secrets.token_urlsafe(32)
        self.server: IPCServer | None = None
        self.process: ManagedProcess | None = None
        self.timer = DebouncedTimer(config.timer_interval_seconds)
        self.termination_reason: str | None = None
        self.adapter: ClaudeAdapter | CodexAdapter | None = None
        self.claude_settings_path: Path | None = None
        self.preserve_codex_hooks_on_cleanup = False

    def _make_llm_driver(self, config: RunConfig) -> LLMDriver:
        if config.mode == "api":
            if not config.supervisor_model:
                raise LLMDriverError("API mode requires --model")
            return OpenRouterDriver(config.supervisor_model)
        if config.platform == "claude":
            return ClaudeSubscriptionDriver(model=config.supervisor_model)
        if config.platform == "codex":
            return CodexSubscriptionDriver(model=config.supervisor_model)
        raise LLMDriverError("fake platform requires an injected LLM driver")

    def initialize_state(self, overwrite: bool = False) -> None:
        self.config = self.config.model_copy(update={"ipc_socket_path": str(self.socket_path)})
        self.store.initialize(self.config, overwrite=overwrite)

    async def start_ipc(self) -> None:
        self.server = IPCServer(self.socket_path, self.auth_token, self.handle_ipc_request)
        await self.server.start()

    async def stop_ipc(self) -> None:
        if self.server:
            await self.server.stop()
            self.server = None
        if self.runtime_dir.exists():
            shutil.rmtree(self.runtime_dir, ignore_errors=True)

    async def prepare_platform(self) -> None:
        if self.config.platform == "claude":
            adapter = ClaudeAdapter(self.store)
            self.claude_settings_path = adapter.create_settings()
            if not await adapter.supervisor_isolation_self_test():
                raise RuntimeError("Claude supervisor-call isolation self-test failed")
            if not await adapter.hook_fire_self_test():
                raise RuntimeError("Claude hook-fire self-test failed")
            self.adapter = adapter
        elif self.config.platform == "codex":
            adapter = CodexAdapter(self.store)
            adapter.recover_stale_hooks()
            planned_hooks = adapter.planned_supervisor_hooks()
            if not adapter.supervisor_hooks_trusted(planned_hooks):
                self._confirm_codex_trust_setup()
                adapter.install()
                self.adapter = adapter
                self.preserve_codex_hooks_on_cleanup = True
                self._print_codex_trust_setup_instruction()
                if not await adapter.trust_preflight(planned_hooks, self.socket_path, self.auth_token):
                    raise RuntimeError(
                        "Codex hook trust setup did not complete. The supervised task was not started. "
                        "The Supervisor hooks were left installed so the next run can resume from the current trust state."
                    )
                self.preserve_codex_hooks_on_cleanup = False
            else:
                adapter.install()
                self.adapter = adapter
                self.preserve_codex_hooks_on_cleanup = False
            if not await adapter.hook_fire_self_test(self.socket_path, self.auth_token):
                detail = f": {adapter.last_self_test_error}" if adapter.last_self_test_error else ""
                raise RuntimeError(f"Codex hook-fire self-test failed{detail}")
            if not await adapter.supervisor_isolation_self_test():
                raise RuntimeError("Codex supervisor-call isolation self-test failed")

    def _confirm_codex_trust_setup(self) -> None:
        print(
            "Codex needs a one-time trust setup before Supervisor can run this task: Supervisor will add its project hooks to .codex/hooks.json, open Codex's built-in trust UI, approve Codex's project-directory trust prompt if it appears so project hooks can load, then wait until Codex records that those exact hooks are trusted; Supervisor will not write Codex's trust file directly. Continue with hook installation and trust setup? [y/N] ",
            end="",
            flush=True,
        )
        try:
            answer = input()
        except EOFError as exc:
            raise RuntimeError("Codex hook trust setup was cancelled because no answer was provided") from exc
        if answer.strip().lower() not in {"y", "yes"}:
            raise RuntimeError("Codex hook trust setup was cancelled; the supervised task was not started")

    @staticmethod
    def _print_codex_trust_setup_instruction() -> None:
        print(
            "\nOpening Codex hook review now. Supervisor will answer Codex's project-directory trust prompt if it appears, then type /hooks and trust the Supervisor-owned hook entries through Codex's own UI. You do not need to type anything; this wrapper will close the setup Codex session automatically once trust is recorded.\n",
            flush=True,
        )

    def cleanup_platform(self) -> None:
        if isinstance(self.adapter, ClaudeAdapter):
            self.adapter.cleanup()
        elif isinstance(self.adapter, CodexAdapter):
            if self.preserve_codex_hooks_on_cleanup:
                return
            self.adapter.cleanup()

    def snapshot(self) -> StateSnapshot:
        config = self.store.get_config()
        health = self.store.get_health()
        last_actions = self.store.read_recent_actions()
        return StateSnapshot(
            config=config,
            health=health,
            progress=self.store.read_text(PROGRESS, ""),
            decisions=self.store.read_text(DECISIONS, ""),
            last_action=last_actions[-1] if last_actions else "",
            last_actions=last_actions,
            pending_intervention=self.store.read_pending(),
        )

    async def handle_ipc_request(self, request: IPCRequest) -> IPCResponse:
        health = self.store.get_health()
        event = HookEvent(
            event_type=request.event_type,
            event_id=request.event_id,
            source_hook=request.source_hook or request.event_type.value,
            payload=request.payload,
            timestamp=request.timestamp,
            generation=health.generation,
        )
        sequence = 0
        if self.server is not None:
            sequence = self.server._sequence
        return await self.handle_event(event, sequence=sequence)

    async def handle_event(self, event: HookEvent, sequence: int) -> IPCResponse:
        started = time.monotonic()
        budget = HookBudget.start(self.config.hook_timeout_seconds)
        handling_path = "policy"
        fallback_reason = None
        response: IPCResponse

        if event.event_type in {EventType.PERMISSION_REQUEST, EventType.PRE_TOOL_USE}:
            policy_decision = self.policy.evaluate(event)
            if policy_decision.kind == PolicyDecisionKind.ALLOW:
                response = IPCResponse(decision_type=DecisionType.ALLOW, payload={"reason": policy_decision.reason}, sequence=sequence)
                self._log(sequence, event, handling_path, started, response, None)
                return response
            if policy_decision.kind == PolicyDecisionKind.DENY:
                patch_health(self.store, HealthDelta(generation=event.generation, denied_requests=1, last_denial=policy_decision.reason))
                response = IPCResponse(decision_type=DecisionType.DENY, payload={"reason": policy_decision.reason}, sequence=sequence)
                self._log(sequence, event, handling_path, started, response, None)
                return response

        if event.event_type in {EventType.POST_TOOL_USE, EventType.POST_TOOL_BATCH, EventType.STOP, EventType.SUBAGENT_STOP}:
            pending = self._claim_pending_if_eligible(event)
            if pending:
                response = self._intervention_response(event, pending.message, sequence)
                self._log(sequence, event, "pending_intervention", started, response, None)
                return response
            response = IPCResponse(decision_type=DecisionType.NOOP, payload={"reason": "observation hook no-op"}, sequence=sequence)
            self._log(sequence, event, "observation_noop", started, response, None)
            return response

        handling_path = "llm"
        try:
            decision = await asyncio.wait_for(self._call_llm(event, sequence), timeout=budget.llm_deadline_seconds or 0.01)
            response = self.apply_llm_decision(event, decision, sequence)
        except (asyncio.TimeoutError, LLMDriverError, ParseFailure) as exc:
            fallback_reason = str(exc) or exc.__class__.__name__
            if isinstance(exc, LLMDriverError) and event.event_type in {EventType.TIMER, EventType.KILL_CANDIDATE}:
                self.store.write_handoff(f"Provider failure during supervisor call.\n\nReason: {fallback_reason}\n")
                self.termination_reason = "provider failure; state preserved"
                if self.process:
                    self.process.terminate_group()
            response = fallback_response(event.event_type, sequence, fallback_reason)
            patch_health(
                self.store,
                HealthDelta(
                    generation=event.generation,
                    timeout_fallback_count=1 if isinstance(exc, asyncio.TimeoutError) else 0,
                    parse_failure_count=1 if isinstance(exc, ParseFailure) else 0,
                    denied_requests=1 if response.decision_type == DecisionType.DENY else 0,
                    last_denial=fallback_reason if response.decision_type == DecisionType.DENY else None,
                ),
            )
        self._log(sequence, event, handling_path, started, response, fallback_reason)
        return response

    async def _call_llm(self, event: HookEvent, sequence: int) -> LLMDecision:
        snapshot = self.snapshot()
        prompt = build_wrapper_supervisor_prompt(
            event,
            snapshot,
            sequence,
            self.store.read_text(self.config.plan_file_path, ""),
        )
        try:
            decision = await self.llm_driver.decide(prompt, timeout_seconds=self.config.hook_timeout_seconds * 0.9)
        except ParseFailure:
            repair_prompt = f"{prompt}\n\nPrevious response was invalid. Return only valid JSON matching the schema."
            decision = await self.llm_driver.decide(repair_prompt, timeout_seconds=self.config.hook_timeout_seconds * 0.9)
        decision.sequence = sequence
        decision.generation = snapshot.health.generation
        return decision

    def apply_llm_decision(self, event: HookEvent, decision: LLMDecision, sequence: int) -> IPCResponse:
        current_generation = self.store.get_health().generation
        if decision.generation is not None and decision.generation != current_generation:
            return IPCResponse(decision_type=DecisionType.NOOP, payload={"reason": "stale LLM response discarded"}, sequence=sequence)

        if decision.decision_entry:
            self.store.append_text_locked(DECISIONS, f"- {decision.decision_entry}\n")
        if decision.completed_step:
            self.store.append_text_locked(PROGRESS, f"- Completed: {decision.completed_step}\n")
            patch_health(self.store, HealthDelta(generation=current_generation, last_progress_sequence=sequence))
        if decision.last_action:
            self.store.append_recent_action(decision.last_action)
        if decision.risk_signals:
            patch_health(self.store, HealthDelta(generation=current_generation, add_risk_signals=decision.risk_signals))

        if event.event_type in {EventType.PERMISSION_REQUEST, EventType.PRE_TOOL_USE} and decision.decision_type not in {DecisionType.ALLOW, DecisionType.DENY}:
            reason = decision.reason or f"LLM returned {decision.decision_type.value}"
            message = f"{event.event_type.value} requires an allow/deny decision in supervised headless mode; denying non-actionable decision: {reason}"
            patch_health(self.store, HealthDelta(generation=current_generation, denied_requests=1, last_denial=message))
            return IPCResponse(decision_type=DecisionType.DENY, payload={"reason": message}, sequence=sequence)

        if decision.decision_type == DecisionType.ALLOW:
            if decision.permission_kind == PermissionDecisionKind.ALLOW_CLASS:
                rule_payload = decision.allow_rule.model_dump(exclude_none=True) if decision.allow_rule else event.payload
                self.allow_rules.add(AllowRule.from_payload(self.workspace, current_generation, rule_payload))
            return IPCResponse(decision_type=DecisionType.ALLOW, payload={"reason": decision.reason}, sequence=sequence)
        if decision.decision_type == DecisionType.DENY:
            patch_health(self.store, HealthDelta(generation=current_generation, denied_requests=1, last_denial=decision.reason))
            return IPCResponse(decision_type=DecisionType.DENY, payload={"reason": decision.reason}, sequence=sequence)
        if decision.decision_type == DecisionType.INTERVENE:
            message = decision.intervention or decision.reason
            patch_health(self.store, HealthDelta(generation=current_generation, interventions=1))
            if self._eligible_for_delivery(event):
                return self._intervention_response(event, message, sequence)
            self.store.write_pending(PendingIntervention(generation=current_generation, sequence=sequence, message=message))
            return IPCResponse(decision_type=DecisionType.NOOP, payload={"pending_intervention": True}, sequence=sequence)
        if decision.decision_type == DecisionType.KILL_RESTART:
            self.apply_kill_restart(decision.handoff or decision.reason or "generation stuck")
            return IPCResponse(decision_type=DecisionType.KILL_RESTART, payload={"reason": decision.reason}, sequence=sequence)
        if decision.decision_type == DecisionType.TASK_COMPLETE:
            self.termination_reason = "task complete"
            if self.process:
                self.process.terminate_group()
            return IPCResponse(decision_type=DecisionType.TASK_COMPLETE, payload={"reason": decision.reason}, sequence=sequence)
        return IPCResponse(decision_type=DecisionType.NOOP, payload={"reason": decision.reason}, sequence=sequence)

    def _eligible_for_delivery(self, event: HookEvent) -> bool:
        return event.event_type in {EventType.POST_TOOL_BATCH, EventType.POST_TOOL_USE, EventType.STOP, EventType.SUBAGENT_STOP}

    def _claim_pending_if_eligible(self, event: HookEvent) -> PendingIntervention | None:
        if not self._eligible_for_delivery(event):
            return None
        return self.store.claim_pending(event.generation)

    def _intervention_response(self, event: HookEvent, message: str, sequence: int) -> IPCResponse:
        if event.event_type in {EventType.STOP, EventType.SUBAGENT_STOP}:
            payload = {"reason": message}
        else:
            payload = {"additionalContext": message}
        return IPCResponse(decision_type=DecisionType.INTERVENE, payload=payload, deferred_intervention_attached=True, sequence=sequence)

    def apply_kill_restart(self, handoff: str) -> None:
        health = self.store.get_health()
        if health.restart_count >= 3:
            self.termination_reason = "task stuck: restart cap reached"
            return
        self.store.write_handoff(handoff)
        if self.process:
            self.process.terminate_group()
        new_generation = health.generation + 1
        patch_health(
            self.store,
            HealthDelta(
                generation=health.generation,
                restart_count=1,
                reset_generation_scoped=True,
                new_generation=new_generation,
            ),
        )
        self.allow_rules.reset_generation(new_generation)
        self.store.write_text_locked("PENDING_INTERVENTION.md", "")
        if self.supervisee_command:
            self.launch_supervisee(restart=True)

    def launch_supervisee(self, restart: bool = False) -> None:
        command = self.supervisee_command or self.default_supervisee_command(restart=restart)
        env = {
            "SUPERVISOR_IPC_SOCKET": str(self.socket_path),
            "SUPERVISOR_IPC_TOKEN": self.auth_token,
            "SUPERVISOR_HOOK_TRACE_PATH": str(self.store.path("codex-hook-trace.log")),
        }
        stdout_path = None
        stderr_path = None
        if self.config.platform == "codex":
            stdout_path = self.store.path("codex-stdout.log")
            stderr_path = self.store.path("codex-stderr.log")
            if not restart:
                self.store.atomic_write_text(stdout_path, "")
                self.store.atomic_write_text(stderr_path, "")
                self.store.atomic_write_text(self.store.path("codex-hook-trace.log"), "")
        self.process = launch_process(command, self.workspace, env=env, stdout_path=stdout_path, stderr_path=stderr_path)

    def default_supervisee_command(self, restart: bool = False) -> list[str]:
        plan = str(Path(self.config.plan_file_path).resolve())
        instruction = f"Read the file at {plan}. This is your task for the session. Execute it step by step until completion."
        if restart:
            instruction = f"{instruction} Also read .supervisor/DECISIONS.md and .supervisor/HANDOFF.md before continuing."
        if self.config.platform == "claude":
            command = ["claude", "-p", instruction]
            if self.claude_settings_path:
                command.extend(["--settings", str(self.claude_settings_path)])
            return command
        if self.config.platform == "codex":
            return [
                "codex",
                "exec",
                *CODEX_EXEC_GIT_TRUST_FLAGS,
                *CODEX_EXEC_NO_WEB_SEARCH_FLAGS,
                "--json",
                "--sandbox",
                "workspace-write",
                instruction,
            ]
        return [os.environ.get("PYTHON", "python3"), "-m", "tests.fake_agent.agent"]

    async def timer_tick(self, sequence: int) -> IPCResponse | None:
        health = self.store.get_health()
        candidate, reason = kill_restart_candidate(health)
        if health.restart_count >= 3:
            self.termination_reason = "task stuck: restart cap reached"
            return IPCResponse(decision_type=DecisionType.KEEP_ALIVE, payload={"reason": self.termination_reason}, sequence=sequence)
        signature = f"{health.model_dump_json()}:{self.store.read_text('PENDING_INTERVENTION.md', '')}"
        if not candidate and not self.timer.should_call_llm(signature):
            return None
        event = HookEvent(
            event_type=EventType.KILL_CANDIDATE if candidate else EventType.TIMER,
            event_id=f"timer-{sequence}",
            source_hook="timer",
            payload={"candidate_reason": reason},
            generation=health.generation,
        )
        return await self.handle_event(event, sequence=sequence)

    def _log(
        self,
        sequence: int,
        event: HookEvent,
        handling_path: str,
        started: float,
        response: IPCResponse,
        fallback_reason: str | None,
    ) -> None:
        entry = DecisionLogEntry(
            sequence=sequence,
            hook_event_id=event.event_id,
            generation=event.generation,
            source_hook=event.source_hook,
            handling_path=handling_path,
            latency_ms=(time.monotonic() - started) * 1000,
            decision=response.model_dump(mode="json"),
            fallback_reason=fallback_reason,
        )
        self.store.append_log(entry)

    def final_report(self) -> str:
        health = self.store.get_health()
        reason = self.termination_reason or "supervisee exited"
        return (
            f"Supervisor final report\n"
            f"Termination: {reason}\n"
            f"Generation: {health.generation}\n"
            f"Restarts: {health.restart_count}\n"
            f"Denied requests: {health.denied_requests}\n"
            f"Interventions: {health.interventions}\n"
            f"Timeout fallbacks: {health.timeout_fallback_count}\n"
            f"Parse failures: {health.parse_failure_count}\n"
        )


def build_wrapper_supervisor_prompt(event: HookEvent, snapshot: StateSnapshot, sequence: int, objective: str) -> str:
    payload = {
        "objective": objective,
        "sequence": sequence,
        "generation": snapshot.health.generation,
        "event": event.model_dump(mode="json"),
        "state": snapshot.model_dump(mode="json"),
        "decision_schema": LLMDecision.model_json_schema(),
        "instructions": WRAPPER_SUPERVISOR_INSTRUCTIONS,
    }
    return json.dumps(payload, indent=2, sort_keys=True)
