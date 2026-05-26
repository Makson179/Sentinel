from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from supervisor.appserver import AppServerClient, AppServerMessage
from supervisor.approvals import ApprovalManager, normalize_approval_request
from supervisor.coder import CoderSession, coder_thread_params
from supervisor.health import kill_restart_candidate, patch_health
from supervisor.schemas import (
    AppEvent,
    AppEventSource,
    ApprovalContext,
    FinalReport,
    HealthDelta,
    SentinelConfig,
    SentinelStatus,
    SupervisorDecision,
    SupervisorDecisionKind,
    SupervisorWakePacket,
)
from supervisor.state import DECISIONS, HANDOFF, LAST_ACTION, PROGRESS, StateStore
from supervisor.supervisor_agent import StatelessSupervisorAgent, SupervisorAgentError
from supervisor.task_select import resolve_task
from supervisor.tui import TerminalTUI, UserCommand


@dataclass(frozen=True)
class ControllerEvent:
    kind: str
    message: AppServerMessage | None = None
    user_command: UserCommand | None = None


class SentinelController:
    def __init__(
        self,
        project_root: Path,
        *,
        task_path: Path | None = None,
        client: AppServerClient | None = None,
        tui: TerminalTUI | None = None,
        model: str | None = None,
        overwrite_state: bool = False,
    ):
        self.project_root = project_root.resolve()
        self.task_path = resolve_task(self.project_root, task_path)
        self.store = StateStore(self.project_root)
        self.model = model
        self.overwrite_state = overwrite_state
        self.event_queue: asyncio.Queue[ControllerEvent] = asyncio.Queue()
        self.client = client or AppServerClient(
            cwd=self.project_root,
            notification_handler=self._on_notification,
            server_request_handler=self._on_server_request,
        )
        self.tui = tui or TerminalTUI()
        self.supervisor: StatelessSupervisorAgent | None = None
        self.approvals: ApprovalManager | None = None
        self.coder: CoderSession | None = None
        self.pending_approvals: dict[int | str, ApprovalContext] = {}
        self.running = False
        self.paused = False
        self._sequence = 0
        self._supervisor_task: asyncio.Task[None] | None = None
        self._supervisor_dirty = False

    async def run(self) -> None:
        self.initialize_state()
        await self.client.start()
        await self.client.initialize()
        await self.tui.start()
        self.running = True
        try:
            await self.preflight()
            self.supervisor = StatelessSupervisorAgent(self.client, self.store, self.task_path, model=self.model)
            self.approvals = ApprovalManager(self.project_root, supervisor=self.supervisor)
            self.coder = CoderSession(self.client, self.store, self.project_root, self.task_path, model=self.model)
            await self.coder.start_thread()
            await self.coder.start_initial_turn()
            self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"status": SentinelStatus.RUNNING}))
            self.tui.status("supervised coder started")
            await self.event_loop()
        finally:
            self.running = False
            await self.tui.stop()
            await self.client.stop()

    def initialize_state(self) -> None:
        config = SentinelConfig(
            project_root=str(self.project_root),
            task_path=str(self.task_path),
            task_hash=_hash_file(self.task_path),
            model=self.model,
        )
        self.store.initialize_sentinel(config, overwrite=self.overwrite_state)

    async def preflight(self) -> None:
        self.tui.status("checking Codex version")
        version = _run_probe(["codex", "--version"])[1]
        self.tui.status("checking Codex app-server schema")
        schema_hash = await asyncio.to_thread(self._generate_schema_hash)
        self.store.update_sentinel_config(
            lambda cfg: cfg.model_copy(update={"codex_version": version, "appserver_schema_hash": schema_hash})
        )
        self.tui.status("checking Codex account")
        account = await self.client.account_read()
        if account.get("requiresOpenaiAuth") and account.get("account") is None:
            raise RuntimeError("Codex auth missing. Run `codex login` before starting Sentinel.")
        self.tui.status("checking Codex rate limits")
        try:
            await self.client.account_rate_limits_read()
        except Exception:
            pass
        self.tui.status("checking available models")
        models = await self.client.model_list()
        if self.model is None:
            self.model = _default_model(models)
            self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"model": self.model}))
        self.tui.status("checking supervisor structured output")
        await self._structured_output_self_test()
        self.tui.status("checking config requirements")
        await self.client.config_requirements_read()
        self.tui.status("checking coder sandbox and approval settings")
        thread = await self.client.thread_start(coder_thread_params(self.project_root, model=self.model))
        approval_policy = thread.get("approvalPolicy")
        sandbox = thread.get("sandbox")
        thread_id = thread.get("thread", {}).get("id") if isinstance(thread.get("thread"), dict) else None
        if approval_policy != "on-request":
            raise RuntimeError("app-server did not accept on-request coder approval policy")
        if not _sandbox_is_read_only(sandbox):
            raise RuntimeError("app-server did not accept read-only coder sandbox")
        if isinstance(thread_id, str):
            try:
                await self.client.thread_archive(thread_id)
            except Exception:
                try:
                    await self.client.thread_unsubscribe(thread_id)
                except Exception:
                    pass

    async def event_loop(self) -> None:
        assert self.tui is not None
        while self.running:
            event_task = asyncio.create_task(self.event_queue.get())
            input_task = asyncio.create_task(self.tui.input_queue.get())
            done, pending = await asyncio.wait({event_task, input_task}, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            for done_task in done:
                completed = done_task.result()
                if isinstance(completed, ControllerEvent):
                    await self.handle_controller_event(completed)
                elif isinstance(completed, UserCommand):
                    await self.handle_user_command(completed)

    async def handle_controller_event(self, event: ControllerEvent) -> None:
        if event.message is None:
            return
        message = event.message
        if event.kind == "server_request":
            await self.handle_server_request(message)
        elif event.kind == "notification":
            await self.handle_notification(message)

    async def handle_user_command(self, command: UserCommand) -> None:
        text = command.text.strip()
        if not text:
            return
        self._append_event(AppEventSource.USER, "user/input", reason=text)
        if text == "/quit":
            await self.finalize("exited by user", status=SentinelStatus.EXITED)
            return
        if text in {"/pause", "\x03"}:
            await self.pause()
            return
        if text == "/resume":
            self.paused = False
            self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"status": SentinelStatus.RUNNING}))
            self.tui.status("resumed")
            return
        if text == "/restart":
            await self.restart("user requested supervised restart")
            return
        if text == "/status":
            cfg = self.store.get_sentinel_config()
            health = self.store.get_health()
            self.tui.render("SYSTEM", f"task={Path(cfg.task_path).name} generation={cfg.generation} active_turn={cfg.active_coder_turn_id} pending_approvals={len(self.pending_approvals)} restarts={health.restart_count}")
            return
        self._schedule_supervisor_check(f"Human message to supervisor: {text}")

    async def handle_server_request(self, message: AppServerMessage) -> None:
        context = normalize_approval_request(message)
        self.pending_approvals[context.server_request_id] = context
        self.store.update_sentinel_config(
            lambda cfg: cfg.model_copy(update={"pending_server_request_ids": list(self.pending_approvals)})
        )
        self._append_event(
            AppEventSource.APPROVAL,
            context.server_request_method,
            thread_id=context.thread_id,
            turn_id=context.turn_id,
            item_id=context.item_id,
            reason=context.command or context.grant_root or context.request_type.value,
        )
        if self.approvals is None:
            resolution = ApprovalManager(self.project_root)._deny(context, "approval manager not ready")
            response = ApprovalManager(self.project_root).response_payload(context, resolution)
        else:
            resolution = await self.approvals.decide(context)
            response = self.approvals.response_payload(context, resolution)
        await self.client.respond(context.server_request_id, response)
        self.tui.render("APPROVAL" if str(resolution.decision).startswith("accept") else "DENIED", f"{resolution.decision}: {resolution.reason}")
        if resolution.persistent_decision:
            self.store.append_text_locked(DECISIONS, f"- {resolution.persistent_decision}\n")
        if str(resolution.decision) in {"decline", "cancel", "denied", "abort"}:
            patch_health(self.store, HealthDelta(generation=self.store.get_health().generation, denied_requests=1, last_denial=resolution.reason))

    async def handle_notification(self, message: AppServerMessage) -> None:
        params = message.params
        method = message.method or "notification"
        thread_id = params.get("threadId")
        turn_id = _turn_id_from_params(params)
        item_id = _item_id_from_params(params)
        if _is_stream_delta_method(method):
            return
        self._append_event(AppEventSource.APP_SERVER, method, thread_id=thread_id, turn_id=turn_id, item_id=item_id)

        cfg = self.store.get_sentinel_config()
        if method == "serverRequest/resolved":
            request_id = params.get("requestId")
            self.pending_approvals.pop(request_id, None)
            self.store.update_sentinel_config(
                lambda current: current.model_copy(update={"pending_server_request_ids": list(self.pending_approvals)})
            )
            return
        if method == "turn/started" and thread_id == cfg.coder_thread_id and isinstance(turn_id, str):
            if self.coder:
                self.coder.active_turn_id = turn_id
            self.store.update_sentinel_config(lambda current: current.model_copy(update={"active_coder_turn_id": turn_id}))
            self.tui.render("CODER", f"turn started {turn_id}")
            return
        if method == "item/completed" and thread_id == cfg.coder_thread_id:
            summary = _item_summary(params.get("item"))
            item = params.get("item")
            if isinstance(item, dict) and item.get("type") == "agentMessage" and isinstance(item.get("text"), str):
                self.tui.render("CODER", item["text"].strip())
                return
            if _is_completed_action(item):
                self.store.write_text_locked(LAST_ACTION, summary + "\n")
                self.tui.render("TOOL", summary)
                self._schedule_supervisor_check(f"Coder completed action: {summary}", triggering_item_id=item_id)
            return
        if method == "turn/completed" and thread_id == cfg.coder_thread_id:
            if self.coder and isinstance(turn_id, str):
                self.coder.mark_turn_completed(turn_id)
            self._schedule_supervisor_check("Coder turn completed", triggering_item_id=item_id)

    async def pause(self) -> None:
        self.paused = True
        self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"status": SentinelStatus.PAUSED}))
        if self.coder:
            try:
                await self.coder.interrupt()
            except Exception:
                pass
        await self._resolve_pending_approvals("paused")
        self.tui.status("paused")

    async def restart(self, reason: str) -> None:
        cfg = self.store.get_sentinel_config()
        if cfg.restart_count >= cfg.max_restarts:
            await self.finalize("restart cap reached", status=SentinelStatus.STUCK)
            return
        self.store.update_sentinel_config(lambda current: current.model_copy(update={"status": SentinelStatus.RESTARTING}))
        if self.coder:
            try:
                await self.coder.interrupt()
            except Exception:
                pass
        await self._resolve_pending_approvals("restart")
        diff_summary = await self.diff_summary()
        handoff = "\n".join(
            [
                f"# Handoff generation {cfg.generation}",
                "",
                f"- Task: {cfg.task_path}",
                f"- Reason: {reason}",
                f"- Diff summary:",
                "```text",
                diff_summary or "diff unavailable",
                "```",
                "",
                "## Progress",
                self.store.read_text(PROGRESS, ""),
                "",
                "## Last Action",
                self.store.read_text(LAST_ACTION, ""),
            ]
        )
        self.store.write_handoff(handoff)
        patch_health(
            self.store,
            HealthDelta(
                generation=cfg.generation,
                restart_count=1,
                reset_generation_scoped=True,
                new_generation=cfg.generation + 1,
            ),
        )
        self.store.update_sentinel_config(
            lambda current: current.model_copy(
                update={
                    "generation": current.generation + 1,
                    "restart_count": current.restart_count + 1,
                    "active_coder_turn_id": None,
                    "coder_thread_id": None,
                    "status": SentinelStatus.RUNNING,
                }
            )
        )
        self.coder = CoderSession(self.client, self.store, self.project_root, self.task_path, model=self.model)
        await self.coder.start_thread()
        await self.coder.start_restart_turn()
        self.tui.render("SYSTEM", "restart complete")

    async def finalize(self, result: str, *, status: SentinelStatus = SentinelStatus.COMPLETE) -> None:
        diff = await self.diff_summary()
        report = FinalReport(
            task_path=str(self.task_path),
            status=status,
            result=result,
            files_changed=_changed_files_from_diff_summary(diff),
            validations=[],
            denied_actions=[],
            interventions=self.store.get_health().interventions,
            restarts=self.store.get_health().restart_count,
            diff_summary=diff,
        )
        self.store.write_final_report(report)
        self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"status": status}))
        self.tui.render("SUPERVISOR", result)
        self.tui.status("final report written: .supervisor/FINAL_REPORT.md")
        self.running = False

    def _schedule_supervisor_check(self, summary: str, *, triggering_item_id: str | None = None) -> None:
        if self.paused or self.supervisor is None:
            return
        if self._supervisor_task and not self._supervisor_task.done():
            self._supervisor_dirty = True
            return
        self._supervisor_task = asyncio.create_task(self._supervisor_check_loop(summary, triggering_item_id))

    async def _supervisor_check_loop(self, summary: str, triggering_item_id: str | None) -> None:
        while True:
            self._supervisor_dirty = False
            await self._run_supervisor_check(summary, triggering_item_id)
            if not self._supervisor_dirty:
                return
            summary = "Supervisor check was dirty; reviewing latest state"
            triggering_item_id = None

    async def _run_supervisor_check(self, summary: str, triggering_item_id: str | None) -> None:
        if self.supervisor is None:
            return
        cfg = self.store.get_sentinel_config()
        wake_sequence = cfg.last_event_sequence + 1
        packet = self.supervisor.build_packet(
            wake_sequence=wake_sequence,
            current_summary=summary,
            diff_summary=await self.diff_summary(),
            triggering_item_id=triggering_item_id,
        )
        try:
            decision = await self.supervisor.decide(packet)
        except SupervisorAgentError as exc:
            self.tui.render("SUPERVISOR", f"noop: {exc}")
            return
        await self.apply_supervisor_decision(decision, packet_thread_id=packet.coder_thread_id)

    async def apply_supervisor_decision(self, decision: SupervisorDecision, *, packet_thread_id: str | None) -> None:
        cfg = self.store.get_sentinel_config()
        if decision.generation is not None and decision.generation != cfg.generation:
            return
        if packet_thread_id != cfg.coder_thread_id:
            return
        if decision.wake_sequence is not None and decision.wake_sequence <= cfg.last_applied_supervisor_sequence:
            return
        self.store.update_sentinel_config(
            lambda current: current.model_copy(update={"last_applied_supervisor_sequence": decision.wake_sequence or current.last_applied_supervisor_sequence})
        )
        if decision.persistent_decision:
            self.store.append_text_locked(DECISIONS, f"- {decision.persistent_decision}\n")
        if decision.progress_update:
            self.store.append_text_locked(PROGRESS, f"- {decision.progress_update}\n")
            patch_health(self.store, HealthDelta(generation=cfg.generation, last_progress_sequence=cfg.last_event_sequence))
        if decision.display_message:
            self.tui.render("SUPERVISOR", decision.display_message)
        if decision.decision == SupervisorDecisionKind.NOOP:
            return
        if decision.decision == SupervisorDecisionKind.INTERVENE and decision.message_to_coder and self.coder:
            self.tui.render("SUPERVISOR", f"steering coder: {decision.reason}")
            await self.coder.steer_or_start(decision.message_to_coder)
            return
        if decision.decision == SupervisorDecisionKind.RESTART:
            candidate, candidate_reason = kill_restart_candidate(self.store.get_health())
            if not candidate:
                message = decision.message_to_coder or (
                    "Continue the current task. Do not restart; use the latest observation to make the next concrete progress step."
                )
                self.tui.render("SUPERVISOR", f"restart rejected without health evidence: {decision.reason}")
                if self.coder:
                    await self.coder.steer_or_start(message)
                return
            if candidate_reason:
                self.tui.render("SUPERVISOR", f"restart candidate: {candidate_reason}")
            await self.restart(decision.reason or "supervisor requested restart")
            return
        if decision.decision == SupervisorDecisionKind.PAUSE:
            await self.pause()
            return
        if decision.decision == SupervisorDecisionKind.COMPLETE:
            if self.pending_approvals or self.store.get_sentinel_config().active_coder_turn_id:
                return
            await self.finalize(decision.reason or "task complete", status=SentinelStatus.COMPLETE)

    async def _resolve_pending_approvals(self, reason: str) -> None:
        if self.approvals is None:
            manager = ApprovalManager(self.project_root)
        else:
            manager = self.approvals
        for request_id, context in list(self.pending_approvals.items()):
            resolution = manager._deny(context, reason)
            await self.client.respond(request_id, manager.response_payload(context, resolution))
            self.pending_approvals.pop(request_id, None)
        self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"pending_server_request_ids": []}))

    async def diff_summary(self) -> str:
        commands = [["git", "status", "--short"], ["git", "diff", "--stat"], ["git", "diff", "--name-only"]]
        parts: list[str] = []
        for command in commands:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *command,
                    cwd=str(self.project_root),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
                text = (stdout + stderr).decode("utf-8", errors="replace").strip()
                parts.append(f"$ {' '.join(command)}\n{text}")
            except Exception as exc:
                parts.append(f"$ {' '.join(command)}\ndiff unavailable: {exc}")
        return "\n\n".join(parts)

    async def _on_notification(self, message: AppServerMessage) -> None:
        await self.event_queue.put(ControllerEvent(kind="notification", message=message))

    async def _on_server_request(self, message: AppServerMessage) -> None:
        await self.event_queue.put(ControllerEvent(kind="server_request", message=message))

    def _append_event(
        self,
        source: AppEventSource,
        event_type: str,
        *,
        thread_id: Any = None,
        turn_id: Any = None,
        item_id: Any = None,
        decision: Any = None,
        reason: str | None = None,
    ) -> None:
        self._sequence += 1
        cfg = self.store.get_sentinel_config()
        event = AppEvent(
            sequence=self._sequence,
            generation=cfg.generation,
            source=source,
            event_type=event_type,
            thread_id=thread_id if isinstance(thread_id, str) else None,
            turn_id=turn_id if isinstance(turn_id, str) else None,
            item_id=item_id if isinstance(item_id, str) else None,
            decision=decision,
            reason=reason,
        )
        self.store.append_event(event)
        self.store.update_sentinel_config(lambda current: current.model_copy(update={"last_event_sequence": self._sequence}))

    def _generate_schema_hash(self) -> str:
        if shutil.which("codex") is None:
            raise RuntimeError("codex executable not found")
        out_dir = self.store.state_dir / "appserver-schema"
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True)
        completed = subprocess.run(
            ["codex", "app-server", "generate-json-schema", "--experimental", "--out", str(out_dir)],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError((completed.stdout + completed.stderr).strip() or "app-server schema generation failed")
        required = ["ClientRequest.json", "ServerRequest.json", "TurnStartParams.json", "CommandExecutionRequestApprovalParams.json"]
        for rel in required:
            if not _schema_file_exists(out_dir, rel):
                raise RuntimeError(f"app-server schema missing required file: {rel}")
        digest = hashlib.sha256()
        for path in sorted(out_dir.rglob("*.json")):
            digest.update(str(path.relative_to(out_dir)).encode("utf-8"))
            digest.update(path.read_bytes())
        return digest.hexdigest()

    async def _structured_output_self_test(self) -> None:
        agent = StatelessSupervisorAgent(self.client, self.store, self.task_path, model=self.model, timeout_seconds=45)
        cfg = self.store.get_sentinel_config()
        packet = SupervisorWakePacket(
            wake_sequence=1,
            latest_event_sequence=cfg.last_event_sequence,
            generation=cfg.generation,
            restart_count=cfg.restart_count,
            task_path=str(self.task_path),
            task_contents="Structured output self-test. Return noop.",
            progress="",
            decisions="",
            last_action="",
            health=self.store.get_health().model_dump(mode="json"),
            recent_events=[],
            current_summary="Startup structured-output self-test. Return decision noop.",
            coder_thread_id=None,
            active_coder_turn_id=None,
        )
        decision = await asyncio.wait_for(agent.decide(packet), timeout=120)
        if decision.decision not in {SupervisorDecisionKind.NOOP, SupervisorDecisionKind.PAUSE}:
            raise RuntimeError("structured-output supervisor self-test returned an unexpected decision")


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _schema_file_exists(out_dir: Path, name: str) -> bool:
    return (out_dir / name).exists() or (out_dir / "v2" / name).exists()


def _run_probe(args: list[str], timeout: float = 5.0) -> tuple[bool, str]:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return completed.returncode == 0, (completed.stdout + completed.stderr).strip()


def _default_model(response: dict[str, Any]) -> str | None:
    data = response.get("data")
    if not isinstance(data, list) or not data:
        return None
    first = data[0]
    if not isinstance(first, dict):
        return None
    for key in ("id", "slug", "name"):
        value = first.get(key)
        if isinstance(value, str):
            return value
    return None


def _sandbox_is_read_only(value: Any) -> bool:
    if value == "read-only":
        return True
    if isinstance(value, dict):
        return value.get("type") == "readOnly"
    return False


def _turn_id_from_params(params: dict[str, Any]) -> str | None:
    if isinstance(params.get("turnId"), str):
        return params["turnId"]
    turn = params.get("turn")
    if isinstance(turn, dict) and isinstance(turn.get("id"), str):
        return turn["id"]
    return None


def _item_id_from_params(params: dict[str, Any]) -> str | None:
    if isinstance(params.get("itemId"), str):
        return params["itemId"]
    item = params.get("item")
    if isinstance(item, dict) and isinstance(item.get("id"), str):
        return item["id"]
    return None


def _item_summary(item: Any) -> str:
    if not isinstance(item, dict):
        return "item completed"
    item_type = item.get("type", "item")
    if item_type == "commandExecution":
        return f"command completed: {item.get('command', '')} exit={item.get('exitCode')}"
    if item_type == "fileChange":
        return f"file change completed: {len(item.get('changes') or [])} changes"
    if item_type == "mcpToolCall":
        return f"mcp tool completed: {item.get('server')}/{item.get('tool')}"
    if item_type == "dynamicToolCall":
        return f"dynamic tool completed: {item.get('tool')}"
    if item_type == "agentMessage":
        return "agent message completed"
    return f"{item_type} completed"


def _is_completed_action(item: Any) -> bool:
    return isinstance(item, dict) and item.get("type") in {"commandExecution", "fileChange", "mcpToolCall", "dynamicToolCall", "webSearch"}


def _is_stream_delta_method(method: str) -> bool:
    return method.endswith("/delta") or method.endswith("/outputDelta") or method in {
        "item/reasoning/summaryTextDelta",
        "item/reasoning/textDelta",
        "command/exec/outputDelta",
        "process/outputDelta",
        "item/commandExecution/outputDelta",
        "item/fileChange/outputDelta",
    }


def _changed_files_from_diff_summary(diff: str | None) -> list[str]:
    if not diff:
        return []
    files: list[str] = []
    status_marker = "$ git status --short"
    if status_marker in diff:
        status_tail = diff.split(status_marker, 1)[1].split("$ git diff --stat", 1)[0]
        for line in status_tail.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("$"):
                continue
            path = stripped[3:] if len(stripped) > 3 else stripped
            path = path.strip()
            if path and not path.startswith(".supervisor/") and path not in files:
                files.append(path)
    marker = "$ git diff --name-only"
    if marker in diff:
        tail = diff.split(marker, 1)[1]
        for line in tail.splitlines():
            path = line.strip()
            if path and not path.startswith("$") and path not in files:
                files.append(path)
    return files
