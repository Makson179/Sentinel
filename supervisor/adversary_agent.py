from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from supervisor.appserver import (
    APP_SERVER_CLEANUP_RPC_TIMEOUT_SECONDS,
    APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
    AppServerClient,
    AppServerError,
    last_agent_message_text,
    text_input,
)
from supervisor.prompts import build_adversary_prompt
from supervisor.schemas import SupervisorWakePacket


DEFAULT_ADVERSARY_TIMEOUT_SECONDS = 900.0


class AdversaryAgentError(RuntimeError):
    pass


@dataclass(frozen=True)
class AdversaryRunResult:
    report_text: str
    thread_id: str
    turn_id: str
    candidate_finding: bool


class AdversaryAgent:
    def __init__(
        self,
        client: AppServerClient,
        project_root: Path,
        *,
        model: str | None = None,
        timeout_seconds: float = DEFAULT_ADVERSARY_TIMEOUT_SECONDS,
        on_thread_start: Callable[[str], None] | None = None,
        on_thread_done: Callable[[str], None] | None = None,
    ):
        self.client = client
        self.project_root = project_root.resolve()
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.on_thread_start = on_thread_start
        self.on_thread_done = on_thread_done

    async def run(
        self,
        packet: SupervisorWakePacket,
        *,
        previous_adversary_report: dict[str, Any] | None = None,
    ) -> AdversaryRunResult:
        prompt = build_adversary_prompt(
            packet,
            previous_adversary_report=previous_adversary_report,
        )
        last_error: str | None = None
        for attempt in range(2):
            try:
                return await self._run_once(prompt)
            except AdversaryAgentError as exc:
                last_error = str(exc)
                if "did not produce an agent message" not in last_error or attempt == 1:
                    raise
        raise AdversaryAgentError(last_error or "adversary run failed")

    async def _run_once(self, prompt: str) -> AdversaryRunResult:
        thread_id: str | None = None
        turn_id: str | None = None
        try:
            thread_response = await self._await_rpc(
                "adversary thread/start response",
                self.client.thread_start(self._thread_params(), timeout=APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS),
                timeout=APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
            )
            thread = thread_response.get("thread", {})
            thread_id = thread.get("id") if isinstance(thread, dict) else None
            if not isinstance(thread_id, str):
                raise AdversaryAgentError("adversary thread/start did not return thread id")
            if self.on_thread_start:
                self.on_thread_start(thread_id)

            turn_response = await self._await_rpc(
                "adversary turn/start response",
                self.client.turn_start(
                    self._turn_params(thread_id, prompt),
                    timeout=self.timeout_seconds,
                ),
                timeout=self.timeout_seconds,
            )
            turn = turn_response.get("turn", {})
            turn_id_value = turn.get("id") if isinstance(turn, dict) else None
            if not isinstance(turn_id_value, str):
                raise AdversaryAgentError("adversary turn/start did not return turn id")
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
                    raise AdversaryAgentError(
                        f"adversary turn/completed notification timed out after {self.timeout_seconds:g}s "
                        f"thread_id={thread_id} turn_id={turn_id}"
                    ) from exc
                turn = completed.params.get("turn", {})

            text = last_agent_message_text(turn)
            if text is None:
                turns = await self._await_rpc(
                    "adversary thread/turns/list response",
                    self.client.thread_turns_list(
                        thread_id,
                        limit=5,
                        items_view="full",
                        timeout=APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
                    ),
                    timeout=APP_SERVER_CONTROL_RPC_TIMEOUT_SECONDS,
                )
                text = _agent_message_text_from_turns(turns.get("data", []), turn_id=turn_id)
            if text is None or not text.strip():
                raise AdversaryAgentError("adversary did not produce an agent message")
            report_text = text.strip()
            return AdversaryRunResult(
                report_text=report_text,
                thread_id=thread_id,
                turn_id=turn_id,
                candidate_finding=_report_has_candidate_finding(report_text),
            )
        except AdversaryAgentError:
            raise
        except Exception as exc:
            raise AdversaryAgentError(f"{exc.__class__.__name__}: {exc}") from exc
        finally:
            if thread_id is not None:
                try:
                    await self.client.thread_archive(thread_id, timeout=APP_SERVER_CLEANUP_RPC_TIMEOUT_SECONDS)
                except Exception:
                    try:
                        await self.client.thread_unsubscribe(
                            thread_id,
                            timeout=APP_SERVER_CLEANUP_RPC_TIMEOUT_SECONDS,
                        )
                    except Exception:
                        pass
                if self.on_thread_done:
                    self.on_thread_done(thread_id)

    def _thread_params(self) -> dict[str, Any]:
        params: dict[str, Any] = {
            "cwd": str(self.project_root),
            "runtimeWorkspaceRoots": [str(self.project_root)],
            "approvalPolicy": "on-request",
            "approvalsReviewer": "user",
            "sandbox": "workspace-write",
            "ephemeral": False,
            "experimentalRawEvents": False,
            "persistExtendedHistory": False,
        }
        if self.model:
            params["model"] = self.model
        return params

    def _turn_params(self, thread_id: str, prompt: str) -> dict[str, Any]:
        params: dict[str, Any] = {
            "threadId": thread_id,
            "input": [text_input(prompt)],
            "cwd": str(self.project_root),
            "runtimeWorkspaceRoots": [str(self.project_root)],
            "approvalPolicy": "on-request",
            "approvalsReviewer": "user",
            "sandboxPolicy": {
                "type": "workspaceWrite",
                "writableRoots": [str(self.project_root)],
                "networkAccess": False,
            },
        }
        if self.model:
            params["model"] = self.model
        return params

    async def _await_rpc(self, stage: str, awaitable: Any, *, timeout: float) -> Any:
        try:
            return await asyncio.wait_for(awaitable, timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise AdversaryAgentError(f"{stage} timed out after {timeout:g}s") from exc
        except AdversaryAgentError:
            raise
        except Exception as exc:
            raise AdversaryAgentError(f"{stage} failed with {exc.__class__.__name__}: {exc}") from exc


def _agent_message_text_from_turns(data: Any, *, turn_id: str | None) -> str | None:
    if not isinstance(data, list):
        return None
    for turn in data:
        if not isinstance(turn, dict):
            continue
        if turn_id is not None and turn.get("id") != turn_id:
            continue
        text = last_agent_message_text(turn)
        if text:
            return text
    return None


def _report_has_candidate_finding(report_text: str) -> bool:
    lowered_lines = [line.strip().lower() for line in report_text.splitlines() if line.strip()]
    for index, line in enumerate(lowered_lines):
        if line.startswith("candidate_finding:"):
            value = line.split(":", 1)[1].strip()
            if value in {"false", "no", "none", "0"}:
                return False
            if value in {"true", "yes", "1"}:
                return True
        if line.startswith("findings:"):
            value = line.split(":", 1)[1].strip()
            if value:
                return value not in {"none", "no", "no findings", "nothing", "n/a", "not found"}
            for following in lowered_lines[index + 1 :]:
                if _looks_like_report_section(following):
                    return False
                normalized = following.lstrip("-*0123456789. )").strip()
                if not normalized or normalized in {"none", "no", "no findings", "nothing", "n/a", "not found"}:
                    continue
                return True
            return False
    return True


def _looks_like_report_section(line: str) -> bool:
    prefixes = (
        "attacked:",
        "held:",
        "not_reached:",
        "not reached:",
        "overall:",
        "candidate_finding:",
        "candidate finding:",
    )
    if any(line.startswith(prefix) for prefix in prefixes):
        return True
    return False
