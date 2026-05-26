from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from supervisor.appserver import AppServerClient, text_input
from supervisor.prompts import build_coder_prompt, build_restart_prompt
from supervisor.state import StateStore


def coder_thread_params(project_root: Path, *, model: str | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {
        "cwd": str(project_root),
        "runtimeWorkspaceRoots": [str(project_root)],
        "approvalPolicy": "on-request",
        "approvalsReviewer": "user",
        "sandbox": "read-only",
        "ephemeral": False,
        "experimentalRawEvents": False,
        "persistExtendedHistory": False,
    }
    if model:
        params["model"] = model
    return params


def coder_turn_params(thread_id: str, text: str, project_root: Path, *, model: str | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {
        "threadId": thread_id,
        "input": [text_input(text)],
        "cwd": str(project_root),
        "runtimeWorkspaceRoots": [str(project_root)],
        "approvalPolicy": "on-request",
        "approvalsReviewer": "user",
        "sandboxPolicy": {"type": "readOnly", "networkAccess": False},
    }
    if model:
        params["model"] = model
    return params


@dataclass
class CoderSession:
    client: AppServerClient
    store: StateStore
    project_root: Path
    task_path: Path
    model: str | None = None
    thread_id: str | None = None
    active_turn_id: str | None = None

    async def start_thread(self) -> str:
        response = await self.client.thread_start(coder_thread_params(self.project_root, model=self.model))
        thread = response.get("thread", {})
        thread_id = thread.get("id")
        if not isinstance(thread_id, str):
            raise RuntimeError("app-server thread/start did not return a thread id")
        self.thread_id = thread_id
        self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"coder_thread_id": thread_id}))
        return thread_id

    async def start_initial_turn(self) -> str:
        return await self.start_turn(build_coder_prompt(self.task_path))

    async def start_restart_turn(self) -> str:
        return await self.start_turn(build_restart_prompt(self.task_path))

    async def start_turn(self, message: str) -> str:
        thread_id = self.thread_id or await self.start_thread()
        response = await self.client.turn_start(coder_turn_params(thread_id, message, self.project_root, model=self.model))
        turn = response.get("turn", {})
        turn_id = turn.get("id")
        if not isinstance(turn_id, str):
            raise RuntimeError("app-server turn/start did not return a turn id")
        self.active_turn_id = turn_id
        self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"active_coder_turn_id": turn_id}))
        return turn_id

    async def steer_or_start(self, message: str) -> str | None:
        if self.thread_id and self.active_turn_id:
            try:
                await self.client.turn_steer(self.thread_id, self.active_turn_id, message)
                return self.active_turn_id
            except Exception:
                self.active_turn_id = None
                self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"active_coder_turn_id": None}))
        if self.thread_id:
            return await self.start_turn(message)
        return None

    async def interrupt(self) -> None:
        if not self.thread_id or not self.active_turn_id:
            return
        await self.client.turn_interrupt(self.thread_id, self.active_turn_id)

    def mark_turn_completed(self, turn_id: str) -> None:
        if self.active_turn_id == turn_id:
            self.active_turn_id = None
            self.store.update_sentinel_config(lambda cfg: cfg.model_copy(update={"active_coder_turn_id": None}))
