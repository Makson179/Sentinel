from __future__ import annotations

import asyncio
import contextlib
import sys
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class UserCommand:
    text: str


class TerminalTUI:
    def __init__(self):
        self.input_queue: asyncio.Queue[UserCommand] = asyncio.Queue()
        self._input_task: asyncio.Task[None] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._reader_registered = False
        self._running = False

    async def start(self) -> None:
        self._running = True
        self._loop = asyncio.get_running_loop()
        try:
            self._loop.add_reader(sys.stdin.fileno(), self._on_stdin_ready)
            self._reader_registered = True
        except (NotImplementedError, OSError, ValueError):
            self._input_task = asyncio.create_task(self._read_input_loop())

    async def stop(self) -> None:
        self._running = False
        if self._reader_registered and self._loop is not None:
            with contextlib.suppress(Exception):
                self._loop.remove_reader(sys.stdin.fileno())
            self._reader_registered = False
        if self._input_task:
            self._input_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await asyncio.wait_for(self._input_task, timeout=0.2)
            self._input_task = None

    def render(self, lane: str, message: str, *, payload: dict[str, Any] | None = None) -> None:
        prefix = lane if lane.startswith("[") else f"[{lane}]"
        print(f"{prefix} {message}", flush=True)

    def status(self, message: str) -> None:
        self.render("SYSTEM", message)

    async def _read_input_loop(self) -> None:
        while self._running:
            try:
                text = await asyncio.to_thread(input, "")
            except EOFError:
                return
            await self.input_queue.put(UserCommand(text=text))

    def _on_stdin_ready(self) -> None:
        line = sys.stdin.readline()
        if line == "":
            return
        self.input_queue.put_nowait(UserCommand(text=line.rstrip("\n")))
