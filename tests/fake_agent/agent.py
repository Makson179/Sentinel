from __future__ import annotations

import asyncio
import os
from pathlib import Path

from supervisor.schemas import EventType
from tests.fake_agent.driver import FakeAgentHarness


async def main() -> None:
    harness = FakeAgentHarness(Path(os.environ["SUPERVISOR_IPC_SOCKET"]), os.environ["SUPERVISOR_IPC_TOKEN"])
    await harness.run_codex_exec_tool_call({"tool_name": "Bash", "command": "pwd"}, "fake-start")
    await harness.send_hook(EventType.STOP, {}, "fake-stop")


if __name__ == "__main__":
    asyncio.run(main())
