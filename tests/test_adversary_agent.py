from __future__ import annotations

import json
from pathlib import Path

from supervisor.adversary_agent import AdversaryAgent, _report_has_candidate_finding
from supervisor.schemas import SupervisorWakePacket, ValidationRun


def _packet(tmp_path: Path) -> SupervisorWakePacket:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\nHandle stack arguments.\n", encoding="utf-8")
    return SupervisorWakePacket(
        wake_sequence=11,
        latest_event_sequence=11,
        generation=0,
        restart_count=0,
        task_path=str(task),
        task_contents=task.read_text(encoding="utf-8"),
        current_summary="coder marked ready",
        latest_relevant_change_sequence=2,
        validations=[
            ValidationRun(
                command="pytest tests/test_app.py",
                exit_code=0,
                passed=True,
                summary="1 passed",
                captured_output="1 passed\n",
                executed_test_files=["tests/test_app.py"],
                sequence=3,
            )
        ],
    )


async def test_adversary_agent_uses_fresh_workspace_write_threads(tmp_path: Path) -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.thread_params = []
            self.turn_params = []
            self.archived = []

        async def thread_start(self, params, *, timeout):
            self.thread_params.append(params)
            return {"thread": {"id": f"adv-thread-{len(self.thread_params)}"}}

        async def turn_start(self, params, *, timeout):
            self.turn_params.append(params)
            turn_number = len(self.turn_params)
            return {
                "turn": {
                    "id": f"adv-turn-{turn_number}",
                    "status": "completed",
                    "items": [
                        {
                            "type": "agentMessage",
                            "text": f"attacked: stack args\nfindings: none\noverall: held {turn_number}",
                        }
                    ],
                }
            }

        async def thread_archive(self, thread_id, *, timeout):
            self.archived.append(thread_id)
            return {}

    client = FakeClient()
    started: list[str] = []
    done: list[str] = []
    agent = AdversaryAgent(
        client,  # type: ignore[arg-type]
        tmp_path,
        timeout_seconds=1,
        on_thread_start=started.append,
        on_thread_done=done.append,
    )

    first = await agent.run(_packet(tmp_path))
    second = await agent.run(_packet(tmp_path))

    assert first.thread_id == "adv-thread-1"
    assert second.thread_id == "adv-thread-2"
    assert started == ["adv-thread-1", "adv-thread-2"]
    assert done == ["adv-thread-1", "adv-thread-2"]
    assert client.archived == ["adv-thread-1", "adv-thread-2"]
    assert client.thread_params[0]["ephemeral"] is False
    assert client.thread_params[0]["persistExtendedHistory"] is False
    assert client.thread_params[0]["sandbox"] == "workspace-write"
    assert client.turn_params[0]["sandboxPolicy"] == {
        "type": "workspaceWrite",
        "writableRoots": [str(tmp_path.resolve())],
        "networkAccess": False,
    }
    prompt_payload = json.loads(client.turn_params[0]["input"][0]["text"])
    assert prompt_payload["task_contents"].startswith("# Task")
    assert "Web/network use is disabled" in prompt_payload["instructions"][1]
    assert "disposable snapshot" in prompt_payload["instructions"][1]
    assert "accepted_completion_review" not in prompt_payload
    assert first.candidate_finding is False


async def test_adversary_agent_reads_completed_report_from_turns_list(tmp_path: Path) -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.thread_params = []
            self.turns_list_calls: list[str] = []
            self.archived: list[str] = []

        async def thread_start(self, params, *, timeout):
            self.thread_params.append(params)
            return {"thread": {"id": "adv-thread"}}

        async def turn_start(self, params, *, timeout):
            return {"turn": {"id": "adv-turn", "status": "completed", "items": []}}

        async def thread_turns_list(self, thread_id, *, limit, items_view, timeout):
            self.turns_list_calls.append(thread_id)
            return {
                "data": [
                    {
                        "id": "adv-turn",
                        "items": [
                            {
                                "type": "agentMessage",
                                "text": "attacked: ephemeral-regression\nfindings: none\noverall: held",
                            }
                        ],
                    }
                ]
            }

        async def thread_archive(self, thread_id, *, timeout):
            self.archived.append(thread_id)
            return {}

    client = FakeClient()
    result = await AdversaryAgent(client, tmp_path, timeout_seconds=1).run(_packet(tmp_path))  # type: ignore[arg-type]

    assert result.thread_id == "adv-thread"
    assert result.turn_id == "adv-turn"
    assert result.report_text.endswith("overall: held")
    assert client.turns_list_calls == ["adv-thread"]
    assert client.archived == ["adv-thread"]
    assert client.thread_params[0]["ephemeral"] is False


async def test_adversary_agent_retries_once_after_no_message(tmp_path: Path) -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.thread_ids: list[str] = []
            self.archived: list[str] = []

        async def thread_start(self, params, *, timeout):
            thread_id = f"adv-thread-{len(self.thread_ids) + 1}"
            self.thread_ids.append(thread_id)
            return {"thread": {"id": thread_id}}

        async def turn_start(self, params, *, timeout):
            if params["threadId"] == "adv-thread-1":
                return {"turn": {"id": "adv-turn-1", "status": "completed", "items": []}}
            return {
                "turn": {
                    "id": "adv-turn-2",
                    "status": "completed",
                    "items": [{"type": "agentMessage", "text": "attacked: retry\nfindings: none\noverall: held"}],
                }
            }

        async def thread_turns_list(self, thread_id, *, limit, items_view, timeout):
            return {"data": [{"id": "adv-turn-1", "items": []}]}

        async def thread_archive(self, thread_id, *, timeout):
            self.archived.append(thread_id)
            return {}

    client = FakeClient()
    result = await AdversaryAgent(client, tmp_path, timeout_seconds=1).run(_packet(tmp_path))  # type: ignore[arg-type]

    assert result.thread_id == "adv-thread-2"
    assert "overall: held" in result.report_text
    assert client.thread_ids == ["adv-thread-1", "adv-thread-2"]
    assert client.archived == ["adv-thread-1", "adv-thread-2"]


def test_adversary_candidate_finding_parser_handles_multiline_findings() -> None:
    assert _report_has_candidate_finding("attacked: x\nfindings:\n- crash on input\noverall: broke")
    assert not _report_has_candidate_finding("attacked: x\nfindings:\n- none\nheld: x\noverall: held")
    assert not _report_has_candidate_finding("candidate_finding: false\nfindings:\n- crash-looking note")
