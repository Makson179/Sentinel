from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from supervisor.adversary_agent import AdversaryAgent, AdversaryAgentError, _report_has_candidate_finding
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
                            "text": (
                                "candidate_finding: false\n"
                                f"attacked: stack args\nfindings: none\nobservations: none\n"
                                f"not_reached: none\noverall: held {turn_number}"
                            ),
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
        model="gpt-adversary",
        intelligence="ultra",
        timeout_seconds=1,
        on_thread_start=started.append,
        on_thread_done=done.append,
    )

    first = await agent.run(_packet(tmp_path))
    previous_report = "candidate_finding: false\nfindings: none\nobservations: none"
    second = await agent.run(
        _packet(tmp_path), previous_adversary_report=previous_report
    )

    assert first.thread_id == "adv-thread-1"
    assert second.thread_id == "adv-thread-2"
    assert started == ["adv-thread-1", "adv-thread-2"]
    assert done == ["adv-thread-1", "adv-thread-2"]
    assert client.archived == ["adv-thread-1", "adv-thread-2"]
    assert client.thread_params[0]["ephemeral"] is False
    assert client.thread_params[0]["persistExtendedHistory"] is False
    assert client.thread_params[0]["sandbox"] == "workspace-write"
    assert client.thread_params[0]["model"] == "gpt-adversary"
    assert "effort" not in client.thread_params[0]
    assert client.thread_params[0]["config"] == {
        "apps": {"_default": {"enabled": False}},
        "include_apps_instructions": False,
    }
    assert client.thread_params[0]["dynamicTools"] == []
    assert client.thread_params[0]["environments"] == []
    assert client.turn_params[0]["model"] == "gpt-adversary"
    assert client.turn_params[0]["effort"] == "ultra"
    assert client.turn_params[0]["sandboxPolicy"] == {
        "type": "workspaceWrite",
        "writableRoots": [str(tmp_path.resolve())],
        "networkAccess": False,
    }
    prompt_payload = json.loads(client.turn_params[0]["input"][0]["text"])
    assert prompt_payload["task_contents"].startswith("# Task")
    assert set(prompt_payload) == {
        "instructions",
        "task_contents",
        "previous_adversary_report",
    }
    assert str(tmp_path.resolve()) not in json.dumps(prompt_payload)
    assert "task_path" not in prompt_payload
    assert "current_workspace_summary" not in prompt_payload
    assert "diff_summary" not in prompt_payload
    assert "changed_files" not in prompt_payload
    assert "validation_freshness_summary" not in prompt_payload
    second_prompt_payload = json.loads(client.turn_params[1]["input"][0]["text"])
    assert second_prompt_payload["previous_adversary_report"] == previous_report
    assert set(second_prompt_payload) == set(prompt_payload)
    assert "judged against the task" in prompt_payload["instructions"][1]
    assert "only when the task itself requires that access" in prompt_payload["instructions"][1]
    assert "disposable snapshot" in prompt_payload["instructions"][1]
    assert "accepted_completion_review" not in prompt_payload
    assert first.candidate_finding is False


def test_adversary_thread_disables_configured_mcp_plugins_and_apps(tmp_path: Path) -> None:
    agent = AdversaryAgent(
        object(),  # type: ignore[arg-type]
        tmp_path,
        configured_mcp_server_names=["openaiDeveloperDocs", " node_repl ", "openaiDeveloperDocs"],
        configured_plugin_names=["sites@openai-bundled", "browser@openai-bundled"],
    )

    params = agent._thread_params()

    assert params["config"] == {
        "apps": {"_default": {"enabled": False}},
        "include_apps_instructions": False,
        "mcp_servers": {
            "node_repl": {"enabled": False},
            "openaiDeveloperDocs": {"enabled": False},
        },
        "plugins": {
            "browser@openai-bundled": {"enabled": False},
            "sites@openai-bundled": {"enabled": False},
        },
    }
    assert params["dynamicTools"] == []
    assert params["environments"] == []


def test_adversary_thread_can_skip_apps_override_without_enabling_app_instructions(tmp_path: Path) -> None:
    agent = AdversaryAgent(
        object(),  # type: ignore[arg-type]
        tmp_path,
        disable_apps=False,
    )

    params = agent._thread_params()

    assert params["config"] == {"include_apps_instructions": False}
    assert "apps" not in params["config"]


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
                                "text": (
                                    "candidate_finding: false\n"
                                    "attacked: ephemeral-regression\nfindings: none\n"
                                    "observations: none\nnot_reached: none\noverall: held"
                                ),
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
                    "items": [
                        {
                            "type": "agentMessage",
                            "text": (
                                "candidate_finding: false\nattacked: retry\nfindings: none\n"
                                "observations: none\nnot_reached: none\noverall: held"
                            ),
                        }
                    ],
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


async def test_adversary_agent_retry_carries_denied_probes_note(tmp_path: Path) -> None:
    # A denial can abort the whole turn before the agent records not_reached; the retry
    # must tell the fresh thread what was refused so it does not replay the same request.
    class FakeClient:
        def __init__(self) -> None:
            self.thread_ids: list[str] = []
            self.prompts: list[str] = []

        async def thread_start(self, params, *, timeout):
            thread_id = f"adv-thread-{len(self.thread_ids) + 1}"
            self.thread_ids.append(thread_id)
            return {"thread": {"id": thread_id}}

        async def turn_start(self, params, *, timeout):
            self.prompts.append(params["input"][0]["text"])
            if params["threadId"] == "adv-thread-1":
                return {"turn": {"id": "adv-turn-1", "status": "completed", "items": []}}
            return {
                "turn": {
                    "id": "adv-turn-2",
                    "status": "completed",
                    "items": [
                        {
                            "type": "agentMessage",
                            "text": (
                                "candidate_finding: false\nattacked: retry\nfindings: none\n"
                                "observations: none\nnot_reached: none\noverall: held"
                            ),
                        }
                    ],
                }
            }

        async def thread_turns_list(self, thread_id, *, limit, items_view, timeout):
            return {"data": [{"id": "adv-turn-1", "items": []}]}

        async def thread_archive(self, thread_id, *, timeout):
            return {}

    client = FakeClient()
    denied = ["some-host-binary --flag file.html (denied: needs supervisor judgment)"]
    result = await AdversaryAgent(
        client,  # type: ignore[arg-type]
        tmp_path,
        timeout_seconds=1,
        denied_probes=lambda: list(denied),
    ).run(_packet(tmp_path))

    assert result.thread_id == "adv-thread-2"
    assert "Retry note" not in client.prompts[0]
    assert "some-host-binary --flag file.html" in client.prompts[1]
    assert "record them under not_reached" in client.prompts[1]


async def test_adversary_agent_retries_failed_turn_instead_of_accepting_progress_message(tmp_path: Path) -> None:
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
                return {"turn": {"id": "adv-turn-1", "status": "inProgress", "items": []}}
            return {
                "turn": {
                    "id": "adv-turn-2",
                    "status": "completed",
                    "items": [
                        {
                            "type": "agentMessage",
                            "text": (
                                "candidate_finding: false\nattacked: retry\nfindings: none\n"
                                "observations: none\nnot_reached: none\noverall: held"
                            ),
                        }
                    ],
                }
            }

        async def wait_for_notification(self, predicate, *, timeout):
            notification = SimpleNamespace(
                method="turn/completed",
                params={
                    "threadId": "adv-thread-1",
                    "turn": {
                        "id": "adv-turn-1",
                        "status": "failed",
                        "error": {
                            "message": "upstream response failed",
                            "codexErrorInfo": "internalServerError",
                        },
                        "items": [
                            {
                                "type": "agentMessage",
                                "text": "I am replaying the previous findings before probing new behavior.",
                            }
                        ],
                    },
                },
            )
            assert predicate(notification)
            return notification

        async def thread_archive(self, thread_id, *, timeout):
            self.archived.append(thread_id)
            return {}

    client = FakeClient()
    result = await AdversaryAgent(client, tmp_path, timeout_seconds=1).run(_packet(tmp_path))  # type: ignore[arg-type]

    assert result.thread_id == "adv-thread-2"
    assert result.candidate_finding is False
    assert client.thread_ids == ["adv-thread-1", "adv-thread-2"]
    assert client.archived == ["adv-thread-1", "adv-thread-2"]


async def test_adversary_agent_retries_incomplete_completed_report(tmp_path: Path) -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.thread_ids: list[str] = []

        async def thread_start(self, params, *, timeout):
            thread_id = f"adv-thread-{len(self.thread_ids) + 1}"
            self.thread_ids.append(thread_id)
            return {"thread": {"id": thread_id}}

        async def turn_start(self, params, *, timeout):
            if params["threadId"] == "adv-thread-1":
                return {
                    "turn": {
                        "id": "adv-turn-1",
                        "status": "completed",
                        "items": [
                            {
                                "type": "agentMessage",
                                "text": (
                                    "candidate_finding: false\n"
                                    "attacked: parser\n"
                                    "findings: none\n"
                                    "observations: none\n"
                                    "overall: held"
                                ),
                            }
                        ],
                    }
                }
            return {
                "turn": {
                    "id": "adv-turn-2",
                    "status": "completed",
                    "items": [
                        {
                            "type": "agentMessage",
                            "text": (
                                "candidate_finding: true\nattacked: parser\n"
                                "findings: malformed input accepted\nobservations: none\n"
                                "not_reached: none\noverall: defects remain"
                            ),
                        }
                    ],
                }
            }

        async def thread_archive(self, thread_id, *, timeout):
            return {}

    result = await AdversaryAgent(FakeClient(), tmp_path, timeout_seconds=1).run(  # type: ignore[arg-type]
        _packet(tmp_path)
    )

    assert result.thread_id == "adv-thread-2"
    assert result.candidate_finding is True


async def test_adversary_agent_surfaces_failed_turn_after_bounded_retry(tmp_path: Path) -> None:
    class FakeClient:
        def __init__(self) -> None:
            self.thread_count = 0

        async def thread_start(self, params, *, timeout):
            self.thread_count += 1
            return {"thread": {"id": f"adv-thread-{self.thread_count}"}}

        async def turn_start(self, params, *, timeout):
            return {
                "turn": {
                    "id": f"adv-turn-{self.thread_count}",
                    "status": "failed",
                    "error": {"message": "provider overloaded", "codexErrorInfo": "serverOverloaded"},
                    "items": [{"type": "agentMessage", "text": "Starting the audit now."}],
                }
            }

        async def thread_archive(self, thread_id, *, timeout):
            return {}

    client = FakeClient()
    with pytest.raises(AdversaryAgentError, match="status='failed'.*provider overloaded"):
        await AdversaryAgent(client, tmp_path, timeout_seconds=1).run(_packet(tmp_path))  # type: ignore[arg-type]

    assert client.thread_count == 2


def test_adversary_candidate_finding_parser_handles_multiline_findings() -> None:
    assert _report_has_candidate_finding("attacked: x\nfindings:\n- crash on input\noverall: broke")
    assert not _report_has_candidate_finding("attacked: x\nfindings:\n- none\nheld: x\noverall: held")
    assert not _report_has_candidate_finding("candidate_finding: false\nfindings:\n- crash-looking note")
