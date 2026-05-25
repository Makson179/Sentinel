from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

import pytest

from supervisor.llm_driver import LLMDriver, LLMDriverError, ParseFailure
from supervisor.schemas import DecisionType, EventType, HealthDelta, HookEvent, IPCRequest, LLMDecision, PermissionDecisionKind, RunConfig
from supervisor.health import patch_health
from supervisor.state import DECISIONS, HANDOFF, LAST_ACTION, PROGRESS
from supervisor.wrapper import SupervisorWrapper
from tests.fake_agent.driver import FakeAgentHarness


class StubDriver(LLMDriver):
    def __init__(self, decisions=None, *, delay: float = 0.0, error: Exception | None = None):
        self.decisions = list(decisions or [])
        self.delay = delay
        self.error = error
        self.calls = 0

    async def decide(self, prompt: str, timeout_seconds: float | None = None) -> LLMDecision:
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        if not self.decisions:
            return LLMDecision(decision_type=DecisionType.NOOP, reason="fine")
        item = self.decisions.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def make_wrapper(workspace: Path, driver: LLMDriver, timeout: float = 1.0) -> SupervisorWrapper:
    config = RunConfig(platform="fake", plan_file_path=str(workspace / "TASK.md"), hook_timeout_seconds=timeout)
    runtime_parent = Path.cwd() / ".test-runtime"
    runtime_parent.mkdir(exist_ok=True)
    wrapper = SupervisorWrapper(workspace, config, llm_driver=driver, runtime_parent=runtime_parent)
    wrapper.initialize_state(overwrite=True)
    return wrapper


def make_codex_wrapper(workspace: Path) -> SupervisorWrapper:
    config = RunConfig(platform="codex", plan_file_path=str(workspace / "TASK.md"))
    runtime_parent = workspace / "runtime"
    runtime_parent.mkdir()
    wrapper = SupervisorWrapper(workspace, config, llm_driver=StubDriver(), runtime_parent=runtime_parent)
    wrapper.initialize_state(overwrite=True)
    return wrapper


def test_codex_exec_command_uses_configured_sandbox_and_logs(workspace: Path) -> None:
    wrapper = make_codex_wrapper(workspace)

    command = wrapper.default_supervisee_command()

    assert command[:7] == [
        "codex",
        "exec",
        "--skip-git-repo-check",
        "--dangerously-bypass-hook-trust",
        "--json",
        "--sandbox",
        "danger-full-access",
    ]


def test_codex_exec_command_honors_sandbox_env(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SUPERVISOR_CODEX_SANDBOX", "workspace-write")
    wrapper = make_codex_wrapper(workspace)

    command = wrapper.default_supervisee_command()

    assert command[command.index("--sandbox") + 1] == "workspace-write"


def test_codex_launch_routes_process_output_to_logs(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    wrapper = make_codex_wrapper(workspace)
    stdout_path = wrapper.store.path("codex-stdout.log")
    stderr_path = wrapper.store.path("codex-stderr.log")
    trace_path = wrapper.store.path("codex-hook-trace.log")
    stdout_path.write_text("stale", encoding="utf-8")
    stderr_path.write_text("stale", encoding="utf-8")
    trace_path.write_text("stale", encoding="utf-8")
    captured: dict[str, object] = {}

    def fake_launch_process(command, cwd, env=None, stdout_path=None, stderr_path=None):
        captured["command"] = command
        captured["cwd"] = cwd
        captured["env"] = env
        captured["stdout_path"] = stdout_path
        captured["stderr_path"] = stderr_path
        return object()

    monkeypatch.setattr("supervisor.wrapper.launch_process", fake_launch_process)

    wrapper.launch_supervisee()

    assert captured["stdout_path"] == stdout_path
    assert captured["stderr_path"] == stderr_path
    assert captured["env"]["SUPERVISOR_HOOK_TRACE_PATH"] == str(trace_path)
    assert captured["env"]["SUPERVISOR_HOOK_TIMEOUT"] == str(wrapper.config.hook_timeout_seconds)
    assert stdout_path.read_text(encoding="utf-8") == ""
    assert stderr_path.read_text(encoding="utf-8") == ""
    assert trace_path.read_text(encoding="utf-8") == ""


def test_codex_restart_uses_default_handoff_command(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    wrapper = make_codex_wrapper(workspace)
    captured: dict[str, object] = {}

    def fake_launch_process(command, cwd, env=None, stdout_path=None, stderr_path=None):
        captured["command"] = command
        captured["cwd"] = cwd
        captured["env"] = env
        captured["stdout_path"] = stdout_path
        captured["stderr_path"] = stderr_path
        return object()

    monkeypatch.setattr("supervisor.wrapper.launch_process", fake_launch_process)

    wrapper.apply_kill_restart("handoff for next generation")

    command = captured["command"]
    assert command[:7] == [
        "codex",
        "exec",
        "--skip-git-repo-check",
        "--dangerously-bypass-hook-trust",
        "--json",
        "--sandbox",
        "danger-full-access",
    ]
    assert ".supervisor/DECISIONS.md" in command[-1]
    assert ".supervisor/HANDOFF.md" in command[-1]
    assert captured["stdout_path"] == wrapper.store.path("codex-stdout.log")
    assert captured["stderr_path"] == wrapper.store.path("codex-stderr.log")


@pytest.mark.asyncio
async def test_timeout_fallback_path(workspace: Path) -> None:
    wrapper = make_wrapper(workspace, StubDriver(delay=0.3), timeout=0.1)
    response = await wrapper.handle_event(HookEvent(event_type=EventType.PERMISSION_REQUEST, payload={"command": "make deploy"}, generation=0), 1)
    assert response.decision_type == DecisionType.DENY
    health = wrapper.store.get_health()
    assert health.timeout_fallback_count == 1
    assert health.denied_requests == 1
    assert health.last_denial == "TimeoutError"


@pytest.mark.asyncio
async def test_llm_driver_error_deny_updates_health(workspace: Path) -> None:
    wrapper = make_wrapper(workspace, StubDriver(error=LLMDriverError("schema path failed")))
    event = HookEvent(event_type=EventType.PRE_TOOL_USE, payload={"tool_name": "Bash", "command": "python -c 'open(\"hello.py\", \"w\").write(\"hi\")'"}, generation=0)

    response = await wrapper.handle_event(event, 1)

    health = wrapper.store.get_health()
    assert response.decision_type == DecisionType.DENY
    assert health.denied_requests == 1
    assert health.last_denial == "schema path failed"


@pytest.mark.asyncio
async def test_stale_llm_response_discard(workspace: Path) -> None:
    wrapper = make_wrapper(workspace, StubDriver())
    decision = LLMDecision(decision_type=DecisionType.INTERVENE, intervention="stale", generation=99)
    response = wrapper.apply_llm_decision(HookEvent(event_type=EventType.POST_TOOL_USE, generation=0), decision, 1)
    assert response.decision_type == DecisionType.NOOP
    assert "stale" in response.payload["reason"]


@pytest.mark.asyncio
async def test_parse_failure_repair_then_success(workspace: Path) -> None:
    wrapper = make_wrapper(
        workspace,
        StubDriver([ParseFailure("bad json"), LLMDecision(decision_type=DecisionType.ALLOW, reason="repaired")]),
    )
    response = await wrapper.handle_event(HookEvent(event_type=EventType.PERMISSION_REQUEST, payload={"command": "make test"}, generation=0), 1)
    assert response.decision_type == DecisionType.ALLOW
    assert wrapper.llm_driver.calls == 2


@pytest.mark.asyncio
async def test_pre_tool_use_gray_zone_calls_llm_inline(workspace: Path) -> None:
    wrapper = make_wrapper(workspace, StubDriver([LLMDecision(decision_type=DecisionType.ALLOW, reason="safe workspace write")]))
    event = HookEvent(event_type=EventType.PRE_TOOL_USE, payload={"tool_name": "Bash", "command": "python -c 'open(\"hello.py\", \"w\").write(\"hi\")'"}, generation=0)

    response = await wrapper.handle_event(event, 1)

    assert response.decision_type == DecisionType.ALLOW
    assert wrapper.llm_driver.calls == 1


@pytest.mark.asyncio
async def test_permission_hooks_deny_non_actionable_llm_decision(workspace: Path) -> None:
    wrapper = make_wrapper(workspace, StubDriver([LLMDecision(decision_type=DecisionType.NOOP, reason="defer")]))
    event = HookEvent(event_type=EventType.PRE_TOOL_USE, payload={"tool_name": "Bash", "command": "python -c 'open(\"hello.py\", \"w\").write(\"hi\")'"}, generation=0)

    response = await wrapper.handle_event(event, 1)

    assert response.decision_type == DecisionType.DENY
    assert "requires an allow/deny decision" in response.payload["reason"]
    assert wrapper.store.get_health().denied_requests == 1


@pytest.mark.asyncio
async def test_fake_harness_models_codex_exec_without_permission_fallback(workspace: Path) -> None:
    wrapper = make_wrapper(
        workspace,
        StubDriver(
            [
                LLMDecision(decision_type=DecisionType.ALLOW, reason="safe"),
            ]
        ),
    )
    await wrapper.start_ipc()
    try:
        harness = FakeAgentHarness(wrapper.socket_path, wrapper.auth_token)
        responses = await harness.run_codex_exec_tool_call(
            {"tool_name": "Bash", "command": "python -c 'open(\"hello.py\", \"w\").write(\"hi\")'"},
            "codex-exec",
            requires_approval=False,
        )
    finally:
        await wrapper.stop_ipc()

    assert [response.decision_type for response in responses] == [DecisionType.ALLOW, DecisionType.NOOP]
    assert wrapper.llm_driver.calls == 1


@pytest.mark.asyncio
async def test_allow_class_creates_session_rule_for_later_fast_path(workspace: Path) -> None:
    command = "python -c 'open(\"hello.py\", \"w\").write(\"hi\")'"
    wrapper = make_wrapper(
        workspace,
        StubDriver(
            [
                LLMDecision(
                    decision_type=DecisionType.ALLOW,
                    permission_kind=PermissionDecisionKind.ALLOW_CLASS,
                    reason="safe repeated workspace write",
                    allow_rule={"tool_name": "Bash", "command": command},
                )
            ]
        ),
    )
    event = HookEvent(event_type=EventType.PRE_TOOL_USE, payload={"tool_name": "Bash", "command": command}, generation=0)

    first = await wrapper.handle_event(event, 1)
    second = await wrapper.handle_event(event, 2)

    assert first.decision_type == DecisionType.ALLOW
    assert second.decision_type == DecisionType.ALLOW
    assert second.payload["reason"] == "session allow rule matched"
    assert wrapper.llm_driver.calls == 1


@pytest.mark.asyncio
async def test_llm_decision_updates_persistent_state(workspace: Path) -> None:
    wrapper = make_wrapper(workspace, StubDriver())
    decision = LLMDecision(
        decision_type=DecisionType.NOOP,
        reason="state updated",
        decision_entry="Keep API compatibility.",
        completed_step="Added wrapper tests.",
        last_action="Ran pytest.",
        risk_signals=["bypass_after_denial"],
    )

    response = wrapper.apply_llm_decision(HookEvent(event_type=EventType.TIMER, generation=0), decision, 7)

    assert response.decision_type == DecisionType.NOOP
    assert "Keep API compatibility." in wrapper.store.read_text(DECISIONS)
    assert "Added wrapper tests." in wrapper.store.read_text(PROGRESS)
    assert wrapper.store.read_text(LAST_ACTION) == "Ran pytest.\n"
    health = wrapper.store.get_health()
    assert health.last_progress_sequence == 7
    assert health.risk_signals == ["bypass_after_denial"]


@pytest.mark.asyncio
async def test_observation_hooks_noop_without_llm_when_no_pending_intervention(workspace: Path) -> None:
    wrapper = make_wrapper(workspace, StubDriver([LLMDecision(decision_type=DecisionType.INTERVENE, reason="not needed")]))

    response = await wrapper.handle_event(HookEvent(event_type=EventType.POST_TOOL_USE, payload={}, generation=0), 1)

    assert response.decision_type == DecisionType.NOOP
    assert response.payload["reason"] == "observation hook no-op"
    assert wrapper.llm_driver.calls == 0


@pytest.mark.asyncio
async def test_timer_pending_intervention_and_later_delivery(workspace: Path) -> None:
    wrapper = make_wrapper(workspace, StubDriver([LLMDecision(decision_type=DecisionType.INTERVENE, intervention="Use the plan order.")]))
    timer_event = HookEvent(event_type=EventType.TIMER, payload={}, generation=0)
    timer_response = await wrapper.handle_event(timer_event, 1)
    assert timer_response.payload["pending_intervention"] is True
    delivery = await wrapper.handle_event(HookEvent(event_type=EventType.POST_TOOL_USE, payload={}, generation=0), 2)
    assert delivery.deferred_intervention_attached
    assert delivery.payload["additionalContext"] == "Use the plan order."


@pytest.mark.asyncio
async def test_kill_restart_generation_reset(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    wrapper = make_wrapper(workspace, StubDriver())
    relaunches: list[bool] = []
    monkeypatch.setattr(wrapper, "launch_supervisee", lambda restart=False: relaunches.append(restart))
    patch_health(wrapper.store, HealthDelta(generation=0, interventions=2, denied_requests=1))
    wrapper.apply_kill_restart("handoff")
    health = wrapper.store.get_health()
    assert health.generation == 1
    assert health.restart_count == 1
    assert health.denied_requests == 0
    assert wrapper.store.path(HANDOFF).read_text(encoding="utf-8") == "handoff"
    assert relaunches == [True]


@pytest.mark.asyncio
async def test_provider_failure_clean_exit_with_handoff(workspace: Path) -> None:
    wrapper = make_wrapper(workspace, StubDriver(error=LLMDriverError("provider down")))
    response = await wrapper.handle_event(HookEvent(event_type=EventType.TIMER, payload={}, generation=0), 1)
    assert response.decision_type == DecisionType.NOOP
    assert "provider failure" in wrapper.termination_reason
    assert "provider down" in wrapper.store.path(HANDOFF).read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_restart_cap_final_report_without_llm(workspace: Path) -> None:
    driver = StubDriver()
    wrapper = make_wrapper(workspace, driver)
    patch_health(wrapper.store, HealthDelta(generation=0, restart_count=3))
    response = await wrapper.timer_tick(1)
    assert response.decision_type == DecisionType.KEEP_ALIVE
    assert driver.calls == 0
    assert "restart cap" in wrapper.final_report()


@pytest.mark.asyncio
async def test_ipc_parallel_hook_callbacks(workspace: Path) -> None:
    wrapper = make_wrapper(workspace, StubDriver())
    await wrapper.start_ipc()
    try:
        harness = FakeAgentHarness(wrapper.socket_path, wrapper.auth_token)
        responses = await harness.send_parallel(10, EventType.PERMISSION_REQUEST, {"tool_name": "Read", "path": "TASK.md"})
    finally:
        await wrapper.stop_ipc()
    assert len({response.sequence for response in responses}) == 10
    assert all(response.decision_type == DecisionType.ALLOW for response in responses)


def send_raw_ipc(socket_path: Path, payload: bytes) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10.0)
        client.connect(str(socket_path))
        client.sendall(payload + b"\n")
        chunks: list[bytes] = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
    return json.loads(b"".join(chunks).split(b"\n", 1)[0].decode("utf-8"))


@pytest.mark.asyncio
async def test_ipc_malformed_json_denies_without_crashing_server(workspace: Path) -> None:
    wrapper = make_wrapper(workspace, StubDriver())
    await wrapper.start_ipc()
    try:
        response = await asyncio.to_thread(send_raw_ipc, wrapper.socket_path, b"{bad")
        harness = FakeAgentHarness(wrapper.socket_path, wrapper.auth_token)
        followup = await harness.send_hook(EventType.PERMISSION_REQUEST, {"tool_name": "Read", "path": "TASK.md"}, "after-bad-json")
    finally:
        await wrapper.stop_ipc()

    assert response["decision_type"] == DecisionType.DENY.value
    assert "IPC failure" in response["payload"]["reason"]
    assert followup.decision_type == DecisionType.ALLOW


@pytest.mark.asyncio
async def test_codex_prepare_installs_hooks_directly(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    events: list[object] = []

    class FakeCodexAdapter:
        last_self_test_error = None
        last_trust_sync_error = None

        def __init__(self, store, hook_timeout_seconds):
            self.store = store
            events.append(("timeout", hook_timeout_seconds))

        def recover_stale_hooks(self) -> None:
            events.append("recover")

        def install(self) -> None:
            events.append("install")

        async def sync_supervisor_hook_trust(self) -> bool:
            events.append("trust-sync")
            return True

        async def hook_fire_self_test(self, ipc_socket_path, auth_token) -> bool:
            events.append(("hook-fire", ipc_socket_path is not None, bool(auth_token)))
            return True

        async def supervisor_isolation_self_test(self) -> bool:
            events.append("isolation")
            return True

        def cleanup(self) -> None:
            events.append("cleanup")

    def fail_input() -> str:
        raise AssertionError("Codex startup must not prompt for hook trust")

    monkeypatch.setattr("supervisor.wrapper.CodexAdapter", FakeCodexAdapter)
    monkeypatch.setattr("builtins.input", fail_input)
    wrapper = make_codex_wrapper(workspace)

    await wrapper.prepare_platform()

    assert events == [
        ("timeout", wrapper.config.hook_timeout_seconds),
        "recover",
        "install",
        "trust-sync",
        ("hook-fire", True, True),
        "isolation",
    ]
    assert capsys.readouterr().out == ""


@pytest.mark.asyncio
async def test_ipc_auth_failure_denies(workspace: Path) -> None:
    wrapper = make_wrapper(workspace, StubDriver())
    await wrapper.start_ipc()
    try:
        harness = FakeAgentHarness(wrapper.socket_path, "wrong")
        response = await harness.send_hook(EventType.PERMISSION_REQUEST, {"tool_name": "Read", "path": "TASK.md"}, "bad-auth")
    finally:
        await wrapper.stop_ipc()
    assert response.decision_type == DecisionType.DENY
