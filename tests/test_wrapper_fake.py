from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from supervisor.llm_driver import LLMDriver, LLMDriverError, ParseFailure
from supervisor.schemas import DecisionType, EventType, HealthDelta, HookEvent, IPCRequest, LLMDecision, RunConfig
from supervisor.health import patch_health
from supervisor.state import HANDOFF
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


def test_codex_exec_command_uses_workspace_sandbox_and_logs(workspace: Path) -> None:
    wrapper = make_codex_wrapper(workspace)

    command = wrapper.default_supervisee_command()

    assert command[:8] == [
        "codex",
        "exec",
        "--skip-git-repo-check",
        "-c",
        'web_search="disabled"',
        "--json",
        "--sandbox",
        "workspace-write",
    ]


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
    assert stdout_path.read_text(encoding="utf-8") == ""
    assert stderr_path.read_text(encoding="utf-8") == ""
    assert trace_path.read_text(encoding="utf-8") == ""


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
async def test_kill_restart_generation_reset(workspace: Path) -> None:
    wrapper = make_wrapper(workspace, StubDriver())
    patch_health(wrapper.store, HealthDelta(generation=0, interventions=2, denied_requests=1))
    wrapper.apply_kill_restart("handoff")
    health = wrapper.store.get_health()
    assert health.generation == 1
    assert health.restart_count == 1
    assert health.denied_requests == 0
    assert wrapper.store.path(HANDOFF).read_text(encoding="utf-8") == "handoff"


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


@pytest.mark.asyncio
async def test_codex_prepare_skips_trust_prompt_when_hooks_already_trusted(workspace: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    events: list[object] = []

    class FakeCodexAdapter:
        last_self_test_error = None

        def __init__(self, store):
            self.store = store

        def recover_stale_hooks(self) -> None:
            events.append("recover")

        def planned_supervisor_hooks(self) -> list[str]:
            events.append("planned")
            return ["planned-hook"]

        def supervisor_hooks_trusted(self, planned_hooks) -> bool:
            events.append(("trusted", planned_hooks))
            return True

        def install(self) -> None:
            events.append("install")

        async def hook_fire_self_test(self, ipc_socket_path, auth_token) -> bool:
            events.append(("hook-fire", ipc_socket_path is not None, bool(auth_token)))
            return True

        async def supervisor_isolation_self_test(self) -> bool:
            events.append("isolation")
            return True

        def cleanup(self) -> None:
            events.append("cleanup")

    def fail_input() -> str:
        raise AssertionError("trusted Codex startup must not prompt")

    monkeypatch.setattr("supervisor.wrapper.CodexAdapter", FakeCodexAdapter)
    monkeypatch.setattr("builtins.input", fail_input)
    wrapper = make_codex_wrapper(workspace)

    await wrapper.prepare_platform()

    assert events == [
        "recover",
        "planned",
        ("trusted", ["planned-hook"]),
        "install",
        ("hook-fire", True, True),
        "isolation",
    ]
    assert capsys.readouterr().out == ""


@pytest.mark.asyncio
async def test_codex_prepare_guides_first_run_trust_setup(workspace: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    events: list[object] = []

    class FakeCodexAdapter:
        last_self_test_error = None

        def __init__(self, store):
            self.store = store

        def recover_stale_hooks(self) -> None:
            events.append("recover")

        def planned_supervisor_hooks(self) -> list[str]:
            events.append("planned")
            return ["planned-hook"]

        def supervisor_hooks_trusted(self, planned_hooks) -> bool:
            events.append(("trusted", planned_hooks))
            return False

        def install(self) -> None:
            events.append("install")

        async def trust_preflight(self, planned_hooks, ipc_socket_path, auth_token) -> bool:
            events.append(("trust-preflight", planned_hooks, ipc_socket_path is not None, bool(auth_token)))
            return True

        async def hook_fire_self_test(self, ipc_socket_path, auth_token) -> bool:
            events.append(("hook-fire", ipc_socket_path is not None, bool(auth_token)))
            return True

        async def supervisor_isolation_self_test(self) -> bool:
            events.append("isolation")
            return True

        def cleanup(self) -> None:
            events.append("cleanup")

    monkeypatch.setattr("supervisor.wrapper.CodexAdapter", FakeCodexAdapter)
    monkeypatch.setattr("builtins.input", lambda: "y")
    wrapper = make_codex_wrapper(workspace)

    await wrapper.prepare_platform()

    assert events == [
        "recover",
        "planned",
        ("trusted", ["planned-hook"]),
        "install",
        ("trust-preflight", ["planned-hook"], True, True),
        ("hook-fire", True, True),
        "isolation",
    ]
    output = capsys.readouterr().out
    assert "one-time trust setup" in output
    assert "Opening Codex hook review now" in output
    assert "You do not need to type anything" in output


@pytest.mark.asyncio
async def test_codex_prepare_cancelled_trust_setup_does_not_install(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[object] = []

    class FakeCodexAdapter:
        def __init__(self, store):
            self.store = store

        def recover_stale_hooks(self) -> None:
            events.append("recover")

        def planned_supervisor_hooks(self) -> list[str]:
            events.append("planned")
            return ["planned-hook"]

        def supervisor_hooks_trusted(self, planned_hooks) -> bool:
            events.append(("trusted", planned_hooks))
            return False

        def install(self) -> None:
            events.append("install")

    monkeypatch.setattr("supervisor.wrapper.CodexAdapter", FakeCodexAdapter)
    monkeypatch.setattr("builtins.input", lambda: "n")
    wrapper = make_codex_wrapper(workspace)

    with pytest.raises(RuntimeError, match="cancelled"):
        await wrapper.prepare_platform()

    assert events == ["recover", "planned", ("trusted", ["planned-hook"])]


@pytest.mark.asyncio
async def test_codex_prepare_incomplete_trust_setup_preserves_installed_hooks(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[object] = []

    class FakeCodexAdapter:
        last_self_test_error = None

        def __init__(self, store):
            self.store = store

        def recover_stale_hooks(self) -> None:
            events.append("recover")

        def planned_supervisor_hooks(self) -> list[str]:
            events.append("planned")
            return ["planned-hook"]

        def supervisor_hooks_trusted(self, planned_hooks) -> bool:
            events.append(("trusted", planned_hooks))
            return False

        def install(self) -> None:
            events.append("install")

        async def trust_preflight(self, planned_hooks, ipc_socket_path, auth_token) -> bool:
            events.append("trust-preflight")
            return False

        def cleanup(self) -> None:
            events.append("cleanup")

    monkeypatch.setattr("supervisor.wrapper.CodexAdapter", FakeCodexAdapter)
    monkeypatch.setattr("builtins.input", lambda: "y")
    wrapper = make_codex_wrapper(workspace)

    with pytest.raises(RuntimeError, match="left installed"):
        await wrapper.prepare_platform()
    wrapper.cleanup_platform()

    assert events == ["recover", "planned", ("trusted", ["planned-hook"]), "install", "trust-preflight"]


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
