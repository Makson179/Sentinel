from __future__ import annotations

import asyncio
import json
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

from supervisor.appserver import AppServerClient, AppServerError, AppServerMessage, ClientRole
from supervisor.coder import CoderSession
from supervisor.context_mode.config import REQUIRED_HOOKS, generate_coder_home
from supervisor.context_mode.session import CheckpointRecoveryKind
from supervisor.context_mode.startup import ContextModeStartupError
from supervisor.controller import BelloController


class _Store:
    def __init__(self) -> None:
        self.metrics: dict[str, object] = {}
        self.logs: list[dict[str, object]] = []

    def update_runtime_metrics(self, patch):
        self.metrics = patch(dict(self.metrics))

    def append_raw_log(self, value):
        self.logs.append(value)

    def update_bello_config(self, patch):
        return None


@pytest.mark.asyncio
async def test_appserver_compaction_rpc_uses_pinned_method() -> None:
    client = AppServerClient(command=["codex"], role=ClientRole.CODER)
    calls: list[tuple[str, dict[str, object] | None, float]] = []

    async def request(method, params=None, *, timeout):
        calls.append((method, params, timeout))
        return {}

    client.request = request  # type: ignore[method-assign]
    await client.thread_compact_start("thread-1", timeout=17.0)
    assert calls == [("thread/compact/start", {"threadId": "thread-1"}, 17.0)]


@pytest.mark.asyncio
async def test_appserver_hooks_list_uses_pinned_method(tmp_path: Path) -> None:
    client = AppServerClient(command=["codex"], role=ClientRole.CODER)
    calls: list[tuple[str, dict[str, object] | None, float]] = []

    async def request(method, params=None, *, timeout):
        calls.append((method, params, timeout))
        return {"data": []}

    client.request = request  # type: ignore[method-assign]
    assert await client.hooks_list([tmp_path], timeout=17.0) == {"data": []}
    assert calls == [("hooks/list", {"cwds": [str(tmp_path)]}, 17.0)]


@pytest.mark.asyncio
async def test_context_hook_preflight_matches_codex_0146_inventory(tmp_path: Path) -> None:
    workspace = (tmp_path / "workspace").resolve()
    workspace.mkdir()
    generated = generate_coder_home(
        tmp_path / "coder-home",
        launcher_path=Path("/bin/true"),
        mcp_bootstrap_path=tmp_path / "mcp.json",
        workspace=workspace,
        hook_bootstraps={event: tmp_path / f"{event}.json" for event in REQUIRED_HOOKS},
    )
    manifest = json.loads((generated.root / "hooks.json").read_text(encoding="utf-8"))
    event_labels = {
        "PreToolUse": "preToolUse",
        "PostToolUse": "postToolUse",
        "SessionStart": "sessionStart",
        "PreCompact": "preCompact",
        "UserPromptSubmit": "userPromptSubmit",
        "Stop": "stop",
    }
    source_path = str((generated.root / "hooks.json").resolve())
    hooks: list[dict[str, object]] = []
    for event in REQUIRED_HOOKS:
        for group in manifest["hooks"][event]:
            for handler in group["hooks"]:
                hooks.append(
                    {
                        "eventName": event_labels[event],
                        "handlerType": "command",
                        "matcher": group.get("matcher"),
                        "command": handler["command"],
                        "sourcePath": source_path,
                        "source": "user",
                        "pluginId": None,
                        "isManaged": False,
                        "enabled": True,
                        "trustStatus": "untrusted",
                    }
                )
    response = {
        "data": [
            {
                "cwd": str(workspace),
                "hooks": hooks,
                "warnings": [],
                "errors": [],
            }
        ]
    }
    client = AppServerClient(
        command=["codex"],
        role=ClientRole.CODER,
        codex_home=generated.root,
    )

    async def hooks_list(cwds, *, timeout=30.0):
        assert cwds == [workspace]
        return response

    client.hooks_list = hooks_list  # type: ignore[method-assign]
    controller = object.__new__(BelloController)
    controller.project_root = workspace
    controller.workspace_root = workspace
    controller.coder_client = client

    await controller._preflight_discovered_coder_hooks()
    hooks[0]["eventName"] = "pre_tool_use"
    with pytest.raises(ContextModeStartupError, match="catalogue mismatch"):
        await controller._preflight_discovered_coder_hooks()


@pytest.mark.asyncio
async def test_coder_steer_race_starts_fresh_turn(tmp_path: Path) -> None:
    class Client:
        def __init__(self) -> None:
            self.steered: list[tuple[str, str, str]] = []
            self.started: list[dict[str, object]] = []

        async def turn_steer(self, thread_id, turn_id, message, *, timeout):
            self.steered.append((thread_id, turn_id, message))
            raise AppServerError("{'code': -32600, 'message': 'no active turn to steer'}")

        async def turn_start(self, params, *, timeout):
            self.started.append(params)
            return {"turn": {"id": "fresh-turn"}}

    client = Client()
    coder = CoderSession(
        client,  # type: ignore[arg-type]
        _Store(),  # type: ignore[arg-type]
        tmp_path,
        tmp_path / "TASK.md",
        thread_id="thread-1",
        active_turn_id="stale-turn",
    )

    assert await coder.steer_or_start("continue") == "fresh-turn"
    assert client.steered == [("thread-1", "stale-turn", "continue")]
    assert len(client.started) == 1
    assert client.started[0]["threadId"] == "thread-1"
    assert coder.active_turn_id == "fresh-turn"


@pytest.mark.asyncio
async def test_coder_compaction_registers_waiter_before_rpc(tmp_path: Path) -> None:
    terminal = AppServerMessage(
        {
            "method": "item/completed",
            "params": {
                "threadId": "thread-1",
                "turnId": "compact-turn",
                "item": {"id": "compact-item", "type": "contextCompaction"},
            },
        },
        role=ClientRole.CODER,
    )
    terminal_turn = AppServerMessage(
        {
            "method": "turn/completed",
            "params": {
                "threadId": "thread-1",
                "turnId": "compact-turn",
                "turn": {"id": "compact-turn", "status": "completed"},
            },
        },
        role=ClientRole.CODER,
    )

    class Client:
        role = ClientRole.CODER
        process_epoch = 0

        def __init__(self) -> None:
            self.waiters_registered = 0
            self.all_waiters_registered = asyncio.Event()
            self.rpc_called = False

        async def wait_for_notification(self, predicate, *, timeout):
            selected = terminal if predicate(terminal) else terminal_turn
            assert predicate(selected)
            self.waiters_registered += 1
            if self.waiters_registered == 2:
                self.all_waiters_registered.set()
            while not self.rpc_called:
                await asyncio.sleep(0)
            return selected

        async def thread_compact_start(self, thread_id, *, timeout):
            assert self.all_waiters_registered.is_set()
            assert thread_id == "thread-1"
            self.rpc_called = True
            return {}

    client = Client()
    coder = CoderSession(
        client,  # type: ignore[arg-type]
        _Store(),  # type: ignore[arg-type]
        tmp_path,
        tmp_path / "task.md",
        thread_id="thread-1",
    )
    assert await coder.compact_thread() == terminal


@pytest.mark.asyncio
async def test_coder_compaction_barrier_waits_for_matching_completed_turn(tmp_path: Path) -> None:
    terminal = AppServerMessage(
        {
            "method": "turn/completed",
            "params": {
                "threadId": "thread-1",
                "turnId": "barrier-turn",
                "turn": {"id": "barrier-turn", "status": "completed"},
            },
        },
        role=ClientRole.CODER,
    )

    class Client:
        role = ClientRole.CODER
        process_epoch = 0

        def __init__(self) -> None:
            self.waiter_registered = asyncio.Event()
            self.rpc_called = False
            self.started: list[dict[str, object]] = []

        async def wait_for_notification(self, predicate, *, timeout):
            assert predicate(terminal)
            self.waiter_registered.set()
            while not self.rpc_called:
                await asyncio.sleep(0)
            return terminal

        async def turn_start(self, params, *, timeout):
            assert self.waiter_registered.is_set()
            self.started.append(params)
            self.rpc_called = True
            return {"turn": {"id": "barrier-turn"}}

    client = Client()
    coder = CoderSession(
        client,  # type: ignore[arg-type]
        _Store(),  # type: ignore[arg-type]
        tmp_path,
        tmp_path / "task.md",
        thread_id="thread-1",
    )

    assert await coder.run_compaction_recovery_barrier("barrier") == terminal
    assert client.started[0]["threadId"] == "thread-1"
    assert coder.active_turn_id is None


@pytest.mark.asyncio
async def test_barrier_terminal_is_not_treated_as_a_coder_work_turn() -> None:
    class Store(_Store):
        def get_bello_config(self):
            return SimpleNamespace(coder_thread_id="thread-1")

    class Coder:
        def __init__(self) -> None:
            self.completed: list[str] = []

        def mark_turn_completed(self, turn_id):
            self.completed.append(turn_id)

    controller = object.__new__(BelloController)
    controller.store = Store()  # type: ignore[assignment]
    controller.coder = Coder()  # type: ignore[assignment]
    controller.pending_approvals = {}
    controller._terminal_cleanup_started = False
    controller._coder_context_compaction_interrupt_turn_id = None
    controller._coder_context_compaction_turn_ids = {"barrier-turn"}
    controller._append_event = lambda *args, **kwargs: None  # type: ignore[method-assign]

    async def unexpected_work_turn(*, item_id):
        raise AssertionError("barrier terminal reached normal coder completion handling")

    controller._handle_coder_turn_completed = unexpected_work_turn  # type: ignore[method-assign]
    await controller.handle_notification(
        AppServerMessage(
            {
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "barrier-turn",
                    "turn": {"id": "barrier-turn", "status": "completed"},
                },
            },
            role=ClientRole.CODER,
        )
    )

    assert controller.coder.completed == ["barrier-turn"]
    assert controller._coder_context_compaction_turn_ids == set()
    assert controller.store.logs[-1]["type"] == "coder_context_compaction_turn_completed"


def _policy_controller() -> BelloController:
    controller = object.__new__(BelloController)
    controller.store = _Store()  # type: ignore[assignment]
    controller._coder_context_thread_id = "thread-1"
    controller._coder_context_input_tokens = None
    controller._coder_context_compaction_baseline_tokens = None
    controller._coder_context_compactions_completed = 0
    controller._coder_context_awaiting_post_compaction_sample = False
    controller._coder_context_compaction_pending = False
    controller._coder_context_compaction_in_progress = False
    controller._coder_context_compaction_turn_ids = set()
    return controller


def test_compaction_policy_uses_effective_input_and_post_compaction_growth() -> None:
    controller = _policy_controller()
    controller._record_coder_context_token_sample(
        thread_id="thread-1",
        turn_id="turn-1",
        token_usage={"last": {"inputTokens": 119_999}},
    )
    assert not controller._coder_context_compaction_pending

    controller._record_coder_context_token_sample(
        thread_id="thread-1",
        turn_id="turn-1",
        token_usage={"last": {"inputTokens": 120_000}},
    )
    assert controller._coder_context_compaction_pending

    controller._coder_context_compactions_completed = 1
    controller._coder_context_compaction_pending = False
    controller._coder_context_awaiting_post_compaction_sample = True
    controller._coder_context_compaction_turn_ids = {"compact-turn"}
    controller._record_coder_context_token_sample(
        thread_id="thread-1",
        turn_id="compact-turn",
        token_usage={"last": {"inputTokens": 140_000}},
    )
    assert controller._coder_context_awaiting_post_compaction_sample
    assert controller._coder_context_compaction_baseline_tokens is None

    controller._record_coder_context_token_sample(
        thread_id="thread-1",
        turn_id="turn-2",
        token_usage={"last": {"inputTokens": 80_000}},
    )
    assert controller._coder_context_compaction_baseline_tokens == 80_000
    assert not controller._coder_context_compaction_pending

    controller._record_coder_context_token_sample(
        thread_id="thread-1",
        turn_id="turn-3",
        token_usage={"last": {"inputTokens": 139_999}},
    )
    assert not controller._coder_context_compaction_pending
    assert controller.store.metrics["coder_context_growth_tokens"] == 59_999

    controller._record_coder_context_token_sample(
        thread_id="thread-1",
        turn_id="turn-3",
        token_usage={"last": {"inputTokens": 140_000}},
    )
    assert controller._coder_context_compaction_pending
    assert controller.store.metrics["coder_context_growth_tokens"] == 60_000


@pytest.mark.asyncio
async def test_compaction_precompact_checkpoint_precedes_rpc_and_verified_recovery() -> None:
    controller = _policy_controller()
    controller.running = True
    controller.paused = False
    controller._terminal_cleanup_started = False
    controller._coder_context_input_tokens = 120_000
    controller._coder_context_compaction_pending = True
    controller.pending_approvals = {}
    controller._coder_transition_lock = asyncio.Lock()
    controller.tui = SimpleNamespace(render=lambda *args: None)
    calls: list[object] = []

    class Coordinator:
        def mark_failed(self):
            calls.append("failed")

    class Runtime:
        coordinator = Coordinator()

        async def quiesce(self, *, timeout_seconds):
            calls.append(("quiesce", timeout_seconds))

    class Coder:
        thread_id = "thread-1"
        active_turn_id = None

        async def compact_thread(self):
            calls.append("compact")
            return AppServerMessage(
                {
                    "method": "item/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "compact-turn",
                        "item": {"id": "compact-item", "type": "contextCompaction"},
                    },
                }
            )

        async def run_compaction_recovery_barrier(self, message):
            calls.append(("barrier", message))
            return AppServerMessage(
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "barrier-turn",
                        "turn": {"id": "barrier-turn", "status": "completed"},
                    },
                }
            )

    async def checkpoint(**kwargs):
        calls.append(("checkpoint", kwargs))
        return SimpleNamespace(checkpoint_id="checkpoint-1")

    async def recover(**kwargs):
        calls.append(("recover", kwargs))

    controller.context_runtime = Runtime()  # type: ignore[assignment]
    controller.coder = Coder()  # type: ignore[assignment]
    controller._checkpoint_context_runtime = checkpoint  # type: ignore[method-assign]
    controller._recover_context_checkpoint = recover  # type: ignore[method-assign]

    assert await controller._maybe_compact_coder_context()
    assert calls == [
        ("quiesce", 30.0),
        (
            "checkpoint",
            {
                "reason": "PreCompact",
                "transition": "compaction",
                "recovery_kind": CheckpointRecoveryKind.COMPACTION,
            },
        ),
        "compact",
        (
            "barrier",
            "Bello internal compaction recovery barrier. Do not perform task work.",
        ),
        (
            "recover",
            {
                "checkpoint_id": "checkpoint-1",
                "recovery_kind": CheckpointRecoveryKind.COMPACTION,
            },
        ),
    ]
    assert controller._coder_context_compactions_completed == 1
    assert controller._coder_context_awaiting_post_compaction_sample
    assert "compact-turn" in controller._coder_context_compaction_turn_ids
    assert "barrier-turn" in controller._coder_context_compaction_turn_ids


@pytest.mark.asyncio
async def test_threshold_interrupts_a_long_active_coder_turn_before_compaction() -> None:
    controller = _policy_controller()
    controller.running = True
    controller.paused = False
    controller._terminal_cleanup_started = False
    controller._coder_context_input_tokens = 120_000
    controller._coder_context_compaction_pending = True
    controller._coder_context_compaction_interrupt_turn_id = None
    controller.pending_approvals = {}
    controller._coder_transition_lock = asyncio.Lock()
    controller.tui = SimpleNamespace(render=lambda *args: None)

    class Coder:
        thread_id = "thread-1"
        active_turn_id = "long-turn"

        def __init__(self) -> None:
            self.interrupts = 0

        async def interrupt(self):
            self.interrupts += 1

    coder = Coder()
    controller.context_runtime = SimpleNamespace()  # type: ignore[assignment]
    controller.coder = coder  # type: ignore[assignment]

    assert not await controller._maybe_compact_coder_context()
    assert coder.interrupts == 1
    assert controller._coder_context_compaction_interrupt_turn_id == "long-turn"
    assert controller._coder_context_compaction_pending

    # Replayed token samples for the same provider turn must not send another
    # interrupt while the terminal turn notification is still pending.
    assert not await controller._maybe_compact_coder_context()
    assert coder.interrupts == 1


@pytest.mark.asyncio
async def test_threshold_does_not_interrupt_turn_after_readiness_marker() -> None:
    controller = _policy_controller()
    controller.running = True
    controller.paused = False
    controller._terminal_cleanup_started = False
    controller._coder_context_input_tokens = 120_000
    controller._coder_context_compaction_pending = True
    controller._coder_context_compaction_interrupt_turn_id = None
    controller._coder_readiness_marker_turn_id = "ready-turn"
    controller.pending_approvals = {}
    controller._coder_transition_lock = asyncio.Lock()
    controller.tui = SimpleNamespace(render=lambda *args: None)

    class Coder:
        thread_id = "thread-1"
        active_turn_id = "ready-turn"

        def __init__(self) -> None:
            self.interrupts = 0

        async def interrupt(self):
            self.interrupts += 1

    coder = Coder()
    controller.context_runtime = SimpleNamespace()  # type: ignore[assignment]
    controller.coder = coder  # type: ignore[assignment]

    assert not await controller._maybe_compact_coder_context()
    assert coder.interrupts == 0
    assert controller._coder_context_compaction_interrupt_turn_id is None
    assert controller._coder_context_compaction_pending


def test_native_precompact_hook_commits_before_sessionstart_recovery(tmp_path: Path) -> None:
    broker_module = runpy.run_path(
        str(
            Path(__file__).parents[1]
            / "release"
            / "context_mode_authority"
            / "bin"
            / "bello-context-broker"
        )
    )
    NativeBroker = broker_module["NativeBroker"]
    BrokerError = broker_module["BrokerError"]
    broker = NativeBroker()
    broker.run_root = tmp_path
    broker.quiesced = True
    broker.binding = {
        "schema_version": 1,
        "stable": {
            "run_id": "run-1",
            "workspace_id": "workspace-1",
            "context_session_id": "session-1",
            "workspace_path": str(tmp_path),
            "base_config_digest": "a" * 64,
        },
        "lifecycle": {
            "binding_version": 2,
            "context_state_epoch": 0,
            "coder_generation": 0,
            "generation_lease_id": "lease-1",
            "coder_process_epoch": 0,
            "app_server_instance_id": "app-1",
            "sandbox_policy_digest": "b" * 64,
            "provider_thread_id": "thread-1",
        },
    }
    controller_checkpoint = broker.rpc_checkpoint(
        {
            "binding": broker.binding,
            "reason": "PreCompact",
            "transition": "compaction",
        }
    )

    broker.process_hook_event("PreCompact", {"trigger": "manual"})
    pending = broker.pending_precompact
    assert pending is not None
    hook_cursor = pending["checkpoint"]["cursor"]
    assert hook_cursor["reason"] == "PreCompact"
    assert (tmp_path / "runtime-metadata" / "native-broker-state.json").is_file()

    controller_recovery = {
        "cursor": controller_checkpoint["cursor"],
        "checkpoint_binding": broker.binding,
        "binding": broker.binding,
        "recovery_kind": "compaction",
    }
    with pytest.raises(BrokerError, match="observed SessionStart"):
        broker.rpc_recover(controller_recovery)

    broker.process_hook_event("SessionStart", {"source": "compact"})
    assert broker.pending_precompact is None
    assert hook_cursor["checkpoint_id"] in broker.recovered_checkpoints
    acknowledgement = broker.rpc_recover(controller_recovery)
    assert acknowledgement["session_start_verified"] is True
    assert broker.compaction_session_start["controller_checkpoint_id"] == controller_checkpoint["cursor"]["checkpoint_id"]

    with pytest.raises(BrokerError, match="already claimed"):
        broker.rpc_recover(controller_recovery)
