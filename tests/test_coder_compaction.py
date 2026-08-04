from __future__ import annotations

import asyncio
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

from supervisor.appserver import AppServerClient, AppServerMessage, ClientRole
from supervisor.coder import CoderSession
from supervisor.context_mode.session import CheckpointRecoveryKind
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
