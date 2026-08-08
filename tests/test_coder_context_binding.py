from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from supervisor.coder import (
    MAX_CODER_RECOVERY_CONTEXT_BYTES,
    CoderBindingError,
    CoderContextBindingSnapshot,
    CoderLifecycleTransition,
    CoderRecoveryContext,
    CoderSession,
)
from supervisor.schemas import BelloConfig
from supervisor.context_mode.routing import (
    derive_context_index_source,
    render_context_mode_routing_text,
)
from supervisor.state import StateStore


def _binding(**updates: object) -> CoderContextBindingSnapshot:
    values: dict[str, object] = {
        "run_id": "run-1",
        "workspace_id": "workspace-1",
        "context_session_id": "session-1",
        "context_state_epoch": 2,
        "binding_version": 7,
        "coder_generation": 3,
        "generation_lease_id": "lease-generation-3",
        "coder_process_epoch": 4,
    }
    values.update(updates)
    return CoderContextBindingSnapshot(**values)  # type: ignore[arg-type]


def _store(tmp_path: Path, *, thread_id: str | None = "old-thread") -> tuple[StateStore, Path]:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_bello(
        BelloConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id=thread_id),
        overwrite=True,
    )
    return store, task


class _CoderClient:
    role = "coder"

    def __init__(self, *, process_epoch: int = 4) -> None:
        self.process_epoch = process_epoch
        self.events: list[tuple[str, object]] = []
        self._thread_number = 0

    async def turn_interrupt(self, thread_id: str, turn_id: str, *, timeout: float) -> None:
        self.events.append(("interrupt", (thread_id, turn_id)))

    async def thread_start(self, params: dict[str, object], *, timeout: float) -> dict[str, object]:
        self._thread_number += 1
        thread_id = f"new-thread-{self._thread_number}"
        self.events.append(("thread_start", params))
        return {"thread": {"id": thread_id}}

    async def thread_resume(self, params: dict[str, object], *, timeout: float) -> dict[str, object]:
        self.events.append(("thread_resume", params))
        return {"thread": {"id": params["threadId"]}}

    async def turn_start(self, params: dict[str, object], *, timeout: float) -> dict[str, object]:
        self.events.append(("turn_start", params))
        return {"turn": {"id": "new-turn"}}


async def test_coder_thread_start_reports_provider_thread_for_telemetry(tmp_path: Path) -> None:
    store, task = _store(tmp_path, thread_id=None)
    started_threads: list[str] = []
    session = CoderSession(
        _CoderClient(),  # type: ignore[arg-type]
        store,
        tmp_path,
        task,
        on_thread_start=started_threads.append,
    )

    assert await session.start_thread() == "new-thread-1"
    assert started_threads == ["new-thread-1"]


async def test_bound_coder_thread_gets_context_mode_before_first_turn(tmp_path: Path) -> None:
    store, task = _store(tmp_path, thread_id=None)
    client = _CoderClient()
    session = CoderSession(
        client,  # type: ignore[arg-type]
        store,
        tmp_path,
        task,
        context_binding=_binding(),
    )

    await session.start_thread()

    assert [name for name, _ in client.events] == ["thread_start"]
    params = client.events[0][1]
    assert isinstance(params, dict)
    source = derive_context_index_source(_binding().generation_lease_id)
    assert params["developerInstructions"] == render_context_mode_routing_text(source)
    assert source in params["developerInstructions"]
    assert params["config"] == {"bypass_hook_trust": True}


def test_context_mode_routing_states_search_limit_and_timeout_units() -> None:
    source = derive_context_index_source("routing-limit-generation")
    routing = render_context_mode_routing_text(source)

    assert "Every `ctx_search` `limit` must be an integer from `1` through `10`" in routing
    assert "never request a larger value such as `20`" in routing
    assert "`timeout` field on all execution tools is measured in milliseconds" in routing
    assert "120000 ms default" in routing
    assert "never second-like values such as `30`, `60`, or `120`" in routing
    assert "statement itself establishes the incomplete-Context boundary" in routing
    assert "do not refuse the native fallback as conflicting with this policy" in routing


def test_binding_snapshot_is_frozen_and_rejects_invalid_lifecycle_values() -> None:
    binding = _binding()

    with pytest.raises(FrozenInstanceError):
        binding.coder_generation = 9  # type: ignore[misc]
    with pytest.raises(CoderBindingError, match="binding_version"):
        _binding(binding_version=0)
    with pytest.raises(CoderBindingError, match="coder_process_epoch"):
        _binding(coder_process_epoch=True)


def test_recovery_context_is_canonical_and_bounded() -> None:
    context = CoderRecoveryContext.from_payload("checkpoint-1", {"z": 1, "a": "value"})

    assert context.payload_json == '{"a":"value","z":1}'
    assert context.to_dict()["checkpoint_id"] == "checkpoint-1"
    with pytest.raises(CoderBindingError, match="exceeds"):
        CoderRecoveryContext.from_payload(
            "checkpoint-large",
            {"summary": "x" * MAX_CODER_RECOVERY_CONTEXT_BYTES},
        )


async def test_generation_handoff_checkpoints_before_new_thread_and_rotates_only_generation(
    tmp_path: Path,
) -> None:
    store, task = _store(tmp_path)
    client = _CoderClient()
    current = _binding()
    next_binding = replace(
        current,
        binding_version=current.binding_version + 1,
        coder_generation=current.coder_generation + 1,
        generation_lease_id="lease-generation-4",
    )

    def checkpoint(request):
        client.events.append(("checkpoint", request))
        assert request.transition is CoderLifecycleTransition.LOGICAL_GENERATION_HANDOFF
        assert request.current_binding is current
        assert request.next_binding is next_binding
        return CoderRecoveryContext.from_payload(
            "checkpoint-generation",
            {"summary": "continue from the durable cursor", "context_event_seq": 18},
        )

    session = CoderSession(
        client,  # type: ignore[arg-type]
        store,
        tmp_path,
        task,
        thread_id="old-thread",
        active_turn_id="old-turn",
        context_binding=current,
        lifecycle_checkpoint=checkpoint,
    )

    thread_id = await session.handoff_generation(next_binding, reason="runtime supervisor restart")

    assert thread_id == "new-thread-1"
    assert session.binding_snapshot == next_binding
    assert next_binding.coder_process_epoch == current.coder_process_epoch
    assert [name for name, _ in client.events] == [
        "interrupt",
        "checkpoint",
        "thread_start",
        "turn_start",
    ]
    turn_params = client.events[-1][1]
    assert isinstance(turn_params, dict)
    prompt = turn_params["input"][0]["text"]  # type: ignore[index]
    envelope = json.loads(prompt.rsplit("\n", 1)[-1])
    assert envelope["binding"]["coder_generation"] == current.coder_generation + 1
    assert envelope["binding"]["coder_process_epoch"] == current.coder_process_epoch
    assert envelope["recovery"]["checkpoint_id"] == "checkpoint-generation"


async def test_transport_recovery_resumes_same_thread_without_generation_handoff(tmp_path: Path) -> None:
    store, task = _store(tmp_path)
    client = _CoderClient()
    current = _binding()
    next_binding = replace(
        current,
        binding_version=current.binding_version + 1,
        coder_process_epoch=current.coder_process_epoch + 1,
    )
    checkpoint = CoderRecoveryContext.from_payload(
        "checkpoint-process",
        {"context_event_seq": 19},
    )
    checkpoint_calls = 0

    async def write_checkpoint(request):
        nonlocal checkpoint_calls
        checkpoint_calls += 1
        assert request.transition is CoderLifecycleTransition.PROCESS_TRANSPORT_RECOVERY
        assert client.process_epoch == current.coder_process_epoch
        return checkpoint

    session = CoderSession(
        client,  # type: ignore[arg-type]
        store,
        tmp_path,
        task,
        thread_id="old-thread",
        active_turn_id="lost-turn",
        context_binding=current,
        lifecycle_checkpoint=write_checkpoint,
    )
    prepared = await session.checkpoint_lifecycle(
        next_binding,
        transition=CoderLifecycleTransition.PROCESS_TRANSPORT_RECOVERY,
        reason="checkpoint before transport restart",
    )
    client.process_epoch = next_binding.coder_process_epoch

    result = await session.recover_transport(
        next_binding,
        reason="crash recovery",
        recovery_context=prepared,
    )

    assert result.resumed is True
    assert result.thread_id == "old-thread"
    assert result.recovery_context is checkpoint
    assert session.binding_snapshot == next_binding
    assert next_binding.coder_generation == current.coder_generation
    assert next_binding.generation_lease_id == current.generation_lease_id
    assert session.active_turn_id is None
    assert checkpoint_calls == 1
    assert [name for name, _ in client.events] == ["thread_resume"]
    resume_params = client.events[0][1]
    assert isinstance(resume_params, dict)
    assert resume_params["threadId"] == "old-thread"
    source = derive_context_index_source(next_binding.generation_lease_id)
    assert resume_params["developerInstructions"] == render_context_mode_routing_text(source)
    with pytest.raises(FrozenInstanceError):
        result.resumed = False  # type: ignore[misc]


async def test_transport_new_thread_fallback_requires_explicit_recovery_turn(tmp_path: Path) -> None:
    store, task = _store(tmp_path)
    client = _CoderClient()
    current = _binding()
    next_binding = replace(
        current,
        binding_version=current.binding_version + 1,
        coder_process_epoch=current.coder_process_epoch + 1,
    )
    checkpoint = CoderRecoveryContext.from_payload("checkpoint-fallback", {"summary": "resume work"})
    session = CoderSession(
        client,  # type: ignore[arg-type]
        store,
        tmp_path,
        task,
        thread_id="old-thread",
        context_binding=current,
    )
    client.process_epoch = next_binding.coder_process_epoch

    result = await session.recover_transport(
        next_binding,
        reason="provider no longer has the old thread",
        resume_thread=False,
        recovery_context=checkpoint,
    )

    assert result.resumed is False
    assert result.thread_id == "new-thread-1"
    assert [name for name, _ in client.events] == ["thread_start"]
    await session.start_recovery_turn(result.recovery_context, reason="provider recovery fallback")
    assert [name for name, _ in client.events] == ["thread_start", "turn_start"]


@pytest.mark.parametrize(
    "operation_name, candidate, message",
    [
        (
            "handoff",
            _binding(binding_version=8, coder_generation=4, generation_lease_id="new", coder_process_epoch=5),
            "must not change coder_process_epoch",
        ),
        (
            "recover",
            _binding(binding_version=8, coder_process_epoch=5, coder_generation=4),
            "must not change coder_generation",
        ),
        (
            "recover",
            _binding(binding_version=9, coder_process_epoch=5),
            "binding_version",
        ),
        (
            "recover",
            _binding(binding_version=8, coder_process_epoch=5, context_state_epoch=3),
            "stable Context Mode fields",
        ),
    ],
)
async def test_lifecycle_paths_reject_mixed_or_non_adjacent_transitions_before_checkpoint(
    tmp_path: Path,
    operation_name: str,
    candidate: CoderContextBindingSnapshot,
    message: str,
) -> None:
    store, task = _store(tmp_path)
    client = _CoderClient()
    checkpoint_called = False

    def checkpoint(_request):
        nonlocal checkpoint_called
        checkpoint_called = True
        return CoderRecoveryContext("should-not-run")

    session = CoderSession(
        client,  # type: ignore[arg-type]
        store,
        tmp_path,
        task,
        thread_id="old-thread",
        context_binding=_binding(),
        lifecycle_checkpoint=checkpoint,
    )

    operation = session.handoff_generation if operation_name == "handoff" else session.recover_transport
    with pytest.raises(CoderBindingError, match=message):
        await operation(candidate, reason="invalid mixed transition")
    assert checkpoint_called is False
    assert client.events == []


def test_bound_session_rejects_supervisor_role_client(tmp_path: Path) -> None:
    store, task = _store(tmp_path)
    client = _CoderClient()
    client.role = "supervisor"

    with pytest.raises(CoderBindingError, match="coder-role"):
        CoderSession(
            client,  # type: ignore[arg-type]
            store,
            tmp_path,
            task,
            context_binding=_binding(),
        )
