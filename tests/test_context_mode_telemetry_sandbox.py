from __future__ import annotations

from pathlib import Path

import pytest

from supervisor.context_mode.events import ClientRole
from supervisor.context_mode.approvals import OneShotCapabilityStore
from supervisor.context_mode._util import digest_json
from supervisor.context_mode.broker import (
    BrokerCore,
    BrokerError,
    BrokerReceiptJournal,
    SandboxExecutionAttestation,
    TerminalReplay,
)
from supervisor.context_mode.session import (
    BindingStore,
    ContextBinding,
    LifecycleSnapshot,
    StableBindingIdentity,
    TransitionReason,
)
from supervisor.context_mode.sandbox import (
    AUTHENTICATED_RUNNER_IDENTITY,
    BackendStatus,
    LINUX_REQUIRED_BACKEND_CHECKS,
    PROCESS_CONTROL_BACKEND_CHECKS,
    ProfileKind,
    SandboxBackendName,
    SandboxError,
    SandboxPathLayout,
    SandboxPolicy,
    authorize_sandbox_launch,
    build_clean_environment,
    detect_sandbox_backend,
    generate_sandbox_policies,
    verified_backend,
)
from supervisor.context_mode.telemetry import (
    AuthoritySeparatedCounters,
    MetricAuthority,
    ProviderThreadKey,
    ProviderTokenGaugeBook,
    TelemetryError,
    ThreadLifecycle,
)


LINUX_CHECKS = tuple(sorted(LINUX_REQUIRED_BACKEND_CHECKS))


def _generated_mcp_policy(
    tmp_path: Path,
    *,
    workspace: Path,
    environment: dict[str, str],
) -> SandboxPolicy:
    return generate_sandbox_policies(
        SandboxPathLayout(
            workspace=workspace,
            runtime=tmp_path / "runtime",
            state=tmp_path / "state",
            mcp_home=tmp_path / "home",
            mcp_temp=tmp_path / "tmp",
            hook_home=tmp_path / "hook-home",
            hook_temp=tmp_path / "hook-temp",
            command_home=tmp_path / "command-home",
            command_scratch=tmp_path / "command-scratch",
            launcher=tmp_path / "launcher",
            bootstrap=tmp_path / "bootstrap",
            proxy_bootstrap_files=(tmp_path / "bootstrap" / "mcp.json",),
            workspace_git=workspace / ".git",
            toolchain_roots=(tmp_path / "toolchain",),
            protected_roots=(tmp_path / "auth",),
        ),
        environment=environment,
    )[ProfileKind.MCP]


def test_sandbox_detection_is_not_sandbox_attestation(tmp_path: Path) -> None:
    detected = detect_sandbox_backend(system="linux", which=lambda _: "/usr/bin/bwrap")
    assert detected.status is BackendStatus.AVAILABLE_UNVERIFIED
    with pytest.raises(SandboxError):
        detected.assert_verified()

    backend = verified_backend(
        name=SandboxBackendName.LINUX_BWRAP_SECCOMP,
        executable="/usr/bin/bwrap",
        verification_id="native-preflight-1",
        completed_checks=LINUX_CHECKS,
    )
    environment = build_clean_environment(
        home=tmp_path / "home",
        temp=tmp_path / "tmp",
        context_mode_dir=tmp_path / "state",
        toolchain_bins=(tmp_path / "runtime" / "bin",),
        platform_tag="linux-x86_64",
        run_id="run",
        workspace_id="workspace",
        context_session_id="session",
    )
    assert environment["BELLO_OFFLINE"] == "1"
    assert "HTTP_PROXY" not in environment
    policy = _generated_mcp_policy(
        tmp_path,
        workspace=tmp_path / "workspace",
        environment=environment,
    )
    authorization = authorize_sandbox_launch(policy, backend)
    assert authorization.policy_digest == policy.digest
    assert authorization.authenticated_runner_identity == AUTHENTICATED_RUNNER_IDENTITY
    assert authorization.process_control_digest == policy.process_control.digest
    assert PROCESS_CONTROL_BACKEND_CHECKS.issubset(backend.checks)
    assert not policy.network_allowed and not policy.loopback_allowed


def test_context_counters_enforce_authority_and_idempotency() -> None:
    counters = AuthoritySeparatedCounters()
    assert counters.increment(
        "context_mode_calls_started",
        authority=MetricAuthority.CONTROLLER_OBSERVED,
        idempotency_key="logical-1",
    )
    assert not counters.increment(
        "context_mode_calls_started",
        authority=MetricAuthority.CONTROLLER_OBSERVED,
        idempotency_key="logical-1",
    )
    with pytest.raises(TelemetryError):
        counters.increment(
            "context_mode_operations_receipted",
            authority=MetricAuthority.CONTROLLER_OBSERVED,
            idempotency_key="operation-1",
        )
    counters.record_receipt_bytes(
        operation_id="operation-1",
        source_bytes=9,
        returned_bytes=5,
        indexed_bytes=100,
    )
    assert counters.value("context_mode_estimated_source_tokens") == 3
    assert counters.value("context_mode_indexed_bytes") == 100


def test_provider_usage_is_a_cumulative_gauge_not_notification_sum(tmp_path: Path) -> None:
    state_path = tmp_path / "provider-gauges.json"
    gauges = ProviderTokenGaugeBook(state_path)
    assert gauges.role_totals(ClientRole.CODER) == {
        "inputTokens": None,
        "cachedInputTokens": None,
        "outputTokens": None,
        "reasoningOutputTokens": None,
        "cacheWriteInputTokens": None,
        "totalTokens": None,
    }
    parent = ProviderThreadKey(ClientRole.CODER, "parent")
    gauges.register_thread(parent, lifecycle=ThreadLifecycle.CREATED)
    first = gauges.update(
        parent,
        {
            "total": {
                "inputTokens": 10,
                "cachedInputTokens": 4,
                "outputTokens": 5,
                "reasoningOutputTokens": 2,
                "totalTokens": 15,
            },
            "last": {"totalTokens": 15},
            "providerExtension": {"kept": True},
        },
    )
    assert first.adjusted_total_tokens == 15
    assert first.live_delta_tokens == 15
    repeated = gauges.update(parent, {"total": {**first.numeric_total_gauge}, "last": {"totalTokens": 15}})
    assert repeated.live_delta_tokens == 0
    increased = gauges.update(
        parent,
        {"total": {"inputTokens": 14, "cachedInputTokens": 6, "outputTokens": 8, "totalTokens": 22}},
    )
    assert increased.live_delta_tokens == 7
    reset = gauges.update(parent, {"total": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2}})
    assert reset.adjusted_total_tokens == 22
    assert set(reset.anomaly_fields) == {"inputTokens", "outputTokens", "totalTokens"}

    child = ProviderThreadKey(ClientRole.CODER, "child")
    gauges.register_thread(
        child,
        lifecycle=ThreadLifecycle.FORKED,
        parent=parent,
        first_snapshot_includes_parent=True,
    )
    child_update = gauges.update(
        child,
        {"total": {"inputTokens": 19, "outputTokens": 11, "totalTokens": 30}},
    )
    assert child_update.adjusted_total_tokens == 8
    assert child_update.live_delta_tokens == 8

    reloaded = ProviderTokenGaugeBook(state_path)
    reloaded.register_thread(parent, lifecycle=ThreadLifecycle.RESUMED)
    assert reloaded.adjusted_field(parent, "cachedInputTokens") == 6
    assert reloaded.anomaly_count == 1
    assert reloaded.raw_payloads(parent)[0]["providerExtension"] == {"kept": True}


def test_provider_gauge_rolls_back_failed_persistence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gauges = ProviderTokenGaugeBook(tmp_path / "provider-gauges.json")
    key = ProviderThreadKey(ClientRole.CODER, "thread")

    with monkeypatch.context() as scoped:
        scoped.setattr(gauges, "_persist", lambda: (_ for _ in ()).throw(OSError("disk full")))
        with pytest.raises(OSError, match="disk full"):
            gauges.register_thread(key, lifecycle=ThreadLifecycle.CREATED)

    gauges.register_thread(key, lifecycle=ThreadLifecycle.CREATED)
    with monkeypatch.context() as scoped:
        scoped.setattr(gauges, "_persist", lambda: (_ for _ in ()).throw(OSError("disk full")))
        with pytest.raises(OSError, match="disk full"):
            gauges.update(key, {"total": {"inputTokens": 5, "totalTokens": 5}})

    assert gauges.adjusted_field(key, "inputTokens") is None
    assert gauges.raw_payloads(key) == ()


def test_broker_retry_uses_durable_terminal_receipt_without_reexecution(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    environment = build_clean_environment(
        home=tmp_path / "home",
        temp=tmp_path / "tmp",
        context_mode_dir=tmp_path / "state",
        toolchain_bins=(tmp_path / "runtime" / "bin",),
        platform_tag="linux-x86_64",
        run_id="run",
        workspace_id="workspace",
        context_session_id="session",
    )
    policy = _generated_mcp_policy(
        tmp_path,
        workspace=workspace,
        environment=environment,
    )
    backend = verified_backend(
        name=SandboxBackendName.LINUX_BWRAP_SECCOMP,
        executable="/usr/bin/bwrap",
        verification_id="native-preflight-1",
        completed_checks=LINUX_CHECKS,
    )
    initial_binding = ContextBinding(
        StableBindingIdentity("run", "workspace", "session", str(workspace), "a" * 64),
        LifecycleSnapshot(1, 0, 1, "lease", 1, "app", policy.digest),
    )
    binding_store = BindingStore(tmp_path / "metadata" / "binding.json")
    binding_store.initialize(initial_binding)
    binding = binding_store.transition(
        expected_version=initial_binding.binding_version,
        reason=TransitionReason.THREAD_CLAIM,
        provider_thread_id="thread",
    )
    capabilities = OneShotCapabilityStore()
    request_key = {"role": "coder", "process_epoch": 1, "request_id": 8}
    logical_digest = digest_json(request_key)
    arguments = {"code": "local evaluator"}
    capability = capabilities.grant(
        binding=binding,
        process_epoch=1,
        tool_name="ctx_execute",
        arguments=arguments,
        cwd=workspace,
        request_key=request_key,
    )
    journal = BrokerReceiptJournal(tmp_path / "metadata" / "receipts.json")
    broker = BrokerCore(
        backend=backend,
        policy=policy,
        capability_store=capabilities,
        receipt_journal=journal,
        binding_store=binding_store,
    )
    call = broker.begin_call(
        binding=binding,
        process_epoch=1,
        mcp_request_id=8,
        logical_request_digest=logical_digest,
        tool_name="ctx_execute",
        arguments=arguments,
        cwd=workspace,
        capability_id=capability.capability_id,
    )
    assert not isinstance(call, TerminalReplay)
    terminal = broker.complete_call(
        call,
        SandboxExecutionAttestation(
            operation_id=call.operation_id,
            backend_verification_id="native-preflight-1",
            policy_digest=policy.digest,
            process_tree_reaped=True,
            result_digest="f" * 64,
            result_reference="spool-result-1",
            context_event_seq=1,
            duration_ms=3,
        ),
    )
    assert terminal.envelope.broker_receipt_digest == terminal.receipt.digest
    retry = broker.begin_call(
        binding=binding,
        process_epoch=1,
        mcp_request_id=8,
        logical_request_digest=logical_digest,
        tool_name="ctx_execute",
        arguments=arguments,
        cwd=workspace,
        capability_id=capability.capability_id,
    )
    assert isinstance(retry, TerminalReplay)
    assert retry.entry.result_reference == "spool-result-1"

    stale_call = broker.begin_call(
        binding=binding,
        process_epoch=1,
        mcp_request_id=9,
        logical_request_digest="9" * 64,
        tool_name="ctx_search",
        arguments={"query": "local"},
        cwd=workspace,
    )
    assert not isinstance(stale_call, TerminalReplay)
    binding_store.transition(
        expected_version=binding.binding_version,
        reason=TransitionReason.STATE_EPOCH_ROTATION,
        context_state_epoch=1,
    )
    with pytest.raises(BrokerError, match="epoch tainted"):
        broker.complete_call(
            stale_call,
            SandboxExecutionAttestation(
                operation_id=stale_call.operation_id,
                backend_verification_id="native-preflight-1",
                policy_digest=policy.digest,
                process_tree_reaped=True,
                result_digest="e" * 64,
                result_reference="stale-result",
                context_event_seq=2,
                duration_ms=1,
            ),
        )
    assert ("workspace", "session", 0) in broker.tainted_epochs
    with pytest.raises(BrokerError, match="stale or not controller-authoritative"):
        broker.begin_call(
            binding=binding,
            process_epoch=1,
            mcp_request_id=10,
            logical_request_digest="8" * 64,
            tool_name="ctx_search",
            arguments={"query": "stale"},
            cwd=workspace,
        )
