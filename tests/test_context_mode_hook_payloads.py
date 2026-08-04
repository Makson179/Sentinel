from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from supervisor.context_mode.hook_payloads import (
    HOOK_PAYLOAD_CONTRACT_DIGEST,
    HookInvocationReplayGuard,
    HookPayloadError,
    HookPayloadReplayError,
    validate_hook_payload,
)
from supervisor.context_mode.session import (
    ContextBinding,
    LifecycleSnapshot,
    StableBindingIdentity,
    TransitionReason,
)


AUTHORITY_KEY = b"hook-payload-test-authority-key!!"


def _binding(workspace: Path) -> ContextBinding:
    return ContextBinding(
        StableBindingIdentity(
            run_id="run-1",
            workspace_id="workspace-1",
            context_session_id="session-1",
            workspace_path=os.fspath(workspace),
            base_config_digest="a" * 64,
        ),
        LifecycleSnapshot(
            binding_version=1,
            context_state_epoch=0,
            coder_generation=1,
            generation_lease_id="lease-1",
            coder_process_epoch=1,
            app_server_instance_id="app-1",
            sandbox_policy_digest="b" * 64,
            provider_thread_id=None,
        ),
    )


def _payload(binding: ContextBinding, event: str, **fields: object) -> dict[str, object]:
    return {
        "hook_event_name": event,
        "session_id": binding.stable.context_session_id,
        "cwd": binding.stable.workspace_path,
        **fields,
    }


@pytest.mark.parametrize(
    ("event", "fields"),
    (
        ("PreToolUse", {"tool_name": "ctx_search", "tool_input": {"query": "x"}, "tool_use_id": "t1"}),
        (
            "PostToolUse",
            {
                "tool_name": "ctx_search",
                "tool_input": {"query": "x"},
                "tool_use_id": "t1",
                "tool_response": {"matches": 1},
            },
        ),
        ("SessionStart", {"source": "recovery"}),
        ("PreCompact", {"trigger": "auto", "custom_instructions": "retain decisions"}),
        ("UserPromptSubmit", {"prompt": "continue"}),
        ("Stop", {"stop_hook_active": True, "last_assistant_message": "done"}),
    ),
)
def test_all_six_hook_schemas_normalize_to_bounded_visible_data(
    tmp_path: Path,
    event: str,
    fields: dict[str, object],
) -> None:
    binding = _binding(tmp_path)
    normalized = validate_hook_payload(
        event=event,
        raw=_payload(binding, event, **fields),
        binding=binding,
        authority_key=AUTHORITY_KEY,
    )

    assert normalized.event == event
    assert normalized.visible["event"] == event
    assert normalized.visible_bytes <= 32 * 1024
    assert normalized.visible_sha256
    assert "session_id" not in normalized.visible
    assert "cwd" not in normalized.visible


def test_hook_secrets_unknown_fields_and_transcript_are_redacted_out_of_band(
    tmp_path: Path,
) -> None:
    binding = _binding(tmp_path)
    raw = _payload(
        binding,
        "UserPromptSubmit",
        prompt="Authorization: Bearer verysecretcredential",
        transcript_path="/must/not/be/read",
        ambient_secret="sk-abcdefghijklmnopqrstuvwxyz",
    )
    normalized = validate_hook_payload(
        event="UserPromptSubmit",
        raw=raw,
        binding=binding,
        authority_key=AUTHORITY_KEY,
        transcript_excerpt="token=topsecret github_pat_abcdefghijklmnopqrstuvwxyz",
    )
    encoded = json.dumps(normalized.visible, sort_keys=True)

    assert "verysecretcredential" not in encoded
    assert "/must/not/be/read" not in encoded
    assert "ambient_secret" not in encoded
    assert normalized.unknown_fields_removed == 1
    assert normalized.redacted_transcript is not None
    assert "topsecret" not in normalized.redacted_transcript
    assert "github_pat_" not in normalized.redacted_transcript
    assert normalized.redacted_or_truncated is True


def test_hook_payload_rejects_duplicate_fields_oversize_and_stale_binding(tmp_path: Path) -> None:
    binding = _binding(tmp_path)
    duplicate = (
        b'{"hook_event_name":"Stop","hook_event_name":"Stop",'
        b'"session_id":"session-1","cwd":"'
        + os.fspath(tmp_path).encode()
        + b'","stop_hook_active":true}'
    )
    with pytest.raises(HookPayloadError, match="duplicate field"):
        validate_hook_payload(
            event="Stop",
            raw=duplicate,
            binding=binding,
            authority_key=AUTHORITY_KEY,
        )
    with pytest.raises(HookPayloadError, match="256 KiB"):
        validate_hook_payload(
            event="UserPromptSubmit",
            raw=b"{" + b"x" * (256 * 1024),
            binding=binding,
            authority_key=AUTHORITY_KEY,
        )
    mismatched = _payload(binding, "Stop", stop_hook_active=True)
    mismatched["session_id"] = "other-session"
    with pytest.raises(HookPayloadError, match="active binding"):
        validate_hook_payload(
            event="Stop",
            raw=mismatched,
            binding=binding,
            authority_key=AUTHORITY_KEY,
        )


def test_hook_claims_are_one_shot_binding_bound_and_expire_fail_closed(tmp_path: Path) -> None:
    now = [100.0]
    binding = _binding(tmp_path)
    normalized = validate_hook_payload(
        event="Stop",
        raw=_payload(binding, "Stop", stop_hook_active=True),
        binding=binding,
        authority_key=AUTHORITY_KEY,
    )
    guard = HookInvocationReplayGuard(AUTHORITY_KEY, clock=lambda: now[0])
    receipt = guard.issue(
        invocation_id="invocation-1",
        claim_token="claim-1",
        request_id=7,
        normalized=normalized,
        binding=binding,
        hook_policy_digest="c" * 64,
    )

    assert receipt.contract_digest == HOOK_PAYLOAD_CONTRACT_DIGEST
    assert guard.claim(
        invocation_id="invocation-1",
        claim_token="claim-1",
        active_binding=binding,
        hook_policy_digest="c" * 64,
    ) == receipt
    with pytest.raises(HookPayloadReplayError):
        guard.claim(
            invocation_id="invocation-1",
            claim_token="claim-1",
            active_binding=binding,
            hook_policy_digest="c" * 64,
        )

    guard.issue(
        invocation_id="invocation-2",
        claim_token="claim-2",
        request_id="request-2",
        normalized=normalized,
        binding=binding,
        hook_policy_digest="c" * 64,
        ttl_seconds=1,
    )
    now[0] += 2
    with pytest.raises(HookPayloadReplayError):
        guard.claim(
            invocation_id="invocation-2",
            claim_token="claim-2",
            active_binding=binding,
            hook_policy_digest="c" * 64,
        )
    with pytest.raises(HookPayloadReplayError):
        guard.issue(
            invocation_id="invocation-2",
            claim_token="new-token",
            request_id="request-2",
            normalized=normalized,
            binding=binding,
            hook_policy_digest="c" * 64,
        )

    guard.issue(
        invocation_id="invocation-3",
        claim_token="claim-3",
        request_id=3,
        normalized=normalized,
        binding=binding,
        hook_policy_digest="c" * 64,
    )
    claimed_binding = binding.transition(
        TransitionReason.THREAD_CLAIM,
        provider_thread_id="thread-1",
    )
    with pytest.raises(HookPayloadReplayError, match="authority is stale"):
        guard.claim(
            invocation_id="invocation-3",
            claim_token="claim-3",
            active_binding=claimed_binding,
            hook_policy_digest="c" * 64,
        )

