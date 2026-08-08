from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from supervisor.appserver import AppServerMessage
from supervisor.approvals import ApprovalManager, normalize_approval_request
from supervisor.schemas import ApprovalDecisionKind, SupervisorDecision, SupervisorDecisionKind


def message(method: str, request_id: int, params: dict) -> AppServerMessage:
    return AppServerMessage({"id": request_id, "method": method, "params": params})


def command_context(tmp_path: Path, command: str, *, available=None):
    return normalize_approval_request(
        message(
            "item/commandExecution/requestApproval",
            100,
            {
                "threadId": "t",
                "turnId": "u",
                "itemId": "i",
                "command": command,
                "cwd": str(tmp_path),
                "availableDecisions": available if available is not None else ["accept", "decline", "cancel"],
            },
        )
    )


class FakeFullSupervisor:
    def __init__(self, decision: SupervisorDecision | None = None, exc: BaseException | None = None) -> None:
        self.decision = decision or SupervisorDecision(
            decision=SupervisorDecisionKind.APPROVE,
            approval_decision=ApprovalDecisionKind.ACCEPT,
            reason="full supervisor approved",
        )
        self.exc = exc
        self.calls = 0
        self.contexts = []
        self.reasons = []

    async def decide_approval(self, context, reason):
        self.calls += 1
        self.contexts.append(context)
        self.reasons.append(reason)
        if self.exc is not None:
            raise self.exc
        return self.decision


@pytest.mark.asyncio
async def test_command_approval_constrained_by_available_decisions(tmp_path: Path) -> None:
    (tmp_path / "TASK.md").write_text("# Task", encoding="utf-8")
    ctx = normalize_approval_request(
        message(
            "item/commandExecution/requestApproval",
            10,
            {
                "threadId": "t",
                "turnId": "u",
                "itemId": "i",
                "command": "ls",
                "cwd": str(tmp_path),
                "availableDecisions": ["decline", "cancel"],
            },
        )
    )

    decision = await ApprovalManager(tmp_path).decide(ctx)

    assert decision.decision in {"decline", "cancel"}


@pytest.mark.asyncio
async def test_network_approval_routes_to_supervisor_or_denies(tmp_path: Path) -> None:
    ctx = normalize_approval_request(
        message(
            "item/commandExecution/requestApproval",
            11,
            {
                "threadId": "t",
                "turnId": "u",
                "itemId": "i",
                "command": "curl https://example.com",
                "networkApprovalContext": {"host": "example.com", "protocol": "https"},
                "availableDecisions": ["accept", "decline", "cancel"],
            },
        )
    )

    decision = await ApprovalManager(tmp_path).decide(ctx)

    assert decision.decision in {"decline", "cancel"}


@pytest.mark.asyncio
async def test_accept_with_execpolicy_amendment_only_for_command(tmp_path: Path) -> None:
    class Reviewer:
        async def decide_approval(self, context, reason):
            return SupervisorDecision(
                decision=SupervisorDecisionKind.APPROVE,
                approval_decision=ApprovalDecisionKind.ACCEPT,
                execpolicy_amendment=["pytest tests/*"],
                reason="safe repeated validation",
            )

    ctx = normalize_approval_request(
        message(
            "item/commandExecution/requestApproval",
            12,
            {
                "threadId": "t",
                "turnId": "u",
                "itemId": "i",
                "command": "pytest tests/test_x.py",
                "availableDecisions": [
                    "accept",
                    {"acceptWithExecpolicyAmendment": {"execpolicy_amendment": ["pytest tests/*"]}},
                    "decline",
                ],
            },
        )
    )

    decision = await ApprovalManager(tmp_path, supervisor=Reviewer()).decide(ctx)

    assert isinstance(decision.decision, dict)
    assert "acceptWithExecpolicyAmendment" in decision.decision


@pytest.mark.asyncio
async def test_accept_for_session_with_exact_execpolicy_amendment_uses_offered_protocol_decision(
    tmp_path: Path,
) -> None:
    amendment = ["./compile.sh"]

    class Reviewer:
        async def decide_approval(self, context, reason):
            return SupervisorDecision(
                decision=SupervisorDecisionKind.APPROVE,
                approval_decision=ApprovalDecisionKind.ACCEPT_FOR_SESSION,
                execpolicy_amendment=amendment,
                reason="approve the exact repeated build",
            )

    offered_decision = {"acceptWithExecpolicyAmendment": {"execpolicy_amendment": amendment}}
    ctx = normalize_approval_request(
        message(
            "item/commandExecution/requestApproval",
            13,
            {
                "threadId": "thread",
                "turnId": "turn",
                "itemId": "build",
                "command": "/bin/bash -lc ./compile.sh",
                "cwd": str(tmp_path),
                "proposedExecpolicyAmendment": amendment,
                "availableDecisions": ["accept", offered_decision, "cancel"],
            },
        )
    )

    decision = await ApprovalManager(tmp_path, supervisor=Reviewer()).decide(ctx)

    assert decision.decision == offered_decision
    assert decision.from_supervisor is True


@pytest.mark.asyncio
async def test_accept_for_session_cannot_substitute_unoffered_execpolicy_amendment(tmp_path: Path) -> None:
    offered_amendment = ["./compile.sh"]

    class Reviewer:
        async def decide_approval(self, context, reason):
            return SupervisorDecision(
                decision=SupervisorDecisionKind.APPROVE,
                approval_decision=ApprovalDecisionKind.ACCEPT_FOR_SESSION,
                execpolicy_amendment=["./other-command"],
                reason="approve a different command",
            )

    ctx = normalize_approval_request(
        message(
            "item/commandExecution/requestApproval",
            14,
            {
                "command": "/bin/bash -lc ./compile.sh",
                "cwd": str(tmp_path),
                "proposedExecpolicyAmendment": offered_amendment,
                "availableDecisions": [
                    "accept",
                    {"acceptWithExecpolicyAmendment": {"execpolicy_amendment": offered_amendment}},
                    "cancel",
                ],
            },
        )
    )

    decision = await ApprovalManager(tmp_path, supervisor=Reviewer()).decide(ctx)

    assert decision.decision == "cancel"


@pytest.mark.asyncio
async def test_network_approval_never_persists_broad_execpolicy_amendment(tmp_path: Path) -> None:
    amendment = ["curl", "-L"]
    supervisor = FakeFullSupervisor(
        SupervisorDecision(
            decision=SupervisorDecisionKind.APPROVE,
            approval_decision=ApprovalDecisionKind.ACCEPT,
            execpolicy_amendment=amendment,
            persistent_decision="allow this command prefix",
            reason="reference host is required by the task",
        )
    )
    ctx = normalize_approval_request(
        message(
            "item/commandExecution/requestApproval",
            120,
            {
                "command": "curl -L https://example.com",
                "cwd": str(tmp_path),
                "networkApprovalContext": {"host": "example.com", "protocol": "https", "port": 443},
                "proposedExecpolicyAmendment": amendment,
                "availableDecisions": [
                    "accept",
                    {"acceptWithExecpolicyAmendment": {"execpolicy_amendment": amendment}},
                    "decline",
                ],
            },
        )
    )

    decision = await ApprovalManager(tmp_path, supervisor=supervisor).decide(ctx)

    assert decision.decision == "accept"
    assert decision.persistent_decision is None


@pytest.mark.asyncio
async def test_network_approval_cannot_write_to_immutable_original_workspace(tmp_path: Path) -> None:
    original = tmp_path / "original"
    original.mkdir()
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    supervisor = FakeFullSupervisor()
    ctx = command_context(
        snapshot,
        f"curl -fsSL https://example.com/ -o {original / 'download.html'}",
    )
    ctx = ctx.model_copy(
        update={
            "network_approval_context": {
                "host": "example.com",
                "protocol": "https",
                "port": 443,
            }
        }
    )

    decision = await ApprovalManager(
        snapshot,
        supervisor=supervisor,
        immutable_paths=(original,),
    ).decide(ctx)

    assert decision.decision in {"decline", "cancel"}
    assert "immutable path" in decision.reason
    assert supervisor.calls == 0


@pytest.mark.asyncio
async def test_network_command_without_protocol_context_still_cannot_persist_amendment(tmp_path: Path) -> None:
    amendment = ["set", "-o", "pipefail"]
    supervisor = FakeFullSupervisor(
        SupervisorDecision(
            decision=SupervisorDecisionKind.APPROVE,
            approval_decision=ApprovalDecisionKind.ACCEPT,
            execpolicy_amendment=amendment,
            persistent_decision="allow this command prefix",
            reason="reference host is required by the task",
        )
    )
    ctx = normalize_approval_request(
        message(
            "item/commandExecution/requestApproval",
            121,
            {
                "command": "set -o pipefail\ncurl -L https://example.com | sed -n '1p'",
                "cwd": str(tmp_path),
                "proposedExecpolicyAmendment": amendment,
                "availableDecisions": [
                    "accept",
                    {"acceptWithExecpolicyAmendment": {"execpolicy_amendment": amendment}},
                    "decline",
                ],
            },
        )
    )

    decision = await ApprovalManager(tmp_path, supervisor=supervisor).decide(ctx)

    assert decision.decision == "accept"
    assert decision.persistent_decision is None


@pytest.mark.asyncio
async def test_network_policy_amendment_cannot_be_accepted_for_session(tmp_path: Path) -> None:
    supervisor = FakeFullSupervisor(
        SupervisorDecision(
            decision=SupervisorDecisionKind.APPROVE,
            approval_decision=ApprovalDecisionKind.ACCEPT_FOR_SESSION,
            reason="repeatable network access",
        )
    )
    ctx = normalize_approval_request(
        message(
            "item/commandExecution/requestApproval",
            122,
            {
                "command": "curl https://example.com",
                "cwd": str(tmp_path),
                "proposedNetworkPolicyAmendments": [{"host": "example.com"}],
                "availableDecisions": ["acceptForSession", "decline", "cancel"],
            },
        )
    )

    decision = await ApprovalManager(tmp_path, supervisor=supervisor).decide(ctx)

    assert decision.decision in {"decline", "cancel"}


@pytest.mark.asyncio
async def test_file_change_to_immutable_task_is_denied(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    ctx = normalize_approval_request(
        message(
            "item/fileChange/requestApproval",
            121,
            {
                "cwd": str(tmp_path),
                "grantRoot": str(task),
                "availableDecisions": ["accept", "decline", "cancel"],
            },
        )
    )

    decision = await ApprovalManager(tmp_path, immutable_paths=(task,)).decide(ctx)

    assert decision.decision in {"decline", "cancel"}
    assert "immutable path" in decision.reason


@pytest.mark.asyncio
async def test_file_change_allows_only_configured_coder_checklist_inside_runtime_state(tmp_path: Path) -> None:
    checklist = tmp_path / ".supervisor" / "coder" / "CHECKLIST.md"
    checklist.parent.mkdir(parents=True)
    checklist.write_text("", encoding="utf-8")
    handoff = tmp_path / ".supervisor" / "HANDOFF.md"
    handoff.write_text("protected", encoding="utf-8")
    checklist_context = normalize_approval_request(
        message(
            "item/fileChange/requestApproval",
            122,
            {
                "cwd": str(tmp_path),
                "grantRoot": str(checklist),
                "availableDecisions": ["accept", "decline", "cancel"],
            },
        )
    )
    handoff_context = normalize_approval_request(
        message(
            "item/fileChange/requestApproval",
            123,
            {
                "cwd": str(tmp_path),
                "grantRoot": str(handoff),
                "availableDecisions": ["accept", "decline", "cancel"],
            },
        )
    )
    manager = ApprovalManager(tmp_path, coder_checklist_path=checklist)

    checklist_decision = await manager.decide(checklist_context)
    handoff_decision = await manager.decide(handoff_context)
    checklist.unlink()
    checklist.hardlink_to(handoff)
    invalid_checklist_decision = await manager.decide(checklist_context)

    assert checklist_decision.decision == "accept"
    assert handoff_decision.decision in {"decline", "cancel"}
    assert handoff_decision.reason == "writes to supervisor runtime/state files are denied"
    assert invalid_checklist_decision.decision in {"decline", "cancel"}
    assert "single-link" in invalid_checklist_decision.reason


@pytest.mark.asyncio
async def test_command_approval_allows_only_exact_coder_checklist_touch(
    tmp_path: Path,
) -> None:
    checklist = tmp_path / ".supervisor" / "coder" / "CHECKLIST.md"
    checklist.parent.mkdir(parents=True)
    checklist.write_text("", encoding="utf-8")
    manager = ApprovalManager(tmp_path, coder_checklist_path=checklist)

    exact = await manager.decide(
        command_context(
            tmp_path,
            "/bin/bash -lc 'touch .supervisor/coder/CHECKLIST.md'",
        )
    )
    sibling = await manager.decide(
        command_context(
            tmp_path,
            "/bin/bash -lc 'touch .supervisor/HANDOFF.md'",
        )
    )

    assert exact.decision == "accept"
    assert exact.reason == "coder checklist write"
    assert sibling.decision in {"decline", "cancel"}


@pytest.mark.asyncio
async def test_file_change_does_not_emit_execpolicy_amendment(tmp_path: Path) -> None:
    class Reviewer:
        async def decide_approval(self, context, reason):
            return SupervisorDecision(
                decision=SupervisorDecisionKind.APPROVE,
                approval_decision=ApprovalDecisionKind.ACCEPT,
                execpolicy_amendment=["never"],
                reason="approve file",
            )

    ctx = normalize_approval_request(
        message(
            "item/fileChange/requestApproval",
            13,
            {"threadId": "t", "turnId": "u", "itemId": "i", "grantRoot": str(tmp_path), "availableDecisions": ["accept", "decline"]},
        )
    )

    decision = await ApprovalManager(tmp_path, supervisor=Reviewer()).decide(ctx)

    assert decision.decision == "accept"


@pytest.mark.asyncio
async def test_file_change_without_exposed_paths_allows_workspace_edit(tmp_path: Path) -> None:
    ctx = normalize_approval_request(
        message(
            "item/fileChange/requestApproval",
            14,
            {"threadId": "t", "turnId": "u", "itemId": "i", "availableDecisions": ["accept", "decline", "cancel"]},
        )
    )

    decision = await ApprovalManager(tmp_path).decide(ctx)

    assert decision.decision == "accept"


@pytest.mark.asyncio
async def test_supervisor_approve_with_denial_choice_fails_closed(tmp_path: Path) -> None:
    class Reviewer:
        async def decide_approval(self, context, reason):
            return SupervisorDecision(
                decision=SupervisorDecisionKind.APPROVE,
                approval_decision=ApprovalDecisionKind.DECLINE,
                reason="wrong shape",
            )

    ctx = normalize_approval_request(
        message(
            "item/commandExecution/requestApproval",
            15,
            {"command": "pytest", "availableDecisions": ["accept", "decline", "cancel"]},
        )
    )

    decision = await ApprovalManager(tmp_path, supervisor=Reviewer()).decide(ctx)

    assert decision.decision in {"decline", "cancel"}


@pytest.mark.asyncio
async def test_supervisor_deny_with_approval_choice_fails_closed(tmp_path: Path) -> None:
    class Reviewer:
        async def decide_approval(self, context, reason):
            return SupervisorDecision(
                decision=SupervisorDecisionKind.DENY,
                approval_decision=ApprovalDecisionKind.ACCEPT,
                reason="wrong shape",
            )

    ctx = normalize_approval_request(
        message(
            "item/commandExecution/requestApproval",
            16,
            {"command": "pytest", "availableDecisions": ["accept", "decline", "cancel"]},
        )
    )

    decision = await ApprovalManager(tmp_path, supervisor=Reviewer()).decide(ctx)

    assert decision.decision in {"decline", "cancel"}


@pytest.mark.asyncio
async def test_accept_for_session_rejected_for_forbidden_classes(tmp_path: Path) -> None:
    class Reviewer:
        async def decide_approval(self, context, reason):
            return SupervisorDecision(
                decision=SupervisorDecisionKind.APPROVE,
                approval_decision=ApprovalDecisionKind.ACCEPT_FOR_SESSION,
                reason="repeatable",
            )

    ctx = normalize_approval_request(
        message(
            "item/commandExecution/requestApproval",
            17,
            {"command": "git push origin main", "availableDecisions": ["acceptForSession", "decline", "cancel"]},
        )
    )

    decision = await ApprovalManager(tmp_path, supervisor=Reviewer()).decide(ctx)

    assert decision.decision in {"decline", "cancel"}


@pytest.mark.asyncio
async def test_execpolicy_amendment_requires_exact_offer(tmp_path: Path) -> None:
    class Reviewer:
        async def decide_approval(self, context, reason):
            return SupervisorDecision(
                decision=SupervisorDecisionKind.APPROVE,
                approval_decision=ApprovalDecisionKind.ACCEPT,
                execpolicy_amendment=["pytest tests/other.py"],
                reason="safe repeated validation",
            )

    ctx = normalize_approval_request(
        message(
            "item/commandExecution/requestApproval",
            18,
            {
                "command": "pytest tests/test_x.py",
                "availableDecisions": [
                    "accept",
                    {"acceptWithExecpolicyAmendment": {"execpolicy_amendment": ["pytest tests/test_x.py"]}},
                    "decline",
                ],
            },
        )
    )

    decision = await ApprovalManager(tmp_path, supervisor=Reviewer()).decide(ctx)

    assert decision.decision == "accept"


@pytest.mark.asyncio
async def test_recursive_delete_of_tracked_path_is_denied(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('tracked')\n", encoding="utf-8")
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True, text=True)
    subprocess.run(["git", "add", "src/app.py"], cwd=tmp_path, check=True, capture_output=True, text=True)
    ctx = normalize_approval_request(
        message(
            "item/commandExecution/requestApproval",
            19,
            {"command": "rm -rf src", "cwd": str(tmp_path), "availableDecisions": ["accept", "decline", "cancel"]},
        )
    )

    decision = await ApprovalManager(tmp_path).decide(ctx)

    assert decision.decision in {"decline", "cancel"}
    assert "git-tracked" in decision.reason


@pytest.mark.asyncio
async def test_deterministic_allow_bypasses_full_review(tmp_path: Path) -> None:
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "ls")

    decision = await ApprovalManager(tmp_path, supervisor=full).decide(ctx)

    assert decision.decision == "accept"
    assert full.calls == 0


@pytest.mark.parametrize(
    "command",
    [
        "/bin/bash -lc 'make -j4'",
        "/bin/bash -lc ./run_visible_tests.sh",
        "{workspace}/.venv/bin/python3 -m pytest tests/public/test_public.py::test_public -v --tb=short",
        "/bin/bash -lc './c_compiler /tmp/input.c -o /tmp/out'",
        "rm -rf tests/__pycache__",
    ],
)
@pytest.mark.asyncio
async def test_project_execution_commands_use_full_supervisor_review(tmp_path: Path, command: str) -> None:
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, command.format(workspace=tmp_path))

    decision = await ApprovalManager(tmp_path, supervisor=full).decide(ctx)

    assert decision.decision == "accept"
    assert full.calls == 1


@pytest.mark.asyncio
async def test_shell_heredoc_task_command_still_uses_full_supervisor(tmp_path: Path) -> None:
    full = FakeFullSupervisor()
    ctx = command_context(
        tmp_path,
        "bash -lc 'cat > /tmp/input.c <<EOF\nint main(void){return 0;}\nEOF'",
    )

    decision = await ApprovalManager(tmp_path, supervisor=full).decide(ctx)

    assert decision.decision == "accept"
    assert full.calls == 1


@pytest.mark.asyncio
async def test_private_c_compiler_input_still_uses_full_supervisor(tmp_path: Path) -> None:
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "./c_compiler /tmp/private/input.c -o /tmp/out")

    decision = await ApprovalManager(tmp_path, supervisor=full).decide(ctx)

    assert decision.decision == "accept"
    assert full.calls == 1


@pytest.mark.asyncio
async def test_deterministic_denial_bypasses_full_review(tmp_path: Path) -> None:
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "bello --task TASK.md")

    decision = await ApprovalManager(tmp_path, supervisor=full).decide(ctx)

    assert decision.decision in {"decline", "cancel"}
    assert "Bello" in decision.reason
    assert full.calls == 0


@pytest.mark.parametrize(
    "command",
    [
        "git status --short && git diff --stat",
        "mkdir build",
        "cp parser.c /tmp/leak.c",
        "python -c \"print('x')\"",
    ],
)
@pytest.mark.asyncio
async def test_commands_requiring_judgment_go_directly_to_full_supervisor(tmp_path: Path, command: str) -> None:
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, command)

    decision = await ApprovalManager(tmp_path, supervisor=full).decide(ctx)

    assert decision.decision == "accept"
    assert decision.reason == "full supervisor approved"
    assert decision.from_supervisor is True
    assert full.calls == 1


@pytest.mark.asyncio
async def test_accept_not_offered_uses_full_supervisor_denial(tmp_path: Path) -> None:
    full = FakeFullSupervisor(
        SupervisorDecision(
            decision=SupervisorDecisionKind.DENY,
            approval_decision=ApprovalDecisionKind.DECLINE,
            reason="full supervisor denied",
        )
    )
    ctx = command_context(tmp_path, "git status --short && git diff --stat", available=["decline", "cancel"])

    decision = await ApprovalManager(tmp_path, supervisor=full).decide(ctx)

    assert decision.decision in {"decline", "cancel"}
    assert full.calls == 1


@pytest.mark.asyncio
async def test_full_supervisor_failure_fails_closed(tmp_path: Path) -> None:
    full = FakeFullSupervisor(exc=RuntimeError("full failed"))
    ctx = command_context(tmp_path, "git status --short && git diff --stat")

    decision = await ApprovalManager(tmp_path, supervisor=full).decide(ctx)

    assert decision.decision in {"decline", "cancel"}
    assert "supervisor approval fallback failed" in decision.reason
    assert full.calls == 1


@pytest.mark.asyncio
async def test_full_supervisor_invalid_output_fails_closed(tmp_path: Path) -> None:
    full = FakeFullSupervisor(
        SupervisorDecision(
            decision=SupervisorDecisionKind.NOOP,
            approval_decision=None,
            reason="not an approval",
        )
    )
    ctx = command_context(tmp_path, "git status --short && git diff --stat")

    decision = await ApprovalManager(tmp_path, supervisor=full).decide(ctx)

    assert decision.decision in {"decline", "cancel"}
    assert "not an approval" in decision.reason
    assert full.calls == 1


@pytest.mark.parametrize(
    "method",
    [
        "item/permissions/requestApproval",
        "item/tool/call",
        "item/tool/requestUserInput",
        "mcpServer/elicitation/request",
        "unknown/request",
    ],
)
@pytest.mark.asyncio
async def test_unsupported_request_types_are_denied_without_full_supervisor(tmp_path: Path, method: str) -> None:
    full = FakeFullSupervisor()
    params = {
        "threadId": "t",
        "turnId": "u",
        "itemId": "i",
        "availableDecisions": ["accept", "decline"],
    }
    ctx = normalize_approval_request(message(method, 200, params))

    decision = await ApprovalManager(tmp_path, supervisor=full).decide(ctx)

    assert decision.decision in {"decline", "cancel"}
    assert full.calls == 0


@pytest.mark.asyncio
async def test_network_approval_goes_directly_to_full_supervisor(tmp_path: Path) -> None:
    full = FakeFullSupervisor()
    ctx = normalize_approval_request(
        message(
            "item/commandExecution/requestApproval",
            201,
            {
                "command": "curl https://example.com",
                "cwd": str(tmp_path),
                "networkApprovalContext": {"host": "example.com", "protocol": "https"},
                "availableDecisions": ["accept", "decline"],
            },
        )
    )

    decision = await ApprovalManager(tmp_path, supervisor=full).decide(ctx)

    assert decision.decision == "accept"
    assert full.calls == 1


def test_runtime_triage_config_defaults_enabled_with_default_model(monkeypatch) -> None:
    from supervisor.approval_triage import DEFAULT_TRIAGE_MODEL, runtime_triage_config_from_env

    monkeypatch.setenv("BELLO_RUNTIME_TRIAGE_ENABLED", "false")
    monkeypatch.delenv("BELLO_RUNTIME_TRIAGE_MODEL", raising=False)
    config = runtime_triage_config_from_env()
    assert config.enabled is True
    assert config.model == DEFAULT_TRIAGE_MODEL


def test_runtime_triage_config_uses_project_enabled_value(monkeypatch) -> None:
    from supervisor.approval_triage import runtime_triage_config_from_env

    monkeypatch.setenv("BELLO_RUNTIME_TRIAGE_ENABLED", "true")
    assert runtime_triage_config_from_env(enabled=False).enabled is False


def test_cheap_runtime_decision_validator() -> None:
    from supervisor.schemas import CheapRuntimeDecision

    assert CheapRuntimeDecision(decision="noop", reason_code="routine_progress").decision == "noop"
    assert CheapRuntimeDecision(decision="escalate", reason_code="drift_or_risk").decision == "escalate"
    with pytest.raises(Exception):
        CheapRuntimeDecision(decision="noop", reason_code="drift_or_risk")  # noop needs benign code
    with pytest.raises(Exception):
        CheapRuntimeDecision(decision="escalate", reason_code="routine_progress")


def test_cheap_runtime_packet_is_slim(tmp_path: Path) -> None:
    import json

    from supervisor.approval_triage import cheap_runtime_packet
    from supervisor.prompts import build_cheap_runtime_prompt
    from supervisor.schemas import SupervisorWakePacket

    pkt = SupervisorWakePacket(
        wake_sequence=5,
        latest_event_sequence=4,
        generation=1,
        restart_count=0,
        task_path=str(tmp_path / "TASK.md"),
        task_contents="X" * 50000,  # large; must NOT be inlined into the cheap packet
        current_summary="Runtime trigger (large_diff): coder edited codegen.c",
    )
    slim = cheap_runtime_packet(pkt)
    assert "wake_reason" in slim
    assert "task_contents" not in slim  # heavy field excluded
    prompt = build_cheap_runtime_prompt(slim)
    assert "X" * 1000 not in prompt  # task body not present
    assert len(prompt) < 8000  # genuinely slim
    assert json.loads(prompt)["instructions"]  # carries the classifier instructions


def test_cheap_runtime_packet_does_not_present_stale_masked_validation_as_current(tmp_path: Path) -> None:
    import json

    from supervisor.approval_triage import cheap_runtime_packet
    from supervisor.schemas import SupervisorWakePacket, TriggeringAction, ValidationRun

    stale = ValidationRun(
        validation_id="stale",
        command="./compile.sh",
        exit_code=0,
        passed=False,
        trusted_validation_outcome="masked_or_unknown",
        masking_reason="behavior_demo_missing_output",
        summary="old masked compile",
        sequence=10,
    )
    packet = SupervisorWakePacket(
        wake_sequence=21,
        latest_event_sequence=20,
        generation=0,
        restart_count=0,
        task_path=str(tmp_path / "TASK.md"),
        task_contents="task",
        current_summary="Runtime trigger (nonzero_exit): diff exited 1",
        triggering_action=TriggeringAction(
            kind="commandExecution",
            command="diff -u expected actual",
            exit_code=1,
            status="completed",
            summary="diff exited 1",
        ),
        validations=[stale],
    )

    slim = cheap_runtime_packet(packet)

    assert slim["triggering_validation"] is None
    assert slim["followup_validations"] == []
    assert "old masked compile" not in json.dumps(slim)


def test_cheap_runtime_packet_keeps_current_validation_and_later_followup(tmp_path: Path) -> None:
    import json

    from supervisor.approval_triage import cheap_runtime_packet
    from supervisor.schemas import SupervisorWakePacket, TriggeringAction, ValidationRun

    stale = ValidationRun(
        validation_id="stale",
        command="./old-check",
        exit_code=0,
        passed=False,
        trusted_validation_outcome="masked_or_unknown",
        masking_reason="behavior_demo_missing_output",
        summary="old masked validation",
        sequence=5,
    )
    current = ValidationRun(
        validation_id="current",
        command="./compile.sh | head",
        exit_code=0,
        passed=False,
        trusted_validation_outcome="masked_or_unknown",
        masking_reason="pipeline_without_pipefail",
        summary="current masked validation",
        sequence=20,
    )
    followup = ValidationRun(
        validation_id="followup",
        command="./trusted-compare",
        exit_code=0,
        passed=True,
        trusted_validation_outcome="passed",
        summary="trusted comparison passed",
        sequence=21,
    )
    packet = SupervisorWakePacket(
        wake_sequence=22,
        latest_event_sequence=21,
        generation=0,
        restart_count=0,
        task_path=str(tmp_path / "TASK.md"),
        task_contents="task",
        current_summary="Runtime trigger (masked_validation): compile pipeline completed",
        triggering_action=TriggeringAction(
            kind="commandExecution",
            command="./compile.sh | head",
            exit_code=0,
            status="completed",
            summary="compile pipeline completed",
        ),
        validations=[stale, current, followup],
    )

    slim = cheap_runtime_packet(packet)
    serialized = json.dumps(slim)

    assert slim["triggering_validation"]["validation_id"] == "current"
    assert [entry["validation_id"] for entry in slim["followup_validations"]] == ["followup"]
    assert "old masked validation" not in serialized


def test_cheap_runtime_packet_reconstructs_legacy_action_and_keeps_binding_context(tmp_path: Path) -> None:
    from supervisor.approval_triage import cheap_runtime_packet
    from supervisor.schemas import PriorIntervention, SupervisorWakePacket, ValidationRun

    current = ValidationRun(
        validation_id="audit",
        command="python3 /tmp/audit.py",
        exit_code=1,
        passed=False,
        trusted_validation_outcome="failed",
        summary="audit mismatch output was truncated",
        captured_output_truncated=True,
        sequence=20,
    )
    packet = SupervisorWakePacket(
        wake_sequence=21,
        latest_event_sequence=20,
        generation=0,
        restart_count=1,
        task_path=str(tmp_path / "TASK.md"),
        task_contents="task",
        current_summary=(
            "Runtime trigger (repeated_same_failing_validation, nonzero_exit): "
            "command completed: python3 /tmp/audit.py exit=1"
        ),
        triggering_item_id="cmd-20",
        validations=[current],
        prior_interventions=[
            PriorIntervention(
                sequence=18,
                reason="The broad audit output is truncated before the actionable mismatch.",
                message_to_coder="Expose the complete first mismatch before rerunning the audit.",
            )
        ],
        latest_relevant_change_sequence=19,
    )

    slim = cheap_runtime_packet(packet)

    assert slim["triggering_action"]["command"] == "python3 /tmp/audit.py"
    assert slim["triggering_action"]["sequence"] == 20
    assert slim["triggering_validation"]["validation_id"] == "audit"
    assert slim["prior_interventions"][0]["sequence"] == 18
    assert slim["validation_state"]["trusted_behavioral_validation_is_fresh"] is False
    assert slim["latest_validation_request"]["sequence"] == 18
    assert slim["routing_signals"]["failed_after_validation_request"] is True


def test_cheap_runtime_packet_exposes_stale_edit_after_stop_and_validate(tmp_path: Path) -> None:
    from supervisor.approval_triage import cheap_runtime_packet
    from supervisor.schemas import ChangedFile, PriorIntervention, SupervisorWakePacket, TriggeringAction

    packet = SupervisorWakePacket(
        wake_sequence=31,
        latest_event_sequence=30,
        generation=0,
        restart_count=0,
        task_path=str(tmp_path / "TASK.md"),
        task_contents="task",
        current_summary="Runtime trigger (large_diff): file change completed: 1 changes",
        triggering_action=TriggeringAction(
            item_id="edit-30",
            kind="fileChange",
            paths=["src/parser.py"],
            status="completed",
            summary="file change completed: 1 changes",
        ),
        recent_events=[{"item_id": "edit-30", "sequence": 30}],
        changed_files=[ChangedFile(path="src/parser.py", status="M", sequence=30)],
        prior_interventions=[
            PriorIntervention(
                sequence=25,
                reason="The affected behavioral comparison is stale.",
                message_to_coder="Stop editing and run the asserting comparison before any further edit.",
            )
        ],
        latest_relevant_change_sequence=30,
    )

    slim = cheap_runtime_packet(packet)

    assert slim["routing_signals"]["stale_edit_after_stop_and_validate"] is True
    assert slim["latest_validation_request"]["sequence"] == 25


def test_cheap_runtime_packet_flags_masked_nonzero_after_validation_request(tmp_path: Path) -> None:
    from supervisor.approval_triage import cheap_runtime_packet
    from supervisor.schemas import PriorIntervention, SupervisorWakePacket, TriggeringAction

    packet = SupervisorWakePacket(
        wake_sequence=41,
        latest_event_sequence=40,
        generation=0,
        restart_count=1,
        task_path=str(tmp_path / "TASK.md"),
        task_contents="task",
        current_summary=(
            "Runtime trigger (masked_validation, nonzero_exit): "
            "command completed: python3 /tmp/comparator.py exit=1"
        ),
        triggering_action=TriggeringAction(
            kind="commandExecution",
            command="python3 /tmp/comparator.py",
            exit_code=1,
            status="failed",
            summary="comparator failed",
        ),
        prior_interventions=[
            PriorIntervention(
                sequence=35,
                reason="The affected behavior still lacks trusted evidence.",
                message_to_coder="Run the asserting comparator before continuing.",
            )
        ],
        latest_relevant_change_sequence=30,
    )

    slim = cheap_runtime_packet(packet)

    assert slim["triggering_validation"] is None
    assert slim["routing_signals"]["masked_nonzero_after_validation_request"] is True


@pytest.mark.asyncio
async def test_adversary_mode_allows_destructive_delete_inside_snapshot(tmp_path: Path) -> None:
    # Contained cleanup escalates (destructive) but stays inside the snapshot → auto-approve.
    (tmp_path / "build").mkdir()
    manager = ApprovalManager(tmp_path, adversary_mode=True)
    context = command_context(tmp_path, "rm -rf build")

    resolution = await manager.decide(context)

    assert resolution.decision == "accept"
    assert "disposable snapshot" in resolution.reason


@pytest.mark.asyncio
async def test_adversary_mode_allows_in_snapshot_file_write(tmp_path: Path) -> None:
    manager = ApprovalManager(tmp_path, adversary_mode=True)
    context = command_context(tmp_path, "mkdir probe_out")

    resolution = await manager.decide(context)

    assert resolution.decision == "accept"


@pytest.mark.asyncio
async def test_adversary_mode_network_command_fails_closed_without_supervisor(tmp_path: Path) -> None:
    manager = ApprovalManager(tmp_path, adversary_mode=True)
    context = command_context(tmp_path, "curl http://localhost:9999/health")

    resolution = await manager.decide(context)

    assert resolution.decision in {"decline", "cancel"}
    assert "requires supervisor judgment" in resolution.reason


@pytest.mark.asyncio
async def test_adversary_mode_interpreter_execution_fails_closed_without_supervisor(tmp_path: Path) -> None:
    # python -c could open a socket or read grading material at runtime, invisible to static
    # analysis — situational, so it needs the supervisor; with none wired it fails closed.
    manager = ApprovalManager(tmp_path, adversary_mode=True)
    context = command_context(
        tmp_path, "python3 -c 'import urllib.request; urllib.request.urlopen(\"http://x\")'"
    )

    resolution = await manager.decide(context)

    assert resolution.decision in {"decline", "cancel"}
    assert "requires supervisor judgment" in resolution.reason


@pytest.mark.asyncio
async def test_adversary_mode_denies_unknown_binary_and_dependency_install_without_supervisor(tmp_path: Path) -> None:
    manager = ApprovalManager(tmp_path, adversary_mode=True)
    for command in ("nc evil.example 443", "pip install requests"):
        resolution = await manager.decide(command_context(tmp_path, command))
        assert resolution.decision in {"decline", "cancel"}, command


@pytest.mark.asyncio
async def test_adversary_mode_denies_workspace_escape_without_supervisor(tmp_path: Path) -> None:
    manager = ApprovalManager(tmp_path, adversary_mode=True)
    context = command_context(tmp_path, "cat /etc/hosts")

    resolution = await manager.decide(context)

    assert resolution.decision in {"decline", "cancel"}


@pytest.mark.asyncio
async def test_adversary_gray_zone_routes_to_full_supervisor(tmp_path: Path) -> None:
    # The same command can be legitimate under one task and cheating under another, so the
    # gray zone is judged situationally by the full supervisor instead of a static deny.
    supervisor = FakeFullSupervisor()
    manager = ApprovalManager(tmp_path, supervisor=supervisor, adversary_mode=True)
    context = command_context(
        tmp_path, "'/Applications/Browser.app/Contents/MacOS/Browser' --headless index.html"
    )

    resolution = await manager.decide(context)

    assert supervisor.calls == 1
    assert "adversary snapshot escalation" in supervisor.reasons[0]
    assert resolution.decision == "accept"


@pytest.mark.asyncio
async def test_adversary_gray_zone_supervisor_deny_declines(tmp_path: Path) -> None:
    supervisor = FakeFullSupervisor(
        decision=SupervisorDecision(
            decision=SupervisorDecisionKind.DENY,
            approval_decision=ApprovalDecisionKind.DECLINE,
            reason="no task grounding for network access",
        )
    )
    manager = ApprovalManager(tmp_path, supervisor=supervisor, adversary_mode=True)
    context = command_context(tmp_path, "curl https://example.com/data")

    resolution = await manager.decide(context)

    assert supervisor.calls == 1
    assert resolution.decision == "decline"


@pytest.mark.asyncio
async def test_adversary_gray_zone_supervisor_error_fails_closed(tmp_path: Path) -> None:
    supervisor = FakeFullSupervisor(exc=RuntimeError("boom"))
    manager = ApprovalManager(tmp_path, supervisor=supervisor, adversary_mode=True)
    context = command_context(tmp_path, "curl https://example.com/data")

    resolution = await manager.decide(context)

    assert resolution.decision in {"decline", "cancel"}


@pytest.mark.asyncio
async def test_adversary_secret_path_denied_without_consulting_supervisor(tmp_path: Path) -> None:
    # Grading/secret material can never be legitimized by task context; the supervisor is
    # not even consulted.
    (tmp_path / ".env").write_text("KEY=1", encoding="utf-8")
    supervisor = FakeFullSupervisor()
    manager = ApprovalManager(tmp_path, supervisor=supervisor, adversary_mode=True)
    context = command_context(tmp_path, "cat .env")

    resolution = await manager.decide(context)

    assert resolution.decision in {"decline", "cancel"}
    assert supervisor.calls == 0
    assert "adversary snapshot policy denies" in resolution.reason


@pytest.mark.asyncio
async def test_without_adversary_mode_gray_zone_still_denied_when_no_supervisor(tmp_path: Path) -> None:
    manager = ApprovalManager(tmp_path)
    context = command_context(tmp_path, "rm -rf build")

    resolution = await manager.decide(context)

    assert resolution.decision in {"decline", "cancel"}
