from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

import pytest

from supervisor.approval_triage import (
    DEFAULT_TRIAGE_MODEL,
    CheapApprovalReviewer,
    cheap_approval_triage_config_from_env,
)
from supervisor.appserver import AppServerMessage
from supervisor.approvals import ApprovalManager, normalize_approval_request
from supervisor.schemas import ApprovalDecisionKind, CheapApprovalDecision, SupervisorDecision, SupervisorDecisionKind


def message(method: str, request_id: int, params: dict) -> AppServerMessage:
    return AppServerMessage({"id": request_id, "method": method, "params": params})


def test_cheap_approval_triage_config_defaults_disabled_with_default_model(monkeypatch) -> None:
    # Cheap approval stays opt-in; deterministic gates cover the obvious cases.
    monkeypatch.delenv("SENTINEL_APPROVAL_TRIAGE_ENABLED", raising=False)
    monkeypatch.delenv("SENTINEL_APPROVAL_TRIAGE_MODEL", raising=False)
    monkeypatch.setenv("SENTINEL_APPROVAL_TRIAGE_TIMEOUT", "3.5")

    config = cheap_approval_triage_config_from_env()

    assert config.enabled is False
    assert config.model == DEFAULT_TRIAGE_MODEL
    assert config.timeout_seconds == 3.5


def test_cheap_approval_triage_can_be_enabled_by_env(monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_APPROVAL_TRIAGE_ENABLED", "true")
    monkeypatch.delenv("SENTINEL_APPROVAL_TRIAGE_MODEL", raising=False)

    config = cheap_approval_triage_config_from_env()

    assert config.enabled is True


def test_cheap_approval_reviewer_uses_configured_model(tmp_path: Path) -> None:
    reviewer = CheapApprovalReviewer(object(), tmp_path, model="cheap-model", timeout_seconds=7)  # type: ignore[arg-type]

    params = reviewer._thread_params()

    assert params["model"] == "cheap-model"
    assert params["cwd"] == str(tmp_path)


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


class FakeCheapReviewer:
    model = "cheap-test"

    def __init__(self, result=None, exc: BaseException | None = None) -> None:
        self.result = result or CheapApprovalDecision(decision="approve_low_impact", reason_code="bounded_read_only")
        self.exc = exc
        self.calls = 0
        self.contexts = []
        self.evaluations = []

    async def review(self, context, evaluation):
        self.calls += 1
        self.contexts.append(context)
        self.evaluations.append(evaluation)
        if self.exc is not None:
            raise self.exc
        return self.result


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
async def test_deterministic_allow_bypasses_cheap_and_full_review(tmp_path: Path) -> None:
    cheap = FakeCheapReviewer()
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "ls")

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision == "accept"
    assert cheap.calls == 0
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
    cheap = FakeCheapReviewer()
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, command.format(workspace=tmp_path))

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision == "accept"
    assert cheap.calls == 0
    assert full.calls == 1


@pytest.mark.asyncio
async def test_shell_heredoc_task_command_still_uses_full_supervisor(tmp_path: Path) -> None:
    cheap = FakeCheapReviewer()
    full = FakeFullSupervisor()
    ctx = command_context(
        tmp_path,
        "bash -lc 'cat > /tmp/input.c <<EOF\nint main(void){return 0;}\nEOF'",
    )

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision == "accept"
    assert cheap.calls == 0
    assert full.calls == 1


@pytest.mark.asyncio
async def test_private_c_compiler_input_still_uses_full_supervisor(tmp_path: Path) -> None:
    cheap = FakeCheapReviewer()
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "./c_compiler /tmp/private/input.c -o /tmp/out")

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision == "accept"
    assert cheap.calls == 0
    assert full.calls == 1


@pytest.mark.asyncio
async def test_deterministic_denial_bypasses_and_cannot_be_overridden_by_cheap_review(tmp_path: Path) -> None:
    cheap = FakeCheapReviewer()
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "sentinel --task TASK.md")

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision in {"decline", "cancel"}
    assert "Sentinel" in decision.reason
    assert cheap.calls == 0
    assert full.calls == 0


@pytest.mark.asyncio
async def test_eligible_command_can_be_plain_accepted_by_cheap_review(tmp_path: Path) -> None:
    cheap = FakeCheapReviewer(
        CheapApprovalDecision(decision="approve_low_impact", reason_code="bounded_read_only")
    )
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "git status --short && git diff --stat")

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision == "accept"
    assert decision.reason == "low-impact command approved by cheap review (bounded_read_only)"
    assert decision.persistent_decision is None
    assert decision.from_supervisor is False
    assert cheap.calls == 1
    assert full.calls == 0


@pytest.mark.asyncio
async def test_workspace_local_write_is_eligible_for_cheap_approval(tmp_path: Path) -> None:
    # Expanded eligibility: a bounded in-workspace write (not read-only) may be cheap-approved.
    cheap = FakeCheapReviewer(
        CheapApprovalDecision(decision="approve_low_impact", reason_code="workspace_local_safe")
    )
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "mkdir build")

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision == "accept"
    assert decision.reason == "low-impact command approved by cheap review (workspace_local_safe)"
    assert decision.from_supervisor is False
    assert cheap.calls == 1
    assert full.calls == 0


@pytest.mark.asyncio
async def test_workspace_escaping_write_bypasses_cheap_review(tmp_path: Path) -> None:
    # A write that leaves the workspace stays hard-blocked from cheap review (integrity/safety).
    cheap = FakeCheapReviewer(
        CheapApprovalDecision(decision="approve_low_impact", reason_code="workspace_local_safe")
    )
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "cp parser.c /tmp/leak.c")

    await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert cheap.calls == 0
    assert full.calls == 1


@pytest.mark.asyncio
async def test_cheap_review_escalation_calls_full_supervisor_once_with_original_reason(tmp_path: Path) -> None:
    cheap = FakeCheapReviewer(CheapApprovalDecision(decision="escalate", reason_code="needs_task_judgment"))
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "git status --short && git diff --stat")

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision == "accept"
    assert decision.reason == "full supervisor approved"
    assert cheap.calls == 1
    assert full.calls == 1
    assert full.contexts == [ctx]
    assert full.reasons == ["shell metacharacters require LLM review"]


@pytest.mark.asyncio
async def test_cheap_review_exception_calls_full_supervisor_without_leaking_marker(tmp_path: Path) -> None:
    marker = "CHEAP_REVIEW_PRIVATE_MARKER_71F2"
    cheap = FakeCheapReviewer(exc=RuntimeError(marker))
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "git status --short && git diff --stat")

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision == "accept"
    assert cheap.calls == 1
    assert full.calls == 1
    assert marker not in full.reasons[0]
    assert marker not in full.contexts[0].model_dump_json()


@pytest.mark.asyncio
async def test_cheap_review_timeout_calls_full_supervisor(tmp_path: Path) -> None:
    class SlowCheapReviewer(FakeCheapReviewer):
        async def review(self, context, evaluation):
            self.calls += 1
            await asyncio.sleep(1)
            return self.result

    cheap = SlowCheapReviewer()
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "git status --short && git diff --stat")

    decision = await ApprovalManager(
        tmp_path,
        supervisor=full,
        cheap_reviewer=cheap,
        cheap_review_timeout_seconds=0.01,
    ).decide(ctx)

    assert decision.decision == "accept"
    assert cheap.calls == 1
    assert full.calls == 1


@pytest.mark.asyncio
async def test_cheap_review_invalid_shape_calls_full_supervisor(tmp_path: Path) -> None:
    cheap = FakeCheapReviewer({"decision": "approve_low_impact", "reason_code": "bounded_read_only", "extra": "no"})
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "git status --short && git diff --stat")

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision == "accept"
    assert cheap.calls == 1
    assert full.calls == 1
    assert full.reasons == ["shell metacharacters require LLM review"]


@pytest.mark.asyncio
async def test_cheap_review_unavailable_calls_full_supervisor(tmp_path: Path) -> None:
    cheap = FakeCheapReviewer(exc=RuntimeError("model unavailable"))
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "git status --short && git diff --stat")

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision == "accept"
    assert cheap.calls == 1
    assert full.calls == 1


@pytest.mark.asyncio
async def test_noncandidate_command_bypasses_cheap_and_calls_full_supervisor(tmp_path: Path) -> None:
    cheap = FakeCheapReviewer()
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "python -c \"print('x')\"")

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision == "accept"
    assert cheap.calls == 0
    assert full.calls == 1


@pytest.mark.asyncio
async def test_accept_not_offered_rejects_cheap_approval_and_uses_full_supervisor(tmp_path: Path) -> None:
    cheap = FakeCheapReviewer()
    full = FakeFullSupervisor(
        SupervisorDecision(
            decision=SupervisorDecisionKind.DENY,
            approval_decision=ApprovalDecisionKind.DECLINE,
            reason="full supervisor denied",
        )
    )
    ctx = command_context(tmp_path, "git status --short && git diff --stat", available=["decline", "cancel"])

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision in {"decline", "cancel"}
    assert cheap.calls == 0
    assert full.calls == 1


@pytest.mark.asyncio
async def test_full_supervisor_failure_after_cheap_escalation_fails_closed(tmp_path: Path) -> None:
    cheap = FakeCheapReviewer(CheapApprovalDecision(decision="escalate", reason_code="needs_task_judgment"))
    full = FakeFullSupervisor(exc=RuntimeError("full failed"))
    ctx = command_context(tmp_path, "git status --short && git diff --stat")

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision in {"decline", "cancel"}
    assert "supervisor approval fallback failed" in decision.reason
    assert cheap.calls == 1
    assert full.calls == 1


@pytest.mark.asyncio
async def test_full_supervisor_invalid_output_after_fallback_fails_closed(tmp_path: Path) -> None:
    cheap = FakeCheapReviewer(CheapApprovalDecision(decision="escalate", reason_code="needs_task_judgment"))
    full = FakeFullSupervisor(
        SupervisorDecision(
            decision=SupervisorDecisionKind.NOOP,
            approval_decision=None,
            reason="not an approval",
        )
    )
    ctx = command_context(tmp_path, "git status --short && git diff --stat")

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision in {"decline", "cancel"}
    assert "not an approval" in decision.reason
    assert cheap.calls == 1
    assert full.calls == 1


@pytest.mark.parametrize(
    ("method", "params"),
    [
        (
            "item/commandExecution/requestApproval",
            {
                "command": "curl https://example.com",
                "networkApprovalContext": {"host": "example.com", "protocol": "https"},
                "availableDecisions": ["accept", "decline"],
            },
        ),
        ("item/fileChange/requestApproval", {"grantRoot": "x", "availableDecisions": ["accept", "decline"]}),
        ("item/permissions/requestApproval", {"availableDecisions": ["accept", "decline"]}),
        ("item/tool/call", {"availableDecisions": ["accept", "decline"]}),
        ("item/tool/requestUserInput", {"availableDecisions": ["accept", "decline"]}),
        ("mcpServer/elicitation/request", {"availableDecisions": ["accept", "decline"]}),
        ("unknown/request", {"availableDecisions": ["accept", "decline"]}),
    ],
)
@pytest.mark.asyncio
async def test_non_command_request_boundaries_never_use_cheap_review(tmp_path: Path, method: str, params: dict) -> None:
    cheap = FakeCheapReviewer()
    full = FakeFullSupervisor()
    params = {"threadId": "t", "turnId": "u", "itemId": "i", **params}
    if method == "item/fileChange/requestApproval":
        params["grantRoot"] = str(tmp_path)
    ctx = normalize_approval_request(message(method, 200, params))

    await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert cheap.calls == 0


def test_runtime_triage_config_defaults_enabled_with_default_model(monkeypatch) -> None:
    from supervisor.approval_triage import DEFAULT_TRIAGE_MODEL, runtime_triage_config_from_env

    monkeypatch.delenv("SENTINEL_RUNTIME_TRIAGE_ENABLED", raising=False)
    monkeypatch.delenv("SENTINEL_RUNTIME_TRIAGE_MODEL", raising=False)
    config = runtime_triage_config_from_env()
    assert config.enabled is True
    assert config.model == DEFAULT_TRIAGE_MODEL


def test_runtime_triage_config_can_be_disabled(monkeypatch) -> None:
    from supervisor.approval_triage import runtime_triage_config_from_env

    monkeypatch.setenv("SENTINEL_RUNTIME_TRIAGE_ENABLED", "false")
    assert runtime_triage_config_from_env().enabled is False


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
