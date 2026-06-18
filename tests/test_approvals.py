from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from supervisor.approval_triage import CheapApprovalReviewer, cheap_approval_triage_config_from_env
from supervisor.appserver import AppServerMessage
from supervisor.approvals import ApprovalManager, normalize_approval_request
from supervisor.schemas import ApprovalDecisionKind, CheapApprovalDecision, SupervisorDecision, SupervisorDecisionKind


def message(method: str, request_id: int, params: dict) -> AppServerMessage:
    return AppServerMessage({"id": request_id, "method": method, "params": params})


def test_cheap_approval_triage_config_requires_separate_model(monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_APPROVAL_TRIAGE_ENABLED", "true")
    monkeypatch.delenv("SENTINEL_APPROVAL_TRIAGE_MODEL", raising=False)
    monkeypatch.setenv("SENTINEL_APPROVAL_TRIAGE_TIMEOUT", "3.5")

    config = cheap_approval_triage_config_from_env()

    assert config.enabled is True
    assert config.model is None
    assert config.timeout_seconds == 3.5


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
async def test_deterministic_allow_bypasses_cheap_and_full_review(tmp_path: Path) -> None:
    cheap = FakeCheapReviewer()
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "ls")

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision == "accept"
    assert cheap.calls == 0
    assert full.calls == 0


@pytest.mark.asyncio
async def test_deterministic_denial_bypasses_and_cannot_be_overridden_by_cheap_review(tmp_path: Path) -> None:
    cheap = FakeCheapReviewer()
    full = FakeFullSupervisor()
    ctx = command_context(tmp_path, "supervisor --task TASK.md")

    decision = await ApprovalManager(tmp_path, supervisor=full, cheap_reviewer=cheap).decide(ctx)

    assert decision.decision in {"decline", "cancel"}
    assert "supervisor" in decision.reason
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
    assert decision.reason == "bounded read-only command approved by cheap review"
    assert decision.persistent_decision is None
    assert decision.from_supervisor is False
    assert cheap.calls == 1
    assert full.calls == 0


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
