from __future__ import annotations

from pathlib import Path

import pytest

from supervisor.appserver import AppServerMessage
from supervisor.approvals import ApprovalManager, normalize_approval_request
from supervisor.schemas import ApprovalDecisionKind, SupervisorDecision, SupervisorDecisionKind


def message(method: str, request_id: int, params: dict) -> AppServerMessage:
    return AppServerMessage({"id": request_id, "method": method, "params": params})


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
