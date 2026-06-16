from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Protocol

from supervisor.appserver import AppServerMessage
from supervisor.policy import PolicyEngine, is_secret_path, normalize_path
from supervisor.schemas import (
    ApprovalContext,
    ApprovalRequestType,
    ApprovalResolution,
    NetworkApprovalContext,
    PolicyDecision,
    PolicyDecisionKind,
    SupervisorDecision,
    SupervisorDecisionKind,
)


COMMAND_APPROVAL_METHOD = "item/commandExecution/requestApproval"
FILE_CHANGE_APPROVAL_METHOD = "item/fileChange/requestApproval"
PERMISSIONS_APPROVAL_METHOD = "item/permissions/requestApproval"
TOOL_USER_INPUT_METHOD = "item/tool/requestUserInput"
DYNAMIC_TOOL_CALL_METHOD = "item/tool/call"
MCP_ELICITATION_METHOD = "mcpServer/elicitation/request"


class SupervisorApprovalReviewer(Protocol):
    async def decide_approval(self, context: ApprovalContext, reason: str) -> SupervisorDecision:
        ...


def normalize_approval_request(message: AppServerMessage) -> ApprovalContext:
    method = message.method or "unknown"
    params = message.params
    request_type = _request_type(method)
    command: str | None = None
    cwd: str | None = _string(params.get("cwd"))
    paths: list[str] = []
    file_changes: list[dict[str, Any]] = []
    diff: str | None = None
    grant_root: str | None = _string(params.get("grantRoot"))
    approval_id = _string(params.get("approvalId"))

    if request_type == ApprovalRequestType.COMMAND:
        command = _string(params.get("command"))
    elif request_type == ApprovalRequestType.FILE_CHANGE:
        if grant_root:
            paths.append(grant_root)
        raw_file_changes = params.get("fileChanges")
        if isinstance(raw_file_changes, dict):
            paths.extend(str(path) for path in raw_file_changes)
            file_changes.extend({"path": str(path), "change": change} for path, change in raw_file_changes.items())
        raw_changes = params.get("changes")
        if isinstance(raw_changes, list):
            paths.extend(_paths_from_changes(raw_changes))
            file_changes.extend(change for change in raw_changes if isinstance(change, dict))

    network = None
    raw_network = params.get("networkApprovalContext")
    if isinstance(raw_network, dict):
        network = NetworkApprovalContext(
            host=str(raw_network.get("host") or ""),
            protocol=str(raw_network.get("protocol") or ""),
            port=raw_network.get("port") if isinstance(raw_network.get("port"), int) else None,
        )

    return ApprovalContext(
        server_request_id=message.request_id if message.request_id is not None else "",
        server_request_method=method,
        request_type=request_type,
        thread_id=_string(params.get("threadId") or params.get("conversationId")),
        turn_id=_string(params.get("turnId")),
        item_id=_string(params.get("itemId") or params.get("callId")),
        approval_id=approval_id,
        command=command,
        cwd=cwd,
        paths=paths,
        file_changes=file_changes,
        diff=diff,
        grant_root=grant_root,
        network_approval_context=network,
        proposed_execpolicy_amendment=_list_of_strings(
            params.get("proposedExecpolicyAmendment") or params.get("proposed_execpolicy_amendment")
        ),
        proposed_network_policy_amendments=_list_or_none(
            params.get("proposedNetworkPolicyAmendments") or params.get("proposed_network_policy_amendments")
        ),
        available_decisions=params.get("availableDecisions") if isinstance(params.get("availableDecisions"), list) else None,
        raw_params=params,
    )


class ApprovalManager:
    def __init__(
        self,
        workspace: Path,
        *,
        supervisor: SupervisorApprovalReviewer | None = None,
        timeout_seconds: float = 180.0,
    ):
        self.workspace = workspace.resolve()
        self.policy = PolicyEngine(self.workspace)
        self.supervisor = supervisor
        self.timeout_seconds = timeout_seconds

    async def decide(self, context: ApprovalContext) -> ApprovalResolution:
        if context.request_type in {
            ApprovalRequestType.TOOL_USER_INPUT,
            ApprovalRequestType.DYNAMIC_TOOL_CALL,
            ApprovalRequestType.MCP_ELICITATION,
            ApprovalRequestType.PERMISSIONS,
            ApprovalRequestType.UNKNOWN,
        }:
            return self._deny(context, "unsupported approval/request type")

        if context.network_approval_context is not None:
            return await self._route_supervisor_or_deny(context, "network approval requires supervisor judgment")

        if context.request_type == ApprovalRequestType.FILE_CHANGE:
            file_decision = self._evaluate_file_change(context)
            if file_decision.kind == PolicyDecisionKind.ALLOW:
                return self._allow(context, file_decision.reason)
            if file_decision.kind == PolicyDecisionKind.DENY:
                return self._deny(context, file_decision.reason)
            return await self._route_supervisor_or_deny(context, file_decision.reason)

        payload: dict[str, Any] = {}
        if context.command:
            payload["command"] = context.command
        if context.cwd:
            payload["cwd"] = context.cwd
        policy_decision = self.policy.evaluate(payload)
        if policy_decision.kind == PolicyDecisionKind.ALLOW:
            return self._allow(context, policy_decision.reason)
        if policy_decision.kind == PolicyDecisionKind.DENY:
            return self._deny(context, policy_decision.reason)
        return await self._route_supervisor_or_deny(context, policy_decision.reason)

    def response_payload(self, context: ApprovalContext, resolution: ApprovalResolution) -> dict[str, Any]:
        method = context.server_request_method
        if method in {COMMAND_APPROVAL_METHOD, FILE_CHANGE_APPROVAL_METHOD}:
            return {"decision": resolution.decision}
        if method == TOOL_USER_INPUT_METHOD:
            return {"answers": {}}
        if method == DYNAMIC_TOOL_CALL_METHOD:
            return {"contentItems": [], "success": False}
        if method == PERMISSIONS_APPROVAL_METHOD:
            return {"permissions": {}, "scope": "turn", "strictAutoReview": True}
        if method == MCP_ELICITATION_METHOD:
            action = resolution.decision if isinstance(resolution.decision, str) and resolution.decision in {"decline", "cancel"} else "cancel"
            return {"action": action, "content": None, "_meta": None}
        return {"decision": resolution.decision}

    async def _route_supervisor_or_deny(self, context: ApprovalContext, reason: str) -> ApprovalResolution:
        if self.supervisor is None:
            return self._deny(context, reason)
        try:
            decision = await asyncio.wait_for(self.supervisor.decide_approval(context, reason), timeout=self.timeout_seconds)
        except Exception as exc:
            return self._deny(context, f"supervisor approval fallback failed: {exc.__class__.__name__}")
        if decision.decision == SupervisorDecisionKind.APPROVE and decision.approval_decision:
            approval = decision.approval_decision.value
            if approval not in {"accept", "acceptForSession"}:
                return self._deny(context, "supervisor approve used a denial decision")
            if decision.execpolicy_amendment:
                protocol_decision = {
                    "acceptWithExecpolicyAmendment": {"execpolicy_amendment": decision.execpolicy_amendment}
                }
                if (
                    approval == "accept"
                    and context.request_type == ApprovalRequestType.COMMAND
                    and self._is_exact_execpolicy_amendment_allowed(context, decision.execpolicy_amendment)
                ):
                    return ApprovalResolution(
                        decision=protocol_decision,
                        reason=decision.reason,
                        persistent_decision=decision.persistent_decision,
                        from_supervisor=True,
                    )
            if approval == "acceptForSession" and _accept_for_session_forbidden(context, self.workspace):
                return self._deny(context, "acceptForSession is forbidden for this approval class")
            if self._is_allowed(context, approval):
                return ApprovalResolution(
                    decision=approval,
                    reason=decision.reason,
                    persistent_decision=decision.persistent_decision,
                    from_supervisor=True,
                )
        if decision.decision == SupervisorDecisionKind.DENY and decision.approval_decision:
            denial = decision.approval_decision.value
            if denial not in {"decline", "cancel"}:
                return self._deny(context, "supervisor deny used an approval decision")
            if self._is_allowed(context, denial):
                return ApprovalResolution(decision=denial, reason=decision.reason, from_supervisor=True)
        return self._deny(context, decision.reason or "supervisor did not return an applicable approval decision")

    def _evaluate_file_change(self, context: ApprovalContext):
        raw_paths = list(context.paths)
        if context.grant_root and context.grant_root not in raw_paths:
            raw_paths.append(context.grant_root)
        if not raw_paths:
            return PolicyDecision.allow("app-server file-change approval without exposed paths treated as workspace edit")
        for raw in raw_paths:
            path = normalize_path(self.workspace, raw)
            if path is None:
                return PolicyDecision.route_llm(f"path escapes workspace or is ambiguous: {raw}")
            if ".supervisor" in path.parts:
                return PolicyDecision.deny("writes to supervisor runtime/state files are denied")
            if is_secret_path(path):
                return PolicyDecision.deny("writes to secret-pattern paths are denied")
        return PolicyDecision.allow("workspace file change inside workspace")

    def _allow(self, context: ApprovalContext, reason: str) -> ApprovalResolution:
        decision = "accept"
        if not self._is_allowed(context, decision):
            choices = ["accept"]
            if not _accept_for_session_forbidden(context, self.workspace):
                choices.append("acceptForSession")
            decision = self._first_allowed(context, choices) or self._deny_decision(context)
        return ApprovalResolution(decision=decision, reason=reason)

    def _deny(self, context: ApprovalContext, reason: str) -> ApprovalResolution:
        return ApprovalResolution(decision=self._deny_decision(context), reason=reason)

    def _deny_decision(self, context: ApprovalContext) -> str:
        return self._first_allowed(context, ["decline", "cancel"]) or "decline"

    def _first_allowed(self, context: ApprovalContext, choices: list[str]) -> str | None:
        for choice in choices:
            if self._is_allowed(context, choice):
                return choice
        return None

    def _is_allowed(self, context: ApprovalContext, decision: str | dict[str, Any]) -> bool:
        keys = context.available_decision_keys
        if keys is None:
            return True
        if isinstance(decision, str):
            return decision in keys
        return any(key in keys for key in decision)

    def _is_exact_execpolicy_amendment_allowed(self, context: ApprovalContext, amendment: list[str]) -> bool:
        if context.proposed_execpolicy_amendment == amendment:
            return True
        if context.available_decisions is None:
            return False
        for decision in context.available_decisions:
            if not isinstance(decision, dict):
                continue
            payload = decision.get("acceptWithExecpolicyAmendment")
            if not isinstance(payload, dict):
                continue
            offered = payload.get("execpolicy_amendment")
            if offered is None:
                offered = payload.get("proposed_execpolicy_amendment")
            if offered == amendment:
                return True
        return False


def _request_type(method: str) -> ApprovalRequestType:
    return {
        COMMAND_APPROVAL_METHOD: ApprovalRequestType.COMMAND,
        FILE_CHANGE_APPROVAL_METHOD: ApprovalRequestType.FILE_CHANGE,
        PERMISSIONS_APPROVAL_METHOD: ApprovalRequestType.PERMISSIONS,
        TOOL_USER_INPUT_METHOD: ApprovalRequestType.TOOL_USER_INPUT,
        DYNAMIC_TOOL_CALL_METHOD: ApprovalRequestType.DYNAMIC_TOOL_CALL,
        MCP_ELICITATION_METHOD: ApprovalRequestType.MCP_ELICITATION,
    }.get(method, ApprovalRequestType.UNKNOWN)


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _list_of_strings(value: Any) -> list[str] | None:
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    return None


def _list_or_none(value: Any) -> list[Any] | None:
    return list(value) if isinstance(value, list) else None


def _paths_from_changes(changes: list[Any]) -> list[str]:
    paths: list[str] = []
    for change in changes:
        if not isinstance(change, dict):
            continue
        for key in ("path", "filePath", "file_path"):
            value = change.get(key)
            if isinstance(value, str):
                paths.append(value)
    return paths


def _accept_for_session_forbidden(context: ApprovalContext, workspace: Path) -> bool:
    if context.network_approval_context is not None:
        return True
    if context.request_type == ApprovalRequestType.FILE_CHANGE:
        return _file_change_session_forbidden(context, workspace)
    if context.command:
        return _command_session_forbidden(context.command)
    return False


def _file_change_session_forbidden(context: ApprovalContext, workspace: Path) -> bool:
    paths = list(context.paths)
    if context.grant_root and context.grant_root not in paths:
        paths.append(context.grant_root)
    if not paths:
        return True
    for raw in paths:
        path = normalize_path(workspace, raw)
        if path is None:
            return True
        if ".supervisor" in path.parts or is_secret_path(path):
            return True
    return False


def _command_session_forbidden(command: str) -> bool:
    lowered = command.lower()
    destructive = ("rm -rf", "rm -fr", "rmdir", "unlink", "del /", "remove-item")
    deploy_publish = ("deploy", "publish", "release", "npm publish", "twine upload", "docker push")
    git_mutation = (
        "git push",
        "git commit",
        "git reset",
        "git checkout",
        "git switch",
        "git rebase",
        "git merge",
        "git tag",
        "git branch",
        "git clean",
    )
    secret_terms = ("secret", ".env", "credential", "token", "password", "private_key", "id_rsa")
    return any(term in lowered for term in destructive + deploy_publish + git_mutation + secret_terms)
