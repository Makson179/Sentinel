# Sentinel Approval Review Mechanism

This report explains how Sentinel handles approval requests from the Codex
app-server, when the deterministic policy decides alone, and when the runtime
supervisor is asked to review the coder's requested action.

The short version:

1. Codex app-server asks Sentinel for approval.
2. Sentinel normalizes the request into an `ApprovalContext`.
3. `ApprovalManager` runs deterministic checks first.
4. Clearly safe requests are approved.
5. Clearly unsafe or unsupported requests are denied.
6. Ambiguous requests are routed to the runtime supervisor when available.
7. If the supervisor is unavailable, invalid, slow, or gives an unusable answer,
   Sentinel denies the request.

This is runtime supervision, not completion review. The approval supervisor can
approve, deny, intervene, restart, pause, or no-op, but approval handling only
uses the `approve` and `deny` shapes to resolve the pending app-server request.

## Main Files

- `supervisor/controller.py`
  - `handle_server_request`
  - `decide_approval`
- `supervisor/approvals.py`
  - `normalize_approval_request`
  - `ApprovalManager.decide`
  - `ApprovalManager._route_supervisor_or_deny`
- `supervisor/policy.py`
  - `PolicyEngine.evaluate`
  - command, path, secret, and destructive-action classifiers
- `supervisor/schemas/models.py`
  - `ApprovalContext`
  - `ApprovalResolution`
  - `ApprovalWakeContext`
  - `SupervisorDecision`
- `supervisor/prompts/prompts.toml`
  - runtime supervisor approval instructions
- `tests/test_approvals.py`
  - approval-manager behavior and fail-closed cases
- `tests/test_policy.py`
  - deterministic policy behavior

## Request Entry Point

Approval requests enter through `SentinelController.handle_server_request`.
The app-server sends a server request when the coder wants to do something that
requires permission, such as executing a command, changing files, requesting
network access, expanding permissions, calling a dynamic tool, or asking for
tool/user input.

The controller immediately normalizes the raw app-server message:

```text
AppServerMessage -> normalize_approval_request(...) -> ApprovalContext
```

Then the controller records the request as pending runtime state:

- it stores the request in `self.pending_approvals`;
- it writes `pending_server_request_ids` into `SentinelConfig`;
- it appends an approval event to the event log;
- it delegates the actual decision to `self.approvals.decide(context)`.

If the run has already reached terminal cleanup, the controller denies the
request instead of letting late app-server activity mutate the final state.

## Normalized Approval Context

`normalize_approval_request` converts protocol-specific request shapes into a
single `ApprovalContext`.

The normalized context can contain:

- `server_request_id`
- `server_request_method`
- `request_type`
- `thread_id`
- `turn_id`
- `item_id`
- `approval_id`
- `command`
- `cwd`
- `paths`
- `file_changes`
- `grant_root`
- `network_approval_context`
- `proposed_execpolicy_amendment`
- `proposed_network_policy_amendments`
- `available_decisions`
- `raw_params`

The `request_type` is derived from the app-server method:

- `item/commandExecution/requestApproval` -> command approval
- `item/fileChange/requestApproval` -> file-change approval
- `item/permissions/requestApproval` -> permissions approval
- `item/tool/requestUserInput` -> tool user input
- `item/tool/call` -> dynamic tool call
- `mcpServer/elicitation/request` -> MCP elicitation
- anything else -> unknown

This normalization matters because the rest of the system does not need to know
every app-server wire shape. It can evaluate a single structured object.

## Deterministic First Layer

`ApprovalManager.decide` is the decision hub.

It deliberately tries deterministic policy before involving the runtime
supervisor. This keeps common safe actions cheap and fast, and it keeps obvious
unsafe actions away from the model.

The deterministic layer can return one of three policy outcomes:

```text
allow
deny
route_llm
```

`allow` becomes an approval response when the app-server offered a compatible
approval decision.

`deny` becomes a denial response.

`route_llm` means deterministic policy does not know enough, so the request can
be routed to the runtime supervisor if a supervisor is configured.

For command approvals, a `route_llm` policy result also carries structured
command-analysis facts when parsing succeeds far enough to classify the request:

- parsed command segments and their executables;
- shell composition operators;
- workspace-relative resolved paths;
- deterministic risk tags such as `network`, `shell_redirection`,
  `command_substitution`, `unknown_executable`, `interpreter_execution`,
  `git_mutation`, `filesystem_write`, `secret_path`, `workspace_escape`,
  `destructive`, `permission_change`, `dependency_mutation`,
  `process_or_service_control`, `deploy_publish_release`, and
  `ambiguous_parse`;
- a `cheap_review_candidate` boolean.

These facts do not weaken deterministic policy. They only let the approval
manager decide whether an unresolved command is eligible for the optional cheap
mechanical review path.

## Unsupported Requests Fail Closed

Some app-server request types are currently unsupported in the approval manager:

- tool user input
- dynamic tool calls
- MCP elicitation
- permission expansion
- unknown request methods

These are denied directly as `unsupported approval/request type`.

This is intentional fail-closed behavior. Sentinel should not silently invent a
safe mapping for protocol surfaces it does not understand yet.

## Network Requests

If `network_approval_context` is present, Sentinel routes the request to the
runtime supervisor if possible:

```text
network approval requires supervisor judgment
```

If no supervisor is available, the request is denied.

Network is not deterministically approved because task relevance depends on
context: downloading dependencies, querying docs, contacting a local service,
or reaching an external host have different risk profiles.

The runtime supervisor sees the network context in the approval packet and must
choose from the available protocol decisions.

## File-Change Requests

File-change approvals use `_evaluate_file_change`.

The deterministic rules are:

- If the app-server exposes no paths, treat it as a workspace edit and allow.
- If a path escapes the workspace or is ambiguous, route to supervisor.
- If a path touches `.supervisor`, deny.
- If a path matches a secret pattern, deny.
- Otherwise allow as `workspace file change inside workspace`.

The `.supervisor` denial is important because `.supervisor/` is live Sentinel
runtime state. If the coder can mutate it, it can corrupt controller state,
pending approvals, progress, logs, or finalization artifacts.

## Command Requests

Command approvals are evaluated by `PolicyEngine.evaluate`.

The policy extracts paths, resolves them relative to the workspace, checks
secret patterns, and then classifies the command.

Examples of deterministic allows:

- read-only git commands like `git status`, `git log`, `git diff`;
- version checks for `python`, `python3`, `node`, `pytest`, and `npm`;
- informational commands like `ls` and `pwd`;
- bounded `find`;
- read-file commands like `cat`, `head`, `sed`, `tail`, `wc` when paths are
  inside the workspace and not secret-pattern paths;
- valid `apply_patch` edits inside the workspace and not touching secrets.

Examples of deterministic denials:

- commands invoking the Sentinel CLI (`sentinel`, plus the legacy
  `supervisor` executable name);
- commands containing `supervisor`;
- remote code execution pipelines like `curl ... | bash`;
- force pushes to protected branches;
- broad permission changes;
- recursive deletion outside the workspace;
- writes to secret-pattern paths.

Examples of route-to-supervisor cases:

- shell metacharacters such as pipes, redirects, command substitution, or command
  separators;
- unparsed shell commands;
- unknown commands outside the deterministic allow list;
- secret-pattern reads;
- write tools without a clear workspace path;
- ambiguous paths.

The exact current rule for Sentinel CLI invocations is path-aware enough to
catch `sentinel`, `sentinel.exe`, and the legacy `supervisor` executable name.
There is also a broad legacy rule for commands containing `supervisor`: if the
command string contains `supervisor`, the policy denies it. That protects
runtime state aggressively, but it can also deny benign commands that merely
mention the word.

## Cheap Command Approval Triage

If `SENTINEL_APPROVAL_TRIAGE_ENABLED=true` and
`SENTINEL_APPROVAL_TRIAGE_MODEL` is configured and passes its strict structured
output self-test, eligible command approvals can be reviewed by a separate cheap
model before the runtime supervisor.

The cheap reviewer uses its own prompt and the strict `CheapApprovalDecision`
schema:

```text
decision: approve_low_impact | escalate
reason_code:
  bounded_read_only
  needs_task_judgment
  possible_side_effect
  sensitive_or_ambiguous
  unsupported_request
```

`approve_low_impact` is valid only with `bounded_read_only`. It maps only to the
plain app-server decision `accept`, with a local Sentinel reason:

```text
bounded read-only command approved by cheap review
```

The cheap reviewer cannot deny, return `acceptForSession`, grant persistent
approval, amend exec or network policy, steer the coder, restart or pause the
run, update progress, write decisions, or resolve non-command approval requests.
It must return `escalate` whenever the command requires task judgment,
usefulness judgment, risk trade-off judgment, or any fact not provided in the
small mechanical packet.

The deterministic candidate gate must pass before the cheap model is called.
The gate requires a command approval, `route_llm`, a command and cwd, parsed
segments, only supported read-only executables, paths inside the workspace, no
secret paths, no network, no writes, no redirects, no substitutions, no
background execution, no interpreter execution, no git mutation, no dependency
or environment mutation, no permission change, no process/service control, no
deployment/publish/release side effect, no destructive operation, no ambiguous
parse, and a compatible plain `accept` decision.

Representative candidates:

- `git status --short && git diff --stat`
- `git diff --name-only | head -n 20`
- `find src -maxdepth 2 -type f | sort`
- `rg "ApprovalManager" src tests | head`
- `cat pyproject.toml | head -n 80`

Representative noncandidates:

- redirects such as `git diff > /tmp/diff.txt`;
- command or process substitution;
- network commands such as `curl` or `wget`;
- interpreter execution such as `python -c`, `node -e`, or `sh -c`;
- dependency installation such as `npm install` or `pip install`;
- git mutation such as `git add`, `git commit`, or `git push`;
- permission changes, destructive commands, secret paths, workspace escapes, and
  unknown executables.

Cheap-review failure is not a denial while the full supervisor is available.
Timeouts, exceptions, unavailable models, invalid JSON, schema-invalid output,
unknown decision values, extra fields, `escalate`, or failed local validation
all fall back to the full supervisor.

## Supervisor Routing

When deterministic policy returns `route_llm` and cheap command triage is not
eligible, disabled, unavailable, shadowed by local validation, or returns
`escalate`, `ApprovalManager` calls:

```text
supervisor.decide_approval(context, reason)
```

In the real controller, that method is `SentinelController.decide_approval`.
It builds a runtime supervisor packet containing:

- wake sequence;
- current summary: `Approval request needs judgment: ...`;
- current diff summary;
- triggering server request id;
- the current approval context;
- all pending approvals;
- last coder message;
- validation ledger;
- prior interventions;
- changed files;
- patch summary from the approval request or current workspace.

Then it calls:

```text
self.supervisor.decide(packet)
```

This uses the runtime supervisor prompt, not the completion-review prompt.

The full supervisor is isolated from cheap-review output. When fallback occurs,
it receives the original normalized `ApprovalContext` and original deterministic
routing reason. Cheap decisions, reason codes, raw responses, exception text,
and prompt contents are not appended to progress, decisions, handoff,
last-action state, or runtime-supervisor packets. Sanitized cheap-review
diagnostics are written only after final approval resolution and are kept in the
raw log, which is not used to build supervisor packets.

## Runtime Supervisor Contract For Approvals

The runtime supervisor output schema is `SupervisorDecision`.

The relevant decisions for approval requests are:

- `approve`
- `deny`

For `approve`, the supervisor must set `approval_decision` to one of:

- `accept`
- `acceptForSession`

For `deny`, the supervisor must set `approval_decision` to one of:

- `decline`
- `cancel`

The supervisor may also provide:

- `reason`
- `persistent_decision`
- `progress_update`
- `display_message`

But approval resolution only uses the fields that can safely map back to the
app-server protocol.

The runtime supervisor prompt says:

- approve when the action is task-relevant, scoped, and justified;
- deny when the action is unjustified, out of scope, irreversible without need,
  or externally visible without authorization;
- use `acceptForSession` only when offered for a narrow, repeating,
  structurally safe action;
- use only the exact exec-policy amendment offered by the app-server.

## Mapping Supervisor Output Back To App-Server Decisions

`ApprovalManager._route_supervisor_or_deny` validates the supervisor decision
before trusting it.

Approval is accepted only if:

- the supervisor decision is `approve`;
- `approval_decision` is `accept` or `acceptForSession`;
- that decision is actually present in `available_decisions`, unless the request
  did not provide an available-decision list;
- `acceptForSession` is not forbidden for the request class;
- any exec-policy amendment exactly matches the app-server-offered amendment.

Denial is accepted only if:

- the supervisor decision is `deny`;
- `approval_decision` is `decline` or `cancel`;
- that decision is compatible with `available_decisions`.

If the supervisor returns the wrong shape, such as `approve` with `decline`, or
`deny` with `accept`, Sentinel denies the request.

If the supervisor times out or raises an exception, Sentinel denies the request.

If the supervisor returns a decision that cannot be mapped to the offered
protocol decisions, Sentinel denies the request.

This keeps the model from expanding its own authority beyond the app-server's
current approval options.

## Session-Wide Approval Guard

`acceptForSession` is more powerful than `accept`, so Sentinel forbids it for
risky classes.

Session approval is forbidden for:

- network approvals;
- file changes with no exposed paths;
- file changes touching `.supervisor`;
- file changes touching secret-pattern paths;
- commands involving destructive operations;
- deploy, publish, or release operations;
- git mutation commands;
- commands mentioning secrets, credentials, tokens, passwords, private keys, or
  similar sensitive terms.

For these cases, even if the runtime supervisor asks for `acceptForSession`,
Sentinel converts the result to denial.

## Response Payloads

After deciding, the controller sends a protocol-specific response back to the
app-server using `client.respond`.

Common mappings:

- command approval -> `{"decision": ...}`
- file-change approval -> `{"decision": ...}`
- tool user input -> `{"answers": {}}`
- dynamic tool call -> `{"contentItems": [], "success": false}`
- permissions request -> `{"permissions": {}, "scope": "turn", "strictAutoReview": true}`
- MCP elicitation -> `{"action": "decline"|"cancel", "content": null, "_meta": null}`

Most unsupported surfaces are denied before this mapping, but the response
payload still has to match the app-server protocol shape.

## What The Coder Sees

If an approval is accepted, the app-server continues the coder's requested
operation.

If an approval is denied, the controller renders a `DENIED` lane message and
steers the coder with the denial reason:

```text
await self.coder.steer_or_start(resolution.reason)
```

It also increments denied-request health accounting and records the last denial.

This means a denial is not silent. It becomes feedback to the coder so the coder
can choose a safer or narrower next step.

## Relationship To Runtime Review

Approval review is one kind of runtime supervisor wake.

It is different from post-action runtime review:

- approval review happens before the requested action executes;
- post-action runtime review happens after a command/tool/file action completes
  and a trigger fires, such as nonzero exit, timeout, masked validation, large
  diff, suspicious file touched, or restart budget.

It is also different from completion review:

- approval review cannot accept the task as complete;
- completion review cannot approve a pending app-server command;
- completion review decides only `accept`, `return`, or `restart`;
- approval review uses runtime decisions such as `approve` and `deny`.

## Failure And Safety Properties

The mechanism is intentionally conservative:

- Unsupported request types are denied.
- Missing supervisor means ambiguous requests are denied.
- Supervisor timeout means denial.
- Invalid supervisor approval shape means denial.
- Supervisor approval not offered by app-server means denial.
- Session-wide approval is blocked for risky classes.
- Secret writes and `.supervisor` writes are denied deterministically.
- The app-server request id remains tracked as pending until resolved.

This design makes Sentinel slower or more restrictive in some edge cases, but it
prevents the coder from using approval prompts as an escape hatch around
workspace, network, secret, runtime-state, or protocol boundaries.

## Useful Test Coverage

`tests/test_approvals.py` covers:

- available-decisions constraints;
- network approval routing or denial;
- exact exec-policy amendment handling;
- file-change approvals not emitting command amendments;
- file-change approvals without exposed paths;
- invalid supervisor approve/deny shapes failing closed;
- `acceptForSession` rejection for forbidden classes;
- exec-policy amendment mismatch fallback.

`tests/test_policy.py` covers:

- symlink/path escape routing;
- secret read routing and secret write denial;
- read-only tool fast paths;
- `apply_patch` workspace allow and secret denial;
- Sentinel CLI invocation denial;
- broad command denials such as commands containing `supervisor`, remote
  execution pipelines, force pushes, and broad chmod.

## Operational Reading

When you see a log line like:

```text
[APPROVAL] accept: workspace file change inside workspace
```

the deterministic file-change policy probably allowed it.

When you see:

```text
[DENIED] decline: writes to supervisor runtime/state files are denied
```

the deterministic file-change policy denied it before the supervisor was asked.

When you see a supervisor wake with:

```text
Approval request needs judgment: command is not in deterministic allow list
```

the deterministic layer could not decide, so the runtime supervisor reviewed
the request using task context, current diff, pending approvals, validation
state, and recent coder state.

The important mental model is:

```text
app-server approval request
  -> normalize
  -> deterministic policy
      -> allow: respond accept if protocol permits
      -> deny: respond decline/cancel
      -> route_llm: ask runtime supervisor
          -> valid approve: respond accept or exact offered amendment
          -> valid deny: respond decline/cancel
          -> invalid/timeout/unavailable: deny
```

That is the whole approval-review mechanism in Sentinel.
