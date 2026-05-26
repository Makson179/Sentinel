Verdict: **do not implement this plan unchanged.** The high-level architecture is correct: Codex-only terminal app, app-server, persistent coder thread, stateless supervisor calls, supervisor-owned approvals, no hooks/plugin/subagent/`codex exec` runtime. That is the right direction. 

I found actual implementation-blocking or correctness-affecting omissions. These should be patched into the plan before Codex starts coding.

1. **Startup order is still wrong.**

The plan starts the initial coder turn before starting the TUI and event loop. That risks missing early notifications, approval requests, or streamed events. App-server docs say that after `turn/start`, the client must keep reading notifications from the active transport stream. ([OpenAI Developers][1])

Change startup to:

```text
1. Validate project directory.
2. Resolve task file or show selector.
3. Initialize .supervisor.
4. Start codex app-server --listen stdio://.
5. Send initialize and initialized.
6. Start app-server reader task.
7. Start TUI/controller event loop.
8. Run auth/model/config/schema preflights.
9. Start persistent coder thread.
10. Start initial coder turn.
```

The current plan has “start initial coder turn” before “start TUI and event loop.” That must be fixed. 

2. **It still lacks app-server schema/version pinning.**

App-server is documented as “primarily for development and debugging” and may change without notice, while the app-server docs provide version-specific schema generation commands. ([OpenAI Developers][2]) ([OpenAI Developers][1])

Add a required preflight:

```text
Run codex --version.
Run codex app-server generate-json-schema --out .supervisor/appserver-schema.
Hash the schema directory.
Store codex_version and appserver_schema_hash in config.json.
Validate fake app-server fixtures and live smoke-test messages against this schema.
Fail startup if required methods or fields are absent.
```

Without this, the implementation can silently break when Codex changes app-server message shapes.

3. **Auth/model preflight is missing.**

The plan starts app-server and checks `configRequirements/read`, but it does not verify that Codex is logged in, usable, and has an available model before starting the run. App-server exposes `account/read`, `account/login/start`, `account/rateLimits/read`, and `model/list`; `model/list` is specifically for discovering available models before clients render or select models. ([OpenAI Developers][1]) ([OpenAI Developers][1])

Add:

```text
Call account/read.
If requiresOpenaiAuth is true and account is null, stop before coder start.
Call model/list.
Select the default model unless user configured another model.
Run one trivial structured-output supervisor self-test.
Optionally call account/rateLimits/read and fail cleanly if usage is exhausted.
```

4. **The approval schema is still wrong for `acceptWithExecpolicyAmendment`.**

The plan lists `acceptWithExecpolicyAmendment` as if it were a string enum inside `approval_decision`. That is incorrect. App-server command approval decisions can be strings, but `acceptWithExecpolicyAmendment` is an object shape: `{ "acceptWithExecpolicyAmendment": { "execpolicy_amendment": [...] } }`. File-change approvals do not support that object. ([OpenAI Developers][1])

Replace this:

```text
approval_decision: accept | acceptForSession | decline | cancel | acceptWithExecpolicyAmendment | null
```

with this:

```text
approval_decision: accept | acceptForSession | decline | cancel | null
execpolicy_amendment: string[] | null
```

Controller rule:

```text
Only emit acceptWithExecpolicyAmendment for command approval requests.
Only emit it if availableDecisions permits it.
Never emit it for file-change approvals.
```

5. **Approval handling still does not explicitly preserve the JSON-RPC server-request id.**

The plan preserves `threadId`, `turnId`, `itemId`, command, cwd, paths, diff, network context, and `availableDecisions`, but it does not explicitly preserve the server-initiated JSON-RPC request id. The client must answer the specific server request. App-server approvals are server-initiated JSON-RPC requests, and `serverRequest/resolved` confirms that the pending request was answered or cleared. ([OpenAI Developers][1]) ([OpenAI Developers][1])

Add to `ApprovalContext`:

```text
server_request_id
server_request_method
thread_id
turn_id
item_id
request_id when present
available_decisions
```

6. **MCP/app approval handling is underspecified.**

The plan says policy should classify MCP/app actions and approvals should normalize app-server server requests, but it does not define how `tool/requestUserInput` is handled. App-server uses `tool/requestUserInput` for side-effecting app/connector tool approvals; this is not the same payload shape as command or file-change approval. ([OpenAI Developers][1]) ([OpenAI Developers][1])

Add one of these two choices:

```text
MVP choice A:
  Disable/ignore apps, MCP, and dynamic tools.
  If tool/requestUserInput or item/tool/call appears, cancel/decline fail-closed.

MVP choice B:
  Implement tool/requestUserInput explicitly:
    preserve server_request_id
    preserve tool/app name
    preserve user-facing options
    map Accept/Decline/Cancel exactly to the offered option ids
    fail closed if the option mapping is unclear
```

For easiest implementation, choose **A** for MVP.

7. **Unsupported app-server surfaces must be explicitly fail-closed.**

The plan says unknown request types cancel/decline, but it does not explicitly ban dangerous app-server APIs. App-server documents `thread/shellCommand` and `process/*` as running outside the normal Codex sandbox; `thread/shellCommand` runs outside the sandbox with full access, and `process/*` is explicit process control outside Codex’s sandbox. ([OpenAI Developers][1]) ([OpenAI Developers][1])

Add:

```text
Sentinel must not expose these APIs to the coder path:
  thread/shellCommand
  process/*
  dynamicTools
  Computer Use / Browser Use
  external app tools unless tool/requestUserInput handler is implemented

If such a request appears:
  cancel if possible;
  otherwise decline;
  log unsupported_request;
  wake supervisor with fail-closed context.
```

8. **`turn/steer` is missing `expectedTurnId`.**

The plan says interventions use `turn/steer` when the coder is active, but app-server requires `expectedTurnId`, and the request fails if there is no active turn. It also does not accept turn-level overrides. ([OpenAI Developers][1])

Add:

```text
turn/steer always includes:
  threadId = coder_thread_id
  expectedTurnId = active_coder_turn_id
  input = supervisor message

If active_coder_turn_id is missing or stale:
  do not steer;
  start a new coder turn instead.
```

9. **Runtime IDs are not specified in `config.json`.**

The plan creates `config.json` but does not say it must store the identifiers needed for crash recovery. Yet crash recovery says to read/resume the previous coder thread and inspect turns. App-server supports `thread/resume`, `thread/read`, and `thread/turns/list`; Sentinel must persist the relevant IDs to use them after restart. ([OpenAI Developers][1])

Add required `config.json` fields:

```json
{
  "project_root": "...",
  "task_path": "...",
  "task_hash": "...",
  "codex_version": "...",
  "appserver_schema_hash": "...",
  "coder_thread_id": "...",
  "active_coder_turn_id": "...",
  "generation": 1,
  "restart_count": 0,
  "max_restarts": 3,
  "last_event_sequence": 0,
  "last_applied_supervisor_sequence": 0,
  "pending_server_request_ids": []
}
```

10. **Stale supervisor decisions are not handled.**

The plan wakes a stateless supervisor after every completed coder action, approval request, user message, timer tick, and turn completion. That creates races. A non-approval supervisor call may return after the coder has already moved on. The old `PLAN.md` had stale-response discard logic; the new plan does not carry it over. The old plan explicitly used generation and sequence checks before applying LLM responses. 

Add:

```text
Every supervisor wake packet includes:
  wake_sequence
  generation
  coder_thread_id
  active_coder_turn_id
  triggering_item_id
  triggering_server_request_id when applicable
  latest_event_sequence

Approval supervisor calls are blocking for that approval request.

Non-approval supervisor checks are coalesced:
  if a check is running, mark supervisor_check_dirty = true;
  when it finishes, discard if stale;
  if dirty, run one new check over the latest state.

Apply decision only if:
  generation still matches;
  coder_thread_id still matches;
  pending approval still exists when applicable;
  decision sequence is newer than last_applied_supervisor_sequence.
```

11. **Restart must wait for interruption and approval resolution before starting the new coder.**

The restart flow interrupts the active coder turn, resolves pending approvals, and starts a fresh coder thread. It does not say to wait for the old turn to actually complete or for `serverRequest/resolved`. That can leave two generations running or leave a dangling approval request. App-server emits `serverRequest/resolved` when pending approval is answered or cleared. ([OpenAI Developers][1])

Change restart to:

```text
1. Set status = restarting.
2. Stop accepting new autonomous actions.
3. Interrupt active coder turn.
4. Cancel/decline all pending approvals.
5. Wait for turn completed/interrupted/failed and serverRequest/resolved.
6. Write HANDOFF.md.
7. Increment generation/restart_count.
8. Archive or mark old coder thread as superseded.
9. Start fresh coder thread.
10. Start new coder turn from task + DECISIONS + PROGRESS + HANDOFF.
```

12. **Restart cap is mentioned but not defined operationally.**

The plan says `health.py` has a restart count cap, but the runtime flow and acceptance criteria do not define the actual cap or stuck behavior. The old plan had a hard `restart_count >= 3` stuck exit. 

Add:

```text
Default max_restarts = 3.

If restart_count >= max_restarts:
  interrupt coder;
  resolve pending approvals;
  write HANDOFF.md;
  write FINAL_REPORT.md with status = stuck;
  exit cleanly.
```

13. **Provider/app-server error policy is missing.**

The plan has app-server crash recovery but not turn/provider failure handling. App-server documents turn failure errors including `ContextWindowExceeded`, `UsageLimitExceeded`, `HttpConnectionFailed`, `ResponseStreamConnectionFailed`, `BadRequest`, `Unauthorized`, `SandboxError`, and `InternalServerError`. ([OpenAI Developers][1])

Add:

```text
On Unauthorized or UsageLimitExceeded:
  write HANDOFF.md;
  write FINAL_REPORT.md with status = provider_failure;
  exit cleanly.

On ContextWindowExceeded in coder thread:
  run supervised restart with HANDOFF.md.

On transient HTTP/stream/internal errors:
  bounded retry;
  if retry fails, write HANDOFF.md and exit cleanly.

On SandboxError:
  wake supervisor with error context;
  if repeated, restart or fail cleanly.
```

14. **Supervisor thread cleanup is missing.**

The supervisor is stateless and starts a fresh app-server thread per decision. The plan does not say what happens to those threads. App-server has `thread/archive` and `thread/unsubscribe`; without cleanup, the product will leak stored supervisor threads. ([OpenAI Developers][1])

Add:

```text
After each supervisor decision:
  persist decision to Sentinel state;
  archive or unsubscribe supervisor thread;
  never resume supervisor threads;
  never use supervisor thread history as memory.
```

15. **Diff summary generation is not specified.**

The plan requires current/final diff summaries in supervisor packets and completion, but it does not define who computes them. Completion requires a final diff summary. 

Add:

```text
Sentinel controller computes diff summaries directly, not through the coder:
  git status --short
  git diff --stat
  git diff --name-only

Run with timeout.
Treat failure as "diff unavailable" and include error in supervisor packet.
Never let coder fabricate final diff summary.
```

This is safe because the controller is the supervisor runtime, and these are read-only local inspection commands.

16. **Exact TUI visual contract is still underspecified.**

The plan says visible rendering for coder messages, tool actions, approvals, supervisor decisions, denials, interventions, restarts, and final summary. That is not enough for your stated product requirement: one chat with distinguishable supervisor and coder lanes/colors. 

Add:

```text
TUI rendering:
  [SUPERVISOR] default/white
  [CODER] green
  [TOOL] dim
  [APPROVAL] yellow
  [DENIED] red
  [USER] blue/gray
  [SYSTEM] dim

The stream is chronological.
Human text is always rendered as USER → SUPERVISOR.
Supervisor-originated steer/restart/deny messages are rendered before application.
```

17. **Config requirements gate is too narrow.**

The plan checks `configRequirements/read` and hard-fails unless `onRequest` and `readOnly` are allowed. That is necessary, but not sufficient. `configRequirements/read` reports admin-enforced constraints and may return `null` if no requirements are configured. ([OpenAI Developers][1]) Managed requirements can constrain approval policies and sandbox modes, but Sentinel still needs a live self-test of the actual requested coder turn settings. ([OpenAI Developers][3])

Add:

```text
After configRequirements/read:
  start a throwaway thread/turn with coder sandbox/approval config;
  verify it starts successfully;
  interrupt/archive it;
  fail startup if the requested config is rejected or altered.
```

18. **The integration smoke tests dropped structured-output and approval coverage in the shorter version.**

The longer uploaded plan includes `outputSchema` supervisor turn and approval-answer smoke tests. The shorter pasted plan’s integration tests list app-server start, initialize, thread/turn, steer, interrupt, restart path, but omits the structured-output and approval-answer smoke tests. Those must stay. 

Required integration smoke tests:

```text
outputSchema supervisor turn returns structured JSON
command approval request can be answered by client
file-change approval request can be answered by client
networkApprovalContext approval is parsed correctly if available
```

Final recommendation: approve the plan **only after these 18 fixes are inserted**. The architecture is right, but the current text still leaves too many protocol-level details undefined for Codex to implement safely in one pass.

[1]: https://developers.openai.com/codex/app-server "App Server – Codex | OpenAI Developers"
[2]: https://developers.openai.com/codex/cli/reference "Command line options – Codex CLI | OpenAI Developers"
[3]: https://developers.openai.com/codex/enterprise/managed-configuration "Managed configuration – Codex | OpenAI Developers"
