# Sentinel Codex App-Server Implementation Plan

## Intent

Rebuild this project into Sentinel: a Codex-only terminal supervisor that drives `codex app-server --listen stdio://`.

Sentinel must not be implemented as a Codex hook wrapper, a `codex exec --json` controller, a plugin, or a subagent workflow. The terminal app owns orchestration, state, approvals, supervision, restart, steering, interruption, and completion. Codex remains the persistent coder through the app-server protocol.

## Current Repository Starting Point

The repository currently contains an older supervisor MVP:

- `supervisor/main.py` exposes `supervisor claude` and `supervisor codex` subcommands.
- `supervisor/wrapper.py` launches vendor CLIs and uses hook/IPC supervision.
- `supervisor/adapters/`, `supervisor/hooks/`, and `supervisor/ipc/` support the old hook architecture.
- `supervisor/llm_driver/codex.py` uses `codex exec --output-schema` for supervisor calls.
- Existing tests validate the old hook/exec behavior.

The Sentinel migration should keep useful logic where it still applies, especially atomic state writes, health counters, schema validation patterns, path safety, and deterministic policy code. The primary runtime should move away from hooks and `codex exec`.

## Product Contract

- One terminal app owns the event loop, state, approvals, user input, supervision, steering, interruption, restart, and completion.
- The coder is a persistent Codex app-server thread.
- The supervisor is stateless. Every supervision decision starts a fresh app-server thread/turn with compact context and strict `outputSchema`.
- The human talks only to Sentinel/supervisor, never directly to the coder.
- Coder actions that require permission use Codex app-server server-request approval flow.
- Sentinel answers approval requests automatically.
- Sentinel supervises actions and approvals, but does not promise perfect pre-read isolation for every readable file.

## CLI

Supported commands:

```text
supervisor
supervisor --task TASK.md
```

Rules:

- `--task` must exist and must end in `.md`.
- Without `--task`, scan for markdown task candidates.
- Exclude `.git`, `.supervisor`, `node_modules`, `vendor`, `dist`, `build`, `target`, `.venv`, and `venv`.
- Rank `TASK.md`, `task.md`, `PLAN.md`, `plan.md`, and `TODO.md` first.
- Abort before Codex starts if no markdown task candidate exists.
- If multiple candidates exist, show a simple terminal selector.

The old `supervisor claude` and `supervisor codex` hook-wrapper commands should be removed or made non-primary after migration.

## Runtime Defaults

Coder turn config:

```json
{
  "approvalPolicy": "onRequest",
  "sandboxPolicy": {
    "type": "readOnly",
    "access": {
      "type": "restricted",
      "includePlatformDefaults": true,
      "readableRoots": ["<project_root>"]
    }
  }
}
```

Supervisor turn config:

- Approval policy: `never`
- Sandbox: `readOnly`
- Fresh app-server thread per supervisor wake-up
- Strict `outputSchema`
- Timeout fallback: decline or cancel approval; never ask the human
- Supervisor threads are ephemeral. Persist the decision to Sentinel state, then archive or unsubscribe the supervisor thread. Never resume supervisor threads or use their thread history as memory.

Wake supervisor after:

- every completed coder action;
- every approval request;
- every human message;
- every restart candidate;
- relevant timer ticks;
- turn completion.

Do not wake the supervisor for every stream delta.

## Startup Preflights

Before starting the persistent coder thread:

- Run `codex --version`.
- Generate or inspect the app-server JSON schema for the installed Codex version.
- Store `codex_version` and an `appserver_schema_hash` in `.supervisor/config.json`.
- Fail startup if required methods or fields are absent from the generated schema.
- Call `account/read`; if Codex requires OpenAI auth and no account is available, stop cleanly before coder start.
- Call `model/list`; select the default model unless the user later adds a model option.
- Run a trivial structured-output supervisor self-test using a fresh app-server thread/turn.
- Run `configRequirements/read`, then verify that the requested coder sandbox and approval settings are accepted before starting the real coder turn.

This compatibility preflight should be lightweight. It exists to catch app-server protocol drift and authentication/config problems before Sentinel starts supervising real work.

## State Files

Initialize `.supervisor/` with:

```text
.supervisor/
  config.json
  PROGRESS.md
  DECISIONS.md
  LAST_ACTION.md
  HEALTH.json
  HANDOFF.md
  FINAL_REPORT.md
  log.jsonl
  events.jsonl
```

`PENDING_INTERVENTION.md` is not the normal delivery path. Keep it only if needed for crash recovery.

Every log/event entry must include:

```text
sequence
timestamp
generation
source
event_type
thread_id
turn_id
item_id
decision
reason
```

`config.json` must persist crash-recovery identifiers:

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

## Modules To Build

### `supervisor/appserver.py`

Codex app-server JSON-RPC client:

- Start `codex app-server --listen stdio://`.
- Read and write newline-delimited JSON-RPC over stdio.
- Allocate request ids.
- Match responses to pending requests.
- Route notifications and server requests to the controller.
- Support reconnect/restart.
- Implement wrappers for:
  - `initialize`
  - `initialized`
  - `account/read`
  - `account/rateLimits/read`
  - `model/list`
  - `configRequirements/read`
  - `thread/start`
  - `thread/read`
  - `thread/resume`
  - `thread/archive`
  - `thread/unsubscribe`
  - `thread/turns/list`
  - `turn/start`
  - `turn/steer`
  - `turn/interrupt`
  - approval responses for app-server server requests

Approval responses must answer the exact JSON-RPC server-request id received from app-server. The client should track `serverRequest/resolved` notifications to clear pending approval state.

### `supervisor/schemas.py` or `supervisor/schemas/models.py`

Add app-server-native models:

- normalized app events;
- approval context;
- supervisor decision schema;
- health/config models;
- turn/thread ids;
- server request envelopes;
- final report data.

`ApprovalContext` must include:

- `server_request_id`;
- `server_request_method`;
- `thread_id`;
- `turn_id`;
- `item_id`;
- approval callback/request id when present;
- request type;
- command/cwd/paths/diff when present;
- `networkApprovalContext` when present;
- `availableDecisions` when present.

Keep backward compatibility only where low-cost. New Sentinel code should import the app-server models directly.

### `supervisor/state.py`

Extend the existing atomic state store:

- initialize all Sentinel state files;
- append `events.jsonl`;
- append `log.jsonl`;
- write progress, decisions, last action, health, handoff, final report;
- preserve existing atomic write and file lock behavior.

### `supervisor/task_select.py`

Implement task validation and markdown selection:

- validate explicit `--task`;
- scan candidates with exclusions;
- rank task-like names first;
- render a minimal selector when needed.

### `supervisor/policy.py`

Adapt deterministic policy for app-server approval contexts:

- classify commands, paths, diffs, network requests, and MCP/app actions;
- instantly allow safe read-only project inspection and known validation commands;
- instantly deny dangerous classes;
- route gray-zone requests to the stateless supervisor;
- enforce that `acceptForSession` is allowed only for narrow structural classes.
- fail closed for unsupported app-server surfaces.

Never use `acceptForSession` for:

- network access;
- secrets;
- broad deletes;
- permission changes;
- deploy/publish commands;
- git force operations;
- supervisor runtime/state files.

Sentinel must not expose these app-server surfaces to the coder path in the MVP:

- `thread/shellCommand`;
- `process/*`;
- dynamic tools;
- Computer Use / Browser Use;
- external app tools unless an explicit `tool/requestUserInput` handler is implemented.

If such a request appears, cancel if possible, otherwise decline; log `unsupported_request`; wake the supervisor with fail-closed context.

### `supervisor/approvals.py`

Approval handling:

- normalize app-server server requests into `ApprovalContext`;
- preserve JSON-RPC `server_request_id`, `server_request_method`, `threadId`, `turnId`, `itemId`, approval callback id when present, request type, command, cwd, paths, diff, network context, and `availableDecisions`;
- choose only from `availableDecisions` when present;
- decide network approvals from `networkApprovalContext`, not command text;
- unknown approval/request types default to `cancel` if available, otherwise `decline`;
- deterministic policy first;
- supervisor fallback for gray-zone requests;
- timeout or invalid supervisor JSON declines/cancels;
- render decisions in the TUI;
- persist durable decisions when applicable.
- MVP handling for `tool/requestUserInput` and `item/tool/call`: fail closed unless a purpose-built mapper exists for the specific tool request shape.
- Command approval can emit `acceptWithExecpolicyAmendment` only as the protocol object shape and only when `availableDecisions` permits it.
- File-change approval must never emit `acceptWithExecpolicyAmendment`.

### `supervisor/supervisor_agent.py`

Stateless supervisor calls:

- start a fresh app-server thread/turn per decision;
- send compact wake packet;
- require strict output schema;
- parse and validate response;
- enforce timeout fallback.

Wake packet includes:

- selected task contents;
- `PROGRESS.md`;
- `DECISIONS.md`;
- `LAST_ACTION.md`;
- `HEALTH.json`;
- `HANDOFF.md` when present;
- bounded recent event window;
- current approval/action summary;
- current diff summary when available;
- generation and restart count.

Decision schema:

```text
decision: noop | approve | deny | intervene | restart | complete | pause
approval_decision: accept | acceptForSession | decline | cancel | null
execpolicy_amendment: string[] | null
reason
message_to_coder
persistent_decision
progress_update
health_delta
display_message
```

For command approvals only, the controller may translate `approval_decision=accept` plus `execpolicy_amendment` into:

```json
{
  "acceptWithExecpolicyAmendment": {
    "execpolicy_amendment": ["..."]
  }
}
```

Only do this when the app-server approval request allows that decision.

Supervisor wake packets also include:

- `wake_sequence`;
- `latest_event_sequence`;
- `coder_thread_id`;
- `active_coder_turn_id`;
- triggering `item_id` when present;
- triggering `server_request_id` when present.

Approval supervisor calls are blocking for that approval. Non-approval checks are coalesced: if a check is already running, mark it dirty; when it finishes, discard stale decisions and run one more check over latest state if dirty.

Apply supervisor decisions only if generation and coder thread still match, the pending approval still exists when applicable, and the decision sequence is newer than `last_applied_supervisor_sequence`.

### `supervisor/coder.py`

Persistent coder thread lifecycle:

- start coder thread;
- start initial task turn;
- continue idle coder turn;
- steer active turn;
- interrupt active turn;
- restart with new generation;
- track active thread/turn ids.

`turn/steer` must include:

- `threadId = coder_thread_id`;
- `expectedTurnId = active_coder_turn_id`;
- input containing the supervisor message.

If `active_coder_turn_id` is missing or stale, do not steer. Start a new coder turn instead.

Initial coder prompt:

```text
You are the coding agent for this supervised run.

Read the selected task file first:
<absolute task path>

Complete the task autonomously. When a command, file edit, network access, MCP/app action, or other operation requires approval, request permission through Codex's normal approval flow. Do not ask the human in chat.

The supervisor/controller is the approval authority. It may approve, deny, steer, interrupt, or restart you.

Use minimal changes. Prefer project conventions. Validate your work before claiming completion.
```

Restart prompt must instruct the new coder generation to read the task plus `.supervisor/DECISIONS.md`, `.supervisor/PROGRESS.md`, and `.supervisor/HANDOFF.md`.

### `supervisor/health.py`

Keep and extend health tracking:

- progress counters;
- repeated failures;
- repeated commands;
- denied actions;
- no-progress timers;
- restart candidate thresholds;
- restart count cap.

Default `max_restarts = 3`. If `restart_count >= max_restarts`, interrupt the coder, resolve pending approvals, write `HANDOFF.md`, write `FINAL_REPORT.md` with status `stuck`, and exit cleanly.

### `supervisor/controller.py`

Single async event queue:

- startup lifecycle;
- app-server event routing;
- state transitions;
- approval routing;
- supervisor wake scheduling;
- timer handling;
- pause/resume;
- restart;
- completion finalization.
- provider/app-server error handling;
- stale supervisor decision discard;
- controller-owned diff summaries.

All decisions must be applied through the controller.

The controller computes diff summaries directly with read-only local inspection commands:

- `git status --short`
- `git diff --stat`
- `git diff --name-only`

Run these with a timeout. If they fail, record `diff unavailable` with the error. Do not let the coder fabricate final diff summaries.

Provider/app-server error policy:

- `Unauthorized` or `UsageLimitExceeded`: write `HANDOFF.md`, write `FINAL_REPORT.md` with status `provider_failure`, and exit cleanly.
- `ContextWindowExceeded` in the coder thread: run supervised restart with `HANDOFF.md`.
- transient HTTP/stream/internal errors: bounded retry, then handoff and clean exit if retry fails.
- repeated `SandboxError`: wake supervisor with error context, then restart or fail cleanly.

### `supervisor/tui.py`

Minimal terminal UI:

- chronological event stream;
- input prompt;
- keyboard shortcuts;
- status view;
- visible rendering for coder messages, tool actions, approval requests, supervisor decisions, denials, interventions, restarts, and final summary.

TUI lanes:

```text
[SUPERVISOR]
[CODER]
[TOOL]
[APPROVAL]
[DENIED]
[USER]
[SYSTEM]
```

The stream is chronological. Human text is always rendered as `USER -> SUPERVISOR`. Supervisor-originated steer/restart/deny messages are rendered before the controller applies them.

Controls:

```text
Ctrl+C   pause: interrupt supervisor call, interrupt coder turn, cancel/decline pending approvals
Ctrl+K   open supervisor prompt without immediate coder interrupt
Ctrl+R   request supervised restart decision
Ctrl+Q   clean exit after state write
/status  show task, generation, active turns, pending approvals, health
/pause   same as Ctrl+C
/resume  resume autonomous loop
/restart supervised restart request
/quit    clean exit
```

Normal human text goes only to the supervisor. It is never sent directly to the coder.

## Runtime Flow

Startup:

1. Validate project directory.
2. Resolve task file or show selector.
3. Initialize `.supervisor`.
4. Start `codex app-server --listen stdio://`.
5. Send `initialize` and `initialized`.
6. Start the app-server reader task.
7. Start the TUI/controller event loop.
8. Run schema, auth, model, structured-output, and config preflights.
9. Hard-fail before coder start unless `onRequest` approval policy and `readOnly` sandbox are accepted.
10. Start persistent coder thread.
11. Start initial coder turn with selected task prompt.

Main loop:

1. Read app-server responses, notifications, and server requests.
2. Append normalized raw events to `events.jsonl`.
3. Render visible events in TUI.
4. Route approval requests to `approvals.py`.
5. Route completed coder actions to stateless supervisor wake-up.
6. Apply supervisor decisions through the controller only.
7. Persist state after every decision.
8. Continue, steer, interrupt, restart, pause, or complete.

Ctrl+C pause:

1. Stop accepting new autonomous actions.
2. Interrupt active supervisor call.
3. Interrupt active coder turn.
4. For unresolved approvals, send `cancel` if available, otherwise `decline`.
5. Wait for `serverRequest/resolved` or turn completion.
6. Enter paused mode.
7. Route user input only to supervisor.

Restart:

1. Set state status to restarting.
2. Stop accepting new autonomous actions.
3. Interrupt active coder turn.
4. Cancel or decline all pending approvals.
5. Wait for turn completed/interrupted/failed and `serverRequest/resolved`.
6. Write `HANDOFF.md` with generation, task path, completed work, diff summary, failed attempts, denied actions, supervisor reason, and next instruction.
7. Increment generation and restart count.
8. Archive or mark the old coder thread as superseded.
9. Start fresh coder thread.
10. Start new coder turn from task + progress + decisions + handoff.

Completion:

1. Accept completion only from supervisor decision `complete`.
2. Require no active approval and no active coder turn.
3. Require final diff summary.
4. Require validation evidence or explicit statement that validation is unavailable.
5. Write `FINAL_REPORT.md`.
6. Render final summary and exit cleanly.

## Obsolete Runtime To Remove Or De-Primary

Remove as primary implementation:

- `.codex/hooks.json` install/restore.
- Hook IPC socket.
- Codex hook trust preflight.
- `codex-stdout.log`.
- `codex-stderr.log`.
- `codex-hook-trace.log`.
- `--dangerously-bypass-hook-trust`.
- `codex exec --json` supervisee runtime.

The old tests for these paths should be replaced or marked legacy once Sentinel tests cover the new app-server runtime.

## Implementation Sequence

1. Add `appserver.py` protocol client and fake app-server test harness.
2. Add app-server models and supervisor decision schema.
3. Extend `state.py` for Sentinel files, event logs, and final reports.
4. Add `task_select.py` and replace CLI startup path.
5. Adapt `policy.py` to app-server approval contexts.
6. Add `approvals.py` with `availableDecisions`, network context, and unknown request fallback.
7. Add `supervisor_agent.py` for stateless fresh-thread decisions with strict `outputSchema`.
8. Add `coder.py` for persistent coder thread lifecycle.
9. Extend `health.py`.
10. Add `controller.py` single event queue and decision application.
11. Add minimal `tui.py`.
12. Remove or de-primary obsolete hook/exec implementation paths.
13. Add integration smoke tests against installed `codex app-server`.

## Test Plan

Unit tests:

- task selection ranking and exclusions;
- state initialization and atomic writes;
- supervisor decision schema validation;
- policy allow/deny/gray-zone classification;
- approval response constrained by `availableDecisions`;
- network approval uses `networkApprovalContext`;
- unknown approval request cancels/declines;
- `acceptForSession` forbidden for unsafe categories;
- health restart thresholds;
- final report generation.

Controller tests with fake app-server:

- startup handshake and config requirements gate;
- initial coder thread and turn start;
- approval request accepted by deterministic policy;
- approval request denied by deterministic policy;
- gray-zone approval calls stateless supervisor;
- supervisor timeout declines approval;
- completed coder action triggers supervisor wake-up;
- stream deltas render but do not wake supervisor;
- intervention uses `turn/steer` when coder active;
- intervention uses `turn/start` when coder idle;
- Ctrl+C interrupts turns and resolves pending approvals;
- restart writes handoff and starts fresh generation;
- app-server crash resumes/reconciles before fresh restart;
- completion writes `FINAL_REPORT.md`.

Integration smoke tests:

- `codex app-server --listen stdio://` starts;
- `initialize`/`initialized` succeeds;
- `configRequirements/read` succeeds;
- `thread/start` and `turn/start` succeed;
- `outputSchema` supervisor turn returns structured JSON;
- command approval request can be answered by client;
- file-change approval request can be answered by client;
- `networkApprovalContext` approval is parsed correctly if available;
- `turn/steer` works;
- `turn/interrupt` works;
- app-server restart path can reconnect and inspect/resume thread.

## Acceptance Criteria

- `supervisor --task TASK.md` starts a Codex-only supervised run.
- Running without task and with multiple markdown files shows selector.
- No normal approval request reaches the human after startup.
- UI shows coder messages, tool actions, approval requests, supervisor decisions, denials, interventions, restarts, and final summary.
- Human input goes only to supervisor.
- Supervisor runs stateless after every completed coder action.
- Coder uses normal app-server approval flow.
- Dangerous actions are denied automatically.
- Gray-zone actions are judged by supervisor structured output.
- Approval timeout denies/cancels.
- Ctrl+C pauses without hanging pending approvals.
- Restart writes `HANDOFF.md`, increments generation, starts fresh coder thread, and continues from task + progress + decisions + handoff.
- Completion writes `FINAL_REPORT.md`.

## Approval Gate

Do not implement this plan until the user reviews `new_plan.md` and explicitly approves implementation or requests changes.
