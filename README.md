# Sentinel

Sentinel is a terminal supervisor for autonomous Codex runs.

It does not run Codex through hooks, plugins, subagents, or `codex exec --json`.
Instead, Sentinel starts `codex app-server --listen stdio://` and controls Codex
through the app-server JSON-RPC protocol.

The goal is simple: let a Codex coding agent work autonomously while a separate
supervisor/controller owns approvals, steering, restarts, state, and final
completion.

## What It Does

Sentinel runs two kinds of Codex work:

- **Coder**: a persistent Codex thread that reads the selected task file, edits
  code, runs commands, and validates the task.
- **Supervisor**: short-lived stateless Codex turns that review compact state
  packets. Runtime monitor turns decide whether to continue, approve, deny,
  steer, restart, or pause; a dedicated completion-review turn accepts or
  returns final readiness after the coder emits the readiness marker.

The human talks to Sentinel, not directly to the coder. Normal approval prompts
should not reach the human during a run.

## Why Not Just Give Codex Full Permissions?



Full permissions are fast, but they also mean the same agent decides and
executes everything.

Sentinel separates those roles:

- safe actions can be approved by deterministic policy;
- dangerous actions are denied automatically;
- gray-zone actions are reviewed by a fresh stateless supervisor turn;
- the coder can be steered or restarted when it drifts;
- completion is accepted only by dedicated completion review;
- state and decisions are written to `.supervisor/` for inspection.

This is designed for unattended work with controlled risk, not for perfect
safety or guaranteed correctness.

## Sentinel Command Order

Rule: write command parts in the same order as this file. If item A should be
before item B in a command, item A has a smaller line number here.

- `pipx install "git+https://github.com/Makson179/Sentinel.git"` - install Sentinel from the default GitHub branch.
- `SENTINEL_SKIP_UPDATE_CHECK=1` - skip the startup update check for one command.
- `sentinel` - main command; run it from the project directory.
- `config` - open the interactive project config editor.
- `doctor` - check Python, Git, Codex, auth, app-server support, install metadata, and update status.
- `update` - update Sentinel, then use the updated install for future runs.
- `--version` - print Sentinel version, installed commit, and update status.
- `-V` - short form of `--version`.
- `--help` - show command help.
- `-h` - short form of `--help`.
- `--task TASK.md` - choose the markdown task file explicitly.
- `--coder-mod MODEL` - choose the Codex model for coder turns; must be used with `--super-mod`.
- `--super-mod MODEL` - choose the Codex model for supervisor turns; must be used with `--coder-mod`.
- `--coder-intelligence VALUE` - choose coder reasoning effort.
- `--super-intelligence VALUE` - choose supervisor reasoning effort.
- `--start-over[=true|false]` - reset `.supervisor` state and start fresh.
- `--clean[=true|false]` - delete workspace files except the selected task file before starting; use only in disposable folders.
- `--adversary[=true|false]` - run the adversarial tester before final completion.
- `--adversary-runs N` - override the adversarial tester pass limit for one run; `0` disables it.
- `--protected-path PATH` - mark a hidden or grading path as protected; repeat this option for multiple paths.

Examples:

```bash
sentinel doctor
sentinel --version
sentinel update
sentinel config
sentinel --task TASK.md --coder-mod gpt-5 --super-mod gpt-5 --start-over
sentinel --task TASK.md --coder-mod gpt-5.5 --super-mod gpt-5.5
SENTINEL_SKIP_UPDATE_CHECK=1 sentinel --task TASK.md
```

## Model Selection

Sentinel resolves run settings by priority: explicit CLI flags for the current
invocation win first, then project defaults saved in `.supervisor/config.json`,
then built-in defaults. The built-in defaults are `gpt-5.5` for both coder and
supervisor, `xhigh` intelligence for both roles, `speed=usual`,
`start-over=true`, `adversary=true`, `max_adversary_runs=1`,
`max_completion_returns_per_generation=10`, and `clean=false`.

Use `sentinel config` to edit the project defaults for the current directory:

```bash
sentinel config
```

The config editor creates `.supervisor/config.json` if it does not exist and
saves values that future `sentinel` runs use when a CLI flag is omitted. It can
edit the task path, coder and supervisor models, reasoning effort, speed,
`start-over`, adversary enablement, adversary run limit, completion-return
limit, `clean`, and protected paths. Choice fields expand in place with Enter;
free-text and numeric fields are typed directly in the `VALUE` column and saved
with Enter. CLI flags override these saved values for one run and do not rewrite
the project config.

Choose models for a single run with:

```bash
sentinel --task TASK.md --coder-mod <coder-model> --super-mod <supervisor-model>
```

`--coder-mod` and `--super-mod` must be provided together. To use the same
model for both roles, pass the same value to both flags.

Add `--fast` or `--fast=true` to use the Codex Fast service tier for both coder
and full supervisor turns. Use `--fast=false` to override a fast project config
for one run.

For adversary settings, explicit `--adversary=true|false` wins. If `--adversary`
is omitted, `--adversary-runs N` overrides the saved run limit for one run and
also implies enabled when `N > 0` or disabled when `N = 0`.

Model names are Codex/OpenAI model slugs accepted by the installed Codex
app-server and the authenticated account. Use `gpt-5.5` for the default 5.5
model. Other usable values are the model slugs exposed to your account by
Codex; Sentinel passes them through unchanged and does not maintain a separate
hard-coded allow-list.

The adversarial tester always uses `gpt-5.5`, independent of `--coder-mod` or
`--super-mod`.

## What You See

The terminal stream is chronological and lane-based:

```text
[SYSTEM] checking Codex version
[SYSTEM] checking Codex app-server schema
[SYSTEM] supervised coder started
[CODER] I will read the task file first.
[TOOL] command completed: cat TASK.md exit=0
[APPROVAL] accept: workspace file change inside workspace
[SUPERVISOR] steering coder: add focused validation before claiming completion
[SYSTEM] final report written: .supervisor/FINAL_REPORT.md
```

Lanes:

- `[SYSTEM]`: Sentinel runtime state.
- `[USER]`: human input to Sentinel.
- `[SUPERVISOR]`: supervisor decisions and steering.
- `[CODER]`: completed coder messages.
- `[TOOL]`: completed tool/command/file actions.
- `[APPROVAL]`: approved requests.
- `[DENIED]`: declined or cancelled requests.

## Startup Preflight

Before starting the real coder, Sentinel checks:

- `codex --version`;
- app-server schema generation and required protocol files;
- Codex account/auth state;
- selected coder, supervisor, and adversarial tester models are available;
- account rate limits when available;
- structured JSON output for the supervisor;
- optional cheap approval triage structured output when
  `SENTINEL_APPROVAL_TRIAGE_ENABLED=true` and
  `SENTINEL_APPROVAL_TRIAGE_MODEL` is configured;
- app-server config requirements;
- requested coder sandbox and approval settings.

If one of these fails, Sentinel exits before real work starts and records the
interruption in `.supervisor/FINAL_REPORT.md`.

## Runtime Model

The coder receives an instruction like:

```text
You are the coding agent for this task.

Read the selected task file first:
<absolute task path>

Complete the task autonomously. When a command, file edit, network access,
MCP/app action, or other operation requires approval, request permission
through Codex's normal approval flow. Do not ask the human in chat.

When work is ready, include Summary, Validation, and the exact readiness marker
on its own line.

Use minimal changes. Prefer project conventions. Validate your work before
declaring readiness.
```

The supervisor does not keep a long chat history. Each supervisor decision gets
a compact packet containing:

- selected task contents;
- `PROGRESS.md`;
- `DECISIONS.md`;
- `LAST_ACTION.md`;
- `HEALTH.json`;
- `HANDOFF.md` when present;
- recent bounded events;
- current approval/action summary;
- current git diff summary;
- generation and restart count.

The runtime monitor returns strict JSON with one decision:

```text
noop | approve | deny | intervene | restart | pause
```

Completion review uses a separate strict schema:

```text
accept | return | restart
```

## Prompt Configuration

All editable Sentinel prompt text lives in one TOML file:

```text
supervisor/prompts/prompts.toml
```

It contains:

- `coder_initial.template`;
- `coder_restart.template`;
- `stateless_supervisor.body_sections`;
- `stateless_supervisor.sections.*`;

The coder templates support the `{task_path}` placeholder. Sentinel loads this
file at runtime before building coder and supervisor turns.

For local experiments, point Sentinel at another prompt file:

```bash
SENTINEL_PROMPTS_FILE=/path/to/prompts.toml sentinel --task TASK.md
```

## Approvals

Codex app-server sends approval requests to Sentinel. Sentinel answers the exact
JSON-RPC server request id.

Deterministic policy handles obvious cases first:

- allow safe read-only project inspection;
- allow known validation commands;
- allow normal workspace file changes;
- deny secrets, broad deletes, permission changes, deploy/publish commands,
  git force operations, and supervisor state edits.

Gray-zone approvals are sent to the stateless supervisor. If the supervisor
times out or returns invalid output, Sentinel fails closed with decline/cancel.

When enabled, command approvals in a narrow gray zone can take a cheaper
mechanical review path before the full supervisor:

```text
deterministic policy
  -> allow or deny
  -> eligible composed read-only command
      -> cheap mechanical review
          -> approve_low_impact: plain accept
          -> escalate/failure/uncertainty: full supervisor
  -> all other gray-zone requests: full supervisor
  -> full-supervisor failure: decline/cancel
```

The cheap reviewer only classifies whether a command is bounded,
operationally read-only, workspace-local, and safe without task context. It
cannot deny, grant `acceptForSession`, amend policy, persist decisions, steer
the coder, or resolve file-change, network, permissions, tool, MCP, or unknown
request types. Its output is not included in the full-supervisor packet; on
uncertainty or failure the full supervisor sees the same approval context and
deterministic routing reason it would have seen without cheap review.

Configure it independently from the full supervisor:

- `SENTINEL_APPROVAL_TRIAGE_ENABLED=true` enables the optional fast path.
- `SENTINEL_APPROVAL_TRIAGE_MODEL=<model>` selects the cheap reviewer model.
  Sentinel does not silently reuse the full supervisor model when this is
  missing.
- `SENTINEL_APPROVAL_TRIAGE_TIMEOUT=<seconds>` sets the cheap-review timeout.

Representative candidates include `git status --short && git diff --stat`,
`git diff --name-only | head -n 20`, `find src -maxdepth 2 -type f | sort`,
and `cat pyproject.toml | head -n 80`. Noncandidates include redirects,
command or process substitution, network commands, interpreters such as
`python -c`, dependency installation, git mutation, permission changes,
destructive commands, secret paths, workspace escapes, and unknown executables.

Unsupported app-server surfaces are fail-closed in the MVP:

- `thread/shellCommand`;
- `process/*`;
- dynamic tools;
- Computer Use / Browser Use;
- external app tools without a purpose-built `tool/requestUserInput` mapper.

## Steering And Restarts

The supervisor can steer the coder with natural language.

If the coder turn is active, Sentinel sends `turn/steer` with the active
`expectedTurnId`. If the coder is idle, Sentinel starts a new turn on the same
coder thread.

Restart creates a new coder generation:

1. interrupt active coder turn;
2. resolve pending approvals;
3. write `.supervisor/HANDOFF.md`;
4. increment generation and restart count;
5. start a fresh coder thread;
6. tell the new coder to read task, decisions, progress, and handoff.

Default restart cap is 3. After that, Sentinel writes a stuck final report and
exits cleanly.

## State Files

Sentinel writes state under `.supervisor/` in the target project:

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

Useful files:

- `config.json`: task path, coder and supervisor models, Codex version, schema
  hash, thread ids, generation.
- `events.jsonl`: normalized event stream.
- `PROGRESS.md`: supervisor progress notes.
- `DECISIONS.md`: persistent supervisor decisions.
- `HANDOFF.md`: restart handoff context.
- `FINAL_REPORT.md`: final result, changed files, validation, risks.

## Controls

Inside the terminal:

```text
/status   show task, generation, active turn, pending approvals, health
/pause    interrupt coder and resolve pending approvals
/resume   resume autonomous loop
/restart  request supervised restart
/quit     write state and exit
```

Keyboard behavior:

```text
Ctrl+C   pause/abort current terminal process
Ctrl+Q   clean exit when implemented by terminal
```

Human text is routed to the supervisor, not directly to the coder.
