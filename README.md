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
  packets and decide whether to continue, approve, deny, steer, restart, pause,
  or complete.

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
- completion is accepted only by the supervisor;
- state and decisions are written to `.supervisor/` for inspection.

This is designed for unattended work with controlled risk, not for perfect
safety or guaranteed correctness.

## User Flow

From a project directory:

```bash
supervisor --task TASK.md
```

or:

```bash
supervisor
```

When `--task` is omitted, Sentinel scans for markdown task files and shows a
selector if there is more than one candidate.

Use `--clean` in a disposable task directory to remove every file and
directory except the selected task file before Sentinel starts.

Task selection rules:

- explicit `--task` must exist and end in `.md`;
- scan excludes `.git`, `.supervisor`, `node_modules`, `vendor`, `dist`,
  `build`, `target`, `.venv`, and `venv`;
- `TASK.md`, `task.md`, `PLAN.md`, `plan.md`, and `TODO.md` rank first.

## Benchmark Mode

Sentinel can run a local benchmark suite:

```bash
supervisor --bench
```

Benchmark prompts live in the source-controlled file:

```text
tests/TEST_PROMPTS.json
```

The generated benchmark workspaces live under `TESTS/`. That directory is
ignored by git because Sentinel recreates and mutates it during benchmark runs.

`TEST_PROMPTS.json` is a JSON object keyed by numeric test id. Each value can
be either a string or a list of lines:

```json
{
  "1": [
    "# Task",
    "",
    "Create hello.py with one line: hello sentinel"
  ],
  "2": "# Task\n\nCreate math_utils.py with add and subtract functions.\n"
}
```

When `supervisor --bench` starts, Sentinel:

1. creates `TESTS/` if it is missing;
2. creates `tests/TEST_PROMPTS.json` if it is missing, then stops because the
   empty file has no prompts yet;
3. creates every `TESTS/<n>/` directory referenced by prompt keys;
4. checks that every existing numeric `TESTS/<n>/` directory has a prompt;
5. clears each benchmark directory, preserving only `TASK.md`;
6. writes every `TESTS/<n>/TASK.md` from `tests/TEST_PROMPTS.json` before the
   first benchmark case starts;
7. runs Sentinel once inside each numeric test directory in numeric order.

Each case runs with `TESTS/<n>/` as the project root and `TASK.md` as the
selected task. Benchmark mode disables git diff summarization for the coder
workspace, records extra performance telemetry, and writes results to:

```text
TESTS/<n>/result.json
TESTS/<n>/.supervisor/perf.jsonl
TESTS/result.json
```

`TESTS/result.json` contains the aggregate run id, success rate, counts, and
mean timing/token metrics. Per-test `result.json` files contain status,
success, validation, error, and metric details for that case.

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
- available models;
- account rate limits when available;
- structured JSON output for the supervisor;
- app-server config requirements;
- requested coder sandbox and approval settings.

If one of these fails, Sentinel exits before real work starts.

## Runtime Model

The coder receives an instruction like:

```text
You are the coding agent for this supervised run.

Read the selected task file first:
<absolute task path>

Complete the task autonomously. When a command, file edit, network access,
MCP/app action, or other operation requires approval, request permission
through Codex's normal approval flow. Do not ask the human in chat.

The supervisor/controller is the approval authority. It may approve, deny,
steer, interrupt, or restart you.

Use minimal changes. Prefer project conventions. Validate your work before
claiming completion.
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

The supervisor returns strict JSON with one decision:

```text
noop | approve | deny | intervene | restart | complete | pause
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

- `config.json`: task path, Codex version, schema hash, thread ids, generation.
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

## Install For Local Development

From this repository:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
```

Run tests:

```bash
.venv/bin/pytest -q
```

## Safe Smoke Test

Use a throwaway project first:

```bash
mkdir /tmp/sentinel-smoke
cd /tmp/sentinel-smoke
git init
cat > TASK.md <<'EOF'
Create hello.py that prints "hello from sentinel".
Then run python3 hello.py to validate it.
EOF
```

Run:

```bash
/path/to/superviser/.venv/bin/supervisor --task TASK.md --start-over
```

Afterwards inspect:

```bash
find .supervisor -maxdepth 1 -type f -print | sort
cat .supervisor/config.json
tail .supervisor/events.jsonl
cat .supervisor/FINAL_REPORT.md
```

To test markdown selection, create a second `.md` file and run without
`--task`:

```bash
echo '# Other task' > NOTES.md
/path/to/superviser/.venv/bin/supervisor --start-over
```

## Current Status

This is an app-server MVP. It has the core Sentinel architecture, but the Codex
app-server protocol is experimental and can change between Codex releases.
Sentinel therefore performs schema/version preflight checks before running.

Legacy hook/IPC modules still exist in the repository for now, but they are not
the primary Sentinel runtime.

Do not run first tests in an important repository. Start with a throwaway git
repo and inspect `.supervisor/` after the run.
