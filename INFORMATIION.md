# Sentinel Project Information

Sentinel is a terminal supervisor for autonomous Codex runs. It is packaged as
`sentinel` version `0.1.0`, exposes the `sentinel` console command, and keeps
its implementation in the internal Python package named `supervisor`.

## Purpose

Sentinel lets a Codex coding agent work in a project while a separate
supervisor/controller owns approvals, steering, restarts, state, and final
completion. It does not drive Codex through hooks, plugins, subagents, or
`codex exec --json`; it starts `codex app-server --listen stdio://` and talks to
Codex through the app-server JSON-RPC protocol.

## Main Flow

From a target project, run:

```bash
sentinel --task TASK.md
```

If `--task` is omitted, Sentinel scans for markdown task files and opens a
selector when there are multiple candidates. Preferred task names include
`TASK.md`, `task.md`, `PLAN.md`, `plan.md`, and `TODO.md`.

The command-order note in `tt.md` says common commands should be written in this
shape:

```bash
pipx install "git+https://github.com/Makson179/Sentinel.git"
sentinel doctor
sentinel --version
sentinel update
sentinel --task TASK.md --model gpt-5 --start-over
sentinel --task TASK.md --coder-mod gpt-5.5 --super-mod gpt-5.5
SENTINEL_SKIP_UPDATE_CHECK=1 sentinel --task TASK.md
```

Use `--clean` only in disposable folders because it deletes workspace files
except the selected task file. Use `--protected-path PATH` to mark hidden or
grading material as protected.

## Architecture

Sentinel is built around separation of duties. The project is not one big
"agent"; it is a controller around Codex app-server that keeps execution,
review, state, and approval decisions in separate places.

The runtime has two Codex roles:

- Coder: a persistent Codex thread that reads the selected task, edits files,
  runs commands, and validates work.
- Supervisor: short stateless Codex turns that review approvals and runtime
  state, steer or restart the coder, and accept or return final readiness.

The controller starts Codex through `codex app-server --listen stdio://`, opens
the coder thread, watches app-server events, answers approval requests, and
writes audit state. The supervisor does not keep a long chat history; every
supervisor wake receives a compact packet with task contents, progress,
decisions, health, recent events, approval context, git diff summary, generation,
and restart count. Runtime supervisor decisions are strict values such as
`noop`, `approve`, `deny`, `intervene`, `restart`, and `pause`; final completion
uses a separate review schema with `accept`, `return`, or `restart`.

The main code paths are:

- `supervisor/main.py`: Click CLI, update gate, task/model flags, and controller
  startup.
- `supervisor/controller.py`: main orchestration loop, readiness handling,
  runtime wakes, restarts, completion review, and final reports.
- `supervisor/appserver.py`: JSON-RPC transport to the external Codex
  app-server process.
- `supervisor/approvals.py` and `supervisor/policy.py`: approval normalization,
  deterministic allow/deny policy, cheap review routing, and full supervisor
  fallback.
- `supervisor/state.py`: `.supervisor/` state files, event logs, health, handoff,
  and final report writes.
- `supervisor/prompts/prompts.toml`: editable prompt templates used to build
  coder and supervisor turns.

## Safety Model

Sentinel answers Codex approval requests before they reach the human during a
normal run. The policy layer can allow safe read-only inspection and ordinary
workspace edits, deny dangerous actions such as secret access, destructive
commands, broad permission changes, deploy/publish commands, git force actions,
and `.supervisor` mutations, or route gray-zone actions to a fresh supervisor
review. Unsupported approval surfaces fail closed.

The default coder sandbox is read-only. For isolated disposable workspaces,
`SENTINEL_CODER_SANDBOX=danger-full-access` can request broader coder access.

## State And Reports

Sentinel writes runtime state into `.supervisor/` inside the target project.
Important files include:

- `config.json`: selected task, models, Codex version, schema hash, threads,
  generation, and status.
- `PROGRESS.md` and `DECISIONS.md`: durable supervisor notes.
- `HANDOFF.md`: restart context for a new coder generation.
- `events.jsonl`, `log.jsonl`, and `supervisor_wakes.jsonl`: audit streams.
- `FINAL_REPORT.md`: final status, changed files, validation, and risks.

## Setup And Validation

Requirements are Python 3.11+, Git, Codex CLI on `PATH`, a logged-in Codex
account, and app-server support in the installed Codex CLI. The practical checks
are:

```bash
python3 --version
git --version
codex --version
codex login
codex app-server generate-json-schema --experimental --out /tmp/sentinel-schema-check
sentinel doctor
```

For local development:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/pytest -q
```

## Project Layout

- `README.md` and `SETUP.md`: user-facing overview and installation/run guide.
- `tt.md`: command-order reference for Sentinel command examples.
- `supervisor/`: implementation package for CLI, controller, app-server,
  approvals, state, health, prompts, task selection, and workspace cleaning.
- `supervisor/prompts/prompts.toml`: editable prompt templates used at runtime.
- `tests/`: pytest coverage for CLI, policy, approvals, state, doctor, task
  selection, schema models, update checks, and workspace cleaning.
- `scripts/`: helper runners for Sentinel task and SpecBench attempts.

## Current Caution

The core runtime depends on the experimental Codex app-server protocol, so
Sentinel performs startup preflight checks before launching real work. First
experiments should be done in a throwaway git repository, then `.supervisor/`
should be inspected before using Sentinel on important projects.
