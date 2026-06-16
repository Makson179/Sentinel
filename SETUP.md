# Sentinel Setup And Usage

This guide explains how to install Sentinel and run the current supervisor
runtime against a local project.

Sentinel is a terminal supervisor for autonomous Codex runs. It starts
`codex app-server --listen stdio://`, launches a persistent coder thread, and
uses short-lived supervisor turns to review approvals, steer progress, restart
bad generations, and accept final completion.

## Requirements

Install these before running Sentinel:

- Python 3.11 or newer.
- Git.
- Codex CLI on `PATH`.
- A logged-in Codex account.
- Network access to the model provider used by Codex.

Check the local tools:

```bash
python3 --version
git --version
codex --version
```

Log in to Codex if needed:

```bash
codex login
```

Sentinel uses the experimental Codex app-server protocol. Your Codex CLI must
support these commands:

```bash
codex app-server --help
codex app-server generate-json-schema --experimental --out /tmp/sentinel-schema-check
```

The second command writes schema files into `/tmp/sentinel-schema-check`. It is
only a capability check and can be removed afterwards.

## Install Sentinel From Source

Clone the repository:

```bash
git clone <sentinel-repo-url> Sentinel
cd Sentinel
```

Create a virtual environment and install the package:

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
```

For development or test work, install the test extras:

```bash
.venv/bin/pip install -e '.[test]'
```

Verify the command is available:

```bash
.venv/bin/supervisor --help
```

The package installs a console script named `supervisor`. The Python package
name is `supervisor-agent`, but users normally run the `supervisor` command.

If you prefer an activated shell:

```bash
source .venv/bin/activate
supervisor --help
```

## Optional Development Check

Run the test suite from the Sentinel repository:

```bash
.venv/bin/pytest -q
```

This is not required for ordinary use, but it is a good check after changing
Sentinel itself.

## Prepare A Target Project

Run Sentinel from the project directory that should be edited by Codex. Start
with a throwaway repository before using it on important work.

Example:

```bash
mkdir /tmp/sentinel-smoke
cd /tmp/sentinel-smoke
git init
```

Create a markdown task file:

```bash
cat > TASK.md <<'EOF'
Create hello.py that prints "hello from sentinel".
Then run python3 hello.py to validate it.
EOF
```

Task files must:

- Be inside the project directory.
- End in `.md`.
- Describe the objective clearly.
- Include expected validation when possible.

Good task files name the concrete outcome, scope boundaries, and the checks the
coder should run before claiming completion.

## Run Sentinel

From the target project directory:

```bash
/path/to/Sentinel/.venv/bin/supervisor --task TASK.md
```

With an activated Sentinel virtual environment:

```bash
cd /path/to/target-project
supervisor --task TASK.md
```

Sentinel will run startup preflight checks, start the Codex app-server, create a
coder thread, and begin supervising the run.

If you omit `--task`, Sentinel scans for markdown files and opens a selector
when there is more than one candidate:

```bash
supervisor
```

Preferred task filenames are ranked first:

- `TASK.md`
- `task.md`
- `PLAN.md`
- `plan.md`
- `TODO.md`

The scan skips common generated or dependency directories, including `.git`,
`.supervisor`, `node_modules`, `vendor`, `dist`, `build`, `target`, `.venv`,
and `venv`.

## Common Run Options

Start from fresh Sentinel state:

```bash
supervisor --task TASK.md --start-over
```

Use a specific model for both coder and supervisor turns:

```bash
supervisor --task TASK.md --model <model-name>
```

Clean a disposable task directory before starting:

```bash
supervisor --task TASK.md --clean
```

`--clean` deletes every file and directory in the current folder except the
selected task file. Use it only in disposable task workspaces.

## Sandbox Mode

By default, the coder runs with Sentinel's read-only sandbox request:

```bash
SENTINEL_CODER_SANDBOX=read-only supervisor --task TASK.md
```

In this mode, Codex asks for approvals when it needs to edit files, run
commands outside the deterministic allow list, or access restricted surfaces.
Sentinel answers those approval requests through deterministic policy or a
fresh supervisor review.

For disposable environments where broader access is intentional:

```bash
SENTINEL_CODER_SANDBOX=danger-full-access supervisor --task TASK.md
```

Only use `danger-full-access` in isolated workspaces or containers.

## Prompt Overrides

Sentinel loads its default prompt text from:

```text
supervisor/prompts/prompts.toml
```

For local prompt experiments, point Sentinel at another TOML file:

```bash
SENTINEL_PROMPTS_FILE=/path/to/prompts.toml supervisor --task TASK.md
```

The override file must contain the same required prompt sections as the bundled
`prompts.toml`.

## What Users See

Terminal output is lane-based:

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
- `[TOOL]`: completed tool, command, or file actions.
- `[APPROVAL]`: approved requests.
- `[DENIED]`: declined or cancelled requests.

Human text typed into the terminal is routed to the supervisor, not directly to
the coder.

## Runtime Controls

Inside the Sentinel terminal:

```text
/status   show task, generation, active turn, pending approvals, and health
/pause    interrupt coder and resolve pending approvals
/resume   resume the autonomous loop
/restart  request a supervised restart
/quit     write state and exit
```

Keyboard behavior:

```text
Ctrl+C   pause or abort the current terminal process
Ctrl+Q   clean exit when implemented by the terminal
```

## Output And State Files

Sentinel writes runtime state under `.supervisor/` in the target project:

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
  supervisor_wakes.jsonl
```

Useful files:

- `FINAL_REPORT.md`: final status, result, changed files, validations, and
  remaining risks.
- `config.json`: selected task, model, Codex version, schema hash, thread ids,
  generation, and status.
- `events.jsonl`: normalized event stream.
- `PROGRESS.md`: durable progress notes.
- `DECISIONS.md`: durable supervisor decisions and constraints.
- `HANDOFF.md`: restart handoff context when a generation is replaced.
- `supervisor_wakes.jsonl`: audit records for supervisor wake packets and
  decisions.

Inspect a finished run:

```bash
find .supervisor -maxdepth 1 -type f -print | sort
cat .supervisor/FINAL_REPORT.md
cat .supervisor/config.json
tail .supervisor/events.jsonl
```

## Safe Smoke Test

Use this before running Sentinel in a real project:

```bash
mkdir /tmp/sentinel-smoke
cd /tmp/sentinel-smoke
git init

cat > TASK.md <<'EOF'
Create hello.py that prints "hello from sentinel".
Then run python3 hello.py to validate it.
EOF

/path/to/Sentinel/.venv/bin/supervisor --task TASK.md --start-over
```

After Sentinel exits:

```bash
cat hello.py
python3 hello.py
cat .supervisor/FINAL_REPORT.md
```

To test task selection:

```bash
echo '# Other task' > NOTES.md
/path/to/Sentinel/.venv/bin/supervisor --start-over
```

Sentinel should show a task selector because both `TASK.md` and `NOTES.md`
exist.

## Troubleshooting

If Sentinel exits before starting real work, check the preflight message.

`codex executable not found`

Install Codex CLI or fix `PATH` so `codex --version` works in the same shell
that runs Sentinel.

`Codex auth missing. Run codex login before starting Sentinel.`

Run:

```bash
codex login
```

Then retry Sentinel.

`app-server schema generation failed`

Your Codex CLI may not support the app-server schema command Sentinel requires.
Upgrade Codex CLI, then verify:

```bash
codex app-server generate-json-schema --experimental --out /tmp/sentinel-schema-check
```

`app-server did not accept on-request coder approval policy`

The installed Codex app-server protocol may have changed or does not support
the approval settings Sentinel requests. Upgrade or pin Codex to a compatible
version.

`unsupported SENTINEL_CODER_SANDBOX=...`

Use one of:

```bash
SENTINEL_CODER_SANDBOX=read-only
SENTINEL_CODER_SANDBOX=danger-full-access
```

`no markdown task file found`

Create a task file such as `TASK.md`, or pass an explicit file:

```bash
supervisor --task path/to/task.md
```

`task file must be inside project root`

Run Sentinel from the project root and choose a task file inside that directory.

## Current Runtime Notes

The primary runtime is the plain `supervisor` command. It uses Codex app-server
JSON-RPC and does not run Codex through hooks, plugins, subagents, or
`codex exec --json`.

Start with:

```bash
supervisor --task TASK.md
```

Do not run first experiments in an important repository. Start with a throwaway
git repo, inspect `.supervisor/`, and only then move to real work.
