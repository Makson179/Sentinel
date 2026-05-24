PLAN.md - Supervisor Agent MVP v5

## What we are building

Supervisor is an open-source CLI tool that replaces the human in the role of overseer for AI coding agents. It runs alongside Claude Code or Codex CLI, observes agent actions, handles permission decisions, detects drift or ineffective work, intervenes when useful, and kills/restarts the coding agent with a handoff when the current generation is stuck.

The core product promise is automation without blind trust. Users should not need to sit at the keyboard approving every command, and they should not need to run coding agents in full permission-bypass mode with no oversight.

The only acceptable user involvement during a run is startup/onboarding. After the supervised task begins, the system must not require the user to approve actions, babysit prompts, or manually recover from normal supervision events.

## MVP scope

Included in MVP:

- Claude Code supervisee support.
- Codex CLI supervisee support.
- Subscription mode supervisor calls through the same vendor CLI as the supervisee.
- API mode supervisor calls through OpenRouter.
- Permission handling with fast-path allow/deny and LLM judgment for gray-zone events.
- Four reaction scenarios: approve/deny permission, fine/no-op, corrective intervention, kill-restart, task complete.
- Kill-restart with `HANDOFF.md`.
- Wrapper-owned state files.
- Deferred interventions through `PENDING_INTERVENTION.md`.
- Debounced timer wake-ups.
- Hook-level deadlines and deterministic fallbacks.
- IPC with authentication.
- Version/capability probing and startup self-tests.
- Final report and decision log.

Excluded from MVP:

- UI/dashboard.
- CLIs other than Claude Code and Codex CLI.
- User-defined custom supervision rules.
- Smart model routing.
- CI/CD integration.
- Multi-agent orchestration.
- Bidirectional supervisee-to-supervisor questions. This is a v0.2 feature and will require explicitly exposing a local MCP/tool interface to the supervisee.

## Component architecture

The system has four separate concerns.

Hook scripts are short-lived processes launched by Claude Code or Codex CLI. They contain no supervision business logic. They serialize the hook event, send it to the wrapper over authenticated IPC, wait for a response within the hook deadline, and return the vendor-specific hook response.

The main wrapper is the long-lived process started by the user with `supervisor`. It owns state, starts and kills the supervisee, runs the event loop, manages IPC, applies fast-path policy, calls the LLM supervisor when needed, enforces hook deadlines, updates health counters, and applies lifecycle actions.

The LLM supervisor is a stateless function call. It receives a compact event/context payload and returns a structured decision object. It does not read or write files, does not hold memory between calls, and does not directly control the supervisee.

State files are persistent session storage in `.supervisor/`. They are read and written only by the wrapper.

## User flow

1. The user installs the package and gets a `supervisor` CLI command.
2. The user writes or selects a markdown task plan. The format is free.
3. The user starts a supervised run:

   ```bash
   supervisor claude --plan TASK.md
   supervisor codex --plan TASK.md
   supervisor claude --mode api --plan TASK.md
   ```

4. The wrapper probes the selected CLI version and required capabilities.
5. The wrapper initializes `.supervisor/` state.
6. The wrapper creates a private runtime directory outside the project tree with mode `0700`, opens a Unix domain socket inside it, and creates a per-session random IPC bearer token in memory.
7. The wrapper installs or prepares hook configuration for the selected supervisee.
8. The wrapper runs startup self-tests: IPC auth, hook fire, supervisor-call isolation, and structured output support.
9. The wrapper launches the supervisee in its own process group with the initial instruction:

   ```text
   Read the file at <selected plan path>. This is your task for the session. Execute it step by step until completion.
   ```

10. The wrapper enters the event loop. Hook events and timer ticks drive supervision until the supervisee exits, the task completes, restart cap is reached, provider failure requires clean exit, or the user interrupts.
11. The wrapper restores any temporary hook configuration, removes runtime files, and prints a final report.

The supervisee is not told about `.supervisor/` or the supervisor. This is not a security boundary. The supervisee may discover project files; the design relies on hook policy and process control, not secrecy of the state directory.

## Operating modes

### Subscription mode

The supervisor LLM calls use the same vendor CLI as the supervisee:

- Claude supervisee: `claude -p`.
- Codex supervisee: `codex exec`.

No separate API key is needed. The user's existing CLI authentication is used. The tradeoff is shared quota with the coding agent. The wrapper does not hardcode model slugs; if the user does not pass a model, the vendor CLI chooses its own default.

### API mode

The supervisor LLM calls use OpenRouter with the user's OpenRouter API key. OpenRouter is used only for supervisor calls; the coding agent continues to use its own CLI authentication or provider configuration.

At startup, the wrapper checks the selected OpenRouter model's structured-output capability metadata. If reliable structured output is unavailable, the wrapper warns and uses parse-and-repair mode. If parse-and-repair repeatedly fails, the run exits cleanly with state preserved.

## State files

All permanent state lives under `.supervisor/` in the project root.

`config.json` contains non-secret session configuration: selected platform, mode, model names where known, timer interval, kill-restart thresholds, plan file path, IPC socket path without token, and the Codex hook installation manifest. It never contains the IPC bearer token or provider API keys.

`PROGRESS.md` contains completed steps, current step, and known issues. The wrapper updates it when the LLM supervisor marks a meaningful step complete.

`DECISIONS.md` is append-only. It stores architectural constraints and decisions that must persist across interventions and restarts.

`LAST_ACTION.md` stores the last meaningful supervisee action in one or two lines.

`PENDING_INTERVENTION.md` is a single-slot deferred correction. Timer-triggered or non-deliverable hook-triggered interventions are written here. The next eligible hook callback atomically claims and clears it under lock before delivery. New pending interventions replace the prior pending message only if the new decision has a higher wrapper sequence number and belongs to the current generation.

`HEALTH.json` stores deterministic health data for the current generation:

- `generation`
- `restart_count`
- `denied_requests`
- `consecutive_failed_tests`
- `repeated_command_count`
- `interventions`
- `minutes_without_progress`
- `risk_signals`
- `last_progress_sequence`
- `last_denial`
- `timeout_fallback_count`
- `parse_failure_count`

`HANDOFF.md` is generated only at kill-restart or provider-failure clean exit. It briefs the next generation or the user on completed work, failure reason, known pitfalls, and next steps.

`log.jsonl` is an append-only event and decision log. Each entry contains monotonic wrapper sequence number, hook event id, generation, source hook, handling path, latency, decision, and any fallback reason.

`codex-stdout.log` and `codex-stderr.log` capture the supervised `codex exec` process output for the current run. Supervised Codex runs use `codex exec --json`, so stdout contains Codex's JSON event stream rather than relying on sparse human output. The logs are truncated at the start of a fresh Codex launch and appended across supervisor restarts within that run.

`codex-hook-trace.log` is a JSONL diagnostic trace written by Supervisor's Codex hook process. It records hook input receipt, IPC responses, and whether the hook emitted empty stdout or Codex JSON. It is separate from hook stdout because Codex parses hook stdout as protocol.

`agent-settings.json` is Claude-only temporary settings passed to Claude Code. It is created at startup and removed at cleanup.

No other permanent state files are introduced. Temporary lock files, temp files for atomic replace, and Unix sockets are implementation artifacts, not user-facing state.

## State locking and concurrency

Hook callbacks can arrive concurrently. The wrapper IPC server accepts concurrent requests, but all persistent state mutation is serialized by per-file locks.

`HEALTH.json` is updated with patch/delta semantics under lock:

1. Acquire lock.
2. Read latest file contents.
3. Verify generation.
4. Apply the delta.
5. Atomic-write the new JSON.
6. Release lock.

Whole-file last-write-wins is forbidden for health updates. Counters must never be overwritten from stale snapshots.

LLM calls are not globally serialized. A global LLM queue would cause later synchronous hooks to miss vendor deadlines. Instead:

- Each event gets a wrapper-assigned monotonic sequence number.
- Each LLM prompt includes the current generation and sequence number.
- Each LLM response is applied only if its generation is still current.
- State-mutating decisions are applied as locked patches.
- Duplicate or superseded decisions are discarded and logged.

`PENDING_INTERVENTION.md` claim-and-clear is atomic:

1. Eligible hook acquires the pending-intervention lock.
2. It reads the pending message.
3. It verifies the message generation matches the active generation.
4. It clears the file with an atomic write.
5. It releases the lock.
6. It attaches the claimed message to the hook response.

Two concurrent hooks cannot deliver the same pending intervention.

## IPC layer

The wrapper creates a private runtime directory with mode `0700` under `$TMPDIR` or `/tmp`, then binds a Unix domain socket inside it. The socket path may be written to `config.json`; it is not secret by itself.

The IPC bearer token is generated per session, held in wrapper memory, and passed to hook scripts through child process environment only. It is never written into project files. This protects against unrelated local processes. It is not a security boundary against a supervisee that can inspect its own process environment.

IPC requests are JSON:

```json
{
  "event_type": "PermissionRequest",
  "event_id": "vendor-event-id-or-generated-id",
  "payload": {},
  "timestamp": "2026-05-24T00:00:00Z",
  "auth_token": "runtime-token"
}
```

The wrapper validates the token, assigns a monotonic sequence number, processes the request, and responds:

```json
{
  "decision_type": "allow",
  "payload": {},
  "deferred_intervention_attached": false,
  "sequence": 123
}
```

Invalid auth receives a deny/no-op response appropriate to the hook type and is logged.

## Fast-path policy

Fast-path policy is deterministic code in `policy.py`. It runs before any LLM call.

### Instant allow

Instant allow applies only when all of the following are true:

- The operation is read-only/informational, or it is a parsed workspace edit using a known file-edit hook payload.
- Every resolved real path is inside the project workspace.
- No resolved path matches the secret-pattern list.
- The command or tool input is parsed confidently.

Examples:

- Claude/Codex file reads inside workspace on non-secret files.
- `Grep`/`Glob` inside workspace on non-secret paths.
- Workspace-scoped `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, and Codex `apply_patch` operations on non-secret paths.
- `cat`, `sed`, `head`, `tail`, `wc`, `ls`, `pwd`, and `find` with bounded workspace paths.
- `git status`, `git log`, and `git diff` without destructive or network flags.
- Version checks such as `python --version`, `node --version`, `pytest --version`.

If path resolution is ambiguous, a symlink escapes the workspace, or a shell command cannot be parsed confidently, route to the LLM.

### Secret-pattern routing

Reads matching secret patterns are not instant-allowed. They route to the LLM with deny bias. Writes matching these patterns are instant-denied.

Secret patterns include:

- `.env`, `.env.*`
- filenames containing `secret`, `credential`, `password`, `passwd`, `token`, `apikey`, `api_key`, `private`, `vault`
- `*.pem`, `*.key`, `*.p12`, `*.pfx`
- `id_rsa*`, `id_ed25519*`
- `.netrc`, `.npmrc`, `.pypirc`
- `.git/`
- `.ssh/`, `.aws/`, `.config/gh/`, `.kube/`, `.docker/config.json`, `.config/gcloud/`
- common cloud credential files such as `credentials`, `credentials.json`, `service-account*.json`

The list is conservative. False positives route to the LLM, not to auto-deny, unless the operation is a write.

### Instant deny

Instant deny applies to operations dangerous regardless of task context:

- Recursive deletion outside the workspace or above the workspace root.
- Writes to secret-pattern paths.
- `curl | bash`, `wget | sh`, or equivalent remote-code-execution pipelines.
- Force push to protected branches: `main`, `master`, `prod`, `production`, `release/*`.
- Broad permission changes such as `chmod 777` or recursive permission changes outside known build/cache directories.
- Attempts to modify supervisor runtime files, IPC socket paths, or hook scripts.

### Session-learned allow

If the LLM returns a type-2 permission decision, the wrapper creates an in-memory allow rule scoped to the current generation. The allow rule is structural, not textual: command/tool name, normalized arguments, workspace scope, and path constraints. It resets on kill-restart and is never persisted across sessions in MVP.

## Hook-level timing

Every synchronous hook-triggered LLM call runs under a deadline derived from the active vendor hook timeout.

At startup, the wrapper discovers or configures the maximum supported hook timeout for the installed CLI. It verifies this with a hook self-test. For each hook callback, the wrapper computes remaining budget and aborts waiting for the LLM at 90 percent of that budget, leaving time to transmit a hook response.

Retries, schema repair, and provider calls inside a synchronous hook must fit within the same deadline. There is no independent retry schedule that can exceed the hook budget.

Timeout fallbacks:

- Permission event: deny.
- PreToolUse guardrail event: deny. Codex exec has no interactive permission fallback, and Codex 0.130.0 treats PreToolUse as continue-or-block rather than as a deferred approval channel.
- Observation event: no-op.
- Kill-restart candidate: keep current generation alive.

The slow LLM response may be logged when it eventually arrives, but it is not applied to the stale event.

Timer-triggered LLM calls are not hook-bound. They may wait through provider retry/backoff. If the provider is unreachable after retries, the wrapper writes a handoff, terminates the supervisee cleanly, restores hook configuration, and exits with state preserved.

## LLM decision schemas

The LLM supervisor always returns structured JSON validated by Pydantic and JSON Schema.

Native enforcement:

- Claude subscription mode uses `claude -p --json-schema`.
- Codex subscription mode uses `codex exec --output-schema`. Codex 0.130.0 forwards the schema into OpenAI structured outputs as `text.format.schema` with strict mode enabled, so the Codex schema file must use the OpenAI strict subset: object schemas include `additionalProperties: false`, every property is listed in `required`, nullable fields use a union with `null`, and arbitrary object payloads are avoided.
- OpenRouter API mode uses provider structured-output support when available.

If output is invalid:

1. Retry once with a repair prompt inside the same hook deadline when hook-bound.
2. If still invalid, apply deterministic fallback:
   - Permission: deny.
   - Observation: no-op.
   - Kill candidate: keep alive.
3. Increment `parse_failure_count` under lock.

API models without reliable structured output start in parse-and-repair mode and are allowed a higher failure threshold before clean exit.

## Supervisor wake-up logic

The wrapper wakes the LLM supervisor only when deterministic code cannot safely decide.

Trigger types:

- Permission request or PreToolUse event that falls through fast-path policy.
- Debounced timer tick when local state indicates risk or unresolved work.
- Kill-restart candidate.
- Action/observation events only when they are delivering an already queued intervention; otherwise PostToolUse, PostToolBatch, Stop, and SubagentStop return no-op synchronously so they do not burn a vendor hook deadline after successful work.

Timer tick default is 120 seconds and resets after event-driven wake-ups. On each tick, the wrapper first checks local state. If health, progress, active tool calls, risk signals, and pending intervention state are unchanged, no LLM call is made.

Timer-triggered decisions can:

- Update wrapper-owned state.
- Write a single pending intervention.
- Set risk signals.
- Confirm kill-restart, which the wrapper applies immediately through process control.

Timer-triggered decisions cannot synchronously deliver a message into the active model turn. Message delivery waits for an eligible hook callback.

## Reaction scenarios

### Permission request

Permission decisions have three types:

- Type 1: allow this specific request.
- Type 2: allow this class for the current generation.
- Type 3: deny with reason.

The wrapper applies type 2 by adding an in-memory session allow rule. It never tells the supervisee to "stop asking"; future matching events are intercepted by policy.

If a denial encodes a persistent architectural rule, the LLM response includes a `decision_entry`, and the wrapper appends it to `DECISIONS.md` under lock.

### Scenario 1 - fine

The LLM signals no intervention needed. It may optionally mark a plan step complete. The wrapper patches `PROGRESS.md`, `LAST_ACTION.md`, and `HEALTH.json`.

### Scenario 2 - intervention

The LLM returns a corrective message and optional persistent decision entries.

If the trigger is an eligible hook callback, the wrapper attaches the correction to the vendor hook response. If no clean delivery channel is active, the wrapper writes it to `PENDING_INTERVENTION.md`.

Eligible delivery hooks:

- Claude `PostToolBatch` with `hookSpecificOutput.additionalContext`.
- Claude `PostToolUse` with `hookSpecificOutput.additionalContext`.
- Claude `Stop` with `decision: "block"` and reason.
- Codex `Stop` with `decision: "block"` and reason.
- Codex `PostToolUse` only if startup self-test confirms a working `additionalContext` equivalent on the installed version.

`PreToolUse` is never used for deferred intervention delivery.

### Scenario 3 - kill-restart

The wrapper marks a kill-restart candidate when deterministic thresholds are met:

- Three interventions without progress.
- Four substantially similar failing commands.
- Fifteen minutes without progress while no legitimate long-running operation is tracked.
- Bypass/rephrase attempt after denial.
- Repeated timeout fallbacks or parse failures that make supervision ineffective.

The LLM judges whether to confirm kill-restart. If confirmed, it returns handoff content. The wrapper writes `HANDOFF.md`, terminates the supervisee process group, clears generation-scoped state, increments `generation` and `restart_count`, and launches a new supervisee instructed to read the plan, `DECISIONS.md`, and `HANDOFF.md`.

If `restart_count >= 3`, the wrapper exits with a "task stuck" report without consulting the LLM.

### Scenario 4 - task complete

The LLM signals completion or all plan items are marked complete in `PROGRESS.md`. The wrapper gracefully terminates the supervisee if still running and prints the final report.

## Claude Code integration

Claude Code uses a session-scoped settings file at `.supervisor/agent-settings.json`, passed via `--settings`.

Registered hooks:

- `PreToolUse`: instant-deny guardrails only. Response uses `hookSpecificOutput.permissionDecision`.
- `PermissionRequest`: primary permission decision channel. Response uses `hookSpecificOutput.decision.behavior`.
- `PostToolBatch`: preferred action observation and intervention delivery via `hookSpecificOutput.additionalContext`.
- `PostToolUse`: fallback observation and intervention delivery via `hookSpecificOutput.additionalContext`.
- `Stop`: turn-end delivery via `decision: "block"` with reason.
- `PreCompact`: health signal.
- `SessionEnd`: cleanup verification.

Claude supervisor calls in subscription mode are isolated with a settings file containing hook disabling configuration and restricted setting sources. Startup self-test must prove a trivial `claude -p` supervisor call does not trigger the session hooks. If isolation cannot be proven, startup fails before the supervised task begins.

If the user launches the supervisee with a bypass/auto permission mode, the startup self-test verifies whether `PreToolUse` and `PermissionRequest` still behave as required. If not, the wrapper rejects that mode for supervised runs.

## Codex CLI integration

Codex hooks are discovered from Codex hook configuration files, not from a `--settings` flag. The MVP uses repo-level `<repo>/.codex/hooks.json` with crash-safe merge and cleanup.

Registered hooks:

- `PreToolUse`: pre-dispatch guardrail. Deterministic fast-path policy handles obvious allow/deny, and gray-zone cases call the supervisor LLM inline because exec mode cannot rely on a later interactive permission fallback.
- `PermissionRequest`: approval-time allow/deny channel when Codex's own tool policy requires approval.
- `PostToolUse`: action observation and intervention delivery only if self-tested context injection works.
- `Stop`: turn-end intervention delivery via `decision: "block"`.
- `PreCompact` and `PostCompact`: health signals.

Codex CLI 0.130.0 supports the hook event names `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`, `SessionStart`, `UserPromptSubmit`, and `Stop`. The MVP installs only the Supervisor-owned events listed above.

Codex exec-mode hook protocol in 0.130.0:

- `PreToolUse` runs before the tool is dispatched. Empty output or `{}` means continue. Supervisor emits empty stdout for allow/no-op. `hookSpecificOutput.permissionDecision: "deny"` with a non-empty `permissionDecisionReason` blocks the tool. `permissionDecision: "allow"` and legacy `decision: "approve"` are explicitly unsupported by Codex's parser.
- `PermissionRequest` runs only inside Codex's approval path, before guardian/user approval. It accepts `hookSpecificOutput.decision.behavior` of `allow` or `deny`; a missing decision falls through to Codex's normal approval path.
- `PostToolUse` accepts empty output for no-op, `hookSpecificOutput.additionalContext` for model-visible follow-up context, and legacy `decision: "block"` with `reason` for feedback/replacement output.
- `Stop` accepts empty output for completion and `decision: "block"` with `reason` when the hook wants Codex to continue with an injected prompt fragment.
- `PreCompact` and `PostCompact` accept empty output for no-op and universal `continue: false` plus `stopReason` if execution should stop.
- `codex exec` defaults approval policy to `never`, and the exec front-end rejects interactive approval requests such as command, file-change, and apply-patch approvals. Therefore Supervisor must never rely on a non-decisive permission hook response in exec mode. Gray-zone `PreToolUse` and `PermissionRequest` callbacks call the supervisor LLM inline and are coerced to allow/deny; non-actionable LLM results and timeouts are denied.

The MVP does not use Codex app-server or SDK steering. Codex process control is OS-level process group kill. Every noninteractive `codex exec` invocation owned by Supervisor includes `--skip-git-repo-check` so the supervised task, hook-fire self-test, and isolated supervisor LLM calls all share the same git-trust behavior. The supervised Codex command is launched as `codex exec --skip-git-repo-check --json --sandbox workspace-write ...` so ordinary workspace writes do not require unsupported interactive approvals and stdout contains an event stream. The child stdin is connected to `/dev/null`; Codex exec treats piped stdin as extra prompt context when a positional prompt is present, so leaving a pipe open can silently block startup or progress. Codex stdout and stderr are written to `.supervisor/codex-stdout.log` and `.supervisor/codex-stderr.log`; hook protocol traces are written to `.supervisor/codex-hook-trace.log`.

### Codex hook install, trust, and restore

Codex hook install must not clobber user hook configuration.

Install algorithm:

1. Acquire a repo-scoped hook install lock. The lock is transient and may live in `.supervisor/` or the runtime directory.
2. Read current `<repo>/.codex/hooks.json` if present.
3. If malformed, abort startup with a clear error. Do not overwrite malformed user config.
4. Remove stale supervisor-owned hook entries from prior crashed runs by stable marker/id.
5. Merge supervisor hook entries into the current user config.
6. Write via atomic temp-file replace.
7. Store a manifest in `.supervisor/config.json` containing supervisor hook ids, original file existence flag, installation timestamp, and content hash before/after install. This is not a backup used for blind restore; it is a cleanup guide.
8. Release the install lock.

Cleanup algorithm:

1. Acquire the hook install lock.
2. Read current `<repo>/.codex/hooks.json`.
3. Remove only supervisor-owned entries matching the manifest marker/id.
4. Preserve any user edits made during the run.
5. If the resulting config is empty and the file did not exist before install, delete the file.
6. Otherwise atomic-write the cleaned config.
7. Clear the manifest fields from `config.json`.
8. Release the lock.

Crash recovery:

- On startup, before installing hooks, remove stale supervisor-owned entries from previous sessions using markers in `config.json` and stable hook ids in `hooks.json`.
- If `config.json` is missing but supervisor-owned hook markers exist, remove those markers conservatively and preserve all other entries.
- Never restore an entire old file over the current file.

Trust preflight:

1. Before installing hooks, the wrapper computes the Supervisor hook keys and current hashes that Codex will derive after merge. Codex 0.130.0 keys hook trust as `<hook source path>:<event label>:<group index>:<handler index>`, where the source path for repo hooks is the absolute `<repo>/.codex/hooks.json` path and event labels are values such as `pre_tool_use`, `permission_request`, and `stop`.
2. The wrapper reads Codex trust state from `$CODEX_HOME/config.toml` when `CODEX_HOME` is set, otherwise from `~/.codex/config.toml`. The trusted state lives under `hooks.state`, with per-hook entries containing `trusted_hash` and optional `enabled`. The wrapper only reads this file; it must not write or edit Codex trust state.
3. If every planned Supervisor hook has a matching `trusted_hash` and is not explicitly disabled, the wrapper skips the trust preflight entirely, installs hooks, and proceeds silently. Repeat runs must not nag users.
4. If any planned Supervisor hook is missing, modified, or disabled in Codex trust state, the wrapper prints one paragraph explaining the one-time setup and asks the user whether to continue.
5. On `yes`, the wrapper installs `.codex/hooks.json`, prints a short instruction, then launches interactive `codex --no-alt-screen` attached to a pseudo-terminal even when the wrapper's own stdout is piped. This avoids Codex's "stdout is not a terminal" failure while keeping setup visible when a real terminal is available.
6. The wrapper automates Codex's native review UI by typing `/hooks` through the PTY as real TUI input, pressing Enter after the slash-command popup recognizes it, then navigating the hooks browser. For each Supervisor-owned hook that is not yet ready, it opens that event, moves to the Supervisor handler row, presses `t` when the hook hash is untrusted or modified, presses Enter when a trusted hook is disabled, then returns to the event list. Hooks that already have the expected `trusted_hash` and are enabled are skipped.
7. The wrapper polls Codex trust state in the background and prints progress such as `Waiting for hook trust approval in Codex... (0/6 hooks trusted)` as counts change. The setup wait is long-running, currently 10 minutes, so users can still complete review manually if automation lags.
8. If trust is incomplete when setup exits or times out, startup fails cleanly but leaves the Supervisor hooks installed in `.codex/hooks.json` so the next wrapper run can resume from partial `hooks.state` progress. The normal cleanup path removes Supervisor hooks after a completed supervised run.
9. When Codex records the expected trusted hashes and the hooks are enabled, the wrapper terminates the setup Codex session and runs the Codex hook-fire self-test. If no expected hook callback reaches Supervisor IPC, startup exits cleanly with the self-test failure detail. The supervised run never starts without working hooks.

No human involvement is required after this preflight succeeds.

Codex supervisor calls in subscription mode run from a temporary working directory that has no `.codex/hooks.json`, with `--ignore-user-config` enabled. Startup self-test must prove the headless supervisor call does not trigger project/user hooks.

## Process lifecycle

The supervisee is launched in its own process group/session.

Kill escalation:

1. Send soft interrupt signal.
2. Wait configured timeout, default 5 seconds.
3. Send `SIGTERM` to process group.
4. Wait configured timeout, default 5 seconds.
5. Send `SIGKILL` to process group.
6. Close pty/pipe descriptors.
7. Drain remaining stdout/stderr.
8. Reap child processes.

Codex app-server `turn/interrupt` is not used in MVP because the supervisee is not launched through app-server.

Long-running tool calls are tracked with hook start/end events only. There is no generic streaming output assumption. If a tool call remains open longer than the configured threshold, `minutes_without_progress` accrues and the situation may become a kill-restart candidate.

## Version and capability handling

Startup probes:

- `claude --version`
- `claude --help`
- trivial `claude -p` structured-output call
- Claude hook-fire and hook-isolation self-tests
- `codex --version`
- `codex exec --help`
- `codex features list` when available
- Codex hook-fire and hook-isolation self-tests
- OpenRouter model capability metadata in API mode

If required capabilities are missing, startup exits before launching the supervised task. The error names the missing capability and suggested vendor CLI upgrade path.

All vendor-specific schema field paths are verified through self-tests where possible. If an installed version differs from current docs, the adapter either switches to a supported fallback or rejects that version.

## Repository structure

```text
supervisor/
  main.py
  wrapper.py
  policy.py
  health.py
  state.py
  timing.py
  version.py
  ipc/
  hooks/
  adapters/
  llm_driver/
  schemas/
  prompts/
  process.py
tests/
  fake_agent/
pyproject.toml
README.md
LICENSE
```

Key modules:

- `policy.py`: fast-path rules, workspace path resolution, secret patterns.
- `health.py`: health delta operations and kill-candidate detection.
- `state.py`: locked state file operations and atomic writes.
- `timing.py`: hook budget computation and timeout fallbacks.
- `version.py`: capability probes and startup self-tests.
- `adapters/codex.py`: hook merge/restore/trust preflight.
- `adapters/claude.py`: session settings and hook schema mapping.

Dependencies:

- `pydantic`
- `click` or `typer`
- `httpx`
- `filelock` or equivalent
- `pexpect` or `ptyprocess` only for fallback lifecycle handling
- `openai` and/or direct HTTP for OpenRouter-compatible calls

## Implementation sequence

1. Schemas: event types, decision types, health deltas, state formats, log entries.
2. Locked state management: atomic writes, `HEALTH.json` patches, pending intervention claim/clear.
3. Policy engine: workspace path resolution, secret routing, instant allow/deny, session allow rules.
4. Timing module: vendor hook budgets, per-event deadlines, fallback decisions.
5. IPC server/client: Unix socket, auth, monotonic sequence assignment, concurrent requests.
6. LLM drivers: headless Claude, headless Codex, OpenRouter API, schema enforcement.
7. Fake agent harness: concurrent hooks, timeouts, pending intervention, kill-restart.
8. Claude adapter: settings file, hooks, isolation self-test.
9. Codex adapter: hook install/cleanup, trust preflight, hook-fire self-test, isolation self-test.
10. Process lifecycle: launch, kill escalation, generation restart.
11. Wrapper event loop: wake-up routing, state assembly, decision application.
12. CLI UX: plan selection, resume/start-over, final report.
13. Integration smoke tests against real Claude Code and Codex CLI versions.

## Test plan

Unit tests:

- Workspace path policy with symlinks and outside-workspace escapes.
- Secret-pattern routing for reads and instant-deny for writes.
- Session allow rule matching and reset on restart.
- `HEALTH.json` concurrent delta application.
- `PENDING_INTERVENTION.md` atomic claim/clear under concurrent delivery.
- Hook deadline fallbacks.
- Stale LLM response discard.
- Codex `hooks.json` merge, cleanup, user-edit preservation, malformed JSON abort, crash recovery.
- Atomic write behavior.

Fake-agent tests:

- Parallel hook callbacks.
- Timeout fallback paths.
- Timer-triggered pending intervention and later delivery.
- Kill-restart generation reset.
- Provider failure clean exit with handoff.
- Restart cap final report.

Integration smoke tests:

- Claude hook fire.
- Claude supervisor-call isolation.
- Claude additionalContext delivery.
- Codex hook trust preflight.
- Codex hook fire.
- Codex hook cleanup after normal exit.
- Codex hook cleanup after simulated crash.
- Codex supervisor-call isolation with temp cwd and `--ignore-user-config`.
- `codex exec --json` observability does not affect control path.
- OpenRouter structured-output and parse-and-repair paths.

## Acceptance criteria

The MVP is implementation-complete when:

- A user can run a supervised Claude Code task without approving actions mid-run.
- A user can run a supervised Codex task after one-time hook trust preflight without approving actions mid-run.
- Fast-path allow/deny works without LLM calls for obvious cases.
- Gray-zone permission requests receive LLM decisions under hook deadlines.
- Timer wake-ups do not call the LLM when state is unchanged.
- Timer interventions are delivered through the next eligible hook or escalated to kill-restart if necessary.
- Kill-restart produces `HANDOFF.md`, starts a new generation, and preserves decisions/progress.
- State files remain valid under concurrent hook events.
- Codex hook config is restored without clobbering user edits, including after crash recovery.
- Supervisor headless calls do not recursively trigger supervision hooks.
- Final reports account for decisions, interventions, timeouts, restarts, and termination reason.
