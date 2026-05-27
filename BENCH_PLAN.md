Correct. My previous benchmark structure was wrong.

Use this replacement benchmark section. It removes `tasks/`, uses `TASK.md` directly, and runs Sentinel inside each `TESTS/<number>/` directory without copying. The current Sentinel plan already supports `supervisor --task TASK.md`, initializes `.supervisor/`, and uses the app-server runtime/state model, so the benchmark should reuse that normal runtime instead of inventing a separate task layout. 

## Benchmark System

Sentinel must support one benchmark command:

```bash
supervisor --bench
```

The benchmark directory is always:

```text
TESTS/
```

`supervisor --bench` runs every numeric immediate subfolder inside `TESTS/`, sorted numerically.

Example:

```text
TESTS/
  1/
    TASK.md
    result.json
    .supervisor/
  2/
    TASK.md
    result.json
    .supervisor/
  10/
    TASK.md
    result.json
    .supervisor/
  result.json
```

Each numeric subfolder is one benchmark test. The folder name is the test id. Folder names must be decimal integers such as `1`, `2`, `3`, `10`.

Each test folder must contain:

```text
TESTS/<n>/TASK.md
```

There are should be 5 tests, you should generate simple different tasks by yourself.

There is no `tasks/` directory. There is no `task.md` inside a nested task folder. There is no workspace copy. Sentinel runs directly inside `TESTS/<n>/`.

## Benchmark Execution

When the user runs:

```bash
supervisor --bench
```

Sentinel performs this sequence:

```text
1. Resolve ./TESTS relative to the current working directory.

2. Find all immediate child directories of TESTS whose names are decimal integers.

3. Sort them numerically:
   TESTS/1
   TESTS/2
   TESTS/10

4. For each test directory:
   a. Enter TESTS/<n> as the current working directory.
   b. Require TESTS/<n>/TASK.md.
   c. Clear previous benchmark runtime state:
      - delete TESTS/<n>/.supervisor if it exists;
      - overwrite TESTS/<n>/result.json at the end.
   d. Run normal Sentinel runtime exactly as:
      supervisor --task TASK.md
      but internally, not by spawning another supervisor process.
   e. Use TESTS/<n> as the project root.
   f. Use TESTS/<n>/TASK.md as the task file.
   g. Write Sentinel runtime state to:
      TESTS/<n>/.supervisor/
   h. Collect benchmark metrics.
   i. Always write:
      TESTS/<n>/result.json

5. After all test directories finish, read all per-test result.json files from this benchmark run.

6. Write aggregate:
   TESTS/result.json
```

The benchmark runner must not copy test folders. It must not create worktrees. It must not require Git. It must not run inside a temporary duplicated workspace. The benchmark is allowed to mutate each `TESTS/<n>/` directory because that is the directory being tested.

## Test Directory Contract

Required:

```text
TESTS/<n>/TASK.md
```

Optional:

```text
TESTS/<n>/bench.json
```

Example `bench.json`:

```json
{
  "timeout_seconds": 1800,
  "validation": [
    "pytest -q"
  ]
}
```

Defaults if `bench.json` is missing:

```text
timeout_seconds = 1800
validation = []
```

Validation commands run in `TESTS/<n>/` after Sentinel finishes. Validation time is measured separately.

If validation is empty, `validation_pass` is `null`, not `false`.

## Per-Test Runtime State

For each benchmark test, normal Sentinel state is written inside that test directory:

```text
TESTS/<n>/
  TASK.md
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
    perf.jsonl
  result.json
```

This matches the main Sentinel plan, which uses `.supervisor/` for config, progress, decisions, health, handoff, final report, and event logs. 

`perf.jsonl` is benchmark-only runtime telemetry. It is used to compute `result.json`.

## Per-Test Result File

Each test must write:

```text
TESTS/<n>/result.json
```

Shape:

```json
{
  "run_id": "2026-05-27T12-00-00Z_7f3a",
  "test_id": "1",
  "test_dir": "TESTS/1",
  "task_file": "TESTS/1/TASK.md",
  "status": "success",
  "success": 1,
  "started_at": "2026-05-27T12:00:00Z",
  "finished_at": "2026-05-27T12:04:32Z",
  "metrics": {
    "wall_time_ms": 272000,
    "startup_time_ms": 3100,
    "time_to_first_action_ms": 9200,

    "supervisor_wait_time_ms": 41000,
    "approval_wait_time_ms": 4800,
    "validation_time_ms": 13000,
    "restart_recovery_time_ms": 0,
    "supervision_overhead_ratio": 0.1507,

    "completed_coder_action_count": 23,
    "supervisor_call_count": 18,
    "approval_request_count": 6,
    "restart_count": 0,

    "supervisor_context_tokens_total_est": 54000,
    "supervisor_context_tokens_mean_est": 3000,
    "supervisor_context_tokens_max_est": 4700,
    "supervisor_context_truncation_count": 0,

    "coder_input_tokens": 120000,
    "coder_cached_input_tokens": 30000,
    "coder_output_tokens": 18000,
    "coder_total_tokens": 138000,

    "supervisor_input_tokens": 54000,
    "supervisor_cached_input_tokens": 0,
    "supervisor_output_tokens": 6000,
    "supervisor_total_tokens": 60000,

    "total_input_tokens": 174000,
    "total_cached_input_tokens": 30000,
    "total_output_tokens": 24000,
    "total_tokens": 198000,

    "supervisor_token_share": 0.303,
    "supervisor_tokens_per_call": 3333.33
  },
  "validation": {
    "validation_pass": true,
    "commands": [
      {
        "command": "pytest -q",
        "exit_code": 0,
        "duration_ms": 13000
      }
    ]
  },
  "error": null
}
```

Allowed `status` values:

```text
success
failed
timeout
stuck
provider_failure
invalid_test
crashed
```

`success` is numeric:

```text
1 = test succeeded
0 = test failed, timed out, got stuck, crashed, or was invalid
```

A test is `invalid_test` if `TASK.md` is missing.

Even invalid, failed, timed-out, stuck, provider-failed, and crashed tests must produce `TESTS/<n>/result.json`.

## Metrics To Track

Only track these.

Time metrics:

```text
wall_time_ms
startup_time_ms
time_to_first_action_ms
supervisor_wait_time_ms
approval_wait_time_ms
validation_time_ms
restart_recovery_time_ms
supervision_overhead_ratio
```

Count metrics:

```text
completed_coder_action_count
supervisor_call_count
approval_request_count
restart_count
```

Supervisor context metrics:

```text
supervisor_context_tokens_total_est
supervisor_context_tokens_mean_est
supervisor_context_tokens_max_est
supervisor_context_truncation_count
```

Token metrics:

```text
coder_input_tokens
coder_cached_input_tokens
coder_output_tokens
coder_total_tokens

supervisor_input_tokens
supervisor_cached_input_tokens
supervisor_output_tokens
supervisor_total_tokens

total_input_tokens
total_cached_input_tokens
total_output_tokens
total_tokens

supervisor_token_share
supervisor_tokens_per_call
```

Do not track UI latency, event count, average gap between events, line count, raw character count, or rate-limit percentage in the MVP benchmark.

## Time Metric Definitions

```text
wall_time_ms =
  run_finished - run_started

startup_time_ms =
  first_coder_turn_started - run_started

time_to_first_action_ms =
  first_coder_action_started - first_coder_turn_started

supervisor_wait_time_ms =
  total time Sentinel/coder is blocked waiting for supervisor decision

approval_wait_time_ms =
  total time between approval_requested and approval_decided

validation_time_ms =
  total duration of validation commands from bench.json

restart_recovery_time_ms =
  total time spent inside restart flows

supervision_overhead_ratio =
  supervisor_wait_time_ms / wall_time_ms
```

All duration metrics use a monotonic clock. Wall-clock timestamps are used only for readable `started_at` and `finished_at`.

## Context Usage

The supervisor is stateless. Sentinel must measure context before every supervisor call.

For each supervisor wake packet, write a `supervisor_context_built` event to:

```text
TESTS/<n>/.supervisor/perf.jsonl
```

Shape:

```json
{
  "event": "supervisor_context_built",
  "supervisor_call_id": "sup_18",
  "trigger": "completed_action",
  "estimated_tokens": 3020,
  "section_estimated_tokens": {
    "task": 500,
    "progress": 300,
    "decisions": 350,
    "last_action": 40,
    "health": 110,
    "handoff": 0,
    "recent_events": 900,
    "approval_or_action_summary": 320,
    "filesystem_change_summary": 220,
    "schema_and_instructions": 280
  },
  "truncated_sections": []
}
```

Use a deterministic estimator for MVP:

```text
estimated_tokens = ceil(character_count / 4)
```

This is only for context-size comparison. Actual token usage must come from app-server token usage events when available.

Per-test context metrics:

```text
supervisor_context_tokens_total_est =
  sum estimated_tokens across all supervisor calls

supervisor_context_tokens_mean_est =
  mean estimated_tokens across supervisor calls

supervisor_context_tokens_max_est =
  max estimated_tokens across supervisor calls

supervisor_context_truncation_count =
  number of supervisor calls where any section was truncated
```

## Token Usage

Actual token usage comes from app-server token usage events when available. If a token metric is not emitted by the installed Codex app-server version, store it as `null`, not `0`.

Coder token usage:

```text
The coder thread is persistent.
Use token usage snapshot deltas for the coder thread.
Final coder usage = final coder snapshot - initial coder snapshot.
```

Supervisor token usage:

```text
Each supervisor decision uses a fresh app-server thread.
Attribute the full token usage of that fresh supervisor thread to that one supervisor call.
Sum all supervisor call usages for the test.
```

Total token usage:

```text
total_input_tokens =
  coder_input_tokens + supervisor_input_tokens

total_cached_input_tokens =
  coder_cached_input_tokens + supervisor_cached_input_tokens

total_output_tokens =
  coder_output_tokens + supervisor_output_tokens

total_tokens =
  coder_total_tokens + supervisor_total_tokens

supervisor_token_share =
  supervisor_total_tokens / total_tokens

supervisor_tokens_per_call =
  supervisor_total_tokens / supervisor_call_count
```

If denominator is zero or null, derived metric is `null`.

## Aggregate Result File

After all numeric test folders finish, Sentinel writes:

```text
TESTS/result.json
```

Shape:

```json
{
  "run_id": "2026-05-27T12-00-00Z_7f3a",
  "tests_dir": "TESTS",
  "test_count": 3,
  "completed_count": 3,
  "failed_count": 1,
  "started_at": "2026-05-27T12:00:00Z",
  "finished_at": "2026-05-27T12:18:41Z",
  "means": {
    "success": 0.6667,

    "wall_time_ms": 301000,
    "startup_time_ms": 3300,
    "time_to_first_action_ms": 9700,

    "supervisor_wait_time_ms": 51000,
    "approval_wait_time_ms": 6200,
    "validation_time_ms": 14000,
    "restart_recovery_time_ms": 4400,
    "supervision_overhead_ratio": 0.1694,

    "completed_coder_action_count": 27.33,
    "supervisor_call_count": 21.67,
    "approval_request_count": 7.33,
    "restart_count": 0.33,

    "supervisor_context_tokens_total_est": 65000,
    "supervisor_context_tokens_mean_est": 3100,
    "supervisor_context_tokens_max_est": 5200,
    "supervisor_context_truncation_count": 0,

    "coder_input_tokens": 135000,
    "coder_cached_input_tokens": 32000,
    "coder_output_tokens": 21000,
    "coder_total_tokens": 156000,

    "supervisor_input_tokens": 65000,
    "supervisor_cached_input_tokens": 0,
    "supervisor_output_tokens": 7200,
    "supervisor_total_tokens": 72200,

    "total_input_tokens": 200000,
    "total_cached_input_tokens": 32000,
    "total_output_tokens": 28200,
    "total_tokens": 228200,

    "supervisor_token_share": 0.3164,
    "supervisor_tokens_per_call": 3332.41
  }
}
```

Aggregation rules:

```text
1. Include only numeric immediate subfolders of TESTS.

2. Read TESTS/<n>/result.json files written by the current benchmark run.

3. For every numeric value under metrics:
   compute arithmetic mean across test folders.

4. For success:
   mean(success) is the benchmark success rate.

5. For null values:
   exclude null from that metric's denominator.
   if every value for a metric is null, aggregate value is null.

6. Do not average strings, arrays, objects, timestamps, or error messages.

7. Per-test result files are the source of truth.
   TESTS/result.json is only the aggregate mean report.
```

## Benchmark Internal Events

During each test run, Sentinel writes:

```text
TESTS/<n>/.supervisor/perf.jsonl
```

Required events:

```text
run_started
appserver_started
appserver_initialized
coder_thread_started
coder_turn_started
first_coder_action_started
approval_requested
approval_decided
supervisor_context_built
supervisor_call_started
supervisor_call_finished
supervisor_decision_applied
validation_started
validation_finished
restart_started
restart_finished
run_finished
token_usage_updated
```

`TESTS/<n>/result.json` is computed from:

```text
TESTS/<n>/.supervisor/perf.jsonl
TESTS/<n>/.supervisor/events.jsonl
TESTS/<n>/.supervisor/HEALTH.json
TESTS/<n>/.supervisor/FINAL_REPORT.md
validation command results
```

## Benchmark Implementation Modules

Add:

```text
supervisor/bench.py
supervisor/bench_runner.py
supervisor/bench_metrics.py
supervisor/bench_results.py
supervisor/bench_context.py
supervisor/bench_tokens.py
```

Responsibilities:

```text
bench.py
  CLI entrypoint for supervisor bench.

bench_runner.py
  Discover TESTS/<number>/ folders.
  Run Sentinel directly inside each test folder.
  Enforce per-test timeout.
  Always write TESTS/<n>/result.json.

bench_metrics.py
  Compute time and count metrics from perf/events.

bench_context.py
  Measure supervisor wake packet estimated tokens.

bench_tokens.py
  Normalize app-server token usage into coder/supervisor/total usage.

bench_results.py
  Write per-test result.json.
  Read current-run per-test results.
  Write TESTS/result.json with means.
```

## Acceptance Criteria

```text
- `supervisor --bench` requires ./TESTS to exist.

- `supervisor --bench` discovers only numeric immediate subfolders of TESTS.

- Test folders run in numeric order.

- Each test folder must contain TASK.md.

- Sentinel runs directly inside TESTS/<n> without copying.

- Sentinel uses TESTS/<n> as the project root.

- Sentinel uses TESTS/<n>/TASK.md as the task file.

- Each test produces TESTS/<n>/result.json.

- Each test writes runtime state under TESTS/<n>/.supervisor/.

- Before each test, previous TESTS/<n>/.supervisor is removed to avoid contaminated metrics.

- Failed, timed-out, invalid, provider-failed, stuck, and crashed tests still produce result.json.

- After all tests, aggregate TESTS/result.json is written.

- TESTS/result.json contains arithmetic means for numeric metrics from per-test result files.

- Null token metrics are not treated as zero.

- No Git repository, commit, branch, worktree, temporary workspace copy, or git command is required for benchmark execution.

- Benchmark mode is non-interactive and must never wait for human approval.
```

Direct patch instruction for Codex:

```text
Replace the previous Benchmark System section.

Benchmark layout:
- Use TESTS/<number>/TASK.md.
- Do not use TESTS/<number>/tasks/.../task.md.
- Do not copy benchmark folders.
- Run Sentinel directly inside each TESTS/<number> directory.
- Use TESTS/<number> as project root.
- Use TASK.md as the selected task.
- Write normal Sentinel state to TESTS/<number>/.supervisor/.
- Write per-test metrics to TESTS/<number>/result.json.
- Write aggregate means to TESTS/result.json.

The command is exactly:
  supervisor --bench
```
