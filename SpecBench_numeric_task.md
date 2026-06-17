# Sentinel runner: SpecBench by numeric task number

This file is the local Codex instruction file for running the supervisor on SpecBench tasks on a remote server.

The remote server is only the execution target. SpecBench is assumed to already be installed there at `/root/SpecBench`; do not clone, install, update, or modify SpecBench from this runbook.

The user says `Run on task N`, where `N` is a 1-based number in the SpecBench task registry on the remote server. Resolve that number to the corresponding SpecBench `task_id`, run the supervisor exactly once on that task, then score with SpecBench validation and held-out tests.

You are a runner, not a judge. Do not evaluate supervisor quality. Do not touch the supervisor logic, coder logic, prompts, scoring logic, hidden tests, or benchmark tasks. Report facts only. The analysis pass happens separately, later.

There is one narrow exception: you may fix execution-environment problems that prevent a valid run, such as bad permissions, broken auth, full disk, a port/name collision, Docker/service not running when the bridge requires it, or path/config mistakes in the run harness. You may not install or update SpecBench from this file, and you may not change what is being measured.

## Local file location

This runbook stays on the local computer. Codex reads it locally, then executes the shell blocks that SSH into the remote server. Do not upload this `.md` file as a required server artifact.

## Assumed server layout

All remote paths below are intentional. Do not invent alternate locations unless the user explicitly tells you the server is different.

```text
/root/SpecBench/
  Already-installed official SpecBench checkout.
  Its Python environment already exists at /root/SpecBench/.venv.

/root/sentinel/
  The supervisor repository.
  Its Python environment already exists at /root/sentinel/.venv.

/root/sentinel/scripts/run_sentinel_specbench_attempt.py
  The bridge runner that connects the supervisor to one SpecBench task.
  This file must be present. Do not use a runner for any other benchmark.

/root/.codex/auth.json
/root/.codex/config.toml
  Codex CLI auth/config. Keep both chmod 600. Keep web search disabled in config.

/root/specbench-runs/
  Output root for all runs.
```

If `/root/SpecBench`, `/root/SpecBench/.venv`, the SpecBench task registry, or the bridge runner is missing, stop and report that the server is not prepared. Do not install benchmark dependencies during the run.

The bridge runner must do the following for one `task_id`: load the SpecBench task, create an isolated workspace containing starter code and visible validation tests only, invoke the supervisor exactly once, collect the supervisor/coder traces and final workspace diff, then run validation and held-out evaluation after the agent run. Held-out tests may live in `/root/SpecBench`, but they must not be copied into the agent workspace or shown in the prompt.

## Task selection: `Run on task N`

When the user says:

```text
Run on task N
```

interpret `N` as the 1-based index of the SpecBench task registry as loaded from:

```text
/root/SpecBench/benchmarks/spec_bench/adapter.py
```

Rules:

- `N=1` means the first registry entry.
- Do not sort, filter, shuffle, or re-rank the registry before numbering.
- If the registry has fewer than 1 task, stop and report.
- If `N` is outside the valid range, stop and report the valid range.
- To run more than one task only when the user explicitly asks, use a space-separated list, for example `TASK_NUMS=(12 18 30)`.
- In STEP 1 and STEP 2, the only task-selection line Codex edits is `TASK_NUMS=(N)`.

For example:

```bash
TASK_NUMS=(7)
```

For multiple tasks:

```bash
TASK_NUMS=(7 14 29)
```

## Optional: show the task-number catalog

Run this only if the user asks what the task numbers are, or if you need to verify what a number maps to before launching.

```bash
ssh root@46.101.235.50 'bash -s' <<'LIST'
set -euo pipefail
SPECBENCH=/root/SpecBench
cd "$SPECBENCH"
/root/SpecBench/.venv/bin/python - <<'PY'
import sys
sys.path.insert(0, "/root/SpecBench")
from benchmarks.spec_bench.adapter import _TASK_REGISTRY
print(f"TASK_COUNT\t{len(_TASK_REGISTRY)}")
print("task_n\ttask_id")
for i, task_id in enumerate(_TASK_REGISTRY.keys(), start=1):
    print(f"{i}\t{task_id}")
PY
LIST
```

## Where this runs

Codex reads this file locally. The benchmark execution itself runs on the remote server `root@46.101.235.50`. Reach it over SSH:

```bash
ssh root@46.101.235.50
```

Run on the server, not on a laptop. The long C and systems tasks are resource-heavy, and local architecture or missing dependencies can make results invalid.

## STEP 1 - Preflight

Run this first. Do not launch until it passes. Edit only `TASK_NUMS=(N)`.

```bash
ssh root@46.101.235.50 'bash -s' <<'PRE'
set -euo pipefail

# EDIT THIS LINE ONLY. Example: TASK_NUMS=(7)
TASK_NUMS=(N)

SPECBENCH=/root/SpecBench
SUPERVISOR=/root/sentinel
RUNNER=/root/sentinel/scripts/run_sentinel_specbench_attempt.py

printf '== required files ==\n'
test -d "$SPECBENCH" || { echo "FATAL: /root/SpecBench missing; server is not prepared"; exit 1; }
test -x "$SPECBENCH/.venv/bin/python" || { echo "FATAL: /root/SpecBench/.venv/bin/python missing; server is not prepared"; exit 1; }
test -f "$SPECBENCH/benchmarks/spec_bench/adapter.py" || { echo "FATAL: SpecBench adapter missing; server is not prepared"; exit 1; }
test -d "$SUPERVISOR" || { echo "FATAL: /root/sentinel missing"; exit 1; }
test -x "$SUPERVISOR/.venv/bin/python" || { echo "FATAL: /root/sentinel/.venv/bin/python missing"; exit 1; }
test -f "$RUNNER" || { echo "FATAL: SpecBench supervisor bridge runner missing at $RUNNER"; exit 1; }
test -f /root/.codex/auth.json || { echo "FATAL: /root/.codex/auth.json missing"; exit 1; }
test -f /root/.codex/config.toml || { echo "FATAL: /root/.codex/config.toml missing"; exit 1; }
chmod 600 /root/.codex/auth.json /root/.codex/config.toml

printf '\n== versions ==\n'
/root/SpecBench/.venv/bin/python --version
/root/sentinel/.venv/bin/python --version
(command -v codex >/dev/null 2>&1 && codex --version) || echo "WARNING: codex binary not found on PATH; runner may use npx fallback or fail"

printf '\n== bridge runner flags ==\n'
/root/sentinel/.venv/bin/python "$RUNNER" --help 2>&1 | head -80

printf '\n== selected SpecBench tasks ==\n'
cd "$SPECBENCH"
/root/SpecBench/.venv/bin/python - "${TASK_NUMS[@]}" <<'PY'
import sys
sys.path.insert(0, "/root/SpecBench")
from benchmarks.spec_bench.adapter import _TASK_REGISTRY
nums = [int(x) for x in sys.argv[1:]]
tasks = list(_TASK_REGISTRY.keys())
if not tasks:
    print("FATAL: empty SpecBench task registry")
    raise SystemExit(1)
print(f"TASK_COUNT\t{len(tasks)}")
print("task_n\ttask_id")
for n in nums:
    if n < 1 or n > len(tasks):
        print(f"FATAL: task number {n} outside valid range 1..{len(tasks)}")
        raise SystemExit(1)
    print(f"{n}\t{tasks[n-1]}")
PY

printf '\nPREFLIGHT PASS\n'
PRE
```

Do not proceed unless `PREFLIGHT PASS` prints.

## STEP 2 - Launch

This writes orchestration to the server and launches under `nohup`, so a dropped SSH connection does not kill the run. Edit only `TASK_NUMS=(N)`.

```bash
ssh root@46.101.235.50 'bash -s' <<'REMOTE'
set -euo pipefail

# EDIT THIS LINE ONLY. Example: TASK_NUMS=(7)
TASK_NUMS=(N)

SPECBENCH=/root/SpecBench
SUPERVISOR=/root/sentinel
RUNNER=/root/sentinel/scripts/run_sentinel_specbench_attempt.py
OUTROOT=/root/specbench-runs
mkdir -p "$OUTROOT"
chmod 600 /root/.codex/auth.json /root/.codex/config.toml

test -f "$RUNNER" || { echo "FATAL: SpecBench supervisor bridge runner missing at $RUNNER"; exit 1; }

STAMP=$(date -u +%Y%m%d-%H%M%S)
RUN="$OUTROOT/run-$STAMP"
mkdir -p "$RUN"

cd "$SPECBENCH"
/root/SpecBench/.venv/bin/python - "${TASK_NUMS[@]}" > "$RUN/selected_tasks.tsv" <<'PY'
import sys
sys.path.insert(0, "/root/SpecBench")
from benchmarks.spec_bench.adapter import _TASK_REGISTRY
nums = [int(x) for x in sys.argv[1:]]
tasks = list(_TASK_REGISTRY.keys())
print("slot\ttask_n\ttask_id")
for slot, n in enumerate(nums, start=1):
    if n < 1 or n > len(tasks):
        raise SystemExit(f"task number {n} outside valid range 1..{len(tasks)}")
    print(f"{slot}\t{n}\t{tasks[n-1]}")
PY

cat > "$RUN/orchestrate.sh" <<'ORCH'
#!/usr/bin/env bash
set -euo pipefail
RUN="$1"
SPECBENCH=/root/SpecBench
SUPERVISOR=/root/sentinel
RUNNER=/root/sentinel/scripts/run_sentinel_specbench_attempt.py
pids=()

while IFS=$'\t' read -r slot task_n task_id; do
  [ "$slot" = "slot" ] && continue
  results="$RUN/slot${slot}"
  mkdir -p "$results"
  echo "slot${slot} task_n=${task_n} task_id=${task_id} results=${results}"
  (
    cd "$SUPERVISOR"
    /root/sentinel/.venv/bin/python "$RUNNER" \
      --task "$task_id" \
      --specbench-dir "$SPECBENCH" \
      --results-root "$results" \
      > "$results/launch.log" 2>&1
    rc=$?
    echo "$rc" > "$results/exit_code"
    exit "$rc"
  ) &
  pids+=("$!")
done < "$RUN/selected_tasks.tsv"

fail=0
for i in "${!pids[@]}"; do
  st=0
  wait "${pids[$i]}" || st=$?
  echo "slot$((i+1)) exit=$st" | tee -a "$RUN/SLOT_STATUS.txt"
  [ "$st" -ne 0 ] && fail=1
done

echo "all_done fail=$fail" | tee -a "$RUN/SLOT_STATUS.txt"
touch "$RUN/DONE"
ORCH
chmod +x "$RUN/orchestrate.sh"

nohup bash "$RUN/orchestrate.sh" "$RUN" > "$RUN/orchestrate.log" 2>&1 &
echo "LAUNCHED pid=$! run_dir=$RUN"
echo "PROGRESS: tail -f $RUN/orchestrate.log  |  DONE when $RUN/DONE exists  |  per-slot in $RUN/SLOT_STATUS.txt"
REMOTE
```

If the bridge runner uses different flag names, check its `--help` output and change only the flag spelling. Do not change the benchmark, the selected task, the supervisor, or the scoring protocol.

## STEP 3 - Check progress / collect

Run anytime. It auto-picks the latest run:

```bash
ssh root@46.101.235.50 'bash -s' <<'CHK'
set -euo pipefail
RUN=$(ls -dt /root/specbench-runs/run-* 2>/dev/null | head -1)
echo "run_dir=$RUN"
test -n "$RUN" || { echo "No runs found"; exit 1; }
test -f "$RUN/DONE" && echo "STATE: DONE" || echo "STATE: RUNNING"
echo "--- selected_tasks.tsv ---"; cat "$RUN/selected_tasks.tsv" 2>/dev/null || true
echo "--- SLOT_STATUS ---"; cat "$RUN/SLOT_STATUS.txt" 2>/dev/null || true
echo "--- tail orchestrate.log ---"; tail -n 40 "$RUN/orchestrate.log" 2>/dev/null || true
CHK
```

A slot with nonzero exit failed as infrastructure or runner execution. Read that slot's `launch.log`. Do not treat a missing or failed slot as a model result.

## What the bridge runner must do per task

1. Load the selected task from SpecBench by `task_id`.
2. Create a fresh workspace containing only starter code and visible validation tests.
3. Keep held-out tests unavailable to the supervisor and coder during the agent run.
4. Invoke the supervisor exactly once.
5. Capture the supervisor state, coder rollout, final files, modified-file list, stdout/stderr, and exit code.
6. Run validation and held-out evaluation after the agent run.
7. Write all artifacts under the supplied `--results-root`.
8. Never mutate the SpecBench task definitions or scoring code.

## Contract

- The agent may see the task specification, starter code, and visible validation tests.
- Held-out tests are used only after the agent run for evaluation.
- The supervisor runs exactly once per selected task.
- A re-run is allowed only after a concrete environment failure is fixed. Do not re-run to fish for a better result.
- Parallel runs must have separate workspaces and separate result directories.
- Do not weaken sandboxing or network controls as a workaround. Repair broken controls instead.

## Fixing the environment

Allowed fixes include missing Python packages in the supervisor venv, missing supervisor venvs, bad file permissions, a missing Codex CLI binary, Docker/service not started when the runner requires it, disk full, a port or container-name collision, or a bridge runner crash caused by path/config mistakes.

Not allowed: installing or updating SpecBench, editing supervisor prompts, changing task specifications, changing validation or held-out tests, exposing held-out tests during the agent run, changing scoring logic, or re-running without a specific infrastructure cause.

Document every fix in the slot report.

## Results and report

Per task, results live under:

```text
/root/specbench-runs/run-<stamp>/slot<N>/
```

The slot should contain `launch.log`, `exit_code`, supervisor/coder traces, final workspace files or diff, validation score, held-out score, and any runner metadata. The run directory contains `selected_tasks.tsv`, `orchestrate.log`, `SLOT_STATUS.txt`, and `DONE`.

Compose a short `run_report.md` in each slot from those artifacts. Include:

- task number and `task_id`.
- exact command used.
- whether the run finished and the slot exit code.
- validation score and held-out score.
- paths to supervisor/coder traces and final workspace artifacts.
- any environment problem and fix.
- whether held-out tests were kept out of the agent workspace.
- whether the slot is a valid scored run or an aborted/not-scored run.

Do not interpret why the supervisor behaved as it did. Report only measured facts.
