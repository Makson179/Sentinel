# Sentinel runner: THREE SWE-bench Pro instances in parallel (self-contained, cold start)

A fresh Codex session can run this with nothing but this file. You run THREE SWE-bench Pro instances through Sentinel end to end, in parallel, on the remote amd64 server, then score each with its own hidden tests. You are a runner, not a judge: do not evaluate Sentinel's quality, and do not touch the agent, the prompts, the contract, or the scoring logic. Report facts only. The analysis pass happens separately, later.

There is ONE narrow exception to "do not fix anything": problems in the **execution environment** (the server, Docker, the runner/harness plumbing, the network-isolation setup, resources) that PREVENT a valid run. Those you fix and re-run. See "Fixing the environment" for the exact boundary. You never touch what is being measured.

## The three instances (baked in; expected test counts)
These exact instance_ids are baked into the launch block. They were chosen for having enough hidden tests that "resolved" is a real signal:

- `d` -> expect fail_to_pass 16, pass_to_pass 35
- `instance_qutebrowser__qutebrowser-f631cd4422744160d9dcf7a0455da532ce973315-v35616345bb8052ea303186706cec663146f0f184` -> expect fail_to_pass 32, pass_to_pass 0
- `instance_navidrome__navidrome-ee21f3957e0de91624427e93c62b8ee390de72e3` -> expect fail_to_pass 15, pass_to_pass 0

To run a different set later, change the three `ID1`/`ID2`/`ID3` lines in the launch block (and update the expected counts in the preflight).

## Where this runs, and why
Everything runs on the remote server `root@46.101.235.50` (native amd64 Ubuntu). Do NOT run on a Mac or Apple Silicon: the SWE-bench Pro images are amd64, and under QEMU emulation services like Redis segfault, turning every result into garbage. Reach it over SSH; the key is set up, so `ssh root@46.101.235.50` works.

## Already set up on the server (the preflight verifies this; do not rebuild)
- Sentinel repo with venv: `/root/sentinel`, Python at `/root/sentinel/.venv/bin/python`, runner at `scripts/run_sentinel_container_attempt.py`
- SWE-bench Pro checkout: `/root/SWE-bench_Pro-os`, scorer `swe_bench_pro_eval.py`, eval data `helper_code/sweap_eval_full_v2.jsonl` (731 rows)
- Codex auth: `/root/.codex/auth.json`, `/root/.codex/config.toml`, with `web_search="disabled"`
- The runner is meant to be concurrency-safe (per-run unique container name, Docker-assigned IP on a shared `sentinel-egress` subnet, per-run proxy port, ref-counted teardown), with network-isolation plumbing and the git-history purge wired in. The preflight spot-checks that the server's runner actually reflects these fixes, so you do not run a stale version.
- Docker, installed and running.

## The run is offline by design (network isolation)
During each instance's agent-run the container is network-isolated: egress allow-listed to the model backend only (chatgpt.com / *.openai.com), everything else blocked, Codex web tools disabled, and the repo's future git history purged after checkout at base so the gold commit is not reachable locally. The agent solves from the task plus the local repo at base plus its own reasoning, with no external fetch and no answer-lookup. Setup and build keep full network; scoring runs in its own separate Docker step.

## STEP 1 - Preflight (run this first; do NOT launch until it passes)
This checks the runner exists and is current, prints the runner's flags so you can confirm the launch flags, and reads fail_to_pass/pass_to_pass the way the scorer needs (case-insensitive, because the local jsonl stores them UPPERCASE while the scorer reads lowercase) and asserts the exact expected counts.

```
ssh root@46.101.235.50 'bash -s' <<'PRE'
set -u
echo "== runner present & current =="
test -f /root/sentinel/scripts/run_sentinel_container_attempt.py || { echo "FATAL: runner missing"; exit 1; }
git -C /root/sentinel log --oneline -3 2>/dev/null || echo "(no git info)"
R=/root/sentinel/scripts/run_sentinel_container_attempt.py
grep -qE "git add -A" "$R" && echo "untracked-capture marker: present" || echo "untracked-capture marker: NOT FOUND (server may be stale, verify before trusting)"
grep -qE "sentinel-egress|--network" "$R" && echo "network-isolation marker: present" || echo "network-isolation marker: NOT FOUND (server may be stale, verify before trusting)"
grep -qE "scoring_sample_for_scorer|fail_to_pass.*FAIL_TO_PASS" "$R" && echo "field-case normalization marker: present" || { echo "field-case normalization marker: NOT FOUND"; exit 1; }
grep -qE "compose_task_text|New interfaces introduced:" "$R" && echo "canonical task exposure marker: present" || { echo "canonical task exposure marker: NOT FOUND"; exit 1; }
echo
echo "== runner flags (confirm the launch flags below exist; adjust names if they differ) =="
/root/sentinel/.venv/bin/python "$R" --help 2>&1 | head -40
echo
echo "== fail_to_pass / pass_to_pass counts (read case-insensitively, asserted) =="
python3 - <<'PY'
import json, ast
f="/root/SWE-bench_Pro-os/helper_code/sweap_eval_full_v2.jsonl"
expect={
 "instance_element-hq__element-web-4fec436883b601a3cac2d4a58067e597f737b817-vnan":(16,35),
 "instance_qutebrowser__qutebrowser-f631cd4422744160d9dcf7a0455da532ce973315-v35616345bb8052ea303186706cec663146f0f184":(32,0),
 "instance_navidrome__navidrome-ee21f3957e0de91624427e93c62b8ee390de72e3":(15,0),
}
def parse(v):
    if isinstance(v,list): return v
    s=str(v).strip()
    try: return ast.literal_eval(s)
    except Exception: return json.loads(s)
got={}
for line in open(f):
    try: r=json.loads(line)
    except Exception: continue
    i=r.get("instance_id")
    if i in expect:
        fk="FAIL_TO_PASS" if "FAIL_TO_PASS" in r else "fail_to_pass"
        pk="PASS_TO_PASS" if "PASS_TO_PASS" in r else "pass_to_pass"
        got[i]=(len(parse(r[fk])), len(parse(r[pk])))
ok=True
for i,(ef,ep) in expect.items():
    g=got.get(i)
    st = "MISSING" if g is None else ("OK" if g==(ef,ep) else "MISMATCH")
    if st!="OK": ok=False
    print(st, i.split("__")[-1][:34], "expected", (ef,ep), "got", g)
print("PREFLIGHT_COUNTS", "PASS" if ok else "FAIL")
raise SystemExit(0 if ok else 1)
PY
PRE
```

Do not proceed unless: the runner is present, the markers look current (or you have verified otherwise), the flags used in the launch block exist, and `PREFLIGHT_COUNTS PASS` prints. A MISMATCH/MISSING here means a wrong instance id or a field-read problem; stop and report.

## STEP 2 - Launch (detached, survives SSH drop, captures per-slot exit codes)
The orchestration is written to the server and launched under `nohup`, so a dropped SSH connection does not kill a multi-hour run. Each slot records its own exit code; the parent waits per-PID and writes a per-slot status file. The only lines you edit are `ID1`/`ID2`/`ID3`.

```
ssh root@46.101.235.50 'bash -s' <<'REMOTE'
set -u
chmod 600 /root/.codex/auth.json /root/.codex/config.toml
STAMP=$(date -u +%Y%m%d-%H%M%S)
RUN=/root/sentinel-runs/run-$STAMP
mkdir -p "$RUN"

cat > "$RUN/orchestrate.sh" <<'ORCH'
#!/usr/bin/env bash
set -u
RUN="$1"; shift
ids=("$@")
cd /root/sentinel
pids=()
for i in "${!ids[@]}"; do
  slot=$((i+1)); id="${ids[$i]}"; results="$RUN/slot$slot"
  mkdir -p "$results"
  echo "slot$slot instance=$id results=$results"
  (
    /root/sentinel/.venv/bin/python scripts/run_sentinel_container_attempt.py \
      --task-id "$id" --results-root "$results" --swe-bench-pro-dir /root/SWE-bench_Pro-os \
      > "$results/launch.log" 2>&1
    rc=$?; echo "$rc" > "$results/exit_code"; exit "$rc"
  ) &
  pids+=($!)
done
fail=0
for i in "${!pids[@]}"; do
  wait "${pids[$i]}"; st=$?
  echo "slot$((i+1)) exit=$st" | tee -a "$RUN/SLOT_STATUS.txt"
  [ "$st" -ne 0 ] && fail=1
done
echo "all_done fail=$fail" | tee -a "$RUN/SLOT_STATUS.txt"
touch "$RUN/DONE"
ORCH
chmod +x "$RUN/orchestrate.sh"

ID1=instance_element-hq__element-web-4fec436883b601a3cac2d4a58067e597f737b817-vnan
ID2=instance_qutebrowser__qutebrowser-f631cd4422744160d9dcf7a0455da532ce973315-v35616345bb8052ea303186706cec663146f0f184
ID3=instance_navidrome__navidrome-ee21f3957e0de91624427e93c62b8ee390de72e3

nohup bash "$RUN/orchestrate.sh" "$RUN" "$ID1" "$ID2" "$ID3" > "$RUN/orchestrate.log" 2>&1 &
echo "LAUNCHED pid=$! run_dir=$RUN"
echo "PROGRESS: tail -f $RUN/orchestrate.log  |  DONE when $RUN/DONE exists  |  per-slot in $RUN/SLOT_STATUS.txt"
REMOTE
```

Note the `run_dir` it prints; you need it for STEP 3. Expect ~6 concurrent model streams (a coder plus a supervisor per slot) on one ChatGPT subscription, so rate-limit/429 throttling is the account, not the code; report it. Three image builds/fetches at once may contend and run slower at the start; let them finish. If a flag name differs from the runner's `--help`, fix the flags in the block, not the intent.

## STEP 3 - Check progress / collect (run anytime)
Substitute the `run_dir` from LAUNCHED, or let it auto-pick the latest run:

```
ssh root@46.101.235.50 'bash -s' <<'CHK'
RUN=$(ls -dt /root/sentinel-runs/run-* 2>/dev/null | head -1)
echo "run_dir=$RUN"
test -f "$RUN/DONE" && echo "STATE: DONE" || echo "STATE: RUNNING"
echo "--- SLOT_STATUS ---"; cat "$RUN/SLOT_STATUS.txt" 2>/dev/null
echo "--- tail orchestrate.log ---"; tail -n 25 "$RUN/orchestrate.log" 2>/dev/null
CHK
```

A slot with `exit!=0` failed; read its `slotN/launch.log`. Do not treat a missing/failed slot as a model result.

## What the runner does, per instance
1. Fetches the instance fields from the dataset (problem_statement, base_commit, dockerhub_tag, test_patch, the test lists, and the rest).
2. Builds the attempt image from the instance's `dockerhub_tag` and installs the Codex CLI plus the Sentinel venv.
3. Mounts `/root/.codex/auth.json` into the container for coder auth.
4. Writes the canonical SWE-bench Pro task text to `/app/TASK.md`: `problem_statement`, then `Requirements:`, then `requirements`, then `New interfaces introduced:`, then `interface`.
5. Checks out base_commit, then purges future git history so the gold commit is not reachable locally.
6. Applies network isolation for the agent-run (egress allow-list to the model backend only, web tools off), runs Sentinel once in `/app` (supervisor plus coder), then tears the isolation down.
7. Extracts the supervisor state (`.supervisor`), the git diff against base_commit (untracked files included, harness artifacts excluded), the final status, and the rollouts.
8. Scores in its own Docker step: applies the hidden test_patch and runs the fail_to_pass and pass_to_pass tests on linux/amd64.

## The contract (the runner enforces this; do not break it)
- The coder sees ONLY the canonical task statement (`problem_statement` + `requirements` + `interface`). Hidden tests never enter the container; they are applied only at scoring, outside the coder's reach.
- The agent-run is offline: egress allow-listed to the model backend only, web tools off, future git history purged. Do not weaken this.
- Sentinel runs exactly once per instance. Do not prompt it again after it finishes. A re-run after an environment fix is a fresh single run, which is fine.
- The three runs must not interfere: separate containers, separate results, shared isolation set up and torn down safely.

## Fixing the environment (the one narrow exception to "do not fix")
If a run fails because of the EXECUTION ENVIRONMENT rather than because of Sentinel, fix the environment and re-run that instance. Things you may fix: Docker not starting, a port or name collision, disk full, the egress proxy or DOCKER-USER rule failing to come up, the runner erroring or colliding under concurrency, a missing harness dependency, broken isolation plumbing that makes the model backend unreachable, and the scoring field-case mismatch below.

**The field-case fix, pinned.** The dataset stores the test-list fields UPPERCASE (`FAIL_TO_PASS`/`PASS_TO_PASS`); the scorer `swe_bench_pro_eval.py` reads them LOWERCASE (`raw_sample["fail_to_pass"]`/`["pass_to_pass"]`, ~lines 556-557) inside a `try/except` that, on a missing key, SILENTLY marks the instance resolved=False. The fix lives in ONE place: the `raw_sample` rows the runner writes for the scorer to read (e.g. the `raw_sample.jsonl` produced at the runner's scoring-input write site). Ensure those rows carry lowercase `fail_to_pass`/`pass_to_pass` keys before the scorer reads them. Do NOT edit the scorer's resolved computation (`(f2p | p2p) <= passed_tests`) and do NOT change the test lists; that is scoring logic, not plumbing.

The boundary: you may fix WHAT MAKES THE MEASUREMENT RUN; you may NOT touch WHAT IS BEING MEASURED.
- Do NOT touch the supervisor or coder logic, the prompts, or the agent's solution.
- Do NOT WEAKEN isolation as a "fix". Repairing broken isolation plumbing (proxy not starting, backend blocked) is allowed; opening the network, restoring web tools, or unpurging history is contamination.
- Only fix genuine failures that ABORT or PREVENT a valid run. Do not change anything to chase a score. Do not loop re-running to fish for a result; fix the specific problem, re-run once, and if it fails again for the same infra reason, report it.
- Document exactly what was broken and what you changed. If a fix would require touching the agent, prompts, contract, scoring logic, or isolation integrity, STOP and report.

## Where the results land
Per instance, under `run-<stamp>/slot<N>/`: `launch.log`, `exit_code`, the agent's diff against base_commit, the coder rollout and per-wake supervisor rollouts, the supervisor state (`.supervisor`), the scoring output. Run-level: `orchestrate.log`, `SLOT_STATUS.txt`, `DONE`. If a slot's rollouts cannot be found, fail that slot with a clear error rather than reporting a partial run.

## Report (facts only, no judgment) - one per instance
The runner already writes its own artifacts. Do NOT overwrite them. COMPOSE a short `run_report.md` in each `slot<N>/` FROM those artifacts, stating:
- instance_id, repo, base_commit, dockerhub_tag, slot exit code.
- the exact command used, so the run is reproducible.
- whether the run finished, how long it took, generations and restarts if visible.
- expected vs scored fail_to_pass/pass_to_pass counts; which fail_to_pass passed or failed; whether any pass_to_pass regressed; overall resolved yes or no.
- **scoring integrity.** If instances come back unresolved AND the scoring log contains `generated an exception` referencing `fail_to_pass`/`pass_to_pass` (the field-case KeyError), the score is INVALID (harness field-case bug), not a model failure: flag it, apply the pinned field-case fix, and re-run. Do not report a silently-defaulted resolved=False as a real result.
- if the run aborted before scoring, write `result: not scored (aborted before scoring)` and where it stopped. That is not a valid run.
- confirm the coder and supervisor rollouts were found and saved, with paths.
- infra sanity (all must hold for a valid, clean run):
  - `grep -riE 'segfault|SIGSEGV|qemu|core dumped' "$results"` finds nothing. ECONNREFUSED is fine only if the coder then brought the service up and tests passed.
  - isolation held: the coder trace shows NO successful external fetch (no curl/wget/web to non-allow-listed hosts), web tools were off (web_search disabled; web_items and history_hits zero), and the gold commit is not reachable locally. If the agent reached external content, the run is CONTAMINATED: flag it and treat the break as an environment problem to fix and re-run.
- any environment problem encountered and any fix you made, stated plainly.
- confirm the three runs did not interfere (separate containers/results, no shared-state collision).

Do not interpret why anything happened or whether Sentinel behaved well. That is the analyst's job in a later pass.
