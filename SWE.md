# Sentinel runner: one SWE-bench Pro instance (on the amd64 server)

You run one SWE-bench Pro instance through Sentinel end to end on the remote amd64 server, then score it with the instance's hidden tests. You are a runner, not a judge: do not evaluate quality or fix anything, report facts only. The analysis pass happens separately, later, via supervisor_review.md.

**To run a different instance, change exactly ONE thing: the `INSTANCE_ID` line in the command below. Nothing else changes.**

## Where this runs, and why

Everything runs on the remote server `root@46.101.235.50` (native amd64 Ubuntu). Do NOT run this on a Mac or any Apple Silicon machine: the SWE-bench Pro images are amd64, and under QEMU emulation services like Redis segfault, which turns every result into garbage. The server is native amd64, so the images run for real.

You reach the server over SSH; the key is already set up, so `ssh root@46.101.235.50` works.

## Already set up on the server (verify, do not rebuild)

- Sentinel repo with its venv: `/root/sentinel`, Python at `/root/sentinel/.venv/bin/python`
- SWE-bench Pro checkout with the scorer: `/root/SWE-bench_Pro-os` (`swe_bench_pro_eval.py`)
- Codex auth: `/root/.codex/auth.json` and `/root/.codex/config.toml`
- Docker, installed and running

If any of these is genuinely missing, stop and say exactly what is absent. Do not fabricate or work around it.

## Run it

SSH into the server first (`ssh root@46.101.235.50`), then run this on the server. The only line you ever edit is `INSTANCE_ID`:

```
INSTANCE_ID=instance_ansible__ansible-e40889e7112ae00a21a2c74312b330e67a766cc0-v1055803c3a812189a1133297f7f5468579283f86

chmod 600 /root/.codex/auth.json /root/.codex/config.toml
RESULTS=/root/sentinel-runs/run-$(date -u +%Y%m%d-%H%M%S)
mkdir -p /root/sentinel-runs
cd /root/sentinel
echo "results_root=$RESULTS  instance=$INSTANCE_ID"
/root/sentinel/.venv/bin/python scripts/run_sentinel_container_attempt.py \
  --task-id "$INSTANCE_ID" \
  --results-root "$RESULTS" \
  --swe-bench-pro-dir /root/SWE-bench_Pro-os
```

The first stretch is the dataset fetch plus the Docker image build or pull, which can take a while; let it run to completion.

**If the runner reports that the task id is not found in the dataset, stop.** Do not substitute a similar-looking id to make it run: a wrong instance produces a wrong result that still looks valid. Recheck `INSTANCE_ID` against the dataset and fix the value.

### Running it non-interactively

If you run this in one shot from your own machine instead of an interactive SSH session, pipe the block to the server's shell over stdin, so nothing passes through SSH quoting (that is where multi-line commands get mangled):

```
ssh root@46.101.235.50 'bash -s' <<'REMOTE'
INSTANCE_ID=instance_NodeBB__NodeBB-04998908ba6721d64eba79ae3b65a351dcfbc5b5-vnan

chmod 600 /root/.codex/auth.json /root/.codex/config.toml
RESULTS=/root/sentinel-runs/run-$(date -u +%Y%m%d-%H%M%S)
mkdir -p /root/sentinel-runs
cd /root/sentinel
echo "results_root=$RESULTS  instance=$INSTANCE_ID"
/root/sentinel/.venv/bin/python scripts/run_sentinel_container_attempt.py \
  --task-id "$INSTANCE_ID" \
  --results-root "$RESULTS" \
  --swe-bench-pro-dir /root/SWE-bench_Pro-os
REMOTE
```

The quoted `<<'REMOTE'` keeps your local shell from touching `$RESULTS`, `$INSTANCE_ID`, and the `$(date ...)`; the server's bash expands them. Whichever form you use, the only line you ever change is `INSTANCE_ID`.

## What the one command does (so you know when it is complete)

The runner does all of this by itself for the given instance:

1. Fetches the instance fields from the dataset (problem_statement, base_commit, dockerhub_tag, test_patch, fail_to_pass, pass_to_pass, and the rest).
2. Builds the attempt image from the instance's `dockerhub_tag` and installs the Codex CLI plus the Sentinel venv into it.
3. Mounts the server's `/root/.codex/auth.json` into the container for coder auth.
4. Writes ONLY the problem_statement to `/app/TASK.md` inside the container.
5. Runs Sentinel once in `/app` (supervisor plus coder). The container has full access; the coder brings up whatever runtime it needs (on the NodeBB run it started Redis itself, for example).
6. Extracts the supervisor state (`.supervisor`), the git diff against base_commit, the final status, and the rollouts.
7. Scores: applies the hidden test_patch and runs fail_to_pass and pass_to_pass in Docker on linux/amd64.

## The contract (the runner already enforces this, do not break it)

- The coder sees ONLY the problem statement. The hidden tests (test_patch, fail_to_pass, pass_to_pass) never enter the container; they are applied only in the scoring step, outside the coder's reach. Do not put them anywhere the coder can read.
- Sentinel runs exactly once. Do not prompt it again to verify, check, or continue after it finishes.

## Where the results land

Everything for the run sits under the `results_root` printed by the command (for example `/root/sentinel-runs/run-<timestamp>/`):

- the agent's diff against base_commit,
- the coder rollout and the per-wake supervisor rollouts,
- the supervisor state (`.supervisor`),
- the live run log,
- the scoring output.

If the rollouts cannot be found, fail with a clear error rather than reporting a partial run.

## Report (facts only, no judgment)

Write a short `run_report.md` at `$RESULTS/run_report.md`:

- instance_id, repo, base_commit, dockerhub_tag.
- the exact command used, so the run is reproducible.
- whether the run finished, how long it took, generations and restarts if visible.
- scoring: which fail_to_pass passed or failed, whether any pass_to_pass regressed, overall resolved yes or no.
- **if the run aborted before the scoring step, it is NOT a valid run.** Do not record it as resolved no. Write `result: not scored (aborted before scoring)` and state where it stopped.
- confirm the coder and supervisor rollouts for this run were found and saved, with their paths.
- infra sanity check: run `grep -riE 'segfault|SIGSEGV|qemu|core dumped' "$RESULTS"` and confirm it finds nothing. On the native amd64 server these can never legitimately appear, so any hit means the score is a crash or emulation artifact, not a real evaluation. Treat `ECONNREFUSED` separately: a transient one is fine if the coder then brought the service up and tests passed (this happened on the NodeBB run with Redis); it is a problem only if the service never came up and tests stayed red.
- any setup problem encountered, stated plainly.

Do not interpret why anything happened or whether Sentinel behaved well. That is the analyst's job in a later pass, via supervisor_review.md.