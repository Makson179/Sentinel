# Handoff for Next Codex Session

Current workspace: `/Users/bocharovmaxim/Desktop/superviser`

Date/context: 2026-06-22. User is working on a supervisor system for SpecBench, especially `specbench_numeric_task` / `c_compiler`. The current conversation was about why supervisor runs underperform raw Codex and what system/prompt/gate changes should be made.

Important constraint from user:

- Do not introduce hardcoded task-specific rules.
- No rules like "after 46/46 public tests, allow only one return".
- No fixed time/budget hacks as behavioral policy.
- The system must remain universal and must work even when there are no public tests.
- Task-specific names like `torture_src`, `46/46`, `c_compiler`, ABI, etc. must not appear in general prompts. They are OK only in offline analysis.

## Current Git State

The worktree is already dirty. Treat existing changes as user/work-in-progress changes and do not revert them without explicit instruction.

Known modified/untracked files at handoff time:

- `need.md`
- `proposal.md`
- `scripts/run_sentinel_specbench_attempt.py`
- `supervisor/approvals.py`
- `supervisor/controller.py`
- `supervisor/main.py`
- `supervisor/policy.py`
- `supervisor/prompts/prompts.toml`
- `supervisor/schemas/models.py`
- `supervisor/supervisor_agent.py`
- `tests/test_policy.py`
- `tests/test_sentinel_state.py`
- `build/`

## Run Context and Results

User inserted `need.md` into `supervisor/prompts/prompts.toml`, then runs were performed on the server.

Snapshot used:

- `/root/sentinel-local-need-20260622-130852`

Four-run supervisor batch:

- `/root/specbench-runs/run-20260622-141650-need-prompt-c_compiler-4x`

Raw baselines:

- Raw Codex: `/root/specbench-runs/raw-codex/run-20260620-133518/slot1`
  - public `46/46`
  - private `154/299`
  - valid
  - web search disabled, network false
  - duration about 29m

- Raw Codex Docker: `/root/specbench-runs/raw-codex-docker/run-20260620-2`
  - public `46/46`
  - private `162/299`
  - valid
  - egress isolation true
  - duration about 29m

Supervisor runs:

- Solo need-prompt:
  - `/root/specbench-runs/run-20260622-131022-need-prompt-c_compiler/slot1`
  - public `46/46`
  - private `149/299`
  - controller `complete`
  - completion returns `1`
  - restarts `0`
  - coder rollouts `1`
  - supervisor rollouts `71`

- 4x slot1:
  - private `107/299`
  - public `46/46`
  - controller `provider_failure`
  - valid scored run, but not representative of normal behavior
  - returns `3`
  - restarts `1`
  - issue: `supervisor check failed: supervisor did not produce an agent message`

- 4x slot2:
  - private `144/299`
  - public `46/46`
  - controller `complete`
  - accepted
  - returns `0`

- 4x slot3:
  - private `162/299`
  - public `46/46`
  - controller `complete`
  - accepted
  - returns `2`
  - this was the best supervisor slot

- 4x slot4:
  - private `122/299`
  - public `46/46`
  - controller `escalated`
  - valid scored run
  - failure was accept-gate proof/evidence plumbing, not benchmark execution
  - accept gate audit failure: `behavior_evidence_matrix has evidence with missing or ambiguous validation_id/inspection_id`

User requested final aggregate excluding the 107 provider-failure run and replacing it with 149:

- values `[149, 144, 162, 122]`
- mean `144.25/299`
- median `146.5/299`
- min/max `122..162`

Actual 4x raw batch values were `[107, 144, 162, 122]`, mean `133.75/299`.

## Core Analysis

Raw Codex outperformed/competed with supervisor because it performed broader visible-artifact exploration. It did not merely pass public tests. It found a visible corpus/resources in the task workspace, sampled it, clustered failures, and implemented broad correctness features.

The supervisor system was often stricter about proof than about finding hidden-like behavioral gaps. That caused wasted returns and failure modes:

- stale returns: returning coder for concerns already likely addressed by newer validation or inspection;
- proof-loop behavior: asking for more evidence of already-covered behavior;
- proof-format fragility: `escalated` caused by missing/ambiguous evidence IDs;
- provider failure pollution: no-message provider failure allowed a semi-debugged workspace to be scored;
- insufficient raw-style exploration: coder/supervisor often relied on public/basic checks and focused demos instead of broad visible resources.

Important conclusion:

- Do not globally weaken rigor.
- Replace brittle/bureaucratic rigor with behavior-grounded rigor.
- Supervisor should be strict about real, fresh behavioral gaps and forbidden access.
- Supervisor should be forgiving/repairing toward its own proof-format plumbing.

## Agreed Direction

The user and assistant converged on this plan:

1. Keep prompts task-agnostic and single-source.
2. Add/strengthen broad exploration behavior for coder.
3. Add supervisor decision artifact before accept/return/restart.
4. Enforce stale concern quarantine.
5. Ban duplicate proof requests.
6. Make return possible only for concrete actionable gaps.
7. Convert proof-format gate from hard terminal failure to repair/retry.
8. Harden provider failure handling.
9. Optionally add an adversarial read-only tester agent behind a feature flag.

## Proposal Status

Read `proposal.md`. Lines 44-53 were accepted with one small addition.

Accepted points:

- Decision artifact fields:
  - `current_state`
  - `resolved_concerns`
  - `stale_concerns`
  - `uncovered_edge_candidates`
  - `actionable_gap_or_none`
  - `decision`

- `uncovered_edge_candidates` is not itself a return reason.
- Speculative gap defaults to accept, not return.
- "Coder did not use visible resources" is not by itself a return reason.
- It becomes a return only if converted into a concrete, uncovered, actionable gap.
- `torture_src` was visible in this specific task, hidden tests were not in workspace, so exploration was legitimate.
- General prompts must not name this corpus or task-specific details.
- All prompt changes must be task-agnostic.

Small addition suggested and accepted as useful:

```text
If returning due to an actionable gap, include the minimal next diagnostic or validation the coder should run first.
```

## Recommended Prompt Changes

Do not add task-specific wording.

For coder:

- After basic correctness, enumerate visible task resources:
  - tests
  - fixtures
  - examples
  - corpora
  - docs
  - reference scripts/outputs
- When feasible, run sampled validations.
- Cluster failures by root cause.
- Prefer fixes that cover broad behavior classes.
- Avoid broad risky rewrites without a minimal repro or diagnostic.

For supervisor completion review:

- Before deciding accept/return/restart, produce or update a structured decision artifact:
  - current implementation state;
  - fresh validations and inspections;
  - resolved concerns;
  - stale/historical concerns;
  - uncovered edge candidates;
  - actionable gap or none;
  - final decision.

- Old concerns may guide where to look, but cannot justify return unless re-confirmed against current code/evidence.
- Do not ask coder to re-prove behavior already covered by fresh validation or inspection.
- Return only for actionable gaps.
- If there is no actionable gap, accept rather than asking for speculative proof.
- If returning, include:
  - exact missing behavior;
  - why it matters for the task;
  - why latest evidence does not cover it;
  - fresh repro / fresh inspection / visible resource example / concrete validation plan;
  - minimal next diagnostic or validation;
  - expected post-fix validation.

## Recommended Gate/Controller Changes

G1. Proof-format gate must not cause terminal `escalated` by itself.

- Missing/ambiguous `validation_id` or `inspection_id` should trigger deterministic repair/regeneration from the existing ledger.
- Proof remains a consistency check.
- Proof-format failure is a supervisor-system issue, not a coder correctness failure.

G2. Freshness as machine check.

- Each return/accept should reference:
  - `basis_event_seq`
  - `last_relevant_edit_seq`
  - `last_validation_seq`
- If newer edits/validations likely close the concern, the decision is invalid and must be recalculated.

G3. Provider failure hardening.

- Separate `rate`, `auth`, `no_message`, `tool_timeout`, etc.
- For `no_message`:
  - retry same supervisor turn;
  - then resume from latest stable event;
  - then rerun slot as infra-invalid.
- Do not score a semi-debugged workspace as representative system quality.

Optional:

- Evidence ledger as typed database with auto IDs.
- Claims can reference only existing validation/inspection IDs.
- Broken references are repairable table problems, not terminal failures.

## Adversarial Agent Idea

Possible future addition: read-only adversarial tester, behind a flag and A/B-tested.

Purpose:

- Run before final accept candidates.
- Try honestly to break the solution.
- Cannot edit code.
- Can generate and run tests/probes.
- Reports raw commands/inputs/outputs.
- Does not make final accept decision.

v0 should be conservative:

- only oracle-free bugs:
  - crash;
  - hang;
  - contract/type violation;
  - explicit invariant violation.
- no invented expected outputs unless directly grounded in spec.
- differential reference testing can be v1 where a legitimate reference exists.

Do not add this as an always-on heavy mechanism before fixing G1/G2/G3 and prompt behavior.

## Priority Order

Recommended implementation order:

1. Prompt changes:
   - coder broad exploration;
   - supervisor decision artifact;
   - stale concern quarantine;
   - duplicate proof ban;
   - actionable return criteria.

2. Gate/controller changes:
   - G1 proof-format repair;
   - G2 freshness machine check;
   - G3 provider failure retry/resume/infra-invalid.

3. Run A/B or parallel slots.

4. Analyze not only score, but reason distribution:
   - returns due fresh edge cases;
   - stale returns;
   - proof repairs;
   - provider retries;
   - accept decisions with no actionable gaps.

5. Only after that, consider adversarial agent v0.

## Tone/Collaboration Preference

User wants direct, rigorous, non-defensive analysis. Avoid vague "maybe" reasoning. If disagreeing, give concrete factual reasoning. User is strongly against hardcoded public-test or time/budget heuristics.



23:16
Division of labor (authoritative). The human writes and finalizes all prompts (coder, reviewer, and the adversarial agent) and the exact shape of the supervisor decision-artifact fields, and hands them over ready. Codex must NOT edit supervisor/prompts/prompts.toml or any prompt text. Codex's scope is the deterministic layer only: G1 (proof-format repair, no terminal escalation from evidence-ID issues), G2 (freshness as a machine check), G3 (provider-failure retry/resume/infra-invalid), the schema backing the decision-artifact fields, and wiring the adversarial agent to run at the accept gate behind a feature flag. Treat the "Recommended Prompt Changes" section of this handoff as reference for the human, NOT as a task for Codex.

Prompt base (canonical). The single source of truth for prompts is the current restructured, single-source, deduplicated prompts.toml (the one already in the workspace, with task-agnostic coder/reviewer rules: scope-bounded completeness, situational blast-radius, per-behavior/family coverage, enumerate-operations reviewer step). All prompt edits land on THIS file. Do not reintroduce or edit the older fragmented version, and do not treat any earlier "inserted need.md into prompts.toml" note as the working base. The three pending prompt additions (coder broad-exploration habit, supervisor staleness + anti-proof-loop sieves, decision-artifact fields) will be delivered by the human against this file; Codex should leave room for the decision-artifact fields in the schema but not author the prompt text.

