# Sentinel Supervisor Review and Self-Improvement

You are reviewing the Sentinel supervisor's behavior on one run, to find what went wrong and why, and to fix the technical causes. You know this codebase; study it first.

## Scope of authority

- You may fix technical causes: controller logic, packet construction, schema, policy, harness, integration.
- You must NOT edit prompts. Prompt text is a reviewed contract. If a problem's cause is the prompt, record it in the report for human review and leave the prompt untouched.

## Using your knowledge of the code

- Use it to check mechanics objectively: what `policy.py` actually allows or denies, what the wake packet actually carried, how completion was decided.
- Do NOT use it to excuse a decision by the system's intent. Judge each supervisor decision only by the evidence in the wake packet it saw at that moment, never by how the system was designed to behave and never by the final outcome. A decision can be right even if the run failed, and wrong even if it succeeded. Judging by outcome rewards luck.

## How to read the run

- The Sentinel run folder has `.supervisor/events.jsonl` (decisions, reasons, sequence) and `.supervisor/LAST_ACTION.md`. Use `events.jsonl` as the index and timeline spine.
- Full evidence is in the Codex rollouts under `~/.codex/sessions` for this run (filter by the run's cwd and time window). Coder rollouts hold commands, outputs, exit codes, patches. Each supervisor wake is its own short rollout: its input is the wake-packet JSON, its output is the decision JSON.
- Reconstruct the timeline: order supervisor wakes by `wake_sequence`, and for each, pair the wake packet (what it saw) with the decision it returned and what the coder did next.

## What to evaluate, per supervisor decision

For each noop/approve/deny/intervene/restart/complete/pause:

- Was it justified by the wake packet at that moment.
- approve/deny: was the action correctly judged in context; was the deny reason clear and delivered to the coder.
- intervene: was the steer warranted and concrete.
- restart: was the generation genuinely unreliable by the evidence then, or premature; was the handoff well formed.
- complete: was there real evidence, or was it premature.
- Were any needed actions missed (a loop left running, an unsafe action approved, a premature completion accepted).
- Overall how supervisor follows the prompt, does it update files correctly and effectively? 

## Cause attribution

Every problem gets exactly one cause label plus a file or log pointer:

- `prompt`: supervisor or coder prompt wording led it wrong. Report only, do not fix.
- `policy`: deterministic allow/deny classes wrong.
- `packet`: supervisor lacked a field it needed and judged blind.
- `schema`: output schema or its validation.
- `harness`: assembly, delivery, reason forwarding, wiring, logging.
- `coder`: the coder model erred, not Sentinel.
- `task_eval`: the task or success criterion was flawed, not the agent.
- 'tech': some problems with how code of supervisor is written

## Output: write `supervisor_review.md`

```markdown
# Supervisor Review

## Run summary
task:
generations / restarts:
decisions total (by type):

## Problems
- id:
  what_happened:
  decision_and_wake: (wake_sequence, what packet showed, decision returned)
  judged_by_snapshot: why this was wrong given only the evidence then
  cause: prompt | policy | packet | schema | harness | coder | task_eval
  pointer: file or log line
  fix: technical change, or "prompt change, review needed" if cause is prompt

## What went well
- decision and why it was correct given the evidence then

## Fixes applied
- file: change: why:

## Left for human review (prompt-caused)
- problem id: suggested prompt change:
```

## Constraints

- Judge by evidence at each wake, not by outcome or design intent.
- One cause label per problem, with a pointer.
- Fix technical causes only. Never edit prompts; surface them for review.
- Do not trust self-reports; verify against rollouts and final state.