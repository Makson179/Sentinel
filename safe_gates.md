# Sentinel Safe Gates Rollout Note

Sentinel now has deterministic, conservative gate infrastructure for reducing supervisor work without changing approval policy. The gates are controller-owned and fail open to the previous review/wake path on unknown data, exceptions, unsupported workspace state, missing hashes, or malformed gate state.

## Configuration

Gate modes live in `.supervisor/config.json` through `SentinelConfig`:

- `runtime_wake_gate_mode`: `disabled | shadow | enforce` (default `disabled`)
- `completion_preflight_gate_mode`: `disabled | shadow | enforce` (default `disabled`)
- `packet_budget_gate_mode`: `disabled | shadow | enforce` (default `shadow`)
- `runtime_large_diff_bands`: default `[1, 2, 4, 8]`
- `completion_packet_manifest_threshold_chars`: default `120000`
- `reviewer_formatting_retry_count`: default `1`
- `fresh_reviewer_fallback_count`: default `1`

Defaults preserve legacy behavior except packet-budget shadow logging. Enable gates gradually after reviewing `gate_decision` and `workspace_state_capture` records in `.supervisor/log.jsonl`.

## Safety Invariants

- App-server approval requests are handled in `handle_server_request` and do not enter runtime wake suppression/coalescing or completion preflight.
- Runtime wake gates can only emit, coalesce until turn end, or suppress exact duplicates. They cannot approve, deny, restart, return, or cancel.
- Completion preflight uses tri-state certainty. `UNKNOWN` always continues to completion review.
- The hard completion preflight path only requests fresh evidence when the shared final behavioral-floor predicate is deterministically failing for the same frozen state.
- Workspace-state mismatch after completion review discards the stale decision and reruns review instead of returning the coder.
- Packet artifact failures fall back to full review packets.

## New Evidence Identity

`ValidationRun.validation_id` remains the stable validation signature for compatibility. New records also carry:

- `validation_signature_id`: stable logical command identity
- `validation_run_id`: unique execution identity
- controller-observed command metadata such as generation, command item ID, completion sequence, output capture status, completion status, and workspace state ID after the command when known

Old persisted records without these fields still parse. Missing run/state IDs are treated as uncertainty for hard preflight.

## Packet Artifacts

When `packet_budget_gate_mode=enforce` and a first full completion packet exceeds the threshold, large diff/context/validation/inspection material is stored under `.supervisor/review_artifacts/<completion_attempt_id>/` with a manifest containing content hashes, sizes, paths, materiality, truncation flags, and workspace state IDs. If writing artifacts fails, Sentinel uses `full_fallback`.
