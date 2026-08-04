---
name: bello-context-mode
description: Reduce large local workspace results through the pinned offline Context Mode worker.
---

# Bello Context Mode

Use this worker only for local workspace data:

- Run bounded derivations with `ctx_execute`.
- Analyze a large file with `ctx_execute_file`; the file is supplied as `FILE_CONTENT`.
- Combine related commands with `ctx_batch_execute`.
- Persist local text or workspace files with `ctx_index`, then retrieve focused excerpts with `ctx_search`.
- Inspect bounded health information with `ctx_stats` and `ctx_doctor`.
- Use `ctx_purge` only after explicit approval.

Prefer code that filters, counts, parses, or summarizes before printing. Large execution results are automatically retained in SQLite/FTS5 and replaced by a bounded preview plus a source label. After compaction, the SessionStart hook restores bounded recent memory and routing guidance.

Do not attempt to leave the active workspace or bypass the Bello launcher and broker. If a local dependency is unavailable, report the missing capability.
