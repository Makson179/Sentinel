"""Canonical model-facing routing policy for Bello Context Mode.

The policy is injected as sticky Codex developer instructions before the
coder's first turn.  The generated audit file reuses the same text so there is
one Python authority for the behavior Bello asks the model to follow.
"""

from __future__ import annotations

import hashlib
import json
import shlex


_ACTIVE_INDEX_SOURCE_MARKER = "__BELLO_ACTIVE_INDEX_SOURCE__"


_CONTEXT_MODE_ROUTING_TEMPLATE = """Bello Context Mode is enabled for this coder thread.

Context Mode is the primary interface for local repository inspection and command execution. Follow these requirements:

1. Bootstrap the repository index before any other repository read, search, or command. Your first tool call in every new coder thread must be `ctx_index` with `path` set to `.`, `maxDepth` set to `20`, `maxFiles` set to `1000`, and `source` set exactly to `__BELLO_ACTIVE_INDEX_SOURCE__`. This collision-resistant source belongs only to the current logical coder generation; remember it and include it as the `source` filter in every `ctx_search` over that snapshot. Never use the bare label `workspace` and never issue an unfiltered `ctx_search`. This is mandatory even when the repository looks small. If the repository exceeds the file limit, index the task-relevant subdirectories separately under fresh collision-resistant labels and filter searches to the matching label.
2. Use the `ctx_*` tools exclusively whenever they can perform the operation without a likely loss of correctness. Native shell command execution is an exception, not an equivalent default.
3. Use `ctx_search` for repository discovery and focused retrieval from the index, always with the exact collision-resistant `source` associated with the relevant snapshot, refresh, or retained command result. Every `ctx_search` `limit` must be an integer from `1` through `10`; never request a larger value such as `20`. Use `ctx_execute_file` when exact current contents of one file must be parsed, filtered, counted, or summarized. Use `ctx_execute` for local shell, Python, or JavaScript commands. Use `ctx_batch_execute` for related independent commands or exploratory test/build probes. Keep outputs focused with `intent` or `queries`. Keep every execution request inspectable: never embed a multi-kilobyte program or heredoc larger than 3 KiB in `ctx_execute`, and keep the combined command/code text across an entire `ctx_batch_execute` below 3 KiB. Add a task-scoped helper script with the normal reviewable file-edit tool, invoke it through a short `ctx_execute` command, and remove the helper before readiness when it is not a deliverable. Do not evade this aggregate bound by splitting one large inline program across batch children. The optional `timeout` field on all execution tools is measured in milliseconds, not seconds; normally omit it to use the 120000 ms default, or use values such as `30000` or `60000`, never second-like values such as `30`, `60`, or `120`.
4. Do not use native shell commands for ordinary reading, listing, or searching, including `cat`, `sed`, `nl`, `head`, `tail`, `rg`, `grep`, `find`, `ls`, `pwd`, and read-only `git` inspection, when a `ctx_*` tool can provide the same evidence.
5. The initial index is a snapshot. After materially changing files, refresh every changed file before relying on indexed search for its new contents. Give each refresh a collision-resistant source label containing a UUID or full timestamp plus the file name, then restrict the corresponding `ctx_search` call with that exact source filter. Never reuse a prior source or short sequential labels such as `refresh-1`, because the store is append-only and source filtering is substring-based. For exact post-edit state, prefer `ctx_execute_file`; never treat an older or unfiltered search hit as authoritative current contents. Re-index a directory once after a broad generated or mechanical rewrite under one new collision-resistant label instead of indexing it after every individual write.
6. Use the normal reviewable file-edit tool for source changes. Do not hide source mutations inside `ctx_execute` or another command runner. Context Mode is mandatory for the reads, searches, derivations, and commands around those edits; it is not a replacement for a structured edit operation.
7. Trusted Context Mode execution receipts count as Bello validation when every command is terminal-complete, provenance is trusted, the real exit status is unmasked, and the bounded broker result contains enough factual test output. Run final canonical validation through `ctx_execute` or `ctx_batch_execute` first. Native shell remains allowed only after an untrusted or incomplete Context result, an actual `ctx_*` failure or unavailable dependency, a required path or executable outside the Context sandbox, or a required `.git` mutation. If Bello steering or a completion gate says a Context validation is untrusted, has no trusted behavioral evidence, or does not count in the validation ledger, that statement itself establishes the incomplete-Context boundary: immediately rerun the requested final validation once through native shell. Do not retry the same `ctx_*` validation, do not refuse the native fallback as conflicting with this policy, and do not mark ready until the native command passes. If you use native shell, state that concrete capability boundary before doing so.
8. `ctx_stats` and `ctx_doctor` are diagnostics, not substitutes for repository work. Do not call `ctx_purge` without explicit user approval.

These routing requirements apply throughout the task, after steering, and after recovery. Do not wait to discover or load a skill: all eight `ctx_*` tools are already available to you."""


CONTEXT_MODE_ROUTING_TEXT = _CONTEXT_MODE_ROUTING_TEMPLATE.replace(
    _ACTIVE_INDEX_SOURCE_MARKER,
    "workspace-<UUID>",
)


def derive_context_index_source(generation_lease_id: str) -> str:
    """Return a non-secret, generation-unique source label for the append-only index."""

    if not isinstance(generation_lease_id, str) or not generation_lease_id.strip():
        raise ValueError("generation_lease_id must be a non-empty string")
    digest = hashlib.sha256(generation_lease_id.encode("utf-8")).hexdigest()
    return f"workspace-{digest}"


def render_context_mode_routing_text(active_index_source: str) -> str:
    """Bind the canonical policy to the controller-derived source for one generation."""

    if (
        not isinstance(active_index_source, str)
        or not active_index_source.startswith("workspace-")
        or len(active_index_source) != len("workspace-") + 64
        or any(character not in "0123456789abcdef" for character in active_index_source[10:])
    ):
        raise ValueError("active_index_source must be a workspace-prefixed SHA-256 label")
    return _CONTEXT_MODE_ROUTING_TEMPLATE.replace(
        _ACTIVE_INDEX_SOURCE_MARKER,
        active_index_source,
    )


CONTEXT_MODE_SESSION_REMINDER = (
    "Bello Context Mode is enabled. Obey the sticky developer routing policy before "
    "any workspace action: bootstrap with its controller-assigned unique source, filter "
    "every ctx_search to the exact relevant source, and use ctx_* exclusively whenever "
    "it can preserve correctness."
)

_SESSION_START_ROUTING_OUTPUT = json.dumps(
    {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": CONTEXT_MODE_SESSION_REMINDER,
        }
    },
    ensure_ascii=True,
    sort_keys=True,
    separators=(",", ":"),
)

# Codex runs matching command hooks as one awaited group without an ordering
# guarantee.  This independent SessionStart handler injects a bounded
# model-facing reminder alongside the signed lifecycle hook, without modifying
# or bypassing the signed broker.
SESSION_START_ROUTING_COMMAND = shlex.join(
    ("printf", "%s\\n", _SESSION_START_ROUTING_OUTPUT)
)
