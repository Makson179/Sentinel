from __future__ import annotations

import re

MarkdownFenceState = tuple[str, int] | None


def advance_markdown_fence(
    line: str,
    state: MarkdownFenceState,
) -> tuple[MarkdownFenceState, bool]:
    """Advance a CommonMark-style fenced block and report a real fence marker.

    Closing runs must use the opening character and be at least as long as the
    opening run.  This matters for quoted output that nests triple backticks inside
    an outer four-backtick fence.
    """

    # A fence nested in a Markdown list can have more than three physical
    # leading spaces after the list container.  We do not have the full block
    # parser here, so recognize any whitespace-indented fence fail-closed;
    # otherwise captured report output can manufacture live section labels.
    candidate = line.lstrip(" \t")
    if state is None:
        opening = re.match(r"^(`{3,}|~{3,})(.*)$", candidate)
        if opening is None:
            return None, False
        marker = opening.group(1)
        remainder = opening.group(2)
        if marker[0] == "`" and "`" in remainder:
            return None, False
        return (marker[0], len(marker)), True

    marker_char, opening_length = state
    closing = re.fullmatch(
        re.escape(marker_char) + "{" + str(opening_length) + r",}[ \t]*",
        candidate,
    )
    if closing is not None:
        return None, True
    return state, False


def unfenced_markdown_lines(text: str) -> list[str]:
    state: MarkdownFenceState = None
    lines: list[str] = []
    for line in text.splitlines():
        before = state
        state, is_marker = advance_markdown_fence(line, state)
        if is_marker or before is not None:
            continue
        lines.append(line)
    return lines
