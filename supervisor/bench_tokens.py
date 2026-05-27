from __future__ import annotations

from collections.abc import Iterable
from typing import Any


TOKEN_FIELDS = (
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "total_tokens",
)

TOKEN_METRIC_FIELDS = (
    "coder_input_tokens",
    "coder_cached_input_tokens",
    "coder_output_tokens",
    "coder_total_tokens",
    "supervisor_input_tokens",
    "supervisor_cached_input_tokens",
    "supervisor_output_tokens",
    "supervisor_total_tokens",
    "total_input_tokens",
    "total_cached_input_tokens",
    "total_output_tokens",
    "total_tokens",
    "supervisor_token_share",
    "supervisor_tokens_per_call",
)


def extract_token_usage(payload: Any) -> dict[str, int] | None:
    return _extract_token_usage(payload, depth=0)


def compute_token_metrics(perf_events: Iterable[dict[str, Any]], *, supervisor_call_count: int) -> dict[str, int | float | None]:
    token_events = [
        event
        for event in perf_events
        if event.get("event") == "token_usage_updated" and isinstance(event.get("usage"), dict)
    ]
    coder_events = [event["usage"] for event in token_events if event.get("role") == "coder"]
    coder_usage = _coder_delta(coder_events)

    supervisor_by_call: dict[str, dict[str, int]] = {}
    for event in token_events:
        if event.get("role") != "supervisor":
            continue
        call_id = event.get("supervisor_call_id")
        if not isinstance(call_id, str):
            continue
        supervisor_by_call[call_id] = event["usage"]
    supervisor_usage = _sum_usages(supervisor_by_call.values()) if supervisor_by_call else _null_usage()

    metrics: dict[str, int | float | None] = {
        "coder_input_tokens": coder_usage["input_tokens"],
        "coder_cached_input_tokens": coder_usage["cached_input_tokens"],
        "coder_output_tokens": coder_usage["output_tokens"],
        "coder_total_tokens": coder_usage["total_tokens"],
        "supervisor_input_tokens": supervisor_usage["input_tokens"],
        "supervisor_cached_input_tokens": supervisor_usage["cached_input_tokens"],
        "supervisor_output_tokens": supervisor_usage["output_tokens"],
        "supervisor_total_tokens": supervisor_usage["total_tokens"],
    }
    metrics["total_input_tokens"] = _add_nullable(metrics["coder_input_tokens"], metrics["supervisor_input_tokens"])
    metrics["total_cached_input_tokens"] = _add_nullable(
        metrics["coder_cached_input_tokens"], metrics["supervisor_cached_input_tokens"]
    )
    metrics["total_output_tokens"] = _add_nullable(metrics["coder_output_tokens"], metrics["supervisor_output_tokens"])
    metrics["total_tokens"] = _add_nullable(metrics["coder_total_tokens"], metrics["supervisor_total_tokens"])
    metrics["supervisor_token_share"] = _ratio(metrics["supervisor_total_tokens"], metrics["total_tokens"])
    metrics["supervisor_tokens_per_call"] = _ratio(metrics["supervisor_total_tokens"], supervisor_call_count)
    return metrics


def _extract_token_usage(payload: Any, *, depth: int) -> dict[str, int] | None:
    if depth > 5:
        return None
    usage = normalize_token_usage(payload)
    if usage is not None:
        return usage
    if isinstance(payload, dict):
        for key in ("usage", "tokenUsage", "token_usage", "modelUsage", "metrics", "turn", "response", "result"):
            if key in payload:
                nested = _extract_token_usage(payload[key], depth=depth + 1)
                if nested is not None:
                    return nested
        for value in payload.values():
            if isinstance(value, (dict, list)):
                nested = _extract_token_usage(value, depth=depth + 1)
                if nested is not None:
                    return nested
    if isinstance(payload, list):
        for item in payload:
            nested = _extract_token_usage(item, depth=depth + 1)
            if nested is not None:
                return nested
    return None


def normalize_token_usage(value: Any) -> dict[str, int] | None:
    if not isinstance(value, dict):
        return None
    input_tokens = _first_int(
        value,
        "input_tokens",
        "inputTokens",
        "prompt_tokens",
        "promptTokens",
        "promptTokenCount",
        "prompt_token_count",
    )
    cached_input_tokens = _first_int(
        value,
        "cached_input_tokens",
        "cachedInputTokens",
        "input_cached_tokens",
        "inputCachedTokens",
        "cache_read_input_tokens",
        "cacheReadInputTokens",
        "cached_prompt_tokens",
        "cachedPromptTokens",
    )
    output_tokens = _first_int(
        value,
        "output_tokens",
        "outputTokens",
        "completion_tokens",
        "completionTokens",
        "completionTokenCount",
        "completion_token_count",
    )
    total_tokens = _first_int(value, "total_tokens", "totalTokens", "totalTokenCount", "total_token_count")
    if total_tokens is None and input_tokens is not None and output_tokens is not None:
        total_tokens = input_tokens + output_tokens
    if input_tokens is None and cached_input_tokens is None and output_tokens is None and total_tokens is None:
        return None
    return {
        "input_tokens": input_tokens,
        "cached_input_tokens": cached_input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }


def _coder_delta(usages: list[dict[str, int]]) -> dict[str, int | None]:
    if not usages:
        return _null_usage()
    if len(usages) == 1:
        return {field: usages[0].get(field) for field in TOKEN_FIELDS}
    first = usages[0]
    last = usages[-1]
    return {
        field: max(0, last[field] - first[field])
        if isinstance(first.get(field), int) and isinstance(last.get(field), int)
        else last.get(field)
        for field in TOKEN_FIELDS
    }


def _sum_usages(usages: Iterable[dict[str, int]]) -> dict[str, int | None]:
    totals: dict[str, int | None] = {}
    for field in TOKEN_FIELDS:
        values = [usage[field] for usage in usages if isinstance(usage.get(field), int)]
        totals[field] = sum(values) if values else None
    return totals


def _null_usage() -> dict[str, None]:
    return {field: None for field in TOKEN_FIELDS}


def _first_int(value: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        raw = value.get(key)
        if isinstance(raw, bool):
            continue
        if isinstance(raw, int):
            return raw
        if isinstance(raw, float) and raw.is_integer():
            return int(raw)
    return None


def _add_nullable(left: int | float | None, right: int | float | None) -> int | float | None:
    if left is None or right is None:
        return None
    return left + right


def _ratio(numerator: int | float | None, denominator: int | float | None) -> float | None:
    if numerator is None or denominator in {None, 0}:
        return None
    return numerator / denominator
