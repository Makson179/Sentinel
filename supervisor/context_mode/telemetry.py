"""Authority-separated Context Mode counters and provider cumulative gauges."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from ._util import (
    ContextModeDataError,
    atomic_write_json,
    load_json_object,
    require_int,
    require_nonempty,
    strict_object,
)
from .events import ClientRole


TELEMETRY_SCHEMA_VERSION = 1


class TelemetryError(ContextModeDataError):
    """A metric was updated by the wrong authority or has invalid semantics."""


class MetricAuthority(str, Enum):
    CONTROLLER_OBSERVED = "controller_observed"
    BROKER_RECEIPT_DERIVED = "broker_receipt_derived"
    PROVIDER_REPORTED = "provider_reported"


@dataclass(frozen=True)
class MetricSpec:
    authority: MetricAuthority
    idempotency: str


_CONTROLLER_COUNTERS = frozenset(
    {
        "context_mode_calls_started",
        "context_mode_calls_completed",
        "context_mode_calls_failed",
        "context_mode_search_calls",
        "context_mode_execute_calls",
        "context_mode_untrusted_results",
        "context_mode_provenance_failures",
        "context_mode_compactions_attempted",
        "context_mode_compactions_recovered",
        "coder_turns",
        "coder_generation_restarts",
        "coder_process_recoveries",
        "coder_process_controlled_recycles",
        "context_mode_purges",
    }
)
_BROKER_COUNTERS = frozenset(
    {
        "context_mode_operations_receipted",
        "context_mode_estimated_source_tokens",
        "context_mode_estimated_returned_tokens",
        "context_mode_indexed_bytes",
    }
)

CONTEXT_METRIC_SPECS: Mapping[str, MetricSpec] = {
    **{
        name: MetricSpec(MetricAuthority.CONTROLLER_OBSERVED, "logical call/lifecycle key")
        for name in _CONTROLLER_COUNTERS
    },
    **{
        name: MetricSpec(MetricAuthority.BROKER_RECEIPT_DERIVED, "broker operation_id")
        for name in _BROKER_COUNTERS
    },
}


class AuthoritySeparatedCounters:
    """Counters that cannot be incremented from two telemetry namespaces."""

    def __init__(
        self,
        state_path: Path | None = None,
        *,
        maximum_idempotency_keys: int = 1_000_000,
    ) -> None:
        require_int(maximum_idempotency_keys, "maximum_idempotency_keys", minimum=1)
        self.state_path = Path(state_path) if state_path is not None else None
        self.maximum_idempotency_keys = maximum_idempotency_keys
        self._values: dict[str, int] = {name: 0 for name in CONTEXT_METRIC_SPECS}
        self._seen: set[tuple[str, str]] = set()
        self._lock = threading.RLock()
        if self.state_path is not None and self.state_path.exists():
            self._load()

    def increment(
        self,
        metric: str,
        *,
        authority: MetricAuthority | str,
        idempotency_key: str,
        amount: int = 1,
    ) -> bool:
        spec = CONTEXT_METRIC_SPECS.get(metric)
        if spec is None:
            raise TelemetryError(f"unknown Context Mode counter: {metric}")
        authority = MetricAuthority(authority)
        if authority is not spec.authority:
            raise TelemetryError(
                f"metric {metric} belongs to {spec.authority.value}, not {authority.value}"
            )
        require_nonempty(idempotency_key, "idempotency_key")
        require_int(amount, "amount")
        key = (metric, idempotency_key)
        with self._lock:
            if key in self._seen:
                return False
            if len(self._seen) >= self.maximum_idempotency_keys:
                raise TelemetryError("counter idempotency state capacity exceeded; refusing fail-open eviction")
            self._seen.add(key)
            self._values[metric] += amount
            try:
                self._persist()
            except BaseException:
                self._values[metric] -= amount
                self._seen.remove(key)
                raise
            return True

    def value(self, metric: str) -> int:
        if metric not in CONTEXT_METRIC_SPECS:
            raise TelemetryError(f"unknown Context Mode counter: {metric}")
        with self._lock:
            return self._values[metric]

    def snapshot(self) -> dict[str, dict[str, int]]:
        with self._lock:
            return {
                authority.value: {
                    name: self._values[name]
                    for name, spec in CONTEXT_METRIC_SPECS.items()
                    if spec.authority is authority
                }
                for authority in (
                    MetricAuthority.CONTROLLER_OBSERVED,
                    MetricAuthority.BROKER_RECEIPT_DERIVED,
                )
            }

    def record_receipt_bytes(
        self,
        *,
        operation_id: str,
        source_bytes: int | None,
        returned_bytes: int | None,
        indexed_bytes: int | None,
    ) -> None:
        authority = MetricAuthority.BROKER_RECEIPT_DERIVED
        self.increment(
            "context_mode_operations_receipted",
            authority=authority,
            idempotency_key=operation_id,
        )
        if source_bytes is not None:
            require_int(source_bytes, "source_bytes")
            self.increment(
                "context_mode_estimated_source_tokens",
                authority=authority,
                idempotency_key=operation_id,
                amount=(source_bytes + 3) // 4,
            )
        if returned_bytes is not None:
            require_int(returned_bytes, "returned_bytes")
            self.increment(
                "context_mode_estimated_returned_tokens",
                authority=authority,
                idempotency_key=operation_id,
                amount=(returned_bytes + 3) // 4,
            )
        if indexed_bytes is not None:
            require_int(indexed_bytes, "indexed_bytes")
            self.increment(
                "context_mode_indexed_bytes",
                authority=authority,
                idempotency_key=operation_id,
                amount=indexed_bytes,
            )

    def _persist(self) -> None:
        if self.state_path is None:
            return
        atomic_write_json(
            self.state_path,
            {
                "schema_version": TELEMETRY_SCHEMA_VERSION,
                "values": dict(sorted(self._values.items())),
                "seen": [list(item) for item in sorted(self._seen)],
            },
            mode=0o600,
        )

    def _load(self) -> None:
        assert self.state_path is not None
        value = load_json_object(self.state_path, max_bytes=128 * 1024 * 1024)
        strict_object(
            value,
            required=frozenset({"schema_version", "values", "seen"}),
            name="authority-separated counter state",
        )
        require_int(value["schema_version"], "schema_version", minimum=1)
        if value["schema_version"] != TELEMETRY_SCHEMA_VERSION:
            raise TelemetryError("unsupported authority-separated counter state schema")
        values = value["values"]
        seen = value["seen"]
        if not isinstance(values, Mapping) or frozenset(values) != frozenset(CONTEXT_METRIC_SPECS):
            raise TelemetryError("counter state metric catalogue mismatch")
        if any(
            isinstance(metric_value, bool)
            or not isinstance(metric_value, int)
            or metric_value < 0
            for metric_value in values.values()
        ):
            raise TelemetryError("counter state values must be non-negative integers")
        if not isinstance(seen, list) or len(seen) > self.maximum_idempotency_keys:
            raise TelemetryError("counter idempotency state is invalid or over capacity")
        parsed_seen: set[tuple[str, str]] = set()
        for item in seen:
            if (
                not isinstance(item, list)
                or len(item) != 2
                or item[0] not in CONTEXT_METRIC_SPECS
                or not isinstance(item[1], str)
                or not item[1]
            ):
                raise TelemetryError("counter idempotency key is malformed")
            parsed_seen.add((item[0], item[1]))
        if len(parsed_seen) != len(seen):
            raise TelemetryError("counter idempotency state contains duplicates")
        self._values = dict(values)
        self._seen = parsed_seen


class ThreadLifecycle(str, Enum):
    CREATED = "created"
    FORKED = "forked"
    RESUMED = "resumed"


@dataclass(frozen=True)
class ProviderThreadKey:
    role: ClientRole
    provider_thread_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.role, ClientRole):
            object.__setattr__(self, "role", ClientRole(self.role))
        require_nonempty(self.provider_thread_id, "provider_thread_id")


@dataclass
class _ProviderGauge:
    lifecycle: ThreadLifecycle
    parent: ProviderThreadKey | None
    baseline: dict[str, int]
    maxima: dict[str, int] = field(default_factory=dict)
    raw_payloads: list[dict[str, Any]] = field(default_factory=list)
    ambiguous: bool = False
    anomalies: int = 0


@dataclass(frozen=True)
class ProviderGaugeUpdate:
    key: ProviderThreadKey
    numeric_total_gauge: Mapping[str, int]
    authoritative_total_tokens: int | None
    adjusted_total_tokens: int | None
    live_delta_tokens: int | None
    anomaly_fields: tuple[str, ...]
    ambiguous: bool
    raw_payload: Mapping[str, Any]


class ProviderTokenGaugeBook:
    """Monotonic cumulative provider totals keyed by role and logical thread."""

    def __init__(self, state_path: Path | None = None):
        self.state_path = Path(state_path) if state_path is not None else None
        self._gauges: dict[ProviderThreadKey, _ProviderGauge] = {}
        self._lock = threading.RLock()
        if self.state_path is not None and self.state_path.exists():
            self._load()

    def register_thread(
        self,
        key: ProviderThreadKey,
        *,
        lifecycle: ThreadLifecycle | str,
        parent: ProviderThreadKey | None = None,
        first_snapshot_includes_parent: bool | None = None,
    ) -> None:
        lifecycle = ThreadLifecycle(lifecycle)
        with self._lock:
            existing = self._gauges.get(key)
            if lifecycle is ThreadLifecycle.RESUMED:
                if existing is None:
                    raise TelemetryError("cannot resume an unknown provider thread gauge")
                return
            if existing is not None:
                raise TelemetryError("provider thread gauge is already registered")
            if lifecycle is ThreadLifecycle.CREATED:
                if parent is not None:
                    raise TelemetryError("created provider thread must not have a parent")
                gauge = _ProviderGauge(lifecycle, None, {})
            else:
                if parent is None or parent not in self._gauges:
                    raise TelemetryError("forked thread requires a registered parent gauge")
                if parent.role is not key.role:
                    raise TelemetryError("forked thread parent role must match")
                parent_maxima = dict(self._gauges[parent].maxima)
                if first_snapshot_includes_parent is True:
                    gauge = _ProviderGauge(lifecycle, parent, parent_maxima)
                elif first_snapshot_includes_parent is False:
                    gauge = _ProviderGauge(lifecycle, parent, {})
                else:
                    gauge = _ProviderGauge(lifecycle, parent, {}, ambiguous=True)
            self._gauges[key] = gauge
            try:
                self._persist()
            except BaseException:
                del self._gauges[key]
                raise

    def update(self, key: ProviderThreadKey, payload: Mapping[str, Any]) -> ProviderGaugeUpdate:
        """Apply only the cumulative ``total`` object; ``last`` is diagnostic."""

        with self._lock:
            if not isinstance(payload, Mapping):
                raise TelemetryError("provider token payload must be an object")
            total = payload.get("total")
            if not isinstance(total, Mapping):
                raise TelemetryError("provider token payload has no cumulative total object")
            # deepcopy preserves provider-specific and ``last`` fields without
            # letting caller mutation rewrite stored telemetry.
            raw_payload = copy.deepcopy(dict(payload))
            numeric: dict[str, int] = {}
            for name, value in total.items():
                if isinstance(name, str) and isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    numeric[name] = value
            gauge = self._gauges.get(key)
            created = gauge is None
            if gauge is None:
                # A normal created thread has a zero baseline.  Explicit fork
                # attribution still requires register_thread before first sample.
                gauge = _ProviderGauge(ThreadLifecycle.CREATED, None, {})
                self._gauges[key] = gauge
            previous_gauge = copy.deepcopy(gauge)
            had_numeric_sample = bool(gauge.maxima)
            previous_adjusted = self._adjusted_authoritative(gauge)
            anomalies: list[str] = []
            for name, value in numeric.items():
                previous = gauge.maxima.get(name)
                if previous is not None and value < previous:
                    anomalies.append(name)
                    continue
                gauge.maxima[name] = value
            if anomalies:
                gauge.anomalies += 1
            gauge.raw_payloads.append(raw_payload)
            authoritative = self._authoritative(gauge.maxima)
            adjusted = self._adjusted_authoritative(gauge)
            if gauge.ambiguous or adjusted is None:
                live_delta = None
            elif not had_numeric_sample:
                # A created thread begins at zero; a proven fork begins at its
                # captured baseline.  Therefore the first adjusted gauge is the
                # first positive live delta, while the raw snapshot remains
                # cumulative provider data.
                live_delta = adjusted
            elif previous_adjusted is None:
                live_delta = None
            else:
                live_delta = max(0, adjusted - previous_adjusted)
            try:
                self._persist()
            except BaseException:
                if created:
                    del self._gauges[key]
                else:
                    self._gauges[key] = previous_gauge
                raise
            return ProviderGaugeUpdate(
                key=key,
                numeric_total_gauge=dict(gauge.maxima),
                authoritative_total_tokens=authoritative,
                adjusted_total_tokens=None if gauge.ambiguous else adjusted,
                live_delta_tokens=live_delta,
                anomaly_fields=tuple(sorted(anomalies)),
                ambiguous=gauge.ambiguous,
                raw_payload=raw_payload,
            )

    @staticmethod
    def _authoritative(values: Mapping[str, int]) -> int | None:
        if "totalTokens" in values:
            return values["totalTokens"]
        if "inputTokens" in values and "outputTokens" in values:
            return values["inputTokens"] + values["outputTokens"]
        return None

    @classmethod
    def _adjusted_authoritative(cls, gauge: _ProviderGauge) -> int | None:
        total = cls._authoritative(gauge.maxima)
        if total is None:
            return None
        baseline = cls._authoritative(gauge.baseline) or 0
        if total < baseline:
            gauge.ambiguous = True
            return None
        return total - baseline

    def adjusted_field(self, key: ProviderThreadKey, field_name: str) -> int | None:
        with self._lock:
            gauge = self._gauges.get(key)
            if gauge is None or gauge.ambiguous or field_name not in gauge.maxima:
                return None
            baseline = gauge.baseline.get(field_name, 0)
            if gauge.maxima[field_name] < baseline:
                return None
            return gauge.maxima[field_name] - baseline

    def role_totals(self, role: ClientRole | str) -> dict[str, int | None]:
        role = ClientRole(role)
        fields = (
            "inputTokens",
            "cachedInputTokens",
            "outputTokens",
            "reasoningOutputTokens",
            "cacheWriteInputTokens",
        )
        with self._lock:
            selected = [(key, gauge) for key, gauge in self._gauges.items() if key.role is role]
            if not selected:
                # No provider observation is not proof of zero usage.  Keep
                # every aggregate explicitly unavailable until at least one
                # cumulative ``total`` sample exists for this role.
                return {**{field_name: None for field_name in fields}, "totalTokens": None}
            ambiguous = any(gauge.ambiguous for _, gauge in selected)
            result: dict[str, int | None] = {}
            for field_name in fields:
                values = [self.adjusted_field(key, field_name) for key, _ in selected]
                result[field_name] = None if ambiguous or any(value is None for value in values) else sum(values)  # type: ignore[arg-type]
            authoritative_values = [self._adjusted_authoritative(gauge) for _, gauge in selected]
            result["totalTokens"] = (
                None
                if ambiguous or any(value is None for value in authoritative_values)
                else sum(authoritative_values)  # type: ignore[arg-type]
            )
            return result

    @property
    def anomaly_count(self) -> int:
        with self._lock:
            return sum(gauge.anomalies for gauge in self._gauges.values())

    @property
    def ambiguous_thread_count(self) -> int:
        with self._lock:
            return sum(gauge.ambiguous for gauge in self._gauges.values())

    def raw_payloads(self, key: ProviderThreadKey) -> tuple[Mapping[str, Any], ...]:
        with self._lock:
            gauge = self._gauges.get(key)
            return tuple(copy.deepcopy(gauge.raw_payloads)) if gauge else ()

    def _persist(self) -> None:
        if self.state_path is None:
            return
        threads = []
        for key, gauge in self._gauges.items():
            threads.append(
                {
                    "role": key.role.value,
                    "provider_thread_id": key.provider_thread_id,
                    "lifecycle": gauge.lifecycle.value,
                    "parent": None
                    if gauge.parent is None
                    else {
                        "role": gauge.parent.role.value,
                        "provider_thread_id": gauge.parent.provider_thread_id,
                    },
                    "baseline": gauge.baseline,
                    "maxima": gauge.maxima,
                    "raw_payloads": gauge.raw_payloads,
                    "ambiguous": gauge.ambiguous,
                    "anomalies": gauge.anomalies,
                }
            )
        atomic_write_json(
            self.state_path,
            {"schema_version": TELEMETRY_SCHEMA_VERSION, "threads": threads},
            mode=0o600,
        )

    def _load(self) -> None:
        assert self.state_path is not None
        value = load_json_object(self.state_path, max_bytes=64 * 1024 * 1024)
        if frozenset(value) != {"schema_version", "threads"}:
            raise TelemetryError("provider gauge state has unexpected fields")
        require_int(value["schema_version"], "schema_version", minimum=1)
        if value["schema_version"] != TELEMETRY_SCHEMA_VERSION or not isinstance(value["threads"], list):
            raise TelemetryError("provider gauge state schema is invalid")
        pending_parent: dict[ProviderThreadKey, Mapping[str, Any] | None] = {}
        for item in value["threads"]:
            if not isinstance(item, Mapping):
                raise TelemetryError("provider gauge thread state must be an object")
            required = {
                "role",
                "provider_thread_id",
                "lifecycle",
                "parent",
                "baseline",
                "maxima",
                "raw_payloads",
                "ambiguous",
                "anomalies",
            }
            if frozenset(item) != required:
                raise TelemetryError("provider gauge thread state fields mismatch")
            key = ProviderThreadKey(ClientRole(item["role"]), item["provider_thread_id"])
            baseline, maxima = item["baseline"], item["maxima"]
            if not isinstance(baseline, Mapping) or not isinstance(maxima, Mapping):
                raise TelemetryError("provider gauge baseline/maxima must be objects")
            for table in (baseline, maxima):
                if any(
                    not isinstance(name, str)
                    or isinstance(number, bool)
                    or not isinstance(number, int)
                    or number < 0
                    for name, number in table.items()
                ):
                    raise TelemetryError("provider gauge numeric state is malformed")
            raw_payloads = item["raw_payloads"]
            if not isinstance(raw_payloads, list) or any(not isinstance(sample, Mapping) for sample in raw_payloads):
                raise TelemetryError("provider raw payload state is malformed")
            if not isinstance(item["ambiguous"], bool):
                raise TelemetryError("provider ambiguous flag must be boolean")
            require_int(item["anomalies"], "anomalies")
            gauge = _ProviderGauge(
                lifecycle=ThreadLifecycle(item["lifecycle"]),
                parent=None,
                baseline=dict(baseline),
                maxima=dict(maxima),
                raw_payloads=[dict(sample) for sample in raw_payloads],
                ambiguous=item["ambiguous"],
                anomalies=item["anomalies"],
            )
            if key in self._gauges:
                raise TelemetryError("duplicate provider thread gauge state")
            self._gauges[key] = gauge
            pending_parent[key] = item["parent"]
        for key, parent_value in pending_parent.items():
            if parent_value is None:
                continue
            if not isinstance(parent_value, Mapping) or frozenset(parent_value) != {"role", "provider_thread_id"}:
                raise TelemetryError("provider parent gauge state is malformed")
            parent = ProviderThreadKey(ClientRole(parent_value["role"]), parent_value["provider_thread_id"])
            if parent not in self._gauges:
                raise TelemetryError("provider parent gauge is missing")
            self._gauges[key].parent = parent


_PROVIDER_FIELD_METRICS = {
    "inputTokens": "input_tokens",
    "cachedInputTokens": "cached_input_tokens",
    "outputTokens": "output_tokens",
    "reasoningOutputTokens": "reasoning_output_tokens",
    "cacheWriteInputTokens": "cache_write_input_tokens",
    "totalTokens": "total_tokens",
}


def provider_metric_names(role: ClientRole | str) -> Mapping[str, str]:
    """Map cumulative provider fields to role-separated public metric names."""

    role = ClientRole(role)
    return {
        field: f"provider_{role.value}_{suffix}"
        for field, suffix in _PROVIDER_FIELD_METRICS.items()
    }


ContextTelemetry = AuthoritySeparatedCounters
