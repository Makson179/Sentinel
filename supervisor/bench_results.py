from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATUS_VALUES = {
    "success",
    "failed",
    "timeout",
    "stuck",
    "provider_failure",
    "invalid_test",
    "crashed",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_per_test_result(path: Path, result: dict[str, Any]) -> None:
    if result.get("status") not in STATUS_VALUES:
        raise ValueError(f"invalid benchmark status: {result.get('status')}")
    _atomic_write_json(path, result)


def write_aggregate_result(
    tests_dir: Path,
    *,
    run_id: str,
    started_at: datetime,
    finished_at: datetime,
    root: Path | None = None,
) -> dict[str, Any]:
    results = []
    for test_dir in numeric_test_dirs(tests_dir):
        result_path = test_dir / "result.json"
        if not result_path.exists():
            continue
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if isinstance(result, dict) and result.get("run_id") == run_id:
            results.append(result)

    aggregate = {
        "run_id": run_id,
        "tests_dir": display_path(tests_dir, root or tests_dir.parent),
        "test_count": len(numeric_test_dirs(tests_dir)),
        "completed_count": len(results),
        "failed_count": sum(1 for result in results if result.get("success") != 1),
        "started_at": iso_z(started_at),
        "finished_at": iso_z(finished_at),
        "means": _means(results),
    }
    _atomic_write_json(tests_dir / "result.json", aggregate)
    return aggregate


def numeric_test_dirs(tests_dir: Path) -> list[Path]:
    if not tests_dir.exists():
        return []
    return sorted(
        [path for path in tests_dir.iterdir() if path.is_dir() and _is_decimal_folder_name(path.name)],
        key=lambda path: int(path.name),
    )


def display_path(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path.resolve())


def _means(results: list[dict[str, Any]]) -> dict[str, int | float | None]:
    means: dict[str, int | float | None] = {}
    success_values = [result.get("success") for result in results if _numeric(result.get("success"))]
    means["success"] = _mean(success_values)

    metric_names: set[str] = set()
    for result in results:
        metrics = result.get("metrics")
        if isinstance(metrics, dict):
            metric_names.update(metrics)
    for name in sorted(metric_names):
        values = []
        saw_metric = False
        for result in results:
            metrics = result.get("metrics")
            if not isinstance(metrics, dict) or name not in metrics:
                continue
            saw_metric = True
            value = metrics[name]
            if _numeric(value):
                values.append(value)
        means[name] = _mean(values) if values else None if saw_metric else None
    return means


def _mean(values: list[int | float]) -> int | float | None:
    if not values:
        return None
    return round(sum(values) / len(values), 4)


def _numeric(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_decimal_folder_name(name: str) -> bool:
    return name.isascii() and name.isdecimal()


def _atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
