from __future__ import annotations

from pathlib import Path
from typing import Any

from supervisor.bench_runner import BenchRunner


async def run_benchmark(project_root: Path, *, model: str | None = None) -> dict[str, Any]:
    runner = BenchRunner(project_root, model=model)
    return await runner.run()
