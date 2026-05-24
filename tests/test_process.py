from __future__ import annotations

import sys
from pathlib import Path

from supervisor.process import launch_process


def test_launch_process_writes_stdout_and_stderr_logs(tmp_path: Path) -> None:
    stdout_path = tmp_path / "codex-stdout.log"
    stderr_path = tmp_path / "codex-stderr.log"
    managed = launch_process(
        [
            sys.executable,
            "-c",
            "import sys; print('stdout marker'); print('stderr marker', file=sys.stderr)",
        ],
        tmp_path,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )

    assert managed.process.wait(timeout=5) == 0
    assert managed.poll() == 0
    assert stdout_path.read_text(encoding="utf-8").strip() == "stdout marker"
    assert stderr_path.read_text(encoding="utf-8").strip() == "stderr marker"


def test_launch_process_closes_child_stdin(tmp_path: Path) -> None:
    stdout_path = tmp_path / "stdin.log"
    managed = launch_process(
        [
            sys.executable,
            "-c",
            "import sys; data = sys.stdin.read(); print(len(data))",
        ],
        tmp_path,
        stdout_path=stdout_path,
    )

    assert managed.process.wait(timeout=5) == 0
    assert stdout_path.read_text(encoding="utf-8").strip() == "0"
