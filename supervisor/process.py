from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, IO


@dataclass
class ManagedProcess:
    process: subprocess.Popen[str]
    command: list[str]
    log_files: tuple[IO[Any], ...] = ()
    _logs_closed: bool = False

    @property
    def pid(self) -> int:
        return self.process.pid

    def poll(self) -> int | None:
        returncode = self.process.poll()
        if returncode is not None:
            self.close_logs()
        return returncode

    def close_logs(self) -> None:
        if self._logs_closed:
            return
        self._logs_closed = True
        for handle in self.log_files:
            try:
                handle.close()
            except OSError:
                pass

    def terminate_group(self, soft_timeout: float = 5.0, term_timeout: float = 5.0) -> int | None:
        try:
            pgid = os.getpgid(self.process.pid)
        except ProcessLookupError:
            self.close_logs()
            return self.process.poll()
        try:
            for sig, timeout in ((signal.SIGINT, soft_timeout), (signal.SIGTERM, term_timeout)):
                if self.process.poll() is not None:
                    return self.process.returncode
                try:
                    os.killpg(pgid, sig)
                except ProcessLookupError:
                    return self.process.poll()
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if self.process.poll() is not None:
                        return self.process.returncode
                    time.sleep(0.05)
            if self.process.poll() is None:
                try:
                    os.killpg(pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                return self.process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                return None
        finally:
            if self.process.poll() is not None:
                self.close_logs()


def launch_process(
    command: list[str],
    cwd: Path,
    env: dict[str, str] | None = None,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
) -> ManagedProcess:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    log_files: list[IO[Any]] = []
    stdout_target: int | IO[Any] = subprocess.PIPE
    stderr_target: int | IO[Any] = subprocess.PIPE
    if stdout_path is not None:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_handle = stdout_path.open("ab")
        log_files.append(stdout_handle)
        stdout_target = stdout_handle
    if stderr_path is not None:
        stderr_path.parent.mkdir(parents=True, exist_ok=True)
        stderr_handle = stderr_path.open("ab")
        log_files.append(stderr_handle)
        stderr_target = stderr_handle
    try:
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            env=merged_env,
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=stdout_target,
            stderr=stderr_target,
            start_new_session=True,
        )
    except Exception:
        for handle in log_files:
            handle.close()
        raise
    return ManagedProcess(process=process, command=command, log_files=tuple(log_files))
