from __future__ import annotations

import os

CODEX_EXEC_GIT_TRUST_FLAGS = ["--skip-git-repo-check"]
CODEX_SANDBOX_ENV = "SUPERVISOR_CODEX_SANDBOX"
DEFAULT_SUPERVISED_CODEX_SANDBOX_MODE = "danger-full-access"
DEFAULT_SUPERVISOR_CODEX_SANDBOX_MODE = "danger-full-access"


def codex_exec_sandbox_flags(default: str = DEFAULT_SUPERVISED_CODEX_SANDBOX_MODE) -> list[str]:
    return ["--sandbox", os.environ.get(CODEX_SANDBOX_ENV, default)]
