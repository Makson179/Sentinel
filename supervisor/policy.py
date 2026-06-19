from __future__ import annotations

import fnmatch
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any, Iterable

from supervisor.schemas import PolicyDecision


SECRET_FILE_GLOBS = {
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "id_ed25519*",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    "service-account*.json",
}

SECRET_NAME_PARTS = {
    "secret",
    "credential",
    "password",
    "passwd",
    "token",
    "apikey",
    "api_key",
    "private",
    "vault",
}

SECRET_PATH_PARTS = {
    ".git",
    ".ssh",
    ".aws",
    ".kube",
}

SECRET_PATH_SUFFIXES = {
    (".config", "gh"),
    (".config", "gcloud"),
    (".docker", "config.json"),
}

READ_ONLY_TOOLS = {"Read", "Grep", "Glob", "LS", "List", "Search"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
APPLY_PATCH_TOOLS = {"apply_patch", "ApplyPatch"}
READ_ONLY_COMMANDS = {
    "cat",
    "find",
    "git",
    "grep",
    "head",
    "ls",
    "node",
    "npm",
    "pwd",
    "pytest",
    "python",
    "python3",
    "rg",
    "sed",
    "tail",
    "wc",
}
READ_FILE_COMMANDS = {"cat", "head", "sed", "tail", "wc"}
VERSION_FLAGS = {"--version", "-V", "version"}


def _parts_lower(path: Path) -> list[str]:
    return [part.lower() for part in path.parts]


def is_secret_path(path: Path) -> bool:
    parts = _parts_lower(path)
    name = path.name.lower()
    if any(part in SECRET_PATH_PARTS for part in parts):
        return True
    for suffix in SECRET_PATH_SUFFIXES:
        if len(parts) >= len(suffix) and tuple(parts[-len(suffix) :]) == suffix:
            return True
    if any(fragment in name for fragment in SECRET_NAME_PARTS):
        return True
    return any(fnmatch.fnmatch(name, pattern.lower()) for pattern in SECRET_FILE_GLOBS)


def normalize_path(workspace: Path, raw: str | os.PathLike[str]) -> Path | None:
    path = Path(raw)
    if not path.is_absolute():
        path = workspace / path
    parent = path if path.exists() else path.parent
    try:
        resolved_parent = parent.resolve(strict=True)
    except FileNotFoundError:
        try:
            resolved_parent = parent.resolve(strict=False)
        except OSError:
            return None
    resolved = resolved_parent if path.exists() else resolved_parent / path.name
    try:
        resolved.relative_to(workspace.resolve())
    except ValueError:
        return None
    return resolved


def extract_paths(payload: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    for key in ("path", "file_path", "filepath", "cwd", "directory"):
        value = payload.get(key)
        if isinstance(value, str):
            candidates.append(value)
    for key in ("paths", "files"):
        value = payload.get(key)
        if isinstance(value, list):
            candidates.extend(item for item in value if isinstance(item, str))
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict):
        candidates.extend(extract_paths(tool_input))
    return candidates


def resolve_all_paths(workspace: Path, raw_paths: Iterable[str]) -> tuple[list[Path], str | None]:
    resolved: list[Path] = []
    for raw in raw_paths:
        path = normalize_path(workspace, raw)
        if path is None:
            return [], f"path escapes workspace or is ambiguous: {raw}"
        resolved.append(path)
    return resolved, None


def _git_read_only(args: list[str]) -> bool:
    if not args:
        return False
    subcommand = args[0]
    if subcommand not in {"status", "log", "diff"}:
        return False
    destructive_or_network = {"push", "fetch", "pull", "reset", "clean", "checkout", "switch"}
    return not any(arg in destructive_or_network for arg in args)


def parse_command(command: str) -> tuple[list[str] | None, str | None]:
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        return None, f"cannot parse shell command: {exc}"
    if not tokens:
        return None, "empty command"
    shell_meta = {"|", "&&", "||", ";", ">", ">>", "<", "$(", "`"}
    if any(token in shell_meta or "$(" in token or "`" in token for token in tokens):
        return tokens, "shell metacharacters require LLM review"
    return tokens, None


def extract_apply_patch_paths(command: str) -> list[str] | None:
    if "*** Begin Patch" not in command:
        return None
    paths: list[str] = []
    prefixes = (
        "*** Add File: ",
        "*** Update File: ",
        "*** Delete File: ",
        "*** Move to: ",
    )
    for line in command.splitlines():
        for prefix in prefixes:
            if line.startswith(prefix):
                value = line[len(prefix) :].strip()
                if value:
                    paths.append(value)
    return paths


def _looks_like_path_argument(token: str, workspace: Path) -> bool:
    if token in {"-", "--"} or token.startswith("-"):
        return False
    if token.startswith(("http://", "https://")):
        return False
    path = Path(token)
    return path.is_absolute() or "/" in token or "." in token or (workspace / token).exists()


def _sed_read_paths(args: list[str], workspace: Path) -> tuple[list[str], str | None]:
    if any(arg == "-i" or arg.startswith("-i") or arg == "--in-place" for arg in args):
        return [], "sed in-place edit requires LLM review"
    candidates: list[str] = []
    script_seen = False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"-e", "--expression"}:
            script_seen = True
            index += 2
            continue
        if arg in {"-f", "--file"}:
            if index + 1 < len(args):
                candidates.append(args[index + 1])
            script_seen = True
            index += 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        if not script_seen:
            script_seen = True
            index += 1
            continue
        if _looks_like_path_argument(arg, workspace):
            candidates.append(arg)
        index += 1
    return candidates, None


def extract_read_command_paths(tokens: list[str], workspace: Path) -> tuple[list[str], str | None]:
    if not tokens or tokens[0] not in READ_FILE_COMMANDS:
        return [], None
    if tokens[0] == "sed":
        return _sed_read_paths(tokens[1:], workspace)
    candidates: list[str] = []
    skip_next = False
    options_with_values = {"-n", "--lines", "-c", "--bytes"}
    for arg in tokens[1:]:
        if skip_next:
            skip_next = False
            continue
        if arg in options_with_values:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        if _looks_like_path_argument(arg, workspace):
            candidates.append(arg)
    return candidates, None


def is_remote_execution_pipeline(command: str) -> bool:
    lowered = command.lower()
    download = ("curl " in lowered or lowered.startswith("curl ") or "wget " in lowered or lowered.startswith("wget "))
    shell = "| bash" in lowered or "| sh" in lowered or "| zsh" in lowered
    return download and shell


def is_force_push_protected(tokens: list[str]) -> bool:
    if not tokens or tokens[0] != "git" or "push" not in tokens:
        return False
    if "--force" not in tokens and "-f" not in tokens and "--force-with-lease" not in tokens:
        return False
    protected = {"main", "master", "prod", "production"}
    for token in tokens:
        if token in protected or token.startswith("release/"):
            return True
    return False


def is_broad_chmod(tokens: list[str], workspace: Path) -> bool:
    if not tokens or tokens[0] != "chmod":
        return False
    if "777" in tokens:
        return True
    if "-R" not in tokens and "--recursive" not in tokens:
        return False
    for token in tokens[1:]:
        if token.startswith("-") or token.isdigit():
            continue
        path = normalize_path(workspace, token)
        if path is None:
            return True
        if not any(part in {"build", "dist", ".cache", "node_modules", "__pycache__"} for part in path.parts):
            return True
    return False


def is_recursive_delete_outside(tokens: list[str], workspace: Path) -> bool:
    if not tokens or tokens[0] != "rm":
        return False
    recursive = any("r" in token for token in tokens[1:] if token.startswith("-"))
    if not recursive:
        return False
    for token in tokens[1:]:
        if token.startswith("-"):
            continue
        if normalize_path(workspace, token) is None:
            return True
        normalized = normalize_path(workspace, token)
        if normalized is not None and normalized == workspace.resolve().parent:
            return True
    return False


def recursive_delete_targets(tokens: list[str]) -> list[str]:
    if not tokens or tokens[0] != "rm":
        return []
    recursive = any("r" in token for token in tokens[1:] if token.startswith("-"))
    force = any("f" in token for token in tokens[1:] if token.startswith("-"))
    if not recursive and not force:
        return []
    return [token for token in tokens[1:] if token and not token.startswith("-")]


def tracked_delete_problem(tokens: list[str], workspace: Path) -> str | None:
    targets = recursive_delete_targets(tokens)
    if not targets:
        return None
    tracked: list[str] = []
    root = workspace.resolve()
    for raw in targets:
        path = normalize_path(root, raw)
        if path is None:
            continue
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        rel_text = str(rel)
        if _git_path_is_tracked_or_contains_tracked(root, rel_text, is_dir=path.is_dir()):
            tracked.append(rel_text)
    if not tracked:
        return None
    return "recursive delete touches git-tracked path(s): " + ", ".join(tracked[:8])


def _git_path_is_tracked_or_contains_tracked(workspace: Path, rel_path: str, *, is_dir: bool) -> bool:
    try:
        if is_dir:
            completed = subprocess.run(
                ["git", "ls-files", "--", rel_path.rstrip("/") + "/"],
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            return bool(completed.stdout.strip())
        completed = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", rel_path],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        return completed.returncode == 0
    except Exception:
        return False


def command_mentions_supervisor(command: str) -> bool:
    return "supervisor" in command.lower()


class PolicyEngine:
    def __init__(self, workspace: Path):
        self.workspace = workspace.resolve()

    def evaluate(self, payload: dict[str, Any]) -> PolicyDecision:
        command = payload.get("command")
        tool_name = payload.get("tool_name")
        operation = payload.get("operation")

        raw_paths = extract_paths(payload)
        paths, path_problem = resolve_all_paths(self.workspace, raw_paths)
        if path_problem and raw_paths:
            return PolicyDecision.route_llm(path_problem)

        if any(is_secret_path(path) for path in paths):
            if operation == "write" or tool_name in WRITE_TOOLS:
                return PolicyDecision.deny("writes to secret-pattern paths are denied")
            return PolicyDecision.route_llm("secret-pattern read requires LLM judgment")

        if isinstance(tool_name, str) and tool_name in APPLY_PATCH_TOOLS:
            patch_text = command if isinstance(command, str) else payload.get("patch")
            if not isinstance(patch_text, str):
                return PolicyDecision.route_llm("apply_patch input missing patch text")
            return self._evaluate_apply_patch(patch_text)

        if isinstance(command, str):
            return self._evaluate_command(command, paths)

        if isinstance(tool_name, str):
            if tool_name in WRITE_TOOLS:
                if any(is_secret_path(path) for path in paths):
                    return PolicyDecision.deny("write to secret-pattern path")
                if paths:
                    return PolicyDecision.allow("workspace write tool inside workspace")
                return PolicyDecision.route_llm("write tool did not provide a workspace path")
            if tool_name in READ_ONLY_TOOLS and not path_problem:
                return PolicyDecision.allow("read-only tool inside workspace")
            return PolicyDecision.route_llm("unknown tool requires LLM judgment")

        if operation == "read" and not path_problem:
            return PolicyDecision.allow("read operation inside workspace")
        if operation == "write" and any(is_secret_path(path) for path in paths):
            return PolicyDecision.deny("write to secret-pattern path")
        return PolicyDecision.route_llm("unclassified event requires LLM judgment")

    def _evaluate_command(self, command: str, paths: list[Path]) -> PolicyDecision:
        if command_mentions_supervisor(command):
            return PolicyDecision.deny("commands containing supervisor are denied")
        patch_paths = extract_apply_patch_paths(command)
        if patch_paths is not None:
            return self._evaluate_patch_paths(patch_paths)
        if is_remote_execution_pipeline(command):
            return PolicyDecision.deny("remote code execution pipeline denied")
        tokens, problem = parse_command(command)
        if tokens is None:
            return PolicyDecision.route_llm(problem or "unparsed command")
        if is_force_push_protected(tokens):
            return PolicyDecision.deny("force push to protected branch denied")
        if is_broad_chmod(tokens, self.workspace):
            return PolicyDecision.deny("broad permission change denied")
        tracked_problem = tracked_delete_problem(tokens, self.workspace)
        if tracked_problem:
            return PolicyDecision.deny(tracked_problem)
        if is_recursive_delete_outside(tokens, self.workspace):
            return PolicyDecision.deny("recursive deletion outside workspace denied")
        if problem:
            return PolicyDecision.route_llm(problem)

        cmd = tokens[0]
        if cmd == "git" and _git_read_only(tokens[1:]):
            return PolicyDecision.allow("read-only git command")
        if cmd in {"python", "python3", "node", "pytest", "npm"} and any(flag in tokens[1:] for flag in VERSION_FLAGS):
            return PolicyDecision.allow("version check")
        if cmd in {"ls", "pwd"}:
            return PolicyDecision.allow("informational shell command")
        if cmd == "find":
            return PolicyDecision.allow("bounded find inside workspace")
        if cmd in READ_FILE_COMMANDS:
            raw_paths, read_problem = extract_read_command_paths(tokens, self.workspace)
            if read_problem:
                return PolicyDecision.route_llm(read_problem)
            resolved, path_problem = resolve_all_paths(self.workspace, raw_paths)
            if path_problem:
                return PolicyDecision.route_llm(path_problem)
            if not resolved:
                return PolicyDecision.route_llm("read command path could not be determined")
            if any(is_secret_path(path) for path in resolved):
                return PolicyDecision.route_llm("secret-pattern read requires LLM judgment")
            return PolicyDecision.allow("read-only command inside workspace")
        if cmd in READ_ONLY_COMMANDS and paths:
            return PolicyDecision.allow("read-only command inside workspace")
        return PolicyDecision.route_llm("command is not in deterministic allow list")

    def _evaluate_apply_patch(self, command: str) -> PolicyDecision:
        patch_paths = extract_apply_patch_paths(command)
        if patch_paths is None:
            return PolicyDecision.route_llm("apply_patch input is not a patch")
        return self._evaluate_patch_paths(patch_paths)

    def _evaluate_patch_paths(self, raw_paths: list[str]) -> PolicyDecision:
        if not raw_paths:
            return PolicyDecision.route_llm("patch paths could not be determined")
        paths, path_problem = resolve_all_paths(self.workspace, raw_paths)
        if path_problem:
            return PolicyDecision.route_llm(path_problem)
        if any(is_secret_path(path) for path in paths):
            return PolicyDecision.deny("writes to secret-pattern paths are denied")
        return PolicyDecision.allow("workspace patch inside workspace")
