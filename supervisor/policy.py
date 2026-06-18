from __future__ import annotations

import fnmatch
import os
import shlex
from pathlib import Path
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict, Field

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
CHEAP_REVIEW_READ_ONLY_COMMANDS = {
    "cat",
    "find",
    "git",
    "grep",
    "head",
    "ls",
    "pwd",
    "rg",
    "sed",
    "sort",
    "tail",
    "uniq",
    "wc",
}
VERSION_REPORT_COMMANDS = {"node", "npm", "pytest", "python", "python3"}
SUPPORTED_CHEAP_COMPOSITION_OPERATORS = {"|", "&&"}
FORBIDDEN_CHEAP_RISK_TAGS = {
    "network",
    "shell_redirection",
    "command_substitution",
    "process_substitution",
    "background_execution",
    "unknown_executable",
    "interpreter_execution",
    "git_mutation",
    "filesystem_write",
    "secret_path",
    "workspace_escape",
    "destructive",
    "permission_change",
    "environment_mutation",
    "dependency_mutation",
    "process_or_service_control",
    "external_side_effect",
    "deploy_publish_release",
    "ambiguous_parse",
}
SHELL_PUNCTUATION = "|&;()<>"
SHELL_OPERATORS = {"|", "&&", "||", ";", "&"}
SHELL_REDIRECT_OPERATORS = {">", ">>", "<", "<<", "<<<", "<>", ">|", "&>", "2>", "2>>"}
NETWORK_COMMANDS = {"curl", "wget"}
SHELL_COMMANDS = {"bash", "fish", "sh", "zsh"}
DESTRUCTIVE_COMMANDS = {"rm", "rmdir", "unlink"}
PERMISSION_COMMANDS = {"chmod", "chown", "chgrp", "sudo"}
PROCESS_CONTROL_COMMANDS = {"kill", "killall", "pkill", "service", "systemctl", "supervisorctl"}
DEPLOY_COMMANDS = {"deploy", "publish", "release"}
DEPENDENCY_MUTATION_COMMANDS = {"pip", "pip3", "yarn", "pnpm"}


class ParsedCommandSegment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    executable: str
    args: list[str] = Field(default_factory=list)
    tokens: list[str] = Field(default_factory=list)
    raw_paths: list[str] = Field(default_factory=list)
    resolved_paths: list[str] = Field(default_factory=list)
    read_only: bool = False


class CommandAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str
    cwd: str | None = None
    tokens: list[str] = Field(default_factory=list)
    segments: list[ParsedCommandSegment] = Field(default_factory=list)
    operators: list[str] = Field(default_factory=list)
    resolved_paths: list[str] = Field(default_factory=list)
    risk_tags: set[str] = Field(default_factory=set)
    parse_error: str | None = None
    cheap_review_candidate: bool = False

    def policy_payload(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        data["risk_tags"] = sorted(self.risk_tags)
        return data


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


def normalize_path_from_cwd(workspace: Path, cwd: Path, raw: str | os.PathLike[str]) -> Path | None:
    path = Path(raw)
    if not path.is_absolute():
        path = cwd / path
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


def _workspace_relative(workspace: Path, path: Path) -> str:
    try:
        return path.relative_to(workspace.resolve()).as_posix()
    except ValueError:
        return str(path)


def _command_working_directory(workspace: Path, cwd: str | None) -> tuple[Path, set[str], str | None]:
    if cwd is None:
        return workspace.resolve(), set(), None
    resolved = normalize_path(workspace, cwd)
    if resolved is None:
        return workspace.resolve(), {"workspace_escape"}, "command working directory escapes workspace or is ambiguous"
    if is_secret_path(resolved):
        return resolved, {"secret_path"}, None
    return resolved, set(), None


def _lex_shell_command(command: str) -> tuple[list[str] | None, str | None]:
    if "\n" in command or "\r" in command:
        return None, "multiline shell command requires supervisor judgment"
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=SHELL_PUNCTUATION)
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer), None
    except ValueError as exc:
        return None, f"cannot parse shell command: {exc}"


def _initial_risk_tags(command: str) -> set[str]:
    tags: set[str] = set()
    if "$(" in command or "`" in command:
        tags.add("command_substitution")
    if "<(" in command or ">(" in command:
        tags.add("process_substitution")
    return tags


def _split_command_segments(tokens: list[str]) -> tuple[list[list[str]], list[str], set[str], str | None]:
    segments: list[list[str]] = []
    operators: list[str] = []
    current: list[str] = []
    tags: set[str] = set()
    parse_error: str | None = None

    for token in tokens:
        if token in SHELL_REDIRECT_OPERATORS or any(char in token for char in (">", "<")):
            tags.add("shell_redirection")
            parse_error = parse_error or "shell redirection requires supervisor judgment"
            continue
        if token in {"(", ")"}:
            tags.add("ambiguous_parse")
            parse_error = parse_error or "shell grouping requires supervisor judgment"
            continue
        if token in SHELL_OPERATORS:
            if token == "&":
                tags.add("background_execution")
                parse_error = parse_error or "background execution requires supervisor judgment"
            elif token not in SUPPORTED_CHEAP_COMPOSITION_OPERATORS:
                tags.add("ambiguous_parse")
                parse_error = parse_error or "unsupported shell composition requires supervisor judgment"
            if current:
                segments.append(current)
                current = []
            else:
                tags.add("ambiguous_parse")
                parse_error = parse_error or "empty command segment requires supervisor judgment"
            operators.append(token)
            continue
        current.append(token)

    if current:
        segments.append(current)
    elif operators:
        tags.add("ambiguous_parse")
        parse_error = parse_error or "trailing shell operator requires supervisor judgment"
    return segments, operators, tags, parse_error


def _resolve_segment_paths(
    workspace: Path,
    cwd: Path,
    raw_paths: Iterable[str],
    tags: set[str],
) -> list[str]:
    resolved_paths: list[str] = []
    for raw in raw_paths:
        resolved = normalize_path_from_cwd(workspace, cwd, raw)
        if resolved is None:
            tags.add("workspace_escape")
            continue
        if is_secret_path(resolved):
            tags.add("secret_path")
        resolved_paths.append(_workspace_relative(workspace, resolved))
    return resolved_paths


def _plain_path_args(args: list[str]) -> list[str]:
    return [arg for arg in args if arg not in {"-", "--"} and not arg.startswith("-")]


def _find_paths_and_bounds(args: list[str]) -> tuple[list[str], bool]:
    paths: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg.startswith("-") or arg in {"(", "!", ")"}:
            break
        paths.append(arg)
        index += 1
    if not paths:
        paths.append(".")
    bounded = False
    for index, arg in enumerate(args):
        if arg == "-maxdepth" and index + 1 < len(args):
            try:
                bounded = int(args[index + 1]) >= 0
            except ValueError:
                bounded = False
            break
    return paths, bounded


def _grep_like_paths(args: list[str], cwd: Path) -> tuple[list[str], bool]:
    paths: list[str] = []
    pattern_seen = False
    explicit_secret_search = False
    options_with_values = {
        "-A",
        "-B",
        "-C",
        "-e",
        "-f",
        "-g",
        "-m",
        "--after-context",
        "--before-context",
        "--context",
        "--file",
        "--glob",
        "--max-count",
        "--regexp",
    }
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"--hidden", "--no-ignore"}:
            explicit_secret_search = True
            index += 1
            continue
        if arg in options_with_values:
            index += 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        if not pattern_seen:
            pattern_seen = True
            index += 1
            continue
        if _looks_like_path_argument(arg, cwd):
            paths.append(arg)
        index += 1
    return paths, explicit_secret_search


def _version_report_only(args: list[str]) -> bool:
    return bool(args) and all(arg in VERSION_FLAGS for arg in args)


def _git_path_args(args: list[str]) -> list[str]:
    if not args:
        return []
    path_args: list[str] = []
    after_separator = False
    for arg in args[1:]:
        if arg == "--":
            after_separator = True
            continue
        if after_separator and not arg.startswith("-"):
            path_args.append(arg)
    return path_args


def _classify_segment(
    segment_tokens: list[str],
    *,
    workspace: Path,
    cwd: Path,
    receives_stdin: bool,
) -> tuple[ParsedCommandSegment, set[str]]:
    executable = segment_tokens[0] if segment_tokens else ""
    args = segment_tokens[1:]
    tags: set[str] = set()
    raw_paths: list[str] = []
    read_only = False

    if not executable:
        tags.add("ambiguous_parse")
    elif executable in NETWORK_COMMANDS or any(arg.startswith(("http://", "https://")) for arg in args):
        tags.add("network")
        tags.add("external_side_effect")
    elif executable in SHELL_COMMANDS:
        tags.add("interpreter_execution")
    elif executable in DESTRUCTIVE_COMMANDS:
        tags.add("destructive")
        tags.add("filesystem_write")
    elif executable in PERMISSION_COMMANDS:
        tags.add("permission_change")
    elif executable in PROCESS_CONTROL_COMMANDS:
        tags.add("process_or_service_control")
    elif executable in DEPLOY_COMMANDS or executable in {"npm"} and any(arg in {"publish", "release"} for arg in args):
        tags.add("deploy_publish_release")
        tags.add("external_side_effect")
    elif executable in DEPENDENCY_MUTATION_COMMANDS or executable == "npm" and any(
        arg in {"add", "ci", "install", "link", "remove", "uninstall", "update"} for arg in args
    ):
        tags.add("dependency_mutation")
        tags.add("filesystem_write")
        tags.add("external_side_effect")
    elif executable == "git":
        if _git_read_only(args):
            read_only = True
            raw_paths = _git_path_args(args)
        else:
            tags.add("git_mutation")
            if any(arg in {"fetch", "pull", "push"} for arg in args):
                tags.add("network")
                tags.add("external_side_effect")
    elif executable in {"ls"}:
        read_only = True
        raw_paths = _plain_path_args(args)
    elif executable == "pwd":
        read_only = not args
        if args:
            tags.add("ambiguous_parse")
    elif executable == "find":
        raw_paths, bounded = _find_paths_and_bounds(args)
        read_only = True
        if not bounded:
            tags.add("ambiguous_parse")
    elif executable in {"rg", "grep"}:
        raw_paths, explicit_secret_search = _grep_like_paths(args, cwd)
        read_only = True
        if explicit_secret_search:
            tags.add("secret_path")
        if not raw_paths and not receives_stdin:
            tags.add("ambiguous_parse")
    elif executable in READ_FILE_COMMANDS:
        raw_paths, read_problem = extract_read_command_paths(segment_tokens, cwd)
        if read_problem:
            tags.add("filesystem_write")
        if raw_paths or receives_stdin:
            read_only = read_problem is None
        else:
            tags.add("ambiguous_parse")
    elif executable in {"sort", "uniq"}:
        raw_paths = _plain_path_args(args)
        if raw_paths or receives_stdin:
            read_only = True
        else:
            tags.add("ambiguous_parse")
    elif executable in VERSION_REPORT_COMMANDS:
        if _version_report_only(args):
            read_only = True
        else:
            tags.add("interpreter_execution")
            if executable == "npm":
                tags.add("dependency_mutation")
    else:
        if "=" in executable:
            tags.add("environment_mutation")
        tags.add("unknown_executable")

    resolved_paths = _resolve_segment_paths(workspace, cwd, raw_paths, tags)
    return (
        ParsedCommandSegment(
            executable=executable,
            args=list(args),
            tokens=list(segment_tokens),
            raw_paths=list(raw_paths),
            resolved_paths=resolved_paths,
            read_only=read_only and not (tags & FORBIDDEN_CHEAP_RISK_TAGS),
        ),
        tags,
    )


def analyze_command(workspace: Path, command: str, cwd: str | None = None) -> CommandAnalysis:
    workspace = workspace.resolve()
    cwd_path, cwd_tags, cwd_problem = _command_working_directory(workspace, cwd)
    tokens, lex_problem = _lex_shell_command(command)
    risk_tags = _initial_risk_tags(command) | cwd_tags
    segments: list[ParsedCommandSegment] = []
    operators: list[str] = []
    parse_error = cwd_problem or lex_problem

    if tokens is None:
        risk_tags.add("ambiguous_parse")
        return CommandAnalysis(
            command=command,
            cwd=cwd,
            tokens=[],
            segments=[],
            operators=[],
            resolved_paths=[],
            risk_tags=risk_tags,
            parse_error=parse_error,
            cheap_review_candidate=False,
        )

    raw_segments, operators, split_tags, split_problem = _split_command_segments(tokens)
    risk_tags |= split_tags
    parse_error = parse_error or split_problem
    for index, raw_segment in enumerate(raw_segments):
        segment, segment_tags = _classify_segment(
            raw_segment,
            workspace=workspace,
            cwd=cwd_path,
            receives_stdin=index > 0 and operators[index - 1] == "|",
        )
        segments.append(segment)
        risk_tags |= segment_tags

    resolved_paths: list[str] = []
    for segment in segments:
        resolved_paths.extend(segment.resolved_paths)
    cheap_review_candidate = (
        parse_error is None
        and bool(segments)
        and all(segment.read_only for segment in segments)
        and all(segment.executable in CHEAP_REVIEW_READ_ONLY_COMMANDS or segment.executable in VERSION_REPORT_COMMANDS for segment in segments)
        and all(operator in SUPPORTED_CHEAP_COMPOSITION_OPERATORS for operator in operators)
        and not (risk_tags & FORBIDDEN_CHEAP_RISK_TAGS)
    )
    return CommandAnalysis(
        command=command,
        cwd=cwd,
        tokens=tokens,
        segments=segments,
        operators=operators,
        resolved_paths=resolved_paths,
        risk_tags=risk_tags,
        parse_error=parse_error,
        cheap_review_candidate=cheap_review_candidate,
    )


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
            return self._evaluate_command(command, paths, cwd=payload.get("cwd") if isinstance(payload.get("cwd"), str) else None)

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

    def _evaluate_command(self, command: str, paths: list[Path], *, cwd: str | None = None) -> PolicyDecision:
        analysis = analyze_command(self.workspace, command, cwd)
        analysis_payload = analysis.policy_payload()
        payload = {
            "command_analysis": analysis_payload,
            "risk_tags": analysis_payload["risk_tags"],
            "parsed_commands": analysis_payload["segments"],
            "resolved_paths": analysis_payload["resolved_paths"],
            "cheap_review_candidate": analysis.cheap_review_candidate,
        }
        if command_mentions_supervisor(command):
            return PolicyDecision.deny("commands containing supervisor are denied", **payload)
        patch_paths = extract_apply_patch_paths(command)
        if patch_paths is not None:
            return self._evaluate_patch_paths(patch_paths)
        if is_remote_execution_pipeline(command):
            return PolicyDecision.deny("remote code execution pipeline denied", **payload)
        tokens, problem = parse_command(command)
        if tokens is None:
            return PolicyDecision.route_llm(problem or "unparsed command", **payload)
        if is_force_push_protected(tokens):
            return PolicyDecision.deny("force push to protected branch denied", **payload)
        if is_broad_chmod(tokens, self.workspace):
            return PolicyDecision.deny("broad permission change denied", **payload)
        if is_recursive_delete_outside(tokens, self.workspace):
            return PolicyDecision.deny("recursive deletion outside workspace denied", **payload)
        if problem:
            return PolicyDecision.route_llm(problem, **payload)

        cmd = tokens[0]
        if cmd == "git" and _git_read_only(tokens[1:]):
            return PolicyDecision.allow("read-only git command", **payload)
        if cmd in {"python", "python3", "node", "pytest", "npm"} and any(flag in tokens[1:] for flag in VERSION_FLAGS):
            return PolicyDecision.allow("version check", **payload)
        if cmd in {"ls", "pwd"}:
            return PolicyDecision.allow("informational shell command", **payload)
        if cmd == "find":
            return PolicyDecision.allow("bounded find inside workspace", **payload)
        if cmd in READ_FILE_COMMANDS:
            raw_paths, read_problem = extract_read_command_paths(tokens, self.workspace)
            if read_problem:
                return PolicyDecision.route_llm(read_problem, **payload)
            resolved, path_problem = resolve_all_paths(self.workspace, raw_paths)
            if path_problem:
                return PolicyDecision.route_llm(path_problem, **payload)
            if not resolved:
                return PolicyDecision.route_llm("read command path could not be determined", **payload)
            if any(is_secret_path(path) for path in resolved):
                return PolicyDecision.route_llm("secret-pattern read requires LLM judgment", **payload)
            return PolicyDecision.allow("read-only command inside workspace", **payload)
        if cmd in READ_ONLY_COMMANDS and cmd not in VERSION_REPORT_COMMANDS and paths:
            return PolicyDecision.allow("read-only command inside workspace", **payload)
        return PolicyDecision.route_llm("command is not in deterministic allow list", **payload)

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
