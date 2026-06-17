#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import shlex
import sys
import tarfile
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PREPARE_WORKSPACE_CODE = r"""
from __future__ import annotations

import json
import os
import shutil
import shlex
import stat
import sys
from pathlib import Path
from typing import Any


def main() -> int:
    specbench_dir = Path(sys.argv[1]).resolve()
    task_id = sys.argv[2]
    workspace = Path(sys.argv[3]).resolve()
    difficulty_level = int(sys.argv[4])
    visible_test_python = Path(sys.argv[5]).expanduser()
    sys.path.insert(0, str(specbench_dir))

    from benchmarks.base import TaskSpec
    from benchmarks.spec_bench.adapter import SpecBenchAdapter, _TASK_REGISTRY

    if task_id not in _TASK_REGISTRY:
        raise SystemExit(f"unknown SpecBench task: {task_id}")

    workspace.mkdir(parents=True, exist_ok=True)
    if any(workspace.iterdir()):
        raise SystemExit(f"workspace already exists and is not empty: {workspace}")

    adapter = SpecBenchAdapter(
        python_executable=sys.executable,
        difficulty_level=difficulty_level,
    )
    task = TaskSpec(id=task_id)
    task_def = adapter._get_task(task_id)

    starter_files = sorted(task_def.starter_code)
    for filename, content in task_def.starter_code.items():
        write_workspace_file(workspace, filename, content)

    visible_files = copy_visible_tests(adapter, task_def, workspace)
    visible_files.extend(copy_visible_resources(task_def, workspace))
    task_text = compose_task_text(adapter.get_task_prompt(task), task_def)
    (workspace / "TASK.md").write_text(task_text, encoding="utf-8")
    write_visible_test_runner(workspace, visible_test_python)

    info = {
        "task_id": task_id,
        "display_name": getattr(task_def, "display_name", task_id),
        "language": getattr(task_def, "language", None),
        "entry_point": getattr(task_def, "entry_point", None),
        "difficulty_level": difficulty_level,
        "visible_test_python": str(visible_test_python),
        "visible_test_command": f"{visible_test_python} -m pytest tests/public -v --tb=short",
        "starter_files": starter_files,
        "visible_test_files": sorted(set(visible_files)),
        "agent_workspace_contains": [
            "starter code",
            "TASK.md",
            "visible public tests",
            "visible public-test fixtures copied without reference/private/id_private directories",
        ],
    }
    (workspace / "specbench_task_info.json").write_text(
        json.dumps(info, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


def safe_relative(path_text: str) -> Path:
    path = Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        raise SystemExit(f"unsafe starter file path from SpecBench task: {path_text!r}")
    return path


def write_workspace_file(workspace: Path, filename: str, content: str) -> None:
    path = workspace / safe_relative(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def copy_visible_tests(adapter: Any, task_def: Any, workspace: Path) -> list[str]:
    visible_files: list[str] = []
    source_tests_root = Path(task_def.public_test_dir).parent
    public_source = Path(adapter._get_effective_public_test_dir(task_def))
    public_dest = workspace / "tests" / "public"
    if public_source.exists():
        shutil.copytree(public_source, public_dest, dirs_exist_ok=True)
        visible_files.extend(relative_files(workspace, public_dest))

    for child in source_tests_root.iterdir():
        if child.name in {"private", "id_private", "gradient", "public", "__pycache__"}:
            continue
        dest = workspace / "tests" / child.name
        if child.is_file():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(child, dest)
            visible_files.append(str(dest.relative_to(workspace)))

    return visible_files


def copy_visible_resources(task_def: Any, workspace: Path) -> list[str]:
    copied: list[str] = []
    task_root = Path(task_def.public_test_dir).parents[1]
    visible_resource_names = {"vectors", "fixtures", "data", "testdata", "assets", "samples"}
    for name in visible_resource_names:
        source = task_root / name
        if not source.exists():
            continue
        dest = workspace / name
        if source.is_dir():
            shutil.copytree(source, dest, dirs_exist_ok=True)
            copied.extend(relative_files(workspace, dest))
        elif source.is_file():
            shutil.copy2(source, dest)
            copied.append(str(dest.relative_to(workspace)))
    return copied


def relative_files(root: Path, base: Path) -> list[str]:
    return [str(path.relative_to(root)) for path in base.rglob("*") if path.is_file()]


def compose_task_text(prompt: str, task_def: Any) -> str:
    display = getattr(task_def, "display_name", getattr(task_def, "task_id", "SpecBench task"))
    task_id = getattr(task_def, "task_id", "unknown")
    return (
        f"# SpecBench Task: {display}\n\n"
        f"- task_id: `{task_id}`\n"
        f"- language: `{getattr(task_def, 'language', 'unknown')}`\n"
        f"- entry point: `{getattr(task_def, 'entry_point', 'unknown')}`\n\n"
        f"{prompt.rstrip()}\n\n"
        "## Workspace\n\n"
        "Starter files are already in this directory. Visible validation tests are under "
        "`tests/public`. Do not modify tests or benchmark metadata; implement the task in "
        "the starter/source files.\n"
    )


def write_visible_test_runner(workspace: Path, visible_test_python: Path) -> None:
    script = workspace / "run_visible_tests.sh"
    script.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"{shlex.quote(str(visible_test_python))} -m pytest tests/public -v --tb=short\n",
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


if __name__ == "__main__":
    raise SystemExit(main())
"""


SCORE_WORKSPACE_CODE = r"""
from __future__ import annotations

import json
import os
import site
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def main() -> int:
    specbench_dir = Path(sys.argv[1]).resolve()
    task_id = sys.argv[2]
    workspace = Path(sys.argv[3]).resolve()
    out_dir = Path(sys.argv[4]).resolve()
    difficulty_level = int(sys.argv[5])
    test_timeout = int(sys.argv[6])
    test_python = Path(sys.argv[7]).expanduser()
    sys.path.insert(0, str(specbench_dir))

    from benchmarks.spec_bench.adapter import SpecBenchAdapter, _TASK_REGISTRY
    from benchmarks.spec_bench.evaluation.runner import TestResult

    if task_id not in _TASK_REGISTRY:
        raise SystemExit(f"unknown SpecBench task: {task_id}")
    if not pytest_available(test_python):
        raise SystemExit(f"test Python cannot run pytest: {test_python}")

    augment_pythonpath(specbench_dir)
    timeout_plugin_available = pytest_timeout_plugin_available(test_python)
    out_dir.mkdir(parents=True, exist_ok=True)
    adapter = SpecBenchAdapter(
        python_executable=str(test_python),
        test_timeout=test_timeout,
        difficulty_level=difficulty_level,
    )
    task_def = adapter._get_task(task_id)
    per_test_timeout = getattr(task_def, "timeout_seconds", None)

    suites: list[tuple[str, str, Path | None]] = [
        ("public", "validation", Path(adapter._get_effective_public_test_dir(task_def))),
        ("id_private", "heldout", Path(getattr(task_def, "id_private_test_dir", "")) if getattr(task_def, "id_private_test_dir", None) else None),
        ("private", "heldout", Path(task_def.private_test_dir)),
    ]
    results: dict[str, Any] = {
        "task_id": task_id,
        "workspace": str(workspace),
        "difficulty_level": difficulty_level,
        "test_python": str(test_python),
        "pytest_timeout_plugin_available": timeout_plugin_available,
        "suites": {},
    }
    for suite, kind, test_dir in suites:
        if test_dir is None or not test_dir.exists():
            results["suites"][suite] = {
                "kind": kind,
                "present": False,
                "score": None,
                "log_path": None,
            }
            continue
        result = run_suite(
            adapter=adapter,
            test_dir=test_dir,
            workspace=workspace,
            test_python=test_python,
            suite_timeout=test_timeout,
            per_test_timeout=per_test_timeout,
            timeout_plugin_available=timeout_plugin_available,
            test_result_cls=TestResult,
        )
        log_path = out_dir / f"{suite}.log"
        log_path.write_text(result.output, encoding="utf-8", errors="replace")
        suite_summary = {
            "kind": kind,
            "present": True,
            "score": result.pass_rate,
            "total": result.total,
            "passed": result.passed,
            "failed": result.failed,
            "errors": result.errors,
            "duration_seconds": result.duration_seconds,
            "log_path": str(log_path),
            "individual_results": result.individual_results,
        }
        results["suites"][suite] = suite_summary
        (out_dir / f"{suite}_score.json").write_text(
            json.dumps(suite_summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    public = results["suites"].get("public", {})
    private = results["suites"].get("private", {})
    id_private = results["suites"].get("id_private", {})
    validation_score = {
        "task_id": task_id,
        "suite": "public",
        "score": public.get("score"),
        "total": public.get("total"),
        "passed": public.get("passed"),
        "failed": public.get("failed"),
        "errors": public.get("errors"),
        "log_path": public.get("log_path"),
    }
    heldout_score = {
        "task_id": task_id,
        "primary_suite": "private",
        "private_score": private.get("score"),
        "private_total": private.get("total"),
        "private_passed": private.get("passed"),
        "private_failed": private.get("failed"),
        "private_errors": private.get("errors"),
        "private_log_path": private.get("log_path"),
        "id_private_score": id_private.get("score"),
        "id_private_total": id_private.get("total"),
        "id_private_passed": id_private.get("passed"),
        "id_private_failed": id_private.get("failed"),
        "id_private_errors": id_private.get("errors"),
        "id_private_log_path": id_private.get("log_path"),
    }
    (out_dir / "validation_score.json").write_text(
        json.dumps(validation_score, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "heldout_score.json").write_text(
        json.dumps(heldout_score, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "scoring_summary.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"validation_score": validation_score, "heldout_score": heldout_score}, indent=2, sort_keys=True))
    return 0


def augment_pythonpath(specbench_dir: Path) -> None:
    entries = [str(specbench_dir)]
    for site_dir in site.getsitepackages():
        path = Path(site_dir)
        if path.exists():
            entries.append(str(path))
    existing = os.environ.get("PYTHONPATH")
    if existing:
        entries.extend([part for part in existing.split(os.pathsep) if part])
    os.environ["PYTHONPATH"] = os.pathsep.join(dict.fromkeys(entries))


def pytest_available(test_python: Path) -> bool:
    result = subprocess.run(
        [str(test_python), "-m", "pytest", "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    )
    return result.returncode == 0


def pytest_timeout_plugin_available(test_python: Path) -> bool:
    result = subprocess.run(
        [str(test_python), "-m", "pytest", "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    )
    return result.returncode == 0 and "--timeout" in result.stdout


def run_suite(
    *,
    adapter: Any,
    test_dir: Path,
    workspace: Path,
    test_python: Path,
    suite_timeout: int,
    per_test_timeout: int | None,
    timeout_plugin_available: bool,
    test_result_cls: Any,
) -> Any:
    if timeout_plugin_available:
        return adapter._runner.run_tests_verbose(
            test_dir=test_dir,
            workspace=workspace,
            per_test_timeout=per_test_timeout,
        )
    return run_pytest_without_timeout_plugin(
        adapter=adapter,
        test_dir=test_dir,
        workspace=workspace,
        test_python=test_python,
        suite_timeout=suite_timeout,
        test_result_cls=test_result_cls,
    )


def run_pytest_without_timeout_plugin(
    *,
    adapter: Any,
    test_dir: Path,
    workspace: Path,
    test_python: Path,
    suite_timeout: int,
    test_result_cls: Any,
) -> Any:
    run_env = os.environ.copy()
    pythonpath = str(workspace)
    if "PYTHONPATH" in run_env:
        pythonpath = f"{workspace}{os.pathsep}{run_env['PYTHONPATH']}"
    run_env["PYTHONPATH"] = pythonpath
    cmd = [
        str(test_python),
        "-m",
        "pytest",
        str(test_dir),
        "-v",
        "--tb=line",
        "--no-header",
    ]
    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=suite_timeout,
            cwd=str(workspace),
            env=run_env,
        )
        duration = time.time() - start
        return adapter._runner._parse_pytest_output(result.stdout + "\n" + result.stderr, duration, truncate=50000)
    except subprocess.TimeoutExpired:
        duration = time.time() - start
        return test_result_cls(
            total=0,
            passed=0,
            failed=0,
            errors=0,
            pass_rate=0.0,
            output=f"TIMEOUT: Tests exceeded {suite_timeout}s limit",
            duration_seconds=duration,
        )


if __name__ == "__main__":
    raise SystemExit(main())
"""


@dataclass(frozen=True)
class RunPaths:
    root: Path
    workspace: Path
    artifacts: Path
    rollouts: Path
    scoring: Path
    visible_test_venv: Path
    codex_home: Path


def main() -> int:
    args = parse_args()
    specbench_dir = args.specbench_dir.expanduser().resolve()
    results_root = args.results_root.expanduser().resolve()
    sentinel_src = args.sentinel_src.expanduser().resolve()
    paths = make_paths(results_root)
    if args.visible_test_venv:
        paths = replace(paths, visible_test_venv=args.visible_test_venv.expanduser().resolve())
    if args.codex_home:
        paths = replace(paths, codex_home=args.codex_home.expanduser().resolve())
    for path in [paths.root, paths.artifacts, paths.rollouts, paths.scoring]:
        path.mkdir(parents=True, exist_ok=True)

    command = [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]]
    started = datetime.now(timezone.utc)
    validate_inputs(args, specbench_dir, sentinel_src, paths)
    codex_home_seed = prepare_codex_home(args, paths)
    codex_approval_prefix_clear = clear_codex_approval_prefixes(paths)
    write_json(
        paths.root / "runner-metadata.json",
        {
            "task_id": args.task,
            "command": command,
            "specbench_dir": str(specbench_dir),
            "results_root": str(paths.root),
            "workspace": str(paths.workspace),
            "started_utc": started.isoformat(),
            "difficulty_level": args.difficulty_level,
            "test_timeout": args.test_timeout,
            "test_python": str(resolve_test_python(args)),
            "visible_test_venv": str(paths.visible_test_venv),
            "visible_test_python": str(resolve_visible_test_python(paths.visible_test_venv)),
            "codex_home": str(paths.codex_home),
            "codex_home_seed": codex_home_seed,
            "codex_approval_prefix_clear": codex_approval_prefix_clear,
        },
    )

    visible_test_python = prepare_visible_test_venv(args, paths)
    task_info = prepare_workspace(args, specbench_dir, paths, visible_test_python=visible_test_python)
    write_json(paths.root / "task-info-public.json", task_info)
    initialize_workspace_git(paths.workspace)

    sentinel_rc = run_sentinel(args, paths, sentinel_src)
    ended = datetime.now(timezone.utc)
    capture_attempt_artifacts(paths)
    hidden_check = check_heldout_absent(paths.workspace)

    scoring_rc = score_workspace(args, specbench_dir, paths)
    rollouts = collect_rollouts(paths, workspace_cwd=str(paths.workspace), start_utc=started, end_utc=ended)
    write_json(paths.rollouts / "rollout_collection_summary.json", rollouts)

    write_run_report(
        args=args,
        paths=paths,
        task_info=task_info,
        command=command,
        started=started,
        ended=ended,
        sentinel_rc=sentinel_rc,
        scoring_rc=scoring_rc,
        hidden_check=hidden_check,
        rollouts=rollouts,
    )
    print(f"run_report={paths.root / 'run_report.md'}")
    return 0 if sentinel_rc == 0 and scoring_rc == 0 and not hidden_check["heldout_tests_present"] else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one Sentinel attempt on one SpecBench task.")
    parser.add_argument("--task", required=True, help="SpecBench task_id, e.g. json_parser.")
    parser.add_argument("--specbench-dir", type=Path, required=True, help="Path to the installed SpecBench checkout.")
    parser.add_argument("--results-root", type=Path, required=True, help="Directory for all run outputs.")
    parser.add_argument("--sentinel-src", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--sentinel-bin", type=Path, help="Supervisor CLI to run. Defaults to sentinel-src/.venv/bin/supervisor.")
    parser.add_argument("--model", help="Optional model passed through to the supervisor CLI.")
    parser.add_argument("--difficulty-level", type=int, default=1, help="Visible public-test difficulty level. Default: 1.")
    parser.add_argument("--test-timeout", type=int, default=900, help="SpecBench suite timeout in seconds.")
    parser.add_argument("--test-python", type=Path, help="Python executable used to run pytest for post-run scoring. Defaults to the runner Python.")
    parser.add_argument("--visible-test-venv", type=Path, help="Per-run venv used by run_visible_tests.sh. Defaults to results-root/visible-test-venv.")
    parser.add_argument("--codex-home", type=Path, help="Per-run CODEX_HOME used by Sentinel/Codex. Defaults to results-root/codex-home.")
    parser.add_argument("--codex-source-home", type=Path, help="Existing Codex home used only to seed auth/config into the isolated CODEX_HOME. Defaults to $CODEX_HOME or ~/.codex.")
    parser.add_argument("--pytest-package", default="pytest", help="Package spec installed into the visible-test venv. Default: pytest.")
    parser.add_argument("supervisor_args", nargs=argparse.REMAINDER, help="Extra args after -- are passed to supervisor.")
    args = parser.parse_args()
    if args.supervisor_args and args.supervisor_args[0] == "--":
        args.supervisor_args = args.supervisor_args[1:]
    if args.difficulty_level < 1:
        parser.error("--difficulty-level must be >= 1")
    return args


def make_paths(root: Path) -> RunPaths:
    return RunPaths(
        root=root,
        workspace=root / "workspace",
        artifacts=root / "artifacts",
        rollouts=root / "rollouts",
        scoring=root / "scoring",
        visible_test_venv=root / "visible-test-venv",
        codex_home=root / "codex-home",
    )


def validate_inputs(args: argparse.Namespace, specbench_dir: Path, sentinel_src: Path, paths: RunPaths) -> None:
    specbench_python = resolve_specbench_python(specbench_dir)
    adapter = specbench_dir / "benchmarks" / "spec_bench" / "adapter.py"
    if not specbench_dir.is_dir():
        raise SystemExit(f"SpecBench directory is missing: {specbench_dir}")
    if not specbench_python.exists():
        raise SystemExit(f"SpecBench Python is missing: {specbench_python}")
    if not os.access(specbench_python, os.X_OK):
        raise SystemExit(f"SpecBench Python is not executable: {specbench_python}")
    if not adapter.exists():
        raise SystemExit(f"SpecBench adapter is missing: {adapter}")
    if not (sentinel_src / "pyproject.toml").exists():
        raise SystemExit(f"sentinel source does not look like a Python project: {sentinel_src}")
    sentinel_bin = resolve_sentinel_bin(args, sentinel_src)
    if not sentinel_bin.exists():
        raise SystemExit(f"supervisor CLI is missing: {sentinel_bin}")
    test_python = resolve_test_python(args)
    if not test_python.exists():
        raise SystemExit(f"test Python is missing: {test_python}")
    if not os.access(test_python, os.X_OK):
        raise SystemExit(f"test Python is not executable: {test_python}")
    if paths.workspace.exists() and any(paths.workspace.iterdir()):
        raise SystemExit(f"workspace already exists and is not empty: {paths.workspace}")
    source_codex_home = resolve_codex_source_home(args)
    if paths.codex_home == source_codex_home:
        raise SystemExit("isolated --codex-home must differ from the source Codex home")
    if paths.codex_home.exists():
        if not paths.codex_home.is_dir():
            raise SystemExit(f"isolated Codex home exists and is not a directory: {paths.codex_home}")
        if any(paths.codex_home.iterdir()):
            raise SystemExit(f"isolated Codex home already exists and is not empty: {paths.codex_home}")


def resolve_sentinel_bin(args: argparse.Namespace, sentinel_src: Path) -> Path:
    if args.sentinel_bin:
        return args.sentinel_bin.expanduser().resolve()
    return sentinel_src / ".venv" / "bin" / "supervisor"


def resolve_codex_source_home(args: argparse.Namespace) -> Path:
    if args.codex_source_home:
        return args.codex_source_home.expanduser().resolve()
    env_home = os.environ.get("CODEX_HOME")
    if env_home:
        return Path(env_home).expanduser().resolve()
    return (Path.home() / ".codex").resolve()


def resolve_test_python(args: argparse.Namespace) -> Path:
    if not args.test_python:
        return Path(sys.executable).expanduser().resolve()

    path = args.test_python.expanduser()
    if is_bare_command(path):
        found = shutil.which(str(path))
        if found:
            return Path(found).resolve()
        if str(path) == "python":
            python3 = shutil.which("python3")
            if python3:
                return Path(python3).resolve()

    if path.is_absolute():
        return path
    return Path.cwd() / path


def is_bare_command(path: Path) -> bool:
    return len(path.parts) == 1


def resolve_specbench_python(specbench_dir: Path) -> Path:
    return resolve_venv_python(specbench_dir / ".venv")


def resolve_visible_test_python(visible_test_venv: Path) -> Path:
    return resolve_venv_python(visible_test_venv)


def resolve_venv_python(venv: Path) -> Path:
    python3 = venv / "bin" / "python3"
    python = venv / "bin" / "python"
    if python3.exists():
        return python3
    if python.exists():
        return python
    return python3


def prepare_codex_home(args: argparse.Namespace, paths: RunPaths) -> dict[str, Any]:
    source = resolve_codex_source_home(args)
    destination = paths.codex_home
    seeded: list[str] = []
    skipped: list[str] = []
    destination.mkdir(parents=True, exist_ok=True)

    allowed_files = [
        ".personality_migration",
        "auth.json",
        "config.toml",
        "installation_id",
        "models_cache.json",
    ]
    allowed_dirs = ["skills"]

    if source.exists():
        for name in allowed_files:
            src = source / name
            if src.is_file():
                shutil.copy2(src, destination / name)
                seeded.append(name)
            else:
                skipped.append(name)
        for name in allowed_dirs:
            src = source / name
            if src.is_dir():
                shutil.copytree(src, destination / name, symlinks=True)
                seeded.append(f"{name}/")
            else:
                skipped.append(f"{name}/")
    else:
        skipped.append("source Codex home missing")

    for name in ["sessions", "archived_sessions"]:
        (destination / name).mkdir(parents=True, exist_ok=True)

    metadata = {
        "source": str(source),
        "destination": str(destination),
        "seeded": seeded,
        "skipped": skipped,
        "excluded_state": [
            "sessions/",
            "archived_sessions/",
            "history.jsonl",
            "log/",
            "shell_snapshots/",
            "*.sqlite",
            "*.sqlite-shm",
            "*.sqlite-wal",
            ".tmp/",
            "rules/*.rules",
        ],
    }
    write_json(paths.artifacts / "codex-home-seed.json", metadata)
    return metadata


def clear_codex_approval_prefixes(paths: RunPaths) -> dict[str, Any]:
    rules_dir = paths.codex_home / "rules"
    removed: list[str] = []
    if rules_dir.exists():
        for path in sorted(rules_dir.rglob("*.rules")):
            if path.is_file() or path.is_symlink():
                removed.append(str(path.relative_to(paths.codex_home)))
                path.unlink()
    rules_dir.mkdir(parents=True, exist_ok=True)
    metadata = {
        "rules_dir": str(rules_dir),
        "removed": removed,
    }
    write_json(paths.artifacts / "codex-approval-prefix-clear.json", metadata)
    return metadata


def prepare_visible_test_venv(args: argparse.Namespace, paths: RunPaths) -> Path:
    python_path = resolve_visible_test_python(paths.visible_test_venv)
    if python_path.exists():
        run([str(python_path), "-m", "pytest", "--version"], log_path=paths.artifacts / "visible-test-venv-check.log")
        return python_path

    if paths.visible_test_venv.exists():
        shutil.rmtree(paths.visible_test_venv)
    run([str(resolve_test_python(args)), "-m", "venv", str(paths.visible_test_venv)], log_path=paths.artifacts / "visible-test-venv-create.log")
    python_path = resolve_visible_test_python(paths.visible_test_venv)
    if not python_path.exists():
        raise SystemExit(f"visible-test venv has neither bin/python3 nor bin/python: {paths.visible_test_venv}")
    run([str(python_path), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"], log_path=paths.artifacts / "visible-test-venv-install.log")
    run([str(python_path), "-m", "pip", "install", args.pytest_package], log_path=paths.artifacts / "visible-test-venv-install.log", append=True)
    run([str(python_path), "-m", "pytest", "--version"], log_path=paths.artifacts / "visible-test-venv-check.log")
    return python_path


def prepare_workspace(args: argparse.Namespace, specbench_dir: Path, paths: RunPaths, *, visible_test_python: Path) -> dict[str, Any]:
    cmd = [
        str(resolve_specbench_python(specbench_dir)),
        "-c",
        PREPARE_WORKSPACE_CODE,
        str(specbench_dir),
        args.task,
        str(paths.workspace),
        str(args.difficulty_level),
        str(visible_test_python),
    ]
    result = run_capture(cmd, log_path=paths.artifacts / "prepare-workspace.log")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"failed to parse workspace preparation output; see {paths.artifacts / 'prepare-workspace.log'}") from exc


def initialize_workspace_git(workspace: Path) -> None:
    run(["git", "init"], cwd=workspace, log_path=workspace / ".git-init.log")
    run(["git", "add", "-A"], cwd=workspace, log_path=workspace / ".git-init.log", append=True)
    run(
        [
            "git",
            "-c",
            "user.name=Sentinel SpecBench Runner",
            "-c",
            "user.email=sentinel-specbench-runner@example.invalid",
            "commit",
            "-m",
            "Initial SpecBench starter workspace",
        ],
        cwd=workspace,
        log_path=workspace / ".git-init.log",
        append=True,
    )


def run_sentinel(args: argparse.Namespace, paths: RunPaths, sentinel_src: Path) -> int:
    sentinel_bin = resolve_sentinel_bin(args, sentinel_src)
    task_arg = paths.workspace / "TASK.md"
    cmd = [
        str(sentinel_bin),
        "--task",
        str(task_arg),
        "--start-over",
    ]
    if args.model:
        cmd.extend(["--model", args.model])
    cmd.extend(args.supervisor_args)
    write_json(paths.artifacts / "sentinel-command.json", cmd)
    env = os.environ.copy()
    env["CODEX_HOME"] = str(paths.codex_home)
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(paths.workspace)
        if not existing_pythonpath
        else f"{paths.workspace}{os.pathsep}{existing_pythonpath}"
    )
    start_path = paths.artifacts / "sentinel-start-utc.txt"
    end_path = paths.artifacts / "sentinel-end-utc.txt"
    start_path.write_text(datetime.now(timezone.utc).isoformat() + "\n", encoding="utf-8")
    rc = run_streaming(cmd, cwd=paths.workspace, log_path=paths.artifacts / "sentinel-live.log", env=env)
    end_path.write_text(datetime.now(timezone.utc).isoformat() + "\n", encoding="utf-8")
    (paths.artifacts / "sentinel-exit-code.txt").write_text(f"{rc}\n", encoding="utf-8")
    return rc


def capture_attempt_artifacts(paths: RunPaths) -> None:
    if (paths.workspace / ".supervisor").exists():
        copytree_replace(paths.workspace / ".supervisor", paths.artifacts / ".supervisor")
    run(["git", "status", "--short"], cwd=paths.workspace, log_path=paths.artifacts / "final_git_status.txt")
    run(["git", "add", "-A"], cwd=paths.workspace, log_path=paths.artifacts / "diff-capture.log")
    run(
        ["git", "diff", "--cached", "--binary", "HEAD"],
        cwd=paths.workspace,
        log_path=paths.artifacts / "agent_diff_vs_initial.diff",
    )
    run(
        ["git", "diff", "--cached", "--stat", "HEAD"],
        cwd=paths.workspace,
        log_path=paths.artifacts / "agent_diff_vs_initial.stat",
    )
    run(
        ["git", "diff", "--cached", "--name-only", "HEAD"],
        cwd=paths.workspace,
        log_path=paths.artifacts / "modified_files.txt",
    )
    run(["git", "reset", "--quiet"], cwd=paths.workspace, log_path=paths.artifacts / "diff-capture.log", append=True)
    make_workspace_tar(paths.workspace, paths.artifacts / "final-workspace-no-git-no-supervisor.tar.gz")


def make_workspace_tar(workspace: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dest, "w:gz") as archive:
        for path in workspace.rglob("*"):
            rel = path.relative_to(workspace)
            if rel.parts and rel.parts[0] in {".git", ".supervisor"}:
                continue
            archive.add(path, arcname=str(rel), recursive=False)


def check_heldout_absent(workspace: Path) -> dict[str, Any]:
    hidden_paths = [
        path
        for path in [workspace / "tests" / "private", workspace / "tests" / "id_private"]
        if path.exists()
    ]
    return {
        "heldout_tests_present": bool(hidden_paths),
        "heldout_paths": [str(path) for path in hidden_paths],
        "checked_paths": ["tests/private", "tests/id_private"],
    }


def score_workspace(args: argparse.Namespace, specbench_dir: Path, paths: RunPaths) -> int:
    cmd = [
        str(resolve_specbench_python(specbench_dir)),
        "-c",
        SCORE_WORKSPACE_CODE,
        str(specbench_dir),
        args.task,
        str(paths.workspace),
        str(paths.scoring),
        str(args.difficulty_level),
        str(args.test_timeout),
        str(resolve_test_python(args)),
    ]
    write_json(paths.scoring / "score-command.json", cmd)
    return run_streaming(cmd, log_path=paths.scoring / "score-run.log")


def collect_rollouts(paths: RunPaths, *, workspace_cwd: str, start_utc: datetime, end_utc: datetime) -> dict[str, Any]:
    artifacts_supervisor = paths.artifacts / ".supervisor"
    coder_thread_id = None
    config_path = artifacts_supervisor / "config.json"
    if config_path.exists():
        try:
            coder_thread_id = json.loads(config_path.read_text(encoding="utf-8")).get("coder_thread_id")
        except json.JSONDecodeError:
            coder_thread_id = None

    supervisor_thread_ids: set[str] = set()
    wakes_path = artifacts_supervisor / "supervisor_wakes.jsonl"
    if wakes_path.exists():
        for line in wakes_path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            thread_id = item.get("thread_id")
            if isinstance(thread_id, str):
                supervisor_thread_ids.add(thread_id)

    for bucket in ["coder", "supervisor", "other"]:
        (paths.rollouts / bucket).mkdir(parents=True, exist_ok=True)

    matched: list[dict[str, Any]] = []
    codex_home = paths.codex_home
    rollout_roots = [
        codex_home / "sessions",
        codex_home / "archived_sessions",
    ]
    for rollout_root in rollout_roots:
        if not rollout_root.exists():
            continue
        for path in rollout_root.rglob("*.jsonl"):
            meta = read_rollout_meta(path)
            if not meta or meta.get("cwd") != workspace_cwd:
                continue
            ts = parse_utc(meta.get("timestamp"))
            if ts and (ts < start_utc.replace(tzinfo=timezone.utc) or ts > end_utc.replace(tzinfo=timezone.utc)):
                continue
            rollout_id = meta.get("id")
            if rollout_id and rollout_id == coder_thread_id:
                bucket = "coder"
            elif rollout_id in supervisor_thread_ids:
                bucket = "supervisor"
            else:
                bucket = "other"
            dest = paths.rollouts / bucket / path.name
            if path.resolve() != dest.resolve():
                shutil.copy2(path, dest)
            matched.append({"id": rollout_id, "cwd": meta.get("cwd"), "source": str(path), "bucket": bucket})

    return {
        "workspace_cwd": workspace_cwd,
        "codex_home": str(codex_home),
        "start_utc": start_utc.isoformat(),
        "end_utc": end_utc.isoformat(),
        "coder_thread_id": coder_thread_id,
        "supervisor_thread_ids": sorted(supervisor_thread_ids),
        "matched_count": len(matched),
        "coder_count": sum(1 for item in matched if item["bucket"] == "coder"),
        "supervisor_count": sum(1 for item in matched if item["bucket"] == "supervisor"),
        "other_count": sum(1 for item in matched if item["bucket"] == "other"),
        "matched": matched,
    }


def read_rollout_meta(path: Path) -> dict[str, Any] | None:
    try:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if item.get("type") == "session_meta":
                    payload = item.get("payload") or {}
                    return {
                        "id": payload.get("id"),
                        "cwd": payload.get("cwd"),
                        "timestamp": payload.get("timestamp") or item.get("timestamp"),
                    }
    except OSError:
        return None
    return None


def write_run_report(
    *,
    args: argparse.Namespace,
    paths: RunPaths,
    task_info: dict[str, Any],
    command: list[str],
    started: datetime,
    ended: datetime,
    sentinel_rc: int,
    scoring_rc: int,
    hidden_check: dict[str, Any],
    rollouts: dict[str, Any],
) -> None:
    validation_score = read_json(paths.scoring / "validation_score.json", {})
    heldout_score = read_json(paths.scoring / "heldout_score.json", {})
    scoring_finished = scoring_rc == 0 and bool(validation_score or heldout_score)
    valid_scored_run = sentinel_rc == 0 and scoring_finished and not hidden_check["heldout_tests_present"]
    report = f"""# Sentinel SpecBench Attempt Report

## Task

- task_id: `{args.task}`
- display_name: `{task_info.get('display_name')}`
- language: `{task_info.get('language')}`
- entry_point: `{task_info.get('entry_point')}`
- difficulty_level: `{args.difficulty_level}`

## Command

```text
{' '.join(command)}
```

## Run

- started_utc: `{started.isoformat()}`
- ended_utc: `{ended.isoformat()}`
- workspace: `{paths.workspace}`
- isolated Codex home: `{paths.codex_home}`
- visible test venv: `{paths.visible_test_venv}`
- visible test python: `{task_info.get('visible_test_python')}`
- Sentinel exit code: `{sentinel_rc}`
- Sentinel live log: `{paths.artifacts / 'sentinel-live.log'}`
- supervisor state: `{paths.artifacts / '.supervisor'}`
- coder/supervisor rollout summary: `{paths.rollouts / 'rollout_collection_summary.json'}`
- matched coder rollouts: `{rollouts.get('coder_count')}`
- matched supervisor rollouts: `{rollouts.get('supervisor_count')}`

## Artifacts

- final git status: `{paths.artifacts / 'final_git_status.txt'}`
- modified files: `{paths.artifacts / 'modified_files.txt'}`
- final diff: `{paths.artifacts / 'agent_diff_vs_initial.diff'}`
- final workspace archive: `{paths.artifacts / 'final-workspace-no-git-no-supervisor.tar.gz'}`

## Scoring

- scoring exit code: `{scoring_rc}`
- validation score: `{validation_score.get('score')}`
- validation passed/total: `{validation_score.get('passed')}/{validation_score.get('total')}`
- held-out private score: `{heldout_score.get('private_score')}`
- held-out private passed/total: `{heldout_score.get('private_passed')}/{heldout_score.get('private_total')}`
- held-out id_private score: `{heldout_score.get('id_private_score')}`
- held-out id_private passed/total: `{heldout_score.get('id_private_passed')}/{heldout_score.get('id_private_total')}`
- scoring summary: `{paths.scoring / 'scoring_summary.json'}`

## Integrity

- held-out tests present in agent workspace: `{hidden_check['heldout_tests_present']}`
- held-out workspace check paths: `{', '.join(hidden_check['checked_paths'])}`
- visible files only before agent run: starter code, TASK.md, tests/public, public-test helpers/resources excluding reference/private/id_private directories.
- valid scored run: `{valid_scored_run}`

## Environment Problems And Fixes

- runner-detected environment problems: `none`
"""
    (paths.root / "run_report.md").write_text(report, encoding="utf-8")


def copytree_replace(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def run_capture(cmd: list[str], *, log_path: Path, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        log.write("$ " + " ".join(cmd) + "\n")
        log.flush()
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
        log.write(result.stdout)
        log.write(result.stderr)
    if result.returncode != 0:
        raise SystemExit(f"command failed with exit {result.returncode}; see {log_path}")
    return result


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    log_path: Path,
    append: bool = False,
    env: dict[str, str] | None = None,
) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with log_path.open(mode, encoding="utf-8") as log:
        log.write("$ " + " ".join(cmd) + "\n")
        log.flush()
        subprocess.run(cmd, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, text=True)


def run_streaming(
    cmd: list[str],
    *,
    log_path: Path,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        log.write("$ " + " ".join(cmd) + "\n")
        log.flush()
        process = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        for line in process.stdout:
            sys.stdout.write(line)
            log.write(line)
        return process.wait()


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


if __name__ == "__main__":
    raise SystemExit(main())
