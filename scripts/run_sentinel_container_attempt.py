#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import textwrap
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DATASET = "ScaleAI/SWE-bench_Pro"
CONTAINER_CWD = "/app"
DEFAULT_DOCKERHUB_USERNAME = "jefzda"
DEFAULT_PLATFORM = "linux/amd64"


@dataclass(frozen=True)
class RunPaths:
    root: Path
    private: Path
    build: Path
    attempt: Path
    attempt_input: Path
    attempt_output: Path
    artifacts: Path
    rollouts: Path
    scoring: Path


def main() -> int:
    args = parse_args()
    sentinel_src = args.sentinel_src.resolve()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    results_root = (args.results_root or Path.home() / "Desktop" / f"sentinel-container-run-{timestamp}").resolve()
    paths = make_paths(results_root)
    for path in paths.__dict__.values():
        path.mkdir(parents=True, exist_ok=True)

    instance = load_instance(args)
    task_id = instance["instance_id"]
    if args.task_id and args.task_id != task_id:
        raise SystemExit(f"--task-id {args.task_id!r} does not match instance JSON {task_id!r}")

    write_json(paths.private / "instance.json", instance)
    task_text = decode_problem_statement(str(instance["problem_statement"]))
    (paths.attempt_input / "TASK.md").write_text(task_text.rstrip() + "\n", encoding="utf-8")
    runtime_config = prepare_codex_runtime_config(args.auth_dir.expanduser().resolve(), paths)

    base_image = args.base_image or dockerhub_image(instance, args.dockerhub_username)
    attempt_image = args.attempt_image or f"sentinel-attempt:{safe_tag(task_id)}-{timestamp}"
    codex_version = args.codex_version or detect_codex_version()

    print(f"results_root={paths.root}")
    print(f"base_image={base_image}")
    print(f"attempt_image={attempt_image}")
    print(f"codex_version={codex_version}")
    print("feasibility=using host ~/.codex/auth.json and config.toml as read-only runtime mounts")

    check_inputs(args, sentinel_src, paths, instance)
    if not args.skip_build:
        build_attempt_image(
            base_image=base_image,
            attempt_image=attempt_image,
            codex_version=codex_version,
            sentinel_src=sentinel_src,
            build_dir=paths.build,
            platform=args.platform,
        )

    start_utc = datetime.now(timezone.utc)
    sentinel_rc = run_attempt_container(
        image=attempt_image,
        paths=paths,
        instance=instance,
        auth_dir=args.auth_dir.expanduser().resolve(),
        runtime_config=runtime_config,
        model=args.model,
        platform=args.platform,
        extra_supervisor_args=args.supervisor_args,
    )
    end_utc = datetime.now(timezone.utc)

    summary = collect_rollouts(paths, container_cwd=CONTAINER_CWD, start_utc=start_utc, end_utc=end_utc)
    test_evidence = scan_test_evidence(paths)
    write_json(paths.rollouts / "rollout_collection_summary.json", summary)
    (paths.attempt / "sentinel-exit-code.txt").write_text(f"{sentinel_rc}\n", encoding="utf-8")

    scoring_rc = 0
    if not args.skip_score:
        scoring_rc = run_scoring(
            paths=paths,
            instance=instance,
            swe_bench_pro_dir=args.swe_bench_pro_dir.resolve() if args.swe_bench_pro_dir else None,
            dockerhub_username=args.dockerhub_username,
            platform=args.platform,
        )
        summarize_scoring(paths, instance)

    write_run_report(paths, instance, base_image, attempt_image, codex_version, sentinel_rc, scoring_rc, summary, test_evidence)
    print(f"run_report={paths.root / 'run_report.md'}")
    return 0 if sentinel_rc == 0 and scoring_rc == 0 else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one Sentinel attempt inside a SWE-bench Pro instance container.")
    parser.add_argument("--task-id", help="SWE-bench Pro instance_id to fetch from HuggingFace.")
    parser.add_argument("--instance-json", type=Path, help="Path to a JSON file containing one SWE-bench Pro instance row.")
    parser.add_argument("--results-root", type=Path, help="Directory for all run outputs.")
    parser.add_argument("--sentinel-src", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--swe-bench-pro-dir", type=Path, help="Path to the SWE-bench_Pro-os checkout used for scoring.")
    parser.add_argument("--dockerhub-username", default=DEFAULT_DOCKERHUB_USERNAME)
    parser.add_argument("--base-image", help="Full Docker image to use as the attempt base. Defaults to dockerhub_tag.")
    parser.add_argument("--attempt-image", help="Docker tag for the built attempt image.")
    parser.add_argument("--codex-version", help="Version of @openai/codex to install. Defaults to local codex --version.")
    parser.add_argument("--auth-dir", type=Path, default=Path.home() / ".codex")
    parser.add_argument("--platform", default=DEFAULT_PLATFORM)
    parser.add_argument("--model", help="Optional model passed to supervisor.")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-score", action="store_true")
    parser.add_argument("supervisor_args", nargs=argparse.REMAINDER, help="Extra args after -- are passed to supervisor.")
    args = parser.parse_args()
    if not args.instance_json and not args.task_id:
        parser.error("provide --instance-json or --task-id")
    if args.supervisor_args and args.supervisor_args[0] == "--":
        args.supervisor_args = args.supervisor_args[1:]
    return args


def make_paths(root: Path) -> RunPaths:
    return RunPaths(
        root=root,
        private=root / "private",
        build=root / "build",
        attempt=root / "attempt",
        attempt_input=root / "attempt" / "input",
        attempt_output=root / "attempt" / "output",
        artifacts=root / "attempt" / "output" / "artifacts",
        rollouts=root / "rollouts",
        scoring=root / "scoring",
    )


def load_instance(args: argparse.Namespace) -> dict[str, Any]:
    if args.instance_json:
        data = json.loads(args.instance_json.read_text(encoding="utf-8"))
        return data["row"] if isinstance(data, dict) and isinstance(data.get("row"), dict) else data
    assert args.task_id
    return fetch_instance(args.task_id)


def fetch_instance(task_id: str) -> dict[str, Any]:
    offset = 0
    length = 100
    while True:
        query = urllib.parse.urlencode(
            {"dataset": DATASET, "config": "default", "split": "test", "offset": offset, "length": length}
        )
        url = f"https://datasets-server.huggingface.co/rows?{query}"
        with urllib.request.urlopen(url, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
        rows = payload.get("rows") or []
        for item in rows:
            row = item.get("row") or {}
            if row.get("instance_id") == task_id:
                row["_row_idx"] = item.get("row_idx")
                return row
        if len(rows) < length:
            raise SystemExit(f"instance_id not found in {DATASET}: {task_id}")
        offset += length


def check_inputs(args: argparse.Namespace, sentinel_src: Path, paths: RunPaths, instance: dict[str, Any]) -> None:
    required = ["instance_id", "repo", "base_commit", "dockerhub_tag", "problem_statement"]
    missing = [key for key in required if not instance.get(key)]
    if missing:
        raise SystemExit(f"instance row missing required fields: {', '.join(missing)}")
    if not (sentinel_src / "pyproject.toml").exists():
        raise SystemExit(f"sentinel source does not look like a Python project: {sentinel_src}")
    auth_dir = args.auth_dir.expanduser().resolve()
    for name in ["auth.json", "config.toml"]:
        if not (auth_dir / name).exists():
            raise SystemExit(f"missing Codex auth/config file: {auth_dir / name}")
    if not args.skip_score and not args.swe_bench_pro_dir:
        raise SystemExit("--swe-bench-pro-dir is required unless --skip-score is set")
    if args.swe_bench_pro_dir and not (args.swe_bench_pro_dir / "swe_bench_pro_eval.py").exists():
        raise SystemExit(f"missing swe_bench_pro_eval.py under {args.swe_bench_pro_dir}")
    for rel in ["codex-home/sessions", "codex-home/archived_sessions", "codex-home/.tmp"]:
        (paths.rollouts / rel).mkdir(parents=True, exist_ok=True)


def prepare_codex_runtime_config(auth_dir: Path, paths: RunPaths) -> Path:
    source = auth_dir / "config.toml"
    text = source.read_text(encoding="utf-8")
    if not re.search(r"(?m)^\s*zsh_path\s*=", text):
        text = 'zsh_path = "/usr/bin/zsh"\n' + text
    runtime_config = paths.private / "codex-container-config.toml"
    runtime_config.write_text(text, encoding="utf-8")
    return runtime_config


def build_attempt_image(
    *,
    base_image: str,
    attempt_image: str,
    codex_version: str,
    sentinel_src: Path,
    build_dir: Path,
    platform: str,
) -> None:
    context = build_dir / "context"
    if context.exists():
        shutil.rmtree(context)
    context.mkdir(parents=True)
    copy_sentinel_source(sentinel_src, context / "sentinel-src")
    dockerfile = context / "Dockerfile"
    dockerfile.write_text(
        textwrap.dedent(
            f"""
            FROM {base_image}
            ARG CODEX_VERSION={codex_version}
            ENV PIP_DISABLE_PIP_VERSION_CHECK=1
            RUN apt-get update \\
                && apt-get install -y --no-install-recommends python3.11-venv ca-certificates zsh \\
                && rm -rf /var/lib/apt/lists/*
            RUN npm install -g @openai/codex@${{CODEX_VERSION}} --no-audit --no-fund
            COPY sentinel-src /opt/sentinel-src
            RUN python3 -m venv /opt/sentinel-venv \\
                && /opt/sentinel-venv/bin/python -m pip install --upgrade pip setuptools wheel \\
                && /opt/sentinel-venv/bin/python -m pip install /opt/sentinel-src
            ENV SHELL="/usr/bin/zsh"
            ENV PATH="/opt/sentinel-venv/bin:${{PATH}}"
            WORKDIR /app
            """
        ).lstrip(),
        encoding="utf-8",
    )
    run(
        [
            "docker",
            "build",
            "--platform",
            platform,
            "-t",
            attempt_image,
            str(context),
        ],
        cwd=build_dir,
        log_path=build_dir / "docker-build.log",
    )


def copy_sentinel_source(src: Path, dst: Path) -> None:
    ignored = {
        ".git",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".test-runtime",
        "build",
        "dist",
        "*.egg-info",
    }

    def ignore(_dir: str, names: list[str]) -> set[str]:
        skipped: set[str] = set()
        for name in names:
            if (
                name in ignored
                or name.endswith(".egg-info")
                or name.endswith(".pyc")
                or name.endswith(".pyo")
            ):
                skipped.add(name)
        return skipped

    shutil.copytree(src, dst, ignore=ignore)


def run_attempt_container(
    *,
    image: str,
    paths: RunPaths,
    instance: dict[str, Any],
    auth_dir: Path,
    runtime_config: Path,
    model: str | None,
    platform: str,
    extra_supervisor_args: list[str],
) -> int:
    base_commit = str(instance["base_commit"])
    command = textwrap.dedent(
        f"""
        set -euo pipefail
        cd /app
        git reset --hard {sh_single(base_commit)}
        git clean -fd
        cp /attempt-input/TASK.md /app/TASK.md
        export SENTINEL_CODER_SANDBOX=danger-full-access
        start_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        echo "$start_utc" > /attempt-out/sentinel-start-utc.txt
        set +e
        /opt/sentinel-venv/bin/supervisor --task TASK.md --start-over {('--model ' + sh_single(model)) if model else ''} {' '.join(sh_single(arg) for arg in extra_supervisor_args)}
        rc=$?
        set -e
        date -u +%Y-%m-%dT%H:%M:%SZ > /attempt-out/sentinel-end-utc.txt
        echo "$rc" > /attempt-out/sentinel-exit-code.txt
        mkdir -p /attempt-out/artifacts
        cp /app/TASK.md /attempt-out/artifacts/TASK.md
        if [ -d /app/.supervisor ]; then cp -a /app/.supervisor /attempt-out/artifacts/.supervisor; fi
        git status --short > /attempt-out/artifacts/final_git_status.txt
        git diff --binary {sh_single(base_commit)} > /attempt-out/artifacts/agent_diff_vs_base.diff
        git diff --stat {sh_single(base_commit)} > /attempt-out/artifacts/agent_diff_vs_base.stat || true
        tar --exclude=.git --exclude=node_modules --exclude=.supervisor -czf /attempt-out/artifacts/final-worktree-no-git-no-node_modules.tar.gz -C /app .
        exit "$rc"
        """
    ).strip()
    log_path = paths.attempt / "sentinel-live.log"
    cmd = [
        "docker",
        "run",
        "--rm",
        "--platform",
        platform,
        # Codex read-only/workspace-write sandboxes use bubblewrap namespaces.
        # The attempt container is disposable, and privileged mode keeps those
        # sandboxes usable inside Docker instead of weakening supervisor policy.
        "--privileged",
        "-v",
        f"{paths.attempt_input}:/attempt-input:ro",
        "-v",
        f"{paths.attempt_output}:/attempt-out",
        "-v",
        f"{paths.rollouts / 'codex-home'}:/root/.codex",
        "-v",
        f"{auth_dir / 'auth.json'}:/root/.codex/auth.json:ro",
        "-v",
        f"{runtime_config}:/root/.codex/config.toml:ro",
        "--entrypoint",
        "/bin/bash",
        image,
        "-c",
        command,
    ]
    (paths.attempt / "docker-run-command.json").write_text(json.dumps(cmd, indent=2) + "\n", encoding="utf-8")
    return run_streaming(cmd, log_path=log_path)


def collect_rollouts(paths: RunPaths, *, container_cwd: str, start_utc: datetime, end_utc: datetime) -> dict[str, Any]:
    artifacts_supervisor = paths.artifacts / ".supervisor"
    coder_thread_id = None
    config_path = artifacts_supervisor / "config.json"
    if config_path.exists():
        try:
            coder_thread_id = json.loads(config_path.read_text(encoding="utf-8")).get("coder_thread_id")
        except json.JSONDecodeError:
            coder_thread_id = None

    supervisor_thread_ids = set()
    wakes_path = artifacts_supervisor / "supervisor_wakes.jsonl"
    if wakes_path.exists():
        for line in wakes_path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            thread_id = item.get("thread_id")
            if thread_id:
                supervisor_thread_ids.add(thread_id)

    for bucket in ["coder", "supervisor", "other"]:
        (paths.rollouts / bucket).mkdir(parents=True, exist_ok=True)

    matched: list[dict[str, Any]] = []
    rollout_roots = [
        paths.rollouts / "codex-home" / "sessions",
        paths.rollouts / "codex-home" / "archived_sessions",
        paths.rollouts / "sessions",
        paths.rollouts / "archived_sessions",
    ]
    for rollout_root in rollout_roots:
        if not rollout_root.exists():
            continue
        for path in rollout_root.rglob("*.jsonl"):
            meta = read_rollout_meta(path)
            if not meta:
                continue
            if meta.get("cwd") != container_cwd:
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
        "container_cwd": container_cwd,
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


def scan_test_evidence(paths: RunPaths) -> dict[str, Any]:
    patterns = [
        "npm test",
        "npm run",
        "npx mocha",
        "pytest",
        "go test",
        "cargo test",
        "yarn test",
        "pnpm test",
    ]
    hits: list[str] = []
    search_files = [paths.attempt / "sentinel-live.log"]
    search_files.extend((paths.rollouts / "coder").glob("*.jsonl"))
    search_files.extend((paths.rollouts / "other").glob("*.jsonl"))
    for path in search_files:
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            lower = line.lower()
            if any(pattern in lower for pattern in patterns):
                hits.append(f"{path}: {line[:500]}")
    out = paths.attempt / "test-command-evidence.txt"
    out.write_text("\n".join(hits) + ("\n" if hits else ""), encoding="utf-8")
    return {"count": len(hits), "path": str(out), "examples": hits[:10]}


def run_scoring(
    *,
    paths: RunPaths,
    instance: dict[str, Any],
    swe_bench_pro_dir: Path | None,
    dockerhub_username: str,
    platform: str,
) -> int:
    assert swe_bench_pro_dir is not None
    raw_sample = paths.scoring / "raw_sample.jsonl"
    patch_json = paths.scoring / "patches.json"
    harness_output = paths.scoring / "harness-output"
    harness_output.mkdir(parents=True, exist_ok=True)
    raw_sample.write_text(json.dumps(instance) + "\n", encoding="utf-8")
    patch = (paths.artifacts / "agent_diff_vs_base.diff").read_text(encoding="utf-8") if (paths.artifacts / "agent_diff_vs_base.diff").exists() else ""
    patch_json.write_text(
        json.dumps([{"instance_id": instance["instance_id"], "patch": patch, "prefix": "container_attempt"}], indent=2)
        + "\n",
        encoding="utf-8",
    )
    venv = paths.scoring / "eval-venv"
    if not venv.exists():
        run([sys.executable, "-m", "venv", str(venv)], log_path=paths.scoring / "eval-venv-create.log")
        pip = venv / "bin" / "pip"
        requirements = swe_bench_pro_dir / "requirements.txt"
        install_cmd = [str(pip), "install", "--upgrade", "pip", "setuptools", "wheel"]
        run(install_cmd, log_path=paths.scoring / "eval-venv-install.log")
        if requirements.exists():
            run([str(pip), "install", "-r", str(requirements)], log_path=paths.scoring / "eval-venv-install.log", append=True)
        run([str(pip), "install", "docker", "pandas", "tqdm"], log_path=paths.scoring / "eval-venv-install.log", append=True)

    cmd = [
        str(venv / "bin" / "python"),
        str(swe_bench_pro_dir / "swe_bench_pro_eval.py"),
        "--raw_sample_path",
        str(raw_sample),
        "--patch_path",
        str(patch_json),
        "--output_dir",
        str(harness_output),
        "--dockerhub_username",
        dockerhub_username,
        "--scripts_dir",
        str(swe_bench_pro_dir / "run_scripts"),
        "--use_local_docker",
        "--num_workers",
        "1",
        "--redo",
        "--docker_platform",
        platform,
    ]
    (paths.scoring / "eval_command.json").write_text(json.dumps(cmd, indent=2) + "\n", encoding="utf-8")
    return run_streaming(cmd, log_path=paths.scoring / "eval-run.log", cwd=swe_bench_pro_dir)


def summarize_scoring(paths: RunPaths, instance: dict[str, Any]) -> None:
    instance_id = instance["instance_id"]
    output_path = paths.scoring / "harness-output" / instance_id / "container_attempt_output.json"
    eval_results_path = paths.scoring / "harness-output" / "eval_results.json"
    summary: dict[str, Any] = {"instance_id": instance_id, "output_path": str(output_path), "eval_results_path": str(eval_results_path)}
    if eval_results_path.exists():
        summary["eval_results"] = json.loads(eval_results_path.read_text(encoding="utf-8"))
    if output_path.exists():
        output = json.loads(output_path.read_text(encoding="utf-8"))
        passed = {item["name"] for item in output.get("tests", []) if item.get("status") == "PASSED"}
        fail_to_pass = parse_list_field(instance.get("fail_to_pass", "[]"))
        pass_to_pass = parse_list_field(instance.get("pass_to_pass", "[]"))
        summary["fail_to_pass_total"] = len(fail_to_pass)
        summary["fail_to_pass_failed"] = sorted(set(fail_to_pass) - passed)
        summary["pass_to_pass_total"] = len(pass_to_pass)
        summary["pass_to_pass_regressed"] = sorted(set(pass_to_pass) - passed)
    write_json(paths.scoring / "scoring_summary.json", summary)


def write_run_report(
    paths: RunPaths,
    instance: dict[str, Any],
    base_image: str,
    attempt_image: str,
    codex_version: str,
    sentinel_rc: int,
    scoring_rc: int,
    rollouts: dict[str, Any],
    test_evidence: dict[str, Any],
) -> None:
    scoring_summary_path = paths.scoring / "scoring_summary.json"
    scoring_summary = json.loads(scoring_summary_path.read_text(encoding="utf-8")) if scoring_summary_path.exists() else {}
    report = f"""# Sentinel Container Attempt Report

## Instance

- instance_id: `{instance.get('instance_id')}`
- repo: `{instance.get('repo')}`
- base_commit: `{instance.get('base_commit')}`
- dockerhub_tag: `{instance.get('dockerhub_tag')}`
- base_image: `{base_image}`
- attempt_image: `{attempt_image}`

## Feasibility

- Base image provided `/app`, Python, Node/npm, git/curl, and outbound network during preflight.
- Codex CLI is installed into the attempt image as `@openai/codex@{codex_version}`.
- Codex auth is provided at runtime by a read-only mount from host `~/.codex/auth.json`; config is generated from host `~/.codex/config.toml` with `zsh_path = "/usr/bin/zsh"` for Linux unified exec.
- Codex rollouts are mounted out through one host-backed `/root/.codex` directory, so `sessions` and `archived_sessions` stay on the same filesystem for Codex archive renames.
- The attempt container sets `SENTINEL_CODER_SANDBOX=danger-full-access` because Codex's Linux read-only sandbox requires user namespace support that was unavailable in the nested Docker attempt container during feasibility probes.

## Attempt

- Sentinel cwd inside container: `{CONTAINER_CWD}`
- TASK.md path inside container: `{CONTAINER_CWD}/TASK.md`
- Coder sandbox inside attempt container: `danger-full-access`
- Sentinel exit code: `{sentinel_rc}`
- Live log: `{paths.attempt / 'sentinel-live.log'}`
- Agent diff: `{paths.artifacts / 'agent_diff_vs_base.diff'}`
- Supervisor state: `{paths.artifacts / '.supervisor'}`
- Test command evidence count: `{test_evidence.get('count')}`
- Test command evidence file: `{test_evidence.get('path')}`

## Rollouts

- Mounted Codex home: `{paths.rollouts / 'codex-home'}`
- Mounted sessions dir: `{paths.rollouts / 'codex-home' / 'sessions'}`
- Mounted archived sessions dir: `{paths.rollouts / 'codex-home' / 'archived_sessions'}`
- Matched rollouts: `{rollouts.get('matched_count')}`
- Coder rollouts: `{rollouts.get('coder_count')}`
- Supervisor rollouts: `{rollouts.get('supervisor_count')}`
- Other `/app` rollouts: `{rollouts.get('other_count')}`
- Summary: `{paths.rollouts / 'rollout_collection_summary.json'}`

## Scoring

- Scoring exit code: `{scoring_rc}`
- Eval command: `{paths.scoring / 'eval_command.json'}`
- Eval log: `{paths.scoring / 'eval-run.log'}`
- Scoring summary: `{scoring_summary_path}`
- Eval results: `{scoring_summary.get('eval_results')}`
- fail_to_pass failed: `{scoring_summary.get('fail_to_pass_failed')}`
- pass_to_pass regressed: `{scoring_summary.get('pass_to_pass_regressed')}`
"""
    (paths.root / "run_report.md").write_text(report, encoding="utf-8")


def dockerhub_image(instance: dict[str, Any], dockerhub_username: str) -> str:
    return f"{dockerhub_username}/sweap-images:{instance['dockerhub_tag']}"


def detect_codex_version() -> str:
    try:
        output = subprocess.check_output(["codex", "--version"], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "0.134.0"
    match = re.search(r"(\d+\.\d+\.\d+)", output)
    return match.group(1) if match else "0.134.0"


def decode_problem_statement(value: str) -> str:
    stripped = value.strip()
    if stripped.startswith('"') and stripped.endswith('"'):
        try:
            decoded = json.loads(stripped)
            if isinstance(decoded, str):
                return decoded
        except json.JSONDecodeError:
            pass
    return value


def parse_list_field(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if not isinstance(value, str):
        return []
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
    except json.JSONDecodeError:
        pass
    try:
        import ast

        parsed = ast.literal_eval(value)
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
    except (SyntaxError, ValueError):
        pass
    return []


def parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def safe_tag(value: str) -> str:
    tag = re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip(".-")
    return tag[:96] or "attempt"


def sh_single(value: str | None) -> str:
    if value is None:
        return "''"
    return "'" + value.replace("'", "'\"'\"'") + "'"


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(cmd: list[str], *, cwd: Path | None = None, log_path: Path, append: bool = False) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with log_path.open(mode, encoding="utf-8") as log:
        log.write("$ " + " ".join(cmd) + "\n")
        log.flush()
        subprocess.run(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, check=True, text=True)


def run_streaming(cmd: list[str], *, log_path: Path, cwd: Path | None = None) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        log.write("$ " + " ".join(cmd) + "\n")
        log.flush()
        process = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        assert process.stdout is not None
        for line in process.stdout:
            sys.stdout.write(line)
            log.write(line)
        return process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
