from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType


def load_container_runner() -> ModuleType:
    runner_path = Path(__file__).resolve().parents[1] / "scripts" / "run_sentinel_container_attempt.py"
    spec = importlib.util.spec_from_file_location("run_sentinel_container_attempt", runner_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_specbench_runner() -> ModuleType:
    runner_path = Path(__file__).resolve().parents[1] / "scripts" / "run_sentinel_specbench_attempt.py"
    spec = importlib.util.spec_from_file_location("run_sentinel_specbench_attempt", runner_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_attempt_container_is_privileged_for_nested_codex_sandboxes(tmp_path: Path, monkeypatch) -> None:
    runner = load_container_runner()
    captured: dict[str, list[str]] = {}

    def fake_run_streaming(cmd: list[str], *, log_path: Path) -> int:
        captured["cmd"] = cmd
        assert log_path == paths.attempt / "sentinel-live.log"
        return 0

    paths = runner.RunPaths(
        root=tmp_path,
        private=tmp_path / "private",
        build=tmp_path / "build",
        attempt=tmp_path / "attempt",
        attempt_input=tmp_path / "attempt" / "input",
        attempt_output=tmp_path / "attempt" / "output",
        artifacts=tmp_path / "attempt" / "output" / "artifacts",
        rollouts=tmp_path / "rollouts",
        scoring=tmp_path / "scoring",
    )
    for path in paths.__dict__.values():
        path.mkdir(parents=True, exist_ok=True)

    auth_dir = tmp_path / "auth"
    auth_dir.mkdir()
    (auth_dir / "auth.json").write_text("{}", encoding="utf-8")
    runtime_config = tmp_path / "config.toml"
    runtime_config.write_text("", encoding="utf-8")
    monkeypatch.setattr(runner, "run_streaming", fake_run_streaming)

    rc = runner.run_attempt_container(
        image="attempt:test",
        container_name="sentinel-attempt-test",
        paths=paths,
        instance={"base_commit": "abc123"},
        auth_dir=auth_dir,
        runtime_config=runtime_config,
        model=None,
        coder_model=None,
        supervisor_model=None,
        platform="linux/amd64",
        extra_supervisor_args=[],
        egress=None,
    )

    assert rc == 0
    cmd = captured["cmd"]
    assert "--privileged" in cmd
    assert cmd.index("--privileged") > cmd.index("linux/amd64")
    assert "--name" in cmd
    assert cmd[cmd.index("--name") + 1] == "sentinel-attempt-test"
    script = cmd[-1]
    assert script.index("git reset --hard 'abc123'") < script.index("rm -rf .git")
    assert "sentinel-diff-base-ref.txt" in script
    assert 'git diff --cached --binary "$sentinel_diff_base_ref"' in script
    assert script.index("git gc --prune=now") < script.index("/opt/sentinel-venv/bin/sentinel")
    assert "git diff --cached --binary 'abc123'" not in script
    written_cmd = json.loads((paths.attempt / "docker-run-command.json").read_text(encoding="utf-8"))
    assert written_cmd == cmd


def test_attempt_image_build_includes_private_sentinel_python(tmp_path: Path, monkeypatch) -> None:
    runner = load_container_runner()
    captured: dict[str, list[str] | Path] = {}

    def fake_copy_sentinel_source(src: Path, dest: Path) -> None:
        captured["copied_from"] = src
        dest.mkdir(parents=True)
        (dest / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")

    def fake_run(cmd: list[str], *, cwd: Path, log_path: Path) -> None:
        captured["cmd"] = cmd
        captured["cwd"] = cwd
        captured["log_path"] = log_path

    monkeypatch.setattr(runner, "copy_sentinel_source", fake_copy_sentinel_source)
    monkeypatch.setattr(runner, "run", fake_run)

    runner.build_attempt_image(
        base_image="example/base:latest",
        attempt_image="attempt:test",
        codex_version="0.0.0",
        sentinel_src=tmp_path / "sentinel-src",
        build_dir=tmp_path / "build",
        platform="linux/amd64",
    )

    dockerfile = (tmp_path / "build" / "context" / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM python:3.11-slim-bullseye AS sentinel-python" in dockerfile
    assert "FROM example/base:latest" in dockerfile
    assert "COPY --from=sentinel-python /usr/local /opt/sentinel-python" in dockerfile
    assert "/opt/sentinel-python/bin/python3.11" in dockerfile
    assert captured["cmd"] == [
        "docker",
        "build",
        "--platform",
        "linux/amd64",
        "-t",
        "attempt:test",
        str(tmp_path / "build" / "context"),
    ]
    assert captured["cwd"] == tmp_path / "build"


def test_attempt_container_raw_codex_mode_uses_same_harness_without_supervisor(tmp_path: Path, monkeypatch) -> None:
    runner = load_container_runner()
    captured: dict[str, list[str]] = {}

    def fake_run_streaming(cmd: list[str], *, log_path: Path) -> int:
        captured["cmd"] = cmd
        assert log_path == paths.attempt / "sentinel-live.log"
        return 0

    paths = runner.RunPaths(
        root=tmp_path,
        private=tmp_path / "private",
        build=tmp_path / "build",
        attempt=tmp_path / "attempt",
        attempt_input=tmp_path / "attempt" / "input",
        attempt_output=tmp_path / "attempt" / "output",
        artifacts=tmp_path / "attempt" / "output" / "artifacts",
        rollouts=tmp_path / "rollouts",
        scoring=tmp_path / "scoring",
    )
    for path in paths.__dict__.values():
        path.mkdir(parents=True, exist_ok=True)

    auth_dir = tmp_path / "auth"
    auth_dir.mkdir()
    (auth_dir / "auth.json").write_text("{}", encoding="utf-8")
    runtime_config = tmp_path / "config.toml"
    runtime_config.write_text("", encoding="utf-8")
    monkeypatch.setattr(runner, "run_streaming", fake_run_streaming)

    rc = runner.run_attempt_container(
        image="attempt:test",
        container_name="sentinel-attempt-raw",
        paths=paths,
        instance={"base_commit": "abc123"},
        auth_dir=auth_dir,
        runtime_config=runtime_config,
        model=None,
        coder_model=None,
        supervisor_model=None,
        platform="linux/amd64",
        extra_supervisor_args=[],
        egress=None,
        agent_mode="raw-codex",
    )

    assert rc == 0
    cmd = captured["cmd"]
    script = cmd[-1]
    assert "/opt/sentinel-venv/bin/sentinel" not in script
    assert "codex exec --json" in script
    assert "--dangerously-bypass-approvals-and-sandbox" in script
    assert """-c 'web_search="disabled"'""" in script
    assert "--output-last-message /attempt-out/raw-codex-final-message.txt" in script
    assert "- < /attempt-input/RAW_CODEX_PROMPT.md" in script
    assert script.index("git gc --prune=now") < script.index("codex exec --json")


def test_specbench_runner_passes_declared_grading_paths_to_supervisor(tmp_path: Path, monkeypatch) -> None:
    runner = load_specbench_runner()
    captured: dict[str, list[str] | Path | dict[str, str]] = {}
    paths = runner.RunPaths(
        root=tmp_path,
        workspace=tmp_path / "workspace",
        artifacts=tmp_path / "artifacts",
        rollouts=tmp_path / "rollouts",
        scoring=tmp_path / "scoring",
        visible_test_venv=tmp_path / "visible-test-venv",
        codex_home=tmp_path / "codex-home",
    )
    for path in paths.__dict__.values():
        path.mkdir(parents=True, exist_ok=True)
    sentinel_bin = tmp_path / "supervisor"
    sentinel_bin.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
    sentinel_bin.chmod(0o755)
    (paths.workspace / "TASK.md").write_text("# Task\n", encoding="utf-8")
    runner.write_json(
        paths.root / "task-info-public.json",
        {"declared_grading_paths": ["/root/SpecBench/examples/c_compiler", "/root/SpecBench/examples/c_compiler/tests/private"]},
    )

    def fake_run_streaming(cmd: list[str], *, cwd: Path | None = None, log_path: Path, env: dict[str, str] | None = None) -> int:
        captured["cmd"] = cmd
        captured["cwd"] = cwd
        captured["log_path"] = log_path
        captured["env"] = env or {}
        return 0

    monkeypatch.setattr(runner, "run_streaming", fake_run_streaming)

    rc = runner.run_sentinel(
        type("Args", (), {"model": None, "coder_mod": None, "super_mod": None, "supervisor_args": [], "sentinel_bin": sentinel_bin})(),
        paths,
        tmp_path,
    )

    assert rc == 0
    cmd = captured["cmd"]
    assert cmd.count("--protected-path") == 2
    first = cmd.index("--protected-path")
    assert cmd[first + 1] == "/root/SpecBench/examples/c_compiler"
    second = cmd.index("--protected-path", first + 1)
    assert cmd[second + 1] == "/root/SpecBench/examples/c_compiler/tests/private"


def test_specbench_runner_skips_scoring_when_sentinel_is_infra_invalid(tmp_path: Path, monkeypatch) -> None:
    runner = load_specbench_runner()
    paths = runner.RunPaths(
        root=tmp_path,
        workspace=tmp_path / "workspace",
        artifacts=tmp_path / "artifacts",
        rollouts=tmp_path / "rollouts",
        scoring=tmp_path / "scoring",
        visible_test_venv=tmp_path / "visible-test-venv",
        codex_home=tmp_path / "codex-home",
    )
    for path in paths.__dict__.values():
        path.mkdir(parents=True, exist_ok=True)

    def fail_score_workspace(*args, **kwargs):
        raise AssertionError("scorer must not run for infra-invalid sentinel exit")

    monkeypatch.setattr(runner, "score_workspace", fail_score_workspace)

    rc = runner.score_workspace_if_sentinel_succeeded(
        type("Args", (), {})(),
        tmp_path,
        paths,
        sentinel_rc=2,
    )

    assert rc == 0
    skipped = json.loads((paths.scoring / "score-skipped.json").read_text(encoding="utf-8"))
    assert skipped["sentinel_exit_code"] == 2
    assert "infra-invalid/not-scored" in skipped["reason"]


def test_container_runner_skips_scoring_when_sentinel_is_infra_invalid(tmp_path: Path, monkeypatch) -> None:
    runner = load_container_runner()
    paths = runner.RunPaths(
        root=tmp_path,
        private=tmp_path / "private",
        build=tmp_path / "build",
        attempt=tmp_path / "attempt",
        attempt_input=tmp_path / "attempt" / "input",
        attempt_output=tmp_path / "attempt" / "output",
        artifacts=tmp_path / "attempt" / "output" / "artifacts",
        rollouts=tmp_path / "rollouts",
        scoring=tmp_path / "scoring",
    )
    for path in paths.__dict__.values():
        path.mkdir(parents=True, exist_ok=True)

    def fail_run_scoring(*args, **kwargs):
        raise AssertionError("scorer must not run for infra-invalid sentinel exit")

    monkeypatch.setattr(runner, "run_scoring", fail_run_scoring)
    args = type(
        "Args",
        (),
        {
            "skip_score": False,
            "swe_bench_pro_dir": tmp_path,
            "dockerhub_username": "user",
            "platform": "linux/amd64",
        },
    )()

    rc = runner.score_attempt_if_sentinel_succeeded(
        args=args,
        paths=paths,
        instance={"instance_id": "case-107"},
        sentinel_rc=2,
    )

    assert rc == 0
    skipped = json.loads((paths.scoring / "score-skipped.json").read_text(encoding="utf-8"))
    assert skipped["sentinel_exit_code"] == 2
    assert "infra-invalid/not-scored" in skipped["reason"]


def test_attempt_container_uses_docker_assigned_ip_on_egress_network(tmp_path: Path, monkeypatch) -> None:
    runner = load_container_runner()
    captured: dict[str, list[str]] = {}

    def fake_run_streaming(cmd: list[str], *, log_path: Path) -> int:
        captured["cmd"] = cmd
        return 0

    paths = runner.RunPaths(
        root=tmp_path,
        private=tmp_path / "private",
        build=tmp_path / "build",
        attempt=tmp_path / "attempt",
        attempt_input=tmp_path / "attempt" / "input",
        attempt_output=tmp_path / "attempt" / "output",
        artifacts=tmp_path / "attempt" / "output" / "artifacts",
        rollouts=tmp_path / "rollouts",
        scoring=tmp_path / "scoring",
    )
    for path in paths.__dict__.values():
        path.mkdir(parents=True, exist_ok=True)

    auth_dir = tmp_path / "auth"
    auth_dir.mkdir()
    (auth_dir / "auth.json").write_text("{}", encoding="utf-8")
    runtime_config = tmp_path / "config.toml"
    runtime_config.write_text("", encoding="utf-8")
    egress = runner.EgressRuntime(
        network_name="sentinel-egress",
        subnet="172.31.250.0/24",
        gateway="172.31.250.1",
        proxy_port=12345,
        proxy_url="http://172.31.250.1:12345",
        allow_domains=("chatgpt.com",),
        common_iptables_rules=(),
        proxy_iptables_rule=(),
    )
    monkeypatch.setattr(runner, "run_streaming", fake_run_streaming)

    rc = runner.run_attempt_container(
        image="attempt:test",
        container_name="sentinel-attempt-unique",
        paths=paths,
        instance={"base_commit": "abc123"},
        auth_dir=auth_dir,
        runtime_config=runtime_config,
        model=None,
        coder_model=None,
        supervisor_model=None,
        platform="linux/amd64",
        extra_supervisor_args=[],
        egress=egress,
    )

    assert rc == 0
    cmd = captured["cmd"]
    assert "--network" in cmd
    assert cmd[cmd.index("--network") + 1] == "sentinel-egress"
    assert "--ip" not in cmd
    assert "--name" in cmd
    assert cmd[cmd.index("--name") + 1] == "sentinel-attempt-unique"
    assert "HTTPS_PROXY=http://172.31.250.1:12345" in cmd


def test_egress_rules_cover_whole_subnet_not_one_container_ip() -> None:
    runner = load_container_runner()

    common = runner.egress_common_iptables_rules("172.31.250.0/24", "172.31.250.1")
    proxy = runner.egress_proxy_iptables_rule("172.31.250.0/24", "172.31.250.1", 32100)

    for rule in [*common, proxy]:
        assert rule[rule.index("-s") + 1] == "172.31.250.0/24"
        assert "172.31.250.10" not in rule
    assert common[-1] == ["-s", "172.31.250.0/24", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"]
    assert proxy == ["-s", "172.31.250.0/24", "-d", "172.31.250.1", "-p", "tcp", "--dport", "32100", "-j", "ACCEPT"]


def test_scoring_sample_adds_lowercase_test_list_aliases() -> None:
    runner = load_container_runner()

    sample = runner.scoring_sample_for_scorer(
        {
            "instance_id": "instance_test",
            "FAIL_TO_PASS": ["test_new"],
            "PASS_TO_PASS": '["test_existing"]',
        }
    )

    assert sample["FAIL_TO_PASS"] == ["test_new"]
    assert sample["PASS_TO_PASS"] == '["test_existing"]'
    assert sample["fail_to_pass"] == ["test_new"]
    assert sample["pass_to_pass"] == '["test_existing"]'


def test_compose_task_text_uses_canonical_swe_bench_pro_sections() -> None:
    runner = load_container_runner()

    text = runner.compose_task_text(
        {
            "problem_statement": "Problem body",
            "requirements": "- Requirement A\n- Requirement B",
            "interface": "Type: Class\nName: VersionChange",
        }
    )

    assert text == (
        "Problem body\n\n"
        "Requirements:\n"
        "- Requirement A\n"
        "- Requirement B\n\n"
        "New interfaces introduced:\n"
        "Type: Class\n"
        "Name: VersionChange"
    )


def test_compose_task_text_keeps_empty_optional_sections() -> None:
    runner = load_container_runner()

    text = runner.compose_task_text({"problem_statement": "Problem only"})

    assert text == "Problem only\n\nRequirements:\n\n\nNew interfaces introduced:\n"


def test_compose_raw_codex_prompt_points_agent_at_task_file() -> None:
    runner = load_container_runner()

    text = runner.compose_raw_codex_prompt("# AGENTS.md\n\nRules")

    assert text.startswith("# AGENTS.md\n\nRules\n\n# Benchmark task")
    assert "`/app/TASK.md`" in text
    assert "problem statement, requirements, and new interfaces" in text


def test_git_history_cleanup_rewrites_repo_to_single_snapshot_commit(tmp_path: Path) -> None:
    runner = load_container_runner()
    repo = tmp_path / "repo"
    artifacts = tmp_path / "artifacts"
    repo.mkdir()
    artifacts.mkdir()

    def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    git("init", "-q")
    git("config", "user.email", "sentinel@example.invalid")
    git("config", "user.name", "Sentinel Test")
    (repo / ".gitignore").write_text("ignored.txt\nignored-dir/\n", encoding="utf-8")
    (repo / "file.txt").write_text("parent\n", encoding="utf-8")
    (repo / "ignored.txt").write_text("tracked ignored parent\n", encoding="utf-8")
    (repo / "ignored-dir").mkdir()
    (repo / "ignored-dir" / "cache.txt").write_text("untracked ignored cache\n", encoding="utf-8")
    git("add", ".gitignore", "file.txt")
    git("add", "-f", "ignored.txt")
    git("commit", "-qm", "parent")
    parent_commit = git("rev-parse", "HEAD").stdout.strip()
    (repo / "file.txt").write_text("base\n", encoding="utf-8")
    git("add", "file.txt")
    git("commit", "-qm", "base")
    base_commit = git("rev-parse", "HEAD").stdout.strip()
    (repo / "file.txt").write_text("future\n", encoding="utf-8")
    git("commit", "-am", "future", "-q")
    future_commit = git("rev-parse", "HEAD").stdout.strip()
    git("tag", "future-tag")
    git("branch", "future-branch", future_commit)
    git("update-ref", "refs/remotes/origin/dev", future_commit)
    git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/dev")
    git("reset", "--hard", base_commit)

    subprocess.run(
        ["bash", "-euo", "pipefail", "-c", runner.git_history_cleanup_script(base_commit, artifacts_dir=str(artifacts))],
        cwd=repo,
        check=True,
        text=True,
    )

    snapshot_commit = git("rev-parse", "HEAD").stdout.strip()
    assert snapshot_commit != base_commit
    assert git("rev-list", "--all", "--count").stdout.strip() == "1"
    assert "ignored.txt" in git("ls-files").stdout.splitlines()
    assert "ignored-dir/cache.txt" not in git("ls-files").stdout.splitlines()
    assert git("tag", "-l").stdout.strip() == ""
    assert git("for-each-ref", "--format=%(refname)", "refs/remotes").stdout.strip() == ""
    remote_refs_dir = repo / ".git" / "refs" / "remotes"
    assert not remote_refs_dir.exists() or not any(path.is_file() or path.is_symlink() for path in remote_refs_dir.rglob("*"))
    assert git("branch", "--format=%(refname:short)").stdout.splitlines() == ["sentinel-base"]
    assert "sentinel base snapshot" in git("log", "--all", "--oneline").stdout
    assert not (repo / ".git" / "ORIG_HEAD").exists()
    assert git("show", "--no-patch", "--oneline", parent_commit, check=False).returncode != 0
    assert git("show", "--no-patch", "--oneline", base_commit, check=False).returncode != 0
    assert git("show", "--no-patch", "--oneline", future_commit, check=False).returncode != 0
    (repo / "file.txt").write_text("agent change\n", encoding="utf-8")
    git("add", "file.txt")
    diff = git("diff", "--cached", "--binary", snapshot_commit).stdout
    assert "-base" in diff
    assert "+agent change" in diff
    assert (artifacts / "git-history-cleanup.log").exists()
    verify = (artifacts / "git-history-cleanup-verify.txt").read_text(encoding="utf-8")
    assert f"original_base_commit={base_commit}" in verify
    assert f"head={snapshot_commit}" in verify
    assert "reachable_commit_count=1" in verify
    assert "original_base_commit_unreachable=yes" in verify
    assert "remote_refs:\nheads:" in verify


def test_runtime_config_disables_codex_web_search(tmp_path: Path) -> None:
    runner = load_container_runner()
    auth_dir = tmp_path / "auth"
    auth_dir.mkdir()
    (auth_dir / "config.toml").write_text('model = "gpt-5.5"\nweb_search = "live"\n', encoding="utf-8")
    paths = runner.RunPaths(
        root=tmp_path,
        private=tmp_path / "private",
        build=tmp_path / "build",
        attempt=tmp_path / "attempt",
        attempt_input=tmp_path / "attempt" / "input",
        attempt_output=tmp_path / "attempt" / "output",
        artifacts=tmp_path / "attempt" / "output" / "artifacts",
        rollouts=tmp_path / "rollouts",
        scoring=tmp_path / "scoring",
    )
    for path in paths.__dict__.values():
        path.mkdir(parents=True, exist_ok=True)

    runtime_config = runner.prepare_codex_runtime_config(auth_dir, paths)

    text = runtime_config.read_text(encoding="utf-8")
    assert 'web_search = "disabled"' in text
    assert 'web_search = "live"' not in text
