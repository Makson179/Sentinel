from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import supervisor.workspace_snapshot as workspace_snapshot_module
from supervisor.workspace_snapshot import (
    SnapshotPatchError,
    WorkspaceSnapshotError,
    apply_snapshot_patch,
    create_workspace_snapshot,
)


def _init_repo(root: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=Test",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "baseline",
        ],
        cwd=root,
        check=True,
    )


def test_snapshot_patch_applies_after_accept_and_real_repo_is_unchanged_beforehand(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    _init_repo(tmp_path)

    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        (snapshot.snapshot_root / "app.py").write_text("value = 2\n", encoding="utf-8")
        (snapshot.snapshot_root / "new.txt").write_text("created\n", encoding="utf-8")

        assert source.read_text(encoding="utf-8") == "value = 1\n"
        assert not (tmp_path / "new.txt").exists()

        result = apply_snapshot_patch(snapshot)

        assert result.applied is True
        assert set(result.changed_paths) == {"app.py", "new.txt"}
        assert source.read_text(encoding="utf-8") == "value = 2\n"
        assert (tmp_path / "new.txt").read_text(encoding="utf-8") == "created\n"
    finally:
        snapshot.cleanup()


def test_snapshot_patch_applies_binary_files(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    binary = tmp_path / "asset.bin"
    binary.write_bytes(b"\x00old\xff")
    _init_repo(tmp_path)

    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        (snapshot.snapshot_root / "asset.bin").write_bytes(b"\x00new\xfe")
        (snapshot.snapshot_root / "new.bin").write_bytes(b"\x89PNG\r\n\x1a\n")

        result = apply_snapshot_patch(snapshot)

        assert result.applied is True
        assert binary.read_bytes() == b"\x00new\xfe"
        assert (tmp_path / "new.bin").read_bytes() == b"\x89PNG\r\n\x1a\n"
    finally:
        snapshot.cleanup()


def test_snapshot_patch_preserves_compiled_deliverables_and_filters_only_caches(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    source = tmp_path / "executor.c"
    source.write_text("int value(void) { return 1; }\n", encoding="utf-8")
    tracked_cache = tmp_path / "tests" / "public" / "__pycache__" / "test_public.cpython-312.pyc"
    tracked_cache.parent.mkdir(parents=True)
    tracked_cache.write_bytes(b"tracked-cache")
    _init_repo(tmp_path)

    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        (snapshot.snapshot_root / "executor.c").write_text("int value(void) { return 2; }\n", encoding="utf-8")
        generated_cache = snapshot.snapshot_root / "tests" / "public" / "__pycache__" / tracked_cache.name
        generated_cache.parent.mkdir(parents=True)
        generated_cache.write_bytes(b"generated-cache")
        (snapshot.snapshot_root / "executor.o").write_bytes(b"\x7fELF\x02\x01object")
        (snapshot.snapshot_root / "sql_database").write_bytes(b"\x7fELF\x02\x01binary")
        (snapshot.snapshot_root / ".pytest_cache").mkdir()
        (snapshot.snapshot_root / ".pytest_cache" / "README.md").write_text("cache\n", encoding="utf-8")

        result = apply_snapshot_patch(snapshot)

        assert result.applied is True
        assert set(result.changed_paths) == {"executor.c", "executor.o", "sql_database"}
        assert set(result.ignored_paths) == {
            ".pytest_cache/README.md",
            "tests/public/__pycache__/test_public.cpython-312.pyc",
        }
        assert source.read_text(encoding="utf-8") == "int value(void) { return 2; }\n"
        assert tracked_cache.read_bytes() == b"tracked-cache"
        assert (tmp_path / "executor.o").read_bytes() == b"\x7fELF\x02\x01object"
        assert (tmp_path / "sql_database").read_bytes() == b"\x7fELF\x02\x01binary"
        assert not (tmp_path / ".pytest_cache").exists()
    finally:
        snapshot.cleanup()


def test_snapshot_patch_keeps_object_deliverable_while_ignoring_cache(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    _init_repo(tmp_path)

    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        (snapshot.snapshot_root / "main.o").write_bytes(b"\x7fELF\x02\x01object")
        cache = snapshot.snapshot_root / "tests" / "__pycache__" / "slt_runner.cpython-312.pyc"
        cache.parent.mkdir(parents=True)
        cache.write_bytes(b"generated-cache")

        result = apply_snapshot_patch(snapshot)

        assert result.applied is True
        assert result.changed_paths == ("main.o",)
        assert result.ignored_paths == ("tests/__pycache__/slt_runner.cpython-312.pyc",)
        assert (tmp_path / "main.o").read_bytes() == b"\x7fELF\x02\x01object"
        assert not (tmp_path / "tests").exists()
    finally:
        snapshot.cleanup()


def test_snapshot_mounts_runtime_state_read_only_and_excludes_secret_files(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    (tmp_path / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    (tmp_path / ".supervisor").mkdir()
    (tmp_path / ".supervisor" / "CONFIG.json").write_text("{}", encoding="utf-8")
    handoff = tmp_path / ".supervisor" / "HANDOFF.md"
    handoff.write_text("initial handoff\n", encoding="utf-8")
    _init_repo(tmp_path)

    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        assert not (snapshot.snapshot_root / ".env").exists()
        assert (snapshot.snapshot_root / ".supervisor").is_symlink()
        assert (snapshot.snapshot_root / ".supervisor" / "CONFIG.json").read_text(encoding="utf-8") == "{}"
        handoff.write_text("updated handoff\n", encoding="utf-8")
        assert (snapshot.snapshot_root / ".supervisor" / "HANDOFF.md").read_text(encoding="utf-8") == (
            "updated handoff\n"
        )
        assert snapshot.task_path.is_symlink()
        assert snapshot.task_path.resolve() == task.resolve()
        assert (snapshot.snapshot_root / ".git").is_dir()
    finally:
        snapshot.cleanup()


@pytest.mark.parametrize("directory", [".supervisor", ".venv", "venv", "node_modules", ".pytest_cache"])
def test_snapshot_rejects_task_inside_runtime_cache_or_dependency_directory(
    tmp_path: Path,
    directory: str,
) -> None:
    task = tmp_path / directory / "TASK.md"
    task.parent.mkdir(parents=True)
    task.write_text("# Task\n", encoding="utf-8")

    with pytest.raises(WorkspaceSnapshotError, match="task path cannot be inside"):
        create_workspace_snapshot(tmp_path, task)


def test_snapshot_patch_rejects_secret_pattern_paths(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    _init_repo(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        (snapshot.snapshot_root / ".env").write_text("TOKEN=new\n", encoding="utf-8")

        with pytest.raises(SnapshotPatchError, match="secret-pattern"):
            apply_snapshot_patch(snapshot)

        assert not (tmp_path / ".env").exists()
    finally:
        snapshot.cleanup()


def test_snapshot_patch_rejects_declared_protected_paths(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    _init_repo(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, task, declared_grading_roots=("hidden",))
    try:
        protected = snapshot.snapshot_root / "hidden"
        protected.mkdir()
        (protected / "answer.txt").write_text("private\n", encoding="utf-8")

        with pytest.raises(SnapshotPatchError, match="declared grading/hidden path access denied"):
            apply_snapshot_patch(snapshot)

        assert not (tmp_path / "hidden").exists()
    finally:
        snapshot.cleanup()


def test_snapshot_patch_rejects_escaping_symlink(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    _init_repo(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        os.symlink("/etc/passwd", snapshot.snapshot_root / "outside-link")

        with pytest.raises(SnapshotPatchError, match="absolute symlink"):
            apply_snapshot_patch(snapshot)

        assert not (tmp_path / "outside-link").exists()
    finally:
        snapshot.cleanup()


def test_snapshot_patch_rejects_task_file_replacement(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("STRICT TASK\n", encoding="utf-8")
    _init_repo(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        snapshot.task_path.unlink()
        snapshot.task_path.write_text("WEAK TASK\n", encoding="utf-8")

        with pytest.raises(SnapshotPatchError, match="task file is immutable"):
            apply_snapshot_patch(snapshot)

        assert task.read_text(encoding="utf-8") == "STRICT TASK\n"
    finally:
        snapshot.cleanup()


def test_snapshot_patch_rejects_absolute_symlink_into_snapshot(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    _init_repo(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        os.symlink(str(snapshot.snapshot_root / "app.py"), snapshot.snapshot_root / "absolute-link")

        with pytest.raises(SnapshotPatchError, match="absolute symlink"):
            apply_snapshot_patch(snapshot)

        assert not (tmp_path / "absolute-link").exists()
    finally:
        snapshot.cleanup()


def test_snapshot_patch_preserves_safe_relative_symlink(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    _init_repo(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        os.symlink("app.py", snapshot.snapshot_root / "app-link")

        result = apply_snapshot_patch(snapshot)

        assert result.changed_paths == ("app-link",)
        assert (tmp_path / "app-link").is_symlink()
        assert os.readlink(tmp_path / "app-link") == "app.py"
    finally:
        snapshot.cleanup()


def test_snapshot_excludes_preexisting_symlink_that_escapes_project(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    task = project / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    os.symlink(outside, project / "outside-absolute")
    os.symlink("../outside.txt", project / "outside-relative")
    _init_repo(project)

    snapshot = create_workspace_snapshot(project, task)
    try:
        for name in ("outside-absolute", "outside-relative"):
            assert not (snapshot.snapshot_root / name).exists()
            assert not (snapshot.snapshot_root / name).is_symlink()
        assert snapshot.excluded_external_symlink_paths == ("outside-absolute", "outside-relative")

        result = apply_snapshot_patch(snapshot)

        assert result.applied is False
        for name in ("outside-absolute", "outside-relative"):
            assert (project / name).is_symlink()
            assert (project / name).resolve() == outside
    finally:
        snapshot.cleanup()


def test_snapshot_rewrites_absolute_internal_symlink_without_changing_original(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    target = tmp_path / "data.txt"
    target.write_text("before\n", encoding="utf-8")
    link = tmp_path / "data-link"
    os.symlink(target, link)
    _init_repo(tmp_path)

    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        snapshot_link = snapshot.snapshot_root / "data-link"
        assert snapshot_link.is_symlink()
        assert not Path(os.readlink(snapshot_link)).is_absolute()
        assert snapshot_link.resolve() == snapshot.snapshot_root / "data.txt"
        assert os.readlink(link) == str(target)
        assert snapshot.rewritten_symlinks[0].path == "data-link"

        snapshot_link.write_text("after\n", encoding="utf-8")
        result = apply_snapshot_patch(snapshot)

        assert result.changed_paths == ("data.txt",)
        assert target.read_text(encoding="utf-8") == "after\n"
        assert os.readlink(link) == str(target)
    finally:
        snapshot.cleanup()


def test_snapshot_patch_can_replace_rewritten_absolute_internal_symlink(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    first = tmp_path / "first.txt"
    first.write_text("first\n", encoding="utf-8")
    second = tmp_path / "second.txt"
    second.write_text("second\n", encoding="utf-8")
    link = tmp_path / "selected"
    os.symlink(first, link)
    _init_repo(tmp_path)

    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        snapshot_link = snapshot.snapshot_root / "selected"
        snapshot_link.unlink()
        os.symlink("second.txt", snapshot_link)

        result = apply_snapshot_patch(snapshot)

        assert result.changed_paths == ("selected",)
        assert link.is_symlink()
        assert os.readlink(link) == "second.txt"
        assert link.resolve() == second
    finally:
        snapshot.cleanup()


def test_snapshot_patch_rollback_restores_original_absolute_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    first = tmp_path / "first.txt"
    first.write_text("first\n", encoding="utf-8")
    second = tmp_path / "second.txt"
    second.write_text("second\n", encoding="utf-8")
    link = tmp_path / "selected"
    os.symlink(first, link)
    _init_repo(tmp_path)

    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        snapshot_link = snapshot.snapshot_root / "selected"
        snapshot_link.unlink()
        os.symlink("second.txt", snapshot_link)

        def fail_verification(*_args, **_kwargs) -> None:
            raise SnapshotPatchError("forced verification failure")

        monkeypatch.setattr(workspace_snapshot_module, "_verify_applied_paths", fail_verification)

        with pytest.raises(SnapshotPatchError, match="forced verification failure"):
            apply_snapshot_patch(snapshot)

        assert link.is_symlink()
        assert os.readlink(link) == str(first)
        assert link.resolve() == first
    finally:
        snapshot.cleanup()


def test_snapshot_patch_preserves_executable_mode(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    _init_repo(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        executable = snapshot.snapshot_root / "tool"
        executable.write_bytes(b"\x7fELF\x02\x01deliverable")
        executable.chmod(0o755)

        apply_snapshot_patch(snapshot)

        assert (tmp_path / "tool").read_bytes() == b"\x7fELF\x02\x01deliverable"
        assert (tmp_path / "tool").stat().st_mode & 0o111 == 0o111
    finally:
        snapshot.cleanup()


def test_snapshot_preserves_git_history(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    _init_repo(tmp_path)
    source.write_text("value = 2\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=Test",
            "commit",
            "-q",
            "-m",
            "second",
        ],
        cwd=tmp_path,
        check=True,
    )

    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        count = subprocess.check_output(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=snapshot.snapshot_root,
            text=True,
        ).strip()
        assert int(count) == 3  # two source commits plus the isolated snapshot baseline
        assert subprocess.check_output(["git", "remote"], cwd=snapshot.snapshot_root, text=True) == ""
    finally:
        snapshot.cleanup()


def test_snapshot_patch_uses_frozen_baseline_after_coder_commit(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    _init_repo(tmp_path)

    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        (snapshot.snapshot_root / "app.py").write_text("value = 2\n", encoding="utf-8")
        subprocess.run(["git", "add", "app.py"], cwd=snapshot.snapshot_root, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.email=coder@example.com",
                "-c",
                "user.name=Coder",
                "commit",
                "-q",
                "-m",
                "coder commit",
            ],
            cwd=snapshot.snapshot_root,
            check=True,
        )

        result = apply_snapshot_patch(snapshot)

        assert result.changed_paths == ("app.py",)
        assert source.read_text(encoding="utf-8") == "value = 2\n"
    finally:
        snapshot.cleanup()


def test_snapshot_patch_restores_trusted_git_config_before_plumbing(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    _init_repo(tmp_path)

    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        subprocess.run(
            ["git", "config", "--local", "filter.untrusted.clean", "false"],
            cwd=snapshot.snapshot_root,
            check=True,
        )
        assert snapshot.git_control_is_trusted() is False
        assert snapshot.restore_git_control() is True
        assert snapshot.git_control_is_trusted() is True
        assert snapshot.restore_git_control() is False
        (snapshot.snapshot_root / "app.py").write_text("value = 2\n", encoding="utf-8")

        result = apply_snapshot_patch(snapshot)

        assert result.changed_paths == ("app.py",)
        assert source.read_text(encoding="utf-8") == "value = 2\n"
        assert "filter.untrusted.clean" not in (snapshot.snapshot_root / ".git" / "config").read_text(
            encoding="utf-8"
        )
    finally:
        snapshot.cleanup()


def test_snapshot_preserves_real_remote_instead_of_local_clone_source(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    _init_repo(tmp_path)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://example.com/project.git"],
        cwd=tmp_path,
        check=True,
    )

    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        remote = subprocess.check_output(
            ["git", "remote", "get-url", "origin"],
            cwd=snapshot.snapshot_root,
            text=True,
        ).strip()
        assert remote == "https://example.com/project.git"
        assert remote != str(tmp_path)
    finally:
        snapshot.cleanup()


def test_snapshot_git_plumbing_ignores_user_filters(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    attributes = tmp_path / ".gitattributes"
    attributes.write_text("*.dat filter=sentinel-test-filter\n", encoding="utf-8")
    data = tmp_path / "value.dat"
    data.write_text("baseline\n", encoding="utf-8")
    _init_repo(tmp_path)

    marker = tmp_path / "filter-ran"
    global_config = tmp_path / "malicious-git-config"
    global_config.write_text(
        "[filter \"sentinel-test-filter\"]\n"
        f"\tclean = sh -c 'touch {marker}; cat'\n"
        "\trequired = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        (snapshot.snapshot_root / "value.dat").write_text("changed\n", encoding="utf-8")
        apply_snapshot_patch(snapshot)

        assert data.read_text(encoding="utf-8") == "changed\n"
        assert not marker.exists()
    finally:
        snapshot.cleanup()


def test_snapshot_mounts_existing_dependencies_without_copying(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    dependency = tmp_path / ".venv" / "bin" / "tool"
    dependency.parent.mkdir(parents=True)
    dependency.write_text("dependency\n", encoding="utf-8")
    _init_repo(tmp_path)

    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        mounted = snapshot.snapshot_root / ".venv"
        assert mounted.is_symlink()
        assert (mounted / "bin" / "tool").read_text(encoding="utf-8") == "dependency\n"
        assert snapshot.readonly_dependency_paths == (".venv",)
    finally:
        snapshot.cleanup()


def test_snapshot_restores_replaced_runtime_links(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    state = tmp_path / ".supervisor"
    state.mkdir()
    (state / "HANDOFF.md").write_text("canonical\n", encoding="utf-8")
    dependency = tmp_path / ".venv" / "bin" / "tool"
    dependency.parent.mkdir(parents=True)
    dependency.write_text("dependency\n", encoding="utf-8")
    _init_repo(tmp_path)

    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        snapshot.task_path.unlink()
        snapshot.task_path.write_text("weakened\n", encoding="utf-8")
        (snapshot.snapshot_root / ".supervisor").unlink()
        (snapshot.snapshot_root / ".supervisor").mkdir()
        (snapshot.snapshot_root / ".supervisor" / "HANDOFF.md").write_text("forged\n", encoding="utf-8")
        (snapshot.snapshot_root / ".venv").unlink()
        (snapshot.snapshot_root / ".venv").mkdir()

        repaired = snapshot.restore_runtime_links()

        assert repaired == ("task", "supervisor_state", "dependency:.venv")
        assert snapshot.task_path.is_symlink()
        assert snapshot.task_path.read_text(encoding="utf-8") == "# Task\n"
        assert (snapshot.snapshot_root / ".supervisor" / "HANDOFF.md").read_text(encoding="utf-8") == "canonical\n"
        assert (snapshot.snapshot_root / ".venv" / "bin" / "tool").read_text(encoding="utf-8") == "dependency\n"
    finally:
        snapshot.cleanup()


def test_snapshot_runtime_link_repair_wraps_filesystem_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    _init_repo(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        snapshot.task_path.unlink()

        def fail_link(*_args, **_kwargs) -> None:
            raise PermissionError("repair denied")

        monkeypatch.setattr(workspace_snapshot_module, "_create_readonly_link", fail_link)

        with pytest.raises(WorkspaceSnapshotError, match="failed to restore.*repair denied"):
            snapshot.restore_runtime_links()
    finally:
        snapshot.cleanup()


def test_snapshot_runtime_link_repair_replaces_fifo(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO files are not supported on this platform")
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    _init_repo(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        snapshot.task_path.unlink()
        os.mkfifo(snapshot.task_path)

        assert snapshot.restore_runtime_links() == ("task",)
        assert snapshot.task_path.is_symlink()
        assert snapshot.task_path.read_text(encoding="utf-8") == "# Task\n"
    finally:
        snapshot.cleanup()


def test_snapshot_git_control_repair_replaces_fifo(tmp_path: Path) -> None:
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO files are not supported on this platform")
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    _init_repo(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        config = snapshot.snapshot_root / ".git" / "config"
        config.unlink()
        os.mkfifo(config)

        assert snapshot.git_control_is_trusted() is False
        assert snapshot.restore_git_control() is True
        assert snapshot.git_control_is_trusted() is True
    finally:
        snapshot.cleanup()


def test_snapshot_creation_wraps_temporary_directory_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")

    def fail_mkdtemp(*_args, **_kwargs):
        raise PermissionError("temporary directory denied")

    monkeypatch.setattr(workspace_snapshot_module.tempfile, "mkdtemp", fail_mkdtemp)

    with pytest.raises(WorkspaceSnapshotError, match="temporary workspace.*temporary directory denied"):
        create_workspace_snapshot(tmp_path, task)


def test_snapshot_patch_wraps_filesystem_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    _init_repo(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        def fail_git_config(*_args, **_kwargs) -> None:
            raise PermissionError("config denied")

        monkeypatch.setattr(workspace_snapshot_module, "_restore_trusted_snapshot_git_config", fail_git_config)

        with pytest.raises(SnapshotPatchError, match="filesystem operation failed.*config denied"):
            apply_snapshot_patch(snapshot)
    finally:
        snapshot.cleanup()


def test_snapshot_patch_rolls_back_when_post_apply_verification_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    _init_repo(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        (snapshot.snapshot_root / "app.py").write_text("value = 2\n", encoding="utf-8")

        def fail_verification(*_args, **_kwargs) -> None:
            raise SnapshotPatchError("forced verification failure")

        monkeypatch.setattr(workspace_snapshot_module, "_verify_applied_paths", fail_verification)

        with pytest.raises(SnapshotPatchError, match="forced verification failure"):
            apply_snapshot_patch(snapshot)

        assert source.read_text(encoding="utf-8") == "value = 1\n"
    finally:
        snapshot.cleanup()


def test_snapshot_patch_rejects_real_workspace_conflict(tmp_path: Path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    _init_repo(tmp_path)
    snapshot = create_workspace_snapshot(tmp_path, task)
    try:
        (snapshot.snapshot_root / "app.py").write_text("value = 2\n", encoding="utf-8")
        source.write_text("value = 3\n", encoding="utf-8")

        with pytest.raises(SnapshotPatchError, match="does not apply cleanly"):
            apply_snapshot_patch(snapshot)

        assert source.read_text(encoding="utf-8") == "value = 3\n"
    finally:
        snapshot.cleanup()
