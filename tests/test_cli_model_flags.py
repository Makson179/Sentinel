from __future__ import annotations

import json

from click.testing import CliRunner

from supervisor.controller import DEFAULT_MODEL, SentinelController
from supervisor.main import _resolve_model_flags, _resolve_run_settings, cli
from supervisor.project_config import DEFAULT_INTELLIGENCE, ProjectConfig, project_config_path


def test_model_flags_default_to_gpt_55() -> None:
    assert _resolve_model_flags(coder_model=None, supervisor_model=None) == (
        DEFAULT_MODEL,
        DEFAULT_MODEL,
    )


def test_model_flag_is_not_registered() -> None:
    result = CliRunner().invoke(cli, ["--model", "gpt-custom"])

    assert result.exit_code != 0
    assert "No such option '--model'" in result.output


def test_split_model_flags_must_be_paired() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ["--coder-mod", "gpt-5.5"])

    assert result.exit_code != 0
    assert "--coder-mod and --super-mod must be used together" in result.output


def test_split_model_flags_conflict_with_shared_model() -> None:
    assert _resolve_model_flags(
        coder_model=None,
        supervisor_model=None,
        default_coder_model="gpt-coder",
        default_supervisor_model="gpt-supervisor",
    ) == ("gpt-coder", "gpt-supervisor")


def test_run_settings_use_project_config_defaults() -> None:
    settings = _resolve_run_settings(
        project_config=ProjectConfig(coder_mod="gpt-coder", super_mod="gpt-super", speed="fast"),
        task_path=None,
        coder_model=None,
        supervisor_model=None,
        coder_intelligence=None,
        supervisor_intelligence=None,
        fast=None,
        start_over=None,
        protected_paths=(),
        clean=None,
        adversary=None,
    )

    assert settings.coder_model == "gpt-coder"
    assert settings.supervisor_model == "gpt-super"
    assert settings.coder_intelligence == DEFAULT_INTELLIGENCE
    assert settings.supervisor_intelligence == DEFAULT_INTELLIGENCE
    assert settings.fast is True
    assert settings.start_over is True
    assert settings.adversary is True


def test_run_settings_cli_values_override_config_for_current_run(tmp_path) -> None:
    task = tmp_path / "TASK.md"
    settings = _resolve_run_settings(
        project_config=ProjectConfig(
            task="CONFIG_TASK.md",
            coder_mod="config-coder",
            super_mod="config-super",
            coder_intelligence="low",
            super_intelligence="medium",
            speed="fast",
            start_over=True,
            adversary=True,
            clean=True,
            protected_path=("hidden",),
        ),
        task_path=task,
        coder_model="cli-coder",
        supervisor_model="cli-super",
        coder_intelligence="high",
        supervisor_intelligence="xhigh",
        fast=False,
        start_over=False,
        protected_paths=(tmp_path / "secret",),
        clean=False,
        adversary=False,
    )

    assert settings.task_path == task
    assert settings.coder_model == "cli-coder"
    assert settings.supervisor_model == "cli-super"
    assert settings.coder_intelligence == "high"
    assert settings.supervisor_intelligence == "xhigh"
    assert settings.fast is False
    assert settings.start_over is False
    assert settings.clean is False
    assert settings.adversary is False
    assert settings.protected_paths == (tmp_path / "secret",)


def test_controller_records_split_models(tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")

    controller = SentinelController(
        tmp_path,
        task_path=task,
        coder_model="gpt-coder",
        supervisor_model="gpt-supervisor",
    )
    controller.initialize_state()

    config = controller.store.get_sentinel_config()
    assert config.model is None
    assert config.coder_model == "gpt-coder"
    assert config.supervisor_model == "gpt-supervisor"


def test_controller_records_intelligence(tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")

    controller = SentinelController(
        tmp_path,
        task_path=task,
        coder_intelligence="low",
        supervisor_intelligence="high",
    )
    controller.initialize_state()

    config = controller.store.get_sentinel_config()
    assert config.coder_intelligence == "low"
    assert config.supervisor_intelligence == "high"


def test_controller_records_fast_mode(tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")

    controller = SentinelController(
        tmp_path,
        task_path=task,
        coder_model="gpt-coder",
        supervisor_model="gpt-supervisor",
        fast=True,
    )
    controller.initialize_state()

    assert controller.store.get_sentinel_config().fast is True


def test_controller_records_runtime_config_flags(tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    protected_path = tmp_path / "hidden"

    controller = SentinelController(
        tmp_path,
        task_path=task,
        clean_workspace=True,
        overwrite_state=False,
        adversary_enabled=False,
        declared_grading_roots=(protected_path,),
    )
    controller.initialize_state()

    config = controller.store.get_sentinel_config()
    assert config.start_over is False
    assert config.clean is True
    assert config.protected_paths == ["hidden"]
    assert config.adversary is False
    assert config.max_adversary_runs == 0


def test_controller_runtime_settings_summary_uses_effective_values(tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    protected_path = tmp_path / "hidden"

    controller = SentinelController(
        tmp_path,
        task_path=task,
        coder_model="cli-coder",
        supervisor_model="cli-supervisor",
        coder_intelligence="high",
        supervisor_intelligence="xhigh",
        fast=True,
        overwrite_state=False,
        clean_workspace=False,
        adversary_enabled=False,
        declared_grading_roots=(protected_path,),
    )

    assert controller._runtime_settings_summary() == (
        "settings: task=TASK.md "
        "coder-mod=cli-coder "
        "super-mod=cli-supervisor "
        "coder-intelligence=high "
        "super-intelligence=xhigh "
        "speed=fast "
        "start-over=false "
        "clean=false "
        "adversary=false "
        "protected-path=hidden"
    )


def test_controller_runtime_overrides_do_not_rewrite_project_config_fields(tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    project_config = ProjectConfig(
        task="CONFIG_TASK.md",
        coder_mod="config-coder",
        super_mod="config-super",
        coder_intelligence="low",
        super_intelligence="medium",
        speed="fast",
        start_over=True,
        adversary=True,
        clean=True,
        protected_path=("hidden",),
    )

    controller = SentinelController(
        tmp_path,
        task_path=task,
        coder_model="cli-coder",
        supervisor_model="cli-super",
        coder_intelligence="high",
        supervisor_intelligence="xhigh",
        fast=False,
        overwrite_state=False,
        clean_workspace=False,
        adversary_enabled=False,
        declared_grading_roots=(tmp_path / "secret",),
        project_config=project_config,
    )
    controller.initialize_state()

    payload = json.loads(project_config_path(tmp_path).read_text(encoding="utf-8"))
    assert payload["task"] == "CONFIG_TASK.md"
    assert payload["coder_mod"] == "config-coder"
    assert payload["super_mod"] == "config-super"
    assert payload["coder_intelligence"] == "low"
    assert payload["super_intelligence"] == "medium"
    assert payload["speed"] == "fast"
    assert payload["start_over"] is True
    assert payload["adversary"] is True
    assert payload["clean"] is True
    assert payload["protected_path"] == ["hidden"]
    assert payload["task_path"] == "CONFIG_TASK.md"
    assert payload["coder_model"] == "config-coder"
    assert payload["supervisor_model"] == "config-super"
    assert payload["supervisor_intelligence"] == "medium"
    assert payload["fast"] is True
    assert payload["max_adversary_runs"] == 1
    assert payload["protected_paths"] == ["hidden"]


def test_fast_true_override_does_not_rewrite_saved_fast_field(tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    project_config = ProjectConfig(speed="usual")

    controller = SentinelController(
        tmp_path,
        task_path=task,
        fast=True,
        project_config=project_config,
    )
    controller.initialize_state()

    payload = json.loads(project_config_path(tmp_path).read_text(encoding="utf-8"))
    assert payload["speed"] == "usual"
    assert payload["fast"] is False
    assert controller._fast_mode() is True
