from __future__ import annotations

import asyncio
import json

import pytest
from click.testing import CliRunner

from supervisor.controller import DEFAULT_MODEL, SentinelController
from supervisor.main import _resolve_run_settings, cli
from supervisor.project_config import (
    MODEL_GPT_5_5,
    MODEL_GPT_5_6_LUNA,
    MODEL_GPT_5_6_SOL,
    ProjectConfig,
    project_config_path,
)


def test_role_models_default_to_gpt_56_sol() -> None:
    settings = _resolve_run_settings(project_config=ProjectConfig())

    assert DEFAULT_MODEL == MODEL_GPT_5_6_SOL
    assert settings.coder_model == MODEL_GPT_5_6_SOL
    assert settings.runtime_model == MODEL_GPT_5_6_SOL
    assert settings.completion_model == MODEL_GPT_5_6_SOL
    assert settings.adversary_model == MODEL_GPT_5_6_SOL


def test_shared_model_flag_is_not_registered() -> None:
    result = CliRunner().invoke(cli, ["--model", "gpt-custom"])

    assert result.exit_code != 0
    assert "No such option" in result.output
    assert "--model" in result.output


def test_four_role_flags_are_registered() -> None:
    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    for option in (
        "--coder-mod",
        "--runtime-mod",
        "--completion-mod",
        "--adversary-mod",
        "--coder-intelligence",
        "--runtime-intelligence",
        "--completion-intelligence",
        "--adversary-intelligence",
    ):
        assert option in result.output


def test_cli_passes_independent_role_models_and_efforts_to_runner(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    captured = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("supervisor.main._startup_update_gate", lambda: None)

    async def fake_run_sentinel(settings):
        captured.append(settings)
        return 0

    def fake_run_async_cleanly(coro):
        assert asyncio.run(coro) == 0

    monkeypatch.setattr("supervisor.main._run_sentinel", fake_run_sentinel)
    monkeypatch.setattr("supervisor.main._run_async_cleanly", fake_run_async_cleanly)

    result = CliRunner().invoke(
        cli,
        [
            "--task",
            str(task),
            "--coder-mod",
            MODEL_GPT_5_6_SOL,
            "--runtime-mod",
            MODEL_GPT_5_5,
            "--completion-mod",
            MODEL_GPT_5_6_SOL,
            "--adversary-mod",
            MODEL_GPT_5_6_SOL,
            "--coder-intelligence",
            "ultra",
            "--runtime-intelligence",
            "xhigh",
            "--completion-intelligence",
            "ultra",
            "--adversary-intelligence",
            "ultra",
        ],
    )

    assert result.exit_code == 0
    assert len(captured) == 1
    settings = captured[0]
    assert settings.coder_model == MODEL_GPT_5_6_SOL
    assert settings.runtime_model == MODEL_GPT_5_5
    assert settings.completion_model == MODEL_GPT_5_6_SOL
    assert settings.adversary_model == MODEL_GPT_5_6_SOL
    assert settings.coder_intelligence == "ultra"
    assert settings.runtime_intelligence == "xhigh"
    assert settings.completion_intelligence == "ultra"
    assert settings.adversary_intelligence == "ultra"


def test_legacy_super_flags_set_both_supervisor_roles() -> None:
    settings = _resolve_run_settings(
        project_config=ProjectConfig(),
        legacy_supervisor_model=MODEL_GPT_5_5,
        legacy_supervisor_intelligence="high",
    )

    assert settings.runtime_model == MODEL_GPT_5_5
    assert settings.completion_model == MODEL_GPT_5_5
    assert settings.runtime_intelligence == "high"
    assert settings.completion_intelligence == "high"
    assert settings.coder_model == MODEL_GPT_5_6_SOL
    assert settings.adversary_model == MODEL_GPT_5_6_SOL


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"legacy_supervisor_model": MODEL_GPT_5_5, "completion_model": MODEL_GPT_5_6_SOL},
            "--super-mod cannot be combined",
        ),
        (
            {"legacy_supervisor_intelligence": "high", "runtime_intelligence": "xhigh"},
            "--super-intelligence cannot be combined",
        ),
    ],
)
def test_legacy_super_flags_reject_ambiguous_modern_overrides(overrides: dict[str, str], message: str) -> None:
    with pytest.raises(RuntimeError, match=message):
        _resolve_run_settings(project_config=ProjectConfig(), **overrides)


def test_run_settings_use_independent_project_config_defaults() -> None:
    settings = _resolve_run_settings(
        project_config=ProjectConfig(
            coder_mod="gpt-coder",
            runtime_mod="gpt-runtime",
            completion_mod="gpt-completion",
            adversary_mod="gpt-adversary",
            coder_intelligence="low",
            runtime_intelligence="medium",
            completion_intelligence="high",
            adversary_intelligence="xhigh",
            speed="fast",
        )
    )

    assert settings.coder_model == "gpt-coder"
    assert settings.runtime_model == "gpt-runtime"
    assert settings.completion_model == "gpt-completion"
    assert settings.adversary_model == "gpt-adversary"
    assert settings.coder_intelligence == "low"
    assert settings.runtime_intelligence == "medium"
    assert settings.completion_intelligence == "high"
    assert settings.adversary_intelligence == "xhigh"
    assert settings.fast is True


def test_run_settings_accept_ultra_independently_for_gpt_56_sol() -> None:
    settings = _resolve_run_settings(
        project_config=ProjectConfig(
            coder_intelligence="ultra",
            runtime_intelligence="xhigh",
            completion_intelligence="ultra",
            adversary_intelligence="ultra",
        )
    )

    assert settings.coder_intelligence == "ultra"
    assert settings.runtime_intelligence == "xhigh"
    assert settings.completion_intelligence == "ultra"
    assert settings.adversary_intelligence == "ultra"


@pytest.mark.parametrize("role", ["coder", "runtime", "completion", "adversary"])
def test_run_settings_reject_ultra_for_luna_per_role(role: str) -> None:
    model_overrides = {f"{role}_model": MODEL_GPT_5_6_LUNA}
    effort_overrides = {f"{role}_intelligence": "ultra"}

    with pytest.raises(RuntimeError, match=rf"{role} model .* does not support reasoning effort ultra"):
        _resolve_run_settings(
            project_config=ProjectConfig(),
            **model_overrides,
            **effort_overrides,
        )


def test_run_settings_cli_values_override_each_role_for_current_run(tmp_path) -> None:
    task = tmp_path / "TASK.md"
    settings = _resolve_run_settings(
        project_config=ProjectConfig(
            task="CONFIG_TASK.md",
            coder_mod="config-coder",
            runtime_mod="config-runtime",
            completion_mod="config-completion",
            adversary_mod="config-adversary",
            speed="fast",
            start_over=True,
            adversary=True,
            clean=True,
            protected_path=("hidden",),
        ),
        task_path=task,
        coder_model="cli-coder",
        runtime_model="cli-runtime",
        completion_model="cli-completion",
        adversary_model="cli-adversary",
        coder_intelligence="low",
        runtime_intelligence="medium",
        completion_intelligence="high",
        adversary_intelligence="xhigh",
        fast=False,
        start_over=False,
        protected_paths=(tmp_path / "secret",),
        clean=False,
        adversary=False,
    )

    assert settings.task_path == task
    assert settings.coder_model == "cli-coder"
    assert settings.runtime_model == "cli-runtime"
    assert settings.completion_model == "cli-completion"
    assert settings.adversary_model == "cli-adversary"
    assert settings.coder_intelligence == "low"
    assert settings.runtime_intelligence == "medium"
    assert settings.completion_intelligence == "high"
    assert settings.adversary_intelligence == "xhigh"
    assert settings.fast is False
    assert settings.start_over is False
    assert settings.clean is False
    assert settings.adversary is False
    assert settings.protected_paths == (tmp_path / "secret",)


def test_controller_records_four_role_models_and_efforts(tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    controller = SentinelController(
        tmp_path,
        task_path=task,
        coder_model="gpt-coder",
        runtime_model="gpt-runtime",
        completion_model="gpt-completion",
        adversary_model="gpt-adversary",
        coder_intelligence="low",
        runtime_intelligence="medium",
        completion_intelligence="high",
        adversary_intelligence="xhigh",
    )

    controller.initialize_state()

    config = controller.store.get_sentinel_config()
    assert config.model is None
    assert config.coder_model == "gpt-coder"
    assert config.runtime_model == "gpt-runtime"
    assert config.completion_model == "gpt-completion"
    assert config.adversary_model == "gpt-adversary"
    assert config.supervisor_model == "gpt-runtime"
    assert config.coder_intelligence == "low"
    assert config.runtime_intelligence == "medium"
    assert config.completion_intelligence == "high"
    assert config.adversary_intelligence == "xhigh"
    assert config.supervisor_intelligence == "medium"


def test_controller_records_fast_mode(tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    controller = SentinelController(tmp_path, task_path=task, fast=True)

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


def test_controller_runtime_settings_summary_uses_all_effective_role_values(tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    controller = SentinelController(
        tmp_path,
        task_path=task,
        coder_model="cli-coder",
        runtime_model="cli-runtime",
        completion_model="cli-completion",
        adversary_model="cli-adversary",
        coder_intelligence="ultra",
        runtime_intelligence="xhigh",
        completion_intelligence="ultra",
        adversary_intelligence="ultra",
        fast=True,
        overwrite_state=False,
        adversary_enabled=False,
        declared_grading_roots=(tmp_path / "hidden",),
    )

    assert controller._runtime_settings_summary() == (
        "settings: task=TASK.md "
        "coder-mod=cli-coder "
        "runtime-mod=cli-runtime "
        "completion-mod=cli-completion "
        "adversary-mod=cli-adversary "
        "coder-intelligence=ultra "
        "runtime-intelligence=xhigh "
        "completion-intelligence=ultra "
        "adversary-intelligence=ultra "
        "speed=fast "
        "start-over=false "
        "clean=false "
        "completion-review=true "
        "adversary=false "
        "protected-path=hidden"
    )


def test_controller_runtime_overrides_do_not_rewrite_project_config_fields(tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    project_config = ProjectConfig(
        task="CONFIG_TASK.md",
        coder_mod="config-coder",
        runtime_mod="config-runtime",
        completion_mod="config-completion",
        adversary_mod="config-adversary",
        coder_intelligence="low",
        runtime_intelligence="medium",
        completion_intelligence="high",
        adversary_intelligence="xhigh",
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
        runtime_model="cli-runtime",
        completion_model="cli-completion",
        adversary_model="cli-adversary",
        project_config=project_config,
    )

    controller.initialize_state()

    payload = json.loads(project_config_path(tmp_path).read_text(encoding="utf-8"))
    assert payload["coder_mod"] == "config-coder"
    assert payload["runtime_mod"] == "config-runtime"
    assert payload["completion_mod"] == "config-completion"
    assert payload["adversary_mod"] == "config-adversary"
    assert payload["super_mod"] == "config-runtime"
    assert payload["coder_intelligence"] == "low"
    assert payload["runtime_intelligence"] == "medium"
    assert payload["completion_intelligence"] == "high"
    assert payload["adversary_intelligence"] == "xhigh"
    assert payload["super_intelligence"] == "medium"
    assert payload["coder_model"] == "config-coder"
    assert payload["runtime_model"] == "config-runtime"
    assert payload["completion_model"] == "config-completion"
    assert payload["adversary_model"] == "config-adversary"
    assert payload["supervisor_model"] == "config-runtime"
    assert payload["supervisor_intelligence"] == "medium"


def test_fast_true_override_does_not_rewrite_saved_fast_field(tmp_path) -> None:
    task = tmp_path / "TASK.md"
    task.write_text("# Task\n", encoding="utf-8")
    project_config = ProjectConfig(speed="usual")
    controller = SentinelController(tmp_path, task_path=task, fast=True, project_config=project_config)

    controller.initialize_state()

    payload = json.loads(project_config_path(tmp_path).read_text(encoding="utf-8"))
    assert payload["speed"] == "usual"
    assert payload["fast"] is False
    assert controller._fast_mode() is True


def _resolve(project_config: ProjectConfig, **overrides):
    return _resolve_run_settings(project_config=project_config, **overrides)


def test_adversary_runs_defaults_to_project_config() -> None:
    settings = _resolve(ProjectConfig())
    assert settings.adversary is True
    assert settings.adversary_runs == 1


def test_adversary_runs_cli_override_implies_enabled() -> None:
    settings = _resolve(ProjectConfig(adversary=False), adversary_runs=3)
    assert settings.adversary is True
    assert settings.adversary_runs == 3


def test_adversary_runs_zero_implies_disabled() -> None:
    settings = _resolve(ProjectConfig(), adversary_runs=0)
    assert settings.adversary is False
    assert settings.adversary_runs == 0


def test_explicit_adversary_flag_wins_over_runs() -> None:
    settings = _resolve(ProjectConfig(), adversary=False, adversary_runs=2)
    assert settings.adversary is False
    assert settings.adversary_runs == 2
