from __future__ import annotations

from click.testing import CliRunner

from supervisor.controller import DEFAULT_MODEL, SentinelController
from supervisor.main import _resolve_model_flags, cli


def test_model_flags_default_to_gpt_55() -> None:
    assert _resolve_model_flags(model=None, coder_model=None, supervisor_model=None) == (
        DEFAULT_MODEL,
        DEFAULT_MODEL,
    )


def test_model_flag_sets_both_roles() -> None:
    assert _resolve_model_flags(model="gpt-custom", coder_model=None, supervisor_model=None) == (
        "gpt-custom",
        "gpt-custom",
    )


def test_split_model_flags_must_be_paired() -> None:
    result = CliRunner().invoke(cli, ["--coder-mod", "gpt-5.5"])

    assert result.exit_code != 0
    assert "--coder-mod and --super-mod must be used together" in result.output


def test_split_model_flags_conflict_with_shared_model() -> None:
    result = CliRunner().invoke(
        cli,
        ["--model", "gpt-5.5", "--coder-mod", "gpt-5.5", "--super-mod", "gpt-5.5"],
    )

    assert result.exit_code != 0
    assert "--model cannot be combined with --coder-mod or --super-mod" in result.output


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
