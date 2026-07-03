from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from supervisor.config_editor import EditorState, available_model_choices, move_down, parameter_defs, select_current
from supervisor.main import cli
from supervisor.project_config import (
    DEFAULT_INTELLIGENCE,
    DEFAULT_MODEL,
    ProjectConfig,
    ProjectConfigError,
    load_project_config,
    project_config_path,
    save_project_config,
)


def test_first_load_creates_default_project_config(tmp_path: Path) -> None:
    config = load_project_config(tmp_path)

    assert config.coder_mod == DEFAULT_MODEL
    assert config.super_mod == DEFAULT_MODEL
    assert config.coder_intelligence == DEFAULT_INTELLIGENCE
    assert config.super_intelligence == DEFAULT_INTELLIGENCE
    assert config.start_over is True
    assert config.adversary is True
    assert config.clean is False
    assert config.task is None
    assert config.protected_path == ()
    assert project_config_path(tmp_path).exists()


def test_project_config_missing_fields_are_defaulted(tmp_path: Path) -> None:
    path = project_config_path(tmp_path)
    path.parent.mkdir()
    path.write_text(json.dumps({"coder_mod": "gpt-coder"}), encoding="utf-8")

    config = load_project_config(tmp_path)

    assert config.coder_mod == "gpt-coder"
    assert config.super_mod == DEFAULT_MODEL
    assert config.start_over is True


def test_project_config_invalid_json_reports_path(tmp_path: Path) -> None:
    path = project_config_path(tmp_path)
    path.parent.mkdir()
    path.write_text("{", encoding="utf-8")

    with pytest.raises(ProjectConfigError, match="invalid Sentinel config JSON"):
        load_project_config(tmp_path)


def test_project_config_save_shape(tmp_path: Path) -> None:
    save_project_config(
        tmp_path,
        ProjectConfig(task="TASK.md", protected_path=("hidden",), speed="fast", clean=True),
    )

    payload = json.loads(project_config_path(tmp_path).read_text(encoding="utf-8"))
    assert payload["task"] == "TASK.md"
    assert payload["protected_path"] == ["hidden"]
    assert payload["speed"] == "fast"
    assert payload["clean"] is True


def test_config_editor_state_expands_selects_and_advances() -> None:
    config = ProjectConfig()
    params = parameter_defs(config)
    speed_index = [param.key for param in params].index("speed")
    state = EditorState(parameter_index=speed_index)

    config, state, action = select_current(config, state)
    assert action is None
    assert state.expanded_index == speed_index
    assert state.option_index is None

    state = move_down(state, parameter_defs(config))
    config, state, action = select_current(config, state)

    assert action is None
    assert config.speed == "usual"
    assert state.parameter_index == speed_index + 1
    assert state.expanded_index is None


def test_config_editor_choice_can_update_boolean() -> None:
    config = ProjectConfig()
    params = parameter_defs(config)
    clean_index = [param.key for param in params].index("clean")
    state = EditorState(parameter_index=clean_index, expanded_index=clean_index)
    state = replace(state, option_index=1)

    config, state, action = select_current(config, state)

    assert action is None
    assert config.clean is True
    assert state.parameter_index == clean_index + 1


def test_config_editor_model_choices_come_from_available_models() -> None:
    config = ProjectConfig(coder_mod="gpt-5.4", super_mod="gpt-5.3-codex-spark")
    params = parameter_defs(config, model_choices=("gpt-5.4-mini", "gpt-5.4"))
    coder_param = next(param for param in params if param.key == "coder_mod")
    super_param = next(param for param in params if param.key == "super_mod")

    assert [option.label for option in coder_param.options] == [
        "gpt-5.5",
        "gpt-5.4-mini",
        "gpt-5.4",
        "gpt-5.3-codex-spark",
    ]
    assert [option.label for option in super_param.options] == [
        "gpt-5.5",
        "gpt-5.4-mini",
        "gpt-5.4",
        "gpt-5.3-codex-spark",
    ]
    assert all(option.action is None for option in coder_param.options)


def test_available_model_choices_falls_back_to_codex_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("supervisor.config_editor._available_models_from_app_server", lambda project_root: ())
    monkeypatch.setenv("HOME", str(tmp_path))
    cache = tmp_path / ".codex" / "models_cache.json"
    cache.parent.mkdir()
    cache.write_text(
        json.dumps(
            {
                "models": [
                    {"slug": "gpt-5.4", "visibility": "list"},
                    {"slug": "gpt-5.5", "visibility": "list"},
                    {"slug": "hidden-model", "visibility": "hidden"},
                    {"slug": "gpt-5.3-codex-spark", "visibility": "list"},
                ]
            }
        ),
        encoding="utf-8",
    )

    assert available_model_choices(tmp_path) == ("gpt-5.5", "gpt-5.4", "gpt-5.3-codex-spark")


def test_config_command_invokes_editor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("supervisor.main.run_config_editor", lambda project_root: ProjectConfig(coder_mod="gpt-coder"))

    result = CliRunner().invoke(cli, ["config"])

    assert result.exit_code == 0
    assert "Saved Sentinel config:" in result.output
    assert "coder-mod: gpt-coder" in result.output
