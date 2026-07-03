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
    changed_project_config_fields,
    ensure_runtime_state_initialized,
    load_project_config,
    project_config_path,
    save_project_config,
    sync_runtime_config_fields,
)
from supervisor.schemas import SentinelConfig
from supervisor.state import CONFIG, PROGRESS, StateStore


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
    assert project_config_path(tmp_path) == tmp_path.resolve() / ".supervisor" / "config.json"
    assert not (tmp_path / ".sentinel").exists()


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
    assert payload["task_path"] == "TASK.md"
    assert payload["protected_paths"] == ["hidden"]
    assert payload["fast"] is True
    assert payload["clean"] is True
    assert "protected_path" not in payload
    assert "speed" not in payload


def test_project_config_loads_runtime_config_shape(tmp_path: Path) -> None:
    store = StateStore(tmp_path)
    store.write_json_locked(
        CONFIG,
        SentinelConfig(
            project_root=str(tmp_path),
            task_path="TASK.md",
            coder_model="gpt-coder",
            supervisor_model="gpt-supervisor",
            coder_intelligence="low",
            supervisor_intelligence="high",
            fast=True,
            start_over=False,
            clean=True,
            protected_paths=["hidden"],
            adversary=False,
            max_adversary_runs=0,
        ),
    )

    config = load_project_config(tmp_path)

    assert config.task == "TASK.md"
    assert config.coder_mod == "gpt-coder"
    assert config.super_mod == "gpt-supervisor"
    assert config.coder_intelligence == "low"
    assert config.super_intelligence == "high"
    assert config.speed == "fast"
    assert config.start_over is False
    assert config.clean is True
    assert config.protected_path == ("hidden",)
    assert config.adversary is False


def test_config_initializes_supervisor_state_when_missing(tmp_path: Path) -> None:
    config = ProjectConfig(speed="fast", adversary=False)

    ensure_runtime_state_initialized(tmp_path, config)

    store = StateStore(tmp_path)
    assert store.path(CONFIG).exists()
    assert store.path(PROGRESS).exists()
    runtime_config = store.get_sentinel_config()
    assert runtime_config.project_root == str(tmp_path.resolve())
    assert runtime_config.task_path == ""
    assert runtime_config.fast is True
    assert runtime_config.adversary is False
    assert runtime_config.max_adversary_runs == 0


def test_config_does_not_touch_existing_supervisor_state_by_default(tmp_path: Path) -> None:
    store = StateStore(tmp_path)
    existing = SentinelConfig(
        project_root=str(tmp_path),
        task_path="TASK.md",
        generation=3,
        coder_thread_id="thread",
        coder_model="runtime-coder",
    )
    store.write_json_locked(CONFIG, existing)

    ensure_runtime_state_initialized(tmp_path, ProjectConfig(coder_mod="config-coder"))

    runtime_config = store.get_sentinel_config()
    assert runtime_config.generation == 3
    assert runtime_config.coder_thread_id == "thread"
    assert runtime_config.coder_model == "runtime-coder"


def test_config_change_patches_only_changed_runtime_fields(tmp_path: Path) -> None:
    store = StateStore(tmp_path)
    store.write_json_locked(
        CONFIG,
        SentinelConfig(
            project_root=str(tmp_path),
            task_path="TASK.md",
            generation=4,
            coder_thread_id="thread",
            coder_model="runtime-coder",
            supervisor_model="runtime-super",
            fast=False,
            clean=False,
        ),
    )

    sync_runtime_config_fields(
        tmp_path,
        ProjectConfig(coder_mod="config-coder", super_mod="config-super", speed="fast", clean=True),
        ("speed",),
    )

    runtime_config = store.get_sentinel_config()
    assert runtime_config.generation == 4
    assert runtime_config.coder_thread_id == "thread"
    assert runtime_config.coder_model == "runtime-coder"
    assert runtime_config.supervisor_model == "runtime-super"
    assert runtime_config.fast is True
    assert runtime_config.clean is False


def test_changed_project_config_fields_tracks_actual_changes() -> None:
    before = ProjectConfig(speed="usual", clean=False)
    after = ProjectConfig(speed="fast", clean=False)

    assert changed_project_config_fields(before, after) == ("speed",)


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
