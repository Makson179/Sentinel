from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from supervisor.config_editor import EditorState, append_inline_text, available_model_choices, move_down, parameter_defs, select_current
from supervisor.main import cli
from supervisor.project_config import (
    DEFAULT_INTELLIGENCE,
    DEFAULT_MODEL,
    INTELLIGENCE_CHOICES,
    MODEL_GPT_5_5,
    MODEL_GPT_5_6_LUNA,
    MODEL_GPT_5_6_SOL,
    MODEL_GPT_5_6_TERRA,
    ProjectConfig,
    ProjectConfigError,
    changed_project_config_fields,
    ensure_runtime_state_initialized,
    intelligence_choices_for_model,
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
    assert config.runtime_mod == DEFAULT_MODEL
    assert config.completion_mod == DEFAULT_MODEL
    assert config.adversary_mod == DEFAULT_MODEL
    assert config.coder_intelligence == DEFAULT_INTELLIGENCE
    assert config.runtime_intelligence == DEFAULT_INTELLIGENCE
    assert config.completion_intelligence == DEFAULT_INTELLIGENCE
    assert config.adversary_intelligence == DEFAULT_INTELLIGENCE
    assert config.start_over is True
    assert config.adversary is True
    assert config.adversary_runs == 1
    assert config.completion_returns_per_generation == 10
    assert config.clean is False
    assert config.task is None
    assert config.protected_path == ()
    assert project_config_path(tmp_path).exists()
    assert project_config_path(tmp_path) == tmp_path.resolve() / ".supervisor" / "config.json"
    assert not (tmp_path / ".sentinel").exists()


def test_gpt_56_sol_is_default_and_reasoning_choices_are_model_specific() -> None:
    assert DEFAULT_MODEL == MODEL_GPT_5_6_SOL
    assert INTELLIGENCE_CHOICES == ("low", "medium", "high", "xhigh", "max", "ultra")
    assert intelligence_choices_for_model(MODEL_GPT_5_6_SOL) == INTELLIGENCE_CHOICES
    assert intelligence_choices_for_model(MODEL_GPT_5_6_TERRA) == INTELLIGENCE_CHOICES
    assert intelligence_choices_for_model(MODEL_GPT_5_6_LUNA) == ("low", "medium", "high", "xhigh", "max")
    assert intelligence_choices_for_model(MODEL_GPT_5_5) == ("low", "medium", "high", "xhigh")


def test_project_config_missing_fields_are_defaulted(tmp_path: Path) -> None:
    path = project_config_path(tmp_path)
    path.parent.mkdir()
    path.write_text(json.dumps({"coder_mod": "gpt-coder"}), encoding="utf-8")

    config = load_project_config(tmp_path)

    assert config.coder_mod == "gpt-coder"
    assert config.runtime_mod == DEFAULT_MODEL
    assert config.completion_mod == DEFAULT_MODEL
    assert config.adversary_mod == DEFAULT_MODEL
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
    assert payload["task_path"] == "TASK.md"
    assert payload["protected_path"] == ["hidden"]
    assert payload["protected_paths"] == ["hidden"]
    assert payload["speed"] == "fast"
    assert payload["fast"] is True
    assert payload["clean"] is True
    assert payload["max_completion_returns_per_generation"] == 10
    assert payload["runtime_mod"] == DEFAULT_MODEL
    assert payload["completion_mod"] == DEFAULT_MODEL
    assert payload["adversary_mod"] == DEFAULT_MODEL


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
            max_completion_returns_per_generation=4,
        ),
    )

    config = load_project_config(tmp_path)

    assert config.task == "TASK.md"
    assert config.coder_mod == "gpt-coder"
    assert config.runtime_mod == "gpt-supervisor"
    assert config.completion_mod == "gpt-supervisor"
    assert config.adversary_mod == DEFAULT_MODEL
    assert config.coder_intelligence == "low"
    assert config.runtime_intelligence == "high"
    assert config.completion_intelligence == "high"
    assert config.adversary_intelligence == DEFAULT_INTELLIGENCE
    assert config.speed == "fast"
    assert config.start_over is False
    assert config.clean is True
    assert config.protected_path == ("hidden",)
    assert config.adversary is False
    assert config.adversary_runs == 0
    assert config.completion_returns_per_generation == 4


def test_project_config_loads_independent_role_models_and_efforts(tmp_path: Path) -> None:
    _write_config_payload(
        tmp_path,
        json.dumps(
            {
                "coder_mod": MODEL_GPT_5_6_SOL,
                "runtime_mod": MODEL_GPT_5_5,
                "completion_mod": MODEL_GPT_5_6_TERRA,
                "adversary_mod": MODEL_GPT_5_6_SOL,
                "coder_intelligence": "ultra",
                "runtime_intelligence": "xhigh",
                "completion_intelligence": "ultra",
                "adversary_intelligence": "max",
            }
        ),
    )

    config = load_project_config(tmp_path, create=False)

    assert config.coder_mod == MODEL_GPT_5_6_SOL
    assert config.runtime_mod == MODEL_GPT_5_5
    assert config.completion_mod == MODEL_GPT_5_6_TERRA
    assert config.adversary_mod == MODEL_GPT_5_6_SOL
    assert config.coder_intelligence == "ultra"
    assert config.runtime_intelligence == "xhigh"
    assert config.completion_intelligence == "ultra"
    assert config.adversary_intelligence == "max"


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
    assert runtime_config.max_completion_returns_per_generation == 10


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
        ProjectConfig(coder_mod="config-coder", runtime_mod="config-super", speed="fast", clean=True),
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


def test_config_editor_starts_inline_edit_for_direct_text_field() -> None:
    config = ProjectConfig()
    params = parameter_defs(config)
    task_index = [param.key for param in params].index("task")
    state = EditorState(parameter_index=task_index)

    config, state, action = select_current(config, state)

    assert action is None
    assert config.task is None
    assert state.editing is True
    assert state.edit_kind == "optional_text"
    assert state.edit_value == ""

    state = append_inline_text(state, "TASK.md")
    config, state, action = select_current(config, state)

    assert action is None
    assert config.task == "TASK.md"
    assert state.editing is False
    assert state.parameter_index == task_index + 1


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


def test_config_editor_inline_adversary_runs_updates_boolean() -> None:
    config = ProjectConfig(adversary=False)
    params = parameter_defs(config)
    runs_index = [param.key for param in params].index("adversary_runs")
    state = EditorState(parameter_index=runs_index)

    config, state, action = select_current(config, state)
    assert action is None
    assert state.editing is True
    assert state.edit_value == "0"

    state = replace(state, edit_value="3")
    config, state, action = select_current(config, state)

    assert action is None
    assert config.adversary is True
    assert config.adversary_runs == 3


def test_config_editor_inline_adversary_runs_zero_disables_adversary() -> None:
    config = ProjectConfig(adversary=True, adversary_runs=2)
    params = parameter_defs(config)
    runs_index = [param.key for param in params].index("adversary_runs")
    state = EditorState(parameter_index=runs_index)

    config, state, action = select_current(config, state)
    state = replace(state, edit_value="0")
    config, state, action = select_current(config, state)

    assert action is None
    assert config.adversary is False
    assert config.adversary_runs == 0


def test_config_editor_inline_completion_return_limit_updates_config() -> None:
    config = ProjectConfig()
    params = parameter_defs(config)
    limit_index = [param.key for param in params].index("completion_returns_per_generation")
    state = EditorState(parameter_index=limit_index)

    config, state, action = select_current(config, state)
    state = replace(state, edit_value="4")
    config, state, action = select_current(config, state)

    assert action is None
    assert config.completion_returns_per_generation == 4


def test_config_editor_inline_number_rejects_invalid_input() -> None:
    config = ProjectConfig()
    params = parameter_defs(config)
    limit_index = [param.key for param in params].index("completion_returns_per_generation")
    state = EditorState(parameter_index=limit_index)

    config, state, action = select_current(config, state)
    state = replace(state, edit_value="-1")
    config, state, action = select_current(config, state)

    assert action is None
    assert config.completion_returns_per_generation == 10
    assert state.editing is True
    assert state.edit_error == "enter a non-negative integer"


def test_config_editor_groups_gpt_56_variants_and_filters_older_models() -> None:
    config = ProjectConfig()
    params = parameter_defs(
        config,
        model_choices=(
            MODEL_GPT_5_6_SOL,
            MODEL_GPT_5_6_TERRA,
            MODEL_GPT_5_6_LUNA,
            MODEL_GPT_5_5,
            "gpt-5.4",
            "gpt-5.3-codex-spark",
        ),
    )
    for role in ("coder", "runtime", "completion", "adversary"):
        model_param = next(param for param in params if param.key == f"{role}_mod")
        variant_param = next(param for param in params if param.key == f"{role}_mod_variant")
        assert [option.label for option in model_param.options] == ["GPT-5.6", "GPT-5.5"]
        assert [option.label for option in variant_param.options] == ["Sol", "Terra", "Luna"]
        assert all(option.action is None for option in model_param.options)


def test_config_editor_switching_variants_clamps_incompatible_reasoning() -> None:
    config = ProjectConfig(coder_mod=MODEL_GPT_5_6_SOL, coder_intelligence="ultra")
    params = parameter_defs(config)
    variant_index = [param.key for param in params].index("coder_mod_variant")
    luna_index = [option.label for option in params[variant_index].options].index("Luna")

    config, state, _action = select_current(
        config,
        EditorState(parameter_index=variant_index, expanded_index=variant_index, option_index=luna_index),
    )

    assert config.coder_mod == MODEL_GPT_5_6_LUNA
    assert config.coder_intelligence == "max"
    assert state.parameter_index == variant_index + 1
    coder_effort = next(param for param in parameter_defs(config) if param.key == "coder_intelligence")
    assert [option.label for option in coder_effort.options] == ["low", "medium", "high", "xhigh", "max"]


def test_config_editor_switching_to_gpt_55_hides_variant_and_clamps_reasoning() -> None:
    config = ProjectConfig(coder_mod=MODEL_GPT_5_6_SOL, coder_intelligence="ultra")
    params = parameter_defs(config)
    family_index = [param.key for param in params].index("coder_mod")
    gpt_55_index = [option.label for option in params[family_index].options].index("GPT-5.5")

    config, _state, _action = select_current(
        config,
        EditorState(parameter_index=family_index, expanded_index=family_index, option_index=gpt_55_index),
    )

    assert config.coder_mod == MODEL_GPT_5_5
    assert config.coder_intelligence == "xhigh"
    assert "coder_mod_variant" not in {parameter.key for parameter in parameter_defs(config)}


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
                    {"slug": MODEL_GPT_5_5, "visibility": "list"},
                    {"slug": MODEL_GPT_5_6_SOL, "visibility": "list"},
                    {"slug": MODEL_GPT_5_6_TERRA, "visibility": "list"},
                    {"slug": MODEL_GPT_5_6_LUNA, "visibility": "list"},
                    {"slug": "hidden-model", "visibility": "hidden"},
                    {"slug": "gpt-5.3-codex-spark", "visibility": "list"},
                ]
            }
        ),
        encoding="utf-8",
    )

    assert available_model_choices(tmp_path) == (
        MODEL_GPT_5_6_SOL,
        MODEL_GPT_5_6_TERRA,
        MODEL_GPT_5_6_LUNA,
        MODEL_GPT_5_5,
    )


@pytest.mark.parametrize(
    ("payload", "error_field"),
    [
        ('{"coder_mod": "gpt-5.6-luna", "coder_intelligence": "ultra"}', "coder_intelligence"),
        ('{"runtime_mod": "gpt-5.5", "runtime_intelligence": "max"}', "runtime_intelligence"),
        ('{"completion_mod": "gpt-5.6-luna", "completion_intelligence": "ultra"}', "completion_intelligence"),
        ('{"adversary_mod": "gpt-5.5", "adversary_intelligence": "max"}', "adversary_intelligence"),
    ],
)
def test_project_config_rejects_reasoning_effort_unsupported_by_model(
    tmp_path: Path,
    payload: str,
    error_field: str,
) -> None:
    _write_config_payload(tmp_path, payload)

    with pytest.raises(ProjectConfigError, match=error_field):
        load_project_config(tmp_path, create=False)


def test_config_command_invokes_editor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("supervisor.main.run_config_editor", lambda project_root: ProjectConfig(coder_mod="gpt-coder"))

    result = CliRunner().invoke(cli, ["config"])

    assert result.exit_code == 0
    assert "Saved Sentinel config:" in result.output
    assert "coder-mod: gpt-coder" in result.output
    assert f"runtime-mod: {DEFAULT_MODEL}" in result.output
    assert f"completion-mod: {DEFAULT_MODEL}" in result.output
    assert f"adversary-mod: {DEFAULT_MODEL}" in result.output


def _write_config_payload(tmp_path: Path, payload: str) -> None:
    path = project_config_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def test_max_adversary_runs_parsed_from_payload(tmp_path) -> None:
    _write_config_payload(tmp_path, '{"max_adversary_runs": 3}')
    config = load_project_config(tmp_path, create=False)
    assert config.adversary is True
    assert config.adversary_runs == 3


def test_max_adversary_runs_zero_disables_adversary(tmp_path) -> None:
    _write_config_payload(tmp_path, '{"max_adversary_runs": 0}')
    config = load_project_config(tmp_path, create=False)
    assert config.adversary is False
    assert config.adversary_runs == 0


def test_max_adversary_runs_rejects_invalid_values(tmp_path) -> None:
    _write_config_payload(tmp_path, '{"max_adversary_runs": -1}')
    with pytest.raises(ProjectConfigError):
        load_project_config(tmp_path, create=False)


def test_to_json_data_round_trips_adversary_runs(tmp_path) -> None:
    config = ProjectConfig(adversary_runs=2)
    data = config.to_json_data()
    assert data["max_adversary_runs"] == 2


def test_max_completion_returns_per_generation_parsed_from_payload(tmp_path) -> None:
    _write_config_payload(tmp_path, '{"max_completion_returns_per_generation": 3}')
    config = load_project_config(tmp_path, create=False)
    assert config.completion_returns_per_generation == 3


def test_max_completion_returns_per_generation_rejects_invalid_values(tmp_path) -> None:
    _write_config_payload(tmp_path, '{"max_completion_returns_per_generation": -1}')
    with pytest.raises(ProjectConfigError):
        load_project_config(tmp_path, create=False)


def test_to_json_data_round_trips_completion_return_limit(tmp_path) -> None:
    config = ProjectConfig(completion_returns_per_generation=4)
    data = config.to_json_data()
    assert data["max_completion_returns_per_generation"] == 4


def test_completion_review_defaults_to_enabled(tmp_path) -> None:
    _write_config_payload(tmp_path, "{}")
    config = load_project_config(tmp_path, create=False)
    assert config.completion_review is True


def test_completion_review_parsed_from_payload(tmp_path) -> None:
    _write_config_payload(tmp_path, '{"completion_review": false}')
    config = load_project_config(tmp_path, create=False)
    assert config.completion_review is False


def test_completion_review_rejects_invalid_values(tmp_path) -> None:
    _write_config_payload(tmp_path, '{"completion_review": "sometimes"}')
    with pytest.raises(ProjectConfigError):
        load_project_config(tmp_path, create=False)


def test_to_json_data_round_trips_completion_review(tmp_path) -> None:
    config = ProjectConfig(completion_review=False)
    data = config.to_json_data()
    assert data["completion_review"] is False


def test_completion_review_syncs_to_runtime_config(tmp_path) -> None:
    from supervisor.state import StateStore
    from supervisor.schemas import SentinelConfig

    task = tmp_path / "TASK.md"
    task.write_text("# Task", encoding="utf-8")
    store = StateStore(tmp_path)
    store.initialize_sentinel(
        SentinelConfig(project_root=str(tmp_path), task_path=str(task), coder_thread_id="thread"),
        overwrite=True,
    )
    assert store.get_sentinel_config().completion_review_enabled is True

    sync_runtime_config_fields(tmp_path, ProjectConfig(completion_review=False), ("completion_review",))

    assert store.get_sentinel_config().completion_review_enabled is False
