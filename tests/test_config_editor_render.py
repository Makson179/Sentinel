from __future__ import annotations

import re
from pathlib import Path

import pytest

from supervisor.config_editor import EditorState, Theme, WidthUtils, parameter_defs, render_editor
from supervisor.project_config import MODEL_GPT_5_5, MODEL_GPT_5_6_LUNA, MODEL_GPT_5_6_SOL, MODEL_GPT_5_6_TERRA, ProjectConfig


@pytest.fixture(autouse=True)
def _default_unicode_symbols(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_CONFIG_ASCII", raising=False)


def _render(
    config: ProjectConfig | None = None,
    state: EditorState | None = None,
    *,
    path: Path | None = None,
    model_choices: tuple[str, ...] | None = None,
    width: int = 80,
    height: int = 14,
) -> str:
    output = render_editor(
        config or ProjectConfig(),
        state or EditorState(),
        path or Path("/tmp/project/.supervisor/config.json"),
        model_choices,
        width=width,
        height=height,
    )
    assert isinstance(output, str)
    return output


def test_config_editor_render_marks_active_row() -> None:
    output = _render(height=12)

    assert "SENTINEL PROJECT CONFIG" in output
    assert "SETTING" in output
    assert "VALUE" in output
    assert any("││ › ▸ ☑  task" in line for line in output.splitlines())


def test_config_editor_render_marks_collapsed_expandable_fields() -> None:
    output = _render(height=14)

    assert any("││   ▸ ◇  coder-mod" in line for line in output.splitlines())
    assert any("││  ─" in line for line in output.splitlines())


def test_config_editor_render_shows_expanded_field_options() -> None:
    config = ProjectConfig()
    params = parameter_defs(config)
    speed_index = [param.key for param in params].index("speed")

    output = _render(config, EditorState(parameter_index=speed_index, expanded_index=speed_index), height=16)

    assert any("▾ ⚡  speed" in line for line in output.splitlines())
    assert "usual" in output
    assert "fast" in output


def test_config_editor_render_marks_active_selected_option() -> None:
    config = ProjectConfig(speed="fast")
    params = parameter_defs(config)
    speed_index = [param.key for param in params].index("speed")

    output = _render(config, EditorState(parameter_index=speed_index, expanded_index=speed_index, option_index=1), height=14)

    assert re.search(r"›\s+└─ ✦  fast", output)


def test_config_editor_render_shows_numeric_limit_fields() -> None:
    config = ProjectConfig()
    params = parameter_defs(config)
    max_returns_index = [param.key for param in params].index("completion_returns_per_generation")
    output = _render(
        config,
        EditorState(parameter_index=max_returns_index),
        width=120,
        height=20,
    )

    assert "max-adversary-runs" in output
    assert "max-completion-returns-per-generation" in output


def test_config_editor_completion_review_row_and_adversary_coupling() -> None:
    config = ProjectConfig()
    params = parameter_defs(config)
    completion_review_index = [param.key for param in params].index("completion_review")
    output = _render(
        config,
        EditorState(parameter_index=completion_review_index),
        width=120,
        height=20,
    )
    assert "completion-review" in output

    params = parameter_defs(ProjectConfig(completion_review=False, adversary=True, adversary_runs=2))
    by_key = {param.key: param for param in params}
    assert by_key["completion_review"].value == "false"
    # adversary runs inside the completion-review accept path, so with the review
    # disabled the editor shows the adversary as effectively off.
    assert by_key["adversary"].value == "false"
    assert by_key["adversary_runs"].value == "0"


def test_config_editor_render_shows_inline_edit_value_cursor() -> None:
    params = parameter_defs(ProjectConfig())
    task_index = [param.key for param in params].index("task")

    output = _render(
        ProjectConfig(),
        EditorState(parameter_index=task_index, editing=True, edit_kind="optional_text", edit_value="TASK.md"),
        width=100,
        height=14,
    )

    assert "Type value. Enter saves. Esc cancels. Backspace edits." in output
    assert "TASK.md▏" in output


def test_config_editor_render_uses_family_and_variant_model_options() -> None:
    config = ProjectConfig(
        coder_mod=MODEL_GPT_5_6_TERRA,
        runtime_mod=MODEL_GPT_5_6_SOL,
        completion_mod=MODEL_GPT_5_6_LUNA,
        adversary_mod=MODEL_GPT_5_5,
    )
    model_choices = (MODEL_GPT_5_6_SOL, MODEL_GPT_5_6_TERRA, MODEL_GPT_5_6_LUNA, MODEL_GPT_5_5)
    params = parameter_defs(config, model_choices=model_choices)
    coder_index = [param.key for param in params].index("coder_mod")

    output = _render(
        config,
        EditorState(parameter_index=coder_index, expanded_index=coder_index),
        model_choices=model_choices,
        width=100,
        height=22,
    )

    assert "GPT-5.6" in output
    assert "GPT-5.5" in output
    assert "coder-5.6-variant" in output
    assert "Terra" in output


def test_config_editor_render_has_independent_rows_for_all_agent_roles() -> None:
    for role in ("coder", "runtime", "completion", "adversary"):
        config = ProjectConfig()
        params = parameter_defs(config)
        effort_index = [param.key for param in params].index(f"{role}_intelligence")
        output = _render(
            config,
            EditorState(parameter_index=effort_index),
            width=120,
            height=20,
        )
        assert f"{role}-mod" in output
        assert f"{role}-5.6-variant" in output
        assert f"{role}-intelligence" in output


def test_config_editor_render_variant_row_has_sol_terra_luna_options() -> None:
    config = ProjectConfig()
    params = parameter_defs(config)
    variant_index = [param.key for param in params].index("coder_mod_variant")

    output = _render(
        config,
        EditorState(parameter_index=variant_index, expanded_index=variant_index),
        width=100,
        height=22,
    )

    assert "Sol" in output
    assert "Terra" in output
    assert "Luna" in output


def test_config_editor_render_middle_truncates_long_paths() -> None:
    path = Path("/tmp/" + "/".join(f"segment-{index}" for index in range(20)) + "/.supervisor/config.json")

    output = _render(path=path, width=80, height=8)
    path_line = output.splitlines()[3]

    assert "Path:" in path_line
    assert "..." in path_line
    assert "config.json" in path_line
    assert WidthUtils.display_width(path_line) == 80


def test_width_utils_are_ansi_safe() -> None:
    red = "\x1b[31mabcdef\x1b[0m"

    assert WidthUtils.strip_ansi(red) == "abcdef"
    assert WidthUtils.display_width(red) == 6
    assert WidthUtils.display_width(WidthUtils.truncate_right(red, 5)) == 5
    assert WidthUtils.display_width(WidthUtils.pad_right(red, 10)) == 10
    assert WidthUtils.truncate_middle("/one/two/three/four/file.json", 16) == "/one/t...le.json"


def test_config_editor_styles_use_dark_blue_background_palette() -> None:
    background_styles = [style for style in Theme.from_environment().styles.values() if "bg:" in style]

    assert background_styles
    assert all("bg:#000000" not in style for style in background_styles)
    assert any("bg:#050716" in style for style in background_styles)
    assert any("bg:#100832" in style for style in background_styles)


def test_config_editor_formatted_fragments_paint_backgrounds() -> None:
    output = render_editor(
        ProjectConfig(),
        EditorState(),
        Path("/tmp/project/.supervisor/config.json"),
        width=80,
        height=12,
        formatted=True,
    )

    assert not isinstance(output, str)
    assert all("bg:" in style for style, text in output if text != "\n")
    assert any("#18f8ff bg:#050716" in style for style, text in output if text == "╭")
    assert any("#f060f8 bg:#050716" in style for style, text in output if text == "╮")
    assert any("bg:#100832" in style for style, text in output if text.strip())
    assert not any("bg:#21146a" in style for style, text in output if text.strip())


def test_config_editor_layout_fits_supported_widths() -> None:
    for width in (80, 100, 120, 160):
        output = _render(width=width, height=12)
        lines = output.splitlines()

        assert len(lines) == 12
        assert lines[0].startswith("╭")
        assert "SENTINEL PROJECT CONFIG" in lines[1]
        assert "CONFIG LOADED" in lines[1]
        assert "ESC" in lines[1]
        assert "Path:" in lines[3]
        assert "Arrows move." in lines[5]
        assert "SETTING" in output
        assert "VALUE" in output
        assert "JSON" in lines[-2]
        assert "Enter to save" in lines[-2]
        assert lines[-1].startswith("╰")
        assert all(WidthUtils.display_width(line) == width for line in lines)


def test_config_editor_side_panel_visibility_tracks_width() -> None:
    assert "NAVIGATION" not in _render(width=80, height=12)
    assert "NAVIGATION" not in _render(width=100, height=12)
    assert "NAVIGATION" in _render(width=120, height=12)
    assert "NAVIGATION" in _render(width=160, height=12)


def test_config_editor_keeps_active_option_visible_with_limited_height() -> None:
    config = ProjectConfig()
    params = parameter_defs(config)
    protected_index = [param.key for param in params].index("protected_path")

    output = _render(
        config,
        EditorState(parameter_index=protected_index, expanded_index=protected_index, option_index=1),
        width=80,
        height=12,
    )

    assert "SENTINEL PROJECT CONFIG" in output.splitlines()[1]
    assert "Path:" in output.splitlines()[3]
    assert "Arrows move." in output.splitlines()[5]
    assert re.search(r"›\s+└─    add path", output)
    assert "JSON" in output.splitlines()[-2]


def test_config_editor_uses_unicode_borders_by_default() -> None:
    output = _render(width=120, height=12)

    assert output.startswith("╭")
    assert "│" in output
    assert "───" in output
    assert "◇ SENTINEL PROJECT CONFIG" in output


def test_config_editor_ascii_borders_are_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_CONFIG_ASCII", "1")

    output = _render(width=120, height=12)

    assert "+---" in output
    assert "|" in output
    assert "│" not in output


def test_config_editor_default_design_matches_reference_structure() -> None:
    config = ProjectConfig(speed="fast", start_over=False)
    params = parameter_defs(config)
    runtime_index = [param.key for param in params].index("runtime_mod")

    output = _render(
        config,
        EditorState(parameter_index=runtime_index, expanded_index=runtime_index),
        width=120,
        height=30,
    )

    assert "CONFIG LOADED" in output
    assert "NAVIGATION" in output
    assert "^ up" in output
    assert "v down" in output
    assert "› select" in output
    assert "↵ enter" in output
    assert "esc back / exit" in output
    assert "STATUS" in output
    assert "TIPS" in output
    assert "› ▾ ☆  runtime-mod" in output
    speed_index = [param.key for param in params].index("speed")
    lower_output = _render(
        config,
        EditorState(parameter_index=speed_index),
        width=120,
        height=20,
    )
    assert re.search(r"⚡  speed\s+fast", lower_output)
    assert re.search(r"↻  start-over\s+false", lower_output)
