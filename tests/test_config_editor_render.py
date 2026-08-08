from __future__ import annotations

import re
from pathlib import Path

import pytest

from supervisor.config_editor import (
    ULTRA_WAVE_BACKGROUNDS,
    EditorState,
    SidePanel,
    Theme,
    WidthUtils,
    parameter_defs,
    render_editor,
)
from supervisor.project_config import MODEL_GPT_5_5, MODEL_GPT_5_6_LUNA, MODEL_GPT_5_6_SOL, MODEL_GPT_5_6_TERRA, ProjectConfig


@pytest.fixture(autouse=True)
def _default_unicode_symbols(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BELLO_CONFIG_ASCII", raising=False)


def _render(
    config: ProjectConfig | None = None,
    state: EditorState | None = None,
    *,
    path: Path | None = None,
    model_choices: tuple[str, ...] | None = None,
    width: int = 80,
    height: int = 14,
    animation_frame: int | None = None,
) -> str:
    output = render_editor(
        config or ProjectConfig(),
        state or EditorState(),
        path or Path("/tmp/project/.supervisor/config.json"),
        model_choices,
        width=width,
        height=height,
        animation_frame=animation_frame,
    )
    assert isinstance(output, str)
    return output


def _formatted_lines(output: list[tuple[str, str]]) -> list[list[tuple[str, str]]]:
    lines: list[list[tuple[str, str]]] = [[]]
    for fragment in output:
        if fragment[1] == "\n":
            lines.append([])
        else:
            lines[-1].append(fragment)
    return lines


def _side_panel_text(config: ProjectConfig, state: EditorState, *, height: int = 30) -> str:
    parameters = parameter_defs(config)
    lines = SidePanel.render(config, parameters, state, 30, height, Theme.from_environment())
    interiors = ["".join(text for _, text in line)[1:-1].strip() for line in lines]
    return " ".join(text for text in interiors if text)


def test_config_editor_render_marks_active_row() -> None:
    output = _render(height=12)

    assert "BELLO PROJECT CONFIG" in output
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
    config = ProjectConfig(completion_review=True, adversary=True)
    params = parameter_defs(config)
    keys = [param.key for param in params]
    max_returns_index = [param.key for param in params].index("completion_returns_before_adversary")
    output = _render(
        config,
        EditorState(parameter_index=max_returns_index),
        width=120,
        height=20,
    )

    assert "max-adversary-runs" in output
    assert "max-reviews-before-adversary" in output
    assert "max-reviews-after-adversary" in output
    assert next(
        parameter.value
        for parameter in params
        if parameter.key == "completion_returns_before_adversary"
    ) == "1"
    assert next(
        parameter.value
        for parameter in params
        if parameter.key == "completion_returns_after_adversary"
    ) == "0"
    assert keys.index("completion_returns_before_adversary") < keys.index("adversary_runs")
    assert keys.index("adversary_runs") < keys.index("completion_returns_after_adversary")


def test_config_editor_render_displays_unlimited_as_a_word() -> None:
    config = ProjectConfig(
        completion_review=True,
        adversary=True,
        completion_returns_before_adversary="unlimited",
        completion_returns_after_adversary="unlimited",
    )
    params = parameter_defs(config)

    assert next(
        parameter.value
        for parameter in params
        if parameter.key == "completion_returns_before_adversary"
    ) == "Unlimited"
    assert next(
        parameter.value
        for parameter in params
        if parameter.key == "completion_returns_after_adversary"
    ) == "Unlimited"


def test_config_editor_render_shows_cheap_runtime_toggle() -> None:
    config = ProjectConfig(cheap_runtime=False)
    params = parameter_defs(config)
    cheap_runtime_index = [param.key for param in params].index("cheap_runtime")

    output = _render(
        config,
        EditorState(parameter_index=cheap_runtime_index),
        width=120,
        height=20,
    )

    assert "cheap-runtime" in output
    assert next(param for param in params if param.key == "cheap_runtime").value == "false"


def test_config_editor_hides_completion_dependencies_when_review_is_disabled() -> None:
    config = ProjectConfig(completion_review=True, adversary=True)
    params = parameter_defs(config)
    completion_review_index = [param.key for param in params].index("completion_review")
    output = _render(
        config,
        EditorState(parameter_index=completion_review_index),
        width=120,
        height=20,
    )
    assert "completion-review" in output

    disabled = ProjectConfig(completion_review=False, adversary=True, adversary_runs=2)
    params = parameter_defs(disabled)
    keys = {param.key for param in params}
    assert next(param for param in params if param.key == "completion_review").value == "false"
    assert {
        "completion_mod",
        "completion_mod_variant",
        "completion_intelligence",
        "adversary_mod",
        "adversary_mod_variant",
        "adversary_intelligence",
        "adversary",
        "adversary_runs",
        "completion_returns_before_adversary",
        "completion_returns_after_adversary",
    }.isdisjoint(keys)

    output = _render(disabled, width=160, height=40)
    assert "completion-mod" not in output
    assert "adversary-mod" not in output
    assert "max-adversary-runs" not in output
    assert "max-reviews" not in output


def test_config_editor_default_surface_is_everyday() -> None:
    config = ProjectConfig()
    params = parameter_defs(config)
    keys = {param.key for param in params}

    assert next(param for param in params if param.key == "completion_review").value == "false"
    assert {"coder_mod", "runtime_mod", "cheap_runtime", "completion_review"}.issubset(keys)
    assert {
        "completion_mod",
        "completion_intelligence",
        "adversary_mod",
        "adversary_intelligence",
        "adversary",
        "adversary_runs",
        "completion_returns_before_adversary",
        "completion_returns_after_adversary",
    }.isdisjoint(keys)


def test_config_editor_hides_only_adversary_dependencies_when_adversary_is_disabled() -> None:
    config = ProjectConfig(completion_review=True, adversary=False, adversary_runs=2)
    params = parameter_defs(config)
    keys = {param.key for param in params}

    assert {
        "completion_mod",
        "completion_mod_variant",
        "completion_intelligence",
        "adversary",
        "completion_returns_before_adversary",
    }.issubset(keys)
    assert {
        "adversary_mod",
        "adversary_mod_variant",
        "adversary_intelligence",
        "adversary_runs",
        "completion_returns_after_adversary",
    }.isdisjoint(keys)

    before_index = [parameter.key for parameter in params].index("completion_returns_before_adversary")
    assert params[before_index].label == "max-reviews"
    output = _render(config, EditorState(parameter_index=before_index), width=160, height=40)
    assert "completion-mod" in output
    assert "max-reviews" in output
    assert "max-reviews-before-adversary" not in output
    assert "adversary-mod" not in output
    assert "max-adversary-runs" not in output
    assert "max-reviews-after-adversary" not in output


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
        config = ProjectConfig(completion_review=True, adversary=True)
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
        assert "BELLO PROJECT CONFIG" in lines[1]
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
    assert "TIPS" in _render(width=120, height=12)
    assert "TIPS" in _render(width=160, height=12)
    assert "NAVIGATION" in _render(width=120, height=20)


def test_config_editor_footer_omits_internal_nested_counter() -> None:
    output = _render(width=120, height=20)

    assert "settings" in output
    assert "nested" not in output


def test_config_editor_all_fields_define_context_help() -> None:
    parameters = parameter_defs(ProjectConfig())

    assert parameters
    assert all(parameter.help_text.strip() for parameter in parameters)


def test_config_editor_side_panel_explains_the_focused_field() -> None:
    config = ProjectConfig()
    parameters = parameter_defs(config)
    start_over_index = [parameter.key for parameter in parameters].index("start_over")
    clean_index = [parameter.key for parameter in parameters].index("clean")

    start_over_help = _side_panel_text(config, EditorState(parameter_index=start_over_index))
    compact_start_over_help = _side_panel_text(config, EditorState(parameter_index=start_over_index), height=10)
    clean_help = _side_panel_text(config, EditorState(parameter_index=clean_index))

    assert "true deletes prior Bello logs, archives, and recovery data" in start_over_help
    assert "Both start a new active run and leave project files unchanged" in start_over_help
    assert "Both start a new active run and leave project files unchanged" in compact_start_over_help
    assert "DANGER: before launch, delete everything in the project folder except the task file" in clean_help
    assert "task file and protected paths" in clean_help
    assert "including .git" in clean_help
    assert "Use arrows to navigate" not in start_over_help


def test_config_editor_review_limit_tip_matches_adversary_mode() -> None:
    enabled = ProjectConfig(completion_review=True, adversary=True)
    enabled_params = parameter_defs(enabled)
    enabled_index = [parameter.key for parameter in enabled_params].index("completion_returns_before_adversary")
    enabled_help = _side_panel_text(enabled, EditorState(parameter_index=enabled_index))

    disabled = ProjectConfig(completion_review=True, adversary=False)
    disabled_params = parameter_defs(disabled)
    disabled_index = [parameter.key for parameter in disabled_params].index("completion_returns_before_adversary")
    disabled_help = _side_panel_text(disabled, EditorState(parameter_index=disabled_index))

    assert "forces the first adversary" in enabled_help
    assert "0 skips these rounds" in enabled_help
    assert "Unlimited removes the cap" in enabled_help
    assert "Maximum completion-review rounds that may return work" in disabled_help
    assert "Bello completes without another review" in disabled_help
    assert "0 skips review" in disabled_help
    assert "Unlimited removes the cap" in disabled_help
    assert "restarts the coder" not in disabled_help

    after_index = [parameter.key for parameter in enabled_params].index(
        "completion_returns_after_adversary"
    )
    after_help = _side_panel_text(enabled, EditorState(parameter_index=after_index))
    assert "0 schedules none" in after_help
    assert "Unlimited removes the cap" in after_help
    assert "adv_report_controller pass still normalizes every" in after_help


def test_config_editor_focused_icon_moves_without_shifting_the_field_name() -> None:
    first = _render(width=120, height=20, animation_frame=0)
    second = _render(width=120, height=20, animation_frame=2)
    first_row = next(line for line in first.splitlines() if "☑" in line and "task" in line)
    second_row = next(line for line in second.splitlines() if "☑" in line and "task" in line)

    assert first_row != second_row
    assert first_row.index("task") == second_row.index("task")
    assert WidthUtils.display_width(first_row) == 120
    assert WidthUtils.display_width(second_row) == 120


@pytest.mark.parametrize("effort", ["xhigh", "max", "ultra"])
def test_config_editor_effort_animation_preserves_row_width(effort: str) -> None:
    config = ProjectConfig()
    parameters = parameter_defs(config)
    effort_index = [parameter.key for parameter in parameters].index("coder_intelligence")
    option_index = [option.label for option in parameters[effort_index].options].index(effort)

    output = _render(
        config,
        EditorState(parameter_index=effort_index, expanded_index=effort_index, option_index=option_index),
        width=120,
        height=24,
        animation_frame=12,
    )
    option_row = next(line for line in output.splitlines() if effort in line and ("├─" in line or "└─" in line))

    assert WidthUtils.display_width(option_row) == 120


def test_config_editor_effort_options_have_distinct_motion_levels() -> None:
    config = ProjectConfig()
    parameters = parameter_defs(config)
    effort_index = [parameter.key for parameter in parameters].index("coder_intelligence")

    def option_line(effort: str, frame: int) -> list[tuple[str, str]]:
        option_index = [option.label for option in parameters[effort_index].options].index(effort)
        output = render_editor(
            config,
            EditorState(parameter_index=effort_index, expanded_index=effort_index, option_index=option_index),
            Path("/tmp/project/.supervisor/config.json"),
            width=120,
            height=24,
            formatted=True,
            animation_frame=frame,
        )
        assert isinstance(output, list)
        return next(
            line
            for line in _formatted_lines(output)
            if effort in "".join(text for _, text in line) and any(branch in "".join(text for _, text in line) for branch in ("├─", "└─"))
        )

    xhigh_first = option_line("xhigh", 0)
    xhigh_second = option_line("xhigh", 2)
    max_first = option_line("max", 0)
    max_second = option_line("max", 2)
    ultra_source = option_line("ultra", 0)
    ultra_first = option_line("ultra", 12)
    ultra_second = option_line("ultra", 15)
    ultra_wave_train = option_line("ultra", 65)

    xhigh_style_first = next(style for style, text in xhigh_first if text == "xhigh")
    xhigh_style_second = next(style for style, text in xhigh_second if text == "xhigh")
    max_style_first = next(style for style, text in max_first if text == "max")
    max_style_second = next(style for style, text in max_second if text == "max")
    ultra_source_style = next(style for style, text in ultra_source if text == "ultra")

    assert xhigh_style_first == xhigh_style_second
    assert max_style_first != max_style_second
    assert f"bg:{ULTRA_WAVE_BACKGROUNDS[-1]}" in ultra_source_style
    assert "".join(text for _, text in ultra_first) == "".join(text for _, text in ultra_second)
    assert ultra_first != ultra_second
    wave_backgrounds = {
        token[3:]
        for style, _ in ultra_wave_train
        for token in style.split()
        if token.startswith("bg:") and token[3:] in ULTRA_WAVE_BACKGROUNDS
    }
    assert len(wave_backgrounds) >= 7
    assert not any("#78e8ff" in style for style, _ in ultra_wave_train)


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

    assert "BELLO PROJECT CONFIG" in output.splitlines()[1]
    assert "Path:" in output.splitlines()[3]
    assert "Arrows move." in output.splitlines()[5]
    assert re.search(r"›\s+└─    add path", output)
    assert "JSON" in output.splitlines()[-2]


def test_config_editor_uses_unicode_borders_by_default() -> None:
    output = _render(width=120, height=12)

    assert output.startswith("╭")
    assert "│" in output
    assert "───" in output
    assert "◇ BELLO PROJECT CONFIG" in output


def test_config_editor_ascii_borders_are_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BELLO_CONFIG_ASCII", "1")

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
