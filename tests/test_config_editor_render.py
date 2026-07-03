from __future__ import annotations

from pathlib import Path

import pytest

from supervisor.config_editor import EditorState, Theme, WidthUtils, parameter_defs, render_editor
from supervisor.project_config import ProjectConfig


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

    assert any("││ › ▸ ☑  task" in line for line in output.splitlines())


def test_config_editor_render_marks_collapsed_expandable_fields() -> None:
    output = _render(height=12)

    assert any("││   ▸ ◇  coder-mod" in line for line in output.splitlines())


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

    assert any("›   └─ ●  fast" in line for line in output.splitlines())


def test_config_editor_render_uses_dynamic_model_options() -> None:
    config = ProjectConfig(coder_mod="project-coder", super_mod="project-super")
    params = parameter_defs(config, model_choices=("alpha-model", "beta-model"))
    coder_index = [param.key for param in params].index("coder_mod")

    output = _render(
        config,
        EditorState(parameter_index=coder_index, expanded_index=coder_index),
        model_choices=("alpha-model", "beta-model"),
        width=100,
        height=18,
    )

    assert "alpha-model" in output
    assert "beta-model" in output
    assert "project-coder" in output
    assert "project-super" in output


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


def test_config_editor_styles_do_not_paint_backgrounds() -> None:
    assert all("bg:" not in style for style in Theme.from_environment().styles.values())


def test_config_editor_layout_fits_supported_widths() -> None:
    for width in (80, 100, 120, 160):
        output = _render(width=width, height=12)
        lines = output.splitlines()

        assert len(lines) == 12
        assert lines[0].startswith("╭")
        assert "Sentinel project config" in lines[1]
        assert "Path:" in lines[3]
        assert "Arrows move." in lines[5]
        assert "JSON" in lines[-2]
        assert lines[-1].startswith("╰")
        assert all(WidthUtils.display_width(line) == width for line in lines)


def test_config_editor_side_panel_visibility_tracks_width() -> None:
    assert "LEGEND" not in _render(width=80, height=12)
    assert "LEGEND" not in _render(width=100, height=12)
    assert "LEGEND" in _render(width=120, height=12)
    assert "LEGEND" in _render(width=160, height=12)


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

    assert "Sentinel project config" in output.splitlines()[1]
    assert "Path:" in output.splitlines()[3]
    assert "Arrows move." in output.splitlines()[5]
    assert any("›   └─    add path" in line for line in output.splitlines())
    assert "JSON" in output.splitlines()[-2]


def test_config_editor_uses_unicode_borders_by_default() -> None:
    output = _render(width=120, height=12)

    assert output.startswith("╭")
    assert "│" in output
    assert "───" in output
    assert "◇  Sentinel project config" in output


def test_config_editor_ascii_borders_are_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_CONFIG_ASCII", "1")

    output = _render(width=120, height=12)

    assert "+---" in output
    assert "|" in output
    assert "│" not in output


def test_config_editor_default_design_matches_reference_structure() -> None:
    config = ProjectConfig(speed="fast", start_over=False)
    params = parameter_defs(config)
    super_index = [param.key for param in params].index("super_mod")

    output = _render(config, EditorState(parameter_index=super_index, expanded_index=super_index), width=120, height=24)

    assert "CONFIG LOADED" in output
    assert "LEGEND" in output
    assert "STATUS" in output
    assert "TIPS" in output
    assert "› ▾ ☆  super-mod" in output
    assert "⚡  speed                fast" in output
    assert "↻  start-over           false" in output
