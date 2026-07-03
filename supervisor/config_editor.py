from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal, cast

from wcwidth import wcwidth

from supervisor.appserver import AppServerClient
from supervisor.project_config import (
    DEFAULT_MODEL,
    INTELLIGENCE_CHOICES,
    SPEED_CHOICES,
    ProjectConfig,
    changed_project_config_fields,
    load_project_config,
    project_config_path,
    sync_runtime_config_fields,
)


EditorAction = Literal["edit_text", "add_protected_path"]
StyledFragment = tuple[str, str]
FragmentLine = list[StyledFragment]
FormattedRender = list[StyledFragment]

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ELLIPSIS = "..."


@dataclass(frozen=True)
class EditorOption:
    label: str
    field: str | None = None
    value: Any = None
    action: EditorAction | None = None


@dataclass(frozen=True)
class EditorParameter:
    key: str
    label: str
    value: str
    options: tuple[EditorOption, ...]


@dataclass(frozen=True)
class EditorState:
    parameter_index: int = 0
    expanded_index: int | None = None
    option_index: int | None = None


@dataclass(frozen=True)
class Symbols:
    active: str = ">"
    collapsed: str = ">"
    expanded: str = "v"
    selected: str = "*"
    horizontal: str = "-"
    vertical: str = "|"
    corner: str = "+"

    @classmethod
    def default(cls) -> Symbols:
        return cls()

    @classmethod
    def unicode(cls) -> Symbols:
        return cls(
            active=">",
            collapsed=">",
            expanded="v",
            selected="*",
            horizontal="─",
            vertical="│",
            corner="┼",
        )


@dataclass(frozen=True)
class Theme:
    symbols: Symbols
    styles: dict[str, str]

    @classmethod
    def from_environment(cls) -> Theme:
        unicode_enabled = os.environ.get("SENTINEL_CONFIG_UNICODE", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        symbols = Symbols.unicode() if unicode_enabled else Symbols.default()
        return cls(
            symbols=symbols,
            styles={
                "root": "bg:#07050b #ddd7eb",
                "header": "bg:#160b25 #f7f1ff bold",
                "badge": "bg:#34204d #9eeaff bold",
                "ok": "#67e8a5 bold",
                "exit": "#d7c7ff",
                "muted": "#9185a6",
                "cyan": "#67e8f9",
                "violet": "#a78bfa",
                "magenta": "#f472d0",
                "green": "#65d98d",
                "yellow": "#facc6b",
                "red": "#fb7185",
                "active": "bg:#211430 #f7f1ff",
                "name": "#eee7ff",
                "border": "#49355f",
                "panel": "bg:#0d0913 #d8d0ea",
            },
        )

    def style(self, *keys: str) -> str:
        return " ".join(self.styles[key] for key in keys if key in self.styles)


@dataclass(frozen=True)
class LayoutSpec:
    width: int
    height: int
    list_height: int
    main_width: int
    side_width: int
    side_panel: bool

    @classmethod
    def from_size(cls, width: int | None = None, height: int | None = None) -> LayoutSpec:
        terminal_size = shutil.get_terminal_size(fallback=(100, 30))
        resolved_width = max(20, width or terminal_size.columns)
        resolved_height = max(4, height or terminal_size.lines)
        side_panel = resolved_width >= 120
        side_width = min(42, max(34, resolved_width // 3)) if side_panel else 0
        gutter_width = 3 if side_panel else 0
        main_width = max(20, resolved_width - side_width - gutter_width)
        fixed_lines = 4
        list_height = max(0, resolved_height - fixed_lines)
        return cls(
            width=resolved_width,
            height=resolved_height,
            list_height=list_height,
            main_width=main_width,
            side_width=side_width,
            side_panel=side_panel,
        )


class WidthUtils:
    @staticmethod
    def strip_ansi(text: str) -> str:
        return ANSI_ESCAPE_RE.sub("", text)

    @staticmethod
    def display_width(text: str) -> int:
        return sum(max(wcwidth(char), 0) for char in WidthUtils.strip_ansi(text))

    @staticmethod
    def take_start(text: str, width: int) -> str:
        if width <= 0:
            return ""
        result: list[str] = []
        used = 0
        index = 0
        while index < len(text):
            match = ANSI_ESCAPE_RE.match(text, index)
            if match is not None:
                result.append(match.group(0))
                index = match.end()
                continue
            char = text[index]
            char_width = max(wcwidth(char), 0)
            if char_width > 0 and used + char_width > width:
                break
            result.append(char)
            used += char_width
            index += 1
        return "".join(result)

    @staticmethod
    def take_end(text: str, width: int) -> str:
        if width <= 0:
            return ""
        text = WidthUtils.strip_ansi(text)
        result: list[str] = []
        used = 0
        for char in reversed(text):
            char_width = max(wcwidth(char), 0)
            if char_width > 0 and used + char_width > width:
                break
            result.append(char)
            used += char_width
        return "".join(reversed(result))

    @staticmethod
    def truncate_right(text: str, width: int, placeholder: str = ELLIPSIS) -> str:
        if width <= 0:
            return ""
        if WidthUtils.display_width(text) <= width:
            return text
        placeholder_width = WidthUtils.display_width(placeholder)
        if width <= placeholder_width:
            return WidthUtils.take_start(placeholder, width)
        prefix = WidthUtils.take_start(text, width - placeholder_width)
        if ANSI_ESCAPE_RE.search(prefix) and not prefix.endswith("\x1b[0m"):
            prefix = f"{prefix}\x1b[0m"
        return f"{prefix}{placeholder}"

    @staticmethod
    def truncate_middle(text: str, width: int, placeholder: str = ELLIPSIS) -> str:
        if width <= 0:
            return ""
        if WidthUtils.display_width(text) <= width:
            return text
        placeholder_width = WidthUtils.display_width(placeholder)
        if width <= placeholder_width:
            return WidthUtils.take_start(placeholder, width)
        available = width - placeholder_width
        left_width = max(1, available // 2)
        right_width = max(0, available - left_width)
        return f"{WidthUtils.take_start(text, left_width)}{placeholder}{WidthUtils.take_end(text, right_width)}"

    @staticmethod
    def pad_right(text: str, width: int) -> str:
        clipped = WidthUtils.truncate_right(text, width)
        padding = max(0, width - WidthUtils.display_width(clipped))
        return f"{clipped}{' ' * padding}"

    @staticmethod
    def pad_left(text: str, width: int) -> str:
        clipped = WidthUtils.truncate_right(text, width)
        padding = max(0, width - WidthUtils.display_width(clipped))
        return f"{' ' * padding}{clipped}"


def parameter_defs(config: ProjectConfig, model_choices: tuple[str, ...] | None = None) -> tuple[EditorParameter, ...]:
    models = _model_choices_for_config(config, model_choices)
    protected_options = [
        EditorOption("clear all", "protected_path", ()),
        EditorOption("add path", action="add_protected_path"),
    ]
    if config.protected_path:
        protected_options.append(EditorOption(f"remove last ({config.protected_path[-1]})", "protected_path", config.protected_path[:-1]))

    return (
        EditorParameter(
            "task",
            "task",
            config.task or "absent",
            (
                EditorOption("absent", "task", None),
                EditorOption("edit path", action="edit_text"),
            ),
        ),
        EditorParameter(
            "coder_mod",
            "coder-mod",
            config.coder_mod,
            tuple(EditorOption(model, "coder_mod", model) for model in models),
        ),
        EditorParameter(
            "super_mod",
            "super-mod",
            config.super_mod,
            tuple(EditorOption(model, "super_mod", model) for model in models),
        ),
        EditorParameter(
            "coder_intelligence",
            "coder-intelligence",
            config.coder_intelligence,
            tuple(EditorOption(value, "coder_intelligence", value) for value in INTELLIGENCE_CHOICES),
        ),
        EditorParameter(
            "super_intelligence",
            "super-intelligence",
            config.super_intelligence,
            tuple(EditorOption(value, "super_intelligence", value) for value in INTELLIGENCE_CHOICES),
        ),
        EditorParameter(
            "speed",
            "speed",
            config.speed,
            tuple(EditorOption(value, "speed", value) for value in SPEED_CHOICES),
        ),
        EditorParameter(
            "start_over",
            "start-over",
            _format_bool(config.start_over),
            (EditorOption("true", "start_over", True), EditorOption("false", "start_over", False)),
        ),
        EditorParameter(
            "adversary",
            "adversary",
            _format_bool(config.adversary),
            (EditorOption("true", "adversary", True), EditorOption("false", "adversary", False)),
        ),
        EditorParameter(
            "clean",
            "clean",
            _format_bool(config.clean),
            (EditorOption("false", "clean", False), EditorOption("true", "clean", True)),
        ),
        EditorParameter(
            "protected_path",
            "protected-path",
            ", ".join(config.protected_path) if config.protected_path else "absent",
            tuple(protected_options),
        ),
    )


def move_down(state: EditorState, parameters: tuple[EditorParameter, ...]) -> EditorState:
    if state.expanded_index == state.parameter_index:
        option_count = len(parameters[state.parameter_index].options)
        if state.option_index is None:
            return replace(state, option_index=0)
        if state.option_index + 1 < option_count:
            return replace(state, option_index=state.option_index + 1)
    next_index = min(state.parameter_index + 1, len(parameters) - 1)
    return EditorState(parameter_index=next_index)


def move_up(state: EditorState, parameters: tuple[EditorParameter, ...]) -> EditorState:
    if state.expanded_index == state.parameter_index and state.option_index is not None:
        if state.option_index > 0:
            return replace(state, option_index=state.option_index - 1)
        return replace(state, option_index=None)
    previous_index = max(state.parameter_index - 1, 0)
    return EditorState(parameter_index=previous_index)


def select_current(
    config: ProjectConfig,
    state: EditorState,
    model_choices: tuple[str, ...] | None = None,
) -> tuple[ProjectConfig, EditorState, EditorAction | None]:
    parameters = parameter_defs(config, model_choices)
    parameter = parameters[state.parameter_index]
    if state.expanded_index != state.parameter_index:
        return config, replace(state, expanded_index=state.parameter_index, option_index=None), None
    if state.option_index is None:
        return config, replace(state, expanded_index=None), None

    option = parameter.options[state.option_index]
    if option.action is not None:
        return config, state, option.action
    if option.field is None:
        return config, advance_after_selection(state, len(parameters)), None
    updated = replace(config, **{option.field: option.value})
    return updated, advance_after_selection(state, len(parameters)), None


def advance_after_selection(state: EditorState, parameter_count: int) -> EditorState:
    return EditorState(parameter_index=min(state.parameter_index + 1, parameter_count - 1))


class Header:
    @staticmethod
    def render(path: Path, layout: LayoutSpec, theme: Theme) -> FragmentLine:
        left: FragmentLine = [
            (theme.style("header"), " Sentinel project config "),
            (theme.style("badge"), f" {path.name} "),
            (theme.style("header"), " "),
            (theme.style("ok"), "CONFIG LOADED"),
        ]
        right: FragmentLine = [(theme.style("exit"), "Esc/q exit ")]
        return _line_with_right(left, right, layout.width, theme, fill_style=theme.style("header"))


class PathBar:
    @staticmethod
    def render(path: Path, layout: LayoutSpec, theme: Theme) -> FragmentLine:
        label = " Path: "
        path_width = max(0, layout.width - WidthUtils.display_width(label) - 1)
        value = WidthUtils.truncate_middle(str(path), path_width)
        return _fit_fragments(
            [
                (theme.style("muted"), label),
                (theme.style("cyan"), value),
            ],
            layout.width,
            theme,
        )


class HelpLine:
    @staticmethod
    def render(layout: LayoutSpec, theme: Theme) -> FragmentLine:
        return _fit_fragments(
            [(theme.style("muted"), " Arrows move. Enter expands or saves. Esc/q exits.")],
            layout.width,
            theme,
        )


class FooterStatus:
    @staticmethod
    def render(
        config: ProjectConfig,
        parameters: tuple[EditorParameter, ...],
        state: EditorState,
        layout: LayoutSpec,
        theme: Theme,
    ) -> FragmentLine:
        option_count = sum(len(parameter.options) for parameter in parameters)
        action = _primary_action_hint(state)
        left: FragmentLine = [
            (theme.style("badge"), " JSON "),
            (theme.style("muted"), f" {len(parameters)} settings "),
            (theme.style("border"), theme.symbols.vertical),
            (theme.style("muted"), f" {option_count} options "),
            (theme.style("border"), theme.symbols.vertical),
            (theme.style("muted"), f" {len(config.protected_path)} protected "),
        ]
        right: FragmentLine = [(theme.style("cyan"), f"{action} ")]
        return _line_with_right(left, right, layout.width, theme)


class ConfigList:
    @staticmethod
    def render(
        config: ProjectConfig,
        parameters: tuple[EditorParameter, ...],
        state: EditorState,
        width: int,
        height: int,
        theme: Theme,
    ) -> list[FragmentLine]:
        rows, active_row = ConfigList._rows(config, parameters, state, width, theme)
        if height <= 0:
            return []
        start = _viewport_start(active_row, len(rows), height)
        visible = rows[start : start + height]
        while len(visible) < height:
            visible.append(_fit_fragments([], width, theme))
        return [_fit_fragments(line, width, theme) for line in visible]

    @staticmethod
    def _rows(
        config: ProjectConfig,
        parameters: tuple[EditorParameter, ...],
        state: EditorState,
        width: int,
        theme: Theme,
    ) -> tuple[list[FragmentLine], int]:
        rows: list[FragmentLine] = []
        active_row = 0
        label_width = _label_width(parameters, width)
        for parameter_index, parameter in enumerate(parameters):
            expanded = state.expanded_index == parameter_index
            active_parameter = state.parameter_index == parameter_index and state.option_index is None
            if active_parameter:
                active_row = len(rows)
            rows.append(ConfigList._parameter_row(parameter, parameter_index, state, expanded, label_width, theme))
            if expanded:
                for option_index, option in enumerate(parameter.options):
                    active_option = state.parameter_index == parameter_index and state.option_index == option_index
                    if active_option:
                        active_row = len(rows)
                    rows.append(ConfigList._option_row(config, parameter, option, active_option, theme))
        return rows, active_row

    @staticmethod
    def _parameter_row(
        parameter: EditorParameter,
        parameter_index: int,
        state: EditorState,
        expanded: bool,
        label_width: int,
        theme: Theme,
    ) -> FragmentLine:
        active = state.parameter_index == parameter_index and state.option_index is None
        active_style = theme.style("active") if active else theme.style("root")
        marker = theme.symbols.active if active else " "
        expand_marker = theme.symbols.expanded if expanded else theme.symbols.collapsed
        name = WidthUtils.pad_right(f"{parameter.label}:", label_width)
        return [
            (active_style, " "),
            (active_style, marker),
            (active_style, " "),
            (active_style, expand_marker),
            (active_style, " "),
            (_merge_styles(active_style, theme.style("name")), name),
            (active_style, " "),
            (_merge_styles(active_style, theme.style(_value_style_key(parameter.key, parameter.value))), parameter.value),
        ]

    @staticmethod
    def _option_row(
        config: ProjectConfig,
        parameter: EditorParameter,
        option: EditorOption,
        active: bool,
        theme: Theme,
    ) -> FragmentLine:
        active_style = theme.style("active") if active else theme.style("root")
        active_marker = theme.symbols.active if active else " "
        selected_marker = theme.symbols.selected if _option_matches_current(config, parameter, option) else " "
        label_style = "muted" if option.action is not None else _value_style_key(parameter.key, option.label)
        return [
            (active_style, " "),
            (active_style, active_marker),
            (active_style, "   "),
            (_merge_styles(active_style, theme.style("green" if selected_marker.strip() else "muted")), selected_marker),
            (active_style, " "),
            (_merge_styles(active_style, theme.style(label_style)), option.label),
        ]


class SidePanel:
    @staticmethod
    def render(
        config: ProjectConfig,
        parameters: tuple[EditorParameter, ...],
        state: EditorState,
        width: int,
        height: int,
        theme: Theme,
    ) -> list[FragmentLine]:
        if width <= 0 or height <= 0:
            return []
        parameter = parameters[state.parameter_index]
        symbols = theme.symbols
        lines: list[FragmentLine] = [
            [(theme.style("border"), symbols.corner + symbols.horizontal * max(0, width - 2) + symbols.corner)],
            _panel_line("Details", width, theme, style_key="name"),
            _panel_line(f"setting  {parameter.label}", width, theme),
            _panel_line(
                f"value    {parameter.value}",
                width,
                theme,
                style_key=_value_style_key(parameter.key, parameter.value),
            ),
            _panel_line(f"choices  {len(parameter.options)}", width, theme),
        ]
        if state.expanded_index == state.parameter_index:
            lines.append(_panel_line("", width, theme))
            for option in parameter.options:
                marker = symbols.selected if _option_matches_current(config, parameter, option) else " "
                lines.append(_panel_line(f"{marker} {option.label}", width, theme))
        else:
            lines.append(_panel_line("", width, theme))
            lines.append(_panel_line("Enter expands this setting", width, theme, style_key="muted"))
        lines.append([(theme.style("border"), symbols.corner + symbols.horizontal * max(0, width - 2) + symbols.corner)])
        visible = lines[:height]
        while len(visible) < height:
            visible.append(_panel_line("", width, theme))
        return [_fit_fragments(line, width, theme, fill_style=theme.style("panel")) for line in visible]


def render_editor(
    config: ProjectConfig,
    state: EditorState,
    path: Path,
    model_choices: tuple[str, ...] | None = None,
    *,
    width: int | None = None,
    height: int | None = None,
    formatted: bool = False,
) -> str | FormattedRender:
    theme = Theme.from_environment()
    layout = LayoutSpec.from_size(width, height)
    parameters = parameter_defs(config, model_choices)
    lines = _render_editor_lines(config, state, path, parameters, layout, theme)
    if formatted:
        return _join_fragment_lines(lines)
    return "\n".join(_plain_line(line) for line in lines)


def _render_editor_lines(
    config: ProjectConfig,
    state: EditorState,
    path: Path,
    parameters: tuple[EditorParameter, ...],
    layout: LayoutSpec,
    theme: Theme,
) -> list[FragmentLine]:
    lines = [
        Header.render(path, layout, theme),
        PathBar.render(path, layout, theme),
        HelpLine.render(layout, theme),
    ]
    config_lines = ConfigList.render(config, parameters, state, layout.main_width, layout.list_height, theme)
    if layout.side_panel:
        side_lines = SidePanel.render(config, parameters, state, layout.side_width, layout.list_height, theme)
        body_lines = [_combine_body_line(left, right, theme) for left, right in zip(config_lines, side_lines, strict=True)]
    else:
        body_lines = [_fit_fragments(line, layout.width, theme) for line in config_lines]
    lines.extend(body_lines)
    lines.append(FooterStatus.render(config, parameters, state, layout, theme))
    return lines[: layout.height]


def _line_with_right(
    left: FragmentLine,
    right: FragmentLine,
    width: int,
    theme: Theme,
    *,
    fill_style: str | None = None,
) -> FragmentLine:
    fill = fill_style or theme.style("root")
    right_width = _fragment_width(right)
    if right_width >= width:
        return _fit_fragments(right, width, theme, fill_style=fill)
    left_width = max(0, width - right_width - 1)
    fitted_left = _fit_fragments(left, left_width, theme, fill_style=fill)
    gap = max(1, width - _fragment_width(fitted_left) - right_width)
    return [*fitted_left, (fill, " " * gap), *right]


def _combine_body_line(left: FragmentLine, right: FragmentLine, theme: Theme) -> FragmentLine:
    return [
        *left,
        (theme.style("border"), f" {theme.symbols.vertical} "),
        *right,
    ]


def _fit_fragments(
    fragments: FragmentLine,
    width: int,
    theme: Theme,
    *,
    fill_style: str | None = None,
) -> FragmentLine:
    if width <= 0:
        return []
    if _fragment_width(fragments) > width:
        return _truncate_fragments(fragments, width, theme)
    padding = width - _fragment_width(fragments)
    return [*fragments, (fill_style or theme.style("root"), " " * padding)]


def _truncate_fragments(fragments: FragmentLine, width: int, theme: Theme) -> FragmentLine:
    if width <= 0:
        return []
    placeholder_width = WidthUtils.display_width(ELLIPSIS)
    if width <= placeholder_width:
        return [(theme.style("muted"), WidthUtils.take_start(ELLIPSIS, width))]
    limit = width - placeholder_width
    used = 0
    result: FragmentLine = []
    for style, text in fragments:
        remaining = limit - used
        if remaining <= 0:
            break
        clipped = WidthUtils.take_start(text, remaining)
        if clipped:
            result.append((style, clipped))
            used += WidthUtils.display_width(clipped)
    result.append((theme.style("muted"), ELLIPSIS))
    return _fit_fragments(result, width, theme)


def _fragment_width(fragments: FragmentLine) -> int:
    return WidthUtils.display_width(_plain_line(fragments))


def _plain_line(fragments: FragmentLine) -> str:
    return "".join(text for _, text in fragments)


def _join_fragment_lines(lines: list[FragmentLine]) -> FormattedRender:
    fragments: FormattedRender = []
    for index, line in enumerate(lines):
        fragments.extend(line)
        if index + 1 < len(lines):
            fragments.append(("", "\n"))
    return fragments


def _label_width(parameters: tuple[EditorParameter, ...], width: int) -> int:
    widest = max((WidthUtils.display_width(parameter.label) + 1 for parameter in parameters), default=8)
    return min(max(10, widest), max(10, width // 3))


def _viewport_start(active_row: int, row_count: int, height: int) -> int:
    if height <= 0 or row_count <= height:
        return 0
    half_window = max(1, height // 2)
    start = max(0, active_row - half_window)
    return min(start, row_count - height)


def _panel_line(text: str, width: int, theme: Theme, *, style_key: str = "muted") -> FragmentLine:
    symbols = theme.symbols
    inner_width = max(0, width - 4)
    clipped = WidthUtils.pad_right(text, inner_width)
    return [
        (theme.style("border"), symbols.vertical),
        (theme.style("panel"), " "),
        (theme.style(style_key), clipped),
        (theme.style("panel"), " "),
        (theme.style("border"), symbols.vertical),
    ]


def _merge_styles(*styles: str) -> str:
    return " ".join(style for style in styles if style)


def _primary_action_hint(state: EditorState) -> str:
    if state.expanded_index == state.parameter_index and state.option_index is not None:
        return "Enter save"
    if state.expanded_index == state.parameter_index:
        return "Enter collapse"
    return "Enter expand"


def _value_style_key(parameter_key: str, value: str) -> str:
    normalized = value.strip().lower()
    if parameter_key in {"coder_mod", "super_mod"}:
        return "magenta"
    if "intelligence" in parameter_key:
        return "violet" if normalized == "xhigh" else "magenta"
    if parameter_key == "speed":
        return "yellow"
    if normalized == "true":
        return "green"
    if normalized == "false":
        return "red"
    if normalized in {"", "absent"}:
        return "violet"
    return "cyan"


def _option_matches_current(config: ProjectConfig, parameter: EditorParameter, option: EditorOption) -> bool:
    if option.action is not None or option.field is None:
        return False
    value = getattr(config, option.field)
    return value == option.value


def _prompt_toolkit_size(get_app: Any) -> tuple[int, int]:
    try:
        size = get_app().output.get_size()
    except Exception:
        terminal_size = shutil.get_terminal_size(fallback=(100, 30))
        return terminal_size.columns, terminal_size.lines
    return max(20, size.columns), max(4, size.rows)


def run_config_editor(project_root: Path) -> ProjectConfig:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError("sentinel config requires an interactive terminal")
    try:
        from prompt_toolkit import Application, prompt
        from prompt_toolkit.application.current import get_app
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.layout.controls import FormattedTextControl
        from prompt_toolkit.layout import Layout
        from prompt_toolkit.layout.containers import Window
    except ImportError as exc:
        raise RuntimeError("sentinel config requires prompt_toolkit; reinstall Sentinel with project dependencies") from exc

    config = load_project_config(project_root, create=True)
    model_choices = available_model_choices(project_root)
    path = project_config_path(project_root)
    state = EditorState()

    while True:
        pending_action: dict[str, EditorAction | bool | None] = {"action": None, "exit": False}

        def render_current() -> FormattedRender:
            width, height = _prompt_toolkit_size(get_app)
            return cast(
                FormattedRender,
                render_editor(config, state, path, model_choices, width=width, height=height, formatted=True),
            )

        control = FormattedTextControl(render_current, focusable=True)
        kb = KeyBindings()

        @kb.add("down")
        def _down(event) -> None:
            nonlocal state
            state = move_down(state, parameter_defs(config, model_choices))
            event.app.invalidate()

        @kb.add("up")
        def _up(event) -> None:
            nonlocal state
            state = move_up(state, parameter_defs(config, model_choices))
            event.app.invalidate()

        @kb.add("enter")
        def _enter(event) -> None:
            nonlocal config, state
            previous_config = config
            config, state, action = select_current(config, state, model_choices)
            if action is None:
                _save_config_change(project_root, previous_config, config)
                event.app.invalidate()
                return
            pending_action["action"] = action
            event.app.exit()

        @kb.add("escape")
        @kb.add("q")
        @kb.add("c-c")
        def _exit(event) -> None:
            pending_action["exit"] = True
            event.app.exit()

        app = Application(layout=Layout(Window(content=control, wrap_lines=False)), key_bindings=kb, full_screen=True)
        app.run()
        if pending_action["exit"]:
            return config

        action = pending_action["action"]
        parameter = parameter_defs(config, model_choices)[state.parameter_index]
        if action == "edit_text" and parameter.key == "task":
            raw = prompt("Task path (blank to unset): ", default=config.task or "")
            previous_config = config
            config = replace(config, task=raw.strip() or None)
            _save_config_change(project_root, previous_config, config)
            state = advance_after_selection(state, len(parameter_defs(config, model_choices)))
        elif action == "add_protected_path":
            raw = prompt("Protected path: ")
            value = raw.strip()
            if value:
                previous_config = config
                config = replace(config, protected_path=tuple([*config.protected_path, value]))
                _save_config_change(project_root, previous_config, config)
            state = advance_after_selection(state, len(parameter_defs(config, model_choices)))


def _format_bool(value: bool) -> str:
    return "true" if value else "false"


def _save_config_change(project_root: Path, previous_config: ProjectConfig, config: ProjectConfig) -> None:
    changed_fields = changed_project_config_fields(previous_config, config)
    if changed_fields:
        sync_runtime_config_fields(project_root, config, changed_fields)


def available_model_choices(project_root: Path) -> tuple[str, ...]:
    models = _available_models_from_app_server(project_root)
    if not models:
        models = _available_models_from_cache()
    return _normalize_model_choices(models)


def _model_choices_for_config(config: ProjectConfig, model_choices: tuple[str, ...] | None) -> tuple[str, ...]:
    return _normalize_model_choices(
        [
            *(model_choices or ()),
            config.coder_mod,
            config.super_mod,
            DEFAULT_MODEL,
        ]
    )


def _normalize_model_choices(models: Any) -> tuple[str, ...]:
    values: list[str] = []
    if isinstance(models, str):
        candidates = [models]
    else:
        candidates = list(models) if isinstance(models, list | tuple | set) else []
    for candidate in candidates:
        if isinstance(candidate, str):
            value = candidate.strip()
            if value and value not in values:
                values.append(value)
    if DEFAULT_MODEL in values:
        values.remove(DEFAULT_MODEL)
    return tuple([DEFAULT_MODEL, *values])


def _available_models_from_cache() -> tuple[str, ...]:
    path = Path.home() / ".codex" / "models_cache.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ()
    models = payload.get("models")
    if not isinstance(models, list):
        return ()
    choices: list[str] = []
    for model in models:
        if not isinstance(model, dict):
            continue
        if model.get("visibility") == "hidden" or model.get("hidden") is True:
            continue
        slug = model.get("slug") or model.get("id") or model.get("model")
        if isinstance(slug, str):
            choices.append(slug)
    return tuple(choices)


def _available_models_from_app_server(project_root: Path) -> tuple[str, ...]:
    async def read_models() -> tuple[str, ...]:
        client = AppServerClient(cwd=project_root)
        await client.start()
        try:
            await client.initialize()
            response = await client.model_list()
            return tuple(_extract_model_ids(response))
        finally:
            await client.stop()

    try:
        return asyncio.run(read_models())
    except Exception:
        return ()


def _extract_model_ids(value: Any) -> set[str]:
    ids: set[str] = set()
    if isinstance(value, dict):
        if value.get("hidden") is True:
            return ids
        for key in ("id", "model", "slug", "name"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                ids.add(candidate.strip())
        for key in ("data", "models", "items"):
            nested = value.get(key)
            if nested is not None:
                ids.update(_extract_model_ids(nested))
    elif isinstance(value, list | tuple):
        for item in value:
            ids.update(_extract_model_ids(item))
    return ids
