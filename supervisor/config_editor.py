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


EditorAction = Literal["add_protected_path"]
InlineEditKind = Literal["optional_text", "non_negative_int", "protected_path_entry"]
StyledFragment = tuple[str, str]
FragmentLine = list[StyledFragment]
FormattedRender = list[StyledFragment]

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ELLIPSIS = "..."
EDIT_CURSOR = "▏"
OUTER_BORDER_GRADIENT = (
    "#18f8ff",
    "#10d0ff",
    "#1888ff",
    "#383080",
    "#8078ff",
    "#b860ff",
    "#f060f8",
)
PANEL_BORDER_GRADIENT = (
    "#182850",
    "#243068",
    "#303878",
    "#383080",
    "#303878",
)
ACTIVE_ROW_BG_GRADIENT = (
    "#100832",
)


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
    edit_kind: InlineEditKind | None = None


@dataclass(frozen=True)
class EditorState:
    parameter_index: int = 0
    expanded_index: int | None = None
    option_index: int | None = None
    editing: bool = False
    edit_kind: InlineEditKind | None = None
    edit_value: str = ""
    edit_error: str | None = None


@dataclass(frozen=True)
class Symbols:
    active: str = ">"
    collapsed: str = ">"
    expanded: str = "v"
    selected: str = "*"
    horizontal: str = "-"
    vertical: str = "|"
    top_left: str = "+"
    top_right: str = "+"
    bottom_left: str = "+"
    bottom_right: str = "+"
    tee_left: str = "+"
    tee_right: str = "+"
    branch_mid: str = "|-"
    branch_last: str = "`-"
    bullet: str = "*"

    @classmethod
    def default(cls) -> Symbols:
        return cls.unicode()

    @classmethod
    def ascii(cls) -> Symbols:
        return cls()

    @classmethod
    def unicode(cls) -> Symbols:
        return cls(
            active="›",
            collapsed="▸",
            expanded="▾",
            selected="✦",
            horizontal="─",
            vertical="│",
            top_left="╭",
            top_right="╮",
            bottom_left="╰",
            bottom_right="╯",
            tee_left="├",
            tee_right="┤",
            branch_mid="├─",
            branch_last="└─",
            bullet="•",
        )


@dataclass(frozen=True)
class Theme:
    symbols: Symbols
    styles: dict[str, str]

    @classmethod
    def from_environment(cls) -> Theme:
        ascii_enabled = os.environ.get("SENTINEL_CONFIG_ASCII", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        symbols = Symbols.ascii() if ascii_enabled else Symbols.default()
        styles = {
            "root": "#ddd7eb bg:#050716",
            "surface": "#ddd7eb bg:#050716",
            "header": "#f3dcff bold bg:#06081a",
            "header_title": "#f860ff bold",
            "logo": "#08ffff bold",
            "badge": "#a990ff bg:#090c22",
            "badge_border": "#30245c bg:#080820",
            "chip": "#40e880 bold bg:#090c22",
            "keycap": "#08ffff bg:#080820",
            "footer": "#d8d0ea bg:#06091c",
            "json_badge": "#08ffff bold bg:#090c22",
            "icon_badge": "#08ffff bold bg:#0b1030",
            "save_badge": "#08ffff bg:#090c22",
            "ok": "#40e880 bold",
            "exit": "#d8cdf4",
            "muted": "#8175a5",
            "muted_purple": "#7050c0",
            "cyan": "#08ffff",
            "violet": "#8078ff",
            "magenta": "#f060f8",
            "magenta_soft": "#a828b8",
            "green": "#40e880",
            "yellow": "#ffc018",
            "red": "#f84858",
            "active": "#f7f1ff bg:#100832",
            "active_dark": "#f7f1ff bg:#100832",
            "active_marker": "#08ffff bold",
            "active_glow_left": "#18f8ff bg:#100832",
            "active_glow_right": "#f060f8 bg:#100832",
            "name": "#f0eaff",
            "border": "#383080 bg:#050716",
            "border_soft": "#182850 bg:#050716",
            "border_left": "#18f8ff bg:#050716",
            "border_right": "#f060f8 bg:#050716",
            "border_bright": "#f060f8 bg:#050716",
            "panel_border": "#303878 bg:#06091c",
            "panel_border_soft": "#182850 bg:#06091c",
            "panel_active_border": "#18f8ff bg:#100832",
            "panel": "#d8d0ea bg:#06091c",
            "panel_header": "#d8d0ea bg:#070a20",
            "panel_title": "#8078ff bold",
            "row_divider": "#182850 bg:#06091c",
            "table_header": "#8078ff bold",
            "tree": "#7050c0",
            "white": "#f0eaff",
        }
        return cls(
            symbols=symbols,
            styles=styles,
        )

    def style(self, *keys: str) -> str:
        return " ".join(self.styles[key] for key in keys if key in self.styles)


@dataclass(frozen=True)
class LayoutSpec:
    width: int
    height: int
    content_width: int
    list_height: int
    main_width: int
    side_width: int
    side_panel: bool
    gap_width: int

    @classmethod
    def from_size(cls, width: int | None = None, height: int | None = None) -> LayoutSpec:
        terminal_size = shutil.get_terminal_size(fallback=(100, 30))
        resolved_width = max(20, width or terminal_size.columns)
        resolved_height = max(4, height or terminal_size.lines)
        side_panel = resolved_width >= 120
        content_width = max(0, resolved_width - 2)
        side_width = min(34, max(30, content_width // 5)) if side_panel else 0
        gap_width = 2 if side_panel else 0
        main_width = max(20, content_width - side_width - gap_width)
        fixed_lines = 8
        list_height = max(0, resolved_height - fixed_lines)
        return cls(
            width=resolved_width,
            height=resolved_height,
            content_width=content_width,
            list_height=list_height,
            main_width=main_width,
            side_width=side_width,
            side_panel=side_panel,
            gap_width=gap_width,
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
            (),
            edit_kind="optional_text",
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
            "adversary_runs",
            "max-adversary-runs",
            str(config.adversary_runs if config.adversary else 0),
            (),
            edit_kind="non_negative_int",
        ),
        EditorParameter(
            "completion_returns_per_generation",
            "max-completion-returns-per-generation",
            str(config.completion_returns_per_generation),
            (),
            edit_kind="non_negative_int",
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
    if state.editing:
        return state
    if state.expanded_index == state.parameter_index:
        option_count = len(parameters[state.parameter_index].options)
        if state.option_index is None and option_count:
            return replace(state, option_index=0)
        if state.option_index + 1 < option_count:
            return replace(state, option_index=state.option_index + 1)
    next_index = min(state.parameter_index + 1, len(parameters) - 1)
    return EditorState(parameter_index=next_index)


def move_up(state: EditorState, parameters: tuple[EditorParameter, ...]) -> EditorState:
    if state.editing:
        return state
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
    if state.editing:
        updated, updated_state = _commit_inline_edit(config, state, parameters)
        return updated, updated_state, None
    if parameter.edit_kind is not None and state.option_index is None:
        return config, _start_inline_edit(config, state, parameter), None
    if state.expanded_index != state.parameter_index:
        return config, replace(state, expanded_index=state.parameter_index, option_index=None), None
    if state.option_index is None:
        return config, replace(state, expanded_index=None), None

    option = parameter.options[state.option_index]
    if option.action == "add_protected_path":
        return config, _start_inline_edit(config, state, parameter, edit_kind="protected_path_entry", initial_value=""), None
    if option.field is None:
        return config, advance_after_selection(state, len(parameters)), None
    updated = _replace_config_field(config, option.field, option.value)
    return updated, advance_after_selection(state, len(parameters)), None


def advance_after_selection(state: EditorState, parameter_count: int) -> EditorState:
    return EditorState(parameter_index=min(state.parameter_index + 1, parameter_count - 1))


def append_inline_text(state: EditorState, text: str) -> EditorState:
    if not state.editing or not _printable_text(text):
        return state
    return replace(state, edit_value=state.edit_value + text, edit_error=None)


def backspace_inline_text(state: EditorState) -> EditorState:
    if not state.editing:
        return state
    return replace(state, edit_value=state.edit_value[:-1], edit_error=None)


def cancel_inline_edit(state: EditorState) -> EditorState:
    if not state.editing:
        return state
    return replace(state, editing=False, edit_kind=None, edit_value="", edit_error=None)


def _start_inline_edit(
    config: ProjectConfig,
    state: EditorState,
    parameter: EditorParameter,
    *,
    edit_kind: InlineEditKind | None = None,
    initial_value: str | None = None,
) -> EditorState:
    kind = edit_kind or parameter.edit_kind
    if kind is None:
        return state
    value = initial_value if initial_value is not None else _inline_initial_value(config, parameter)
    return replace(
        state,
        expanded_index=None,
        option_index=None,
        editing=True,
        edit_kind=kind,
        edit_value=value,
        edit_error=None,
    )


def _inline_initial_value(config: ProjectConfig, parameter: EditorParameter) -> str:
    if parameter.key == "task":
        return config.task or ""
    if parameter.key == "adversary_runs":
        return str(config.adversary_runs if config.adversary else 0)
    if parameter.key == "completion_returns_per_generation":
        return str(config.completion_returns_per_generation)
    return parameter.value if parameter.value != "absent" else ""


def _commit_inline_edit(
    config: ProjectConfig,
    state: EditorState,
    parameters: tuple[EditorParameter, ...],
) -> tuple[ProjectConfig, EditorState]:
    parameter = parameters[state.parameter_index]
    raw = state.edit_value.strip()
    if state.edit_kind == "optional_text":
        updated = _replace_config_field(config, parameter.key, raw or None)
        return updated, advance_after_selection(state, len(parameters))
    if state.edit_kind == "protected_path_entry":
        updated = config
        if raw:
            updated = replace(config, protected_path=tuple([*config.protected_path, raw]))
        return updated, advance_after_selection(state, len(parameters))
    if state.edit_kind == "non_negative_int":
        if not raw.isdecimal():
            return config, replace(state, edit_error="enter a non-negative integer")
        updated = _replace_config_field(config, parameter.key, int(raw))
        return updated, advance_after_selection(state, len(parameters))
    return config, cancel_inline_edit(state)


def _replace_config_field(config: ProjectConfig, field: str, value: Any) -> ProjectConfig:
    if field == "adversary_runs":
        runs = int(value)
        return replace(config, adversary_runs=runs, adversary=runs > 0)
    return replace(config, **{field: value})


def _printable_text(text: str) -> bool:
    return bool(text) and all(char >= " " and char != "\x7f" for char in text)


class Header:
    @staticmethod
    def render(path: Path, layout: LayoutSpec, theme: Theme) -> FragmentLine:
        left: FragmentLine = [
            (_merge_styles(theme.style("header"), theme.style("logo")), _logo_symbol(theme)),
            (theme.style("header"), " "),
            (_merge_styles(theme.style("header"), theme.style("header_title")), "SENTINEL PROJECT CONFIG"),
            (theme.style("header"), " "),
            *_inline_badge(path.name, theme, "badge"),
        ]
        if layout.content_width < 90:
            right: FragmentLine = [
                *_inline_badge(f"{theme.symbols.bullet} CONFIG LOADED", theme, "chip"),
                (theme.style("header"), " "),
                *_inline_badge("ESC", theme, "keycap"),
                (_merge_styles(theme.style("header"), theme.style("exit")), " / q"),
            ]
        else:
            right = [
                *_inline_badge(f"{theme.symbols.bullet} CONFIG LOADED", theme, "chip"),
                (theme.style("header"), " "),
                *_inline_badge("ESC", theme, "keycap"),
                (_merge_styles(theme.style("header"), theme.style("exit")), " / q to exit "),
            ]
        return _frame_line(
            _line_with_right(left, right, layout.content_width, theme, fill_style=theme.style("header")),
            layout,
            theme,
            fill_style=theme.style("header"),
        )


class PathBar:
    @staticmethod
    def render(path: Path, layout: LayoutSpec, theme: Theme) -> FragmentLine:
        prefix_width = WidthUtils.display_width(f"  {_path_symbol(theme)}  Path: ")
        path_width = max(0, layout.content_width - prefix_width - 2)
        value = WidthUtils.truncate_middle(str(path), path_width)
        return _frame_line(
            _fit_fragments(
                [
                    (_merge_styles(theme.style("surface"), theme.style("cyan")), f"  {_path_symbol(theme)}  "),
                    (_merge_styles(theme.style("surface"), theme.style("white")), "Path: "),
                    (_merge_styles(theme.style("surface"), theme.style("cyan")), value),
                ],
                layout.content_width,
                theme,
                fill_style=theme.style("surface"),
            ),
            layout,
            theme,
            fill_style=theme.style("surface"),
        )


class HelpLine:
    @staticmethod
    def render(layout: LayoutSpec, theme: Theme, state: EditorState) -> FragmentLine:
        text = (
            "    Type value. Enter saves. Esc cancels. Backspace edits."
            if state.editing
            else "    Arrows move. Enter expands or saves. Esc/q exits."
        )
        return _frame_line(
            _fit_fragments(
                [(_merge_styles(theme.style("surface"), theme.style("muted")), text)],
                layout.content_width,
                theme,
                fill_style=theme.style("surface"),
            ),
            layout,
            theme,
            fill_style=theme.style("surface"),
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
        nested_count = _visible_option_count(parameters, state)
        left: FragmentLine = [
            *_inline_badge(_code_symbol(theme), theme, "icon_badge"),
            (theme.style("footer"), " "),
            *_inline_badge("JSON", theme, "json_badge"),
            (theme.style("footer"), "  "),
            (_merge_styles(theme.style("footer"), theme.style("muted")), f"{len(parameters)} keys"),
            (_merge_styles(theme.style("footer"), theme.style("muted")), f"  {theme.symbols.bullet}  "),
            (_merge_styles(theme.style("footer"), theme.style("muted")), f"{nested_count} nested"),
            (theme.style("footer"), "  "),
        ]
        right: FragmentLine = [
            *_inline_badge(_save_symbol(theme), theme, "save_badge"),
            (theme.style("footer"), " "),
            (_merge_styles(theme.style("footer"), theme.style("exit")), "Enter to save "),
        ]
        return _frame_line(
            _line_with_right(left, right, layout.content_width, theme, fill_style=theme.style("footer")),
            layout,
            theme,
            fill_style=theme.style("footer"),
        )


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
        if height == 1:
            return [_fit_fragments(rows[active_row], width, theme, fill_style=theme.style("surface"))]

        label_width = _label_width(parameters, max(0, width - 2))
        row_height = max(0, height - 3)
        start = _viewport_start(active_row, len(rows), row_height)
        visible = rows[start : start + row_height]
        inner_width = max(0, width - 2)
        rendered: list[FragmentLine] = [_panel_border(width, theme, top=True)]
        if height > 2:
            rendered.append(_panel_row(ConfigList._table_header(label_width, theme), inner_width, theme))
        rendered.extend(_panel_row(row, inner_width, theme) for row in visible)
        while len(rendered) < height - 1:
            rendered.append(_panel_row([], inner_width, theme))
        rendered.append(_panel_border(width, theme, top=False))
        return rendered[:height]

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
        label_width = _label_width(parameters, max(0, width - 2))
        inner_width = max(0, width - 2)
        for parameter_index, parameter in enumerate(parameters):
            expanded = not state.editing and state.expanded_index == parameter_index
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
            if parameter_index + 1 < len(parameters):
                rows.append(ConfigList._row_divider(inner_width, theme))
        return rows, active_row

    @staticmethod
    def _table_header(label_width: int, theme: Theme) -> FragmentLine:
        marker_width = 9
        return [
            (theme.style("panel_header"), " " * marker_width),
            (_merge_styles(theme.style("panel_header"), theme.style("table_header")), WidthUtils.pad_right("SETTING", label_width)),
            (theme.style("panel_header"), "  "),
            (_merge_styles(theme.style("panel_header"), theme.style("table_header")), "VALUE"),
        ]

    @staticmethod
    def _row_divider(width: int, theme: Theme) -> FragmentLine:
        if width <= 4:
            return [(theme.style("row_divider"), theme.symbols.horizontal * max(0, width))]
        return [
            (theme.style("panel"), "  "),
            (theme.style("row_divider"), theme.symbols.horizontal * (width - 4)),
            (theme.style("panel"), "  "),
        ]

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
        active_style = theme.style("active") if active else theme.style("panel")
        marker = theme.symbols.active if active else " "
        expand_marker = theme.symbols.expanded if expanded else theme.symbols.collapsed
        icon = _parameter_icon(parameter.key, theme)
        name = WidthUtils.pad_right(parameter.label, label_width)
        return [
            (active_style, " "),
            (_merge_styles(active_style, theme.style("active_marker" if active else "muted")), marker),
            (active_style, " "),
            (_merge_styles(active_style, theme.style("violet")), expand_marker),
            (active_style, " "),
            (_merge_styles(active_style, theme.style(_icon_style_key(parameter.key))), icon),
            (active_style, "  "),
            (_merge_styles(active_style, theme.style("name")), name),
            (active_style, "  "),
            *_parameter_value_fragments(parameter, parameter_index, state, active_style, theme),
        ]

    @staticmethod
    def _option_row(
        config: ProjectConfig,
        parameter: EditorParameter,
        option: EditorOption,
        active: bool,
        theme: Theme,
    ) -> FragmentLine:
        active_style = theme.style("active") if active else theme.style("panel")
        active_marker = theme.symbols.active if active else " "
        selected_marker = theme.symbols.selected if _option_matches_current(config, parameter, option) else " "
        label_style = "muted" if option.action is not None else _value_style_key(parameter.key, option.label)
        return [
            (active_style, " "),
            (_merge_styles(active_style, theme.style("active_marker" if active else "muted")), active_marker),
            (active_style, "      "),
            (_merge_styles(active_style, theme.style("tree")), _option_branch(parameter, option, theme)),
            (active_style, " "),
            (_merge_styles(active_style, theme.style("green" if selected_marker.strip() else "muted")), selected_marker),
            (active_style, "  "),
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
        symbols = theme.symbols
        content: list[FragmentLine] = [
            _side_text("NAVIGATION", theme, style_key="panel_title"),
            _side_text("^ up", theme, style_key="name"),
            _side_text("v down", theme, style_key="name"),
            _side_text(f"{symbols.active} select", theme, style_key="name"),
            _side_text(f"{_enter_symbol(theme)} enter", theme, style_key="name"),
            _side_text("esc back / exit", theme, style_key="name"),
            _side_divider(width, theme),
            _side_text("STATUS", theme, style_key="panel_title"),
            _side_text(f"{symbols.selected} Ready", theme, style_key="green"),
            _side_text("  Config valid", theme, style_key="muted"),
            _side_divider(width, theme),
            _side_text("TIPS", theme, style_key="panel_title"),
            _side_text(f"{_tip_symbol(theme)} Use arrows to", theme, style_key="muted"),
            _side_text("  navigate", theme, style_key="muted"),
            _side_text("  Enter to edit", theme, style_key="muted"),
            _side_text("  or expand", theme, style_key="muted"),
        ]
        if height == 1:
            return [_fit_fragments(content[0], width, theme, fill_style=theme.style("panel"))]

        inner_width = max(0, width - 2)
        visible = content[: max(0, height - 2)]
        rendered: list[FragmentLine] = [_panel_border(width, theme, top=True)]
        rendered.extend(_panel_row(line, inner_width, theme) for line in visible)
        while len(rendered) < height - 1:
            rendered.append(_panel_row([], inner_width, theme))
        rendered.append(_panel_border(width, theme, top=False))
        return rendered[:height]


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
        _horizontal_line(layout, theme, top=True),
        Header.render(path, layout, theme),
        _horizontal_line(layout, theme, tee=True),
        PathBar.render(path, layout, theme),
        _horizontal_line(layout, theme, tee=True),
        HelpLine.render(layout, theme, state),
    ]
    config_lines = ConfigList.render(config, parameters, state, layout.main_width, layout.list_height, theme)
    if layout.side_panel:
        side_lines = SidePanel.render(config, parameters, state, layout.side_width, layout.list_height, theme)
        body_lines = [
            _frame_line(_combine_body_line(left, right, layout, theme), layout, theme, fill_style=theme.style("surface"))
            for left, right in zip(config_lines, side_lines, strict=True)
        ]
    else:
        body_lines = [
            _frame_line(
                _fit_fragments(line, layout.content_width, theme, fill_style=theme.style("surface")),
                layout,
                theme,
                fill_style=theme.style("surface"),
            )
            for line in config_lines
        ]
    lines.extend(body_lines)
    lines.append(FooterStatus.render(config, parameters, state, layout, theme))
    lines.append(_horizontal_line(layout, theme, top=False))
    return lines[: layout.height]


def _horizontal_line(layout: LayoutSpec, theme: Theme, *, top: bool = False, tee: bool = False) -> FragmentLine:
    symbols = theme.symbols
    if top:
        left = symbols.top_left
        right = symbols.top_right
    elif tee:
        left = symbols.tee_left
        right = symbols.tee_right
    else:
        left = symbols.bottom_left
        right = symbols.bottom_right
    return [
        (theme.style("border_left"), left),
        *_horizontal_border_segments(symbols.horizontal, layout.content_width, theme),
        (theme.style("border_right"), right),
    ]


def _frame_line(
    fragments: FragmentLine,
    layout: LayoutSpec,
    theme: Theme,
    *,
    fill_style: str | None = None,
) -> FragmentLine:
    inner = _fit_fragments(fragments, layout.content_width, theme, fill_style=fill_style or theme.style("surface"))
    return [
        (theme.style("border_left"), theme.symbols.vertical),
        *inner,
        (theme.style("border_right"), theme.symbols.vertical),
    ]


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


def _inline_badge(text: str, theme: Theme, style_key: str) -> FragmentLine:
    return [
        (theme.style("badge_border"), " "),
        (_merge_styles(theme.style("badge"), theme.style(style_key)), f" {text} "),
        (theme.style("badge_border"), " "),
    ]


def _horizontal_border_segments(symbol: str, width: int, theme: Theme) -> FragmentLine:
    return _gradient_segments(symbol, width, OUTER_BORDER_GRADIENT, "#050716")


def _gradient_segments(symbol: str, width: int, colors: tuple[str, ...], bg: str) -> FragmentLine:
    if width <= 0:
        return []
    fragments: FragmentLine = []
    current_color: str | None = None
    current_text: list[str] = []
    for index in range(width):
        color_index = min(len(colors) - 1, index * len(colors) // width)
        color = colors[color_index]
        if color != current_color and current_text:
            fragments.append((_color_style(cast(str, current_color), bg), "".join(current_text)))
            current_text = []
        current_color = color
        current_text.append(symbol)
    if current_text and current_color is not None:
        fragments.append((_color_style(current_color, bg), "".join(current_text)))
    return fragments


def _color_style(fg: str, bg: str) -> str:
    return f"{fg} bg:{bg}"


def _combine_body_line(left: FragmentLine, right: FragmentLine, layout: LayoutSpec, theme: Theme) -> FragmentLine:
    gap = (theme.style("surface"), " " * layout.gap_width)
    return [
        *left,
        gap,
        *right,
    ]


def _panel_border(width: int, theme: Theme, *, top: bool) -> FragmentLine:
    symbols = theme.symbols
    left = symbols.top_left if top else symbols.bottom_left
    right = symbols.top_right if top else symbols.bottom_right
    inner_width = max(0, width - 2)
    return [
        (theme.style("panel_border"), left),
        *_gradient_segments(symbols.horizontal, inner_width, PANEL_BORDER_GRADIENT, "#06091c"),
        (theme.style("panel_border"), right),
    ]


def _panel_row(fragments: FragmentLine, inner_width: int, theme: Theme) -> FragmentLine:
    active = _line_has_style(fragments, theme.style("active"))
    if active:
        fill_style = theme.style("active")
    elif _line_has_style(fragments, theme.style("panel_header")):
        fill_style = theme.style("panel_header")
    else:
        fill_style = theme.style("panel")
    fitted = _fit_active_row_fragments(fragments, inner_width, theme) if active else _fit_fragments(
        fragments,
        inner_width,
        theme,
        fill_style=fill_style,
    )
    left_edge_style = theme.style("active_glow_left") if active else theme.style("panel_border")
    right_edge_style = theme.style("active_glow_right") if active else theme.style("panel_border")
    return [
        (left_edge_style, theme.symbols.vertical),
        *fitted,
        (right_edge_style, theme.symbols.vertical),
    ]


def _fit_active_row_fragments(fragments: FragmentLine, width: int, theme: Theme) -> FragmentLine:
    fitted = _fit_fragments(fragments, width, theme, fill_style=theme.style("active"))
    return _apply_background_gradient(fitted, max(1, width), ACTIVE_ROW_BG_GRADIENT)


def _apply_background_gradient(fragments: FragmentLine, width: int, colors: tuple[str, ...]) -> FragmentLine:
    rendered: FragmentLine = []
    column = 0
    for style, text in fragments:
        current_style: str | None = None
        current_text: list[str] = []
        for char in text:
            char_width = max(wcwidth(char), 0)
            color_index = min(len(colors) - 1, column * len(colors) // width)
            next_style = _style_with_bg(style, colors[color_index])
            if next_style != current_style and current_text:
                rendered.append((cast(str, current_style), "".join(current_text)))
                current_text = []
            current_style = next_style
            current_text.append(char)
            column += char_width
        if current_text and current_style is not None:
            rendered.append((current_style, "".join(current_text)))
    return rendered


def _style_with_bg(style: str, bg: str) -> str:
    tokens = [token for token in style.split() if not token.startswith("bg:")]
    return " ".join([*tokens, f"bg:{bg}"])


def _side_text(text: str, theme: Theme, *, style_key: str) -> FragmentLine:
    return [
        (theme.style("panel"), "  "),
        (_merge_styles(theme.style("panel"), theme.style(style_key)), text),
    ]


def _side_divider(width: int, theme: Theme) -> FragmentLine:
    return [
        (theme.style("panel_border"), theme.symbols.horizontal * max(0, width - 2)),
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
        return [(_merge_styles(theme.style("surface"), theme.style("muted")), WidthUtils.take_start(ELLIPSIS, width))]
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
    result.append((_merge_styles(theme.style("surface"), theme.style("muted")), ELLIPSIS))
    return _fit_fragments(result, width, theme)


def _fragment_width(fragments: FragmentLine) -> int:
    return WidthUtils.display_width(_plain_line(fragments))


def _plain_line(fragments: FragmentLine) -> str:
    return "".join(text for _, text in fragments)


def _line_has_style(fragments: FragmentLine, style_key: str) -> bool:
    return any(style_key in style for style, _ in fragments)


def _join_fragment_lines(lines: list[FragmentLine]) -> FormattedRender:
    fragments: FormattedRender = []
    for index, line in enumerate(lines):
        fragments.extend(line)
        if index + 1 < len(lines):
            fragments.append(("", "\n"))
    return fragments


def _label_width(parameters: tuple[EditorParameter, ...], width: int) -> int:
    widest = max((WidthUtils.display_width(parameter.label) + 1 for parameter in parameters), default=8)
    return min(max(32, widest), max(24, width // 2))


def _visible_option_count(parameters: tuple[EditorParameter, ...], state: EditorState) -> int:
    if state.editing:
        return 0
    if state.expanded_index is None:
        return 0
    if state.expanded_index < 0 or state.expanded_index >= len(parameters):
        return 0
    return len(parameters[state.expanded_index].options)


def _parameter_icon(parameter_key: str, theme: Theme) -> str:
    if _ascii_symbols(theme):
        return {
            "task": "T",
            "coder_mod": "C",
            "super_mod": "S",
            "coder_intelligence": "I",
            "super_intelligence": "I",
            "speed": "F",
            "start_over": "R",
            "adversary": "A",
            "adversary_runs": "N",
            "completion_returns_per_generation": "N",
            "clean": "X",
            "protected_path": "P",
        }.get(parameter_key, "-")
    return {
        "task": "☑",
        "coder_mod": "◇",
        "super_mod": "☆",
        "coder_intelligence": "✾",
        "super_intelligence": "✾",
        "speed": "⚡",
        "start_over": "↻",
        "adversary": "◈",
        "adversary_runs": "#",
        "completion_returns_per_generation": "#",
        "clean": "✧",
        "protected_path": "▣",
    }.get(parameter_key, "•")


def _ascii_symbols(theme: Theme) -> bool:
    return theme.symbols.top_left == "+"


def _logo_symbol(theme: Theme) -> str:
    return "S" if _ascii_symbols(theme) else "◇"


def _path_symbol(theme: Theme) -> str:
    return ">" if _ascii_symbols(theme) else "▣"


def _code_symbol(theme: Theme) -> str:
    return "<>" if _ascii_symbols(theme) else "</>"


def _save_symbol(theme: Theme) -> str:
    return "[]" if _ascii_symbols(theme) else "▥"


def _enter_symbol(theme: Theme) -> str:
    return "ret" if _ascii_symbols(theme) else "↵"


def _tip_symbol(theme: Theme) -> str:
    return "*" if _ascii_symbols(theme) else "◇"


def _icon_style_key(parameter_key: str) -> str:
    return {
        "task": "violet",
        "coder_mod": "violet",
        "super_mod": "magenta",
        "coder_intelligence": "magenta",
        "super_intelligence": "magenta",
        "speed": "yellow",
        "start_over": "magenta",
        "adversary": "green",
        "adversary_runs": "cyan",
        "completion_returns_per_generation": "cyan",
        "clean": "red",
        "protected_path": "magenta",
    }.get(parameter_key, "muted")


def _option_branch(parameter: EditorParameter, option: EditorOption, theme: Theme) -> str:
    return theme.symbols.branch_last if option == parameter.options[-1] else theme.symbols.branch_mid


def _viewport_start(active_row: int, row_count: int, height: int) -> int:
    if height <= 0 or row_count <= height:
        return 0
    if height == 1:
        return min(active_row, row_count - height)
    half_window = max(1, height // 2)
    start = max(0, active_row - half_window)
    return min(start, row_count - height)


def _panel_line(text: str, width: int, theme: Theme, *, style_key: str = "muted") -> FragmentLine:
    symbols = theme.symbols
    inner_width = max(0, width - 4)
    clipped = WidthUtils.pad_right(text, inner_width)
    return [
        (theme.style("panel_border"), symbols.vertical),
        (theme.style("panel"), " "),
        (_merge_styles(theme.style("panel"), theme.style(style_key)), clipped),
        (theme.style("panel"), " "),
        (theme.style("panel_border"), symbols.vertical),
    ]


def _merge_styles(*styles: str) -> str:
    return " ".join(style for style in styles if style)


def _primary_action_hint(state: EditorState) -> str:
    if state.expanded_index == state.parameter_index and state.option_index is not None:
        return "Enter to save"
    if state.expanded_index == state.parameter_index:
        return "Enter to collapse"
    return "Enter to expand"


def _value_style_key(parameter_key: str, value: str) -> str:
    normalized = value.strip().lower()
    if parameter_key in {"coder_mod", "super_mod"}:
        return "magenta_soft"
    if parameter_key in {"adversary_runs", "completion_returns_per_generation"}:
        return "cyan"
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


def _parameter_value_fragments(
    parameter: EditorParameter,
    parameter_index: int,
    state: EditorState,
    active_style: str,
    theme: Theme,
) -> FragmentLine:
    value_style = _merge_styles(active_style, theme.style(_value_style_key(parameter.key, parameter.value)))
    if state.editing and state.parameter_index == parameter_index:
        fragments: FragmentLine = [
            (value_style, state.edit_value),
            (_merge_styles(active_style, theme.style("active_marker")), EDIT_CURSOR),
        ]
        if state.edit_error:
            fragments.extend(
                [
                    (active_style, "  "),
                    (_merge_styles(active_style, theme.style("red")), state.edit_error),
                ]
            )
        return fragments
    return [(value_style, parameter.value)]


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
        from prompt_toolkit import Application
        from prompt_toolkit.application.current import get_app
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.layout.controls import FormattedTextControl
        from prompt_toolkit.layout import Layout
        from prompt_toolkit.layout.containers import Window
        from prompt_toolkit.styles import Style
    except ImportError as exc:
        raise RuntimeError("sentinel config requires prompt_toolkit; reinstall Sentinel with project dependencies") from exc

    config = load_project_config(project_root, create=True)
    model_choices = available_model_choices(project_root)
    path = project_config_path(project_root)
    state = EditorState()
    should_exit = False

    def render_current() -> FormattedRender:
        width, height = _prompt_toolkit_size(get_app)
        return cast(
            FormattedRender,
            render_editor(config, state, path, model_choices, width=width, height=height, formatted=True),
        )

    control = FormattedTextControl(render_current, focusable=True, show_cursor=False)
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
        config, state, _action = select_current(config, state, model_choices)
        _save_config_change(project_root, previous_config, config)
        event.app.invalidate()

    @kb.add("backspace")
    def _backspace(event) -> None:
        nonlocal state
        state = backspace_inline_text(state)
        event.app.invalidate()

    @kb.add("escape")
    def _escape(event) -> None:
        nonlocal state, should_exit
        if state.editing:
            state = cancel_inline_edit(state)
            event.app.invalidate()
            return
        should_exit = True
        event.app.exit()

    @kb.add("q")
    def _q(event) -> None:
        nonlocal state, should_exit
        if state.editing:
            state = append_inline_text(state, event.data)
            event.app.invalidate()
            return
        should_exit = True
        event.app.exit()

    @kb.add("c-c")
    def _ctrl_c(event) -> None:
        nonlocal should_exit
        should_exit = True
        event.app.exit()

    @kb.add("<any>")
    def _any(event) -> None:
        nonlocal state
        state = append_inline_text(state, event.data)
        event.app.invalidate()

    app = Application(
        layout=Layout(Window(content=control, wrap_lines=False)),
        key_bindings=kb,
        full_screen=True,
        style=Style.from_dict({"": "bg:#050617"}),
    )
    app.run()
    if should_exit:
        return config
    return config


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
