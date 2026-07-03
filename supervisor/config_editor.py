from __future__ import annotations

import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal

from supervisor.project_config import (
    INTELLIGENCE_CHOICES,
    SPEED_CHOICES,
    ProjectConfig,
    load_project_config,
    project_config_path,
    save_project_config,
)


EditorAction = Literal["edit_text", "add_protected_path"]


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


def parameter_defs(config: ProjectConfig) -> tuple[EditorParameter, ...]:
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
            (
                EditorOption("gpt-5.5", "coder_mod", "gpt-5.5"),
                EditorOption("edit model", action="edit_text"),
            ),
        ),
        EditorParameter(
            "super_mod",
            "super-mod",
            config.super_mod,
            (
                EditorOption("gpt-5.5", "super_mod", "gpt-5.5"),
                EditorOption("edit model", action="edit_text"),
            ),
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


def select_current(config: ProjectConfig, state: EditorState) -> tuple[ProjectConfig, EditorState, EditorAction | None]:
    parameters = parameter_defs(config)
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


def render_editor(config: ProjectConfig, state: EditorState, path: Path) -> str:
    lines = [
        "Sentinel project config",
        f"Path: {path}",
        "",
        "Arrows move. Enter expands or saves. Esc/q exits.",
        "",
    ]
    parameters = parameter_defs(config)
    for parameter_index, parameter in enumerate(parameters):
        cursor = ">" if state.parameter_index == parameter_index and state.option_index is None else " "
        lines.append(f"{cursor} {parameter.label}: {parameter.value}")
        if state.expanded_index == parameter_index:
            for option_index, option in enumerate(parameter.options):
                option_cursor = ">" if state.parameter_index == parameter_index and state.option_index == option_index else " "
                lines.append(f"  {option_cursor} {option.label}")
    return "\n".join(lines)


def run_config_editor(project_root: Path) -> ProjectConfig:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise RuntimeError("sentinel config requires an interactive terminal")
    try:
        from prompt_toolkit import Application, prompt
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.layout.containers import Window
        from prompt_toolkit.layout.controls import FormattedTextControl
        from prompt_toolkit.layout import Layout
    except ImportError as exc:
        raise RuntimeError("sentinel config requires prompt_toolkit; reinstall Sentinel with project dependencies") from exc

    config = load_project_config(project_root, create=True)
    path = project_config_path(project_root)
    state = EditorState()

    while True:
        pending_action: dict[str, EditorAction | bool | None] = {"action": None, "exit": False}
        control = FormattedTextControl(lambda: render_editor(config, state, path), focusable=True)
        kb = KeyBindings()

        @kb.add("down")
        def _down(event) -> None:
            nonlocal state
            state = move_down(state, parameter_defs(config))
            event.app.invalidate()

        @kb.add("up")
        def _up(event) -> None:
            nonlocal state
            state = move_up(state, parameter_defs(config))
            event.app.invalidate()

        @kb.add("enter")
        def _enter(event) -> None:
            nonlocal config, state
            config, state, action = select_current(config, state)
            if action is None:
                save_project_config(project_root, config)
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
            save_project_config(project_root, config)
            return config

        action = pending_action["action"]
        parameter = parameter_defs(config)[state.parameter_index]
        if action == "edit_text" and parameter.key in {"task", "coder_mod", "super_mod"}:
            if parameter.key == "task":
                raw = prompt("Task path (blank to unset): ", default=config.task or "")
                config = replace(config, task=raw.strip() or None)
            elif parameter.key == "coder_mod":
                raw = prompt("Coder model: ", default=config.coder_mod)
                config = replace(config, coder_mod=raw.strip() or config.coder_mod)
            else:
                raw = prompt("Supervisor model: ", default=config.super_mod)
                config = replace(config, super_mod=raw.strip() or config.super_mod)
            save_project_config(project_root, config)
            state = advance_after_selection(state, len(parameter_defs(config)))
        elif action == "add_protected_path":
            raw = prompt("Protected path: ")
            value = raw.strip()
            if value:
                config = replace(config, protected_path=tuple([*config.protected_path, value]))
                save_project_config(project_root, config)
            state = advance_after_selection(state, len(parameter_defs(config)))


def _format_bool(value: bool) -> str:
    return "true" if value else "false"
