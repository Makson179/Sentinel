from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal

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


def render_editor(config: ProjectConfig, state: EditorState, path: Path, model_choices: tuple[str, ...] | None = None) -> str:
    lines = [
        "Sentinel project config",
        f"Path: {path}",
        "",
        "Arrows move. Enter expands or saves. Esc/q exits.",
        "",
    ]
    parameters = parameter_defs(config, model_choices)
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
    model_choices = available_model_choices(project_root)
    path = project_config_path(project_root)
    state = EditorState()

    while True:
        pending_action: dict[str, EditorAction | bool | None] = {"action": None, "exit": False}
        control = FormattedTextControl(lambda: render_editor(config, state, path, model_choices), focusable=True)
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
