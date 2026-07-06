from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


DEFAULT_MODEL = "gpt-5.5"
DEFAULT_INTELLIGENCE = "xhigh"
INTELLIGENCE_CHOICES = ("low", "medium", "high", "xhigh")
SPEED_CHOICES = ("usual", "fast")
RUNTIME_SYNC_FIELDS = (
    "task",
    "coder_mod",
    "super_mod",
    "coder_intelligence",
    "super_intelligence",
    "speed",
    "start_over",
    "completion_review",
    "adversary",
    "adversary_runs",
    "completion_returns_per_generation",
    "clean",
    "protected_path",
)


class ProjectConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProjectConfig:
    task: str | None = None
    coder_mod: str = DEFAULT_MODEL
    super_mod: str = DEFAULT_MODEL
    coder_intelligence: str = DEFAULT_INTELLIGENCE
    super_intelligence: str = DEFAULT_INTELLIGENCE
    speed: str = "usual"
    start_over: bool = True
    completion_review: bool = True
    adversary: bool = True
    adversary_runs: int = 1
    completion_returns_per_generation: int = 10
    clean: bool = False
    protected_path: tuple[str, ...] = ()

    @property
    def fast(self) -> bool:
        return self.speed == "fast"

    def to_json_data(self) -> dict[str, Any]:
        return {
            "task": self.task,
            "coder_mod": self.coder_mod,
            "super_mod": self.super_mod,
            "coder_intelligence": self.coder_intelligence,
            "super_intelligence": self.super_intelligence,
            "speed": self.speed,
            "start_over": self.start_over,
            "completion_review": self.completion_review,
            "adversary": self.adversary,
            "max_adversary_runs": self.adversary_runs,
            "max_completion_returns_per_generation": self.completion_returns_per_generation,
            "clean": self.clean,
            "protected_path": list(self.protected_path),
        }


def default_project_config() -> ProjectConfig:
    return ProjectConfig()


def project_config_path(project_root: Path) -> Path:
    from supervisor.state import CONFIG, STATE_DIR_NAME

    return project_root.resolve() / STATE_DIR_NAME / CONFIG


def load_project_config(project_root: Path, *, create: bool = True) -> ProjectConfig:
    path = project_config_path(project_root)
    if not path.exists():
        config = default_project_config()
        if create:
            ensure_runtime_state_initialized(project_root, config)
        return config

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProjectConfigError(f"invalid Sentinel config JSON at {path}: {exc}") from exc
    except OSError as exc:
        raise ProjectConfigError(f"could not read Sentinel config at {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ProjectConfigError(f"invalid Sentinel config at {path}: expected a JSON object")
    return _config_from_payload(payload, path=path)


def save_project_config(project_root: Path, config: ProjectConfig) -> None:
    ensure_runtime_state_initialized(project_root, config)
    sync_runtime_config_fields(project_root, config, RUNTIME_SYNC_FIELDS)


def ensure_runtime_state_initialized(project_root: Path, config: ProjectConfig) -> None:
    from supervisor.state import CONFIG, STATE_DIR_NAME, StateStore

    state_dir = project_root.resolve() / STATE_DIR_NAME
    if state_dir.exists():
        config_path = state_dir / CONFIG
        if not config_path.exists():
            StateStore(project_root).write_json_locked(CONFIG, _runtime_config_from_project_config(project_root, config))
        return
    store = StateStore(project_root)
    store.initialize_sentinel(_runtime_config_from_project_config(project_root, config), mode="fresh")


def sync_runtime_config_fields(project_root: Path, config: ProjectConfig, fields: Iterable[str]) -> None:
    selected_fields = tuple(dict.fromkeys(field for field in fields if field in RUNTIME_SYNC_FIELDS))
    if not selected_fields:
        return

    from pydantic import ValidationError

    from supervisor.schemas import SentinelConfig
    from supervisor.state import CONFIG, StateStore

    store = StateStore(project_root)
    raw_config: Any
    try:
        raw_config = store.read_json(CONFIG, {})
    except (OSError, json.JSONDecodeError):
        raw_config = {}

    runtime_config: SentinelConfig
    if isinstance(raw_config, dict) and raw_config:
        try:
            runtime_config = SentinelConfig.model_validate(raw_config)
        except ValidationError:
            runtime_config = _runtime_config_from_project_config(project_root, config)
    else:
        runtime_config = _runtime_config_from_project_config(project_root, config)

    updates = _runtime_updates_for_fields(config, selected_fields)
    if updates:
        store.write_json_locked(CONFIG, runtime_config.model_copy(update=updates))


def changed_project_config_fields(before: ProjectConfig, after: ProjectConfig) -> tuple[str, ...]:
    return tuple(field for field in RUNTIME_SYNC_FIELDS if getattr(before, field) != getattr(after, field))


def _config_from_payload(payload: dict[str, Any], *, path: Path) -> ProjectConfig:
    default = default_project_config()
    return ProjectConfig(
        task=_optional_string(_first_present(payload, ("task", "task_path"), default.task, skip_none=True), "task_path", path=path),
        coder_mod=_required_string(
            _first_present(payload, ("coder_mod", "coder_model", "model"), default.coder_mod, skip_none=True),
            "coder_model",
            path=path,
        ),
        super_mod=_required_string(
            _first_present(payload, ("super_mod", "supervisor_model", "model"), default.super_mod, skip_none=True),
            "supervisor_model",
            path=path,
        ),
        coder_intelligence=_choice(
            _first_present(payload, ("coder_intelligence",), default.coder_intelligence, skip_none=True),
            "coder_intelligence",
            INTELLIGENCE_CHOICES,
            path=path,
        ),
        super_intelligence=_choice(
            _first_present(
                payload,
                ("super_intelligence", "supervisor_intelligence"),
                default.super_intelligence,
                skip_none=True,
            ),
            "supervisor_intelligence",
            INTELLIGENCE_CHOICES,
            path=path,
        ),
        speed=_speed_from_payload(payload, default.speed, path=path),
        start_over=_bool(payload.get("start_over", default.start_over), "start_over", path=path),
        completion_review=_bool(
            payload.get("completion_review", default.completion_review), "completion_review", path=path
        ),
        adversary=_adversary_from_payload(payload, default.adversary, path=path),
        adversary_runs=_adversary_runs_from_payload(payload, default.adversary_runs, path=path),
        completion_returns_per_generation=_non_negative_int(
            payload.get("max_completion_returns_per_generation", default.completion_returns_per_generation),
            "max_completion_returns_per_generation",
            path=path,
        ),
        clean=_bool(payload.get("clean", default.clean), "clean", path=path),
        protected_path=tuple(
            _string_list(
                _first_present(payload, ("protected_path", "protected_paths"), default.protected_path, skip_none=True),
                "protected_paths",
                path=path,
            )
        ),
    )


def _first_present(payload: dict[str, Any], keys: tuple[str, ...], default: Any, *, skip_none: bool = False) -> Any:
    for key in keys:
        if key in payload and (not skip_none or payload[key] is not None):
            return payload[key]
    return default


def _optional_string(value: Any, field: str, *, path: Path) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    raise ProjectConfigError(f"invalid Sentinel config at {path}: {field} must be a string or null")


def _required_string(value: Any, field: str, *, path: Path) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    raise ProjectConfigError(f"invalid Sentinel config at {path}: {field} must be a non-empty string")


def _choice(value: Any, field: str, choices: tuple[str, ...], *, path: Path) -> str:
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in choices:
            return normalized
    expected = ", ".join(choices)
    raise ProjectConfigError(f"invalid Sentinel config at {path}: {field} must be one of: {expected}")


def _speed_from_payload(payload: dict[str, Any], default: str, *, path: Path) -> str:
    if payload.get("speed") is not None:
        return _choice(payload["speed"], "speed", SPEED_CHOICES, path=path)
    if "fast" in payload:
        return "fast" if _bool(payload["fast"], "fast", path=path) else "usual"
    return default


def _adversary_from_payload(payload: dict[str, Any], default: bool, *, path: Path) -> bool:
    if "adversary" in payload:
        return _bool(payload["adversary"], "adversary", path=path)
    if "max_adversary_runs" in payload:
        return _adversary_runs_value(payload["max_adversary_runs"], path=path) > 0
    return default


def _adversary_runs_from_payload(payload: dict[str, Any], default: int, *, path: Path) -> int:
    if "max_adversary_runs" in payload:
        return _adversary_runs_value(payload["max_adversary_runs"], path=path)
    return default


def _adversary_runs_value(value: Any, *, path: Path) -> int:
    return _non_negative_int(value, "max_adversary_runs", path=path)


def _non_negative_int(value: Any, field: str, *, path: Path) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    raise ProjectConfigError(f"invalid Sentinel config at {path}: {field} must be a non-negative integer")


def _bool(value: Any, field: str, *, path: Path) -> bool:
    if isinstance(value, bool):
        return value
    raise ProjectConfigError(f"invalid Sentinel config at {path}: {field} must be true or false")


def _string_list(value: Any, field: str, *, path: Path) -> list[str]:
    if not isinstance(value, list | tuple):
        raise ProjectConfigError(f"invalid Sentinel config at {path}: {field} must be a list of strings")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ProjectConfigError(f"invalid Sentinel config at {path}: {field} must be a list of strings")
        stripped = item.strip()
        if stripped:
            result.append(stripped)
    return result


def _runtime_config_from_project_config(project_root: Path, config: ProjectConfig):
    from supervisor.schemas import SentinelConfig

    return SentinelConfig(
        project_root=str(project_root.resolve()),
        **_runtime_updates_for_fields(config, RUNTIME_SYNC_FIELDS),
    )


def _runtime_updates_for_fields(config: ProjectConfig, fields: Iterable[str]) -> dict[str, Any]:
    selected = set(fields)
    updates: dict[str, Any] = {}
    if "task" in selected:
        updates["task"] = config.task
        updates["task_path"] = config.task or ""
    if selected.intersection({"coder_mod", "super_mod"}):
        updates["coder_mod"] = config.coder_mod
        updates["super_mod"] = config.super_mod
        updates["model"] = config.coder_mod if config.coder_mod == config.super_mod else None
        updates["coder_model"] = config.coder_mod
        updates["supervisor_model"] = config.super_mod
    if "coder_intelligence" in selected:
        updates["coder_intelligence"] = config.coder_intelligence
    if "super_intelligence" in selected:
        updates["super_intelligence"] = config.super_intelligence
        updates["supervisor_intelligence"] = config.super_intelligence
    if "speed" in selected:
        updates["speed"] = config.speed
        updates["fast"] = config.fast
    if "start_over" in selected:
        updates["start_over"] = config.start_over
    if "clean" in selected:
        updates["clean"] = config.clean
    if "protected_path" in selected:
        updates["protected_path"] = list(config.protected_path)
        updates["protected_paths"] = list(config.protected_path)
    if "completion_review" in selected:
        updates["completion_review_enabled"] = config.completion_review
    if selected.intersection({"adversary", "adversary_runs"}):
        updates["adversary"] = config.adversary
        updates["max_adversary_runs"] = config.adversary_runs if config.adversary else 0
    if "completion_returns_per_generation" in selected:
        updates["max_completion_returns_per_generation"] = config.completion_returns_per_generation
    return updates
