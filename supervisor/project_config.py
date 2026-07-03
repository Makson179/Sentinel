from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_CONFIG_DIR = ".sentinel"
PROJECT_CONFIG_FILE = "config.json"
DEFAULT_MODEL = "gpt-5.5"
DEFAULT_INTELLIGENCE = "xhigh"
INTELLIGENCE_CHOICES = ("low", "medium", "high", "xhigh")
SPEED_CHOICES = ("usual", "fast")


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
    adversary: bool = True
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
            "adversary": self.adversary,
            "clean": self.clean,
            "protected_path": list(self.protected_path),
        }


def default_project_config() -> ProjectConfig:
    return ProjectConfig()


def project_config_path(project_root: Path) -> Path:
    return project_root.resolve() / PROJECT_CONFIG_DIR / PROJECT_CONFIG_FILE


def load_project_config(project_root: Path, *, create: bool = True) -> ProjectConfig:
    path = project_config_path(project_root)
    if not path.exists():
        config = default_project_config()
        if create:
            save_project_config(project_root, config)
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
    path = project_config_path(project_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(config.to_json_data(), indent=2, sort_keys=True) + "\n"
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def _config_from_payload(payload: dict[str, Any], *, path: Path) -> ProjectConfig:
    default = default_project_config()
    return ProjectConfig(
        task=_optional_string(payload.get("task", default.task), "task", path=path),
        coder_mod=_required_string(payload.get("coder_mod", default.coder_mod), "coder_mod", path=path),
        super_mod=_required_string(payload.get("super_mod", default.super_mod), "super_mod", path=path),
        coder_intelligence=_choice(
            payload.get("coder_intelligence", default.coder_intelligence),
            "coder_intelligence",
            INTELLIGENCE_CHOICES,
            path=path,
        ),
        super_intelligence=_choice(
            payload.get("super_intelligence", default.super_intelligence),
            "super_intelligence",
            INTELLIGENCE_CHOICES,
            path=path,
        ),
        speed=_choice(payload.get("speed", default.speed), "speed", SPEED_CHOICES, path=path),
        start_over=_bool(payload.get("start_over", default.start_over), "start_over", path=path),
        adversary=_bool(payload.get("adversary", default.adversary), "adversary", path=path),
        clean=_bool(payload.get("clean", default.clean), "clean", path=path),
        protected_path=tuple(_string_list(payload.get("protected_path", default.protected_path), "protected_path", path=path)),
    )


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
