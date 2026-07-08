"""Supervisor Agent MVP package."""

__all__ = ["__version__"]

import importlib.metadata as _metadata
import tomllib as _tomllib
from pathlib import Path as _Path


def _read_version() -> str:
    try:
        return _metadata.version("sentinel-supervisor")
    except _metadata.PackageNotFoundError:
        pyproject = _Path(__file__).resolve().parents[1] / "pyproject.toml"
        try:
            data = _tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except OSError:
            return "0+unknown"
        version = data.get("project", {}).get("version")
        return version if isinstance(version, str) else "0+unknown"


__version__ = _read_version()
