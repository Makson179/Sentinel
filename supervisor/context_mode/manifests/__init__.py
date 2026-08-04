"""Pinned, non-executable release metadata bundled with ``supervisor``."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any


def load_manifest_resource(name: str) -> dict[str, Any]:
    if name not in {
        "catalog-v1.json",
        "release-defaults.json",
        "runtime-manifest.schema.json",
        "sandbox-policy.schema.json",
        "protocol-schemas-v1.json",
    }:
        raise ValueError(f"unknown Context Mode manifest resource: {name!r}")
    value = json.loads(files(__package__).joinpath(name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Context Mode manifest resource is not an object: {name}")
    return value


__all__ = ["load_manifest_resource"]
