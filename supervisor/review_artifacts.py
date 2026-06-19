from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from supervisor.state import StateStore, require_inside_workspace


class ReviewArtifact(BaseModel):
    artifact_id: str
    kind: str
    path: str | None = None
    content_hash: str
    character_count: int
    material: bool = True
    truncated: bool = False
    storage_path: str
    workspace_state_id: str | None = None


class ReviewArtifactManifest(BaseModel):
    completion_attempt_id: str
    workspace_state_id: str | None = None
    artifacts: list[ReviewArtifact] = Field(default_factory=list)


def write_review_artifacts(
    store: StateStore,
    *,
    completion_attempt_id: str,
    workspace_state_id: str | None,
    artifacts: list[tuple[str, str | None, str, bool]],
) -> ReviewArtifactManifest:
    safe_attempt = _safe_component(completion_attempt_id)
    root = require_inside_workspace(store.workspace, store.state_dir / "review_artifacts" / safe_attempt)
    root.mkdir(parents=True, exist_ok=True)
    manifest = ReviewArtifactManifest(completion_attempt_id=completion_attempt_id, workspace_state_id=workspace_state_id)
    seen: set[str] = set()
    for index, (kind, source_path, content, truncated) in enumerate(artifacts):
        digest = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
        artifact_id = f"{_safe_component(kind)}-{digest[:20]}"
        if artifact_id in seen:
            artifact_id = f"{artifact_id}-{index}"
        seen.add(artifact_id)
        filename = f"{artifact_id}.txt"
        target = require_inside_workspace(store.workspace, root / filename)
        store.atomic_write_text(target, content)
        manifest.artifacts.append(
            ReviewArtifact(
                artifact_id=artifact_id,
                kind=kind,
                path=source_path,
                content_hash=f"sha256:{digest}",
                character_count=len(content),
                material=bool(content.strip()),
                truncated=truncated,
                storage_path=str(target.relative_to(store.workspace)),
                workspace_state_id=workspace_state_id,
            )
        )
    manifest_path = require_inside_workspace(store.workspace, root / "manifest.json")
    store.atomic_write_text(manifest_path, manifest.model_dump_json(indent=2) + "\n")
    return manifest


def manifest_to_packet_dict(manifest: ReviewArtifactManifest) -> dict[str, Any]:
    return manifest.model_dump(mode="json")


def _safe_component(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in value.strip())
    cleaned = cleaned.strip("-_")
    return cleaned[:120] or "artifact"
