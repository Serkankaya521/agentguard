"""Model/detector/policy version registry (task plan 41).

Immutable versioned artifacts with content hash, provenance, and compatibility;
supports rollback. Versions are immutable: republishing an existing version fails.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from serialization import content_hash  # packages/contracts/src


@dataclass(frozen=True)
class VersionedArtifact:
    kind: str                    # detector | model | policy
    name: str
    version: str
    content_hash: str
    provenance: str
    compatibility: dict = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ArtifactVersionRegistry:
    def __init__(self) -> None:
        self._versions: dict[tuple[str, str], list[VersionedArtifact]] = {}
        self._active: dict[tuple[str, str], str] = {}

    def _key(self, kind, name):
        return (kind, name)

    def publish(self, *, kind: str, name: str, version: str, content: dict,
                provenance: str, compatibility: Optional[dict] = None) -> VersionedArtifact:
        key = self._key(kind, name)
        vers = self._versions.setdefault(key, [])
        if any(a.version == version for a in vers):
            raise ValueError(f"version {version} already exists (immutable)")
        art = VersionedArtifact(kind, name, version, content_hash(content), provenance,
                                dict(compatibility or {}))
        vers.append(art)
        self._active[key] = version  # newest becomes active on publish
        return art

    def get(self, kind: str, name: str, version: str) -> Optional[VersionedArtifact]:
        return next((a for a in self._versions.get(self._key(kind, name), [])
                     if a.version == version), None)

    def active(self, kind: str, name: str) -> Optional[VersionedArtifact]:
        v = self._active.get(self._key(kind, name))
        return self.get(kind, name, v) if v else None

    def list_versions(self, kind: str, name: str) -> list[VersionedArtifact]:
        return list(self._versions.get(self._key(kind, name), []))

    def rollback(self, kind: str, name: str) -> Optional[VersionedArtifact]:
        vers = self._versions.get(self._key(kind, name), [])
        if len(vers) < 2:
            return self.active(kind, name)
        self._active[self._key(kind, name)] = vers[-2].version  # previous version
        return self.active(kind, name)
