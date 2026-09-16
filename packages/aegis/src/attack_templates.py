"""Attack-template governance (task plan 39).

Attack templates are versioned, provenance-tracked, and can only become ACTIVE
through the governance pipeline (a PRODUCTION-stage proposal). AEGIS cannot
self-activate a template.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Optional


@dataclass(frozen=True)
class AttackTemplate:
    template_id: str
    name: str
    technique: str
    version: str
    content: dict
    provenance: str
    state: str = "draft"          # draft | proposed | active | retired
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AttackTemplateRegistry:
    def __init__(self) -> None:
        self._templates: dict[str, AttackTemplate] = {}

    def add_draft(self, *, template_id: str, name: str, technique: str, version: str,
                  content: dict, provenance: str) -> AttackTemplate:
        t = AttackTemplate(template_id, name, technique, version, content, provenance)
        self._templates[template_id] = t
        return t

    def propose(self, template_id: str) -> AttackTemplate:
        t = self._templates[template_id]
        t = replace(t, state="proposed")
        self._templates[template_id] = t
        return t

    def activate(self, template_id: str, *, approved_proposal) -> AttackTemplate:
        """Activate only via a governed PRODUCTION-stage attack_template proposal."""
        if getattr(approved_proposal, "kind", None) != "attack_template":
            raise ValueError("proposal is not an attack_template proposal")
        if getattr(approved_proposal, "stage", None) != "PRODUCTION":
            raise ValueError("template activation requires a PRODUCTION-stage proposal")
        t = self._templates[template_id]
        if t.state != "proposed":
            raise ValueError("only a proposed template can be activated")
        t = replace(t, state="active")
        self._templates[template_id] = t
        return t

    def retire(self, template_id: str) -> AttackTemplate:
        t = replace(self._templates[template_id], state="retired")
        self._templates[template_id] = t
        return t

    def active_templates(self) -> list[AttackTemplate]:
        return [t for t in self._templates.values() if t.state == "active"]
