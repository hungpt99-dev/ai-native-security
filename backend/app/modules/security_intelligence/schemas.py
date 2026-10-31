"""Typed security context: the only thing the AI layer is allowed to reason over."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class MissingInformation(BaseModel):
    """A piece of context the platform could not supply.

    Reported explicitly so neither the model nor the UI can mistake absence for
    evidence of safety.
    """

    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    affects: list[str] = Field(default_factory=list)


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str
    kind: str
    source: str
    locator: str | None = None
    text: str = ""
    sha256: str = ""
    injection_markers: list[str] = Field(default_factory=list)

    def as_prompt_block(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "source": self.source,
            "locator": self.locator,
            "text": self.text,
            "sha256": self.sha256,
        }


class SecurityContext(BaseModel):
    """Everything known about one finding, frozen and reproducible."""

    model_config = ConfigDict(extra="forbid")

    context_version: str = "1"
    builder_version: str = "1"
    generated_at: datetime
    finding: dict[str, Any] = Field(default_factory=dict)
    asset: dict[str, Any] = Field(default_factory=dict)
    repository: dict[str, Any] = Field(default_factory=dict)
    dependency: dict[str, Any] = Field(default_factory=dict)
    vulnerability: dict[str, Any] = Field(default_factory=dict)
    business: dict[str, Any] = Field(default_factory=dict)
    history: dict[str, Any] = Field(default_factory=dict)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    missing_information: list[MissingInformation] = Field(default_factory=list)
    truncated: bool = False

    def canonical_payload(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        data.pop("generated_at", None)
        return data

    def evidence_hash(self) -> str:
        canonical = json.dumps(self.canonical_payload(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def prompt_payload(self) -> dict[str, Any]:
        """Compact structure for the prompt (evidence text lives in E blocks)."""
        return {
            "context_version": self.context_version,
            "finding": self.finding,
            "asset": self.asset,
            "repository": self.repository,
            "dependency": self.dependency,
            "vulnerability": self.vulnerability,
            "business": self.business,
            "history": self.history,
            "missing_information": [item.model_dump(mode="json") for item in self.missing_information],
            "evidence_keys": [item.key for item in self.evidence],
            "truncated": self.truncated,
        }

    def render_for_prompt(self) -> str:
        return json.dumps(self.prompt_payload(), indent=2, sort_keys=True, default=str)

    def missing_codes(self) -> list[str]:
        return [item.code for item in self.missing_information]

    def injection_markers(self) -> list[str]:
        markers: set[str] = set()
        for item in self.evidence:
            markers.update(item.injection_markers)
        return sorted(markers)
