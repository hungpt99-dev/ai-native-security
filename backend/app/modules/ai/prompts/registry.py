"""Versioned prompt registry.

Prompts are code: typed, reviewed, versioned. Changing a prompt requires bumping
``version``; the registry rejects duplicate ``(id, version)`` pairs and the
execution ledger stores the version and a hash of the rendered template, so an
assessment can always be traced to the exact prompt that produced it.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from app.modules.ai.schemas.provider import AIRequest, EvidenceBlock


class PromptRegistryError(RuntimeError):
    """Raised on duplicate or unknown prompt identifiers."""


@dataclass(frozen=True)
class PromptTemplate:
    id: str
    version: str
    system: str
    schema_id: str | None = None
    schema_version: str | None = None
    description: str = ""
    default_max_output_tokens: int | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)

    def build(
        self,
        *,
        instruction: str,
        evidence: list[EvidenceBlock] | None = None,
        max_output_tokens: int | None = None,
        temperature: float | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AIRequest:
        return AIRequest(
            prompt_id=self.id,
            prompt_version=self.version,
            system_prompt=self.system,
            instruction=instruction,
            evidence=evidence or [],
            schema_id=self.schema_id,
            schema_version=self.schema_version,
            max_output_tokens=max_output_tokens or self.default_max_output_tokens,
            temperature=temperature,
            metadata=metadata or {},
        )

    @property
    def sha256(self) -> str:
        material = f"{self.id}:{self.version}:{self.schema_id}:{self.system}"
        return hashlib.sha256(material.encode()).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "description": self.description,
            "sha256": self.sha256,
        }


_REGISTRY: dict[str, dict[str, PromptTemplate]] = {}
_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*$")


def register(template: PromptTemplate) -> PromptTemplate:
    if not _VERSION_RE.match(template.version):
        raise PromptRegistryError(
            f"Prompt version must be numeric (got {template.version!r} for {template.id})"
        )
    versions = _REGISTRY.setdefault(template.id, {})
    if template.version in versions:
        raise PromptRegistryError(f"Duplicate prompt {template.id}@{template.version}")
    versions[template.version] = template
    return template


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def get_prompt(prompt_id: str, version: str | None = None) -> PromptTemplate:
    versions = _REGISTRY.get(prompt_id)
    if not versions:
        raise PromptRegistryError(f"Unknown prompt id: {prompt_id}")
    if version is not None:
        template = versions.get(version)
        if template is None:
            raise PromptRegistryError(f"Unknown prompt version: {prompt_id}@{version}")
        return template
    return versions[max(versions, key=_version_key)]


def list_prompts() -> list[dict[str, Any]]:
    return [
        template.as_dict()
        for versions in _REGISTRY.values()
        for template in sorted(versions.values(), key=lambda item: _version_key(item.version))
    ]


def clear_registry() -> None:
    """Test helper."""
    _REGISTRY.clear()
