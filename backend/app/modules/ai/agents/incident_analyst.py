"""AI incident analyst.

Turns an incident plus its aggregated evidence into a structured, cited report.
It never changes the incident's status, severity, priority or risk score; those
are owned by the deterministic services.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.config import get_settings
from app.core.security import redact_text
from app.modules.ai.prompts import INCIDENT_INSTRUCTION, INCIDENT_PROMPT
from app.modules.ai.prompts.registry import PromptTemplate
from app.modules.ai.providers.base import AIProvider
from app.modules.ai.schemas.outputs import IncidentInvestigationOutput
from app.modules.ai.schemas.provider import AIRequest, AIResult, EvidenceBlock

MAX_EVENT_GROUPS = 12


@dataclass
class IncidentEvidence:
    """The bounded evidence set handed to the model."""

    blocks: list[EvidenceBlock]
    facts: dict[str, Any]
    event_groups: list[dict[str, Any]]
    missing: list[str] = field(default_factory=list)

    def keys(self) -> set[str]:
        return {block.key for block in self.blocks}


@dataclass
class IncidentAnalysis:
    output: IncidentInvestigationOutput
    result: AIResult
    prompt: PromptTemplate
    evidence: IncidentEvidence
    dropped_evidence: list[str] = field(default_factory=list)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _event_group_key(event: Any) -> tuple[str, str, str]:
    return (
        str(getattr(event, "event_type", "")),
        str(getattr(event, "rule_slug", "") or ""),
        str(getattr(event, "severity", "")),
    )


def aggregate_events(events: list[Any]) -> list[dict[str, Any]]:
    """Collapse hundreds of rows into a bounded, counted summary.

    The platform never streams raw events to a model. Each group carries counts
    and the fields a human would look at first; the rest stays queryable.
    """
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for event in events:
        key = _event_group_key(event)
        normalized = getattr(event, "normalized", {}) or {}
        group = groups.get(key)
        if group is None:
            container = normalized.get("container") or {}
            group = {
                "event_type": key[0],
                "rule": key[1] or None,
                "severity": key[2],
                "occurrences": 0,
                "first_seen": _iso(getattr(event, "first_seen_at", None)),
                "last_seen": _iso(getattr(event, "last_seen_at", None)),
                "sample": {
                    field: redact_text(str(normalized[field]))[:400]
                    for field in (
                        "process",
                        "command_line",
                        "file_path",
                        "remote_ip",
                        "remote_port",
                        "user",
                        "rule_name",
                    )
                    if normalized.get(field) is not None
                },
                "container": container or None,
                "host": normalized.get("host"),
                "pod": normalized.get("pod"),
                "namespace": normalized.get("namespace"),
            }
            groups[key] = group
        group["occurrences"] += int(getattr(event, "occurrence_count", 1) or 1)
        last_seen = _iso(getattr(event, "last_seen_at", None))
        if last_seen and (group["last_seen"] is None or last_seen > group["last_seen"]):
            group["last_seen"] = last_seen
    ordered = sorted(
        groups.values(),
        key=lambda item: (-int(item["occurrences"]), str(item["event_type"])),
    )
    return ordered[:MAX_EVENT_GROUPS]


def build_evidence(
    *,
    incident: Any,
    asset: Any,
    profile: Any,
    events: list[Any],
    findings: list[Any],
) -> IncidentEvidence:
    settings = get_settings()
    missing: list[str] = []
    blocks: list[EvidenceBlock] = []

    facts = {
        "incident_id": str(incident.id),
        "title": incident.title,
        "summary": redact_text(incident.summary or "")[:2000] or None,
        "severity": incident.severity,
        "priority": incident.priority,
        "status": incident.status,
        "risk_score": incident.risk_score,
        "category": incident.category,
        "detection_rule": incident.detection_rule_slug,
        "opened_at": _iso(incident.opened_at),
        "event_count": incident.event_count,
        "finding_count": incident.finding_count,
    }
    blocks.append(
        EvidenceBlock(
            key="E1",
            source="incident",
            locator=f"incident/{incident.id}",
            text=json.dumps(facts, sort_keys=True, default=str),
            metadata={"kind": "incident"},
        )
    )

    if asset is None:
        missing.append("asset_not_resolved: the incident is not attributed to an inventory asset")
        asset_facts: dict[str, Any] = {"resolved": False}
    else:
        asset_facts = {
            "name": asset.name,
            "kind": asset.kind,
            "repo_url": asset.repo_url,
            "external_ref": asset.external_ref,
        }
        if profile is None:
            missing.append(
                "business_context_missing: criticality, environment, exposure and owner are unset"
            )
            asset_facts["business_context"] = None
        else:
            asset_facts["business_context"] = {
                "criticality": profile.criticality,
                "environment": profile.environment,
                "internet_exposed": profile.internet_exposed,
                "data_sensitivity": profile.data_sensitivity,
                "business_importance": profile.business_importance,
                "owner_team": profile.owner_team,
            }
    blocks.append(
        EvidenceBlock(
            key="E2",
            source="asset",
            locator=str(asset.id) if asset is not None else None,
            text=json.dumps(asset_facts, sort_keys=True, default=str),
            metadata={"kind": "asset"},
        )
    )

    groups = aggregate_events(events)
    if not groups:
        missing.append("runtime_events_missing: no events are attached to this incident")
    for index, group in enumerate(groups):
        blocks.append(
            EvidenceBlock(
                key=f"E{index + 3}",
                source="security_event",
                locator=str(group["event_type"]),
                text=json.dumps(group, sort_keys=True, default=str),
                metadata={"kind": "event_group"},
            )
        )

    for finding in findings[:5]:
        blocks.append(
            EvidenceBlock(
                key=f"F{len(blocks) + 1}",
                source="finding",
                locator=str(finding.id),
                text=json.dumps(
                    {
                        "title": finding.title,
                        "severity": finding.severity,
                        "status": finding.status,
                        "cve_id": finding.cve_id,
                        "package": finding.package_name,
                        "version": finding.package_version,
                        "file": finding.file_path,
                    },
                    sort_keys=True,
                    default=str,
                ),
                metadata={"kind": "finding"},
            )
        )
    if not findings:
        missing.append("linked_findings_missing: no vulnerability is linked to this incident")

    # Total input ceiling: keep the incident + asset + the first groups.
    while blocks and len(json.dumps([b.text for b in blocks])) > settings.ai_max_input_chars:
        blocks.pop()
        missing.append("evidence_truncated: evidence exceeded the configured prompt budget")
    return IncidentEvidence(blocks=blocks, facts=facts, event_groups=groups, missing=missing)


def build_request(evidence: IncidentEvidence, *, max_output_tokens: int | None = None) -> AIRequest:
    instruction = (
        f"{INCIDENT_INSTRUCTION}\n\n"
        "INCIDENT FACTS (structured JSON; null means unknown):\n"
        f"{json.dumps(evidence.facts, sort_keys=True, default=str)}"
    )
    return INCIDENT_PROMPT.build(
        instruction=instruction,
        evidence=evidence.blocks,
        max_output_tokens=max_output_tokens,
        metadata={"incident_id": evidence.facts.get("incident_id")},
    )


def run(
    provider: AIProvider,
    evidence: IncidentEvidence,
    *,
    request: AIRequest | None = None,
    max_output_tokens: int | None = None,
) -> IncidentAnalysis:
    request = request or build_request(evidence, max_output_tokens=max_output_tokens)
    result = provider.generate_structured(request, IncidentInvestigationOutput)
    if result.structured is None:  # pragma: no cover - providers raise instead
        raise ValueError("Provider returned no structured output")
    output = IncidentInvestigationOutput.model_validate(result.structured)

    provided = evidence.keys()
    seen: set[str] = set()
    unique = []
    for ref in output.evidence:
        if ref.key in seen:
            continue
        seen.add(ref.key)
        unique.append(ref)
    dropped = [ref.key for ref in unique if ref.key not in provided]
    output = output.model_copy(update={"evidence": [ref for ref in unique if ref.key in provided]})

    # Attack steps may only cite keys that survived validation.
    step_refs = {key for step in output.attack_steps for key in step.evidence}
    if step_refs - provided:
        output = output.model_copy(
            update={
                "attack_steps": [
                    step.model_copy(
                        update={"evidence": [key for key in step.evidence if key in provided]}
                    )
                    for step in output.attack_steps
                ]
            }
        )

    missing = list(output.missing_information) + list(evidence.missing)
    if not output.evidence:
        # No citation survived: the report cannot be treated as a finding.
        missing.append(
            "no_valid_citations: the model cited no supplied evidence, so its conclusion "
            "cannot be verified"
        )
        output = output.model_copy(update={"status": "NEEDS_MANUAL_REVIEW"})
    if missing or output.confidence < 0.5:
        output = output.model_copy(update={"requires_human_review": True})
    output = output.model_copy(update={"missing_information": list(dict.fromkeys(missing))[:20]})

    return IncidentAnalysis(
        output=output,
        result=result,
        prompt=INCIDENT_PROMPT,
        evidence=evidence,
        dropped_evidence=dropped,
    )
