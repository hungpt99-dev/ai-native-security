"""Security Context Builder.

Assembles every piece of evidence the platform holds about one finding, reports
what it does not hold, and freezes the result into a snapshot. Deterministic: it
never calls a model. Same inputs produce the same ``evidence_hash``.

Evidence is retrieved — not dumped. Repository content is limited to the snippets
that already exist on the finding (Semgrep matched lines, Trivy/Gitleaks
metadata) plus dependency and intelligence facts; whole files or repositories are
never included.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.enums import ACTIVE_FINDING_STATUSES
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.modules.assets.models import Asset
from app.modules.findings.models import Finding, FindingHistory
from app.modules.security_intelligence import dependency_graph, repository_metadata
from app.modules.security_intelligence.models import (
    AssetSecurityProfile,
    SecurityContextSnapshot,
)
from app.modules.security_intelligence.schemas import (
    EvidenceItem,
    MissingInformation,
    SecurityContext,
)
from app.modules.security_intelligence.versions import minimum_fixed_version
from app.modules.vulnerabilities import epss as epss_module
from app.modules.vulnerabilities.models import (
    Vulnerability,
    VulnerabilityAffectedPackage,
    VulnerabilityReference,
)

logger = get_logger(__name__)

BUILDER_VERSION = "1"

#: Evidence priority used when the input budget is exceeded (highest first).
EVIDENCE_PRIORITY = {
    "finding": 0,
    "vulnerability": 1,
    "dependency": 2,
    "code": 3,
    "history": 4,
    "business": 5,
}


class SecurityContextBuilder:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    # ------------------------------------------------------------------ public
    def build(
        self,
        db: Session,
        finding_id: uuid.UUID,
        *,
        scan_id: uuid.UUID | None = None,
    ) -> SecurityContext:
        finding = db.get(Finding, finding_id)
        if finding is None:
            raise NotFoundError("Finding not found", details={"finding_id": str(finding_id)})
        asset = db.get(Asset, finding.asset_id)
        if asset is None:
            raise NotFoundError("Asset not found", details={"asset_id": str(finding.asset_id)})

        missing: list[MissingInformation] = []
        context = SecurityContext(
            context_version=self.settings.ai_context_version,
            builder_version=BUILDER_VERSION,
            generated_at=datetime.now(UTC),
        )

        context.finding = self._finding_section(finding)
        context.asset = self._asset_section(asset)
        context.repository = repository_metadata.as_context(repository_metadata.get(db, asset.id))
        if not context.repository.get("collected"):
            missing.append(
                MissingInformation(
                    code="repository_metadata_missing",
                    message="No repository metadata has been collected for this asset yet.",
                    affects=["repository"],
                )
            )

        context.business, business_missing = self._business_section(db, asset)
        missing.extend(business_missing)

        context.dependency = self._dependency_section(db, finding)
        if not context.dependency.get("available"):
            missing.append(
                MissingInformation(
                    code="dependency_graph_unavailable",
                    message="Direct/transitive dependency information is not available for this package.",
                    affects=["dependency", "reachability"],
                )
            )

        context.vulnerability, vuln_missing, affected = self._vulnerability_section(db, finding)
        missing.extend(vuln_missing)

        context.history = self._history_section(db, finding)
        if not context.vulnerability.get("fixed_versions"):
            missing.append(
                MissingInformation(
                    code="fixed_versions_unavailable",
                    message="No authoritative fixed version is known for this finding.",
                    affects=["remediation"],
                )
            )

        evidence: list[EvidenceItem] = []
        evidence.extend(self._finding_evidence(finding, context.finding))
        evidence.extend(self._vulnerability_evidence(finding, context.vulnerability, affected))
        evidence.extend(self._dependency_evidence(finding, context.dependency))
        evidence.extend(self._code_evidence(finding))
        evidence.extend(self._history_evidence(context.history))
        evidence.extend(self._business_evidence(context.business))

        evidence, truncated = self._apply_budget(evidence)
        context.evidence = evidence
        context.truncated = truncated
        context.missing_information = missing

        # A snippet the platform does not hold is a real gap for reachability.
        if not any(item.kind == "code" for item in evidence):
            context.missing_information.append(
                MissingInformation(
                    code="no_code_snippet",
                    message=(
                        "No source evidence is attached to this finding, so use of the "
                        "vulnerable functionality cannot be assessed from code."
                    ),
                    affects=["reachability", "functionality_used"],
                )
            )
        if not context.vulnerability.get("epss_score") and context.vulnerability.get("cve_id"):
            context.missing_information.append(
                MissingInformation(
                    code="epss_unavailable",
                    message="No EPSS score is stored for this CVE.",
                    affects=["exploit_likelihood"],
                )
            )
        if context.vulnerability.get("is_kev") is None:
            context.missing_information.append(
                MissingInformation(
                    code="kev_status_unknown",
                    message="CISA KEV status could not be determined for this finding.",
                    affects=["exploit_activity"],
                )
            )
        # There is no runtime integration in this platform; say so instead of
        # implying runtime confirmation exists.
        context.missing_information.append(
            MissingInformation(
                code="runtime_context_unavailable",
                message="No runtime/deployment telemetry is integrated, so live exploitability is unknown.",
                affects=["reachability"],
            )
        )
        return context

    def persist(self, db: Session, context: SecurityContext, *, finding: Finding) -> SecurityContextSnapshot:
        snapshot = SecurityContextSnapshot(
            finding_id=finding.id,
            asset_id=finding.asset_id,
            scan_id=finding.last_scan_id,
            context_version=context.context_version,
            builder_version=context.builder_version,
            evidence_hash=context.evidence_hash(),
            payload=context.model_dump(mode="json"),
            missing_information=[item.model_dump(mode="json") for item in context.missing_information],
        )
        db.add(snapshot)
        db.flush()
        logger.info(
            "security context snapshot created",
            extra={
                "extra_fields": {
                    "snapshot_id": str(snapshot.id),
                    "finding_id": str(finding.id),
                    "evidence": len(context.evidence),
                    "missing": len(context.missing_information),
                    "truncated": context.truncated,
                }
            },
        )
        return snapshot

    def build_and_persist(
        self, db: Session, finding_id: uuid.UUID, *, scan_id: uuid.UUID | None = None
    ) -> tuple[SecurityContext, SecurityContextSnapshot]:
        context = self.build(db, finding_id, scan_id=scan_id)
        finding = db.get(Finding, finding_id)
        assert finding is not None
        snapshot = self.persist(db, context, finding=finding)
        return context, snapshot

    # ----------------------------------------------------------------- sections
    def _finding_section(self, finding: Finding) -> dict[str, Any]:
        metadata = finding.metadata_json or {}
        intel = metadata.get("intel") if isinstance(metadata.get("intel"), dict) else {}
        return {
            "id": str(finding.id),
            "scanner": finding.scanner,
            "category": finding.category,
            "severity": finding.severity,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "description": (finding.description or "")[:2000],
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "package_name": finding.package_name,
            "package_version": finding.package_version,
            "purl": finding.purl,
            "cve_id": finding.cve_id,
            "cvss_score": float(finding.cvss_score) if finding.cvss_score is not None else None,
            "status": finding.status,
            "fingerprint": finding.fingerprint,
            "first_detected_at": finding.first_detected_at.isoformat() if finding.first_detected_at else None,
            "last_detected_at": finding.last_detected_at.isoformat() if finding.last_detected_at else None,
            "intel_summary": {
                "is_kev": (intel or {}).get("is_kev"),
                "sources": (intel or {}).get("sources"),
                "cvss_vector": (intel or {}).get("cvss_vector"),
                "kev_due_date": (intel or {}).get("kev_due_date"),
            },
            "scanner_metadata": {
                key: value
                for key, value in metadata.items()
                if key
                in {
                    "lines",
                    "cwe",
                    "owasp",
                    "confidence",
                    "fixed_version",
                    "primary_url",
                    "target",
                    "status",
                    "secret_masked",
                    "match_masked",
                    "osv_id",
                    "fixed_versions",
                    "is_kev",
                    "ecosystem",
                    "references",
                    "code",
                }
            },
        }

    @staticmethod
    def _asset_section(asset: Asset) -> dict[str, Any]:
        return {
            "id": str(asset.id),
            "name": asset.name,
            "repo_url": asset.repo_url,
            "provider": asset.provider,
            "default_branch": asset.default_branch,
            "description": asset.description,
            "monitoring_enabled": asset.monitoring_enabled,
            "last_scan_at": asset.last_scan_at.isoformat() if asset.last_scan_at else None,
            "last_scan_status": asset.last_scan_status,
        }

    def _business_section(self, db: Session, asset: Asset) -> tuple[dict[str, Any], list[MissingInformation]]:
        profile = db.get(AssetSecurityProfile, asset.id)
        missing: list[MissingInformation] = []
        if profile is None:
            missing.append(
                MissingInformation(
                    code="business_context_not_configured",
                    message=(
                        "Business context (criticality, exposure, environment) is not "
                        "configured for this asset."
                    ),
                    affects=["business_context", "risk_scoring"],
                )
            )
            return {
                "configured": False,
                "criticality": None,
                "environment": None,
                "internet_exposed": None,
                "business_importance": None,
                "data_sensitivity": None,
                "owner_team": None,
            }, missing

        for field_name, code in (
            ("criticality", "asset_criticality_not_configured"),
            ("environment", "asset_environment_not_configured"),
            ("internet_exposed", "internet_exposure_not_configured"),
            ("business_importance", "business_importance_not_configured"),
            ("data_sensitivity", "data_sensitivity_not_configured"),
        ):
            if getattr(profile, field_name) is None:
                missing.append(
                    MissingInformation(
                        code=code,
                        message=f"{field_name.replace('_', ' ').title()} is not configured for this asset.",
                        affects=["business_context", "risk_scoring"],
                    )
                )
        return {
            "configured": True,
            "criticality": profile.criticality,
            "environment": profile.environment,
            "internet_exposed": profile.internet_exposed,
            "business_importance": profile.business_importance,
            "data_sensitivity": profile.data_sensitivity,
            "owner_team": profile.owner_team,
            "notes": profile.notes,
        }, missing

    def _dependency_section(self, db: Session, finding: Finding) -> dict[str, Any]:
        if not finding.package_name:
            return {"available": False, "reason": "finding_has_no_package"}
        return dependency_graph.analyze_package(
            db,
            asset_id=finding.asset_id,
            package_name=finding.package_name,
            package_version=finding.package_version,
        )

    def _vulnerability_section(
        self, db: Session, finding: Finding
    ) -> tuple[dict[str, Any], list[MissingInformation], list[VulnerabilityAffectedPackage]]:
        missing: list[MissingInformation] = []
        entries: list[Vulnerability] = []
        if finding.cve_id:
            entries = list(
                db.execute(select(Vulnerability).where(Vulnerability.cve_id == finding.cve_id)).scalars()
            )
        osv_id = (finding.metadata_json or {}).get("osv_id")
        if not entries and osv_id:
            entries = list(
                db.execute(
                    select(Vulnerability).where(
                        Vulnerability.source == "OSV", Vulnerability.source_id == str(osv_id)
                    )
                ).scalars()
            )
        if not entries and finding.scanner == "osv":
            entries = list(
                db.execute(
                    select(Vulnerability).where(
                        Vulnerability.source == "OSV", Vulnerability.source_id == finding.rule_id
                    )
                ).scalars()
            )

        if not entries:
            missing.append(
                MissingInformation(
                    code="vulnerability_intel_missing",
                    message=(
                        "No stored vulnerability-intelligence record matches this finding, "
                        "so CVSS, KEV and affected-version data are unavailable."
                    ),
                    affects=["vulnerability_context", "risk_scoring"],
                )
            )
            return (
                {
                    "available": False,
                    "cve_id": finding.cve_id,
                    "osv_id": osv_id,
                    "sources": [],
                    "is_kev": None,
                    "epss_score": None,
                },
                missing,
                [],
            )

        best = max(entries, key=lambda entry: float(entry.cvss_score or 0))
        is_kev = any(entry.is_kev for entry in entries)
        kev_entry = next((entry for entry in entries if entry.is_kev), None)
        referenced: list[dict[str, Any]] = []
        for entry in entries:
            for reference in db.execute(
                select(VulnerabilityReference).where(VulnerabilityReference.vulnerability_id == entry.id)
            ).scalars():
                referenced.append(
                    {"url": reference.url, "type": reference.ref_type, "source": reference.source}
                )

        affected_rows: list[VulnerabilityAffectedPackage] = []
        if finding.package_name:
            for entry in entries:
                for row in db.execute(
                    select(VulnerabilityAffectedPackage).where(
                        VulnerabilityAffectedPackage.vulnerability_id == entry.id,
                        VulnerabilityAffectedPackage.package_name == finding.package_name,
                    )
                ).scalars():
                    affected_rows.append(row)

        fixed_versions = sorted(
            {version for row in affected_rows for version in (row.fixed_versions or []) if version}
        )
        if not fixed_versions:
            fixed_versions = sorted(
                {
                    version
                    for entry in entries
                    for row in db.execute(
                        select(VulnerabilityAffectedPackage).where(
                            VulnerabilityAffectedPackage.vulnerability_id == entry.id
                        )
                    ).scalars()
                    for version in (row.fixed_versions or [])
                }
            )

        epss_scores = epss_module.scores_for(db, {entry.cve_id for entry in entries if entry.cve_id})
        epss_entry = next(iter(epss_scores.values()), None)
        ecosystem = (affected_rows[0].ecosystem if affected_rows else None) or (
            (finding.metadata_json or {}).get("ecosystem")
        )

        section = {
            "available": True,
            "cve_id": finding.cve_id or best.cve_id,
            "osv_id": best.osv_id or osv_id,
            "sources": sorted({entry.source for entry in entries}),
            "summary": best.summary,
            "description": (best.description or "")[:3000],
            "cvss_score": float(best.cvss_score) if best.cvss_score is not None else None,
            "cvss_vector": best.cvss_vector,
            "severity": best.severity,
            "published_at": best.published_at.isoformat() if best.published_at else None,
            "modified_at": best.modified_at.isoformat() if best.modified_at else None,
            "is_kev": is_kev,
            "kev_due_date": kev_entry.kev_due_date.isoformat()
            if kev_entry and kev_entry.kev_due_date
            else None,
            "kev_required_action": kev_entry.kev_required_action if kev_entry else None,
            "epss_score": epss_entry["score"] if epss_entry else None,
            "epss_percentile": epss_entry["percentile"] if epss_entry else None,
            "epss_scored_date": epss_entry["scored_date"] if epss_entry else None,
            "ecosystem": ecosystem,
            "affected_versions": sorted(
                {version for row in affected_rows for version in (row.affected_versions or [])}
            )[:50],
            "fixed_versions": fixed_versions[:50],
            "minimum_fixed_version": minimum_fixed_version(fixed_versions, ecosystem),
            "version_ranges": [row.version_ranges for row in affected_rows if row.version_ranges][:5],
            "references": referenced[:15],
        }
        if not referenced:
            missing.append(
                MissingInformation(
                    code="exploit_references_unavailable",
                    message="No advisory or exploit reference is stored for this vulnerability.",
                    affects=["exploitability"],
                )
            )
        return section, missing, affected_rows

    def _history_section(self, db: Session, finding: Finding) -> dict[str, Any]:
        rows = list(
            db.execute(
                select(FindingHistory)
                .where(FindingHistory.finding_id == finding.id)
                .order_by(FindingHistory.created_at.desc())
                .limit(20)
            ).scalars()
        )
        same_rule = (
            db.execute(
                select(Finding.id).where(
                    Finding.asset_id == finding.asset_id,
                    Finding.scanner == finding.scanner,
                    Finding.rule_id == finding.rule_id,
                    Finding.id != finding.id,
                )
            )
            .scalars()
            .all()
        )
        return {
            "events": [
                {
                    "event": row.event,
                    "from_status": row.from_status,
                    "to_status": row.to_status,
                    "actor": row.actor,
                    "note": row.note,
                    "at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in rows
            ],
            "active_findings_same_rule_on_asset": len(same_rule),
            "status": finding.status,
            "is_active": finding.status in ACTIVE_FINDING_STATUSES,
        }

    # ----------------------------------------------------------------- evidence
    def _finding_evidence(self, finding: Finding, section: dict[str, Any]) -> list[EvidenceItem]:
        parts = [
            f"scanner={finding.scanner} rule={finding.rule_id} severity={finding.severity}",
            f"title: {finding.title}",
        ]
        if finding.description:
            parts.append(f"description: {finding.description[:1500]}")
        if finding.file_path:
            parts.append(f"location: {finding.file_path}:{finding.line_number or '?'}")
        if finding.package_name:
            parts.append(
                f"package: {finding.package_name} {finding.package_version or ''} "
                f"(ecosystem={(section.get('scanner_metadata') or {}).get('ecosystem') or 'unknown'})"
            )
        if finding.cve_id:
            parts.append(f"cve: {finding.cve_id}")
        return [self._item("E1", "finding", finding.scanner, finding.file_path, "\n".join(parts))]

    def _vulnerability_evidence(
        self,
        finding: Finding,
        section: dict[str, Any],
        affected: list[VulnerabilityAffectedPackage],
    ) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        if not section.get("available"):
            return items
        lines = [
            f"identifiers: cve={section.get('cve_id')} osv={section.get('osv_id')} "
            f"sources={','.join(section.get('sources') or [])}",
            f"cvss: {section.get('cvss_score')} vector={section.get('cvss_vector')}",
            f"cisa_kev: {section.get('is_kev')} due={section.get('kev_due_date')} "
            f"action={section.get('kev_required_action')}",
            f"epss: {section.get('epss_score')} percentile={section.get('epss_percentile')} "
            f"date={section.get('epss_scored_date')}",
            f"affected_versions: {section.get('affected_versions')}",
            f"fixed_versions: {section.get('fixed_versions')} "
            f"minimum_fixed={section.get('minimum_fixed_version')}",
        ]
        if section.get("summary"):
            lines.append(f"summary: {section['summary']}")
        if section.get("description"):
            lines.append(f"description: {section['description'][:1500]}")
        references = section.get("references") or []
        if references:
            lines.append("references: " + ", ".join(str(ref.get("url")) for ref in references[:10]))
        items.append(
            self._item(
                "E2",
                "vulnerability",
                ",".join(section.get("sources") or ["vulnerability_intel"]),
                str(section.get("cve_id") or section.get("osv_id")),
                "\n".join(lines),
            )
        )
        for index, row in enumerate(affected[:2], start=3):
            text = (
                f"package={row.package_name} ecosystem={row.ecosystem} purl={row.purl}\n"
                f"affected={row.affected_versions}\nfixed={row.fixed_versions}\nranges={row.version_ranges}"
            )
            items.append(self._item(f"E{index}", "vulnerability", "affected_package", row.package_name, text))
        return items

    def _dependency_evidence(self, finding: Finding, section: dict[str, Any]) -> list[EvidenceItem]:
        if not section or section.get("reason") == "finding_has_no_package":
            return []
        if not section.get("available") and not section.get("package_name"):
            return []
        lines = [
            f"package: {section.get('package_name')} {section.get('installed_version') or ''}",
            f"ecosystem: {section.get('ecosystem')} purl={section.get('purl')}",
            f"is_direct: {section.get('is_direct')} depth_from_root: {section.get('depth')}",
            f"parents: {[(p.get('name'), p.get('version')) for p in section.get('parents') or []]}",
            f"direct_entry_points: {section.get('direct_entry_points') or []}",
            f"graph_available: {section.get('available')} reason={section.get('reason')}",
        ]
        return [
            self._item(
                "E4",
                "dependency",
                "sbom",
                section.get("package_name"),
                "\n".join(lines),
            )
        ]

    def _code_evidence(self, finding: Finding) -> list[EvidenceItem]:
        if not self.settings.ai_allow_source_sharing:
            return []
        metadata = finding.metadata_json or {}
        snippet = metadata.get("code") if isinstance(metadata.get("code"), dict) else None
        text = ""
        locator = f"{finding.file_path}:{finding.line_number or '?'}" if finding.file_path else None
        if isinstance(snippet, dict) and snippet.get("text"):
            text = str(snippet["text"])
            locator = str(snippet.get("locator") or locator)
        elif metadata.get("lines"):
            text = str(metadata["lines"])
        if not text:
            return []
        if len(text) > self.settings.ai_max_snippet_chars * max(1, self.settings.ai_max_snippets):
            text = text[: self.settings.ai_max_snippet_chars]
        return [self._item("E5", "code", finding.scanner, locator, text)]

    def _history_evidence(self, history: dict[str, Any]) -> list[EvidenceItem]:
        if not history.get("events"):
            return []
        text = "\n".join(
            f"{event['at']} {event['event']} "
            f"{event.get('from_status') or ''}->{event.get('to_status') or ''} "
            f"by {event['actor']}"
            for event in history["events"][:10]
            if event.get("at")
        )
        return [self._item("E6", "history", "finding_history", None, text)]

    def _business_evidence(self, business: dict[str, Any]) -> list[EvidenceItem]:
        if not business.get("configured"):
            return []
        text = "\n".join(
            f"{key}={business.get(key)}"
            for key in (
                "criticality",
                "environment",
                "internet_exposed",
                "business_importance",
                "data_sensitivity",
                "owner_team",
            )
        )
        return [self._item("E7", "business", "asset_security_profile", "asset", text)]

    def _item(self, key: str, kind: str, source: str, locator: str | None, text: str) -> EvidenceItem:
        from app.modules.ai.services.redaction import sanitize

        sanitized = sanitize(text, max_chars=self.settings.ai_max_snippet_chars * 2)
        return EvidenceItem(
            key=key,
            kind=kind,
            source=source,
            locator=locator,
            text=sanitized.text,
            sha256=sanitized.sha256,
            injection_markers=sanitized.injection_markers,
        )

    def _apply_budget(self, evidence: list[EvidenceItem]) -> tuple[list[EvidenceItem], bool]:
        """Cap total prompt size, highest-priority evidence first."""
        limit = self.settings.ai_max_input_chars
        max_items = self.settings.ai_context_max_evidence
        ordered = sorted(evidence, key=lambda item: EVIDENCE_PRIORITY.get(item.kind, 9))
        kept: list[EvidenceItem] = []
        used = 0
        truncated = False
        for item in ordered:
            if len(kept) >= max_items:
                truncated = True
                break
            remaining = limit - used
            if remaining <= 200:
                truncated = True
                break
            text = item.text
            if len(text) > remaining:
                text = text[: max(0, remaining - 50)] + "\n[truncated]"
                truncated = True
            kept.append(item.model_copy(update={"text": text}))
            used += len(text)
        return kept, truncated
