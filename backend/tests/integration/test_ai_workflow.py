"""End-to-end AI workflow on a real PostgreSQL database, with a fake provider.

These tests exercise the actual services: context building, deterministic signals,
policy blending, ledger rows, the LangGraph investigation, remediation version
validation, the approval lifecycle and deterministic verification.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.enums import (
    RemediationStatus,
    ScanStatus,
    Severity,
    VerificationStatus,
)
from app.modules.ai.models import AIExecution
from app.modules.ai.providers.fake import FakeProvider
from app.modules.ai.services import investigations as investigations_service
from app.modules.ai.services import tools
from app.modules.findings import service as findings_service
from app.modules.findings.models import Finding
from app.modules.knowledge_base.models import SecurityDecision
from app.modules.remediation import service as remediation_service
from app.modules.risk_analysis import service as risk_service
from app.modules.sbom.service import store_sbom
from app.modules.scanners.base import NormalizedFinding
from app.modules.scanners.syft import SbomDocument, SbomEdge, SbomPackageInfo
from app.modules.scans.models import Scan
from app.modules.security_intelligence.context_builder import SecurityContextBuilder
from app.modules.security_intelligence.models import AssetSecurityProfile, SecurityContextSnapshot
from app.modules.verification import service as verification_service
from app.modules.vulnerabilities import repository as vuln_repo
from app.modules.vulnerabilities.models import VulnerabilityEpss
from app.modules.vulnerabilities.records import (
    AffectedPackageRecord,
    ReferenceRecord,
    VulnerabilityRecord,
)

CVE = "CVE-2021-23337"


# --------------------------------------------------------------------- helpers
def risk_payload(finding_key: str = "E1") -> dict:
    return {
        "risk_level": "HIGH",
        "risk_score": 80,
        "confidence": 0.75,
        "summary": "Public-facing app bundles a vulnerable lodash.",
        "impact_analysis": "Prototype pollution can reach template rendering.",
        "exploitability_analysis": "Listed in CISA KEV and has public advisories.",
        "affected_components": ["api"],
        "evidence": [{"key": finding_key, "note": "package and version"}],
        "missing_information": [],
        "recommended_actions": ["Upgrade lodash to the fixed release"],
        "requires_human_review": True,
    }


def investigation_payload(evidence_key: str = "E2") -> dict:
    return {
        "status": "POTENTIAL_IMPACT",
        "confidence": 0.6,
        "summary": "Direct dependency, reachable from the HTTP layer in principle.",
        "answers": {
            "what_is_vulnerable": "lodash 4.17.20 template helper",
            "dependency_entry_point": "direct npm dependency",
            "functionality_used": "no call site evidence was supplied",
            "externally_reachable": "the service is internet-facing per configuration",
            "potential_impact": "prototype pollution could affect template output",
        },
        "impact_analysis": "Partial evidence only.",
        "exploitability_analysis": "KEV listed, but no call-site evidence.",
        "evidence": [{"key": evidence_key, "note": "advisory"}],
        "missing_information": ["call-site snippet"],
        "next_steps": ["confirm template usage", "check exposure"],
    }


def remediation_payload(version: str = "4.17.21") -> dict:
    return {
        "strategy": "DEPENDENCY_UPGRADE",
        "summary": f"Upgrade lodash to {version}.",
        "reasoning": "Installed version is inside the affected range.",
        "target_package": "lodash",
        "current_version": "4.17.20",
        "recommended_version": version,
        "changes": [{"file": "package-lock.json", "description": "bump lodash"}],
        "patch": "--- a/package.json\n+++ b/package.json\n",
        "breaking_change_risks": ["minor API surface change"],
        "recommended_tests": ["npm test"],
        "expected_security_improvement": "Removes the affected code path.",
        "missing_information": [],
        "requires_human_approval": True,
    }


def provider_for(**payloads) -> FakeProvider:
    def responder(request, schema):
        payload = payloads.get(request.prompt_id)
        if payload is None:
            raise AssertionError(f"unexpected prompt id {request.prompt_id}")
        return payload(request, schema) if callable(payload) else payload

    return FakeProvider(responder=responder)


@pytest.fixture()
def ai_enabled(monkeypatch: pytest.MonkeyPatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "ai_enabled", True, raising=False)
    monkeypatch.setattr(settings, "ai_model", "test-model", raising=False)
    monkeypatch.setattr(settings, "ai_auto_analyze", False, raising=False)
    monkeypatch.setattr(settings, "ai_daily_budget_usd", 100.0, raising=False)
    monkeypatch.setattr(settings, "ai_allow_source_sharing", True, raising=False)
    return settings


@pytest.fixture()
def seeded(db, asset_factory, storage):
    asset = asset_factory(name="nodegoat")
    now = datetime.now(UTC)
    scan = Scan(
        asset_id=asset.id,
        status=ScanStatus.COMPLETED.value,
        trigger="MANUAL",
        started_at=now,
        finished_at=now,
        total_findings=1,
        critical_count=1,
    )
    db.add(scan)
    db.flush()

    normalized = NormalizedFinding(
        scanner="trivy",
        rule_id=CVE,
        title="lodash prototype pollution",
        category="vulnerability",
        severity=Severity.CRITICAL.value,
        description="Versions of lodash before 4.17.21 are vulnerable to command injection via template.",
        package_name="lodash",
        package_version="4.17.20",
        purl="pkg:npm/lodash@4.17.20",
        cve_id=CVE,
        cvss_score=9.8,
        metadata={
            "ecosystem": "npm",
            "fixed_version": "4.17.21",
            "references": ["https://github.com/advisories/GHSA-35jh-r3h4-6jhm"],
            "lines": "_.template(userInput)",
        },
    )
    findings_service.record_scan_findings(db, asset_id=asset.id, scan_id=scan.id, normalized=[normalized])
    finding = db.execute(select(Finding).where(Finding.asset_id == asset.id)).scalar_one()

    record = VulnerabilityRecord(
        source="OSV",
        source_id="GHSA-35jh-r3h4-6jhm",
        cve_id=CVE,
        osv_id="GHSA-35jh-r3h4-6jhm",
        summary="Command injection in lodash",
        description="lodash versions before 4.17.21 are vulnerable to command injection via template.",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity="CRITICAL",
        is_kev=True,
        kev_due_date=date(2022, 1, 24),
        references=[
            ReferenceRecord(url="https://nvd.nist.gov/vuln/detail/CVE-2021-23337", ref_type="ADVISORY")
        ],
        affected_packages=[
            AffectedPackageRecord(
                ecosystem="npm",
                package_name="lodash",
                purl="pkg:npm/lodash",
                affected_versions=["4.17.20"],
                fixed_versions=["4.17.21"],
                version_ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
            )
        ],
    )
    vuln_repo.upsert_vulnerability(db, record)
    db.add(
        VulnerabilityEpss(
            cve_id=CVE, score=0.94, percentile=0.997, scored_date=date.today(), model_version="v2025"
        )
    )

    document = SbomDocument(
        content=b'{"bomFormat":"CycloneDX"}',
        format="CYCLONEDX_JSON",
        spec_version="1.5",
        tool_version="syft-test",
        packages=[
            SbomPackageInfo(name="lodash", version="4.17.20", ecosystem="npm", purl="pkg:npm/lodash@4.17.20"),
            SbomPackageInfo(name="express", version="4.18.2", ecosystem="npm", purl="pkg:npm/express@4.18.2"),
        ],
        edges=[
            SbomEdge(from_ref=None, to_ref="pkg:npm/express@4.18.2", to_name="express", to_version="4.18.2"),
            SbomEdge(
                from_ref="pkg:npm/express@4.18.2",
                to_ref="pkg:npm/lodash@4.17.20",
                from_name="express",
                from_version="4.18.2",
                to_name="lodash",
                to_version="4.17.20",
            ),
        ],
        direct_package_keys={("express", "4.18.2")},
    )
    store_sbom(db, asset_id=asset.id, scan_id=scan.id, document=document, storage=storage)
    db.commit()
    return SimpleNamespace(asset=asset, scan=scan, finding=finding)


# --------------------------------------------------------------------- context
def test_context_snapshot_is_reproducible_and_reports_gaps(db, seeded) -> None:
    builder = SecurityContextBuilder()
    first = builder.build(db, seeded.finding.id)
    second = builder.build(db, seeded.finding.id)

    assert first.evidence_hash() == second.evidence_hash()
    assert first.vulnerability["cve_id"] == CVE
    assert first.vulnerability["is_kev"] is True
    assert first.vulnerability["epss_score"] == pytest.approx(0.94)
    assert first.vulnerability["fixed_versions"] == ["4.17.21"]
    assert first.dependency["available"] is True
    assert first.dependency["is_direct"] is False
    assert any(item.kind == "code" for item in first.evidence)

    codes = set(first.missing_codes())
    assert "business_context_not_configured" in codes
    assert "runtime_context_unavailable" in codes

    snapshot = builder.persist(db, first, finding=seeded.finding)
    db.commit()
    stored = db.get(SecurityContextSnapshot, snapshot.id)
    assert stored is not None
    assert stored.evidence_hash == first.evidence_hash()


def test_business_context_is_reported_when_configured(db, seeded) -> None:
    db.add(
        AssetSecurityProfile(
            asset_id=seeded.asset.id,
            criticality="CRITICAL",
            environment="PRODUCTION",
            internet_exposed=True,
            business_importance="MISSION_CRITICAL",
            data_sensitivity="CONFIDENTIAL",
            owner_team="platform",
        )
    )
    db.commit()
    context = SecurityContextBuilder().build(db, seeded.finding.id)
    assert context.business["internet_exposed"] is True
    assert "business_context_not_configured" not in context.missing_codes()


# ------------------------------------------------------------------------ risk
def test_risk_assessment_keeps_five_numbers_separate(db, seeded, ai_enabled) -> None:
    provider = provider_for(**{"risk.assessment": risk_payload()})
    assessment = risk_service.assess(db, seeded.finding.id, provider=provider, principal="tester")

    assert assessment.cvss_score is not None and float(assessment.cvss_score) == pytest.approx(9.8)
    assert assessment.deterministic_score >= 70
    assert assessment.ai_risk_score == 80
    assert assessment.final_score == round(assessment.deterministic_score * 0.65 + 80 * 0.35)
    assert assessment.risk_level == "HIGH"
    assert assessment.deterministic_only is False
    assert assessment.ai_risk_level == "HIGH"
    assert assessment.model == "test-model"
    assert any(signal["key"] == "kev" and signal["known"] for signal in assessment.signals)

    # CVSS on the finding is untouched by the AI layer.
    db.refresh(seeded.finding)
    assert float(seeded.finding.cvss_score) == pytest.approx(9.8)

    execution = db.execute(select(AIExecution)).scalars().first()
    assert execution is not None
    assert execution.status == "SUCCEEDED"
    assert execution.prompt_id == "risk.assessment"
    assert execution.input_tokens is not None


def test_risk_assessment_without_ai_is_explicitly_deterministic(db, seeded, monkeypatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "ai_enabled", False, raising=False)
    assessment = risk_service.assess(db, seeded.finding.id, provider=FakeProvider(configured=False))

    assert assessment.deterministic_only is True
    assert assessment.ai_risk_score is None
    assert assessment.ai_risk_level is None
    codes = {item["code"] for item in assessment.missing_information}
    assert "ai_unavailable_for_assessment" in codes
    # Missing business context lowers confidence (weighted coverage), never risk.
    total_weight = sum(signal["weight"] for signal in assessment.signals)
    known_weight = sum(signal["weight"] for signal in assessment.signals if signal["known"])
    coverage = known_weight / total_weight
    assert assessment.confidence == pytest.approx(round(min(1.0, coverage * 0.85), 2))
    assert coverage < 1.0


def test_provider_failure_still_persists_a_labelled_assessment(db, seeded, ai_enabled) -> None:
    from app.modules.ai.errors import AIProviderError

    provider = FakeProvider(responses=[AIProviderError("upstream exploded")])
    assessment = risk_service.assess(db, seeded.finding.id, provider=provider)

    assert assessment.deterministic_only is True
    assert any(item["code"] == "ai_unavailable_for_assessment" for item in assessment.missing_information)
    ledger = db.execute(select(AIExecution)).scalars().all()
    assert any(row.status == "FAILED" for row in ledger)


# --------------------------------------------------------------- investigation
def test_investigation_workflow_persists_report_and_evidence(db, seeded, ai_enabled) -> None:
    provider = provider_for(**{"investigation.finding": investigation_payload()})
    investigation = investigations_service.investigate(db, seeded.finding.id, provider=provider)

    assert investigation.status == "POTENTIAL_IMPACT"
    assert investigation.workflow_name == "investigation"
    assert investigation.model == "test-model"
    evidence = investigations_service.evidence_for(db, investigation.id)
    assert evidence, "evidence rows must be persisted"
    cited = [row for row in evidence if row.evidence_metadata.get("cited")]
    assert cited, "the reported citation must resolve to a stored evidence row"
    assert investigation.answers["dependency_entry_point"] == "direct npm dependency"
    assert float(investigation.confidence) == pytest.approx(0.6)


def test_unsupported_citations_are_dropped_and_downgraded(db, seeded, ai_enabled) -> None:
    provider = provider_for(**{"investigation.finding": investigation_payload(evidence_key="E99")})
    investigation = investigations_service.investigate(db, seeded.finding.id, provider=provider)
    assert investigation.status == "NEEDS_MANUAL_REVIEW"
    assert not [
        row
        for row in investigations_service.evidence_for(db, investigation.id)
        if row.evidence_metadata.get("cited")
    ]


def test_investigation_without_ai_is_inconclusive(db, seeded, monkeypatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "ai_enabled", False, raising=False)
    investigation = investigations_service.investigate(
        db, seeded.finding.id, provider=FakeProvider(configured=False)
    )
    assert investigation.status == "INCONCLUSIVE"
    assert investigation.error_code == "ai_unavailable"
    assert any(
        item["code"] == "ai_unavailable_for_investigation" for item in investigation.missing_information
    )


# ------------------------------------------------------------------ remediation
def test_remediation_accepts_authoritative_fixed_version(db, seeded, ai_enabled) -> None:
    provider = provider_for(**{"remediation.finding": remediation_payload("4.17.21")})
    recommendation = remediation_service.propose(db, seeded.finding.id, provider=provider)

    assert recommendation.recommended_version == "4.17.21"
    assert recommendation.version_verified is True
    assert recommendation.status == RemediationStatus.AWAITING_APPROVAL.value
    assert recommendation.patch_format == "unified-diff"
    assert recommendation.requires_human_approval is True


def test_remediation_rejects_a_version_the_data_does_not_support(db, seeded, ai_enabled) -> None:
    provider = provider_for(**{"remediation.finding": remediation_payload("9.9.9")})
    recommendation = remediation_service.propose(db, seeded.finding.id, provider=provider)

    assert recommendation.recommended_version is None
    assert recommendation.version_verified is False
    codes = {item["code"] for item in recommendation.missing_information}
    assert "recommended_version_rejected" in codes


def test_approval_lifecycle_records_a_decision(db, seeded, ai_enabled) -> None:
    provider = provider_for(**{"remediation.finding": remediation_payload("4.17.21")})
    recommendation = remediation_service.propose(db, seeded.finding.id, provider=provider)

    approved = remediation_service.approve(
        db, recommendation.id, actor="analyst", note="approved for sprint 12"
    )
    assert approved.status == RemediationStatus.APPROVED.value
    assert approved.approved_by == "analyst"
    decision = db.execute(select(SecurityDecision)).scalars().one()
    assert decision.decision_type == "APPROVE_REMEDIATION"
    assert decision.actor == "analyst"

    from app.core.errors import ConflictError

    with pytest.raises(ConflictError):
        remediation_service.transition(
            db, approved, RemediationStatus.AWAITING_APPROVAL.value
        )

    # The post-verification states are reachable (VERIFIED → DEPLOYED → CLOSED).
    remediation_service.transition(db, approved, RemediationStatus.VALIDATING.value, actor="analyst")
    remediation_service.transition(db, approved, RemediationStatus.VERIFIED.value, actor="analyst")
    remediation_service.transition(db, approved, RemediationStatus.DEPLOYED.value, actor="analyst")
    closed = remediation_service.transition(
        db, approved, RemediationStatus.CLOSED.value, actor="analyst"
    )
    assert closed.status == RemediationStatus.CLOSED.value


# ----------------------------------------------------------------- verification
def _completed_scan_with_package(db, asset_id, *, version: str, keep_finding: bool, extra_high: bool):
    now = datetime.now(UTC)
    scan = Scan(
        asset_id=asset_id,
        status=ScanStatus.COMPLETED.value,
        trigger="MANUAL",
        started_at=now,
        finished_at=now,
    )
    db.add(scan)
    db.flush()
    if keep_finding:
        normalized = NormalizedFinding(
            scanner="trivy",
            rule_id=CVE,
            title="lodash prototype pollution",
            category="vulnerability",
            severity=Severity.CRITICAL.value,
            package_name="lodash",
            package_version=version,
            cve_id=CVE,
            cvss_score=9.8,
        )
        findings_service.record_scan_findings(db, asset_id=asset_id, scan_id=scan.id, normalized=[normalized])
    if extra_high:
        findings_service.record_scan_findings(
            db,
            asset_id=asset_id,
            scan_id=scan.id,
            normalized=[
                NormalizedFinding(
                    scanner="semgrep",
                    rule_id="python.lang.security.audit.exec",
                    title="command injection",
                    category="sast",
                    severity=Severity.CRITICAL.value,
                    file_path="app/new.py",
                    line_number=3,
                )
            ],
        )
    return scan


def _give_scan_package(db, storage, scan, asset_id, version: str) -> None:
    document = SbomDocument(
        content=b"{}",
        format="CYCLONEDX_JSON",
        spec_version="1.5",
        tool_version="syft-test",
        packages=[SbomPackageInfo(name="lodash", version=version, ecosystem="npm")],
    )
    store_sbom(db, asset_id=asset_id, scan_id=scan.id, document=document, storage=storage)
    db.commit()


def test_verification_confirms_a_real_fix(db, seeded, storage, ai_enabled) -> None:
    provider = provider_for(**{"remediation.finding": remediation_payload("4.17.21")})
    recommendation = remediation_service.propose(db, seeded.finding.id, provider=provider)
    remediation_service.approve(db, recommendation.id, actor="analyst", note="ok")
    remediation_service.transition(db, recommendation, RemediationStatus.VALIDATING.value, actor="analyst")

    verification_scan = _completed_scan_with_package(
        db, seeded.asset.id, version="4.17.21", keep_finding=False, extra_high=False
    )
    _give_scan_package(db, storage, verification_scan, seeded.asset.id, "4.17.21")

    # The original finding is no longer detected in the new scan.
    seeded.finding.status = "RESOLVED"
    seeded.finding.last_scan_id = seeded.scan.id
    db.commit()

    results = verification_service.on_scan_completed(db, verification_scan.id)
    assert len(results) == 1
    verification = results[0]
    assert verification.status == VerificationStatus.VERIFIED_FIXED.value
    assert verification.after_version == "4.17.21"
    assert verification.before_version == "4.17.20"
    db.refresh(recommendation)
    assert recommendation.status == RemediationStatus.VERIFIED.value


def test_verification_detects_no_progress(db, seeded, storage, ai_enabled) -> None:
    provider = provider_for(**{"remediation.finding": remediation_payload("4.17.21")})
    recommendation = remediation_service.propose(db, seeded.finding.id, provider=provider)
    remediation_service.approve(db, recommendation.id, actor="analyst", note="ok")
    remediation_service.transition(db, recommendation, RemediationStatus.VALIDATING.value, actor="analyst")

    verification_scan = _completed_scan_with_package(
        db, seeded.asset.id, version="4.17.20", keep_finding=True, extra_high=False
    )
    _give_scan_package(db, storage, verification_scan, seeded.asset.id, "4.17.20")
    db.commit()

    results = verification_service.on_scan_completed(db, verification_scan.id)
    assert results[0].status == VerificationStatus.STILL_VULNERABLE.value
    db.refresh(recommendation)
    assert recommendation.status == RemediationStatus.FAILED.value


def test_verification_flags_new_risk_introduced(db, seeded, storage, ai_enabled) -> None:
    provider = provider_for(**{"remediation.finding": remediation_payload("4.17.21")})
    recommendation = remediation_service.propose(db, seeded.finding.id, provider=provider)
    remediation_service.approve(db, recommendation.id, actor="analyst", note="ok")
    remediation_service.transition(db, recommendation, RemediationStatus.VALIDATING.value, actor="analyst")

    verification_scan = _completed_scan_with_package(
        db, seeded.asset.id, version="4.17.21", keep_finding=False, extra_high=True
    )
    _give_scan_package(db, storage, verification_scan, seeded.asset.id, "4.17.21")
    seeded.finding.status = "RESOLVED"
    seeded.finding.last_scan_id = seeded.scan.id
    db.commit()

    results = verification_service.on_scan_completed(db, verification_scan.id)
    assert results[0].status == VerificationStatus.NEW_RISK_INTRODUCED.value
    assert results[0].new_findings_count == 1


# ------------------------------------------------------------------- assistant
def test_assistant_tools_are_read_only_and_scope_aware(db, seeded) -> None:
    catalog = {entry["name"] for entry in tools.tool_catalog()}
    assert "list_findings" in catalog
    assert not any("sql" in name or "shell" in name or "url" in name for name in catalog)

    result = tools.execute(db, "list_findings", {"severity": ["CRITICAL"]})
    assert result.error is None
    assert result.count == 1

    other_scope = frozenset({uuid.uuid4()})
    denied = tools.execute(db, "asset_overview", {"asset_id": str(seeded.asset.id)}, asset_scope=other_scope)
    assert denied.error is not None
    assert denied.rows is None

    unknown = tools.execute(db, "run_sql", {"query": "select 1"})
    assert unknown.error == "unknown_tool"


def test_assistant_plans_and_answers_with_tool_grounding(db, seeded, ai_enabled) -> None:
    from app.modules.ai.services import assistant as assistant_service

    def plan(request, schema):
        # Deliberately non-canonical: the service must normalise "calls"/"args".
        return {
            "calls": [
                {"tool": "list_findings", "args": {"severity": ["CRITICAL"]}, "rationale": "top items"}
            ],
            "reasoning": "need the critical findings",
        }

    def answer(request, schema):
        return {
            "answer": "There is one critical finding on nodegoat (lodash 4.17.20).",
            "cited_finding_ids": [str(seeded.finding.id)],
            "cited_asset_ids": [str(seeded.asset.id)],
            "data_gaps": [],
        }

    provider = provider_for(**{"assistant.plan": plan, "assistant.answer": answer})
    reply = assistant_service.ask(
        db,
        question="Which critical findings do we have?",
        principal="analyst",
        provider=provider,
    )
    assert "lodash" in reply.answer
    assert reply.tool_results and reply.tool_results[0]["tool"] == "list_findings"
    assert reply.tool_results[0]["count"] == 1
    assert reply.cited_finding_ids == [str(seeded.finding.id)]
    assert len(reply.executions) == 2


# ------------------------------------------------------------------------ auth
def test_asset_scope_is_enforced_on_ai_endpoints(client, db, seeded, ai_enabled, monkeypatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "auth_enabled", True, raising=False)
    monkeypatch.setattr(settings, "api_keys", ["scoped-key"], raising=False)
    monkeypatch.setattr(settings, "api_key_scopes", {"1": [str(uuid.uuid4())]}, raising=False)

    response = client.post(
        f"/api/v1/findings/{seeded.finding.id}/risk-assessment",
        headers={"X-API-Key": "scoped-key"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"

    own = client.post(
        f"/api/v1/findings/{seeded.finding.id}/security-context",
        headers={"X-API-Key": "scoped-key"},
    )
    assert own.status_code == 403


def test_ai_health_endpoint_never_leaks_the_key(client, ai_enabled) -> None:
    response = client.get("/api/v1/ai/health")
    assert response.status_code == 200
    body = response.json()
    assert "api_key" not in body
    assert body["enabled"] is True
    assert "budget" in body
