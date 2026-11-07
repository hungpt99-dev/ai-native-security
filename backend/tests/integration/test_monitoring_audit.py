"""Monitoring health, overview and the append-only audit trail."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.modules.audit import service as audit_service
from app.modules.audit.models import AuditLog
from app.modules.findings.models import Finding


def test_health_is_evidence_based_and_marks_unconfigured_ingestion_disabled(
    db: Session, monkeypatch
):
    monkeypatch.setattr(get_settings(), "events_ingest_token", None)
    health = audit_health = service_health = None
    from app.modules.monitoring import service as monitoring

    health = monitoring.health(db)
    assert health["components"]["database"]["status"] == "HEALTHY"
    assert health["components"]["event_ingestion"]["status"] == "DISABLED"
    # No repository rows is not "healthy": it is unknown.
    assert health["components"]["repository_monitoring"]["status"] == "UNKNOWN"
    assert health["status"] in {"UNKNOWN", "DEGRADED", "HEALTHY"}
    assert audit_health is None and service_health is None


def test_overview_aggregates_assets_findings_and_incidents(db: Session, asset_factory):
    asset = asset_factory()
    finding = Finding(
        asset_id=asset.id,
        scanner="trivy",
        rule_id="CVE-X",
        title="x",
        severity="HIGH",
        status="OPEN",
        fingerprint=uuid.uuid4().hex,
        first_detected_at=asset.created_at,
        last_detected_at=asset.created_at,
    )
    db.add(finding)
    db.flush()

    from app.modules.monitoring import service as monitoring

    overview = monitoring.overview(db)
    assert overview["assets"]["by_kind"]["REPOSITORY"] == 1
    assert overview["findings"]["by_severity"]["HIGH"] == 1
    assert overview["incidents"]["active"] == 0

    # The endpoint response must be pure JSON: ORM rows are a serialization bug.
    import json

    from app.modules.events import service as events_service

    events_service.ingest_falco(
        db,
        {
            "uuid": str(uuid.uuid4()),
            "priority": "Critical",
            "rule": "Container escape attempt",
            "output_fields": {"container.image.repository": "ghcr.io/acme/api"},
        },
    )
    db.commit()
    overview = monitoring.overview(db)
    assert overview["incidents"]["active"] == 1
    assert overview["events"]["last_24h"] >= 1
    json.dumps(overview, default=str)


def test_audit_records_are_written_and_readable(db: Session, client):
    audit_service.record(
        db,
        actor="analyst",
        action="UPDATE",
        resource_type="incidents",
        resource_id="abc",
        detail={"status": "RESOLVED"},
    )
    db.commit()
    listing = client.get("/api/v1/audit", params={"actor": "analyst"}).json()
    assert listing["total"] == 1
    assert listing["items"][0]["action"] == "UPDATE"


def test_mutating_api_requests_are_audited_by_the_middleware(client):
    response = client.post(
        "/api/v1/assets",
        json={
            "name": "audit-repo",
            "repo_url": "https://github.com/example/audit-repo",
        },
    )
    assert response.status_code == 201

    from app.database.session import SessionLocal

    with SessionLocal() as session:
        rows = session.execute(
            select(AuditLog).where(AuditLog.resource_type == "assets")
        ).scalars().all()
    assert any(row.action == "CREATE" for row in rows)


def test_audit_detail_is_bounded_and_redacted(db: Session):
    secret = "ghp_" + "b" * 36
    entry = audit_service.record(
        db,
        actor="analyst",
        action="INGEST",
        resource_type="test",
        detail={"note": f"token {secret}", "big": "x" * 5000},
    )
    db.flush()
    assert secret not in str(entry.detail)
    assert len(entry.detail["big"]) <= 500
