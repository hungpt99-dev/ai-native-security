"""Integration tests: incident lifecycle, correlation, risk, authorization."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Principal
from app.core.config import get_settings
from app.modules.assets.models import Asset
from app.modules.events import service as events_service
from app.modules.findings.models import Finding
from app.modules.incidents import service as incidents_service
from app.modules.incidents.models import Incident, IncidentFinding, IncidentInvestigation
from app.modules.security_intelligence.models import AssetSecurityProfile


def _critical_falco(**fields) -> dict:
    return {
        "uuid": str(uuid.uuid4()),
        "time": datetime.now(UTC).isoformat(),
        "priority": "Critical",
        "rule": "Container escape attempt",
        "output": "escape",
        "output_fields": {
            "proc.name": "nsenter",
            "container.image.repository": "ghcr.io/acme/api:1.2.3",
            **fields,
        },
    }


def _finding(db: Session, asset_id: uuid.UUID, *, severity="HIGH", cve="CVE-2024-0001") -> Finding:
    now = datetime.now(UTC)
    finding = Finding(
        asset_id=asset_id,
        scanner="trivy",
        rule_id=cve,
        title=f"{cve} in openssl",
        severity=severity,
        status="OPEN",
        fingerprint=uuid.uuid4().hex,
        cve_id=cve,
        first_detected_at=now,
        last_detected_at=now,
    )
    db.add(finding)
    db.flush()
    return finding


def test_incident_detail_contains_timeline_events_and_findings(db: Session):
    events_service.ingest_falco(db, _critical_falco())
    db.commit()
    incident = db.execute(select(Incident)).scalar_one()
    asset_id = incident.asset_id
    _finding(db, asset_id)
    db.commit()

    data = incidents_service.details(db, incident.id)
    assert data["incident"].id == incident.id
    assert len(data["events"]) == 1
    assert [entry.kind for entry in data["timeline"]][0] == "CREATED"


def test_second_matching_event_attaches_to_the_open_incident(db: Session):
    events_service.ingest_falco(db, _critical_falco())
    # A different process is a different event with the same detection rule, so
    # it must attach to the open incident instead of opening a second one.
    events_service.ingest_falco(db, _critical_falco(**{"proc.name": "sh"}))
    db.commit()
    incident = db.execute(select(Incident)).scalar_one()
    assert incident.event_count == 2
    kinds = [entry.kind for entry in incidents_service.timeline(db, incident.id)]
    assert "EVENT_ATTACHED" in kinds


def test_incident_status_transitions_are_enforced(db: Session):
    events_service.ingest_falco(db, _critical_falco())
    db.commit()
    incident = db.execute(select(Incident)).scalar_one()
    incidents_service.change_status(
        db, incident, new_status="INVESTIGATING", actor="analyst", note="looking"
    )
    assert incident.acknowledged_at is not None
    from app.core.errors import ConflictError

    try:
        incidents_service.change_status(
            db, incident, new_status="CONTAINED", actor="analyst"
        )
    except ConflictError:
        raise AssertionError("INVESTIGATING -> CONTAINED must be allowed") from None
    try:
        incidents_service.change_status(db, incident, new_status="TRIAGING", actor="analyst")
    except ConflictError:
        pass
    else:  # pragma: no cover - regression guard
        raise AssertionError("CONTAINED -> TRIAGING must be refused")


def test_asset_criticality_and_exposure_raise_incident_priority(db: Session):
    events_service.ingest_falco(db, _critical_falco(priority="Warning", rule="Shell"))
    db.commit()
    incident = db.execute(select(Incident)).scalar_one()
    baseline = incident.risk_score
    db.add(
        AssetSecurityProfile(
            asset_id=incident.asset_id,
            criticality="CRITICAL",
            internet_exposed=True,
            environment="PRODUCTION",
        )
    )
    db.flush()
    incidents_service.recompute_risk(db, incident)
    assert incident.risk_score > baseline


def test_correlation_links_same_cve_across_assets(db: Session):
    events_service.ingest_falco(db, _critical_falco())
    db.commit()
    incident = db.execute(select(Incident)).scalar_one()
    local = _finding(db, incident.asset_id, cve="CVE-2024-9999")
    # The finding appeared after the incident was opened; link it explicitly so
    # correlation has a CVE to follow.
    db.add(IncidentFinding(incident_id=incident.id, finding_id=local.id, reason="manual"))
    incident.finding_count = 1
    db.flush()

    other = Asset(
        name="other",
        kind="REPOSITORY",
        repo_url="https://github.com/example/other",
        provider="GITHUB",
    )
    db.add(other)
    db.flush()
    remote = _finding(db, other.id, cve="CVE-2024-9999")
    db.commit()

    result = incidents_service.correlate(db, incident, actor="analyst")
    db.commit()
    assert result["findings"] == 1
    assert remote.id


def test_incident_api_requires_authorization_and_hides_unscoped(db: Session, client, monkeypatch):
    events_service.ingest_falco(db, _critical_falco())
    db.commit()

    settings = get_settings()
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "api_keys", ["test-key"])
    monkeypatch.setattr(settings, "api_key_scopes", {"1": []})
    response = client.get("/api/v1/incidents")
    assert response.status_code == 401

    response = client.get("/api/v1/incidents", headers={"X-API-Key": "test-key"})
    assert response.status_code == 200
    assert response.json()["total"] == 0

    monkeypatch.setattr(settings, "api_key_scopes", {})
    response = client.get("/api/v1/incidents", headers={"X-API-Key": "test-key"})
    assert response.json()["total"] == 1


def test_incident_state_survives_ai_availability(db: Session):
    """An AI investigation row is optional evidence, not a state transition."""
    events_service.ingest_falco(db, _critical_falco())
    db.commit()
    incident = db.execute(select(Incident)).scalar_one()
    assert db.execute(select(IncidentInvestigation)).scalar_one_or_none() is None
    assert incident.status == "OPEN"  # no AI run, no state change


def test_principal_scope_denies_unattributed_assets():
    scoped = Principal(subject="k", is_authenticated=True, asset_scope=frozenset({uuid.uuid4()}))
    assert scoped.allows(None) is False
    assert Principal(subject="a", is_authenticated=False).allows(None) is True
