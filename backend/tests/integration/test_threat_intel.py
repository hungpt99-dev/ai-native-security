"""Integration tests: threat intelligence ingestion and event matching."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ValidationError
from app.modules.events import service as events_service
from app.modules.events.models import SecurityEvent
from app.modules.threat_intel import service
from app.modules.threat_intel.models import ThreatIndicator


def test_indicator_values_are_normalized_and_validated():
    assert service.normalize_value("IP", "2001:0DB8::1") == "2001:db8::1"
    assert service.normalize_value("DOMAIN", "Evil.Example.COM.") == "evil.example.com"
    assert service.normalize_value("SHA256", "A" * 64) == "a" * 64
    with pytest.raises(ValidationError):
        service.normalize_value("IP", "999.1.1.1")
    with pytest.raises(ValidationError):
        service.normalize_value("SHA256", "not-a-hash")
    with pytest.raises(ValidationError):
        service.normalize_value("URL", "file:///etc/passwd")


def test_upsert_counts_and_deduplicates_within_a_batch(db: Session):
    result = service.upsert_indicators(
        db,
        [
            {"indicator_type": "IP", "value": "203.0.113.5", "confidence": 90},
            {"indicator_type": "IP", "value": "203.0.113.5"},
            {"indicator_type": "IP", "value": "bad-ip"},
        ],
        source="MANUAL",
        actor="analyst",
    )
    db.commit()
    assert result["created"] == 1
    assert result["rejected"] == 1
    assert db.execute(select(ThreatIndicator)).scalar_one().confidence == 90


def test_event_matching_enriches_and_escalates_risk(db: Session):
    service.upsert_indicators(
        db,
        [{"indicator_type": "IP", "value": "203.0.113.66", "confidence": 95, "severity": "CRITICAL"}],
        source="MANUAL",
        actor="analyst",
    )
    events_service.ingest_generic(
        db,
        [
            {
                "event_type": "connection.outbound",
                "category": "NETWORK",
                "severity": "LOW",
                "normalized": {"remote_ip": "203.0.113.66", "remote_port": 443},
            }
        ],
    )
    db.commit()
    event = db.execute(select(SecurityEvent)).scalar_one()
    matches = event.enrichment["threat_matches"]
    assert matches[0]["value"] == "203.0.113.66"
    assert event.risk_score is not None and event.risk_score >= 35


def test_expired_indicators_do_not_match(db: Session):
    service.upsert_indicators(
        db,
        [
            {
                "indicator_type": "IP",
                "value": "203.0.113.77",
                "expires_at": datetime(2020, 1, 1, tzinfo=UTC),
            }
        ],
        source="MANUAL",
    )
    db.commit()
    matches = service.match_indicators(db, [{"type": "IP", "value": "203.0.113.77"}])
    assert matches == []


def test_indicator_api_ingests_lists_and_deactivates(db: Session, client):
    response = client.post(
        "/api/v1/threat-intel/indicators",
        json={
            "source": "MANUAL",
            "indicators": [
                {"indicator_type": "DOMAIN", "value": "c2.example.net", "confidence": 80}
            ],
        },
    )
    assert response.status_code == 201
    assert response.json()["created"] == 1

    listing = client.get("/api/v1/threat-intel/indicators", params={"indicator_type": "DOMAIN"})
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    indicator_id = listing.json()["items"][0]["id"]

    summary = client.get("/api/v1/threat-intel/summary").json()
    assert summary["active"] == 1
    assert summary["by_type"]["DOMAIN"] == 1

    deactivated = client.post(f"/api/v1/threat-intel/indicators/{indicator_id}/deactivate")
    assert deactivated.status_code == 200
    assert deactivated.json()["active"] is False


def test_invalid_batch_is_rejected_without_partial_write(db: Session, client):
    response = client.post(
        "/api/v1/threat-intel/indicators",
        json={
            "source": "MANUAL",
            "indicators": [{"indicator_type": "IP", "value": "not-an-ip"}],
        },
    )
    assert response.status_code == 201
    assert response.json()["created"] == 0
    assert response.json()["rejected"] == 1
