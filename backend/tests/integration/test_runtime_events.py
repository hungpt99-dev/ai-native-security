"""Integration tests: runtime event ingestion, detection, dedupe, incidents."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.modules.assets.models import Asset
from app.modules.events import anomaly
from app.modules.events import service as events_service
from app.modules.events.models import SecurityEvent
from app.modules.events.normalize import normalize_falco
from app.modules.incidents.models import Incident


def _falco_payload(*, rule: str = "Terminal shell in container", priority: str = "Warning",
                   image: str = "ghcr.io/acme/api:1.2.3", **fields) -> dict:
    return {
        "uuid": str(uuid.uuid4()),
        "time": datetime.now(UTC).isoformat(),
        "priority": priority,
        "rule": rule,
        "output": "A shell was spawned in a container",
        "output_fields": {
            "proc.name": "bash",
            "proc.cmdline": "bash -i",
            "container.image.repository": image,
            **fields,
        },
    }


def test_ingestion_creates_event_and_auto_discovers_container_asset(db: Session):
    payload = _falco_payload()
    result = events_service.ingest_falco(db, payload)
    db.commit()

    assert result["created"] == 1
    event = db.execute(select(SecurityEvent)).scalar_one()
    assert event.source == "FALCO"
    assert event.severity == "HIGH"  # shell-in-container rule
    assert event.rule_slug == "runtime.shell_in_container"
    asset = db.execute(
        select(Asset).where(Asset.external_ref == "docker://ghcr.io/acme/api:1.2.3")
    ).scalar_one()
    assert asset.kind == "CONTAINER_IMAGE"
    assert event.asset_id == asset.id


def test_duplicate_event_increments_occurrences_instead_of_rows(db: Session):
    base = _falco_payload()
    base["uuid"] = None
    events_service.ingest_falco(db, base)
    # A second alert with the same identity but a different provider id is the
    # same detection, not a new row.
    second = dict(base)
    second["time"] = (datetime.now(UTC) + timedelta(seconds=5)).isoformat()
    result = events_service.ingest_falco(db, second)
    db.commit()
    assert result["deduplicated"] == 1
    event = db.execute(select(SecurityEvent)).scalar_one()
    assert event.occurrence_count == 2


def test_provider_event_id_replay_is_a_noop(db: Session):
    payload = _falco_payload()
    first = events_service.ingest_falco(db, payload)
    second = events_service.ingest_falco(db, payload)
    db.commit()
    assert first["created"] == 1
    assert second["deduplicated"] == 1
    assert second["results"][0]["reason"] == "source_event_id"
    assert len(db.execute(select(SecurityEvent)).scalars().all()) == 1


def test_critical_falco_event_opens_a_p1_incident(db: Session):
    events_service.ingest_falco(db, _falco_payload(priority="Critical", rule="Container escape attempt"))
    db.commit()
    incident = db.execute(select(Incident)).scalar_one()
    assert incident.severity == "CRITICAL"
    assert incident.priority == "P1"
    event = db.execute(select(SecurityEvent)).scalar_one()
    assert event.incident_id == incident.id
    assert incident.event_count == 1


def test_threshold_rule_creates_an_incident_only_after_the_count(db: Session):
    for index in range(9):
        events_service.ingest_generic(
            db,
            [
                {
                    "event_type": "auth.failure",
                    "category": "IDENTITY",
                    "severity": "LOW",
                    # A distinct user keeps each attempt a distinct event, which
                    # is what a real authentication log produces.
                    "normalized": {"remote_ip": "198.51.100.7", "user": f"admin{index}"},
                }
            ],
        )
    db.commit()
    assert db.execute(select(Incident)).scalar_one_or_none() is None

    events_service.ingest_generic(
        db,
        [
            {
                "event_type": "auth.failure",
                "category": "IDENTITY",
                "severity": "LOW",
                "normalized": {"remote_ip": "198.51.100.7", "user": "final-attempt"},
            }
        ],
    )
    db.commit()
    incident = db.execute(select(Incident)).scalar_one()
    assert incident.detection_rule_slug == "identity.repeated_auth_failure"
    assert incident.event_count == 1


def test_events_from_different_addresses_do_not_aggregate(db: Session):
    for index in range(12):
        events_service.ingest_generic(
            db,
            [
                {
                    "event_type": "auth.failure",
                    "category": "IDENTITY",
                    "severity": "LOW",
                    "normalized": {"remote_ip": f"198.51.100.{index + 1}"},
                }
            ],
        )
    db.commit()
    assert db.execute(select(Incident)).scalar_one_or_none() is None


def test_unknown_falco_priority_is_never_silently_high():
    event = normalize_falco({"priority": "weird", "rule": "x"})
    assert event.severity == "UNKNOWN"


def test_api_requires_the_ingest_token(monkeypatch, client):
    settings = get_settings()
    monkeypatch.setattr(settings, "events_ingest_token", None)
    response = client.post("/api/v1/ingest/falco", json=_falco_payload())
    assert response.status_code == 503

    monkeypatch.setattr(settings, "events_ingest_token", "sensor-secret")
    assert client.post("/api/v1/ingest/falco", json=_falco_payload()).status_code == 401
    response = client.post(
        "/api/v1/ingest/falco",
        json=_falco_payload(),
        headers={"X-ANS-Ingest-Token": "sensor-secret"},
    )
    assert response.status_code == 202
    assert response.json()["created"] == 1


def test_event_api_lists_filters_and_triages(db: Session, client):
    events_service.ingest_falco(db, _falco_payload())
    db.commit()
    listing = client.get("/api/v1/events", params={"severity": "HIGH"}).json()
    assert listing["total"] == 1
    event_id = listing["items"][0]["id"]

    detail = client.get(f"/api/v1/events/{event_id}")
    assert detail.status_code == 200
    assert detail.json()["rule_slug"] == "runtime.shell_in_container"

    note = client.post(f"/api/v1/events/{event_id}/notes", json={"body": "Investigating"})
    assert note.status_code == 201
    assert client.get(f"/api/v1/events/{event_id}/notes").json()[0]["body"] == "Investigating"

    ack = client.post(f"/api/v1/events/{event_id}/acknowledge")
    assert ack.status_code == 200 and ack.json()["status"] == "ACKNOWLEDGED"
    closed = client.post(f"/api/v1/events/{event_id}/close")
    assert closed.status_code == 200 and closed.json()["status"] == "CLOSED"


def test_custom_detection_rule_is_validated_and_versioned(db: Session, client):
    bad = client.post(
        "/api/v1/events/rules",
        json={
            "slug": "custom.bad",
            "name": "Bad rule",
            "conditions": {"all": [{"field": "normalized.process", "op": "exec", "value": "x"}]},
        },
    )
    assert bad.status_code == 422

    created = client.post(
        "/api/v1/events/rules",
        json={
            "slug": "custom.tmp_writes",
            "name": "Writes to /tmp",
            "conditions": {
                "all": [
                    {"field": "normalized.file_path", "op": "startswith", "value": "/tmp/"},
                    {"field": "normalized.container.image", "op": "exists", "value": True},
                ]
            },
        },
    )
    assert created.status_code == 201
    rule_id = created.json()["id"]
    patched = client.patch(
        f"/api/v1/events/rules/{rule_id}",
        json={
            "conditions": {
                "all": [
                    {"field": "normalized.file_path", "op": "startswith", "value": "/var/tmp/"}
                ]
            }
        },
    )
    assert patched.status_code == 200
    assert patched.json()["version"] == 2


def test_builtin_rule_conditions_are_immutable(db: Session, client):
    rule = client.get("/api/v1/events/rules").json()[0]
    response = client.patch(
        f"/api/v1/events/rules/{rule['id']}",
        json={"conditions": {"all": [{"field": "normalized.process", "op": "eq", "value": "x"}]}},
    )
    assert response.status_code == 422


def test_anomaly_pass_detects_a_rate_spike(db: Session, monkeypatch):
    monkeypatch.setattr(get_settings(), "events_anomaly_min_count", 5)
    monkeypatch.setattr(get_settings(), "events_anomaly_baseline_days", 3)
    asset = Asset(
        name="api", kind="HOST", repo_url=None, external_ref="host://api-1", provider="NONE"
    )
    db.add(asset)
    db.flush()

    now = datetime.now(UTC)
    for _ in range(4):
        db.add(
            SecurityEvent(
                fingerprint=uuid.uuid4().hex,
                category="RUNTIME",
                source="GENERIC",
                event_type="process.execution",
                title="process",
                severity="LOW",
                asset_id=asset.id,
                first_seen_at=now - timedelta(days=2),
                last_seen_at=now - timedelta(days=2),
                occurrence_count=2,
            )
        )
    for _ in range(12):
        db.add(
            SecurityEvent(
                fingerprint=uuid.uuid4().hex,
                category="RUNTIME",
                source="GENERIC",
                event_type="process.execution",
                title="process",
                severity="LOW",
                asset_id=asset.id,
                first_seen_at=now - timedelta(hours=1),
                last_seen_at=now - timedelta(hours=1),
                occurrence_count=1,
            )
        )
    db.commit()

    result = anomaly.run(db)
    db.commit()
    assert result["created"] == 1
    anomaly_event = db.execute(
        select(SecurityEvent).where(SecurityEvent.event_type == "anomaly.event_rate")
    ).scalar_one()
    assert anomaly_event.normalized["status"] == "anomaly"
    assert anomaly_event.enrichment["anomaly"]["recent_count"] == 12
