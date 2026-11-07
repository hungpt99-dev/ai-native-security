"""AI incident investigation: evidence, citations, failures, and guardrails."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.modules.ai.models import AIExecution
from app.modules.ai.providers.fake import FakeProvider
from app.modules.ai.services import incident_investigation
from app.modules.events import service as events_service
from app.modules.incidents import service as incidents_service
from app.modules.incidents.models import Incident


def _event(**fields) -> dict:
    return {
        "uuid": str(uuid.uuid4()),
        "time": datetime.now(UTC).isoformat(),
        "priority": "Critical",
        "rule": "Container escape attempt",
        "output": "escape attempt",
        "output_fields": {
            "proc.name": "nsenter",
            "proc.cmdline": "nsenter --target 1 --mount",
            "container.image.repository": "ghcr.io/acme/api",
            **fields,
        },
    }


def _incident(db: Session) -> Incident:
    events_service.ingest_falco(db, _event())
    db.commit()
    return db.execute(select(Incident)).scalar_one()


def _output(**overrides) -> dict:
    payload = {
        "status": "CONFIRMED_IMPACT",
        "confidence": 0.8,
        "summary": "A process attempted to enter the host mount namespace.",
        "likely_attack_path": "Container escape via nsenter",
        "business_impact": "Host compromise would expose all workloads on the node.",
        "attack_steps": [
            {"order": 1, "description": "nsenter executed inside the container", "evidence": ["E1", "E3"]}
        ],
        "evidence": [{"key": "E1", "note": "incident facts"}, {"key": "E3", "note": "event group"}],
        "missing_information": [],
        "containment_actions": ["Isolate the node and preserve logs"],
        "investigation_queries": ["List processes started in the container"],
        "requires_human_review": True,
    }
    payload.update(overrides)
    return payload


@pytest.fixture()
def ai_on(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "ai_enabled", True, raising=False)
    monkeypatch.setattr(settings, "ai_model", "test-model", raising=False)
    monkeypatch.setattr(settings, "ai_daily_budget_usd", 100.0, raising=False)
    return settings


def test_unconfigured_ai_persists_a_labelled_inconclusive_report(db: Session, monkeypatch):
    incident = _incident(db)
    monkeypatch.setattr(get_settings(), "ai_enabled", False, raising=False)
    row = incident_investigation.investigate(db, incident.id, provider=FakeProvider(configured=False))
    db.commit()

    assert row.status == "INCONCLUSIVE"
    assert row.error_code == "ai_unavailable"
    assert "unavailable" in row.summary.lower()
    assert row.confidence is None
    assert incident.status == "OPEN"  # never changed by the investigation
    assert db.execute(select(AIExecution)).scalar_one_or_none() is None


def test_ai_investigation_persists_cited_report_and_ledger(db: Session, ai_on):
    incident = _incident(db)
    provider = FakeProvider(responses=[_output()])
    row = incident_investigation.investigate(db, incident.id, provider=provider)
    db.commit()

    assert row.status == "CONFIRMED_IMPACT"
    assert row.summary.startswith("A process attempted")
    assert row.confidence == pytest.approx(0.8)
    assert {item["key"] for item in row.evidence} == {"E1", "E3"}
    assert row.next_actions == ["Isolate the node and preserve logs"]
    execution = db.execute(select(AIExecution)).scalar_one()
    assert execution.kind == "INCIDENT_INVESTIGATION"
    assert execution.status == "SUCCEEDED"
    assert execution.asset_id == incident.asset_id
    # the report is append-only evidence; the incident is unchanged
    assert incident.status == "OPEN"
    assert incident.severity == "CRITICAL"


def test_unknown_citations_are_dropped_and_unverifiable_reports_need_review(db: Session, ai_on):
    incident = _incident(db)
    provider = FakeProvider(
        responses=[
            _output(
                evidence=[{"key": "E99", "note": "invented"}],
                attack_steps=[{"order": 1, "description": "invented", "evidence": ["E99"]}],
            )
        ]
    )
    row = incident_investigation.investigate(db, incident.id, provider=provider)
    db.commit()
    assert row.status == "NEEDS_MANUAL_REVIEW"
    assert row.evidence == []
    assert row.attack_steps[0]["evidence"] == []
    messages = " ".join(item["message"] for item in row.missing_information)
    assert "no_valid_citations" in messages


def test_provider_failure_is_recorded_not_faked(db: Session, ai_on):
    incident = _incident(db)
    from app.modules.ai.errors import AIProviderError

    provider = FakeProvider(responses=[AIProviderError("upstream exploded")])
    row = incident_investigation.investigate(db, incident.id, provider=provider)
    db.commit()
    assert row.status == "INCONCLUSIVE"
    assert row.error_code == "ai_investigation_failed"
    assert "failed" in row.summary.lower()
    execution = db.execute(select(AIExecution)).scalar_one()
    assert execution.status == "FAILED"


def test_investigation_api_and_history(db: Session, client, ai_on, monkeypatch):
    incident = _incident(db)
    monkeypatch.setattr(
        incident_investigation, "get_provider", lambda: FakeProvider(responses=[_output()])
    )

    response = client.post(f"/api/v1/incidents/{incident.id}/investigate")
    assert response.status_code == 200
    assert response.json()["status"] == "CONFIRMED_IMPACT"

    history = client.get(f"/api/v1/incidents/{incident.id}/investigations").json()
    assert len(history) == 1
    assert history[0]["evidence"][0]["key"] == "E1"


def test_evidence_is_bounded_and_counts_are_aggregated(db: Session, ai_on):
    incident = _incident(db)
    for index in range(40):
        events_service.ingest_generic(
            db,
            [
                {
                    "event_type": f"process.execution.{index % 3}",
                    "category": "RUNTIME",
                    "severity": "LOW",
                    "normalized": {"process": f"proc{index}", "remote_ip": "203.0.113.1"},
                    "raw": {"payload": "x" * 5000},
                }
            ],
        )
    db.commit()

    from app.modules.ai.agents import incident_analyst

    data = incidents_service.details(db, incident.id)
    evidence = incident_analyst.build_evidence(
        incident=incident,
        asset=data["asset"],
        profile=None,
        events=data["events"],
        findings=data["findings"],
    )
    assert len(evidence.event_groups) <= incident_analyst.MAX_EVENT_GROUPS
    assert any("business_context_missing" in item for item in evidence.missing)
    total_chars = sum(len(block.text) for block in evidence.blocks)
    assert total_chars < get_settings().ai_max_input_chars
