"""API surface for SBOM lifecycle: status, actions, history, diff, webhooks."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import JobKind
from app.modules.sbom import lifecycle, service
from app.workers.models import Job
from tests.integration.helpers import IntelSpec, add_vulnerability, affected_range, document, package

SECRET = "webhook-test-secret"


def _snapshot(
    db: Session, asset_id, packages, *, commit="a" * 40, reason="FULL_SCAN", previous=None
):
    snapshot = service.store_sbom(
        db,
        asset_id=asset_id,
        scan_id=None,
        document=document(packages),
        commit_sha=commit,
        branch="main",
        creation_reason=reason,
        previous_snapshot_id=previous.id if previous else None,
    )
    db.commit()
    return snapshot


def _signed(body: bytes, secret: str = SECRET) -> dict[str, str]:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-GitHub-Event": "push",
        "X-GitHub-Delivery": "delivery-" + uuid.uuid4().hex[:8],
        "X-Hub-Signature-256": f"sha256={digest}",
    }


def _push_payload(repo_url: str, *, branch: str = "main", files=("package.json",)) -> bytes:
    return json.dumps(
        {
            "ref": f"refs/heads/{branch}",
            "before": "b" * 40,
            "after": "c" * 40,
            "deleted": False,
            "repository": {"clone_url": repo_url, "html_url": repo_url},
            "commits": [
                {
                    "id": "c" * 40,
                    "added": [],
                    "modified": list(files),
                    "removed": [],
                }
            ],
        }
    ).encode()


# ------------------------------------------------------------------- endpoints
def test_status_endpoint_reports_snapshot_and_monitoring(
    client: TestClient, db: Session, asset_factory
) -> None:
    asset = asset_factory()
    snapshot = _snapshot(db, asset.id, [package("requests", "2.31.0")])

    response = client.get(f"/api/v1/assets/{asset.id}/sbom/status")

    assert response.status_code == 200
    body = response.json()
    assert body["latest_snapshot"]["id"] == str(snapshot.id)
    assert body["latest_snapshot"]["commit_sha"] == "a" * 40
    assert body["latest_snapshot"]["dependency_fingerprint"]
    assert body["freshness"] in {"UNKNOWN", "CURRENT", "MISSING", "STALE", "PENDING", "FAILED"}
    assert body["monitoring_status"] == "UNKNOWN"
    assert body["vulnerable_components"] == 0
    assert set(body["pending"]) == {
        "dependency_check",
        "sbom_generation",
        "reassessment",
        "dependency_change_pending",
    }
    assert body["last_dependency_check"] is None
    assert body["next_reassessment"] is None


def test_status_endpoint_404_for_unknown_asset(client: TestClient) -> None:
    response = client.get(f"/api/v1/assets/{uuid.uuid4()}/sbom/status")
    assert response.status_code == 404


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("check", "SBOM_CHANGE_CHECK"),
        ("generate", "SBOM_GENERATE"),
        ("reassess", "SBOM_VULNERABILITY_REASSESSMENT"),
    ],
)
def test_manual_actions_enqueue_jobs_once(
    client: TestClient, db: Session, asset_factory, path: str, kind: str
) -> None:
    asset = asset_factory()
    _snapshot(db, asset.id, [package("requests", "2.31.0")])

    first = client.post(f"/api/v1/assets/{asset.id}/sbom/{path}")
    second = client.post(f"/api/v1/assets/{asset.id}/sbom/{path}")

    assert first.status_code == 202
    assert first.json()["kind"] == kind
    assert first.json()["job_id"] is not None
    assert second.status_code == 202
    assert second.json()["deduplicated"] is True
    assert second.json()["job_id"] == first.json()["job_id"]
    jobs = db.execute(select(Job).where(Job.kind == kind)).scalars().all()
    assert len(jobs) == 1


def test_reassess_rejects_a_snapshot_from_another_asset(
    client: TestClient, db: Session, asset_factory
) -> None:
    owner = asset_factory()
    other = asset_factory()
    snapshot = _snapshot(db, owner.id, [package("requests", "2.31.0")])

    response = client.post(
        f"/api/v1/assets/{other.id}/sbom/reassess", params={"sbom_id": str(snapshot.id)}
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_monitoring_runs_are_listed_and_filterable(
    client: TestClient, db: Session, asset_factory
) -> None:
    asset = asset_factory()
    run = lifecycle.start_run(
        db, asset_id=asset.id, kind="DEPENDENCY_CHECK", trigger="MANUAL"
    )
    lifecycle.finish_run(
        db, run, status="SUCCEEDED", outcome="UNCHANGED", metrics={"head_source": "test"}
    )

    listing = client.get(f"/api/v1/assets/{asset.id}/sbom/monitoring-runs")
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 1
    assert body["items"][0]["kind"] == "DEPENDENCY_CHECK"
    assert body["items"][0]["outcome"] == "UNCHANGED"
    assert body["items"][0]["metrics"] == {"head_source": "test"}

    filtered = client.get(
        f"/api/v1/assets/{asset.id}/sbom/monitoring-runs",
        params={"kind": "VULNERABILITY_REASSESSMENT"},
    ).json()
    assert filtered["total"] == 0

    by_status = client.get(
        f"/api/v1/assets/{asset.id}/sbom/monitoring-runs", params={"status": "FAILED"}
    ).json()
    assert by_status["total"] == 0


def test_diff_endpoint_reports_counts_and_details(
    client: TestClient, db: Session, asset_factory
) -> None:
    asset = asset_factory()
    previous = _snapshot(
        db,
        asset.id,
        [
            package("requests", "2.31.0"),
            package("urllib3", "1.26.0", ecosystem="PyPI"),
            package("flask", "3.0.0"),
        ],
        commit="a" * 40,
    )
    current = _snapshot(
        db,
        asset.id,
        [
            package("requests", "2.32.0"),
            package("flask", "3.0.0"),
            package("httpx", "0.27.0"),
        ],
        commit="b" * 40,
        reason="DEPENDENCY_CHANGE",
        previous=previous,
    )

    response = client.get(f"/api/v1/sboms/{current.id}/diff")

    assert response.status_code == 200
    body = response.json()
    assert body["previous_sbom_id"] == str(previous.id)
    assert body["current_sbom_id"] == str(current.id)
    assert (body["added"], body["removed"], body["version_changed"], body["unchanged"]) == (
        1,
        1,
        1,
        1,
    )
    kinds = {item["change"] for item in body["items"]}
    assert kinds == {"ADDED", "REMOVED", "VERSION_CHANGED"}
    assert body["total"] == 3

    unchanged = client.get(
        f"/api/v1/sboms/{current.id}/diff", params={"change": "UNCHANGED"}
    ).json()
    assert unchanged["total"] == 1
    assert unchanged["items"][0]["name"] == "flask"

    explicit = client.get(
        f"/api/v1/sboms/{current.id}/diff", params={"against": str(previous.id), "page_size": 2}
    ).json()
    assert len(explicit["items"]) == 2
    assert explicit["pages"] == 2


def test_diff_without_recorded_lineage_does_not_guess(
    client: TestClient, db: Session, asset_factory
) -> None:
    asset = asset_factory()
    _snapshot(db, asset.id, [package("requests", "2.31.0")], commit="a" * 40)
    current = _snapshot(db, asset.id, [package("requests", "2.32.0")], commit="b" * 40)

    body = client.get(f"/api/v1/sboms/{current.id}/diff").json()

    # Pre-existing snapshots have no lineage and identical row timestamps:
    # reporting "everything added" is correct, guessing a predecessor is not.
    assert body["previous_sbom_id"] is None
    assert body["added"] == 1
    assert body["version_changed"] == 0


def test_diff_rejects_snapshots_from_different_assets(
    client: TestClient, db: Session, asset_factory
) -> None:
    first = _snapshot(db, asset_factory().id, [package("requests", "2.31.0")])
    second = _snapshot(db, asset_factory().id, [package("requests", "2.32.0")])

    response = client.get(f"/api/v1/sboms/{second.id}/diff", params={"against": str(first.id)})
    assert response.status_code == 422


def test_diff_unknown_snapshot_is_404(client: TestClient) -> None:
    assert client.get(f"/api/v1/sboms/{uuid.uuid4()}/diff").status_code == 404


def test_summary_endpoint_exposes_measured_counters(
    client: TestClient, db: Session, asset_factory
) -> None:
    asset = asset_factory()
    run = lifecycle.start_run(
        db, asset_id=asset.id, kind="VULNERABILITY_REASSESSMENT", trigger="SCHEDULED"
    )
    lifecycle.finish_run(
        db,
        run,
        status="SUCCEEDED",
        components_evaluated=42,
        findings_created=2,
        findings_updated=1,
    )

    body = client.get("/api/v1/sbom/monitoring/summary").json()

    assert body["reassessments"] == 1
    assert body["components_evaluated"] == 42
    assert body["findings_created"] == 2
    assert body["estimate_basis"]
    assert "estimated_full_scans_avoided" in body


def test_existing_sbom_endpoints_gained_provenance_without_breaking(
    client: TestClient, db: Session, asset_factory
) -> None:
    asset = asset_factory()
    snapshot = _snapshot(db, asset.id, [package("requests", "2.31.0")])

    detail = client.get(f"/api/v1/sboms/{snapshot.id}").json()
    assert detail["commit_sha"] == "a" * 40
    assert detail["creation_reason"] == "FULL_SCAN"
    assert detail["generation_status"] == "READY"
    assert detail["generated_at"]

    listing = client.get(f"/api/v1/assets/{asset.id}/sboms").json()
    assert listing["total"] == 1
    assert listing["items"][0]["dependency_fingerprint"] == snapshot.dependency_fingerprint

    packages = client.get(f"/api/v1/sboms/{snapshot.id}/packages").json()
    assert packages["total"] == 1


def test_findings_expose_and_filter_discovery_source(
    client: TestClient, db: Session, asset_factory
) -> None:
    from app.modules.findings import service as findings_service
    from app.modules.scanners.base import NormalizedFinding

    asset = asset_factory()
    findings_service.record_findings(
        db,
        asset_id=asset.id,
        scan_id=None,
        normalized=[
            NormalizedFinding(
                scanner="trivy",
                rule_id="RULE-1",
                title="From a scan",
                category="misconfiguration",
                severity="HIGH",
                file_path="Dockerfile",
                line_number=3,
            ),
            NormalizedFinding(
                scanner="osv",
                rule_id="GHSA-prov-0001",
                title="From stored inventory",
                category="vulnerability",
                severity="HIGH",
                package_name="requests",
                package_version="2.31.0",
                cve_id="CVE-2026-5000",
            ),
        ],
        discovery_source="FULL_SCAN",
    )
    findings_service.record_findings(
        db,
        asset_id=asset.id,
        scan_id=None,
        normalized=[
            NormalizedFinding(
                scanner="osv",
                rule_id="GHSA-prov-0002",
                title="From stored inventory only",
                category="vulnerability",
                severity="MEDIUM",
                package_name="flask",
                package_version="2.0.0",
                cve_id="CVE-2026-5001",
            ),
        ],
        discovery_source="SBOM_REASSESSMENT",
    )
    db.commit()

    everything = client.get("/api/v1/findings").json()
    assert everything["total"] == 3
    assert {item["discovery_source"] for item in everything["items"]} == {
        "FULL_SCAN",
        "SBOM_REASSESSMENT",
    }

    stored = client.get(
        "/api/v1/findings", params={"discovery_source": "SBOM_REASSESSMENT"}
    ).json()
    assert stored["total"] == 1
    assert stored["items"][0]["title"] == "From stored inventory only"
    assert stored["items"][0]["discovery_source"] == "SBOM_REASSESSMENT"


# -------------------------------------------------------------------- webhooks
def test_github_webhook_enqueues_a_lightweight_check(
    client: TestClient, db: Session, asset_factory, settings
) -> None:
    settings.webhook_secret = SECRET
    asset = asset_factory(repo_url="https://github.com/acme/widgets")
    _snapshot(db, asset.id, [package("requests", "2.31.0")])

    body = _push_payload(asset.repo_url)
    response = client.post("/api/v1/webhooks/github", content=body, headers=_signed(body))

    assert response.status_code == 202
    assert response.json()["status"] == "ENQUEUED"
    jobs = db.execute(select(Job).where(Job.kind == JobKind.SBOM_CHANGE_CHECK.value)).scalars().all()
    assert len(jobs) == 1
    assert jobs[0].payload["head_sha"] == "c" * 40
    assert jobs[0].payload["changed_paths"] == ["package.json"]
    assert jobs[0].payload["trigger"] == "WEBHOOK"
    # No scan was enqueued by the webhook.
    assert db.execute(select(Job).where(Job.kind == JobKind.SCAN.value)).scalar_one_or_none() is None


def test_github_webhook_is_idempotent_per_delivery(
    client: TestClient, db: Session, asset_factory, settings
) -> None:
    settings.webhook_secret = SECRET
    asset = asset_factory(repo_url="https://github.com/acme/idempotent")
    body = _push_payload(asset.repo_url)
    headers = _signed(body)

    first = client.post("/api/v1/webhooks/github", content=body, headers=headers)
    second = client.post("/api/v1/webhooks/github", content=body, headers=headers)

    assert first.json()["status"] == "ENQUEUED"
    assert second.status_code == 202
    assert second.json()["status"] == "DUPLICATE"
    jobs = db.execute(select(Job).where(Job.kind == JobKind.SBOM_CHANGE_CHECK.value)).scalars().all()
    assert len(jobs) == 1


def test_github_webhook_rejects_a_bad_signature(
    client: TestClient, db: Session, asset_factory, settings
) -> None:
    settings.webhook_secret = SECRET
    asset = asset_factory(repo_url="https://github.com/acme/bad-sig")
    body = _push_payload(asset.repo_url)
    headers = _signed(body, secret="wrong")

    response = client.post("/api/v1/webhooks/github", content=body, headers=headers)

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"
    assert db.execute(select(Job)).scalar_one_or_none() is None


def test_webhook_for_unknown_repository_is_ignored(
    client: TestClient, db: Session, settings
) -> None:
    settings.webhook_secret = SECRET
    body = _push_payload("https://github.com/acme/not-registered")

    response = client.post("/api/v1/webhooks/github", content=body, headers=_signed(body))

    assert response.status_code == 202
    assert response.json()["status"] == "UNKNOWN_REPOSITORY"
    assert response.json()["job_id"] is None


def test_webhook_ignores_non_push_events(
    client: TestClient, db: Session, asset_factory, settings
) -> None:
    settings.webhook_secret = SECRET
    asset_factory(repo_url="https://github.com/acme/ping")
    body = json.dumps({"zen": "Design for failure."}).encode()
    headers = {**_signed(body), "X-GitHub-Event": "ping"}

    response = client.post("/api/v1/webhooks/github", content=body, headers=headers)

    assert response.status_code == 202
    assert response.json()["status"] == "IGNORED"
    assert response.json()["reason"].startswith("unsupported event")


def test_webhook_is_disabled_without_a_secret(
    client: TestClient, asset_factory, settings
) -> None:
    settings.webhook_secret = None
    body = _push_payload("https://github.com/acme/anything")

    response = client.post("/api/v1/webhooks/github", content=body, headers=_signed(body))

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "webhook_disabled"


def test_gitlab_webhook_requires_the_shared_token(
    client: TestClient, db: Session, asset_factory, settings
) -> None:
    settings.webhook_secret = SECRET
    asset = asset_factory(repo_url="https://gitlab.com/acme/gitlab-widget")
    payload = {
        "ref": "refs/heads/main",
        "before": "b" * 40,
        "after": "d" * 40,
        "project": {"git_http_url": asset.repo_url},
        "commits": [{"id": "d" * 40, "added": ["pnpm-lock.yaml"], "modified": [], "removed": []}],
    }
    body = json.dumps(payload).encode()

    rejected = client.post(
        "/api/v1/webhooks/gitlab",
        content=body,
        headers={"X-Gitlab-Token": "nope", "X-Gitlab-Event": "Push Hook"},
    )
    assert rejected.status_code == 401

    accepted = client.post(
        "/api/v1/webhooks/gitlab",
        content=body,
        headers={
            "X-Gitlab-Token": SECRET,
            "X-Gitlab-Event": "Push Hook",
            "X-Gitlab-Event-UUID": "gitlab-" + uuid.uuid4().hex[:8],
        },
    )
    assert accepted.status_code == 202
    assert accepted.json()["status"] == "ENQUEUED"
    jobs = db.execute(select(Job).where(Job.kind == JobKind.SBOM_CHANGE_CHECK.value)).scalars().all()
    assert jobs[0].payload["changed_paths"] == ["pnpm-lock.yaml"]


def test_webhook_ignores_a_push_to_a_non_monitored_branch(
    client: TestClient, db: Session, asset_factory, settings
) -> None:
    settings.webhook_secret = SECRET
    asset = asset_factory(repo_url="https://github.com/acme/branchy", default_branch="main")
    body = _push_payload(asset.repo_url, branch="feature/x")

    response = client.post("/api/v1/webhooks/github", content=body, headers=_signed(body))

    assert response.status_code == 202
    assert response.json()["status"] == "IGNORED"
    assert "feature/x" in response.json()["reason"]
    assert db.execute(select(Job)).scalar_one_or_none() is None


def test_reassessment_job_is_not_a_scan_job(
    client: TestClient, db: Session, asset_factory
) -> None:
    asset = asset_factory()
    _snapshot(db, asset.id, [package("requests", "2.31.0")])
    add_vulnerability(
        db,
        IntelSpec(
            osv_id="GHSA-api-0001",
            cve_id="CVE-2026-2000",
            package_name="requests",
            ranges=affected_range("0", "2.32.0"),
        ),
    )
    db.commit()

    response = client.post(f"/api/v1/assets/{asset.id}/sbom/reassess")
    job = db.get(Job, uuid.UUID(response.json()["job_id"]))
    assert job is not None
    assert job.kind == JobKind.SBOM_VULNERABILITY_REASSESSMENT.value
    assert all(
        entry.kind != JobKind.SCAN.value
        for entry in db.execute(select(Job)).scalars().all()
    )
