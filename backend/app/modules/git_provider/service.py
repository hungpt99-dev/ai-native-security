"""Webhook ingestion: signature verification, deduplication, enqueueing.

Design constraints:

* the endpoint is authenticated by the provider's signature, not by an API key,
  so it is mounted outside the API-key router;
* a delivery is idempotent: ``UNIQUE (provider, delivery_id)`` makes a retried
  delivery a no-op;
* a webhook never runs a scan or a scanner — it enqueues a lightweight
  dependency change check and returns 202 immediately;
* repository identity is matched against a registered asset after URL
  normalisation (https, allow-listed host), so a webhook cannot address an
  arbitrary repository.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError, AuthenticationError, ValidationError
from app.core.logging import get_logger
from app.core.security import constant_time_equals
from app.core.validators import validate_repository_url
from app.modules.assets.models import Asset
from app.modules.assets.repository import get_asset_by_url
from app.modules.git_provider.client import (
    WebhookPush,
    parse_github_push,
    parse_gitlab_push,
    payload_digest,
)
from app.modules.git_provider.models import WebhookDelivery
from app.modules.sbom import lifecycle
from app.modules.sbom.dependencies import classify_paths
from app.workers.models import Job

logger = get_logger(__name__)

SUPPORTED_EVENTS = {"github": "push", "gitlab": "Push Hook"}

#: Headers that are stored for audit; signature/token headers never are.
SAFE_HEADER_KEYS = ("x-github-event", "x-gitlab-event", "user-agent", "content-type")


class WebhookDisabledError(AppError):
    status_code = 503
    code = "webhook_disabled"


@dataclass
class DeliveryResult:
    action: str
    provider: str
    delivery_id: str
    asset_id: uuid.UUID | None = None
    job_id: uuid.UUID | None = None
    reason: str | None = None


def verify_github_signature(secret: str, raw_body: bytes, signature: str | None) -> bool:
    """Verify ``X-Hub-Signature-256`` (HMAC-SHA256 over the raw body)."""
    if not signature:
        return False
    value = signature.strip()
    if value.startswith("sha256="):
        value = value[len("sha256=") :]
    expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return constant_time_equals(expected, value.lower())


def verify_gitlab_token(secret: str, token: str | None) -> bool:
    if not token:
        return False
    return constant_time_equals(secret, token.strip())


def _lower_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in headers.items()}


def ingest_delivery(
    db: Session,
    *,
    provider: str,
    headers: Mapping[str, str],
    raw_body: bytes,
) -> DeliveryResult:
    """Verify, deduplicate and enqueue one webhook delivery."""
    settings = get_settings()
    if not settings.webhook_secret:
        raise WebhookDisabledError(
            "Webhook ingestion is disabled: ANS_WEBHOOK_SECRET is not configured"
        )
    provider = provider.lower()
    if provider not in SUPPORTED_EVENTS:
        raise ValidationError("Unsupported webhook provider", details={"provider": provider})

    lowered = _lower_headers(headers)
    if provider == "github":
        if not verify_github_signature(
            settings.webhook_secret, raw_body, lowered.get("x-hub-signature-256")
        ):
            raise AuthenticationError("Invalid webhook signature")
        event = lowered.get("x-github-event", "")
        delivery_id = lowered.get("x-github-delivery") or payload_digest(raw_body)[:32]
    else:
        if not verify_gitlab_token(settings.webhook_secret, lowered.get("x-gitlab-token")):
            raise AuthenticationError("Invalid webhook token")
        event = lowered.get("x-gitlab-event", "")
        delivery_id = lowered.get("x-gitlab-event-uuid") or payload_digest(raw_body)[:32]

    existing = db.execute(
        select(WebhookDelivery).where(
            WebhookDelivery.provider == provider,
            WebhookDelivery.delivery_id == delivery_id,
        )
    ).scalar_one_or_none()
    if existing is not None:
        logger.info(
            "webhook delivery ignored (already processed)",
            extra={
                "extra_fields": {
                    "provider": provider,
                    "delivery_id": delivery_id,
                    "action": existing.action,
                }
            },
        )
        return DeliveryResult(
            action="DUPLICATE",
            provider=provider,
            delivery_id=delivery_id,
            asset_id=existing.asset_id,
            job_id=existing.job_id,
            reason="delivery already processed",
        )

    delivery = WebhookDelivery(
        provider=provider,
        delivery_id=delivery_id,
        event=event,
        action="IGNORED",
        received_at=datetime.now(UTC),
        payload_digest=payload_digest(raw_body),
        changed_paths=[],
        headers={key: lowered[key] for key in SAFE_HEADER_KEYS if key in lowered},
    )
    push: WebhookPush | None = None
    if event != SUPPORTED_EVENTS[provider]:
        delivery.reason = f"unsupported event: {event or 'unknown'}"
    else:
        try:
            payload = _parse_json(raw_body)
            push = parse_github_push(payload) if provider == "github" else parse_gitlab_push(payload)
        except ValueError:
            delivery.action = "REJECTED"
            delivery.reason = "payload is not valid JSON"
        if push is None and delivery.action != "REJECTED":
            delivery.reason = "event does not describe a branch push"

    asset: Asset | None = None
    job: Job | None = None
    if push is not None and delivery.action != "REJECTED":
        delivery.branch = push.branch
        delivery.head_commit_sha = push.after_sha
        delivery.changed_paths = push.changed_paths[: settings.sbom_max_changed_paths]
        try:
            reference = validate_repository_url(push.repo_url)
        except ValidationError as exc:
            delivery.action = "REJECTED"
            delivery.reason = exc.message
            reference = None
        if reference is not None:
            delivery.repo_url = reference.url
            asset = get_asset_by_url(db, reference.url)
            if asset is None:
                delivery.action = "UNKNOWN_REPOSITORY"
                delivery.reason = "repository is not a registered asset"
            elif push.deleted:
                delivery.reason = "branch deletion is not a composition change"
            elif push.branch != asset.default_branch:
                delivery.reason = (
                    f"push targets {push.branch}; monitoring follows {asset.default_branch}"
                )
            else:
                analysis = classify_paths(push.changed_paths)
                # Enqueue even when no dependency input changed: the check
                # records that the commit was evaluated, which is what makes
                # "composition unchanged since snapshot" provable.
                job, created = lifecycle.enqueue_check(
                    db,
                    asset,
                    trigger="WEBHOOK",
                    branch=push.branch,
                    head_sha=push.after_sha,
                    changed_paths=push.changed_paths or None,
                )
                delivery.action = "ENQUEUED"
                delivery.asset_id = asset.id
                delivery.job_id = job.id if job else None
                delivery.reason = (
                    f"{len(analysis.dependency_files)} dependency input(s) changed"
                    if analysis.dependency_files
                    else "no dependency input changed; commit still evaluated"
                )
                logger.info(
                    "webhook dependency check enqueued",
                    extra={
                        "extra_fields": {
                            "provider": provider,
                            "asset_id": str(asset.id),
                            "job_id": str(job.id) if job else None,
                            "deduplicated": not created,
                            "dependency_inputs": [entry.path for entry in analysis.dependency_files],
                        }
                    },
                )

    db.add(delivery)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return DeliveryResult(
            action="DUPLICATE",
            provider=provider,
            delivery_id=delivery_id,
            reason="delivery already processed",
        )
    return DeliveryResult(
        action=delivery.action,
        provider=provider,
        delivery_id=delivery_id,
        asset_id=delivery.asset_id,
        job_id=delivery.job_id,
        reason=delivery.reason,
    )


def _parse_json(raw_body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw_body or b"{}")
    except ValueError as exc:
        raise ValueError("invalid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    return payload


def recent_deliveries(db: Session, *, limit: int = 50) -> list[WebhookDelivery]:
    return list(
        db.execute(
            select(WebhookDelivery).order_by(WebhookDelivery.received_at.desc()).limit(limit)
        ).scalars()
    )
