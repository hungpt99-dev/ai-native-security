"""Inbound repository webhook endpoints.

Mounted **outside** the API-key router on purpose: authenticity comes from the
provider signature (GitHub HMAC-SHA256, GitLab shared token), not from a shared
API key that a provider cannot send. Every request is verified, deduplicated and
answered with 202; no repository work happens inside the request.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.core.errors import ValidationError
from app.database.session import get_db
from app.modules.git_provider.service import ingest_delivery

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

#: Provider payloads are large (commits + diffs). Anything bigger is rejected
#: before it is parsed.
MAX_WEBHOOK_BYTES = 5 * 1024 * 1024


async def _handle(
    request: Request, db: Session, provider: str
) -> dict[str, Any]:
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > MAX_WEBHOOK_BYTES:
        raise ValidationError("Webhook payload is too large")
    body = await request.body()
    if len(body) > MAX_WEBHOOK_BYTES:
        raise ValidationError("Webhook payload is too large")
    if not body:
        raise ValidationError("Webhook payload is empty")
    result = ingest_delivery(db, provider=provider, headers=request.headers, raw_body=body)
    return {
        "status": result.action,
        "provider": result.provider,
        "delivery_id": result.delivery_id,
        "reason": result.reason,
        "asset_id": str(result.asset_id) if result.asset_id else None,
        "job_id": str(result.job_id) if result.job_id else None,
    }


@router.post("/github", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    """GitHub ``push`` events. Signed with ``X-Hub-Signature-256``."""
    return await _handle(request, db, "github")


@router.post("/gitlab", status_code=status.HTTP_202_ACCEPTED)
async def gitlab_webhook(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, Any]:
    """GitLab ``Push Hook`` events. Verified with ``X-Gitlab-Token``."""
    return await _handle(request, db, "gitlab")


@router.get("/health")
def webhook_health() -> dict[str, str]:
    """Cheap probe that does not reveal whether the secret is configured."""
    return {"status": "ok"}

