"""Daily AI spend accounting and budget enforcement (fail closed)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import AIExecutionStatus
from app.modules.ai.errors import AIBudgetExceededError
from app.modules.ai.models import AIExecution

_BILLABLE_STATUSES = (
    AIExecutionStatus.SUCCEEDED.value,
    AIExecutionStatus.INVALID_OUTPUT.value,
    AIExecutionStatus.FAILED.value,
    AIExecutionStatus.TIMED_OUT.value,
)


def start_of_day() -> datetime:
    now = datetime.now(UTC)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def spend_today(db: Session) -> float:
    total = db.execute(
        select(func.coalesce(func.sum(AIExecution.cost_usd), 0)).where(
            AIExecution.created_at >= start_of_day(),
            AIExecution.status.in_(_BILLABLE_STATUSES),
        )
    ).scalar_one()
    return float(total or 0)


def usage_summary(db: Session) -> dict[str, float]:
    row = db.execute(
        select(
            func.coalesce(func.sum(AIExecution.cost_usd), 0),
            func.coalesce(func.sum(AIExecution.input_tokens), 0),
            func.coalesce(func.sum(AIExecution.output_tokens), 0),
            func.count(AIExecution.id),
        ).where(AIExecution.created_at >= start_of_day())
    ).one()
    return {
        "cost_usd_today": float(row[0] or 0),
        "input_tokens_today": int(row[1] or 0),
        "output_tokens_today": int(row[2] or 0),
        "executions_today": int(row[3] or 0),
    }


def enforce(db: Session, *, estimated_cost: float = 0.0) -> None:
    """Raise when today's spend has reached the configured budget."""
    settings = get_settings()
    budget = float(settings.ai_daily_budget_usd or 0)
    if budget <= 0:
        return
    spent = spend_today(db)
    if spent + estimated_cost >= budget:
        raise AIBudgetExceededError(
            "Daily AI budget exhausted",
            details={"spent_usd": round(spent, 6), "budget_usd": budget},
        )
