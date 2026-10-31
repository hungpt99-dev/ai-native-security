"""Risk policy maths: bands, AI/deterministic blend, confidence.

Kept separate from both the signals and the model so the combination rule is one
small, testable function — and so a reviewer can see exactly how a final priority
was produced.
"""

from __future__ import annotations

from typing import Any

from app.core.enums import RiskLevel


def band_for(score: int, bands: dict[str, Any]) -> str:
    if score >= int(bands.get("critical", 85)):
        return RiskLevel.CRITICAL.value
    if score >= int(bands.get("high", 70)):
        return RiskLevel.HIGH.value
    if score >= int(bands.get("medium", 50)):
        return RiskLevel.MEDIUM.value
    if score >= int(bands.get("low", 25)):
        return RiskLevel.LOW.value
    return RiskLevel.INFO.value


def combine(
    *,
    deterministic_score: int,
    ai_score: int | None,
    ai_level: str | None,
    ai_confidence: float | None,
    coverage: float,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Blend deterministic and AI judgement into the final priority.

    * No AI score ⇒ the final score *is* the deterministic score, flagged
      ``deterministic_only``. An AI failure never silently becomes an AI result.
    * With AI: ``final = det * w_det + ai * w_ai`` (weights from the policy).
    * ``final`` risk level comes from the bands, never from the model's label.
      The model's own label is kept alongside for comparison.
    """
    bands = policy.get("bands") or {}
    blend = policy.get("ai_blend") or {}
    confidence_policy = policy.get("confidence") or {}
    w_det = float(blend.get("deterministic", 0.65))
    w_ai = float(blend.get("ai", 0.35))
    total = (w_det + w_ai) or 1.0

    deterministic_only = ai_score is None
    if deterministic_only:
        final_score = int(deterministic_score)
        confidence = round(min(1.0, coverage * 0.85), 2)
    else:
        assert ai_score is not None  # guaranteed by deterministic_only above
        final_score = int(round((deterministic_score * w_det + float(ai_score) * w_ai) / total))
        ai_weight = float(confidence_policy.get("ai_weight", 0.6))
        coverage_weight = float(confidence_policy.get("coverage_weight", 0.4))
        bonus = float(confidence_policy.get("coverage_bonus", 0.25))
        confidence = round(
            min(
                (float(ai_confidence or 0) * ai_weight + coverage * coverage_weight),
                coverage + bonus,
                1.0,
            ),
            2,
        )

    final_score = max(0, min(100, final_score))
    risk_level = band_for(final_score, bands)
    review_below = float(confidence_policy.get("review_below", 0.55))
    requires_review = deterministic_only or confidence < review_below or ai_level != risk_level

    return {
        "final_score": final_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "deterministic_only": deterministic_only,
        "requires_human_review": requires_review,
        "blend": {"deterministic": w_det, "ai": w_ai},
    }


def priority_rank(risk_level: str) -> int:
    order = {
        RiskLevel.CRITICAL.value: 0,
        RiskLevel.HIGH.value: 1,
        RiskLevel.MEDIUM.value: 2,
        RiskLevel.LOW.value: 3,
        RiskLevel.INFO.value: 4,
        RiskLevel.UNKNOWN.value: 5,
    }
    return order.get(risk_level, 5)
