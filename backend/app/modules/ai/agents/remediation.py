"""AI remediation assistant: proposals only."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.modules.ai.prompts import REMEDIATION_INSTRUCTION, REMEDIATION_PROMPT
from app.modules.ai.providers.base import AIProvider
from app.modules.ai.schemas.outputs import RemediationOutput
from app.modules.ai.schemas.provider import AIRequest, AIResult, EvidenceBlock
from app.modules.risk_analysis.models import RiskAssessment
from app.modules.security_intelligence.schemas import SecurityContext


@dataclass
class RemediationAnalysis:
    output: RemediationOutput
    result: AIResult
    dropped_evidence: list[str] = field(default_factory=list)


def build_request(
    context: SecurityContext,
    *,
    risk: RiskAssessment | None = None,
    investigation_summary: str | None = None,
    max_output_tokens: int | None = None,
) -> AIRequest:
    instruction = (
        f"{REMEDIATION_INSTRUCTION}\n\n"
        "SECURITY CONTEXT (structured JSON; null means unknown):\n"
        f"{context.render_for_prompt()}"
    )
    if risk is not None:
        instruction += (
            "\n\nPLATFORM RISK ASSESSMENT (already computed; do not recompute):\n"
            f"risk_level={risk.risk_level} final_score={risk.final_score} "
            f"deterministic_score={risk.deterministic_score} ai_risk_score={risk.ai_risk_score}\n"
            f"summary={risk.summary or ''}"
        )
    if investigation_summary:
        instruction += f"\n\nPRIOR INVESTIGATION SUMMARY:\n{investigation_summary[:1200]}"

    evidence = [EvidenceBlock(**item.as_prompt_block()) for item in context.evidence]
    return REMEDIATION_PROMPT.build(
        instruction=instruction,
        evidence=evidence,
        max_output_tokens=max_output_tokens,
        metadata={"finding_id": context.finding.get("id")},
    )


def run(
    provider: AIProvider,
    context: SecurityContext,
    *,
    risk: RiskAssessment | None = None,
    investigation_summary: str | None = None,
    request: AIRequest | None = None,
    max_output_tokens: int | None = None,
) -> RemediationAnalysis:
    request = request or build_request(
        context,
        risk=risk,
        investigation_summary=investigation_summary,
        max_output_tokens=max_output_tokens,
    )
    result = provider.generate_structured(request, RemediationOutput)
    if result.structured is None:  # pragma: no cover
        raise ValueError("Provider returned no structured output")
    output = RemediationOutput.model_validate(result.structured)
    # RemediationOutput deliberately carries no citation list: the actionable
    # claim (a version) is validated against authoritative data instead.
    return RemediationAnalysis(output=output, result=result, dropped_evidence=[])
