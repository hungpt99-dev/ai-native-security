"""AI risk analyst.

Turns a frozen security context into a structured, evidence-cited risk opinion.
It never computes the deterministic score and never decides the final priority:
that is the policy engine's job.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.modules.ai.prompts import RISK_INSTRUCTION, RISK_PROMPT
from app.modules.ai.prompts.registry import PromptTemplate
from app.modules.ai.providers.base import AIProvider
from app.modules.ai.schemas.outputs import RiskAssessmentOutput
from app.modules.ai.schemas.provider import AIRequest, AIResult, EvidenceBlock
from app.modules.security_intelligence.schemas import SecurityContext


@dataclass
class RiskAnalysis:
    output: RiskAssessmentOutput
    result: AIResult
    prompt: PromptTemplate
    dropped_evidence: list[str] = field(default_factory=list)
    cited_evidence: list[str] = field(default_factory=list)

    def as_evidence(self) -> list[dict[str, str]]:
        return [{"key": ref.key, "note": ref.note} for ref in self.output.evidence]


def build_request(context: SecurityContext, *, max_output_tokens: int | None = None) -> AIRequest:
    instruction = (
        f"{RISK_INSTRUCTION}\n\n"
        "SECURITY CONTEXT (structured JSON; fields whose value is null are unknown):\n"
        f"{context.render_for_prompt()}"
    )
    evidence = [EvidenceBlock(**item.as_prompt_block()) for item in context.evidence]
    return RISK_PROMPT.build(
        instruction=instruction,
        evidence=evidence,
        max_output_tokens=max_output_tokens,
        metadata={"finding_id": context.finding.get("id")},
    )


def run(
    provider: AIProvider,
    context: SecurityContext,
    *,
    request: AIRequest | None = None,
    max_output_tokens: int | None = None,
) -> RiskAnalysis:
    request = request or build_request(context, max_output_tokens=max_output_tokens)
    result = provider.generate_structured(request, RiskAssessmentOutput)
    if result.structured is None:  # pragma: no cover - providers raise instead
        raise ValueError("Provider returned no structured output")
    output = RiskAssessmentOutput.model_validate(result.structured)

    provided = {item.key for item in context.evidence}
    seen: set[str] = set()
    unique_refs = []
    for ref in output.evidence:
        if ref.key in seen:
            continue
        seen.add(ref.key)
        unique_refs.append(ref)
    output = output.model_copy(update={"evidence": unique_refs})
    dropped = [ref.key for ref in output.evidence if ref.key not in provided]
    if dropped:
        output = output.model_copy(
            update={"evidence": [ref for ref in output.evidence if ref.key in provided]}
        )

    # Guardrails applied after the fact, because a model can contradict itself:
    #   * any missing information forces human review;
    #   * low confidence forces human review.
    missing = list(output.missing_information)
    force_review = bool(missing) or output.confidence < 0.5
    if force_review and not output.requires_human_review:
        output = output.model_copy(update={"requires_human_review": True})

    return RiskAnalysis(
        output=output,
        result=result,
        prompt=RISK_PROMPT,
        dropped_evidence=dropped,
        cited_evidence=[ref.key for ref in output.evidence],
    )
