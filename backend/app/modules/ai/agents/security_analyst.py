"""AI security analyst: evidence-bounded investigation of one finding."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.modules.ai.prompts import INVESTIGATION_INSTRUCTION, INVESTIGATION_PROMPT
from app.modules.ai.providers.base import AIProvider
from app.modules.ai.schemas.outputs import InvestigationOutput
from app.modules.ai.schemas.provider import AIRequest, AIResult, EvidenceBlock
from app.modules.risk_analysis.signals import SignalSet
from app.modules.security_intelligence.schemas import SecurityContext


@dataclass
class InvestigationAnalysis:
    output: InvestigationOutput
    result: AIResult
    dropped_evidence: list[str] = field(default_factory=list)

    @property
    def cited_keys(self) -> list[str]:
        return [reference.key for reference in self.output.evidence]


def build_request(
    context: SecurityContext,
    signals: SignalSet | None = None,
    *,
    max_output_tokens: int | None = None,
) -> AIRequest:
    instruction = (
        f"{INVESTIGATION_INSTRUCTION}\n\n"
        "SECURITY CONTEXT (structured JSON; null means unknown, never negative evidence):\n"
        f"{context.render_for_prompt()}"
    )
    if signals is not None:
        instruction += (
            f"\n\nDETERMINISTIC SIGNALS (computed by the platform, not by you):\n{signals.as_dict()}"
        )
    evidence = [EvidenceBlock(**item.as_prompt_block()) for item in context.evidence]
    return INVESTIGATION_PROMPT.build(
        instruction=instruction,
        evidence=evidence,
        max_output_tokens=max_output_tokens,
        metadata={"finding_id": context.finding.get("id")},
    )


def run(
    provider: AIProvider,
    context: SecurityContext,
    signals: SignalSet | None = None,
    *,
    request: AIRequest | None = None,
    max_output_tokens: int | None = None,
) -> InvestigationAnalysis:
    request = request or build_request(context, signals, max_output_tokens=max_output_tokens)
    result = provider.generate_structured(request, InvestigationOutput)
    if result.structured is None:  # pragma: no cover
        raise ValueError("Provider returned no structured output")
    output = InvestigationOutput.model_validate(result.structured)

    provided = {item.key for item in context.evidence}
    seen: set[str] = set()
    unique_refs = []
    for reference in output.evidence:
        if reference.key in seen:
            continue
        seen.add(reference.key)
        unique_refs.append(reference)
    output = output.model_copy(update={"evidence": unique_refs})
    dropped = [reference.key for reference in output.evidence if reference.key not in provided]
    if dropped:
        output = output.model_copy(
            update={"evidence": [ref for ref in output.evidence if ref.key in provided]}
        )

    # A report that claims impact without a single citation is treated as
    # unsupported: it keeps its prose but is downgraded to manual review.
    if output.status in {"CONFIRMED_IMPACT", "POTENTIAL_IMPACT"} and not output.evidence:
        output = output.model_copy(
            update={
                "status": "NEEDS_MANUAL_REVIEW",
                "requires_human_review": True,
            }
        )
    if output.confidence < 0.4 and output.status in {"CONFIRMED_IMPACT"}:
        output = output.model_copy(update={"status": "NEEDS_MANUAL_REVIEW"})

    return InvestigationAnalysis(output=output, result=result, dropped_evidence=dropped)
