"""Structured model outputs.

These are the contracts the model must satisfy. They intentionally cannot express
"this is safe": the strongest negative statement available is
``NO_EVIDENCE_FOUND``/``INCONCLUSIVE``, and ``requires_human_review`` defaults to
true.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

RiskLevelLiteral = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
InvestigationStatusLiteral = Literal[
    "CONFIRMED_IMPACT",
    "POTENTIAL_IMPACT",
    "NO_EVIDENCE_FOUND",
    "INCONCLUSIVE",
    "NEEDS_MANUAL_REVIEW",
]
RemediationStrategyLiteral = Literal[
    "DEPENDENCY_UPGRADE",
    "CONFIGURATION_CHANGE",
    "CODE_FIX",
    "COMPONENT_REMOVAL",
    "MITIGATION",
    "NO_ACTION_AVAILABLE",
]


class EvidenceRef(BaseModel):
    """A citation of evidence the platform supplied, by its key (``E1``)."""

    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=16)
    note: str = Field(default="", max_length=600)


class RiskAssessmentOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_level: RiskLevelLiteral
    risk_score: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    summary: str = Field(min_length=1, max_length=1200)
    impact_analysis: str = Field(default="", max_length=2000)
    exploitability_analysis: str = Field(default="", max_length=2000)
    affected_components: list[str] = Field(default_factory=list, max_length=20)
    evidence: list[EvidenceRef] = Field(default_factory=list, max_length=20)
    missing_information: list[str] = Field(default_factory=list, max_length=20)
    recommended_actions: list[str] = Field(default_factory=list, max_length=10)
    requires_human_review: bool = True


class InvestigationAnswers(BaseModel):
    model_config = ConfigDict(extra="forbid")

    what_is_vulnerable: str = Field(default="unknown", max_length=1200)
    dependency_entry_point: str = Field(default="unknown", max_length=1200)
    functionality_used: str = Field(default="unknown", max_length=1200)
    externally_reachable: str = Field(default="unknown", max_length=1200)
    potential_impact: str = Field(default="unknown", max_length=2000)


class InvestigationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: InvestigationStatusLiteral
    confidence: float = Field(ge=0, le=1)
    summary: str = Field(min_length=1, max_length=1600)
    answers: InvestigationAnswers
    impact_analysis: str = Field(default="", max_length=2000)
    exploitability_analysis: str = Field(default="", max_length=2000)
    evidence: list[EvidenceRef] = Field(default_factory=list, max_length=25)
    missing_information: list[str] = Field(default_factory=list, max_length=20)
    next_steps: list[str] = Field(default_factory=list, max_length=10)


class ProposedChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file: str = Field(default="", max_length=1000)
    description: str = Field(default="", max_length=1200)


class RemediationOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    strategy: RemediationStrategyLiteral
    summary: str = Field(min_length=1, max_length=1200)
    reasoning: str = Field(default="", max_length=2000)
    target_package: str | None = Field(default=None, max_length=255)
    current_version: str | None = Field(default=None, max_length=128)
    recommended_version: str | None = Field(default=None, max_length=128)
    changes: list[ProposedChange] = Field(default_factory=list, max_length=20)
    patch: str | None = Field(default=None, max_length=12000)
    breaking_change_risks: list[str] = Field(default_factory=list, max_length=15)
    recommended_tests: list[str] = Field(default_factory=list, max_length=15)
    expected_security_improvement: str | None = Field(default=None, max_length=1200)
    missing_information: list[str] = Field(default_factory=list, max_length=20)
    requires_human_approval: bool = True


class AssistantOutput(BaseModel):
    """The assistant answers in prose but must cite retrieved rows.

    ``answer`` accepts the synonyms models actually emit (``summary``, ``reply``,
    …) so a well-formed answer is not discarded over a key name. Unknown extra
    keys are tolerated and ignored: the prose is the model's output either way,
    and citations are validated separately.
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    answer: str = Field(
        min_length=1,
        max_length=8000,
        validation_alias=AliasChoices("answer", "reply", "response", "summary", "text"),
    )
    cited_finding_ids: list[str] = Field(default_factory=list, max_length=50)
    cited_asset_ids: list[str] = Field(default_factory=list, max_length=50)
    data_gaps: list[str] = Field(default_factory=list, max_length=10)


class ToolCall(BaseModel):
    """A request from the model to read data through a registered tool.

    ``name`` is the field every OpenAI-style tool call uses; ``tool`` is accepted
    as an alias so either convention validates.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    name: str = Field(
        min_length=1,
        max_length=64,
        validation_alias=AliasChoices("name", "tool", "tool_name"),
    )
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("arguments", "args", "params", "input"),
    )
    rationale: str = Field(default="", max_length=300)


class AssistantPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_calls: list[ToolCall] = Field(default_factory=list, max_length=6)
    reasoning: str = Field(default="", max_length=600)


class PlannedCalls(BaseModel):
    """Lenient envelope for the planning step.

    Different models wrap the call list differently (``tool_calls``, ``calls``,
    ``steps``, or a bare array). Validation must not fail on the container name:
    the service normalises whatever arrives and then validates each call against
    ``ToolCall``. Unknown extra keys are allowed here and ignored downstream.
    """

    model_config = ConfigDict(extra="allow")

    tool_calls: list[dict[str, Any]] | None = None
    reasoning: str | None = None
