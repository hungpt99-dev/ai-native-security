"""Security assistant: plan -> read-only tools -> grounded answer.

Two model calls per question:

1. **plan** — the model chooses tools from a fixed catalogue (no execution power),
2. **answer** — the model answers using only the rows returned by those tools.

Every step is recorded: the plan, the tool calls, the rows, the execution ids and
the final citations, so an answer can be audited after the fact.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import AIExecutionKind
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.modules.ai.prompts import ASSISTANT_INSTRUCTION, ASSISTANT_PROMPT
from app.modules.ai.prompts.assistant import ASSISTANT_PLAN_PROMPT
from app.modules.ai.providers.base import AIProvider
from app.modules.ai.providers.registry import get_provider
from app.modules.ai.schemas.outputs import AssistantOutput, AssistantPlan, PlannedCalls, ToolCall
from app.modules.ai.schemas.provider import AIRequest, EvidenceBlock
from app.modules.ai.services import budgets, tools
from app.modules.ai.services.executions import record_result, track_execution
from app.modules.knowledge_base.models import AssistantConversation, AssistantMessage

logger = get_logger(__name__)

MAX_TOOL_RESULT_CHARS = 6000


@dataclass
class AssistantReply:
    conversation_id: uuid.UUID
    answer: str
    tool_results: list[dict[str, Any]] = field(default_factory=list)
    cited_finding_ids: list[str] = field(default_factory=list)
    cited_asset_ids: list[str] = field(default_factory=list)
    data_gaps: list[str] = field(default_factory=list)
    executions: list[str] = field(default_factory=list)
    model: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "conversation_id": str(self.conversation_id),
            "answer": self.answer,
            "tool_results": self.tool_results,
            "cited_finding_ids": self.cited_finding_ids,
            "cited_asset_ids": self.cited_asset_ids,
            "data_gaps": self.data_gaps,
            "executions": self.executions,
            "model": self.model,
        }


def get_conversation(db: Session, conversation_id: uuid.UUID) -> AssistantConversation:
    conversation = db.get(AssistantConversation, conversation_id)
    if conversation is None:
        raise NotFoundError("Conversation not found", details={"conversation_id": str(conversation_id)})
    return conversation


def history(db: Session, conversation_id: uuid.UUID, limit: int = 50) -> list[AssistantMessage]:
    from sqlalchemy import select

    return list(
        db.execute(
            select(AssistantMessage)
            .where(AssistantMessage.conversation_id == conversation_id)
            .order_by(AssistantMessage.created_at.asc())
            .limit(limit)
        ).scalars()
    )


def _plan_request(question: str, max_tools: int) -> AIRequest:
    catalogue = json.dumps(tools.tool_catalog(), indent=2, sort_keys=True)
    instruction = (
        f"Registered tools (JSON Schema):\n{catalogue}\n\n"
        f"Select at most {max_tools} tool calls to answer this question:\n{question}"
    )
    return ASSISTANT_PLAN_PROMPT.build(instruction=instruction, max_output_tokens=700)


def _answer_request(question: str, results: list[tools.ToolResult]) -> AIRequest:
    evidence = [
        EvidenceBlock(
            key=f"T{index}",
            source=f"tool:{result.name}",
            locator=None,
            text=json.dumps(result.as_dict(), sort_keys=True, default=str)[:MAX_TOOL_RESULT_CHARS],
        )
        for index, result in enumerate(results, start=1)
    ]
    instruction = (
        f"{ASSISTANT_INSTRUCTION}\n\nUSER QUESTION:\n{question}\n\n"
        "The retrieved rows are in the evidence blocks. If they do not answer the "
        "question, say what is missing in data_gaps."
    )
    return ASSISTANT_PROMPT.build(instruction=instruction, evidence=evidence, max_output_tokens=1200)


_CALL_KEYS = ("tool_calls", "calls", "tools", "steps", "plan", "actions")


def _normalise_plan(payload: Any) -> AssistantPlan:
    """Accept the container shapes models actually emit for a tool plan."""
    items: list[Any] = []
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        for key in _CALL_KEYS:
            value = payload.get(key)
            if isinstance(value, list):
                items = value
                break
        else:
            # A single call object is also common.
            if payload.get("name") or payload.get("tool"):
                items = [payload]
    calls: list[ToolCall] = []
    for item in items[:8]:
        try:
            calls.append(ToolCall.model_validate(item))
        except Exception:  # noqa: BLE001 - an unusable call is dropped, not fatal
            logger.warning(
                "dropping malformed tool call from plan",
                extra={"extra_fields": {"item_keys": sorted(item) if isinstance(item, dict) else []}},
            )
    return AssistantPlan(tool_calls=calls[:6])


def ask(
    db: Session,
    *,
    question: str,
    principal: str,
    conversation_id: uuid.UUID | None = None,
    provider: AIProvider | None = None,
    asset_scope: frozenset[uuid.UUID] | None = None,
) -> AssistantReply:
    settings = get_settings()
    question = (question or "").strip()
    if not question:
        raise ValueError("Question must not be empty")

    if conversation_id is not None:
        conversation = get_conversation(db, conversation_id)
    else:
        conversation = AssistantConversation(title=question[:120], principal=principal)
        db.add(conversation)
        db.flush()

    db.add(
        AssistantMessage(
            conversation_id=conversation.id,
            role="user",
            content=question,
        )
    )
    conversation.message_count = (conversation.message_count or 0) + 1
    db.commit()

    provider = provider or get_provider()
    if not settings.ai_enabled or not provider.is_configured():
        from app.modules.ai.errors import AIUnavailableError

        raise AIUnavailableError(
            "The security assistant requires an AI provider",
            details={"provider": provider.name, "enabled": settings.ai_enabled},
        )

    budgets.enforce(db)
    executions: list[str] = []
    max_tools = max(1, min(settings.ai_assistant_max_tool_calls, 6))

    # ---------------------------------------------------------------- planning
    plan_request = _plan_request(question, max_tools)
    with track_execution(
        db,
        kind=AIExecutionKind.ASSISTANT.value,
        request=plan_request,
        provider_name=provider.name,
        model=settings.ai_model,
        principal=principal,
    ) as execution:
        plan_result = provider.generate_structured(plan_request, PlannedCalls)
        record_result(execution, plan_result)
        executions.append(str(execution.id))
    plan = _normalise_plan(plan_result.structured)

    # ------------------------------------------------------------- execution
    results: list[tools.ToolResult] = []
    seen: set[tuple[str, str]] = set()
    for call in plan.tool_calls[:max_tools]:
        marker = (call.name, json.dumps(call.arguments, sort_keys=True, default=str))
        if marker in seen:
            continue
        seen.add(marker)
        result = tools.execute(db, call.name, call.arguments, asset_scope=asset_scope)
        results.append(result)
        logger.info(
            "assistant tool call",
            extra={
                "extra_fields": {
                    "conversation_id": str(conversation.id),
                    "tool": call.name,
                    "count": result.count,
                    "error": result.error,
                }
            },
        )

    db.add(
        AssistantMessage(
            conversation_id=conversation.id,
            role="tool",
            content="",
            tool_calls=[call.model_dump(mode="json") for call in plan.tool_calls[:max_tools]],
            tool_results=[result.as_dict() for result in results],
        )
    )
    conversation.message_count = (conversation.message_count or 0) + 1
    db.commit()

    # ----------------------------------------------------------------- answer
    answer_request = _answer_request(question, results)
    with track_execution(
        db,
        kind=AIExecutionKind.ASSISTANT.value,
        request=answer_request,
        provider_name=provider.name,
        model=settings.ai_model,
        principal=principal,
    ) as execution:
        answer_result = provider.generate_structured(answer_request, AssistantOutput)
        record_result(execution, answer_result)
        executions.append(str(execution.id))

    output = AssistantOutput.model_validate(answer_result.structured or {})
    message = AssistantMessage(
        conversation_id=conversation.id,
        role="assistant",
        content=output.answer,
        tool_calls=[],
        tool_results=[],
        cited_finding_ids=output.cited_finding_ids,
    )
    db.add(message)
    conversation.message_count = (conversation.message_count or 0) + 1
    db.commit()

    return AssistantReply(
        conversation_id=conversation.id,
        answer=output.answer,
        tool_results=[result.as_dict() for result in results],
        cited_finding_ids=output.cited_finding_ids,
        cited_asset_ids=output.cited_asset_ids,
        data_gaps=output.data_gaps,
        executions=executions,
        model=settings.ai_model,
    )
