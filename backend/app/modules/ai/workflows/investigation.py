"""Investigation workflow (LangGraph).

The graph is deliberately small and linear-with-one-retry. Each node has one job,
state is explicit, and every node records its own timing so a stuck run is
diagnosable from the investigation row instead of from logs alone.

Nodes:
    load_context -> compute_signals -> investigate -> persist
                                         ^     |
                                         +-----+ (retry once on a retryable provider error)
"""

from __future__ import annotations

import time
import uuid
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.modules.ai import agents
from app.modules.ai.errors import AIProviderError, AIResponseError
from app.modules.ai.providers.base import AIProvider
from app.modules.ai.services.executions import record_result, track_execution
from app.modules.findings.models import Finding
from app.modules.risk_analysis.signals import compute_signals
from app.modules.security_intelligence.context_builder import SecurityContextBuilder
from app.modules.security_intelligence.schemas import SecurityContext

logger = get_logger(__name__)

WORKFLOW_NAME = "investigation"
WORKFLOW_VERSION = "1"
MAX_INVESTIGATION_ATTEMPTS = 2


class InvestigationState(TypedDict, total=False):
    finding_id: str
    asset_id: str
    context: dict[str, Any] | None
    snapshot_id: str | None
    signals: dict[str, Any] | None
    output: dict[str, Any] | None
    execution_id: str | None
    error: dict[str, Any] | None
    attempts: int
    trace: list[dict[str, Any]]


def _trace(state: InvestigationState, node: str, started: float, **extra: Any) -> list[dict[str, Any]]:
    trace = list(state.get("trace") or [])
    trace.append({"node": node, "duration_ms": int((time.perf_counter() - started) * 1000), **extra})
    return trace


def build_graph(db: Session, provider: AIProvider, *, principal: str, policy: dict[str, Any]):
    """Compile the graph with the session and provider bound to the nodes."""

    builder = SecurityContextBuilder()

    def load_context(state: InvestigationState) -> InvestigationState:
        started = time.perf_counter()
        finding_id = uuid.UUID(state["finding_id"])
        context = builder.build(db, finding_id)
        finding = db.get(Finding, finding_id)
        assert finding is not None
        snapshot = builder.persist(db, context, finding=finding)
        db.commit()
        return {
            **state,
            "asset_id": str(finding.asset_id),
            "context": context.model_dump(mode="json"),
            "snapshot_id": str(snapshot.id),
            "trace": _trace(state, "load_context", started, evidence=len(context.evidence)),
        }

    def compute_signals_node(state: InvestigationState) -> InvestigationState:
        started = time.perf_counter()
        assert state["context"] is not None
        context = SecurityContext.model_validate(state["context"])
        signals = compute_signals(context, policy)
        return {
            **state,
            "signals": signals.as_dict(),
            "trace": _trace(state, "compute_signals", started, score=signals.score),
        }

    def investigate(state: InvestigationState) -> InvestigationState:
        started = time.perf_counter()
        assert state["context"] is not None
        context = SecurityContext.model_validate(state["context"])
        signals = compute_signals(context, policy)
        attempts = int(state.get("attempts") or 0) + 1
        request = agents.security_analyst.build_request(context, signals)
        try:
            with track_execution(
                db,
                kind="INVESTIGATION",
                request=request,
                provider_name=provider.name,
                model=request_metadata_model(request),
                finding_id=uuid.UUID(state["finding_id"]),
                asset_id=uuid.UUID(state["asset_id"]) if state.get("asset_id") else None,
                context_snapshot_id=uuid.UUID(state["snapshot_id"]) if state.get("snapshot_id") else None,
                principal=principal,
            ) as execution:
                analysis = agents.security_analyst.run(provider, context, signals, request=request)
                record_result(execution, analysis.result)
                execution_id = str(execution.id)
        except (AIProviderError, AIResponseError) as exc:
            return {
                **state,
                "attempts": attempts,
                "execution_id": None,
                "output": None,
                "error": {"code": getattr(exc, "code", "ai_error"), "message": str(exc)[:500]},
                "trace": _trace(state, "investigate", started, attempt=attempts, error=type(exc).__name__),
            }

        return {
            **state,
            "attempts": attempts,
            "output": analysis.output.model_dump(mode="json"),
            "execution_id": execution_id,
            "error": None,
            "trace": _trace(state, "investigate", started, attempt=attempts),
        }

    def route_after_investigate(state: InvestigationState) -> str:
        if state.get("output"):
            return "persist"
        if int(state.get("attempts") or 0) < MAX_INVESTIGATION_ATTEMPTS:
            error = state.get("error") or {}
            if error.get("code") in {"ai_provider_error", "ai_rate_limited"}:
                return "retry"
        return "persist"

    def retry(state: InvestigationState) -> InvestigationState:
        return {**state, "trace": _trace(state, "retry", time.perf_counter())}

    def persist(state: InvestigationState) -> InvestigationState:
        started = time.perf_counter()
        return {**state, "trace": _trace(state, "persist", started)}

    graph = StateGraph(InvestigationState)
    graph.add_node("load_context", load_context)
    graph.add_node("compute_signals", compute_signals_node)
    graph.add_node("investigate", investigate)
    graph.add_node("retry", retry)
    graph.add_node("persist", persist)
    graph.add_edge(START, "load_context")
    graph.add_edge("load_context", "compute_signals")
    graph.add_edge("compute_signals", "investigate")
    graph.add_conditional_edges(
        "investigate",
        route_after_investigate,
        {"persist": "persist", "retry": "retry"},
    )
    graph.add_edge("retry", "investigate")
    graph.add_edge("persist", END)
    return graph.compile()


def request_metadata_model(request: Any) -> str:
    from app.core.config import get_settings

    return get_settings().ai_model
