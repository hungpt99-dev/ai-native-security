"""Plan normalisation: models emit several shapes for the same intent."""

from __future__ import annotations

from app.modules.ai.services.assistant import _normalise_plan


def test_canonical_shape() -> None:
    plan = _normalise_plan(
        {"tool_calls": [{"name": "list_findings", "arguments": {"severity": ["HIGH"]}}]}
    )
    assert len(plan.tool_calls) == 1
    assert plan.tool_calls[0].name == "list_findings"
    assert plan.tool_calls[0].arguments == {"severity": ["HIGH"]}


def test_calls_with_tool_and_args() -> None:
    plan = _normalise_plan(
        {"calls": [{"tool": "kev_findings", "args": {"limit": 5}, "rationale": "exploited"}]}
    )
    assert plan.tool_calls[0].name == "kev_findings"
    assert plan.tool_calls[0].arguments == {"limit": 5}


def test_bare_list_and_single_object() -> None:
    assert _normalise_plan([{"name": "platform_overview", "arguments": {}}]).tool_calls
    assert _normalise_plan({"name": "platform_overview", "arguments": {}}).tool_calls


def test_malformed_entries_are_dropped_not_fatal() -> None:
    plan = _normalise_plan(
        {
            "steps": [
                "not a dict",
                {"no_name": True},
                {"name": "platform_overview", "arguments": {}},
            ]
        }
    )
    assert len(plan.tool_calls) == 1
    assert plan.tool_calls[0].name == "platform_overview"


def test_empty_plan_is_valid() -> None:
    assert _normalise_plan({}).tool_calls == []
    assert _normalise_plan(None).tool_calls == []


def test_assistant_output_accepts_answer_aliases() -> None:
    from app.modules.ai.schemas.outputs import AssistantOutput

    parsed = AssistantOutput.model_validate(
        {"summary": "Two findings matter.", "cited_finding_ids": [], "extra_key": 1}
    )
    assert parsed.answer == "Two findings matter."
