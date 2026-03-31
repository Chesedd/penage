from penage.core.planner_context import build_planner_context
from penage.core.state import State


def test_planner_context_includes_active_pivot_and_constraint():
    st = State(
        facts={"base_url": "http://localhost", "orch_step": 3},
        known_paths={"/dashboard", "/orders"},
        promoted_pivot_targets=["/orders/123"],
        promoted_pivot_ids=["123"],
        promoted_pivot_source="auth_confusion",
        promoted_pivot_reason="confirmed pivot",
        promoted_pivot_active_until_step=6,
    )

    text = build_planner_context(step=3, state=st, extra_constraint="prefer receipts")
    assert "BaseURL=http://localhost" in text
    assert "PromotedPivotTargets=['/orders/123']" in text
    assert "PromotedPivotIds=['123']" in text
    assert "Constraint=prefer receipts" in text
    assert text.endswith("Return JSON plan.")


def test_planner_context_compact_mode_clips_long_text():
    st = State(last_http_excerpt="x" * 1200)
    text = build_planner_context(step=1, state=st, extra_constraint=None, compact=True)
    assert "<...clipped...>" in text