from __future__ import annotations

from penage.core.state import State
from penage.core.usage import EarlyStopThresholds, UsageTracker


def test_no_evidence_stop_triggers_after_gap():
    t = UsageTracker()
    st = State()

    # Step 1: no evidence yet.
    t.observe_step(st, step=1)
    # Step 5: still no evidence → gap = 5 - 0 = 5.
    t.observe_step(st, step=5)

    thresholds = EarlyStopThresholds(
        max_tool_calls=0,
        max_cost_usd=0,
        max_wall_clock_s=0,
        max_no_evidence_steps=3,
    )
    reason = t.check_early_stop(thresholds)
    assert reason is not None
    assert "no_evidence_steps" in reason

    # New evidence arrives → gap resets, stop no longer fires.
    st.validation_evidence_count = 1
    t.observe_step(st, step=6)
    assert t.check_early_stop(thresholds) is None


def test_no_evidence_stop_with_none_threshold_is_disabled():
    t = UsageTracker()
    st = State()
    t.observe_step(st, step=1)
    t.observe_step(st, step=50)

    thresholds = EarlyStopThresholds(
        max_tool_calls=0,
        max_cost_usd=0,
        max_wall_clock_s=0,
        max_no_evidence_steps=None,
    )
    assert t.check_early_stop(thresholds) is None


def test_policy_source_streak_stop_triggers_at_cap():
    t = UsageTracker()
    st = State()
    st.same_policy_source_streak = 5
    t.observe_step(st, step=1)

    thresholds = EarlyStopThresholds(
        max_tool_calls=0,
        max_cost_usd=0,
        max_wall_clock_s=0,
        max_policy_source_streak=5,
    )
    reason = t.check_early_stop(thresholds)
    assert reason is not None
    assert "policy_source_streak" in reason


def test_policy_source_streak_stop_below_cap_is_none():
    t = UsageTracker()
    st = State()
    st.same_policy_source_streak = 5
    t.observe_step(st, step=1)

    thresholds = EarlyStopThresholds(
        max_tool_calls=0,
        max_cost_usd=0,
        max_wall_clock_s=0,
        max_policy_source_streak=6,
    )
    assert t.check_early_stop(thresholds) is None


def test_action_repeat_ratio_stop_triggers_when_ratio_hits_threshold():
    t = UsageTracker()
    fingerprints = ["a"] * 8 + ["b", "c"]
    for fp in fingerprints:
        t.record_action_fingerprint(fp)

    thresholds = EarlyStopThresholds(
        max_tool_calls=0,
        max_cost_usd=0,
        max_wall_clock_s=0,
        max_action_repeat_ratio=0.7,
        action_repeat_window=10,
    )
    reason = t.check_early_stop(thresholds)
    assert reason is not None
    assert "action_repeat_ratio" in reason


def test_action_repeat_ratio_stop_below_threshold_is_none():
    t = UsageTracker()
    for fp in ["a"] * 8 + ["b", "c"]:
        t.record_action_fingerprint(fp)

    thresholds = EarlyStopThresholds(
        max_tool_calls=0,
        max_cost_usd=0,
        max_wall_clock_s=0,
        max_action_repeat_ratio=0.8,
        action_repeat_window=10,
    )
    assert t.check_early_stop(thresholds) is None


def test_action_repeat_ratio_stop_ignored_when_window_not_full():
    t = UsageTracker()
    for fp in ["a", "a", "a"]:
        t.record_action_fingerprint(fp)

    thresholds = EarlyStopThresholds(
        max_tool_calls=0,
        max_cost_usd=0,
        max_wall_clock_s=0,
        max_action_repeat_ratio=0.5,
        action_repeat_window=10,
    )
    assert t.check_early_stop(thresholds) is None


def test_ablation_all_correlation_thresholds_none():
    t = UsageTracker()
    st = State()
    st.same_policy_source_streak = 999

    # Saturate all correlation signals. With all None thresholds, nothing fires.
    for fp in ["a"] * 20:
        t.record_action_fingerprint(fp)
    t.observe_step(st, step=100)

    thresholds = EarlyStopThresholds(
        max_tool_calls=0,
        max_cost_usd=0,
        max_wall_clock_s=0,
        max_no_evidence_steps=None,
        max_policy_source_streak=None,
        max_action_repeat_ratio=None,
    )
    assert t.check_early_stop(thresholds) is None


def test_combined_ablation_only_active_signal_fires():
    t = UsageTracker()
    st = State()
    st.same_policy_source_streak = 99

    # Saturate both policy streak and action repeats.
    for fp in ["a"] * 20:
        t.record_action_fingerprint(fp)
    t.observe_step(st, step=50)

    # Only action_repeat_ratio active: reason mentions action_repeat_ratio.
    only_repeat = EarlyStopThresholds(
        max_tool_calls=0,
        max_cost_usd=0,
        max_wall_clock_s=0,
        max_no_evidence_steps=None,
        max_policy_source_streak=None,
        max_action_repeat_ratio=0.5,
        action_repeat_window=10,
    )
    reason = t.check_early_stop(only_repeat)
    assert reason is not None
    assert "action_repeat_ratio" in reason
    assert "policy_source_streak" not in reason

    # Only policy_source_streak active: reason mentions policy_source_streak.
    only_policy = EarlyStopThresholds(
        max_tool_calls=0,
        max_cost_usd=0,
        max_wall_clock_s=0,
        max_no_evidence_steps=None,
        max_policy_source_streak=5,
        max_action_repeat_ratio=None,
    )
    reason = t.check_early_stop(only_policy)
    assert reason is not None
    assert "policy_source_streak" in reason
    assert "action_repeat_ratio" not in reason


def test_check_early_stop_signature_back_compat_without_kwargs():
    # Existing callers pass only `thresholds` — must keep working.
    t = UsageTracker()
    thresholds = EarlyStopThresholds(max_tool_calls=1, max_cost_usd=0, max_wall_clock_s=0)
    assert t.check_early_stop(thresholds) is None
    t.record_tool_call("coordinator", 0.1)
    reason = t.check_early_stop(thresholds)
    assert reason is not None
    assert "tool_calls" in reason
