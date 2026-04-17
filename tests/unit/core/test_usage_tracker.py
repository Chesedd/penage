from __future__ import annotations

import time

from penage.core.usage import EarlyStopThresholds, RoleMetrics, UsageTracker


def test_record_llm_call_accumulates_tokens_and_cost():
    t = UsageTracker()
    t.record_llm_call("coordinator", "anthropic", {
        "input_tokens": 100,
        "output_tokens": 50,
        "cached_tokens": 20,
        "reasoning_tokens": 0,
    }, cost=0.005)

    t.record_llm_call("coordinator", "anthropic", {
        "input_tokens": 80,
        "output_tokens": 30,
        "cached_tokens": 10,
        "reasoning_tokens": 5,
    }, cost=0.003)

    m = t._roles["coordinator"]
    assert m.input_tokens == 180
    assert m.output_tokens == 80
    assert m.cached_tokens == 30
    assert m.reasoning_tokens == 5
    assert m.llm_calls == 2
    assert abs(m.dollar_cost - 0.008) < 1e-9


def test_record_tool_call_accumulates_calls_and_wall_clock():
    t = UsageTracker()
    t.record_tool_call("coordinator", 0.5)
    t.record_tool_call("coordinator", 1.2)
    t.record_tool_call("sandbox", 0.3)

    assert t._roles["coordinator"].tool_calls == 2
    assert abs(t._roles["coordinator"].wall_clock_seconds - 1.7) < 1e-9
    assert t._roles["sandbox"].tool_calls == 1
    assert t.total_tool_calls == 3


def test_accumulation_across_multiple_roles():
    t = UsageTracker()
    t.record_llm_call("coordinator", "openai", {"input_tokens": 100, "output_tokens": 40}, cost=0.01)
    t.record_llm_call("specialist", "anthropic", {"input_tokens": 200, "output_tokens": 60}, cost=0.02)
    t.record_tool_call("coordinator", 1.0)
    t.record_tool_call("validator", 0.5)

    assert t.total_input_tokens == 300
    assert t.total_output_tokens == 100
    assert t.total_llm_calls == 2
    assert t.total_tool_calls == 2
    assert abs(t.total_cost_usd - 0.03) < 1e-9


def test_early_stop_tool_calls():
    t = UsageTracker()
    thresholds = EarlyStopThresholds(max_tool_calls=3, max_cost_usd=0, max_wall_clock_s=0)

    for _ in range(2):
        t.record_tool_call("coordinator", 0.1)
    assert t.check_early_stop(thresholds) is None

    t.record_tool_call("coordinator", 0.1)
    reason = t.check_early_stop(thresholds)
    assert reason is not None
    assert "tool_calls=3" in reason


def test_early_stop_cost():
    t = UsageTracker()
    thresholds = EarlyStopThresholds(max_tool_calls=0, max_cost_usd=0.05, max_wall_clock_s=0)

    t.record_llm_call("coordinator", "anthropic", {"input_tokens": 10}, cost=0.03)
    assert t.check_early_stop(thresholds) is None

    t.record_llm_call("coordinator", "anthropic", {"input_tokens": 10}, cost=0.03)
    reason = t.check_early_stop(thresholds)
    assert reason is not None
    assert "cost_usd" in reason


def test_early_stop_wall_clock():
    t = UsageTracker(_episode_start=time.perf_counter() - 400)
    thresholds = EarlyStopThresholds(max_tool_calls=0, max_cost_usd=0, max_wall_clock_s=300)

    reason = t.check_early_stop(thresholds)
    assert reason is not None
    assert "wall_clock_s" in reason


def test_early_stop_returns_none_when_all_within_budget():
    t = UsageTracker()
    thresholds = EarlyStopThresholds(max_tool_calls=40, max_cost_usd=0.30, max_wall_clock_s=300)

    t.record_tool_call("coordinator", 0.5)
    t.record_llm_call("coordinator", "fake", {"input_tokens": 10}, cost=0.001)

    assert t.check_early_stop(thresholds) is None


def test_early_stop_disabled_thresholds():
    t = UsageTracker()
    thresholds = EarlyStopThresholds(max_tool_calls=0, max_cost_usd=0, max_wall_clock_s=0)

    for _ in range(100):
        t.record_tool_call("coordinator", 1.0)
    t.record_llm_call("coordinator", "fake", {}, cost=999.0)

    assert t.check_early_stop(thresholds) is None


def test_to_dict_structure():
    t = UsageTracker()
    t.record_llm_call("coordinator", "anthropic", {
        "input_tokens": 100,
        "output_tokens": 50,
        "cached_tokens": 20,
        "reasoning_tokens": 0,
    }, cost=0.005)
    t.record_tool_call("coordinator", 0.5)
    t.record_tool_call("sandbox", 0.3)

    d = t.to_dict()

    assert "by_role" in d
    assert "totals" in d

    assert "coordinator" in d["by_role"]
    assert "sandbox" in d["by_role"]

    coordinator = d["by_role"]["coordinator"]
    assert coordinator["input_tokens"] == 100
    assert coordinator["output_tokens"] == 50
    assert coordinator["cached_tokens"] == 20
    assert coordinator["reasoning_tokens"] == 0
    assert coordinator["llm_calls"] == 1
    assert coordinator["tool_calls"] == 1
    assert coordinator["dollar_cost"] == 0.005

    totals = d["totals"]
    assert totals["input_tokens"] == 100
    assert totals["output_tokens"] == 50
    assert totals["tool_calls"] == 2
    assert totals["llm_calls"] == 1
    assert totals["api_cost_usd"] == 0.005
    assert "wall_clock_s" in totals
    assert isinstance(totals["wall_clock_s"], float)


def test_to_dict_empty_tracker():
    t = UsageTracker()
    d = t.to_dict()

    assert d["by_role"] == {}
    assert d["totals"]["input_tokens"] == 0
    assert d["totals"]["output_tokens"] == 0
    assert d["totals"]["tool_calls"] == 0
    assert d["totals"]["llm_calls"] == 0
    assert d["totals"]["api_cost_usd"] == 0.0


def test_role_metrics_to_dict_round_trips():
    m = RoleMetrics(input_tokens=10, output_tokens=5, tool_calls=2, wall_clock_seconds=1.23456, dollar_cost=0.0001234)
    d = m.to_dict()

    assert d["input_tokens"] == 10
    assert d["output_tokens"] == 5
    assert d["tool_calls"] == 2
    assert d["wall_clock_seconds"] == 1.235
    assert d["dollar_cost"] == 0.000123


def test_token_usage_missing_keys_default_to_zero():
    t = UsageTracker()
    t.record_llm_call("coordinator", "fake", {}, cost=0.0)

    m = t._roles["coordinator"]
    assert m.input_tokens == 0
    assert m.output_tokens == 0
    assert m.cached_tokens == 0
    assert m.reasoning_tokens == 0
    assert m.llm_calls == 1


def test_record_llm_call_with_specialist_writes_both_maps():
    t = UsageTracker()
    t.record_llm_call(
        "sandbox",
        "fake",
        {"input_tokens": 10, "output_tokens": 5, "cached_tokens": 2, "reasoning_tokens": 1},
        cost=0.01,
        specialist="xss",
    )

    role_m = t._roles["sandbox"]
    spec_m = t._specialists["xss"]

    assert role_m.llm_calls == 1
    assert role_m.input_tokens == 10
    assert role_m.output_tokens == 5
    assert role_m.cached_tokens == 2
    assert role_m.reasoning_tokens == 1
    assert abs(role_m.dollar_cost - 0.01) < 1e-9

    assert spec_m.llm_calls == 1
    assert spec_m.input_tokens == 10
    assert spec_m.output_tokens == 5
    assert spec_m.cached_tokens == 2
    assert spec_m.reasoning_tokens == 1
    # cost is not duplicated to specialist bucket
    assert spec_m.dollar_cost == 0.0

    # totals read from by_role only — no double counting
    d = t.to_dict()
    assert d["totals"]["input_tokens"] == 10
    assert d["totals"]["output_tokens"] == 5
    assert d["totals"]["llm_calls"] == 1
    assert d["totals"]["api_cost_usd"] == 0.01

    assert "by_specialist" in d
    assert "xss" in d["by_specialist"]
    assert d["by_specialist"]["xss"]["llm_calls"] == 1


def test_record_llm_call_without_specialist_leaves_map_empty():
    t = UsageTracker()
    t.record_llm_call("sandbox", "fake", {"input_tokens": 7, "output_tokens": 3})

    assert t._specialists == {}
    d = t.to_dict()
    assert d["by_specialist"] == {}


def test_record_llm_call_empty_specialist_string_is_ignored():
    t = UsageTracker()
    t.record_llm_call("sandbox", "fake", {"input_tokens": 1}, specialist="")

    assert t._specialists == {}
    assert t.to_dict()["by_specialist"] == {}


def test_to_dict_always_contains_by_specialist_key():
    t = UsageTracker()
    d = t.to_dict()
    assert "by_specialist" in d
    assert d["by_specialist"] == {}
