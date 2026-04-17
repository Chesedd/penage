from __future__ import annotations

from penage.core.usage import (
    UsageTracker,
    bind_usage_tracker,
    current_usage_tracker,
)


def test_current_usage_tracker_returns_none_outside_bind():
    assert current_usage_tracker() is None


def test_bind_usage_tracker_exposes_tracker_within_block():
    t = UsageTracker()
    with bind_usage_tracker(t):
        assert current_usage_tracker() is t
    assert current_usage_tracker() is None


def test_bind_usage_tracker_resets_on_exception():
    t = UsageTracker()
    try:
        with bind_usage_tracker(t):
            assert current_usage_tracker() is t
            raise RuntimeError("boom")
    except RuntimeError:
        pass
    assert current_usage_tracker() is None
