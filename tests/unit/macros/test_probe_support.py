from __future__ import annotations

from penage.macros.probe_support import dedup_paths, normalized_probe_paths
from penage.macros.probe_resource_family import build_family_paths


def test_normalized_probe_paths_filters_assets_and_normalizes_slashes():
    paths = normalized_probe_paths(["dashboard", "/dashboard", "/static/app.js", ""], limit=10)
    assert paths == ["/dashboard"]


def test_dedup_paths_preserves_order():
    assert dedup_paths(["/a", "/a", "/b", "", "/c"], limit=10) == ["/a", "/b", "/c"]


def test_build_family_paths_expands_id_template_and_numeric_seed():
    templated = build_family_paths("/profile/<id>/status", ["100", "200"], "profile")
    assert "/profile/100/status" in templated

    derived = build_family_paths("/profile/300123/status", ["300111"], "profile")
    assert "/profile/300111/archive" in derived
    assert "/profile/300111/status" in derived