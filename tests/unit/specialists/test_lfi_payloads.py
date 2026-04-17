from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from penage.specialists.shared.path_traversal import LfiTargetFamily

_PAYLOADS_FILE = (
    Path(__file__).resolve().parents[3] / "penage" / "payloads" / "lfi.yaml"
)

_REQUIRED_FIELDS = {
    "id",
    "category",
    "family",
    "depth",
    "payload",
    "expected_markers",
    "notes",
}
_EXPECTED_CATEGORIES = {
    "unix",
    "windows",
    "bypass",
    "php-wrapper",
    "absolute",
}


@pytest.fixture(scope="module")
def payloads() -> list[dict]:
    with _PAYLOADS_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, list), "lfi.yaml must decode to a list"
    return data


def test_yaml_parses_cleanly(payloads: list[dict]):
    assert payloads, "lfi.yaml must not be empty"
    assert 25 <= len(payloads) <= 30, (
        f"expected 25-30 payloads, got {len(payloads)}"
    )
    for entry in payloads:
        assert isinstance(entry, dict)


def test_all_entries_have_required_fields(payloads: list[dict]):
    seen_ids: set[str] = set()
    for entry in payloads:
        missing = _REQUIRED_FIELDS - entry.keys()
        assert not missing, (
            f"entry {entry.get('id')!r} missing fields: {missing}"
        )
        pid = entry["id"]
        assert isinstance(pid, str) and pid, "id must be a non-empty string"
        assert pid not in seen_ids, f"duplicate id: {pid}"
        seen_ids.add(pid)
        assert isinstance(entry["payload"], str) and entry["payload"]
        assert isinstance(entry["notes"], str) and entry["notes"]
        assert isinstance(entry["depth"], int) and entry["depth"] >= 0, (
            f"entry {pid!r}: depth must be a non-negative int"
        )
        assert isinstance(entry["expected_markers"], list), (
            f"entry {pid!r}: expected_markers must be a list"
        )
        for marker in entry["expected_markers"]:
            assert isinstance(marker, str) and marker, (
                f"entry {pid!r}: expected_markers must contain non-empty strings"
            )


def test_category_coverage(payloads: list[dict]):
    categories = {entry["category"] for entry in payloads}
    missing = _EXPECTED_CATEGORIES - categories
    extra = categories - _EXPECTED_CATEGORIES
    assert not missing, f"missing categories: {missing}"
    assert not extra, f"unexpected categories: {extra}"
    per_category: dict[str, int] = {}
    for entry in payloads:
        per_category[entry["category"]] = (
            per_category.get(entry["category"], 0) + 1
        )
    # Minimums per the task spec.
    assert per_category["unix"] >= 10
    assert per_category["windows"] >= 4
    assert per_category["bypass"] >= 6
    assert per_category["php-wrapper"] >= 4
    assert per_category["absolute"] >= 2


def test_family_values_in_enum(payloads: list[dict]):
    valid = {f.value for f in LfiTargetFamily}
    for entry in payloads:
        assert entry["family"] in valid, (
            f"entry {entry['id']!r} has family={entry['family']!r} "
            f"which is not in LfiTargetFamily ({sorted(valid)})"
        )
