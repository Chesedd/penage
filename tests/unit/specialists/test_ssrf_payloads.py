from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_PAYLOADS_FILE = (
    Path(__file__).resolve().parents[3] / "penage" / "payloads" / "ssrf.yaml"
)

_REQUIRED_FIELDS = {"id", "category", "payload", "notes"}
_EXPECTED_CATEGORIES = {
    "internal-loopback",
    "metadata-aws",
    "metadata-gcp",
    "metadata-azure",
    "scheme-bypass",
    "encoding-bypass",
    "hostname-tricks",
    "protocol-smuggle",
}
# Anything outside a URL that looks like a shell metacharacter suggests the
# payload crossed from URL territory into command territory.
_SHELL_METACHARS_RE = re.compile(r"[;`|&><$]")


@pytest.fixture(scope="module")
def payloads() -> list[dict]:
    with _PAYLOADS_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, list), "ssrf.yaml must decode to a list"
    return data


def test_yaml_parses_cleanly(payloads: list[dict]):
    assert payloads, "ssrf.yaml must not be empty"
    for entry in payloads:
        assert isinstance(entry, dict)


def test_all_entries_have_required_fields(payloads: list[dict]):
    seen_ids: set[str] = set()
    for entry in payloads:
        missing = _REQUIRED_FIELDS - entry.keys()
        assert not missing, f"entry {entry.get('id')!r} missing fields: {missing}"
        assert "expected_marker" in entry, (
            f"entry {entry.get('id')!r} must declare expected_marker (may be null)"
        )
        pid = entry["id"]
        assert isinstance(pid, str) and pid, "id must be a non-empty string"
        assert pid not in seen_ids, f"duplicate id: {pid}"
        seen_ids.add(pid)
        assert isinstance(entry["payload"], str) and entry["payload"]
        assert isinstance(entry["notes"], str) and entry["notes"]


def test_no_destructive_commands_in_payloads(payloads: list[dict]):
    for entry in payloads:
        payload = entry["payload"]
        # SSRF payloads are URLs; shell metacharacters are never needed inside
        # them and would indicate an accidental command-injection smell.
        assert not _SHELL_METACHARS_RE.search(payload), (
            f"entry {entry['id']!r} contains shell metacharacters in payload: {payload!r}"
        )


def test_category_coverage(payloads: list[dict]):
    categories = {entry["category"] for entry in payloads}
    assert categories == _EXPECTED_CATEGORIES, (
        f"unexpected or missing categories: "
        f"missing={_EXPECTED_CATEGORIES - categories} "
        f"extra={categories - _EXPECTED_CATEGORIES}"
    )
    per_category: dict[str, int] = {}
    for entry in payloads:
        per_category[entry["category"]] = per_category.get(entry["category"], 0) + 1
    for cat in _EXPECTED_CATEGORIES:
        assert per_category.get(cat, 0) >= 1, f"category {cat} has no payloads"
