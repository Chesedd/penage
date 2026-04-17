from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_PAYLOADS_FILE = (
    Path(__file__).resolve().parents[3] / "penage" / "payloads" / "xxe.yaml"
)

_REQUIRED_FIELDS = {"id", "category", "template", "content_type", "notes"}
_EXPECTED_CATEGORIES = {
    "classic-unix",
    "classic-windows",
    "parameter_entity-unix",
    "oob_blind-unix",
    "error-based",
    "soap-wrapped",
    "billion-laughs",
    "no-doctype-sanity",
}
_EXPECTED_TEMPLATES = {"classic", "parameter_entity", "oob_blind"}
# Shell metacharacters should never appear in an XML body. If they do, it is
# almost certainly a copy-paste accident from a command-injection payload.
_SHELL_METACHARS_RE = re.compile(r"[`$]|\brm\s+-rf\b|\bDROP\s+TABLE\b", re.IGNORECASE)


@pytest.fixture(scope="module")
def payloads() -> list[dict]:
    with _PAYLOADS_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, list), "xxe.yaml must decode to a list"
    return data


def test_yaml_parses_cleanly(payloads: list[dict]):
    assert payloads, "xxe.yaml must not be empty"
    assert 20 <= len(payloads) <= 25, (
        f"expected 20-25 payloads, got {len(payloads)}"
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

        assert entry["template"] in _EXPECTED_TEMPLATES, (
            f"entry {pid!r}: unknown template {entry['template']!r}"
        )
        assert isinstance(entry["content_type"], str) and entry["content_type"]
        assert isinstance(entry["notes"], str) and entry["notes"]
        # uri is structurally optional in the schema (not in _REQUIRED_FIELDS)
        # but every declared entry in xxe.yaml today includes one; every
        # template we ship reads {URI}. Enforce it.
        assert "uri" in entry, f"entry {pid!r}: missing uri"
        assert isinstance(entry["uri"], str) and entry["uri"]


def test_category_coverage(payloads: list[dict]):
    categories = {entry["category"] for entry in payloads}
    assert categories == _EXPECTED_CATEGORIES, (
        f"missing={_EXPECTED_CATEGORIES - categories} "
        f"extra={categories - _EXPECTED_CATEGORIES}"
    )
    per_category: dict[str, int] = {}
    for entry in payloads:
        per_category[entry["category"]] = per_category.get(entry["category"], 0) + 1
    for cat in _EXPECTED_CATEGORIES:
        assert per_category.get(cat, 0) >= 1, f"category {cat} has no payloads"


def test_oob_blind_entries_use_oob_placeholder(payloads: list[dict]):
    oob_entries = [e for e in payloads if e["category"] == "oob_blind-unix"]
    assert oob_entries, "no oob_blind-unix entries defined"
    for entry in oob_entries:
        assert entry["template"] == "oob_blind", (
            f"entry {entry['id']!r}: oob_blind-unix category must use oob_blind template"
        )
        assert "{OOB_URL}" in entry["uri"], (
            f"entry {entry['id']!r}: oob_blind uri must contain '{{OOB_URL}}' placeholder"
        )


def test_billion_laughs_entry_has_dos_warning_in_notes(payloads: list[dict]):
    bl = [e for e in payloads if e["category"] == "billion-laughs"]
    assert len(bl) == 1, "exactly one billion-laughs reference entry expected"
    notes = bl[0]["notes"].lower()
    assert "dos" in notes, "billion-laughs notes must mention DoS risk"
    assert "opt-in" in notes or "allow_dos" in notes, (
        "billion-laughs notes must mention the opt-in gate"
    )


def test_no_destructive_commands_in_payloads(payloads: list[dict]):
    for entry in payloads:
        for field in ("uri", "payload"):
            value = entry.get(field)
            if not isinstance(value, str):
                continue
            assert not _SHELL_METACHARS_RE.search(value), (
                f"entry {entry['id']!r} field {field!r}: "
                f"looks like a shell command, not an XML URI/body: {value!r}"
            )


def test_classic_entries_have_entity_name(payloads: list[dict]):
    for entry in payloads:
        if entry["template"] != "classic":
            continue
        assert "entity_name" in entry, (
            f"entry {entry['id']!r}: classic template must declare entity_name"
        )
        assert re.match(r"^[A-Za-z_][A-Za-z0-9_-]*$", entry["entity_name"]), (
            f"entry {entry['id']!r}: entity_name {entry['entity_name']!r} "
            "is not a valid XML Name"
        )
