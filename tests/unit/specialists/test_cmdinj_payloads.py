from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from penage.specialists.shared.destructive_filter import DestructiveCommandFilter

_SLEEP_RE = re.compile(r"\b(?:sleep|timeout\s+/t)\s+(\d+)\b", re.IGNORECASE)
_PING_COUNT_RE = re.compile(r"\bping\s+-[cn]\s+(\d+)\b", re.IGNORECASE)

_PAYLOADS_FILE = (
    Path(__file__).resolve().parents[3] / "penage" / "payloads" / "cmdinj.yaml"
)

_REQUIRED_FIELDS = {"id", "category", "os", "payload", "notes"}
_EXPECTED_CATEGORIES = {
    "echo-separator",
    "quote-escape",
    "blind-sleep-linux",
    "blind-sleep-windows",
    "blind-ping",
    "fingerprint",
    "encoding-bypass",
    "blind-dns-oob",
}
_VALID_OS = {"any", "linux", "windows"}


@pytest.fixture(scope="module")
def payloads() -> list[dict]:
    with _PAYLOADS_FILE.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, list), "cmdinj.yaml must decode to a list"
    return data


def test_yaml_parses_cleanly(payloads: list[dict]):
    assert payloads, "cmdinj.yaml must not be empty"
    assert 25 <= len(payloads) <= 35, (
        f"expected 25-35 payloads, got {len(payloads)}"
    )
    for entry in payloads:
        assert isinstance(entry, dict)


def test_all_entries_have_required_fields(payloads: list[dict]):
    seen_ids: set[str] = set()
    for entry in payloads:
        missing = _REQUIRED_FIELDS - entry.keys()
        assert not missing, f"entry {entry.get('id')!r} missing fields: {missing}"
        pid = entry["id"]
        assert isinstance(pid, str) and pid, "id must be a non-empty string"
        assert pid not in seen_ids, f"duplicate id: {pid}"
        seen_ids.add(pid)
        assert isinstance(entry["payload"], str) and entry["payload"]
        assert isinstance(entry["notes"], str) and entry["notes"]
        assert entry["os"] in _VALID_OS, (
            f"entry {pid!r}: os must be one of {_VALID_OS}, got {entry['os']!r}"
        )
        assert entry["category"] in _EXPECTED_CATEGORIES, (
            f"entry {pid!r}: unexpected category {entry['category']!r}"
        )


def test_no_destructive_payload_in_library(payloads: list[dict]):
    """Every payload must pass the default DestructiveCommandFilter."""
    f = DestructiveCommandFilter()
    for entry in payloads:
        verdict = f.check(entry["payload"])
        assert verdict.allowed, (
            f"entry {entry['id']!r} is blocked by default filter "
            f"(reason={verdict.reason}, matched={verdict.matched_pattern}); "
            f"payload={entry['payload']!r}"
        )


def test_no_excessive_sleep_in_library(payloads: list[dict]):
    """Every sleep/timeout/ping count in the library is <= 10."""
    for entry in payloads:
        payload = entry["payload"]
        for match in _SLEEP_RE.finditer(payload):
            n = int(match.group(1))
            assert n <= 10, (
                f"entry {entry['id']!r} has sleep/timeout value {n}, "
                f"must be <= 10"
            )
        for match in _PING_COUNT_RE.finditer(payload):
            n = int(match.group(1))
            assert n <= 10, (
                f"entry {entry['id']!r} has ping count {n}, must be <= 10"
            )


def test_category_coverage(payloads: list[dict]):
    categories = {entry["category"] for entry in payloads}
    missing = _EXPECTED_CATEGORIES - categories
    extra = categories - _EXPECTED_CATEGORIES
    assert not missing, f"missing categories: {missing}"
    assert not extra, f"unexpected categories: {extra}"
    per_category: dict[str, int] = {}
    for entry in payloads:
        per_category[entry["category"]] = per_category.get(entry["category"], 0) + 1
    for cat in _EXPECTED_CATEGORIES:
        assert per_category.get(cat, 0) >= 1, f"category {cat} has no payloads"


def test_marker_placeholder_present_in_echo_payloads(payloads: list[dict]):
    """Every payload that wraps a marker probe must carry the {MARKER} token.

    Categories driven by reflected echo: echo-separator, quote-escape,
    encoding-bypass. Their payloads call ``echo`` and must rely on the
    runtime-substituted token rather than a hard-coded one.
    """
    echo_categories = {"echo-separator", "quote-escape", "encoding-bypass"}
    for entry in payloads:
        if entry["category"] not in echo_categories:
            continue
        assert "{MARKER}" in entry["payload"], (
            f"entry {entry['id']!r} ({entry['category']}) must contain "
            f"the literal '{{MARKER}}' placeholder"
        )


def test_fingerprint_entries_carry_expected_signal(payloads: list[dict]):
    """Fingerprint payloads should advertise their expected_signal in notes."""
    for entry in payloads:
        if entry["category"] != "fingerprint":
            continue
        assert "expected_signal" in entry["notes"], (
            f"fingerprint entry {entry['id']!r} must mention "
            f"'expected_signal' in notes"
        )
