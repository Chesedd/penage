"""Golden-trace snapshot harness for Stage 4.3.

Usage::

    from tests.support.golden_trace import (
        assert_trace_matches_golden,
        load_jsonl_trace,
        normalize_trace,
    )

    events = load_jsonl_trace(trace_path)
    assert_trace_matches_golden(events, "xss_reflected_evidence")

Regenerate stored files with ``PENAGE_UPDATE_GOLDEN=1`` (e.g.
``PENAGE_UPDATE_GOLDEN=1 pytest -q tests/integration/golden/``). A
warning is printed to stderr on regen so it is hard to miss in CI logs.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

GOLDEN_ROOT = Path(__file__).resolve().parents[1] / "golden" / "traces"

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_ISO_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$"
)

# Keys whose values are wall-clock / elapsed telemetry. The trace pipeline
# stamps ``ts_ms`` on every event via :class:`penage.core.tracer.JsonlTracer`;
# ``elapsed_ms`` / ``duration_ms`` may appear inside Observation-like payloads.
# When either is present, the value is replaced with a stable placeholder.
#
# What makes a key "ephemeral": its value is a function of wall-clock time or
# measured runtime (timestamps, elapsed deltas), not of the episode's semantic
# state. Two replays of the same episode against a deterministic target will
# diverge on these keys while every other field stays stable.
#
# Specific entries:
#   ts_ms / timestamp     — event emission time stamped by the tracer.
#   started_at / finished_at — per-step or per-action wall-clock boundaries.
#   duration_ms / elapsed_ms — measured subprocess / HTTP latency.
#
# Invariant: normalized traces replace these values with ``<KEY_UPPER>`` before
# golden-diff comparison — i.e. ephemeral keys are excluded from replay-
# equality checks while every non-ephemeral field must match byte-for-byte.
_EPHEMERAL_KEYS: frozenset[str] = frozenset(
    {
        "ts_ms",
        "timestamp",
        "started_at",
        "finished_at",
        "duration_ms",
        "elapsed_ms",
    }
)


def normalize_trace(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if k in _EPHEMERAL_KEYS:
                out[k] = f"<{k.upper()}>"
            else:
                out[k] = normalize_trace(v)
        return out
    if isinstance(value, list):
        return [normalize_trace(v) for v in value]
    if isinstance(value, tuple):
        return [normalize_trace(v) for v in value]
    if isinstance(value, str):
        if _UUID_RE.match(value):
            return "<UUID>"
        if _ISO_TS_RE.match(value):
            return "<TIMESTAMP>"
        return value
    return value


def load_jsonl_trace(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    out: list[dict[str, Any]] = []
    text = p.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        out.append(json.loads(stripped))
    return out


def _serialize(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)


def assert_trace_matches_golden(
    trace: Any,
    scenario: str,
    *,
    root: Path = GOLDEN_ROOT,
) -> None:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{scenario}.json"
    normalized = normalize_trace(trace)
    serialized = _serialize(normalized)

    if os.environ.get("PENAGE_UPDATE_GOLDEN") == "1":
        path.write_text(serialized + "\n", encoding="utf-8")
        print(
            f"[golden-trace] wrote {path} (PENAGE_UPDATE_GOLDEN=1)",
            file=sys.stderr,
        )
        return

    if not path.exists():
        raise AssertionError(
            f"Golden file {path} missing. "
            f"Run with PENAGE_UPDATE_GOLDEN=1 to create it."
        )

    expected_text = path.read_text(encoding="utf-8").rstrip("\n")
    if serialized == expected_text:
        return

    actual_obj = json.loads(serialized)
    expected_obj = json.loads(expected_text)
    print(
        f"[golden-trace] mismatch for scenario {scenario!r} at {path}. "
        f"To accept: PENAGE_UPDATE_GOLDEN=1 pytest -q tests/integration/golden/",
        file=sys.stderr,
    )
    assert actual_obj == expected_obj
