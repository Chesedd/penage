"""Golden-trace snapshot harness for deterministic episode recordings.

Usage
-----

1. Run a deterministic specialist / orchestrator slice with a
   :class:`penage.core.tracer.JsonlTracer` pointed at a ``tmp_path`` file.
2. Call :func:`load_trace_events` on the JSONL path to parse the events list.
3. Call :func:`assert_trace_matches_golden(events, "<scenario>")` to compare
   against ``tests/golden/traces/<scenario>.json``.

Run with ``PENAGE_UPDATE_GOLDEN=1`` to regenerate the golden files (prints a
warning to stderr so CI cannot silently accept a regen).

The harness is intentionally free of snapshot-library dependencies and does
its own canonical JSON encoding so byte-level diffs are reproducible.
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
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_ISO_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$"
)

_EPHEMERAL_KEYS = frozenset(
    {
        "ts_ms",
        "timestamp",
        "started_at",
        "finished_at",
        "duration_ms",
        "elapsed_ms",
        "episode_id",
    }
)


def _normalize_ephemeral(key: str, value: Any) -> Any:
    if value is None:
        return None
    return f"<{key.upper()}>"


def normalize_trace(value: Any) -> Any:
    """Recursively replace ephemeral fields with stable placeholders.

    Keys named in :data:`_EPHEMERAL_KEYS` collapse to ``"<KEY>"`` (or
    ``None`` if they were originally ``None``). String values that look like
    RFC 4122 UUIDs or ISO-8601 timestamps are normalized too.
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if k in _EPHEMERAL_KEYS:
                out[k] = _normalize_ephemeral(k, v)
            else:
                out[k] = normalize_trace(v)
        return out
    if isinstance(value, list):
        return [normalize_trace(v) for v in value]
    if isinstance(value, str):
        if _UUID_RE.match(value):
            return "<UUID>"
        if _ISO_TS_RE.match(value):
            return "<TIMESTAMP>"
        return value
    return value


def load_trace_events(path: Path) -> list[dict[str, Any]]:
    """Parse a JSONL trace file into an ordered list of event dicts."""
    raw = path.read_text(encoding="utf-8")
    events: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(json.loads(line))
    return events


def _serialize(normalized: Any) -> str:
    return json.dumps(normalized, indent=2, sort_keys=True, ensure_ascii=False)


def assert_trace_matches_golden(
    trace: Any,
    scenario: str,
    *,
    root: Path = GOLDEN_ROOT,
) -> None:
    """Compare a normalized trace against ``<root>/<scenario>.json``.

    In ``PENAGE_UPDATE_GOLDEN=1`` mode the golden file is rewritten with the
    canonical serialization of the current trace and a warning is printed to
    stderr. Otherwise the function asserts equality; on mismatch pytest
    produces a structural dict/list diff via the normal ``assert`` path.
    """
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{scenario}.json"
    normalized = normalize_trace(trace)
    serialized = _serialize(normalized) + "\n"

    if os.environ.get("PENAGE_UPDATE_GOLDEN") == "1":
        path.write_text(serialized, encoding="utf-8")
        print(
            f"[golden_trace] PENAGE_UPDATE_GOLDEN=1: rewrote {path}",
            file=sys.stderr,
        )
        return

    if not path.exists():
        raise AssertionError(
            f"Golden file {path} missing. "
            f"Run with PENAGE_UPDATE_GOLDEN=1 to create it."
        )

    expected_raw = path.read_text(encoding="utf-8")
    if serialized == expected_raw:
        return

    expected = json.loads(expected_raw)
    actual = json.loads(serialized)
    assert actual == expected, (
        f"Golden trace mismatch for scenario {scenario!r}. "
        f"To accept: PENAGE_UPDATE_GOLDEN=1 pytest -q tests/integration/golden/"
    )
