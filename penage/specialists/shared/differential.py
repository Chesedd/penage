"""Differential-response comparison utility for IDOR-class verification.

This module provides a pure, network-free helper that classifies a pair of
HTTP responses (A = owner / role A, B = other user / role B) into a
:class:`DifferentialSignal`. The caller — typically an IDOR specialist —
uses the signal to decide whether a finding crosses the evidence-gate
threshold (CLAUDE.md invariant #4: IDOR is validated via differential tests).

Responsibilities:

* :func:`extract_markers` — pull PII / owner-scoped tokens (emails, order
  ids, usernames, CSRF tokens, API keys, UUIDs) out of a response body.
  A denylist and minimum-length rule prune generic placeholders that would
  otherwise yield false positives.
* :func:`compare_responses` — classify the pair (A, B) into a
  :class:`DifferentialSignal` using two layers of evidence:

  1. Identical body hash (strongest) — byte-for-byte the same page
     returned to two different roles.
  2. Shared PII markers — A's owner-scoped tokens appearing in B's body.

  Weaker status/length differentials produce ``STATUS_DIFFERENTIAL``; both
  roles being denied produces ``BOTH_DENIED``.

The module is intentionally read-only: no HTTP, no cookie handling, no
state mutation. Callers are responsible for fetching responses via the
appropriate guarded HTTP tool before invoking :func:`compare_responses`.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

logger = logging.getLogger(__name__)


class DifferentialSignal(str, Enum):
    """Classification of two-response comparison outcomes.

    Ordered from strongest to weakest evidence of IDOR:
      - LEAK_IDENTICAL_BODY: same body (by hash), different cookies.
        High-confidence IDOR — role B sees role A's exact page.
      - LEAK_SHARED_MARKERS: role A's response contains unique PII
        tokens (emails, order-ids, account numbers, usernames); role
        B's response contains the same tokens. Strong evidence.
      - STATUS_DIFFERENTIAL: A=200 B=403 (expected) или A=200 B=200
        with very different body length. Weak; caller decides.
      - BOTH_DENIED: both 401/403/404 — no signal, safe behaviour.
      - NO_SIGNAL: responses differ in uninteresting ways.
    """

    LEAK_IDENTICAL_BODY = "leak_identical_body"
    LEAK_SHARED_MARKERS = "leak_shared_markers"
    STATUS_DIFFERENTIAL = "status_differential"
    BOTH_DENIED = "both_denied"
    NO_SIGNAL = "no_signal"


@dataclass(frozen=True, slots=True)
class ExtractedMarkers:
    """Tokens extracted from a response body that are likely PII/owner-scoped."""

    emails: list[str] = field(default_factory=list)
    order_ids: list[str] = field(default_factory=list)
    usernames_quoted: list[str] = field(default_factory=list)
    csrf_tokens: list[str] = field(default_factory=list)
    api_keys: list[str] = field(default_factory=list)
    uuids: list[str] = field(default_factory=list)

    def all_tokens(self) -> set[str]:
        s: set[str] = set()
        s.update(self.emails)
        s.update(self.order_ids)
        s.update(self.usernames_quoted)
        s.update(self.csrf_tokens)
        s.update(self.api_keys)
        s.update(self.uuids)
        return s

    def is_empty(self) -> bool:
        return not self.all_tokens()


@dataclass(frozen=True, slots=True)
class ResponseComparison:
    """Result of :func:`compare_responses`.

    :param signal: classification of the (A, B) pair.
    :param shared_markers: tokens that appear in both A and B when
        ``signal == LEAK_SHARED_MARKERS`` (empty otherwise).
    :param a_status, b_status: HTTP status codes of A and B.
    :param a_body_len, b_body_len: raw body length in characters.
    :param a_body_hash, b_body_hash: first 16 hex chars of SHA-256 of the
        body; sufficient for within-episode comparison and keeps traces
        compact (CLAUDE.md invariant #5).
    :param notes: free-form diagnostic strings (downgrade reasons,
        length ratios, etc.) — meant for the trace, not machine logic.
    """

    signal: DifferentialSignal
    shared_markers: list[str] = field(default_factory=list)
    a_status: int | None = None
    b_status: int | None = None
    a_body_len: int = 0
    b_body_len: int = 0
    a_body_hash: str = ""
    b_body_hash: str = ""
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Regex patterns for owner-scoped markers
# ---------------------------------------------------------------------------

# Email: conservative — буквы/цифры/._+-, @, домен, tld 2-24.
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}",
)

# Order/invoice IDs: key followed by digits or mixed id-like string.
# Покрывает: "Order ID: 12345", "invoice_number: ABC-123-42",
# "#ORD-998877".
_ORDER_ID_RE = re.compile(
    r"(?:order[_\s]?(?:id|number|no)?|invoice[_\s]?(?:id|number|no)?|#ORD)"
    r"[\s:#=\-]{0,4}([A-Z0-9][A-Z0-9\-]{3,32})",
    re.IGNORECASE,
)

# HTML: welcome / account holder markers with a quoted or whitespace-
# delimited name. E.g. <span class="username">alice</span>,
# "Welcome, alice!", data-user="bob42".
_USERNAME_QUOTED_RE = re.compile(
    r"""(?:username|user[_\-]?name|account[_\s]holder|welcome[,\s]+)"""
    r"""["'>\s:=]{1,4}([A-Za-z0-9_.\-]{3,32})""",
    re.IGNORECASE,
)

# CSRF tokens: hex-ish 20+ chars tied to name=csrf/csrf_token.
_CSRF_RE = re.compile(
    r"""(?:csrf[_\-]?token|authenticity[_\-]?token|xsrf)"""
    r"""["'=:\s]{1,4}([A-Za-z0-9+/=_\-]{20,128})""",
    re.IGNORECASE,
)

# Generic API key markers.
_API_KEY_RE = re.compile(
    r"""(?:api[_\-]?key|access[_\-]?token|bearer)"""
    r"""["'=:\s]{1,4}([A-Za-z0-9+/=_\-]{16,128})""",
    re.IGNORECASE,
)

# UUIDs: canonical 8-4-4-4-12.
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)

# Common framework tokens we should NEVER treat as owner-scoped
# — they appear in every response regardless of auth.
_GENERIC_TOKEN_DENYLIST = frozenset({
    "undefined", "null", "example", "example.com", "localhost",
    "admin@example.com", "user@example.com", "noreply@",
    "00000000-0000-0000-0000-000000000000",
})

_MIN_MARKER_LEN = 3
_MAX_MARKERS_PER_KIND = 16


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def extract_markers(body: str, *, max_per_kind: int = _MAX_MARKERS_PER_KIND) -> ExtractedMarkers:
    """Extract PII/owner-scoped tokens from a response body.

    All regexes are case-insensitive; the returned values preserve the
    original casing from the body. Deduplicated and capped at
    max_per_kind to bound memory/noise.
    """
    if not body:
        return ExtractedMarkers()

    emails = _collect(_EMAIL_RE, body, max_per_kind)
    order_ids = _collect_group1(_ORDER_ID_RE, body, max_per_kind)
    usernames = _collect_group1(_USERNAME_QUOTED_RE, body, max_per_kind)
    csrf = _collect_group1(_CSRF_RE, body, max_per_kind)
    api_keys = _collect_group1(_API_KEY_RE, body, max_per_kind)
    uuids = _collect(_UUID_RE, body, max_per_kind)

    return ExtractedMarkers(
        emails=_clean_list(emails),
        order_ids=_clean_list(order_ids),
        usernames_quoted=_clean_list(usernames),
        csrf_tokens=_clean_list(csrf),
        api_keys=_clean_list(api_keys),
        uuids=_clean_list(uuids),
    )


def _collect(pattern: re.Pattern[str], body: str, cap: int) -> list[str]:
    seen: list[str] = []
    seen_set: set[str] = set()
    for m in pattern.finditer(body):
        val = m.group(0)
        key = val.lower()
        if key in seen_set:
            continue
        seen_set.add(key)
        seen.append(val)
        if len(seen) >= cap:
            break
    return seen


def _collect_group1(pattern: re.Pattern[str], body: str, cap: int) -> list[str]:
    seen: list[str] = []
    seen_set: set[str] = set()
    for m in pattern.finditer(body):
        try:
            val = m.group(1)
        except IndexError:
            continue
        if not val:
            continue
        key = val.lower()
        if key in seen_set:
            continue
        seen_set.add(key)
        seen.append(val)
        if len(seen) >= cap:
            break
    return seen


def _clean_list(items: Iterable[str]) -> list[str]:
    """Drop denylisted / too-short tokens."""
    out: list[str] = []
    for item in items:
        s = item.strip()
        if len(s) < _MIN_MARKER_LEN:
            continue
        if s.lower() in _GENERIC_TOKEN_DENYLIST:
            continue
        if "@" in s:
            if any(s.lower().startswith(d) for d in _GENERIC_TOKEN_DENYLIST):
                continue
        out.append(s)
    return out


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def compare_responses(
    *,
    a_body: str,
    a_status: int | None,
    b_body: str,
    b_status: int | None,
    shared_markers_min: int = 1,
    body_length_ratio_weak: float = 0.5,
) -> ResponseComparison:
    """Classify the pair (A, B) into a DifferentialSignal.

    Semantics:
      A — request by the resource owner (role A, authenticated).
      B — request by another user or unauthenticated (role B).

    STRONG (verified IDOR):
      1. Both A and B succeeded (2xx) AND A.body == B.body (hash equal,
         non-trivial length): LEAK_IDENTICAL_BODY.
      2. Both A and B succeeded AND markers extracted from A appear in
         B's body in sufficient count (>= shared_markers_min):
         LEAK_SHARED_MARKERS. `shared_markers` lists the overlapping
         tokens.

    MEDIUM (candidate):
      3. A succeeded, B returned 200 with a notably different body
         (length ratio), OR A=200 and B returned 5xx suggesting a
         partial processing path: STATUS_DIFFERENTIAL.

    NO SIGNAL:
      4. Both denied (401/403/404): BOTH_DENIED.
      5. Default: NO_SIGNAL.

    Body-length guard: if both bodies are shorter than 32 chars, any
    "identical body" match is downgraded to NO_SIGNAL — these are
    usually empty error pages that happen to match.
    """
    a_body = a_body or ""
    b_body = b_body or ""
    a_len = len(a_body)
    b_len = len(b_body)
    a_hash = _hash(a_body) if a_body else ""
    b_hash = _hash(b_body) if b_body else ""

    a_ok = _is_2xx(a_status)
    b_ok = _is_2xx(b_status)
    a_denied = _is_denied(a_status)
    b_denied = _is_denied(b_status)

    notes: list[str] = []

    if a_denied and b_denied:
        return ResponseComparison(
            signal=DifferentialSignal.BOTH_DENIED,
            a_status=a_status, b_status=b_status,
            a_body_len=a_len, b_body_len=b_len,
            a_body_hash=a_hash, b_body_hash=b_hash,
            notes=notes,
        )

    if a_ok and b_ok and a_hash and a_hash == b_hash:
        if a_len >= 32:
            return ResponseComparison(
                signal=DifferentialSignal.LEAK_IDENTICAL_BODY,
                shared_markers=[],
                a_status=a_status, b_status=b_status,
                a_body_len=a_len, b_body_len=b_len,
                a_body_hash=a_hash, b_body_hash=b_hash,
                notes=["identical body hash, length >= 32"],
            )
        notes.append("identical body but too short; downgraded")

    if a_ok and b_ok:
        a_markers = extract_markers(a_body)
        if not a_markers.is_empty():
            b_markers = extract_markers(b_body)
            shared = sorted(a_markers.all_tokens() & b_markers.all_tokens())
            if len(shared) >= shared_markers_min:
                return ResponseComparison(
                    signal=DifferentialSignal.LEAK_SHARED_MARKERS,
                    shared_markers=shared[:16],
                    a_status=a_status, b_status=b_status,
                    a_body_len=a_len, b_body_len=b_len,
                    a_body_hash=a_hash, b_body_hash=b_hash,
                    notes=notes,
                )

    if a_ok and b_ok:
        if a_len > 0:
            ratio = min(a_len, b_len) / max(a_len, b_len)
            if ratio <= body_length_ratio_weak:
                notes.append(f"body-length ratio {ratio:.2f}")
                return ResponseComparison(
                    signal=DifferentialSignal.STATUS_DIFFERENTIAL,
                    a_status=a_status, b_status=b_status,
                    a_body_len=a_len, b_body_len=b_len,
                    a_body_hash=a_hash, b_body_hash=b_hash,
                    notes=notes,
                )

    if a_ok and not b_ok and b_status is not None and 500 <= b_status < 600:
        notes.append("A=2xx, B=5xx (partial processing)")
        return ResponseComparison(
            signal=DifferentialSignal.STATUS_DIFFERENTIAL,
            a_status=a_status, b_status=b_status,
            a_body_len=a_len, b_body_len=b_len,
            a_body_hash=a_hash, b_body_hash=b_hash,
            notes=notes,
        )

    return ResponseComparison(
        signal=DifferentialSignal.NO_SIGNAL,
        a_status=a_status, b_status=b_status,
        a_body_len=a_len, b_body_len=b_len,
        a_body_hash=a_hash, b_body_hash=b_hash,
        notes=notes,
    )


def _hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _is_2xx(status: int | None) -> bool:
    return status is not None and 200 <= int(status) < 300


def _is_denied(status: int | None) -> bool:
    if status is None:
        return False
    s = int(status)
    return s in (401, 403, 404)
