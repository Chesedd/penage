from __future__ import annotations

import re
from typing import Iterable, Mapping, Optional
from urllib.parse import urlparse

from penage.core.observations import Observation
from penage.utils.html_paths import extract_paths


DEFAULT_ALLOWED_HOSTS = {"localhost", "127.0.0.1"}
MAX_EXCERPT_CHARS = 2000
MAX_FULL_TEXT_CHARS = 120_000
MAX_EXTRACTED_PATHS = 200
FLAG_RE = re.compile(r"(FLAG\{[^}]{0,200}\}|flag\{[^}]{0,200}\})")


def resolve_allowed_hosts(allowed_hosts: Optional[Iterable[str]] = None) -> set[str]:
    return set(allowed_hosts) if allowed_hosts else set(DEFAULT_ALLOWED_HOSTS)


def validate_http_url(url: str, *, allowed_hosts: set[str]) -> Optional[str]:
    try:
        p = urlparse(url)
    except Exception:
        return "Invalid URL (parse failed)"

    if p.scheme not in ("http", "https"):
        return f"Disallowed URL scheme: {p.scheme!r}"

    host = (p.hostname or "").lower()
    if not host:
        return "URL has no host"

    if host not in allowed_hosts:
        return f"Host not in allowlist: {host!r}"

    return None


def http_action_error(*, method: object, url: object, allowed_hosts: set[str]) -> Optional[str]:
    if not method or not isinstance(method, str):
        return "HTTP action missing 'method' (string)"
    if not url or not isinstance(url, str):
        return "HTTP action missing 'url' (string)"

    url_err = validate_http_url(url, allowed_hosts=allowed_hosts)
    if url_err:
        return f"HTTP url validation failed: {url_err}"
    return None


def extract_http_payload(text: str) -> dict[str, object]:
    excerpt = text[:MAX_EXCERPT_CHARS]

    text_full = text
    if len(text_full) > MAX_FULL_TEXT_CHARS:
        text_full = text_full[:MAX_FULL_TEXT_CHARS] + "\n<...truncated...>\n"

    try:
        paths = sorted(list(extract_paths(text)))[:MAX_EXTRACTED_PATHS]
    except Exception:
        paths = []

    matches = list(FLAG_RE.finditer(text))
    contains_flag_like = bool(matches)
    flag_snippets: list[str] = []
    for m in matches[:3]:
        a = max(0, m.start() - 80)
        b = min(len(text), m.end() + 80)
        flag_snippets.append(text[a:b])

    return {
        "text_excerpt": excerpt,
        "text_full": text_full,
        "text_len": len(text),
        "paths": paths,
        "contains_flag_like": contains_flag_like,
        "flag_snippets": flag_snippets,
    }


def build_http_observation(
    *,
    elapsed_ms: int,
    status_code: int,
    url: str,
    headers: Mapping[str, object],
    text: str,
    transport: str,
    extra: Optional[dict[str, object]] = None,
) -> Observation:
    data: dict[str, object] = {
        "status_code": int(status_code),
        "url": url,
        "headers": dict(headers),
        "transport": transport,
    }
    data.update(extract_http_payload(text))
    if extra:
        data.update(extra)
    return Observation(ok=True, elapsed_ms=elapsed_ms, data=data)