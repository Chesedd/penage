from __future__ import annotations

import re
from typing import Set
from urllib.parse import urlparse


_ATTR_URL_RE = re.compile(r'\b(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

_JS_PATH_RE = re.compile(r"""['"](/[^'"\s]{1,300})['"]""")

_ASSET_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".map")


def extract_paths(html: str) -> Set[str]:
    out: Set[str] = set()
    if not html:
        return out

    for m in _ATTR_URL_RE.finditer(html):
        val = (m.group(1) or "").strip()
        if not val:
            continue
        low = val.lower()
        if val.startswith("#") or low.startswith("javascript:") or low.startswith("mailto:"):
            continue

        if low.startswith("http://") or low.startswith("https://"):
            try:
                out.add(urlparse(val).path or "/")
            except Exception:
                continue
        else:
            out.add(val)

    for m in _JS_PATH_RE.finditer(html):
        p = m.group(1)
        if not p or not p.startswith("/"):
            continue
        low = p.lower()
        if low.startswith("/static/") or low.endswith(_ASSET_EXT):
            continue
        out.add(p)

    return out