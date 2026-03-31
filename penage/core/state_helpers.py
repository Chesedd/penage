from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from penage.core.actions import Action, ActionType


_NUM_RE = re.compile(r"\b\d+\b")
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.I,
)

STATIC_HTTP_EXT = (
    ".css",
    ".js",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
)

STATIC_CONTENT_TYPE_PREFIXES = (
    "text/css",
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
    "image/",
    "font/",
    "application/font",
)

AUTH_REQUIRED_HTTP_PATH_HINTS = (
    "dashboard",
    "profile",
    "account",
    "orders",
    "admin",
    "token",
)


def clip_text(text: str, limit: int) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + "\n<...clipped...>\n"


def dedup_keep_order(items: list[str], *, limit: int) -> list[str]:
    seen = set()
    out: list[str] = []
    for item in items:
        if not isinstance(item, str):
            continue
        s = item.strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= limit:
            break
    return out


def extract_numeric_ids(text: str, *, limit: int = 40) -> list[str]:
    if not text:
        return []
    return dedup_keep_order([m.group(0) for m in _NUM_RE.finditer(text)], limit=limit)


def normalize_path_for_family(path: str) -> str:
    if not path:
        return "/"
    out = _UUID_RE.sub("<uuid>", path)
    out = _NUM_RE.sub("<num>", out)
    return out


def keys_preview(obj: object) -> list[str]:
    if not isinstance(obj, dict):
        return []
    return sorted(str(k) for k in obj.keys())[:20]


def truncate_forms(forms: list[dict[str, object]], *, max_forms: int = 3, max_inputs: int = 8) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for f in forms[:max_forms]:
        if not isinstance(f, dict):
            continue
        inputs_preview: list[dict[str, object]] = []
        inputs = f.get("inputs")
        if isinstance(inputs, list):
            for inp in inputs[:max_inputs]:
                if not isinstance(inp, dict):
                    continue
                inputs_preview.append(
                    {
                        "name": inp.get("name"),
                        "type": inp.get("type"),
                        "required": bool(inp.get("required")),
                        "hidden": bool(inp.get("hidden")),
                    }
                )
        out.append(
            {
                "method": f.get("method"),
                "action": f.get("action"),
                "inputs": inputs_preview,
            }
        )
    return out


def promoted_path_candidates_from_auth_hits(auth_hits: list[dict[str, object]]) -> list[str]:
    out: list[str] = []
    seen = set()

    def push(x: str) -> None:
        s = str(x or "").strip()
        if not s:
            return
        try:
            path = urlparse(s).path or s
        except Exception:
            path = s
        if not str(path).startswith("/"):
            path = "/" + str(path)
        if path in seen:
            return
        seen.add(path)
        out.append(path)

    for hit in auth_hits:
        if not isinstance(hit, dict):
            continue

        post_location = hit.get("post_location")
        if isinstance(post_location, str) and post_location:
            push(post_location)

        improved = hit.get("improved_targets")
        if isinstance(improved, list):
            for item in improved:
                if not isinstance(item, dict):
                    continue
                p = item.get("path")
                if isinstance(p, str) and p:
                    push(p)
                loc = item.get("location")
                if isinstance(loc, str) and loc:
                    push(loc)

    return out[:8]


def promoted_ids_from_auth_hits(auth_hits: list[dict[str, object]]) -> list[str]:
    out: list[str] = []
    seen = set()
    for hit in auth_hits:
        if not isinstance(hit, dict):
            continue
        ident = str(hit.get("id") or "").strip()
        if not ident or not ident.isdigit():
            continue
        if ident in seen:
            continue
        seen.add(ident)
        out.append(ident)
    return out[:8]


def looks_like_login_gate_http_page(text: str, url: str, content_type: str) -> bool:
    try:
        path = (urlparse(url).path or "").lower()
    except Exception:
        path = str(url or "").lower()

    if not any(h in path for h in AUTH_REQUIRED_HTTP_PATH_HINTS):
        return False

    low = str(text or "").lower()
    low_ct = str(content_type or "").lower()

    if "text/html" not in low_ct and "<html" not in low and "<form" not in low:
        return False

    title_login = "<title>login" in low or ">login -" in low or ">login<" in low
    username_form = "<form" in low and 'name="username"' in low
    password_form = "<form" in low and 'type="password"' in low

    has_logout = "logout" in low
    has_welcome = "welcome," in low or "welcome back" in low

    return (title_login or (username_form and password_form)) and not has_logout and not has_welcome


def looks_like_static_http_url(url: str) -> bool:
    try:
        path = (urlparse(url).path or "").lower()
    except Exception:
        path = str(url or "").lower()

    if not path:
        return False
    if path.startswith("/static/"):
        return True
    return path.endswith(STATIC_HTTP_EXT)


def path_only(url_or_path: str) -> str:
    if not url_or_path:
        return ""
    try:
        parsed = urlparse(url_or_path)
        if parsed.scheme or parsed.netloc:
            return parsed.path or "/"
    except Exception:
        pass
    return url_or_path if url_or_path.startswith("/") else ("/" + url_or_path)


def action_family(action: Action) -> str:
    if action.type == ActionType.HTTP:
        params = action.params or {}
        method = str(params.get("method") or "GET").upper()
        url = str(params.get("url") or "")
        try:
            parsed = urlparse(url)
            path = normalize_path_for_family(parsed.path or "/")
            query_keys = sorted({str(k) for k, _ in parse_qsl(parsed.query, keep_blank_values=True)})[:20]
        except Exception:
            path = url
            query_keys = []
        data_keys = keys_preview(params.get("data"))
        json_keys = keys_preview(params.get("json"))
        return f"http:{method}:{path}:q={query_keys}:data={data_keys}:json={json_keys}"

    if action.type == ActionType.SHELL:
        return "shell"
    if action.type == ActionType.PYTHON:
        return "python"
    if action.type == ActionType.MACRO:
        return f"macro:{str((action.params or {}).get('name') or '')}"
    return action.type.value