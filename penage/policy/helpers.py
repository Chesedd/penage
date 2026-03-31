from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from penage.core.actions import Action, ActionType
from penage.core.state import State


_NUM_RE = re.compile(r"\b\d+\b")
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.I,
)

_GUESSED_IDOR_HINTS = (
    "/user/",
    "/users/",
    "/profile/",
    "/account/",
    "/api/user/",
    "/api/users/",
)

_STATIC_EXT = (
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


def is_logout_action(a: Action) -> bool:
    if a.type != ActionType.HTTP:
        return False
    url = str((a.params or {}).get("url") or "")
    if not url:
        return False
    path = (urlparse(url).path or "").lower()
    return path == "/logout" or "/logout" in path or path == "/signout" or "/signout" in path


def normalize_path(path: str) -> str:
    if not path:
        return "/"
    out = _UUID_RE.sub("<uuid>", path)
    out = _NUM_RE.sub("<num>", out)
    return out


def keys_preview(obj: object) -> list[str]:
    if not isinstance(obj, dict):
        return []
    return sorted(str(k) for k in obj.keys())[:20]


def action_path(a: Action) -> str:
    if a.type != ActionType.HTTP:
        return ""
    url = str((a.params or {}).get("url") or "")
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        return parsed.path or "/"
    except Exception:
        return url


def macro_name(a: Action) -> str:
    if a.type != ActionType.MACRO:
        return ""
    return str((a.params or {}).get("name") or "").strip()


def action_family(a: Action) -> str:
    if a.type == ActionType.HTTP:
        params = a.params or {}
        method = str(params.get("method") or "GET").upper()
        url = str(params.get("url") or "")
        try:
            parsed = urlparse(url)
            path = normalize_path(parsed.path or "/")
            query_keys = sorted({str(k) for k, _ in parse_qsl(parsed.query, keep_blank_values=True)})[:20]
        except Exception:
            path = url
            query_keys = []

        data_keys = keys_preview(params.get("data"))
        json_keys = keys_preview(params.get("json"))
        return f"http:{method}:{path}:q={query_keys}:data={data_keys}:json={json_keys}"

    if a.type == ActionType.SHELL:
        return "shell"
    if a.type == ActionType.PYTHON:
        return "python"
    if a.type == ActionType.MACRO:
        return f"macro:{macro_name(a)}"
    return a.type.value


def action_contains_any_id(a: Action, ids: list[str]) -> bool:
    if not ids:
        return False

    params = a.params or {}
    blobs: list[str] = []

    url = str(params.get("url") or "")
    if url:
        blobs.append(url)

    data = params.get("data")
    if isinstance(data, dict):
        blobs.extend(str(v) for v in data.values())

    json_body = params.get("json")
    if isinstance(json_body, dict):
        blobs.extend(str(v) for v in json_body.values())

    if a.type == ActionType.SHELL:
        cmd = str(params.get("command") or "")
        if cmd:
            blobs.append(cmd)

    if a.type == ActionType.MACRO:
        blobs.append(str(params))

    joined = "\n".join(blobs)
    return any(str(x) and str(x) in joined for x in ids)


def path_matches_any_target(path: str, targets: list[str]) -> bool:
    if not path or not targets:
        return False
    for t in targets:
        ts = str(t or "").strip()
        if not ts:
            continue
        if path == ts or path.startswith(ts.rstrip("/") + "/"):
            return True
    return False


def pivot_active(state: State) -> bool:
    curr_step = int(state.facts.get("orch_step") or 0)
    return curr_step <= int(getattr(state, "promoted_pivot_active_until_step", 0) or 0)


def macro_commitment_active(state: State) -> bool:
    if bool(state.facts.get("macro_session_established")):
        return True
    if isinstance(state.facts.get("macro_followup_hits_preview"), list) and state.facts.get("macro_followup_hits_preview"):
        return True
    if isinstance(state.facts.get("macro_family_hits_preview"), list) and state.facts.get("macro_family_hits_preview"):
        return True
    if pivot_active(state) and (
        list(getattr(state, "promoted_pivot_targets", []) or [])
        or list(getattr(state, "promoted_pivot_ids", []) or [])
    ):
        return True
    return False


def is_guessed_idor_path(path: str) -> bool:
    low = str(path or "").lower()
    return any(h in low for h in _GUESSED_IDOR_HINTS)


def is_static_path(path: str) -> bool:
    low = str(path or "").lower()
    return low.startswith("/static/") or low.endswith(_STATIC_EXT)