from dataclasses import dataclass
from typing import List
from urllib.parse import urljoin, urlparse

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.specialists.base import SpecialistConfig
from penage.utils.fingerprint import action_fingerprint


_HINTS = (
    "flag",
    "receipt",
    "order",
    "orders",
    "archive",
    "admin",
    "debug",
    "download",
    "export",
    "preferences",
    "settings",
    "dashboard",
    "profile",
    "account",
    "logout",
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

_PIVOT_CLOSE_ENDPOINTS = ("/dashboard", "/logout", "/orders", "/profile", "/account")


def _path(url: str) -> str:
    try:
        return (urlparse(url).path or "").lower()
    except Exception:
        return ""


def _looks_like_asset(url: str) -> bool:
    path = _path(url)
    if not path:
        return False
    if path.startswith("/static/"):
        return True
    return path.endswith(_BLOCKED_EXT)


def _pivot_active(st: State) -> bool:
    return st.orch_step <= st.promoted_pivot_active_until_step


def _pivot_targets(st: State) -> list[str]:
    vals = list(getattr(st, "promoted_pivot_targets", []) or [])
    out: list[str] = []
    for x in vals:
        if not isinstance(x, str):
            continue
        s = x.strip()
        if s:
            out.append(s)
    return out


def _keep_under_pivot(path: str, pivot_targets: list[str]) -> bool:
    low = str(path or "").lower()
    if low in _PIVOT_CLOSE_ENDPOINTS:
        return True
    for t in pivot_targets:
        ts = str(t or "").rstrip("/")
        if not ts:
            continue
        if low == ts or low.startswith(ts + "/"):
            return True
    return False


@dataclass(slots=True)
class NavigatorSpecialist:
    name: str = "navigator"

    def propose(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        base_url = state.base_url
        if not base_url:
            return []

        paths = sorted(list(state.known_paths or []))
        if not paths:
            return []

        pivot_targets = _pivot_targets(state) if _pivot_active(state) else []

        out: List[CandidateAction] = []
        for p in paths:
            if not isinstance(p, str) or not p:
                continue

            if p.startswith("http://") or p.startswith("https://"):
                url = p
            else:
                url = urljoin(base_url, p)

            # Hard drop all static assets at the source.
            if _looks_like_asset(url):
                continue

            path = _path(url)
            if pivot_targets and not _keep_under_pivot(path, pivot_targets):
                continue

            score = 0.1
            low = url.lower()
            for h in _HINTS:
                if h in low:
                    score += 1.0

            a = Action(
                type=ActionType.HTTP,
                params={"method": "GET", "url": url},
                timeout_s=30,
                tags=["nav"],
            )
            fp = action_fingerprint(a)
            if fp in state.visited_actions_fingerprint:
                continue

            out.append(
                CandidateAction(
                    action=a,
                    source=self.name,
                    score=score,
                    cost=1.0,
                    reason=f"explore known path {p}",
                )
            )

        out.sort(key=lambda c: c.score, reverse=True)
        return out[: max(1, config.max_candidates)]