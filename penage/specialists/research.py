from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.specialists.base import SpecialistConfig
from penage.utils.fingerprint import action_fingerprint


_HARD_ASSET_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot")
_SOFT_ASSET_EXT = (".css", ".js", ".map")

_FALLBACK_ENDPOINTS = (
    "/robots.txt",
    "/sitemap.xml",
    "/openapi.json",
    "/swagger",
    "/swagger-ui",
    "/api",
    "/api/v1",
    "/debug",
    "/admin",
    "/health",
)

_PIVOT_CLOSE_ENDPOINTS = (
    "/dashboard",
    "/logout",
    "/orders",
    "/profile",
    "/account",
)


def _path_of(url_or_path: str) -> str:
    try:
        parsed = urlparse(url_or_path)
        if parsed.scheme or parsed.netloc:
            return (parsed.path or "").lower()
    except Exception:
        pass
    return str(url_or_path or "").lower()


def _is_hard_asset(path_or_url: str) -> bool:
    return _path_of(path_or_url).endswith(_HARD_ASSET_EXT)


def _is_soft_asset(path_or_url: str) -> bool:
    return _path_of(path_or_url).endswith(_SOFT_ASSET_EXT)


def _best_context_text(st: State) -> str:
    best = getattr(st, "best_http_text_full", None)
    if isinstance(best, str) and best:
        return best
    last = getattr(st, "last_http_text_full", None)
    if isinstance(last, str) and last:
        return last
    fact_last = st.facts.get("last_http_text_full")
    if isinstance(fact_last, str):
        return fact_last
    return ""


def _best_id_candidates(st: State) -> List[str]:
    ids = list(getattr(st, "best_http_ids", []) or [])
    page_ids = st.facts.get("page_ids") or []
    if isinstance(page_ids, list):
        ids.extend(str(x) for x in page_ids if isinstance(x, str))

    seen = set()
    out: List[str] = []
    for x in ids:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
        if len(out) >= 20:
            break
    return out


def _is_stuck(st: State, *, threshold: int) -> bool:
    used = int(st.http_requests_used or 0)
    if used < 2:
        return False

    streak = int(getattr(st, "no_new_paths_streak", 0) or 0)
    if streak <= 0:
        streak = int(st.facts.get("no_new_paths_streak") or 0)

    return streak >= threshold


def _xss_or_js_context(st: State) -> bool:
    blob = "\n".join(
        [
            str(getattr(st, "best_http_url", "") or "").lower(),
            str(getattr(st, "last_http_url", "") or "").lower(),
            _best_context_text(st).lower(),
            "\n".join(str(x).lower() for x in (st.best_http_paths or [])[:40]),
        ]
    )
    return any(
        h in blob
        for h in (
            "xss",
            "<script",
            "javascript",
            "onerror",
            "onload",
            "innerhtml",
            "document.cookie",
            "fetch(",
            "$.ajax",
            "axios",
            "static/css",
            "static/js",
        )
    )


def _negative_paths(st: State) -> set[str]:
    out: set[str] = set()
    for x in st.research_negatives[-40:]:
        if isinstance(x, str) and x:
            out.add(_path_of(x))
    return out


def _recent_memory_paths(st: State) -> List[str]:
    out: List[str] = []
    for item in st.recent_http_memory[-st.recent_http_memory_limit :]:
        if not isinstance(item, dict):
            continue
        paths = item.get("paths")
        if not isinstance(paths, list):
            continue
        for p in paths:
            if isinstance(p, str) and p:
                out.append(p)
    return out


def _pivot_active(st: State) -> bool:
    curr_step = int(st.facts.get("orch_step") or 0)
    return curr_step <= int(getattr(st, "promoted_pivot_active_until_step", 0) or 0)


def _pivot_targets(st: State) -> list[str]:
    vals = list(getattr(st, "promoted_pivot_targets", []) or [])
    return [str(x) for x in vals if isinstance(x, str) and x]


def _pivot_ids(st: State) -> list[str]:
    vals = list(getattr(st, "promoted_pivot_ids", []) or [])
    return [str(x) for x in vals if isinstance(x, str) and x]


def _is_close_pivot_sibling(path: str, pivot_targets: list[str]) -> bool:
    low = str(path or "").lower()
    if not low:
        return False
    if low in _PIVOT_CLOSE_ENDPOINTS:
        return True
    for t in pivot_targets:
        ts = str(t or "").rstrip("/")
        if not ts:
            continue
        if low == ts or low.startswith(ts + "/"):
            return True
    return False


def _filter_paths_for_active_pivot(st: State, paths: List[str]) -> List[str]:
    if not _pivot_active(st):
        return paths

    pivot_targets = _pivot_targets(st)
    out: List[str] = []
    seen = set()

    for p in paths:
        low = _path_of(p)
        if not low or low in seen:
            continue
        if _is_hard_asset(low) or _is_soft_asset(low):
            continue
        if not _is_close_pivot_sibling(low, pivot_targets):
            continue
        seen.add(low)
        out.append(p)

    return out[:12]


def _extract_contextual_candidates(st: State) -> list[tuple[str, str, list[str], float]]:
    """
    Returns tuples:
      (path, reason, tags, score_bonus)
    """
    allow_assets = _xss_or_js_context(st) and not _pivot_active(st)
    neg = _negative_paths(st)
    ids = _best_id_candidates(st)
    pivot_active = _pivot_active(st)
    pivot_targets = _pivot_targets(st)

    out: list[tuple[str, str, list[str], float]] = []
    seen = set()

    def add(path: str, reason: str, tags: Optional[list[str]] = None, bonus: float = 0.0) -> None:
        if not path:
            return
        p = path.strip()
        if not p:
            return
        if p.startswith("http://") or p.startswith("https://"):
            norm = _path_of(p)
        else:
            norm = p if p.startswith("/") else ("/" + p)

        low = _path_of(norm)
        if not low:
            return
        if low in neg:
            return
        if _is_hard_asset(low):
            return
        if _is_soft_asset(low):
            if not allow_assets:
                return
        if pivot_active and not _is_close_pivot_sibling(low, pivot_targets):
            return
        if low in seen:
            return

        seen.add(low)
        out.append((norm, reason, list(tags or []), bonus))

    for p in sorted(list(st.known_paths or [])):
        if not isinstance(p, str) or not p:
            continue
        low = _path_of(p)
        if _is_hard_asset(low):
            continue
        if _is_soft_asset(low):
            if allow_assets:
                add(p, "contextual asset path from known_paths", ["asset-context"], 0.8)
            continue

        bonus = 0.0
        if any(h in low for h in ("flag", "receipt", "order", "archive", "admin", "debug", "api", "xss", "solution", "result")):
            bonus += 0.8
        add(p, "known path from prior pages", [], bonus)

    for p in _recent_memory_paths(st):
        low = _path_of(p)
        if _is_hard_asset(low):
            continue
        if _is_soft_asset(low):
            if allow_assets:
                add(p, "contextual asset path from recent_http_memory", ["asset-context"], 0.6)
            continue
        add(p, "path seen in recent_http_memory", [], 0.4)

    for h in st.research_hypotheses[:10]:
        if not isinstance(h, dict):
            continue
        p = str(h.get("path") or "").strip()
        why = str(h.get("why") or "research hypothesis").strip()
        conf = float(h.get("confidence") or 0.0)
        tags: list[str] = []
        if _is_soft_asset(p) and allow_assets:
            tags.append("asset-context")
        add(p, f"carry-over research hypothesis: {why}", tags, conf)

    if not pivot_active:
        for oid in ids[:8]:
            add(f"/order/{oid}", f"ID-based synthesis from visible id {oid}", [], 0.7)
            add(f"/order/{oid}/receipt", f"receipt sibling from visible id {oid}", [], 1.0)
            add(f"/order/{oid}/archive", f"archive sibling from visible id {oid}", [], 0.8)
            add(f"/order/{oid}/invoice", f"invoice sibling from visible id {oid}", [], 0.7)
            add(f"/order/{oid}/status", f"status sibling from visible id {oid}", [], 0.5)

    if not out:
        fallback = list(_PIVOT_CLOSE_ENDPOINTS) if pivot_active else list(_FALLBACK_ENDPOINTS)
        for p in fallback:
            add(p, "generic fallback endpoint", [], 0.1)

    return out[:32]


def _sh_quote(s: str) -> str:
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


@dataclass(slots=True)
class ResearchSpecialist:
    name: str = "research"
    stuck_threshold: int = 2
    max_http_hypotheses: int = 2
    enable_sandbox_fuzz: bool = True
    cooldown_steps: int = 2
    max_fuzz_runs: int = 3
    fuzz_cooldown_steps: int = 4

    def propose(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        _ = config

        base_url = str(state.facts.get("base_url") or "")
        if not base_url:
            return []

        if not _is_stuck(state, threshold=self.stuck_threshold):
            return []

        curr_step = int(state.facts.get("orch_step") or 0)
        last_step = int(state.facts.get("research_det_last_step") or 0)
        if curr_step and last_step and (curr_step - last_step) < self.cooldown_steps:
            return []

        candidates = _extract_contextual_candidates(state)
        state.facts["research_det_last_step"] = curr_step
        state.facts["research_det_preview"] = [
            {"path": p, "reason": why, "tags": tags, "bonus": bonus}
            for (p, why, tags, bonus) in candidates[:10]
        ]

        actions: List[CandidateAction] = []

        count = 0
        for p, why, tags, bonus in candidates:
            if count >= self.max_http_hypotheses:
                break

            if p.startswith("http://") or p.startswith("https://"):
                url = p
            else:
                url = urljoin(base_url, p)

            if urlparse(url).scheme not in ("http", "https"):
                continue

            low_path = str(urlparse(url).path or "").lower()
            if _is_hard_asset(low_path):
                continue
            if _is_soft_asset(low_path):
                continue

            if _pivot_active(state):
                pivots = _pivot_targets(state)
                close = _is_close_pivot_sibling(low_path, pivots)
                if not close:
                    continue

            action_tags = ["research", "hypothesis"]
            if tags:
                action_tags.extend(tags)

            a = Action(
                type=ActionType.HTTP,
                params={"method": "GET", "url": url},
                timeout_s=30,
                tags=action_tags,
            )

            fp = action_fingerprint(a)
            if fp in state.visited_actions_fingerprint:
                continue

            family_penalty = 0.0
            last_family = str(getattr(state, "last_action_family", "") or "")
            if "/order/<num>" in last_family and "/order/" in _path_of(url):
                family_penalty = 1.2

            score = 22.5 + float(bonus) - family_penalty
            cost = 1.2

            actions.append(
                CandidateAction(
                    action=a,
                    source=self.name,
                    score=score,
                    cost=cost,
                    reason=f"stuck: deterministic research hypothesis {p} ({why})",
                )
            )
            count += 1

        if self.enable_sandbox_fuzz and state.tool_calls_sandbox > 0:
            ran = int(state.facts.get("research_fuzz_runs") or 0)
            last_fuzz_step = int(state.facts.get("research_last_fuzz_step") or 0)
            if ran < self.max_fuzz_runs and ((not last_fuzz_step) or ((curr_step - last_fuzz_step) >= self.fuzz_cooldown_steps)):
                fuzz_words = None
                if _pivot_active(state):
                    fuzz_words = list(_PIVOT_CLOSE_ENDPOINTS)
                fuzz_action = self._build_sandbox_fuzz(base_url, state, words=fuzz_words)
                if fuzz_action is not None:
                    cmd = str((fuzz_action.params or {}).get("command") or "")
                    fp2 = str(hash(cmd))
                    if fp2 != str(state.facts.get("research_last_fuzz_fp") or ""):
                        actions.append(
                            CandidateAction(
                                action=fuzz_action,
                                source=self.name,
                                score=26.0,
                                cost=2.2,
                                reason="stuck: deterministic research fuzz of contextual/common endpoints",
                            )
                        )

        actions.sort(key=lambda c: (c.score, -c.cost), reverse=True)
        return actions[:5]

    def _build_sandbox_fuzz(self, base_url: str, state: State, words: Optional[List[str]] = None) -> Optional[Action]:
        if words is None:
            words = []

            for p, _reason, tags_list, _bonus in _extract_contextual_candidates(state)[:16]:
                try:
                    path = urlparse(p).path if (p.startswith("http://") or p.startswith("https://")) else p
                except Exception:
                    path = p
                if not isinstance(path, str) or not path:
                    continue
                if _is_hard_asset(path):
                    continue
                if _is_soft_asset(path) and "asset-context" not in (tags_list or []):
                    continue
                words.append(path if path.startswith("/") else ("/" + path))

            for p in _FALLBACK_ENDPOINTS:
                words.append(p)

        seen = set()
        words2: List[str] = []
        for w in words:
            if w in seen:
                continue
            if _is_hard_asset(w) or _is_soft_asset(w):
                continue
            seen.add(w)
            words2.append(w)
            if len(words2) >= 18:
                break

        if not words2:
            return None

        script = r"""
set -euo pipefail

BASE="$1"

python - "$BASE" "$@" <<'PY'
import json, subprocess, sys

base = sys.argv[1].rstrip("/")
paths = sys.argv[2:]
hits = []
codes = {}

def curl_head(url: str) -> int:
    try:
        p = subprocess.run(
            ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "-I", url],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
            text=True,
        )
        s = (p.stdout or "").strip()
        if s.isdigit():
            return int(s)
    except Exception:
        return 0
    return 0

for path in paths:
    url = base + path
    code = curl_head(url)
    if code:
        codes[path] = code
    if code in (200, 204, 301, 302, 307, 308, 401, 403):
        hits.append(path)

print(json.dumps({"paths": hits[:200], "codes": codes}, ensure_ascii=False))
PY
""".strip()

        cmd = f"{script}\n{_sh_quote(base_url)} " + " ".join(_sh_quote(w) for w in words2)
        return Action(
            type=ActionType.SHELL,
            params={"command": cmd},
            timeout_s=60,
            tags=["sandbox", "research", "fuzz"],
        )