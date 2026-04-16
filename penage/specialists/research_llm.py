from __future__ import annotations

import json
import re
import textwrap
from dataclasses import dataclass
from typing import ClassVar, List, Optional
from urllib.parse import urljoin, urlparse

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.llm.base import LLMClient, LLMMessage
from penage.specialists.base import SpecialistConfig, AsyncSpecialist
from penage.utils.jsonx import parse_json_object


_ID_RE = re.compile(r"\b\d{3,}\b")
_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.I,
)

_HARD_ASSET_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot")
_SOFT_ASSET_EXT = (".css", ".js", ".map")


def _is_stuck(st: State, *, threshold: int) -> bool:
    used = int(st.http_requests_used or 0)
    if used < 3:
        return False
    streak = st.no_new_paths_streak
    return streak >= threshold


def _safe_url(base_url: str, path_or_url: str) -> Optional[str]:
    if not path_or_url:
        return None
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        u = path_or_url
    else:
        u = urljoin(base_url, path_or_url if path_or_url.startswith("/") else ("/" + path_or_url))
    try:
        p = urlparse(u)
    except Exception:
        return None
    if p.scheme not in ("http", "https"):
        return None
    return u


def _clip(s: str, n: int) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[:n] + "\n<...clipped...>\n"


def _sh_quote(s: str) -> str:
    return "'" + str(s).replace("'", "'\"'\"'") + "'"


def _extract_id_candidates(text: str) -> List[str]:
    if not text:
        return []
    ids: list[str] = []
    for m in _UUID_RE.finditer(text):
        ids.append(m.group(0))
    for m in _ID_RE.finditer(text):
        ids.append(m.group(0))

    seen = set()
    out: list[str] = []
    for x in ids:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out[:30]


def _path_of(path_or_url: str) -> str:
    try:
        return (urlparse(path_or_url).path or path_or_url or "").lower()
    except Exception:
        return str(path_or_url or "").lower()


def _is_hard_asset_path(path_or_url: str) -> bool:
    return _path_of(path_or_url).endswith(_HARD_ASSET_EXT)


def _is_soft_asset_path(path_or_url: str) -> bool:
    return _path_of(path_or_url).endswith(_SOFT_ASSET_EXT)


def _xss_or_js_context(state: State) -> bool:
    hay = [
        str(getattr(state, "best_http_url", "") or "").lower(),
        str(getattr(state, "last_http_url", "") or "").lower(),
        str(getattr(state, "best_http_text_full", "") or "").lower(),
        str(getattr(state, "last_http_text_full", "") or "").lower(),
    ]
    blob = "\n".join(hay)
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


@dataclass(slots=True)
class ResearchLLMSpecialist(AsyncSpecialist):
    name: ClassVar[str] = "research_llm"

    llm: LLMClient

    stuck_threshold: int = 2
    max_http_hypotheses: int = 2

    enable_sandbox_fuzz: bool = True
    max_fuzz_paths: int = 18

    max_fuzz_runs: int = 3
    fuzz_cooldown_steps: int = 4

    cooldown_steps: int = 1

    score_http: float = 26.0
    score_fuzz: float = 27.0

    llm_timeout_hint_s: float = 18.0

    async def propose_async(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        _ = config

        base_url = state.base_url
        if not base_url:
            return []

        if not _is_stuck(state, threshold=self.stuck_threshold):
            return []

        curr_step = state.orch_step
        last_step = int(getattr(state, "research_llm_last_step", 0) or 0)
        if curr_step and last_step and (curr_step - last_step) < self.cooldown_steps:
            return []

        allow_contextual_assets = _xss_or_js_context(state)

        best_url = str(getattr(state, "best_http_url", "") or "")
        best_full = getattr(state, "best_http_text_full", None)
        best_full_s = best_full if isinstance(best_full, str) else ""

        last_url = str(state.last_http_url or "")
        last_status = state.last_http_status

        ctx_url = best_url or last_url
        ctx_text = best_full_s or (state.last_http_text_full or "")
        ctx_text_excerpt = _clip(ctx_text, 9000)

        known_paths = sorted(list(state.known_paths))[:140]
        forms = state.last_forms[:4]

        best_ids = list(getattr(state, "best_http_ids", []) or [])
        id_candidates = best_ids[:30] if best_ids else _extract_id_candidates(ctx_text_excerpt)

        prompt = {
            "base_url": base_url,
            "context_http": {
                "url": ctx_url,
                "last_http_url": last_url,
                "last_http_status": last_status,
                "best_http_url": best_url,
                "best_http_score": float(getattr(state, "best_http_score", 0.0) or 0.0),
                "text_full_excerpt": ctx_text_excerpt,
            },
            "signals": {
                "id_candidates": id_candidates,
                "known_paths": known_paths,
                "last_forms": forms,
            },
            "budgets": {
                "http_requests_used": int(state.http_requests_used or 0),
                "total_text_len_seen": int(state.total_text_len_seen or 0),
                "tool_calls_sandbox": int(state.tool_calls_sandbox or 0),
            },
            "task": (
                "We are stuck. Propose next actions that are most likely to reveal new endpoints, "
                "state transitions, or access-controlled resources. "
                "If you see an ID-based URL pattern (e.g. /order/<id>/receipt), instantiate it using id_candidates. "
                "If the context is clearly XSS/JS-heavy, you MAY also propose directly referenced CSS/JS/map assets."
            ),
            "constraints": {
                "max_hypotheses_total": 6,
                "max_http_hypotheses_to_execute": self.max_http_hypotheses,
                "avoid_static_assets": not allow_contextual_assets,
                "allow_contextual_static_assets": allow_contextual_assets,
                "prefer_context": True,
                "generic_only_if_context_weak": True,
                "time_budget_hint_s": self.llm_timeout_hint_s,
            },
            "output_schema": {
                "hypotheses": [
                    {"method": "GET|HEAD", "path": "/path or full url", "why": "short reason", "confidence": 0.0}
                ],
                "fuzz_paths": ["/path1", "/path2"],
                "notes": "optional",
            },
        }

        messages = [
            LLMMessage(
                role="system",
                content=(
                    "You are a research assistant for an automated web pentest agent.\n"
                    "Return ONLY a JSON object.\n"
                    "\n"
                    "Rules:\n"
                    "- Prefer CONTEXT-DERIVED hypotheses from the provided HTML/JS snippet, known paths, and forms.\n"
                    "- If you see URL construction patterns in text (concatenation, format strings, templating), instantiate them.\n"
                    "- Use id_candidates to instantiate any ID-based routes.\n"
                    "- Only if context is weak, propose a SMALL set of generic endpoints.\n"
                    "- Avoid static assets by default.\n"
                    "- Exception: if the page is clearly XSS/JS-heavy, you MAY propose directly referenced CSS/JS/map assets.\n"
                    "- Never propose image/font assets.\n"
                    "- Keep it cheap: propose GET/HEAD only.\n"
                    "\n"
                    "Output schema:\n"
                    "{\n"
                    "  \"hypotheses\": [{\"method\":\"GET|HEAD\",\"path\":\"/path or full url\",\"why\":\"...\",\"confidence\":0..1}],\n"
                    "  \"fuzz_paths\": [\"/path1\", \"/path2\"],\n"
                    "  \"notes\": \"optional\"\n"
                    "}\n"
                ),
            ),
            LLMMessage(role="user", content=json.dumps(prompt, ensure_ascii=False)),
        ]

        state.research_llm_last_step = curr_step

        resp = await self.llm.generate(messages)
        obj = parse_json_object(resp.text) or {}
        if not isinstance(obj, dict):
            state.research_tracking.last_result = {
                "ok": False,
                "error": "invalid_json",
                "text_excerpt": _clip(resp.text or "", 400),
            }
            return []

        hyps = obj.get("hypotheses") or []
        fuzz_paths = obj.get("fuzz_paths") or []
        notes = obj.get("notes")

        hyp_preview = []
        if isinstance(hyps, list):
            for h in hyps[:6]:
                if not isinstance(h, dict):
                    continue
                hyp_preview.append(
                    {
                        "method": str(h.get("method") or "GET").upper(),
                        "path": str(h.get("path") or "")[:240],
                        "why": str(h.get("why") or "")[:240],
                        "confidence": float(h.get("confidence") or 0.0),
                    }
                )

        fuzz_preview = []
        if isinstance(fuzz_paths, list):
            for p in fuzz_paths[: self.max_fuzz_paths]:
                if isinstance(p, str) and p.strip():
                    fuzz_preview.append(p.strip()[:240])

        state.research_tracking.last_result = {
            "ok": True,
            "notes": str(notes or "")[:400],
            "hypotheses": hyp_preview,
            "fuzz_paths": fuzz_preview,
        }

        out: List[CandidateAction] = []

        fuzz_list: List[str] = []
        if isinstance(fuzz_paths, list):
            for p in fuzz_paths:
                if not isinstance(p, str):
                    continue
                p = p.strip()
                if not p:
                    continue
                if not p.startswith("/"):
                    p = "/" + p
                if _is_hard_asset_path(p):
                    continue
                if _is_soft_asset_path(p) and not allow_contextual_assets:
                    continue
                fuzz_list.append(p)
                if len(fuzz_list) >= self.max_fuzz_paths:
                    break

        if not fuzz_list and isinstance(hyps, list):
            for h in hyps:
                if not isinstance(h, dict):
                    continue
                p = str(h.get("path") or "").strip()
                if not p:
                    continue
                if p.startswith("http://") or p.startswith("https://"):
                    try:
                        p = urlparse(p).path or "/"
                    except Exception:
                        continue
                if not p.startswith("/"):
                    p = "/" + p
                if _is_hard_asset_path(p):
                    continue
                if _is_soft_asset_path(p) and not allow_contextual_assets:
                    continue
                fuzz_list.append(p)
                if len(fuzz_list) >= self.max_fuzz_paths:
                    break

        if self.enable_sandbox_fuzz and state.tool_calls_sandbox > 0 and fuzz_list:
            ran = state.research_tracking.fuzz_runs
            if ran < self.max_fuzz_runs:
                last_fuzz_step = state.research_tracking.last_fuzz_step
                if (not last_fuzz_step) or ((curr_step - last_fuzz_step) >= self.fuzz_cooldown_steps):
                    fp2 = "paths:" + "|".join(sorted(fuzz_list))
                    if fp2 != state.research_tracking.last_fuzz_fp:
                        fuzz_action = self._build_sandbox_fuzz(base_url, fuzz_list)
                        out.append(
                            CandidateAction(
                                action=fuzz_action,
                                source=self.name,
                                score=self.score_fuzz,
                                cost=2.3,
                                reason="stuck: sandbox fuzz to cheaply validate many context-derived endpoints (HEAD) and add hits to known_paths",
                            )
                        )

        count = 0
        if isinstance(hyps, list):
            hyps_sorted: list[tuple[float, dict]] = []
            for h in hyps:
                if not isinstance(h, dict):
                    continue
                conf = float(h.get("confidence") or 0.0)
                hyps_sorted.append((conf, h))
            hyps_sorted.sort(key=lambda x: x[0], reverse=True)

            for conf, h in hyps_sorted:
                if count >= self.max_http_hypotheses:
                    break

                method = str(h.get("method") or "GET").upper()
                path = str(h.get("path") or "")
                why = str(h.get("why") or "llm hypothesis").strip()

                if method not in ("GET", "HEAD"):
                    continue

                if _is_hard_asset_path(path):
                    continue
                if _is_soft_asset_path(path) and not allow_contextual_assets:
                    continue

                u = _safe_url(base_url, path)
                if not u:
                    continue

                tags = ["research", "hypothesis", "llm"]
                if _is_soft_asset_path(u):
                    tags.append("asset-context")

                a = Action(
                    type=ActionType.HTTP,
                    params={"method": method, "url": u},
                    timeout_s=30,
                    tags=tags,
                )

                fp = f"{a.type.value}:{json.dumps(a.params, sort_keys=True, ensure_ascii=False, default=str)}"
                if fp in state.visited_actions_fingerprint:
                    continue

                out.append(
                    CandidateAction(
                        action=a,
                        source=self.name,
                        score=self.score_http,
                        cost=1.2 if "asset-context" not in tags else 1.0,
                        reason=f"stuck: LLM hypothesis (conf={conf:.2f}): {why}",
                    )
                )
                count += 1

        out.sort(key=lambda c: c.score, reverse=True)
        return out[:5]

    def _build_sandbox_fuzz(self, base_url: str, paths: List[str]) -> Action:
        paths_json = json.dumps(paths[: self.max_fuzz_paths], ensure_ascii=False)

        py = r"""
import json, os, subprocess, sys

base = sys.argv[1].rstrip("/")
paths = json.loads(os.environ.get("PATHS_JSON", "[]"))

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

OK = {200,201,202,204,301,302,303,307,308,401,403}

for path in paths:
    if not isinstance(path, str):
        continue
    path = path.strip()
    if not path:
        continue
    if not path.startswith("/"):
        path = "/" + path

    url = base + path
    code = curl_head(url)
    if code:
        codes[path] = code
    if code in OK:
        hits.append(path)

print(json.dumps({"paths": hits[:200], "codes": codes}, ensure_ascii=False))
"""

        py = textwrap.dedent(py).strip() + "\n"

        cmd = (
            f"BASE={_sh_quote(base_url)} "
            f"PATHS_JSON={_sh_quote(paths_json)} "
            "python - \"$BASE\" <<'PY'\n"
            f"{py}"
            "PY\n"
        )

        return Action(
            type=ActionType.SHELL,
            params={"command": cmd},
            timeout_s=60,
            tags=["sandbox", "research", "fuzz", "llm"],
        )