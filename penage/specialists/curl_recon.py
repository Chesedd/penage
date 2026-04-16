from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.specialists.base import SpecialistConfig


@dataclass(slots=True)
class CurlReconSpecialist:
    name: str = "curl_recon"

    max_runs: int = 5
    cooldown_steps: int = 3
    min_text_len_hint: int = 250

    def propose(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        _ = config

        base_url = state.base_url
        if not base_url:
            return []

        if state.tool_calls_sandbox <= 0:
            return []

        if state.curl_recon.runs >= self.max_runs:
            return []

        if state.curl_recon.last_step and state.orch_step and (state.orch_step - state.curl_recon.last_step) < self.cooldown_steps:
            return []

        if state.curl_recon.useless_streak >= 2:
            return []

        url = self._choose_target_url(state, base_url=base_url)
        if not url:
            return []

        if self._looks_like_asset(url):
            return []

        last_target = state.curl_recon.last_target_url
        if last_target and last_target == url:
            return []

        cj = "/tmp/penage_cookies.txt"
        raw = "/tmp/penage_recon_raw.txt"

        py = r"""
import re, json, sys

raw = open(sys.argv[1], "r", errors="replace").read()

parts = raw.split("\r\n\r\n", 1)
if len(parts) == 2:
    body = parts[1]
else:
    parts = raw.split("\n\n", 1)
    body = parts[1] if len(parts) == 2 else raw

paths = set()

for m in re.finditer(r'\b(?:href|src|action|data-url|data-href|data-action)\s*=\s*["\']([^"\']+)["\']', body, re.I):
    v = m.group(1).strip()
    if not v or v.startswith("#"):
        continue
    if v.lower().startswith(("javascript:", "mailto:", "tel:")):
        continue
    paths.add(v)

for m in re.finditer(r"['\"](/[^'\"\s]{1,300})['\"]", body):
    v = m.group(1)
    if v.lower().endswith((".png",".jpg",".jpeg",".gif",".svg",".ico",".woff",".woff2",".ttf",".eot")):
        continue
    paths.add(v)

ids = []
for m in re.finditer(r"\b\d{4,}\b", body):
    ids.append(m.group(0))
seen = set()
ids2 = []
for x in ids:
    if x in seen:
        continue
    seen.add(x)
    ids2.append(x)
ids2 = ids2[:40]

paths_sorted = sorted(paths)[:500]
asset_like = 0
for p in paths_sorted:
    low = (p or "").lower()
    if low.startswith("/static/") or low.endswith((".css",".js",".map",".png",".jpg",".jpeg",".gif",".svg",".ico",".woff",".woff2",".ttf",".eot")):
        asset_like += 1

out = {
  "paths": paths_sorted,
  "ids": ids2,
  "stats": {"paths_total": len(paths_sorted), "asset_like": asset_like}
}
print(json.dumps(out, ensure_ascii=False))
""".strip()

        cmd = (
            "set -euo pipefail\n"
            f"URL={_sh_quote(url)}\n"
            f"CJ={_sh_quote(cj)}\n"
            f"RAW={_sh_quote(raw)}\n"
            'curl -i -sS --compressed -L -b "$CJ" -c "$CJ" "$URL" > "$RAW"\n'
            f"python - \"$RAW\" <<'PY'\n{py}\nPY\n"
        )

        action = Action(
            type=ActionType.SHELL,
            params={"command": cmd},
            timeout_s=60,
            tags=["sandbox", "curl", "recon"],
        )

        state.curl_recon.last_target_url = url

        return [
            CandidateAction(
                action=action,
                source=self.name,
                score=11.5,
                cost=2.0,
                reason=f"Sandbox curl recon on strongest target page: {url}",
            )
        ]

    def _choose_target_url(self, state: State, *, base_url: str) -> Optional[str]:
        candidates: List[str] = []

        best_url = str(getattr(state, "best_http_url", "") or "")
        last_url = str(getattr(state, "last_http_url", "") or "")

        if best_url:
            candidates.append(best_url)
        if last_url and last_url != best_url:
            candidates.append(last_url)

        for item in reversed(state.recent_http_memory[-state.recent_http_memory_limit :]):
            if not isinstance(item, dict):
                continue
            u = item.get("url")
            if isinstance(u, str) and u:
                candidates.append(u)

        if not candidates:
            candidates.append(base_url)

        for url in candidates:
            try:
                p = urlparse(url)
            except Exception:
                continue
            if p.scheme not in ("http", "https"):
                continue
            if self._looks_like_asset(url):
                continue

            if url == best_url and isinstance(getattr(state, "best_http_text_full", None), str):
                if len(getattr(state, "best_http_text_full", "") or "") >= self.min_text_len_hint:
                    return url

            if url == last_url and isinstance(getattr(state, "last_http_text_full", None), str):
                if len(getattr(state, "last_http_text_full", "") or "") >= self.min_text_len_hint:
                    return url

            # recent memory fallback
            return url

        return None

    def _looks_like_asset(self, url: str) -> bool:
        try:
            path = (urlparse(url).path or "").lower()
        except Exception:
            return False
        return path.endswith(
            (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot")
        )


def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"