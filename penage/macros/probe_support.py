from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import urljoin, urlparse

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.macros.base import MacroExecutionContext


BLOCKED_EXT = (
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


MeaningfulFn = Callable[[Observation, str], bool]


def path_of(url: str) -> str:
    try:
        return (urlparse(url).path or "").strip()
    except Exception:
        return str(url or "").strip()


def is_asset_path(path: str) -> bool:
    low = str(path or "").lower()
    return low.startswith("/static/") or low.endswith(BLOCKED_EXT)


def extract_status(obs: Observation) -> int:
    if not isinstance(obs.data, dict):
        return 0
    try:
        return int(obs.data.get("status_code") or 0)
    except Exception:
        return 0


def extract_location(obs: Observation) -> str:
    if not isinstance(obs.data, dict):
        return ""
    headers = obs.data.get("headers") or {}
    if isinstance(headers, dict):
        return str(headers.get("location") or "")
    return ""


def extract_set_cookie(obs: Observation) -> bool:
    if not isinstance(obs.data, dict):
        return False
    headers = obs.data.get("headers") or {}
    if isinstance(headers, dict):
        return bool(headers.get("set-cookie"))
    return False


def body_excerpt(obs: Observation, limit: int = 180) -> str:
    if not isinstance(obs.data, dict):
        return ""
    text = str(obs.data.get("text_full") or obs.data.get("text_excerpt") or "")
    return text[:limit]


def dedup_paths(paths: Iterable[str], *, limit: int) -> list[str]:
    out: list[str] = []
    seen = set()
    for p in paths:
        s = str(p or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= limit:
            break
    return out


def normalized_probe_paths(raw_paths: Iterable[Any], *, limit: int) -> list[str]:
    paths: list[str] = []
    seen = set()
    for raw in raw_paths:
        if not isinstance(raw, str):
            continue
        p = raw.strip()
        if not p:
            continue
        if not p.startswith("/"):
            p = "/" + p
        if p in seen or is_asset_path(p):
            continue
        seen.add(p)
        paths.append(p)
        if len(paths) >= limit:
            break
    return paths


def coerce_http_action(spec: Dict[str, Any]) -> Action:
    method = str(spec.get("method") or "GET").upper()
    url = str(spec.get("url") or "")
    params = {"method": method, "url": url}

    data = spec.get("data")
    if isinstance(data, dict) and data:
        params["data"] = data

    query_params = spec.get("params")
    if isinstance(query_params, dict) and query_params:
        params["params"] = query_params

    headers = spec.get("headers")
    if isinstance(headers, dict) and headers:
        params["headers"] = headers

    return Action(
        type=ActionType.HTTP,
        params=params,
        timeout_s=float(spec.get("timeout_s") or 30),
        tags=list(spec.get("tags") or []),
    )


async def run_macro_http_action(
    *,
    ctx: MacroExecutionContext,
    macro_name: str,
    action: Action,
) -> Observation:
    obs = await ctx.tools.run(action)
    if ctx.tracer is not None:
        ctx.tracer.record_macro_substep(macro_name, action, obs, step=ctx.step)
    return obs


@dataclass(frozen=True, slots=True)
class ProbeItem:
    path: str
    status: int
    location: str
    excerpt: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "location": self.location,
            "excerpt": self.excerpt,
        }


@dataclass(frozen=True, slots=True)
class ProbeResult:
    hits: List[Dict[str, Any]]
    misses: List[Dict[str, Any]]
    paths: List[str]
    recommended_next: List[Dict[str, Any]]


async def probe_get_paths(
    *,
    ctx: MacroExecutionContext,
    macro_name: str,
    base_url: str,
    paths: Iterable[str],
    tags: Optional[list[str]] = None,
    timeout_s: float = 20,
    meaningful_fn: MeaningfulFn,
    include_extra_paths: bool = False,
    recommended_reason: str,
    recommended_limit: int = 8,
    path_limit: int = 40,
) -> ProbeResult:
    hits: list[dict[str, Any]] = []
    misses: list[dict[str, Any]] = []
    out_paths: list[str] = []

    for path in paths:
        url = urljoin(base_url, path) if base_url else path
        action = Action(
            type=ActionType.HTTP,
            params={"method": "GET", "url": url},
            timeout_s=timeout_s,
            tags=list(tags or []),
        )
        obs = await run_macro_http_action(ctx=ctx, macro_name=macro_name, action=action)

        location = extract_location(obs)
        item = ProbeItem(
            path=path,
            status=extract_status(obs),
            location=location,
            excerpt=body_excerpt(obs),
        ).to_dict()

        out_paths.append(path)
        if location:
            loc_path = path_of(location)
            if loc_path:
                out_paths.append(loc_path if loc_path.startswith("/") else f"/{loc_path}")

        if meaningful_fn(obs, path):
            hits.append(item)
        else:
            misses.append(item)

        if include_extra_paths and isinstance(obs.data, dict):
            extra_paths = obs.data.get("paths") or []
            if isinstance(extra_paths, list):
                for p in extra_paths:
                    if isinstance(p, str) and p and not is_asset_path(p):
                        out_paths.append(p if p.startswith("/") else f"/{p}")

    deduped_paths = dedup_paths(out_paths, limit=path_limit)
    recommended_next: list[dict[str, Any]] = []
    for hit in hits[:recommended_limit]:
        path = str(hit.get("path") or "").strip()
        if not path:
            continue
        url = urljoin(base_url, path) if base_url else path
        recommended_next.append(
            {
                "type": "http",
                "method": "GET",
                "url": url,
                "reason": recommended_reason,
            }
        )

    return ProbeResult(
        hits=hits,
        misses=misses,
        paths=deduped_paths,
        recommended_next=recommended_next[:recommended_limit],
    )