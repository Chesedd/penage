from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from penage.core.observations import Observation
from penage.macros.base import MacroExecutionContext
from penage.macros.probe_support import body_excerpt, extract_status, normalized_probe_paths, probe_get_paths


DEFAULT_SUFFIXES = {
    "order": ["", "/details", "/status", "/archive", "/invoice"],
    "user": ["", "/profile", "/settings"],
    "generic": ["", "/details", "/status", "/download", "/archive"],
}


def _meaningful_hit(obs: Observation, path: str) -> bool:
    if not obs.ok:
        return False
    status = extract_status(obs)
    if status in (301, 302, 303, 307, 308, 401, 403):
        return True
    if status in (200, 201, 202, 204):
        excerpt = body_excerpt(obs, limit=300).lower()
        if "not found" in excerpt or "404" in excerpt:
            return False
        if "/receipt" in path and "receipt" in excerpt and "order id" in excerpt:
            return True
        if len(excerpt.strip()) >= 40:
            return True
    return False


def build_family_paths(seed_path: str, ids: List[str], family_kind: str) -> List[str]:
    seed = str(seed_path or "").strip()
    if not seed:
        return []

    suffixes = list(DEFAULT_SUFFIXES.get(family_kind, DEFAULT_SUFFIXES["generic"]))
    out: List[str] = []
    seen = set()

    norm_seed = seed if seed.startswith("/") else "/" + seed
    if "<id>" in norm_seed:
        for ident in ids:
            base = norm_seed.replace("<id>", str(ident))
            for suf in suffixes:
                p = base + suf
                if p not in seen:
                    seen.add(p)
                    out.append(p)
        return out

    parts = [x for x in norm_seed.split("/") if x]
    if len(parts) >= 2 and parts[1].isdigit():
        root = f"/{parts[0]}/<id>"
        for ident in ids:
            base = root.replace("<id>", str(ident))
            for suf in suffixes:
                p = base + suf
                if p not in seen:
                    seen.add(p)
                    out.append(p)
        return out

    if norm_seed not in seen:
        out.append(norm_seed)
    return out


@dataclass(slots=True)
class ProbeResourceFamilyMacro:
    name: str = "probe_resource_family"

    async def run(self, *, args: Dict[str, Any], ctx: MacroExecutionContext) -> Observation:
        base_url = str(args.get("base_url") or ctx.state.facts.get("base_url") or "")
        seed_path = str(args.get("seed_path") or "").strip()
        family_kind = str(args.get("family_kind") or "generic").strip().lower()

        ids_raw = args.get("ids") or []
        ids: List[str] = []
        seen_ids = set()
        if isinstance(ids_raw, list):
            for x in ids_raw:
                s = str(x or "").strip()
                if not s or s in seen_ids:
                    continue
                seen_ids.add(s)
                ids.append(s)

        if not seed_path:
            return Observation(ok=False, error="macro_missing_seed_path")

        paths = normalized_probe_paths(build_family_paths(seed_path, ids, family_kind), limit=24)
        if not paths:
            return Observation(ok=False, error="macro_no_family_paths")

        result = await probe_get_paths(
            ctx=ctx,
            macro_name=self.name,
            base_url=base_url,
            paths=paths,
            tags=["macro", "family-probe"],
            timeout_s=25,
            meaningful_fn=_meaningful_hit,
            include_extra_paths=False,
            recommended_reason="meaningful family probe hit",
            recommended_limit=8,
            path_limit=40,
        )

        return Observation(
            ok=True,
            data={
                "macro_name": self.name,
                "hits": result.hits[:16],
                "misses": result.misses[:16],
                "paths": result.paths[:40],
                "recommended_next": result.recommended_next[:8],
                "stats": {
                    "hits_total": len(result.hits),
                    "misses_total": len(result.misses),
                    "paths_total": len(paths),
                    "ids_total": len(ids),
                },
            },
        )