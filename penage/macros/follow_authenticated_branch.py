from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from penage.core.observations import Observation
from penage.macros.base import MacroExecutionContext
from penage.macros.probe_support import body_excerpt, extract_status, normalized_probe_paths, probe_get_paths


DEFAULT_PATHS = ["/dashboard", "/orders", "/profile", "/account"]


def _looks_login_gate(obs: Observation, path: str) -> bool:
    low_path = str(path or "").lower()
    if low_path not in ("/dashboard", "/orders", "/profile", "/account"):
        return False

    excerpt = body_excerpt(obs, limit=500).lower()
    title_login = "<title>login" in excerpt or "login - " in excerpt
    username_field = 'name="username"' in excerpt
    password_field = 'type="password"' in excerpt
    has_logout = "logout" in excerpt
    has_welcome = "welcome" in excerpt

    return (title_login or (username_field and password_field)) and not has_logout and not has_welcome


def _meaningful(obs: Observation, path: str) -> bool:
    if not obs.ok:
        return False
    status = extract_status(obs)
    if status in (301, 302, 303, 307, 308, 401, 403):
        return True
    if status in (200, 201, 202, 204) and not _looks_login_gate(obs, path):
        return True
    return False


@dataclass(slots=True)
class FollowAuthenticatedBranchMacro:
    name: str = "follow_authenticated_branch"

    async def run(self, *, args: Dict[str, Any], ctx: MacroExecutionContext) -> Observation:
        base_url = str(args.get("base_url") or ctx.state.base_url or "")
        raw_paths = args.get("paths") or DEFAULT_PATHS
        if not isinstance(raw_paths, list):
            raw_paths = list(DEFAULT_PATHS)

        paths = normalized_probe_paths(raw_paths[:12], limit=12)
        if not paths:
            return Observation(ok=False, error="macro_no_followup_paths")

        result = await probe_get_paths(
            ctx=ctx,
            macro_name=self.name,
            base_url=base_url,
            paths=paths,
            tags=["macro", "followup", "auth"],
            timeout_s=20,
            meaningful_fn=_meaningful,
            include_extra_paths=True,
            recommended_reason="meaningful authenticated follow-up hit",
            recommended_limit=8,
            path_limit=30,
        )

        return Observation(
            ok=True,
            data={
                "macro_name": self.name,
                "hits": result.hits[:12],
                "misses": result.misses[:12],
                "paths": result.paths[:30],
                "recommended_next": result.recommended_next[:8],
                "stats": {
                    "hits_total": len(result.hits),
                    "misses_total": len(result.misses),
                    "paths_total": len(paths),
                },
            },
        )