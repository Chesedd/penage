from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from penage.core.observations import Observation
from penage.macros.base import MacroExecutionContext
from penage.macros.probe_support import (
    body_excerpt,
    coerce_http_action,
    extract_location,
    extract_set_cookie,
    extract_status,
    path_of,
    probe_get_paths,
    run_macro_http_action,
)


DEFAULT_FOLLOWUP_PATHS = ["/dashboard", "/orders", "/profile", "/account"]


def _looks_meaningful(obs: Observation, path: str) -> bool:
    if not obs.ok:
        return False
    status = extract_status(obs)
    return status in (200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403)


@dataclass(slots=True)
class ReplayAuthSessionMacro:
    name: str = "replay_auth_session"

    async def run(self, *, args: Dict[str, Any], ctx: MacroExecutionContext) -> Observation:
        login_spec = args.get("login_action")
        if not isinstance(login_spec, dict):
            return Observation(ok=False, error="macro_missing_login_action")

        login_action = coerce_http_action(login_spec)
        base_url = str(args.get("base_url") or ctx.state.base_url or "")
        followup_paths = args.get("followup_paths") or list(DEFAULT_FOLLOWUP_PATHS)
        if not isinstance(followup_paths, list):
            followup_paths = list(DEFAULT_FOLLOWUP_PATHS)

        login_obs = await run_macro_http_action(ctx=ctx, macro_name=self.name, action=login_action)
        login_status = extract_status(login_obs)
        login_location = extract_location(login_obs)
        login_set_cookie = extract_set_cookie(login_obs)

        paths = []
        if login_location:
            login_path = path_of(login_location)
            if login_path:
                paths.append(login_path if login_path.startswith("/") else f"/{login_path}")

        probe_result = await probe_get_paths(
            ctx=ctx,
            macro_name=self.name,
            base_url=base_url,
            paths=followup_paths[:8],
            tags=["macro", "followup", "auth"],
            timeout_s=20,
            meaningful_fn=_looks_meaningful,
            include_extra_paths=False,
            recommended_reason="meaningful authenticated follow-up hit",
            recommended_limit=8,
            path_limit=20,
        )
        paths.extend(probe_result.paths)

        session_established = (
            (login_status in (301, 302, 303, 307, 308) and bool(login_location))
            or login_set_cookie
            or any(int(x.get("status") or 0) == 200 for x in probe_result.hits)
        )

        result = {
            "macro_name": self.name,
            "session_established": session_established,
            "login": {
                "status": login_status,
                "location": login_location,
                "set_cookie": login_set_cookie,
                "excerpt": body_excerpt(login_obs, limit=160),
            },
            "followups": probe_result.hits[:8] + probe_result.misses[:8],
            "meaningful_hits": probe_result.hits[:8],
            "paths": probe_result.paths[:20],
            "stats": {
                "followups_total": len(probe_result.hits) + len(probe_result.misses),
                "meaningful_hits_total": len(probe_result.hits),
            },
        }

        return Observation(ok=True, data=result)