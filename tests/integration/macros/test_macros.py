from __future__ import annotations

import pytest

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.macros.base import MacroExecutor
from penage.macros.follow_authenticated_branch import FollowAuthenticatedBranchMacro
from penage.macros.probe_resource_family import ProbeResourceFamilyMacro
from penage.macros.replay_auth_session import ReplayAuthSessionMacro


class DummyTools:
    def __init__(self) -> None:
        self.urls: list[str] = []

    async def run(self, action: Action) -> Observation:
        url = str((action.params or {}).get("url") or "")
        self.urls.append(url)

        if url.endswith("/login"):
            return Observation(
                ok=True,
                data={
                    "status_code": 302,
                    "url": url,
                    "headers": {"location": "/dashboard", "set-cookie": "sid=1"},
                    "text_excerpt": "redirect",
                    "text_full": "redirect",
                },
            )
        if url.endswith("/dashboard"):
            return Observation(
                ok=True,
                data={
                    "status_code": 200,
                    "url": url,
                    "headers": {"content-type": "text/html"},
                    "text_excerpt": '<html><a href="/orders">orders</a></html>',
                    "text_full": '<html><a href="/orders">orders</a></html>',
                    "paths": ["/orders"],
                },
            )
        if "/order/100/receipt" in url:
            return Observation(
                ok=True,
                data={
                    "status_code": 200,
                    "url": url,
                    "headers": {"content-type": "text/html"},
                    "text_excerpt": "Receipt Order ID 100",
                    "text_full": "Receipt Order ID 100",
                },
            )
        return Observation(
            ok=True,
            data={
                "status_code": 404,
                "url": url,
                "headers": {"content-type": "text/html"},
                "text_excerpt": "not found",
                "text_full": "not found",
            },
        )


@pytest.mark.asyncio
async def test_replay_auth_session_macro_replays_login_and_records_hits(tmp_path):
    tools = DummyTools()
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="macro")
    executor = MacroExecutor()
    executor.register(ReplayAuthSessionMacro())

    action = Action(
        type=ActionType.MACRO,
        params={
            "name": "replay_auth_session",
            "args": {
                "base_url": "http://localhost",
                "login_action": {"method": "POST", "url": "http://localhost/login", "data": {"u": "a"}},
                "followup_paths": ["/dashboard", "/orders"],
            },
        },
    )

    obs = await executor.run(action, state=State(), step=1, tools=tools, tracer=tracer)

    assert obs.ok is True
    assert obs.data["session_established"] is True
    assert obs.data["login"]["status"] == 302
    assert obs.data["meaningful_hits"][0]["path"] == "/dashboard"
    assert "http://localhost/login" in tools.urls


@pytest.mark.asyncio
async def test_follow_authenticated_branch_macro_filters_assets_and_recommends_hits(tmp_path):
    tools = DummyTools()
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="macro")
    macro = FollowAuthenticatedBranchMacro()

    obs = await macro.run(
        args={"base_url": "http://localhost", "paths": ["/dashboard", "/static/app.js", "/orders"]},
        ctx=type("Ctx", (), {"tools": tools, "state": State(), "step": 2, "tracer": tracer})(),
    )

    assert obs.ok is True
    assert obs.data["hits"][0]["path"] == "/dashboard"
    assert all(not p.endswith("app.js") for p in obs.data["paths"])
    assert obs.data["recommended_next"][0]["url"] == "http://localhost/dashboard"


@pytest.mark.asyncio
async def test_probe_resource_family_macro_expands_family_paths(tmp_path):
    tools = DummyTools()
    tracer = JsonlTracer(tmp_path / "trace.jsonl", episode_id="macro")
    macro = ProbeResourceFamilyMacro()

    obs = await macro.run(
        args={"base_url": "http://localhost", "seed_path": "/order/<id>/receipt", "ids": ["100"], "family_kind": "order"},
        ctx=type("Ctx", (), {"tools": tools, "state": State(), "step": 3, "tracer": tracer})(),
    )

    assert obs.ok is True
    assert obs.data["stats"]["ids_total"] == 1
    assert any(item["path"] == "/order/100/receipt" for item in obs.data["hits"])
    assert any(url.endswith("/order/100/receipt") for url in tools.urls)