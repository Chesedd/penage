from __future__ import annotations

import pytest

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.tools.runner import ToolRunner


class FakeHttpBackend:
    def __init__(self) -> None:
        self.actions: list[Action] = []
        self.closed = False

    async def run(self, action: Action) -> Observation:
        self.actions.append(action)
        return Observation(ok=True, data={"transport": "fake-http"})

    async def aclose(self) -> None:
        self.closed = True


class FakeSandboxTool:
    def __init__(self) -> None:
        self.actions: list[Action] = []
        self.closed = False

    async def run(self, action: Action) -> Observation:
        self.actions.append(action)
        return Observation(ok=True, data={"transport": "fake-sandbox"})

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_tool_runner_routes_http_to_http_backend():
    http_backend = FakeHttpBackend()
    sandbox_tool = FakeSandboxTool()
    runner = ToolRunner(http_backend=http_backend, sandbox_tool=sandbox_tool)

    action = Action(type=ActionType.HTTP, params={"method": "GET", "url": "http://localhost/"})
    obs = await runner.run(action)

    assert obs.ok is True
    assert http_backend.actions == [action]
    assert sandbox_tool.actions == []


@pytest.mark.asyncio
async def test_tool_runner_routes_shell_to_sandbox_tool_and_closes_both():
    http_backend = FakeHttpBackend()
    sandbox_tool = FakeSandboxTool()
    runner = ToolRunner(http_backend=http_backend, sandbox_tool=sandbox_tool)

    action = Action(type=ActionType.SHELL, params={"command": "echo ok"})
    obs = await runner.run(action)

    assert obs.ok is True
    assert sandbox_tool.actions == [action]

    await runner.aclose()
    assert http_backend.closed is True
    assert sandbox_tool.closed is True