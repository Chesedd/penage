from __future__ import annotations

import pytest

from penage.core.actions import Action, ActionType
from penage.sandbox.base import SandboxResult
from penage.tools.curl_http_tool import CurlHttpTool


class FakeSandbox:
    def __init__(self, stdout: str, *, ok: bool = True) -> None:
        self.stdout = stdout
        self.ok = ok
        self.commands: list[str] = []

    async def run_shell(self, *, cmd: str, timeout_s: float, cwd=None, env=None) -> SandboxResult:
        self.commands.append(cmd)
        return SandboxResult(
            ok=self.ok,
            exit_code=0 if self.ok else 1,
            stdout=self.stdout,
            stderr="" if self.ok else "curl failed",
            elapsed_ms=3,
            error=None if self.ok else "curl failed",
        )

    async def run_python(self, *, code: str, timeout_s: float, cwd=None, env=None) -> SandboxResult:
        raise AssertionError("not used")


@pytest.mark.asyncio
async def test_curl_http_tool_parses_last_response_block_and_normalizes_payload():
    raw = (
        "HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n"
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        '<html><body><form action="/submit"></form>FLAG{curl_flag}</body></html>'
    )
    sandbox = FakeSandbox(raw)
    tool = CurlHttpTool.create_default(sandbox, allowed_hosts={"localhost"})
    action = Action(type=ActionType.HTTP, params={"method": "GET", "url": "http://localhost/test"})

    obs = await tool.run(action)

    assert obs.ok is True
    assert obs.data["status_code"] == 200
    assert obs.data["transport"] == "curl"
    assert "/submit" in obs.data["paths"]
    assert obs.data["contains_flag_like"] is True
    assert sandbox.commands, "curl command was not executed"


@pytest.mark.asyncio
async def test_curl_http_tool_returns_transport_error_payload_when_sandbox_fails():
    sandbox = FakeSandbox("", ok=False)
    tool = CurlHttpTool.create_default(sandbox, allowed_hosts={"localhost"})
    action = Action(type=ActionType.HTTP, params={"method": "GET", "url": "http://localhost/test"})

    obs = await tool.run(action)

    assert obs.ok is False
    assert obs.data["transport"] == "curl"
    assert "curl_cmd" in obs.data