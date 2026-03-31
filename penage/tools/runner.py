from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

import httpx

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.sandbox.base import Sandbox
from penage.sandbox.null import NullSandbox
from penage.tools.curl_http_tool import CurlHttpTool
from penage.tools.http_backend import HttpBackend
from penage.tools.http_tool import HttpTool
from penage.tools.sandbox_tool import SandboxTool


@dataclass(slots=True)
class ToolRunner:
    http_backend: HttpBackend
    sandbox_tool: SandboxTool

    async def aclose(self) -> None:
        try:
            await self.http_backend.aclose()
        except Exception:
            pass

        try:
            await self.sandbox_tool.aclose()
        except Exception:
            pass

    @classmethod
    def create_default(
        cls,
        *,
        allowed_hosts: Optional[Iterable[str]] = None,
        http_client: Optional[httpx.AsyncClient] = None,
        sandbox: Optional[Sandbox] = None,
        use_curl_http: bool = False,
    ) -> "ToolRunner":
        client = http_client or httpx.AsyncClient()
        sb = sandbox or NullSandbox()
        sandbox_tool = SandboxTool(sandbox=sb)

        http_backend: HttpBackend
        if use_curl_http:
            http_backend = CurlHttpTool.create_default(sb, allowed_hosts=allowed_hosts)
        else:
            http_backend = HttpTool.create_default(client, allowed_hosts=allowed_hosts)

        return cls(http_backend=http_backend, sandbox_tool=sandbox_tool)

    async def run(self, action: Action) -> Observation:
        if action.type == ActionType.HTTP:
            return await self.http_backend.run(action)

        if action.type in (ActionType.SHELL, ActionType.PYTHON):
            return await self.sandbox_tool.run(action)

        if action.type == ActionType.NOTE:
            return Observation(ok=True, data={"note": action.params})

        return Observation(ok=False, error=f"Unsupported action type: {action.type}")