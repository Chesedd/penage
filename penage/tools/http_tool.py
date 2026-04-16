from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, Optional

import httpx

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.tools.http_support import build_http_observation, http_action_error, resolve_allowed_hosts


@dataclass(slots=True)
class HttpTool:
    client: httpx.AsyncClient
    allowed_hosts: set[str]

    @classmethod
    def create_default(cls, client: httpx.AsyncClient, allowed_hosts: Optional[Iterable[str]] = None) -> "HttpTool":
        return cls(client=client, allowed_hosts=resolve_allowed_hosts(allowed_hosts))

    async def aclose(self) -> None:
        await self.client.aclose()

    async def run(self, action: Action) -> Observation:
        params = action.params or {}
        method = params.get("method")
        url = params.get("url")

        err = http_action_error(method=method, url=url, allowed_hosts=self.allowed_hosts)
        if err:
            return Observation(ok=False, error=err)

        method = str(method).upper()
        url = str(url)
        headers = params.get("headers")
        qparams = params.get("params")
        data = params.get("data")
        json_body = params.get("json")
        cookies = params.get("cookies")
        follow_redirects = params.get("follow_redirects", True)

        timeout_s = params.get("timeout_s")
        if timeout_s is None:
            timeout_s = action.timeout_s
        if timeout_s is None:
            timeout_s = 30.0

        start = time.perf_counter()
        try:
            resp = await self.client.request(
                method=method,
                url=url,
                headers=headers,
                params=qparams,
                data=data,
                json=json_body,
                cookies=cookies,
                follow_redirects=bool(follow_redirects),
                timeout=timeout_s,
            )

            text = resp.text if resp.text is not None else ""
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return build_http_observation(
                elapsed_ms=elapsed_ms,
                status_code=resp.status_code,
                url=str(resp.url),
                headers=dict(resp.headers),
                text=text,
                transport="httpx",
            )
        except httpx.TimeoutException:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return Observation(ok=False, elapsed_ms=elapsed_ms, error=f"HTTP timeout after {timeout_s}s")
        except Exception as e:  # LEGACY: catch-all at HTTP boundary
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return Observation(ok=False, elapsed_ms=elapsed_ms, error=f"HTTP request failed: {e}")