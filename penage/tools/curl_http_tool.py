from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, Mapping, Optional
from urllib.parse import urlencode

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.sandbox.base import Sandbox
from penage.tools.http_support import build_http_observation, http_action_error, resolve_allowed_hosts


_DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0 Safari/537.36"
)


@dataclass(slots=True)
class CurlHttpTool:
    sandbox: Sandbox
    allowed_hosts: set[str]
    cookie_jar_path: str = "/tmp/penage_cookies.txt"

    @classmethod
    def create_default(cls, sandbox: Sandbox, allowed_hosts: Optional[Iterable[str]] = None) -> "CurlHttpTool":
        return cls(sandbox=sandbox, allowed_hosts=resolve_allowed_hosts(allowed_hosts))

    async def aclose(self) -> None:
        return None

    async def run(self, action: Action) -> Observation:
        params = action.params or {}
        method = params.get("method")
        url = params.get("url")

        err = http_action_error(method=method, url=url, allowed_hosts=self.allowed_hosts)
        if err:
            return Observation(ok=False, error=err)

        method_u = str(method).upper()
        url = str(url)
        headers = params.get("headers")
        qparams = params.get("params")
        data = params.get("data")
        json_body = params.get("json")
        cookies = params.get("cookies")
        follow_redirects = bool(params.get("follow_redirects", True))

        timeout_s = params.get("timeout_s")
        if timeout_s is None:
            timeout_s = action.timeout_s
        if timeout_s is None:
            timeout_s = 30.0

        eff_url = url
        if isinstance(qparams, Mapping) and qparams:
            qs = urlencode([(str(k), "" if v is None else str(v)) for k, v in qparams.items()])
            joiner = "&" if "?" in eff_url else "?"
            eff_url = eff_url + joiner + qs

        cookie_header = None
        if isinstance(cookies, Mapping) and cookies:
            cookie_header = "; ".join([f"{k}={v}" for k, v in cookies.items()])

        curl_parts: list[str] = []
        curl_parts += ["curl", "-i", "-sS", "--compressed"]
        curl_parts += ["-c", self.cookie_jar_path, "-b", self.cookie_jar_path]

        if follow_redirects and method_u in ("GET", "HEAD"):
            curl_parts += ["-L"]

        if method_u not in ("GET", "POST"):
            curl_parts += ["-X", method_u]

        curl_parts += ["-H", "Expect:"]
        curl_parts += ["-H", f"User-Agent: {_DEFAULT_UA}"]
        curl_parts += ["-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"]
        curl_parts += ["-H", "Accept-Language: en-US,en;q=0.9"]

        if isinstance(headers, Mapping):
            for k, v in headers.items():
                curl_parts += ["-H", f"{k}: {v}"]
        if cookie_header:
            curl_parts += ["-H", f"Cookie: {cookie_header}"]

        if json_body is not None and data is not None:
            data = None

        if json_body is not None:
            import json as _json

            payload = _json.dumps(json_body)
            curl_parts += ["-H", "Content-Type: application/json", "--data-raw", payload]
        elif data is not None:
            if isinstance(data, Mapping):
                payload = urlencode([(str(k), "" if v is None else str(v)) for k, v in data.items()])
                curl_parts += ["--data-raw", payload]
            else:
                curl_parts += ["--data-raw", str(data)]

        curl_parts += ["--max-time", str(float(timeout_s))]
        curl_parts += [eff_url]
        cmd = _shell_join(curl_parts)

        t0 = time.perf_counter()
        res = await self.sandbox.run_shell(cmd=cmd, timeout_s=float(timeout_s))
        elapsed_ms = int((time.perf_counter() - t0) * 1000)

        if not res.ok:
            return Observation(
                ok=False,
                elapsed_ms=elapsed_ms,
                error=f"curl failed: {res.stderr or res.error or 'unknown'}",
                data={"transport": "curl", "curl_cmd": cmd},
            )

        raw = res.stdout or ""
        status_code, headers_out, body = _split_http_response(raw)
        if status_code is None:
            status_code = 0

        extra: dict[str, object] = {}
        if int(status_code) >= 400:
            extra["curl_cmd"] = cmd

        return build_http_observation(
            elapsed_ms=elapsed_ms,
            status_code=int(status_code),
            url=eff_url,
            headers=headers_out,
            text=body,
            transport="curl",
            extra=extra,
        )


def _shell_join(parts: list[str]) -> str:
    def q(s: str) -> str:
        return "'" + s.replace("'", "'\"'\"'") + "'"

    return " ".join(q(p) for p in parts)


import re
_STATUS_RE = re.compile(r"^HTTP/\d+(?:\.\d+)?\s+(\d{3})\b", re.MULTILINE)


def _split_http_response(raw: str) -> tuple[Optional[int], dict[str, str], str]:
    if not raw:
        return None, {}, ""

    statuses = list(_STATUS_RE.finditer(raw))
    if not statuses:
        return None, {}, raw

    last = statuses[-1]
    status_code = int(last.group(1))

    start = last.start()
    rest = raw[start:]
    sep = "\r\n\r\n"
    if sep in rest:
        head, body = rest.split(sep, 1)
    else:
        sep = "\n\n"
        if sep in rest:
            head, body = rest.split(sep, 1)
        else:
            return status_code, {}, rest

    headers: dict[str, str] = {}
    lines = head.splitlines()[1:]
    for line in lines:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()

    return status_code, headers, body