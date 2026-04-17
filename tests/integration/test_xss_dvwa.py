"""End-to-end XssSpecialist exercise against a live DVWA (low difficulty) container.

Marked with ``integration`` and ``docker``; skipped automatically when Docker is
unavailable or pulls fail. Expected container: vulnerables/web-dvwa. Security
level is forced to ``low`` before probing.

Not selected by the default ``pytest -q`` run. To execute:

    pytest -q -m "integration and docker" tests/integration/test_xss_dvwa.py
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from contextlib import closing
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.docker]


DVWA_IMAGE = "vulnerables/web-dvwa:latest"
DVWA_CONTAINER = "penage-dvwa-xss-test"
DEFAULT_USER = "admin"
DEFAULT_PASS = "password"


def _docker_available() -> bool:
    binary = shutil.which("docker")
    if binary is None:
        return False
    try:
        rc = subprocess.run(
            [binary, "info", "--format", "{{.ServerVersion}}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).returncode
    except (subprocess.SubprocessError, OSError):
        return False
    return rc == 0


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_for_http(url: str, *, timeout_s: float = 90.0) -> bool:
    import httpx

    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=3.0)
            if r.status_code < 500:
                return True
        except Exception as exc:
            last_err = exc
        time.sleep(1.0)
    if last_err is not None:
        pytest.skip(f"DVWA did not become reachable: {last_err}")
    return False


@pytest.fixture(scope="module")
def dvwa_container() -> str:
    if not _docker_available():
        pytest.skip("Docker is not available; skipping DVWA integration test")

    binary = shutil.which("docker")
    assert binary is not None

    subprocess.run(
        [binary, "rm", "-f", DVWA_CONTAINER],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    port = _free_port()
    run_cmd = [
        binary,
        "run",
        "-d",
        "--rm",
        "--name",
        DVWA_CONTAINER,
        "-p",
        f"{port}:80",
        DVWA_IMAGE,
    ]
    try:
        subprocess.run(run_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=120)
    except subprocess.SubprocessError as exc:
        pytest.skip(f"failed to start DVWA container ({DVWA_IMAGE}): {exc}")

    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_http(f"{base_url}/login.php", timeout_s=120.0)
        yield base_url
    finally:
        subprocess.run(
            [binary, "rm", "-f", DVWA_CONTAINER],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def _login_and_set_low(base_url: str):
    import httpx

    client = httpx.Client(base_url=base_url, follow_redirects=True, timeout=10.0)

    setup = client.get("/setup.php")
    if "Create / Reset Database" in setup.text:
        setup_token = _extract_token(setup.text)
        client.post("/setup.php", data={"create_db": "Create / Reset Database", "user_token": setup_token})
        time.sleep(2.0)

    login = client.get("/login.php")
    token = _extract_token(login.text)
    client.post(
        "/login.php",
        data={"username": DEFAULT_USER, "password": DEFAULT_PASS, "Login": "Login", "user_token": token},
    )

    security_page = client.get("/security.php")
    sec_token = _extract_token(security_page.text)
    client.post(
        "/security.php",
        data={"security": "low", "seclev_submit": "Submit", "user_token": sec_token},
    )
    return client


def _extract_token(html: str) -> str:
    marker = "name='user_token' value='"
    idx = html.find(marker)
    if idx == -1:
        return ""
    start = idx + len(marker)
    end = html.find("'", start)
    if end == -1:
        return ""
    return html[start:end]


@pytest.mark.asyncio
async def test_xss_specialist_detects_reflected_xss_on_dvwa_low(dvwa_container):
    base_url = dvwa_container

    client = _login_and_set_low(base_url)
    reflected_url = f"{base_url}/vulnerabilities/xss_r/"

    import httpx
    from penage.core.actions import Action, ActionType
    from penage.core.observations import Observation
    from penage.core.state import State
    from penage.llm.fake import FakeLLMClient
    from penage.memory.store import MemoryStore
    from penage.specialists.base import SpecialistConfig
    from penage.specialists.vulns.xss import XssSpecialist
    from penage.tools.http_tool import HttpTool

    cookies = dict(client.cookies)

    class _CookieHttp(HttpTool):
        async def run(self, action: Action) -> Observation:  # type: ignore[override]
            params = dict(action.params)
            merged = dict(cookies)
            merged.update(params.get("cookies") or {})
            params["cookies"] = merged
            return await super().run(Action(type=action.type, params=params, timeout_s=action.timeout_s, tags=list(action.tags)))

    httpx_client = httpx.AsyncClient()
    http_tool = _CookieHttp.create_default(httpx_client, allowed_hosts={"127.0.0.1", "localhost"})

    llm = FakeLLMClient(fixed_text=json.dumps([
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ]))
    specialist = XssSpecialist(
        http_tool=http_tool,
        llm_client=llm,
        memory=MemoryStore(":memory:"),
        browser_validator=None,  # Browser binary unavailable in CI; reflection-only finding suffices.
        validation_recorder=None,
        max_http_budget=40,
    )

    state = State(base_url=base_url)
    state.last_http_url = f"{reflected_url}?name=ping"

    candidates = await specialist.propose_async(state, config=SpecialistConfig(max_candidates=4))
    try:
        assert candidates, "expected at least an unverified reflection finding"
        finding = candidates[0].metadata["evidence"]
        assert finding["parameter"] == "name"
        assert finding["context"] in {"html_body", "attr_quoted", "attr_unquoted"}
    finally:
        await http_tool.aclose()
        client.close()
