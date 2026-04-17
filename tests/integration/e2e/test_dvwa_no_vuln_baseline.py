"""E2E scenario #2 — no-vulnerability baseline against DVWA ``/index.php``.

Drives the full penage runtime against DVWA's authenticated landing page
and asserts the specialists return no ``validated`` findings — i.e. no
false positives on a safe endpoint.

Skips automatically when DVWA is unreachable — see ``conftest.py``.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import pytest

from penage.app.bootstrap import build_runtime
from penage.app.config import RuntimeConfig
from penage.core.guard import RunMode
from penage.core.state import State
from penage.core.tracer import JsonlTracer

from tests.support.dvwa_auth import DvwaSession


pytestmark = pytest.mark.e2e_dvwa


def _build_cfg(base_url: str, trace_path: Path, *, target_url: str) -> RuntimeConfig:
    host = urlparse(base_url).hostname or "127.0.0.1"
    return RuntimeConfig(
        base_url=target_url,
        llm_provider="ollama",
        llm_model="llama3.1",
        ollama_model="llama3.1",
        ollama_url="http://localhost:11434",
        trace_path=trace_path,
        summary_path=None,
        mode=RunMode.SAFE_HTTP,
        allow_static=False,
        actions_per_step=1,
        max_steps=8,
        max_http_requests=40,
        max_total_text_len=200_000,
        enable_specialists=True,
        policy_enabled=True,
        sandbox_backend="null",
        docker_image="python:3.12-slim",
        docker_network="none",
        experiment_tag="e2e_dvwa_no_vuln_baseline",
        allowed_hosts=(host,),
        browser_verification=True,
        browser_launch_args=("--no-sandbox", "--disable-dev-shm-usage"),
    )


def _inject_cookies(bundle, cookies: dict[str, str], host: str) -> None:
    client = bundle.tools.http_backend.client
    for name, value in cookies.items():
        client.cookies.set(name, value, domain=host)


@pytest.mark.asyncio
async def test_no_vuln_baseline_yields_no_validated_findings(
    dvwa_session: DvwaSession, tmp_path: Path
) -> None:
    target_url = f"{dvwa_session.base_url}/index.php"
    trace_path = tmp_path / "trace.jsonl"
    cfg = _build_cfg(dvwa_session.base_url, trace_path, target_url=target_url)

    tracer = JsonlTracer(trace_path, episode_id="e2e-no-vuln-baseline")
    bundle = build_runtime(cfg, tracer)

    host = urlparse(dvwa_session.base_url).hostname or "127.0.0.1"
    _inject_cookies(bundle, dvwa_session.cookies, host)

    try:
        state = State(base_url=bundle.base_url)
        state, _tracker = await bundle.orchestrator.run_episode(
            user_prompt=(
                f"Target: {target_url}. This is the authenticated landing "
                "page — survey it but do not fabricate findings."
            ),
            state=state,
            max_steps=cfg.max_steps,
            actions_per_step=cfg.actions_per_step,
            max_http_requests=cfg.max_http_requests,
            max_total_text_len=cfg.max_total_text_len,
        )
    finally:
        await bundle.tools.aclose()
        await bundle.llm.aclose()
        bundle.memory.close()

    validated = [
        r for r in state.validation_results
        if str(r.get("level")) == "validated"
    ]
    assert not validated, (
        f"expected no validated findings on a safe endpoint; got: {validated!r}"
    )
