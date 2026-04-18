"""E2E scenario #4 — SQLi on DVWA ``sqli``, security ``low``.

Drives the full penage runtime against a live DVWA and asserts that the
SQLi specialist emits at least one **verified** ``sqli_finding`` NOTE
action over the course of an episode. Unlike the XSS E2E scenarios, the
SQLi specialist is its own oracle — ``ValidationGate`` silently skips
SQLi NOTE actions (``HttpEvidenceValidator`` short-circuits on non-HTTP
actions; no ``browser_target`` is set), so the gate does not populate
per-finding validation records. The truthy signal therefore lives in
the JSONL trace: an ``action`` event whose ``action.params`` is shaped
like ``{"kind": "sqli_finding", "finding": {"verified": True, ...}}``
(see ``docs/design/e2e_dvwa_scenarios.md`` §3.4.3, shape (A)).

Skips automatically when DVWA is unreachable — see ``conftest.py``.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import pytest

from penage.app.bootstrap import build_runtime
from penage.core.state import State
from penage.core.tracer import JsonlTracer

from tests.support.dvwa_auth import DvwaSession
from tests.support.e2e_config import build_dvwa_runtime_config


pytestmark = pytest.mark.e2e_dvwa


def _inject_cookies(bundle, cookies: dict[str, str], host: str) -> None:
    """Seed the ToolRunner's httpx client with DVWA auth cookies.

    The stock ``HttpTool`` uses a shared ``httpx.AsyncClient``; setting
    cookies on its jar makes every subsequent request carry them,
    without touching :class:`RuntimeConfig` or the production factory.
    """
    client = bundle.tools.http_backend.client
    for name, value in cookies.items():
        client.cookies.set(name, value, domain=host)


@pytest.mark.xfail(
    strict=False,
    reason=(
        "Verified SQLi on DVWA low requires (1) payload library enrichment "
        "for reliable error-based extraction, (2) policy score rebalancing "
        "so specialist NOTE actions win selection at actions_per_step=1 "
        "(currently 5.0/11.0 vs LLM 24.0), and (3) blind-timing SLEEP "
        "propagation diagnostic. Tracked in Stage 5 backlog. "
        "Fingerprint-level detection already works (backend_hint=mysql "
        "observed in specialist_phase events); emission also works but "
        "loses rank competition."
    ),
)
@pytest.mark.asyncio
async def test_sqli_low_yields_verified_sqli_finding(
    dvwa_session: DvwaSession, tmp_path: Path
) -> None:
    target_url = (
        f"{dvwa_session.base_url}/vulnerabilities/sqli/?id=1&Submit=Submit"
    )
    trace_path = tmp_path / "trace.jsonl"
    host = urlparse(dvwa_session.base_url).hostname or "127.0.0.1"
    cfg = build_dvwa_runtime_config(
        dvwa_session.base_url,
        trace_path,
        target_url=target_url,
        allowed_host=host,
        experiment_tag="e2e_dvwa_sqli_low",
        max_steps=16,
        max_http_requests=80,
        max_total_text_len=400_000,
    )

    tracer = JsonlTracer(trace_path, episode_id="e2e-sqli-low")
    bundle = build_runtime(cfg, tracer)

    _inject_cookies(bundle, dvwa_session.cookies, host)

    try:
        state = State(base_url=bundle.base_url)
        state, _tracker = await bundle.orchestrator.run_episode(
            user_prompt=(
                f"Target: {target_url}. Probe the 'id' query parameter for "
                "SQL injection. Try error-based and blind-timing payloads; "
                "the SqliSpecialist is the oracle — rely on it to confirm "
                "findings."
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

    trace_content = trace_path.read_text(encoding="utf-8") if trace_path.exists() else ""
    trace_lines = [
        json.loads(line) for line in trace_content.splitlines() if line.strip()
    ]
    sqli_verified = [
        ev for ev in trace_lines
        if ev.get("event") == "action"
        and (
            (ev.get("payload") or {}).get("action") or {}
        ).get("params", {}).get("kind") == "sqli_finding"
        and (
            ((ev["payload"]["action"]["params"] or {}).get("finding") or {}).get(
                "verified"
            )
            is True
        )
    ]
    assert len(sqli_verified) > 0, (
        f"expected at least one verified SQLi finding in trace, got "
        f"{len(sqli_verified)}; trace has {len(trace_lines)} events total"
    )
