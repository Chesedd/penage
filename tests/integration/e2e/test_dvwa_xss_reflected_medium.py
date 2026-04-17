"""E2E scenario #5 — reflected XSS on DVWA ``xss_r``, security ``medium``.

Same endpoint as the reflected-low scenario but with DVWA's ``medium``
filter (case-sensitive ``<script>`` blacklist) — exercises the XSS
specialist's filter-inference + payload-mutation paths against a real
defense rather than a no-op. Re-authenticates inline at ``medium`` so
the session-scoped ``dvwa_session`` fixture (which forces ``low``)
stays unchanged for sibling scenarios.

Skips automatically when DVWA is unreachable — see ``conftest.py``.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import pytest

from penage.app.bootstrap import build_runtime
from penage.core.state import State
from penage.core.tracer import JsonlTracer

from tests.support.dvwa_auth import DvwaSession, authenticate
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


@pytest.mark.asyncio
async def test_xss_reflected_medium_yields_validated_or_evidence(
    dvwa_session: DvwaSession, tmp_path: Path
) -> None:
    medium_session = await authenticate(
        dvwa_session.base_url, security_level="medium"
    )
    target_url = f"{medium_session.base_url}/vulnerabilities/xss_r/?name=probe"
    trace_path = tmp_path / "trace.jsonl"
    host = urlparse(medium_session.base_url).hostname or "127.0.0.1"
    cfg = build_dvwa_runtime_config(
        medium_session.base_url,
        trace_path,
        target_url=target_url,
        allowed_host=host,
        experiment_tag="e2e_dvwa_xss_reflected_medium",
        max_steps=12,
        max_http_requests=60,
        max_total_text_len=400_000,
    )

    tracer = JsonlTracer(trace_path, episode_id="e2e-xss-reflected-medium")
    bundle = build_runtime(cfg, tracer)

    _inject_cookies(bundle, medium_session.cookies, host)

    try:
        state = State(base_url=bundle.base_url)
        state, _tracker = await bundle.orchestrator.run_episode(
            user_prompt=(
                f"Target: {target_url}. Probe the 'name' query parameter for "
                "reflected XSS; the server applies a basic filter, so mutate "
                "payloads as needed and rely on browser verification if available."
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

    positive = [
        r for r in state.validation_results
        if str(r.get("level")) in {"validated", "evidence"}
    ]
    assert positive, (
        "expected at least one ValidationResult with level validated/evidence; "
        f"got: {state.validation_results!r}"
    )

    trace_text = trace_path.read_text(encoding="utf-8") if trace_path.exists() else ""
    assert "xss" in trace_text.lower(), "expected xss-related events in trace"

    validated = [r for r in positive if r.get("level") == "validated"]
    for r in validated:
        evidence = r.get("evidence") or {}
        markers = evidence.get("execution_markers") if isinstance(evidence, dict) else None
        assert markers, (
            "validated ValidationResult must carry non-empty execution_markers; "
            f"got: {r!r}"
        )
