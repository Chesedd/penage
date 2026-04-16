from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import parse_qsl, urlparse

import pytest

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.llm.fake import FakeLLMClient
from penage.memory.store import MemoryStore
from penage.specialists.base import SpecialistConfig
from penage.specialists.shared.oob_listener import OobHit
from penage.specialists.vulns.ssrf import SsrfSpecialist


Responder = Callable[[Action], Observation]


@dataclass
class FakeHttp:
    responder: Responder
    calls: list[Action] = field(default_factory=list)

    async def run(self, action: Action) -> Observation:
        self.calls.append(action)
        return self.responder(action)

    async def aclose(self) -> None:
        return None


@dataclass
class _FakeOobListener:
    """Test double for :class:`OobListener`.

    ``hit_to_return`` is the :class:`OobHit` that :meth:`wait_for_hit` yields
    (``None`` simulates timeout). ``running`` toggles :attr:`is_running`.
    """

    hit_to_return: OobHit | None = None
    running: bool = True
    token_seq: int = 0
    probe_url_template: str = "http://127.0.0.1:55555/canary/{token}"

    @property
    def is_running(self) -> bool:
        return self.running

    async def register_token(self) -> tuple[str, str]:
        self.token_seq += 1
        token = f"tok{self.token_seq:03d}" + "0" * max(0, 16 - 6)
        return token, self.probe_url_template.format(token=token)

    async def wait_for_hit(self, token: str, timeout_s: float) -> OobHit | None:
        _ = (token, timeout_s)
        return self.hit_to_return


def _param_value(action: Action, parameter: str) -> str:
    params = action.params
    method = str(params.get("method") or "GET").upper()
    if method == "GET":
        q = dict(parse_qsl(urlparse(str(params["url"])).query, keep_blank_values=True))
        return q.get(parameter, "")
    data = params.get("data") or {}
    return str(data.get(parameter, ""))


def _ok(text: str, *, url: str | None = None, status: int = 200) -> Observation:
    return Observation(
        ok=True,
        elapsed_ms=10,
        data={
            "status_code": status,
            "url": url,
            "headers": {"content-type": "text/html"},
            "text_full": text,
            "text_excerpt": text[:400],
        },
    )


def _state_with_query_target(base_url: str, parameter: str, value: str = "hello") -> State:
    st = State(base_url=base_url)
    st.last_http_url = f"{base_url}?{parameter}={value}"
    return st


# ---------------------------------------------------------------------------
# Phase 1 — target discovery
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_ssrf_candidate_params_returns_empty():
    """Non-URL-ish parameter with non-URL value discovers no targets."""
    specialist = SsrfSpecialist(
        http_tool=FakeHttp(responder=lambda a: _ok("irrelevant")),
        llm_client=FakeLLMClient(fixed_text=""),
        memory=MemoryStore(":memory:"),
    )
    state = _state_with_query_target("http://localhost/search", "q", value="lol")
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []


@pytest.mark.asyncio
async def test_target_discovery_via_param_name_heuristic():
    """Parameter name ``webhook`` triggers SSRF candidacy without a URL value."""
    specialist = SsrfSpecialist()
    state = _state_with_query_target("http://localhost/app", "webhook", value="plain-text")
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    assert targets[0].parameter == "webhook"
    assert targets[0].channel == "GET"


@pytest.mark.asyncio
async def test_target_discovery_via_url_value():
    """Parameter whose value starts with ``http://`` is a candidate even if
    the parameter name isn't on the hint list."""
    specialist = SsrfSpecialist()
    base = "http://localhost/app"
    st = State(base_url=base)
    st.last_http_url = f"{base}?foo=http%3A%2F%2Fexample.com%2F"
    targets = specialist._discover_targets(st)
    assert [t.parameter for t in targets] == ["foo"]


# ---------------------------------------------------------------------------
# Phase 2 — OOB canary probing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oob_hit_produces_verified_finding():
    """A synchronous OOB hit short-circuits into a verified ssrf_oob finding."""
    hit = OobHit(
        token="tok001" + "0" * 10,
        remote_addr="10.0.0.7",
        path="/canary/tok0010000000000000",
        headers={"User-Agent": "curl/8.0"},
        ts=time.time(),
    )
    listener = _FakeOobListener(hit_to_return=hit, running=True)

    def respond(action: Action) -> Observation:
        return _ok("<html>ok</html>", url=action.params.get("url"))

    http_tool = FakeHttp(responder=respond)
    memory = MemoryStore(":memory:")
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=memory,
        oob_listener=listener,  # type: ignore[arg-type]
    )

    state = _state_with_query_target("http://localhost/fetcher", "url", value="http://x/")
    candidates = await specialist.propose_async(state, config=SpecialistConfig())

    assert candidates, "expected a verified SSRF candidate"
    evidence = candidates[0].metadata["evidence"]
    assert evidence["verified"] is True
    assert evidence["kind"] == "ssrf_oob"
    assert evidence["mode"] == "oob"
    assert evidence["evidence"]["oob_hit"]["remote_addr"] == "10.0.0.7"
    assert candidates[0].score == 13.0


@pytest.mark.asyncio
async def test_oob_timeout_does_not_short_circuit():
    """When the OOB waiter times out, we must proceed to phase 3."""
    listener = _FakeOobListener(hit_to_return=None, running=True)

    def respond(action: Action) -> Observation:
        return _ok("<html>nothing here</html>", url=action.params.get("url"))

    http_tool = FakeHttp(responder=respond)
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=MemoryStore(":memory:"),
        oob_listener=listener,  # type: ignore[arg-type]
        max_http_budget=20,
    )

    state = _state_with_query_target("http://localhost/fetcher", "url", value="http://x/")
    await specialist.propose_async(state, config=SpecialistConfig())

    # Phase 2 probe + at least one phase 3 probe must have been dispatched.
    assert len(http_tool.calls) >= 2


@pytest.mark.asyncio
async def test_no_listener_gracefully_skips_phase_2(tmp_path):
    """When no listener is configured, phase 2 emits a note and phase 3
    still runs."""
    trace_path = tmp_path / "trace.jsonl"
    tracer = JsonlTracer(trace_path, episode_id="unit-ssrf")

    http_tool = FakeHttp(responder=lambda a: _ok("no-markers-here", url=a.params.get("url")))
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=None,
        tracer=tracer,
        oob_listener=None,
        max_http_budget=20,
    )

    state = _state_with_query_target("http://localhost/app", "url", value="http://x/")
    await specialist.propose_async(state, config=SpecialistConfig())

    events = [json.loads(line) for line in trace_path.read_text().splitlines() if line.strip()]
    notes = [e for e in events if e["event"] == "note"]
    assert any("ssrf:oob_listener_unavailable" in e["payload"]["text"] for e in notes)
    phases = sorted({e["payload"]["phase"] for e in events if e["event"] == "specialist_phase"})
    assert 2 not in phases  # phase 2 skipped
    assert 1 in phases and 3 in phases


# ---------------------------------------------------------------------------
# Phase 3 — internal-target probing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_internal_probe_marker_match_produces_verified_finding():
    """Response body containing ``ami-id`` on a 169.254.* probe is a
    verified metadata leak (``expected_marker`` from YAML = ``ami-id``)."""
    memory = MemoryStore(":memory:")

    def respond(action: Action) -> Observation:
        value = _param_value(action, "url")
        if "169.254.169.254" in value and "meta-data" in value:
            return _ok("ami-id\nami-launch-index\n", url=action.params.get("url"))
        return _ok("nothing", url=action.params.get("url"))

    http_tool = FakeHttp(responder=respond)
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=memory,
        oob_listener=None,
        max_http_budget=20,
    )

    state = _state_with_query_target("http://localhost/fetcher", "url", value="http://x/")
    candidates = await specialist.propose_async(state, config=SpecialistConfig())

    assert candidates
    evidence = candidates[0].metadata["evidence"]
    assert evidence["verified"] is True
    assert evidence["kind"] == "ssrf_metadata_leak"
    assert evidence["mode"] == "internal_marker"
    assert "ami-id" in evidence["evidence"]["response_markers"]
    assert candidates[0].score == 11.0


# ---------------------------------------------------------------------------
# Budget / memory / no-deps invariants
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_budget_exhaustion_short_circuits():
    """A below-minimum HTTP cap aborts cleanly without any HTTP traffic."""
    http_tool = FakeHttp(responder=lambda a: _ok("x", url="x"))
    specialist = SsrfSpecialist(
        http_tool=http_tool,
        llm_client=FakeLLMClient(fixed_text=""),
        memory=None,
        oob_listener=None,
        max_http_budget=4,  # below min_reserve_http default 10
    )
    state = _state_with_query_target("http://localhost/x", "url", value="http://x/")
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    assert http_tool.calls == []


@pytest.mark.asyncio
async def test_propose_async_without_dependencies_returns_empty():
    """Missing http_tool or llm_client must yield no candidates (no crash)."""
    state = _state_with_query_target("http://localhost/x", "url", value="http://x/")
    s1 = SsrfSpecialist(http_tool=None, llm_client=FakeLLMClient(fixed_text=""))
    s2 = SsrfSpecialist(http_tool=FakeHttp(responder=lambda a: _ok("x")), llm_client=None)
    assert await s1.propose_async(state, config=SpecialistConfig()) == []
    assert await s2.propose_async(state, config=SpecialistConfig()) == []


@pytest.mark.asyncio
async def test_memory_record_attempt_called_per_outcome():
    """Every outcome must land in MemoryStore (so future runs can skip it)."""
    memory = MemoryStore(":memory:")

    def respond(action: Action) -> Observation:
        return _ok("boring", url=action.params.get("url"))

    specialist = SsrfSpecialist(
        http_tool=FakeHttp(responder=respond),
        llm_client=FakeLLMClient(fixed_text=""),
        memory=memory,
        oob_listener=_FakeOobListener(hit_to_return=None, running=True),  # type: ignore[arg-type]
        max_http_budget=20,
    )

    state = _state_with_query_target("http://localhost/app", "url", value="http://x/")
    await specialist.propose_async(state, config=SpecialistConfig())

    # Any phase-2 probe_url and every phase-3 payload we sent must now be
    # recorded against this host/parameter — i.e. memory saw >=1 attempt.
    host = "localhost"
    tried_any = memory._conn.execute(
        "SELECT COUNT(*) FROM scan_state WHERE host = ? AND parameter = ?",
        (host, "url"),
    ).fetchone()[0]
    assert tried_any >= 2
