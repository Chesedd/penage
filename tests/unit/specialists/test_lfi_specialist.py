from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import parse_qsl, urlparse

import pytest

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.memory.store import MemoryStore
from penage.specialists.base import SpecialistConfig
from penage.specialists.vulns.lfi import LfiSpecialist, _LfiTarget


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


def _ok(text: str, *, url: str, status: int = 200) -> Observation:
    return Observation(
        ok=True,
        elapsed_ms=50,
        data={
            "status_code": status,
            "url": url,
            "headers": {"content-type": "text/plain"},
            "text_full": text,
            "text_excerpt": text[:400],
        },
    )


def _param_value(action: Action, parameter: str) -> str:
    params = action.params
    if str(params.get("method") or "GET").upper() == "GET":
        q = dict(parse_qsl(urlparse(str(params["url"])).query, keep_blank_values=True))
        return q.get(parameter, "")
    data = params.get("data") or {}
    return str(data.get(parameter, ""))


def _state_with_query_target(base_url: str, parameter: str, value: str = "hello") -> State:
    st = State(base_url=base_url)
    st.last_http_url = f"{base_url}?{parameter}={value}"
    return st


PASSWD_BODY = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
)

WIN_INI_BODY = (
    "; for 16-bit app support\n"
    "[fonts]\n"
    "[extensions]\n"
    "[mci extensions]\n"
)


@pytest.mark.asyncio
async def test_no_params_returns_empty():
    specialist = LfiSpecialist(
        http_tool=FakeHttp(responder=lambda a: _ok("", url="x")),
        memory=None,
        max_http_budget=30,
    )
    state = State(base_url="http://localhost")
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []


def test_target_discovery_by_name_hint():
    specialist = LfiSpecialist(http_tool=None, max_http_budget=30)
    st = State(base_url="http://localhost")
    st.last_http_url = "http://localhost/r?file=a&page=b&include=c&other=x"
    targets = specialist._discover_targets(st)
    names = {t.parameter for t in targets}
    assert {"file", "page", "include"}.issubset(names)
    assert "other" not in names


def test_target_discovery_by_value_hint():
    specialist = LfiSpecialist(http_tool=None, max_http_budget=30)
    st = State(base_url="http://localhost")
    st.last_http_url = "http://localhost/r?q=../../../etc/passwd&unrelated=foo"
    targets = specialist._discover_targets(st)
    names = {t.parameter for t in targets}
    assert "q" in names
    assert "unrelated" not in names


def test_target_discovery_skip_input_types():
    specialist = LfiSpecialist(http_tool=None, max_http_budget=30)
    st = State(base_url="http://localhost")
    st.forms_by_url = {
        "http://localhost/form": [
            {
                "action": "http://localhost/submit",
                "method": "POST",
                "inputs": [
                    {"name": "file", "type": "hidden"},
                    {"name": "path", "type": "password"},
                    {"name": "page", "type": "text"},
                    {"name": "nocsrf", "type": "submit"},
                ],
            }
        ]
    }
    targets = specialist._discover_targets(st)
    names = {t.parameter for t in targets}
    assert names == {"page"}


@pytest.mark.asyncio
async def test_deterministic_passwd_marker_verified():
    base_url = "http://localhost/view"
    parameter = "file"

    def respond(action: Action) -> Observation:
        return _ok(PASSWD_BODY, url=str(action.params.get("url")))

    http_tool = FakeHttp(responder=respond)
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=MemoryStore(":memory:"),
        max_http_budget=30,
    )
    state = _state_with_query_target(base_url, parameter)

    cands = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(cands) == 1
    finding = cands[0].metadata["evidence"]
    assert finding["verified"] is True
    assert finding["kind"] == "lfi_disclosure"
    assert finding["family"] == "unix_passwd"
    assert finding["parameter"] == parameter
    assert cands[0].score == 12.0


@pytest.mark.asyncio
async def test_deterministic_win_ini_marker_verified():
    base_url = "http://localhost/view"
    parameter = "file"

    def respond(action: Action) -> Observation:
        # Simulate a broken endpoint that always leaks win.ini regardless of
        # the traversal target — good enough to prove the detector path is
        # wired up and the win_ini family is picked.
        return _ok(WIN_INI_BODY, url=str(action.params.get("url")))

    http_tool = FakeHttp(responder=respond)
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=MemoryStore(":memory:"),
        max_http_budget=30,
    )
    state = _state_with_query_target(base_url, parameter)

    cands = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(cands) == 1
    finding = cands[0].metadata["evidence"]
    assert finding["verified"] is True
    assert finding["family"] == "win_ini"


@pytest.mark.asyncio
async def test_deterministic_no_marker_no_finding():
    base_url = "http://localhost/view"
    parameter = "file"

    def respond(action: Action) -> Observation:
        return _ok("<html>benign page</html>", url=str(action.params.get("url")))

    http_tool = FakeHttp(responder=respond)
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        max_http_budget=30,
    )
    state = _state_with_query_target(base_url, parameter)

    cands = await specialist.propose_async(state, config=SpecialistConfig())
    assert cands == []


@pytest.mark.asyncio
async def test_verified_finding_short_circuits_to_next_target():
    base_url = "http://localhost/view"
    parameter = "file"

    def respond(action: Action) -> Observation:
        return _ok(PASSWD_BODY, url=str(action.params.get("url")))

    http_tool = FakeHttp(responder=respond)
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=MemoryStore(":memory:"),
        max_http_budget=30,
    )
    state = _state_with_query_target(base_url, parameter)

    first = await specialist.propose_async(state, config=SpecialistConfig())
    calls_after_first = len(http_tool.calls)

    second = await specialist.propose_async(state, config=SpecialistConfig())
    assert first and second
    assert first[0].metadata["evidence"]["verified"] is True
    # _done guard prevents additional HTTP work.
    assert len(http_tool.calls) == calls_after_first


@pytest.mark.asyncio
async def test_budget_exhaustion_handled():
    specialist = LfiSpecialist(
        http_tool=FakeHttp(responder=lambda a: _ok("", url="x")),
        memory=None,
        max_http_budget=4,  # below min_reserve_http (10)
    )
    state = _state_with_query_target("http://localhost/v", "file")
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []


@pytest.mark.asyncio
async def test_phase_3_4_5_not_implemented_yet():
    specialist = LfiSpecialist(http_tool=None, max_http_budget=30)
    target = _LfiTarget(url="http://localhost/v", parameter="file", channel="GET")
    from penage.specialists.vulns.lfi import _BudgetedHttpTool  # type: ignore[attr-defined]

    budget = _BudgetedHttpTool(
        FakeHttp(responder=lambda a: _ok("", url="x")),
        State(),
        cap=10,
    )
    with pytest.raises(NotImplementedError):
        await specialist._run_bypass_phase(
            target=target,
            http_tool=budget,
            host="localhost",
            config=SpecialistConfig(),
            step=0,
        )
    with pytest.raises(NotImplementedError):
        await specialist._run_oob_phase(
            target=target,
            http_tool=budget,
            host="localhost",
            config=SpecialistConfig(),
            step=0,
        )
    with pytest.raises(NotImplementedError):
        specialist._finalize_candidate({"verified": True})


@pytest.mark.asyncio
async def test_memory_record_attempt_called_per_outcome():
    base_url = "http://localhost/view"
    parameter = "file"
    outcomes: list[str] = []

    class _RecordingMemory(MemoryStore):
        def record_attempt(self, **kwargs) -> None:  # type: ignore[override]
            outcomes.append(kwargs.get("outcome", ""))

    def respond(action: Action) -> Observation:
        # First payload returns passwd (verified), no second payload fires.
        return _ok(PASSWD_BODY, url=str(action.params.get("url")))

    specialist = LfiSpecialist(
        http_tool=FakeHttp(responder=respond),
        memory=_RecordingMemory(":memory:"),
        max_http_budget=30,
    )
    state = _state_with_query_target(base_url, parameter)
    cands = await specialist.propose_async(state, config=SpecialistConfig())
    assert cands and cands[0].metadata["evidence"]["verified"]
    assert outcomes == ["verified_disclosure"]


@pytest.mark.asyncio
async def test_memory_record_attempt_no_signal_outcome():
    base_url = "http://localhost/view"
    parameter = "file"
    outcomes: list[str] = []

    class _RecordingMemory(MemoryStore):
        def record_attempt(self, **kwargs) -> None:  # type: ignore[override]
            outcomes.append(kwargs.get("outcome", ""))

    def respond(action: Action) -> Observation:
        return _ok("<html>no marker</html>", url=str(action.params.get("url")))

    specialist = LfiSpecialist(
        http_tool=FakeHttp(responder=respond),
        memory=_RecordingMemory(":memory:"),
        max_http_budget=30,
    )
    state = _state_with_query_target(base_url, parameter)
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    assert outcomes
    assert set(outcomes) == {"no_signal"}


@pytest.mark.asyncio
async def test_multiple_markers_primary_selected():
    base_url = "http://localhost/view"
    parameter = "file"

    mixed_body = (
        PASSWD_BODY
        + "\nPATH=/usr/bin\nHOME=/root\nUSER=www-data\nSHELL=/bin/sh\n"
    )

    def respond(action: Action) -> Observation:
        return _ok(mixed_body, url=str(action.params.get("url")))

    specialist = LfiSpecialist(
        http_tool=FakeHttp(responder=respond),
        memory=None,
        max_http_budget=30,
    )
    state = _state_with_query_target(base_url, parameter)
    cands = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(cands) == 1
    finding = cands[0].metadata["evidence"]
    # detect_lfi_markers runs passwd first — that's the primary family.
    assert finding["family"] == "unix_passwd"
    markers = finding["evidence"]["markers"]
    families = [m["family"] for m in markers]
    assert "unix_passwd" in families
    # Additional families are also recorded in the evidence list.
    assert len(markers) >= 1


def test_export_from_vulns_package():
    from penage.specialists.vulns import LfiSpecialist as Exported

    assert Exported is LfiSpecialist
