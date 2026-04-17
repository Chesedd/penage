from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.llm.fake import FakeLLMClient
from penage.specialists.base import SpecialistConfig
from penage.specialists.vulns import CmdInjSpecialist
from penage.specialists.vulns.cmdinj import _CmdInjTarget


@dataclass
class FakeHttp:
    calls: list[Action] = field(default_factory=list)

    async def run(self, action: Action) -> Observation:
        self.calls.append(action)
        return Observation(ok=True, elapsed_ms=10, data={"status_code": 200, "text_full": "", "text_excerpt": ""})

    async def aclose(self) -> None:
        return None


def _make_specialist(
    *,
    http: FakeHttp | None = FakeHttp(),
    llm: FakeLLMClient | None = None,
) -> CmdInjSpecialist:
    return CmdInjSpecialist(
        http_tool=http,
        llm_client=llm if llm is not None else FakeLLMClient(fixed_text=""),
        max_http_budget=20,
    )


@pytest.mark.asyncio
async def test_no_params_returns_empty() -> None:
    specialist = _make_specialist()
    state = State(base_url="http://localhost")
    result = await specialist.propose_async(state, config=SpecialistConfig())
    assert result == []


@pytest.mark.asyncio
async def test_missing_http_tool_returns_empty() -> None:
    specialist = CmdInjSpecialist(http_tool=None, llm_client=FakeLLMClient(fixed_text=""))
    state = State(base_url="http://localhost")
    state.last_http_url = "http://localhost/ping?host=1"
    result = await specialist.propose_async(state, config=SpecialistConfig())
    assert result == []


@pytest.mark.asyncio
async def test_missing_llm_client_returns_empty() -> None:
    specialist = CmdInjSpecialist(http_tool=FakeHttp(), llm_client=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://localhost/ping?host=1"
    result = await specialist.propose_async(state, config=SpecialistConfig())
    assert result == []


def test_target_discovery_priority_ordering() -> None:
    specialist = _make_specialist()
    state = State(base_url="http://localhost")
    state.forms_by_url = {
        "http://localhost/act": [
            {
                "action": "http://localhost/act",
                "method": "POST",
                "inputs": [
                    {"name": "comment", "type": "text"},
                    {"name": "cmd", "type": "text"},
                ],
            }
        ]
    }
    targets = specialist._discover_targets(state)
    assert [t.parameter for t in targets] == ["cmd", "comment"]


def test_target_discovery_from_query_string() -> None:
    specialist = _make_specialist()
    state = State(base_url="http://localhost")
    state.last_http_url = "http://localhost/ping?host=example.com&debug=true"
    targets = specialist._discover_targets(state)
    params = [t.parameter for t in targets]
    assert set(params) == {"host", "debug"}
    assert params[0] == "host"  # priority first
    host_target = next(t for t in targets if t.parameter == "host")
    assert host_target.channel == "GET"
    assert host_target.url == "http://localhost/ping"
    assert host_target.original_value == "example.com"


def test_target_discovery_from_form_inputs() -> None:
    specialist = _make_specialist()
    state = State(base_url="http://localhost")
    state.forms_by_url = {
        "http://localhost/submit": [
            {
                "action": "http://localhost/submit",
                "method": "POST",
                "inputs": [
                    {"name": "host", "type": "text", "value": "10.0.0.1"},
                    {"name": "note", "type": "text", "value": "hello"},
                ],
            }
        ]
    }
    targets = specialist._discover_targets(state)
    assert {t.parameter for t in targets} == {"host", "note"}
    host_target = next(t for t in targets if t.parameter == "host")
    assert host_target.channel == "POST"
    assert host_target.original_value == "10.0.0.1"


def test_target_discovery_dedup() -> None:
    specialist = _make_specialist()
    state = State(base_url="http://localhost")
    state.forms_by_url = {
        "http://localhost/act": [
            {
                "action": "http://localhost/act",
                "method": "POST",
                "inputs": [
                    {"name": "cmd", "type": "text"},
                    {"name": "cmd", "type": "text"},
                ],
            },
            {
                "action": "http://localhost/act",
                "method": "POST",
                "inputs": [
                    {"name": "cmd", "type": "text"},
                ],
            },
        ]
    }
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    assert targets[0].parameter == "cmd"


def test_target_discovery_original_value_defaults() -> None:
    specialist = _make_specialist()
    state = State(base_url="http://localhost")
    state.forms_by_url = {
        "http://localhost/run": [
            {
                "action": "http://localhost/run",
                "method": "POST",
                "inputs": [
                    {"name": "ping", "type": "text"},
                    {"name": "unknown_param", "type": "text"},
                ],
            }
        ]
    }
    targets = {t.parameter: t for t in specialist._discover_targets(state)}
    assert targets["ping"].original_value == "1"
    assert targets["unknown_param"].original_value == ""


def test_target_discovery_skip_input_types() -> None:
    specialist = _make_specialist()
    state = State(base_url="http://localhost")
    state.forms_by_url = {
        "http://localhost/act": [
            {
                "action": "http://localhost/act",
                "method": "POST",
                "inputs": [
                    {"name": "csrf", "type": "hidden"},
                    {"name": "go", "type": "submit"},
                    {"name": "upload", "type": "file"},
                    {"name": "pw", "type": "password"},
                    {"name": "cmd", "type": "text"},
                ],
            }
        ]
    }
    targets = specialist._discover_targets(state)
    assert [t.parameter for t in targets] == ["cmd"]


@pytest.mark.asyncio
async def test_not_implemented_phases_raise() -> None:
    specialist = _make_specialist()
    target = _CmdInjTarget(url="http://localhost/x", parameter="cmd", channel="GET")
    with pytest.raises(NotImplementedError):
        await specialist._run_echo_phase(
            target=target,
            http_tool=None,  # type: ignore[arg-type]
            host="localhost",
            config=SpecialistConfig(),
            step=0,
        )
    with pytest.raises(NotImplementedError):
        await specialist._measure_baseline(target, None)  # type: ignore[arg-type]
    with pytest.raises(NotImplementedError):
        await specialist._run_fingerprint_phase(
            target=target,
            http_tool=None,  # type: ignore[arg-type]
            config=SpecialistConfig(),
            step=0,
        )
    with pytest.raises(NotImplementedError):
        await specialist._run_blind_phase(
            target=target,
            http_tool=None,  # type: ignore[arg-type]
            host="localhost",
            baseline={},
            os_hint=None,
            config=SpecialistConfig(),
            step=0,
        )
    with pytest.raises(NotImplementedError):
        await specialist._run_mutation_phase(
            target=target,
            http_tool=None,  # type: ignore[arg-type]
            host="localhost",
            prior_signals={},
            config=SpecialistConfig(),
            step=0,
        )
