from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.specialists.base import SpecialistConfig
from penage.specialists.vulns.xxe import XxeSpecialist, _XxeTarget


@dataclass
class FakeHttp:
    calls: list[Action] = field(default_factory=list)

    async def run(self, action: Action) -> Observation:
        self.calls.append(action)
        return Observation(ok=True, data={"status_code": 200, "text_full": ""})

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_no_xml_candidate_target_returns_empty():
    specialist = XxeSpecialist(http_tool=FakeHttp(), max_http_budget=25)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://localhost/about"
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []


def test_target_discovery_recent_http_memory_xml():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    state = State(base_url="http://localhost")
    state.recent_http_memory = [
        {
            "url": "http://localhost/api/data",
            "headers": {"Content-Type": "application/xml; charset=utf-8"},
        }
    ]
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    t = targets[0]
    assert t.url == "http://localhost/api/data"
    assert t.delivery == "body"
    assert t.parameter == ""
    assert t.channel == "POST"
    assert t.content_type == "application/xml"


def test_target_discovery_recent_http_memory_soap():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    state = State(base_url="http://localhost")
    state.recent_http_memory = [
        {
            "url": "http://localhost/svc/endpoint",
            "headers": {"content-type": "application/soap+xml"},
        }
    ]
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    assert targets[0].content_type == "application/soap+xml"
    assert targets[0].delivery == "body"


def test_target_discovery_path_hint():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://localhost/api/soap/endpoint"
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    assert targets[0].url == "http://localhost/api/soap/endpoint"
    assert targets[0].delivery == "body"
    assert targets[0].content_type == "application/xml"


def test_target_discovery_path_hint_wsdl():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://localhost/wsdl/service"
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    assert targets[0].delivery == "body"
    assert "/wsdl" in (targets[0].url or "").lower()


def test_target_discovery_param_hint_xml():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    state = State(base_url="http://localhost")
    state.forms_by_url = {
        "http://localhost/form": [
            {
                "action": "http://localhost/submit",
                "method": "POST",
                "inputs": [
                    {"name": "xml", "type": "text"},
                    {"name": "title", "type": "text"},
                ],
            }
        ]
    }
    targets = specialist._discover_targets(state)
    names = {t.parameter for t in targets}
    assert "xml" in names
    assert "title" not in names
    xml_target = next(t for t in targets if t.parameter == "xml")
    assert xml_target.delivery == "param"
    assert xml_target.channel == "POST"


def test_target_discovery_param_hint_soap():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    state = State(base_url="http://localhost")
    state.forms_by_url = {
        "http://localhost/form": [
            {
                "action": "http://localhost/submit",
                "method": "POST",
                "inputs": [
                    {"name": "soap_envelope", "type": "text"},
                ],
            }
        ]
    }
    targets = specialist._discover_targets(state)
    assert any(t.parameter == "soap_envelope" and t.delivery == "param" for t in targets)


def test_target_discovery_dedup_across_sources():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    state = State(base_url="http://localhost")
    url = "http://localhost/api/soap/endpoint"
    # Same URL appears in BOTH source A (recent_http_memory with XML CT)
    # and source B (URL-path hint).
    state.last_http_url = url
    state.recent_http_memory = [
        {"url": url, "headers": {"content-type": "application/xml"}}
    ]
    targets = specialist._discover_targets(state)
    bodies = [t for t in targets if t.delivery == "body" and t.url == url]
    assert len(bodies) == 1


def test_target_discovery_skip_input_types_hidden_password():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    state = State(base_url="http://localhost")
    state.forms_by_url = {
        "http://localhost/form": [
            {
                "action": "http://localhost/submit",
                "method": "POST",
                "inputs": [
                    {"name": "xml", "type": "hidden"},
                    {"name": "soap", "type": "password"},
                    {"name": "data", "type": "submit"},
                    {"name": "body", "type": "text"},
                ],
            }
        ]
    }
    targets = specialist._discover_targets(state)
    names = {t.parameter for t in targets}
    assert "xml" not in names
    assert "soap" not in names
    assert "data" not in names
    assert "body" in names


def test_target_discovery_max_targets_respected():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25, max_targets=2)
    state = State(base_url="http://localhost")
    state.recent_http_memory = [
        {"url": f"http://localhost/api/{i}", "headers": {"content-type": "application/xml"}}
        for i in range(5)
    ]
    targets = specialist._discover_targets(state)
    assert len(targets) == 2


@pytest.mark.asyncio
async def test_phase_2_3_4_5_not_implemented_raise():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    with pytest.raises(NotImplementedError):
        await specialist._run_classic_phase()
    with pytest.raises(NotImplementedError):
        await specialist._run_param_entity_phase()
    with pytest.raises(NotImplementedError):
        await specialist._run_oob_phase()
    with pytest.raises(NotImplementedError):
        specialist._finalize_candidate()
    with pytest.raises(NotImplementedError):
        specialist._render_payload()
    with pytest.raises(NotImplementedError):
        specialist._build_delivery()


@pytest.mark.asyncio
async def test_missing_http_tool_returns_empty():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://localhost/api/soap/endpoint"
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []


def test_export_from_vulns_package():
    from penage.specialists.vulns import XxeSpecialist as Imported

    assert Imported is XxeSpecialist
