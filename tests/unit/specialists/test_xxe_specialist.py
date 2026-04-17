from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

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
async def test_phase_3_4_5_not_implemented_raise():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    with pytest.raises(NotImplementedError):
        await specialist._run_param_entity_phase()
    with pytest.raises(NotImplementedError):
        await specialist._run_oob_phase()
    with pytest.raises(NotImplementedError):
        specialist._finalize_candidate()


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


# ---------------------------------------------------------------------------
# Phase 2 — classic SYSTEM-entity probes
# ---------------------------------------------------------------------------


@dataclass
class ScriptedHttp:
    """HTTP double that returns a caller-provided body for every request."""

    body_for: Callable[[Action], str] = field(
        default_factory=lambda: (lambda a: "")
    )
    status_for: Callable[[Action], int] = field(
        default_factory=lambda: (lambda a: 200)
    )
    calls: list[Action] = field(default_factory=list)

    async def run(self, action: Action) -> Observation:
        self.calls.append(action)
        return Observation(
            ok=True,
            data={
                "status_code": self.status_for(action),
                "text_full": self.body_for(action),
            },
        )

    async def aclose(self) -> None:
        return None


def _state_with_xml_body_target(url: str = "http://localhost/api/xml") -> State:
    state = State(base_url="http://localhost")
    state.recent_http_memory = [
        {
            "url": url,
            "headers": {"Content-Type": "application/xml"},
        }
    ]
    return state


def _prime_cache(
    specialist: XxeSpecialist, entries: list[dict[str, Any]]
) -> None:
    specialist._yaml_cache = entries


_PASSWD_LINE = "root:x:0:0:root:/root:/bin/bash\n"
_WIN_INI_BODY = "[fonts]\nMS Sans Serif=\n[extensions]\ntxt=notepad.exe\n"


@pytest.mark.asyncio
async def test_classic_passwd_verified():
    http = ScriptedHttp(body_for=lambda a: _PASSWD_LINE)
    specialist = XxeSpecialist(http_tool=http, max_http_budget=25)
    _prime_cache(
        specialist,
        [
            {
                "id": "xxe-classic-passwd",
                "category": "classic-unix",
                "template": "classic",
                "uri": "file:///etc/passwd",
                "entity_name": "xxe",
                "content_type": "application/xml",
                "payload": "",
            }
        ],
    )
    state = _state_with_xml_body_target()
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(out) == 1
    candidate = out[0]
    assert candidate.score == 12.0
    finding = candidate.metadata["evidence"]
    assert finding["verified"] is True
    assert finding["family"] == "unix_passwd"
    assert finding["kind"] == "xxe_classic_disclosure"


@pytest.mark.asyncio
async def test_classic_win_ini_verified():
    http = ScriptedHttp(body_for=lambda a: _WIN_INI_BODY)
    specialist = XxeSpecialist(http_tool=http, max_http_budget=25)
    _prime_cache(
        specialist,
        [
            {
                "id": "xxe-classic-win-ini",
                "category": "classic-windows",
                "template": "classic",
                "uri": "file:///C:/Windows/win.ini",
                "entity_name": "xxe",
                "content_type": "application/xml",
                "payload": "",
            }
        ],
    )
    state = _state_with_xml_body_target()
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(out) == 1
    finding = out[0].metadata["evidence"]
    assert finding["verified"] is True
    assert finding["family"] == "win_ini"


@pytest.mark.asyncio
async def test_classic_no_marker_no_finding():
    http = ScriptedHttp(body_for=lambda a: "<response>ok</response>")
    specialist = XxeSpecialist(http_tool=http, max_http_budget=25)
    _prime_cache(
        specialist,
        [
            {
                "id": "xxe-classic-passwd",
                "category": "classic-unix",
                "template": "classic",
                "uri": "file:///etc/passwd",
                "entity_name": "xxe",
                "content_type": "application/xml",
                "payload": "",
            }
        ],
    )
    state = _state_with_xml_body_target()
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []


@pytest.mark.asyncio
async def test_classic_dos_payload_dropped():
    http = ScriptedHttp(body_for=lambda a: "")
    specialist = XxeSpecialist(http_tool=http, max_http_budget=25)

    # Recursive-entity payload trips XmlSafetyFilter.check → allowed=False.
    recursive = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE r [\n'
        '  <!ENTITY a "x">\n'
        '  <!ENTITY b "&a;&a;">\n'
        ']>\n'
        '<r>&b;</r>'
    )
    _prime_cache(
        specialist,
        [
            {
                "id": "xxe-dos-test",
                "category": "error-based",
                "template": "error-based",
                "uri": "",
                "entity_name": "xxe",
                "content_type": "application/xml",
                "payload": recursive,
            }
        ],
    )

    notes: list[str] = []
    specialist._note = notes.append  # type: ignore[method-assign]

    state = _state_with_xml_body_target()
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    assert len(http.calls) == 0  # no HTTP fired for blocked payload.
    assert any("xxe:dos_payload_dropped" in n for n in notes)


@pytest.mark.asyncio
async def test_body_delivery_sends_raw_xml():
    http = ScriptedHttp(body_for=lambda a: "")
    specialist = XxeSpecialist(http_tool=http, max_http_budget=25)
    _prime_cache(
        specialist,
        [
            {
                "id": "xxe-classic-passwd",
                "category": "classic-unix",
                "template": "classic",
                "uri": "file:///etc/passwd",
                "entity_name": "xxe",
                "content_type": "application/xml",
                "payload": "",
            }
        ],
    )
    state = _state_with_xml_body_target()
    await specialist.propose_async(state, config=SpecialistConfig())
    assert len(http.calls) == 1
    params = http.calls[0].params
    assert isinstance(params["data"], str)
    assert params["data"].startswith("<?xml")
    assert "<!DOCTYPE" in params["data"]
    assert params["headers"]["Content-Type"] == "application/xml"


@pytest.mark.asyncio
async def test_param_delivery_sends_xml_in_form_field():
    http = ScriptedHttp(body_for=lambda a: "")
    specialist = XxeSpecialist(http_tool=http, max_http_budget=25)
    _prime_cache(
        specialist,
        [
            {
                "id": "xxe-classic-passwd",
                "category": "classic-unix",
                "template": "classic",
                "uri": "file:///etc/passwd",
                "entity_name": "xxe",
                "content_type": "application/xml",
                "payload": "",
            }
        ],
    )
    state = State(base_url="http://localhost")
    state.forms_by_url = {
        "http://localhost/form": [
            {
                "action": "http://localhost/submit",
                "method": "POST",
                "inputs": [{"name": "xml", "type": "text"}],
            }
        ]
    }
    await specialist.propose_async(state, config=SpecialistConfig())
    assert len(http.calls) == 1
    params = http.calls[0].params
    assert isinstance(params["data"], dict)
    assert "xml" in params["data"]
    assert params["data"]["xml"].startswith("<?xml")
    assert "headers" not in params


@pytest.mark.asyncio
async def test_soap_wrapped_envelope_shape():
    http = ScriptedHttp(body_for=lambda a: "")
    specialist = XxeSpecialist(http_tool=http, max_http_budget=25)
    entry = {
        "id": "xxe-soap-passwd",
        "category": "soap-wrapped",
        "template": "classic",
        "uri": "file:///etc/passwd",
        "entity_name": "xxe",
        "content_type": "text/xml",
        "payload": "",
    }
    rendered = specialist._render_payload(entry, oob_url=None)
    assert rendered is not None
    assert "<soap:Envelope" in rendered
    assert "<soap:Body>" in rendered
    assert "<!DOCTYPE" in rendered
    assert 'file:///etc/passwd' in rendered


def test_error_based_template_substitutes_placeholders():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    entry = {
        "id": "xxe-error-custom",
        "category": "error-based",
        "template": "error-based",
        "uri": "file:///etc/passwd",
        "entity_name": "err",
        "content_type": "application/xml",
        "payload": (
            '<?xml version="1.0"?>\n'
            '<!DOCTYPE r [<!ENTITY {ENTITY_NAME} SYSTEM "{URI}">]>\n'
            '<r>&{ENTITY_NAME};</r>'
        ),
    }
    out = specialist._render_payload(entry, oob_url=None)
    assert out is not None
    assert "{URI}" not in out
    assert "{ENTITY_NAME}" not in out
    assert "file:///etc/passwd" in out
    assert "&err;" in out


def test_no_doctype_sanity_has_no_entity():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    entry = {
        "id": "xxe-sanity-no-doctype",
        "category": "no-doctype-sanity",
        "template": "classic",
        "uri": "file:///dev/null",
        "entity_name": "xxe",
        "content_type": "application/xml",
        "payload": "",
    }
    out = specialist._render_payload(entry, oob_url=None)
    assert out is not None
    assert out.startswith("<?xml")
    assert "<!ENTITY" not in out


def test_parameter_entity_template_returns_none():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    entry = {
        "id": "xxe-param",
        "category": "parameter_entity-unix",
        "template": "parameter_entity",
        "uri": "file:///etc/passwd",
        "entity_name": "",
        "content_type": "application/xml",
        "payload": "",
    }
    assert specialist._render_payload(entry, oob_url=None) is None


def test_oob_blind_template_returns_none():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    entry = {
        "id": "xxe-oob",
        "category": "oob_blind-unix",
        "template": "oob_blind",
        "uri": "{OOB_URL}",
        "entity_name": "",
        "content_type": "application/xml",
        "payload": "",
    }
    assert specialist._render_payload(entry, oob_url=None) is None


@pytest.mark.asyncio
async def test_verified_short_circuits_to_next_target():
    http = ScriptedHttp(body_for=lambda a: _PASSWD_LINE)
    specialist = XxeSpecialist(
        http_tool=http, max_http_budget=40, max_targets=3,
    )
    _prime_cache(
        specialist,
        [
            {
                "id": "xxe-classic-passwd",
                "category": "classic-unix",
                "template": "classic",
                "uri": "file:///etc/passwd",
                "entity_name": "xxe",
                "content_type": "application/xml",
                "payload": "",
            }
        ],
    )
    state = State(base_url="http://localhost")
    state.recent_http_memory = [
        {"url": f"http://localhost/api/{i}",
         "headers": {"Content-Type": "application/xml"}}
        for i in range(3)
    ]
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(out) == 1
    # Only the first target's probe was fired before short-circuit.
    assert len(http.calls) == 1
    assert specialist._done is True


@pytest.mark.asyncio
async def test_budget_exhaustion_handled():
    http = ScriptedHttp(body_for=lambda a: "")
    specialist = XxeSpecialist(
        http_tool=http,
        max_http_budget=7,  # below min_reserve_http=8
    )
    _prime_cache(
        specialist,
        [
            {
                "id": "xxe-classic-passwd",
                "category": "classic-unix",
                "template": "classic",
                "uri": "file:///etc/passwd",
                "entity_name": "xxe",
                "content_type": "application/xml",
                "payload": "",
            }
        ],
    )
    notes: list[str] = []
    specialist._note = notes.append  # type: ignore[method-assign]
    state = _state_with_xml_body_target()
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    assert len(http.calls) == 0
    assert any("xxe:insufficient_budget" in n for n in notes)


@pytest.mark.asyncio
async def test_observation_recorded_per_payload():
    http = ScriptedHttp(body_for=lambda a: "<response>neutral</response>")
    specialist = XxeSpecialist(http_tool=http, max_http_budget=25)
    _prime_cache(
        specialist,
        [
            {
                "id": "xxe-classic-passwd",
                "category": "classic-unix",
                "template": "classic",
                "uri": "file:///etc/passwd",
                "entity_name": "xxe",
                "content_type": "application/xml",
                "payload": "",
            }
        ],
    )
    state = _state_with_xml_body_target()
    await specialist.propose_async(state, config=SpecialistConfig())
    assert len(http.calls) == 1
    # One observation recorded per probe, keyed by url|body|parameter.
    assert len(specialist._observations) == 1
    records = next(iter(specialist._observations.values()))
    assert len(records) == 1
    rec = records[0]
    assert rec["payload_id"] == "xxe-classic-passwd"
    assert rec["status"] == 200
    assert "body_excerpt" in rec
    assert rec["xml_parse_error"] is False


@pytest.mark.asyncio
async def test_memory_record_attempt_called_with_verified_classic_outcome():
    http = ScriptedHttp(body_for=lambda a: _PASSWD_LINE)

    recorded: list[dict[str, Any]] = []

    class FakeMemory:
        def record_attempt(
            self,
            *,
            episode_id: str,
            host: str,
            parameter: str,
            payload: str,
            outcome: str,
            filters_json: str = "",
        ) -> None:
            recorded.append(
                {
                    "episode_id": episode_id,
                    "host": host,
                    "parameter": parameter,
                    "payload": payload,
                    "outcome": outcome,
                }
            )

    specialist = XxeSpecialist(
        http_tool=http,
        memory=FakeMemory(),
        max_http_budget=25,
    )
    _prime_cache(
        specialist,
        [
            {
                "id": "xxe-classic-passwd",
                "category": "classic-unix",
                "template": "classic",
                "uri": "file:///etc/passwd",
                "entity_name": "xxe",
                "content_type": "application/xml",
                "payload": "",
            }
        ],
    )
    state = _state_with_xml_body_target()
    await specialist.propose_async(state, config=SpecialistConfig())
    assert recorded, "memory.record_attempt was never called"
    outcomes = [r["outcome"] for r in recorded]
    assert "verified_classic" in outcomes
