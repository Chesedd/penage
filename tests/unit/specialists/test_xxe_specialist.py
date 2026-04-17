from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

import pytest

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.specialists.base import SpecialistConfig
from penage.specialists.shared.oob_listener import OobHit
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


def _target(url: str = "http://localhost/api/xml") -> _XxeTarget:
    return _XxeTarget(
        url=url,
        delivery="body",
        parameter="",
        channel="POST",
        content_type="application/xml",
    )


def test_phase_5_xml_parse_error_produces_parser_reachable_candidate():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    target = _target()
    observations = [
        {
            "payload_id": "xxe-classic-passwd",
            "status": 200,
            "body_excerpt": "xmlParseEntityRef: no name",
            "xml_parse_error": True,
            "hits": ["xml_parse_error"],
        }
    ]
    candidate = specialist._finalize_candidate(
        target=target, channel=target.channel, observations=observations,
    )
    assert candidate is not None
    assert candidate["verified"] is False
    assert candidate["kind"] == "xxe_parser_reachable"
    assert candidate["mode"] == "candidate"
    assert candidate["family"] == "xml_parse_error"
    assert candidate["payload_id"] == "xxe-classic-passwd"
    assert candidate["evidence"]["xml_parse_error"] is True
    assert candidate["evidence"]["http_status"] == 200
    assert "parser reachable" in candidate["summary"].lower()


def test_phase_5_status_differential_produces_candidate():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    target = _target()
    observations = [
        {
            "payload_id": "xxe-a",
            "status": 200,
            "body_excerpt": "<ok/>",
            "xml_parse_error": False,
            "hits": [],
        },
        {
            "payload_id": "xxe-b",
            "status": 500,
            "body_excerpt": "internal server error",
            "xml_parse_error": False,
            "hits": [],
        },
    ]
    candidate = specialist._finalize_candidate(
        target=target, channel=target.channel, observations=observations,
    )
    assert candidate is not None
    assert candidate["verified"] is False
    assert candidate["kind"] == "xxe_status_differential"
    assert candidate["mode"] == "candidate"
    assert candidate["payload_id"] == "xxe-b"
    assert 200 in candidate["evidence"]["status_spread"]
    assert 500 in candidate["evidence"]["status_spread"]


def test_phase_5_no_observations_returns_none():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    target = _target()
    assert (
        specialist._finalize_candidate(
            target=target, channel=target.channel, observations=[],
        )
        is None
    )


def test_phase_5_all_4xx_returns_none():
    specialist = XxeSpecialist(http_tool=None, max_http_budget=25)
    target = _target()
    observations = [
        {
            "payload_id": "xxe-a",
            "status": 400,
            "body_excerpt": "bad request",
            "xml_parse_error": False,
            "hits": [],
        },
        {
            "payload_id": "xxe-b",
            "status": 403,
            "body_excerpt": "forbidden",
            "xml_parse_error": False,
            "hits": [],
        },
    ]
    assert (
        specialist._finalize_candidate(
            target=target, channel=target.channel, observations=observations,
        )
        is None
    )


@pytest.mark.asyncio
async def test_candidate_emitted_with_score_3_for_parser_reachable():
    # Response body carries an xml_parse_error marker string, but no strong
    # disclosure marker. Phases 2-4 produce no verified finding, so phase 5
    # finalizes a parser-reachable candidate.
    http = ScriptedHttp(
        body_for=lambda a: "XML parsing error: premature end of data",
        status_for=lambda a: 200,
    )
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
    assert candidate.score == 3.0
    finding = candidate.metadata["evidence"]
    assert finding["verified"] is False
    assert finding["kind"] == "xxe_parser_reachable"


@pytest.mark.asyncio
async def test_candidate_emitted_with_score_2_for_status_differential():
    calls = {"n": 0}

    def status_for(action: Action) -> int:
        calls["n"] += 1
        return 200 if calls["n"] == 1 else 500

    http = ScriptedHttp(
        body_for=lambda a: "<response>ok</response>",
        status_for=status_for,
    )
    specialist = XxeSpecialist(http_tool=http, max_http_budget=25)
    _prime_cache(
        specialist,
        [
            {
                "id": "xxe-a",
                "category": "classic-unix",
                "template": "classic",
                "uri": "file:///etc/passwd",
                "entity_name": "xxe",
                "content_type": "application/xml",
                "payload": "",
            },
            {
                "id": "xxe-b",
                "category": "classic-unix",
                "template": "classic",
                "uri": "file:///etc/hosts",
                "entity_name": "xxe",
                "content_type": "application/xml",
                "payload": "",
            },
        ],
    )
    state = _state_with_xml_body_target()
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(out) == 1
    candidate = out[0]
    assert candidate.score == 2.0
    finding = candidate.metadata["evidence"]
    assert finding["verified"] is False
    assert finding["kind"] == "xxe_status_differential"


@pytest.mark.asyncio
async def test_verified_takes_precedence_over_candidate_emit():
    # First probe verifies (passwd body). Phase 5 must not overwrite the
    # verified finding, and the emitter must ship a score=12.0 CandidateAction.
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
    # No unverified candidate was stashed.
    assert all(f.get("verified") for f in specialist._findings)


def test_runtime_factory_wires_xxe():
    from pathlib import Path as _Path

    from penage.app.config import RuntimeConfig
    from penage.app.runtime_factory import build_specialists
    from penage.core.guard import RunMode

    class _FakeLLM:
        provider_name = "fake"

    cfg = RuntimeConfig(
        base_url="http://localhost:8080",
        llm_provider="ollama",
        llm_model="llama3.1",
        ollama_model="llama3.1",
        ollama_url="http://localhost:11434",
        trace_path=_Path("trace.jsonl"),
        summary_path=None,
        mode=RunMode.SAFE_HTTP,
        allow_static=False,
        actions_per_step=1,
        max_steps=5,
        max_http_requests=10,
        max_total_text_len=1000,
        enable_specialists=True,
        policy_enabled=False,
        sandbox_backend="null",
        docker_image="python:3.12-slim",
        docker_network="none",
        experiment_tag="",
        allowed_hosts=(),
    )

    manager = build_specialists(
        cfg, _FakeLLM(), memory=None, tools=None, tracer=None
    )
    assert manager is not None
    assert any(isinstance(s, XxeSpecialist) for s in manager.specialists)
    assert any(getattr(s, "name", "") == "xxe" for s in manager.specialists)


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


# ---------------------------------------------------------------------------
# Phases 3 & 4 — parameter-entity + OOB blind
# ---------------------------------------------------------------------------


@dataclass
class _FakeOobListener:
    """Test double for :class:`OobListener`.

    ``hit_to_return`` is what :meth:`wait_for_hit` yields (``None`` = timeout).
    ``running`` toggles :attr:`is_running`. ``register_raises`` forces
    :meth:`register_token` to raise for register-failure scenarios.
    """

    hit_to_return: OobHit | None = None
    running: bool = True
    token_seq: int = 0
    probe_url_template: str = "http://127.0.0.1:55555/canary/{token}"
    register_raises: BaseException | None = None

    @property
    def is_running(self) -> bool:
        return self.running

    async def register_token(self) -> tuple[str, str]:
        if self.register_raises is not None:
            raise self.register_raises
        self.token_seq += 1
        token = f"tok{self.token_seq:03d}" + "0" * max(0, 16 - 6)
        return token, self.probe_url_template.format(token=token)

    async def wait_for_hit(self, token: str, timeout_s: float) -> OobHit | None:
        _ = (token, timeout_s)
        return self.hit_to_return


def _param_entity_passwd_entry() -> dict[str, Any]:
    return {
        "id": "xxe-param-passwd",
        "category": "parameter_entity-unix",
        "template": "parameter_entity",
        "uri": "file:///etc/passwd",
        "entity_name": "",
        "content_type": "application/xml",
        "payload": "",
    }


def _oob_passwd_entry() -> dict[str, Any]:
    return {
        "id": "xxe-oob-passwd",
        "category": "oob_blind-unix",
        "template": "oob_blind",
        "uri": "{OOB_URL}",
        "entity_name": "",
        "content_type": "application/xml",
        "local_file": "/etc/passwd",
        "payload": "",
    }


@pytest.mark.asyncio
async def test_phase_3_param_entity_passwd_verified():
    # Classic probe comes first in propose_async: it must miss so phase 3 runs.
    # ScriptedHttp returns passwd for EVERY request — phase 2 would already hit
    # on the classic category, so we prime cache with only parameter_entity.
    http = ScriptedHttp(body_for=lambda a: _PASSWD_LINE)
    specialist = XxeSpecialist(http_tool=http, max_http_budget=25)
    _prime_cache(specialist, [_param_entity_passwd_entry()])

    state = _state_with_xml_body_target()
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(out) == 1
    finding = out[0].metadata["evidence"]
    assert finding["verified"] is True
    assert finding["kind"] == "xxe_param_entity_disclosure"
    assert finding["mode"] == "parameter_entity"
    assert finding["family"] == "unix_passwd"
    assert finding["evidence"]["bypass_source"] == "parameter_entity"
    # The payload MUST be a parameter-entity shape.
    assert len(http.calls) == 1
    body = http.calls[0].params["data"]
    assert isinstance(body, str)
    assert "<!ENTITY % param1 SYSTEM" in body


@pytest.mark.asyncio
async def test_phase_3_no_marker_no_finding():
    http = ScriptedHttp(body_for=lambda a: "<response>neutral</response>")
    specialist = XxeSpecialist(http_tool=http, max_http_budget=25)
    _prime_cache(specialist, [_param_entity_passwd_entry()])

    state = _state_with_xml_body_target()
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    # A parameter-entity probe was sent even though no marker landed.
    assert len(http.calls) == 1
    body = http.calls[0].params["data"]
    assert "<!ENTITY % param1 SYSTEM" in body


@pytest.mark.asyncio
async def test_phase_3_dos_payload_dropped():
    http = ScriptedHttp(body_for=lambda a: "")
    specialist = XxeSpecialist(http_tool=http, max_http_budget=25)

    # Six entities trip XmlSafetyFilter.check → allowed=False.
    recursive = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE r [\n'
        '  <!ENTITY a "x">\n'
        '  <!ENTITY b "x">\n'
        '  <!ENTITY c "x">\n'
        '  <!ENTITY d "x">\n'
        '  <!ENTITY e "x">\n'
        '  <!ENTITY f "x">\n'
        '  <!ENTITY g "x">\n'
        ']>\n'
        '<r>ok</r>'
    )
    # We can't make build_parameter_entity_payload produce that directly,
    # but we can patch the helper the phase calls to force the DoS path.
    from penage.specialists.vulns import xxe as xxe_module

    orig = xxe_module.build_parameter_entity_payload
    xxe_module.build_parameter_entity_payload = lambda uri: recursive  # type: ignore[assignment]
    try:
        _prime_cache(specialist, [_param_entity_passwd_entry()])
        notes: list[str] = []
        specialist._note = notes.append  # type: ignore[method-assign]
        state = _state_with_xml_body_target()
        out = await specialist.propose_async(state, config=SpecialistConfig())
    finally:
        xxe_module.build_parameter_entity_payload = orig  # type: ignore[assignment]

    assert out == []
    assert len(http.calls) == 0
    assert any("xxe:dos_payload_dropped" in n for n in notes)


@pytest.mark.asyncio
async def test_phase_4_no_oob_listener_skips_gracefully():
    http = ScriptedHttp(body_for=lambda a: "<response>neutral</response>")
    specialist = XxeSpecialist(http_tool=http, max_http_budget=25, oob_listener=None)
    _prime_cache(specialist, [_oob_passwd_entry()])

    notes: list[str] = []
    specialist._note = notes.append  # type: ignore[method-assign]

    state = _state_with_xml_body_target()
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    assert any("xxe:oob_listener_unavailable" in n for n in notes)
    assert len(http.calls) == 0  # no payloads were dispatched.


@pytest.mark.asyncio
async def test_phase_4_oob_listener_not_running_skips():
    http = ScriptedHttp(body_for=lambda a: "<response>neutral</response>")
    listener = _FakeOobListener(hit_to_return=None, running=False)
    specialist = XxeSpecialist(
        http_tool=http,
        max_http_budget=25,
        oob_listener=listener,  # type: ignore[arg-type]
    )
    _prime_cache(specialist, [_oob_passwd_entry()])

    notes: list[str] = []
    specialist._note = notes.append  # type: ignore[method-assign]

    state = _state_with_xml_body_target()
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    assert any("xxe:oob_listener_unavailable" in n for n in notes)
    assert len(http.calls) == 0


@pytest.mark.asyncio
async def test_phase_4_oob_hit_produces_verified_blind_finding():
    hit = OobHit(
        token="tok001" + "0" * 10,
        remote_addr="10.0.0.7",
        path="/canary/tok0010000000000000",
        headers={"User-Agent": "libxml2/2.9.14"},
        ts=time.time(),
    )
    listener = _FakeOobListener(hit_to_return=hit, running=True)
    http = ScriptedHttp(body_for=lambda a: "<response>neutral</response>")
    specialist = XxeSpecialist(
        http_tool=http,
        max_http_budget=25,
        oob_listener=listener,  # type: ignore[arg-type]
    )
    _prime_cache(specialist, [_oob_passwd_entry()])

    state = _state_with_xml_body_target()
    out = await specialist.propose_async(state, config=SpecialistConfig())

    assert len(out) == 1
    finding = out[0].metadata["evidence"]
    assert finding["verified"] is True
    assert finding["kind"] == "xxe_oob_blind"
    assert finding["mode"] == "oob_blind"
    assert finding["family"] == "oob_echo"
    assert finding["evidence"]["oob_hit"]["remote_addr"] == "10.0.0.7"
    assert finding["evidence"]["oob_hit"]["path"] == "/canary/tok0010000000000000"
    assert finding["evidence"]["local_file_probed"] == "/etc/passwd"
    assert finding["evidence"]["bypass_source"] == "oob_blind"
    # At least one HTTP probe was fired.
    assert len(http.calls) >= 1
    body = http.calls[0].params["data"]
    assert "file:///etc/passwd" in body
    assert "127.0.0.1:55555" in body


@pytest.mark.asyncio
async def test_phase_4_oob_timeout_no_finding():
    listener = _FakeOobListener(hit_to_return=None, running=True)
    http = ScriptedHttp(body_for=lambda a: "<response>neutral</response>")
    specialist = XxeSpecialist(
        http_tool=http,
        max_http_budget=25,
        oob_listener=listener,  # type: ignore[arg-type]
        max_oob_payloads=1,
    )
    _prime_cache(specialist, [_oob_passwd_entry()])

    state = _state_with_xml_body_target()
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    # The payload fired even though no hit landed.
    assert len(http.calls) == 1


@pytest.mark.asyncio
async def test_phase_4_oob_register_failure_noted_continues():
    listener = _FakeOobListener(
        hit_to_return=None,
        running=True,
        register_raises=RuntimeError("boom"),
    )
    http = ScriptedHttp(body_for=lambda a: "<response>neutral</response>")
    specialist = XxeSpecialist(
        http_tool=http,
        max_http_budget=25,
        oob_listener=listener,  # type: ignore[arg-type]
        max_oob_payloads=2,
    )
    _prime_cache(
        specialist,
        [_oob_passwd_entry(), _oob_passwd_entry()],
    )

    notes: list[str] = []
    specialist._note = notes.append  # type: ignore[method-assign]

    state = _state_with_xml_body_target()
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    # Every entry tried registration and failed — no HTTP dispatched.
    assert len(http.calls) == 0
    assert any("xxe:oob_register_failed" in n for n in notes)


@pytest.mark.asyncio
async def test_verified_oob_evidence_includes_remote_addr_and_path():
    hit = OobHit(
        token="tok001" + "0" * 10,
        remote_addr="192.0.2.55",
        path="/canary/tok0010000000000000",
        headers={"User-Agent": "libxml2/2.9"},
        ts=time.time(),
    )
    listener = _FakeOobListener(hit_to_return=hit, running=True)
    http = ScriptedHttp(body_for=lambda a: "")
    specialist = XxeSpecialist(
        http_tool=http,
        max_http_budget=25,
        oob_listener=listener,  # type: ignore[arg-type]
    )
    _prime_cache(specialist, [_oob_passwd_entry()])

    state = _state_with_xml_body_target()
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(out) == 1
    evidence = out[0].metadata["evidence"]["evidence"]
    assert evidence["oob_hit"]["remote_addr"] == "192.0.2.55"
    assert evidence["oob_hit"]["path"] == "/canary/tok0010000000000000"
