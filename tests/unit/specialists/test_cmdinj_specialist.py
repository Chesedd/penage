from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.llm.fake import FakeLLMClient
from penage.specialists.base import SpecialistConfig
from penage.specialists.vulns import CmdInjSpecialist
from penage.specialists.vulns.cmdinj import (
    _BudgetedHttpTool,
    _CmdInjTarget,
    _marker_appears_escaped,
)


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


@dataclass
class ScriptedHttp:
    """Fake HTTP backend returning a scripted Observation per call.

    - ``bodies``: list of response text bodies matched positionally to calls.
      Use ``None`` for an explicit failure (``ok=False``).
    - ``elapsed_ms_seq``: optional per-call elapsed_ms values. Defaults to 10.
    - ``body_matcher``: optional callable ``(Action) -> str`` that returns the
      body when set; overrides ``bodies``. Used to echo a specific marker back
      after inspecting the payload that was sent.
    """

    bodies: list[str | None] = field(default_factory=list)
    elapsed_ms_seq: list[int] | None = None
    body_matcher: object | None = None
    calls: list[Action] = field(default_factory=list)

    async def run(self, action: Action) -> Observation:
        idx = len(self.calls)
        self.calls.append(action)
        elapsed = 10
        if self.elapsed_ms_seq is not None and idx < len(self.elapsed_ms_seq):
            elapsed = self.elapsed_ms_seq[idx]
        if self.body_matcher is not None:
            body = self.body_matcher(action)  # type: ignore[misc]
            if body is None:
                return Observation(ok=False, error="scripted_failure")
            return Observation(
                ok=True,
                elapsed_ms=elapsed,
                data={"status_code": 200, "text_full": body, "text_excerpt": body[:200]},
            )
        body = self.bodies[idx] if idx < len(self.bodies) else ""
        if body is None:
            return Observation(ok=False, error="scripted_failure")
        return Observation(
            ok=True,
            elapsed_ms=elapsed,
            data={"status_code": 200, "text_full": body, "text_excerpt": body[:200]},
        )

    async def aclose(self) -> None:
        return None


def _state_with_query(url: str = "http://localhost/ping?host=1") -> State:
    state = State(base_url="http://localhost")
    state.last_http_url = url
    return state


@pytest.mark.asyncio
async def test_baseline_timing_measured() -> None:
    http = ScriptedHttp(bodies=["", "", ""], elapsed_ms_seq=[100, 200, 300])
    specialist = CmdInjSpecialist(
        http_tool=http,
        llm_client=FakeLLMClient(fixed_text=""),
        max_http_budget=20,
        baseline_samples=3,
    )
    target = _CmdInjTarget(url="http://localhost/ping", parameter="host", channel="GET", original_value="1")
    budgeted = _BudgetedHttpTool(http, State(base_url="http://localhost"), cap=10)
    baseline = await specialist._measure_baseline(target, budgeted)
    assert baseline is not None
    assert baseline["samples"] == [0.1, 0.2, 0.3]
    assert baseline["median_s"] == 0.2
    assert baseline["max_s"] == 0.3


@pytest.mark.asyncio
async def test_baseline_std_reported() -> None:
    http = ScriptedHttp(bodies=["", "", ""], elapsed_ms_seq=[100, 200, 300])
    specialist = CmdInjSpecialist(
        http_tool=http,
        llm_client=FakeLLMClient(fixed_text=""),
        max_http_budget=20,
        baseline_samples=3,
    )
    target = _CmdInjTarget(url="http://localhost/ping", parameter="host", channel="GET", original_value="1")
    budgeted = _BudgetedHttpTool(http, State(base_url="http://localhost"), cap=10)
    baseline = await specialist._measure_baseline(target, budgeted)
    assert baseline is not None
    assert "std_ms" in baseline
    # stdev of [0.1, 0.2, 0.3] seconds is 0.1 s = 100 ms.
    assert baseline["std_ms"] == pytest.approx(100.0, rel=1e-6)


@pytest.mark.asyncio
async def test_echo_marker_reflected_verified() -> None:
    # The fake backend echoes back the payload that was sent, which contains
    # the unique marker -> verified finding.
    def _echo_back(action: Action) -> str:
        params = action.params
        if params.get("method") == "GET":
            return f"pre {params['url']} post"
        data = params.get("data") or {}
        return "pre " + " ".join(str(v) for v in data.values()) + " post"

    http = ScriptedHttp(body_matcher=_echo_back)
    specialist = CmdInjSpecialist(
        http_tool=http,
        llm_client=FakeLLMClient(fixed_text=""),
        max_http_budget=20,
    )
    target = _CmdInjTarget(url="http://localhost/ping", parameter="host", channel="GET", original_value="1")
    budgeted = _BudgetedHttpTool(http, State(base_url="http://localhost"), cap=10)
    finding = await specialist._run_echo_phase(
        target=target,
        http_tool=budgeted,
        host="localhost",
        config=SpecialistConfig(),
        step=0,
    )
    assert finding is not None
    assert finding["verified"] is True
    assert finding["mode"] == "echo"
    assert finding["parameter"] == "host"
    marker = finding["evidence"]["marker"]
    assert marker.startswith("pncmd_")
    assert marker in finding["evidence"]["response_excerpt"]
    assert finding["evidence"]["os_hint"] == "unknown"
    assert finding["evidence"]["fingerprint_signals"] == []


@pytest.mark.asyncio
async def test_echo_marker_escaped_recorded_as_no_exec() -> None:
    # Body never contains the raw marker but contains an HTML-escaped separator.
    # This should produce a "reflected_no_exec" outcome and no verified finding.
    attempts: list[tuple[str, str]] = []

    class _MemSpy:
        def record_attempt(self, *, episode_id, host, parameter, payload, outcome):
            _ = (episode_id, host, parameter, payload)
            attempts.append((payload, outcome))

    def _escape_back(action: Action) -> str:
        # Respond with HTML-escaped separator but no raw marker anywhere.
        return "error near &#59; syntax"

    http = ScriptedHttp(body_matcher=_escape_back)
    specialist = CmdInjSpecialist(
        http_tool=http,
        llm_client=FakeLLMClient(fixed_text=""),
        max_http_budget=20,
        max_echo_payloads=2,
        memory=_MemSpy(),  # type: ignore[arg-type]
    )
    target = _CmdInjTarget(url="http://localhost/x", parameter="cmd", channel="GET", original_value="1")
    budgeted = _BudgetedHttpTool(http, State(base_url="http://localhost"), cap=10)
    finding = await specialist._run_echo_phase(
        target=target,
        http_tool=budgeted,
        host="localhost",
        config=SpecialistConfig(),
        step=0,
    )
    assert finding is None
    assert attempts, "expected at least one recorded attempt"
    assert all(outcome == "reflected_no_exec" for _, outcome in attempts)


@pytest.mark.asyncio
async def test_echo_no_reflection_no_finding() -> None:
    http = ScriptedHttp(body_matcher=lambda action: "nothing interesting here")
    specialist = CmdInjSpecialist(
        http_tool=http,
        llm_client=FakeLLMClient(fixed_text=""),
        max_http_budget=20,
        max_echo_payloads=3,
    )
    target = _CmdInjTarget(url="http://localhost/x", parameter="cmd", channel="POST", original_value="")
    budgeted = _BudgetedHttpTool(http, State(base_url="http://localhost"), cap=10)
    finding = await specialist._run_echo_phase(
        target=target,
        http_tool=budgeted,
        host="localhost",
        config=SpecialistConfig(),
        step=0,
    )
    assert finding is None


@pytest.mark.asyncio
async def test_echo_destructive_yaml_entry_dropped() -> None:
    # Inject a destructive entry into the cache. _filter must reject it and
    # the specialist must not perform the HTTP call.
    http = ScriptedHttp(body_matcher=lambda action: "")
    specialist = CmdInjSpecialist(
        http_tool=http,
        llm_client=FakeLLMClient(fixed_text=""),
        max_http_budget=20,
        max_echo_payloads=1,
    )
    specialist._yaml_cache = [
        {
            "id": "destructive-test",
            "category": "echo-separator",
            "separator": ";",
            "payload": "; rm -rf / ; echo {MARKER}",
        }
    ]
    target = _CmdInjTarget(url="http://localhost/x", parameter="cmd", channel="GET", original_value="1")
    budgeted = _BudgetedHttpTool(http, State(base_url="http://localhost"), cap=10)
    finding = await specialist._run_echo_phase(
        target=target,
        http_tool=budgeted,
        host="localhost",
        config=SpecialistConfig(),
        step=0,
    )
    assert finding is None
    assert http.calls == []  # filter dropped, no HTTP request was made


@pytest.mark.asyncio
async def test_fingerprint_linux_hint() -> None:
    http = ScriptedHttp(body_matcher=lambda action: "something Linux 5.4.0-generic something")
    specialist = CmdInjSpecialist(
        http_tool=http,
        llm_client=FakeLLMClient(fixed_text=""),
        max_http_budget=20,
        max_fingerprint_payloads=1,
    )
    target = _CmdInjTarget(url="http://localhost/x", parameter="cmd", channel="GET", original_value="1")
    budgeted = _BudgetedHttpTool(http, State(base_url="http://localhost"), cap=10)
    os_hint, signals = await specialist._run_fingerprint_phase(
        target=target,
        http_tool=budgeted,
        config=SpecialistConfig(),
        step=0,
    )
    assert os_hint == "linux"
    assert signals  # at least one payload id captured


@pytest.mark.asyncio
async def test_fingerprint_windows_hint() -> None:
    http = ScriptedHttp(body_matcher=lambda action: "Microsoft Windows [Version 10.0.19045.3693]")
    specialist = CmdInjSpecialist(
        http_tool=http,
        llm_client=FakeLLMClient(fixed_text=""),
        max_http_budget=20,
        max_fingerprint_payloads=1,
    )
    target = _CmdInjTarget(url="http://localhost/x", parameter="cmd", channel="GET", original_value="1")
    budgeted = _BudgetedHttpTool(http, State(base_url="http://localhost"), cap=10)
    os_hint, signals = await specialist._run_fingerprint_phase(
        target=target,
        http_tool=budgeted,
        config=SpecialistConfig(),
        step=0,
    )
    assert os_hint == "windows"
    assert signals


@pytest.mark.asyncio
async def test_fingerprint_unknown_hint() -> None:
    http = ScriptedHttp(body_matcher=lambda action: "nothing useful")
    specialist = CmdInjSpecialist(
        http_tool=http,
        llm_client=FakeLLMClient(fixed_text=""),
        max_http_budget=20,
        max_fingerprint_payloads=2,
    )
    target = _CmdInjTarget(url="http://localhost/x", parameter="cmd", channel="GET", original_value="1")
    budgeted = _BudgetedHttpTool(http, State(base_url="http://localhost"), cap=10)
    os_hint, signals = await specialist._run_fingerprint_phase(
        target=target,
        http_tool=budgeted,
        config=SpecialistConfig(),
        step=0,
    )
    assert os_hint == "unknown"
    assert signals == []


@pytest.mark.asyncio
async def test_verified_finding_prevents_second_target() -> None:
    # Two query-string params -> two targets. First target's echo probe
    # reflects the marker (verified). The specialist must mark itself done
    # and NOT run any more probes on the second target.
    def _echo_first_only(action: Action) -> str:
        url = action.params.get("url", "")
        data = action.params.get("data") or {}
        body = url
        if data:
            body += " " + " ".join(str(v) for v in data.values())
        if "host=" in url and "pncmd_" in url:
            return body
        if "cmd=" in url and "pncmd_" in url:
            # Second target: reflect so we'd also verify — but we shouldn't
            # reach this point because _done stops the loop.
            return body
        return ""

    http = ScriptedHttp(body_matcher=_echo_first_only, elapsed_ms_seq=[10] * 50)
    specialist = CmdInjSpecialist(
        http_tool=http,
        llm_client=FakeLLMClient(fixed_text=""),
        max_http_budget=40,
        baseline_samples=2,
        max_echo_payloads=2,
        max_fingerprint_payloads=1,
    )
    state = State(base_url="http://localhost")
    state.last_http_url = "http://localhost/run?host=1&cmd=x"

    result = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(result) == 1
    candidate = result[0]
    assert candidate.metadata["evidence"]["verified"] is True
    assert specialist._done is True
    # Only the first target should have been used: its parameter should appear
    # in attempted, and the keys should be <= 1 (the second target is skipped
    # by the break after verified finding).
    assert len(specialist._attempted) == 1
    first_key = next(iter(specialist._attempted))
    assert "|host" in first_key


def test_marker_appears_escaped_helper() -> None:
    assert _marker_appears_escaped("error near &#59; syntax", "pncmd_abc") is True
    assert _marker_appears_escaped("nothing special", "pncmd_abc") is False
    # If the marker itself is present verbatim we consider it NOT just-escaped.
    assert _marker_appears_escaped("yes pncmd_abc here &#59;", "pncmd_abc") is False
