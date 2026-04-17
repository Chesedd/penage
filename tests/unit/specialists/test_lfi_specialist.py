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
async def test_has_weak_marker_detects_partial_signals():
    assert LfiSpecialist._has_weak_marker("see /etc/passwd") is True
    assert LfiSpecialist._has_weak_marker("look at win.ini") is True
    assert LfiSpecialist._has_weak_marker("root: something") is True
    # Proper passwd line is *strong*, not weak.
    assert LfiSpecialist._has_weak_marker("root:x:0:0:root:/root:/bin/bash") is False
    assert LfiSpecialist._has_weak_marker("nothing interesting") is False
    assert LfiSpecialist._has_weak_marker("") is False


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


_YAML_MIXED_CATEGORIES = """\
- id: lfi-unix-1
  category: unix
  family: unix_passwd
  depth: 3
  payload: ../../../etc/passwd
  expected_markers: []
  notes: unix one
- id: lfi-unix-2
  category: unix
  family: unix_hosts
  depth: 3
  payload: ../../../etc/hosts
  expected_markers: []
  notes: unix two
- id: lfi-bypass-1
  category: bypass
  family: unix_passwd
  depth: 4
  payload: ....//....//....//etc/passwd
  expected_markers: []
  notes: bypass one
- id: lfi-bypass-2
  category: bypass
  family: unix_passwd
  depth: 4
  payload: ..%2f..%2f..%2fetc%2fpasswd
  expected_markers: []
  notes: bypass two
"""


def test_load_yaml_entries_filters_by_bypass_category(tmp_path):
    yaml_path = tmp_path / "lfi.yaml"
    yaml_path.write_text(_YAML_MIXED_CATEGORIES, encoding="utf-8")
    specialist = LfiSpecialist(
        http_tool=None,
        max_http_budget=30,
        payload_library_path=yaml_path,
    )
    entries = specialist._load_yaml_entries(categories=("bypass",), limit=10)
    assert len(entries) == 2
    assert all(e["category"] == "bypass" for e in entries)
    assert {e["id"] for e in entries} == {"lfi-bypass-1", "lfi-bypass-2"}


def test_load_yaml_entries_multi_category(tmp_path):
    yaml_path = tmp_path / "lfi.yaml"
    yaml_path.write_text(_YAML_MIXED_CATEGORIES, encoding="utf-8")
    specialist = LfiSpecialist(
        http_tool=None,
        max_http_budget=30,
        payload_library_path=yaml_path,
    )
    entries = specialist._load_yaml_entries(
        categories=("unix", "bypass"), limit=10
    )
    categories = {e["category"] for e in entries}
    assert categories == {"unix", "bypass"}
    assert len(entries) == 4


# --- Phase 3 (deterministic bypass) --------------------------------------

def _magic_payload_responder(
    parameter: str, magic_payload: str, body_on_hit: str = PASSWD_BODY
) -> Responder:
    """Return a responder that only reveals ``body_on_hit`` on exact match."""

    def _respond(action: Action) -> Observation:
        value = _param_value(action, parameter)
        url = str(action.params.get("url"))
        if value == magic_payload:
            return _ok(body_on_hit, url=url)
        return _ok("<html>no marker</html>", url=url)

    return _respond


@pytest.mark.asyncio
async def test_phase_3_url_encoded_bypass_verified():
    base_url = "http://localhost/view"
    parameter = "file"
    # Priority-2 (single URL-encoded) form at depth 3, generated by
    # ``generate_traversal_variants`` for ``/etc/passwd``.
    magic = "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

    http_tool = FakeHttp(responder=_magic_payload_responder(parameter, magic))
    # Budget is sized so the deterministic set reaches priority-2 variants;
    # defaults cap phase 3 at 8 candidates which is exhausted by priority-1.
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=MemoryStore(":memory:"),
        max_http_budget=200,
        max_bypass_payloads=50,
    )
    state = _state_with_query_target(base_url, parameter)

    cands = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(cands) == 1
    finding = cands[0].metadata["evidence"]
    assert finding["verified"] is True
    assert finding["kind"] == "lfi_bypass_verified"
    assert finding["mode"] == "bypass"
    assert finding["family"] == "unix_passwd"
    assert finding["payload"] == magic
    assert finding["evidence"]["bypass_source"] == "generated"
    assert cands[0].score == 12.0


@pytest.mark.asyncio
async def test_phase_3_double_encoded_bypass_verified():
    base_url = "http://localhost/view"
    parameter = "file"
    # Priority-1 (double URL-encoded) form at depth 3. Priority-1 has 18
    # generated variants across the three well-known targets; to reach a
    # specific depth-3 form regardless of set iteration order we need the
    # cap to cover the whole priority-1 band.
    magic = "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"

    http_tool = FakeHttp(responder=_magic_payload_responder(parameter, magic))
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        max_http_budget=200,
        max_bypass_payloads=50,
    )
    state = _state_with_query_target(base_url, parameter)

    cands = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(cands) == 1
    finding = cands[0].metadata["evidence"]
    assert finding["kind"] == "lfi_bypass_verified"
    assert finding["mode"] == "bypass"
    assert finding["payload"] == magic
    assert finding["family"] == "unix_passwd"
    assert finding["evidence"]["bypass_source"] == "generated"


@pytest.mark.asyncio
async def test_phase_3_nullbyte_bypass_verified():
    base_url = "http://localhost/view"
    parameter = "file"
    # Priority-4 (null-byte) form at depth 3, generated by
    # ``generate_traversal_variants`` via ``base + "%00"``.
    magic = "../../../etc/passwd%00"

    http_tool = FakeHttp(responder=_magic_payload_responder(parameter, magic))
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        max_http_budget=200,
        max_bypass_payloads=50,
    )
    state = _state_with_query_target(base_url, parameter)

    cands = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(cands) == 1
    finding = cands[0].metadata["evidence"]
    assert finding["kind"] == "lfi_bypass_verified"
    assert finding["payload"] == magic
    assert finding["evidence"]["bypass_source"] == "generated"


@pytest.mark.asyncio
async def test_phase_3_yaml_bypass_payload_used():
    base_url = "http://localhost/view"
    parameter = "file"
    # yaml-only: generator emits null-byte variants at depths 3 and max_depth,
    # not at depth 5 with the "%00.jpg" suffix — so this payload lives
    # exclusively in the lfi.yaml ``bypass`` category.
    magic = "../../../../../etc/passwd%00.jpg"

    http_tool = FakeHttp(responder=_magic_payload_responder(parameter, magic))
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        max_http_budget=30,
    )
    state = _state_with_query_target(base_url, parameter)

    cands = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(cands) == 1
    finding = cands[0].metadata["evidence"]
    assert finding["kind"] == "lfi_bypass_verified"
    assert finding["payload"] == magic
    assert finding["evidence"]["bypass_source"] == "yaml"


@pytest.mark.asyncio
async def test_phase_3_priority_double_encoded_first():
    base_url = "http://localhost/view"
    parameter = "file"

    http_tool = FakeHttp(
        responder=lambda a: _ok(
            "<html>no marker</html>", url=str(a.params.get("url"))
        )
    )
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        max_http_budget=30,
    )
    state = _state_with_query_target(base_url, parameter)

    cands = await specialist.propose_async(state, config=SpecialistConfig())
    assert cands == []

    # Phase 2 fires ``max_deterministic_payloads`` (default 8) probes.
    # Phase 3's first call starts at index 8 — that payload must be a
    # double-URL-encoded form (priority 1).
    assert len(http_tool.calls) > 8
    first_phase_3 = http_tool.calls[8]
    value = _param_value(first_phase_3, parameter)
    assert "%252e" in value


@pytest.mark.asyncio
async def test_phase_3_no_hit_returns_none_no_findings_appended():
    base_url = "http://localhost/view"
    parameter = "file"

    http_tool = FakeHttp(
        responder=lambda a: _ok(
            "<html>no marker</html>", url=str(a.params.get("url"))
        )
    )
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        max_http_budget=30,
    )
    state = _state_with_query_target(base_url, parameter)

    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    # Phase 2 fires 8 deterministic probes, phase 3 adds more on top.
    assert len(http_tool.calls) > 8
    # No verified findings recorded.
    assert specialist._findings == []


# --- Phase 3 (LLM mutation tail) -----------------------------------------


class _FakeTracer:
    """Minimal tracer that captures notes/events in memory (no file I/O)."""

    episode_id = "fake-episode"

    def __init__(self) -> None:
        self.notes: list[str] = []
        self.events: list[tuple[str, dict]] = []

    def record_note(self, text: str, *, step: int | None = None) -> None:
        self.notes.append(text)

    def write_event(self, event: str, payload: dict) -> None:
        self.events.append((event, dict(payload)))


class _FakeLLM:
    """LLMClient placeholder — ``PayloadMutator`` is mocked, so this is
    only here to satisfy the ``self.llm_client is None`` gate.
    """

    provider_name = "fake"


def _make_fake_mutator(
    *,
    payloads: list[str] | None = None,
    raises: Exception | None = None,
    log: list[tuple] | None = None,
):
    """Factory for a drop-in fake ``PayloadMutator`` class.

    ``log`` (if provided) receives ``("init",)`` on construction and
    ``("mutate", max_candidates, context_type_value)`` on each ``mutate``
    call — tests use it to prove the mutator was or wasn't invoked.
    """

    class _FakeMutator:
        def __init__(self, *, llm_client, payload_library_path) -> None:
            if log is not None:
                log.append(("init",))

        async def mutate(self, *, context, filter_model, max_candidates):
            if log is not None:
                log.append(("mutate", max_candidates, context.context_type.value))
            if raises is not None:
                raise raises
            return list(payloads or [])

    return _FakeMutator


@pytest.mark.asyncio
async def test_phase_3_mutation_triggered_when_deterministic_fails(monkeypatch):
    base_url = "http://localhost/view"
    parameter = "file"
    log: list[tuple] = []
    monkeypatch.setattr(
        "penage.specialists.vulns.lfi.PayloadMutator",
        _make_fake_mutator(
            payloads=["llm-payload-1", "llm-payload-2"], log=log
        ),
    )

    http_tool = FakeHttp(
        responder=lambda a: _ok(
            "<html>no marker</html>", url=str(a.params.get("url"))
        )
    )
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        llm_client=_FakeLLM(),
        max_http_budget=30,
    )
    state = _state_with_query_target(base_url, parameter)

    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    # Mutator was constructed and mutate() was called once with the LFI context.
    assert ("init",) in log
    mutate_entries = [entry for entry in log if entry[0] == "mutate"]
    assert len(mutate_entries) == 1
    assert mutate_entries[0][1] == 3  # max_candidates
    assert mutate_entries[0][2] == "lfi_param"
    # Both LLM payloads were fired against the target parameter.
    fired = [_param_value(c, parameter) for c in http_tool.calls]
    assert "llm-payload-1" in fired
    assert "llm-payload-2" in fired


@pytest.mark.asyncio
async def test_phase_3_mutation_skipped_if_no_llm_client(monkeypatch):
    log: list[tuple] = []
    monkeypatch.setattr(
        "penage.specialists.vulns.lfi.PayloadMutator",
        _make_fake_mutator(payloads=["should-not-fire"], log=log),
    )

    tracer = _FakeTracer()
    http_tool = FakeHttp(
        responder=lambda a: _ok(
            "<html>no marker</html>", url=str(a.params.get("url"))
        )
    )
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        llm_client=None,
        tracer=tracer,
        max_http_budget=30,
    )
    state = _state_with_query_target("http://localhost/view", "file")

    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    # Mutator must not be constructed or called when no llm_client is wired.
    assert log == []
    fired = [_param_value(c, "file") for c in http_tool.calls]
    assert "should-not-fire" not in fired
    assert any("mutation_skipped=True" in n for n in tracer.notes)


@pytest.mark.asyncio
async def test_phase_3_mutation_skipped_if_budget_low(monkeypatch):
    log: list[tuple] = []
    monkeypatch.setattr(
        "penage.specialists.vulns.lfi.PayloadMutator",
        _make_fake_mutator(payloads=["should-not-fire"], log=log),
    )

    tracer = _FakeTracer()
    http_tool = FakeHttp(
        responder=lambda a: _ok(
            "<html>no marker</html>", url=str(a.params.get("url"))
        )
    )
    # Budget 20 is enough to enter phase 3 (remaining=12 after phase 2's 8
    # probes, 12 >= min_reserve_http=10) but phase 3 deterministic then
    # drains 8 more, leaving remaining=4 < 10 at the mutation gate.
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        llm_client=_FakeLLM(),
        tracer=tracer,
        max_http_budget=20,
        min_reserve_http=10,
    )
    state = _state_with_query_target("http://localhost/view", "file")

    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    assert not any(entry[0] == "mutate" for entry in log)
    fired = [_param_value(c, "file") for c in http_tool.calls]
    assert "should-not-fire" not in fired
    assert any("mutation_skipped=True" in n for n in tracer.notes)


@pytest.mark.asyncio
async def test_phase_3_mutation_payload_verified(monkeypatch):
    base_url = "http://localhost/view"
    parameter = "file"
    magic = "llm-magic-mutation"
    monkeypatch.setattr(
        "penage.specialists.vulns.lfi.PayloadMutator",
        _make_fake_mutator(payloads=[magic]),
    )

    http_tool = FakeHttp(
        responder=_magic_payload_responder(parameter, magic, body_on_hit=PASSWD_BODY),
    )
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=MemoryStore(":memory:"),
        llm_client=_FakeLLM(),
        max_http_budget=30,
    )
    state = _state_with_query_target(base_url, parameter)

    cands = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(cands) == 1
    finding = cands[0].metadata["evidence"]
    assert finding["verified"] is True
    assert finding["kind"] == "lfi_mutation_verified"
    assert finding["mode"] == "mutation"
    assert finding["family"] == "unix_passwd"
    assert finding["payload"] == magic
    assert finding["evidence"]["bypass_source"] == "llm_mutation"


@pytest.mark.asyncio
async def test_phase_3_mutation_error_logged_no_crash(monkeypatch):
    log: list[tuple] = []
    monkeypatch.setattr(
        "penage.specialists.vulns.lfi.PayloadMutator",
        _make_fake_mutator(raises=RuntimeError("boom"), log=log),
    )

    tracer = _FakeTracer()
    http_tool = FakeHttp(
        responder=lambda a: _ok(
            "<html>no marker</html>", url=str(a.params.get("url"))
        )
    )
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        llm_client=_FakeLLM(),
        tracer=tracer,
        max_http_budget=30,
    )
    state = _state_with_query_target("http://localhost/view", "file")

    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    # mutate() was called and raised, but the specialist handled it gracefully.
    assert any(entry[0] == "mutate" for entry in log)
    assert any(n.startswith("lfi:mutation_error") for n in tracer.notes)
    # Zero mutation HTTP calls fired past the failure.
    assert any(
        "bypass_phase_no_verified" in n and "mutation_tried=0" in n
        for n in tracer.notes
    )


# --- Phase 4 (OOB probes) ------------------------------------------------

import base64

from penage.specialists.shared.oob_listener import OobHit


def _build_php_base64_body() -> str:
    """Produce a benign body carrying a base64-encoded PHP source block.

    Needs to be long enough (>= 100 base64 chars) to match the code-leak
    detector regex, and to decode into a blob that contains one of the
    PHP tokens it checks for.
    """
    php_src = (
        "<?php\n"
        "$_GET['page'];\n"
        + "function f() { return include($_GET['x']); }\n" * 10
        + "?>\n"
    )
    encoded = base64.b64encode(php_src.encode("utf-8")).decode("ascii")
    assert len(encoded) > 100
    return f"HTTP/1.1 200 OK\nContent-Type: text/plain\n\n{encoded}\n"


class _FakeOobListener:
    """Minimal in-memory stand-in for OobListener — never opens a socket.

    The real listener binds to 127.0.0.1; the fake just synthesises the
    register_token / wait_for_hit contract so specialists can be unit
    tested without running an aiohttp server.
    """

    def __init__(
        self,
        *,
        is_running: bool = True,
        should_hit: bool = True,
        remote_addr: str = "127.0.0.1",
        raise_on_register: Exception | None = None,
    ) -> None:
        self.is_running = is_running
        self._should_hit = should_hit
        self._remote_addr = remote_addr
        self._raise = raise_on_register
        self.register_calls = 0
        self.wait_calls: list[tuple[str, float]] = []

    async def register_token(self) -> tuple[str, str]:
        self.register_calls += 1
        if self._raise is not None:
            raise self._raise
        return ("tok-abc123", "http://127.0.0.1:55555/canary/tok-abc123")

    async def wait_for_hit(self, token: str, timeout_s: float) -> OobHit | None:
        self.wait_calls.append((token, timeout_s))
        if self._should_hit:
            return OobHit(
                token=token,
                remote_addr=self._remote_addr,
                path=f"/canary/{token}",
                headers={},
                ts=0.0,
            )
        return None


def _state_with_query_target_value(
    base_url: str, parameter: str, value: str
) -> State:
    st = State(base_url=base_url)
    st.last_http_url = f"{base_url}?{parameter}={value}"
    return st


@pytest.mark.asyncio
async def test_phase_4_php_filter_base64_decoded_detects_code_leak():
    base_url = "http://localhost/view"
    parameter = "file"
    php_body = _build_php_base64_body()

    def respond(action: Action) -> Observation:
        value = _param_value(action, parameter)
        url = str(action.params.get("url"))
        if value.startswith("php://filter/convert.base64-encode/resource="):
            return _ok(php_body, url=url)
        return _ok("<html>no marker</html>", url=url)

    http_tool = FakeHttp(responder=respond)
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        llm_client=None,
        max_http_budget=200,
        max_bypass_payloads=50,
    )
    # original_value = index.php so the probe resource resolves to "index".
    state = _state_with_query_target_value(base_url, parameter, "index.php")

    cands = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(cands) == 1
    finding = cands[0].metadata["evidence"]
    assert finding["verified"] is True
    assert finding["kind"] == "lfi_code_leak_php"
    assert finding["mode"] == "oob_php_filter"
    assert finding["family"] == "code_leak"
    assert finding["payload"].startswith("php://filter/convert.base64-encode/resource=")
    assert finding["evidence"]["bypass_source"] == "php_filter"
    assert cands[0].score == 12.0


@pytest.mark.asyncio
async def test_phase_4_oob_hit_produces_ssrf_chain_finding():
    base_url = "http://localhost/view"
    parameter = "file"

    listener = _FakeOobListener(is_running=True, should_hit=True)

    def respond(action: Action) -> Observation:
        # Everything benign — the OOB hit, not the body, verifies this.
        return _ok("<html>benign</html>", url=str(action.params.get("url")))

    http_tool = FakeHttp(responder=respond)
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        llm_client=None,
        oob_listener=listener,
        oob_wait_s=0.1,
        max_http_budget=200,
        max_bypass_payloads=50,
    )
    state = _state_with_query_target_value(base_url, parameter, "report.txt")

    cands = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(cands) == 1
    finding = cands[0].metadata["evidence"]
    assert finding["verified"] is True
    assert finding["kind"] == "lfi_ssrf_chain"
    assert finding["mode"] == "oob_file_url"
    assert finding["evidence"]["oob_hit"]["remote_addr"] == "127.0.0.1"
    assert finding["evidence"]["chained_with_ssrf_semantics"] is True
    assert finding["evidence"]["bypass_source"] == "oob_file_url"
    assert listener.register_calls == 1
    assert listener.wait_calls and listener.wait_calls[0][0] == "tok-abc123"
    assert cands[0].score == 12.0


@pytest.mark.asyncio
async def test_phase_4_no_oob_listener_skips_file_url_probe():
    base_url = "http://localhost/view"
    parameter = "file"
    tracer = _FakeTracer()

    def respond(action: Action) -> Observation:
        return _ok("<html>benign</html>", url=str(action.params.get("url")))

    http_tool = FakeHttp(responder=respond)
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        llm_client=None,
        oob_listener=None,  # no listener — file:// probe is skipped
        tracer=tracer,
        max_http_budget=200,
        max_bypass_payloads=50,
    )
    state = _state_with_query_target_value(base_url, parameter, "index.php")

    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    # php_filter probe is still attempted (it does not need a listener)...
    fired = [_param_value(c, parameter) for c in http_tool.calls]
    assert any(p.startswith("php://filter/") for p in fired)
    # ...but no file-url / OOB probe should fire and no hit should register.
    assert not any("canary" in p for p in fired)
    assert any(
        "oob_phase_no_verified" in n and "file_oob_tried=False" in n
        for n in tracer.notes
    )


@pytest.mark.asyncio
async def test_phase_4_oob_listener_not_running_skips():
    base_url = "http://localhost/view"
    parameter = "file"
    tracer = _FakeTracer()
    listener = _FakeOobListener(is_running=False, should_hit=True)

    def respond(action: Action) -> Observation:
        return _ok("<html>benign</html>", url=str(action.params.get("url")))

    http_tool = FakeHttp(responder=respond)
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        llm_client=None,
        oob_listener=listener,
        tracer=tracer,
        max_http_budget=200,
        max_bypass_payloads=50,
    )
    state = _state_with_query_target_value(base_url, parameter, "index.php")

    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []
    # Listener was never asked to register a token because it wasn't running.
    assert listener.register_calls == 0
    assert listener.wait_calls == []
    assert any(
        "oob_phase_no_verified" in n and "file_oob_tried=False" in n
        for n in tracer.notes
    )


# --- Phase 5 (candidate finalization) ------------------------------------


@pytest.mark.asyncio
async def test_phase_5_weak_signal_candidate_emitted():
    base_url = "http://localhost/view"
    parameter = "file"
    # "root:" without a passwd line — weak marker, not strong.
    body = "the root: user is busy\ntry /etc/passwd\n"

    http_tool = FakeHttp(
        responder=lambda a: _ok(body, url=str(a.params.get("url")))
    )
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        llm_client=None,
        max_http_budget=30,
    )
    state = _state_with_query_target(base_url, parameter)

    cands = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(cands) == 1
    finding = cands[0].metadata["evidence"]
    assert finding["verified"] is False
    assert finding["kind"] == "lfi_weak_signal"
    assert finding["mode"] == "candidate"
    assert finding["parameter"] == parameter
    assert finding["evidence"]["weak_marker"] is True
    assert finding["reason"] == "partial_marker"
    assert cands[0].score == 3.0


@pytest.mark.asyncio
async def test_phase_5_size_anomaly_candidate_emitted():
    base_url = "http://localhost/view"
    parameter = "file"
    # No markers (strong or weak), but the body is big enough to trip the
    # size-anomaly heuristic (> 1500 chars).
    body = "<html>" + ("benign filler content blob " * 80) + "</html>"
    assert len(body) > 1500
    assert "root:" not in body.lower()
    assert "/etc/passwd" not in body.lower()

    http_tool = FakeHttp(
        responder=lambda a: _ok(body, url=str(a.params.get("url")))
    )
    specialist = LfiSpecialist(
        http_tool=http_tool,
        memory=None,
        llm_client=None,
        max_http_budget=30,
    )
    state = _state_with_query_target(base_url, parameter)

    cands = await specialist.propose_async(state, config=SpecialistConfig())
    assert len(cands) == 1
    finding = cands[0].metadata["evidence"]
    assert finding["verified"] is False
    assert finding["kind"] == "lfi_size_differential"
    assert finding["mode"] == "candidate"
    assert finding["evidence"]["size_anomaly"] is True
    assert finding["reason"] == "response_size_anomaly"
    assert cands[0].score == 2.0


@pytest.mark.asyncio
async def test_phase_5_no_observations_returns_none():
    specialist = LfiSpecialist(http_tool=None, max_http_budget=30)
    target = _LfiTarget(url="http://localhost/v", parameter="file", channel="GET")

    # Observations present but with all flags false — still no candidate.
    obs_none = [
        {
            "payload": "../../../etc/passwd",
            "status": 200,
            "body_excerpt": "nothing",
            "weak_marker": False,
            "size_anomaly": False,
        }
    ]
    assert (
        specialist._finalize_candidate(
            target=target, channel="GET", host_status_observations=obs_none
        )
        is None
    )
    # Empty observations list also returns None.
    assert (
        specialist._finalize_candidate(
            target=target, channel="GET", host_status_observations=[]
        )
        is None
    )


def test_verified_finding_takes_precedence_over_candidate():
    specialist = LfiSpecialist(http_tool=None, max_http_budget=30)
    candidate = {
        "verified": False,
        "kind": "lfi_weak_signal",
        "mode": "candidate",
        "summary": "Weak LFI signal",
        "family": "unknown",
    }
    verified = {
        "verified": True,
        "kind": "lfi_disclosure",
        "mode": "deterministic",
        "family": "unix_passwd",
        "summary": "LFI disclosure",
    }
    # Even with the candidate appended last, verified wins over unverified.
    specialist._findings = [verified, candidate]
    cands = specialist._emit_if_any()
    assert len(cands) == 1
    assert cands[0].metadata["evidence"]["verified"] is True
    assert cands[0].score == 12.0
    assert "verified" in cands[0].action.tags


def test_runtime_factory_wires_lfi_specialist():
    from pathlib import Path
    from penage.app.config import RuntimeConfig
    from penage.app.runtime_factory import build_specialists
    from penage.core.guard import RunMode
    from penage.llm.fake import FakeLLMClient

    cfg = RuntimeConfig(
        base_url="http://localhost:8080",
        llm_provider="ollama",
        llm_model="llama3.1",
        ollama_model="llama3.1",
        ollama_url="http://localhost:11434",
        trace_path=Path("trace.jsonl"),
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
    fake_llm = FakeLLMClient()
    manager = build_specialists(cfg, fake_llm)
    assert manager is not None
    assert any(isinstance(s, LfiSpecialist) for s in manager.specialists)
