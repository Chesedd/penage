from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import pytest

from penage.core.actions import Action
from penage.core.observations import Observation
from penage.core.state import State
from penage.specialists.base import SpecialistConfig
from penage.specialists.vulns.idor import IdorSpecialist, _IdorTarget


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


def _noop(action: Action) -> Observation:
    return Observation(ok=True, elapsed_ms=1, data={"status_code": 200, "text_full": ""})


@pytest.mark.asyncio
async def test_no_candidate_targets_returns_empty():
    specialist = IdorSpecialist(http_tool=FakeHttp(_noop))
    state = State(base_url="http://localhost")
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []


@pytest.mark.asyncio
async def test_missing_http_tool_returns_empty():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://localhost/r?id=42"
    out = await specialist.propose_async(state, config=SpecialistConfig())
    assert out == []


def test_query_param_id_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/users?id=42"
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    t = targets[0]
    assert t.id_location == "query"
    assert t.id_param == "id"
    assert t.id_value == "42"
    assert t.is_numeric is True
    assert t.channel == "GET"


def test_query_param_user_id_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/r?user_id=42"
    targets = specialist._discover_targets(state)
    names = {t.id_param for t in targets}
    assert "user_id" in names


def test_query_param_non_hint_name_not_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/r?page=42"
    targets = specialist._discover_targets(state)
    assert targets == []


def test_path_numeric_segment_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/users/42"
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    t = targets[0]
    assert t.id_location == "path"
    assert t.path_segment_index == 1
    assert t.is_numeric is True
    assert t.id_value == "42"


def test_path_uuid_segment_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    state.last_http_url = f"http://x/doc/{uuid}"
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    t = targets[0]
    assert t.id_location == "path"
    assert t.id_value == uuid
    assert t.is_numeric is False


def test_path_prefixed_id_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/o/ord_ABCD1234"
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    t = targets[0]
    assert t.id_location == "path"
    assert t.id_value == "ord_ABCD1234"
    assert t.is_numeric is False


def test_path_non_id_segment_ignored():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/users/profile"
    targets = specialist._discover_targets(state)
    assert targets == []


def test_form_hidden_order_id_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.forms_by_url = {
        "http://x/cart": [
            {
                "action": "http://x/checkout",
                "method": "POST",
                "inputs": [
                    {"name": "order_id", "type": "hidden", "value": "123"},
                ],
            }
        ]
    }
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    t = targets[0]
    assert t.id_location == "form"
    assert t.id_param == "order_id"
    assert t.id_value == "123"
    assert t.channel == "POST"
    assert t.is_numeric is True


def test_form_visible_user_id_discovered():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.forms_by_url = {
        "http://x/page": [
            {
                "action": "http://x/submit",
                "method": "POST",
                "inputs": [
                    {"name": "user_id", "type": "text", "value": "7"},
                ],
            }
        ]
    }
    targets = specialist._discover_targets(state)
    assert len(targets) == 1
    t = targets[0]
    assert t.id_location == "form"
    assert t.id_param == "user_id"
    assert t.is_numeric is True


def test_form_password_input_skipped():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.forms_by_url = {
        "http://x/page": [
            {
                "action": "http://x/submit",
                "method": "POST",
                "inputs": [
                    {"name": "user_id", "type": "password", "value": "1"},
                ],
            }
        ]
    }
    targets = specialist._discover_targets(state)
    assert targets == []


def test_dedup_across_recent_http_memory_and_last_url():
    specialist = IdorSpecialist(http_tool=None)
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/r?id=42"
    state.recent_http_memory = [{"url": "http://x/r?id=42"}]
    targets = specialist._discover_targets(state)
    query_targets = [t for t in targets if t.id_location == "query"]
    assert len(query_targets) == 1


def test_max_targets_respected():
    specialist = IdorSpecialist(http_tool=None, max_targets=3)
    state = State(base_url="http://localhost")
    state.recent_http_memory = [
        {"url": f"http://x/r{i}?id={i}"} for i in range(10)
    ]
    targets = specialist._discover_targets(state)
    assert len(targets) == 3


@pytest.mark.asyncio
async def test_phases_0_2_3_4_5_not_implemented_raise():
    specialist = IdorSpecialist(http_tool=None)
    with pytest.raises(NotImplementedError):
        await specialist._run_login_phase()
    with pytest.raises(NotImplementedError):
        await specialist._run_horizontal_phase()
    with pytest.raises(NotImplementedError):
        await specialist._run_enumeration_phase()
    with pytest.raises(NotImplementedError):
        await specialist._run_vertical_phase()
    with pytest.raises(NotImplementedError):
        specialist._finalize_candidate()


@pytest.mark.asyncio
async def test_passwords_not_written_to_state():
    secret = "secret_role_a_pw_9371"
    secret_b = "secret_role_b_pw_4820"
    specialist = IdorSpecialist(
        http_tool=FakeHttp(_noop),
        role_a_password=secret,
        role_b_password=secret_b,
    )
    state = State(base_url="http://localhost")
    state.last_http_url = "http://x/r?id=1"
    await specialist.propose_async(state, config=SpecialistConfig())
    serialized = repr(state)
    assert secret not in serialized
    assert secret_b not in serialized
