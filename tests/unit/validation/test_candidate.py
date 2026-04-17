from __future__ import annotations

import json

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.validation.candidate import CandidateFinding


def _make_candidate(
    *,
    text_full: str = "",
    text_excerpt: str = "<html>hello</html>",
    extra_state: dict | None = None,
    evidence_so_far: dict | None = None,
) -> CandidateFinding:
    action = Action(
        type=ActionType.HTTP,
        params={"method": "GET", "url": "http://target/x?q=canary"},
    )
    obs = Observation(
        ok=True,
        data={
            "status_code": 200,
            "url": "http://target/x?q=canary",
            "headers": {"content-type": "text/html"},
            "text_full": text_full,
            "text_excerpt": text_excerpt,
        },
    )
    state_snapshot = {
        "base_url": "http://target",
        "last_http_url": "http://target/x?q=canary",
        "last_http_status": 200,
        "last_http_excerpt": text_excerpt,
    }
    if extra_state:
        state_snapshot.update(extra_state)
    return CandidateFinding(
        kind="xss",
        action=action,
        obs=obs,
        state_snapshot=state_snapshot,
        evidence_so_far=evidence_so_far or {},
    )


def test_candidate_to_prompt_payload_is_json_serialisable():
    candidate = _make_candidate()
    payload = candidate.to_prompt_payload()
    assert isinstance(payload, dict)
    serialised = json.dumps(payload, ensure_ascii=False)
    assert "xss" in serialised
    assert payload["kind"] == "xss"
    assert payload["action"]["type"] == "http"
    assert payload["observation"]["ok"] is True


def test_candidate_payload_drops_text_full_and_caps_excerpt():
    big_page = "A" * 10_000
    big_excerpt = "B" * 5_000
    candidate = _make_candidate(text_full=big_page, text_excerpt=big_excerpt)
    payload = candidate.to_prompt_payload()

    obs_data = payload["observation"]["data"]
    assert "text_full" not in obs_data
    assert len(obs_data["text_excerpt"]) <= 2000

    snapshot = payload["state_snapshot"]
    assert len(snapshot["last_http_excerpt"]) <= 2000


def test_candidate_payload_scrubs_sensitive_snapshot_keys():
    candidate = _make_candidate(
        extra_state={
            "cookies": {"session": "SECRET_COOKIE_VALUE"},
            "api_key": "sk-live-SECRET",
            "notes_tail": "benign note",
        },
    )
    payload = candidate.to_prompt_payload()
    serialised = json.dumps(payload, ensure_ascii=False)
    assert "SECRET_COOKIE_VALUE" not in serialised
    assert "sk-live-SECRET" not in serialised
    assert "benign note" in serialised


def test_candidate_payload_includes_evidence_so_far():
    candidate = _make_candidate(
        evidence_so_far={
            "http_validator": "candidate",
            "browser_verifier": {"kind": "alert", "text": "1"},
        },
    )
    payload = candidate.to_prompt_payload()
    assert payload["evidence_so_far"]["http_validator"] == "candidate"
    assert payload["evidence_so_far"]["browser_verifier"]["kind"] == "alert"
