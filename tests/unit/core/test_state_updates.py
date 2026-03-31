from __future__ import annotations

import json

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.state import State
from penage.core.state_updates import StateUpdater
from penage.core.tracer import JsonlTracer


def _updater(tmp_path):
    return StateUpdater(tracer=JsonlTracer(tmp_path / "trace.jsonl", episode_id="test"))


def test_state_updater_records_negative_http_result_and_recent_memory(tmp_path):
    updater = _updater(tmp_path)
    st = State(facts={"base_url": "http://localhost", "orch_step": 1})
    action = Action(type=ActionType.HTTP, params={"method": "GET", "url": "http://localhost/missing"})
    obs = Observation(
        ok=True,
        data={
            "status_code": 404,
            "url": "http://localhost/missing",
            "headers": {"content-type": "text/html"},
            "text_excerpt": "not found",
            "text_full": "<html><body>not found</body></html>",
            "text_len": 35,
            "paths": [],
        },
    )

    updater.update_state(st, action, obs)

    assert st.last_http_status == 404
    assert "/missing" in st.research_negatives
    assert st.recent_failures[-1]["path"] == "/missing"
    assert st.recent_http_memory[-1]["url"] == "http://localhost/missing"
    assert st.last_action_family is not None


def test_state_updater_promotes_pivot_from_auth_confusion_shell_output(tmp_path):
    updater = _updater(tmp_path)
    st = State(facts={"orch_step": 4})
    action = Action(type=ActionType.SHELL, params={"command": "python recon.py"})
    payload = {
        "auth_hits": [
            {
                "id": "1337",
                "post_location": "/dashboard",
                "improved_targets": [{"path": "/orders/1337/receipt"}],
            }
        ],
        "paths": ["/dashboard"],
        "ids": ["1337"],
    }
    obs = Observation(ok=True, data={"stdout": json.dumps(payload)})

    updater.update_state(st, action, obs)

    assert st.promoted_pivot_ids == ["1337"]
    assert "/dashboard" in st.promoted_pivot_targets
    assert "/orders/1337/receipt" in st.promoted_pivot_targets
    assert st.facts["auth_confusion_runs"] == 1
    assert "1337" in st.best_http_ids