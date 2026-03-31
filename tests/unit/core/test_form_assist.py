from penage.core.actions import Action, ActionType
from penage.core.form_assist import FormAssist
from penage.core.state import State


def test_form_assist_moves_query_params_into_post_data_and_fills_hidden_and_required_fields():
    st = State(
        last_forms=[
            {
                "method": "POST",
                "action": "http://localhost/login",
                "inputs": [
                    {"name": "csrf", "type": "hidden", "value": "abc", "required": False, "hidden": True},
                    {"name": "username", "type": "text", "value": None, "required": True, "hidden": False},
                    {"name": "password", "type": "password", "value": None, "required": True, "hidden": False},
                ],
            }
        ]
    )
    action = Action(
        type=ActionType.HTTP,
        params={
            "method": "POST",
            "url": "http://localhost/login",
            "params": {"username": "alice", "password": "secret"},
            "data": {},
        },
    )

    normalized = FormAssist().normalize_http_post(action, st)

    assert normalized.params["params"] == {}
    assert normalized.params["data"] == {
        "username": "alice",
        "password": "secret",
        "csrf": "abc",
    }


def test_form_assist_uses_path_match_from_forms_memory():
    st = State(
        forms_by_url={
            "http://localhost/step1": [
                {
                    "method": "POST",
                    "action": "http://localhost/auth/submit",
                    "inputs": [
                        {"name": "token", "type": "hidden", "value": "t1", "required": False, "hidden": True},
                    ],
                }
            ]
        }
    )
    action = Action(
        type=ActionType.HTTP,
        params={"method": "POST", "url": "http://localhost/auth/submit", "data": {}},
    )

    normalized = FormAssist().normalize_http_post(action, st)
    assert normalized.params["data"] == {"token": "t1"}