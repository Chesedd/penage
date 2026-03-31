from penage.core.actions import Action, ActionType
from penage.core.guard import ExecutionGuard, RunMode, allowed_action_types_for_mode


def test_allowed_action_types_for_safe_http_mode():
    assert allowed_action_types_for_mode(RunMode.SAFE_HTTP) == {ActionType.HTTP, ActionType.NOTE}


def test_execution_guard_filters_disallowed_actions():
    guard = ExecutionGuard(allowed={ActionType.HTTP, ActionType.NOTE})
    actions = [
        Action(type=ActionType.HTTP, params={"method": "GET", "url": "http://localhost/"}),
        Action(type=ActionType.SHELL, params={"command": "id"}),
        Action(type=ActionType.NOTE, params={"text": "hi"}),
    ]

    filtered = guard.filter(actions)
    assert [a.type for a in filtered] == [ActionType.HTTP, ActionType.NOTE]