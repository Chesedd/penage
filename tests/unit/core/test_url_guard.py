from penage.core.actions import Action, ActionType
from penage.core.url_guard import UrlGuard


def test_url_guard_blocks_static_assets_only_for_http_actions():
    guard = UrlGuard(block_static_assets=True)
    actions = [
        Action(type=ActionType.HTTP, params={"method": "GET", "url": "http://localhost/static/app.js"}),
        Action(type=ActionType.HTTP, params={"method": "GET", "url": "http://localhost/dashboard"}),
        Action(type=ActionType.SHELL, params={"command": "echo ok"}),
    ]

    filtered = guard.filter(actions)
    assert [a.type for a in filtered] == [ActionType.HTTP, ActionType.SHELL]
    assert filtered[0].params["url"].endswith("/dashboard")