import pytest

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.state import State
from penage.validation.http import HttpEvidenceValidator


@pytest.mark.asyncio
async def test_http_validator_validates_explicit_flag_signal():
    validator = HttpEvidenceValidator()
    action = Action(type=ActionType.HTTP, params={"method": "GET", "url": "http://localhost/flag"})
    obs = Observation(
        ok=True,
        data={
            "status_code": 200,
            "url": "http://localhost/flag",
            "headers": {"content-type": "text/html"},
            "text_full": "hello FLAG{demo_flag}",
            "text_excerpt": "hello FLAG{demo_flag}",
            "contains_flag_like": True,
            "flag_snippets": ["FLAG{demo_flag}"],
        },
    )

    result = await validator.validate(action=action, obs=obs, state=State())
    assert result is not None
    assert result.level == "validated"
    assert result.kind == "flag_capture"


@pytest.mark.asyncio
async def test_http_validator_suppresses_login_gate_pages():
    validator = HttpEvidenceValidator()
    action = Action(type=ActionType.HTTP, params={"method": "GET", "url": "http://localhost/dashboard"})
    obs = Observation(
        ok=True,
        data={
            "status_code": 200,
            "url": "http://localhost/dashboard",
            "headers": {"content-type": "text/html"},
            "text_full": '<html><title>Login</title><form><input name="username"><input type="password"></form></html>',
            "text_excerpt": "Login page",
        },
    )

    assert await validator.validate(action=action, obs=obs, state=State()) is None