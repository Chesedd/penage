from __future__ import annotations

import pytest

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.state import State
from penage.sandbox.browser_base import Browser
from penage.sandbox.fake_browser import FakeBrowser
from penage.validation.browser import BrowserEvidenceValidator, MARKERS_JSON_EXPR


_MARKER = "__penage_xss_marker__"
_PROBE = "window.__penage_xss_marker__ || ''"


def _browser_action(
    *,
    url: str = "http://target/vuln?q=payload",
    payload: str = "<script>__penage_xss_marker__</script>",
    browser_target: bool = True,
) -> Action:
    params: dict[str, object] = {"method": "GET", "url": url}
    if browser_target:
        params["browser_target"] = True
        params["browser_payload"] = payload
    return Action(type=ActionType.HTTP, params=params, tags=["xss", "probe"])


def _obs() -> Observation:
    return Observation(ok=True, data={"status_code": 200, "url": "http://target/vuln"})


def test_fake_browser_satisfies_browser_protocol():
    assert isinstance(FakeBrowser(), Browser)


@pytest.mark.asyncio
async def test_validator_ignores_non_browser_target_action():
    fake = FakeBrowser()
    validator = BrowserEvidenceValidator(browser=fake)

    action = _browser_action(browser_target=False)
    result = await validator.validate(action=action, obs=_obs(), state=State())

    assert result is None
    assert fake.navigations == []
    assert fake.js_calls == []


@pytest.mark.asyncio
async def test_validator_ignores_browser_target_without_url_or_payload():
    fake = FakeBrowser()
    validator = BrowserEvidenceValidator(browser=fake)

    action = Action(
        type=ActionType.HTTP,
        params={"browser_target": True, "url": "http://target/x"},
    )
    result = await validator.validate(action=action, obs=_obs(), state=State())

    assert result is None
    assert fake.navigations == []


@pytest.mark.asyncio
async def test_validator_returns_none_when_navigate_fails():
    url = "http://target/vuln?q=payload"
    fake = FakeBrowser(navigate_failures={url})
    validator = BrowserEvidenceValidator(browser=fake)

    action = _browser_action(url=url)
    result = await validator.validate(action=action, obs=_obs(), state=State())

    assert result is None
    assert fake.navigations == [url]
    assert fake.js_calls == []


@pytest.mark.asyncio
async def test_validator_returns_none_when_payload_not_reflected():
    url = "http://target/vuln?q=payload"
    payload = "<script>__penage_xss_marker__</script>"
    fake = FakeBrowser(dom_responses={url: "<html><body>no reflection here</body></html>"})
    validator = BrowserEvidenceValidator(browser=fake)

    action = _browser_action(url=url, payload=payload)
    result = await validator.validate(action=action, obs=_obs(), state=State())

    assert result is None
    assert fake.navigations == [url]
    assert fake.js_calls == []


@pytest.mark.asyncio
async def test_validator_returns_evidence_when_reflected_without_execution():
    url = "http://target/vuln?q=payload"
    payload = "<script>__penage_xss_marker__</script>"
    fake = FakeBrowser(
        dom_responses={url: f"<html><body>reflected: {payload}</body></html>"},
        js_responses={_PROBE: "", MARKERS_JSON_EXPR: "[]"},
    )
    validator = BrowserEvidenceValidator(browser=fake)

    action = _browser_action(url=url, payload=payload)
    result = await validator.validate(action=action, obs=_obs(), state=State())

    assert result is not None
    assert result.level == "evidence"
    assert result.kind == "xss_browser_reflection"
    assert result.evidence["url"] == url
    assert result.evidence["payload"] == payload
    assert result.evidence["execution_markers"] == []
    assert payload in result.evidence["reflection_dom_fragment"]
    assert fake.js_calls == [_PROBE, MARKERS_JSON_EXPR]


@pytest.mark.asyncio
async def test_validator_returns_validated_when_probe_marker_present():
    url = "http://target/vuln?q=payload"
    payload = "<script>__penage_xss_marker__</script>"
    fake = FakeBrowser(
        dom_responses={url: f"<html><body>reflected: {payload}</body></html>"},
        js_responses={
            _PROBE: _MARKER,
            MARKERS_JSON_EXPR: '[{"type": "alert", "message": "1"}]',
        },
    )
    validator = BrowserEvidenceValidator(browser=fake)

    action = _browser_action(url=url, payload=payload)
    result = await validator.validate(action=action, obs=_obs(), state=State())

    assert result is not None
    assert result.level == "validated"
    assert result.kind == "xss_browser_execution"
    assert result.evidence["js_result"] == _MARKER
    markers = result.evidence["execution_markers"]
    assert markers == [{"type": "alert", "message": "1"}]
    assert fake.js_calls == [_PROBE, MARKERS_JSON_EXPR]


@pytest.mark.asyncio
async def test_validator_validated_via_markers_array_only():
    """Default probe returns an opaque value but the marker JSON is populated.

    This mirrors the real Playwright path, where ``window.__penage_xss_marker__``
    is an array of dialog records: ``str(arr)`` in Python does not contain
    the marker substring, so execution must be recognised via the JSON probe.
    """
    url = "http://target/vuln?q=payload"
    payload = "<script>alert(1)</script>"
    fake = FakeBrowser(
        dom_responses={url: f"<html><body>reflected: {payload}</body></html>"},
        js_responses={
            _PROBE: "[object Object]",
            MARKERS_JSON_EXPR: '[{"type": "alert", "message": "1"}]',
        },
    )
    validator = BrowserEvidenceValidator(browser=fake)

    action = _browser_action(url=url, payload=payload)
    result = await validator.validate(action=action, obs=_obs(), state=State())

    assert result is not None
    assert result.level == "validated"
    assert result.evidence["execution_markers"] == [{"type": "alert", "message": "1"}]


@pytest.mark.asyncio
async def test_validator_respects_custom_markers_and_probe():
    url = "http://target/vuln"
    payload = "custom-payload-token"
    fake = FakeBrowser(
        dom_responses={url: f"<html>{payload}</html>"},
        js_responses={"window.custom_marker": "ALPHA"},
    )
    validator = BrowserEvidenceValidator(
        browser=fake,
        execution_markers=("ALPHA", "BETA"),
        probe_expr="window.custom_marker",
    )

    action = _browser_action(url=url, payload=payload)
    result = await validator.validate(action=action, obs=_obs(), state=State())

    assert result is not None
    assert result.level == "validated"
    # Custom probe fires first; markers JSON probe runs too (returns None →
    # empty list), but execution is still detected via the custom marker.
    assert fake.js_calls == ["window.custom_marker", MARKERS_JSON_EXPR]
    assert result.evidence["execution_markers"] == []


@pytest.mark.asyncio
async def test_fake_browser_aclose_is_idempotent():
    fake = FakeBrowser()
    assert fake.closed is False

    await fake.aclose()
    assert fake.closed is True

    await fake.aclose()
    assert fake.closed is True
