"""Runtime Protocol conformance checks.

`EvidenceValidator` is a `@runtime_checkable` Protocol after the async
migration (Stage 4.1.b.i). Both concrete validators — HTTP and browser —
must satisfy the same Protocol so `ValidationGate` can consume them
interchangeably via one path (invariant #4).
"""

from __future__ import annotations

from penage.sandbox.fake_browser import FakeBrowser
from penage.validation.base import EvidenceValidator
from penage.validation.browser import BrowserEvidenceValidator
from penage.validation.http import HttpEvidenceValidator


def test_http_validator_conforms_to_evidence_validator_protocol():
    validator = HttpEvidenceValidator()
    assert isinstance(validator, EvidenceValidator)


def test_browser_validator_conforms_to_evidence_validator_protocol():
    validator = BrowserEvidenceValidator(FakeBrowser())
    assert isinstance(validator, EvidenceValidator)
