from __future__ import annotations

from penage.validation.verdict import ValidationVerdict


def test_pass_factory_sets_passed_true_and_evidence():
    v = ValidationVerdict.pass_("ok", foo="bar")
    assert v.passed is True
    assert v.reason == "ok"
    assert v.evidence == {"foo": "bar"}


def test_fail_factory_sets_passed_false():
    v = ValidationVerdict.fail("no")
    assert v.passed is False
    assert v.reason == "no"
    assert v.evidence == {}


def test_pass_factory_with_no_evidence_has_empty_dict():
    v = ValidationVerdict.pass_("ok")
    assert v.passed is True
    assert v.evidence == {}
