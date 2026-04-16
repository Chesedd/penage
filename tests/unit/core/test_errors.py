from __future__ import annotations

import pytest

from penage.core.errors import (
    BudgetExceeded,
    LLMResponseError,
    PenageError,
    PlannerError,
    SandboxError,
    ToolError,
    ValidationError,
)


_ALL_SUBTYPES = [PlannerError, ToolError, SandboxError, ValidationError, BudgetExceeded, LLMResponseError]


@pytest.mark.parametrize("cls", _ALL_SUBTYPES)
def test_subtype_is_catchable_by_penage_error(cls):
    with pytest.raises(PenageError):
        raise cls("test message")


@pytest.mark.parametrize("cls", _ALL_SUBTYPES)
def test_subtype_carries_message(cls):
    err = cls("something went wrong")
    assert err.message == "something went wrong"
    assert str(err) == "something went wrong"


@pytest.mark.parametrize("cls", _ALL_SUBTYPES)
def test_subtype_carries_optional_cause(cls):
    cause = RuntimeError("root cause")
    err = cls("wrapper", cause=cause)
    assert err.cause is cause
    assert err.__cause__ is cause


@pytest.mark.parametrize("cls", _ALL_SUBTYPES)
def test_subtype_cause_defaults_to_none(cls):
    err = cls("no cause")
    assert err.cause is None
    assert err.__cause__ is None


def test_penage_error_is_exception():
    assert issubclass(PenageError, Exception)


def test_hierarchy_does_not_cross_catch():
    with pytest.raises(SandboxError):
        raise SandboxError("sandbox fail")

    caught = False
    try:
        raise SandboxError("sandbox fail")
    except LLMResponseError:
        caught = True
    except PenageError:
        pass
    assert not caught, "SandboxError should not be caught by LLMResponseError"
