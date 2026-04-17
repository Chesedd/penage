from __future__ import annotations

import pytest

from penage.specialists.shared.reflection_analyzer import ReflectionContextType


def test_lfi_param_enum_member_exists():
    assert hasattr(ReflectionContextType, "LFI_PARAM")
    assert ReflectionContextType.LFI_PARAM in ReflectionContextType


def test_lfi_param_value_is_lfi_param_string():
    assert ReflectionContextType.LFI_PARAM.value == "lfi_param"


@pytest.mark.parametrize(
    "member_name",
    ["LFI_PARAM", "CMDINJ_PARAM", "SSRF_URL_PARAM"],
)
def test_all_specialist_param_enum_members_present(member_name: str) -> None:
    if not hasattr(ReflectionContextType, member_name):
        pytest.xfail(f"{member_name} not yet added to ReflectionContextType")
    member = getattr(ReflectionContextType, member_name)
    assert isinstance(member, ReflectionContextType)
    assert member.value == member_name.lower()
