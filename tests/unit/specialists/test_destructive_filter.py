from __future__ import annotations

import pytest

from penage.specialists.shared.destructive_filter import (
    DEFAULT_FILTER,
    DestructiveCommandFilter,
    is_allowed,
)


@pytest.fixture
def default_filter() -> DestructiveCommandFilter:
    return DestructiveCommandFilter()


@pytest.mark.parametrize(
    "payload",
    [
        "echo hello",
        "; echo penage_marker_abc",
        "sleep 3",
        "uname -a",
        "ls -la",
        "ping -c 4 127.0.0.1",
        "timeout /t 5",
    ],
)
def test_benign_payload_allowed(
    default_filter: DestructiveCommandFilter, payload: str
):
    verdict = default_filter.check(payload)
    assert verdict.allowed is True
    assert verdict.reason is None
    assert verdict.matched_pattern is None


def test_rm_rf_blocked(default_filter: DestructiveCommandFilter):
    verdict = default_filter.check("; rm -rf /var/www")
    assert verdict.allowed is False
    assert verdict.reason == "destructive_command"
    assert verdict.matched_pattern is not None


@pytest.mark.parametrize(
    "payload",
    [
        "rm -rf /",
        "rm   -rf /tmp/foo",
        "rM -Rf /etc",
        "; rm -rf .",
    ],
)
def test_rm_rf_variants(default_filter: DestructiveCommandFilter, payload: str):
    verdict = default_filter.check(payload)
    assert verdict.allowed is False, f"variant {payload!r} should be blocked"
    assert verdict.reason == "destructive_command"


def test_fork_bomb_blocked(default_filter: DestructiveCommandFilter):
    verdict = default_filter.check(":(){ :|:& };:")
    assert verdict.allowed is False
    assert verdict.reason == "destructive_command"


@pytest.mark.parametrize(
    "payload",
    [
        "; shutdown -h now",
        "&& reboot",
        "| halt",
        "| poweroff",
        "; halt -p",
    ],
)
def test_shutdown_reboot_blocked(
    default_filter: DestructiveCommandFilter, payload: str
):
    verdict = default_filter.check(payload)
    assert verdict.allowed is False
    assert verdict.reason == "destructive_command"


@pytest.mark.parametrize(
    "payload",
    [
        "& format c:",
        "& format D:",
        "& format z:",
    ],
)
def test_format_drive_blocked(
    default_filter: DestructiveCommandFilter, payload: str
):
    verdict = default_filter.check(payload)
    assert verdict.allowed is False
    assert verdict.reason == "destructive_command"


def test_excessive_sleep_blocked(default_filter: DestructiveCommandFilter):
    verdict = default_filter.check("; sleep 20")
    assert verdict.allowed is False
    assert verdict.reason == "excessive_sleep"
    assert verdict.matched_pattern is not None


def test_excessive_sleep_blocked_with_allow_destructive_true():
    """DoS safety is unconditional: allow_destructive does not unblock sleeps."""
    f = DestructiveCommandFilter(allow_destructive=True, max_sleep_seconds=10)
    verdict = f.check("; sleep 60")
    assert verdict.allowed is False
    assert verdict.reason == "excessive_sleep"


def test_allow_destructive_unblocks_rm_rf():
    f = DestructiveCommandFilter(allow_destructive=True)
    verdict = f.check("; rm -rf /opt/target")
    assert verdict.allowed is True
    assert verdict.reason is None


def test_ping_c_high_count_blocked(default_filter: DestructiveCommandFilter):
    verdict = default_filter.check("; ping -c 100 127.0.0.1")
    assert verdict.allowed is False
    assert verdict.reason == "excessive_sleep"


def test_ping_n_high_count_blocked_windows(
    default_filter: DestructiveCommandFilter,
):
    verdict = default_filter.check("& ping -n 100 127.0.0.1")
    assert verdict.allowed is False
    assert verdict.reason == "excessive_sleep"


def test_timeout_t_high_value_blocked(default_filter: DestructiveCommandFilter):
    verdict = default_filter.check("& timeout /t 60")
    assert verdict.allowed is False
    assert verdict.reason == "excessive_sleep"


def test_userdel_groupdel_blocked(default_filter: DestructiveCommandFilter):
    assert default_filter.check("; userdel root").allowed is False
    assert default_filter.check("; groupdel admins").allowed is False


def test_kill_init_blocked(default_filter: DestructiveCommandFilter):
    verdict = default_filter.check("; kill -9 1")
    assert verdict.allowed is False
    assert verdict.reason == "destructive_command"


def test_dd_if_blocked(default_filter: DestructiveCommandFilter):
    verdict = default_filter.check("; dd if=/dev/zero of=/dev/sda")
    assert verdict.allowed is False
    assert verdict.reason == "destructive_command"


def test_mkfs_blocked(default_filter: DestructiveCommandFilter):
    assert default_filter.check("; mkfs /dev/sda1").allowed is False
    assert default_filter.check("; mkfs.ext4 /dev/sda1").allowed is False


def test_is_allowed_convenience_function():
    assert is_allowed("echo hello") is True
    assert is_allowed("; rm -rf /") is False
    assert is_allowed("; sleep 5") is True
    assert is_allowed("; sleep 9999") is False
    assert DEFAULT_FILTER.allow_destructive is False


def test_reason_field_populated_correctly(default_filter: DestructiveCommandFilter):
    destructive = default_filter.check("; rm -rf /")
    assert destructive.reason == "destructive_command"
    assert destructive.matched_pattern is not None and destructive.matched_pattern

    sleepy = default_filter.check("; sleep 99")
    assert sleepy.reason == "excessive_sleep"
    assert sleepy.matched_pattern is not None and "99" in sleepy.matched_pattern

    benign = default_filter.check("echo ok")
    assert benign.reason is None
    assert benign.matched_pattern is None


def test_excessive_sleep_takes_priority_over_destructive():
    """Order: excessive_sleep is checked before destructive_command."""
    f = DestructiveCommandFilter(max_sleep_seconds=5)
    verdict = f.check("rm -rf / && sleep 60")
    assert verdict.allowed is False
    assert verdict.reason == "excessive_sleep"
