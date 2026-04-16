"""Default safety filter for command-injection and LFI payload generators.

This module is intentionally placed under ``penage/specialists/shared`` so that
multiple vulnerability specialists (CmdInjSpecialist, LfiSpecialist, ...) can
share a single source of truth for "what counts as destructive". It must NOT
import from ``penage.specialists.vulns`` -- shared utilities cannot depend on
the specialists that consume them (CLAUDE.md, invariant #1).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_DESTRUCTIVE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\brm\s+-rf\b", "rm -rf"),
    (r"\bmkfs(\.\w+)?\b", "mkfs"),
    (r"\bdd\s+if=", "dd if="),
    (r"\bshutdown\b", "shutdown"),
    (r"\breboot\b", "reboot"),
    (r"\bhalt\s+-p\b", "halt -p"),
    (r"\bhalt\b", "halt"),
    (r"\bpoweroff\b", "poweroff"),
    (r":\s*\(\s*\)\s*\{.*\}\s*;?\s*:", "fork bomb"),
    (r"\bformat\s+[a-zA-Z]:", "format <drive>:"),
    (r"\bdel\s+/[fqs]", "del /f|/q|/s"),
    (r"\bchmod\s+000\b", "chmod 000"),
    (r"\bchown\s+-?[rR]\s", "chown -R"),
    (r"\bpasswd\s+[^\s|]", "passwd <user>"),
    (r"\buserdel\b", "userdel"),
    (r"\bgroupdel\b", "groupdel"),
    (r"\bkill\s+-9\s+1\b", "kill -9 1"),
)

_COMPILED_DESTRUCTIVE: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(p, re.IGNORECASE), label) for p, label in _DESTRUCTIVE_PATTERNS
)

_SLEEP_RE = re.compile(r"\b(?:sleep|timeout\s+/t)\s+(\d+)\b", re.IGNORECASE)
_PING_COUNT_RE = re.compile(r"\bping\s+-[cn]\s+(\d+)\b", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class FilterVerdict:
    """Result of running a payload through :class:`DestructiveCommandFilter`."""

    allowed: bool
    reason: str | None = None
    matched_pattern: str | None = None


class DestructiveCommandFilter:
    """Blocks payloads that could cause irreversible damage or DoS on a target.

    SECURITY INVARIANT (CLAUDE.md #4): penetration-testing specialists must
    never execute destructive operations without an explicit opt-in. This
    filter is the default gate. Matched payloads are dropped and logged as
    ``destructive_payload_dropped`` tracer notes by the caller.
    """

    def __init__(
        self,
        *,
        allow_destructive: bool = False,
        max_sleep_seconds: int = 15,
    ) -> None:
        self._allow_destructive = bool(allow_destructive)
        self._max_sleep_seconds = int(max_sleep_seconds)

    @property
    def allow_destructive(self) -> bool:
        return self._allow_destructive

    @property
    def max_sleep_seconds(self) -> int:
        return self._max_sleep_seconds

    def check(self, payload: str) -> FilterVerdict:
        """Return ``FilterVerdict.allowed=False`` for destructive/DoS payloads.

        Categories blocked (even with ``allow_destructive=True`` -> only
        the ``destructive`` category is unblocked; ``excessive_sleep`` is
        ALWAYS blocked to prevent DoS):

        * ``destructive`` -- ``rm -rf``, ``mkfs``, ``dd if=``, ``shutdown``,
          ``reboot``, ``halt``, ``poweroff``, fork bombs, ``format <drive>:``,
          ``del /f|/s|/q``, ``chmod 000``, ``chown -R``, ``passwd <user>``,
          ``userdel``, ``groupdel``, ``kill -9 1``.
        * ``excessive_sleep`` -- ``sleep N`` / ``timeout /t N`` /
          ``ping -c N`` where ``N > max_sleep_seconds``.
        """
        for match in _SLEEP_RE.finditer(payload):
            if int(match.group(1)) > self._max_sleep_seconds:
                return FilterVerdict(
                    allowed=False,
                    reason="excessive_sleep",
                    matched_pattern=match.group(0),
                )
        for match in _PING_COUNT_RE.finditer(payload):
            if int(match.group(1)) > self._max_sleep_seconds:
                return FilterVerdict(
                    allowed=False,
                    reason="excessive_sleep",
                    matched_pattern=match.group(0),
                )

        if not self._allow_destructive:
            for pattern, label in _COMPILED_DESTRUCTIVE:
                m = pattern.search(payload)
                if m is not None:
                    return FilterVerdict(
                        allowed=False,
                        reason="destructive_command",
                        matched_pattern=label,
                    )

        return FilterVerdict(allowed=True)


DEFAULT_FILTER = DestructiveCommandFilter()


def is_allowed(payload: str) -> bool:
    """Convenience wrapper around the module-level default filter."""
    return DEFAULT_FILTER.check(payload).allowed


__all__ = [
    "DEFAULT_FILTER",
    "DestructiveCommandFilter",
    "FilterVerdict",
    "is_allowed",
]
