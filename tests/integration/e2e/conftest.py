"""Fixtures for the opt-in DVWA E2E suite (``e2e_dvwa`` marker).

The suite is default-deselected (see ``pytest.ini``); developers run it
against a live DVWA instance they brought up themselves:

    docker compose -f compose/e2e_dvwa.yml up -d
    pytest -m e2e_dvwa tests/integration/e2e/ -o addopts= -v
    docker compose -f compose/e2e_dvwa.yml down -v

The fixture does **not** manage the compose lifecycle — that is the
developer's job (design doc ``docs/design/e2e_dvwa.md`` §B). All it does
is: probe ``DVWA_BASE_URL`` for reachability, and if alive, walk the
login + setup + security-low flow once per session and expose the
authenticated cookie jar via :class:`DvwaSession`.

``DVWA_BASE_URL`` defaults to ``http://127.0.0.1:4280`` to match
``compose/e2e_dvwa.yml``. Override the env var to point at any other
DVWA instance — useful for ad-hoc debugging against a remote lab.
"""
from __future__ import annotations

import asyncio
import os

import pytest

from tests.support.dvwa_auth import DvwaSession, authenticate, is_dvwa_healthy


DVWA_BASE_URL = os.environ.get("DVWA_BASE_URL", "http://127.0.0.1:4280")


@pytest.fixture(scope="session")
def dvwa_session() -> DvwaSession:
    """Authenticated DVWA handle, cached for the whole session.

    Kept synchronous (wraps ``asyncio.run``) so pytest-asyncio doesn't
    need a session-scoped event loop — the project's pytest-asyncio
    config uses the default function-scope loop, and a session-scoped
    async fixture would otherwise force us to ship a custom
    ``event_loop`` fixture. The pure-HTTP flow finishes in well under a
    second against a warm DVWA, so the extra loop create/teardown is
    negligible.
    """
    if not asyncio.run(is_dvwa_healthy(DVWA_BASE_URL)):
        pytest.skip(
            f"DVWA unreachable at {DVWA_BASE_URL}. "
            "Bring it up via `docker compose -f compose/e2e_dvwa.yml up -d`."
        )
    return asyncio.run(authenticate(DVWA_BASE_URL))
