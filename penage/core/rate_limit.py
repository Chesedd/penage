from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator
from urllib.parse import urlparse


class RateLimiter:
    """Per-host concurrency cap for outbound requests to targets.

    One :class:`asyncio.Semaphore` is maintained per host key (lowercased
    ``netloc``). Different hosts never block each other — the cap is scoped
    to a single target's capacity. ``http://`` and ``https://`` to the same
    ``host:port`` share a single semaphore because they hit the same server.

    If ``max_concurrent_per_host`` is ``None`` or ``0`` the limiter is a
    zero-overhead no-op — :meth:`acquire` yields immediately without
    allocating any semaphores.

    One instance is created per :class:`~penage.app.runtime_factory.RuntimeComponents`
    build (i.e. one per episode, per invariant #11 in ``CLAUDE.md``).
    Callers inject the same instance into every component that initiates
    network I/O to the target (``HttpTool``, ``PlaywrightBrowser``).
    """

    def __init__(self, max_concurrent_per_host: int | None) -> None:
        self._max: int | None = max_concurrent_per_host if max_concurrent_per_host else None
        self._semaphores: dict[str, asyncio.Semaphore] = {}

    def _host_key(self, url: str) -> str:
        parsed = urlparse(url)
        return (parsed.netloc or "").lower()

    @asynccontextmanager
    async def acquire(self, url: str) -> AsyncIterator[None]:
        """Acquire the per-host slot for ``url``.

        Yields once a slot is available. When the limiter is disabled the
        context manager yields immediately without any synchronization.
        Releases the slot on exit. Safe to nest and safe under cancellation
        (``asyncio.Semaphore`` releases on context-manager exit regardless
        of how the block leaves).
        """
        if self._max is None:
            yield
            return
        host = self._host_key(url)
        sem = self._semaphores.get(host)
        if sem is None:
            sem = asyncio.Semaphore(self._max)
            self._semaphores[host] = sem
        async with sem:
            yield
