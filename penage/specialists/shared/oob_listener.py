from __future__ import annotations

import asyncio
import logging
import socket
import time
import uuid
from dataclasses import dataclass
from typing import Any

from aiohttp import web

logger = logging.getLogger(__name__)

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_TOKEN_LEN = 16
_ACK_PREFIX = "penage_oob_ack_"
_LISTEN_BACKLOG = 128


@dataclass(frozen=True, slots=True)
class OobHit:
    """One captured out-of-band HTTP hit against a registered canary token."""

    token: str
    remote_addr: str
    path: str
    headers: dict[str, str]
    ts: float


class OobListener:
    """In-process HTTP listener for SSRF canary hits.

    Binds to ``127.0.0.1`` by default; never exposed publicly. Any registered
    token gets a unique URL ``http://<bind_host>:<actual_port>/canary/<token>``
    that the specialist feeds to the target. The target's subsequent HTTP
    request to that URL is captured as an :class:`OobHit`.

    Responses carry the body ``penage_oob_ack_<token>`` so that, if the
    SSRF-vulnerable target mirrors our response body back to the attacker,
    the marker can be picked up without needing the OOB channel at all.

    Safety:

    * Non-loopback binds log a warning but are allowed (lab-network scenario).
    * The ``Authorization`` header is stripped from captured headers to avoid
      leaking credentials that could be sent by a target.
    * Request bodies are never logged; only remote addr, method, path and the
      header count.

    The listener is an async context manager; :meth:`start` is idempotent and
    :meth:`stop` wakes up all pending :meth:`wait_for_hit` callers.
    """

    def __init__(
        self,
        *,
        bind_host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self._bind_host = bind_host
        self._bind_port = int(port)
        self._runner: web.AppRunner | None = None
        self._site: web.BaseSite | None = None
        self._sock: socket.socket | None = None
        self._actual_port: int = 0
        self._running = False
        self._events: dict[str, asyncio.Event] = {}
        self._hits: dict[str, OobHit] = {}
        self._stopped = asyncio.Event()
        self._token_lock = asyncio.Lock()

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def port(self) -> int:
        """Actual bound port (non-zero only after :meth:`start`)."""
        return self._actual_port

    async def start(self) -> None:
        """Bind socket, start the aiohttp runner. Idempotent."""
        if self._running:
            return

        if self._bind_host not in _LOOPBACK_HOSTS:
            logger.warning(
                "OobListener binding to non-loopback host %s; only use in an isolated lab network.",
                self._bind_host,
            )

        self._stopped = asyncio.Event()
        self._events = {}
        self._hits = {}

        app = web.Application()
        app.router.add_route("*", "/canary/{token}", self._handle_canary)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()

        family = socket.AF_INET6 if ":" in self._bind_host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((self._bind_host, self._bind_port))
        except OSError:
            sock.close()
            await runner.cleanup()
            raise
        sock.listen(_LISTEN_BACKLOG)
        sock.setblocking(False)
        self._actual_port = sock.getsockname()[1]

        site = web.SockSite(runner, sock)
        await site.start()

        self._runner = runner
        self._site = site
        self._sock = sock
        self._running = True

    async def stop(self) -> None:
        """Graceful shutdown; wakes every pending waiter."""
        if not self._running:
            return
        self._running = False
        self._stopped.set()
        for ev in self._events.values():
            ev.set()

        if self._site is not None:
            await self._site.stop()
        if self._runner is not None:
            await self._runner.cleanup()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

        self._site = None
        self._runner = None
        self._sock = None
        self._actual_port = 0

    async def register_token(self) -> tuple[str, str]:
        """Allocate a fresh token and return ``(token, full_probe_url)``."""
        if not self._running:
            raise RuntimeError("OobListener is not running; call start() first")
        async with self._token_lock:
            for _ in range(8):
                token = uuid.uuid4().hex[:_TOKEN_LEN]
                if token not in self._events:
                    self._events[token] = asyncio.Event()
                    break
            else:  # pragma: no cover - UUID collision is astronomically unlikely
                raise RuntimeError("failed to allocate unique OOB token after retries")

        host = self._bind_host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        url = f"http://{host}:{self._actual_port}/canary/{token}"
        return token, url

    async def wait_for_hit(self, token: str, timeout_s: float) -> OobHit | None:
        """Block until a hit on ``token`` lands, listener stops, or timeout.

        Returns the captured :class:`OobHit` on success, ``None`` on timeout or
        when the listener is stopped before any hit arrives.
        """
        ev = self._events.get(token)
        if ev is None:
            return None
        if token in self._hits:
            return self._hits[token]
        try:
            await asyncio.wait_for(ev.wait(), timeout=timeout_s)
        except asyncio.TimeoutError:
            return None
        return self._hits.get(token)

    async def _handle_canary(self, request: web.Request) -> web.Response:
        token = request.match_info.get("token", "")
        ev = self._events.get(token)
        if ev is None:
            return web.Response(status=404, text="not found")

        remote_addr = "unknown"
        transport = request.transport
        if transport is not None:
            peer = transport.get_extra_info("peername")
            if peer:
                remote_addr = peer[0]

        headers = {
            k: v for k, v in request.headers.items() if k.lower() != "authorization"
        }
        hit = OobHit(
            token=token,
            remote_addr=remote_addr,
            path=request.path,
            headers=headers,
            ts=time.time(),
        )
        self._hits.setdefault(token, hit)
        ev.set()

        logger.info(
            "oob_hit token=%s remote=%s method=%s path=%s header_count=%d",
            token,
            remote_addr,
            request.method,
            request.path,
            len(headers),
        )
        return web.Response(status=200, text=f"{_ACK_PREFIX}{token}")

    async def __aenter__(self) -> "OobListener":
        await self.start()
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.stop()


__all__ = ["OobHit", "OobListener"]
