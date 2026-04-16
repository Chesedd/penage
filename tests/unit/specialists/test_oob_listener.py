from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import aiohttp
import pytest

from penage.specialists.shared.oob_listener import OobHit, OobListener


async def _get(url: str, *, method: str = "GET") -> tuple[int, str]:
    async with aiohttp.ClientSession() as session:
        async with session.request(method, url) as resp:
            return resp.status, await resp.text()


@pytest.mark.asyncio
async def test_start_stop_idempotent():
    listener = OobListener()
    try:
        await listener.start()
        assert listener.is_running is True
        first_port = listener.port
        await listener.start()  # no-op
        assert listener.is_running is True
        assert listener.port == first_port
    finally:
        await listener.stop()
        assert listener.is_running is False
        await listener.stop()  # no-op, must not raise
        assert listener.is_running is False


@pytest.mark.asyncio
async def test_register_token_returns_unique_token():
    async with OobListener() as listener:
        tokens = set()
        for _ in range(10):
            token, _ = await listener.register_token()
            assert token not in tokens
            assert len(token) == 16
            tokens.add(token)


@pytest.mark.asyncio
async def test_register_token_url_format():
    async with OobListener() as listener:
        token, url = await listener.register_token()
        parsed = urlparse(url)
        assert parsed.scheme == "http"
        assert parsed.hostname == "127.0.0.1"
        assert parsed.port == listener.port
        assert parsed.path == f"/canary/{token}"


@pytest.mark.asyncio
async def test_bind_loopback_by_default():
    async with OobListener() as listener:
        _token, url = await listener.register_token()
        parsed = urlparse(url)
        assert parsed.hostname == "127.0.0.1"


@pytest.mark.asyncio
async def test_hit_before_wait_is_captured():
    async with OobListener() as listener:
        token, url = await listener.register_token()

        status, body = await _get(url)
        assert status == 200
        assert body == f"penage_oob_ack_{token}"

        hit = await listener.wait_for_hit(token, timeout_s=1.0)
        assert isinstance(hit, OobHit)
        assert hit.token == token
        assert hit.path == f"/canary/{token}"
        assert hit.remote_addr == "127.0.0.1"
        assert hit.ts > 0


@pytest.mark.asyncio
async def test_hit_after_wait_started():
    async with OobListener() as listener:
        token, url = await listener.register_token()

        waiter = asyncio.create_task(listener.wait_for_hit(token, timeout_s=3.0))
        # Let the waiter actually suspend before firing the hit.
        await asyncio.sleep(0.05)

        status, _ = await _get(url, method="POST")
        assert status == 200

        hit = await waiter
        assert isinstance(hit, OobHit)
        assert hit.token == token


@pytest.mark.asyncio
async def test_wait_timeout_returns_none():
    async with OobListener() as listener:
        token, _ = await listener.register_token()
        hit = await listener.wait_for_hit(token, timeout_s=0.05)
        assert hit is None


@pytest.mark.asyncio
async def test_unknown_token_returns_404():
    async with OobListener() as listener:
        url = f"http://127.0.0.1:{listener.port}/canary/deadbeefdeadbeef"
        status, _ = await _get(url)
        assert status == 404


@pytest.mark.asyncio
async def test_non_canary_path_returns_404():
    async with OobListener() as listener:
        url = f"http://127.0.0.1:{listener.port}/not-a-canary"
        status, _ = await _get(url)
        assert status == 404

        url2 = f"http://127.0.0.1:{listener.port}/"
        status2, _ = await _get(url2)
        assert status2 == 404


@pytest.mark.asyncio
async def test_stop_wakes_up_waiters():
    listener = OobListener()
    await listener.start()
    try:
        token, _ = await listener.register_token()
        waiter = asyncio.create_task(listener.wait_for_hit(token, timeout_s=10.0))
        await asyncio.sleep(0.05)
    finally:
        await listener.stop()

    result = await asyncio.wait_for(waiter, timeout=1.0)
    assert result is None


@pytest.mark.asyncio
async def test_authorization_header_stripped():
    async with OobListener() as listener:
        token, url = await listener.register_token()
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers={"Authorization": "Bearer secret"}):
                pass
        hit = await listener.wait_for_hit(token, timeout_s=1.0)
        assert hit is not None
        for k in hit.headers:
            assert k.lower() != "authorization"
