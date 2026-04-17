from __future__ import annotations

import asyncio

import pytest

from penage.core.rate_limit import RateLimiter


async def _track_concurrency(
    limiter: RateLimiter,
    url: str,
    counter: dict[str, int],
    hold_s: float,
) -> None:
    async with limiter.acquire(url):
        counter["cur"] += 1
        if counter["cur"] > counter["peak"]:
            counter["peak"] = counter["cur"]
        await asyncio.sleep(hold_s)
        counter["cur"] -= 1


@pytest.mark.asyncio
async def test_rate_limiter_limits_concurrency_per_host():
    limiter = RateLimiter(2)
    counter = {"cur": 0, "peak": 0}

    tasks = [
        asyncio.create_task(
            _track_concurrency(limiter, "http://example.com/x", counter, 0.02)
        )
        for _ in range(10)
    ]
    await asyncio.gather(*tasks)

    assert counter["peak"] == 2
    assert counter["cur"] == 0


@pytest.mark.asyncio
async def test_rate_limiter_different_hosts_independent():
    limiter = RateLimiter(2)
    host_a = {"cur": 0, "peak": 0}
    host_b = {"cur": 0, "peak": 0}

    tasks = []
    for _ in range(5):
        tasks.append(
            asyncio.create_task(
                _track_concurrency(limiter, "http://a.example.com/p", host_a, 0.02)
            )
        )
        tasks.append(
            asyncio.create_task(
                _track_concurrency(limiter, "http://b.example.com/p", host_b, 0.02)
            )
        )
    await asyncio.gather(*tasks)

    assert host_a["peak"] == 2
    assert host_b["peak"] == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("disabled_value", [None, 0])
async def test_rate_limiter_disabled_mode(disabled_value):
    limiter = RateLimiter(disabled_value)
    counter = {"cur": 0, "peak": 0}

    tasks = [
        asyncio.create_task(
            _track_concurrency(limiter, "http://example.com/x", counter, 0.01)
        )
        for _ in range(50)
    ]
    await asyncio.gather(*tasks)

    assert counter["peak"] == 50


@pytest.mark.asyncio
async def test_rate_limiter_disabled_mode_allocates_no_semaphores():
    limiter = RateLimiter(None)
    async with limiter.acquire("http://x/"):
        pass
    async with limiter.acquire("http://y/"):
        pass
    assert limiter._semaphores == {}


@pytest.mark.asyncio
async def test_rate_limiter_host_key_ignores_scheme():
    limiter = RateLimiter(2)
    counter = {"cur": 0, "peak": 0}

    tasks = []
    for _ in range(5):
        tasks.append(
            asyncio.create_task(
                _track_concurrency(limiter, "http://example.com:8080/x", counter, 0.02)
            )
        )
        tasks.append(
            asyncio.create_task(
                _track_concurrency(limiter, "https://example.com:8080/x", counter, 0.02)
            )
        )
    await asyncio.gather(*tasks)

    # http:// and https:// to same host:port share the same semaphore
    assert counter["peak"] == 2


@pytest.mark.asyncio
async def test_rate_limiter_host_key_lowercase():
    limiter = RateLimiter(2)
    counter = {"cur": 0, "peak": 0}

    tasks = []
    for _ in range(5):
        tasks.append(
            asyncio.create_task(
                _track_concurrency(limiter, "http://EXAMPLE.com/x", counter, 0.02)
            )
        )
        tasks.append(
            asyncio.create_task(
                _track_concurrency(limiter, "http://example.com/x", counter, 0.02)
            )
        )
    await asyncio.gather(*tasks)

    assert counter["peak"] == 2


@pytest.mark.asyncio
async def test_rate_limiter_releases_on_exception():
    limiter = RateLimiter(1)

    with pytest.raises(RuntimeError):
        async with limiter.acquire("http://example.com/x"):
            raise RuntimeError("boom")

    # Slot must be released; the next acquire must not hang.
    async with limiter.acquire("http://example.com/x"):
        pass
