from __future__ import annotations

import pytest

from penage.memory.store import MemoryStore


@pytest.fixture
def store():
    s = MemoryStore(":memory:")
    yield s
    s.close()


def test_record_and_was_tried_round_trip(store):
    assert not store.was_tried(
        episode_id="ep1", host="localhost", parameter="q", payload="<script>"
    )

    store.record_attempt(
        episode_id="ep1",
        host="localhost",
        parameter="q",
        payload="<script>",
        outcome="blocked",
        filters_json='{"blocked":["script"]}',
    )

    assert store.was_tried(
        episode_id="ep1", host="localhost", parameter="q", payload="<script>"
    )


def test_was_tried_is_scoped_by_episode(store):
    store.record_attempt(
        episode_id="ep1",
        host="localhost",
        parameter="q",
        payload="p",
        outcome="ok",
    )
    assert store.was_tried(episode_id="ep1", host="localhost", parameter="q", payload="p")
    assert not store.was_tried(episode_id="ep2", host="localhost", parameter="q", payload="p")


def test_record_attempt_upserts_outcome(store):
    store.record_attempt(
        episode_id="ep1", host="h", parameter="p", payload="x", outcome="pending"
    )
    store.record_attempt(
        episode_id="ep1", host="h", parameter="p", payload="x", outcome="validated"
    )

    cur = store._conn.execute(
        "SELECT outcome FROM scan_state WHERE episode_id=? AND host=? AND parameter=? AND payload=?",
        ("ep1", "h", "p", "x"),
    )
    rows = cur.fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "validated"


def test_bypass_accumulation_increments_success_count(store):
    store.record_bypass(
        host_fingerprint="fp1", stack_fingerprint="flask", kind="xss-payload",
        value="<svg/onload=alert(1)>", success=True,
    )
    store.record_bypass(
        host_fingerprint="fp1", stack_fingerprint="flask", kind="xss-payload",
        value="<svg/onload=alert(1)>", success=True,
    )
    store.record_bypass(
        host_fingerprint="fp1", stack_fingerprint="flask", kind="xss-payload",
        value="<svg/onload=alert(1)>", success=False,
    )

    cur = store._conn.execute(
        "SELECT success_count, fail_count FROM cross_target "
        "WHERE host_fingerprint=? AND signature_kind=? AND signature_value=?",
        ("fp1", "xss-payload", "<svg/onload=alert(1)>"),
    )
    s, f = cur.fetchone()
    assert s == 2
    assert f == 1


def test_get_effective_bypasses_respects_min_success_threshold(store):
    store.record_bypass(
        host_fingerprint="fp1", stack_fingerprint="flask", kind="xss",
        value="strong", success=True,
    )
    store.record_bypass(
        host_fingerprint="fp1", stack_fingerprint="flask", kind="xss",
        value="strong", success=True,
    )
    store.record_bypass(
        host_fingerprint="fp1", stack_fingerprint="flask", kind="xss",
        value="weak", success=True,
    )

    strong = store.get_effective_bypasses(
        host_fingerprint="fp1", signature_kind="xss", min_success=2
    )
    assert strong == ["strong"]

    any_ = store.get_effective_bypasses(
        host_fingerprint="fp1", signature_kind="xss", min_success=1
    )
    assert "strong" in any_
    assert "weak" in any_


def test_get_effective_bypasses_scoped_by_host_and_kind(store):
    store.record_bypass(
        host_fingerprint="fp1", stack_fingerprint="", kind="xss",
        value="a", success=True,
    )
    store.record_bypass(
        host_fingerprint="fp1", stack_fingerprint="", kind="xss",
        value="a", success=True,
    )
    store.record_bypass(
        host_fingerprint="fp2", stack_fingerprint="", kind="xss",
        value="a", success=True,
    )
    store.record_bypass(
        host_fingerprint="fp1", stack_fingerprint="", kind="sqli",
        value="b", success=True,
    )
    store.record_bypass(
        host_fingerprint="fp1", stack_fingerprint="", kind="sqli",
        value="b", success=True,
    )

    assert store.get_effective_bypasses(
        host_fingerprint="fp1", signature_kind="xss", min_success=2
    ) == ["a"]
    assert store.get_effective_bypasses(
        host_fingerprint="fp1", signature_kind="sqli", min_success=2
    ) == ["b"]
    assert store.get_effective_bypasses(
        host_fingerprint="fp2", signature_kind="xss", min_success=2
    ) == []


def test_get_effective_bypasses_orders_by_success_desc(store):
    for _ in range(5):
        store.record_bypass(
            host_fingerprint="fp", stack_fingerprint="", kind="k", value="a", success=True,
        )
    for _ in range(3):
        store.record_bypass(
            host_fingerprint="fp", stack_fingerprint="", kind="k", value="b", success=True,
        )
    for _ in range(2):
        store.record_bypass(
            host_fingerprint="fp", stack_fingerprint="", kind="k", value="c", success=True,
        )

    result = store.get_effective_bypasses(
        host_fingerprint="fp", signature_kind="k", min_success=2
    )
    assert result == ["a", "b", "c"]


def test_file_backed_store_persists_across_connections(tmp_path):
    db = tmp_path / "mem.sqlite"

    s1 = MemoryStore(db)
    s1.record_attempt(
        episode_id="ep1", host="h", parameter="p", payload="x", outcome="ok",
    )
    s1.close()

    s2 = MemoryStore(db)
    assert s2.was_tried(episode_id="ep1", host="h", parameter="p", payload="x")
    s2.close()
