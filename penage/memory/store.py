from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import List, Union


SchemaPath = Path(__file__).parent / "schema.sql"


class MemoryStore:
    """Persistent memory backed by SQLite.

    Two tables:
    - scan_state: per-episode payload attempts and inferred filter models
    - cross_target: long-term signatures of successful bypasses per host/stack
    """

    def __init__(self, db_path: Union[str, Path]) -> None:
        self._db_path = db_path
        path_str = str(db_path) if not isinstance(db_path, str) else db_path

        if path_str != ":memory:":
            Path(path_str).parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(path_str)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        schema_sql = SchemaPath.read_text(encoding="utf-8")
        self._conn.executescript(schema_sql)
        self._conn.commit()

    def record_attempt(
        self,
        *,
        episode_id: str,
        host: str,
        parameter: str,
        payload: str,
        outcome: str,
        filters_json: str = "",
    ) -> None:
        """Upsert an attempt in scan_state keyed by (episode_id, host, parameter, payload)."""
        self._conn.execute(
            """
            INSERT INTO scan_state
                (episode_id, host, parameter, payload, outcome, inferred_filters_json, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(episode_id, host, parameter, payload) DO UPDATE SET
                outcome = excluded.outcome,
                inferred_filters_json = excluded.inferred_filters_json,
                timestamp = excluded.timestamp
            """,
            (episode_id, host, parameter, payload, outcome, filters_json, time.time()),
        )
        self._conn.commit()

    def was_tried(
        self,
        *,
        episode_id: str,
        host: str,
        parameter: str,
        payload: str,
    ) -> bool:
        cur = self._conn.execute(
            """
            SELECT 1 FROM scan_state
            WHERE episode_id = ? AND host = ? AND parameter = ? AND payload = ?
            LIMIT 1
            """,
            (episode_id, host, parameter, payload),
        )
        return cur.fetchone() is not None

    def record_bypass(
        self,
        *,
        host_fingerprint: str,
        stack_fingerprint: str,
        kind: str,
        value: str,
        success: bool,
    ) -> None:
        """Upsert cross_target counters; increments success_count or fail_count."""
        now = time.time()
        if success:
            self._conn.execute(
                """
                INSERT INTO cross_target
                    (host_fingerprint, stack_fingerprint, signature_kind, signature_value,
                     success_count, fail_count, updated_at)
                VALUES (?, ?, ?, ?, 1, 0, ?)
                ON CONFLICT(host_fingerprint, signature_kind, signature_value) DO UPDATE SET
                    success_count = success_count + 1,
                    stack_fingerprint = excluded.stack_fingerprint,
                    updated_at = excluded.updated_at
                """,
                (host_fingerprint, stack_fingerprint, kind, value, now),
            )
        else:
            self._conn.execute(
                """
                INSERT INTO cross_target
                    (host_fingerprint, stack_fingerprint, signature_kind, signature_value,
                     success_count, fail_count, updated_at)
                VALUES (?, ?, ?, ?, 0, 1, ?)
                ON CONFLICT(host_fingerprint, signature_kind, signature_value) DO UPDATE SET
                    fail_count = fail_count + 1,
                    stack_fingerprint = excluded.stack_fingerprint,
                    updated_at = excluded.updated_at
                """,
                (host_fingerprint, stack_fingerprint, kind, value, now),
            )
        self._conn.commit()

    def get_effective_bypasses(
        self,
        *,
        host_fingerprint: str,
        signature_kind: str,
        min_success: int = 2,
    ) -> List[str]:
        """Return signature_values that have succeeded at least min_success times for this host."""
        cur = self._conn.execute(
            """
            SELECT signature_value
            FROM cross_target
            WHERE host_fingerprint = ? AND signature_kind = ? AND success_count >= ?
            ORDER BY success_count DESC, updated_at DESC
            """,
            (host_fingerprint, signature_kind, int(min_success)),
        )
        return [row[0] for row in cur.fetchall()]

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
