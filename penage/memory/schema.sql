-- penage persistent memory schema
-- Short-term: per-episode scan state (payloads tried, inferred filters)
-- Long-term: cross-target knowledge (bypasses that worked against a host/stack)

CREATE TABLE IF NOT EXISTS scan_state (
    episode_id TEXT NOT NULL,
    host TEXT NOT NULL,
    parameter TEXT NOT NULL,
    payload TEXT NOT NULL,
    outcome TEXT NOT NULL,
    inferred_filters_json TEXT NOT NULL DEFAULT '',
    timestamp REAL NOT NULL,
    PRIMARY KEY (episode_id, host, parameter, payload)
);

CREATE INDEX IF NOT EXISTS idx_scan_state_episode_host
    ON scan_state(episode_id, host);

CREATE TABLE IF NOT EXISTS cross_target (
    host_fingerprint TEXT NOT NULL,
    stack_fingerprint TEXT NOT NULL DEFAULT '',
    signature_kind TEXT NOT NULL,
    signature_value TEXT NOT NULL,
    success_count INTEGER NOT NULL DEFAULT 0,
    fail_count INTEGER NOT NULL DEFAULT 0,
    updated_at REAL NOT NULL,
    PRIMARY KEY (host_fingerprint, signature_kind, signature_value)
);

CREATE INDEX IF NOT EXISTS idx_cross_target_kind
    ON cross_target(host_fingerprint, signature_kind);
