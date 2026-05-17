-- Honai database schema.
-- See docs/SCHEMA.md for the canonical contract and field semantics.
-- This file is the executable form of that contract.
-- Idempotent: safe to run on every ingest/tail.py startup.

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ---------------------------------------------------------------------------
-- sessions: one row per attacker session captured by Cowrie.
-- Writer: ingest/tail.py (INSERT, plus dedup UPDATE of seen_count/updated_at).
-- Writer: agents/ (UPDATE verdict, verdict_reason, tags, triaged_at, status).
-- Reader: notify/ (watches verdict='critical' triaged rows).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cowrie_session  TEXT    NOT NULL,
    src_ip          TEXT    NOT NULL,
    src_port        INTEGER,
    dst_port        INTEGER NOT NULL DEFAULT 22,
    started_at      TEXT    NOT NULL,
    ended_at        TEXT    NOT NULL,
    duration_sec    REAL    NOT NULL,
    username        TEXT,
    password        TEXT,
    login_success   INTEGER NOT NULL DEFAULT 0 CHECK (login_success IN (0, 1)),
    commands        TEXT    NOT NULL DEFAULT '[]',
    transcript      TEXT    NOT NULL DEFAULT '',
    payload_hash    TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'new'
                    CHECK (status IN ('new', 'triaged', 'archived')),
    verdict         TEXT
                    CHECK (verdict IS NULL OR verdict IN ('benign', 'suspicious', 'critical')),
    verdict_reason  TEXT,
    tags            TEXT    NOT NULL DEFAULT '[]',
    triaged_at      TEXT,
    seen_count      INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sessions_status
    ON sessions (status);

CREATE INDEX IF NOT EXISTS idx_sessions_payload_hash_started
    ON sessions (payload_hash, started_at);

CREATE INDEX IF NOT EXISTS idx_sessions_src_ip
    ON sessions (src_ip);

CREATE INDEX IF NOT EXISTS idx_sessions_verdict_updated
    ON sessions (verdict, updated_at);

-- Bump updated_at on every UPDATE so writers don't have to remember.
CREATE TRIGGER IF NOT EXISTS trg_sessions_updated_at
AFTER UPDATE ON sessions
FOR EACH ROW
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE sessions SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- ---------------------------------------------------------------------------
-- digests: one row per digest the agent layer renders.
-- Writer: agents/. Reader: notify/ (picks latest row to push).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS digests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    period_start    TEXT    NOT NULL,
    period_end      TEXT    NOT NULL,
    session_count   INTEGER NOT NULL DEFAULT 0,
    critical_count  INTEGER NOT NULL DEFAULT 0,
    markdown        TEXT    NOT NULL,
    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_digests_created_at
    ON digests (created_at DESC);

-- ---------------------------------------------------------------------------
-- alerts: ledger of notifications sent. Prevents double-paging across restarts.
-- Writer: notify/ only.
-- Exactly one of (session_id, digest_id) is non-NULL; enforced by CHECK.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER REFERENCES sessions (id) ON DELETE SET NULL,
    digest_id   INTEGER REFERENCES digests  (id) ON DELETE SET NULL,
    kind        TEXT    NOT NULL CHECK (kind IN ('critical_session', 'suspicious_session', 'digest')),
    channel     TEXT    NOT NULL CHECK (channel IN ('telegram', 'email')),
    status      TEXT    NOT NULL DEFAULT 'sent' CHECK (status IN ('sent', 'failed')),
    error       TEXT,
    sent_at     TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (
        (kind IN ('critical_session', 'suspicious_session') AND session_id IS NOT NULL AND digest_id IS NULL)
        OR
        (kind = 'digest'                                    AND digest_id  IS NOT NULL AND session_id IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_alerts_session_kind
    ON alerts (session_id, kind);

CREATE INDEX IF NOT EXISTS idx_alerts_digest_kind
    ON alerts (digest_id, kind);
