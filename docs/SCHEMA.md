# Honai database schema

`sessions.db` is a SQLite file. It is the contract surface between the ingestion
layer (Charlie's half) and the agent layer (Garv's half). Both sides should
treat this file as the source of truth for what data exists and what each field
means.

If a schema change is needed, both teammates must agree before it lands.

---

## Tables

### `sessions`

One row per attacker session captured by Cowrie. Inserted by `ingest/tail.py`
when a Cowrie session ends; updated by the agent layer once triaged.

| Column            | Type     | Null | Default              | Notes                                                                       |
| ----------------- | -------- | ---- | -------------------- | --------------------------------------------------------------------------- |
| `id`              | INTEGER  | no   | autoincrement        | Primary key                                                                 |
| `cowrie_session`  | TEXT     | no   | —                    | Cowrie's session UUID (`session` field in `cowrie.json`)                    |
| `src_ip`          | TEXT     | no   | —                    | Attacker IP                                                                 |
| `src_port`        | INTEGER  | yes  | NULL                 | Attacker source port                                                        |
| `dst_port`        | INTEGER  | no   | 22                   | Honeypot port the attacker hit                                              |
| `started_at`      | TEXT     | no   | —                    | ISO-8601 UTC, from Cowrie's connection-open event                           |
| `ended_at`        | TEXT     | no   | —                    | ISO-8601 UTC, from Cowrie's connection-close event                          |
| `duration_sec`    | REAL     | no   | —                    | `ended_at - started_at`                                                     |
| `username`        | TEXT     | yes  | NULL                 | Last username attempted                                                     |
| `password`        | TEXT     | yes  | NULL                 | Last password attempted (logged for research; honeypot creds only)          |
| `login_success`   | INTEGER  | no   | 0                    | 0/1 — did Cowrie accept the login                                           |
| `commands`        | TEXT     | no   | `'[]'`               | JSON array of commands the attacker ran                                     |
| `transcript`      | TEXT     | no   | `''`                 | Full text transcript: prompts, commands, and Cowrie's faked responses       |
| `payload_hash`    | TEXT     | no   | —                    | SHA-256 of normalized `commands` — used for dedup                           |
| `status`          | TEXT     | no   | `'new'`              | `new` \| `triaged` \| `archived`                                            |
| `verdict`         | TEXT     | yes  | NULL                 | `benign` \| `suspicious` \| `critical` — set by agent                       |
| `verdict_reason`  | TEXT     | yes  | NULL                 | Short explanation from agent                                                |
| `tags`            | TEXT     | no   | `'[]'`               | JSON array of free-form tags from agent (e.g. `["miner", "mirai-variant"]`) |
| `triaged_at`      | TEXT     | yes  | NULL                 | ISO-8601 UTC, set by agent when it updates `status` to `triaged`            |
| `seen_count`      | INTEGER  | no   | 1                    | Incremented on dedup hits                                                   |
| `created_at`      | TEXT     | no   | `CURRENT_TIMESTAMP`  | Row insert time                                                             |
| `updated_at`      | TEXT     | no   | `CURRENT_TIMESTAMP`  | Bumped on any update                                                        |

Indexes:
- `idx_sessions_status` on `(status)` — agent polls `WHERE status='new'`
- `idx_sessions_payload_hash_started` on `(payload_hash, started_at)` — dedup lookups
- `idx_sessions_src_ip` on `(src_ip)`
- `idx_sessions_verdict_updated` on `(verdict, updated_at)` — notify layer watches `verdict='critical'`

---

### `digests`

One row per digest the agent layer produces. Written by Garv's agent; read by
the notification layer.

| Column           | Type    | Null | Default             | Notes                                                  |
| ---------------- | ------- | ---- | ------------------- | ------------------------------------------------------ |
| `id`             | INTEGER | no   | autoincrement       | Primary key                                            |
| `period_start`   | TEXT    | no   | —                   | ISO-8601 UTC, start of the window this digest covers   |
| `period_end`     | TEXT    | no   | —                   | ISO-8601 UTC, end of the window                        |
| `session_count`  | INTEGER | no   | 0                   | Sessions covered                                       |
| `critical_count` | INTEGER | no   | 0                   | How many were verdict='critical'                       |
| `markdown`       | TEXT    | no   | —                   | Rendered digest body, Markdown                         |
| `created_at`     | TEXT    | no   | `CURRENT_TIMESTAMP` | Row insert time                                        |

The notification layer reads `SELECT * FROM digests ORDER BY id DESC LIMIT 1`
to find the latest digest to push.

---

### `alerts`

Ledger of notifications sent. Prevents the notify layer from double-alerting on
the same critical session if it restarts.

| Column        | Type    | Null | Default             | Notes                                                  |
| ------------- | ------- | ---- | ------------------- | ------------------------------------------------------ |
| `id`          | INTEGER | no   | autoincrement       | Primary key                                            |
| `session_id`  | INTEGER | yes  | NULL                | FK → `sessions.id` (NULL for digest alerts)            |
| `digest_id`   | INTEGER | yes  | NULL                | FK → `digests.id` (NULL for session alerts)            |
| `kind`        | TEXT    | no   | —                   | `critical_session` \| `digest`                         |
| `channel`     | TEXT    | no   | —                   | `telegram` \| `email`                                  |
| `status`      | TEXT    | no   | `'sent'`            | `sent` \| `failed`                                     |
| `error`       | TEXT    | yes  | NULL                | Error message if `status='failed'`                     |
| `sent_at`     | TEXT    | no   | `CURRENT_TIMESTAMP` | When the send happened                                 |

---

## Lifecycle conventions

### Status flow (`sessions.status`)

```
new ──(agent triages)──► triaged ──(optional: digest covers it)──► archived
```

- **`new`**: Just inserted by `ingest/tail.py`. Agent layer polls these.
- **`triaged`**: Agent has set `verdict`, `verdict_reason`, `tags`, and
  `triaged_at`. Notification layer checks here for `verdict='critical'`.
- **`archived`**: Optional terminal state — kept around for later analysis but
  no longer surfaced in the live pipeline.

The agent should update `status` and `verdict` in the same transaction so the
notify layer never sees a half-triaged row.

### Verdict values (`sessions.verdict`)

- **`benign`**: Idle scanner, no commands run, or harmless probe.
- **`suspicious`**: Real attacker behavior but nothing worth waking anyone up
  for (credential stuffing, basic recon).
- **`critical`**: Live-fire alert — actual malware download, persistence
  attempt, lateral-movement probe, or anything novel. Triggers the urgent
  notification path.

### Deduplication

When `ingest/tail.py` is about to insert a row, it computes `payload_hash` over
the normalized command list (lowercase, whitespace-collapsed, JSON-encoded).
Then:

```sql
SELECT id FROM sessions
 WHERE payload_hash = :hash
   AND started_at >= datetime('now', '-1 hour')
 ORDER BY id DESC LIMIT 1;
```

If a row is found, increment `seen_count` and update `updated_at` instead of
inserting. Otherwise insert a new row.

Rationale: identical bot payloads hammer the honeypot in bursts. Storing each
hit explodes the row count without adding information. The 1-hour window means
the same payload from a different campaign hours later still gets its own row.

### Timestamps

All timestamps are ISO-8601 UTC strings (`YYYY-MM-DDTHH:MM:SSZ`). Use SQLite's
`CURRENT_TIMESTAMP` for row metadata; use Cowrie's event timestamps for
`started_at` / `ended_at`.

---

## Cross-half API contract (TL;DR)

**Ingestion → DB**
- Inserts rows into `sessions` with `status='new'` and `verdict=NULL`.
- Never reads or modifies `verdict`, `verdict_reason`, `tags`, `triaged_at`.

**Agent → DB**
- Polls `SELECT * FROM sessions WHERE status='new' ORDER BY id`.
- For each: sets `verdict`, `verdict_reason`, `tags`, `triaged_at`, and
  `status='triaged'` in a single transaction.
- Writes periodic digests into `digests`.

**Notify → DB**
- Watches `SELECT * FROM sessions WHERE status='triaged' AND verdict='critical'`
  for rows that don't yet have a `critical_session` row in `alerts`.
- Reads latest row from `digests` on a schedule and emits a `digest` alert if
  it's newer than the last one sent.
- Only writes to `alerts`. Never modifies `sessions` or `digests`.
