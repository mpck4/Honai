"""
Digest agent — summarises recently triaged sessions and writes a row to `digests`.
Run on a cron: every 30 min for demo, weekly in prod.

Usage (run from the agents/ directory):
    cd agents && python digest.py

Required env vars:
    DB_PATH          Path to sessions.db (default: /data/sessions.db)
    GROQ_API_KEY
    TELEGRAM_TOKEN
    TELEGRAM_CHAT_ID
"""

import json
import os
import sqlite3
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

from groq import Groq, RateLimitError

from notify import send_digest_alert

DB_PATH = os.environ.get("DB_PATH", "/data/sessions.db")

_client = Groq()

_SYSTEM_PROMPT = """You are a security analyst writing a digest for a site owner.
Given a list of SSH honeypot sessions from the past period, write a concise 3-paragraph
narrative in Markdown:
1. Overall picture — how many sessions, top source IPs, general attacker profile
2. Most interesting sessions — what attackers actually tried to do
3. Anything worth following up on (or reassurance that nothing critical happened)

Be direct and plain-English. No jargon the average indie dev wouldn't know.
"""


def _period_start(conn: sqlite3.Connection) -> str:
    """Start of the window = end of the last digest, or earliest session if no digests yet."""
    row = conn.execute(
        "SELECT period_end FROM digests ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if row:
        return row["period_end"]
    earliest = conn.execute("SELECT MIN(started_at) FROM sessions").fetchone()
    return earliest[0] or datetime.now(timezone.utc).isoformat()


MAX_SESSIONS_IN_PROMPT = 100


def _fetch_sessions(conn: sqlite3.Connection, since: str) -> list[dict]:
    rows = conn.execute(
        """
        SELECT src_ip, verdict, verdict_reason, tags, commands, started_at, duration_sec
          FROM sessions
         WHERE status = 'triaged'
           AND triaged_at >= ?
         ORDER BY started_at
        """,
        (since,),
    ).fetchall()
    return [dict(r) for r in rows]


def _build_prompt(sessions: list[dict], period_start: str, period_end: str) -> str:
    total = len(sessions)
    # Prioritise critical/suspicious, then cap to avoid token overflow
    _rank = {"critical": 0, "suspicious": 1, "benign": 2}
    ranked = sorted(sessions, key=lambda s: _rank.get(s["verdict"], 3))
    capped = ranked[:MAX_SESSIONS_IN_PROMPT]

    summary_lines = []
    for s in capped:
        cmds = json.loads(s["commands"] or "[]")[:5]
        summary_lines.append(
            f"- {s['src_ip']} | {s['verdict']} | {s['verdict_reason']} | cmds: {cmds}"
        )
    session_block = "\n".join(summary_lines) if summary_lines else "_(no sessions)_"
    truncation_note = f"\n_(showing {len(capped)} of {total} sessions — prioritised by severity)_" if total > MAX_SESSIONS_IN_PROMPT else ""
    return (
        f"Period: {period_start} → {period_end}\n"
        f"Total sessions: {total}{truncation_note}\n\n"
        f"{session_block}"
    )


def run() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")

    period_end = datetime.now(timezone.utc).isoformat()
    period_start = _period_start(conn)

    sessions = _fetch_sessions(conn, period_start)
    critical_count = sum(1 for s in sessions if s["verdict"] == "critical")

    if not sessions:
        print("[digest] no new triaged sessions — skipping")
        return

    prompt = _build_prompt(sessions, period_start, period_end)

    try:
        completion = _client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=1024,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        )
        markdown = completion.choices[0].message.content.strip()
    except RateLimitError:
        print("[digest] Groq rate limit hit — skipping this run, will retry next cron")
        return
    except Exception as exc:
        print(f"[digest] Groq error: {exc}")
        return

    with conn:
        cursor = conn.execute(
            """
            INSERT INTO digests (period_start, period_end, session_count, critical_count, markdown, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (period_start, period_end, len(sessions), critical_count, markdown, period_end),
        )
        digest_id = cursor.lastrowid

    print(f"[digest] wrote digest {digest_id} covering {len(sessions)} sessions")

    send_digest_alert(conn, digest_id, markdown)


if __name__ == "__main__":
    run()
