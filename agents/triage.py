"""
Triage agent — polls sessions.db for new sessions, asks an LLM for a verdict,
writes results back, and fires Telegram alerts for suspicious/critical sessions.

Usage (run from the agents/ directory):
    cd agents && python triage.py

Required env vars:
    DB_PATH          Path to sessions.db (default: /data/sessions.db)
    GROQ_API_KEY
    TELEGRAM_TOKEN
    TELEGRAM_CHAT_ID
"""

import json
import os
import sqlite3
import time
from datetime import datetime, timezone

from groq import Groq, RateLimitError

from notify import send_alert

DB_PATH = os.environ.get("DB_PATH", "/data/sessions.db")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "10"))

_client = Groq()

_SYSTEM_PROMPT = """You are a security analyst triaging SSH honeypot sessions.
Analyze the session and respond with a JSON object (no markdown, raw JSON only):
{
  "verdict": "benign" | "suspicious" | "critical",
  "verdict_reason": "<one sentence explanation>",
  "tags": ["<tag1>", "<tag2>"]
}

Verdict guide:
- benign: idle scanner, no commands, harmless credential probe
- suspicious: real attacker behavior — credential stuffing, recon, basic enumeration
- critical: active exploitation — malware download, persistence, lateral movement, novel technique

Tags: short labels like "mirai-variant", "miner", "port-scan", "credential-stuffing", "wget-dropper"
"""


def _build_user_prompt(row: sqlite3.Row) -> str:
    return (
        f"Source IP: {row['src_ip']}\n"
        f"Login success: {bool(row['login_success'])}\n"
        f"Username tried: {row['username']}\n"
        f"Password tried: {row['password']}\n"
        f"Commands: {row['commands']}\n\n"
        f"Full transcript:\n{row['transcript']}"
    )


_VALID_VERDICTS = {"benign", "suspicious", "critical"}


def _parse_llm_response(raw: str) -> dict:
    # Strip markdown code fences if the model wraps its output
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1]
        raw = raw.rsplit("```", 1)[0]
    result = json.loads(raw.strip())
    if result.get("verdict") not in _VALID_VERDICTS:
        result["verdict"] = "benign"
    return result


def _triage_session(row: sqlite3.Row) -> dict:
    completion = _client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        max_tokens=256,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(row)},
        ],
    )
    raw = completion.choices[0].message.content.strip()
    return _parse_llm_response(raw)


def _process_row(conn: sqlite3.Connection, row: sqlite3.Row) -> None:
    try:
        result = _triage_session(row)
    except RateLimitError:
        print("[triage] Groq rate limit hit — backing off 60s")
        time.sleep(60)
        return
    except Exception as exc:
        print(f"[triage] Groq error for session {row['id']}: {exc}")
        return

    verdict = result.get("verdict", "benign")
    verdict_reason = result.get("verdict_reason", "")
    tags = json.dumps(result.get("tags", []))
    now = datetime.now(timezone.utc).isoformat()

    with conn:
        conn.execute(
            """
            UPDATE sessions
               SET verdict = ?,
                   verdict_reason = ?,
                   tags = ?,
                   triaged_at = ?,
                   status = 'triaged',
                   updated_at = ?
             WHERE id = ? AND status = 'new'
            """,
            (verdict, verdict_reason, tags, now, now, row["id"]),
        )

    print(f"[triage] session {row['id']} ({row['src_ip']}) → {verdict}")

    if verdict in ("suspicious", "critical"):
        # Re-fetch so notify sees the updated row
        updated = conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (row["id"],)
        ).fetchone()
        send_alert(conn, updated)


def run() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Reduce lock contention with concurrent writers (tail.py, digest.py)
    conn.execute("PRAGMA journal_mode=WAL")

    print(f"[triage] watching {DB_PATH} every {POLL_INTERVAL}s")

    while True:
        rows = conn.execute(
            "SELECT * FROM sessions WHERE status = 'new' ORDER BY id"
        ).fetchall()

        for row in rows:
            _process_row(conn, row)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
