"""Telegram alert helper and alerts ledger writer."""

import json
import os
import re
import sqlite3
from datetime import datetime, timezone

import requests


def _require_env(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f"Required env var {name!r} is not set")
    return val


def _telegram_url() -> str:
    return f"https://api.telegram.org/bot{_require_env('TELEGRAM_TOKEN')}/sendMessage"


def _chat_id() -> str:
    return _require_env("TELEGRAM_CHAT_ID")


def _escape_markdown(text: str) -> str:
    """Escape characters that break Telegram Markdown mode."""
    return re.sub(r"([_*`\[])", r"\\\1", text)


def _already_alerted(conn: sqlite3.Connection, session_id: int) -> bool:
    row = conn.execute(
        "SELECT 1 FROM alerts WHERE session_id = ? AND kind IN ('critical_session', 'suspicious_session') LIMIT 1",
        (session_id,),
    ).fetchone()
    return row is not None


def _record_alert(
    conn: sqlite3.Connection,
    *,
    session_id: int | None = None,
    digest_id: int | None = None,
    kind: str,
    status: str,
    error: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO alerts (session_id, digest_id, kind, channel, status, error, sent_at)
        VALUES (?, ?, ?, 'telegram', ?, ?, ?)
        """,
        (session_id, digest_id, kind, status, error, datetime.now(timezone.utc).isoformat()),
    )


def _format_message(row: sqlite3.Row) -> str:
    verdict_emoji = {"suspicious": "⚠️", "critical": "🚨"}.get(row["verdict"], "ℹ️")
    try:
        cmds = json.loads(row["commands"] or "[]")[:3]
        cmds_text = "\n".join(f"  `{c}`" for c in cmds) if cmds else "  _(no commands)_"
    except Exception:
        cmds_text = "  _(parse error)_"

    reason = _escape_markdown(row["verdict_reason"] or "")
    return (
        f"{verdict_emoji} *{row['verdict'].upper()}* — {row['src_ip']}\n"
        f"_{reason}_\n\n"
        f"*Commands:*\n{cmds_text}\n\n"
        f"Session: `{row['cowrie_session']}`"
    )


def send_alert(conn: sqlite3.Connection, row: sqlite3.Row) -> None:
    """Send a Telegram alert for a suspicious/critical session, deduped via alerts table."""
    session_id = row["id"]

    if _already_alerted(conn, session_id):
        return

    kind = "critical_session" if row["verdict"] == "critical" else "suspicious_session"
    text = _format_message(row)

    try:
        resp = requests.post(
            _telegram_url(),
            json={"chat_id": _chat_id(), "text": text, "parse_mode": "Markdown"},
            timeout=10,
        )
        resp.raise_for_status()
        _record_alert(conn, session_id=session_id, kind=kind, status="sent")
    except Exception as exc:
        _record_alert(conn, session_id=session_id, kind=kind, status="failed", error=str(exc))

    conn.commit()


def send_digest_alert(conn: sqlite3.Connection, digest_id: int, markdown: str) -> None:
    """Send the latest digest to Telegram, deduped via alerts table."""
    if conn.execute(
        "SELECT 1 FROM alerts WHERE digest_id = ? AND kind = 'digest' LIMIT 1",
        (digest_id,),
    ).fetchone():
        return

    # Telegram has a 4096-char limit; truncate gracefully
    text = markdown[:4000] + ("\n…_(truncated)_" if len(markdown) > 4000 else "")

    try:
        resp = requests.post(
            _telegram_url(),
            json={"chat_id": _chat_id(), "text": text, "parse_mode": "Markdown"},
            timeout=10,
        )
        resp.raise_for_status()
        _record_alert(conn, digest_id=digest_id, kind="digest", status="sent")
    except Exception as exc:
        _record_alert(conn, digest_id=digest_id, kind="digest", status="failed", error=str(exc))

    conn.commit()
