"""Tail Cowrie's cowrie.json log and persist sessions to SQLite.

Follows the file line by line, groups Cowrie events by session UUID, and writes
one row to `sessions` per session.closed event (with dedup against identical
payloads seen in the last hour).

See docs/SCHEMA.md for the DB contract.

Usage:
    python -m ingest.tail \\
        --cowrie-log /path/to/cowrie.json \\
        --db /path/to/sessions.db \\
        --state /path/to/.tail.state \\
        [--once]

Defaults assume local dev layout (./var/cowrie.json, ./sessions.db, ./var/.tail.state).
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import pathlib
import signal
import sqlite3
import sys
import time
from datetime import datetime
from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_INIT_SQL = REPO_ROOT / "db" / "init.sql"
DEFAULT_COWRIE_LOG = REPO_ROOT / "var" / "cowrie.json"
DEFAULT_DB_PATH = REPO_ROOT / "sessions.db"
DEFAULT_STATE_PATH = REPO_ROOT / "var" / ".tail.state"

DEDUP_WINDOW_SECONDS = 3600
POLL_INTERVAL_SECONDS = 0.5
STALE_SESSION_SECONDS = 3600


@dataclasses.dataclass
class SessionAccumulator:
    """In-memory accumulation of Cowrie events for one SSH session."""

    cowrie_session: str
    src_ip: str = ""
    src_port: int | None = None
    dst_port: int = 22
    started_at: str = ""
    last_event_at: str = ""
    username: str | None = None
    password: str | None = None
    login_success: int = 0
    commands: list[str] = dataclasses.field(default_factory=list)
    transcript_lines: list[str] = dataclasses.field(default_factory=list)
    last_event_monotonic: float = dataclasses.field(default_factory=time.monotonic)

    def absorb(self, event: dict[str, Any]) -> None:
        eventid = event.get("eventid", "")
        ts = event.get("timestamp", "")
        if ts and not self.started_at:
            self.started_at = ts
        if ts:
            self.last_event_at = ts
        self.last_event_monotonic = time.monotonic()

        clock = _short_clock(ts)

        if eventid == "cowrie.session.connect":
            self.src_ip = event.get("src_ip", self.src_ip)
            self.src_port = event.get("src_port", self.src_port)
            self.dst_port = event.get("dst_port", self.dst_port)
            self.transcript_lines.append(
                f"[{clock}] connect from {self.src_ip}:{self.src_port}"
            )
        elif eventid in ("cowrie.login.success", "cowrie.login.failed"):
            self.username = event.get("username", self.username)
            self.password = event.get("password", self.password)
            outcome = "success" if eventid.endswith("success") else "failed"
            if outcome == "success":
                self.login_success = 1
            self.transcript_lines.append(
                f"[{clock}] login.{outcome} {self.username!r} / {self.password!r}"
            )
        elif eventid == "cowrie.command.input":
            cmd = event.get("input", "")
            self.commands.append(cmd)
            self.transcript_lines.append(f"[{clock}] $ {cmd}")
        elif eventid == "cowrie.session.file_download":
            url = event.get("url", "")
            outfile = event.get("outfile", "")
            self.transcript_lines.append(f"[{clock}] download {url} -> {outfile}")
        elif eventid == "cowrie.session.closed":
            try:
                duration = float(event.get("duration", 0.0))
            except (TypeError, ValueError):
                duration = 0.0
            self.transcript_lines.append(f"[{clock}] session closed (duration={duration:.1f}s)")


def _short_clock(ts: str) -> str:
    """Render '2026-05-17T12:34:56.789Z' as '12:34:56' for transcript prefixes."""
    if not ts or "T" not in ts:
        return "??:??:??"
    time_part = ts.split("T", 1)[1]
    return time_part.split(".", 1)[0].rstrip("Z")[:8]


def _payload_hash(commands: list[str]) -> str:
    """Stable hash for dedup: lowercase + whitespace-collapsed + newline-joined."""
    normalized = "\n".join(" ".join(c.split()).lower() for c in commands)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _duration_seconds(started_at: str, ended_at: str) -> float:
    try:
        s = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        e = datetime.fromisoformat(ended_at.replace("Z", "+00:00"))
        return max(0.0, (e - s).total_seconds())
    except ValueError:
        return 0.0


def bootstrap_db(db_path: pathlib.Path, init_sql_path: pathlib.Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path, isolation_level=None)  # autocommit; we BEGIN explicitly
    con.row_factory = sqlite3.Row
    con.executescript(init_sql_path.read_text(encoding="utf-8"))
    return con


def persist_session(con: sqlite3.Connection, acc: SessionAccumulator) -> str:
    """Insert or dedup-update one session. Returns 'inserted' or 'deduped'."""
    if not acc.started_at or not acc.last_event_at:
        return "skipped"

    ended_at = acc.last_event_at
    duration = _duration_seconds(acc.started_at, ended_at)
    payload_hash = _payload_hash(acc.commands)
    commands_json = json.dumps(acc.commands, ensure_ascii=False)
    transcript = "\n".join(acc.transcript_lines)

    con.execute("BEGIN IMMEDIATE")
    try:
        existing = con.execute(
            """
            SELECT id FROM sessions
             WHERE payload_hash = ?
               AND started_at >= datetime(?, '-1 hour')
             ORDER BY id DESC LIMIT 1
            """,
            (payload_hash, acc.started_at),
        ).fetchone()

        if existing is not None:
            con.execute(
                """
                UPDATE sessions
                   SET seen_count = seen_count + 1,
                       ended_at   = ?,
                       updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?
                """,
                (ended_at, existing["id"]),
            )
            con.execute("COMMIT")
            return "deduped"

        con.execute(
            """
            INSERT INTO sessions (
                cowrie_session, src_ip, src_port, dst_port,
                started_at, ended_at, duration_sec,
                username, password, login_success,
                commands, transcript, payload_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                acc.cowrie_session,
                acc.src_ip or "unknown",
                acc.src_port,
                acc.dst_port,
                acc.started_at,
                ended_at,
                duration,
                acc.username,
                acc.password,
                acc.login_success,
                commands_json,
                transcript,
                payload_hash,
            ),
        )
        con.execute("COMMIT")
        return "inserted"
    except Exception:
        con.execute("ROLLBACK")
        raise


def load_state(state_path: pathlib.Path) -> dict[str, Any]:
    if not state_path.exists():
        return {"offset": 0, "size": 0}
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {"offset": 0, "size": 0}


def save_state(state_path: pathlib.Path, offset: int, size: int) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_path.with_suffix(state_path.suffix + ".tmp")
    tmp.write_text(json.dumps({"offset": offset, "size": size}), encoding="utf-8")
    tmp.replace(state_path)


def process_events(
    con: sqlite3.Connection,
    sessions: dict[str, SessionAccumulator],
    events: list[dict[str, Any]],
) -> tuple[int, int]:
    inserted = deduped = 0
    for event in events:
        sid = event.get("session")
        if not sid:
            continue
        acc = sessions.get(sid) or SessionAccumulator(cowrie_session=sid)
        sessions[sid] = acc
        acc.absorb(event)

        if event.get("eventid") == "cowrie.session.closed":
            outcome = persist_session(con, acc)
            if outcome == "inserted":
                inserted += 1
            elif outcome == "deduped":
                deduped += 1
            sessions.pop(sid, None)
    return inserted, deduped


def evict_stale(
    con: sqlite3.Connection,
    sessions: dict[str, SessionAccumulator],
) -> int:
    """Flush any session that's gone quiet for STALE_SESSION_SECONDS."""
    now = time.monotonic()
    stale_ids = [
        sid
        for sid, acc in sessions.items()
        if now - acc.last_event_monotonic > STALE_SESSION_SECONDS
    ]
    flushed = 0
    for sid in stale_ids:
        acc = sessions.pop(sid)
        if persist_session(con, acc) == "inserted":
            flushed += 1
    return flushed


def read_new_lines(
    log_path: pathlib.Path, state: dict[str, Any]
) -> tuple[list[dict[str, Any]], int]:
    """Read new lines since last offset. Detects rotation by shrinking size."""
    if not log_path.exists():
        return [], state["offset"]

    size = log_path.stat().st_size
    offset = state["offset"]
    if size < offset:
        offset = 0  # truncation / rotation

    events: list[dict[str, Any]] = []
    with log_path.open("rb") as f:
        f.seek(offset)
        buf = f.read()
        new_offset = offset

        # Process whole lines only; a trailing partial line (no \n) stays unread.
        if not buf:
            return [], offset
        last_newline = buf.rfind(b"\n")
        if last_newline == -1:
            return [], offset
        complete = buf[: last_newline + 1]
        new_offset = offset + len(complete)

        for raw in complete.splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                events.append(json.loads(raw))
            except ValueError:
                # Malformed line — log and skip rather than block the pipeline.
                print(f"[warn] skipping malformed JSON line: {raw[:120]!r}", file=sys.stderr)

    return events, new_offset


def run(
    log_path: pathlib.Path,
    db_path: pathlib.Path,
    state_path: pathlib.Path,
    init_sql_path: pathlib.Path,
    once: bool,
) -> int:
    con = bootstrap_db(db_path, init_sql_path)
    state = load_state(state_path)
    sessions: dict[str, SessionAccumulator] = {}

    stop = {"flag": False}

    def _stop(signum, frame):  # noqa: ARG001
        stop["flag"] = True

    signal.signal(signal.SIGINT, _stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _stop)

    total_inserted = total_deduped = 0
    print(
        f"[tail] log={log_path} db={db_path} state={state_path} "
        f"start_offset={state['offset']} mode={'once' if once else 'follow'}"
    )

    while not stop["flag"]:
        events, new_offset = read_new_lines(log_path, state)
        if events:
            inserted, deduped = process_events(con, sessions, events)
            total_inserted += inserted
            total_deduped += deduped
            if inserted or deduped:
                print(f"[tail] +{inserted} inserted, +{deduped} deduped")

        if new_offset != state["offset"]:
            size = log_path.stat().st_size if log_path.exists() else 0
            state = {"offset": new_offset, "size": size}
            save_state(state_path, new_offset, size)

        evict_stale(con, sessions)

        if once:
            break
        time.sleep(POLL_INTERVAL_SECONDS)

    # Final flush on shutdown.
    for sid in list(sessions):
        persist_session(con, sessions.pop(sid))

    con.close()
    print(f"[tail] done. total inserted={total_inserted} deduped={total_deduped}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cowrie-log", type=pathlib.Path, default=DEFAULT_COWRIE_LOG)
    parser.add_argument("--db", type=pathlib.Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--state", type=pathlib.Path, default=DEFAULT_STATE_PATH)
    parser.add_argument("--init-sql", type=pathlib.Path, default=DEFAULT_INIT_SQL)
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process currently available lines and exit (for testing or cron).",
    )
    args = parser.parse_args(argv)
    return run(args.cowrie_log, args.db, args.state, args.init_sql, args.once)


if __name__ == "__main__":
    raise SystemExit(main())
