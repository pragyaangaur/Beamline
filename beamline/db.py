"""SQLite persistence: keys, usage, and the beacon chain.

SQLite is the right call for V1. The whole working set is keys plus a pulse chain that
grows at 1440 rows/day; that is 500k rows after a year. WAL mode handles the read
concurrency, and the write path is one row per minute plus usage counters. Moving to
Postgres later is a schema copy, and the `Database` interface here is the seam.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
    key_id       TEXT PRIMARY KEY,
    secret_hash  TEXT NOT NULL,
    env          TEXT NOT NULL,
    tier         TEXT NOT NULL,
    label        TEXT NOT NULL DEFAULT '',
    owner        TEXT NOT NULL DEFAULT '',
    created_at   REAL NOT NULL,
    revoked_at   REAL,
    last_used_at REAL
);

CREATE TABLE IF NOT EXISTS usage (
    key_id   TEXT NOT NULL,
    period   TEXT NOT NULL,          -- 'YYYY-MM' billing period
    requests INTEGER NOT NULL DEFAULT 0,
    bytes    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, period)
);

CREATE TABLE IF NOT EXISTS pulses (
    round      INTEGER PRIMARY KEY,
    timestamp  REAL NOT NULL,
    output     TEXT NOT NULL,
    prev_output TEXT NOT NULL,
    body       TEXT NOT NULL          -- full pulse JSON
);
CREATE INDEX IF NOT EXISTS pulses_ts ON pulses(timestamp);
"""


def current_period() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._local = threading.local()
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path, check_same_thread=False, timeout=10.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=10000")
            self._local.conn = conn
        return conn

    # --- keys -------------------------------------------------------------
    def insert_key(self, key_id: str, secret_hash: str, env: str, tier: str,
                   label: str, owner: str, created_at: float) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO api_keys (key_id, secret_hash, env, tier, label, owner, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (key_id, secret_hash, env, tier, label, owner, created_at),
            )

    def get_key(self, key_id: str) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM api_keys WHERE key_id = ?", (key_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_keys(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT key_id, env, tier, label, owner, created_at, revoked_at, last_used_at"
            " FROM api_keys ORDER BY created_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def revoke_key(self, key_id: str) -> bool:
        with self._conn() as c:
            cur = c.execute(
                "UPDATE api_keys SET revoked_at = ? WHERE key_id = ? AND revoked_at IS NULL",
                (time.time(), key_id),
            )
            return cur.rowcount > 0

    def touch_key(self, key_id: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE api_keys SET last_used_at = ? WHERE key_id = ?",
                      (time.time(), key_id))

    # --- usage ------------------------------------------------------------
    def record_usage(self, key_id: str, n_bytes: int) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO usage (key_id, period, requests, bytes) VALUES (?,?,1,?)"
                " ON CONFLICT(key_id, period) DO UPDATE SET"
                " requests = requests + 1, bytes = bytes + excluded.bytes",
                (key_id, current_period(), n_bytes),
            )

    def get_usage(self, key_id: str, period: str | None = None) -> dict:
        row = self._conn().execute(
            "SELECT requests, bytes FROM usage WHERE key_id = ? AND period = ?",
            (key_id, period or current_period()),
        ).fetchone()
        return {"requests": row["requests"], "bytes": row["bytes"]} if row else {"requests": 0, "bytes": 0}

    # --- beacon -----------------------------------------------------------
    def insert_pulse(self, pulse: dict) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR IGNORE INTO pulses (round, timestamp, output, prev_output, body)"
                " VALUES (?,?,?,?,?)",
                (pulse["round"], pulse["timestamp_ms"] / 1000.0, pulse["output"],
                 pulse["prev_output"], json.dumps(pulse)),
            )

    def latest_pulse(self) -> dict | None:
        row = self._conn().execute(
            "SELECT body FROM pulses ORDER BY round DESC LIMIT 1"
        ).fetchone()
        return json.loads(row["body"]) if row else None

    def get_pulse(self, round_no: int) -> dict | None:
        row = self._conn().execute(
            "SELECT body FROM pulses WHERE round = ?", (round_no,)
        ).fetchone()
        return json.loads(row["body"]) if row else None

    def pulse_range(self, start: int, count: int) -> list[dict]:
        rows = self._conn().execute(
            "SELECT body FROM pulses WHERE round >= ? ORDER BY round LIMIT ?",
            (start, min(count, 500)),
        ).fetchall()
        return [json.loads(r["body"]) for r in rows]

    def pulse_count(self) -> int:
        return self._conn().execute("SELECT COUNT(*) AS n FROM pulses").fetchone()["n"]
