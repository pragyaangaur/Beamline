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

-- A draw announced before the pulse that decides it exists.
--
-- The beacon proves a pulse was not tampered with. It cannot prove the draw was
-- named first, and "named first" is the property the whole product rests on: a
-- runner who picks the tag after seeing the pulse, or picks which pulse to use,
-- rigs the outcome without touching a single byte of cryptography. Recording the
-- announcement -- the exact tag, the exact target round, and the round the chain
-- had reached at the time -- is what turns that convention into evidence.
--
-- created_after_round is the load-bearing column. If it is below target_round, the
-- pulse that decided the draw had not been emitted when the draw was named.
CREATE TABLE IF NOT EXISTS commitments (
    commit_id          TEXT PRIMARY KEY,
    tag                TEXT NOT NULL,
    target_round       INTEGER NOT NULL,
    created_at_ms      INTEGER NOT NULL,
    created_after_round INTEGER NOT NULL,
    key_id             TEXT NOT NULL DEFAULT '',
    public_key         TEXT,
    signature          TEXT,
    body               TEXT NOT NULL      -- full signed receipt JSON
);
CREATE INDEX IF NOT EXISTS commitments_round ON commitments(target_round);
CREATE INDEX IF NOT EXISTS commitments_key ON commitments(key_id, created_at_ms);

-- A signing-key change, endorsed by the key being retired.
--
-- Without this, rotation is whatever the pulses claim: a verifier told to trust two
-- keys accepts a chain that switches between them, and nothing anywhere shows the
-- first key ever agreed. That is indistinguishable from an archive substitution by
-- somebody who persuaded the verifier to trust their key too.
--
-- The record is signed twice. The outgoing key signs to endorse; the incoming key
-- signs to prove the operator actually holds it, so a rotation cannot be issued
-- towards a key nobody controls.
CREATE TABLE IF NOT EXISTS key_rotations (
    effective_round INTEGER PRIMARY KEY,
    from_public_key TEXT NOT NULL,
    to_public_key   TEXT NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    body            TEXT NOT NULL      -- full signed rotation record JSON
);

-- A stranger's attempt to predict a pulse before it exists.
--
-- This table is the challenge. Beamline claims a pulse cannot be predicted, and a
-- claim nobody can attempt is not falsifiable -- it is marketing. Recording the
-- attempt, signed, against a round that has not been emitted is what converts
-- "trust us" into a bet the operator can visibly lose.
--
-- received_after_round is the load-bearing column, exactly as it is for commitments:
-- if it is below target_round, the pulse being predicted did not exist when the
-- prediction was lodged. If it is not, the row is a copy and scores nothing.
--
-- prefix_bits is kept for losing rows too, which is most of them. Each is one sample
-- of a geometric(1/2) distribution under the null hypothesis, so the failures
-- accumulate into a public test for bias in the published output.
CREATE TABLE IF NOT EXISTS predictions (
    prediction_id        TEXT PRIMARY KEY,
    target_round         INTEGER NOT NULL,
    predicted_output     TEXT NOT NULL,
    handle               TEXT NOT NULL DEFAULT '',
    submitter            TEXT NOT NULL DEFAULT '',   -- coarse origin, for rate limiting
    received_at_ms       INTEGER NOT NULL,
    received_after_round INTEGER NOT NULL,
    resolved_at_ms       INTEGER,
    actual_output        TEXT,
    prefix_bits          INTEGER,
    exact                INTEGER NOT NULL DEFAULT 0,
    body                 TEXT NOT NULL      -- full signed prediction receipt JSON
);
CREATE INDEX IF NOT EXISTS predictions_round ON predictions(target_round);
CREATE INDEX IF NOT EXISTS predictions_pending ON predictions(target_round, resolved_at_ms);
CREATE INDEX IF NOT EXISTS predictions_submitter ON predictions(submitter, received_at_ms);
CREATE INDEX IF NOT EXISTS predictions_recent ON predictions(received_at_ms DESC);
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

    # --- commitments ------------------------------------------------------
    def insert_commitment(self, receipt: dict, key_id: str = "") -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO commitments (commit_id, tag, target_round, created_at_ms,"
                " created_after_round, key_id, public_key, signature, body)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (receipt["commit_id"], receipt["tag"], receipt["target_round"],
                 receipt["created_at_ms"], receipt["created_after_round"], key_id,
                 receipt.get("public_key"), receipt.get("signature"),
                 json.dumps(receipt)),
            )

    def count_commitments_by(self, key_id: str, target_round: int) -> int:
        """How many draws this committer has already registered against this round.

        Stamped into the receipt as `sequence`. A runner who registers twenty draws
        against one pulse and publishes the flattering one is holding a receipt that
        says so, which is the difference between the practice being visible and being
        provable.
        """
        return self._conn().execute(
            "SELECT COUNT(*) AS n FROM commitments WHERE key_id = ? AND target_round = ?",
            (key_id, target_round),
        ).fetchone()["n"]

    def get_commitment(self, commit_id: str) -> dict | None:
        row = self._conn().execute(
            "SELECT body FROM commitments WHERE commit_id = ?", (commit_id,)
        ).fetchone()
        return json.loads(row["body"]) if row else None

    def commitments_for_round(self, target_round: int) -> list[dict]:
        """Every draw announced against one pulse.

        Public on purpose: an entrant who can see all the commitments naming a round
        can tell whether the runner announced one draw or quietly announced twenty and
        published the one they liked.
        """
        rows = self._conn().execute(
            "SELECT body FROM commitments WHERE target_round = ? ORDER BY created_at_ms",
            (target_round,),
        ).fetchall()
        return [json.loads(r["body"]) for r in rows]

    def count_commitments(self) -> int:
        return self._conn().execute(
            "SELECT COUNT(*) AS n FROM commitments").fetchone()["n"]

    # --- key rotations ----------------------------------------------------
    def insert_rotation(self, record: dict) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO key_rotations (effective_round, from_public_key,"
                " to_public_key, created_at_ms, body) VALUES (?,?,?,?,?)",
                (record["effective_round"], record["from_public_key"],
                 record["to_public_key"], record["created_at_ms"], json.dumps(record)),
            )

    def rotations(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT body FROM key_rotations ORDER BY effective_round").fetchall()
        return [json.loads(r["body"]) for r in rows]

    # --- predictions ------------------------------------------------------
    def insert_prediction(self, receipt: dict, submitter: str = "") -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO predictions (prediction_id, target_round, predicted_output,"
                " handle, submitter, received_at_ms, received_after_round, body)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (receipt["prediction_id"], receipt["target_round"],
                 receipt["predicted_output"], receipt.get("handle", ""), submitter,
                 receipt["received_at_ms"], receipt["received_after_round"],
                 json.dumps(receipt)),
            )

    def _prediction_row(self, row: sqlite3.Row) -> dict:
        return {
            "prediction_id": row["prediction_id"],
            "target_round": row["target_round"],
            "predicted_output": row["predicted_output"],
            "handle": row["handle"],
            "resolved_at_ms": row["resolved_at_ms"],
            "actual_output": row["actual_output"],
            "prefix_bits": row["prefix_bits"],
            "exact": bool(row["exact"]),
            "receipt": json.loads(row["body"]),
        }

    def get_prediction(self, prediction_id: str) -> dict | None:
        row = self._conn().execute(
            "SELECT * FROM predictions WHERE prediction_id = ?", (prediction_id,)
        ).fetchone()
        return self._prediction_row(row) if row else None

    def predictions_for_round(self, target_round: int) -> list[dict]:
        """Every prediction lodged against one round.

        Public and complete, for the same reason the commitment list is: a challenge
        where the operator chooses which attempts to acknowledge is not a challenge.
        """
        rows = self._conn().execute(
            "SELECT * FROM predictions WHERE target_round = ? ORDER BY received_at_ms",
            (target_round,),
        ).fetchall()
        return [self._prediction_row(r) for r in rows]

    def unresolved_predictions(self, target_round: int) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM predictions WHERE target_round = ? AND resolved_at_ms IS NULL",
            (target_round,),
        ).fetchall()
        return [self._prediction_row(r) for r in rows]

    def resolve_prediction(self, prediction_id: str, actual_output: str,
                           bits: int, exact: bool) -> None:
        """Record the verdict. Write-once: a resolved prediction is never re-scored.

        The `resolved_at_ms IS NULL` guard is not defensive tidiness. Without it a
        replayed resolution could overwrite a winning row with a later, losing one,
        which is precisely the move an operator would want and precisely what the
        challenger cannot check for themselves.
        """
        with self._conn() as c:
            c.execute(
                "UPDATE predictions SET resolved_at_ms = ?, actual_output = ?,"
                " prefix_bits = ?, exact = ? WHERE prediction_id = ?"
                " AND resolved_at_ms IS NULL",
                (int(time.time() * 1000), actual_output, bits, 1 if exact else 0,
                 prediction_id),
            )

    def rounds_awaiting_resolution(self, max_round: int, limit: int = 50) -> list[int]:
        """Rounds that are published but still hold unscored predictions.

        Resolution normally happens the instant a round lands. This exists because
        "normally" is not good enough for the one table a stranger is invited to
        audit: a restart mid-pulse, or a transient error in the pulse loop, would
        otherwise leave a prediction permanently unscored, and an unscored prediction
        is indistinguishable from an ignored one.
        """
        rows = self._conn().execute(
            "SELECT DISTINCT target_round FROM predictions"
            " WHERE resolved_at_ms IS NULL AND target_round <= ?"
            " ORDER BY target_round LIMIT ?",
            (max_round, limit),
        ).fetchall()
        return [r["target_round"] for r in rows]

    def count_predictions_by(self, submitter: str, target_round: int) -> int:
        return self._conn().execute(
            "SELECT COUNT(*) AS n FROM predictions WHERE submitter = ? AND target_round = ?",
            (submitter, target_round),
        ).fetchone()["n"]

    def recent_predictions(self, limit: int = 20) -> list[dict]:
        rows = self._conn().execute(
            "SELECT * FROM predictions ORDER BY received_at_ms DESC LIMIT ?",
            (min(limit, 200),),
        ).fetchall()
        return [self._prediction_row(r) for r in rows]

    def prediction_stats(self) -> dict:
        row = self._conn().execute(
            "SELECT COUNT(*) AS total,"
            " COUNT(resolved_at_ms) AS resolved,"
            " COALESCE(SUM(exact), 0) AS exact,"
            " COALESCE(MAX(prefix_bits), 0) AS best_bits,"
            " COALESCE(AVG(prefix_bits), 0.0) AS mean_bits,"
            " COUNT(DISTINCT NULLIF(handle, '')) AS handles"
            " FROM predictions"
        ).fetchone()
        return dict(row)

    def pulse_count(self) -> int:
        return self._conn().execute("SELECT COUNT(*) AS n FROM pulses").fetchone()["n"]
