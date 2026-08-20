"""On-disk archive of harvested entropy blocks.

Layout:

    data/pool/
        index.db              SQLite: block hashes, shard locations, timestamps
        anu-000001.bin        packed 6-bit blocks, append-only
        anu-000002.bin        ...

Two properties matter more than anything else here.

**Deduplication is a correctness requirement, not an optimisation.** A block served
twice carries the entropy of one block. Archiving it twice and later crediting it
twice would inflate the pool's entropy accounting by exactly the amount that makes
the accounting worthless. Every block is keyed by SHA-256 in an indexed table, so a
repeat is detected in O(1) and discarded before it is written.

**The archive is consume-once.** `reserve()` hands out blocks that have not been fed
into the entropy pool before and marks them consumed. Replaying archived bytes adds
no unpredictability, so a pool that re-read the same shard would be lying to itself.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .entropy import blocks as B

SHARD_MAX_BLOCKS = 8192          # ~6 MB per shard at 768 bytes/block
PACKED_BLOCK_BYTES = 768         # 1024 chars packed at 6 bits

SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks (
    hash       TEXT PRIMARY KEY,
    shard      INTEGER NOT NULL,
    slot       INTEGER NOT NULL,
    n_chars    INTEGER NOT NULL,
    fetched_at REAL NOT NULL,
    consumed_at REAL
);
CREATE INDEX IF NOT EXISTS blocks_unconsumed ON blocks(consumed_at) WHERE consumed_at IS NULL;
CREATE TABLE IF NOT EXISTS stats (k TEXT PRIMARY KEY, v REAL NOT NULL);
"""


@dataclass
class StoreStats:
    total_blocks: int
    unconsumed_blocks: int
    duplicates_rejected: int
    invalid_rejected: int
    entropy_bits_available: float
    bytes_on_disk: int
    shards: int
    oldest: float | None
    newest: float | None

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["entropy_bits_available"] = round(d["entropy_bits_available"])
        return d


class EntropyStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._local = threading.local()
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.root / "index.db", check_same_thread=False, timeout=15.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    def _shard_path(self, n: int) -> Path:
        return self.root / f"anu-{n:06d}.bin"

    # --- counters ---------------------------------------------------------
    def _bump(self, key: str, n: float = 1) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO stats (k,v) VALUES (?,?) "
                      "ON CONFLICT(k) DO UPDATE SET v = v + excluded.v", (key, n))

    def counter(self, key: str) -> float:
        row = self._conn().execute("SELECT v FROM stats WHERE k=?", (key,)).fetchone()
        return row["v"] if row else 0.0

    def note_invalid(self) -> None:
        self._bump("invalid_rejected")

    # --- writing ----------------------------------------------------------
    def add_block(self, text: str) -> bool:
        """Archive one validated block. Returns False if it was a duplicate.

        Duplicates are counted, not silently dropped: a rising duplicate rate is the
        signal that the upstream endpoint has started serving from a cache, which is
        exactly when harvesting should slow down or stop.
        """
        h = B.block_id(text)
        packed = B.pack(text)
        if len(packed) > PACKED_BLOCK_BYTES:
            # Slots are fixed width so reads are a single seek. A block that does not
            # fit must be refused loudly: writing it would silently truncate the tail
            # and hand back corrupted entropy on the next read.
            raise ValueError(
                f"block of {len(text)} chars packs to {len(packed)} bytes, which "
                f"exceeds the {PACKED_BLOCK_BYTES}-byte slot "
                f"(max {B.BLOCK_CHARS} chars per block)"
            )

        with self._lock:
            conn = self._conn()
            if conn.execute("SELECT 1 FROM blocks WHERE hash=?", (h,)).fetchone():
                self._bump("duplicates_rejected")
                return False

            row = conn.execute("SELECT MAX(shard) AS s FROM blocks").fetchone()
            shard = row["s"] if row["s"] is not None else 1
            used = conn.execute("SELECT COUNT(*) AS n FROM blocks WHERE shard=?",
                                (shard,)).fetchone()["n"]
            if used >= SHARD_MAX_BLOCKS:
                shard += 1
                used = 0

            path = self._shard_path(shard)
            # Fixed-width slots keep reads O(1) via seek, and make a torn write
            # recoverable: a short final record is simply an unused slot.
            with path.open("ab") as f:
                f.seek(used * PACKED_BLOCK_BYTES)
                f.write(packed.ljust(PACKED_BLOCK_BYTES, b"\x00"))

            with conn:
                conn.execute(
                    "INSERT INTO blocks (hash, shard, slot, n_chars, fetched_at) "
                    "VALUES (?,?,?,?,?)", (h, shard, used, len(text), time.time()))
            self._bump("blocks_written")
            return True

    # --- reading ----------------------------------------------------------
    def reserve(self, limit: int = 1) -> list[str]:
        """Take up to `limit` never-before-consumed blocks and mark them consumed."""
        with self._lock:
            conn = self._conn()
            rows = conn.execute(
                "SELECT hash, shard, slot, n_chars FROM blocks "
                "WHERE consumed_at IS NULL ORDER BY fetched_at LIMIT ?", (limit,)
            ).fetchall()
            if not rows:
                return []

            out = []
            for r in rows:
                path = self._shard_path(r["shard"])
                try:
                    with path.open("rb") as f:
                        f.seek(r["slot"] * PACKED_BLOCK_BYTES)
                        data = f.read(PACKED_BLOCK_BYTES)
                    out.append(B.unpack(data, r["n_chars"]))
                except (OSError, B.InvalidBlock):
                    # A shard that has gone missing or corrupt must not stall the
                    # reader; drop the index entry and carry on.
                    continue
            with conn:
                conn.executemany("UPDATE blocks SET consumed_at=? WHERE hash=?",
                                 [(time.time(), r["hash"]) for r in rows])
            return out

    def unconsumed_count(self) -> int:
        return self._conn().execute(
            "SELECT COUNT(*) AS n FROM blocks WHERE consumed_at IS NULL").fetchone()["n"]

    def iter_all_chars(self, limit_blocks: int | None = None):
        """Yield archived block text regardless of consumption state.

        For offline statistical analysis only -- the randomness test suite needs to
        read the archive without marking it consumed.
        """
        # Ordered by shard so each file is opened once and read with sequential seeks.
        # Re-opening per block costs one syscall pair per row, which dominates on an
        # archive of tens of thousands of blocks.
        q = "SELECT shard, slot, n_chars FROM blocks ORDER BY shard, slot"
        if limit_blocks:
            q += f" LIMIT {int(limit_blocks)}"

        handle = None
        current = None
        try:
            for r in self._conn().execute(q):
                if r["shard"] != current:
                    if handle is not None:
                        handle.close()
                    path = self._shard_path(r["shard"])
                    handle = path.open("rb") if path.exists() else None
                    current = r["shard"]
                if handle is None:
                    continue
                handle.seek(r["slot"] * PACKED_BLOCK_BYTES)
                data = handle.read(PACKED_BLOCK_BYTES)
                try:
                    yield B.unpack(data, r["n_chars"])
                except B.InvalidBlock:
                    continue
        finally:
            if handle is not None:
                handle.close()

    def stats(self) -> StoreStats:
        c = self._conn()
        agg = c.execute(
            "SELECT COUNT(*) n, SUM(n_chars) chars, MIN(fetched_at) lo, MAX(fetched_at) hi,"
            " COUNT(DISTINCT shard) shards FROM blocks").fetchone()
        unconsumed = c.execute(
            "SELECT COALESCE(SUM(n_chars),0) AS chars FROM blocks WHERE consumed_at IS NULL"
        ).fetchone()["chars"]
        return StoreStats(
            total_blocks=agg["n"] or 0,
            unconsumed_blocks=self.unconsumed_count(),
            duplicates_rejected=int(self.counter("duplicates_rejected")),
            invalid_rejected=int(self.counter("invalid_rejected")),
            entropy_bits_available=B.entropy_bits(unconsumed or 0),
            bytes_on_disk=sum(p.stat().st_size for p in self.root.glob("anu-*.bin")),
            shards=agg["shards"] or 0,
            oldest=agg["lo"], newest=agg["hi"],
        )

    def import_legacy_text(self, path: Path, block_chars: int = B.BLOCK_CHARS) -> tuple[int, int]:
        """Import a flat ASCII archive from the original scraper. Returns (added, skipped)."""
        if not path.exists():
            return (0, 0)
        text = path.read_text(encoding="ascii", errors="ignore").strip()
        added = skipped = 0
        for i in range(0, len(text) - block_chars + 1, block_chars):
            chunk = text[i:i + block_chars]
            try:
                B.validate(chunk)
            except B.InvalidBlock:
                skipped += 1
                self.note_invalid()
                continue
            if self.add_block(chunk):
                added += 1
            else:
                skipped += 1
        return added, skipped
