"""SQLite persistence: the only module that touches the database.

- Writes are serialized (process lock + BEGIN IMMEDIATE), so the chain head can't fork even with
  several writer processes.
- Reads use a fresh connection. In WAL mode they never block writers, and a single SELECT sees
  a consistent snapshot, which lets verify/export stream the whole chain in O(1) memory.
- DB triggers block DELETE and changes to chain columns. This is a guardrail against application
  bugs, not a security boundary: the hash chain is what detects tampering by a DB admin.
"""

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime, timedelta

from app.chain import ARCHIVE_EVENT, GENESIS_HASH, REDACTED, REDACTION_EVENT, build_record

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA secure_delete = ON;  -- redacted bytes are zeroed, not left in free pages
CREATE TABLE IF NOT EXISTS events (
    seq           INTEGER PRIMARY KEY,
    timestamp     TEXT    NOT NULL,
    event_type    TEXT,
    actor_id      TEXT,
    resource_type TEXT,
    resource_id   TEXT,
    payload       TEXT,             -- JSON object; redacted fields hold "[REDACTED]"
    salts         TEXT,             -- JSON {field: salt}; a missing salt = redacted field
    field_hashes  TEXT,             -- JSON {field: commitment}
    prev_hash     TEXT    NOT NULL,
    hash          TEXT    NOT NULL,
    archived      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_actor    ON events(actor_id, seq);
CREATE INDEX IF NOT EXISTS ix_resource ON events(resource_type, resource_id, seq);
CREATE INDEX IF NOT EXISTS ix_type     ON events(event_type, seq);
CREATE INDEX IF NOT EXISTS ix_time     ON events(timestamp);
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
    BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_chain_immutable
    BEFORE UPDATE OF seq, timestamp, prev_hash, hash ON events
    BEGIN SELECT RAISE(ABORT, 'chain columns are immutable'); END;
"""

COLUMNS = ("seq", "timestamp", "event_type", "actor_id", "resource_type", "resource_id",
           "payload", "salts", "field_hashes", "prev_hash", "hash", "archived")
KEYS = ("seq", "timestamp", "eventType", "actorId", "resourceType", "resourceId",
        "payload", "salts", "fieldHashes", "prevHash", "hash", "archived")
JSON_KEYS = {"payload", "salts", "fieldHashes"}
FILTERS = {"actorId": "actor_id", "resourceType": "resource_type",  # API name -> column
           "resourceId": "resource_id", "eventType": "event_type"}
SELECT = f"SELECT {', '.join(COLUMNS)} FROM events"  # noqa: S608 - constant columns


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


def iso(dt: datetime) -> str:
    """Fixed-width UTC ISO-8601, so lexical order == time order in SQL."""
    dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def to_record(row: tuple) -> dict:
    r = dict(zip(KEYS, row, strict=True))
    for k in JSON_KEYS:
        r[k] = json.loads(r[k]) if r[k] is not None else None
    r["archived"] = bool(r["archived"])
    return r


def to_row(r: dict) -> tuple:
    return tuple(json.dumps(r[k]) if k in JSON_KEYS else r[k] for k in KEYS)


class AuditStore:
    def __init__(self, path: str):
        self.path = path
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self._db.executescript(SCHEMA)
        self._lock = threading.Lock()

    # ---- writes -------------------------------------------------------------------------
    def _write(self, fn):
        """Run fn inside one serialized, atomic write transaction."""
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                result = fn()
                self._db.execute("COMMIT")
                return result
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def _append(self, event: dict) -> dict:
        head = self._db.execute(
            "SELECT seq, hash, timestamp FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        seq, prev, last_ts = head or (0, GENESIS_HASH, "")
        ts = max(iso(datetime.now(UTC)), last_ts)  # monotonic even if the wall clock steps back
        record = build_record(seq + 1, prev, ts, event)
        self._db.execute(f"INSERT INTO events ({', '.join(COLUMNS)}) VALUES "  # noqa: S608 - fixed columns
                         f"({', '.join('?' * len(COLUMNS))})", to_row(record))
        return record

    def append(self, event: dict) -> dict:
        return self._write(lambda: self._append(event))

    def redact(self, seq: int, fields: list[str], reason: str, requested_by: str) -> dict:
        """Remove payload values but keep their commitments, so the chain still verifies.

        The redaction is recorded as a chained RECORD_REDACTED event (who/why/what). verify()
        treats any redacted field without such an event as tampering.
        """
        def op():
            row = self._db.execute(f"{SELECT} WHERE seq = ?", (seq,)).fetchone()
            if row is None:
                raise NotFound(f"record {seq} not found")
            r = to_record(row)
            if r["archived"] or r["eventType"] in (REDACTION_EVENT, ARCHIVE_EVENT):
                raise Conflict("archived records and system events cannot be redacted")
            if unknown := set(fields) - r["payload"].keys():
                raise Conflict(f"unknown payload fields: {sorted(unknown)}")
            targets = sorted(f for f in set(fields) if f in r["salts"])
            if not targets:
                raise Conflict("fields are already redacted")
            payload = r["payload"] | dict.fromkeys(targets, REDACTED)
            salts = {k: v for k, v in r["salts"].items() if k not in targets}
            self._db.execute("UPDATE events SET payload = ?, salts = ? WHERE seq = ?",
                             (json.dumps(payload), json.dumps(salts), seq))
            return self._append({
                "eventType": REDACTION_EVENT, "actorId": requested_by,
                "resourceType": "AUDIT_EVENT", "resourceId": str(seq),
                "payload": {"targetSeq": seq, "fields": targets, "reason": reason}})
        audit_event = self._write(op)
        with self._lock:  # flush WAL so the old value is not left in the -wal file
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return audit_event

    def archive(self, older_than_days: float, requested_by: str) -> dict:
        """Retention: turn records older than the window into tombstones.

        A tombstone keeps seq/timestamp/prevHash/hash, so chain links still verify. Content is
        purged. Timestamps are monotonic, so "older than cutoff" is always a contiguous prefix.
        The run is authorized by a chained RECORDS_ARCHIVED event; verify flags tombstones
        beyond its throughSeq.
        """
        cutoff = iso(datetime.now(UTC) - timedelta(days=older_than_days))

        def op():
            through, count = self._db.execute(
                "SELECT MAX(seq), SUM(archived = 0) FROM events WHERE timestamp < ?",
                (cutoff,)).fetchone()
            if not count:
                return {"archivedCount": 0, "throughSeq": through, "event": None}
            self._db.execute(
                "UPDATE events SET archived = 1, event_type = NULL, actor_id = NULL, "
                "resource_type = NULL, resource_id = NULL, payload = NULL, salts = NULL, "
                "field_hashes = NULL WHERE seq <= ? AND archived = 0", (through,))
            event = self._append({
                "eventType": ARCHIVE_EVENT, "actorId": requested_by,
                "resourceType": "AUDIT_LOG", "resourceId": "retention",
                "payload": {"throughSeq": through, "cutoff": cutoff, "count": count,
                            "olderThanDays": older_than_days}})
            return {"archivedCount": count, "throughSeq": through, "event": event}
        return self._write(op)

    # ---- reads --------------------------------------------------------------------------
    def _read(self, sql: str, params=()) -> Iterator[dict]:
        with closing(sqlite3.connect(self.path)) as conn:
            for row in conn.execute(sql, params):
                yield to_record(row)

    def get(self, seq: int) -> dict | None:
        return next(self._read(f"{SELECT} WHERE seq = ?", (seq,)), None)

    def query(self, filters: dict, start: datetime | None, end: datetime | None,
              limit: int, cursor: int = 0) -> tuple[list[dict], int | None]:
        """Keyset pagination on seq. `start` is inclusive and `end` is exclusive."""
        where, params = ["archived = 0", "seq > ?"], [cursor]
        for key, column in FILTERS.items():
            if filters.get(key) is not None:
                where.append(f"{column} = ?")
                params.append(filters[key])
        if start:
            where.append("timestamp >= ?")
            params.append(iso(start))
        if end:
            where.append("timestamp < ?")
            params.append(iso(end))
        sql = f"{SELECT} WHERE {' AND '.join(where)} ORDER BY seq LIMIT ?"  # noqa: S608 - whitelisted columns
        rows = list(self._read(sql, (*params, limit + 1)))
        page = rows[:limit]
        return page, (page[-1]["seq"] if len(rows) > limit else None)

    def iter_chain(self, from_seq: int = 1) -> Iterator[dict]:
        return self._read(f"{SELECT} WHERE seq >= ? ORDER BY seq", (from_seq,))
