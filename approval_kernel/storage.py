"""SQLite storage, schema, and transaction handling.

The schema enforces the kernel's invariants twice: once in Python, and again in
the database with triggers and CHECK constraints, so a bug in the application
layer cannot silently mutate history.

* ``candidates`` and ``ledger`` reject UPDATE and DELETE outright.
* ``ledger`` rejects inserts whose ``seq`` is not exactly ``max(seq) + 1``.
* ``authorities`` cannot record more attempts or spend than its limits.

Triggers are a guard rail, not a security boundary: anyone with raw write access
to the file can drop them. Tampering by such an actor is what the keyed hash
chain in :mod:`approval_kernel.ledger` exists to detect.

Concurrency model: an in-memory database uses one shared connection serialized
by a lock. A file database gives each thread its own connection and relies on
SQLite's ``BEGIN IMMEDIATE`` write lock plus conditional updates, so it is also
correct across processes sharing the same file.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS candidates (
    candidate_id    TEXT    NOT NULL,
    version         INTEGER NOT NULL CHECK (version >= 1),
    action_type     TEXT    NOT NULL,
    target          TEXT    NOT NULL,
    risk            TEXT    NOT NULL,
    payload_json    TEXT    NOT NULL,
    payload_hash    TEXT    NOT NULL,
    limits_json     TEXT    NOT NULL,
    proposed_by     TEXT    NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL CHECK (expires_at > created_at),
    parent_digest   TEXT,
    digest          TEXT    NOT NULL UNIQUE,
    PRIMARY KEY (candidate_id, version)
);
CREATE TRIGGER IF NOT EXISTS candidates_no_update BEFORE UPDATE ON candidates
BEGIN SELECT RAISE(ABORT, 'candidates are immutable; propose a revision'); END;
CREATE TRIGGER IF NOT EXISTS candidates_no_delete BEFORE DELETE ON candidates
BEGIN SELECT RAISE(ABORT, 'candidates are immutable'); END;

CREATE TABLE IF NOT EXISTS ledger (
    seq           INTEGER PRIMARY KEY,
    kind          TEXT    NOT NULL,
    candidate_id  TEXT    NOT NULL,
    version       INTEGER NOT NULL,
    digest        TEXT    NOT NULL,
    actor         TEXT    NOT NULL,
    reason        TEXT    NOT NULL,
    at            INTEGER NOT NULL,
    prev_hash     TEXT    NOT NULL,
    entry_hash    TEXT    NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS ledger_by_candidate ON ledger (candidate_id, version, seq);
CREATE TRIGGER IF NOT EXISTS ledger_no_update BEFORE UPDATE ON ledger
BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_no_delete BEFORE DELETE ON ledger
BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_contiguous BEFORE INSERT ON ledger
WHEN NEW.seq IS NOT (SELECT COALESCE(MAX(seq), 0) + 1 FROM ledger)
BEGIN SELECT RAISE(ABORT, 'ledger seq must be contiguous'); END;

CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT    PRIMARY KEY,
    owner_id    TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    closed_at   INTEGER
);

CREATE TABLE IF NOT EXISTS nonces (
    nonce         TEXT    PRIMARY KEY,
    session_id    TEXT    NOT NULL REFERENCES sessions (session_id),
    candidate_id  TEXT    NOT NULL,
    version       INTEGER NOT NULL,
    digest        TEXT    NOT NULL,
    issued_at     INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    used_at       INTEGER
);

CREATE TABLE IF NOT EXISTS authorities (
    token_id         TEXT    PRIMARY KEY,
    candidate_id     TEXT    NOT NULL,
    version          INTEGER NOT NULL,
    digest           TEXT    NOT NULL,
    ledger_seq       INTEGER NOT NULL REFERENCES ledger (seq),
    issued_at        INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    max_attempts     INTEGER NOT NULL CHECK (max_attempts >= 1),
    max_spend_cents  INTEGER NOT NULL CHECK (max_spend_cents >= 0),
    attempts         INTEGER NOT NULL DEFAULT 0,
    spent_cents      INTEGER NOT NULL DEFAULT 0,
    CHECK (attempts BETWEEN 0 AND max_attempts),
    CHECK (spent_cents BETWEEN 0 AND max_spend_cents)
);
"""


class Database:
    """Owns SQLite connections and hands out serialized write transactions."""

    def __init__(self, path: str | Path = ":memory:", *, timeout: float = 30.0) -> None:
        self._path = str(path)
        self._memory = self._path == ":memory:"
        self._timeout = timeout
        self._lock = threading.RLock()
        self._local = threading.local()
        self._all: list[sqlite3.Connection] = []
        self._shared: sqlite3.Connection | None = self._open() if self._memory else None
        with self._lock:
            self.connection().executescript(SCHEMA)

    @property
    def path(self) -> str:
        return self._path

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._path,
            timeout=self._timeout,
            isolation_level=None,  # we issue BEGIN/COMMIT explicitly
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if not self._memory:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = FULL")
        with self._lock:
            self._all.append(conn)
        return conn

    def connection(self) -> sqlite3.Connection:
        if self._shared is not None:
            return self._shared
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._open()
            self._local.conn = conn
        return conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a block inside ``BEGIN IMMEDIATE`` (one writer at a time)."""
        lock = self._lock if self._memory else _NULL_LOCK
        with lock:
            conn = self.connection()
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    @contextmanager
    def reader(self) -> Iterator[sqlite3.Connection]:
        """Run read-only queries against a consistent snapshot."""
        lock = self._lock if self._memory else _NULL_LOCK
        with lock:
            conn = self.connection()
            conn.execute("BEGIN")
            try:
                yield conn
            finally:
                conn.execute("ROLLBACK")

    def close(self) -> None:
        with self._lock:
            for conn in self._all:
                conn.close()
            self._all.clear()
            self._shared = None
            self._local = threading.local()


class _NullLock:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc: object) -> None:
        return None


_NULL_LOCK = _NullLock()
