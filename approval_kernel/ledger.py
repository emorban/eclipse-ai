"""Append-only, tamper-evident decision ledger.

Every decision (approve, reject, expire, revoke) is a ledger entry bound to the
exact candidate version and digest it concerns. Entries form a keyed hash chain:

    entry_hash[n] = HMAC-SHA256(ledger_key, prev_hash[n] || canonical(fields[n]))
    prev_hash[n]  = entry_hash[n-1]      (prev_hash[1] = GENESIS)

The fields include ``seq``, so the chain detects:

* **edits** -- a changed field no longer matches its entry_hash
* **deletions** -- a gap in ``seq`` and a broken ``prev_hash`` link
* **reordering** -- entries moved to a different ``seq`` fail their MAC
* **forged rewrites** -- recomputing the chain requires the ledger key

Truncating the *tail* leaves a shorter but internally valid chain; no chain can
detect that on its own. :class:`LedgerAnchor` covers it: persist the head
anchor somewhere the database writer cannot reach, then pass it to
:meth:`DecisionLedger.verify`.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
from dataclasses import dataclass, field
from enum import StrEnum

from .canonical import canonical_json
from .clock import Clock
from .errors import LedgerIntegrityError

GENESIS = "0" * 64


class Decision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    EXPIRE = "expire"
    REVOKE = "revoke"


# Which decisions are legal given the most recent decision on a candidate version.
# ``None`` means "no decision yet" (pending).
ALLOWED_TRANSITIONS: dict[Decision | None, frozenset[Decision]] = {
    None: frozenset({Decision.APPROVE, Decision.REJECT, Decision.EXPIRE}),
    Decision.APPROVE: frozenset({Decision.REVOKE}),
    Decision.REJECT: frozenset(),
    Decision.EXPIRE: frozenset(),
    Decision.REVOKE: frozenset(),
}


@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    kind: Decision
    candidate_id: str
    version: int
    digest: str
    actor: str
    reason: str
    at: int
    prev_hash: str
    entry_hash: str


@dataclass(frozen=True)
class LedgerAnchor:
    """A (seq, entry_hash) pair recorded outside the database."""

    seq: int
    entry_hash: str


@dataclass(frozen=True)
class ChainReport:
    ok: bool
    length: int
    head: LedgerAnchor | None
    problems: tuple[str, ...] = field(default_factory=tuple)

    def raise_for_problems(self) -> None:
        if not self.ok:
            raise LedgerIntegrityError(list(self.problems))


def _entry_fields(
    seq: int,
    kind: str,
    candidate_id: str,
    version: int,
    digest: str,
    actor: str,
    reason: str,
    at: int,
) -> dict[str, object]:
    return {
        "seq": seq,
        "kind": kind,
        "candidate_id": candidate_id,
        "version": version,
        "digest": digest,
        "actor": actor,
        "reason": reason,
        "at": at,
    }


def compute_entry_hash(key: bytes, prev_hash: str, fields: dict[str, object]) -> str:
    message = prev_hash.encode("ascii") + b"\x00" + canonical_json(fields)
    return hmac.new(key, message, hashlib.sha256).hexdigest()


class DecisionLedger:
    def __init__(self, key: bytes, clock: Clock) -> None:
        if len(key) < 32:
            raise ValueError("ledger key must be at least 32 bytes")
        self._key = key
        self._clock = clock

    def append(
        self,
        conn: sqlite3.Connection,
        *,
        kind: Decision,
        candidate_id: str,
        version: int,
        digest: str,
        actor: str,
        reason: str = "",
    ) -> LedgerEntry:
        """Append one entry. Must run inside a write transaction."""
        last = conn.execute("SELECT seq, entry_hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        seq = 1 if last is None else int(last["seq"]) + 1
        prev_hash = GENESIS if last is None else str(last["entry_hash"])
        at = self._clock.now()
        fields = _entry_fields(seq, kind.value, candidate_id, version, digest, actor, reason, at)
        entry_hash = compute_entry_hash(self._key, prev_hash, fields)
        conn.execute(
            "INSERT INTO ledger (seq, kind, candidate_id, version, digest, actor, reason, at,"
            " prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (seq, kind.value, candidate_id, version, digest, actor, reason, at, prev_hash, entry_hash),
        )
        return LedgerEntry(seq, kind, candidate_id, version, digest, actor, reason, at, prev_hash, entry_hash)

    def latest_decision(
        self, conn: sqlite3.Connection, candidate_id: str, version: int
    ) -> LedgerEntry | None:
        row = conn.execute(
            "SELECT * FROM ledger WHERE candidate_id = ? AND version = ? ORDER BY seq DESC LIMIT 1",
            (candidate_id, version),
        ).fetchone()
        return None if row is None else _from_row(row)

    def entries(self, conn: sqlite3.Connection) -> list[LedgerEntry]:
        return [_from_row(row) for row in conn.execute("SELECT * FROM ledger ORDER BY seq")]

    def verify(self, conn: sqlite3.Connection, anchor: LedgerAnchor | None = None) -> ChainReport:
        """Walk the full chain and report every inconsistency found.

        Problems are localized: after an edited row is flagged, verification
        continues from that row's stored hash so a single edit produces a
        single finding instead of a cascade.
        """
        problems: list[str] = []
        expected_seq = 1
        prev_hash = GENESIS
        seen: dict[int, str] = {}
        rows = conn.execute("SELECT * FROM ledger ORDER BY seq").fetchall()
        for row in rows:
            seq = int(row["seq"])
            if seq != expected_seq:
                problems.append(f"sequence gap: expected seq {expected_seq}, found {seq}")
            if row["prev_hash"] != prev_hash:
                problems.append(f"seq {seq}: prev_hash does not link to the preceding entry")
            fields = _entry_fields(
                seq,
                row["kind"],
                row["candidate_id"],
                int(row["version"]),
                row["digest"],
                row["actor"],
                row["reason"],
                int(row["at"]),
            )
            recomputed = compute_entry_hash(self._key, row["prev_hash"], fields)
            if not hmac.compare_digest(recomputed, str(row["entry_hash"])):
                problems.append(f"seq {seq}: entry contents do not match entry_hash")
            if row["kind"] not in Decision._value2member_map_:
                problems.append(f"seq {seq}: unknown decision kind {row['kind']!r}")
            seen[seq] = str(row["entry_hash"])
            prev_hash = str(row["entry_hash"])
            expected_seq = seq + 1

        if anchor is not None:
            stored = seen.get(anchor.seq)
            if stored is None:
                problems.append(f"anchor seq {anchor.seq} missing: ledger truncated")
            elif not hmac.compare_digest(stored, anchor.entry_hash):
                problems.append(f"anchor seq {anchor.seq} hash differs: history rewritten")

        head = None
        if rows:
            last = rows[-1]
            head = LedgerAnchor(int(last["seq"]), str(last["entry_hash"]))
        return ChainReport(ok=not problems, length=len(rows), head=head, problems=tuple(problems))


def _from_row(row: sqlite3.Row) -> LedgerEntry:
    return LedgerEntry(
        seq=int(row["seq"]),
        kind=Decision(row["kind"]),
        candidate_id=row["candidate_id"],
        version=int(row["version"]),
        digest=row["digest"],
        actor=row["actor"],
        reason=row["reason"],
        at=int(row["at"]),
        prev_hash=row["prev_hash"],
        entry_hash=row["entry_hash"],
    )
