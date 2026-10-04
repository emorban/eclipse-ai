"""Owner sessions, decision challenges, and single-use nonces.

How the owner authenticates (passkey, local UI, signed chat message) is outside
this package. What the kernel guarantees once a session exists:

* A session belongs to one permitted owner and expires.
* Each decision requires a **challenge** issued to that session for one exact
  ``(candidate_id, version, digest)``. The owner decides on what they were
  shown, not on whatever the candidate has become since.
* The challenge nonce is single-use and short-lived (replay protection).
* The owner returns a **proof**: an HMAC over the challenge and the decision,
  keyed with the session secret. A process that can call the kernel but does
  not hold the session secret -- such as the proposing agent -- cannot produce
  an approval.

Session secrets are derived (``HMAC(session_key, session_id)``) rather than
stored, so a copy of the database alone does not yield a usable secret.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from dataclasses import dataclass, field

from .canonical import canonical_json
from .clock import Clock
from .errors import (
    NonceExpiredError,
    NonceInvalidError,
    NonceReplayError,
    ProofInvalidError,
    SessionExpiredError,
    SessionNotFoundError,
)
from .ledger import Decision


@dataclass(frozen=True)
class OwnerSession:
    session_id: str
    owner_id: str
    created_at: int
    expires_at: int
    secret: bytes = field(repr=False)


@dataclass(frozen=True)
class Challenge:
    nonce: str
    session_id: str
    candidate_id: str
    version: int
    digest: str
    expires_at: int


@dataclass(frozen=True)
class RedeemedChallenge:
    owner_id: str
    session_id: str
    candidate_id: str
    version: int
    digest: str


def challenge_message(challenge: Challenge, decision: Decision) -> bytes:
    return canonical_json(
        {
            "kind": "approval-kernel/decision/v1",
            "decision": decision.value,
            "nonce": challenge.nonce,
            "session_id": challenge.session_id,
            "candidate_id": challenge.candidate_id,
            "version": challenge.version,
            "digest": challenge.digest,
        }
    )


def sign_challenge(secret: bytes, challenge: Challenge, decision: Decision) -> str:
    """Owner-side helper: produce the proof for ``decision`` on ``challenge``."""
    return hmac.new(secret, challenge_message(challenge, decision), hashlib.sha256).hexdigest()


class SessionManager:
    def __init__(
        self,
        session_key: bytes,
        clock: Clock,
        owners: frozenset[str],
        *,
        session_ttl: int = 900,
        nonce_ttl: int = 120,
    ) -> None:
        if len(session_key) < 32:
            raise ValueError("session key must be at least 32 bytes")
        if not owners:
            raise ValueError("at least one owner must be configured")
        self._key = session_key
        self._clock = clock
        self._owners = frozenset(owners)
        self._session_ttl = session_ttl
        self._nonce_ttl = nonce_ttl

    @property
    def owners(self) -> frozenset[str]:
        return self._owners

    def _secret_for(self, session_id: str) -> bytes:
        return hmac.new(self._key, b"session:" + session_id.encode(), hashlib.sha256).digest()

    def open(self, conn: sqlite3.Connection, owner_id: str, ttl: int | None = None) -> OwnerSession:
        if owner_id not in self._owners:
            raise SessionNotFoundError(f"{owner_id!r} is not a permitted owner")
        ttl = self._session_ttl if ttl is None else ttl
        if ttl <= 0:
            raise ValueError("session ttl must be positive")
        now = self._clock.now()
        session_id = "sess_" + secrets.token_urlsafe(18)
        conn.execute(
            "INSERT INTO sessions (session_id, owner_id, created_at, expires_at) VALUES (?,?,?,?)",
            (session_id, owner_id, now, now + ttl),
        )
        return OwnerSession(session_id, owner_id, now, now + ttl, self._secret_for(session_id))

    def close(self, conn: sqlite3.Connection, session_id: str) -> None:
        conn.execute(
            "UPDATE sessions SET closed_at = ? WHERE session_id = ? AND closed_at IS NULL",
            (self._clock.now(), session_id),
        )

    def require_active(self, conn: sqlite3.Connection, session_id: str) -> sqlite3.Row:
        row: sqlite3.Row | None = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is None:
            raise SessionNotFoundError("unknown session")
        if row["owner_id"] not in self._owners:
            raise SessionNotFoundError("session owner is no longer permitted")
        if row["closed_at"] is not None:
            raise SessionExpiredError("session was closed")
        if self._clock.now() >= int(row["expires_at"]):
            raise SessionExpiredError("session has expired")
        return row

    def issue_challenge(
        self,
        conn: sqlite3.Connection,
        session_id: str,
        *,
        candidate_id: str,
        version: int,
        digest: str,
    ) -> Challenge:
        session = self.require_active(conn, session_id)
        now = self._clock.now()
        expires_at = min(now + self._nonce_ttl, int(session["expires_at"]))
        nonce = secrets.token_urlsafe(24)
        conn.execute(
            "INSERT INTO nonces (nonce, session_id, candidate_id, version, digest, issued_at,"
            " expires_at) VALUES (?,?,?,?,?,?,?)",
            (nonce, session_id, candidate_id, version, digest, now, expires_at),
        )
        return Challenge(nonce, session_id, candidate_id, version, digest, expires_at)

    def redeem(
        self,
        conn: sqlite3.Connection,
        session_id: str,
        nonce: str,
        proof: str,
        decision: Decision,
    ) -> RedeemedChallenge:
        """Verify and consume a challenge. Must run inside a write transaction.

        If the surrounding transaction later rolls back (for example because the
        decision itself is refused), the nonce is restored with it.
        """
        session = self.require_active(conn, session_id)
        row = conn.execute("SELECT * FROM nonces WHERE nonce = ?", (nonce,)).fetchone()
        if row is None or not hmac.compare_digest(str(row["session_id"]), session_id):
            raise NonceInvalidError("nonce was not issued to this session")
        if row["used_at"] is not None:
            raise NonceReplayError("nonce has already been used")
        if self._clock.now() >= int(row["expires_at"]):
            raise NonceExpiredError("challenge has expired; request a new one")
        challenge = Challenge(
            nonce=row["nonce"],
            session_id=row["session_id"],
            candidate_id=row["candidate_id"],
            version=int(row["version"]),
            digest=row["digest"],
            expires_at=int(row["expires_at"]),
        )
        expected = sign_challenge(self._secret_for(session_id), challenge, decision)
        if not isinstance(proof, str) or not hmac.compare_digest(expected, proof):
            raise ProofInvalidError("decision proof does not verify")
        claimed = conn.execute(
            "UPDATE nonces SET used_at = ? WHERE nonce = ? AND used_at IS NULL",
            (self._clock.now(), nonce),
        )
        if claimed.rowcount != 1:  # lost a race with another redeemer
            raise NonceReplayError("nonce has already been used")
        return RedeemedChallenge(
            owner_id=session["owner_id"],
            session_id=session_id,
            candidate_id=challenge.candidate_id,
            version=challenge.version,
            digest=challenge.digest,
        )
