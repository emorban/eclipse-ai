"""The approval kernel: one object that owns the whole approval boundary.

Lifecycle::

    agent    propose()/revise()      -> ActionCandidate (immutable, versioned)
    owner    open_session()          -> OwnerSession (holds the proof secret)
    owner    challenge()             -> Challenge for one exact candidate version
    owner    approve()/reject()      -> ledger entry (+ authority token on approve)
    executor authorize()/execute()   -> checks token + live state, counts the attempt

Read-only actions (by the operator's registry, not the agent's say-so) pass
``authorize`` without a token. Everything else needs an authority token that
still matches the latest candidate version, an un-revoked approval in the
ledger, and remaining budget.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

from .authority import (
    ActionRequest,
    AuthorityClaims,
    Authorization,
    Keyring,
    decode_token,
    encode_token,
)
from .candidates import KEEP, ActionCandidate, ActionRegistry, CandidateStore, Limits, RiskClass
from .canonical import content_hash
from .clock import Clock, SystemClock
from .errors import (
    AuthorityExpiredError,
    AuthorityRequiredError,
    AuthorityRevokedError,
    CandidateExpiredError,
    InvalidTransitionError,
    LimitExceededError,
    MalformedTokenError,
    ScopeViolationError,
    SelfApprovalError,
    StaleVersionError,
)
from .ledger import ALLOWED_TRANSITIONS, ChainReport, Decision, DecisionLedger, LedgerAnchor, LedgerEntry
from .sessions import Challenge, OwnerSession, SessionManager
from .storage import Database

T = TypeVar("T")

SYSTEM_ACTOR = "system:clock"


@dataclass(frozen=True)
class KernelKeys:
    """Independent keys for the three things the kernel authenticates."""

    authority: Keyring
    ledger_key: bytes
    session_key: bytes

    @classmethod
    def from_master(cls, master: bytes, *, kid: str = "k1") -> KernelKeys:
        """Derive purpose-separated keys from one master secret (>= 32 bytes)."""
        if len(master) < 32:
            raise ValueError("master secret must be at least 32 bytes")

        def derive(label: str) -> bytes:
            return hmac.new(master, b"approval-kernel/v1/" + label.encode(), hashlib.sha256).digest()

        return cls(
            authority=Keyring({kid: derive("authority:" + kid)}, active=kid),
            ledger_key=derive("ledger"),
            session_key=derive("session"),
        )

    @classmethod
    def generate(cls) -> KernelKeys:
        return cls.from_master(secrets.token_bytes(32))


@dataclass(frozen=True)
class Approval:
    entry: LedgerEntry
    token: str
    claims: AuthorityClaims


@dataclass(frozen=True)
class IntegrityReport:
    ledger: ChainReport
    candidate_problems: tuple[str, ...]
    binding_problems: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.ledger.ok and not self.candidate_problems and not self.binding_problems


class ApprovalKernel:
    def __init__(
        self,
        db: Database,
        keys: KernelKeys,
        *,
        registry: ActionRegistry,
        owners: frozenset[str] | set[str],
        clock: Clock | None = None,
        authority_ttl: int = 300,
        session_ttl: int = 900,
        nonce_ttl: int = 120,
        clock_skew: int = 5,
    ) -> None:
        self._db = db
        self._keys = keys
        self._clock = clock or SystemClock()
        self._registry = registry
        self._candidates = CandidateStore(registry, self._clock)
        self._ledger = DecisionLedger(keys.ledger_key, self._clock)
        self._sessions = SessionManager(
            keys.session_key,
            self._clock,
            frozenset(owners),
            session_ttl=session_ttl,
            nonce_ttl=nonce_ttl,
        )
        if authority_ttl <= 0:
            raise ValueError("authority_ttl must be positive")
        self._authority_ttl = authority_ttl
        self._skew = clock_skew

    # ------------------------------------------------------------------ agent

    def propose(
        self,
        action_type: str,
        target: str,
        payload: Any,
        *,
        proposed_by: str,
        risk: RiskClass | None = None,
        limits: Limits | None = None,
        ttl_seconds: int = 3600,
    ) -> ActionCandidate:
        with self._db.transaction() as conn:
            return self._candidates.create(
                conn,
                action_type=action_type,
                target=target,
                payload=payload,
                risk=risk,
                limits=limits,
                ttl_seconds=ttl_seconds,
                proposed_by=proposed_by,
            )

    def revise(
        self,
        candidate_id: str,
        *,
        proposed_by: str,
        target: str | None = None,
        payload: Any = KEEP,
        risk: RiskClass | None = None,
        limits: Limits | None = None,
        ttl_seconds: int = 3600,
    ) -> ActionCandidate:
        """Create the next version. Authority minted for older versions stops working."""
        with self._db.transaction() as conn:
            return self._candidates.revise(
                conn,
                candidate_id,
                proposed_by=proposed_by,
                target=target,
                payload=payload,
                risk=risk,
                limits=limits,
                ttl_seconds=ttl_seconds,
            )

    def candidate(self, candidate_id: str, version: int | None = None) -> ActionCandidate:
        with self._db.reader() as conn:
            return self._candidates.get(conn, candidate_id, version)

    def history(self, candidate_id: str) -> list[ActionCandidate]:
        with self._db.reader() as conn:
            return self._candidates.history(conn, candidate_id)

    def status(self, candidate_id: str, version: int | None = None) -> str:
        """``pending`` or the most recent decision for that version."""
        with self._db.reader() as conn:
            cand = self._candidates.get(conn, candidate_id, version)
            latest = self._ledger.latest_decision(conn, cand.candidate_id, cand.version)
        return "pending" if latest is None else latest.kind.value

    # ------------------------------------------------------------------ owner

    def open_session(self, owner_id: str, ttl: int | None = None) -> OwnerSession:
        with self._db.transaction() as conn:
            return self._sessions.open(conn, owner_id, ttl)

    def close_session(self, session_id: str) -> None:
        with self._db.transaction() as conn:
            self._sessions.close(conn, session_id)

    def challenge(self, session_id: str, candidate_id: str, version: int | None = None) -> Challenge:
        """Issue a single-use challenge for the *latest* version of a candidate."""
        with self._db.transaction() as conn:
            latest = self._candidates.latest_version(conn, candidate_id)
            if version is not None and version != latest:
                raise StaleVersionError(f"version {version} superseded by version {latest}")
            cand = self._candidates.get(conn, candidate_id, latest)
            if cand.is_expired(self._clock.now()):
                raise CandidateExpiredError("candidate decision window has closed")
            return self._sessions.issue_challenge(
                conn,
                session_id,
                candidate_id=cand.candidate_id,
                version=cand.version,
                digest=cand.digest,
            )

    def approve(self, session_id: str, nonce: str, proof: str, *, reason: str = "") -> Approval:
        with self._db.transaction() as conn:
            entry, cand = self._decide(conn, session_id, nonce, proof, Decision.APPROVE, reason)
            now = self._clock.now()
            expires_at = min(now + self._authority_ttl, cand.expires_at)
            claims = AuthorityClaims(
                token_id="auth_" + secrets.token_urlsafe(18),
                candidate_id=cand.candidate_id,
                version=cand.version,
                digest=cand.digest,
                action_type=cand.action_type,
                target=cand.target,
                payload_hash=cand.payload_hash,
                max_attempts=cand.limits.max_attempts,
                max_spend_cents=cand.limits.max_spend_cents,
                issued_at=now,
                expires_at=expires_at,
                approved_by=entry.actor,
            )
            conn.execute(
                "INSERT INTO authorities (token_id, candidate_id, version, digest, ledger_seq,"
                " issued_at, expires_at, max_attempts, max_spend_cents) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    claims.token_id,
                    claims.candidate_id,
                    claims.version,
                    claims.digest,
                    entry.seq,
                    claims.issued_at,
                    claims.expires_at,
                    claims.max_attempts,
                    claims.max_spend_cents,
                ),
            )
            return Approval(entry, encode_token(claims, self._keys.authority), claims)

    def reject(self, session_id: str, nonce: str, proof: str, *, reason: str = "") -> LedgerEntry:
        with self._db.transaction() as conn:
            return self._decide(conn, session_id, nonce, proof, Decision.REJECT, reason)[0]

    def revoke(self, session_id: str, nonce: str, proof: str, *, reason: str = "") -> LedgerEntry:
        with self._db.transaction() as conn:
            return self._decide(conn, session_id, nonce, proof, Decision.REVOKE, reason)[0]

    def _decide(
        self,
        conn: sqlite3.Connection,
        session_id: str,
        nonce: str,
        proof: str,
        decision: Decision,
        reason: str,
    ) -> tuple[LedgerEntry, ActionCandidate]:
        redeemed = self._sessions.redeem(conn, session_id, nonce, proof, decision)
        cand = self._candidates.get(conn, redeemed.candidate_id, redeemed.version)
        if cand.digest != redeemed.digest:
            raise StaleVersionError("candidate changed after the challenge was issued")
        latest = self._candidates.latest_version(conn, cand.candidate_id)
        if latest != cand.version and decision is not Decision.REVOKE:
            raise StaleVersionError(f"version {cand.version} superseded by version {latest}")
        if redeemed.owner_id == cand.proposed_by:
            raise SelfApprovalError("the proposer of an action cannot decide on it")
        if decision is Decision.APPROVE and cand.is_expired(self._clock.now()):
            raise CandidateExpiredError("candidate decision window has closed")
        self._check_transition(conn, cand, decision)
        entry = self._ledger.append(
            conn,
            kind=decision,
            candidate_id=cand.candidate_id,
            version=cand.version,
            digest=cand.digest,
            actor=redeemed.owner_id,
            reason=reason,
        )
        return entry, cand

    def _check_transition(self, conn: sqlite3.Connection, cand: ActionCandidate, decision: Decision) -> None:
        latest = self._ledger.latest_decision(conn, cand.candidate_id, cand.version)
        current = None if latest is None else latest.kind
        if decision not in ALLOWED_TRANSITIONS[current]:
            state = "pending" if current is None else current.value
            raise InvalidTransitionError(f"cannot {decision.value} a candidate that is {state}")

    def expire_stale(self) -> list[LedgerEntry]:
        """Record an ``expire`` decision for every pending latest version past its window."""
        now = self._clock.now()
        written: list[LedgerEntry] = []
        with self._db.transaction() as conn:
            rows = conn.execute(
                "SELECT c.candidate_id, c.version FROM candidates c"
                " WHERE c.expires_at <= ?"
                " AND c.version = (SELECT MAX(version) FROM candidates WHERE candidate_id = c.candidate_id)"
                " AND NOT EXISTS (SELECT 1 FROM ledger l WHERE l.candidate_id = c.candidate_id"
                "                 AND l.version = c.version)"
                " ORDER BY c.created_at, c.candidate_id",
                (now,),
            ).fetchall()
            for row in rows:
                cand = self._candidates.get(conn, row["candidate_id"], int(row["version"]))
                written.append(
                    self._ledger.append(
                        conn,
                        kind=Decision.EXPIRE,
                        candidate_id=cand.candidate_id,
                        version=cand.version,
                        digest=cand.digest,
                        actor=SYSTEM_ACTOR,
                        reason="decision window elapsed",
                    )
                )
        return written

    # --------------------------------------------------------------- executor

    def authorize(self, request: ActionRequest, token: str | None = None) -> Authorization:
        """Admit one execution attempt, or raise. Gated attempts are counted atomically."""
        risk = self._registry.classify(request.action_type)
        if not risk.requires_approval:
            return Authorization(request=request, read_only=True)
        if token is None:
            raise AuthorityRequiredError(f"{request.action_type} is {risk.value}; authority required")

        claims = decode_token(token, self._keys.authority)
        now = self._clock.now()
        if claims.issued_at > now + self._skew:
            raise MalformedTokenError("token issued in the future")
        if now >= claims.expires_at:
            raise AuthorityExpiredError("authority token has expired")
        self._check_scope(claims, request)

        with self._db.transaction() as conn:
            latest = self._candidates.latest_version(conn, claims.candidate_id)
            if latest != claims.version:
                raise StaleVersionError(
                    f"authority is for version {claims.version}; candidate is now version {latest}"
                )
            cand = self._candidates.get(conn, claims.candidate_id, claims.version)
            if cand.digest != claims.digest or cand.payload_hash != claims.payload_hash:
                raise ScopeViolationError("stored candidate no longer matches the authority")
            decision = self._ledger.latest_decision(conn, cand.candidate_id, cand.version)
            if decision is None or decision.kind is not Decision.APPROVE:
                state = "pending" if decision is None else decision.kind.value
                raise AuthorityRevokedError(f"approval is not in force (state: {state})")
            if decision.digest != claims.digest:
                raise AuthorityRevokedError("ledger approval is bound to a different digest")
            row = conn.execute("SELECT * FROM authorities WHERE token_id = ?", (claims.token_id,)).fetchone()
            if row is None or row["digest"] != claims.digest:
                raise AuthorityRevokedError("authority was never issued by this kernel")
            used = conn.execute(
                "UPDATE authorities SET attempts = attempts + 1, spent_cents = spent_cents + ?"
                " WHERE token_id = ? AND attempts < max_attempts"
                " AND spent_cents + ? <= max_spend_cents",
                (request.spend_cents, claims.token_id, request.spend_cents),
            )
            if used.rowcount != 1:
                if int(row["attempts"]) >= int(row["max_attempts"]):
                    raise LimitExceededError("attempt limit reached")
                raise LimitExceededError("spend limit would be exceeded")
            after = conn.execute(
                "SELECT attempts, max_attempts, spent_cents, max_spend_cents FROM authorities"
                " WHERE token_id = ?",
                (claims.token_id,),
            ).fetchone()
        return Authorization(
            request=request,
            read_only=False,
            token_id=claims.token_id,
            candidate_id=claims.candidate_id,
            version=claims.version,
            attempt=int(after["attempts"]),
            attempts_remaining=int(after["max_attempts"]) - int(after["attempts"]),
            spend_remaining_cents=int(after["max_spend_cents"]) - int(after["spent_cents"]),
        )

    @staticmethod
    def _check_scope(claims: AuthorityClaims, request: ActionRequest) -> None:
        if request.action_type != claims.action_type:
            raise ScopeViolationError(f"authority covers {claims.action_type!r}, not {request.action_type!r}")
        if request.target != claims.target:
            raise ScopeViolationError("request target is outside the approved scope")
        if content_hash(request.payload) != claims.payload_hash:
            raise ScopeViolationError("request payload differs from the approved payload")
        if request.spend_cents > claims.max_spend_cents:
            raise LimitExceededError("request spend exceeds the approved spend limit")

    def execute(
        self,
        request: ActionRequest,
        handler: Callable[[ActionRequest], T],
        token: str | None = None,
    ) -> T:
        """Authorize, then run ``handler``. The attempt counts even if the handler fails."""
        self.authorize(request, token)
        return handler(request)

    # ----------------------------------------------------------------- audit

    def ledger_entries(self) -> list[LedgerEntry]:
        with self._db.reader() as conn:
            return self._ledger.entries(conn)

    def ledger_head(self) -> LedgerAnchor | None:
        with self._db.reader() as conn:
            return self._ledger.verify(conn).head

    def verify_integrity(self, anchor: LedgerAnchor | None = None) -> IntegrityReport:
        """Check the ledger chain, every candidate digest, and ledger-to-candidate bindings."""
        with self._db.reader() as conn:
            chain = self._ledger.verify(conn, anchor)
            candidate_problems = self._candidates.verify_all(conn)
            stored: Mapping[tuple[str, int], str] = {
                (r["candidate_id"], int(r["version"])): r["digest"]
                for r in conn.execute("SELECT candidate_id, version, digest FROM candidates")
            }
            binding: list[str] = []
            for r in conn.execute("SELECT seq, candidate_id, version, digest FROM ledger"):
                key = (r["candidate_id"], int(r["version"]))
                if stored.get(key) != r["digest"]:
                    binding.append(f"seq {r['seq']}: decision does not match stored candidate")
        return IntegrityReport(chain, tuple(candidate_problems), tuple(binding))
