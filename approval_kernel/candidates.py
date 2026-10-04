"""Immutable, versioned action candidates.

An agent never acts directly on a consequential target. It *proposes* an
:class:`ActionCandidate`: what it wants to do, to which target, with which
payload, under which limits, until when. The owner decides on that exact
candidate, identified by ``(candidate_id, version, digest)``.

Candidates are never edited. A revision is a new row with ``version + 1`` whose
``parent_digest`` points at the version it replaces, so the full negotiation
history is preserved and an approval can never silently "follow" an edit.
"""

from __future__ import annotations

import json
import re
import secrets
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .canonical import canonical_json, content_hash
from .clock import Clock
from .errors import (
    CandidateIntegrityError,
    CandidateNotFoundError,
    PolicyError,
    RiskDowngradeError,
)

_ACTION_TYPE = re.compile(r"^[a-z][a-z0-9_.:-]{0,63}$")
MAX_TARGET_LENGTH = 512
MAX_TTL_SECONDS = 7 * 24 * 3600
KEEP: Any = object()  # sentinel: "carry this field over from the parent version"


class RiskClass(StrEnum):
    """Capability class of an action, ordered from least to most consequential."""

    READ_ONLY = "read_only"  # observes state; may run without approval
    WRITE = "write"  # changes local/internal state
    EXTERNAL = "external"  # leaves the system: messages, payments, third-party APIs

    @property
    def rank(self) -> int:
        return _RISK_RANK[self]

    @property
    def requires_approval(self) -> bool:
        return self is not RiskClass.READ_ONLY


_RISK_RANK = {RiskClass.READ_ONLY: 0, RiskClass.WRITE: 1, RiskClass.EXTERNAL: 2}


@dataclass(frozen=True)
class Limits:
    """Budget attached to an approval and enforced on every use of its authority."""

    max_attempts: int = 1
    max_spend_cents: int = 0

    def __post_init__(self) -> None:
        for name in ("max_attempts", "max_spend_cents"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise PolicyError(f"{name} must be an integer")
        if not 1 <= self.max_attempts <= 1000:
            raise PolicyError("max_attempts must be between 1 and 1000")
        if self.max_spend_cents < 0:
            raise PolicyError("max_spend_cents cannot be negative")

    def to_dict(self) -> dict[str, int]:
        return {"max_attempts": self.max_attempts, "max_spend_cents": self.max_spend_cents}


class ActionRegistry:
    """Operator-declared action types and their minimum risk class.

    The agent does not get to decide how dangerous its own action is. A candidate
    may declare a *higher* risk than the registry floor, never a lower one, and
    unknown action types are refused rather than defaulted.
    """

    def __init__(self, entries: Mapping[str, RiskClass] | None = None) -> None:
        self._floor: dict[str, RiskClass] = {}
        for action_type, risk in (entries or {}).items():
            self.register(action_type, risk)

    def register(self, action_type: str, risk: RiskClass) -> None:
        if not _ACTION_TYPE.match(action_type):
            raise PolicyError(f"invalid action type: {action_type!r}")
        if action_type in self._floor:
            raise PolicyError(f"action type already registered: {action_type}")
        self._floor[action_type] = RiskClass(risk)

    def classify(self, action_type: str) -> RiskClass:
        try:
            return self._floor[action_type]
        except KeyError:
            raise PolicyError(f"unknown action type: {action_type!r}") from None

    def resolve(self, action_type: str, declared: RiskClass | None) -> RiskClass:
        floor = self.classify(action_type)
        if declared is None:
            return floor
        declared = RiskClass(declared)
        if declared.rank < floor.rank:
            raise RiskDowngradeError(
                f"{action_type} is at least {floor.value}; candidate declared {declared.value}"
            )
        return declared


@dataclass(frozen=True)
class ActionCandidate:
    """One immutable version of a proposed action.

    The payload is held as canonical JSON text, and :attr:`payload` returns a
    fresh copy, so no caller can mutate a candidate after it has been hashed.
    """

    candidate_id: str
    version: int
    action_type: str
    target: str
    risk: RiskClass
    payload_json: str
    payload_hash: str
    limits: Limits
    proposed_by: str
    created_at: int
    expires_at: int
    parent_digest: str | None
    digest: str

    @property
    def payload(self) -> Any:
        return json.loads(self.payload_json)

    def is_expired(self, now: int) -> bool:
        return now >= self.expires_at

    @staticmethod
    def compute_digest(
        *,
        candidate_id: str,
        version: int,
        action_type: str,
        target: str,
        risk: RiskClass,
        payload_hash: str,
        limits: Limits,
        proposed_by: str,
        created_at: int,
        expires_at: int,
        parent_digest: str | None,
    ) -> str:
        return content_hash(
            {
                "kind": "approval-kernel/candidate/v1",
                "candidate_id": candidate_id,
                "version": version,
                "action_type": action_type,
                "target": target,
                "risk": risk.value,
                "payload_hash": payload_hash,
                "limits": limits.to_dict(),
                "proposed_by": proposed_by,
                "created_at": created_at,
                "expires_at": expires_at,
                "parent_digest": parent_digest,
            }
        )

    def recompute_digest(self) -> str:
        return self.compute_digest(
            candidate_id=self.candidate_id,
            version=self.version,
            action_type=self.action_type,
            target=self.target,
            risk=self.risk,
            payload_hash=self.payload_hash,
            limits=self.limits,
            proposed_by=self.proposed_by,
            created_at=self.created_at,
            expires_at=self.expires_at,
            parent_digest=self.parent_digest,
        )


def _validate_target(target: str) -> str:
    if not isinstance(target, str) or not target.strip():
        raise PolicyError("target must be a non-empty string")
    if len(target) > MAX_TARGET_LENGTH:
        raise PolicyError("target is too long")
    return target


def _validate_ttl(ttl_seconds: int) -> int:
    if not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
        raise PolicyError(f"ttl_seconds must be between 1 and {MAX_TTL_SECONDS}")
    return ttl_seconds


def _validate_actor(actor: str) -> str:
    if not isinstance(actor, str) or not actor.strip():
        raise PolicyError("proposed_by must be a non-empty string")
    return actor


class CandidateStore:
    """Persists candidates and refuses to return any row whose digest drifted."""

    def __init__(self, registry: ActionRegistry, clock: Clock) -> None:
        self._registry = registry
        self._clock = clock

    def create(
        self,
        conn: sqlite3.Connection,
        *,
        action_type: str,
        target: str,
        payload: Any,
        risk: RiskClass | None = None,
        limits: Limits | None = None,
        ttl_seconds: int = 3600,
        proposed_by: str,
    ) -> ActionCandidate:
        return self._insert(
            conn,
            candidate_id="cand_" + secrets.token_hex(12),
            version=1,
            action_type=action_type,
            target=target,
            payload=payload,
            risk=risk,
            limits=limits or Limits(),
            ttl_seconds=ttl_seconds,
            proposed_by=proposed_by,
            parent=None,
        )

    def revise(
        self,
        conn: sqlite3.Connection,
        candidate_id: str,
        *,
        proposed_by: str,
        target: str | None = None,
        payload: Any = KEEP,
        risk: RiskClass | None = None,
        limits: Limits | None = None,
        ttl_seconds: int = 3600,
    ) -> ActionCandidate:
        parent = self.get(conn, candidate_id)
        return self._insert(
            conn,
            candidate_id=candidate_id,
            version=parent.version + 1,
            action_type=parent.action_type,  # the kind of action never changes
            target=parent.target if target is None else target,
            payload=parent.payload if payload is KEEP else payload,
            risk=parent.risk if risk is None else risk,
            limits=parent.limits if limits is None else limits,
            ttl_seconds=ttl_seconds,
            proposed_by=proposed_by,
            parent=parent,
        )

    def _insert(
        self,
        conn: sqlite3.Connection,
        *,
        candidate_id: str,
        version: int,
        action_type: str,
        target: str,
        payload: Any,
        risk: RiskClass | None,
        limits: Limits,
        ttl_seconds: int,
        proposed_by: str,
        parent: ActionCandidate | None,
    ) -> ActionCandidate:
        resolved = self._registry.resolve(action_type, risk)
        _validate_target(target)
        _validate_actor(proposed_by)
        now = self._clock.now()
        expires_at = now + _validate_ttl(ttl_seconds)
        payload_json = canonical_json(payload).decode("utf-8")
        payload_hash = content_hash(payload)
        parent_digest = parent.digest if parent else None
        digest = ActionCandidate.compute_digest(
            candidate_id=candidate_id,
            version=version,
            action_type=action_type,
            target=target,
            risk=resolved,
            payload_hash=payload_hash,
            limits=limits,
            proposed_by=proposed_by,
            created_at=now,
            expires_at=expires_at,
            parent_digest=parent_digest,
        )
        conn.execute(
            "INSERT INTO candidates (candidate_id, version, action_type, target, risk,"
            " payload_json, payload_hash, limits_json, proposed_by, created_at, expires_at,"
            " parent_digest, digest) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                candidate_id,
                version,
                action_type,
                target,
                resolved.value,
                payload_json,
                payload_hash,
                canonical_json(limits.to_dict()).decode("utf-8"),
                proposed_by,
                now,
                expires_at,
                parent_digest,
                digest,
            ),
        )
        return self.get(conn, candidate_id, version)

    def latest_version(self, conn: sqlite3.Connection, candidate_id: str) -> int:
        row = conn.execute(
            "SELECT MAX(version) FROM candidates WHERE candidate_id = ?", (candidate_id,)
        ).fetchone()
        if row is None or row[0] is None:
            raise CandidateNotFoundError(f"no candidate {candidate_id!r}")
        return int(row[0])

    def get(self, conn: sqlite3.Connection, candidate_id: str, version: int | None = None) -> ActionCandidate:
        if version is None:
            version = self.latest_version(conn, candidate_id)
        row = conn.execute(
            "SELECT * FROM candidates WHERE candidate_id = ? AND version = ?",
            (candidate_id, version),
        ).fetchone()
        if row is None:
            raise CandidateNotFoundError(f"no candidate {candidate_id!r} version {version}")
        return self._from_row(row)

    def history(self, conn: sqlite3.Connection, candidate_id: str) -> list[ActionCandidate]:
        rows = conn.execute(
            "SELECT * FROM candidates WHERE candidate_id = ? ORDER BY version", (candidate_id,)
        ).fetchall()
        if not rows:
            raise CandidateNotFoundError(f"no candidate {candidate_id!r}")
        return [self._from_row(row) for row in rows]

    def verify_all(self, conn: sqlite3.Connection) -> list[str]:
        """Return a problem description for every stored candidate that fails integrity."""
        problems: list[str] = []
        for row in conn.execute("SELECT * FROM candidates ORDER BY candidate_id, version"):
            try:
                self._from_row(row)
            except CandidateIntegrityError as exc:
                problems.append(str(exc))
        return problems

    @staticmethod
    def _from_row(row: sqlite3.Row) -> ActionCandidate:
        label = f"{row['candidate_id']} v{row['version']}"
        try:
            limits_raw = json.loads(row["limits_json"])
            payload = json.loads(row["payload_json"])
            candidate = ActionCandidate(
                candidate_id=row["candidate_id"],
                version=int(row["version"]),
                action_type=row["action_type"],
                target=row["target"],
                risk=RiskClass(row["risk"]),
                payload_json=row["payload_json"],
                payload_hash=row["payload_hash"],
                limits=Limits(**limits_raw),
                proposed_by=row["proposed_by"],
                created_at=int(row["created_at"]),
                expires_at=int(row["expires_at"]),
                parent_digest=row["parent_digest"],
                digest=row["digest"],
            )
        except (ValueError, TypeError, PolicyError) as exc:
            raise CandidateIntegrityError(f"candidate {label} is unreadable: {exc}") from exc
        if content_hash(payload) != candidate.payload_hash:
            raise CandidateIntegrityError(f"candidate {label} payload does not match its hash")
        if candidate.recompute_digest() != candidate.digest:
            raise CandidateIntegrityError(f"candidate {label} does not match its digest")
        return candidate
