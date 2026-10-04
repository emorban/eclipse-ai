"""approval_kernel -- a public reference implementation of an agent approval boundary.

Agents propose; owners decide; executors verify. See README.md in this package.
Standard library only (sqlite3, hashlib, hmac, secrets).
"""

from __future__ import annotations

from . import errors
from .authority import ActionRequest, AuthorityClaims, Authorization, Keyring, decode_token
from .candidates import ActionCandidate, ActionRegistry, Limits, RiskClass
from .canonical import canonical_json, content_hash
from .clock import Clock, ManualClock, SystemClock
from .kernel import Approval, ApprovalKernel, IntegrityReport, KernelKeys
from .ledger import ChainReport, Decision, LedgerAnchor, LedgerEntry
from .sessions import Challenge, OwnerSession, sign_challenge
from .storage import Database

__all__ = [
    "ActionCandidate",
    "ActionRegistry",
    "ActionRequest",
    "Approval",
    "ApprovalKernel",
    "AuthorityClaims",
    "Authorization",
    "ChainReport",
    "Challenge",
    "Clock",
    "Database",
    "Decision",
    "IntegrityReport",
    "KernelKeys",
    "Keyring",
    "LedgerAnchor",
    "LedgerEntry",
    "Limits",
    "ManualClock",
    "OwnerSession",
    "RiskClass",
    "SystemClock",
    "canonical_json",
    "content_hash",
    "decode_token",
    "errors",
    "sign_challenge",
]

__version__ = "0.1.0"
