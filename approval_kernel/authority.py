"""Scoped, signed, expiring authority tokens.

An authority token is the only thing an executor accepts as permission to run a
state-changing action. It is minted once, at approval time, and carries:

* the candidate id, version, and digest it was minted for
* the exact action type, target, and payload hash in scope
* attempt and spend limits
* issue and expiry times, the approving owner, and the signing key id

Wire format (all parts base64url without padding, except the prefix and kid)::

    ak1.<kid>.<claims>.<sig>      sig = HMAC-SHA256(key[kid], "ak1.<kid>.<claims>")

HMAC keeps the package dependency-free. The trade-off is that verifiers hold
the signing key; a deployment that needs verify-only executors would swap the
:class:`Keyring` for an asymmetric scheme without changing the claim model.

The signature only proves the kernel minted the token. Whether it is *still*
honoured is decided at use time against the database (see
:meth:`approval_kernel.kernel.ApprovalKernel.authorize`).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from .canonical import canonical_json
from .errors import MalformedTokenError, SignatureInvalidError, UnknownKeyError

TOKEN_PREFIX = "ak1"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not text or any(c not in _B64URL for c in text):
        raise MalformedTokenError("token segment is not base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise MalformedTokenError("token segment is not base64url") from exc


_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


class Keyring:
    """Named HMAC keys. New tokens use ``active``; older kids still verify.

    Removing a kid from the ring invalidates every token signed with it, which
    is the coarse-grained "revoke everything" lever.
    """

    def __init__(self, keys: Mapping[str, bytes], active: str) -> None:
        if active not in keys:
            raise ValueError("active key id must be present in the keyring")
        for kid, key in keys.items():
            if not kid or "." in kid:
                raise ValueError(f"invalid key id {kid!r}")
            if len(key) < 32:
                raise ValueError(f"key {kid!r} must be at least 32 bytes")
        self._keys = dict(keys)
        self.active = active

    def __contains__(self, kid: object) -> bool:
        return kid in self._keys

    def sign(self, kid: str, message: bytes) -> bytes:
        return hmac.new(self._keys[kid], message, hashlib.sha256).digest()

    def verify(self, kid: str, message: bytes, signature: bytes) -> bool:
        if kid not in self._keys:
            return False
        return hmac.compare_digest(self.sign(kid, message), signature)


@dataclass(frozen=True)
class AuthorityClaims:
    token_id: str
    candidate_id: str
    version: int
    digest: str
    action_type: str
    target: str
    payload_hash: str
    max_attempts: int
    max_spend_cents: int
    issued_at: int
    expires_at: int
    approved_by: str


_CLAIM_TYPES: dict[str, type] = {
    "token_id": str,
    "candidate_id": str,
    "version": int,
    "digest": str,
    "action_type": str,
    "target": str,
    "payload_hash": str,
    "max_attempts": int,
    "max_spend_cents": int,
    "issued_at": int,
    "expires_at": int,
    "approved_by": str,
}


def encode_token(claims: AuthorityClaims, keyring: Keyring) -> str:
    kid = keyring.active
    body = b64url_encode(canonical_json(asdict(claims)))
    signing_input = f"{TOKEN_PREFIX}.{kid}.{body}".encode("ascii")
    return f"{TOKEN_PREFIX}.{kid}.{body}.{b64url_encode(keyring.sign(kid, signing_input))}"


def decode_token(token: Any, keyring: Keyring) -> AuthorityClaims:
    """Verify the signature, then parse and type-check the claims.

    Claims are never interpreted before the signature has been checked.
    """
    if not isinstance(token, str) or len(token) > 8192:
        raise MalformedTokenError("token must be a string of reasonable length")
    parts = token.split(".")
    if len(parts) != 4 or parts[0] != TOKEN_PREFIX:
        raise MalformedTokenError("token is not in ak1.<kid>.<claims>.<sig> form")
    _, kid, body, sig = parts
    if kid not in keyring:
        raise UnknownKeyError(f"token signed with unknown key id {kid!r}")
    signature = b64url_decode(sig)
    signing_input = f"{TOKEN_PREFIX}.{kid}.{body}".encode("ascii")
    if not keyring.verify(kid, signing_input, signature):
        raise SignatureInvalidError("token signature does not verify")
    try:
        raw = json.loads(b64url_decode(body))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedTokenError("token claims are not JSON") from exc
    if not isinstance(raw, dict) or set(raw) != set(_CLAIM_TYPES):
        raise MalformedTokenError("token claims have unexpected fields")
    for name, expected in _CLAIM_TYPES.items():
        value = raw[name]
        if not isinstance(value, expected) or isinstance(value, bool):
            raise MalformedTokenError(f"claim {name} has the wrong type")
    return AuthorityClaims(**raw)


@dataclass(frozen=True)
class ActionRequest:
    """What an executor is about to do, described independently of any token."""

    action_type: str
    target: str
    payload: Any
    spend_cents: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.spend_cents, int) or isinstance(self.spend_cents, bool):
            raise ValueError("spend_cents must be an integer")
        if self.spend_cents < 0:
            raise ValueError("spend_cents cannot be negative")


@dataclass(frozen=True)
class Authorization:
    """Proof that one execution attempt was admitted (and, if gated, counted)."""

    request: ActionRequest
    read_only: bool
    token_id: str | None = None
    candidate_id: str | None = None
    version: int | None = None
    attempt: int = 0
    attempts_remaining: int | None = None
    spend_remaining_cents: int | None = None
