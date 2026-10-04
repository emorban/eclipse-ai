"""Canonical JSON serialization and content hashing.

Approval is only meaningful if "the thing the owner approved" and "the thing
being executed" can be compared exactly. Python's ``json.dumps`` is not stable
enough by default (key order, whitespace, float formatting, NaN), so every
payload is passed through a strict canonical form before it is hashed:

* objects: string keys only, emitted in sorted order
* arrays: lists or tuples (tuples become arrays)
* scalars: ``None``, ``bool``, ``int``, ``str``
* **floats are rejected** -- monetary and numeric limits must be integers
  (for example cents), which avoids representation drift between producers
* no insignificant whitespace, UTF-8 output, bounded nesting depth

The rules are deliberately narrower than JSON itself. A payload that cannot be
canonicalized cannot be approved.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .errors import CanonicalizationError

MAX_DEPTH = 32
HASH_PREFIX = "sha256:"


def _normalize(value: Any, depth: int, path: str) -> Any:
    if depth > MAX_DEPTH:
        raise CanonicalizationError(f"nesting deeper than {MAX_DEPTH} at {path}")
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return int(value)  # collapses int subclasses (IntEnum etc.) to plain int
    if isinstance(value, float):
        raise CanonicalizationError(f"floats are not canonical (use integers) at {path}")
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"object keys must be strings at {path}")
            out[key] = _normalize(item, depth + 1, f"{path}.{key}")
        return out
    if isinstance(value, (list, tuple)):
        return [_normalize(item, depth + 1, f"{path}[{i}]") for i, item in enumerate(value)]
    raise CanonicalizationError(f"unsupported type {type(value).__name__} at {path}")


def normalize(value: Any) -> Any:
    """Return a plain-JSON copy of ``value`` or raise CanonicalizationError."""
    return _normalize(value, 0, "$")


def canonical_json(value: Any) -> bytes:
    """Serialize ``value`` to canonical UTF-8 JSON bytes."""
    normalized = normalize(value)
    text = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:  # lone surrogates
        raise CanonicalizationError(f"string is not valid UTF-8: {exc}") from exc


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_hash(value: Any) -> str:
    """Stable, prefixed SHA-256 of the canonical form of ``value``."""
    return HASH_PREFIX + sha256_hex(canonical_json(value))
