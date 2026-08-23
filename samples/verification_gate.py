from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class CompletionClaim:
    task: str
    claimed_outputs: tuple[str, ...]


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    missing_outputs: tuple[str, ...]


def verify_completion(
    claim: CompletionClaim,
    observed_outputs: Iterable[str],
) -> VerificationResult:
    """Verify a worker completion claim against independently observed outputs.

    The worker's own status message is not evidence. The caller supplies the
    outputs it can actually observe, and required outputs must be present before
    the claim is accepted.
    """

    observed = {item.strip() for item in observed_outputs if item.strip()}
    required = tuple(item.strip() for item in claim.claimed_outputs if item.strip())
    missing = tuple(item for item in required if item not in observed)

    return VerificationResult(ok=not missing, missing_outputs=missing)
