"""Exception hierarchy for the approval kernel.

Every refusal the kernel makes is a distinct, catchable type. Callers that only
care about "was this allowed?" can catch :class:`ApprovalKernelError`; callers
that need to react differently (re-prompt the owner, re-propose a candidate,
alert on tampering) can catch the narrower types.

The kernel fails closed: any of these exceptions means the action did not
receive authority and no usage was recorded.
"""

from __future__ import annotations


class ApprovalKernelError(Exception):
    """Base class for every refusal raised by the approval kernel."""


# --- serialization -----------------------------------------------------------


class CanonicalizationError(ApprovalKernelError, ValueError):
    """A value cannot be represented in canonical JSON (floats, bytes, sets...)."""


# --- policy ------------------------------------------------------------------


class PolicyError(ApprovalKernelError):
    """The request violates static policy (unknown action, bad limits, ...)."""


class RiskDowngradeError(PolicyError):
    """A candidate declared a lower risk class than its action type allows."""


class AuthorityRequiredError(PolicyError):
    """A state-changing action was attempted without an authority token."""


# --- candidates --------------------------------------------------------------


class CandidateError(ApprovalKernelError):
    """Base class for candidate lookup and lifecycle problems."""


class CandidateNotFoundError(CandidateError):
    """No candidate exists with the requested id / version."""


class CandidateExpiredError(CandidateError):
    """The candidate's decision window has closed."""


class StaleVersionError(CandidateError):
    """The referenced version is no longer the latest revision."""


class CandidateIntegrityError(CandidateError):
    """A stored candidate no longer matches its recorded digest."""


# --- decisions ---------------------------------------------------------------


class DecisionError(ApprovalKernelError):
    """Base class for invalid decisions."""


class InvalidTransitionError(DecisionError):
    """The decision is not allowed from the candidate's current state."""


class SelfApprovalError(DecisionError):
    """The proposer of an action attempted to decide on it."""


# --- sessions / nonces -------------------------------------------------------


class SessionError(ApprovalKernelError):
    """Base class for owner session problems."""


class SessionNotFoundError(SessionError):
    """Unknown session id, or the owner is not permitted to open sessions."""


class SessionExpiredError(SessionError):
    """The owner session has expired or was closed."""


class NonceError(SessionError):
    """Base class for challenge nonce problems."""


class NonceInvalidError(NonceError):
    """The nonce is unknown or was issued to a different session."""


class NonceReplayError(NonceError):
    """The nonce was already redeemed."""


class NonceExpiredError(NonceError):
    """The nonce's validity window has passed."""


class ProofInvalidError(SessionError):
    """The owner's proof over the challenge did not verify."""


# --- authority tokens --------------------------------------------------------


class AuthorityError(ApprovalKernelError):
    """Base class for authority token refusals."""


class MalformedTokenError(AuthorityError):
    """The token cannot be parsed or its claims are structurally invalid."""


class SignatureInvalidError(AuthorityError):
    """The token signature does not verify."""


class UnknownKeyError(SignatureInvalidError):
    """The token names a signing key the verifier does not hold."""


class AuthorityExpiredError(AuthorityError):
    """The token's validity window has passed."""


class ScopeViolationError(AuthorityError):
    """The requested action is outside the token's approved scope."""


class LimitExceededError(AuthorityError):
    """The attempt or spend budget attached to the token is exhausted."""


class AuthorityRevokedError(AuthorityError):
    """The underlying approval is no longer in force."""


# --- ledger ------------------------------------------------------------------


class LedgerIntegrityError(ApprovalKernelError):
    """The decision ledger failed hash-chain verification."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        summary = "; ".join(self.problems[:5])
        more = "" if len(self.problems) <= 5 else f" (+{len(self.problems) - 5} more)"
        super().__init__(f"ledger integrity check failed: {summary}{more}")
