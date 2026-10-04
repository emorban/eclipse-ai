import unittest

from approval_support import AGENT, OWNER, KernelTestCase

from approval_kernel import Decision, Limits, sign_challenge
from approval_kernel.errors import (
    InvalidTransitionError,
    NonceExpiredError,
    NonceInvalidError,
    NonceReplayError,
    ProofInvalidError,
    SessionExpiredError,
    SessionNotFoundError,
    StaleVersionError,
)


class SessionAndNonceTests(KernelTestCase):
    def test_only_configured_owners_can_open_sessions(self) -> None:
        with self.assertRaises(SessionNotFoundError):
            self.kernel.open_session(AGENT)

    def test_session_secret_is_not_in_repr(self) -> None:
        session = self.kernel.open_session(OWNER)
        self.assertNotIn(session.secret.hex(), repr(session))

    def test_replayed_nonce_is_refused(self) -> None:
        cand = self.propose_payment()
        session = self.kernel.open_session(OWNER)
        challenge = self.kernel.challenge(session.session_id, cand.candidate_id)
        proof = sign_challenge(session.secret, challenge, Decision.APPROVE)
        self.kernel.approve(session.session_id, challenge.nonce, proof)
        with self.assertRaises(NonceReplayError):
            self.kernel.approve(session.session_id, challenge.nonce, proof)
        reject_proof = sign_challenge(session.secret, challenge, Decision.REJECT)
        with self.assertRaises(NonceReplayError):
            self.kernel.reject(session.session_id, challenge.nonce, reject_proof)
        self.assertEqual(len(self.kernel.ledger_entries()), 1)

    def test_proof_is_bound_to_the_decision(self) -> None:
        cand = self.propose_payment()
        session = self.kernel.open_session(OWNER)
        challenge = self.kernel.challenge(session.session_id, cand.candidate_id)
        reject_proof = sign_challenge(session.secret, challenge, Decision.REJECT)
        with self.assertRaises(ProofInvalidError):
            self.kernel.approve(session.session_id, challenge.nonce, reject_proof)
        # the failed attempt did not burn the nonce: the real decision still works
        self.kernel.reject(session.session_id, challenge.nonce, reject_proof)
        self.assertEqual(self.kernel.status(cand.candidate_id), "reject")

    def test_agent_without_session_secret_cannot_approve(self) -> None:
        cand = self.propose_payment()
        session = self.kernel.open_session(OWNER)
        challenge = self.kernel.challenge(session.session_id, cand.candidate_id)
        forged = sign_challenge(b"\x00" * 32, challenge, Decision.APPROVE)
        with self.assertRaises(ProofInvalidError):
            self.kernel.approve(session.session_id, challenge.nonce, forged)
        with self.assertRaises(ProofInvalidError):
            self.kernel.approve(session.session_id, challenge.nonce, "")

    def test_nonce_cannot_be_used_from_another_session(self) -> None:
        cand = self.propose_payment()
        first = self.kernel.open_session(OWNER)
        second = self.kernel.open_session(OWNER)
        challenge = self.kernel.challenge(first.session_id, cand.candidate_id)
        proof = sign_challenge(second.secret, challenge, Decision.APPROVE)
        with self.assertRaises(NonceInvalidError):
            self.kernel.approve(second.session_id, challenge.nonce, proof)
        with self.assertRaises(NonceInvalidError):
            self.kernel.approve(first.session_id, "made-up-nonce", proof)

    def test_expired_nonce_is_refused(self) -> None:
        cand = self.propose_payment()
        session = self.kernel.open_session(OWNER)
        challenge = self.kernel.challenge(session.session_id, cand.candidate_id)
        self.clock.advance(121)
        with self.assertRaises(NonceExpiredError):
            self.kernel.approve(
                session.session_id,
                challenge.nonce,
                sign_challenge(session.secret, challenge, Decision.APPROVE),
            )

    def test_expired_and_closed_sessions_are_refused(self) -> None:
        cand = self.propose_payment()
        session = self.kernel.open_session(OWNER, ttl=60)
        challenge = self.kernel.challenge(session.session_id, cand.candidate_id)
        self.clock.advance(60)
        with self.assertRaises(SessionExpiredError):
            self.kernel.approve(
                session.session_id,
                challenge.nonce,
                sign_challenge(session.secret, challenge, Decision.APPROVE),
            )
        with self.assertRaises(SessionExpiredError):
            self.kernel.challenge(session.session_id, cand.candidate_id)

        other = self.kernel.open_session(OWNER)
        self.kernel.close_session(other.session_id)
        with self.assertRaises(SessionExpiredError):
            self.kernel.challenge(other.session_id, cand.candidate_id)

    def test_challenge_over_old_version_cannot_approve_revision(self) -> None:
        """What-you-saw-is-what-you-approve: a revision invalidates open challenges."""
        cand = self.propose_payment()
        session = self.kernel.open_session(OWNER)
        challenge = self.kernel.challenge(session.session_id, cand.candidate_id)
        self.kernel.revise(cand.candidate_id, proposed_by=AGENT, limits=Limits(50, 1_000_000))
        with self.assertRaises(StaleVersionError):
            self.kernel.approve(
                session.session_id,
                challenge.nonce,
                sign_challenge(session.secret, challenge, Decision.APPROVE),
            )
        self.assertEqual(self.kernel.ledger_entries(), [])

    def test_decision_state_machine(self) -> None:
        cand = self.propose_payment()
        self.decide(cand, Decision.REJECT)
        with self.assertRaises(InvalidTransitionError):
            self.decide(cand, Decision.APPROVE)
        with self.assertRaises(InvalidTransitionError):
            self.decide(cand, Decision.REVOKE)

        other = self.propose_payment()
        with self.assertRaises(InvalidTransitionError):
            self.decide(other, Decision.REVOKE)  # nothing to revoke yet
        self.decide(other, Decision.APPROVE)
        with self.assertRaises(InvalidTransitionError):
            self.decide(other, Decision.APPROVE)
        self.decide(other, Decision.REVOKE)
        self.assertEqual(self.kernel.status(other.candidate_id), "revoke")


if __name__ == "__main__":
    unittest.main()
