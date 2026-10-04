import json
import threading
import unittest
from dataclasses import replace

from approval_support import AGENT, MASTER, OTHER_MASTER, PAYLOAD, KernelTestCase

from approval_kernel import ActionRequest, Database, Decision, KernelKeys, Keyring, Limits
from approval_kernel.authority import b64url_decode, b64url_encode, encode_token
from approval_kernel.errors import (
    ApprovalKernelError,
    AuthorityExpiredError,
    AuthorityRequiredError,
    AuthorityRevokedError,
    LimitExceededError,
    MalformedTokenError,
    PolicyError,
    ScopeViolationError,
    SignatureInvalidError,
    StaleVersionError,
    UnknownKeyError,
)


class AuthorityHappyPathTests(KernelTestCase):
    def test_end_to_end_approval_and_execution(self) -> None:
        cand, approval = self.approve_payment()
        self.assertEqual(approval.claims.candidate_id, cand.candidate_id)
        self.assertEqual(approval.claims.digest, cand.digest)
        self.assertEqual(approval.entry.kind, Decision.APPROVE)

        executed: list[ActionRequest] = []
        result = self.kernel.execute(self.payment_request(spend=1200), executed.append, approval.token)
        self.assertIsNone(result)
        self.assertEqual(len(executed), 1)
        self.assertTrue(self.kernel.verify_integrity().ok)

    def test_read_only_actions_skip_approval(self) -> None:
        request = ActionRequest("files.read", "notes/today.md", {"lines": 20})
        auth = self.kernel.authorize(request)
        self.assertTrue(auth.read_only)
        self.assertIsNone(auth.token_id)
        self.assertEqual(self.kernel.execute(request, lambda r: r.target), "notes/today.md")

    def test_write_and_external_actions_require_authority(self) -> None:
        for action in ("files.write", "payments.send"):
            with self.subTest(action=action), self.assertRaises(AuthorityRequiredError):
                self.kernel.authorize(ActionRequest(action, "t", {}))

    def test_unknown_actions_are_refused_at_execution(self) -> None:
        with self.assertRaises(PolicyError):
            self.kernel.authorize(ActionRequest("shell.exec", "host", {}))

    def test_usage_is_reported_per_attempt(self) -> None:
        _, approval = self.approve_payment(limits=Limits(max_attempts=3, max_spend_cents=1000))
        first = self.kernel.authorize(self.payment_request(spend=400), approval.token)
        second = self.kernel.authorize(self.payment_request(spend=500), approval.token)
        self.assertEqual((first.attempt, first.attempts_remaining, first.spend_remaining_cents), (1, 2, 600))
        self.assertEqual(
            (second.attempt, second.attempts_remaining, second.spend_remaining_cents), (2, 1, 100)
        )


class AuthorityAdversarialTests(KernelTestCase):
    def test_tampered_payload_is_refused(self) -> None:
        _, approval = self.approve_payment()
        tampered = {**PAYLOAD, "to": "attacker-account"}
        with self.assertRaises(ScopeViolationError):
            self.kernel.authorize(self.payment_request(payload=tampered), approval.token)

    def test_scope_escalation_is_refused(self) -> None:
        _, approval = self.approve_payment()
        cases = {
            "other action type": {"action_type": "email.send"},
            "other target": {"target": "vendor-43"},
        }
        for label, override in cases.items():
            with self.subTest(label), self.assertRaises(ScopeViolationError):
                self.kernel.authorize(self.payment_request(**override), approval.token)
        with self.assertRaises(LimitExceededError):
            self.kernel.authorize(self.payment_request(spend=1201), approval.token)
        # none of the refused attempts consumed budget
        self.assertEqual(self.kernel.authorize(self.payment_request(), approval.token).attempt, 1)

    def test_edited_claims_break_the_signature(self) -> None:
        _, approval = self.approve_payment()
        prefix, kid, body, sig = approval.token.split(".")
        claims = json.loads(b64url_decode(body))
        claims["max_attempts"] = 1000
        claims["target"] = "vendor-43"
        forged = ".".join([prefix, kid, b64url_encode(json.dumps(claims).encode()), sig])
        with self.assertRaises(SignatureInvalidError):
            self.kernel.authorize(self.payment_request(target="vendor-43"), forged)

    def test_wrong_signing_key_is_refused(self) -> None:
        _, approval = self.approve_payment()
        other = self.make_kernel(self.db, KernelKeys.from_master(OTHER_MASTER))
        with self.assertRaises(SignatureInvalidError):
            other.authorize(self.payment_request(), approval.token)

    def test_unknown_key_id_is_refused(self) -> None:
        _, approval = self.approve_payment()
        rotated = KernelKeys.from_master(MASTER, kid="k2")
        other = self.make_kernel(self.db, rotated)
        with self.assertRaises(UnknownKeyError):
            other.authorize(self.payment_request(), approval.token)

    def test_retired_key_still_verifies_after_rotation(self) -> None:
        _, approval = self.approve_payment()
        ring = Keyring({"k1": _derive_k1(), "k2": b"\x07" * 32}, active="k2")
        other = self.make_kernel(self.db, replace(self.keys, authority=ring))
        self.assertEqual(other.authorize(self.payment_request(), approval.token).attempt, 1)

    def test_validly_signed_but_never_issued_token_is_refused(self) -> None:
        """Defends against a leaked signing key minting tokens outside approval."""
        _, approval = self.approve_payment()
        fake = replace(approval.claims, token_id="auth_minted_offline", max_attempts=1000)
        token = encode_token(fake, self.keys.authority)
        with self.assertRaises(AuthorityRevokedError):
            self.kernel.authorize(self.payment_request(), token)

    def test_garbage_tokens_are_malformed(self) -> None:
        for token in ("", "ak1", "ak1.k1.x", "jwt.k1.a.b", "ak1.k1.!!!.sig", "x" * 9000):
            with self.subTest(token=token[:20]), self.assertRaises(ApprovalKernelError):
                self.kernel.authorize(self.payment_request(), token)
        with self.assertRaises(MalformedTokenError):
            self.kernel.authorize(self.payment_request(), "ak1.k1.a.b.c")

    def test_expired_authority_is_refused(self) -> None:
        _, approval = self.approve_payment()
        self.clock.advance(300)
        with self.assertRaises(AuthorityExpiredError):
            self.kernel.authorize(self.payment_request(), approval.token)

    def test_authority_never_outlives_the_candidate(self) -> None:
        _, approval = self.approve_payment(ttl_seconds=90)
        self.assertEqual(approval.claims.expires_at - approval.claims.issued_at, 90)

    def test_revision_after_approval_invalidates_authority(self) -> None:
        cand, approval = self.approve_payment()
        self.kernel.revise(cand.candidate_id, proposed_by=AGENT, payload={**PAYLOAD, "amount_cents": 99})
        with self.assertRaises(StaleVersionError):
            self.kernel.authorize(self.payment_request(), approval.token)

    def test_revoked_approval_invalidates_authority(self) -> None:
        cand, approval = self.approve_payment()
        self.kernel.authorize(self.payment_request(), approval.token)
        self.decide(cand, Decision.REVOKE)
        with self.assertRaises(AuthorityRevokedError):
            self.kernel.authorize(self.payment_request(), approval.token)

    def test_attempt_limit_is_enforced(self) -> None:
        _, approval = self.approve_payment()  # max_attempts=2
        self.kernel.authorize(self.payment_request(), approval.token)
        self.kernel.authorize(self.payment_request(), approval.token)
        with self.assertRaises(LimitExceededError):
            self.kernel.authorize(self.payment_request(), approval.token)

    def test_cumulative_spend_limit_is_enforced(self) -> None:
        _, approval = self.approve_payment(limits=Limits(max_attempts=5, max_spend_cents=1000))
        self.kernel.authorize(self.payment_request(spend=700), approval.token)
        with self.assertRaises(LimitExceededError):
            self.kernel.authorize(self.payment_request(spend=301), approval.token)
        self.kernel.authorize(self.payment_request(spend=300), approval.token)

    def test_handler_failure_still_counts_the_attempt(self) -> None:
        _, approval = self.approve_payment(limits=Limits(max_attempts=1))

        def boom(_: ActionRequest) -> None:
            raise RuntimeError("downstream failure")

        with self.assertRaises(RuntimeError):
            self.kernel.execute(self.payment_request(), boom, approval.token)
        with self.assertRaises(LimitExceededError):
            self.kernel.execute(self.payment_request(), lambda r: None, approval.token)


def _derive_k1() -> bytes:
    import hashlib
    import hmac

    return hmac.new(MASTER, b"approval-kernel/v1/authority:k1", hashlib.sha256).digest()


class ConcurrentUseTests(KernelTestCase):
    use_file_db = True

    def _race(self, workers: list[threading.Thread]) -> None:
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=60)
            self.assertFalse(worker.is_alive(), "worker hung")

    def test_parallel_threads_never_exceed_attempt_limit(self) -> None:
        _, approval = self.approve_payment(limits=Limits(max_attempts=5, max_spend_cents=0))
        barrier = threading.Barrier(24)
        admitted: list[int] = []
        refused: list[Exception] = []
        lock = threading.Lock()

        def attempt() -> None:
            barrier.wait()
            try:
                auth = self.kernel.authorize(self.payment_request(), approval.token)
            except LimitExceededError as exc:
                with lock:
                    refused.append(exc)
            else:
                with lock:
                    admitted.append(auth.attempt)

        self._race([threading.Thread(target=attempt) for _ in range(24)])
        self.assertEqual(sorted(admitted), [1, 2, 3, 4, 5])
        self.assertEqual(len(refused), 19)

    def test_separate_processes_sharing_the_file_never_exceed_spend(self) -> None:
        """Two kernels on two Database objects model two processes on one file."""
        _, approval = self.approve_payment(limits=Limits(max_attempts=100, max_spend_cents=1000))
        second_db = Database(self.db.path)
        self.addCleanup(second_db.close)
        kernels = [self.kernel, self.make_kernel(second_db, self.keys)]
        barrier = threading.Barrier(20)
        spent: list[int] = []
        lock = threading.Lock()

        def attempt(index: int) -> None:
            kernel = kernels[index % 2]
            barrier.wait()
            try:
                kernel.authorize(self.payment_request(spend=150), approval.token)
            except LimitExceededError:
                return
            with lock:
                spent.append(150)

        self._race([threading.Thread(target=attempt, args=(i,)) for i in range(20)])
        self.assertEqual(sum(spent), 900)  # 6 x 150; a 7th would exceed 1000


if __name__ == "__main__":
    unittest.main()
