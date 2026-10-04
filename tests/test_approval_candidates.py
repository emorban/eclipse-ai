import sqlite3
import unittest

from approval_support import AGENT, OWNER, PAYLOAD, KernelTestCase

from approval_kernel import Decision, Limits, RiskClass, canonical_json, content_hash
from approval_kernel.errors import (
    CandidateExpiredError,
    CandidateIntegrityError,
    CanonicalizationError,
    PolicyError,
    RiskDowngradeError,
    SelfApprovalError,
    StaleVersionError,
)


class CanonicalJsonTests(unittest.TestCase):
    def test_key_order_and_whitespace_do_not_change_the_hash(self) -> None:
        a = {"b": [1, 2, {"y": True, "x": None}], "a": "é"}
        b = {"a": "é", "b": [1, 2, {"x": None, "y": True}]}
        self.assertEqual(canonical_json(a), canonical_json(b))
        self.assertEqual(content_hash(a), content_hash(b))
        self.assertEqual(canonical_json(a), '{"a":"é","b":[1,2,{"x":null,"y":true}]}'.encode())

    def test_tuples_serialize_like_lists(self) -> None:
        self.assertEqual(content_hash({"k": (1, 2)}), content_hash({"k": [1, 2]}))

    def test_small_changes_change_the_hash(self) -> None:
        self.assertNotEqual(content_hash({"amount": 100}), content_hash({"amount": 1000}))
        self.assertNotEqual(content_hash({"flag": True}), content_hash({"flag": 1}))

    def test_rejects_non_canonical_values(self) -> None:
        for bad in (1.5, float("nan"), b"bytes", {1: "int key"}, {"s": {1, 2}}, object()):
            with self.subTest(bad=bad), self.assertRaises(CanonicalizationError):
                canonical_json(bad)

    def test_rejects_excessive_nesting_and_lone_surrogates(self) -> None:
        deep: object = "leaf"
        for _ in range(40):
            deep = [deep]
        with self.assertRaises(CanonicalizationError):
            canonical_json(deep)
        with self.assertRaises(CanonicalizationError):
            canonical_json("\ud800")


class CandidateTests(KernelTestCase):
    def test_proposal_is_bound_to_its_content(self) -> None:
        cand = self.propose_payment()
        self.assertEqual(cand.version, 1)
        self.assertEqual(cand.risk, RiskClass.EXTERNAL)
        self.assertEqual(cand.payload_hash, content_hash(PAYLOAD))
        self.assertEqual(cand.recompute_digest(), cand.digest)
        self.assertEqual(self.kernel.status(cand.candidate_id), "pending")

    def test_payload_accessor_returns_a_copy(self) -> None:
        cand = self.propose_payment()
        cand.payload["amount_cents"] = 999_999
        self.assertEqual(cand.payload["amount_cents"], 1200)
        self.assertEqual(self.kernel.candidate(cand.candidate_id).payload, PAYLOAD)

    def test_revision_creates_new_version_and_keeps_history(self) -> None:
        v1 = self.propose_payment()
        v2 = self.kernel.revise(v1.candidate_id, proposed_by=AGENT, payload={**PAYLOAD, "memo": "q3"})
        self.assertEqual(v2.version, 2)
        self.assertEqual(v2.parent_digest, v1.digest)
        self.assertNotEqual(v2.digest, v1.digest)
        history = self.kernel.history(v1.candidate_id)
        self.assertEqual([c.version for c in history], [1, 2])
        self.assertEqual(history[0], v1)  # untouched

    def test_stored_candidates_cannot_be_updated_or_deleted(self) -> None:
        cand = self.propose_payment()
        conn = self.db.connection()
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute(
                "UPDATE candidates SET target = 'attacker' WHERE candidate_id = ?", (cand.candidate_id,)
            )
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM candidates WHERE candidate_id = ?", (cand.candidate_id,))

    def test_direct_payload_edit_is_detected_on_load(self) -> None:
        cand = self.propose_payment()
        conn = self.db.connection()
        conn.execute("DROP TRIGGER candidates_no_update")
        conn.execute(
            "UPDATE candidates SET payload_json = ? WHERE candidate_id = ?",
            ('{"amount_cents":999999,"memo":"monthly hosting","to":"attacker"}', cand.candidate_id),
        )
        with self.assertRaises(CandidateIntegrityError):
            self.kernel.candidate(cand.candidate_id)
        self.assertFalse(self.kernel.verify_integrity().ok)

    def test_unknown_action_type_is_refused(self) -> None:
        with self.assertRaises(PolicyError):
            self.kernel.propose("shell.exec", "host", {"cmd": "ls"}, proposed_by=AGENT)

    def test_agent_cannot_downgrade_risk_class(self) -> None:
        with self.assertRaises(RiskDowngradeError):
            self.kernel.propose(
                "payments.send", "vendor-42", PAYLOAD, proposed_by=AGENT, risk=RiskClass.READ_ONLY
            )

    def test_agent_may_raise_risk_class(self) -> None:
        cand = self.kernel.propose(
            "files.write", "notes/today.md", {"text": "hi"}, proposed_by=AGENT, risk=RiskClass.EXTERNAL
        )
        self.assertEqual(cand.risk, RiskClass.EXTERNAL)

    def test_invalid_limits_and_ttl_are_refused(self) -> None:
        with self.assertRaises(PolicyError):
            Limits(max_attempts=0)
        with self.assertRaises(PolicyError):
            Limits(max_spend_cents=-1)
        with self.assertRaises(PolicyError):
            self.propose_payment(ttl_seconds=0)
        with self.assertRaises(PolicyError):
            self.kernel.propose("files.write", "  ", {}, proposed_by=AGENT)

    def test_owner_cannot_approve_own_proposal(self) -> None:
        cand = self.propose_payment(proposed_by=OWNER)
        with self.assertRaises(SelfApprovalError):
            self.decide(cand)

    def test_challenge_for_superseded_version_is_refused(self) -> None:
        v1 = self.propose_payment()
        self.kernel.revise(v1.candidate_id, proposed_by=AGENT, limits=Limits(5, 5000))
        session = self.kernel.open_session(OWNER)
        with self.assertRaises(StaleVersionError):
            self.kernel.challenge(session.session_id, v1.candidate_id, version=1)

    def test_expired_candidate_cannot_be_approved_and_is_expired_by_sweep(self) -> None:
        cand = self.propose_payment(ttl_seconds=60)
        self.clock.advance(61)
        with self.assertRaises(CandidateExpiredError):
            self.decide(cand)
        entries = self.kernel.expire_stale()
        self.assertEqual([(e.kind, e.candidate_id) for e in entries], [(Decision.EXPIRE, cand.candidate_id)])
        self.assertEqual(self.kernel.status(cand.candidate_id), "expire")
        self.assertEqual(self.kernel.expire_stale(), [])  # idempotent


if __name__ == "__main__":
    unittest.main()
