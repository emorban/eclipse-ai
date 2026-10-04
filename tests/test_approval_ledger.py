import sqlite3
import unittest

from approval_support import OTHER_MASTER, KernelTestCase

from approval_kernel import Decision, KernelKeys, LedgerAnchor
from approval_kernel.errors import LedgerIntegrityError
from approval_kernel.ledger import GENESIS


class LedgerChainTests(KernelTestCase):
    def setUp(self) -> None:
        super().setUp()
        # Four decisions: approve, reject, approve, revoke.
        a, b, c = self.propose_payment(), self.propose_payment(), self.propose_payment()
        self.decide(a, Decision.APPROVE)
        self.decide(b, Decision.REJECT)
        self.decide(c, Decision.APPROVE)
        self.decide(c, Decision.REVOKE)
        self.conn = self.db.connection()

    def _unlock(self) -> None:
        """Simulate an attacker with raw write access to the database file."""
        self.conn.execute("DROP TRIGGER ledger_no_update")
        self.conn.execute("DROP TRIGGER ledger_no_delete")
        self.conn.execute("DROP TRIGGER ledger_contiguous")
        self.conn.execute("PRAGMA foreign_keys = OFF")

    def test_clean_chain_verifies(self) -> None:
        entries = self.kernel.ledger_entries()
        self.assertEqual([e.seq for e in entries], [1, 2, 3, 4])
        self.assertEqual(entries[0].prev_hash, GENESIS)
        for prev, nxt in zip(entries, entries[1:], strict=False):
            self.assertEqual(nxt.prev_hash, prev.entry_hash)
        report = self.kernel.verify_integrity()
        self.assertTrue(report.ok, report)
        self.assertEqual(report.ledger.length, 4)
        self.assertEqual(report.ledger.head, LedgerAnchor(4, entries[-1].entry_hash))

    def test_triggers_block_update_delete_and_out_of_order_insert(self) -> None:
        with self.assertRaises(sqlite3.DatabaseError):
            self.conn.execute("UPDATE ledger SET kind = 'approve' WHERE seq = 2")
        with self.assertRaises(sqlite3.DatabaseError):
            self.conn.execute("DELETE FROM ledger WHERE seq = 4")
        with self.assertRaises(sqlite3.DatabaseError):
            self.conn.execute("INSERT INTO ledger VALUES (9, 'approve', 'x', 1, 'd', 'a', '', 0, 'p', 'h')")
        self.assertTrue(self.kernel.verify_integrity().ok)

    def test_edited_row_is_detected(self) -> None:
        self._unlock()
        self.conn.execute("UPDATE ledger SET kind = 'approve' WHERE seq = 2")  # reject -> approve
        report = self.kernel.verify_integrity().ledger
        self.assertFalse(report.ok)
        self.assertEqual(report.problems, ("seq 2: entry contents do not match entry_hash",))
        with self.assertRaises(LedgerIntegrityError):
            report.raise_for_problems()

    def test_edited_actor_is_detected(self) -> None:
        self._unlock()
        self.conn.execute("UPDATE ledger SET actor = 'someone-else' WHERE seq = 1")
        self.assertFalse(self.kernel.verify_integrity().ok)

    def test_deleted_row_is_detected(self) -> None:
        self._unlock()
        self.conn.execute("DELETE FROM ledger WHERE seq = 3")
        problems = self.kernel.verify_integrity().ledger.problems
        self.assertIn("sequence gap: expected seq 3, found 4", problems)
        self.assertIn("seq 4: prev_hash does not link to the preceding entry", problems)

    def test_reordered_rows_are_detected(self) -> None:
        self._unlock()
        rows = {r["seq"]: dict(r) for r in self.conn.execute("SELECT * FROM ledger")}
        # Swap the bodies of entries 2 and 3 while keeping seq values contiguous.
        for seq, source in ((2, rows[3]), (3, rows[2])):
            self.conn.execute(
                "UPDATE ledger SET kind=?, candidate_id=?, version=?, digest=?, actor=?, reason=?,"
                " at=?, prev_hash=?, entry_hash=? WHERE seq=?",
                (
                    source["kind"],
                    source["candidate_id"],
                    source["version"],
                    source["digest"],
                    source["actor"],
                    source["reason"],
                    source["at"],
                    source["prev_hash"],
                    source["entry_hash"] + "-tmp",
                    seq,
                ),
            )
        for seq in (2, 3):
            self.conn.execute(
                "UPDATE ledger SET entry_hash = REPLACE(entry_hash, '-tmp', '') WHERE seq = ?", (seq,)
            )
        self.assertFalse(self.kernel.verify_integrity().ok)

    def test_rewrite_without_ledger_key_is_detected(self) -> None:
        """An attacker who recomputes the whole chain with a guessed key still fails."""
        from approval_kernel.ledger import _entry_fields, compute_entry_hash

        self._unlock()
        forged_key = KernelKeys.from_master(OTHER_MASTER).ledger_key
        prev = GENESIS
        for row in self.conn.execute("SELECT * FROM ledger ORDER BY seq").fetchall():
            kind = "approve" if row["seq"] == 2 else row["kind"]
            fields = _entry_fields(
                row["seq"],
                kind,
                row["candidate_id"],
                row["version"],
                row["digest"],
                row["actor"],
                row["reason"],
                row["at"],
            )
            new_hash = compute_entry_hash(forged_key, prev, fields)
            self.conn.execute(
                "UPDATE ledger SET kind=?, prev_hash=?, entry_hash=? WHERE seq=?",
                (kind, prev, new_hash, row["seq"]),
            )
            prev = new_hash
        report = self.kernel.verify_integrity().ledger
        self.assertFalse(report.ok)
        self.assertEqual(len(report.problems), 4)  # every entry fails its MAC

    def test_tail_truncation_needs_an_external_anchor(self) -> None:
        anchor = self.kernel.ledger_head()
        assert anchor is not None
        self._unlock()
        self.conn.execute("DELETE FROM ledger WHERE seq = 4")
        # Without the anchor the shorter chain is internally consistent ...
        self.assertTrue(self.kernel.verify_integrity().ledger.ok)
        # ... with it, truncation is detected.
        report = self.kernel.verify_integrity(anchor=anchor).ledger
        self.assertFalse(report.ok)
        self.assertIn("anchor seq 4 missing: ledger truncated", report.problems)

    def test_binding_to_candidate_digest_is_checked(self) -> None:
        self._unlock()
        self.conn.execute("UPDATE ledger SET digest = 'sha256:' || hex(randomblob(32)) WHERE seq = 1")
        report = self.kernel.verify_integrity()
        self.assertFalse(report.ok)
        self.assertTrue(report.binding_problems)


if __name__ == "__main__":
    unittest.main()
