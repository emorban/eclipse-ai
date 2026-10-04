"""Shared fixtures for approval_kernel tests (not a test module itself)."""

from __future__ import annotations

import os
import tempfile
import unittest
from typing import Any

from approval_kernel import (
    ActionRegistry,
    ActionRequest,
    Approval,
    ApprovalKernel,
    Database,
    Decision,
    KernelKeys,
    Limits,
    ManualClock,
    RiskClass,
    sign_challenge,
)
from approval_kernel.candidates import ActionCandidate

MASTER = b"\x01" * 32
OTHER_MASTER = b"\x02" * 32
OWNER = "owner:primary"
AGENT = "agent:planner"
PAYLOAD: dict[str, Any] = {"amount_cents": 1200, "memo": "monthly hosting", "to": "vendor-42"}


def make_registry() -> ActionRegistry:
    return ActionRegistry(
        {
            "files.read": RiskClass.READ_ONLY,
            "files.write": RiskClass.WRITE,
            "payments.send": RiskClass.EXTERNAL,
            "email.send": RiskClass.EXTERNAL,
        }
    )


class KernelTestCase(unittest.TestCase):
    """Builds a kernel on a manual clock; file-backed when ``use_file_db`` is set."""

    use_file_db = False

    def setUp(self) -> None:
        self.clock = ManualClock()
        if self.use_file_db:
            self._tmp = tempfile.TemporaryDirectory()
            self.addCleanup(self._tmp.cleanup)
            self.db = Database(os.path.join(self._tmp.name, "kernel.sqlite3"))
        else:
            self.db = Database()
        self.addCleanup(self.db.close)
        self.keys = KernelKeys.from_master(MASTER)
        self.kernel = self.make_kernel(self.db, self.keys)

    def make_kernel(self, db: Database, keys: KernelKeys, **kwargs: Any) -> ApprovalKernel:
        return ApprovalKernel(db, keys, registry=make_registry(), owners={OWNER}, clock=self.clock, **kwargs)

    def propose_payment(self, **kwargs: Any) -> ActionCandidate:
        params: dict[str, Any] = {
            "proposed_by": AGENT,
            "limits": Limits(max_attempts=2, max_spend_cents=1200),
        }
        params.update(kwargs)
        return self.kernel.propose("payments.send", "vendor-42", PAYLOAD, **params)

    def decide(
        self,
        candidate: ActionCandidate,
        decision: Decision = Decision.APPROVE,
        *,
        kernel: ApprovalKernel | None = None,
    ) -> Any:
        kernel = kernel or self.kernel
        session = kernel.open_session(OWNER)
        challenge = kernel.challenge(session.session_id, candidate.candidate_id, candidate.version)
        proof = sign_challenge(session.secret, challenge, decision)
        method = {
            Decision.APPROVE: kernel.approve,
            Decision.REJECT: kernel.reject,
            Decision.REVOKE: kernel.revoke,
        }[decision]
        return method(session.session_id, challenge.nonce, proof, reason="test")

    def approve_payment(self, **kwargs: Any) -> tuple[ActionCandidate, Approval]:
        candidate = self.propose_payment(**kwargs)
        approval = self.decide(candidate)
        return candidate, approval

    @staticmethod
    def payment_request(spend: int = 0, **overrides: Any) -> ActionRequest:
        fields: dict[str, Any] = {
            "action_type": "payments.send",
            "target": "vendor-42",
            "payload": dict(PAYLOAD),
            "spend_cents": spend,
        }
        fields.update(overrides)
        return ActionRequest(**fields)
