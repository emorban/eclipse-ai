# approval_kernel

A public reference implementation of the **approval boundary** pattern used in Eclipse: agents may *propose* consequential actions, only an owner may *approve* them, and executors run them only with a scoped, expiring authority that still matches what was approved.

It is written from scratch for this portfolio. It is not the private Eclipse runtime, and it does not depend on any model provider. It uses only the Python standard library (`sqlite3`, `hashlib`, `hmac`, `secrets`) and targets Python 3.11+.

## Why it exists

The samples in [`../samples`](../samples) show the idea in a few lines: write-capable tools need an explicit permit. A boolean permit is not enough in a real agent system. Agents revise their plans mid-flight, approvals go stale, tokens leak, retries multiply, and logs get edited. This package makes each of those failure modes an explicit, tested refusal.

## Lifecycle

```text
agent     propose() / revise()   -> ActionCandidate  (immutable, versioned, content-hashed)
owner     open_session()         -> OwnerSession     (holds a secret the agent never sees)
owner     challenge()            -> Challenge        (single-use nonce for one exact version)
owner     approve() / reject()   -> ledger entry     (+ authority token on approve)
executor  authorize() / execute()-> Authorization    (signature, scope, live state, budget)
auditor   verify_integrity()     -> IntegrityReport  (hash chain, digests, bindings)
```

## Invariants enforced

| # | Invariant | Where |
|---|-----------|-------|
| 1 | Payloads are hashed in a strict canonical JSON form (sorted keys, no floats, no NaN, bounded depth). | `canonical.py` |
| 2 | Candidates are immutable. A revision is a new version that links to its parent digest. SQLite triggers reject `UPDATE`/`DELETE`. | `candidates.py`, `storage.py` |
| 3 | The operator registry, not the agent, sets each action type's minimum risk class. Unknown action types are refused, and a candidate cannot downgrade its risk. | `ActionRegistry` |
| 4 | `read_only` actions run without approval. `write` and `external` actions need an authority token. | `ApprovalKernel.authorize` |
| 5 | Every decision needs a challenge issued for one exact `(candidate_id, version, digest)`, a single-use nonce that has not expired, and an HMAC proof from the owner's session secret that names the decision. | `sessions.py` |
| 6 | Proposers cannot decide on their own candidates. Decisions follow a state machine: `pending -> approve/reject/expire`, `approve -> revoke`. | `kernel.py`, `ledger.py` |
| 7 | The decision ledger is append-only (triggers) and tamper-evident (keyed HMAC-SHA256 chain over contiguous sequence numbers). | `ledger.py` |
| 8 | Authority tokens are signed and expiring. They are scoped to one action type, target, payload hash, and candidate version, and they never outlive the candidate. | `authority.py` |
| 9 | At use time a token must also match the latest candidate version, an approval still in force in the ledger, and an issuance record. A validly signed token the kernel never issued is refused. | `ApprovalKernel.authorize` |
| 10 | Attempt and cumulative spend limits are enforced with one conditional `UPDATE` inside `BEGIN IMMEDIATE`, backed by `CHECK` constraints. This holds across threads and across processes that share the file. | `kernel.py`, `storage.py` |
| 11 | Time is injected, so every expiry path is tested deterministically. | `clock.py` |

## Threat model (brief)

**In scope:**
- **A buggy or manipulated agent.** It can call `propose`, `revise`, and `authorize` freely. Without an owner session secret it cannot approve. Without a matching token it cannot execute writes. It cannot widen scope by editing the payload, the target, the action type, the limits, or the token claims.
- **Stale approval.** If the agent revises a candidate after approval, or the owner revokes it, outstanding tokens stop working.
- **Replay.** Nonces are single-use and short-lived. A token's attempt budget is consumed atomically, so a replayed token cannot exceed it.
- **Direct database tampering.** Edited, deleted, or reordered ledger rows, or a rewritten chain, are caught by `verify_integrity()` as long as the attacker does not hold the ledger key. Candidate rows are re-hashed every time they are loaded.
- **Key compromise (partial).** A leaked authority key can sign tokens, but the database must also hold an issuance record bound to an approval in force. Removing a key id from the `Keyring` invalidates every token signed with it.

**Out of scope / known limits:**
- **Owner authentication.** How an owner proves identity before `open_session` (passkey, local UI, signed message) belongs to the host application.
- **Tail truncation.** Deleting the newest ledger entries leaves a shorter chain that is still valid. Persist `ledger_head()` somewhere the database writer cannot reach, and pass it as `anchor=`.
- **Symmetric keys.** HMAC keeps the package dependency-free, but every verifier holds the signing key. Executors that should only verify would need an asymmetric signature such as Ed25519.
- **What counts as an attempt.** An attempt is counted before the handler runs, so a failed execution still uses budget. This is deliberate: it is safer for actions that are not idempotent.

## Usage

```python
from approval_kernel import (
    ActionRegistry, ActionRequest, ApprovalKernel, Database, Decision,
    KernelKeys, Limits, RiskClass, sign_challenge,
)

registry = ActionRegistry({
    "files.read": RiskClass.READ_ONLY,
    "payments.send": RiskClass.EXTERNAL,
})
kernel = ApprovalKernel(
    Database("approvals.sqlite3"),
    KernelKeys.from_master(master_secret),  # 32+ bytes from your secret store
    registry=registry,
    owners={"owner:primary"},
)

# Agent side
cand = kernel.propose(
    "payments.send", "vendor-42", {"amount_cents": 1200, "memo": "hosting"},
    proposed_by="agent:planner",
    limits=Limits(max_attempts=2, max_spend_cents=1200),
    ttl_seconds=3600,
)

# Owner side (the session secret stays with the owner's client)
session = kernel.open_session("owner:primary")
challenge = kernel.challenge(session.session_id, cand.candidate_id)
proof = sign_challenge(session.secret, challenge, Decision.APPROVE)
approval = kernel.approve(session.session_id, challenge.nonce, proof, reason="expected invoice")

# Executor side
request = ActionRequest("payments.send", "vendor-42",
                        {"amount_cents": 1200, "memo": "hosting"}, spend_cents=1200)
kernel.execute(request, send_payment, token=approval.token)

# Read-only actions need no token
kernel.execute(ActionRequest("files.read", "notes.md", {}), read_file)

# Audit
anchor = kernel.ledger_head()          # store this outside the database
assert kernel.verify_integrity(anchor).ok
```

## Tests

```bash
python -m unittest discover -s tests -v
```

The approval tests live in `tests/test_approval_*.py`. Most of them are adversarial: tampered payloads, edited token claims, the wrong or an unknown signing key, replayed and cross-session nonces, expired sessions, nonces and authorities, revisions after approval, revocation, scope escalation, attempt and spend exhaustion, direct SQLite edits, deletions, reordering and full chain rewrites, tail truncation with an anchor, and 24 threads plus two separate connections racing for one limited token.
