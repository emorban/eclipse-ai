# Eclipse AI — Engineering Highlights

## Persistent memory as a system boundary

Long-term memory is useful only if the system can distinguish durable facts from transient context. Eclipse treats memory as an explicit interface with deliberate writes and scoped retrieval rather than as an automatic transcript archive.

The public sample keeps storage in memory for simplicity, but the boundary is the important part: callers add normalized records through one interface and retrieval returns ranked matches rather than exposing arbitrary internal storage.

See [`../samples/memory_store.py`](../samples/memory_store.py).

## Capability-aware tool routing

Tools are registered with capability metadata. A state-changing tool is not interchangeable with a read-only lookup.

The public router requires an explicit write permit before invoking any tool marked `writes_state=True`. A production system can extend that same idea with scoped permissions, approval state, identity, audit logs, environment restrictions, and target validation.

See [`../samples/tool_router.py`](../samples/tool_router.py).

## Delegation is not proof

Multi-agent systems make it easy to mistake a worker response for completion. Eclipse separates **claim** from **verification**: a worker can report that it produced outputs, but the parent workflow still checks the required evidence before accepting the task as complete.

See [`../samples/verification_gate.py`](../samples/verification_gate.py).

## Capability preflight

Before delegating work, the system should ask whether the selected execution context can actually perform it. Examples include host filesystem access, network access, credentials, package installation, or permission to write state.

If the worker lacks a required capability, delegation is the wrong execution path regardless of how capable the model itself is.

## Runtime truth over remembered truth

Persistent memory becomes dangerous when it is treated as live configuration. Eclipse therefore distinguishes contextual memory from operational truth. Current files, service health, configuration, and provider responses should be checked when the answer depends on present system state.

## Safe write boundaries

Read-only verification is usually safe to automate broadly. Writes require tighter scope. A robust write path should know:

- what is being changed
- which authority permits it
- which target is affected
- whether preconditions still hold
- what evidence confirms success
- how failure is surfaced

This pattern matters whether the action is editing a file, changing infrastructure, sending communication, or mutating application state.

## Approval kernel (reference implementation)

[`../approval_kernel`](../approval_kernel) is a standalone, stdlib-only implementation of that write boundary, written for this public repository. It is not the private runtime code. It turns the checklist above into enforced invariants:

- an agent proposes an **immutable, versioned candidate** whose payload is hashed in canonical JSON form
- an owner decides through a **single-use challenge** bound to one exact candidate version, signed with a session secret the agent never holds
- each decision is appended to a **hash-chained ledger** in SQLite. Triggers block edits, and a keyed verifier detects edits, deletions, reordering, and rewrites
- approval mints a **scoped, expiring authority token**, checked again at use time against the latest version, the ledger state, and an atomically enforced attempt and spend budget

See [`../approval_kernel/README.md`](../approval_kernel/README.md) for the invariants and threat model.

## Verification before completion

A task should be considered complete only when its acceptance criteria can be observed. Depending on the task, that might mean:

- a required file exists
- a test passes
- a service reports healthy
- an expected record was written
- a deployment is serving the expected version
- a downstream system confirms the change

The verification layer prevents “the agent said it finished” from becoming the system’s source of truth.

## Testing philosophy

The public repository uses Python’s standard library so the examples remain easy to inspect and run. Tests focus on the core contracts:

- approval-boundary invariants under adversarial input (tampering, replay, expiry, scope escalation, concurrency)
- memory normalization and retrieval
- rejection of unauthorized writes
- rejection of unknown tools
- failure when required completion evidence is missing

The private runtime uses broader operational verification; those details are intentionally excluded from this portfolio.

## Product-engineering lesson

The deeper Eclipse became, the less the main challenge was model intelligence. The harder problems were **state, authority, delegation, verification, and failure handling**. Those are conventional systems problems applied to a new agentic interface — and they determine whether an AI system is merely impressive in a demo or dependable in real use.