# Eclipse AI — Product & Engineering Case Study

## The problem

Most AI assistants are strongest inside a single conversation. They can reason about a request, but useful work in a real operating environment raises harder systems questions:

- What should persist after the conversation ends?
- How should the system decide which tool or agent can act?
- How do you keep a read from becoming an accidental write?
- How do you know delegated work actually completed?
- What happens when memory disagrees with current runtime state?
- Where should human approval remain mandatory?

Eclipse was built as an exploration of those questions around a persistent local AI operating environment.

## Product thesis

The useful product is not “a smarter chatbot.” It is a **coordinated system around the model**: memory, tools, specialized agents, explicit authority boundaries, verification, and recovery behavior.

The design goal is to make the system more dependable as the number of workflows grows rather than simply giving one model more context.

## Design decisions

### 1. Long-term memory is opt-in
A persistent assistant should not automatically store every interaction. Durable memory needs deliberate promotion rules so temporary ideas, errors, and stale assumptions do not silently become long-term truth.

### 2. Tool capability is part of the contract
The system should know whether a capability reads information or changes state. That classification can then drive approval requirements, routing, auditability, and test coverage.

### 3. The parent agent owns completion
Sub-agents are workers, not sources of truth. The coordinator can delegate research, implementation, or verification, but it should independently check whether the requested artifact or state exists before declaring success.

### 4. Runtime truth outranks remembered truth
Persistent context is useful until the world changes. Configuration, files, health checks, provider responses, and current system state should override stale memory when they disagree.

### 5. Consequential authority stays explicit
Automation becomes more useful as it can do more, but usefulness does not require unrestricted autonomy. Writes and consequential actions should remain gated by clear scope, explicit authority, and observable execution.

## Representative failure modes

The most important lessons came from failure cases rather than happy-path demos:

- a delegated task returned success even though the target artifact did not exist
- a worker lacked the host capability required for the task
- remembered configuration became stale after the runtime changed
- multiple execution paths created inconsistent assumptions about who owned state
- automation could appear healthy while a required downstream dependency was unavailable

Those failures pushed the architecture toward **capability preflight, explicit write boundaries, evidence-based completion, and live-state verification**.

## Public examples

This repository contains intentionally small examples rather than copied private runtime code:

- `memory_store.py` demonstrates an explicit memory write/retrieval boundary
- `tool_router.py` demonstrates capability-aware tool registration and write permission
- `verification_gate.py` demonstrates the distinction between a completion claim and verified evidence

Each sample has executable tests and the repository runs them in GitHub Actions.

## What I owned

I defined the operating model and architecture for Eclipse: how memory should behave, how tasks should be classified, how agents and tools should be separated, where approval belongs, how delegation should be verified, and what “done” means for an automated task.

I also directed implementation, reviewed agent-generated and hand-authored code, investigated failure modes, established reliability rules, and tested the system against real operational workflows.

## Why this is a public portfolio instead of the production repository

A persistent personal AI system naturally accumulates information that should never be public: operator memory, current projects, credentials, machine paths, provider configuration, recovery procedures, and task history.

The public portfolio therefore preserves the **engineering ideas and representative implementation patterns** while the live Eclipse environment remains private.

## What this demonstrates for product / engineering roles

Eclipse is useful as a portfolio project because it sits between product thinking and systems engineering. The work requires reasoning about:

- user trust and automation boundaries
- distributed task ownership
- state and source-of-truth design
- testability and observability
- failure recovery
- agentic system architecture
- operational UX, not just model UX

The core lesson is simple: as AI systems gain tools and persistence, **verification and authority become as important as intelligence**.