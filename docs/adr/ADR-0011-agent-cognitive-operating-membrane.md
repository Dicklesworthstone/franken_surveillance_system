# ADR-0011 — Agent cognitive operating membrane

**Status:** accepted design decision  
**Date:** 2026-08-31  
**Decision owners:** `fss-agent-core`, `fss-agent-session`, `fss-situation`, `fss-investigation`, `fss-affordance`, `fss-agent-plan`, `fss-handoff`  
**Gate:** `GATE-115` / `QL-AGENT-001`

## Context

FSS spans devices, packet continuity, media, storage, models, geometry, graph/search, policy,
effects, archive, privacy, and repair. Exposing those subsystems directly would make every agent
reconstruct the world model, state machine, authority boundaries, uncertainty, prerequisites, and
next-step logic in its context window. That architecture would spend tokens and calls on repeated
bookkeeping, encourage stale mixed-generation reasoning, and make correct long-horizon control
fragile.

A single prose summary is not a solution. It hides omissions, provenance, contradictions,
coverage, validity, cost, and authority. A very large tool catalog is also not a solution: tool
names do not encode a coherent operating model, and domain-specific handlers tend to accumulate
unique semantics.

## Decision

FSS adopts an **agent cognitive operating membrane** above the packet, authority, cognition, and
effect planes. The membrane is not a source of physical truth and does not own effect outcomes. It
composes lower semantic owners into one mission-relative, anchor-pinned, budgeted, capability-
projected cognitive and control surface.

The canonical object hierarchy is:

```text
MissionContract → ObjectiveContract
AgentSession → versioned AgentWorkspace → AgentSessionCapsule
SituationCapsule
  ├─ SituationFrame
  │    └─ WorldEnvelope
  │         ├─ nominal estimate
  │         ├─ certified core facts and certified absences
  │         ├─ material alternative worlds
  │         ├─ protected adversarial residuals
  │         ├─ common invariants and unresolved dimensions
  │         └─ discriminating/collapse affordances
  ├─ MeaningfulDelta
  ├─ ContextPack + SemanticCompressionReceipt
  ├─ active cases/plans/obligations/resource state
  ├─ controlEnvelope: robust/conditional/probe/wait/blocked
  └─ ActionAffordance frontier
InvestigationCase → HypothesisWorkspace / AgentFinding / probes / stop rules
ControlPlan → witnessed contingent DAG → prepared domain effects
ExecutionEpisode → ExperienceCapsule → FeedbackProposal / LearningProposal
HandoffCapsule → root-last minimum-sufficient continuity graph
```

The public `fss/1` semantic grammar is limited to:

```text
session.open · session.resume · session.orient · session.follow
query · investigate · plan · commit · wait · cancel · explain
handoff · feedback · doctor
```

Domain-specific behavior is represented by typed targets, queries, intent families, views,
evidence handles, and prepared effects. CLI, Rust API, MCP, TUI, reports, and future desktop/mobile
surfaces render the same operation and view registries. A transport may omit an unqualified
operation, but it may not redefine one.

Knowledge state, provenance class, hypothesis disposition, access transformation, and operation/
effect outcome are orthogonal fields. The primary driver publication is `SituationCapsule`; its
inner `SituationFrame` is the minimum sufficient mission-relative world model. That frame carries
one exact `WorldEnvelope`: not a single overconfident guess, but the certified core plus every
materially decision-distinct world still compatible with authorized evidence, including protected
high-consequence adversarial residuals. Compact projections carry `SemanticCompressionReceipt` and
priced hydration handles.

The capsule closes an **evidence → possibilities → control** loop. Its `controlEnvelope` classifies
each nondominated affordance as robust across all protected worlds, conditional on named worlds and
discriminating evidence, information-gathering, wait/watch, or blocked. A consequential effect may
be recommended only when it is robust across the protected world set or when the exact branch
condition, approval, rollback/reconciliation plan, and residual risk are explicit. Ranking or token
pressure may never remove a protected world. Recommendations are hard-clamped, component-explained,
and never confer effect authority.

Mission-critical continuity cannot reside only in conversational context. Sessions, workspaces,
cases, findings, plans, obligations, work claims, episodes, and handoffs are immutable revisions or
root-last object graphs. Long work is region-owned and survives request disconnect; cancellation
means request, drain, reconcile/compensate, and finalize.

Resolved work may generate evidence-linked learning proposals, fixtures, hard negatives,
procedures, or anti-patterns. Learning remains advisory until explicit validation and promotion;
trauma-guard evidence can demote, retire, or invert harmful transfer.

## Consequences

### Positive

- A cold or resumed agent can understand the current mission, situation, epistemic limits,
  obligations, resource pressure, and valid next moves without manually joining subsystem calls.
- Every summary remains mechanically connected to exact lower evidence and generations.
- The agent can distinguish what is invariant across possible worlds from what depends on one
  interpretation, and can choose a robust action or the cheapest useful discriminator accordingly.
- Uncertainty, contradiction, absence, redaction, staleness, and indeterminate effects cannot be
  hidden behind prose or a confidence scalar.
- The system can optimize task quality per complete resource vector rather than call count.
- Multi-agent work can coordinate through immutable findings and bounded work claims without
  shared-scratch races or effect-authority leakage.
- Handoff and accumulated experience become measurable system capabilities rather than prompt
  conventions.
- Presentation transports can be different while semantics remain identical and testable.

### Costs

- The object/schema/registry surface is larger than a conventional REST or MCP wrapper.
- Situation composition, context selection, affordance ranking, and handoff publication require
  deterministic reference implementations and task-level evaluation corpora.
- The design refuses easy but misleading shortcuts such as raw dumps, generic tool escape hatches,
  opaque recommendation scores, and autonomous memory mutation.
- Some useful operations will remain unavailable on a transport until its cancellation,
  bidirectional, output-commitment, and continuity semantics are qualified.

## Alternatives rejected

1. **One tool per subsystem command.** Rejected because it transfers ontology/state-machine work to
   the agent and creates privileged escape hatches.
2. **One universal natural-language agent endpoint.** Rejected because interpretation, taint,
   authority, cost, and effect boundaries become opaque.
3. **Raw world snapshot plus model reasoning.** Rejected because it is token-expensive, mixes
   generations, hides absence/coverage limits, and weakens replay.
4. **Autonomous agent memory that rewrites policy.** Rejected because experience is not current
   truth or authority and harmful transfer is inevitable.
5. **A fourth canonical agent truth plane.** Rejected because situation and planning are derived
   composition; authority and effect truth retain their existing owners.
6. **Conversation as workspace/handoff.** Rejected because it is unversioned, non-portable,
   non-auditable, and cannot survive model/session boundaries safely.

## Required evidence

`QL-AGENT-001` must retain:

- cold/warm orientation and minimum-sufficiency/omission-counterfactual receipts;
- epistemic/provenance/hypothesis fidelity and absence/coverage tests;
- meaningful follow/silence/interrupt/disconnect/resume tests;
- hypothesis/VOI/stop-rule and affordance/Pareto/sensitivity tests;
- plan/effect/obligation closure under crash, stale-anchor, duplicate, and lost-ACK schedules;
- multi-agent claim/finding and capability-noninterference tests;
- root-last handoff/rebase under generation/authority/schema drift;
- learning/trauma-guard/harmful-transfer tests;
- cross-surface semantic equivalence and robot-documentation checks;
- task correctness, calibration, evidence use, unsafe-action rate, full resource cost, operator
  intervention, handoff loss, and accretion metrics.

## Machine and normative sources

- `AGENT_COGNITION_AND_CONTROL.md`
- `AGENT_COGNITIVE_CONTROL_PLANE.md`
- `AGENT_OPERATING_MODEL.md`
- `architecture/agent_contracts.json`
- `architecture/agent_abstraction_stack.json`
- `architecture/agent_operating_model.json`
- `architecture/agent_operations.json`
- `architecture/agent_views.json`
- `registries/AGENT_CONTRACTS.md`
- `registries/AGENT_ABSTRACTIONS.md`
- `registries/AGENT_OPERATIONS.md`
- `registries/AGENT_VIEWS.md`
