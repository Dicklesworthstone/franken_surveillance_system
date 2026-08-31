# AGENTS.md

Read this entire file and `COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md` before editing.
The repository is designed for autonomous coding agents, but it does not permit an agent to infer
missing authority, lower a gate, or replace a specified architecture with a quick substitute.

## Prime directive

Build a deterministic, evidence-native semantic control plane for owner-authorized physical
sensors. Preserve uncertainty and provenance. Keep cognition derived. Make effects explicit,
idempotent, capability-scoped, and later verifiable. Make the whole system legible through the one
canonical linked abstraction tower: runtime authority/custody → source evidence → world facts and
coverage → derived beliefs → SituationCapsule → investigation/hypotheses → affordance frontier →
plan/effect/obligation → outcome/episode → learning/memory → workspace/handoff. Mission and
ObjectiveContract, semantic protocol, privacy/capability projection, and full cost are cross-cutting
coordinates, not rival layers.

## Truth hierarchy

1. Machine-readable registries and versioned schemas.
2. Normative comprehensive plan and ADRs.
3. Tests and retained proof bundles.
4. Implementation.
5. Explanatory documentation.

When these disagree, do not choose the most convenient one. Record the drift, identify the owning
contract, and repair the set coherently.

## Non-negotiable architecture

- Rust 2024 on the pinned nightly toolchain.
- Asupersync only for asynchronous orchestration; no Tokio adapters hidden behind features.
- `#![forbid(unsafe_code)]` in every FSS workspace crate, target, example, test, and build helper; there is no local exception path.
- Production media, model, graph, storage, and protocol semantics are first-party pure Rust. Foreign frameworks/applications are laboratory or migration oracles only.
- `Cx` or an equivalent explicit authority reaches every I/O, time, sleep, lock, network,
  secret, effect, and sealed laboratory-oracle process boundary.
- Region ownership; cancellation is request→drain→finalize; no orphan work.
- Authority, cognition, and effect planes are type-distinct.
- Canonical history is one ordered `EvidenceDeltaBatch` universe. Derived state is anchor-pinned and rebuildable.
- Negative reads require `CoverageWitness`; semantic plans require read/write witnesses.
- ATP moves immutable object graphs only and never carries effect authority.
- Root-last publication distinguishes staged, visible, durable, replicated, protected, and retrievable states.
- Graph algorithms use registered projections, CGSE tie-breaks, and complexity/output witnesses.
- Immutable model/device/config generations.
- Stable IDs are never renumbered; superseded entries remain tombstoned.
- AgentSession, AgentWorkspace, ContractBasis, universal request/response envelopes,
  SituationCapsule, SituationFrame, WorldEnvelope, ContextPack, investigation,
  affordance, plan, episode, and handoff semantics come from the agent machine registries; no
  transport invents a parallel vocabulary.
- Knowledge state, provenance class, hypothesis disposition, access transform, and effect outcome
  remain orthogonal typed fields.
- No mission-critical fact, assumption, obligation, lease, indeterminate effect, or next step may
  exist only in conversational context.
- Compact agent outputs require a semantic compression receipt and priced evidence-hydration
  handles; recommendations require a decomposed nondominated affordance frontier.
- Protected high-loss possible worlds cannot disappear through ranking, model reranking,
  compression, transfer, view changes, or handoff. Every action is classified as robust,
  conditional, information-gathering, wait/watch, blocked, or unavailable against the exact
  `WorldEnvelope`; plans bind its digest and name supported and unsafe worlds.

## Workflow

1. **Restore the mission:** inspect the latest `AgentSessionCapsule`/handoff, current authority,
   active obligations, work claims, invalidations, and negative evidence. Never rely on remembered
   chat state.
2. **Orient from one anchor:** request or construct the smallest sufficient `SituationCapsule` and
   verify its exact `ContractBasis`, inner `SituationFrame`/`WorldEnvelope`, epistemic map,
   compression receipt, resource pressure, and categorized control envelope.
3. **Establish scope:** stable requirement IDs, mission/objective contract, files, authority changes,
   migrations, budgets, affected planes, and qualification gates.
4. **Preserve alternatives:** for uncertain work, create/revise an `InvestigationCase` with
   competing hypotheses, evidence, contradictions, predicted observations, falsifiers, shared
   failure domains, probe costs, and stop rules.
5. **Implement the smallest coherent vertical contract:** begin with deterministic reference
   behavior, explicit failure states, stable handles, and the agent-facing projection—not a fake
   end-to-end demo or isolated subsystem trick.
6. **Make the next move legible:** expose typed nondominated affordances after capability/privacy/
   safety clamps, with value, cost, risk, reversibility, invalidators, and expected proof. A
   recommendation never grants effect authority.
7. **Close the loop:** consequential work is objective → witnessed plan → prepare → revalidate →
   commit → wait/cancel → observe → verify/reconcile. Leave every obligation terminal, delegated,
   or explicitly indeterminate.
8. **Add failures first:** cancellation, packet gaps, clock skew, corrupt data, stale firmware,
   model crash, partial archive publication, duplicate requests, stale workspaces, handoff drift,
   missing coverage, and ambiguous effects.
9. **Qualify as an agent task:** run direct local qualification plus deterministic reference,
   differential, fault, semantic-compression, handoff, multi-agent, and resource-economy lanes.
   Workflow YAML contains no unique logic.
10. **Accrete carefully:** produce evidence-linked findings, episodes, negative evidence, fixtures,
    anti-patterns, or learning proposals. Do not silently activate policy/model/threshold/authority
    changes.
11. **Publish a typed handoff:** before ending work, persist current mission, situation roots,
    cases, findings, plans, obligations, unknowns, invalidations, budgets, authority, continuations,
    and valid next affordances.
12. **Update status honestly:** documentation and evidence pointers may not upgrade a claim beyond
    the proof actually retained.

## Prohibited shortcuts

- Calling adapter acceptance “streaming.”
- Calling a decoded frame “retained evidence” without source custody or an explicit omission.
- Calling one camera’s model score “corroborated.”
- Treating a missing detection during a coverage gap as evidence of absence.
- Letting a VLM trigger an effect directly.
- Mixing embeddings or scores across model generations.
- Downloading “latest” model weights at runtime.
- Storing secrets in config, logs, traces, evidence, prompts, or fixtures.
- Reusing a vendor’s cloud token outside its exact adapter capability.
- Presenting a mobile screen capture or app automation path as a stable native integration.
- Adding a global lock, mutable singleton, unbounded channel, detached thread, or unbounded retry.
- Silently changing retention, redaction, identity, or alert policy from learned feedback.
- Optimizing before the operation-cost row and semantic oracle exist.
- Adding a foreign production runtime behind IPC and calling the system pure Rust.
- Treating a green hosted workflow as release authority or publishing a partial target matrix.
- Returning raw world dumps when a bounded decision-oriented situation projection is possible.
- Hiding mission state, assumptions, obligations, or required next steps in conversation only.
- Flattening `unknown`, `not_observable`, `redacted`, `stale`, `conflicted`, or `indeterminate` into
  null, low confidence, or omitted output.
- Collapsing knowledge state, provenance, hypothesis disposition, and effect outcome into one score.
- Presenting an opaque recommendation rank without hard-clamp filtering, component values,
  alternatives, sensitivity, invalidators, and expected proof.
- Treating an agent memory, prior handoff, vendor claim, or prediction as current canonical truth.
- Coalescing away terminal transitions, coverage loss, contradictions, plan invalidation, effect
  uncertainty, or urgent obligations from a follow stream.
- Calling fewer tool calls “agent efficiency” without measuring task correctness, safety,
  calibration, full resource cost, and operator burden.

## Agent-facing output

Machine output uses the registered `AgentResponseEnvelope` and stable exit/error identities. Human
output may be richer, but it is never the only contract. Every decision-bearing response preserves:

- mission/session/workspace and exact authority anchor;
- inner `SituationFrame` or other typed payload;
- knowledge state, provenance, uncertainty, contradictions, coverage, redactions, and validity;
- evidence handles and hydration costs rather than forced bulk bytes;
- `SemanticCompressionReceipt` for bounded projections;
- consumed/remaining budget and explicit degradation;
- active plans, obligations, leases, indeterminate effects, and continuation/resnapshot state;
- valid typed affordances or an explicit terminal/blocked/waiting/unauthorized/not-observable reason;
- safe retry/rebase/reconcile/repair/approval/alternative guidance.

Explain event and control conclusions using evidence identities, model/policy/calibration generations,
shared failure domains, counterfactuals, and what evidence would change the decision. Never truncate
mid-object or omit a safety/uncertainty warning to fit a token budget; return continuations or priced
hydration handles.

## Security boundary

Interoperability work is limited to devices and accounts the operator owns or is explicitly
authorized to test. Never implement credential theft, authentication bypass, third-party account
access, broad scanning, persistence on vendor devices, or evasion. Reverse engineering must be
minimal, documented, reproducible against lab fixtures, and isolated from production credentials.

## Local release authority

`scripts/qualify.sh` is the semantic qualification entrypoint. DSR executes it from clean snapshots on controlled native hosts with exact sibling closure. GitHub workflows are portable supplementary specifications only. No agent may weaken a lane because hosted capacity is unavailable.

## Definition of done

A requirement is done only when its contract, success/failure semantics, migrations, deterministic
reference, fault tests, compatibility identity, privacy/security behavior, performance cost, proof
bundle, status, and documentation agree. “Code exists” is not a completion state.
