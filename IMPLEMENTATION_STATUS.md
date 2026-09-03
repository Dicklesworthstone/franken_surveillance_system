# Implementation status

**As of:** 2026-09-03  
**Project state:** pre-release deterministic reference implementation; not production-qualified  
**Release authority:** repository-owned local qualification and retained DSR receipts, not hosted CI

## Executive summary

Franken Surveillance System now has a coherent, dependency-light Rust reference spine from immutable source evidence through canonical authority state, guarded external effects, agent situation projection, meaningful deltas, exact continuation, and progressive semantic hydration. The repository is no longer merely an architecture corpus or crate skeleton.

It is also not a complete surveillance product. Native device adapters, production media/model/graph/storage services, persistent distributed operation, every human and agent surface, complete qualification matrices, and the aggregate release root remain open. Status below distinguishes implemented reference semantics from production completion.

## Implemented deterministic reference spine

### Canonical authority, evidence, and custody

- Stable typed identities and canonical encoding.
- Content digests and root-closed object manifests.
- Immutable sensor capsules and capture-time uncertainty intervals.
- Coverage witnesses and explicit negative-evidence boundaries.
- Ordered `EvidenceDeltaBatch` authority history and exact `LedgerAnchor` succession.
- Durable reference journal recovery with incomplete-tail policy.
- Child-first, root-last publication into the reference ledger.
- Deterministic virtual acquisition, transport mutation, replay bundles, and mock-model execution.

### Events, policy, and effects

- Evidence-linked event hypotheses with explicit lifecycle state.
- Reference unknown-presence policy that requires independent failure domains before alert preparation.
- Separate alert prepare, commit, provider observation, reconciliation, and terminal publication stages.
- Idempotency identities, operation receipts, obligations, and indeterminate-effect retention.
- Guarded situation projection: only an exact local `Prepared` receipt preserves commit; missing or later operation state exposes status/reconciliation.
- Rejection of forged, structurally inconsistent, stale, or mismatched effect receipts.

### Agent situation and control membrane

- `ContractBasis`, `KnowledgeCell`, `PossibleWorld`, `WorldEnvelope`, `ActionAffordance`, `SituationFrame`, `SituationCapsule`, and root-closed handoff contracts.
- Conservative distinction among known, estimated, unknown, conflicted, stale, not observable, redacted, indeterminate, and not applicable state.
- Retention of protected high-consequence worlds rather than rank-only pruning.
- Categorized control envelope for robust, conditional, information-gathering, wait, blocked, and unavailable affordances.
- Full multidimensional resource state and action cost, including latency, tokens, bytes, model calls, CPU, accelerator, energy, network, storage operations, privacy exposure, and operator attention.
- Proof-bearing semantic context packs and compression receipts with critical-preservation checks and priced expansion handles.
- Deterministic reference situation publications binding situation, control, resources, context, compression, and proof roots.

### Meaningful change and continuation

- Deterministic `MeaningfulDelta` comparison between exact situation publications.
- Protected non-coalescible classes for contradictions, coverage loss, plan invalidation, obligation change, external-effect uncertainty, authority/policy change, and terminal transitions.
- Explicit tracking of known-premise removal and contradiction resolution.
- Separation of resource pressure from material world change.
- Silence certificates proving no decision-relevant change, including across harmless successor commits.
- Exact continuation streams with content-bound entries, page digests, monotone positions, expiry, stream identity, contract basis, anchor, view, and session checks.

### Semantic handles and H0–H4 hydration

The FSS-210 deterministic reference slice is implemented:

- immutable `SemanticHandle` identity over the exact subject;
- independently versioned descriptor digests for delivery policy and availability;
- contiguous H0–H4 hydration ladders;
- exact per-level capability and full-vector cost maps;
- distinct privacy class and transform identity;
- typed available, superseded, deleted, expired, corrupt, privacy-transformed, and not-observable states;
- exact `HydrationRequest`, `HydrationArtifact`, `HydrationReceipt`, and `HydrationResponse` contracts;
- deterministic reference descriptor/artifact catalog;
- exact descriptor lookup rather than silent “latest” substitution;
- capability, privacy, H4-purpose, and resource enforcement;
- explicit lower-level downgrade only when permitted;
- proof-root closure and exact progressive continuation;
- tamper, rebinding, cursor-misuse, deletion, expiry, denial, downgrade, and deterministic-replay tests;
- external-consumer coverage of the public `fss-core` API.

FSS-210 remains **in progress**, not complete. Machine schemas/registries, persistent custody and retention proofs, every public surface, fault schedules, aggregate qualification, and GATE-115 evidence remain outstanding.

## Qualification currently represented in the repository

The repository contains executable policy, Rust, agent-reference, manifest, dependency, and release-assembly lanes. The implemented Rust contracts include focused unit, integration, adversarial, durability, replay, effect-fault, situation-projection, meaningful-delta, continuation, compression, and hydration tests.

A passing developer run demonstrates the exact checked tree only. It does not by itself establish production claims, hardware interoperability, model quality, privacy compliance under every deployment, or aggregate release qualification. Those require retained lane receipts and the declared qualification roots.

## Work packages still materially open

### Production runtime and boundaries

- Asupersync-owned production service topology, cancellation/drain evidence, and bounded concurrency across all processes.
- Native camera discovery, transport, codec/media, calibration, archive, drone, notification, and vendor-boundary implementations.
- Persistent FrankenSQLite/FrankenFS/ATP integration beyond the deterministic in-process reference stores.
- Production pure-Rust model runtime, package verification, generation management, batching, calibration, and fallback.
- Certified graph/search kernels and incremental graph intelligence.

### Agent operating system

- Durable mission/objective/session/workspace stores and complete state machines.
- Session-local symbol tables with stale-alias recovery and non-disclosure.
- Attention frontier, investigation/hypothesis workspace, information-value acquisition, contingent planning, execution episodes, outcome attribution, and learning promotion.
- Multi-agent work claims, leases, transfer, duplicate-work prevention, cancellation, and orphan-obligation recovery.
- First-class binding of every context-pack expansion reference to a published semantic-handle descriptor.
- Equivalent typed payloads and decision digests across Rust API, CLI, MCP, TUI, reports, subscriptions, and handoffs.

### Security, privacy, retention, and deletion

- End-to-end capability/privacy projection over every hydration, export, retention, and effect path.
- Persistent retention schedules, legal holds, graph-complete deletion, derivative accounting, and deletion proof.
- Secret-bearing boundary isolation, key management, audit export, incident response, and recovery drills.
- Complete stale/rollback/downgrade and one-version-universe enforcement across deployed binaries and stored objects.

### Qualification and release

- Remaining deterministic reference, property, metamorphic, differential, fault, crash, cancellation, lost-acknowledgement, disconnect, multi-agent, pressure, migration, upgrade, rollback, and full mission rehearsals.
- Complete `TEST-AGENT-*`, adapter, model, graph, storage, security, privacy, and performance families.
- QL-AGENT aggregate thresholds for correctness, calibration, hazardous-action rate, evidence use, handoff continuity, operator burden, and full resource cost.
- GATE-115 agent qualification and the later native platform/release gates.
- Locally produced, root-last GATE-120 release qualification root.

## Requirement-status guidance

- **Implemented reference slice:** deterministic code and focused executable tests exist for the named semantics.
- **In progress:** important acceptance dimensions remain, such as schemas, other surfaces, persistent integration, fault evidence, or aggregate qualification.
- **Qualified:** every required lane has retained proof for the exact source, dependency, toolchain, platform, and artifact identity.
- **Released:** the complete local release root has been published after artifact custody, native matrix, canary, upgrade, rollback, and public verification.

No task should be closed solely because a neighboring type, schema, shared helper, or happy-path demo exists.

## Immediate optimal sequence

1. Finish FSS-210 schema/registry and context-pack binding without weakening immutable-handle semantics.
2. Implement the next session-oriented contract on top of exact continuation and hydration rather than inventing another cursor or expansion dialect.
3. Extend the reference mission rehearsal through typed hydration, handoff, stale descriptor, lost acknowledgement, and cancellation outcomes.
4. Establish cross-surface canonical payload equivalence before multiplying presentation-specific features.
5. Integrate persistent custody/retention and deletion proofs before claiming H3 source-evidence production readiness.
6. Accumulate retained QL-AGENT evidence and only then advance GATE-115 status.

## Known status limitations

- Repository integrity manifests must be regenerated whenever tracked source or documentation changes; a stale manifest is a repository-policy failure, not an ignorable cosmetic difference.
- Hosted workflow results are supplementary and may be queued or cancelled by concurrency. They are not substitutes for local retained receipts.
- The large bead graph encodes complete program acceptance. This document summarizes implementation state and does not override bead dependencies, registries, schemas, ADRs, or qualification gates.
