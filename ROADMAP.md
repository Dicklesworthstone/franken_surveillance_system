# Franken Surveillance System roadmap

This roadmap is an implementation-order guide. The bead graph, normative architecture, stable registries, qualification lanes, and release gates remain authoritative. A checked box here means the stated reference capability exists; it does not imply production qualification.

The accepted [Blender twin integration plan](BLENDER_TWIN_INTEGRATION_PLAN.md) is the
detailed companion for existing-model import, automatic camera registration, world
tracking, and predictive handoff. Its [implementation crosswalk](docs/BLENDER_TWIN_IMPLEMENTATION_TASKS.md)
links the work to existing FSS requirements and beads without changing their status.

## Phase 0 — Constitutional repository and deterministic kernel

- [x] Rust 2024 workspace on the pinned toolchain.
- [x] Workspace-level prohibition of memory-unsafe Rust.
- [x] Stable identity, canonical encoding, digest, time, and error contracts.
- [x] Layered architecture, dependency, stable-ID, policy, and release registries.
- [x] Repository-owned policy, dependency, manifest, Rust, agent, and release qualification entrypoints.
- [ ] Keep layered integrity manifests synchronized with every tracked source revision.
- [ ] Close all source/registry/schema drift beads with retained before-and-after evidence.

## Phase 1 — Evidence, custody, and canonical authority

- [x] Immutable sensor capsules and uncertain capture intervals.
- [x] Coverage witnesses and explicit negative-evidence semantics.
- [x] Content-addressed in-memory object graph and child-first/root-last publication.
- [x] Ordered reference `EvidenceDeltaBatch` authority ledger.
- [x] Durable journal recovery and incomplete-tail policy.
- [x] Deterministic virtual source, delivery mutation, replay bundle, and mock-model path.
- [ ] Production object storage, MVCC ledger, rebuild, backup, restore, retention, and graph-complete deletion.
- [ ] ATP replication with complete custody and availability proofs.

## Phase 2 — Event and external-effect reference path

- [x] Evidence-linked event hypotheses and conservative unknown-presence policy.
- [x] Independent-failure-domain requirement before alert preparation.
- [x] Prepare/commit/watch/reconcile/terminal publication grammar.
- [x] Idempotency, obligations, local operation receipts, and indeterminate outcomes.
- [x] Guarded situation projection that requires exact `Prepared` state before exposing commit.
- [x] Verified-delivery, lost-acknowledgement, and proved-failure reference scenarios.
- [ ] Production notification boundary, adapters, retries, provider lookup, and retained delivery qualification.
- [ ] Complete cancellation, disconnect, crash, timeout, and compensation campaigns.

## Phase 3 — Agent cognitive operating membrane

- [x] Contract basis and orthogonal epistemic/provenance/hypothesis state.
- [x] Possible-world envelope with protected adversarial residuals.
- [x] Capability-valid affordance frontier and categorized control envelope.
- [x] Situation frame, situation capsule, deterministic publication, and root-closed handoff.
- [x] Full multidimensional resource state and action costs.
- [x] Semantic context pack and critical-preserving compression receipt.
- [x] Meaningful-delta classification with protected non-coalescible transitions.
- [x] Silence certificates and exact continuation streams.
- [x] Immutable semantic handles and deterministic H0–H4 hydration reference behavior.
- [ ] Bind every expansion reference in every registered view to an exact semantic-handle descriptor.
- [ ] Durable mission, objective, session, symbol-table, workspace, and handoff-resume stores.
- [ ] Attention frontier, investigations, hypotheses, information-value acquisition, contingent plans, execution episodes, and learning proposals.
- [ ] Multi-agent work claims, leases, transfer, duplicate prevention, and orphan recovery.
- [ ] Canonical Rust API/CLI/MCP/TUI/report/subscription payload equivalence.

## Phase 4 — Native sensing, media, models, and graph intelligence

- [ ] Qualified camera discovery, transport, authentication, continuity, and health adapters.
- [ ] Pure-Rust media ingest, decode/encode, timing, geometry, calibration, and archive path.
- [ ] Pure-Rust model package verification, execution, batching, calibration, generation transition, and fallback.
- [ ] Certified graph/search algorithms with witnesses, incremental maintenance, and deterministic fallback.
- [ ] Owner-authorized drone capture, explicit flight control boundary, geofence, battery, and evidence custody.
- [ ] Existing Blender twin import into native immutable visual/geometric/behavioral representations.
- [ ] Evidence-linked localization atlas and robust 2D-to-3D camera registration.
- [ ] Terrain-aware world tracks retaining class, posture, support, and shared uncertainty.
- [ ] Next-camera, occlusion-emergence/frame-region, and capture/availability-time forecasts.
- [ ] Human/animal/unknown trajectory priors with protected off-path alternatives.
- [ ] Live twin/calibration/clock/coverage invalidation and native inspection views.
- [ ] Interoperability laboratory campaigns against retained foreign oracles without admitting foreign runtimes into production.

## Phase 5 — Security, privacy, retention, and operations

- [ ] End-to-end capability projection and privacy transforms across all reads and effects.
- [ ] Key management, secret isolation, audit export, tamper evidence, incident response, and recovery drills.
- [ ] Retention schedules, legal holds, derivative lineage, deletion completeness, and deletion proof.
- [ ] One-version-universe upgrade, rollback, stale-generation, and mixed-binary refusal campaigns.
- [ ] Bounded service topology, cancellation drains, pressure degradation, observability, and resource accounting under Asupersync.

## Phase 6 — Qualification and release

- [ ] Complete every required deterministic reference, property, metamorphic, differential, fault, crash, cancellation, migration, security, privacy, performance, and end-to-end test family.
- [ ] Meet QL-AGENT task-correctness, calibration, hazardous-action, evidence-use, continuity, operator-burden, and full-resource thresholds.
- [ ] Pass GATE-115 for the agent cognitive operating membrane.
- [ ] Pass native adapter, media, model, graph, storage, security, privacy, platform, upgrade, rollback, and canary gates.
- [ ] Assemble signed artifacts with complete dependency, source, toolchain, platform, and custody receipts.
- [ ] Publish the complete locally qualified GATE-120 release root child-first and root-last.

## Near-term critical path

The existing agent/custody critical path remains:

1. finish FSS-210 schema/registry and context-pack binding;
2. implement durable session and symbol-table semantics over the existing exact cursor and hydration contracts;
3. extend real-entrypoint rehearsals through hydration, handoff, stale descriptor, lost acknowledgement, cancellation, and resume;
4. prove cross-surface canonical equivalence before adding independent presentation logic;
5. integrate persistent custody, retention, and deletion before treating H3 as production source access;
6. accumulate retained QL-AGENT evidence and advance GATE-115 only when all required dimensions are terminal.

### Parallel twin-to-handoff critical path

Prioritize these vertical capabilities alongside the existing agent/custody work,
using reference fixtures until live media and runtime prerequisites qualify:

1. freeze the neutral export contract and import an actual evaluated scene;
2. prove coordinate conversions, support queries, and robust supplied-correspondence PnP;
3. automate matching with the source-image/landmark atlas and bounded alternatives;
4. retain 2D observations while estimating terrain-aware world tracks;
5. demonstrate next-camera, frame-region, and time predictions on two-camera recordings;
6. add class-conditioned route priors without deleting protected off-path hypotheses;
7. qualify live invalidation, privacy, cancellation, resource pressure, and Blender-absent operation.

Existing-twin installation does not require another reconstruction or simultaneous
drone flight when unchanged static landmarks suffice. The manual shuttle remains
available for missing geometry, scale, or time evidence. Reconcile affected bead
dependencies explicitly before implementation; imported data does not bypass
calibration, custody, or GATE-070/080/115 evidence. All new runtime items above are
unchecked because adopting a plan is not implementing or qualifying its features.
