# FSS second-pass research ledger

**As-of:** 2026-08-31
**Purpose:** record the source material and exact design extraction performed for the second architectural pass. A source being inspected does not imply its implementation is production-ready or directly depended upon.

## Method

For each project the audit asked:

1. What mechanism is actually load-bearing for FSS?
2. What invariant does it establish?
3. Which FSS crate/process owns it?
4. What weaker imitation must be prohibited?
5. What deterministic/reference model exists?
6. What failure boundary remains when the import is unavailable?
7. What evidence admits it?

## Asupersync

Inspected:

- `README.md`
- `asupersync_plan_v4.md`
- `asupersync_v4_formal_semantics.md`
- `docs/atp_architecture.md`
- `src/atp/diagnostics/mod.rs`
- NATS integration proposal

Extracted:

- region ownership and quiescence;
- `Cx` authority/budgets;
- four-valued outcomes;
- request→drain→finalize cancellation;
- reserve/commit and obligations;
- deterministic LabRuntime, schedule exploration, trace normalization;
- cancellation progress certificates;
- ATP verified object graphs, journals, path states, verifier stages, repair;
- evidence-guided but clamped scheduling;
- semantic subject fabric, service classes, account/import-export trust graphs, packet/authority/reasoning planes.

## FrankenSQLite

Inspected:

- root README and architecture;
- `begin_concurrent.rs`;
- `commit_combiner.rs`;
- `bocpd.rs`;
- MVCC source tree.

Extracted:

- multi-version reads;
- read/write sets and SSI dangerous structures;
- semantic operation/change logs;
- safe merge/replay doctrine;
- deterministic commit sequence allocation and flat combining;
- cache-line separation and sharding;
- online regime-change detection;
- recovery/VFS/differential discipline;
- readiness honesty around partially integrated features.

## FrankenFS

Inspected:

- root README;
- comprehensive V1 spec;
- MVCC store implementation and source tree;
- release/evidence language.

Extracted:

- staged/visible/durable epochs;
- block-level MVCC and COW;
- root-last multi-artifact publication;
- rooted path capabilities;
- doctor/repair plan/apply;
- RaptorQ protection and decode drills;
- evidence ledgers and readiness dimensions;
- same-binary experiments;
- crash matrices and writeback-cache safety posture.

## Frankensearch

Inspected:

- root README;
- Quill comprehensive plan;
- FSVI/Quill architectural references.

Extracted:

- progressive two-tier retrieval;
- immutable model and generation identity;
- searchable delta vs durable seal;
- globally disjoint ID ranges and merge-by-concat;
- columnar sort-based ingest;
- schema-specialized safe SIMD;
- pinned oracles/divergence ledgers;
- derived-index doctrine and explainable score ledgers;
- graceful degradation without semantic model.

## Franken Markdown

Inspected:

- root README and planning/source references.

Extracted:

- zero-dependency pure core posture;
- exact byte spans and stable projections;
- bounded nonrecursive parsing;
- deterministic HTML/PDF/WASM parity;
- staged sibling publication and rollback;
- taint and provenance;
- source-to-output equivalence and diagnostics.

## FrankengraphDB

Inspected:

- root README;
- comprehensive-plan structure and crate census;
- calibration/chronicle/claim/delta/evidence crate families.

Extracted:

- one version universe;
- Chronicle content-addressed commit stream;
- Strata temperature-tiered relations;
- Loom FreeJoin/factorized/WCO execution;
- Ripple Z-set incremental maintenance;
- deterministic plan certificates/decision cards;
- branch-per-agent semantic merge;
- capability-before-expansion;
- hybrid text/vector/graph planning;
- closed dependency universe and unsafe boundary ledger.

## FrankenNetworkX

Inspected:

- root README and algorithm catalog.

Extracted:

- observable behavior and iteration order as contract;
- CGSE tie-break policies;
- complexity witnesses and decision-path ledgers;
- strict vs bounded hardened modes;
- differential parity;
- large algorithm catalog across paths, flow/cuts, matching, centrality, communities, trees, DAGs, temporal and spectral methods;
- self-healing conformance artifacts.

## Dwarf Fortress MCP

Inspected:

- comprehensive plan;
- Franken-stack deep dive;
- architecture registries.

Extracted:

- semantic control plane over an externally changing partially observed world;
- observation anchors and resumable deltas;
- positive/negative witnesses;
- optimistic semantic plan transactions;
- delayed-effect obligations and honest terminal outcomes;
- authoritative/cognition/effect planes;
- capability-scoped multi-agent access;
- token economy and compact evidence;
- import admission gates and substitute prohibitions.

## FastMCP Rust

Inspected:

- root README and current qualification boundaries;
- comprehensive protocol-plan structure.

Extracted:

- request-owned work and cancellation;
- bounded protocol/JSON/output surfaces;
- capability-oriented handlers;
- four-valued outcomes and budgets;
- qualification per transport/profile rather than source-presence claims;
- no generic escape hatch.

## Eidetic Engine CLI

Inspected:

- root README;
- comprehensive plan.

Extracted:

- local-first durable operational memory;
- typed memory/provenance graph;
- explainable hybrid retrieval;
- deterministic context packs;
- confidence decay and harmful-feedback trauma guard;
- anti-pattern inversion;
- explicit curation and immutable supersession;
- derived indexes and advisory-only role.

## Doodlestein Self-Releaser

Inspected:

- root README and strict release behavior.

Extracted:

- workflow YAML as single portable specification;
- local `act` plus native macOS/Windows hosts;
- clean disk-backed source snapshots;
- exact version and sibling closure;
- resumable target attempts;
- authoritative manifest withheld until all targets pass;
- signing/SBOM/source custody;
- upload followed by download-and-verify;
- structured JSON/exit semantics;
- local-first release authority.

## Agent-system synthesis pass

After the subsystem/dependency pass established the physical and computational substrate, a third
pass re-read the same projects from the driver's seat. The question changed from “which component
mechanism should FSS import?” to “which stable cognitive abstraction would let an agent understand
and control the entire fabric with minimum resource expenditure and maximum epistemic honesty?”

The synthesis combined:

- Asupersync regions, contexts, budgets, obligations, cancellation, and durable transfer roots into
  owned agent sessions, plans, waits, and handoffs;
- FrankenSQLite anchors, witnesses, immutable revision history, and rebase semantics into mission,
  workspace, case, finding, plan, and session state;
- FrankenGraphDB/NetworkX versioned projections, branches, deterministic algorithms, minimal
  subgraphs, set cover, flow, and critical path into situations, explanations, affordances, active
  perception, and multi-agent work graphs;
- Frankensearch progressive retrieval and Eidetic Engine context packing/feedback/trauma guard into
  priced evidence hydration, semantic compression, operational memory, and accretive learning;
- Dwarf Fortress MCP and FastMCP Rust's semantic intent, delayed-effect truth, bounded presentation,
  and honest indeterminacy into one public `fss/1` operation grammar;
- FrankenFS and ATP root-last custody into portable `AgentSessionCapsule`, `HandoffCapsule`, and
  `ExperienceCapsule` object graphs;
- DSR's task-level qualification into a sealed agent gauntlet measuring decision quality per full
  resource and operator cost rather than tool-call count.

The resulting canonical hierarchy is `SituationCapsule` as the primary driver publication, with an
inner mission-relative `SituationFrame`; that frame contains a `WorldEnvelope` separating the
certified core from material alternatives and protected adversarial residuals; the capsule's
`controlEnvelope` projects that possibility set into robust, conditional, information-gathering,
wait/watch, and blocked affordances. `ContextPack` plus `SemanticCompressionReceipt` is the
budget-shaped materialization; `AgentCognitiveEnvelope` is a generic decision-bearing payload; and
`AgentResponseEnvelope` is the universal lifecycle/transport wrapper. This closes the previously missing
evidence → possibilities → control bridge without creating another truth plane.

## Resulting artifacts

- `FRANKENSTACK_DEEP_DIVE.md`
- root constitutions `DEPENDENCY_CONSTITUTION.md`, `GRAPH_ANALYTICS_AND_SENSOR_MESH.md`,
  `ATP_AND_DISTRIBUTED_EVIDENCE.md`, `PURE_RUST_MODEL_RUNTIME.md`,
  `LOCAL_QUALIFICATION_AND_RELEASE.md`, `AGENT_COGNITION_AND_CONTROL.md`,
  `AGENT_COGNITIVE_CONTROL_PLANE.md`, and `AGENT_OPERATING_MODEL.md`, with policy-checked `docs/` mirrors;
- `docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md`;
- `docs/MVCC_EVIDENCE_LEDGER.md`;
- `docs/GRAPH_ALGORITHM_ATLAS.md`;
- `docs/FRANKEN_IMPORT_ADMISSION_GATES.md`;
- `docs/PERFORMANCE_AND_MECHANICAL_SYMPATHY.md`;
- `docs/LOCAL_QUALIFICATION_WITH_DSR.md`;
- machine-readable architecture registries and schemas.
- `architecture/agent_contracts.json` plus operation, view, abstraction, and operating-model registries;
- agent mission/session/situation/query/investigation/affordance/plan/episode/learning/handoff schemas;
- `QL-AGENT-001`, agent-specific decision cards, publication primitives, SLOs, costs, errors, and tests.
