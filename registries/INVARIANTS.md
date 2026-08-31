# Invariant registry

Stable invariant IDs are never renumbered. A superseded invariant remains as a tombstone with its replacement. Current machine source: `architecture/invariants.json`.

| ID | Invariant | Status |
|---|---|---|
| `INV-001` | Authority, cognition, and effect records are type-distinct and stored separately. | `normative` |
| `INV-002` | No model output is authoritative evidence and no model directly authorizes an effect. | `normative` |
| `INV-003` | Every retained observation names exact source bytes or records why source retention was forbidden. | `normative` |
| `INV-004` | Capture time is an interval with a declared clock basis, never an unjustified point timestamp. | `normative` |
| `INV-005` | Stream acceptance, first frame, continuity verification, and semantic detection are distinct states. | `normative` |
| `INV-006` | Every asynchronous child is owned by an Asupersync region and shutdown drains to a terminal or indeterminate receipt. | `normative` |
| `INV-007` | Consequential effects use prepare, revalidate, commit, observe, and verify semantics with idempotency. | `normative` |
| `INV-008` | Credentials are scoped to an adapter instance, never included in traces, model prompts, or evidence bundles. | `normative` |
| `INV-009` | Proprietary adapters operate only against owner-authorized devices and accounts; credential bypass is out of scope. | `normative` |
| `INV-010` | Original encoded media is never silently replaced by a transcoded derivative. | `normative` |
| `INV-011` | Published object graphs are root-last; a visible root cannot reference uncommitted children. | `normative` |
| `INV-012` | Derived indexes, graphs, embeddings, tracks, and digital-twin renderings are rebuildable from canonical evidence. | `normative` |
| `INV-013` | A model generation is immutable; mixed-generation embeddings or logits cannot share one score space. | `normative` |
| `INV-014` | Alert thresholds are versioned policy, not mutable model-side constants. | `normative` |
| `INV-015` | An alert includes evidence, uncertainty, sensor-health context, and a deterministic decision fingerprint. | `normative` |
| `INV-016` | Absence of detection cannot become evidence of absence when coverage, continuity, or calibration is degraded. | `normative` |
| `INV-017` | Privacy masks and excluded zones are applied before remote publication and before any model not authorized for unredacted data. | `normative` |
| `INV-018` | Face identification, cross-property identity linkage, and biometric enrollment are disabled by default. | `normative` |
| `INV-019` | The drone is a manually piloted calibration and observation sensor until a separate flight-safety qualification exists. | `normative` |
| `INV-020` | No v1 effect can deploy a weapon, pursue a person, or physically confront a subject. | `normative` |
| `INV-021` | Every public readiness claim is derivable from a retained proof bundle and a registered claim class. | `normative` |
| `INV-022` | Negative evidence, failed experiments, and known blind spots are retained and release-visible. | `normative` |
| `INV-023` | Local qualification is release authority; hosted CI is supplementary evidence. | `normative` |
| `INV-024` | A vendor firmware or app generation not in the compatibility registry fails closed or enters an explicit degraded mode. | `normative` |
| `INV-025` | A redacted or deleted object cannot remain reachable through an undeclared alternate index or cache. | `normative` |
| `INV-026` | Every durable schema is versioned and old versions remain readable or have a deterministic migration. | `normative` |
| `INV-027` | Every adaptive policy is bounded by non-adaptive safety invariants and logs its decision basis. | `normative` |
| `INV-028` | Detection quality is measured at event level under realistic class imbalance, not inferred from frame accuracy. | `normative` |
| `INV-029` | A false-negative claim includes the defined threat distribution and a confidence bound; absolute never-miss claims are forbidden. | `normative` |
| `INV-030` | Any operation whose registered cost cannot satisfy its SLO fails design review before implementation. | `normative` |
| `INV-031` | The production dependency universe is closed to FSS, admitted first-party crates, and registered foundational exceptions; convenience is not an exception. | `normative` |
| `INV-032` | Foreign codecs, model runtimes, vendor SDKs, vendor applications, and proprietary helpers may appear only in sealed laboratory or one-time migration lanes and are excluded from the production release closure and runtime invocation graph. | `normative` |
| `INV-033` | Production neither dynamically loads code nor downloads models, plugins, schemas, tokenizers, or executable artifacts at runtime. | `normative` |
| `INV-034` | All canonical history, graph/search updates, subscriptions, branches, and replication derive from one ordered EvidenceDeltaBatch universe. | `normative` |
| `INV-035` | Every derived generation names the exact authoritative high-water mark and projection policy it consumed. | `normative` |
| `INV-036` | External object identities are stable and never recycled; stale internal handles are rejected by generation. | `normative` |
| `INV-037` | Every non-unique graph or planning answer declares a canonical tie-break, output order, numeric policy, and decision-path digest. | `normative` |
| `INV-038` | Authorization and privacy scope are compiled before graph/search expansion so counts, degree, reachability, and absence cannot leak hidden state. | `normative` |
| `INV-039` | Every planning-relevant graph execution emits a complexity and output witness against a pinned projection and anchor. | `normative` |
| `INV-040` | Resource pressure may degrade only through a registered ladder and can never silently drop canonical evidence, committed effects, or required cleanup obligations. | `normative` |
| `INV-041` | A zero-copy or shared view pins immutable or versioned backing storage and cannot outlive reuse or reallocation of that storage. | `normative` |
| `INV-042` | A zero-copy or performance claim requires semantic-equivalence proof and same-binary measurement showing that the removed copy or cost is actually material. | `normative` |
| `INV-043` | Shipping acquisition, media, codec, model, graph, storage, UI, and orchestration paths are first-party Rust and cannot dispatch to a foreign executable or language runtime. | `normative` |
| `INV-044` | Model weights and executable graphs are immutable, local, verified object graphs; production model execution performs no network acquisition. | `normative` |
| `INV-045` | Every accelerator result identifies device, kernel, numeric, and model generations and satisfies a registered deterministic or tolerance-certified contract. | `normative` |
| `INV-046` | ATP publishes a received object graph only after child closure, post-repair canonical digests, and the root identity verify. | `normative` |
| `INV-047` | ATP transports immutable state and evidence but never carries mutation authority for alerts, deletion, PTZ, activation, or other consequential effects. | `normative` |
| `INV-048` | Archive completion requires the configured replication and retrievability evidence, not merely a successful upload response. | `normative` |
| `INV-049` | Every FSS workspace crate, target, example, test, and build helper carries an unconditional unsafe-code prohibition; the FSS repository defines no unsafe exception path. | `normative` |
| `INV-050` | Adaptive policies are shadow-first, hard-clamped, reproducible, and paired with a safe fallback and rollback root. | `normative` |
| `INV-051` | A release is built from a clean source snapshot with an exact clean Asupersync and Franken-suite sibling revision closure. | `normative` |
| `INV-052` | A partial platform or qualification matrix may retain staged artifacts but can never publish or bless a release root. | `normative` |
| `INV-053` | Every public claim has a registered class, scope, evidence roots, exclusions, and expiry or revalidation trigger. | `normative` |
| `INV-054` | A calibration generation carries covariance or uncertainty, validity regions, residual evidence, and explicit invalidation conditions. | `normative` |
| `INV-055` | Claims of corroboration or independence name shared sensors, models, clocks, networks, training data, and other failure domains. | `normative` |
| `INV-056` | No search, graph, event, or coverage surface claims absence or completeness without a coverage certificate over the authorized domain and generation. | `normative` |
| `INV-057` | A speculative branch cannot commit fabricated state; it may emit only candidate intents that are recompiled and revalidated against live authority. | `normative` |
| `INV-058` | Every long-running operation has durable identity, checkpoints, ownership, resume fences, and a terminal or explicitly indeterminate result. | `normative` |
| `INV-059` | Canonical durable bytes use hand-written versioned formats with magic, limits, canonical ordering, checksums, and migration fixtures; serde layout is never the format. | `normative` |
| `INV-060` | Build scripts and sealed qualification perform no network access and use only pre-provisioned verified inputs with locked offline resolution. | `normative` |
| `INV-061` | Asupersync is the only asynchronous runtime; no detached task, second executor, or unowned worker may enter the process. | `normative` |
| `INV-062` | A proprietary device is production-supported only through an owned wire protocol, documented local interface, standards surface, or safe admitted first-party substrate; vendor SDKs and app automation remain laboratory-only. | `normative` |
| `INV-063` | Every canonical read pins one EvidenceAnchor; a result cannot silently mix device, stream, ledger, graph, search, model, policy, or calibration generations. | `normative` |
| `INV-064` | Every negative read carries a CoverageWitness naming the authorized domain, continuity, completeness, exclusions, and stop reason. | `normative` |
| `INV-065` | Concurrent plans validate semantic read and write witnesses; raw-byte merge and last-writer-wins are forbidden for canonical security state. | `normative` |
| `INV-066` | ATP transports immutable verified object graphs and resumable evidence only; non-idempotent physical or notification effects never ride the bulk transfer plane. | `normative` |
| `INV-067` | Staged, visible, durable, replicated, and protected publication states are distinct and cannot be collapsed into a single success flag. | `normative` |
| `INV-068` | A searchable in-memory delta is provisional until its durable generation root is verified and published; callers can distinguish both states. | `normative` |
| `INV-069` | Graph, search, geometry, memory, and model results are anchor-pinned derived projections and cannot silently redefine canonical evidence. | `normative` |
| `INV-070` | Every non-unique algorithmic answer declares a deterministic tie-break policy, output order, and decision-path digest. | `normative` |
| `INV-071` | Every planning-relevant graph execution emits a GraphAlgorithmWitness with projection identity, complexity counts, budget, exactness, and output digest. | `normative` |
| `INV-072` | Authorization and privacy filtration occur before search, graph expansion, aggregation, absence counting, or model input construction. | `normative` |
| `INV-073` | Regime detectors and adaptive policies may tune batching, sampling, caching, and refinement effort but may never lower safety, privacy, freshness, witness, or confirmation requirements. | `normative` |
| `INV-074` | Observation history, time travel, replication, subscriptions, derived high-water marks, and speculative branches share one append-only version universe. | `normative` |
| `INV-075` | Every advertised archive or evidence root is independently reconstructible from its manifest and is subject to periodic retrievability and repair drills. | `normative` |
| `INV-076` | A release begins from a clean source identity and an exact clean sibling-revision closure; mutable developer checkouts are not release inputs. | `normative` |
| `INV-077` | The aggregate release manifest is withheld until every required local target and cross-target invariant passes and published bytes are downloaded and reverified. | `normative` |
| `INV-078` | The direct dependency universe is closed to std, the pinned nightly, Asupersync, admitted Franken-suite crates, and individually approved fundamental exceptions. | `normative` |
| `INV-079` | The production release is executable-language pure Rust; DSR/bootstrap scripts may orchestrate qualification but own no FSS runtime semantics and are not packaged as product dependencies. | `normative` |
| `INV-080` | Operational memory, centrality, anomaly scores, and learned household context are advisory and cannot authorize an effect without current canonical evidence and policy. | `normative` |
| `INV-081` | Diagnostics, progress certificates, traces, and optional statistical monitors may explain or schedule work but cannot mutate the authoritative result they observe. | `normative` |
| `INV-082` | A branch or counterfactual world may emit candidate intents only; fabricated branch state is never merged byte-for-byte into the live deployment. | `normative` |
