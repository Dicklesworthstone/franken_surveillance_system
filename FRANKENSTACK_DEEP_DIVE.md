# Franken-stack deep dive for `franken_surveillance_system`

**Document class:** architecture-source audit and integration contract
**Status:** normative companion to the comprehensive plan
**Initial issue date:** 2026-08-30
**Rule:** an idea is not “leveraged” merely because its project name appears in a dependency list

---

## 0. Why this document exists

A surveillance system is an unusually hostile integration problem. It combines untrusted network
inputs, proprietary account flows, lossy wireless links, native media codecs, GPU model runtimes,
long-lived state, privacy-sensitive evidence, partially observed physical events, and effects that
may matter precisely when the system is degraded. A normal architecture can make this work in a
demo. The Franken-stack mechanisms make it possible to know what worked, what did not, what remains
uncertain, and what can be recovered after failure.

This audit asks a stricter question for each sibling project:

1. What concrete mechanism is useful to FSS?
2. Which FSS subsystem owns its semantics?
3. What tempting but incorrect transplant is rejected?
4. What admission evidence is required before the dependency becomes load-bearing?
5. How does FSS continue deterministically before that dependency is ready?

The result is a **semantic import map**, not a marketing compatibility chart.

## 1. Cross-stack synthesis

Across the nine source projects, the same deep architecture appears repeatedly:

```text
pure deterministic semantic core
    + explicit capability-scoped effects
    + immutable identities and versioned generations
    + crash-safe transactional publication
    + derived projections with certificates
    + cancellation and quiescence as protocols
    + deterministic replay and adversarial fault schedules
    + claims derived from retained evidence
```

FSS applies that architecture to a live physical property. The authoritative object is not “the
latest model answer.” It is a multi-version evidence universe containing:

- sensor/device/firmware/app identities;
- original encoded media identities or explicit non-retention reasons;
- conservative capture-time intervals and clock evidence;
- stream continuity and decode receipts;
- calibration generations and transform uncertainty;
- model, preprocessing, and policy generations;
- immutable event revisions and their evidence edges;
- effect intents, leases, idempotency identities, receipts, and terminal proofs;
- archive object roots and retrievability results;
- privacy masks, retention decisions, deletion closures, and export custody;
- negative evidence and known blind spots.

Everything else—frames, thumbnails, tracks, embeddings, vector indexes, graph neighborhoods,
digital-twin renderings, summaries, context packs—is a derived projection.

---

# 2. `asupersync`: reliability is a protocol

## 2.1 Mechanisms imported

### `Cx` as operation authority

Every FSS operation that may observe or affect the world needs more than cancellation. It needs a
context carrying:

- deadline and poll/cost budgets;
- cancellation state and reason;
- trace and deterministic replay identity;
- principal and capability set;
- privacy/retention scope;
- lease/fence identity for effects;
- resource limits for bytes, frames, model work, network, and subprocesses.

A camera adapter that reads credentials from a global singleton or a model host that can open
arbitrary files would violate the architecture even if its Rust API accepted `&Cx` cosmetically.
Authority must reach the actual boundary.

### Region ownership

A configured property owns sensor regions. A sensor region owns its adapter session, receive pump,
continuity monitor, packet spool, decode workers, model windows, archive publisher, and health
obligations. An event region owns its candidate windows, trackers, verifier calls, policy decision,
alert delivery, and evidence publication.

The region tree is an operational proof: closing a region must imply that every child is terminal,
cancelled and drained, or durably indeterminate with an owner.

### Request → drain → finalize cancellation

Dropping a future is not a shutdown strategy for a physical stream. Cancellation must:

1. stop admitting new packets/effects;
2. request child cancellation;
3. drain adapter, codec, model, ledger, and archive in-flight work;
4. flush or abort staged objects;
5. reconcile vendor/network receipts;
6. persist terminal or indeterminate outcomes;
7. release credentials, leases, descriptors, and subprocesses;
8. verify quiescence.

FSS uses this protocol for stream restart, firmware drift, operator shutdown, privacy deletion,
model upgrade, archive failover, and process exit.

### Four-valued outcomes

`Result<T, E>` cannot express the core operational distinctions:

- success;
- expected domain failure;
- cancellation with reason and drain evidence;
- panic/internal failure.

Network and vendor boundaries add a fifth *semantic state*—indeterminate effect—which is encoded in
operation receipts rather than flattened into an error. A timeout after issuing a camera command
is not proof that it did not happen.

### Reserve/commit effects and obligations

FSS effects use an immutable intent and precondition anchor. Preparation reserves authority and
resources without executing the consequence. Commit revalidates policy, lease, device generation,
calibration, and idempotency before crossing the effect boundary. An obligation remains until the
system observes and verifies the promised postcondition or records indeterminacy.

This applies to alerts, PTZ, camera configuration, archive deletion, evidence export, retention
changes, and any future drone mission.

### Deterministic LabRuntime, schedule exploration, and ATP

The same replay corpus must exercise:

- packet reorder/loss/duplication;
- cancellation at every await and publication barrier;
- clock steps and uncertainty expansion;
- adapter disconnect/reconnect races;
- codec crash/hang/partial output;
- model OOM, timeout, malformed output, and generation rollover;
- database kill points;
- multipart archive failure;
- concurrent agent leases;
- alert delivery ambiguity.

ATP-style immutable capsules are a natural transport for bounded state and evidence between edge
nodes, GPU workers, and archive publishers. FSS does not use distributed transport to move mutable
shared objects.

## 2.2 FSS owners

| Asupersync mechanism | FSS semantic owner |
|---|---|
| `Cx`, budgets, capability context | `fss-runtime` / `fss-types` |
| Region tree and quiescence | `fss-runtime` |
| Effect prepare/commit | `fss-effect` / domain effect crate |
| Obligations | `fss-obligation` |
| LabRuntime/replay | `fss-lab` |
| ATP capsules | `fss-transport` / `fss-evidence` |

## 2.3 Rejected transplant

FSS does **not** make the pure media parser, geometry kernels, score calibration, or schema types
asynchronous merely because Asupersync is present. Deterministic synchronous kernels remain pure;
Asupersync owns orchestration and effects.

## 2.4 Integration gate `INT-AS-001`

Asupersync becomes load-bearing only when a property lifecycle test proves:

- no task/subprocess/descriptors survive region closure;
- cancellation reason survives every layer;
- all staged ledger/object effects are committed, aborted, or indeterminate;
- bounded channels cannot deadlock shutdown;
- replay under the same seed produces the same semantic transitions;
- resource budgets fail closed under malicious input.

A temporary deterministic single-threaded executor remains the reference until this gate passes.

---

# 3. `frankensqlite`: the canonical evidence ledger

## 3.1 Mechanisms imported

### Transactional truth, not scattered logs

FSS must answer after a crash:

- Which stream generation was active?
- Which source packet ranges were retained?
- What clock uncertainty applied?
- Which model generation saw which frames?
- Which hypothesis revision existed before the alert?
- Which policy and capability authorized it?
- Was the alert request durably written before dispatch?
- Was delivery acknowledged, observed, or left indeterminate?
- Which archive children exist and which root became visible?
- Which privacy deletion remains incomplete?

These facts belong in a transactional ledger with stable schemas and snapshot reads.

### MVCC and semantic snapshots

Operators and agents need coherent views while streams continue. A query anchor names the ledger
revision, model registry generation, calibration generation, policy generation, and derived-index
certificates. Readers do not block acquisition writers; agents can resume from a previous anchor
and receive bounded deltas.

### Typed layers and recovery

FSS follows FrankenSQLite’s separation of storage primitives, transaction semantics, schema/query
layers, and orchestration. Recovery is not an implementation detail. Every table family has an
owner, migration policy, invariant, and rebuild classification.

### Claim discipline

The most important import is epistemic. FSS distinguishes:

- schema/type source present;
- deterministic reference behavior present;
- persistence path implemented;
- crash matrix qualified;
- production environment qualified;
- aggregate feature ready.

A row count or passing happy-path query is not persistence readiness.

## 3.2 Canonical/derived boundary

Canonical in the ledger:

- identities and generations;
- configuration and policy revisions;
- source-object manifests and custody;
- capture/receive intervals and continuity;
- operation intents and receipts;
- immutable event revisions;
- calibration certificates;
- privacy and retention state;
- proof-bundle indices and negative evidence.

Derived and rebuildable:

- decoded frames and thumbnails;
- embeddings and ANN indexes;
- graph materializations;
- current track caches;
- VLM summaries;
- heat maps and digital-twin renderings;
- convenience denormalizations.

## 3.3 Rejected transplant

FSS does not prematurely make FrankenSQLite the only possible implementation. Before the required
APIs and kill-point matrix qualify, the semantic contract admits:

1. an in-memory deterministic reference ledger;
2. an append-only fixture ledger for replay;
3. the eventual FrankenSQLite adapter.

All three must produce the same semantic receipts.

## 3.4 Integration gate `INT-FSQL-001`

Required evidence:

- schema migration and downgrade fixtures;
- MVCC anchor consistency under continuous ingest;
- first-committer-wins/idempotency races;
- root-last object publication transaction;
- crash injection at every durable barrier;
- recovery of active obligations and indeterminate effects;
- deletion closure transaction;
- bounded read/write latency under declared camera counts;
- no Tokio/native SQLite dependency leakage.

---

# 4. `frankenfs`: object custody, repair, and publication

## 4.1 Mechanisms imported

### Explicit block/file effects

FSS’s pure core does not call the filesystem directly. Object staging, rename/publish, sync,
metadata, free-space checks, and repair are explicit capabilities. This permits replay, fault
injection, platform-specific qualification, and deterministic error semantics.

### Root-last publication

A remote or local archive event is an object graph:

```text
source packet chunks
analysis/proxy derivatives
model receipts
track/geometry artifacts
policy decision
human-readable report
        ↓
child manifest(s)
        ↓
event evidence root
```

Children are staged and verified first. The root is published last. A visible root therefore
means every declared child was committed or explicitly omitted under policy. If publication dies
midway, unreachable children are garbage-collectable; a half-valid root is forbidden.

### Content seals and plan/apply repair

Repair is two-phase. `doctor` produces a sealed plan naming exact object identities, expected
states, proposed mutations, risk, and rollback. `repair.apply` revalidates the seal and current
state before mutation. No “scan and fix whatever looks odd” operation receives ambient write
access.

### Proof bundles

A support bundle includes machine-readable manifests plus bounded human diagnostics, exact build
and config identities, timeline, event ring, errors, reproduction command, and privacy review.
Raw household footage is not included by default.

## 4.2 FSS owners

- `fss-object-store`: content identities, staging, roots, reachability.
- `fss-archive`: local/remote publication and retrievability.
- `fss-evidence`: evidence graph and support bundles.
- `fss-repair`: doctor/plan/apply.

## 4.3 Rejected transplant

FSS does not require a custom filesystem or RaptorQ encoding in its first vertical slice. It
imports the custody and evidence discipline first. Erasure coding becomes a separate costed design
choice after object-size, provider durability, local spool, and repair workloads are measured.

## 4.4 Integration gate `INT-FFS-001`

- torn write and partial rename/object-store simulations;
- disk-full behavior at each stage;
- root-last reachability proof;
- scrub detects corruption and never repairs without authority;
- repair writeback serializes with active publication;
- deletion removes every canonical reachability edge and queues derived cleanup;
- restore reconstructs the exact event root and decision fingerprint.

---

# 5. `frankensearch`: progressive retrieval over derived evidence

## 5.1 Mechanisms imported

### Progressive result delivery

Agents and operators need a useful answer quickly, then refinement:

1. exact IDs, time/zone filters, and lexical matches;
2. fast multimodal embeddings;
3. graph/geometry constraints;
4. higher-quality embedding or reranking;
5. evidence hydration and verification.

The initial answer is labeled initial, and refinement can fail without erasing it.

### Model identity as a type-level boundary

Embeddings from different models, revisions, preprocessors, dimensions, quantizations, or privacy
masks cannot share a vector space merely because the array lengths match. An index generation
names the complete producer identity; activation is atomic after a full backfill.

### Derived index doctrine

Search is never the source of truth. A hit points back to canonical event revisions, source spans,
object digests, transforms, and score contributions. If indexes disappear, the ledger and evidence
remain and can rebuild them.

### Pinned oracle and differential gauntlet

A replacement implementation does not become default because it benchmarks faster. It stays
behind a feature or adapter seam while a pinned incumbent/oracle checks semantic behavior,
quality, crashes, and same-workload performance.

## 5.2 Search surfaces

FSS search must support:

- “show all unknown-presence events near the north fence after dark”;
- “find clips visually similar to this jacket without asserting identity”;
- “which camera gaps preceded the last three indeterminate events?”;
- “which false alarms involved rain, infrared insects, or moving foliage?”;
- “find every event affected by calibration generation 17”;
- “what negative evidence contradicts the current intrusion hypothesis?”;
- “what deserves the next 800 agent tokens?”

Every result includes the retrieval generation, score kind, component scores, evidence roots,
privacy state, and canonical anchor.

## 5.3 Rejected transplant

FSS does not use semantic retrieval as threat detection. An embedding-nearest clip is a candidate
or explanation aid, not a threat fact. Search cannot silently promote old labels into current
policy.

## 5.4 Integration gate `INT-FSEARCH-001`

- exact model-generation rejection tests;
- deterministic tie ordering;
- atomic backfill activation;
- index-loss rebuild;
- stale canonical-row admission checks;
- progressive result schema and refinement failure;
- privacy deletion closure across lexical/vector caches;
- held-out retrieval quality with confidence intervals.

---

# 6. `franken_markdown`: deterministic reports, spans, and taint

## 6.1 Mechanisms imported

FSS produces technical material with evidentiary weight: event reports, adapter protocol notes,
firmware compatibility records, model cards, calibration reports, policy diffs, support bundles,
and export manifests. They should come from one typed representation and render deterministically
to Markdown/HTML/PDF without browser-only semantics.

Exact source spans matter when a report quotes:

- a vendor specification;
- an ONVIF capability response;
- a policy rule;
- a model limitation;
- operator notes;
- an adapter lab transcript.

Untrusted text is tainted. A sentence found in a camera metadata field or imported document does
not become an instruction, capability, or policy.

Staged multi-output publication matters when an evidence export contains machine JSON, HTML, PDF,
and checksums: either the coherent bundle becomes visible or none does.

## 6.2 Rejected transplant

The renderer does not own evidence semantics. It receives a typed, redacted report model and may
not fetch arbitrary URLs, read secrets, or decide what to omit.

## 6.3 Integration gate `INT-FMD-001`

- byte-stable render fixture under `SOURCE_DATE_EPOCH`;
- identical evidence IDs across JSON/Markdown/HTML/PDF;
- source-span and redaction tests;
- no remote asset fetch in evidence mode;
- staged sibling rollback;
- bounded output and malicious Markdown corpus.

---

# 7. `frankengraphdb`: one version universe and typed claims

## 7.1 Mechanisms imported

### One version universe

A surveillance graph is meaningless if its nodes silently refer to different worlds. A query
anchor therefore binds:

- canonical ledger revision;
- sensor/device/firmware generations;
- stream generations;
- calibration generation;
- model/index generations;
- policy generation;
- privacy mask generation;
- graph materialization certificate.

A graph edge such as `TRACK_OBSERVED_BY_SENSOR` or `EVENT_OCCURS_IN_ZONE` carries provenance and
validity, not only endpoints.

### Graph is a projection, not the sole source of truth

The graph makes cross-camera and causal reasoning efficient:

- sensors overlap zones;
- tracks have observations;
- event revisions depend on tracks and evidence;
- calibration transforms connect coordinate frames;
- device failures affect coverage cells;
- alerts derive from policies and event revisions;
- memories support or contradict hypotheses.

Canonical event/evidence rows remain authoritative. Graph materializations are certificate-bound
and rebuildable.

### Typed claims

FSS copies the discipline of declaring whether a statement is:

- invariant;
- formal proof;
- bounded model;
- statistical estimate;
- SLO result;
- benchmark;
- compatibility result.

Each class requires different evidence. “The detector got every staged intruder” cannot justify a
formal never-miss claim. “The schema exists” cannot justify compatibility.

### Operation-cost registry

Each operation registers its semantic steps and variable costs before an SLO is accepted. For
example, a camera-second may incur hashing, decode, motion gating, detector frames, active-track
updates, occasional VLM windows, object-store PUTs, and retained bytes. If the declared hardware,
latency, and cost budget cannot pay those steps, the architecture must change before code lands.

### No substitute architecture

A global-lock event store, opaque Python monolith, all-frames frontier VLM, or “temporary” mutable
cloud database would establish the wrong semantic seams. FSS allows phased implementation but not
an incompatible substitute represented as progress toward the target.

## 7.2 Rejected transplant

FSS does not import graph-database generality indiscriminately. The initial graph schema is narrow,
typed, and surveillance-specific. A generic query language cannot bypass privacy, anchor, or
capability constraints.

## 7.3 Integration gate `INT-FGDB-001`

- graph certificate binds exactly one version universe;
- stale/mixed-generation edge rejection;
- deterministic graph materialization and query tie breaks;
- delete/rebuild equivalence;
- canonical-to-graph provenance closure;
- cost rows derive measured SLO denominators;
- graph loss never destroys evidence.

---

# 8. `dwarf_fortress_mcp`: a semantic control plane over a partially observed world

## 8.1 Why this is the closest analogy

Dwarf Fortress actions may be accepted, delayed, blocked, invalidated, completed much later, or
left ambiguous. Physical sensor operations have the same shape:

- a login can succeed while live view remains unavailable;
- an adapter can accept start while no frame arrives;
- frames can arrive while timestamps are unusable;
- a detector can fire while corroboration fails;
- an alert API can accept a message while delivery is unknown;
- a PTZ request can time out after the camera moves;
- archive upload can finish while the root is unpublished;
- a drone file can exist while its calibration relation is unresolved.

FSS imports the Dwarf plan’s insistence on semantic states, immutable plans, observations,
obligations, idempotency, and later proof.

## 8.2 Observation anchors and resumable deltas

An agent does not need an endless raw telemetry dump. It requests a bounded projection at anchor A
and later asks for changes since A. The delta carries new/changed/tombstoned identities, coverage
changes, active obligations, event revisions, and continuation. If the anchor is too old or its
version universe is unavailable, the server returns an explicit resnapshot requirement.

## 8.3 Intent compilation and two-phase effects

A high-level request such as “keep the driveway in view for the next five minutes” is not sent as
an arbitrary vendor command. It compiles into an immutable plan naming camera, PTZ limits, current
pose, privacy zones, lease, duration, rollback/restore pose, health checks, and verification
predicate. The caller previews it, receives the digest, and commits that exact digest.

## 8.4 Obligations and honest completion

FSS distinguishes:

```text
requested
→ authenticated
→ adapter accepted
→ first observation
→ continuity verified
→ semantic postcondition observed
→ terminal obligation verified
```

The system may stop at any state and say why. Dispatch is never represented as completion.

## 8.5 Rejected transplant

Unlike a game, a home has real people and legal/privacy consequences. FSS does not provide hidden
omniscience, arbitrary mutation, broad agent control, or irreversible autonomy to make the agent
interface convenient.

## 8.6 Integration gate `INT-DFMCP-001`

- anchor/delta resume and expiry matrix;
- immutable intent digest and conflicting idempotency rejection;
- prepare/commit/observe/verify for representative effects;
- bounded token responses with evidence handles;
- lease fencing between two agents;
- recovery of active obligations after crash;
- no raw vendor command or shell escape through MCP.

---

# 9. `fastmcp_rust`: the capability-scoped agent boundary

## 9.1 Mechanisms imported

FastMCP’s most relevant contribution is not JSON-RPC convenience. It is a disciplined public
boundary:

- request-owned concurrent work;
- budgets rather than only wall-clock timeouts;
- explicit cancellation checkpoints;
- four-valued outcomes;
- typed tools/resources/prompts;
- qualification boundaries that refuse to equate source presence with protocol support.

FSS tools are granular capabilities. Read tools cannot mutate. PTZ cannot alter retention. Export
cannot access unrelated events. Vendor adapter diagnostics cannot reveal credentials. A model
cannot call effect tools because model hosts receive no such capability.

## 9.2 Read-first surface

The default MCP principal receives bounded status, health, event, evidence, calibration, coverage,
archive verification, and doctor resources. Effects require separate grants and usually a
prepare/commit pair. High-impact effects can require a human approval token whose content is not
available to the model host.

## 9.3 Rejected transplant

FSS will not advertise aggregate MCP conformance merely because FastMCP compiles or because a
protocol version constant is current. Transport cancellation, authentication, bidirectional
calls, session lifecycle, cache partitioning, and subprocess cleanup each retain qualification
status.

## 9.4 Integration gate `INT-FMCP-001`

- exact protocol-generation negotiation tests;
- live wire cancellation and quiescence;
- authority preservation across middleware and cache;
- bounded output and continuation;
- concurrent request isolation;
- no credential/control-text leakage;
- effect idempotency and lease tests;
- process-group cleanup for adapter/model helpers.

---

# 10. `eidetic_engine_cli`: long-horizon learning without rewriting truth

## 10.1 Mechanisms imported

FSS will encounter repeating deployment-specific facts:

- the maple branch triggers camera 3 in wind from the northeast;
- firmware generation X corrupts timestamps after reconnect;
- the resident taking trash out follows a common path at a common time;
- a raccoon has a distinctive low trajectory near the bins;
- model generation Y missed a crawling red-team actor in IR mode;
- a calibration certificate drifts after freeze/thaw movement;
- a particular alert wording caused operators to dismiss a real event.

These are valuable memories with evidence, confidence, recency, utility feedback, and explicit
anti-patterns. Eidetic Engine’s local-first, immutable, explainable memory is the right substrate.

### Memory cannot rewrite authority

A memory may:

- propose a detector prompt or hard-negative test;
- boost retrieval of similar incidents;
- suggest that an event is a known benign pattern;
- recommend recalibration or adapter downgrade;
- supply an operator runbook.

It may not:

- delete canonical evidence;
- change a privacy mask or retention rule;
- whitelist a person permanently;
- lower a high-risk alert threshold;
- mark an event resolved;
- mutate a model generation;
- authorize an effect.

Those require explicit policy/effect workflows.

### Feedback and trauma guard

False alarms and misses produce feedback linked to exact event revisions and proof bundles. Harmful
memory feedback should demote aggressively. A repeatedly misleading heuristic becomes a visible
anti-pattern, not a silently forgotten failure.

## 10.2 Rejected transplant

FSS does not let a memory daemon autonomously rewrite state mid-event. Curation is propose/validate/
apply and every promotion produces an audit revision.

## 10.3 Integration gate `INT-EE-001`

- memory provenance resolves to retained event/evidence roots;
- deterministic context packs at a canonical anchor;
- stale/deleted evidence invalidates memory admission;
- harmful feedback demotion and anti-pattern conversion;
- no memory mutation of canonical/security/privacy tables;
- memory/index loss is rebuildable;
- operator can explain, supersede, tombstone, and export every memory.

---

# 11. Integration composition: how the pieces cooperate

## 11.1 Normal event path

1. An Asupersync sensor region owns adapter and media children.
2. The adapter emits bounded packet capsules with device/firmware generation and capture bounds.
3. The ledger reserves a capsule identity.
4. The object store stages source bytes; metadata is verified; the capsule root publishes last.
5. Derived decode and quality tasks consume the immutable capsule.
6. Detection/tracking/model hosts emit receipts keyed to exact inputs and generations.
7. Calibration binds observations into a shared coordinate/time universe.
8. The event engine creates an immutable hypothesis revision.
9. Graph/search projections publish certificates for that canonical revision.
10. Policy evaluates calibrated evidence, sensor health, privacy, and operator context.
11. An alert effect is prepared, committed, dispatched, observed, and verified.
12. The evidence root and deterministic report publish.
13. Later feedback becomes an Eidetic memory proposal, never a rewrite of the event.

## 11.2 Failure path

If a model crashes after reading frames:

- the model host outcome is panicked/failed;
- its receipt states no valid output;
- the event remains at its previous revision;
- a cheaper stage may continue;
- policy sees the degraded verifier state;
- an urgent event may still alert under a registered single-sensor exception;
- cancellation drains the model process;
- the evidence bundle retains the failure and exact inputs for replay.

If archive publication fails after children upload:

- the root remains unpublished;
- canonical state records staged children and retry/GC obligation;
- the alert is not falsely represented as remotely archived;
- local evidence remains available subject to spool policy;
- recovery can retry idempotently or collect unreachable children.

## 11.3 Degraded stack behavior

| Missing component | Required behavior |
|---|---|
| FrankenSQLite unavailable/unqualified | deterministic reference/file ledger; no false durability claim |
| FrankenFS integration unavailable | explicit host filesystem adapter with staged publication contract |
| Semantic model unavailable | lexical/metadata/geometry paths continue; degradation surfaced |
| Graph projection stale | canonical event query works without graph boosts |
| Eidetic memory unavailable | detection continues without learned context |
| Vendor cloud unavailable | local standards adapters continue; vendor sensor becomes unavailable/degraded |
| GPU unavailable | fast CPU/edge path or explicit capacity degradation; no silent frame dropping |
| Remote archive unavailable | bounded encrypted local spool and backlog obligation |
| MCP unavailable | CLI/library path remains; no core dependence on daemon |

---

# 12. Dependency and authority DAG

The target dependency direction is inward toward pure contracts:

```text
fss-types / fss-error / fss-schema
        ↑
reference state machines and pure algorithms
        ↑
ledger, object-store, runtime, adapter/model contracts
        ↑
acquisition, media, geometry, cognition, archive
        ↑
policy/effects/evidence/search/memory
        ↑
CLI, MCP, ops UI, interoperability lab
```

Rules:

- a lower layer never imports a product or vendor crate;
- a vendor adapter cannot import the canonical ledger implementation;
- a model host cannot import effect capabilities;
- a search or graph projection cannot mutate canonical event truth;
- a report renderer cannot fetch data independently;
- a privacy layer may remove authority/data but never add it;
- lab crates are excluded from default builds and release artifacts until qualified.

---

# 13. Import ledger

| Import ID | Source | FSS mechanism | Replacement prohibition | Admission gate |
|---|---|---|---|---|
| `IMP-AS-001` | Asupersync | region-owned sensor lifecycle | no detached tasks/threads | `INT-AS-001` |
| `IMP-AS-002` | Asupersync | reserve/commit effects and obligations | no fire-and-forget effect | `INT-AS-001` |
| `IMP-FSQL-001` | FrankenSQLite | MVCC canonical ledger | no mutable JSON/log truth | `INT-FSQL-001` |
| `IMP-FFS-001` | FrankenFS | root-last evidence objects | no visible partial root | `INT-FFS-001` |
| `IMP-FSEARCH-001` | Frankensearch | progressive derived retrieval | no search-as-truth | `INT-FSEARCH-001` |
| `IMP-FMD-001` | Franken Markdown | deterministic reports | no browser-only evidence | `INT-FMD-001` |
| `IMP-FGDB-001` | FrankenGraphDB | version-universe graph | no mixed-generation graph | `INT-FGDB-001` |
| `IMP-FGDB-002` | FrankenGraphDB | typed claims/cost registry | no untyped readiness/SLO | `GATE-000` |
| `IMP-DFMCP-001` | Dwarf Fortress MCP | anchor/delta semantic control | no raw telemetry dumps as API | `INT-DFMCP-001` |
| `IMP-FMCP-001` | FastMCP Rust | capability-scoped agent tools | no generic shell/vendor proxy | `INT-FMCP-001` |
| `IMP-EE-001` | Eidetic Engine | evidence-linked operational memory | no memory rewrite of truth | `INT-EE-001` |

---

# 14. What is intentionally not imported

The Franken label does not justify complexity. FSS intentionally rejects:

- custom video codecs before measured need;
- a custom object store before B2/R2/local adapters prove the semantic contract;
- a graph database as the only canonical store;
- model inference in the core process;
- generalized distributed consensus for a single-property first deployment;
- autonomous drone flight before calibration value and flight safety are separately proven;
- RaptorQ “everywhere” without an operation-cost and recovery model;
- semantic embeddings for every frame by default;
- a daemon requirement for every CLI operation;
- online policy tuning of hard alert/privacy boundaries;
- replacing established standards merely to own more code.

Alien artifact technology means stronger invariants per unit of complexity, not maximal machinery.

---

# 15. Initial integration order

1. Freeze identities, schemas, event/acquisition/effect state machines, and claim classes.
2. Implement a single-threaded deterministic reference world and replay adapter.
3. Add synthetic property, sensor gaps, benign routines, staged intrusion, and archive fixtures.
4. Integrate Asupersync regions without changing reference semantics.
5. Add canonical ledger adapters and kill-point recovery.
6. Add UVC, then RTSP, then ONVIF Profile T/M.
7. Add source-byte custody, codec subprocess supervision, and low-latency proxy.
8. Add model-host protocol and a cheap detector/tracker vertical slice.
9. Add event revisions, policy, and evidence bundles.
10. Add static calibration, then the drone calibration shuttle.
11. Add remote archive, retrieval audit, and privacy deletion closure.
12. Add search/graph/memory projections.
13. Add MCP read surface, then prepared effects.
14. Enter proprietary adapter labs only after the reference path and security boundary are real.
15. Optimize only after operation-cost rows and pinned oracles exist.

This order is deliberately less visually impressive than “connect Wyze and ask a VLM whether it
sees a burglar.” It produces a system whose impressive behavior can later be trusted.
