<div align="center">

# Franken Surveillance System (`fss`)

**A pure-Rust, evidence-native, local-first sensor fabric for owner-authorized cameras and manually piloted capture drones.**

*Cheap consumer hardware. One version universe. Certified graph intelligence. Pure-Rust media and models. Crash-safe evidence. No ambient authority.*

![Status](https://img.shields.io/badge/status-architecture%20constitution-yellow)
![Rust](https://img.shields.io/badge/Rust-accepted%20nightly-orange)
![Unsafe](https://img.shields.io/badge/FSS%20unsafe-forbidden-brightgreen)
![Runtime](https://img.shields.io/badge/runtime-Asupersync-blueviolet)
![Release](https://img.shields.io/badge/release-local%20DSR%20authority-blue)
![License](https://img.shields.io/badge/license-MIT-blue)

</div>

> [!IMPORTANT]
> This repository currently contains the **normative architecture, deep Franken-suite audits,
> registries, schemas, and a dependency-free Rust contract skeleton**. It does not yet acquire
> camera feeds, decode video, run models, reconstruct a property, upload archives, or deliver
> alerts. The boundary is explicit in [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md).

## The thesis

Consumer security hardware is cheap and increasingly capable, but each product is an island. A
battery camera may expose only a proprietary app. A USB gimbal camera may be standards-compliant but
physically tethered. A drone may provide a superb moving view while lacking a supported control SDK.
Conventional NVRs can record streams, but they do not usually create a calibrated,
provenance-carrying world model that an autonomous agent can query and operate safely.

FSS is intended to turn heterogeneous owner-authorized sensors into one coherent system:

```text
cameras / microphones / manually piloted drone captures
                         │
       first-party UVC · RTSP/RTP · ONVIF · focused adapters
                         │
 packet truth + source bytes + time intervals + health receipts
                         │
              EvidenceDeltaBatch universe
                         │
       ┌─────────────────┼──────────────────┐
       │                 │                  │
 source custody      live operator      cognition
 ATP object graphs   Rust proxy/UI      Rust models + graphs
       │                 │                  │
       └─────────────────┴─────────┬────────┘
                                  │
             calibrated tracks + 3D twin + coverage
                                  │
 quality → detect → track → associate → temporal verify
                                  │
        event transaction with evidence and uncertainty
                                  │
   versioned policy → abstain / request view / alert plan
                                  │
       idempotent effect + observed/verified receipt
```

The radical part is not “run a VLM on camera footage.” It is the substrate beneath every model:

- **Four operational planes.** Packet, authority, cognition, and effect states are type-distinct.
  A decoded frame is not source continuity; a model score is not physical fact; a provider ACK is
  not a verified alert.
- **One version universe.** Canonical history is an ordered immutable `EvidenceDeltaBatch` stream.
  Graphs, search, subscriptions, replicas, model caches, checkpoints, and branches publish exact
  high-water marks instead of each inventing “current.”
- **Semantic MVCC.** Event and effect decisions carry positive and negative witnesses, model/
  calibration/policy epochs, and revalidate before consequential publication.
- **Pure-Rust production.** FSS owns packet protocols, codecs, containers, model execution, graph
  algorithms, archive protocols, and orchestration in first-party safe Rust. FFmpeg, PyTorch/ONNX,
  NetworkX, C SQLite, Tantivy, browsers, and vendor applications are pinned laboratory oracles only.
- **ATP object graphs.** Source media, checkpoints, model packages, derived generations, exports,
  and releases move by verified manifest/chunk/repair graphs with resume, post-repair digest proof,
  and root-last publication.
- **Certified graph intelligence.** Cross-camera association, temporal reachability, blind-spot
  cuts, active perception, deletion closure, and runtime deadlock analysis use registered snapshot-
  pinned algorithms with canonical tie-breaks and complexity/output witnesses.
- **Digital-twin calibration.** A manually piloted drone or handheld camera can serve as a
  calibration shuttle, linking fixed camera views to a metric reconstruction and uncertainty-aware
  coverage model.
- **Event-level epistemology.** Quality is measured under realistic class imbalance with event
  AUPRC, recall at a false-alert budget, calibration, time-to-detect, abstention, observability, and
  miss bounds—not frame accuracy or a cherry-picked demo.
- **Proof-carrying operations.** Publication is child-first/root-last; effects use prepare →
  revalidate → commit → observe → verify; repair is doctor → sealed plan → apply; claims derive from
  retained proof roots.
- **Local release authority.** Doodlestein Self-Releaser executes clean-snapshot qualification on
  controlled local machines. GitHub workflows are portable specifications, not a required trust
  root.

## What “Franken” means

The first draft named the sibling projects. The second pass audits them mechanism by mechanism:
what invariant each idea establishes, which FSS crate owns it, what weaker substitute is forbidden,
what reference model defines it, how failure degrades, and what evidence admits it.

| Project | Load-bearing FSS inheritance |
|---|---|
| [`asupersync`](https://github.com/Dicklesworthstone/asupersync) | region ownership, `Cx` authority, multidimensional budgets, request→drain→finalize cancellation, obligations, deterministic LabRuntime, ATP, hard-clamped decisions |
| [`frankensqlite`](https://github.com/Dicklesworthstone/frankensqlite) | multi-version anchors, positive/negative hierarchical witnesses, SSI, deterministic commit combining, semantic merge ladder, crash classification |
| [`frankenfs`](https://github.com/Dicklesworthstone/frankenfs) | staged/visible/durable/replicated/retrievable custody, root-last publication, unified repair serialization, RaptorQ, retrievability, deletion closure |
| [`frankensearch`](https://github.com/Dicklesworthstone/frankensearch) | immutable generations, searchable delta versus durable seal, Quill merge=concat, columnar ingest, progressive retrieval, absence certificates, oracle gauntlets |
| [`franken_markdown`](https://github.com/Dicklesworthstone/franken_markdown) | exact bytes/spans, taint, bounded nonrecursive parsing, one semantic document source, deterministic HTML/PDF reports |
| [`frankengraphdb`](https://github.com/Dicklesworthstone/frankengraphdb) | one delta universe, temperature tiers, factorized joins, incremental retract/add views, branches, typed claims, operation-cost and decision-card discipline |
| [`franken_networkx`](https://github.com/Dicklesworthstone/franken_networkx) | canonical graph semantics, immutable O(1) snapshot views, deterministic algorithms, complexity witnesses, adversarial conformance, offline specialization |
| [`dwarf_fortress_mcp`](https://github.com/Dicklesworthstone/dwarf_fortress_mcp) | honest control of a delayed, externally changing, partially observed world; durable obligations; token-efficient semantic views |
| [`fastmcp_rust`](https://github.com/Dicklesworthstone/fastmcp_rust) | request-owned capability-scoped MCP presentation, four-valued outcomes, bounded outputs, application-owned durable tasks |
| [`eidetic_engine_cli`](https://github.com/Dicklesworthstone/eidetic_engine_cli) | typed evidence-backed operational memory, decay/trauma guard, immutable curation, deterministic context packs |
| [`frankentorch`](https://github.com/Dicklesworthstone/frankentorch) | typed tensors, frozen operator IR, static dispatch, scalar reference and safe optimized kernels, canonical model packages, differential conformance |
| [`doodlestein_self_releaser`](https://github.com/Dicklesworthstone/doodlestein_self_releaser) | clean source/sibling closure, controlled native hosts, resumable-but-never-partial matrices, signed exact assets, local receipts as authority |

Start with [`FRANKENSTACK_DEEP_DIVE.md`](FRANKENSTACK_DEEP_DIVE.md) and the
[`deep-dive index`](docs/deep-dives/INDEX.md). The machine import ledger is
[`architecture/franken_imports.json`](architecture/franken_imports.json).

## Pure-Rust and dependency constitution

The production closure is deliberately narrow:

```text
std/core/alloc
+ FSS workspace crates
+ Asupersync
+ exact admitted Franken-suite revisions
+ a tiny DEP-recorded foundational exception set
```

Every FSS crate forbids unsafe. Asupersync is the sole runtime. No Tokio, async-std, smol, Rayon-
owned pool, Python/PyO3, FFmpeg/libav, OpenCV, ONNX Runtime, libtorch, CUDA runtime binding,
proprietary SDK, browser engine, Node/Electron/Tauri, generic graph/search/database engine, dynamic
plugin, runtime model download, or networked build script enters production.

The current default external exception candidates are only `serde` and `serde_json`, and only for bounded control/report data-shape roles. Serde never defines canonical durable bytes.

This is stricter than “a safe Rust core with unsafe helpers out of process.” A required foreign
service is still a foreign production runtime. Missing first-party capability remains unsupported
or fails closed; it does not silently activate a fallback.

See [`DEPENDENCY_CONSTITUTION.md`](DEPENDENCY_CONSTITUTION.md) and
[`architecture/dependency_allowlist.toml`](architecture/dependency_allowlist.toml).

## Device posture

FSS starts from replay and standards before proprietary adapters:

| Tier | Surface | Initial examples | Policy |
|---|---|---|---|
| 0 | Deterministic replay | synthetic and consented packet/frame/event fixtures | First implementation and oracle |
| 1 | Open local standards | UVC/UAC, RTSP/RTP, ONVIF Profile T; optional Profile M metadata | Preferred production path |
| 2 | Documented vendor API | products with a supported local/cloud protocol | Exact version, authority, and compatibility tuple |
| 3 | Authorized interoperability lab | Wyze Cam v4, AOSU P1 Max, DJI Flip capture routes | Owner devices/accounts only; no credential bypass; firmware/app/region-specific |
| 4 | Import-only | SD-card or exported clips | Useful evidence, never represented as live coverage |

Insta360 Link is a useful UVC/UAC reference sensor. Wyze Cam v4 and AOSU P1 Max begin as
interoperability-lab candidates unless a qualified standards/API surface is established. DJI Flip
begins as manually piloted capture/import; FSS has no autonomous flight authority.

See [`DEVICE_ADAPTER_MATRIX.md`](DEVICE_ADAPTER_MATRIX.md) and
[`INTEROPERABILITY_LAB.md`](INTEROPERABILITY_LAB.md).

## Architecture in one page

### Four planes

1. **Packet:** exact transport/source bytes, protocol sequence, compressed access units, time and
   continuity evidence.
2. **Authority:** identities, generations, source custody, policy, calibration/coverage, event
   revisions, effects, obligations, and receipts.
3. **Cognition:** decoded media, tensors, detections, tracks, associations, graph/search projections,
   digital twin, operational memory, and explanations.
4. **Effect:** alerts, PTZ/settings, retention/deletion/export, activation, and repair mutation.

### One ordered version universe

An immutable `EvidenceDeltaBatch` is the common source for history, graph/search maintenance,
subscriptions, checkpoints, replicas, and branches. Every response reports:

```text
authority anchor
search high-water
graph high-water
model-result high-water
calibration and coverage generations
staleness or gap
```

A caller can demand alignment, accept bounded lag, or receive an explicit stale/degraded result.

See [`docs/ONE_VERSION_UNIVERSE.md`](docs/ONE_VERSION_UNIVERSE.md).

### Target crate families

```text
Foundation:      fss-types · fss-error · fss-schema · fss-numeric · fss-identity
Runtime/fabric:  fss-runtime · fss-capability · fss-subject · fss-obligation · fss-lab · fss-decision
Device:          fss-device-core · fss-device-uvc · fss-device-rtsp · fss-device-onvif
                 fss-device-vendor · fss-drone-capture
Media:           fss-packet · fss-container · fss-codec-* · fss-audio · fss-live
Authority:       fss-ledger · fss-witness · fss-object · fss-publication · fss-checkpoint · fss-privacy
Transfer:        fss-transfer · fss-archive · fss-provider-s3 · fss-repair · fss-retrievability
Geometry:        fss-time · fss-calibration · fss-geometry · fss-twin · fss-coverage
Models:          fss-tensor · fss-operator · fss-kernel-cpu · fss-model-ir/import/runtime/registry
Cognition:       fss-quality · fss-detect · fss-track · fss-associate · fss-temporal · fss-fusion
                 fss-event · fss-policy
Knowledge:       fss-search · fss-graph/query/algorithms · fss-forge · fss-memory · fss-explain
Effects:         fss-plan · fss-effect · fss-alert · fss-export
Presentation:    fss-api · fss-cli · fss-mcp · fss-report · fss-ops · optional fss-ui
Qualification:   fss-reference · fss-fixtures · fss-gauntlet · fss-bench · fss-release
```

The checked-in workspace is intentionally smaller. Empty crate theater is not implementation.

## Pure-Rust media and streaming

FSS separates source evidence, live delivery, and analysis:

- source bytes and packet/timing maps are immutable custody objects;
- live derivatives prioritize bounded latency and can reduce quality under pressure;
- analysis decodes only the frames/regions/resolutions demanded by the cascade;
- remux is preferred to transcode;
- H.264/H.265/MJPEG and required audio profiles are admitted incrementally;
- scalar parser/decoder semantics remain the oracle for safe optimized/SIMD kernels;
- frame/tensor views pin immutable or generation-leased backing storage;
- pressure follows a registered degradation ladder and never silently drops canonical evidence or
  committed obligations.

FFmpeg/ffprobe and browsers compare behavior in the lab. They are absent from the production
closure. See [`docs/STREAMING_AND_MEDIA_KERNEL.md`](docs/STREAMING_AND_MEDIA_KERNEL.md).

## Pure-Rust model runtime

Open-weight models are imported offline into immutable FSS packages containing a frozen first-party
operator IR, canonical tensor objects, preprocessing/postprocessing, numeric policy, licenses,
quality/conformance receipts, and repair metadata.

The runtime is CPU-first and specialized for frozen inference graphs: packed weights, cache-shaped
tiling, liveness-planned scratch arenas, safe SIMD, fused preprocess/layout/early operators, and
static shape-specialized dispatch. Every optimized kernel has a scalar reference and exact or
tolerance-certified contract. Optional accelerators are first-party and receipt-bearing; CPU
fallback remains qualified.

Python, PyTorch/ONNX Runtime, and accelerator incumbents remain lab oracles. Production does not
interpret arbitrary framework graphs or download models at runtime.

See [`PURE_RUST_MODEL_RUNTIME.md`](PURE_RUST_MODEL_RUNTIME.md) and
[`docs/deep-dives/FRANKENTORCH.md`](docs/deep-dives/FRANKENTORCH.md).

## Detection is a cascade, not a monolith

A frontier VLM is too expensive, nondeterministic, and weakly calibrated to inspect every frame or
authorize alerts alone. The target cascade is:

1. sensor health, blur, darkness, obstruction, glare, replay, and tamper checks;
2. cheap activity/change/audio gates with explicit coverage state;
3. fast detector and segmenter;
4. within-camera tracking and trajectory features;
5. geometry/time-gated cross-camera association with k-best alternatives;
6. open-vocabulary unusual-object/behavior retrieval;
7. bounded temporal multimodal reasoning;
8. an independent verifier with a different failure profile;
9. conformal/sequential calibration and semantic event transaction;
10. alert, abstain, request another view, or retain silently.

Every stage emits a generation-pinned result. Later models can contradict earlier results; they
cannot erase source provenance or directly authorize an effect.

## Certified graph intelligence

Graphs are operational kernels, not dashboards. Initial registered families cover:

- dynamic connectivity and temporal reachability;
- articulation points, bridges, dominators, max-flow/min-cut, and Gomory-Hu failure summaries;
- shortest/k-shortest trajectories;
- bipartite matching, k-best assignment, and min-cost flow for association;
- SCC/condensation/topological critical path for obligations and plans;
- set cover, facility location, and submodular active perception/coverage;
- PPR attention, d-separation/shared-failure analysis, factorized joins;
- canonical deletion reachability and wait-cycle detection.

Every run pins an authorized immutable projection and emits a `GraphAlgorithmWitness` with
canonical tie-break, output digest, complexity counters, and decision path. Incremental standing
predicates are checked against full recomputation.

See [`GRAPH_ANALYTICS_AND_SENSOR_MESH.md`](GRAPH_ANALYTICS_AND_SENSOR_MESH.md),
[`docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md`](docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md), and
[`registries/GRAPH_ALGORITHMS.md`](registries/GRAPH_ALGORITHMS.md).

## Digital twin and calibration shuttle

The target setup avoids asking a homeowner to perform a professional survey:

1. place optional printable/illuminated calibration markers;
2. start fixed-camera capture and a calibration session;
3. manually fly or carry a camera through fixed views and overlap zones;
4. reconstruct the property and moving-camera trajectory;
5. jointly solve intrinsics, extrinsics, time offset/skew, rolling-shutter terms, scale, and
   trajectory;
6. compute covariance, residuals, coverage, occlusion, blind spots, and expected transit intervals;
7. publish a generation certificate with validity regions and invalidators.

A moved camera, crop/zoom/firmware change, seasonal occlusion, or residual drift degrades or
invalidates the certificate. NeRF/Gaussian-splat renderings are useful views, not metric authority.

See [`DIGITAL_TWIN_AND_CALIBRATION.md`](DIGITAL_TWIN_AND_CALIBRATION.md).

## ATP archive, repair, and deletion

Source media, evidence bundles, checkpoints, model packages, graph/search/calibration/twin
snapshots, replay corpora, and releases move as immutable ATP object graphs. The receiver stages
children, verifies manifests and canonical digests, repairs only against exact generations,
verifies closure, and publishes the root last.

“Uploaded” is not “archived.” Completion can require independent replicas and proof-of-
retrievability samples. Deletion enumerates repair symbols, replicas, indexes, embeddings, caches,
journals, and staging objects before publishing a tombstone root.

ATP never carries mutation authority. See
[`ATP_AND_DISTRIBUTED_EVIDENCE.md`](ATP_AND_DISTRIBUTED_EVIDENCE.md) and
[`docs/ATP_ARCHIVE_AND_REPLICATION.md`](docs/ATP_ARCHIVE_AND_REPLICATION.md).

## The quality objective

“Never miss a true intruder” is the right motivating aspiration and the wrong unqualified claim.
FSS turns it into:

- event-level AUPRC over a declared threat distribution;
- recall lower bounds at a declared false-alerts-per-property-day budget;
- time-to-detect and time-to-deliver distributions;
- probability calibration and selective-risk curves;
- distinct slices for darkness, occlusion, crawling/crouching, dark clothing, weather, foliage,
  wildlife, residents, delivery/service workers, children, and tampering;
- explicit `NotObservable` accounting for failed/occluded/uncalibrated coverage;
- property/session-separated held-out evaluation;
- retained misses, near misses, false alarms, contradictions, and broken assumptions;
- claims that name shared model/sensor/clock/network/training-data failure domains.

A missing or degraded sensor is not a negative observation. FSS must say “coverage uncertified”
rather than lower the score silently.

## Agent and operator surface

The surface is read-first and bounded:

```text
fss.status
fss.device.list / inspect
fss.stream.health
fss.observe.delta
fss.event.list / inspect / explain
fss.timeline.query
fss.search
fss.graph.query
fss.coverage.inspect / blind-spots
fss.archive.verify
fss.evidence.pack
fss.doctor.bundle

fss.alert.prepare / commit        # effect
fss.camera.ptz.prepare / commit   # effect
fss.retention.prepare / commit    # effect
fss.deletion.prepare / commit     # effect
fss.export.prepare / commit       # effect
```

There is no generic shell, SQL, vendor-method, codec, model-prompt, object-store, or drone-control
escape hatch. Requests own their children and budgets; long work is a durable application-owned
task; MCP is only a presentation adapter.

## Local qualification and release

The release authority is local:

1. create a clean immutable source snapshot;
2. capture exact clean Asupersync/Franken-suite revisions;
3. resolve locked and offline after provisioning;
4. run repository policy, Rust, deterministic lab, crash, ATP, graph, media, model, device,
   security/privacy, performance, soak, and package lanes as required by claims;
5. retain partial target artifacts across resume but never bless them;
6. build exact assets with checksums, minisign/Ed25519 signatures, SBOM, provenance, source/
   dependency and qualification manifests;
7. upload, download, and verify;
8. publish the release manifest root last.

The repository pins the latest nightly that has passed a promotion gauntlet. Releases never build
against an ambient moving `nightly`. GitHub workflow YAML calls repository scripts and can be
executed locally by DSR/compatible tooling; GitHub-hosted runners are not required.

See [`LOCAL_QUALIFICATION_AND_RELEASE.md`](LOCAL_QUALIFICATION_AND_RELEASE.md).

## Repository map

| Path | Purpose |
|---|---|
| [`COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md`](COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md) | Normative architecture, execution plan, and first 200 issues |
| [`FRANKENSTACK_DEEP_DIVE.md`](FRANKENSTACK_DEEP_DIVE.md) | Cross-project synthesis and constitutional imports |
| [`docs/deep-dives/INDEX.md`](docs/deep-dives/INDEX.md) | One deep mechanism audit per sibling project |
| [`DEPENDENCY_CONSTITUTION.md`](DEPENDENCY_CONSTITUTION.md) | Canonical pure-Rust closed-universe policy; its byte-identical `docs/` mirror is policy-checked |
| [`docs/ONE_VERSION_UNIVERSE.md`](docs/ONE_VERSION_UNIVERSE.md) | `EvidenceDeltaBatch`, anchors, high-water marks, branches, and recovery |
| [`docs/MVCC_EVIDENCE_LEDGER.md`](docs/MVCC_EVIDENCE_LEDGER.md) | Positive/negative witnesses, SSI, commit combining, and reconciliation |
| [`docs/STREAMING_AND_MEDIA_KERNEL.md`](docs/STREAMING_AND_MEDIA_KERNEL.md) | First-party packet, container, codec, live, and analysis design |
| [`PURE_RUST_MODEL_RUNTIME.md`](PURE_RUST_MODEL_RUNTIME.md) | Canonical frozen model package and first-party execution constitution; its `docs/` mirror is policy-checked |
| [`docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md`](docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md) | Projection and certified algorithm architecture |
| [`docs/GRAPH_ALGORITHM_ATLAS.md`](docs/GRAPH_ALGORITHM_ATLAS.md) | Operational use, ties, complexity, and admission per algorithm |
| [`GRAPH_ANALYTICS_AND_SENSOR_MESH.md`](GRAPH_ANALYTICS_AND_SENSOR_MESH.md) | Canonical certified graph/sensor-mesh doctrine; its `docs/` mirror is policy-checked |
| [`ATP_AND_DISTRIBUTED_EVIDENCE.md`](ATP_AND_DISTRIBUTED_EVIDENCE.md) | Canonical ATP object-graph, repair, federation, deletion, and receipt doctrine; its `docs/` mirror is policy-checked |
| [`docs/ATP_ARCHIVE_AND_REPLICATION.md`](docs/ATP_ARCHIVE_AND_REPLICATION.md) | Object transfer, repair, retrievability, and deletion |
| [`docs/DECISION_CARDS_AND_EXPERIMENTS.md`](docs/DECISION_CARDS_AND_EXPERIMENTS.md) | Hard-clamped adaptation and same-binary evidence |
| [`docs/PERFORMANCE_AND_MECHANICAL_SYMPATHY.md`](docs/PERFORMANCE_AND_MECHANICAL_SYMPATHY.md) | Profile-first safe optimization and resource economics |
| [`LOCAL_QUALIFICATION_AND_RELEASE.md`](LOCAL_QUALIFICATION_AND_RELEASE.md) | Canonical DSR-first qualification and root-last release constitution; its `docs/` mirror is policy-checked |
| [`docs/LOCAL_QUALIFICATION_WITH_DSR.md`](docs/LOCAL_QUALIFICATION_WITH_DSR.md) | Clean-snapshot native-host DSR execution contract |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Compact architecture reference |
| [`DEVICE_ADAPTER_MATRIX.md`](DEVICE_ADAPTER_MATRIX.md) | Exact device/firmware/app/region compatibility states |
| [`MODEL_REGISTRY.md`](MODEL_REGISTRY.md) | Model candidate, package, license, and admission registry |
| [`DIGITAL_TWIN_AND_CALIBRATION.md`](DIGITAL_TWIN_AND_CALIBRATION.md) | Calibration and coverage doctrine |
| [`DATA_FORMATS.md`](DATA_FORMATS.md) | Durable identities, object families, and schemas |
| [`SECURITY.md`](SECURITY.md) / [`PRIVACY.md`](PRIVACY.md) | Authority, secrets, taint, retention, identity, and deletion |
| [`architecture/`](architecture/) | Machine invariants, imports, dependencies, algorithms, publications, decisions, costs, and release policy |
| [`registries/`](registries/) | Human-readable stable registries |
| [`schemas/`](schemas/) | Draft 2020-12 interchange/evidence schemas |
| [`scripts/qualify.sh`](scripts/qualify.sh) | Repository-local qualification contract |
| [`docs/NEGATIVE_EVIDENCE.md`](docs/NEGATIVE_EVIDENCE.md) / [`docs/PERF_LEDGER.md`](docs/PERF_LEDGER.md) | Failed hypotheses and measured wins |
| [`MANIFEST.sha256`](MANIFEST.sha256) | Snapshot integrity manifest |

## Inspect the skeleton

```bash
python3 scripts/generate-manifest.py
bash scripts/qualify.sh --lane policy
bash scripts/qualify.sh --lane rust
cargo run -p fss-cli -- capabilities --json
cargo run -p fss-cli -- doctor --json
```

The current artifact environment may not have the pinned Rust nightly installed; the policy and
artifact checks are independently executable with Python. A passing skeleton build does **not**
qualify any camera, codec, model, graph algorithm, archive provider, or alert path.

## Non-goals

FSS is not:

- a way to access devices, accounts, or footage without the owner’s authorization;
- a credential-bypass, exploit-distribution, or covert-monitoring toolkit;
- a public face-recognition or cross-property identity network;
- a guarantee that no intrusion can ever be missed;
- an autonomous armed, confrontational, pursuit, or drone-flight system;
- a cloud-required product or generic smart-home platform;
- a Rust supervisor around required foreign production runtimes;
- a generic shell/SQL/vendor/model/codec interface for agents;
- a benchmark leaderboard without retained semantic and statistical evidence;
- a release process dependent on GitHub-hosted Actions.

## Current status

The project remains at **`GATE-000`: architecture constitution**.

Implemented now:

- the comprehensive plan and second-pass Franken-stack constitution;
- twelve project-specific deep dives plus an adjacent-project census;
- eighty-two machine-readable hard invariants;
- rich mechanism-level import, dependency, algorithm, publication, decision, cost, schema, and local
  qualification registries;
- JSON Schemas for sensor capsules, event hypotheses, evidence bundles, operation receipts,
  calibration/coverage certificates, delta batches, graph witnesses, ATP manifests/receipts, model packages/execution receipts, adapter/drain/release certificates, and Decision Cards;
- a dependency-free safe-Rust semantic skeleton;
- policy/manifest validation and local qualification wrapper;
- ADRs for pure Rust, one version universe, ATP separation, graph witnesses, local DSR authority,
  and oracle-only foreign runtimes.

Not implemented now:

- real camera/drone acquisition;
- RTSP/RTP/ONVIF/UVC protocol stacks;
- codecs, containers, live proxy, or UI;
- canonical persistence and ATP cloud transport;
- tensor kernels or model inference;
- calibration, reconstruction, coverage, graph/search engines;
- detection, tracking, association, event fusion, alerts, or MCP server;
- full DSR release matrix.

That gap is the ordered work—not hidden capability—described by the plan.

## License

MIT. Device firmware, vendor applications, model weights, codecs, datasets, and cloud services keep
their own licenses and terms. FSS treats license, exact bytes, firmware/app/model generations, and
allowed use as runtime correctness inputs rather than paperwork deferred until release.
