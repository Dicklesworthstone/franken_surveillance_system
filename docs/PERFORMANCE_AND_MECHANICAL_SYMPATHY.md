# FSS performance and mechanical-sympathy doctrine

**Status:** normative optimization plan
**Revision:** 1
**Date:** 2026-08-31

FSS aims for exceptional performance without sacrificing memory safety, deterministic semantics, or dependency discipline. Performance comes from architecture, data layout, bounded work, focused algorithms, and measurement—not from ambient parallelism or unsafe shortcuts.

## 1. Optimization order

1. remove unnecessary work;
2. avoid decode/transcode/model calls;
3. choose a better algorithm or representation;
4. make access sequential and cache-shaped;
5. partition ownership and eliminate contention;
6. batch narrow publication points;
7. use safe vectorization;
8. exploit hardware accelerators through isolated protocols;
9. consider a ledgered unsafe island only after all above fail a release-critical SLO.

## 2. Three data paths

### Source path

Preserve encoded packets with minimal copying, timestamp bounds, integrity, and root-last custody. Remux rather than transcode whenever possible.

### Live path

Bounded low-latency proxy with disposable latest-state semantics. It may drop frames under policy but must report gaps and never affect source custody.

### Cognition path

Demand-driven sampling and progressive refinement. Decode only windows/crops/resolutions required by active candidates; reuse decode surfaces across compatible model stages.

## 3. Ownership and sharding

- one stream ingress owner per generation;
- per-worker bounded arenas and flat columns;
- stable shard selection by site/sensor/sequence;
- no shared per-frame `HashMap` hot path;
- immutable sealed generations shared by reference;
- per-shard queues with work stealing only through Asupersync-owned scheduling;
- backpressure before memory growth;
- NUMA/heterogeneous-core topology recorded in performance receipts.

## 4. Columnar hot data

Separate columns for timestamps, object IDs, bounding boxes, confidence, zone IDs, feature vectors, and provenance handles. This enables:

- sequential filtering;
- compact hot working sets;
- safe SIMD;
- zero-copy graph/search views;
- cheap compression;
- late materialization of large metadata;
- factorized query outputs.

Rich variable metadata remains out of line and content-addressed.

## 5. Copy budget

Every pipeline stage declares allowed copies:

- network/kernel to owned packet buffer;
- packet to source object staging;
- decode output to shared frame surface;
- crop/resize to model input;
- result to compact column.

Unexpected copies are traced by size/class. Zero-copy is not pursued when it expands lifetime, pins scarce buffers, or weakens cancellation; the objective is bounded, explicit copies.

## 6. Buffer pools and arenas

Pools are generation- and size-classed, region-owned, pressure-aware, and poison/quarantine malformed boundary output. Leases are obligations. A buffer cannot be returned while a child view is live. Lab mode checks double-return, leak, and use-after-generation logically without unsafe code.

## 7. Ingest and sealing

Share-nothing workers append to flat columns and local posting/feature blocks. Sealing sorts/partitions by stable IDs. Globally disjoint sequence/time ranges permit merge-by-concatenation for ordinary runs. Compaction rewrites only when tombstone/correction density or format migration justifies it.

## 8. Narrow flat combining

Use flat combining only for tiny contended state:

- commit/observation sequence allocation;
- generation root publication;
- idempotency outcome sealing;
- active-commit registration;
- release manifest finalization.

The combiner performs no I/O or callbacks while locked. Slots are cache-line-separated where measured contention warrants it.

## 9. Safe SIMD

Candidate kernels:

- pixel quality statistics;
- color/gradient/motion reductions;
- bounding-box IoU and gating;
- feature cosine/dot products;
- quantization/dequantization;
- posting/varint/block decode;
- timestamp interval comparisons;
- bitset coverage operations;
- checksum/fountain finite-field work through owned safe interfaces.

Each kernel has:

- scalar reference;
- exact/tolerance contract;
- forced scalar/vector arms;
- architecture dispatch;
- malformed/unaligned/tail tests;
- same-binary semantic digest;
- per-architecture performance evidence.

## 10. Graph performance

- inline micro-adjacency for tiny neighborhoods;
- sorted delta blocks for recent mutations;
- sealed compressed CSR/columnar runs for stable relations;
- zero-copy immutable snapshot views;
- incremental Z-set maintenance for standing relations;
- factorized/WCO joins for cyclic/multiway patterns;
- bounded traversal and early capability filtering;
- algorithm-specific complexity witnesses.

A graph representation change is admitted only after exact reference equivalence and measured end-to-end benefit.

## 11. Model cascade economics

The cascade minimizes expensive work:

1. continuity/image-quality/tamper checks;
2. deterministic motion/change/audio gates;
3. low-cost detector/segmenter;
4. tracker and geometry constraints;
5. cross-camera candidate gating;
6. open-vocabulary model on selected crops/windows;
7. temporal VLM on compact event clips;
8. independent verifier only near consequential thresholds.

The policy accounts for model latency, GPU memory, energy, thermal state, uncertainty reduction, and expected event value. Safety clamps define minimum inspection for protected scenarios.

## 12. Scheduling lanes

| Lane | Work | Rule |
|---|---|---|
| `CriticalCapture` | source packet custody, clock, health | never starved by derived work |
| `Interactive` | live view, operator/agent query | bounded latency, may use provisional generations |
| `Incident` | active event verification/alert | preempts background, preserves source |
| `Durability` | archive/root replication, held evidence | deadline/value aware |
| `Background` | compaction, embeddings, graph rebuild, scrub | pressure-shed first |
| `Qualification` | local tests/benchmarks | isolated resource envelope |

Lane policy is deterministic under a recorded epoch. Adaptive schedulers operate within minimum/maximum allocations.

## 13. Backpressure and degradation

Pressure propagates toward producers. Typed responses include reduced frame sampling, lower proxy quality, deferred nonessential embeddings, paused compaction, slower background archive, or rejected new optional queries. FSS does not silently grow queues.

Irreplaceable source and active incident work outrank rebuildable indexes and disposable proxies. A gap updates coverage state immediately.

## 14. Cache policy

Caches are generation-keyed and cannot expose unpublished data. Request coalescing joins identical reads only when authority, privacy, anchor, freshness, and output contract match. Cache policy candidates use same-binary A/B; S3-FIFO/ARC-like adaptation is workload-specific, not universal.

## 15. I/O policy

- large sequential source/object writes;
- aligned chunk classes chosen from device/provider evidence;
- batching without delaying root publication beyond SLO;
- local fsync policy explicit by evidence class;
- direct I/O/mmap only behind admitted safe/unsafe boundary;
- cloud object size selected from dated operation-cost manifests;
- multipart parallelism bounded by memory/network/service class;
- read-ahead based on incident/query access pattern.

## 16. Numeric policy

Geometry, tracking, calibration, scores, and graph weights define precision, accumulation, determinism, NaN/overflow, and tolerance. Fast-math or architecture-dependent reductions are forbidden in strict reproducibility lanes unless a separate approximate policy and certificate exists.

## 17. Benchmark doctrine

Every claimed optimization has:

- pinned source/toolchain/host/workload roots;
- one binary with runtime arm selection;
- A/A null;
- warmup and sample policy;
- semantic output digest before timing comparison;
- median/p90/p95/p99 and dispersion;
- CPU/GPU/memory/I/O/network/energy counters as relevant;
- thermal state;
- confidence interval or robust comparison;
- negative result ledger;
- exact reproduction command.

Microbenchmarks identify walls; end-to-end workloads justify architecture changes.

## 18. Performance budgets

Each registered operation defines asymptotic and concrete budgets. Examples:

- packet admission: amortized O(1), no unbounded allocation;
- source segment seal: O(bytes) sequential plus O(children) manifest;
- event candidate gate: O(frames or changed blocks), bounded window;
- cross-camera association: sparse candidate graph, not all-pairs global comparison;
- graph query: declared complexity and expansion cap;
- agent response: fixed token/evidence bytes;
- cancellation drain: potential must descend or report blocker;
- archive publication: O(bytes) transfer and O(objects) verification with bounded concurrency.

An operation whose cost model cannot meet its registered SLO fails design review before implementation.

## 19. Optimization prohibitions

- dropping source/provenance to reduce storage;
- mixing generations to avoid rebuild;
- hidden approximate graph/model result represented as exact;
- unsafe code without safe fallback and evidence;
- unbounded batching/queues;
- benchmark-only semantics;
- per-frame JSON in the packet hot path;
- generic dynamic value maps in inner loops;
- model invocation on every frame by default;
- global locks around decode/inference/upload;
- performance claim without semantic equivalence.
