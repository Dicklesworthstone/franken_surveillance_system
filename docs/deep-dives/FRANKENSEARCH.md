# Deep dive: `frankensearch` and Quill as progressive, immutable, explainable evidence retrieval

**Document class:** normative source-to-design audit
**FSS integration gate:** `INT-FSEARCH-001`
**Status:** design import; search adapter remains unqualified
**Audit basis:** current search architecture and Quill comprehensive plan inspected 2026-08-31

## 1. The useful abstraction

The shallow import would be “add vector search.” The deep import is a progressive decision process over immutable generations:

```text
cheap exact/lexical candidates
-> fast semantic candidates
-> graph/temporal expansion
-> expensive reranking or multimodal verification
-> evidence shaping under budget
```

Every stage can return a useful bounded result, names the same authority anchor, and explains what it did. Search is cognition over canonical evidence; it never becomes source truth.

## 2. Immutable generation per request

A query pins one `SearchGeneration` containing:

- consumed `EvidenceDeltaBatch` high-water mark;
- document/event/track schema epoch;
- analyzer and chunking policy;
- lexical segment roots;
- embedding model and quantization identities;
- ANN structure generation;
- redaction/authorization projection;
- exact-document and known-gap counts;
- activation/continuity certificate.

Activation is build -> verify -> continuity check -> publish root -> retire prior generation. A request cannot see half of two generations. “Latest” is resolved to an explicit generation before execution.

## 3. Searchable delta, durable seal

Quill’s separation of immediate visibility from durable sealing maps well to live events. New authority deltas enter a bounded searchable in-memory delta. Sealing creates an immutable segment, writes checksums and indexes, and publishes a new root. Commit is durability/publication; it is not the first moment data can be queried.

FSS constraints:

- delta visibility still names its exact authority high-water mark;
- bounded memory and backpressure prevent unbounded watch-mode growth;
- restart replays canonical deltas; the delta is not the source of truth;
- sealed and delta results share one deterministic ranking/tie-break contract;
- a query receipt declares whether results included an unsealed delta.

## 4. Merge = concatenate for time-partitioned evidence

Quill’s absolute-ID/docid-range insight suggests an FSS event-segment design. Sealed segments own disjoint ordered ranges of stable event/document ordinals. Posting blocks use absolute or range-base identities and self-delimiting encoding. Ordinary merge can concatenate compatible blocks without decoding/re-encoding every posting. Tombstone-dense compaction is a separate operation with a new generation.

For FSS this is especially attractive because evidence arrives in ordered time/generation batches. Segment metadata includes time range, authority high-water mark, privacy projection, and model/analyzer identity. Concatenation is permitted only when ranges and identities are disjoint and ordering is canonical.

## 5. Columnar ingest and schema-specialized front ends

FSS does not need a general web-search schema. It has a narrow set of repeated fields:

- event/track/device IDs;
- time intervals and zones;
- event kinds, state, severity, observability, and uncertainty;
- camera, model, policy, calibration, and adapter generations;
- object/action labels and OCR/transcript text where authorized;
- evidence provenance and contradiction summaries;
- operator notes and policy memories.

A schema-specialized ingest path tokenizes/normalizes into flat columns, assigns stable term IDs, and radix/sort-partitions postings rather than routing every value through generic dynamic maps. Safe nightly `std::simd` kernels may accelerate byte classification only after scalar parity and workload profiling.

## 6. Progressive FSS query ladder

The default ladder is:

1. exact typed filters, IDs, time ranges, device/zone, and state;
2. lexical BM25 over canonical text and registered fields;
3. temporal and graph expansion from high-confidence seeds;
4. fast local embedding retrieval;
5. structured fusion from relevance, urgency, freshness, confidence, provenance, novelty, and actionability;
6. optional quality embedding/cross-encoder/multimodal rerank;
7. evidence, explanation, and continuation shaping to byte/token budget.

Each stage records candidate count, pruning, score components, generation, stop reason, and cost. A later stage may reorder but cannot erase provenance or silently expand authority.

## 7. Model-space identity is non-negotiable

Embedding dimension is insufficient identity. An embedding space binds:

```text
weights digest
model architecture and revision
tokenizer/image preprocess
dtype and quantization
normalization and pooling
output dimension and metric
runtime/kernel generation
```

Vectors from different spaces are never mixed in one ANN index or compared directly. Activation of a new space requires complete backfill or a dual-generation query whose fusion happens at rank/evidence level, not vector arithmetic.

## 8. Top-k, tie-break, and score ledgers

Search results use a registered total order:

```text
primary score descending
then evidence class / exactness
then event-time policy
then stable external identity
```

NaNs and invalid scores fail closed. The score ledger records raw source scores, normalization, fusion, boosts, penalties, model/graph generations, and tie-break decisions. Deterministic replay recomputes the same order from the ledger.

## 9. Absence claims require coverage certificates

Top-k retrieval and “no relevant result exists” are different. An absence response must state:

- authorized corpus/domain;
- pinned generation/high-water mark;
- exact and approximate stages consulted;
- known unindexed or quarantined records;
- analyzer/model availability;
- recall certificate or `uncertified` status;
- time/zone/sensor coverage limitations.

Search cannot turn incomplete indexing into confidence that nothing happened.

## 10. Derived-index doctrine and rebuild

Lexical, vector, ANN, snippets, and ranking caches are derived. The ledger/object graph retains enough canonical material to rebuild them deterministically. Rebuild:

1. pins an authority root;
2. streams canonical records without whole-corpus materialization;
3. builds segments and vector artifacts in staging;
4. verifies counts, hashes, query fixtures, and continuity;
5. publishes one generation root;
6. leaves the prior generation available until readers drain.

A damaged index produces degraded retrieval, not corrupted event truth.

## 11. Pinned oracles and differential gauntlets

FSS adopts Quill’s conformance discipline. A replacement engine remains behind a feature/adapter seam while a pinned incumbent or simple reference acts as oracle. The gauntlet includes:

- query parsing and typed-filter semantics;
- analyzer/token/span parity;
- rank-conformance classes and intentional-divergence register;
- exact score/tie fixtures where the contract requires them;
- malformed/corrupt segment behavior;
- delta/sealed/full-rebuild equivalence;
- crash publication and rollback;
- quality metrics on held-out event queries;
- same-binary performance with A/A null controls;
- no tuning on the held-out conformance corpus.

A source file named `bm25` is not evidence of lexical compatibility.

## 12. Event attention is retrieval, not effect authority

Attention ranking may combine:

- event severity and urgency;
- unresolved effect/alert indeterminacy;
- novelty and contradiction;
- sensor/coverage degradation;
- causal proximity and graph centrality;
- operator/agent task context;
- expected information gain;
- age and deadline.

It chooses what to inspect next. It cannot suppress a mandatory alert, weaken privacy, or authorize an effect. Missing graph/embedding features degrade to the deterministic baseline.

## 13. FSS semantic owners

| Imported mechanism | FSS owner | Replacement prohibition |
|---|---|---|
| Immutable lexical/vector generations | `fss-search` | No mutable cross-generation reader |
| Searchable delta + durable seal | `fss-search` | No unbounded in-memory truth store |
| Quill-style segments | `fss-lexical` | No generic dependency before gauntlet |
| Embedding-space registry | `fss-model-registry`, `fss-vector` | No dimension-only compatibility |
| Progressive fusion | `fss-retrieval` | No opaque single score without ledger |
| Coverage/absence certificate | `fss-retrieval` | No cache-miss absence claim |
| Differential gauntlet | `fss-search-gauntlet` | No default flip on benchmark alone |

## 14. Superficial imitations that would fail

1. Updating one mutable index while readers query it.
2. Mixing vectors because dimensions match.
3. Treating semantic search as canonical event storage.
4. Requiring the highest-quality model before returning any result.
5. Reporting a fused score without source components and tie-break.
6. Merging segments by full decode/re-encode when the workload permits ordered concatenation.
7. Storing large media or generic document stores already owned by the evidence layer.
8. Saying “nothing found” when a model/index is missing or stale.
9. Benchmarking only queries the replacement was tuned on.
10. Using Tantivy/another engine in production merely because it is the oracle.

## 15. Admission evidence for `INT-FSEARCH-001`

1. Immutable generation activation, continuity validation, rollback, and old-reader draining.
2. Delta/sealed/rebuilt query equivalence at the same authority anchor.
3. Deterministic top-k and full score-ledger replay, including ties and NaNs.
4. Exact source/evidence-span reconstruction.
5. Authorization filtering before candidate generation and noninterference tests for counts/absence.
6. Known-gap and absence certificates fail closed.
7. Embedding-space mismatch rejection and complete backfill/dual-query activation tests.
8. Segment corruption, truncation, checksum, tombstone, and crash matrix.
9. Differential oracle corpus with every divergence classified and reproducer retained.
10. Held-out event-query nDCG/MRR/Recall plus task-level agent usefulness.
11. Same-binary indexing/query benchmarks with raw distributions, memory, energy, and A/A controls.
12. Search remains useful without semantic models and declares degradation explicitly.

## 16. Deliberately rejected imports

- A dependency-heavy general search stack as permanent architecture.
- ANN as the default answer to small exact collections.
- A mutable “universal” embedding space.
- Search-driven deletion without canonical graph closure.
- Centrality/novelty as alert authorization.
- Runtime model downloads.

## 17. Resulting architectural leap

FSS retrieval becomes a bounded, resumable investigation engine. It can answer quickly, refine when worthwhile, explain every rank change, cite exact evidence, and say honestly when it cannot certify absence—all while the authoritative history remains independent and rebuildable.
