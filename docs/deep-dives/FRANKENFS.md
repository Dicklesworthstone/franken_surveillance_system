# Deep dive: `frankenfs` as the custody, publication, cache, repair, and durability substrate

**Document class:** normative source-to-design audit
**FSS integration gate:** `INT-FFS-001`
**Status:** design import; object-spool integration remains unqualified
**Audit basis:** comprehensive spec, current README, mounted-repair serialization contract, MVCC/repair/writeback and evidence doctrine inspected 2026-08-31

## 1. The key transfer

The shallow import would be “use FrankenFS for files.” The deep import is that filesystem/object state is an effect domain with explicit visibility, durability, ownership, repair, and publication semantics.

FSS handles irreplaceable evidence under continuous writes and asynchronous remote replication. It needs a state lattice, not a boolean `saved` flag:

```text
reserved -> staged -> materialized -> verified -> visible -> durable
         -> replicated -> remotely verified -> retrievable
         -> retained / held / deletion-planned / deleted-or-indeterminate
```

Each transition has an owner, preconditions, generation fence, receipt, crash behavior, and compensating/quarantine path.

## 2. `staged >= visible >= durable` becomes a media/object epoch contract

FrankenFS’s writeback reasoning transfers directly. FSS distinguishes:

- **staged:** bytes exist in private scratch or an unpublished object generation;
- **visible:** a local reader with the proper anchor can reach the object;
- **durable:** the local durability boundary has completed and is evidenced;
- **replicated:** a provider accepted committed children;
- **remote-verified:** provider bytes or checksums were independently read/checked;
- **retrievable:** a sampled or full restore reconstructed the graph from the public root.

Visibility does not imply durability. Provider acceptance does not imply graph publication. `flush`-like operations do not become `fsync` merely because they returned success. FSS names the actual boundary for each backend.

## 3. Root-last coherent publication

Every multi-artifact publication follows:

1. enumerate intended children and identities;
2. preflight authority, destinations, quotas, and existing roots;
3. reserve one publication generation and lease;
4. stage every child under an unreachable namespace;
5. verify bytes, schemas, lineage, and limits;
6. apply required local durability barriers;
7. compute the manifest and root seal;
8. atomically expose the root pointer;
9. retain or retire the prior root according to policy;
10. emit a publication receipt and schedule retrievability checks.

Examples:

- sensor capsule + packet index + timing evidence + thumbnails;
- event bundle + redacted media + machine JSON + HTML/PDF + signatures;
- calibration parameters + covariance + residuals + coverage maps;
- model generation + weights + execution plan + tokenizer/preprocess + license;
- release artifacts + checksums + signatures + SBOM + qualification receipt.

A directory containing most children is not a published generation.

## 4. Mutation authority and repair share one serializer

The mounted-repair contract provides a crucial lesson: repair cannot bypass the normal mutation authority. In FSS, foreground writers and repairers for overlapping objects enter the same serializer. A repair plan must not overwrite newer camera data, refresh parity over unverified bytes, or publish a replacement root while a newer writer owns the generation.

Required repair invariants:

1. one snapshot/generation cut per diagnosis and apply attempt;
2. overlapping foreground and repair writes share a serializer;
3. dirty/unpublished data is not treated as durable source truth;
4. only registered durability boundaries authorize repair;
5. mutating repair holds an active lease and fence;
6. repair symbols match the current source generation;
7. cancellation leaves no hidden partial mutation;
8. failed source repair cannot refresh repair symbols;
9. repaired plaintext is rehashed and graph closure reverified;
10. publication occurs only under a new root; no in-place history rewrite.

Until these hold, scrub is detection-only and repair fails closed.

## 5. Doctor -> sealed repair plan -> apply

`doctor` diagnoses and emits findings. It never performs opportunistic mutation. `repair plan` converts selected findings into an immutable plan bound to:

- current object/ledger root;
- affected object ranges and generations;
- expected corruption/missing-child evidence;
- chosen source replicas or repair symbols;
- estimated work, risk, and storage cost;
- required lease and authority;
- expected postconditions;
- rollback/quarantine behavior;
- expiry and invalidators.

`repair apply` revalidates the seal and current root. Any relevant drift rejects the plan. Apply emits a transition-by-transition ledger, including cleanup and reproducer.

The same shape applies to adapter credential repair, calibration repair, index rebuild, archive reconciliation, and deletion cleanup.

## 6. RaptorQ/self-healing is a policy, not a magic checkbox

FSS uses repair symbols selectively for long-lived immutable object graphs and transfer windows. The policy considers:

```text
probability of corruption or loss
correlation/common-cause structure
replica count and provider diversity
retrieval time objective
object temperature and retention
encoding/refresh CPU and storage overhead
cost of irrecoverable loss
stale-symbol window
```

Repair ratios and refresh timing are decision-card arms. Eager, lazy, adaptive, and hybrid refresh remain bounded by hard freshness rules. A Beta posterior or sequential evidence may update the estimated loss rate; it cannot override generation mismatch, missing source digest, or failed durability.

FSS never claims that fountain codes protect a mutable object unless the symbol-generation protocol is qualified. Repair is supplemental to replicas, integrity hashes, and root manifests—not a replacement.

## 7. Cache policy is generation-aware and evidence-neutral

FSS imports several cache disciplines:

- cache keys include immutable generation and relevant privacy/authority scope;
- staged data cannot populate a cache visible to committed readers;
- request coalescing joins only requests with compatible freshness, scope, and redaction;
- eviction cannot discard the only copy of an unresolved obligation;
- hot/cold decisions are workload policy, not correctness;
- ARC/S3-FIFO or other strategies are admitted by same-binary evidence rather than brand preference;
- cache telemetry failure cannot change semantic answers;
- old readers may retain immutable snapshots while new roots publish.

Frame/tensor caches use structural sharing only for immutable storage. Exported views pin or freeze backing allocations; growable buffers cannot be exposed as stable zero-copy views.

## 8. Content-defined and semantic chunking

FSS distinguishes chunking purposes:

- **codec semantic boundaries:** keyframe/GOP or independently decodable ranges;
- **transport chunks:** ATP/FEC units optimized for resume and repair;
- **content-defined chunks:** deduplication of stable payloads where byte identity is useful;
- **privacy/deletion units:** graph-addressable units small enough for policy closure;
- **provider objects:** sized for request-cost, tail latency, and retrieval patterns.

One chunk size cannot optimize all five. Manifests relate layers explicitly. Source media is never rewritten merely to fit an archive object size.

## 9. Snapshot and clone-on-write semantics

Immutable roots make several operations cheap:

- investigator/agent branches share a base evidence graph;
- an export redaction variant path-copies only changed manifest nodes;
- a new calibration generation shares unaffected scene geometry;
- a model activation shares unchanged tokenizer/preprocess objects;
- a retention policy change creates a new manifest/policy view without rewriting retained bytes;
- a repair creates a new root while preserving the damaged root for forensics until policy permits retirement.

Structural sharing is O(1) at the root and O(changed path) for COW updates. It does not mean mutable aliasing.

## 10. Proof-of-retrievability and restore are the archive truth

Remote archive completion requires more than upload API success. FSS periodically samples or fully restores objects by:

1. fetching the published root;
2. resolving every selected child and repair dependency;
3. verifying provider metadata only as a hint;
4. verifying ciphertext and plaintext identities at the correct layers;
5. reconstructing through repair symbols when the test calls for it;
6. validating schema and graph closure;
7. recording latency, egress, request count, and cost;
8. quarantining or repairing failed graphs.

A provider may be healthy while a particular manifest is incomplete. Retrievability state is per root and per tested policy.

## 11. Graph-complete deletion and cryptographic erasure

Deletion begins from a sealed reachability plan over:

- source objects and alternate renditions;
- packet/frame indexes and thumbnails;
- tracks, embeddings, captions, transcripts, and search segments;
- graph projections and materialized views;
- repair symbols, replicas, caches, backups, and transfer journals;
- exports and provider objects under FSS authority;
- encryption keys and key-wrapping records;
- legal/operational holds and blocked descendants.

Apply revalidates the graph root and holds. Outcomes distinguish local deletion, remote confirmed deletion, provider-expiry scheduled, cryptographic erasure, replica lag, and unknown third-party copies. FSS does not use “deleted” as a single undifferentiated state.

## 12. Filesystem capabilities and path confinement

Every filesystem operation occurs under a rooted capability defining:

- allowed roots and object classes;
- read/write/create/delete methods;
- symlink and traversal policy;
- byte/file/count budgets;
- durability and publication policy;
- temporary/staging namespace;
- lease/fence and generation;
- privacy class.

FSS does not claim race-free path confinement from string canonicalization. High-risk host operations remain disabled until the selected FrankenFS or helper boundary proves the required platform semantics.

## 13. Evidence over claim and source-derived inventories

The project imports FrankenFS’s readiness separation:

```text
contract present
reference semantics verified
fault/crash behavior verified
filesystem/object adapter verified
live-device success verified
cross-version compatibility verified
performance verified
recovery/restore verified
```

Rejection-only tests are negative evidence, not proof that success works. Quantitative README claims are derived from machine-readable inventories where possible, preventing stale counts from becoming marketing facts.

## 14. FSS semantic owners

| Imported mechanism | FSS owner | Replacement prohibition |
|---|---|---|
| Publication generations/root-last | `fss-object`, `fss-publication` | No partially visible sibling sets |
| Visibility/durability state lattice | `fss-object`, backend adapters | No boolean `saved`/`uploaded` truth |
| Cache generation discipline | `fss-cache` | No staged or cross-scope cache leakage |
| Repair plan/apply | `fss-repair` | No opportunistic in-place repair |
| Repair symbols/retrievability | `fss-durability`, `fss-transfer` | No repair success without content verification |
| Filesystem capabilities | `fss-fs-cap` | No ambient path authority |
| Deletion closure | `fss-privacy`, `fss-retention` | No primary-object-only deletion |

## 15. Superficial imitations that would fail

1. Writing a manifest after files without making root exposure atomic.
2. Calling provider upload success “archived.”
3. Refreshing repair symbols after a partially failed source write.
4. Running background repair outside the foreground mutation serializer.
5. Treating `flush` or process-buffer drain as durability.
6. Caching unpublished objects under keys later reused by committed readers.
7. Coalescing reads with different redaction or freshness requirements.
8. Deleting source media while leaving embeddings, repair symbols, or exports reachable.
9. Claiming zero-copy while exporting pointers into growable/reused frame pools.
10. Timing an optimization before proving identical semantic output and A/A stability.

## 16. Admission evidence for `INT-FFS-001`

1. Complete crash matrix for reserve/stage/materialize/verify/publish/retire transitions.
2. Root visibility never precedes child durability required by policy.
3. Generation fences reject stale publisher and repair workers after restart.
4. Foreground writes and repair use one serializer for overlapping domains.
5. Detection-only scrub remains nonmutating when repair admission is absent.
6. Repair plans reject stale roots, leases, symbols, and privacy/hold changes.
7. Corruption, truncation, wrong-child, stale-symbol, and cancellation fixtures preserve the old root and produce reproducer artifacts.
8. Independent reconstruction of every advertised root from manifests and retained objects.
9. Local and remote retrievability campaigns include provider partial failure, lost response, duplicate upload, and restore through repair.
10. Cache tests prove generation/scope isolation and immutable-reader coherence.
11. Deletion closure reaches every registered derived/replica/repair/cache family and reports blocked/unknown copies.
12. Same-binary storage/cache/chunking experiments establish semantic equivalence before timing.
13. Platform path-attack corpus covers traversal, symlink, race, Unicode, case, and namespace edge cases within the actual support boundary.

## 17. Deliberately rejected imports

- Turning FSS into a general-purpose filesystem.
- Depending on FUSE in the authoritative hot path.
- Assuming every object deserves repair symbols.
- Treating physical compaction as permission to erase logical audit history.
- Using remote object-store listings as the canonical manifest.
- In-place mutation of evidence roots.

## 18. Resulting architectural leap

The system can answer not merely “does this file exist?” but:

> “Which generation owns these bytes, who may see them, when did they become visible and durable, which root makes them authoritative, how can they be independently reconstructed, what repair evidence exists, and what exactly must disappear under deletion?”

That is evidence custody rather than file management.
