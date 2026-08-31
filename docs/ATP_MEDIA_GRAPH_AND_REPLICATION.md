# ATP media graph and replication design

**Status:** normative design
**Revision:** 1
**Date:** 2026-08-31

FSS uses Asupersync ATP as its bulk state/evidence movement plane. The transferred unit is not a path, file, clip, or multipart upload. It is a domain-separated, manifest-described, integrity-verified object graph whose root is exposed only after child and closure verification.

## 1. Why ordinary uploads are insufficient

A surveillance incident is not one MP4 file. It may include original packet ranges from several cameras, uncertain timestamps, audio, proxy clips, thumbnails, detections, track columns, calibration transforms, policy/model receipts, redaction derivatives, alert receipts, and a report. Uploading those independently creates ambiguity:

- which exact children compose the incident;
- whether a partial upload is discoverable;
- whether a retry duplicated or replaced data;
- whether derived objects still match source bytes;
- whether keys and repair metadata exist;
- whether the graph can be reconstructed after local loss;
- whether deletion closed every reachable copy.

ATP makes graph closure and publication first-class.

## 2. Object identity

Every object identity is domain-separated:

```text
ObjectId = H(
  "fss-object-v1" ||
  object_kind ||
  codec_or_schema_id ||
  canonical_metadata ||
  plaintext_or_ciphertext_policy ||
  bytes
)
```

The exact hash and truncation policy are registry-owned. Ciphertext-addressed and plaintext-addressed objects are distinct classes; the manifest states which identity is used. Keys are never embedded in the object graph.

## 3. Root families

| Root kind | Children |
|---|---|
| `SourceSegmentRoot` | packet chunks, timing map, stream generation, continuity map, integrity sidecars |
| `LiveProxyRoot` | disposable CMAF/WebRTC segments and playlist generation |
| `AnalysisWindowRoot` | sampled frames/audio, preprocessing receipt, source-range references |
| `FeatureGenerationRoot` | column shards, model identity, quantization/numeric policy |
| `EventEvidenceRoot` | source references, tracks, graph witnesses, model/policy decisions, alert receipts |
| `CalibrationRoot` | observations, trajectory, transforms, covariance, residuals, coverage model |
| `DigitalTwinRoot` | metric geometry, semantic zones, uncertainty, visualization derivatives |
| `IndexGenerationRoot` | lexical/vector/graph segments and consumed high-water mark |
| `ModelPackageRoot` | weights, tokenizer/preprocess, license, code/config, test vectors |
| `SupportBundleRoot` | bounded logs, registries, receipts, redacted samples, reproduction commands |
| `QualificationRoot` | fixtures, outputs, semantic digests, performance samples, environment manifest |
| `ReleaseRoot` | source closure, binaries, checksums, signatures, SBOMs, qualification roots |

## 4. Manifest structure

A transfer manifest includes:

- root kind and format version;
- root and child object identities;
- object sizes and chunk ranges;
- canonical child ordering;
- sparse/optional sections;
- dependency edges and closure count;
- encryption/key-context identifiers;
- compression/codec/schema identifiers;
- repair-symbol groups and source symbol parameters;
- source anchor and privacy class;
- retention/hold policy;
- minimum replicas and allowed destinations;
- exposure predicate;
- maximum memory/disk/network budgets;
- producer and verifier identities.

A manifest may refer to already-present content-addressed children. The receiver proves availability and integrity; it does not blindly retransfer them.

## 5. Transfer lifecycle

```text
Reserved
→ ManifestValidated
→ PathsDiscovered
→ ChildrenScheduled
→ Receiving
→ ChildVerified
→ GraphClosureVerified
→ Quarantined | ExposureReady
→ RootPublished
→ ReplicaQualified
→ Scrubbed
→ Retired
```

The path lifecycle is separately explicit:

```text
Discover → Candidate → Probing → Active → Suspect → Draining → Closed
```

A failed path is drained so buffers, file handles, requests, and accounting obligations cannot leak. Losing racing paths are not abruptly abandoned.

## 6. Verifier stages

### PreFlight

Checks manifest schema, identity domain, graph size/depth, allowed object kinds, privacy/destination policy, key availability, quotas, and destination generation fence.

### InFlight

Checks chunk length, range, ordering policy, rolling integrity, duplicate/replay identity, decompression bounds, and cancellation checkpoints.

### PostFlight

Checks full-object identity, schema/container structure, child count, repair group consistency, and staged storage durability.

### Exposure

Checks graph closure, privacy transforms, policy epochs, root generation, high-water continuity, and authorized reader class before publishing the root.

### Recovery

Replays the journal, classifies staged children, repairs recoverable groups, discards/quarantines ambiguous data, and publishes only roots whose closure can be independently proven.

## 7. Crash-resumable journal

The local journal is append-only, checksummed, versioned, canonical, and bounded. It records:

- transfer/root identity;
- manifest identity;
- reserved resources;
- path state transitions;
- verified byte ranges and child identities;
- repair symbols received/generated;
- publication fence and root state;
- cancellation/close outcome;
- last durable journal offset.

Large journals spill to an unpublished object graph rather than growing unbounded. Resume validates the journal root and all previously credited ranges. “File exists” is never accepted as verification.

## 8. Multipath scheduling

Candidate paths may include local disk, LAN peers, direct cloud endpoints, relay hosts, removable media, and multiple cloud providers. The scheduler optimizes expected completion/cost/reliability under declared service class.

Inputs include:

- recent throughput and latency distributions;
- failure and corruption evidence;
- provider operation/egress costs;
- path concurrency limits;
- thermal/network pressure;
- privacy/jurisdiction policy;
- source uniqueness and repair coverage;
- deadline and incident value.

Adaptive allocation may use bandit or Bayesian policies, but hard rules dominate:

- integrity verification cannot be skipped;
- prohibited destinations receive zero allocation;
- a path in `Suspect` cannot expose data;
- minimum local reserve is preserved for live capture;
- high-value incident roots preempt disposable proxy replication;
- policy changes create a new decision card.

## 9. Repair symbols

RaptorQ repair symbols are first-class objects grouped by a protected source set. A policy records:

- source symbol size and padding;
- source count and repair count/ratio;
- object selection and grouping;
- generation/refresh rules;
- key and compression ordering;
- decode memory/CPU budget;
- expected failure model;
- maximum stale protection window;
- decode-drill cadence.

Repair is not “parity exists.” Qualification performs actual loss/corruption/decode drills and validates reconstructed semantic roots.

## 10. Archive publication

Cloud publication follows:

1. reserve archive generation and operation budget;
2. materialize encrypted child objects locally;
3. publish/verify manifest children remotely;
4. verify remote object identity or authenticated checksum metadata;
5. verify graph closure from remote reads;
6. publish a small root marker last;
7. read the root back through an independent client path;
8. record provider receipt and cost counters;
9. update ledger durability state.

A provider SDK success is not the commit point. The root marker and independent readback are.

## 11. Local spool and pressure

The spool has explicit classes:

- irreplaceable source bytes not yet root-published;
- event/hold evidence awaiting durability;
- normal retention footage;
- rebuildable feature/index data;
- disposable live proxies.

Pressure shedding proceeds in reverse authority/value order. It may drop disposable proxies and recomputable analysis outputs before source evidence. It cannot delete held evidence or silently claim continuous coverage after source loss.

## 12. Retrievability

Audits sample more than object presence:

- manifest and child fetch;
- key lookup and decryption;
- hash/AEAD verification;
- repair decode with simulated losses;
- container/packet reconstruction;
- source timing map recovery;
- event/report semantic assembly;
- independent output digest.

Audit selection is risk-weighted but contains a uniform random component. Failure creates a repair obligation and can revoke durability qualification.

## 13. Deletion closure

Deletion is a graph operation:

1. resolve all roots and reverse references within authority scope;
2. apply holds, legal/privacy policy, and replica inventory;
3. prepare a sealed deletion plan;
4. tombstone discovery surfaces;
5. delete children/roots at each destination with generation fences;
6. delete/rotate key material where cryptographic erasure is applicable;
7. rebuild derived indexes and caches;
8. prove no undeclared reachable copy remains in registered stores;
9. emit `DeletionClosed` or explicit residual findings.

Unknown/unregistered destinations prevent a complete-deletion claim.

## 14. ATP is not an effect bus

PTZ, siren, spotlight, camera settings, credentials, policy activation, retention mutation, and drone control do not ride ATP. They need request identity, bounded preconditions, fencing, idempotency, operation lookup, observed mutation, and reconciliation. ATP may move an immutable plan or evidence bundle, never confer mutation authority.

## 15. Reference model

The initial oracle is single-threaded and local:

- ordered manifest children;
- one path;
- no compression;
- no repair symbols;
- fixed chunk size;
- deterministic crash injection after each journal record;
- independent full rehash before root publication.

Optimized multipath, dedup, repair, direct I/O, and concurrency must produce the same root and exposure decision.

## 16. Admission gates

ATP production admission requires:

- corruption/truncation/reordering/duplication campaigns;
- crash at every journal/publication state;
- resume equivalence;
- path race and drain-leak tests;
- graph-depth/size/resource attacks;
- quarantine non-bypass;
- repair decode drills;
- cloud readback and provider-error reconciliation;
- privacy/destination policy noninterference;
- deletion closure;
- same-root equivalence across scheduling policies;
- bounded diagnostic/scheduler feedback.
