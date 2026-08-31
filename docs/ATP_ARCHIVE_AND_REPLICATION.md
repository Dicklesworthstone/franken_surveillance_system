# ATP archive, replication, repair, and retrievability plane

**Document class:** normative transfer architecture
**Revision:** 1
**Date:** 2026-08-31
**Schema:** [`../schemas/transfer_receipt.v1.json`](../schemas/transfer_receipt.v1.json)

## 1. ATP's role

Asupersync Transfer Protocol (ATP) is FSS's bulk immutable object-graph movement plane. It transports:

- source media and derivatives;
- evidence/event/export bundles;
- authority checkpoints and delta ranges;
- graph/search/model/calibration/twin generations;
- replay corpora and crashpacks;
- model packages and repair symbols;
- release/proof artifacts.

ATP is **not** the effect transport for PTZ, alerts, deletion authorization, model activation, or any non-idempotent mutation. Those use semantic effect protocols with fencing and reconciliation.

## 2. Object graph

A transfer root names a manifest. The manifest names child objects, which may name chunks and repair symbols. Identities are domain-separated content digests over canonical bytes and metadata. The receiver verifies:

- manifest schema/version/limits;
- every object digest;
- parent-child closure;
- encryption/authentication metadata;
- expected source and destination policy;
- post-repair reconstructed digest;
- root identity.

Publication occurs only after complete verification.

## 3. Chunking and layouts

Chunking policy depends on object family and workload, not one global constant. The policy considers:

- camera segment/keyframe boundaries;
- object-store operation cost;
- local filesystem alignment and cache behavior;
- resume granularity;
- RaptorQ symbol size and loss model;
- deduplication value and privacy leakage;
- retrieval pattern;
- maximum verification memory.

Content-defined chunking is not automatically superior; stable media/container boundaries can preserve streaming semantics and reduce metadata.

## 4. Transfer lifecycle

```text
Planned
→ Reserved
→ ManifestVerified
→ Fetching
→ Staged
→ ObjectVerified
→ GraphClosed
→ RootPublished
→ RetrievabilityVerified
→ Complete
```

Cancellation drains in-flight paths and leaves a resumable journal. A transfer can also terminate `Failed`, `Cancelled`, or `Indeterminate` with exact obligations.

## 5. Multipath and hedging

Path candidates can include local disk, LAN peer, cloud providers, and repair sources. A transfer brain may race/hedge paths based on measured latency, throughput, cost, failure, and pressure. Losing paths are cancelled and drained; they cannot leak sockets, temporary objects, or billing work.

Adaptive choice is clamped by integrity, privacy, residency, and cost policies. It cannot choose an unauthorized replica because it is faster.

## 6. RaptorQ and repair

Repair symbols are immutable children tied to an exact object generation. Adaptive repair overhead uses a safe baseline plus shadow-measured policy; it never claims recovered data until the reconstructed canonical digest matches.

Repair lifecycle:

1. detect missing/corrupt symbols;
2. plan immutable repair against a sealed root;
3. acquire repair lease/fence;
4. stage reconstruction;
5. verify reconstructed canonical digest;
6. publish repaired replica/object root;
7. refresh repair symbols only after source object durability;
8. record decode and custody evidence.

Stale repair symbols or changed source generations fail closed.

## 7. Provider adapters

FSS owns narrow object protocols rather than linking broad cloud SDKs. An adapter provides bounded operations such as:

- create/abort multipart upload;
- put/get ranged object;
- list exact manifest prefix with continuation;
- head/verify metadata;
- conditional publish/copy;
- delete exact object generation.

Credentials are capability-scoped and never enter manifests or transfer receipts. Provider-specific behavior is isolated below common object semantics.

## 8. Archive states

An archive object progresses through distinct states:

```text
local_staged
local_durable
remote_staged
remote_children_verified
remote_root_published
replication_policy_satisfied
retrievability_sample_passed
```

“Uploaded” is not synonymous with archived. Policy can require multiple independent providers/failure domains.

## 9. Proof of retrievability

FSS periodically samples retained object graphs using deterministic or unpredictable policy as appropriate. A proof records:

- object/root and replica generation;
- challenge/sample identity;
- requested byte/symbol ranges;
- expected and observed digests;
- latency/cost;
- provider/path;
- result and repair action.

A failed sample schedules repair/re-replication and changes readiness. It is never silently ignored.

## 10. Deletion closure

Deletion is graph-complete. A deletion plan enumerates:

- source/derivative chunks and manifests;
- repair symbols;
- local/remote replicas;
- indexes, embeddings, graph relations, caches;
- transfer journals and staging objects;
- exported bundles under FSS custody;
- retained tombstone/audit records allowed by policy.

Apply revalidates the basis root and authorization, deletes children according to provider semantics, publishes a tombstone root, and verifies unreachability. Unknown external copies are reported rather than falsely claimed deleted.

## 11. Cost-aware planning

The planner estimates storage, Class A/B operations, retrieval, egress, repair overhead, and minimum retention. Pricing is an input manifest with date/source, not code constants. A plan can choose object size, provider, replication, and scrub cadence, but hard durability/privacy constraints dominate cost.

## 12. Admission tests

- corruption, truncation, duplicate, reorder, and symbol-loss campaigns;
- process death at every lifecycle transition;
- resume with stale journal and changed destination generation;
- multipath winner/loser drain;
- provider eventual-consistency and partial-list fixtures;
- multipart orphan cleanup;
- post-repair digest mismatch refusal;
- local/remote root-last visibility;
- retrievability failure and repair loop;
- graph-complete deletion with hidden-reference adversarial corpus;
- credential/tenant capability noninterference;
- same-binary chunk/repair policy experiments;
- full reconstruction from manifests on an independent implementation.
