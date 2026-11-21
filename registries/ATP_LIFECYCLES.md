# ATP transfer, path, and archive lifecycle registry

**Machine source:** [`architecture/atp_lifecycles.json`](../architecture/atp_lifecycles.json)
**Tracking bead:** `fss-x4a.13.31`
**Receipt schema:** [`schemas/transfer_receipt.v1.json`](../schemas/transfer_receipt.v1.json) (`fss.transfer_receipt.v1`)
**Reference implementation:** `crates/fss-object/src/atp_lifecycle/`

This registry reconciles the normative ATP documents (`docs/ATP_AND_DISTRIBUTED_EVIDENCE.md`,
`docs/ATP_ARCHIVE_AND_REPLICATION.md`, and `docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md`) into one
layer-qualified vocabulary without erasing their distinct layers or silently discarding any legacy
document spelling. No transport may invent unlisted aliases.

## Non-collapse rules

`offered`, `received`, `verified`, `graph_closed`, `durable`, `committed`, `published`,
`replicated`, `retrievable`, `protected`, and `complete` are never synonyms.

- Delivery of bytes or path completion never grants retention, indexing, activation, or effect authority.
- Root visibility is always last and requires verified child closure, post-repair canonical digests,
  live authorization, and the current publication fence.
- `Indeterminate` means remote semantic commit or publication may have occurred and lookup cannot
  resolve; it owns a durable reconciliation obligation.
- Cancellation stops new offers, drains all losing and in-flight paths, seals a checksummed
  resumable journal, and classifies every staged child as reusable, quarantined, or collectable.

## Layer 1 — Semantic transfer lifecycle (`atp.semantic.*`)

Forward progression:
`Proposed → Reserved → Offered → Receiving → ChildrenVerified → GraphClosed → DurabilitySatisfied → RootCommitted → ReceiptSealed`

| Canonical State | Name | Terminal | Allowed Next States |
|---|---|---|---|
| `atp.semantic.proposed` | `Proposed` | no | `Reserved`, `Rejected`, `Aborted` |
| `atp.semantic.reserved` | `Reserved` | no | `Offered`, `Rejected`, `Aborted` |
| `atp.semantic.offered` | `Offered` | no | `Receiving`, `Aborted`, `Quarantined` |
| `atp.semantic.receiving` | `Receiving` | no | `ChildrenVerified`, `Aborted`, `Quarantined` |
| `atp.semantic.children_verified` | `ChildrenVerified` | no | `GraphClosed`, `Aborted`, `Quarantined` |
| `atp.semantic.graph_closed` | `GraphClosed` | no | `DurabilitySatisfied`, `Aborted`, `Quarantined` |
| `atp.semantic.durability_satisfied` | `DurabilitySatisfied` | no | `RootCommitted`, `Aborted`, `Quarantined`, `Indeterminate` |
| `atp.semantic.root_committed` | `RootCommitted` | no | `ReceiptSealed`, `Indeterminate` |
| `atp.semantic.receipt_sealed` | `ReceiptSealed` | yes | `Superseded` |
| `atp.semantic.rejected` | `Rejected` | yes | none |
| `atp.semantic.aborted` | `Aborted` | yes | none |
| `atp.semantic.quarantined` | `Quarantined` | yes | none |
| `atp.semantic.indeterminate` | `Indeterminate` | yes | none |
| `atp.semantic.superseded` | `Superseded` | yes | none |

## Layer 2 — Archive publication lifecycle (`atp.archive.*`)

Forward progression:
`Planned → Reserved → ManifestVerified → Fetching → Staged → ObjectVerified → GraphClosed → ExposureReady → RootPublished → ReplicaQualified → RetrievabilityVerified → Complete → Scrubbed → Retired`

| Canonical State | Name | Terminal | Allowed Next States |
|---|---|---|---|
| `atp.archive.planned` | `Planned` | no | `Reserved`, `Cancelled`, `Failed` |
| `atp.archive.reserved` | `Reserved` | no | `ManifestVerified`, `Cancelled`, `Failed` |
| `atp.archive.manifest_verified` | `ManifestVerified` | no | `Fetching`, `Cancelled`, `Failed`, `Quarantined` |
| `atp.archive.fetching` | `Fetching` | no | `Staged`, `Cancelled`, `Failed`, `Quarantined` |
| `atp.archive.staged` | `Staged` | no | `ObjectVerified`, `Cancelled`, `Failed`, `Quarantined` |
| `atp.archive.object_verified` | `ObjectVerified` | no | `GraphClosed`, `Cancelled`, `Failed`, `Quarantined` |
| `atp.archive.graph_closed` | `GraphClosed` | no | `ExposureReady`, `Cancelled`, `Failed`, `Quarantined` |
| `atp.archive.exposure_ready` | `ExposureReady` | no | `RootPublished`, `Cancelled`, `Failed`, `Quarantined`, `Indeterminate` |
| `atp.archive.root_published` | `RootPublished` | no | `ReplicaQualified`, `Failed`, `Indeterminate` |
| `atp.archive.replica_qualified` | `ReplicaQualified` | no | `RetrievabilityVerified`, `Failed`, `Indeterminate` |
| `atp.archive.retrievability_verified` | `RetrievabilityVerified` | no | `Complete`, `Failed` |
| `atp.archive.complete` | `Complete` | no | `Scrubbed`, `Retired` |
| `atp.archive.scrubbed` | `Scrubbed` | no | `Scrubbed`, `Retired`, `Quarantined` |
| `atp.archive.retired` | `Retired` | yes | none |
| `atp.archive.quarantined` | `Quarantined` | yes | none |
| `atp.archive.cancelled` | `Cancelled` | yes | none |
| `atp.archive.failed` | `Failed` | yes | none |
| `atp.archive.indeterminate` | `Indeterminate` | yes | none |

### Archive object custody progression (`atp.archive_object.*`)

`local_staged → local_durable → remote_staged → remote_children_verified → remote_root_published → replication_policy_satisfied → retrievability_sample_passed`

## Layer 3 — Multipath transport path lifecycle (`atp.path.*`)

`Discover → Candidate → Probing → Active → Suspect → Draining → Closed`

| Canonical State | Name | Terminal | Allowed Next States |
|---|---|---|---|
| `atp.path.discover` | `Discover` | no | `Candidate`, `Draining` |
| `atp.path.candidate` | `Candidate` | no | `Probing`, `Draining` |
| `atp.path.probing` | `Probing` | no | `Active`, `Suspect`, `Draining` |
| `atp.path.active` | `Active` | no | `Suspect`, `Draining` |
| `atp.path.suspect` | `Suspect` | no | `Probing`, `Draining` |
| `atp.path.draining` | `Draining` | no | `Closed` (only when `live_work == 0`) |
| `atp.path.closed` | `Closed` | yes | none |

## Legacy and cross-document crosswalk

Every spelling across the normative ATP documents maps deterministically to a layer-qualified
canonical state. Spellings shared across layers (`Reserved`, `Receiving`, `GraphClosed`,
`Quarantined`, `Indeterminate`) must be layer-qualified and fail closed when supplied bare without a
layer selector.

| Legacy / Document Spelling | Source Document | Target Layer | Canonical State | Mapping |
|---|---|---|---|---|
| `ManifestVerified` | `docs/ATP_ARCHIVE_AND_REPLICATION.md` | `archive_publication` | `atp.archive.manifest_verified` | `distinct_canonical` |
| `ManifestValidated` | `docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md` | `archive_publication` | `atp.archive.manifest_verified` | `mapped_alias` |
| `PathsDiscovered` | `docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md` | `path` | `atp.path.candidate` | `layer_rehomed` |
| `ChildrenScheduled` | `docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md` | `archive_publication` | `atp.archive.fetching` | `mapped_alias` |
| `ChildVerified` | `docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md` | `archive_publication` | `atp.archive.object_verified` | `mapped_alias` |
| `ObjectVerified` | `docs/ATP_ARCHIVE_AND_REPLICATION.md` | `archive_publication` | `atp.archive.object_verified` | `distinct_canonical` |
| `GraphClosureVerified` | `docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md` | `archive_publication` | `atp.archive.graph_closed` | `mapped_alias` |
| `ExposureReady` | `docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md` | `archive_publication` | `atp.archive.exposure_ready` | `distinct_canonical` |
| `RootPublished` | `docs/ATP_ARCHIVE_AND_REPLICATION.md` | `archive_publication` | `atp.archive.root_published` | `distinct_canonical` |
| `ReplicaQualified` | `docs/ATP_MEDIA_GRAPH_AND_REPLICATION.md` | `archive_publication` | `atp.archive.replica_qualified` | `distinct_canonical` |
| `RetrievabilityVerified` | `docs/ATP_ARCHIVE_AND_REPLICATION.md` | `archive_publication` | `atp.archive.retrievability_verified` | `distinct_canonical` |

## Deterministic refusal rules

| Code | Rule |
|---|---|
| `atp.refuse.skipped_publication` | Reject any skipped or backward transition on any lifecycle layer. |
| `atp.refuse.root_before_child` | Reject root commit or root publication while any declared child is unverified, unclosed, or below required durability. |
| `atp.refuse.stale_fence` | Reject any operation presenting a fence older than the active publication lease/fence. |
| `atp.refuse.receipt_before_commit` | Reject sealing a committed receipt prior to `RootCommitted` / `RootPublished`. |
| `atp.refuse.path_close_live_work` | Reject closing any path with nonzero in-flight operations, buffers, or open handles, or bypassing `Draining`. |
| `atp.refuse.complete_without_retrievability` | Reject transitioning archive publication to `Complete` without a matching witnessed `RetrievabilityVerified` proof. |
| `atp.refuse.authority_revoked` | Reject progression after capability, privacy, or destination authorization is revoked or expired. |
| `atp.refuse.repair_digest_mismatch` | Reject post-repair verification unless the reconstructed canonical digest equals the manifest child digest. |
| `atp.refuse.unknown_spelling` | Reject unlisted aliases or unqualified cross-layer ambiguous spellings. |
| `atp.refuse.incompatible_version` | Reject unsupported format versions, unknown critical extensions, or stale generation/anchor bindings. |
