# Queries across pinned recording catalogs

The native recording metadata reader can query a bounded set of AVC or HEVC
catalogs in one request. This advances VIT-008 (`fss-vit-je36t.8`): an interval
can span several catalogs without requiring the caller to combine independent
results, double-count repeated windows, or infer gaps from a single page.

This is reference functionality. Its scope is explicitly selected published
metadata, not global archive discovery, source-media retrieval, live camera
coverage, or a release-qualified recorder.

## Native contract

`fss_reference::agent_recordings::set::query_recording_set` accepts a
`RecordingSetQueryRequest` with one to eight `RecordingCatalogPin { slot, root }`
values. Every catalog must match the exact codec, sensor, stream generation,
historical source anchor, receive clock, decode clock and tick rate in the
request. Different clocks or generations cannot be merged by relabelling ticks.

The half-open request interval uses that native decode clock. Catalog pins are
sorted canonically before reading and hashing. Reordering the same pins does not
change the request or decision identity. Repeated catalog slots or roots refuse
before filesystem access; no implicit "latest" lookup or directory enumeration
occurs.

Every catalog and member publication is verified, including members outside the
requested interval. Identical window descriptors found in several catalogs
become one output row with every catalog root and original ordinal retained.
That row contributes its whole-window byte quote once. Inconsistent descriptors
for a reused slot or root refuse the complete request. Distinct overlapping
windows remain distinct and retain their separate costs.

Gaps are computed over the union of the selected indexed intervals. They mean
that none of these explicit indexes contains a window for those ticks. They do
not establish why footage is missing, whether another catalog contains it, or
whether physical activity was absent. Payload availability remains unknown:
the query reads metadata and publication records, never source media.

## Shared bounds and change detection

One request-owned `PinnedMetadataReader` meters all catalogs, members and final
revalidation. No allowance is refilled when moving to another catalog.

| Bound | Default ceiling |
| --- | ---: |
| Explicit catalogs | 8 |
| Aggregate admitted window descriptors, including repeated memberships | 64 |
| Distinct publication bindings | 72 |
| Manifest and typed metadata objects | 80 |
| Manifest edges | 1,024 |
| Archive read bytes | 8 MiB |
| Archive filesystem calls | 10,000 |

The aggregate descriptor bound applies after each independently bounded native
catalog parse; it is not a parser-iteration meter. Read bytes and filesystem
calls are charged even when the subsequent descriptor admission refuses.
Selection count and the quoted later hydration bytes have separate bounds.

Before a result is released, every admitted metadata object is rehashed and
every exact publication binding and referenced deletion marker is checked
again. An earlier catalog binding, metadata object, or deletion marker that
differs at final revalidation invalidates the whole request. Cancellation,
missing metadata, conflicting
descriptors, pending publication or exhausted allowance returns a refusal,
never a successful prefix.

The result also carries the complete reference union, including unselected
member roots and source leaves, for a protected caller to check against its
current deletion authority. These filesystem observations do not create an
atomic snapshot or grant authority to hydrate or disclose media.

## Regression scope

`agent_recordings_set_contract` exercises real synthetic AVC/HEVC recording
and catalog encodings. It covers duplicate membership and cost, canonical input
order, catalog-bound row identity, scope and pin refusal, shared budgets,
overlapping intervals, conflicting rehashed descriptors, cancellation,
unselected members, and mutations that require final global revalidation.

The initial implementation has passed scoped pinned-toolchain Rust formatting
and independent source review. Native execution and deployment qualification
must be reported separately; authored tests are not a test pass.
