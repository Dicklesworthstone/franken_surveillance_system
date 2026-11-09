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
missing metadata, conflicting descriptors, pending publication or exhausted allowance returns a refusal,
never a successful prefix.

The result also carries the complete reference union, including unselected
member roots and source leaves, for a protected caller to check against its
current deletion authority. These filesystem observations do not create an
atomic snapshot or grant authority to hydrate or disclose media.

## CLI and MCP entrypoints

The existing `fss query --target recordings` command accepts `--catalogs` in
place of `--catalog-slot` and `--catalog-root`. Supply a comma-separated list
of exact `slot=sha256:<64 lowercase hexadecimal digits>` pairs. The other
source pins have their existing meanings. For example, with shell variables
set to actual approved roots and exact source identities:

```bash
fss query --json --target recordings \
  --root "$deployment_root" --archive-root "$archive_root" \
  --codec avc \
  --catalogs "catalog-one=$catalog_one_root,catalog-two=$catalog_two_root" \
  --sensor sensor:front-door --stream stream:primary --generation 1 \
  --source-anchor "$source_anchor" --receive-clock "$receive_clock" \
  --decode-clock "$decode_clock" --time-scale 90000 \
  --start-tick 0 --end-tick 180000 \
  --max-windows 32 --max-hydration-bytes 67108864
```

Use `--codec hevc` for the same HEVC metadata path. Optional `--principal` and
`--anchor` keep their existing current-deployment meanings. The catalog set
keeps one exact source/decode-clock scope. Choose either decode-tick bounds or
retained-clock UTC bounds; singleton catalog flags cannot accompany `--catalogs`.
Existing singleton tick and UTC queries retain their grammars and owners.

The MCP `query` tool exposes `catalogs` as an array of one to eight closed
objects with `slot` and `root` fields. Send the same source pins and selected time
bounds as in the CLI, using decimal strings for exact large integer pins. Its archive
root is fixed when the server launches; a request cannot override the deployment
or archive owner. MCP dispatches through the same native parser, execution and
response projection as the CLI. Both return the existing AOP-005 envelope,
not a separate export or media interface.

## Retained-clock UTC across catalog pages

Native capture publishes eight windows per catalog page, while one retained
clock companion can describe up to 64 windows. Use `--catalogs` to include every
page needed to bind that complete clock index. The native owner is
`agent_recordings::utc_set::query_recordings_utc_set`; it verifies the complete
catalog union and clock descriptor binding before selecting any UTC candidates.

With the same source pins as above, replace the tick bounds with all four UTC
options:

```bash
fss query --json --target recordings \
  --root "$deployment_root" --archive-root "$archive_root" \
  --codec avc \
  --catalogs "catalog-one=$catalog_one_root,catalog-two=$catalog_two_root" \
  --sensor sensor:front-door --stream stream:primary --generation 1 \
  --source-anchor "$source_anchor" --receive-clock "$receive_clock" \
  --decode-clock "$decode_clock" --time-scale 90000 \
  --clock-slot "$clock_slot" --clock-root "$clock_root" \
  --start-utc-ns "$utc_start_ns" --end-utc-ns "$utc_end_ns" \
  --max-windows 32 --max-hydration-bytes 67108864
```

MCP accepts the same `catalogs` array with `clock_slot`, `clock_root`,
`start_utc_ns` and `end_utc_ns`. Both UTC endpoints are exact decimal strings.
Tick fields, singleton catalog fields and `discover_catalogs` refuse in this
mode. The query does not discover additional pages or silently drop clock rows
whose catalog was omitted.

All pages, clock metadata, member roots and final checks share one archive
allowance: at most 73 publication bindings, 82 metadata objects, 2,048 manifest
edges, 64 MiB and 20,000 filesystem calls. The aggregate membership ceiling
remains 64. Every unannotated window stays `clock_unavailable` regardless of the
requested interval and consumes the same selected-window and hydration-quote
limits. Known-clock rows carry conditional node-observation intervals; indexed
gaps never certify physical absence. See the [retained clock metadata contract](RECORDING_CLOCK_METADATA_QUERY.md)
for the clock model and native capture-page regressions.

The protected owner is
`agent_recording_context::utc_set::query_recordings_utc_set_in_deployment`.
It preserves the current-deployment checks, H0-only handles and complete-or-refuse
output bounds described below. Each row retains every catalog membership, and
its whole-window hydration quote is counted once.

## UTC discovery without manual catalog pins

Use `--discover-catalogs yes` with the same exact source scope and retained-clock pins
to find every canonical page in that namespace. This mode does not have the explicit
catalog list's eight-page ceiling:

```bash
fss query --json --target recordings \
  --root "$deployment_root" --archive-root "$archive_root" \
  --codec avc --discover-catalogs yes \
  --sensor sensor:front-door --stream stream:primary --generation 1 \
  --source-anchor "$source_anchor" --receive-clock "$receive_clock" \
  --decode-clock "$decode_clock" --time-scale 90000 \
  --clock-slot "$clock_slot" --clock-root "$clock_root" \
  --start-utc-ns "$utc_start_ns" --end-utc-ns "$utc_end_ns" \
  --max-windows 32 --max-hydration-bytes 67108864
```

MCP uses `discover_catalogs: true` with the four clock/UTC fields. Manual catalog
pins and decode-tick bounds are excluded. The native owner is
`agent_recordings::utc_discover::discover_recordings_utc`; the protected owner is
`agent_recording_context::utc_discover::discover_recordings_utc_in_deployment`.

The complete namespace scan admits at most 4,096 windows, 1,024 pages and 16,384
root-directory entries per observation. Namespace discovery, all catalog/window
metadata, the clock join and final revalidation use one reader with 64 MiB and
1,000,000 filesystem calls. A missing page, unindexed tail, changed namespace,
revoked source or missing clock member refuses the complete query.

The output binds the complete inventory digest and counts, while listing catalog
details and H0 metadata handles only for selected windows. This keeps output
proportional to the requested result rather than the entire archive. Current
deployment deletion checks still cover every source reference, including all
unselected windows.

One clock companion can annotate at most 64 windows. Every other discovered
window stays clock-unavailable and remains a candidate under every UTC interval.
If those required unknowns exceed the selected-window or quote limit, the query
refuses. An explicit catalog-set query remains available when the caller intends
a smaller, independently pinned scope. See [the complete discovery contract](RECORDING_ARCHIVE_DISCOVERY.md).

## UTC across independently pinned capture sessions

The set modes above deliberately retain one exact source generation and clock
scope. For a UTC interval spanning capture sessions, use
`agent_recordings::utc_sessions::query_recordings_utc_sessions` and the existing
`recordings` target's `--sessions` selector. Each of at most eight inputs supplies
its own codec, original source scope, one to eight catalog pins and exact retained
clock pin. All inputs must identify the same sensor and stream. Decode ticks are
never compared across clocks or normalized into an inferred common epoch.

The session union reuses the same catalog and complete clock-join verifiers with
one shared reader. Per-input admission remains at most 64 descriptors; the whole
union admits at most 512, with 584 publication roots, 656 metadata objects,
16,384 manifest edges, 64 MiB total read bytes and 160,000 filesystem calls.
Every unknown-time member remains a candidate and consumes the aggregate output
and hydration-quote limits. A complete empty contribution from a later session
is allowed after the selected-row or quote budget reaches zero, provided that
its full catalog/clock and custody checks succeed.

Canonical session-pin digests determine source ordering; native decode ticks
determine ordering only within each source. Rows preserve the session index,
source identity and all catalog memberships. Every session's independent clock
policy, uncertainty and conditional gaps remain visible, alongside the
conditional union's gaps. Duplicate scopes or publication pins refuse before
I/O, and a window root or slot shared by distinct source scopes refuses rather
than being silently merged. The final global pass covers early sessions and
unselected references after all inputs have been admitted.

The protected caller retains current deployment context and checks the entire
reference union against current deletion authority. Its 32-row response bound
applies across all sessions. The request grants no source hydration or disclosure
authority, and independent retained UTC assertions do not establish synchronized
clocks or physical continuity. See [the capture-session UTC contract and
CLI/MCP syntax](RECORDING_SESSION_UTC_QUERY.md).

## Current deployment context and output

The protected reader is
`fss_reference::agent_recording_context::set::query_recording_set_in_deployment`.
It reads current deployment metadata before and after the complete native query
using one nonrefillable deployment allowance. An obsolete expected anchor,
changed current effect history or layout, or any committed deletion intersecting
the complete archive reference union refuses the whole query. Unselected member
sources participate in that check. Matching observations still do not promise an
atomic snapshot across the independently owned archive and deployment.

The response retains the current situation frame, hypotheses and obligations.
Catalog propositions identify every admitted catalog. Each unique window
proposition lists all immutable catalog memberships; overlap-derived indexed
gaps remain distinct from physical absence. Source payload availability and
trusted UTC stay unknown. Metadata handles are unique and H0-only. A whole-window
byte quote estimates later work and grants no media hydration or disclosure.

The CLI defaults to at most 32 selected unique windows. Its complete response
must fit within 256 KiB, and reads have a cooperative 60-second deadline.
Selection, budget, cancellation or output-size failure returns a refusal instead
of a truncated success.

## Regression scope

`agent_recordings_set_contract` exercises real synthetic AVC/HEVC recording
and catalog encodings. It covers duplicate membership and cost, canonical input
order, catalog-bound row identity, scope and pin refusal, shared budgets,
overlapping intervals, conflicting rehashed descriptors, cancellation,
unselected members, and mutations that require final global revalidation.

Nine deployment-context tests exercise current hypotheses, anchor changes,
shared budgets, writer locks, unread payload corruption, in-flight deployment
changes, and an actual committed deletion that leaves independent archive bytes
intact. CLI and MCP contracts cover strict grammar, both codecs, immutable owner
binding, refusal propagation and byte-identical native dispatch. Three process
contracts exercise the real CLI executable, canonical pin order, shared windows
and late-catalog refusal.

Validation results are recorded in the session handoff. Authored regression cases
and source review are not substitutes for native execution or deployment
qualification. VIT-008 remains open for automatic cross-session discovery,
stronger clock/source qualification, continuous operation and live qualification.
Explicit UTC catalog sets and bounded pinned-session unions are implemented;
[namespace discovery](RECORDING_ARCHIVE_DISCOVERY.md) also admits an exact
retained-clock UTC query through its own request and decision identities.
