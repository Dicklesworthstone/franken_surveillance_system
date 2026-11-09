# Metadata discovery across a native recording archive

VIT-008 (`fss-vit-je36t.8`) requires usable retained-footage queries. Exact
singleton and catalog-set queries already exist, but they require the caller to
know every catalog slot and root. Native discovery removes that requirement for
one explicitly selected AVC or HEVC archive namespace. It can inspect an ordinary
archive spanning many full catalog pages while returning a small complete result.

This is reference functionality over published metadata. The caller still names
the archive owner, codec, sensor, stream generation, historical source anchor,
receive clock, decode clock and tick rate. These exact pins derive the existing
archive writer's namespace; discovery does not register a source or combine
different generations or clocks.

## Native decode-clock API and completeness

`fss_reference::agent_recordings::discover::discover_recordings` accepts a
`RecordingDiscoveryRequest` and finite `RecordingDiscoveryLimits`. The request
selects a half-open interval in the explicitly named decode clock. No catalog
slot/root list is needed.

The reader enumerates the existing roots directory within a finite allowance.
Only the selected literal namespace is interpreted. Its canonical window and
catalog slots must form a contiguous sequence starting at window zero. Every
window must belong to exactly one verified page, with matching slot/root
membership and coherent nonoverlapping decode intervals across pages. Every page
and member manifest is checked, including windows outside the requested interval.

A published but unindexed tail returns `UnindexedWindows`. Missing ordinals,
overlapping pages, conflicting membership, pending publication, corrupt metadata,
deletion markers, exhausted bounds or cancellation refuse the complete query.
This query never opens a publisher, recovers or repairs an archive, acquires a
writer lock, or reads source media. The existing archive writer remains the owner
of indexing and recovery.

An empty namespace is a valid empty metadata observation with an indexed gap
covering the requested interval. It establishes neither physical absence nor
source payload availability. A gap within a populated namespace has the same
limited meaning: no verified index entry covers those native ticks.

## Shared work bounds

The existing `PinnedMetadataReader` now offers one optional bounded namespace
observation. Exact-pin queries retain their original behavior without directory
scans. A discovery reader shares one nonrefillable byte/I/O allowance across its
initial inventory, all page and member verification, and complete final
revalidation. The final scan must observe the same selected root records and
membership. Unrelated entries consume enumeration allowance but their contents
are not read or interpreted.

| Default native decode-clock bound | Ceiling |
| --- | ---: |
| Root-directory entries per observation, including unrelated entries | 16,384 |
| Verified archive windows | 4,096 |
| Verified catalog pages | 1,024 |
| Selected output windows | Request supplied, at most 64 |
| Publication bindings | 5,120 |
| Manifest and typed metadata objects | 6,144 |
| Manifest edges | 65,536 |
| Archive read bytes, including final verification | 64 MiB |
| Archive filesystem calls, including final verification | 1,000,000 |

The larger scan allowance is independent of the smaller output limit. A query
matching too many windows refuses rather than returning a successful prefix.
Narrowing the interval reduces output and its quoted hydration cost, without
skipping verification of the remaining namespace.

Results carry the namespace digest, an inventory digest binding every sorted
root record, all verified page identities, selected window handles with exact
catalog memberships, indexed gaps, actual read usage and a decision digest.
Each selected window contributes its entire later hydration byte quote. That
quote grants no media authority. The complete reference union includes all
unselected member source leaves so protected callers can apply current deletion
restrictions before releasing a result.

Matching observations are a bounded change-detection mechanism, not an atomic
filesystem snapshot or a guarantee that source payloads are retrievable.

## UTC discovery with a retained clock

`agent_recordings::utc_discover::discover_recordings_utc` accepts a
`RecordingUtcDiscoveryRequest` with the same exact source namespace, an
independently pinned retained-clock slot/root, and a half-open Unix-nanosecond
interval. It discovers the complete canonical catalog universe without requiring
manual catalog pins. The clock slot must be the one derived from the full codec,
source generation and clock scope; discovering pages never substitutes a new
clock root for the caller's pin.

Tick discovery and UTC discovery share the same namespace verifier and inventory
identity. UTC discovery and the explicit UTC-set reader share the same complete
clock join and temporal selection. Neither shared helper creates or finishes a
reader. One `PinnedMetadataReader` owns the initial namespace observation, every
catalog and member, clock reconstruction, complete closure checks, and final
metadata/publication/tombstone/namespace revalidation. The implementation does
not compose two public queries with independent allowances.

Every retained clock row must match an exact verified namespace member before
selection. An empty namespace or missing page cannot discard a clock member and
produce an empty success. Catalog windows with no retained clock annotation stay
explicitly `clock_unavailable` and are returned regardless of the requested UTC
interval. They consume the same output and whole-window hydration-quote limits
as known-time candidates. If the complete selection cannot fit, the query
refuses; narrowing time cannot exclude a window whose time is unavailable.

The full namespace bounds remain 4,096 windows and 1,024 pages, independently of
the retained clock's 64-window format limit. This allows ordinary capture pages
and sparse clock annotations beyond the eight explicit-pin page ceiling. The
UTC reader adds one clock publication, its manifest and typed index, and its
maximum flat reference closure to the existing discovery allowance:

| Default native UTC bound | Ceiling |
| --- | ---: |
| Root-directory entries per observation | 16,384 |
| Verified archive windows / catalog pages | 4,096 / 1,024 |
| Retained clock annotations | 64 |
| Complete selected output, including unavailable clocks | Request supplied, at most 64 |
| Publication bindings | 5,121 |
| Distinct manifest and typed metadata objects | 6,146 |
| Manifest reference edges | 65,857 |
| One metadata object | 16 MiB |
| Aggregate read bytes / filesystem calls, including final verification | 64 MiB / 1,000,000 |

The object allowance covers 4,096 recording manifests, 1,024 catalog
manifest/index pairs and one clock manifest/index pair. Actual aggregate bytes,
edges and filesystem work remain separately bounded; a cardinality ceiling is
not a promise that every object combination fits every other limit. Caller
limits may narrow these ceilings, including to zero, but cannot enlarge them.

Results add the clock root, canonical clock metadata digest, retained approval
identity, reconstructed correction interval and policy, clock-window/bracket
counts, and the same conditional UTC rows used by explicit UTC-set queries.
Catalog positions follow canonical page order; rows preserve native decode
order and their exact page membership. Request and decision identities use
`fss.agent_recordings.utc_discovery.request.v1` and
`fss.agent_recordings.utc_discovery.decision.v1`; existing tick-discovery and
explicit-pin identities are unchanged. Unrelated directory entries consume
scan/I/O allowance but do not change the selected inventory identity.

Declared UTC gaps exclude only the union of conditional node-observation
envelopes. Windows with unavailable clocks may overlap those gaps. This read
does not authenticate UTC, replay packet admissions, establish camera exposure
time or infer physical coverage. See the [retained-clock query guide](
RECORDING_CLOCK_METADATA_QUERY.md) for the exact inclusive-envelope selection
and uncertainty rules.

## CLI and MCP

Use `--discover-catalogs yes` with the existing recording target and exact source
pins. Shell variables below represent actual owner-selected paths and historical
source/clock digests:

```bash
fss query --json --target recordings \
  --root "$deployment_root" --archive-root "$archive_root" \
  --codec avc --discover-catalogs yes \
  --sensor sensor:front-door --stream stream:primary --generation 1 \
  --source-anchor "$source_anchor" --receive-clock "$receive_clock" \
  --decode-clock "$decode_clock" --time-scale 90000 \
  --start-tick 0 --end-tick 180000 \
  --max-windows 32 --max-hydration-bytes 67108864
```

Use `--codec hevc` for HEVC. `--principal` and `--anchor` keep their existing
current-deployment meanings. To query UTC, replace the two tick bounds with
`--clock-slot "$clock_slot" --clock-root "$clock_root"` and
`--start-utc-ns "$start_utc_ns" --end-utc-ns "$end_utc_ns"` while retaining
`--discover-catalogs yes` and every source pin. Discovery cannot be combined with
`--catalogs` or singleton catalog pins, and decode-tick and UTC bounds cannot be
mixed. Explicit singleton and catalog-set queries retain their existing grammars
and limits.

The MCP `query` tool accepts `"target":"recordings"` and
`"discover_catalogs":true` with the same source pins and either tick bounds or
`clock_slot`, `clock_root`, `start_utc_ns` and `end_utc_ns`. The
flag must be Boolean `true`; omission leaves the existing explicit-pin modes.
Pass generation, tick/UTC bounds and hydration-byte limits as decimal strings so
values above JavaScript's exact integer range remain intact. `time_scale` and
`max_windows` retain their bounded integer schemas. The deployment and archive
roots come from the server's launch configuration; a request cannot override
either owner or the principal. MCP uses the same native CLI parser, execution
and AOP-005 response.

## Protected context and compact output

`agent_recording_context::discover::discover_recordings_in_deployment` reads
deployment history before and after the full archive query, sharing one
deployment allowance across both reads. It refuses stale expected anchors,
changed deployment history/layout and committed deletion intersecting **any**
verified archive reference, including source leaves outside the selected interval.
Historical archive scope does not create current source registration.

`agent_recording_context::utc_discover::discover_recordings_utc_in_deployment`
applies the same bracketed deployment and complete-reference deletion checks to
UTC discovery, including unselected windows and the clock's flat closure. Its
plan binds the complete namespace inventory and exact clock root. Only selected
pages are expanded into propositions and evidence handles, so a large scanned
namespace does not force an unbounded response. Clock-unavailable rows remain
`not_observable`; the retained clock conditions and protected current situation
remain visible even for a known-time selection with no matching rows.

The answer retains current situation hypotheses and obligations. Its inventory
proposition identifies the exact namespace and inventory digests, total verified
pages/windows, selected count, scope and quote. Only pages supporting selected
windows are expanded into catalog propositions and H0-only evidence handles.
All other pages remain bound by the complete inventory digest; scanning a large
archive does not require dumping that archive into the agent response. Every
selected row preserves its exact catalog root and ordinal.

Indexed gaps remain `not_observable`, while physical presence/absence, trusted
UTC and source-payload availability remain `unknown`. Empty decode-clock namespaces retain
current protected context and the same explicit uncertainty. No media hydration,
export, recovery or source contact is performed.

The protected CLI/MCP path allows at most 32 selected windows, a complete
response of at most 256 KiB, and a cooperative 60-second read deadline. Any
selection, response, budget or cancellation failure refuses the complete query;
it never turns a truncated result into success.

## Verification scope

`pinned_namespace_contract` covers root membership addition/removal/rebinding,
pending or malformed records, symlinks, unrelated namespaces, nonrefillable scan
and metadata budgets, cancellation and final revalidation.
`agent_recordings_discovery_contract` covers real synthetic AVC and HEVC archives
of 130 windows over three ordinary catalog pages, narrow cross-page queries,
absent source payloads, empty namespaces, unindexed tails, corruption, sequence
failures and mutations during the query. Synthetic fixtures do not establish
physical camera coverage or production readiness.

Eight protected-context contracts include a real authorized fixture import and
committed deletion that denies an unselected source while the independent archive
remains intact. Five CLI process contracts exercise both codecs, selected-only
projection, empty-namespace context, overflow, corruption and an unindexed tail.
CLI grammar and MCP dispatch contracts cover exact pins/integers, fixed owners,
mode exclusion and byte-identical success/refusal forwarding.

`agent_recordings_utc_discovery_contract` adds ten native contracts covering
AVC/HEVC captures of nine, 64 and 65 windows, native eight-window pages, more than
eight discovered pages, complete clock joining, and 128/129-window namespaces
whose unavailable-clock remainder reaches/exceeds the output bound. They also
cover exact shared-budget accounting, absent/corrupt source payloads, empty or
truncated clock universes, namespace mutation, late clock/source deletion,
cancellation and parity with the existing selection/inventory owners. Six
protected CLI/MCP/context contracts exercise nine pages, selected-page output,
unknown-clock quotes, changed deployment heads and committed deletion of an
unselected source. These new contracts have been source-reviewed and formatted;
they have not executed because the pinned build was killed while compiling
unchanged Asupersync before reaching these Rust paths.

The core checkpoint is `56146fab5ec9525d900cc63f59c5d9df408e664c`. Native
execution and qualification results are recorded in the session handoff; test
source alone is not a native pass or release qualification.
