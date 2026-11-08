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

## Native API and completeness

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

| Default native bound | Ceiling |
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

## Verification scope

`pinned_namespace_contract` covers root membership addition/removal/rebinding,
pending or malformed records, symlinks, unrelated namespaces, nonrefillable scan
and metadata budgets, cancellation and final revalidation.
`agent_recordings_discovery_contract` covers real synthetic AVC and HEVC archives
of 130 windows over three ordinary catalog pages, narrow cross-page queries,
absent source payloads, empty namespaces, unindexed tails, corruption, sequence
failures and mutations during the query. Synthetic fixtures do not establish
physical camera coverage or production readiness.

At the initial native-core checkpoint, these contracts are authored and scoped
pinned-rustfmt checks pass. The real pinned-toolchain baseline build is still in
progress; this document does not claim native test execution or release
qualification. Protected deployment, CLI and MCP integration is the next
checkpoint in the same session.
