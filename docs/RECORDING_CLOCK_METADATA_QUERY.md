# Pinned recording lookup by retained clock metadata

The native `agent_recordings::utc::query_recordings_utc` read selects AVC/HEVC
recording candidates by a half-open Unix-nanosecond interval. It requires independent
immutable catalog and clock-index pins, the original source/generation/clock scope,
and an exact clock publication namespace. It reads publication and typed metadata
only; original media and packet coordinates are not replayed.

## What is established

The sealed `RecordingClockMetadata` verifier reconstructs the existing retained
clock format: raw local NTP exchange, completed host-read brackets, fixed drift and
lifetime policy, original window descriptors, complete flat closure and inclusive
node-observation envelopes. Every clock entry must match the independently pinned
catalog before time filtering. Its private backing index cannot be passed to the
source-verified clock publication API.

These are **conditional retained claims**, not trusted UTC, camera exposure times or
proof that a packet was received at the declared coordinate. The original
`load_clock_index` owner still performs source replay when that stronger check is
required. The metadata result exposes the original signed correction interval,
sample-bracket ceiling, drift assumption and synchronization lifetime. A historical
approval digest grants no current acquisition, hydration or disclosure authority.

## Selection and gaps

A closed declared envelope `[lo, hi]` is a candidate for request `[start, end)` when
`hi >= start` and `lo < end`. Whole recording handles and their complete hydration
quotes are returned. Native decode coordinates and all source pins remain attached.

Every catalog member without a matching clock entry is returned explicitly as
`clock_unavailable`, even when the request lies outside the known clock envelopes.
Such rows consume the same window and byte-quote quotas. They cannot be silently
excluded by an unavailable time mapping. If all required rows exceed either quota,
the query refuses atomically.

`indexed_gaps` describes parts of the request outside the union of declared clock
envelopes. Unannotated windows may overlap those gaps. The gaps do not establish
missing source recordings, why footage is unavailable, continuous coverage or
physical absence. Source-media availability remains unknown for every result.

## Bounded read owner

The catalog, clock index, every member publication, both complete flat closures and
final metadata/slot/tombstone revalidation share one `PinnedMetadataReader`.
Default native ceilings are 64 catalog members, 66 pinned roots, 132 metadata
objects, 1,024 reference edges, 16 MiB per metadata object, 64 MiB total read bytes
and 20,000 filesystem calls. No allowance refills during final revalidation.

The path opens no publisher or recovery owner, takes no writer lock, scans no
archive directory, contacts no device and reads no original media. Malformed,
repinned, tombstoned, cancelled or over-budget observations cannot become a
successful empty result. Computation inside a bounded canonical decode is not
preemptively cancellable; the request checks cancellation again before a result
can escape.

`agent_recording_context::utc::query_recordings_utc_in_deployment` brackets this
read with metadata-only deployment history replay. Both passes share a separate
256 MiB / 65,536-read allowance. Exact authority/effect prefix, layout and deletion
state must agree. Any committed deletion anywhere in the complete catalog/clock
closure refuses the read, including unselected windows and source children.
The tick-based query uses the same complete-closure deletion check.

Current protected situation knowledge remains part of the canonical AOP-005
query/case response. The principal is an audit label. Separately verified archive
and deployment observations are not an atomic snapshot or proof of source
registration. CLI/MCP integration uses the same existing `recordings` target with mutually exclusive
UTC flags; see [the native recording query guide](AGENT_NATIVE_RECORDING_QUERY.md).

## UTC selection across native capture pages

`agent_recordings::utc_set::query_recordings_utc_set` extends the same conditional
UTC interpretation to an explicit set of one through eight catalog pins. Native
capture publishes eight windows per catalog page while one retained clock index
may describe up to 64 windows. Selecting only one of those pages cannot establish
the clock's complete descriptor universe. The set reader verifies every pinned
page, then requires every clock entry to match an exact member of their union
before applying the requested time interval. An omitted clock member refuses the
whole query, including a query whose interval would otherwise return no rows.

The request pins one codec, source/generation/clock scope, unordered catalog set
and independently pinned clock index. Pins are sorted canonically; duplicate
catalog slots or roots refuse. An identical recording appearing in multiple
catalogs retains every catalog index, root and original ordinal in its result
row, while its window quota and whole-window byte quote are charged once. A root
with conflicting descriptors, or a slot naming different roots, refuses. The
same `clock_unavailable` handling and conditional gap semantics described above
apply across the complete union.

The shared default allowance supports eight full native capture pages:

| Ceiling | UTC catalog-set read |
| --- | ---: |
| Explicit catalogs | 8 |
| Aggregate catalog descriptors, including repeated memberships | 64 |
| Pinned publication roots | 73 |
| Distinct metadata objects read | 82 |
| Manifest reference edges | 2,048 |
| Bytes in one metadata object | 16 MiB |
| Aggregate read bytes, including final revalidation | 64 MiB |
| Filesystem calls, including final revalidation | 20,000 |

The 82-object allowance covers 64 recording manifests, eight catalog
manifest/index pairs and one clock manifest/index pair. Recording metadata and
original payloads remain unopened; their complete references still participate
in local tombstone checks and the protected caller's deletion-state check. One
`PinnedMetadataReader` owns the entire request and revalidates early pages and the
clock after selection. There is no per-page budget refill or partial successful
result after a bound, cancellation, mutation or deletion refusal.

Set request, row and decision identities use separate
`fss.agent_recordings.utc_set.*.v1` domains. The original singleton request,
response and digest identities are unchanged. This entry point requires explicit
catalog pins; directory discovery does not imply permission to construct a UTC
catalog universe or obtain a fresh read allowance.

## Validation scope

The UTC catalog-set extension adds twelve native contracts and five CLI/context
contracts, plus parser and MCP cases. They cover both codecs, nine- and 64-window
captures, duplicate memberships, unknown clocks, atomic output/quote ceilings,
shared read budgets, incomplete page unions, revoked sources and late metadata
or deployment changes. Source reviews and pinned scoped formatting have passed;
the 21 new UTC-set tests remain unexecuted.

On 2026-11-09, both the linked native UTC test build and a metadata-only check
were killed with signal 9 while compiling unchanged Asupersync 0.5.0, before
reaching the changed Rust paths. Both used the complete pinned nightly, locked
offline dependencies, one Cargo job, no incremental compilation and zero debug
information. The schema suite passed 64 cases with one existing skip, and the
changed-file integrity checks passed. See [the exact commands and shared validation
scope](../IMPLEMENTATION_STATUS.md#retention-and-utc-catalog-set-validation--2026-11-09).

The bounded query and its adversarial contracts require the repository's pinned
native compiler and unchanged locked production dependencies. On 2026-11-07, two
attempts at the complete native dependency check were killed compiling unchanged
Asupersync 0.5.0, including the recorded serialized low-memory configuration.
Independent source review and scoped Rust formatting are supplementary checks;
they do not establish a Rust test pass or release qualification.
