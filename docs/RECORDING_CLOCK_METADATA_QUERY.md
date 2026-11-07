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
registration. CLI/MCP integration is documented in the native recording query guide
when available.

## Validation scope

The bounded query and its adversarial contracts require the repository's pinned
native compiler and unchanged locked production dependencies. On 2026-11-07, two
attempts at the complete native dependency check were killed compiling unchanged
Asupersync 0.5.0, including the recorded serialized low-memory configuration.
Independent source review and scoped Rust formatting are supplementary checks;
they do not establish a Rust test pass or release qualification.
