# HEVC recording catalog and decode-range discovery

`rtsp::recording_catalog::hevc` adds a codec-pinned discovery page over the
existing replay-verified HEVC recording windows. It uses the same bounded
catalog grammar, scope, selection engine and flattened object-reference closure
as AVC. It does not create another source store, packet parser, decoder or runtime.

## Construct and query

Supply a `CatalogScope` with the exact `RecordingScope`, an explicitly identified
decode clock, and its positive tick rate. A receive clock or RTP timestamp does
not establish the decode clock. `HevcCatalogBuilder::push` borrows an immutable
`PreparedHevcRecording` and its exact local `SlotName`; the caller can then drop
the large recording while the builder retains only its descriptor. Alternatively,
`prepare_hevc_catalog` accepts a bounded slice of `HevcCatalogWindow` values.

A page has at most 64 chronological, nonoverlapping windows and at most 64 KiB
of new canonical index plus manifest payload. Duplicate slots/roots, reversed or
overlapping intervals, differing scope/tick rate and exhausted counts fail before
mutating the builder. Input recordings must already have passed their native
source replay. Page preparation itself performs no I/O or publication.

`HevcRecordingCatalog::select` uses half-open decode intervals. It returns each
whole IDR-led window that intersects the request, its requested overlap, the
advertised complete output bytes, and every interval not indexed by this page.
Count/byte excess refuses the entire selection; it does not return a truncated
answer labeled complete. Even a one-tick request prices the full selected
recording. No encoded bytes are cropped, no sample timing is guessed, and an
unindexed interval is not a camera outage, coverage witness or evidence of absence.

## Codec and reference boundary

The public HEVC wrapper cannot escape as an AVC catalog and admits only typed
HEVC recordings. The private family choice is fixed by the public constructor or
verification entrypoint, not inferred from untrusted metadata. Merely relabeling
and rehashing a catalog cannot make an AVC root a HEVC window: every descriptor
must reconstruct the exact codec-specific recording manifest from its four role
objects. Existing AVC constructors, identities and canonical bytes are unchanged.

The catalog manifest directly references all window roots AND all original
source, initialization, media and index objects, plus its own metadata digest.
This flat closure preserves deletion/tombstone dependencies even without recursive
window-root discovery. Shared source/lookahead objects deduplicate by content
identity without changing media intervals. It is not permission to delete source,
disclose footage, activate retention policy or commit canonical ledger reachability.

`verify_hevc_catalog` checks the checksum, exact canonical representation, scope,
codec family, ordered descriptors and full reference closure. This is metadata
verification, not fresh provenance/custody or successful playback of the windows.

## Representation

The immutable manifest kind is `hevc_recording_catalog_v1`; the index domain is
`fss.hevc_recording_catalog.v1`, version 1. The existing canonical field grammar
is retained: domain/version; sensor, stream, generation, anchor, receive-clock,
decode-clock, time scale; descriptor count; then each slot, window root, decode
start/end, packet/sample/NAL/byte counts and source/init/media/index digests.
A canonical SHA-256 digest of the body is the 33-byte trailer. Trailing bytes,
unknown versions, foreign kinds and mismatched role roots are refused.

The AVC domain remains `fss.recording_catalog.v1` and its manifest kind remains
`avc_recording_catalog_v1`. This is a new HEVC family, not an in-place AVC migration.

## Verification boundary

```sh
cargo test -p fss-reference --test hevc_catalog_contract --test recording_catalog_golden_contract
```

The new tests build real replay-verified synthetic HEVC windows. They cover
independent canonical encoding, flat source closure, exact half-open selection,
whole-window budgets, scope/decode-clock isolation, transactional correction,
codec relabeling, corruption, truncation, duplicate roots/slots and page capacity.
The existing AVC canonical-byte regression remains applicable unchanged.

Rust build/tests/formatting and qualification were not run in this editing
environment because no Rust toolchain is available. Source-level checks do not
establish a passing Rust result. No device, decode or release gate is promoted.
