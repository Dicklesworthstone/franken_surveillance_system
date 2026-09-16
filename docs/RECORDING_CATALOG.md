# Immutable recording catalogs and verified range retrieval

This reference slice advances FSS-068 incident retrieval/verification: an owner
can discover and retrieve multiple recorded windows through one pinned catalog
rather than already knowing every window's slot and root. It does not close the
bead's production, provider, privacy, or qualification gates.

## Content and identity

`rtsp::recording_catalog` holds up to 64 chronological, nonoverlapping windows.
Each descriptor pins its local slot, root, four role-ordered object identities,
decode interval, counts, and complete payload byte length. The catalog root
references every window root AND every source/initialization/media/index leaf,
plus its own metadata. Shared leaves are deduplicated. A source is not hidden
behind an opaque child reference for reachability/deletion purposes.

`CatalogScope` includes the exact `RecordingScope`, tick rate, and an additional
explicit owner decode-clock identity. DTS is not a capture timestamp. A receive
clock does not identify a decode timeline. Supplying windows declares that they
share the specified decode basis; the catalog cannot infer this from RTP. Changed
sensor, stream, generation, anchor, receive clock, or decode basis requires a new
scope. Pages are immutable and occupy distinct slots; there is no mutable latest
pointer, implicit directory scan, or unbounded linked history.

Use `prepare_catalog` for a borrowed batch or `CatalogBuilder` to load, admit,
and drop each recording separately. The builder retains metadata only. It
accepts existing `PreparedRecording` values, not caller-invented summaries.
Refusals do not advance the builder or consume a recording.

## Publication and retrieval

`CatalogPublication` exclusively borrows an existing `LocalRootPublisher`.
Each progress step first loads one already durable recording through the normal
original-packet verifier and checks every descriptor field. Only after all
windows pass is the index staged. The root-last publisher re-verifies the flat
closure at its normal cut points before making a catalog visible/durable. A
staged index is not a published catalog. Cancellation leaves staged custody and
previous recording roots intact. Indeterminate publication remains typed and
requires reopening/reconciliation, not a new remux or overwrite.

`load_catalog` checks an exact durable slot/root, canonical index/checksum,
expected scope, flat closure, tombstones, and child slot bindings. It returns
structural discovery metadata, NOT a fresh whole-media verification receipt.
`RecordingRangeRead` subsequently loads and verifies one selected window per
step and retains only metadata between steps. Each output is a COMPLETE IDR-led
window, with the requested overlap reported separately. Encoded bytes are not
cropped or transcoded. The owner must authorize disclosure of those whole
windows: the query interval is not a privacy filter or a grant to disclose
additional footage. CLI verification prints hashes/counts, not raw media.

Every interval in a query is partitioned into selected window overlaps or
`unindexed` intervals. The latter includes internal gaps and ranges outside the
page. Neither indexed DTS nor missing entries certifies camera coverage,
continuity, decoded completeness, or absence of a scene/event. Empty selections
return the entire query as unindexed. Selection refuses an over-budget query
instead of silently returning a truncated page.

Only `RangeProgress::Complete` returns the aggregate point-in-time read receipt.
It re-reads the pinned catalog and records returned windows, actual output bytes,
query scope and all unindexed intervals. Earlier returned windows remain owned
by the caller if a later step fails. A failed/cancelled/expired request cannot
emit a successful aggregate receipt. Completion is delivered once; repeated
steps return `Exhausted`, not new verification. Media can change on disk after a
read; no retained future-availability claim is made.

## Bounds and ownership

Canonical catalog index plus manifest is capped at 64 KiB. The wire format uses
`fss.recording_catalog.v1`, u64 version 1, big-endian canonical scalar/text/digest
fields and an algorithm-qualified SHA-256 trailer. Counts are checked before
allocation; unknown versions, trailing bytes, duplicate roots/slots, overlap,
missing/extra references, wrong scope, and checksum failures are refused.

Queries cap windows and complete returned payload bytes (default 256 MiB).
That byte budget is NOT physical I/O, RSS, or hashing work. Each window read
retains the existing separate 32 MiB recording bound, and local owners with an
object-read ceiling above 32 MiB are refused. Catalog reads can temporarily
allocate up to that supplied spool limit before enforcing the smaller accepted
catalog size. Publication's final closure verification can reread multiple
windows; it is bounded by the page and publisher, not one small syscall.

The library owns no network connection, background task, filesystem discovery,
crypto, retention policy, or authority grant. It uses an already supplied owner.
The cancellation probe must enforce live revocation/deadline checks at cut
points; supplied `now_ns` alone controls admission, not syscall elapsed time.
Visible catalog references participate in the existing deletion owner's closure
rules. The catalog does not silently unpublish a root or delete protected source.

## Commands

The example operates on an EXISTING archive and takes every scope field from the
caller. Digests use `sha256:<64 lowercase hex>` (owner scope anchors may also use
supported algorithm-qualified identities). Window arguments must be ordered by
DTS. `index` creates an immutable catalog slot; `query` requires its exact root.

```sh
cargo run --locked -p fss-reference --example recording_catalog -- \
  index ARCHIVE CATALOG_SLOT SENSOR STREAM GENERATION \
  ANCHOR RECEIVE_CLOCK DECODE_CLOCK TIME_SCALE \
  WINDOW_SLOT_1=WINDOW_ROOT_1 WINDOW_SLOT_2=WINDOW_ROOT_2

cargo run --locked -p fss-reference --example recording_catalog -- \
  query ARCHIVE CATALOG_SLOT SENSOR STREAM GENERATION \
  ANCHOR RECEIVE_CLOCK DECODE_CLOCK TIME_SCALE \
  CATALOG_ROOT START_TICK END_TICK MAX_OUTPUT_BYTES
```

The command uses a bounded reference owner and a 30-second admission/cancellation
budget. Owner open itself takes locks and performs recovery; this is not a
read-only filesystem promise or production provider adapter.

The existing fixture replay now runs capture -> two window publications ->
catalog publication -> reopen -> full window verification -> range verification.
It also corrects the prior example's `SlotName::parse` call to borrow its formatted
string. Fixture timing remains explicitly synthetic, not inferred camera time.

```sh
cargo run --locked -p fss-reference --example recording_capture_replay -- NEW_DIRECTORY
cargo test --locked -p fss-reference \
  --test recording_catalog_contract \
  --test recording_catalog_local_contract \
  --test recording_catalog_golden_contract
python3 scripts/check_recording_catalog_fixture.py
```

## Verification boundary

The 23 added Rust test functions cover selection, canonical corruption, exact
scope, output budgets, metadata-only construction, original source readback,
publication cancellation, partial reads, deadline/reversal, four root-publication
crash boundaries, and self-consistent but false descriptors. The Rust compiler,
tests and examples were NOT executed in the authoring environment: no Rust
toolchain is available. They must not be described as passing qualification.

The independent Python wire/interval oracle DID run. It checked 10,001 interval
cases and refused 1,370 truncations/single-byte changes. Its 685-byte index and
434-byte root are pinned in the Rust golden tests. These metadata fixtures name
opaque synthetic objects, not playable media or a source-verification proof.
The oracle does not execute Rust or prove filesystem crash behavior.
