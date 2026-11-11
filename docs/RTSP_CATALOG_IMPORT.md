# Complete RTSP catalog import

The native RTSP archive seals independently verifiable recording windows of at most
256 samples. One complete catalog page or an explicitly ordered selection of
complete pages can become one retained import for native decoding, motion,
whole-recording watch and corroboration. This preserves one analysis range across
both storage-window and catalog-page boundaries. For example, a capture that seals
eight windows per page can retain all four pages of a 32-window attempt under one
import identity without resetting tracking at each page.

The implementation is an offline composition of existing AVC/HEVC packet
verification, fragmented MP4 handling and retained file publication. It does not
open a camera connection. The source archive and the destination deployment remain
separate owners.

For historical recorder capture, use
[`fss-import-rtsp replay`](RTSP_REPLAY_IMPORT.md) to retain the complete companion
replay request, acknowledgement, capture approval and discovery provenance together
with every original window. Window/catalog/page selection alone does not carry
that separate historical receipt.

To import a finite ordered collection of windows, catalogs or page selections and
run independent whole-recording watch in one approved operation, use
[`fss-watch-rtsp-selected`](RTSP_SELECTED_WATCH.md).

The original continuous single-page retained-origin profile is ADP-RTSP-CATALOG-ARCHIVE-001;
the continuous explicit page-list profile is ADP-RTSP-CATALOG-PAGES-001. An explicitly
approved gap-preserving selection uses ADP-RTSP-GAPPED-CATALOG-001. These do not register
or promote device adapters, qualify a camera, or change the frozen device-admission
registry. The original single-page and single-window identities, proof bytes and
CLI approvals remain unchanged.

## Selection and continuity

The caller supplies one exact durable catalog slot/root, or a complete ordered
list of exact slot/root pairs, an explicit codec and the common recording and
decode-clock scope. Every window in every selected page is included. Partial pages,
mutable latest pointers, directory discovery and interval cropping are not part
of this import contract. Page order is supplied explicitly and checked against
native decode intervals; it is never silently sorted or repaired.

Before any destination object is staged, the importer:

1. Reserves the cumulative page-read work allowance and verifies each codec-specific
   catalog root, canonical index, exact flat closure and externally supplied scope.
2. Checks cumulative page/window/sample counts, original bytes and the complete
   canonical proof envelope across the selection. Repeated page or window roots
   and slots refuse. It reserves every native-window read before loading any window.
3. Replays every original recording window through its native AVC or HEVC
   verifier and matches the root, sensor/stream/generation, time scale, decode
   interval, packet/sample/NAL counts and byte length to its catalog descriptor.
4. By default, requires each preceding decode interval to end exactly where the next
   starts. The separately approved `--decode-gaps preserve` profile instead accepts
   ordered nonoverlapping intervals, records every positive gap, and requires an
   independent random-access restart after each gap. Both profiles require
   byte-identical MP4 initialization across all windows.
5. Constructs one MP4 from the first initialization and every media fragment.
   Each independently sealed native fragment starts with movie-fragment sequence
   one, so the derived MP4 renumbers only the four-byte `mfhd` sequence field to
   one through the total window count, including across page boundaries. Sample
   bytes, decode/presentation timestamps,
   durations, box sizes and sample offsets remain unchanged. The complete native
   sample and container byte map, including strict increasing fragment sequences,
   must then validate.

Original archived fragments are retained byte for byte; sequence renumbering is
only a deterministic container remux in the derived MP4. There is no transcoding,
padding or gap repair. The continuous profile has no per-window tracker restart.
A valid archive catalog or page selection containing a decode gap is refused by
the default profile. Configuration transitions, overlaps and reordered windows
are refused by both profiles as a whole; the original archive remains
independently readable. The common scope includes sensor, stream, generation,
source anchor, receive-clock identity, decode-clock identity and time scale.

Decode continuity is an owner-declared media timeline property. It does not certify
physical camera coverage, capture-clock synchronization, scene observability or
the absence of an event.

## Time interpretation

Relative capture offsets use native MP4 presentation timestamps across the entire
selection, including composition offsets and presentation reordering. The earliest
presentation sample establishes the relative origin.

An absolute capture origin remains an explicit operator assumption with supplied
uncertainty. When it is absent, every sample retains the existing unknown capture
interval from zero through the destination receive timestamp. RTP timestamps and
host receive clocks are never silently substituted for an absolute capture clock.

Changing any catalog pin, page order, codec, clock scope, capture assumption or
admission bound changes the import identity. Selecting one page through the
explicit page-list API still uses its own versioned identity; it cannot reuse the
original single-page profile's approval or origin proof.

## Operator command

Select the catalog form of the existing binary:

    fss-import-rtsp \
      --archive /absolute/existing/archive \
      --root /absolute/destination/deployment \
      --site site:example \
      --catalog-slot catalog-000001 \
      --catalog-root sha256:CATALOG_ROOT \
      --codec avc \
      --sensor-id sensor:camera \
      --stream-id stream:camera \
      --generation 1 \
      --anchor sha256:SOURCE_AUTHORITY_ANCHOR \
      --receive-clock sha256:RECEIVE_CLOCK \
      --decode-clock sha256:DECODE_CLOCK \
      --time-scale 90000 \
      --receive-time-ns 1000000000000 \
      --owner-authorized yes \
      --read-originals yes \
      --retain-originals yes

Replace the placeholders with the exact catalog's owner-selected values. Optional
absolute time requires both --capture-start-ns and --capture-uncertainty-ns.

To import several complete pages, replace the two catalog selector arguments with
one ordered list and optionally tighten the cumulative page bound:

    --catalog-pages 'catalog-000001@sha256:FIRST_ROOT,catalog-000002@sha256:SECOND_ROOT' \
    --max-pages 2

Use the exact durable page pins returned by the capture/archive owner and retain
the same codec and complete clock/sensor scope arguments. There is no implicit
selection of the rest of an attempt. Each slot is at most 128 ASCII bytes and
cannot contain `@` or `,`; a list of 64 maximum-length slots and SHA-256 roots fits
the separately bounded 12,863-byte argument. Other argument values retain their
4,096-byte bound. JSON output admits at most 64 KiB so every selected pin remains
visible even with maximum-length slots and escaped paths.

Without --approve the binary emits a bounded JSON plan without filesystem, clock
or network I/O. The plan includes every exact catalog pin, clock identity, whole-page
selection, custody policy and cumulative ceilings. Execute the same selection with
--approve sha256:PLAN_DIGEST from that preview. Any changed request, path, owner,
bound or deadline requires its own exact plan digest.

The completed JSON includes import_identity, windows, frames, decode_clock,
time_scale and the declared decode interval. Single-page results include
catalog_root; page-list results include pages and the complete ordered catalog_pages
array. The returned import
identity is accepted by the ordinary retained-media and whole-recording analysis
commands. Source archive access is not needed for subsequent destination analysis.

The existing --window-slot/--window-root form, its default 256-frame bound, its
canonical identities and its approval bytes remain unchanged. The single-page
--catalog-slot/--catalog-root form also retains its original bytes. Window,
single-page and page-list selectors are mutually exclusive; --max-pages applies
only to an explicit page list.

## Review clips across windows and pages

### Preserve a known gap explicitly

Add the following option to either complete catalog selection before obtaining
its approval digest:

```sh
--decode-gaps preserve
```

The default is `--decode-gaps reject`; spelling that default explicitly preserves
the existing request digest, preview and approval bytes. `preserve` selects a
different request identity, authority trait, origin proof and operator approval.
An approval for the continuous import cannot approve the gap-preserving import,
or vice versa. The option applies to catalog/page selections, not single windows.

The completed gap-preserving import reports `decode_gap_count` and
`decode_gap_intervals` in the supplied decode clock's ticks. These are verified
from the complete native catalog descriptors and independently from the combined
MP4 sample timing. Retained capsules and segments mark the first sample after each
gap, and cold provenance replay must reproduce those exact flags. Original
`tfdt`, DTS, PTS, durations and source packets remain intact. No samples are
inserted and no timestamps are rebased to conceal missing footage.

Use the returned import identity with the movie commands below. Each selected
decoder span remains on one side of a discontinuity and independently starts from
an admitted AVC IDR or HEVC IRAP. A direct native decode range crossing the gap
still refuses. Movie selection reports presentation gaps separately: signed
composition offsets mean the presentation intervals should not be inferred from
the catalog's decode envelope. `--output-timing movie` preserves those exact
presentation holes and the whole query duration without inventing gap frames or
extending the preceding frame's duration. Player display during a hole is not
certified. A gap-only selection reports zero pictures; movie export cannot create
a picture-bearing clip from it.

The new origin uses adapter generation `gen:rtsp-gapped-catalog:v1:PROOF_DIGEST`.
It retains the same original closure, bounds, current privacy masks, tombstone
checks and replay requirements as the continuous catalog profiles. Neither this
profile nor its gap report certifies camera coverage, UTC synchronization, or
the absence of an event.

### Select and export a local review

After the approved import completes, pass its `import_identity` to
`fss-file select-movie` or `export-movie`. A half-open movie interval can cross
any included native window or catalog-page boundary. Original sample indices,
fragment decode starts and signed composition offsets are preserved across the
whole import. Selection uses presentation time; the catalog's declared start/end
are decode-clock coordinates. Inspect the movie timescale and selected intervals
instead of assuming that the first picture starts at zero or equating either
clock with UTC.

For example, if a 90,000-tick movie has adjacent pictures across a window boundary
at tick 104,400, the following interval reviews 60 ms across that boundary:

```sh
fss-file select-movie --root /absolute/destination/deployment --site site:example \
  --import-id sha256:IMPORT_ID --start-movie-tick 101700 --end-movie-tick 107100

fss-file export-movie --root /absolute/destination/deployment --site site:example \
  --import-id sha256:IMPORT_ID --start-movie-tick 101700 --end-movie-tick 107100 \
  --interpretation ycbcr --output /absolute/review.mkv \
  --output-format gray-mkv --output-timing movie \
  --max-origin-read-bytes 138412032 --work-units 1000000000
```

Replace the identity and coordinates with the completed import's actual values.
The original archive may be offline; every native original must remain available
in the destination. Before returning even an empty selection, the reader verifies
all catalog roots/indexes and every original window, repeats the sequence-only
remux, and compares the complete reconstructed MP4 against retained source bytes.
A damaged later, unselected page or window therefore refuses an early clip.
The exact catalog/page adapter and origin-proof generation appear in the selection
report instead of being relabelled as an ordinary file source.

Selection reserves one whole-call original-read allowance before I/O. For a
catalog/page import its charge is **4 MiB for the bounded proof plus all original
catalog/window bytes**, conservatively counting shared objects again per window.
The default/hard ceiling is 132 MiB: the existing 128 MiB original closure plus
the 4 MiB proof reservation. `selection_origin_read_bytes_charged` reports this
reservation, independently of the reconstructed MP4's
`selection_source_bytes_read`. Other authority/proof metadata retain their own
bounds; the reservation is not a measurement of all filesystem traffic.

The subsequent native decode spans share their existing nonrefillable work and
read allowances. Each span can reconstruct the complete catalog again, and that
read is charged again; a boundary cannot reset a budget. Export still admits at
most 1,024 aggregate coded samples including preroll and 1,024 output occurrences,
even though the import may contain more samples. Current destination masks apply
before selected luma is cached. All prerequisite decoding must finish before any
output file is created. Movie-timed lossless output preserves clipped durations
and the full query envelope, including unrepresented leading, internal and trailing intervals.

This workflow clips an already-approved continuous or gap-preserving catalog import.
It does not combine disjoint discoveries into a newly authorized import, and
configuration transitions still refuse. Output is a local screened
derivative, with the [shared movie export contract](RETAINED_DECODE_WORKFLOW.md#exporting-an-exact-movie-time-selection).
Remote grants, payment-zone attestations, retained derivative custody and delivery
remain separate work.

## Bounds

| Limit | Whole-selection maximum and default |
|---|---:|
| Complete catalog pages, when selecting a page list | 64 |
| Complete native windows | 64 |
| Complete samples | 16,384 |
| All catalog metadata plus all original window payloads | 128 MiB |
| Combined MP4 | 64 MiB |
| Canonical origin proof | 4 MiB |

The original-byte accounting includes every catalog root/index and each complete
window, counting shared objects conservatively per window. A smaller requested
limit applies to the entire selection. The page-list path does not raise or renew
the existing window, sample, source, reconstructed-media or proof ceilings. The
importer refuses an oversized selection without truncating it. Since every page
contains at least one window, the selected page count must also fit the cumulative
window bound.

The legacy single-page path keeps its existing 32 MiB work reservation per catalog
or recording window. The new page-list path conservatively reserves 32 MiB plus
64 KiB per catalog, then 64 MiB per recording window, all against one whole-call
work budget before the respective first read. Those reservations also cover a
malformed final object read before the native owner's cumulative-byte refusal;
they are not increased retained-original allowances. Actual original and media
admission limits remain independent. The cooperative timeout and current original-read/retention authority
are checked at custody boundaries. A single native verification is bounded but
is not preempted midway.

## Destination custody and retry

The destination retains every selected catalog root/index and every original window root,
RTP source pack, canonical recording index, initialization and fragment. It also
retains the combined MP4 chunks, source capsules and a versioned origin proof.
Ordinary typed import parts and the final root preserve the existing root-last
publication and ordered capsule authority.

A cold retained read verifies that this entire origin closure belongs to the
import. It independently replays the retained native packet windows, checks every
catalog pin and descriptor, repeats the global deterministic fragment-sequence remux and
reconstructs the exact MP4 sample/capture map. A read cursor
caches at most one verified 64 MiB combined MP4 and drops packet packs after replay;
it does not repeat original-packet replay or MP4 reconstruction for every frame.
These origin replay reads charge the same optional whole-recording source allowance.
The existing retained root and bounded proof-metadata checks still run per sample;
that source allowance is not a bound on all metadata I/O or hashing work. Current
tombstones still refuse cached reads.

The cache is a read snapshot, not a promise of future disk availability.
Derivative publication and complete source verification independently reread the
original closure. Damage to a later window's original packet pack prevents even
an early sample from being certified as this complete selection. Missing or damaged
metadata in a later page likewise prevents cold source verification.

Exact interrupted retries resume the existing publication plan. A completed retry
reverifies the existing complete closure without appending new authority. Bytes
behind an already visible destination root cannot be repaired from a new source
copy. Current destination sensor privacy masks apply to decoded pixels, and the
ordinary deletion plan includes the catalog, every original window and its origin
proof.

Preflight failures leave an existing deployment's import objects and authority
history unchanged. As with the original command, approved execution may open or
initialize the destination owner before source-content verification; it does not
promise zero filesystem writes on failure. The unapproved plan preview is the
zero-I/O path.

## Focused contracts

    cargo test --locked --offline -p fss-reference --test rtsp_catalog_import_contract
    cargo test --locked --offline -p fss-cli --test rtsp_catalog_import_cli
    cargo test --locked --offline -p fss-cli --bin fss-import-rtsp
    cargo test --locked --offline -p fss-reference --test rtsp_import_contract
    cargo test --locked --offline -p fss-cli --test rtsp_import_cli

The explicit gap profile adds five reference contracts under
`rtsp_catalog_import_contract::movie_selection::gaps`, plus distinct-approval CLI
contracts. They cover cold reopen, source-capsule and segment gap witnesses,
decoder barriers, gap-only queries, corruption of an unselected original,
identity separation, cumulative limits, scope and configuration refusal. The
movie CLI fixture covers both codecs and both catalog forms with a one-second
hole, byte-exact timed output, offline original archives and current masks.

On 2026-11-09, the exact pinned nightly passed all seven tests in
`cargo test --locked --offline -p fss-container --test rtsp_movie_timeline_contract`.
The new component case exercises actual native AVC/HEVC window muxes, independent
decoder spans, selected pixels and timed Matroska bytes across an internal gap,
plus a query wholly inside the gap. This component target does not execute the
retained importer, custody authority or CLI processes. Both subsequent full
reference typecheck attempts were killed inside unchanged Asupersync 0.5.0 metadata
compilation before reaching project code, including one serial-compiler,
reduced-MIR retry. The new retained/CLI integration therefore remains untypechecked
and unexecuted here. The [session handoff](SESSION_HANDOFF_2026-11-09_GAPS_REDUCTIONS.json)
records exact scope, commands and evidence; no release qualification is claimed.

The contracts exercise a real 320-frame AVC packet catalog and a separate
320-frame capture-sized selection of ten windows across an eight-window page and
a two-window page. Both cold-decode and complete whole-recording watch with zero
tracking restarts, including at the page boundary at frame 256. They cover original
fragment custody and global sequence-only remux, cumulative read exhaustion,
HEVC presentation offsets and privacy masks, complete deletion closure, all
selection bounds, duplicate/out-of-order/stale pins, valid gapped/reconfigured
selection refusal, interrupted and cold retry, later-page original/metadata damage,
deletion after a cached read, the maximum64-page CLI argument, and the real CLI's
single-page and page-list offline verify/decode workflows.
Synthetic fixtures establish these executable custody and continuity contracts;
they do not qualify camera hardware or detector accuracy.

The movie-review extension adds eight retained catalog/page contracts and one CLI
process contract covering both AVC catalog and HEVC page-list exports. These are
authored but uncompiled and unexecuted in this session. The separate native movie
target passes all six component contracts, including two cross-window cases with
exact pixels, clipped timing, global indices and query-envelope gaps. It constructs
the sequence-normalized fixture directly and does not execute the private retained
catalog joiner or custody/CLI path. See the
[typed movie-review handoff](SESSION_HANDOFF_2026-11-07_CATALOG_MOVIE.json) for source
pins and the existing runtime compilation limitation.
