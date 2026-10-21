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

To import a finite ordered collection of windows, catalogs or page selections and
run independent whole-recording watch in one approved operation, use
[`fss-watch-rtsp-selected`](RTSP_SELECTED_WATCH.md).

The original single-page retained-origin profile is ADP-RTSP-CATALOG-ARCHIVE-001;
the explicit page-list profile is ADP-RTSP-CATALOG-PAGES-001. These do not register
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
4. Requires each preceding decode interval to end exactly where the next starts,
   and requires byte-identical MP4 initialization across all windows.
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
padding, gap repair or per-window tracker restart.
A valid archive catalog or page selection containing a decode gap or a
configuration transition is refused as a whole; its original archive remains
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
