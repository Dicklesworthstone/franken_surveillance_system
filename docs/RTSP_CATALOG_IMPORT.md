# Complete RTSP catalog import

The native RTSP archive seals independently verifiable recording windows of at most
256 samples. A complete catalog page can now become one retained import for native
decoding, motion, whole-recording watch and corroboration. This preserves the
analysis range across those storage-window boundaries.

The implementation is an offline composition of existing AVC/HEVC packet
verification, fragmented MP4 handling and retained file publication. It does not
open a camera connection. The source archive and the destination deployment remain
separate owners.

The versioned retained-origin profile is ADP-RTSP-CATALOG-ARCHIVE-001. As with the
existing single-window origin profile, this does not register or promote a new
device adapter, qualify a camera, or change the frozen device-admission registry.

## Selection and continuity

The caller supplies one exact durable catalog slot/root, an explicit codec and
the catalog's complete recording and decode-clock scope. Every window in that
page is selected. Partial pages, mutable latest pointers and interval cropping
are not part of this import contract.

Before any destination object is staged, the importer:

1. Verifies the codec-specific catalog root, canonical index, exact flat closure
   and externally supplied scope.
2. Checks cumulative count and original-byte allowances across the complete page.
3. Replays every original recording window through its native AVC or HEVC
   verifier and matches the root, sensor/stream/generation, time scale, decode
   interval, packet/sample/NAL counts and byte length to its catalog descriptor.
4. Requires each preceding decode interval to end exactly where the next starts,
   and requires byte-identical MP4 initialization across all windows.
5. Constructs one MP4 from the first initialization and every media fragment.
   Each independently sealed native fragment starts with movie-fragment sequence
   one, so the derived MP4 renumbers only the four-byte `mfhd` sequence field to
   one through the window count. Sample bytes, decode/presentation timestamps,
   durations, box sizes and sample offsets remain unchanged. The complete native
   sample and container byte map, including strict increasing fragment sequences,
   must then validate.

Original archived fragments are retained byte for byte; sequence renumbering is
only a deterministic container remux in the derived MP4. There is no transcoding,
padding, gap repair or per-window tracker restart.
A valid archive catalog containing a decode gap or a configuration transition is
refused as a whole; its original archive remains independently readable.

Decode continuity is an owner-declared media timeline property. It does not certify
physical camera coverage, capture-clock synchronization, scene observability or
the absence of an event.

## Time interpretation

Relative capture offsets use native MP4 presentation timestamps across the entire
page, including composition offsets and presentation reordering. The earliest
presentation sample establishes the relative origin.

An absolute capture origin remains an explicit operator assumption with supplied
uncertainty. When it is absent, every sample retains the existing unknown capture
interval from zero through the destination receive timestamp. RTP timestamps and
host receive clocks are never silently substituted for an absolute capture clock.

Changing the catalog, codec, clock scope, capture assumption or any admission bound
changes the import identity.

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

Without --approve the binary emits a bounded JSON plan without filesystem, clock
or network I/O. The plan includes the exact catalog, clock identity, whole-page
selection, custody policy and cumulative ceilings. Execute the same selection with
--approve sha256:PLAN_DIGEST from that preview. Any changed request, path, owner,
bound or deadline requires its own exact plan digest.

The completed JSON includes import_identity, catalog_root, windows, frames,
decode_clock, time_scale and the declared decode interval. The returned import
identity is accepted by the ordinary retained-media and whole-recording analysis
commands. Source archive access is not needed for subsequent destination analysis.

The existing --window-slot/--window-root form, its default 256-frame bound, its
canonical identities and its approval bytes remain unchanged. Window and catalog
selectors cannot be combined.

## Bounds

| Limit | Whole-catalog maximum and default |
|---|---:|
| Complete native windows | 64 |
| Complete samples | 16,384 |
| Catalog plus all original window payloads | 128 MiB |
| Combined MP4 | 64 MiB |
| Canonical origin proof | 4 MiB |

The original-byte accounting includes each complete window and counts shared
objects conservatively per window. A smaller requested limit applies to the
whole page. The importer refuses a page that exceeds any bound without truncating
it or renewing the allowance for each window.

Each native archive read reserves the existing 32 MiB input envelope against the
same whole-call work budget; actual original and media admission limits remain
independent. The cooperative timeout and current original-read/retention authority
are checked at custody boundaries. A single native verification is bounded but
is not preempted midway.

## Destination custody and retry

The destination retains the catalog root/index and every original window root,
RTP source pack, canonical recording index, initialization and fragment. It also
retains the combined MP4 chunks, source capsules and a versioned origin proof.
Ordinary typed import parts and the final root preserve the existing root-last
publication and ordered capsule authority.

A cold retained read verifies that this entire origin closure belongs to the
import. It independently replays the retained native packet windows, checks every
catalog descriptor, repeats the deterministic fragment-sequence remux and
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
an early sample from being certified as this complete catalog import.

Exact interrupted retries resume the existing publication plan. A completed retry
reverifies the existing complete closure without appending new authority. Bytes
behind an already visible destination root cannot be repaired from a new source
copy. Current destination sensor privacy masks apply to decoded pixels, and the
ordinary deletion plan includes the catalog, every original window and its origin
proof.

## Focused contracts

    cargo test --locked --offline -p fss-reference --test rtsp_catalog_import_contract
    cargo test --locked --offline -p fss-cli --test rtsp_catalog_import_cli
    cargo test --locked --offline -p fss-cli --bin fss-import-rtsp
    cargo test --locked --offline -p fss-reference --test rtsp_import_contract
    cargo test --locked --offline -p fss-cli --test rtsp_import_cli

The added contracts exercise a real 320-frame AVC packet catalog through cold
native stream decoding and whole-recording watch, original fragment custody and
sequence-only remux, cumulative read exhaustion,
HEVC presentation offsets and privacy masks, complete deletion closure, all
selection bounds, valid gapped/reconfigured catalog refusal, interrupted and cold
retry, original-packet damage, and the real CLI's offline verify/decode workflow.
Synthetic fixtures establish these executable custody and continuity contracts;
they do not qualify camera hardware or detector accuracy.
