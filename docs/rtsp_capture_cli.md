# Capture native RTSP/AVC into a recoverable recording archive

`fss-capture-rtsp` connects one approved camera route to the existing native AVC
recording archive. Each published window retains original RTP, packet-to-NAL-to-MP4
mapping, initialization segment and media fragment. A separate pin journal synchronizes
recovery references before publication barriers. Only a `window_durable` slot/root
names a recording usable by `fss-import-rtsp`.

This bounded reference command supports one owner-approved plaintext RTSP-over-TCP
session, one AVC track and an explicitly declared fixed cadence. Authentication
challenges are refused without credential lookup or authenticated retry. It does not
discover devices, reconnect, decode pixels or certify scene coverage.

## Review the exact plan

Choose two new, separate absolute paths whose parents already exist. Protect the pin
journal independently from footage storage. Both directories must stay outside one
another, including through parent aliases. Supply the camera's known literal IP,
exact RTSP authority, scoped presentation path, SSRC, ingress and stream generation.
The authority maps to that IP and never triggers DNS.

Set the digest variables below to nonzero SHA-256 identities for source authority,
receive clock, declared camera timing policy and independently chosen journal epoch.
For a camera configured for 25 pictures per second, declare 3,600 ticks at 90,000 Hz:

```sh
fss-capture-rtsp \
  --root /owner/private/porch-archive \
  --pins /owner/recovery/porch-pins \
  --peer 192.168.1.40:554 --authority 192.168.1.40:554 \
  --presentation /stream/main --control-root /stream \
  --sensor-id sensor:porch --stream-id stream:porch \
  --generation 1 --ingress 1 --ssrc 7 \
  --anchor "$SOURCE_ANCHOR" --receive-clock "$RECEIVE_CLOCK" \
  --timing-evidence "$TIMING_EVIDENCE" --journal-id "$JOURNAL_ID" \
  --frame-duration-ticks 3600 --stop-after-pictures 50 \
  --owner-authorized yes --plaintext yes --retain-originals yes
```

Without `--approve`, parsing, native configuration validation and JSON preview perform
no filesystem, clock or network I/O. The plan exposes `approval`, source and clock
identities, archive namespace, paths, endpoint and every effective native limit.
Repeat exactly with `--approve sha256:HEX` after reviewing it. Changed bounds, route,
identities, destinations or timing need new approval; argument order does not matter.
Ingress accepts the full nonzero 128-bit unsigned range. Its preview field is a decimal
string, and the approval and decode-clock identities bind all 16 bytes exactly.
Digest inputs and an audit principal do not authenticate the camera.

Execution refuses existing destinations, including earlier incomplete attempts.
It resolves both parents and checks separation before creating either owner. The new
archive uses mode 0700 on Unix; parent permissions remain the operator's responsibility.
Original media is retained unencrypted.

## Timing and deliberate stops

The frame duration is an operator timing assumption. The first assembled picture starts
at relative decode time zero; every next RTP timestamp must equal its predecessor plus
that duration, with native 32-bit rollover. Complete sample intervals must fit the
64-bit relative timeline. Gaps, duplicate/reordered timestamps, drift or changed source
identity stop capture. There is no interpolation, guessed capture time or clock reset.

Composition offsets remain zero. Streams requiring B-picture presentation reordering
are outside this timing model. Capture time remains unknown. Startup pictures before
the first IDR consume timing but are counted separately as skipped. The target counts
pictures admitted by the recording collector, not successfully decoded pixels.

At the requested count, further socket reads/writes are disabled and the selected prefix
is explicitly sealed. Earlier windows cut at an IDR still drain normally. Once the final
sealed window reaches `window_accepted`, the socket closes with cause `owner_stopped`
and the reserved storage-drain allowance starts, before its checkpoint, window and final
catalog publication. Those publications retain their ordinary journal barriers. Success
requires every collected picture to be durable and every durable window to be indexed;
the deliberate stop never becomes EOF.
The remote RTSP session may remain until the camera expires it; that uncertainty is reported.

## Structured progress and import

Both plan and runtime use `schema: "fss.rtsp_capture_cli.v1"`. The plan has
`phase: "planned"`; runtime JSONL rows have monotonic `sequence`, `kind` and `detail`
fields. Preserve complete stdout rows independently.

| Runtime kind | Established state |
|---|---|
| `started` | Exact approved request and source scope |
| `request_queued` / `protocol` | Request admission or accepted RTSP state |
| `picture_collected` | Relative-timed source-linked picture, not durable |
| `window_accepted` | Prepared window accepted by the archive owner |
| `checkpoint_candidate` | Candidate recovery reference independently journaled |
| `checkpoint_durable` | Recovery-work publication confirmed and journaled |
| `window_durable` | Normal recording locally durable and source verified |
| `catalog_published` | Immutable catalog page locally durable |
| `terminal` | Completion/refusal, durable prefix, omissions and recovery references |

A work root is not a normal recording. Copy `window_durable.detail.slot` and
`window_durable.detail.root` into the [retained recording importer](rtsp_recording_import.md):

```sh
fss-import-rtsp \
  --archive /owner/private/porch-archive \
  --root /owner/private/deployment --site site:home \
  --window-slot "$WINDOW_SLOT" --window-root "$WINDOW_ROOT" --codec avc \
  --sensor-id sensor:porch --stream-id stream:porch --generation 1 \
  --anchor "$SOURCE_ANCHOR" --receive-clock "$RECEIVE_CLOCK" \
  --receive-time-ns 5000000000 \
  --owner-authorized yes --read-originals yes --retain-originals yes
```

Receive time is a separate declaration, not an inferred physical capture origin. Review
the import plan and repeat with its approval. A completed destination keeps original
recording evidence and supports native verification/decode with the capture archive
offline. Downstream motion, watch and corroboration preserve their own timing, privacy,
calibration and effect gates. Current destination masks apply before decoded pixels
reach consumers.

## Import a complete catalog page

Each `catalog_published.detail` also exposes the exact `slot`, `root`, `decode_clock`,
`time_scale`, recording `source`, and `codec`. These fields are checked against the
durable native page before reporting. The [whole-catalog importer](RTSP_CATALOG_IMPORT.md)
can join its adjacent windows into one retained recording for whole-recording analysis:

```sh
fss-import-rtsp \
  --archive /owner/private/porch-archive \
  --root /owner/private/deployment --site site:home \
  --catalog-slot "$CATALOG_SLOT" --catalog-root "$CATALOG_ROOT" --codec avc \
  --decode-clock "$DECODE_CLOCK" --time-scale 90000 \
  --sensor-id sensor:porch --stream-id stream:porch --generation 1 \
  --anchor "$SOURCE_ANCHOR" --receive-clock "$RECEIVE_CLOCK" \
  --receive-time-ns 5000000000 \
  --owner-authorized yes --read-originals yes --retain-originals yes
```

Review and approve this import separately. A published page contains up to eight windows;
an attempt may publish several pages. Each page is one exact complete selection, not a
promise that it covers the entire attempt. The importer independently refuses gaps,
changed initialization and excessive cumulative work or bytes. A successful import keeps
the page and every original window in destination custody for cold verification and decode.
The combined MP4 assigns increasing fragment sequence numbers to copies of the independent
windows, each of which originally starts at one. Original bytes and manifests stay intact;
sample payloads, timing, box sizes and fragment-relative offsets are unchanged. Import and
cold verification apply the same deterministic composition rule.

## Partial capture, omissions and recovery

Early EOF before the target returns a failing exit even when its completed prefix was
archived. Protocol/timing faults may leave unsealed originals that were never published.
Terminal output distinguishes durable/indexed pictures, the last normal window,
candidate/confirmed work references, journal anchor, network totals and unsettled session
state. An independently retained pin does not prove its media remains retrievable.

Keep both directories after interruption. Reopen and verify the exact journal prefix,
work root and source closure through the native archive-pin recovery owner. The last
independently retained anchor bounds acceptable recovery. Rerunning capture does not
resume or repair an existing attempt.

Selected original RTP datagrams are retained inside verified windows. The raw TCP
representation, RTSP headers/authentication challenges and RTCP are omitted. Unselected
RTP and unsealed/prepared tails have separate accounting. These overlapping representations
are not an additive byte-conservation equation. No raw payload or challenge text is logged.

Output and synchronous storage have bounded bytes and checked admission deadlines;
a single blocking host syscall is not forcibly preempted. Failed or partial output rows
are never retried. Source custody and the independent journal remain the recovery basis
when stdout is unavailable.

## Bounds and verification

Every effective value appears in the plan. Ceilings do not guarantee that the requested
pictures arrive or fit the store. Defaults include a 30-second capture deadline, a
10-second final storage-drain allowance, 100,000 steps, 64 MiB received wire, 8 MiB report,
32 windows of up to 128 pictures, and 512 MiB storage. Run `fss-capture-rtsp --help` for
switches. Native packet, NAL, picture, source-byte and residence limits remain independent;
no bound evicts prior state to make room.

Payload type defaults to 96, media index to 0 and RTP/RTCP channels to 0/1.
`--payload-type` selects that exact AVC mapping during DESCRIBE, even when the chosen
media section advertises several H.264 alternatives. Missing, unsupported or malformed
selected offers refuse without borrowing another offer's parameters. The same payload
type binds native reconstruction and retained original packets. Its negotiated clock
must be 90,000 Hz. Final draining has its own allowance, capped by capture deadline plus
drain timeout.

```sh
cargo test --locked --offline -p fss-cli \
  --bin fss-capture-rtsp --test capture_rtsp_cli
cargo clippy --locked --offline -p fss-cli --bin fss-capture-rtsp -- -D warnings
```

Tests cover pure approval/path/limit validation, fixed-cadence timing, loopback capture
through archive/import/cold native decode, early-EOF prefix importability, authentication
refusal without secret disclosure, malformed source, wrong cadence, parent aliases, exact
payload selection and multi-window capture through catalog import and cold decode.
They use real CLI processes and repository fixtures; they do not qualify actual cameras.

Native checks on pinned `nightly-2026-08-31` have passed the 22 capture plan/timing
cases, 12 live-recording cases and seven plain/Digest payload-selection cases. The
nine real-process cases include the catalog composition regression; the dedicated
catalog suite additionally exercises AVC/HEVC, retained originals and cold replay.
The supplementary GitHub smoke workflow runs these reference checks. Repository-owned
qualification lanes and native DSR receipts remain release authority.
