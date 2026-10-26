# Capture native RTSP/AVC or HEVC into a recoverable recording archive

`fss-capture-rtsp` connects one approved camera route to a native AVC or HEVC
recording archive. Choose `--codec avc` (the default) or `--codec hevc` before reviewing
the plan. Each published window retains original RTP, packet-to-NAL-to-MP4
mapping, initialization segment and media fragment. A separate pin journal synchronizes
recovery references before publication barriers. Only a `window_durable` slot/root
names a recording usable by `fss-import-rtsp`.

For one approved capture followed by trained detection and retained offline replay,
use [`fss-capture-rtsp sentinel`](LIVE_RTSP_SENTINEL.md). Its outer approval also
binds the destination, package, sampling and analysis bounds.

This bounded reference command supports one owner-approved plaintext RTSP-over-TCP
session, one selected video track and an explicitly declared fixed cadence. Authentication
challenges are refused by default. Linux operators can explicitly authorize scoped
Digest authentication using the private credential-file contract below. It does not
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
Source digests and an audit principal do not authenticate the camera.

Execution refuses existing destinations, including earlier incomplete attempts.
It resolves both parents and checks separation before creating either owner. The new
archive uses mode 0700 on Unix; parent permissions remain the operator's responsibility.
Original media is retained unencrypted.

## Select HEVC explicitly

Use `--codec hevc` for a camera whose selected SDP media section advertises exactly
one `H265/90000` payload. `--payload-type` must match that offer. By default the selected description
must contain exactly one VPS, SPS and PPS in `sprop-vps`, `sprop-sps` and `sprop-pps`.
The native configuration reader checks their IDs, profile/temporal agreement and bounded
dimensions before SETUP or PLAY. Missing, ambiguous, mismatched or unsupported parameters
stop the attempt; another media offer or an AVC configuration is never substituted.
The current HEVC profile admits no DON interleaving and uses bounded Main/Main10,
single-layer 4:2:0 configuration-prefix checks. This does not certify a camera's full
bitstream or successful pixel decoding.

For example, for a camera configured to send HEVC payload 98 at 25 pictures per second:

```sh
fss-capture-rtsp --codec hevc --payload-type 98 \
  --root /owner/private/porch-hevc-archive \
  --pins /owner/recovery/porch-hevc-pins \
  --peer 192.168.1.40:554 --authority 192.168.1.40:554 \
  --presentation /stream/main --control-root /stream \
  --sensor-id sensor:porch --stream-id stream:porch \
  --generation 1 --ingress 1 --ssrc 7 \
  --anchor "$SOURCE_ANCHOR" --receive-clock "$RECEIVE_CLOCK" \
  --timing-evidence "$TIMING_EVIDENCE" --journal-id "$JOURNAL_ID" \
  --frame-duration-ticks 3600 --stop-after-pictures 50 \
  --owner-authorized yes --plaintext yes --retain-originals yes
```

Substitute the actual camera mapping and owner identities. Review this command's own
plan and repeat it with its exact `--approve` value. HEVC selects its own archive,
work-root and pin-journal family and binds its native reconstruction, assembly,
configuration and boundary-lookahead ceilings. Changing codecs changes the approval
and decode-clock identity. Existing default/explicit AVC requests keep their AVC
identities. Both codecs use the same optional Digest credential-file lease described below.

### Supply a known HEVC configuration when SDP omits it

A camera can advertise the exact HEVC payload without including its parameter sets
in SDP. If the operator already has the camera's exact VPS, SPS and PPS, add all three
options before reviewing the capture plan:

```sh
  --hevc-vps "$VPS_NAL_HEX" \
  --hevc-sps "$SPS_NAL_HEX" \
  --hevc-pps "$PPS_NAL_HEX"
```

Each value is one complete original NAL, including its two-byte HEVC header, encoded
as hexadecimal without spaces or an Annex-B start code. The command accepts 3–2,048
bytes per NAL. All three options require `--codec hevc` and must be supplied together.
The pure plan checks the tuple's native parameter types, IDs, profile/temporal agreement
and geometry bounds before credential reads, directory creation or a socket attempt.
These are configuration-prefix checks; they do not certify full bitstream conformance.

The preview includes a `hevc_configuration` object containing each NAL's SHA-256
identity and byte length. Every original byte, including an uninterpreted suffix,
is bound into the approval and decode-clock identity. Adding or changing the tuple
requires its own approval and changes the HEVC archive namespace. Uppercase and
lowercase hexadecimal represent the same original bytes.

This mode still requires the exact selected `H265/90000` payload before SETUP.
The supplied tuple is immutable; SDP parameters cannot fill in or replace it, and
the normal recording checks reject incompatible source configuration. Timing,
original-source retention, independent recovery pins and the final storage drain
use the same native owner. Omitting all three options retains the default selected-SDP
configuration path and its existing approval identities.

## Authenticate an owner-authorized camera

On Linux, add both of these options to the capture command before reviewing its plan:

```sh
  --credential-file /owner/private/porch-rtsp-credential \
  --auth-realm 'EXACT CAMERA REALM'
```

The file contains exactly two newline-terminated records: the username, then the
password. The username must be nonempty, printable ASCII, at most 256 bytes, and
contain no colon. The password is printable ASCII, at most 1,024 bytes, and may
contain colons. The complete file is bounded to 1,282 bytes. It must be a regular
file with one hard link, owner-read permission and no group or other permissions
(for example, mode `0600`). A final symlink, directory, oversized file or extra
record is refused. Keep it outside both capture destinations.

Prepare this file through the operator's private credential workflow. Do not place
the password in command-line arguments, environment variables or the capture plan.
Preview does not read the file. After exact approval, the command resolves a lease
over its identity and contents before creating capture destinations or connecting.
Every TCP authorization checkpoint revalidates the file's identity, permissions,
size and change timestamps. Modification, replacement, removal or permission drift
revokes the lease and stops network progress. Rotation requires a new capture
attempt; it never silently refreshes an existing authenticated session.

The plan binds the credential path, exact realm digest, backend and algorithm
policy. SHA-256 or SHA-256-sess with `qop=auth` is the default. A camera that requires
legacy MD5 needs `--legacy-md5 yes`; a legacy camera without qop additionally needs
`--legacy-no-qop yes`. Each choice changes the approval. Basic authentication,
realm substitution and an implicit downgrade are refused. The native Digest owner
retains its bounded retry, stale-nonce and deadline checks.

Linux's verified `/dev/urandom` character device supplies a fresh 128-bit cnonce
for each signed request. Credential and entropy I/O have explicit authority and
bounded read loops. Credentials are borrowed only while constructing the native
request; progress and retained recording objects contain no password or
Authorization header. The local allocation is cleared on drop on a best-effort
basis; this is not a certified zeroization or protected-memory implementation.

Runtime reports count authentication challenges, responses and signed requests.
Digest authenticates the client to the camera under the selected protocol; this
plaintext transport neither encrypts media nor establishes authenticated server
identity. The existing explicit `--plaintext yes` approval remains required.
The file/entropy backend is Linux-only; other platforms refuse authenticated
execution while retaining the existing unauthenticated capture behavior.

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

HEVC collection requires a real observed picture boundary: a following picture prefix,
AUD or explicit EOS/EOB from the source. An RTP marker, an explicit capture stop or socket
EOF cannot complete a HEVC picture. Reaching the target can therefore require reading
the next boundary-bearing packet. The whole original packet stays in the selected window;
trailing NALs that witness the boundary are counted as `source_only_nals` and do not become
extra media samples. Adjacent windows can share such original packets without sharing
selected pictures. A lone IDR followed only by a marker and EOF remains an unverified tail.

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

For the HEVC capture example, use `--archive /owner/private/porch-hevc-archive` and
`--codec hevc` with the exact HEVC `window_durable` slot/root. Keep its source scope and
clock declarations. The importer uses the native HEVC source verifier; it does not
transcode to AVC or infer the codec from untrusted metadata. After the import completes,
`fss-file verify` and `fss-file decode` use destination custody with the capture archive
offline. See the retained importer guide for the returned import identity and range flags.

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

HEVC catalog pages use the same invocation with `--codec hevc`, their own archive path
and exact reported catalog pins and decode clock. Source-only boundary NALs remain in
the original window closure while the joined MP4 contains only the selected pictures.
Several exact published pages can also be supplied through the catalog importer's
ordered `--catalog-pages` contract; page order and all common codec/clock scope remain explicit.

## Partial capture, omissions and recovery

Early EOF before the target returns a failing exit even when its completed prefix was
archived. Once all observed HEVC source input has drained, its final seal starts the
storage-drain allowance before the final window's checkpoint. Source termination by EOB
uses the same completed-prefix path; `peer_eof` separately reports actual TCP EOF.
Protocol/timing faults may leave unsealed originals that were never published.
Terminal output distinguishes durable/indexed pictures, the last normal window,
candidate/confirmed work references, journal anchor, network totals and unsettled session
state. An independently retained pin does not prove its media remains retrievable.

Keep both directories after interruption. Reopen and verify the exact journal prefix,
work root and source closure through the native archive-pin recovery owner. The last
independently retained anchor bounds acceptable recovery. Rerunning capture does not
resume or repair an existing attempt.

The recovery operator also selects its codec explicitly. For HEVC, inspect the retained
journal prefix and an exact candidate or confirmed work reference before restoring:

```sh
fss-archive inspect-pins --codec hevc \
  --pin-root /owner/recovery/porch-hevc-pins \
  --journal-id "$JOURNAL_ID" --expected-namespace "$ARCHIVE_NAMESPACE" \
  --minimum-sequence "$JOURNAL_SEQUENCE" --minimum-root "$JOURNAL_ROOT"

fss-archive inspect-work --codec hevc \
  --root /owner/private/porch-hevc-archive \
  --work-slot "$WORK_SLOT" --work-root "$WORK_ROOT" \
  --expected-namespace "$ARCHIVE_NAMESPACE"
```

Use the independently retained `journal_anchor` and `candidate_pin`/`confirmed_pin`
fields from the terminal report; a newer candidate must be reconciled before its
predecessor. Journal inspection alone reports `work_custody=not_checked`. Work inspection
reopens the exact protected source without publishing normal archive slots. Explicit
`restore-work --commit yes` or `restore-pins --commit yes` then restores verified pending
work; pin restoration additionally takes the existing archive `--root`. Both retain
`--codec hevc` and their other inspection identity arguments. Missing or corrupt candidate
work refuses restoration instead of falling back to an older confirmed root. Recovery
does not reopen the camera or invent a completed target count.

Selected original RTP datagrams are retained inside verified windows. The raw TCP
representation, RTSP headers/authentication challenges and RTCP are omitted. Unselected
RTP and unsealed/prepared tails have separate accounting. These overlapping representations
are not an additive byte-conservation equation. No raw payload or challenge text is logged.
For HEVC, `window_durable.detail.source_only_nals` and terminal
`durable_source_only_nals` describe retained boundary lookahead. Terminal
`released_active_rtp_bytes` describes buffers released from active collection, which can
overlap already durable source; it is not a count of deleted or omitted evidence.

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

Payload type defaults to 96 for either codec, media index to 0 and RTP/RTCP channels to 0/1.
For AVC, `--payload-type` selects that exact mapping during DESCRIBE, even when the chosen
media section advertises several H.264 alternatives. Missing, unsupported or malformed
selected offers refuse without borrowing another offer's parameters. The same payload
type binds native reconstruction and retained original packets. Its negotiated clock
must be 90,000 Hz. Final draining has its own allowance, capped by capture deadline plus
drain timeout. HEVC uses the single-offer and exact selected configuration rules above;
it does not inherit AVC's multiple-offer selector.

```sh
cargo test --locked --offline -p fss-cli \
  --bin fss-capture-rtsp --test capture_rtsp_cli
cargo clippy --locked --offline -p fss-cli --bin fss-capture-rtsp -- -D warnings
cargo test --locked --offline -p fss-reference --test live_hevc_archive_contract
```

Tests cover pure approval/path/limit validation, fixed-cadence timing, loopback capture
through archive/import/cold native decode, early-EOF prefix importability, malformed
source, wrong cadence, parent aliases, exact payload selection and multi-window capture
through catalog import and cold decode. Authentication cases independently validate
SHA-256 and SHA-256-sess wire responses, fresh cnonces and one stale-nonce refresh. They
exercise Basic/MD5 default refusal, wrong realm, nonce replay, downgrade, retry exhaustion,
credential removal/replacement during the handshake, camera-control scope changes and
unread secrets during preview. Reports, archive objects and pin files are scanned for
credential and Authorization-header disclosure. They use real CLI processes and repository
fixtures; they do not qualify actual cameras.

The HEVC contract suites additionally exercise selected-SDP refusals, authenticated
capture, real source-only boundary witnesses, unverified EOF tails, window/catalog
import and cold native decode. Native loopback cases exercise explicit input stop before
the first checkpoint, protected draining beyond the retired network lease, revocation
while input is still live, and cold recovery from confirmed capture-generated work.

Before the HEVC operator addition, the AVC/Digest baseline on pinned
`nightly-2026-08-31` passed 30 unit cases and 14 real-process cases with locked offline
dependencies and debug assertions. That historical result does not qualify the new HEVC path.
The supplementary GitHub smoke workflow runs these reference checks. Repository-owned
qualification lanes and native DSR receipts remain release authority.
