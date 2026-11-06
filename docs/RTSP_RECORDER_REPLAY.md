# Bounded recorder RTSP replay

Use the native AVC capture pipeline to retrieve a finite prefix of historical
footage from an explicitly supplied recorder replay URI. The request and the
recorder's acknowledgement are retained in a separate durable receipt linked to
the exact original recording windows.

This advances VIT-022 (`fss-vit022-recorder-retrieval-5js5o`). Recording search,
ONVIF GetReplayUri, vendor URI discovery, upstream retention inventory and
historical per-frame timestamp indexing remain outside this profile.

## Capture an explicitly selected interval

Add both options to an otherwise valid single AVC capture plan:

```sh
fss-capture-rtsp \
  --root /private/new-replay-archive --pins /private/new-replay-pins \
  --peer 192.0.2.20:554 --authority recorder.example:554 \
  --presentation /recordings/channel1 --control-root /recordings \
  --sensor-id sensor:front-door --stream-id stream:recorder-channel1 \
  --generation 1 --ingress 1 --ssrc 7 \
  --anchor sha256:OWNER_AUTHORITY_DIGEST \
  --receive-clock sha256:THIS_CAPTURE_RECEIVE_CLOCK_DIGEST \
  --timing-evidence sha256:FIXED_CADENCE_EVIDENCE_DIGEST \
  --journal-id sha256:INDEPENDENT_JOURNAL_ID \
  --frame-duration-ticks 3600 --stop-after-pictures 250 \
  --replay-start 20261101T120000Z --replay-end 20261101T120100Z \
  --owner-authorized yes --plaintext yes --retain-originals yes
```

The addresses and digest labels above are placeholders. Use the recorder's
explicit replay URI and real nonzero SHA-256 identities. The first invocation
only returns a plan: it performs no filesystem, clock, credential or network
I/O. Repeat the same options with the returned `--approve sha256:...` to run.
Both output directories must be new and their parents must already exist.

Changing the interval or route changes the replay request, archive namespace and
approval. Changing capture limits also changes approval. Equivalent fractional
timestamp spellings normalize to the same interval. The ordinary live plan,
request bytes and recording identities remain unchanged when both replay
options are absent.

The current profile requires AVC and an explicitly pinned SSRC. Existing scoped
Digest authentication, finite picture/time/source/storage bounds and fixed
90000 Hz RTP cadence still apply. A requested stop closes the socket and drains
original recording/catalog publication. It does **not** certify that the entire
historical interval was delivered. An early EOF is an incomplete result, even
when a complete original prefix can be retained.

Replay is refused in HEVC/JPEG, automatic-SSRC, reconnect, retain-source,
sentinel, onboarding-wrapper and offline recovery modes. There is no live
fallback, alternate URI, widened request, reverse playback or implicit seek.
The existing single-attempt progress watchdog can still stop a stalled replay.

## Protocol contract

After DESCRIBE, an owner explicitly selects `ClientCommand::SetupReplay` instead
of live SETUP. A successful replay SETUP permits exactly one
`ClientCommand::PlayReplay(ReplayWindow)`. Both requests carry
`Require: onvif-replay`; PLAY also carries a canonical closed
`Range: clock=START-END` and `Rate-Control: no`. A replay SETUP cannot authorize
live PLAY, and a live SETUP cannot authorize replay PLAY.

`ReplayWindow::from_timestamps(start, end)` accepts compact UTC coordinates
`YYYYMMDDThhmmss[.fraction]Z`, with one through nine fractional digits. Gregorian
dates are validated in 1970–9999; leap seconds are outside the admitted profile.
Rendering removes insignificant fractional zeros. The interval must be forward,
nonempty and at most seven days, to the nanosecond. This bound does not extend
the independent connection deadline, authority lease or media/work/byte ceilings.

A successful PLAY must include exactly one closed clock range contained in the
request. A narrower accepted range is retained explicitly. Missing, duplicate,
malformed, open or widened ranges refuse before Playing. This is deliberately a
stricter profile than general RTSP frame alignment: playback outside the approved
historical interval needs separate authority. Optional Rate-Control/Scale echoes
must agree with unpaced forward playback; absent echoes are allowed, but
duplicate or contradictory assertions refuse.

`ClientProgress::ReplayAccepted(ReplayAcceptance)` carries the requested
interval, acknowledged interval and actual successful PLAY CSeq. Session matching,
request deadlines and channel admission remain enforced. Digest authentication
retains the exact range and required option across authorized retries, signs the
ordinary SETUP/PLAY wire methods, and exposes the final successful CSeq.

Replay statuses 456, 457 and 551 have distinct payload-free typed refusals. A 457
means invalid/out-of-bounds range; it is **not proof of upstream retention expiry**.
The CLI preserves those statuses and causes in its terminal report.

## Durable request and acknowledgement receipts

The replay request binds the original sensor/stream/generation, authority anchor,
receive-clock identity, credential-free route digest, requested range and the
original fixed-cadence decode-clock identity. Its noncircular derived decode clock
fixes a distinct archive namespace. The receipt requires original window slots
to be the contiguous prefix of that exact namespace; a live archive's slots
cannot be relabelled as recorder playback.

`ReplayWindowProof::from_avc` extracts descriptors from sealed native recordings.
Only observed durable windows enter the final receipt. `ReplayReceipt::prepare`
retains the complete request, original catalog scope, approval, accepted range,
successful PLAY CSeq, exact slot/root/leaf identities, local termination cause and
a separate original-publication completion flag. It admits at most 64 windows
and 64 KiB of combined companion metadata/manifest. A valid accepted attempt with
no saved media can retain an empty receipt without an original-media claim.

`publish_replay_receipt` verifies every original through the native source loader,
checks current slots and tombstones, then publishes the companion root last
through the existing cancellable publisher. It does not copy, rewrite or delete
original media. An incomplete attempt can retain its durable prefix and receipt;
its original capture error remains the result. Storage failure or cancellation
can leave the companion unavailable or indeterminate, which is reported
separately. A receipt does not settle unfinished archive work or grant recovery.

Preserve the `replay_receipt_published` event's slot, root and request identity,
along with the original capture preview and both stores. The terminal
`recorder_replay` object also reports the receipt state. Independently pinned
cold retrieval is available through:

```rust
load_replay_receipt(
    &publisher,
    expected_receipt_root,
    &expected_catalog_scope,
    expected_request_identity,
    &cancellation,
)
```

Cold loading reconstructs the canonical request and derived clock, validates the
exact metadata and flattened closure, replays every original recording, and
rechecks current slots, tombstones and companion bytes before returning. A
coherently rehashed false descriptor is insufficient: native source facts must
match. The expected roots, scope and request remain independent caller pins.

## Time semantics and limits

Requested UTC and acknowledged UTC are protocol intent and recorder assertions.
They do not establish calibrated capture time, received-frame UTC, continuity,
complete retrieval or physical absence. Existing packet receive clocks and
relative decode timing retain their meanings. Optional node-clock indexes still
describe present-time read/admission observations; `fss-archive query-utc` does
not silently become a historical-recorder-time query.

ONVIF historical RTP extensions remain in the original datagrams when present,
but this slice does not interpret them. RTCP sender-report time is not substituted
for historical frame time. Fixed cadence and closed presentation-prefix rules
continue to reject unsupported gaps, timing changes and unresolved reordering.

Raw RTSP/control wire remains omitted. The replay companion retains the validated
request/acknowledgement facts, not credentials, session tokens or URI text.
Transport and local original-media custody retain their existing plaintext
policies; no new encryption or recorder-identity claim is made.

## Regression coverage and validation status

- `rtsp_replay_contract`: 15 native protocol contracts for calendars, nanosecond
  bounds, unchanged live bytes, replay state isolation, headers, response policy,
  CSeq/session matching, typed refusals, cancellation and Digest retries.
- `recording_replay_contract`: 15 native custody contracts for canonical request
  and namespace binding, original re-verification, cold reopen, changed pins,
  hostile rehashed metadata, cancellation, publication interruption, tombstones
  and empty accepted attempts.
- CLI planning contracts check canonical approval, route/cadence provenance,
  incompatible modes and replay-specific resource limits. Native loopback
  recorder tests exercise real approved capture, receipt readback, original
  import/decode, incomplete EOF and response/refusal handling.

The local environment became unavailable before replay compilation. Recovered
sources and contracts received independent review. At protocol checkpoint
`8bc2267`, supplementary native run
[42270744851](https://github.com/Dicklesworthstone/franken_surveillance_system/actions/runs/42270744851)
passed all 15 replay protocol contracts and all 298 existing capture-binary unit
tests, plus the selected keepalive/reconnect integrations. The overall job still
reported the unchanged qualification-policy failures and a HEVC description test
failure also present in an earlier pre-replay run.

Receipt and new CLI integration contracts have been authored and source-reviewed;
their native execution is pending at this checkpoint. Hardware recorder
interoperability and release qualification remain open.

## Primary specifications

- [ONVIF Streaming Specification](https://www.onvif.org/specs/stream/ONVIF-Streaming-Spec.pdf),
  replay transport, required option, range, rate control and historical RTP.
- [ONVIF Replay Control Service](https://www.onvif.org/specs/srv/replay/ONVIF-ReplayControl-Service-Spec.pdf),
  obtaining an explicit replay URI.
- [RFC 2326](https://www.rfc-editor.org/rfc/rfc2326.html), PLAY and status semantics.
