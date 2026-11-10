# Bounded recorder RTSP replay

Use the native AVC or HEVC capture pipeline to retrieve a finite prefix of historical
footage from an explicitly supplied recorder replay URI. The request and the
recorder's acknowledgement are retained in a separate durable receipt linked to
the exact original recording windows.

This advances VIT-022 (`fss-vit022-recorder-retrieval-5js5o`). The separate
[ONVIF recording discovery workflow](ONVIF_RECORDING_DISCOVERY.md) now obtains a
scoped GetReplayUri from an exact recording selection and supplies a protected
`from-onvif-replay` handoff. Remote search sessions, vendor-specific URI discovery,
proof of upstream media retention and historical per-frame timestamp indexing remain open.

## Capture an explicitly selected interval

Add both options to an otherwise valid single AVC or HEVC capture plan:

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

The profile requires an explicitly selected AVC or HEVC codec and a pinned SSRC. Existing scoped
Digest authentication, finite picture/time/source/storage bounds and fixed
90000 Hz RTP cadence still apply. A requested stop closes the socket and drains
original recording/catalog publication. It does **not** certify that the entire
historical interval was delivered. An early EOF is an incomplete result, even
when a complete original prefix can be retained.

For HEVC, add `--codec hevc --payload-type N` with the recorder's exact advertised
H265 payload. Set `--frame-duration-ticks` and `--timing-evidence` for the actual
owner-approved cadence; for example, a 5 fps fixture uses 18000 ticks at 90000 Hz.
The default codec remains AVC. HEVC uses the existing exact selected SDP
VPS/SPS/PPS tuple, or the existing explicit `--hevc-vps`, `--hevc-sps` and
`--hevc-pps` options when the owner supplies all three. It never switches payload
or codec after refusal. The approved codec is included in the replay request,
derived decode clock, archive namespace, receipt family and approval.

HEVC picture boundaries still require real source syntax. RTP marker bits,
requested UTC endpoints and TCP EOF cannot complete an unfinished picture.
Boundary lookahead and incomplete source retained by the native collector stay
source-only in the original recording index; the receipt cannot upgrade them to
media samples. The ordinary HEVC source-protection journal, bounded storage
pause and independent final drain remain in use.

Replay is refused in JPEG, automatic-SSRC, reconnect, retain-source,
sentinel, live onboarding-wrapper and offline recovery modes. The explicit
`from-onvif-replay` wrapper is the separate recording-discovery path and retains
its own source binding and outer approval. There is no live
fallback, alternate URI, widened request, reverse playback or implicit seek.
The existing single-attempt progress watchdog can still stop a stalled replay.
When that watchdog is selected, the durable receipt retains the admitted outer
approval that binds its stop policy together with the nested capture plan.

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

`ReplayWindowProof::from_avc` and `ReplayWindowProof::from_hevc` extract descriptors
from the corresponding sealed native recordings. Mixed-codec receipt windows
are refused, including an HEVC publication plan passed to the AVC constructor.
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
cold retrieval is available from the operator CLI:

```sh
fss-archive inspect-replay \
  --root /private/new-replay-archive --codec avc \
  --sensor sensor:front-door --stream stream:recorder-channel1 --generation 1 \
  --anchor sha256:OWNER_AUTHORITY_DIGEST \
  --receive-clock sha256:THIS_CAPTURE_RECEIVE_CLOCK_DIGEST \
  --decode-clock sha256:REPLAY_BOUND_DECODE_CLOCK_DIGEST --time-scale 90000 \
  --expected-replay-root sha256:RETAINED_RECEIPT_ROOT \
  --expected-replay-request sha256:RETAINED_REQUEST_IDENTITY
```

Replace the labels with the independently retained preview/event values. The
decode clock is the replay-bound clock from the capture preview. The existing
archive owner takes exclusive locks and performs its normal recovery and source
verification. Invalid pins or incomplete verification produce no success report.
The JSON report is at most 64 KiB and describes the request, acknowledgement,
approval, termination and original window roots without emitting media payloads.
`--help` lists the deadline and inventory/byte limits. The library equivalent is:

```rust
load_replay_receipt(
    &publisher,
    expected_receipt_root,
    &expected_catalog_scope,
    expected_request_identity,
    &cancellation,
)
```

Use `--codec hevc` for an HEVC receipt. The equivalent library entry points are
`ReplayRequest::new_hevc`, `ReplayWindowProof::from_hevc`,
`hevc_replay_slot` and `load_hevc_replay_receipt`. Publishing uses the same
`publish_replay_receipt` owner for both native families. `ReplayReceipt::slot()`
derives the selected family's immutable slot. The inspector and loaders require
the codec before reading stored metadata: neither a manifest nor a stored tag
can select another verifier or enable an AVC fallback.

| Profile | Receipt manifest kind | Immutable slot prefix |
|---|---|---|
| AVC | `avc_recording_replay_receipt_v1` | `fssrr1-avc-` |
| HEVC | `hevc_recording_replay_receipt_v1` | `fssrr1-hevc-` |

HEVC request, derived clock, receipt metadata and slot identities use separate
versioned domains. The existing AVC domains, canonical byte layout and identities
are unchanged. Original AVC and HEVC recording formats are unchanged.

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

The HEVC extension adds native contracts for codec-separated identities, cold
reopen of real source-only boundary witnesses, mixed-family refusal, absent
originals, coherently rehashed false accounting, cancellation and source
tombstones. `live_hevc_archive_contract` additionally checks the automatic owner's
exact replay SETUP/PLAY bytes, contained acknowledgement and refusal to change an
already selected replay interval.

The `capture_rtsp_cli replay::` cases now exercise both AVC and HEVC using actual
loopback RTSP servers and the native capture executable. HEVC success and early
EOF cases cold-load the receipt, check original datagrams and source-only NALs,
run the real inspector, import the original and decode it after the capture store
is taken offline. Missing, duplicate and out-of-range acknowledgements arrive in
the same socket write as valid media to check that failed control fences queued
HEVC bytes. Statuses 456/457/551 must retain their exact refusal and send no second
PLAY or live fallback. `archive_replay_process` covers explicit HEVC inspection
and a deliberately substituted AVC selector.

These additions require execution of the focused native targets in
`scripts/check_recording_lifecycle.sh replay`. Local execution of this extension
is currently blocked by the unchanged Asupersync 0.5.0 dependency being killed
during metadata compilation at approximately 1.98 GiB peak resident memory, before
FSS type checking. The earlier 350-test AVC result below does not establish that
the new HEVC tests passed. No dependency, feature or qualification gate is changed
to avoid that limitation.

The later focused predecessor run executed the native receipt and CLI targets,
passing 163 tests and exposing 10 failures across HEVC admission and fixtures.
The HEVC state guard was corrected on main in `2f402c2`, hold fixtures in `48d2bc7`,
and unrelated-import fixture ordering in `9b21280`. These corrections and the new
ONVIF-bound path still require exact-head native execution; see the
[retained results](validation/2026-11-10-recorder-native-results.json).

### Previously executed AVC baseline

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
  import/decode, incomplete EOF, supervised outer approval and response/refusal
  handling. Eight archive process contracts exercise cold operator inspection,
  changed or absent pins, argument refusal before open, existing-owner conflicts,
  inventory limits, tombstoned originals and empty accepted attempts.

**Prior AVC native execution passed: 350 tests, zero failures, zero ignored cases.**

| Native target | Passed | Selection |
|---|---:|---|
| `rtsp_replay_contract` | 15 | Complete target |
| `recording_replay_contract` | 15 | Complete target |
| `capture_rtsp_cli replay::` | 6 | All replay cases; 100 unrelated cases filtered |
| `fss-capture-rtsp` binary units | 302 | Complete target |
| `archive_replay_process` | 8 | Complete target |
| `archive_operator_process` | 4 | Complete existing compatibility target |

The six loopbacks exercise the actual approved native capture executable,
original packet custody, cold receipt loading, original import and native decode.
The archive process cases run the real inspector executable. Independent source
review and locked Cargo type checking also passed.

The successful build used pinned nightly `2026-08-31`, unchanged locked production
dependencies, one Cargo/frontend/backend/linker job, no debug information or
incremental compilation, and 256 Asupersync codegen units. LLVM `fewer-names`
reduced compilation memory after the initial native build was killed. No
dependency, source, feature, assertion, panic strategy or repository gate changed
to obtain these results.

[Native results and reproduction settings](RTSP_REPLAY_NATIVE_RESULTS.json)
retain the exact compiler, source base/overlay blobs, commands, counts, elapsed
times, peak memory and development-log hashes. The tested worktree is based on
`aabf93d` with six final feature files matching published `9ae9a98`. These targeted
runs do not qualify unrelated concurrent upstream changes or the full repository.
Hardware recorder interoperability and release qualification remain open.

## Primary specifications

- [ONVIF Streaming Specification](https://www.onvif.org/specs/stream/ONVIF-Streaming-Spec.pdf),
  replay transport, required option, range, rate control and historical RTP.
- [ONVIF Replay Control Service](https://www.onvif.org/specs/srv/replay/ONVIF-ReplayControl-Service-Spec.pdf),
  obtaining an explicit replay URI.
- [RFC 2326](https://www.rfc-editor.org/rfc/rfc2326.html), PLAY and status semantics.
