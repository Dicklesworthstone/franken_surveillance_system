# Historical recording discovery and native replay

The read-only ONVIF recording client fills the discovery gap before native recorder
playback: an owner can enumerate configured recordings, explicitly choose one exact
token and closed interval, inspect its advertised information, and obtain a replay URI
within an independently approved RTSP scope.

This is a bounded part of VIT-022 / `fss-vit022-recorder-retrieval-5js5o`.
It creates no remote search session, recording job or configuration change. It does not
claim complete Profile G support, actual retained-media coverage or trusted historical
capture time.

## Operator workflow

### 1. List recording configurations

Use the same explicitly approved HTTP origin, service subtree and authentication
settings as ordinary ONVIF onboarding:

```sh
fss-onvif recordings \
  --peer 192.0.2.20:80 --authority recorder.example:80 \
  --device-path /onvif/device_service --service-root /onvif \
  --output /private/recording-inventory.json \
  --owner-authorized yes --plaintext yes
```

The first call returns a pure plan without reading credentials, opening output files,
consulting clocks or contacting the device. Repeat the exact arguments with its
`--approve sha256:...` value to perform the bounded request. The output path must be new,
under an existing private canonical directory. The inventory is created with mode 0600;
stdout contains counts, digests and outcomes. Read the private inventory to choose the
exact recording token. No source address or descriptive name is followed.

For HTTP Digest, add `--credential-file /private/onvif-credentials --auth-realm EXACT_REALM`
to both plan and execution. Existing SHA-256/qop defaults and explicit legacy exceptions
remain in force. Alternatively use `--auth-mode username-token --credential-file ...`
with no realm/legacy options. Credential leases are checked by the existing owner.

### 2. Resolve one recording and interval

```sh
fss-onvif replay \
  --peer 192.0.2.20:80 --authority recorder.example:80 \
  --device-path /onvif/device_service --service-root /onvif \
  --recording-token OWNER_SELECTED_TOKEN --codec hevc \
  --replay-start 20261101T120000Z --replay-end 20261101T120100Z \
  --rtsp-peer 192.0.2.20:554 --rtsp-authority recorder.example:554 \
  --output /private/recording-replay.json \
  --owner-authorized yes --plaintext yes
```

These addresses, token, codec and dates are illustrative owner inputs. Choose the actual
recording and independently approved RTSP destination. Preview and approve this exact
selection separately from inventory. These new commands reject `--profile` and
`--media-version`, which belong to the live-media path.

The approved operation retrieves information first. A different response token, missing
or ambiguous video track, removed state, contradictory extrema or any known bound outside
the request refuses before GetReplayUri. The interval is never changed. Successful output
is a closed `fss.onvif_recording_replay_handoff.v1` document; retain the returned
`output_digest` independently for the next step.

The private handoff embeds the complete canonical recording information in bounded hex
chunks, exact replay URI, explicit codec/window, independently pinned peer/authority,
the discovery approval, and service/information/URI observation identities. It records
unknown URI lifetime and explicitly denies capture authorization and source-evidence
status. It cannot be substituted with a live-profile handoff or inventory.

### 3. Acquire originals through native replay

The new wrapper supplies the discovered route, codec and interval to the existing native
AVC/HEVC owner. The caller still provides all source, timing, custody and resource authority:

```sh
fss-capture-rtsp from-onvif-replay \
  --onvif-source /private/recording-replay.json \
  --onvif-digest sha256:RETAINED_OUTPUT_DIGEST \
  --root /private/new-replay-archive --pins /private/new-replay-pins \
  --control-root /recordings \
  --sensor-id sensor:front-door --stream-id stream:recorder-channel1 \
  --generation 1 --ingress 1 --ssrc 7 --payload-type 96 \
  --anchor sha256:OWNER_AUTHORITY_DIGEST \
  --receive-clock sha256:THIS_CAPTURE_RECEIVE_CLOCK_DIGEST \
  --timing-evidence sha256:FIXED_CADENCE_EVIDENCE_DIGEST \
  --journal-id sha256:INDEPENDENT_JOURNAL_ID \
  --frame-duration-ticks 3600 --stop-after-pictures 250 \
  --owner-authorized yes --plaintext yes --retain-originals yes
```

Replace every digest label with the real nonzero SHA-256 value. Supply the recorder's
actual payload, cadence and independently approved SDP control subtree; `/recordings`
is an example. A protected URI-derived subtree can instead be selected through the
existing `--onvif-control-root-digest` resolver. Native RTSP credentials, when required,
need their own exact realm and protected credential file.

Preview reads and validates the private handoff and destination parents; it creates no
capture store and contacts no recorder. Retain and approve the **top-level** `approval`
in the `fss.rtsp_from_onvif_replay_plan.v1` response, then repeat the exact arguments.
The embedded `native_capture` describes the child plan.

Before execution the wrapper rereads the input and checks its complete byte digest and
actual private-file fingerprint. Replacing the inode with identical bytes requires a new
approval. The embedded canonical information is decoded and range-checked again.
Permissions, file identity, codec, window, route, native limits or destination changes
invalidate the relevant approval.

This wrapper owns `--peer`, `--authority`, `--presentation`, `--codec`,
`--replay-start` and `--replay-end`, so overrides refuse. One finite retained-original
capture attempt is admitted. Reconnect, offline recovery and supervision wrappers remain
outside this path. A recorder refusal never triggers a live fallback or automatic
rediscovery.

## Durable provenance and cold inspection

Each source-bearing native request binds nine independent SHA-256 pins: ONVIF selection
approval; complete handoff bytes; observed protected-file identity; canonical service
projection; complete GetServices response; exact recording token; canonical complete
recording information; exact replay URI; and complete GetReplayUri response. That binding
changes the request and derived decode namespace before any original window is created.

The separate durable receipt retains the actual outer capture approval, request,
acknowledgement, stop/publication state and immutable original windows. ONVIF-bound AVC
and HEVC metadata have distinct domains. Existing direct AVC/HEVC canonical byte layouts,
manifest families and source recording formats remain unchanged.

Preserve the receipt root, request identity and complete catalog scope from the existing
publication event/preview. `fss-archive inspect-replay` then verifies the request, nine
source pins and all native original windows using the independently selected codec and
expected identities. Cold inspection does not require the private handoff or a recorder
connection. See [the exact inspection command](RTSP_RECORDER_REPLAY.md#durable-request-and-acknowledgement-receipts).

Receipt digests preserve the selected observations; they do not authenticate the recorder.
Requested/advertised/acknowledged UTC still does not establish per-frame historical
capture time, continuous retention, complete delivery or physical absence.

## Native operations

The public `fss_reference::onvif::client::recording` module provides:

- `inventory(&ClientConfig, &impl OnvifContext)`: GetServices, then GetRecordings.
  The result includes all bounded recording configurations and tracks, exact selected
  service advertisements, response-body digests and actual HTTP exchange count.
- `select(&ClientConfig, token, ReplayWindow, &impl OnvifContext)`: GetServices,
  then GetRecordingInformation for exactly that token, then GetReplayUri.
  The result retains complete information, exact URI, independently approved RTSP
  peer/authority, both observation identities and the exchange count.

The existing owner supplies literal HTTP peer, exact Host authority, service subtree,
generation, approval, finite deadline and resource ceilings. Existing scoped HTTP Digest
or explicit UsernameToken authentication is reused. HTTP Digest permits at most one
scoped challenge retry per operation. UsernameToken first obtains camera UTC for token
freshness only, then uses fresh owner-provided entropy for each signed request. Neither
mode imports credential, clock or route authority from recorder metadata.

Every GetServices entry is validated before namespace selection; duplicate namespaces,
malformed entries, faults and excess entries refuse instead of returning a prefix.
Recording and selected Search/Replay routes must remain within the approved HTTP origin
and subtree. The selected replay URI must separately match the pinned RTSP peer and exact
authority. There is no DNS lookup, redirect, Basic-auth fallback or implicit live URI.

## What the observations mean

The bounded inventory admits at most 64 recordings, at most 32 tracks per recording,
512 bytes per descriptive field, and the existing complete SOAP/XML bounds. Retention
duration is configuration observed on the device, not evidence that any particular media
is still available. Opaque source addresses are descriptive data and are never followed.

Selection requires one video track. Audio and metadata tracks can coexist, but a
recording with no video or multiple video tracks is refused. Codec remains an explicit
owner choice for the separate native replay operation; a track name cannot choose it.

Recording-wide and track-wide earliest/latest times are independently represented.
Every supplied bound must contain the exact request. Contradictory extrema, removed
recordings and mismatched tokens refuse before GetReplayUri. A partly unknown range
still enforces every supplied bound. Missing track timestamps are retained as unknown
in this observational subset, without claiming schema or device conformance. Even a
fully contained range does not prove continuity: holes can exist between the extrema.

GetReplayUri supplies no stable lifetime guarantee. Its exact URI remains sensitive
operator input and must not be logged as ordinary diagnostics. A later replay can refuse
because recorder state changed; the client does not substitute a live stream or clip the
requested interval.

## Canonical private information

`RecordingInformation::canonical_bytes` binds the complete projected fields and the
SHA-256 of the complete original SOAP body, including unprojected extensions.
`from_canonical_bytes` enforces the 64 KiB ceiling, exact token lexemes, valid enums,
bounded text, unique tracks, complete consumption and byte-identical reencoding.
`RecordingServices::digest` independently binds the complete GetServices response
identity and selected endpoints. These identities preserve observations; they do not
authenticate the recorder or turn metadata into retained video evidence.

The separate native RTSP replay contract is documented in
[RTSP recorder replay](RTSP_RECORDER_REPLAY.md). Its exact SETUP/PLAY range, independent
capture approval, immutable original windows and cold receipt verification remain the
authority for acquired source media.

## Verification scope

Shared contracts exercise the actual production wire module in both the core-only target
and native reference target; they do not substitute a parser. Native client contracts use
owned loopback HTTP peers and the real scoped client. The bounded test commands are:

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-core --test onvif_recording_wire_contract
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference --test onvif_recording_contract
```

The complete discovery-to-capture slice adds 40 distinct contracts: 24 native discovery,
4 operator planning/signing, 5 actual SOAP producer processes, 3 native receipt/source
and 4 protected capture process contracts. The 14 shared wire cases also run through
the core-only target. Existing ONVIF and direct replay regressions remain selected by
`bash scripts/check_recording_lifecycle.sh onvif-recording` and the `all` selector.
The new recording-discovery and protected-capture contracts have not yet executed in this session. The local
executor became unavailable after the earlier resource-limited baseline. Final source
snapshots were preserved through GitHub and independently reviewed for API and authority
consistency. Review is not compilation or runtime evidence. Repository-owned local DSR
qualification and hardware interoperability remain open.

The preceding recorder/review native run is retained separately in
[the exact native-results record](validation/2026-11-10-recorder-native-results.json).
That earlier run exposed the shared HEVC admission guard repaired in `2f402c2`; it does
not verify this new discovery path. The final GitHub snapshots could not receive a local
formatter, compiler or runtime pass after the executor outage. No source or dependency
substitution, test weakening or qualification claim is used to conceal that limitation.

## Primary contracts

- [ONVIF Recording Control WSDL](https://www.onvif.org/ver10/recording.wsdl)
- [ONVIF Recording Search WSDL](https://www.onvif.org/ver10/search.wsdl)
- [ONVIF Replay Control WSDL](https://www.onvif.org/ver10/replay.wsdl)
- [ONVIF common schema](https://www.onvif.org/ver10/schema/onvif.xsd)
