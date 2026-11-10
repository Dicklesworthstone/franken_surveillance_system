# Historical recording discovery and native replay

The read-only ONVIF recording client fills the discovery gap before native recorder
playback: an owner can enumerate configured recordings, explicitly choose one exact
token and closed interval, inspect its advertised information, and obtain a replay URI
within an independently approved RTSP scope.

This is a bounded part of VIT-022 / `fss-vit022-recorder-retrieval-5js5o`.
It creates no remote search session, recording job or configuration change. It does not
claim complete Profile G support, actual retained-media coverage or trusted historical
capture time.

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

The new recording-discovery contracts have not yet executed in this session. The local
executor became unavailable after the earlier resource-limited baseline. Final source
snapshots were preserved through GitHub and independently reviewed for API and authority
consistency. Review is not compilation or runtime evidence. Repository-owned local DSR
qualification and hardware interoperability remain open.

The preceding recorder/review native run is retained separately in
[the exact native-results record](validation/2026-11-10-recorder-native-results.json).
That earlier run exposed the shared HEVC admission guard repaired in `2f402c2`; it does
not verify this new discovery path.

## Primary contracts

- [ONVIF Recording Control WSDL](https://www.onvif.org/ver10/recording.wsdl)
- [ONVIF Recording Search WSDL](https://www.onvif.org/ver10/search.wsdl)
- [ONVIF Replay Control WSDL](https://www.onvif.org/ver10/replay.wsdl)
- [ONVIF common schema](https://www.onvif.org/ver10/schema/onvif.xsd)
