# Owner-authorized ONVIF onboarding and RTSP capture

`fss-onvif` opens the standards onboarding path from an explicitly approved
ONVIF device service to a concrete video profile and exact RTSP stream URI.
It performs bounded, native SOAP/HTTP requests for service discovery,
`GetProfiles`, and, when an exact profile is selected, `GetStreamUri`.
`fss-capture-rtsp from-onvif` consumes the resulting private handoff through the
existing RTSP recording, source-custody, pin-journal, and import path.

The implemented subset uses SOAP 1.2 over explicitly approved plaintext HTTP
and RTSP over interleaved TCP. Choose the service lane explicitly:

| Option | Discovery and profiles | Capture handoff |
| --- | --- | --- |
| Omitted or `--media-version media1` | `GetCapabilities`, Media1 `GetProfiles` | H.264/AVC; both observed invalidation flags must be false and timeout semantically zero |
| `--media-version media2` | `GetServices`, exact Media2 namespace, `GetProfiles(Type=VideoEncoder)` | H.264/AVC or H.265/HEVC; explicit Media2 indefinite-URI contract |

There is no automatic service fallback. Selecting Media2 changes the approval
digest; an existing Media1 approval cannot authorize it. Media1's default
approval encoding and private handoff format remain compatible.

Profile inventory can describe JPEG, MPEG4, unsupported video encodings, and
profiles without video, but those cannot produce a capture handoff. Expiring or
one-use Media1 URIs are refused. Media2 returns only a URI; its lifetime basis is
the service contract, not invented Media1 flags or a measured device guarantee.
This is not a declaration of ONVIF Profile T conformance or physical-camera
qualification.

## 1. Prepare the operator inputs

Use an ONVIF endpoint from an owner-approved device configuration or an already
reviewed discovery result. Discovery metadata does not authorize a connection.
Supply the literal HTTP socket address, the exact HTTP authority (`Host`), and
the narrow service subtree allowed for this operation. The client performs no
DNS resolution. A hostname authority is an exact HTTP label sent to the pinned
IP; an IP-literal authority must match the pinned peer. An explicit authority
port must match the peer port; omission means HTTP port 80.

Create an existing private output directory. Output paths must be absolute and
canonical, with no symlink components. The directory must not be writable by
group or other users. Each approved request creates a **new** file with mode
0600. Existing files and symlinks are never overwritten.

Choose the camera's authentication method explicitly:

| Authentication | Options | Request policy |
| --- | --- | --- |
| No configured credentials | Omit credential options | Unsigned requests; an authentication challenge refuses |
| HTTP Digest | `--credential-file` and exact `--auth-realm`; optional `--auth-mode http-digest` | One unsigned request and at most one authenticated retry per operation |
| WS-Security UsernameToken PasswordDigest | `--auth-mode username-token` and `--credential-file` | One unsigned device-time query, then a fresh UsernameToken on every discovery, profile, and URI request |

The credential file contains exactly `username LF password LF`;
it is a private regular file with owner-read permission, no group/other
permissions, and one link; the file itself cannot be a symlink. Provision it through the
operator's secret-management workflow. Do not put a password in the command
line, stream URI, shell history, or repository. The file is read only after the
plan has been approved; replacement, modification, removal, or permission
changes revoke its lease during the operation.
Both authentication modes share the existing bounded printable-ASCII credential
format; this command does not broaden the username/password character set.

Digest defaults to SHA-256 with `qop=auth`. `--legacy-md5 yes` and
`--legacy-no-qop yes` are separate explicit compatibility choices. Every signed
SOAP retry uses a fresh operating-system nonce and the exact HTTP request
target. Only one challenged retry is allowed per operation. There is no automatic
authentication fallback or simultaneous HTTP/WS-Security authentication. Basic,
PasswordText, redirects, TLS, and transport fallback are unsupported. Plaintext HTTP does not
authenticate the server identity or encrypt the exchange.

### Cameras requiring UsernameToken authentication

Use `--auth-mode username-token` in place of `--auth-realm` and the legacy Digest
options. A realm, `--legacy-md5`, or `--legacy-no-qop` is rejected in this mode,
including a legacy option set to `no`. The selected authentication method,
media version, and device-time bootstrap policy are bound into the distinct
`fss.onvif_operator_plan.v3` approval. Existing unsigned and HTTP Digest v1/v2
approvals keep their original encoding and cannot authorize UsernameToken.

After approval, the client requests `GetSystemDateAndTime` once from the exact
pinned device endpoint without credentials. It requires one unambiguous, valid
UTC date and time. The observed camera UTC is advanced by the operation's owned
monotonic clock for subsequent token creation. This works when the camera and
host clocks disagree without reading the host wall clock or changing device
settings. Camera UTC is **only authentication freshness input**; it never becomes
recording, event, receipt, or source-time authority. The supported UTC range is
1970–9999; impossible dates and leap-second values are refused rather than
assigned an inferred timestamp.

Each authenticated request revalidates the private credential lease, obtains a
fresh 128-bit operating-system nonce, and constructs the standard
`Base64(SHA-1(raw nonce + Created + password))` digest. SHA-1 is limited to this
legacy protocol requirement; retained evidence still uses its existing content
identity. The password is never sent as PasswordText. A rejection, SOAP fault,
missing or invalid camera UTC, revoked credential lease, entropy failure, or
expired operation stops the session. A UsernameToken session uses at most three
HTTP exchanges for inventory or four for selection and never retries with a
different authentication method.

## 2. List the media profiles

For example, with owner-supplied addresses and paths:

```bash
onvif_options=(
  --media-version media2
  --peer 192.0.2.10:80
  --authority 192.0.2.10
  --device-path /onvif/device_service
  --service-root /onvif
  --output /srv/fss-private/camera-1-profiles.json
  --owner-authorized yes
  --plaintext yes
  --credential-file /srv/fss-private/camera-1-credentials
  --auth-realm OWNER_VERIFIED_REALM
)

fss-onvif "${onvif_options[@]}"
```

For a UsernameToken camera, replace the example's `--auth-realm
OWNER_VERIFIED_REALM` pair with `--auth-mode username-token`. Keep the independent
HTTP route, service subtree, credential-file, plaintext consent, and output
choices. Apply the same authentication choice when selecting a stream below.

Without `--approve`, this emits a pure plan. It opens no files, credentials,
clock, or sockets. Review the exact peer, HTTP authority, subtree, output path,
credential reference, and bounded limits. Repeat the exact arguments with the
returned approval digest:

```bash
fss-onvif "${onvif_options[@]}" --approve sha256:RETURNED_PLAN_DIGEST
```

The approved operation reads the selected lane's service discovery and profiles. The advertised media
endpoint must preserve the exact approved HTTP authority and remain inside the
approved service subtree. An unrelated host, port, path, redirect, embedded
credential, or unsupported endpoint is refused before it can receive a request
or credentials.

Stdout reports completion, profile count, HTTP exchange count, and the SHA-256
digest of the exact private output bytes. The private inventory has schema
`fss.onvif_media1_inventory.v1` or `fss.onvif_media2_inventory.v1` and contains
the advertised profile tokens, names, encoding, resolution, and whether the
capture subset supports each video profile. Media2 also preserves the advertised
service version; it does not invent Media1 transport-capability flags. Read
that file through a private operator interface and choose an exact supported
video profile token. Camera metadata remains an untrusted
advertisement; resolution and successful onboarding do not establish scene
coverage, source continuity, or capture-time truth.

## 3. Select the stream into a private handoff

Run a new plan with a new output path and all three selection options:

```bash
selection_options=(
  --media-version media2
  --peer 192.0.2.10:80
  --authority 192.0.2.10
  --device-path /onvif/device_service
  --service-root /onvif
  --output /srv/fss-private/camera-1-rtsp.json
  --owner-authorized yes
  --plaintext yes
  --credential-file /srv/fss-private/camera-1-credentials
  --auth-realm OWNER_VERIFIED_REALM
  --profile OWNER_SELECTED_EXACT_PROFILE_TOKEN
  --rtsp-peer 192.0.2.10:554
  --rtsp-authority 192.0.2.10
)

fss-onvif "${selection_options[@]}"
fss-onvif "${selection_options[@]}" --approve sha256:RETURNED_SELECTION_DIGEST
```

The RTSP socket and authority are an independent owner choice. The client
re-reads service discovery and profiles, verifies that the exact token still
exists and has a supported video encoder, and requests that profile's RTSP URI.
Media2 explicitly requests `Protocol=RTSP`, meaning RTP over TCP. The returned authority
must match `--rtsp-authority` exactly, including explicit-port spelling. An
omitted RTSP port means 554 and must agree with `--rtsp-peer`. No URI authority
is rewritten and no advertised alternate target is followed.

The resulting handoff contains the exact URI, peer, authority, codec and
onboarding/profile digests. Media1 retains `fss.onvif_rtsp_handoff.v1` with AVC
and the stable lifetime fields. Media2 writes `fss.onvif_rtsp_handoff.v2`, with
`codec` set to `avc` or `hevc`, `media_version` set to `media2`, and
`uri_validity.basis` set to `media2_indefinite_contract`. It contains no Media1
invalidation or timeout fields. The capture reader accepts both versions with
strict field validation. Query parameters and
supported percent escapes retain their exact spelling. Embedded credentials,
control characters, fragments, path traversal, ambiguous separator escapes,
and unsupported schemes are refused. URI text, camera names, credentials,
realm, challenge nonce, and raw profile tokens do not appear in ordinary
stdout/stderr. Retain the safe completion result's `output_digest` for capture.

Selection does not open the RTSP endpoint or grant capture authority. ONVIF
credentials and approvals are not transferred to the RTSP session. UsernameToken
nonces, password digests, and camera authentication timestamps are never stored
in the inventory or handoff, and ordinary stdout/stderr remain redacted.

## 4. Approve capture using the established source and timing owners

`from-onvif` supplies only the exact peer, authority, presentation URI, and
selected AVC or HEVC codec. Supply the normal archive, independent pin journal, sensor/stream IDs,
generation, ingress identity, SSRC, authority anchor, receive clock, timing
evidence, journal identity, cadence, stopping condition, and retention
authorization. These must describe the actual intended source; they cannot be
inferred from ONVIF metadata.

```bash
capture_options=(
  from-onvif
  --onvif-source /srv/fss-private/camera-1-rtsp.json
  --onvif-digest sha256:EXACT_HANDOFF_OUTPUT_DIGEST
  --root /srv/fss-recordings/camera-1-new
  --pins /srv/fss-pins/camera-1-new
  --control-root /OWNER_APPROVED_RTSP_TRACK_SUBTREE
  --sensor-id sensor:camera-1
  --stream-id stream:camera-1-main
  --generation 1
  --ingress OWNER_ASSIGNED_INGRESS_NUMBER
  --ssrc OWNER_VERIFIED_SSRC_NUMBER
  --anchor sha256:OWNER_AUTHORITY_ANCHOR
  --receive-clock sha256:OWNER_RECEIVE_CLOCK
  --timing-evidence sha256:OWNER_TIMING_EVIDENCE
  --journal-id sha256:OWNER_PIN_JOURNAL_IDENTITY
  --frame-duration-ticks OWNER_SUPPORTED_FIXED_CADENCE
  --stop-after-pictures OWNER_PICTURE_LIMIT
  --owner-authorized yes
  --plaintext yes
  --retain-originals yes
)

fss-capture-rtsp "${capture_options[@]}"
fss-capture-rtsp "${capture_options[@]}" --approve sha256:RETURNED_CAPTURE_DIGEST
```

All uppercase placeholders must be replaced with real owner-established
values; they are intentionally not fabricated evidence. See
`fss-capture-rtsp --help` for supported bounds, codec-specific cadence/reordering options,
source custody, RTCP handling, and ordinary capture requirements. If RTSP
requires Digest authentication, add its independently approved
`--credential-file` and exact `--auth-realm` options to the capture arguments.
For HEVC, select the intended RTP payload type if needed with `--payload-type`.
The native recorder verifies the selected SDP H265 offer and its VPS/SPS/PPS;
the existing explicit owner-supplied HEVC parameter options also remain available.
An ONVIF H.265 advertisement cannot override an H264 SDP response or authorize an
unsupported bitstream. All codec, source-timing and picture-boundary checks remain
owned by native acquisition and recording.

The capture preview reads only the bounded protected handoff through an owned
context, checks its exact byte digest and schema, and emits a separate capture
approval with redacted URI text. It opens no camera, RTSP credentials, archive,
or pin journal. The approval binds both the ordinary capture plan and the
handoff's path, contents, file identity, permissions, ownership, and change
metadata. Execution re-reads and checks these before entering the native
capture owner. Replacing the file with identical bytes also requires a new
preview and approval.

Do not supply `--peer`, `--authority`, `--presentation`, or `--codec` in this
mode. The explicit `--control-root` is a query-free subtree for advertised SDP
track controls; the returned presentation URI cannot grant permission to
sibling tracks. The handoff must remain outside the archive and pin-journal
paths. The default `--capture-mode single` runs one ordinary capture attempt
with those exact paths. Its existing approval encoding is preserved. Choose
the explicit reconnect mode below when planning a supervised session, source
retention, a finite campaign, or subsequent recovery of those campaign stores.

Successful capture uses the existing publication and custody mechanisms.
Native retained import and cold decode remain available through
`fss-import-rtsp` and `fss-file`. Onboarding output itself is operator
configuration, never recording evidence or a substitute for retained source
bytes and independent recovery pins.

## 5. Supervise capture, retain datagrams, and recover original stores

Add `--capture-mode reconnect` to the protected handoff command to delegate to
the established reconnect owner. Its existing options remain available. For
example, this plans three independently retained sessions with bounded retries
and a ten-second owner-clock duration per session:

```bash
reconnect_options=(
  "${capture_options[@]}"
  --capture-mode reconnect
  --max-attempts 3
  --retry-delay-ms 250
  --retry-max-delay-ms 5000
  --timeout-ms 30000
  --progress-timeout-ms 5000
  --capture-duration-ms 10000
  --continue-after-success yes
)

fss-capture-rtsp "${reconnect_options[@]}"
fss-capture-rtsp "${reconnect_options[@]}" --approve sha256:RETURNED_OUTER_PLAN_DIGEST
```

Use `--max-attempts 1` for one supervised session. Omit the duration and campaign
options if only failure-driven reconnect is intended. The picture limit remains
a hard per-attempt ceiling; the earlier approved successful stop applies.
Progress supervision starts at accepted PLAY and detects lack of collected
pictures without treating keepalives or RTCP as video progress. Its expiry is a
failure, not source EOF or a successful timed segment. Authentication, authority,
codec/timing faults, incomplete publication and exhausted budgets still stop the
run. The existing `--retry-interrupted yes` option separately authorizes only its
documented, settled-prefix interruption cases.

In this mode `--root` and `--pins` are prefixes. Actual destinations are fresh
siblings such as `camera-1-new.attempt-0001`, `camera-1-new.attempt-0002`, and so on.
Each attempt has its own generation, receive/decode clocks and journal identity.
All derived archive, journal and optional source destinations must be disjoint
from the protected handoff; canonical parent aliases are checked too. The outer
preview includes every possible child and aggregate resource ceilings. Private
presentation and control URIs are redacted even when they contain no query.

The outer approval binds the mode, protected handoff bytes and fingerprint, and
the complete native plan. Neither an ordinary capture approval nor a nested
child approval authorizes this command. Finite campaigns preserve each attempt's
outcome and do not assert gap-free recording, cross-attempt continuity, or an
always-on service.

To retain complete received RTP/RTCP datagrams before media progress, add the
existing explicit source-custody options to the same plan:

```bash
source_options=(
  --source-root /srv/fss-source/camera-1-new
  --source-retention-evidence sha256:OWNER_DATAGRAM_RETENTION_EVIDENCE
  --max-datagrams 8192
  --source-storage-bytes 268435456
  --source-work 1000000000
)

fss-capture-rtsp "${reconnect_options[@]}" "${source_options[@]}"
fss-capture-rtsp "${reconnect_options[@]}" "${source_options[@]}" \
  --approve sha256:RETURNED_SOURCE_CAPTURE_DIGEST
```

Source retention is explicit and unencrypted, includes malformed received
datagrams, and uses a separate new `PREFIX.attempt-NNNN` store per attempt.
Datagram, storage and work ceilings are per attempt and are priced in the outer
preview. A source failure stops capture; the wrapper does not recreate or resume
a failed source store. Preserve all stores and complete JSONL receipts.

For both AVC and HEVC, recorded packet custody preserves the original network
intake receipt time through delayed polling and backpressure. Queue-admission
time remains separate and continues to govern queue deadlines. Recovery compares
the exact retained packet bytes and original receive timestamps against the raw
source chain. Existing archives with inconsistent timestamps remain refused;
the command does not rewrite historical evidence or relax this correspondence.

For **offline recovery**, repeat the original reconnect and source options,
remove the capture approval, and request a new preview:

```bash
fss-capture-rtsp "${reconnect_options[@]}" "${source_options[@]}" --recover yes
fss-capture-rtsp "${reconnect_options[@]}" "${source_options[@]}" --recover yes \
  --approve sha256:RETURNED_OUTER_RECOVERY_DIGEST
```

The wrapper binds the freshly observed native recovery digest into a new outer
approval. The native owner holds and rechecks the original stores and validates
that outer approval at its existing pre-mutation gate. Execution does not run a
second preview scan or replenish source-work/deadline allowances. After lengthy
inspection the handoff's identity and bytes are revalidated before approval can
be accepted. A changed store, replaced handoff or stale capture approval refuses.
Recovery opens no camera or credentials; source-retained recovery verifies its
original datagram chains. `--recovery-timeout-ms` bounds the native recovery
operation, including the enclosing approval check.

Use `--recover index` with another fresh outer preview/approval to publish any
eligible recovered catalog tail. Recovery and indexing retain their existing
minimum pin/source fences, all-selected preflight, original source checks and
idempotent publication behavior. They create no new capture epochs and do not
establish capture completion. Switching a completed single-mode command into
reconnect mode cannot recover its original unsuffixed stores: select the mode
when first planning capture and preserve the exact original options.

## Failure and scope behavior

All network, clock, credential, output, and wait boundaries carry live
request-owned runtime authority and bounded budgets. Cancellation closes
admission, drains ownership, and preserves a cancelled outcome. SOAP faults,
auth failures, route mismatches, unsupported selected profiles/URIs, malformed
XML/HTTP, revoked credentials, deadline exhaustion, and output publication
failures return bounded sanitized error codes. Neither output errors nor
failed requests become a successful handoff.

Output is created only after a complete validated result, and success includes
an exact read-back of the private retained bytes. If writing fails after file
creation, a partial private file can remain. Preserve it for operator
inspection and choose a new output path and approval for a retry; the command
does not overwrite or silently delete it.

No device settings, PTZ controls, audio channels, account discovery, vendor
credentials, firmware changes, or provisioning bypass are implemented here.
The native private-file integration is Linux-specific. Physical-camera
interoperability, expiring URI lifecycle support, TLS,
Profile M, and full Profile T qualification remain separate work.

## Verification scope

Repository tests use owned loopback HTTP/RTSP peers and checked-in AVC/HEVC media.
The process fixture verifies real SHA-256 Digest responses with fresh nonces,
private profile inventory, same-origin service enforcement, credential
revocation, handoff replacement/content/permission refusals, and exact
query/percent-escaped URI use through DESCRIBE/PLAY and scoped SETUP. The successful
paths publish source custody, import retained media, and cold-decode both AVC
and Media2-selected HEVC. The HEVC test reopens retained source independently,
takes the original capture archive offline, and decodes from the imported
custody. A mismatching SDP codec refuses before remote SETUP. Wire and client
tests also cover Media2 namespace/version selection, bounded service inventories,
missing video configurations, and refusal of implicit service fallback.
The UsernameToken-only process fixture independently checks each transmitted
password digest and fresh nonce against an intentionally skewed camera UTC. It
verifies private Media1 inventory and Media2 selection through real native HEVC
capture, retained import, and cold decode. Additional cases refuse ambiguous or
invalid UTC, mixed authentication flags, stale approval modes, foreign service
origins, credential revocation, HTTP Digest challenges, and SOAP authentication
faults without fallback or secret disclosure. Deterministic contracts cover
known digest vectors, UTC rollover and overflow, exact XML namespaces, request
size limits, and signed-request lifetime checks.
The protected reconnect fixture exercises real source EOF, a successor with a
fresh generation and independent retained datagrams, then separately approved
offline recovery and indexing with no camera connection. A Media2 HEVC fixture
also captures seven original datagrams and two pictures, verifies the retained
source head and exact packet membership, then restores and indexes the HEVC
archive offline with distinct approvals. The fixtures also check private
query-free URI redaction, nested-approval refusal and collisions with derived
attempt/source destinations. Recovery and indexing owner tests deny the enclosing
approval while the original stores are locked and verify no publication or pin
mutation occurs.
Private-file tests additionally cover symlinks, hardlinks, parent replacement,
create races, bounded reads, cancellation, and same-inode output tampering.
These tests establish the implementation's bounded ownership and byte path;
they do not certify a particular camera, deployment, or standard profile.

Protocol shapes follow the official [device WSDL](https://www.onvif.org/ver10/device/wsdl/devicemgmt.wsdl),
[Media1 WSDL](https://www.onvif.org/ver10/media/wsdl/media.wsdl),
[Media2 WSDL](https://www.onvif.org/ver20/media/wsdl/media.wsdl), and
[ONVIF schema](https://www.onvif.org/ver10/schema/onvif.xsd).
Authentication and the pre-authentication device-time operation follow
[ONVIF Core 25.12, sections 5.9.1 and 8.3.6](https://www.onvif.org/specs/2512/ONVIF-Core-Spec-v2512.pdf)
and [OASIS UsernameToken Profile 1.1.1, section 3.1](https://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-UsernameTokenProfile-v1.1.1-os.html).
