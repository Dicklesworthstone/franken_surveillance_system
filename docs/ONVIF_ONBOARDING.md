# Owner-authorized ONVIF onboarding and RTSP capture

`fss-onvif` opens the standards onboarding path from an explicitly approved
ONVIF device service to a concrete video profile and exact RTSP stream URI.
It performs bounded, native SOAP/HTTP requests for `GetCapabilities`,
`GetProfiles`, and, when an exact profile is selected, `GetStreamUri`.
`fss-capture-rtsp from-onvif` consumes the resulting private handoff through the
existing RTSP recording, source-custody, pin-journal, and import path.

The implemented subset is ONVIF Media1 over explicitly approved plaintext HTTP,
RTSP over interleaved TCP, and H.264/AVC. Profile inventory can describe JPEG,
MPEG4, unsupported video encodings, and profiles without video, but those cannot
produce a capture handoff. A selected URI must have both invalidation flags
false and a semantically zero timeout. Expiring or one-use URIs are refused.
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

When the camera requires HTTP Digest, provide `--credential-file` and its exact
`--auth-realm`. The credential file contains exactly `username LF password LF`;
it is a private regular file with owner-read permission, no group/other
permissions, and one link; the file itself cannot be a symlink. Provision it through the
operator's secret-management workflow. Do not put a password in the command
line, stream URI, shell history, or repository. The file is read only after the
plan has been approved; replacement, modification, removal, or permission
changes revoke its lease during the operation.

Digest defaults to SHA-256 with `qop=auth`. `--legacy-md5 yes` and
`--legacy-no-qop yes` are separate explicit compatibility choices. Every signed
SOAP retry uses a fresh operating-system nonce and the exact HTTP request
target. Only one challenged retry is allowed per operation. There is no Basic,
WS-Security, redirect, TLS, or transport fallback. Plaintext HTTP does not
authenticate the server identity or encrypt the exchange.

## 2. List the media profiles

For example, with owner-supplied addresses and paths:

```bash
onvif_options=(
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

Without `--approve`, this emits a pure plan. It opens no files, credentials,
clock, or sockets. Review the exact peer, HTTP authority, subtree, output path,
credential reference, and bounded limits. Repeat the exact arguments with the
returned approval digest:

```bash
fss-onvif "${onvif_options[@]}" --approve sha256:RETURNED_PLAN_DIGEST
```

The approved operation reads capabilities and profiles. The advertised media
endpoint must preserve the exact approved HTTP authority and remain inside the
approved service subtree. An unrelated host, port, path, redirect, embedded
credential, or unsupported endpoint is refused before it can receive a request
or credentials.

Stdout reports completion, profile count, HTTP exchange count, and the SHA-256
digest of the exact private output bytes. The private inventory has schema
`fss.onvif_media1_inventory.v1` and contains the advertised profile tokens,
names, encoding, resolution, and whether the capture subset supports each
video profile. Read that file through a private operator interface and choose
an exact H.264 profile token. Camera metadata remains an untrusted
advertisement; resolution and successful onboarding do not establish scene
coverage, source continuity, or capture-time truth.

## 3. Select the stream into a private handoff

Run a new plan with a new output path and all three selection options:

```bash
selection_options=(
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
re-reads capabilities and profiles, verifies that the exact token still exists
and has H.264 video, and requests that profile's RTSP URI. The returned authority
must match `--rtsp-authority` exactly, including explicit-port spelling. An
omitted RTSP port means 554 and must agree with `--rtsp-peer`. No URI authority
is rewritten and no advertised alternate target is followed.

The resulting `fss.onvif_rtsp_handoff.v1` file contains the exact URI, peer,
authority, AVC codec, and onboarding/profile digests. Query parameters and
supported percent escapes retain their exact spelling. Embedded credentials,
control characters, fragments, path traversal, ambiguous separator escapes,
and unsupported schemes are refused. URI text, camera names, credentials,
realm, challenge nonce, and raw profile tokens do not appear in ordinary
stdout/stderr. Retain the safe completion result's `output_digest` for capture.

Selection does not open the RTSP endpoint or grant capture authority. HTTP
Digest credentials and approvals are not transferred to the RTSP session.

## 4. Approve capture using the established source and timing owners

`from-onvif` supplies only the exact peer, authority, presentation URI, and AVC
codec. Supply the normal archive, independent pin journal, sensor/stream IDs,
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
`fss-capture-rtsp --help` for supported bounds, AVC cadence/reordering options,
source custody, RTCP handling, and ordinary capture requirements. If RTSP
requires Digest authentication, add its independently approved
`--credential-file` and exact `--auth-realm` options to the capture arguments.

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
paths. This initial integration runs one ordinary capture attempt; it does not
enable the separate reconnect, retained-source, or recovery wrappers.

Successful capture uses the existing publication and custody mechanisms.
Native retained import and cold decode remain available through
`fss-import-rtsp` and `fss-file`. Onboarding output itself is operator
configuration, never recording evidence or a substitute for retained source
bytes and independent recovery pins.

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
interoperability, expiring URI lifecycle support, TLS/WS-Security, Media2,
Profile M, and full Profile T qualification remain separate work.

## Verification scope

Repository tests use owned loopback HTTP/RTSP peers and checked-in AVC media.
The process fixture verifies real SHA-256 Digest responses with fresh nonces,
private profile inventory, same-origin service enforcement, credential
revocation, handoff replacement/content/permission refusals, and exact
query/percent-escaped URI use through DESCRIBE/PLAY and scoped SETUP. The successful
path publishes source custody, imports retained media, and cold-decodes it.
Private-file tests additionally cover symlinks, hardlinks, parent replacement,
create races, bounded reads, cancellation, and same-inode output tampering.
These tests establish the implementation's bounded ownership and byte path;
they do not certify a particular camera, deployment, or standard profile.
