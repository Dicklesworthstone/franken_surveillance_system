# UniFi Direct: experimental packet reference

This is an in-progress owner-authorized interoperability lane. Native discovery
has contacted one owner-controlled G4, and native ingress has processed a
passive capture through loopback. An experimental networked controller has
reached TLS and WebSocket upgrade with that camera, but has not completed its
conversation or produced a native clip. It does not independently authenticate
the peer, provide continuous native recording, or establish general device or
firmware support.
Existing UniFi Protect export handling is separate and remains unchanged.

## Working reference and proposed route

The laboratory setup used xuio/scrypted-unifi-direct commit
`2920ce8896aadd603e2847d17554905592d155e8` and an owner-authorized G4 Instant.
The device reported firmware `UVC.v4.70.37.67.M_9b6a37f.240320.0635` on
2026-11-04. The Rust discovery probe and passive-media replay observations below
apply to that owned laboratory device and do not establish full compatibility.
The camera's management connection used a TLS WebSocket, and the controller
commanded a TCP push using `extendedFlv`. This wire description is based on the
reference implementation and must be checked against sanitized fixtures and
exact device/firmware tuples. The emulator's peer address and claimed identity
are not cryptographic camera authentication.

An eight-second, in-memory, passive observation of this G4's 720p push on
2026-11-04 yielded 1,100,611 contiguous captured TCP payload bytes. A structural
scanner found 208 video, 109 audio, and 2 metadata candidate tags; all 318
measured gaps between adjacent candidates were 16 bytes. Only aggregate counts
and sizes were retained from that observation. The observation started
midstream and did not validate sender identity, decode, continuity, every frame,
other camera models or longer runs; it does not justify assuming all UniFi
trailers are 16 bytes. No source media or credentials were added to the repository.
A second in-memory 720p observation found 208 structurally framed AVC sample
candidates. All 208 matched a four-byte NAL-length walk and reported a zero
composition offset; two claimed FLV keyframe type and 206 inter-frame type.
Those are observations of tag framing, not proof of the configuration record,
valid H.264 syntax, successful decoding, or future camera behavior.

On 2026-11-05, a native Asupersync UDP discovery test on `trj` sent one
owner-scoped local broadcast and received one UVC candidate: the G4 Instant,
whose response advertised the same address as its sender. This is an
unauthenticated discovery claim, not proof of ownership, adoption state, or
access authority. The test made no camera configuration changes. The exact
executed stripped test binary's SHA-256 was
`5f33b5be478defe9c7186c076ac5bba6a395325c476f6d78d442f65e65dd41af`.

Also on 2026-11-05, an eight-second passive capture of the running camera's
existing push was reassembled in memory. Because capture began midstream, the
laboratory harness prepended a synthetic FLV header and replayed the resulting
96,697-byte input through `TcpIngress` and `DirectIngress` over native
Asupersync loopback on `trj`. The Rust code returned 209 AVC sample-tag
candidates and preserved the complete received source in emitted records and
the remaining 16-byte tail. Eleven choices skipped an earlier incomplete
candidate; 315 records were therefore marked provisional. This is actual G4
traffic processed by the Rust path, not a direct camera TCP connection, a
verified boundary/decoder result, source custody, or a continuous recording.
No captured media or credentials were written into the repository.

The source-preserving AVC track now retains a bounded configuration epoch and
returns connection-relative SPS, PPS and sample NAL ranges without inventing
RTP packet custody. It fences on malformed AVC input or discontinuous records,
reports samples seen before a configuration separately, and propagates
provisional framing to dependent samples. The caller must still bind each
track to its connection and stream generation, retain the original bytes,
and establish receive-time, decoded-picture and archive custody separately.

In a later eight-second passive G4 capture, the TCP ingress and this track
processed 118,455 source bytes, including a synthetic FLV header, as 325
records with 210 AVC sample tags. All 210 were reported as unconfigured;
no source AVC configuration was present in the midstream capture. There were
no provisional records in this particular replay, and the original 16-byte
tail was retained. A separate eight-second passive observation found 209
samples matching a four-byte length hypothesis and candidate NAL types 1
(208) and 5 (1); no in-band SPS or PPS NAL was observed. This does not prove
that the camera never sends them. Both observations used heuristic structural
tag boundaries and do not establish a verified source or decoded video.

The track's four synthetic tests, eight existing AVC tests and four existing
stream tests passed on `hz2`. The source track and TCP integration tests then
passed six of six non-ignored cases at base
`955562d03290395612e2bd59eaa8066de79ddd72`, overlay
`083709d89dc1637c62c668497a18a5c521468a3ec98428f58ac7f460a18cb16b`.
The separately invoked one-test passive replay on `trj` used the exact
Linux test binary with SHA-256
`bc35e9450bf0f9a4aff22acdda25cc3233f9d511103a0e6bfcc58f68df6e066a`.
The active recorder and its upload, firewall and discovery services remained
active after the test.

`TrackedIngress` now composes that track directly with the task-owned TCP/FLV
source owner. It transfers each exact record alongside its interpretation; if
interpretation fails, it returns that record with the refusal and fences later
reads. Pending and unparsed bytes remain available on retirement. On `hz2`,
four packet-track tests and three native-ingress tests passed at base
`955562d03290395612e2bd59eaa8066de79ddd72` and overlay
`321c418f465082d90c566ad5f21b8fe45c5cc912c758faa3fc0765de4a9af095`;
the separate owner-camera test was ignored in that synthetic run. For a
subsequent live passive replay on `trj`, a debug-stripped copy of that test
binary was transferred with matching SHA-256
`a5cf6ed514bfacde077a4eed2a82f1b8475b1d279a6e612e4470f1c3e9f04fbd`.
It processed 97,244 source bytes, including a synthetic header, as 322
records with 209 unconfigured AVC sample tags, zero provisional records,
and a retained 16-byte tail. The recorder, upload timer, firewall, and
discovery timer were active afterward. This passive replay does not establish
camera identity, a live native controller, decoded pictures, custody or
recording completeness.

`fss-container::flv_avc` now provides a separate source-mapped AVC MP4
reference for this transport. It requires one exact SPS/PPS configuration,
contiguous framed source coverage (including interleaved non-video records),
an IDR-led fragment, validated primary-picture prefixes and a later distinct
picture as a witness. It refuses provisional records and does not assume an
FLV tag candidate is an authenticated boundary. The owner must still bind the
connection and configuration epoch, retain source bytes, and publish custody.
It currently supports a single SPS/PPS pair without AVC configuration
extensions, writes video only, and buffers no input on the caller's behalf.

On synthetic fixtures, three emitted samples passed the native MP4 demuxer and
their decoded pixel hashes matched the original fixture in the Rust H.264
decoder. Three FLV mux contracts plus twelve existing AVC mux contracts
passed on `hz2` at base `955562d03290395612e2bd59eaa8066de79ddd72`, overlay
`c705ba65a3d8e97e9a396919c15775b17d5cdd7b4fe5f85845f4f2af1f2d4478`.

For a separate real-camera laboratory check, the existing recorder's recent
MP4 supplied an H.264 configuration; it was injected into a passive fresh G4
stream capture in memory. The Rust decoder produced three 1280×720 frames.
Another capture was synthetically trimmed to an IDR candidate, given that
separately sourced configuration, remuxed with source ranges, demuxed, and
decoded into three 1280×720 frames. The separate configuration's identity and
epoch relative to the live capture were not independently verified. These
checks did not retain media, drive the native controller, or establish native
recording continuity. The latter used a debug-stripped binary with SHA-256
`9661d1f9ba002ea0020dea5c601269b536ee84679d4c262dbfa3ff80383c5ba1`, built
at overlay `3360c125f8180aa2689e98ea53493995871e570a99f6c91128524f609e8ee764`.

An initial independent FFmpeg pixel comparison on another capture did not
match the Rust decoder; that run did not establish identical compressed inputs
and used FFmpeg's default frame synchronization. A subsequent independently
captured sample explicitly matched all three compressed NAL inputs and used
FFmpeg's passthrough frame synchronization. All three decoded I420 frame
SHA-256 comparisons matched. Because this was a different capture, it does not
explain the earlier discrepancy. The latter check used a debug-stripped test
binary SHA-256 `e4d37106ebf67b5bd25fb4937f1d928fcc871bf14f403e1998270908ed71e0c9`,
built at overlay `6833fbaa51855a79925520ffac68b943b22aab6163c3d60b9cc82b2d6b9deeb1`.
Both tests injected a configuration from a separate recording and selected an
IDR candidate; neither validates the identity or continuity of a native live
camera session. Image bytes and private comparison hashes were kept in memory.

The bounded FLV recording owner now groups source records into IDR-led MP4
fragments, explicitly returns pre-roll, carries audio and metadata as original
source records without muxing them, and returns unfinished source on retirement.
It does not itself persist source or output. In synthetic tests it produced two
three-picture fragments across a 32-bit FLV timestamp rollover; pre-roll,
buffer-exhaustion, malformed-picture and source-recovery contracts passed.

The first 20-second passive G4 segment replay failed closed on a provisional
framing boundary. A subsequent separate 20-second analysis found 875 of 875
observed adjacent-tag gaps were 16 bytes with zero bytes at trailer offsets
4 through 11, and all selected tags had zero stream ID. Three earlier
incomplete candidates caused ambiguous selections. The independently published
[pyunifiwire format notes](https://github.com/rjmotion/pyunifiwire/blob/ab424de6426826a9fba4cab7b5e20684355fea66/SPEC.md)
describe a 16-byte trailer for another UniFi model; the local G4 observations
do not prove this holds for every model, firmware, or stream. The explicit
`StructuredTrailer16` policy now requires that padding and a zero FLV stream
ID, preserves its policy in each source record, and stops without consuming
the buffered bytes on a mismatch. The existing conservative and provisional
search policies remain available.

Using that explicitly selected policy, a later 20-second passive G4 replay
produced three video-only MP4 fragments containing 450 samples; the native
decoder decoded three frames from each fragment at 1280×720. The remaining
26 source records and 16-byte unparsed tail were returned, not discarded. This
test injected a synthetic configuration obtained from a separate recording,
inserted a synthetic trailer after it, and selected a starting IDR candidate.
It neither authenticated the capture nor published or retained a recording.
The debug-stripped test executable SHA-256 was
`ee6d90673133637ec93b1e6a1815ca2b8ab3cfe96f96e8634a80c5cd99e3c50c`.
Seventeen targeted synthetic tests passed on `hz3` at base
`955562d03290395612e2bd59eaa8066de79ddd72`, overlay
`a0896ced876136e54cef60a8e45ab4c0084a585038ee49e96cf9b65b430d347f`.

A further 20-second passive capture was replayed through task-owned
Asupersync loopback TCP ingress, structured FLV framing, the bounded recording
owner, MP4 demux and native H.264 decode. It produced three fragments with
450 samples, decoded nine frames at 1280×720, and returned 56 unclosed source
records plus the 16-byte framing tail. The separate synthetic configuration,
synthetic trailer, selected IDR and unverified identity limitations above
still apply. This is a loopback replay, not a direct native camera session or
a durable recording. The debug-stripped test binary SHA-256 was
`c965c7eefb2b5a4ecf68565ba0da46db797b0145eb6c7bb2a006e44db38e3567`,
built on `hz3` with overlay
`0f20752db2f4a6bd762596968bcad7b45b70bf977a0431cdd347612305f87c1f`.

The recorder now also copies the later-picture boundary witness (including
interleaved source records) under an independent byte limit before committing a
fragment cursor. Each completed segment binds its exact configuration record
and derived initialization. A separate bounded, in-memory evidence preparation
constructs a canonical object graph describing the exact source and witness
records, FLV framing policy, media-clock timing, and source-to-MP4 NAL mappings.
This graph is neither a durable receipt nor authorization to store or disclose
media, and it supplies no physical capture time. Six synthetic recorder and
evidence tests passed on `hz3`, base
`955562d03290395612e2bd59eaa8066de79ddd72`, overlay
`399b562e73083cc0d703f1d7f6d133db0ab3cbcce4f2faf59d213ec065c5031e`.

A fresh 20-second passive G4 sample produced three fragments and 450 video
samples; three frames from each decoded at 1280×720, and each fragment passed
in-memory evidence-graph preparation and boundary-source checks. The 94
unclosed records and 16-byte tail remained with the caller. This used the same
synthetic configuration, inserted trailer, selected IDR and Asupersync
loopback replay described above; no media was persisted, and the camera was not
authenticated by this test. The debug-stripped executable SHA-256 was
`f3856bd687b5d8099a4d04727085cf6b6ebabfefc81ab6d5612c72be4f1fbaad`,
built on `hz3` with overlay
`fdc98b5ad333757f80de59dcde52b9c4e8a57f3b58557c543965793a944f6177`.

After the ledger adapter was added, another fresh passive G4 replay again
produced three fragments, 450 samples, and nine decoded 1280×720 frames; all
three in-memory graphs and original boundary witnesses were verified. The
caller retained 134 unclosed records and the 16-byte framing tail. The same
synthetic configuration, inserted trailer, selected IDR, unauthenticated
source and loopback restrictions still apply; no camera media was persisted.
The debug-stripped executable SHA-256 was
`36dc88de92ec4e27cb1588c4a4b440732a846d1b724ad9c6385e249a8ff2b61b`;
its `hz3` build overlay was
`90d07521ee53ddebd6f16b0b3f34b83b180be92a9b69275ecb049a93fe2978f5`.

A further passive 20-second midstream observation found 569 structurally
complete AVC video-tag candidates: three IDR and 566 non-IDR NALs, with no
configuration tag and no in-band SPS or PPS NAL. No candidates failed the
bounded length-prefix check; the data stayed in memory. This is one short
observation, not a universal firmware guarantee. It explains why a midstream
passive replay still requires separately sourced configuration and why the
native owner must retain the camera's original configuration from connection
start to bind a genuine configuration epoch.

An FLV-specific publication adapter now stages the original configuration,
source records and boundary witnesses before the MP4 objects and commits the
prepared root through the existing ledgered publisher. It requires an explicit
original-byte retention authority and independently supplied physical capture
bounds; a media timestamp or receive time does not satisfy that requirement.
Synthetic source records were published into a local deployment, the same plan
was retried without a second ledger entry, and every object was recovered
after reopening the deployment. A missing capture interval, denied retention,
and retention revocation during staging were refused without committing a root.
An authorized reader reopened a retained configuration object after restart;
it refused an unledgered root, denied read authority, a mismatched capture pin,
and an object outside the manifest. A separate bounded segment reader now
revalidates the pinned graph, source and witness hashes, source-to-fragment NAL
bytes, original codec parameter sets, and MP4 sample timing and ranges. It
rechecks read authority throughout and returns no partial clip on failure. In
an isolated synthetic deployment, a segment was published, reopened, recovered
byte-for-byte, and decoded into three frames; low work budget, denied and
revoked access, a wrong capture pin, and an intentionally corrupted object were
refused. Seven recording contract tests passed on `hz3`. The reader does not
independently establish physical capture time, authenticate the camera, or prove
continuity; FLV boundary selection remains heuristic. The local spool is not
encrypted by this adapter. This is a synthetic storage test, not a live-camera
recording or an operational retention service.

The intended native path is an authority-scoped and cancellation-owned
controller, a bounded TCP ingress, source-preserving extended-FLV parsing, and
source-linked compressed pictures handed to the existing native media and
archive owners. Audio, detections, control effects, and outward interoperability
remain separately qualified capabilities. TLS dependency admission remains
open under `DEP-TLS-001` and must not be bypassed by an unqualified dependency
or a hidden foreign process.

`unifi_direct::pipeline` now composes the task-owned TCP source and FLV framer
with the in-memory recorder, transferring original source records and returning
unparsed and unclosed data at retirement. A loopback fixture drove the
controller conversation, sent video to its requested listener, and produced
two fragments with six decoded frames while reconstructing the original source.
The same fixture forced a recorder capacity refusal and verified that the
pipeline stopped and returned the received source prefix without loss.
This fixture does not exercise TLS or an actual camera. A separate passive
20-second G4 observation was replayed through the same pipeline on `trj`:
three fragments contained 450 samples, and nine frames decoded at 1280×720;
16 bytes remained in the framing tail. As above, this replay used a synthetic
configuration from a separate recording and a synthetically selected IDR;
camera authenticity and configuration-epoch identity remain unverified. No
media was persisted by the replay, and the recorder and both timers remained
active afterward. The stripped Linux test binary SHA-256 was
`2e69f85a813f35208e3d55ec45dd8a27d6fccad42bab28862cf75e7806440d23`.
The remote Cargo compilation finished, but RCH rejected unrelated Linux
artifact synchronization onto the Mac with exit 102; the retained job was
recovered and acknowledged, and only the independently hash-matched test
binary was copied to `trj`. This is not a native live controller, sustained
recording, evidence publication, or a retention service.

`unifi_direct::listener` now binds one task-scoped IPv4 media listener, checks
network and media grants as well as caller-supplied listener and peer policy,
and attaches an accepted connection to that same task before constructing the
recording pipeline. Its startup operation binds first, uses the actual bound
port in the controller's stream request, and accepts one admitted connection.
An ephemeral port is checked again after binding. A native
loopback test used the actual bound port in the controller's stream request,
then received and decoded the fixture stream. The test also refused a denied
bind, a revoked pending accept, and a denied peer; the task-ingress test refused
a different task before the first read. A separate fixture revoked listener
policy during negotiation and confirmed that the stream-setting frame was not
sent; its committed operation remained open. Eight tests passed on `hz3` across
the controller fixture and async execution targets. The listener is one-shot and does not supply
a reconnect supervisor. Peer IP policy and the claimed MAC do not authenticate
a camera. This listener has not been deployed or connected to the physical G4.

The currently pinned `asupersync = 0.5.0` exposes a `tls` feature that enables
`rustls/ring`. That is not the pure-Rust provider direction specified in the
open TLS record. A newer local Asupersync checkout has a provider-independent
`tls-core` feature, but it is not the version pinned by this project and its
presence does not establish FSS admission or qualification. The implementation
must qualify a compatible provider and exact feature/dependency closure, either
through a justified Asupersync upgrade or the separately scoped TLS boundary
described by the existing ADR; enabling `tls` on 0.5.0 is not a resolution.
The intended `rustls-rustcrypto` provider's upstream README at revision
[`70f76c039e587192688af18a80d5d6435dedaf22`](https://github.com/RustCrypto/rustls-rustcrypto/blob/70f76c039e587192688af18a80d5d6435dedaf22/README.md)
advises against production use and identifies incomplete TLS support. The
exact release and provider choice therefore need review as part of the open
admission; this observation does not authorize switching to a native provider
or silently relaxing the project's policy.
At that development revision, its provider hook, key-exchange code and
randomized signer also obtain system entropy directly. The project requires
an explicitly scoped entropy authority, so swapping only one randomness hook
would not establish compliance; the exact candidate's full entropy path needs
qualification.
The existing dependency record principally describes outbound client TLS;
this use is an inbound TLS server. Its server certificate and key custody,
camera-side certificate validation behavior, server entropy, and peer identity
policy require explicit treatment in the applicable admission record and tests.
Possession of a server certificate alone does not authenticate the camera.
On 2026-11-05 an independent local TLS client connected to the existing
controller listener on `trj` without sending a WebSocket upgrade. The listener
accepted TLS 1.3 with `TLS_AES_256_GCM_SHA384`, and separately TLS 1.2 with
`ECDHE-RSA-AES128-GCM-SHA256`; the client reported an RSA-PSS signature and a
self-signed certificate. These observations establish only what that listener
accepted from that client. They do not establish the G4's negotiated TLS
version, certificate-verification behavior, peer identity, or whether a new
provider is eligible for FSS admission.
The same independent TLS client also connected to the owner's G4 Instant's
local HTTPS listener, without making an HTTP request or logging in. It observed
TLS 1.3 with `TLS_CHACHA20_POLY1305_SHA256`, and separately TLS 1.2 with
`ECDHE-ECDSA-AES256-GCM-SHA384`, an ECDSA P-256 signature, and a self-signed
certificate. These are two client-selected negotiations against this specific
camera firmware, not a complete supported-suite list or a certificate
authenticity check. The camera's HTTP login remains untested.

A separate [TLS v1 certificate lab](../experiments/unifi_tls_v1_lab/README.md)
then exercised `rustls` 0.23.43 with `rustls-rustcrypto` at the exact revision
above against the owner's G4 HTTPS listener, without sending application data.
The camera presents an X.509 v1 certificate; rustls's certificate-based
signature helper returned `UnsupportedCertVersion` for it even when the
observed certificate matched. The lab instead parsed that pinned certificate
with `x509-cert` 0.2.5 and verified its P-256 handshake signature through
rustls's raw-public-key helper. Both TLS 1.3 and TLS 1.2 handshakes completed;
for each version a modified certificate pin and a different, valid P-256
public key were rejected. OpenSSL independently reported that the substituted
public key was valid. The TLS 1.2 lab accepts only P-256/SHA-256 and uses the
raw-key signature verifier on rustls's supplied TLS 1.2 handshake message; it
does not claim general TLS 1.2 signature-scheme coverage.

The matching pin was obtained from the same network without independent
identity verification. The lab verifier does not validate certificate dates,
hostname, or a certificate chain, and it never sends credentials. It uses
blocking standard-library sockets, ambient provider entropy, and an upstream
provider that warns against production use. These results establish only a
credential-free interoperability route for this camera, not authenticated
identity, FSS provider admission, Asupersync integration, or production safety.

A later [owned HTTPS status-line lab](../experiments/unifi_https_status_lab/README.md)
used Asupersync, the FSS metered TCP transport, and the same experimental
provider to send one credential-free `GET /api/1.1/status` after the observed
certificate and handshake signature matched. The owner's G4 returned HTTP 401
in both TLS 1.2 and TLS 1.3 cases. For each version, changed-certificate and
valid-wrong-key controls rejected the handshake before the HTTP request; all
six task receipts completed. This is a direct application response from the
network endpoint, not independent camera authentication, login, full HTTP
response parsing, or video. The same-network pin and unqualified provider
limitations remain. The stripped executable SHA-256 was
`0fe7e10973ac41d5a1ec3e28080482ec2fac813b545ab9d576d6049547088d58`.

The subsequent [authenticated HTTPS lab](../experiments/unifi_https_auth_lab/README.md)
used the existing owner-controlled private camera credential after its
observed TLS pin and signature matched. On `trj`, the final task-owned Rust
client received HTTP 200 from both login and the read-only status endpoint;
it retained only object-presence flags and did not issue settings commands.
Changed-certificate and valid-wrong-key controls stopped before a deliberately
nonexistent credential file was read. A disposable TLS loopback independently
checked the login/cookie/status sequence, and three Rust tests covered cookie,
JSON and private-file refusal. The final live-test executable SHA-256 was
`331908ddbb6b385eba4a8ed398b00a6c51ce5c02d17a8fa58b8b8e3e6f221a49`.
The test created a camera login session; session expiry was not established.
The same-network pin is not independent device identity, the TLS provider and
entropy boundary are not production-admitted, and this does not establish
native camera control, video streaming, or continuous recording.

The later [direct HTTPS snapshot lab](../experiments/unifi_https_snapshot_lab/README.md)
added a single authenticated `/snap.jpeg` request on the same task-owned
connection. A disposable loopback fixture first exercised login, cookie,
status, snapshot and the FSS JPEG decoder. On `trj`, the owner's G4 returned
HTTP 200 for the snapshot and the pure-Rust decoder reconstructed one
640×360 luma frame in memory. Pin and wrong-key controls refused before
credential access, and the recorder and both timers remained active. The
stripped executable SHA-256 was
`e058b7dac6e4b3e0fbd349abfe7bfbbe94fb814e6637d0e0d8e35a9606d6f5b7`.
No camera image was deliberately persisted, no source custody was published,
and neither physical identity, capture time, video continuity nor a native
recording service was established. The laboratory's TLS, entropy, synchronous
file I/O and secret-memory limitations remain.

An output-enabled revision of that lab subsequently received, decoded and
created a private temporary JPEG from the G4. A private task-workspace copy
matched the original bytes and was shown to the owner. Four Rust tests and an
independent disposable TLS/JPEG fixture passed; the changed-pin and wrong-key
controls again refused before credential access. The stripped executable
SHA-256 was
`2a0963657d6c12d0dd028217072c6562aeca83ddd83b4ec139f49f75e4161200`.
The file is not a custody or recording receipt, and the pin is still not
independent device identity. The existing recorder and timers remained active.

`fss_reference::unifi_direct::camera_api` now owns the bounded local login,
status and snapshot request/response sequence used by the lab. It binds each
prepared request to its session, rejects ambiguous cookies and malformed
responses, permits a retry only after an explicitly unwritten request, and
fences an indeterminate write. Four Rust contract tests passed on `hz3`, and
the independent TLS fixture exercised the same project source. On `trj`, that
source then logged into the owner's G4, read status and decoded one 640×360
snapshot; changed-pin and wrong-key controls stopped before credential access.
The stripped executable SHA-256 was
`9677e491f893a41ee2d311f067399f9308a542f090e58f947d7b4461b1ec8884`.
This test created a login session with unknown expiry; it did not persist the
image, take over the controller, or establish independently authenticated
device identity, streaming or recording. The camera refused TCP connections on
ports 554 and 7447 during a separate bounded probe; that observation is not a
claim about all devices or possible stream configurations.

`fss_reference::unifi_direct::camera_http` now owns the login, status,
settings and snapshot sequence over a caller-supplied metered asynchronous
transport. It checks task grants and current peer/session policy on every I/O
poll, bounds HTTP framing and response size, and fences the session if an
exchange is interrupted or refused. The caller still supplies and validates
TLS, camera identity, credentials and a live lease; this owner does not itself
provide discovery, device adoption or continuous recording. On `hz4`, six
camera API tests and one owned HTTP integration test passed, including a real
loopback sequence, same-task clock revalidation, malformed response and
cancellation/refusal controls. The camera-specific TLS lab subsequently used
the earlier read-only revision of this owner with an independent TLS fixture (including a 60,000-byte
settings response), then logged into the owner's G4 and decoded a 640×360
snapshot. Changed-pin and wrong-key controls were rejected before credential
access. This is an experimental, same-network-observed TLS identity and a
fresh login session with unknown expiry, not native recorder or onboarding
qualification. See the [snapshot lab](../experiments/unifi_https_snapshot_lab/README.md)
for binary/source identities and the initial clock-regression failure.

The camera-local API now supports read-only settings observations after login
and status. It returns only the claimed controller IPv4 address (or explicit
unset, missing or unsupported state) and a local binding to the peer and
session generation; it does not return other settings or grant a handoff. Six
contract tests passed on `hz3`. On `trj`, an independent TLS fixture with a
60,000-byte settings field reproduced a `message buffer full` error in the
previous lab adapter; processing each accepted TLS record prefix fixed that
fixture. An initial live settings attempt had produced the same error. The
corrected binary then logged into the G4, read status and settings, and decoded
a 640×360 snapshot; the camera reported a controller address matching this
connection's source address on `trj`. Changed-pin and wrong-key controls
rejected before credential access. The stripped binary SHA-256 was
`a581c9a91b2a4d43dec6b4405d1c934bdfe1cd5e6f882eed86c1cd6feb5bc923`.
The successful check created one login session; the initial failed attempt's
session outcome and session expiry are not established. The recorder and both
timers remained active. This is a single untrusted, same-network observation,
not a durable rollback plan, independent identity proof, or authorization to
change the controller; a future handoff must re-read and revalidate current
state and account for all required settings and recovery steps.

A subsequent read-only run on 2026-11-05 repeated the direct G4 login, status,
settings, and snapshot sequence using that same pinned laboratory binary. All
four requests returned HTTP 200, and the FSS decoder reconstructed a 640×360
luma frame. This created another camera session with unknown expiry; no image
was persisted. The same observed-pin and experimental-provider limits apply.
This was not a test of the archive reader or native continuous recording.

Later the same day, a fresh read-only physical G4 check on `trj` used the
earlier laboratory snapshot executable with SHA-256
`9677e491f893a41ee2d311f067399f9308a542f090e58f947d7b4461b1ec8884`.
It returned HTTP 200 for status and snapshot, decoded a 640×360 luma frame in
memory, and reported a completed task receipt. No image was persisted. This
creates another camera login session whose expiry is not established, and the
same observed-pin and experimental-provider limits apply. It does not test
native continuous video, identity authentication, or automatic enrollment.
Separately, the transitional recorder restarted at 18:42 Eastern before that
snapshot check. Its journal subsequently reported recording started, and seven
upload runs reported eight verified segments copied without a deferral. These
observations do not establish that recording was gap-free around the restart.
The recorder later restarted again at 19:01 Eastern and was active after the
subsequent observation below; its upload service's most recent run reported
success. Its journal shows that FFmpeg exited with code zero before the
recorder service restarted; the inspected log categories did not identify why
the stream ended. This likewise does not establish uninterrupted coverage.

The isolated handoff lab now has an explicit `--observe-only` mode that reads
controller settings twice and exits before journal creation or any settings
write. On `vmi1153651`, the binary compiled and its independent encrypted
fixture passed 14 cases, including expected, destination, different and
changing controller claims in read-only mode. The exact binary SHA-256 was
`bbb5499ab306d567b5c09d52538ca6d1b06e9b5fdd725b7e0a8031fae8bd7602`.
On the owner's G4, it reported two matching observations of the expected
existing controller, no effect and a completed task receipt; the unused
journal path remained absent. The run created a camera login session with
unknown expiry. The claim remains unverified, and it does not settle the
earlier ambiguous handoff or prove an earlier request's timing or cause.
The project setup owner subsequently gained an `observe` method
that composes scoped discovery admission with two settings reads and no effect
preparation. Socket fixture cases for matching and changing claims were also
added. A separate strict-remote `cargo check --locked -p fss-reference --lib`
passed on `ovh-a`, and a strict-remote `cargo check` of the contract test target
passed on `ts1`. An earlier remote test started on `trj` but was terminated
after disk telemetry became unavailable; same-job recovery later acknowledged
exit 137 and source release. A subsequent strict-remote run on `ts1` completed
all 14 contract tests successfully, including both new observation tests.
These synthetic project tests do not establish live-camera execution of the
project-level method or complete automated enrollment.

`unifi_direct::handoff` now prepares an inert controller-address change bound
to the exact semantic request, reported prior IPv4 address, camera and peer
claims, session generation and lease fence. Unknown or unset prior addresses
are refused. A reverse-address digest is only a preview: it neither authorizes
a reverse request nor accounts for all controller state. Six camera API tests
and three handoff tests passed on `hz3`; one handoff test prepared and
committed the exact registered management effect using an actual file journal,
then retained its unresolved obligation. The plan itself exposes no sendable
HTTP request. The camera API additionally provides a guarded dispatch that
requires the matching committed journal-backed permit, caller-owned metered
transport, current claims and a caller-supplied live authority check. It repeats
the authority check on transport writes and flushes and fences the session on
an uncertain write. The request digest binds semantic method, path, peer,
generation and body; the private session cookie is assembled separately and
is not part of the durable digest. A local write or HTTP 200 does not establish
remote association: fresh settings readback and independent reconciliation are
required, and the journal obligation remains open. Fixture tests exercise this
path: three synthetic dispatch tests passed on `hz3`, including revoked
authority and cancellation after one byte. After interruption, the fixture
reopened the file journal and recovered the committed operation in
reconciliation-only mode. It has not dispatched a change to the physical
camera. Independently
authenticated identity, qualified TLS, supervised durable journal I/O, a
working native controller and a complete recovery procedure remain necessary
before switching a controller.

The owned camera HTTP session now connects that journal-backed handoff to its
existing authenticated session. It applies both the session policy and the
handoff policy, retains the claimed permit for reconciliation, reads one
bounded HTTP response, and requires a fresh settings readback. A cancelled
response read fences the session. The plan classifies a representable readback
as requested, previous or different after checking its peer/session binding;
unset, missing and unsupported values remain separate untrusted observations.
On `hz4`, the handoff fixtures exercised successful HTTP readback, stale and
denied writes, cancellation and the still-committed journal obligation. These
are loopback tests: no controller change has been sent to the physical camera,
and a reported requested address is not proof of identity or adoption.


The experimental `unifi_direct::conversation` owner composes the existing
session and task-effect APIs into a bounded hello, delayed agreement and
stream-setting exchange, including a bounded set of interleaved time-sync
requests. Each outbound management or setting message gets a separate
journal-backed operation; the caller supplies current approval, identity and
lease checks. The returned settings reply is an untrusted observation, not a
recording or proof of an active stream. All committed obligations still need
reconciliation. The operation owns neither a listener nor media ingress, and
its synchronous journal calls still require a supervised nonblocking strategy
before production use. A disposable loopback fixture, not the physical G4,
exercises the automated exchange and time sync.
The standalone lab's Cargo.lock SHA-256 is
`017e952a29789ba62564821042553b421260e20ec74bbf0268a50ba512b58685`;
the Linux executable SHA-256 was
`eb35852b8c34b4bb4356514c4e4a083482800e0e9ef6b07687d3224680ef6eba`.
The independently copied source, manifest, and lockfile in the repository are
byte-identical to those used for the `hz2` build and six live attempts on
`trj`. The target-specific active Cargo dependency tree contained neither
`ring` nor `aws-lc-rs`; this is not a full transitive unsafe-code, build-script,
entropy, advisory, or supply-chain audit.

An additional [isolated server lab](../experiments/unifi_tls_05_server_lab/README.md)
drives `rustls-pure` over the workspace's pinned Asupersync 0.5 without its
`ring`-based TLS feature. Eight disposable-fixture tests passed on `hz3`,
including a complete encrypted controller-to-media loopback, independent
OpenSSL trust controls, a silent peer, and interruption after one ciphertext
byte. The adapter, provider and entropy path are not admitted, and full-duplex
backpressure, TLS 1.2, physical camera identity, the camera-to-controller
handshake and production supervision remain open. No live G4 controller was
changed by these tests.

A second [Asupersync TLS lab](../experiments/unifi_tls_async_lab/README.md)
drives the same pinned provider's sans-I/O TLS state machine using the project's
Asupersync 0.5.0 TCP runtime, with finite connect and handshake timeouts, byte
limits and iteration limits. On the same G4 and observed pin, both TLS 1.2 and
TLS 1.3 completed, and both the modified-pin and valid-wrong-key controls were
rejected in each protocol version. No application data or credentials were
sent. The standalone lockfile SHA-256 is
`ea190ec234a98495f74c1ea6d014f3b4364df58dff183318c9f39b180aa495ed` and the
Linux executable SHA-256 is
`a29c0097f0fbaabff3ec40960a2653de7822a8a79b04caf364e19632113ee053`.
The lab source, manifest and lockfile in the repository match the copies used
for the `hz2` build and six tests on `trj`. Its Linux active dependency tree
contains neither `ring` nor `aws-lc-rs`.
It has a standalone dependency resolution and no FSS `TaskCx`, durable owner,
qualified entropy path, trusted identity or production TLS admission. It is
runtime interoperability evidence, not a native FSS camera integration.
The locally installed Asupersync 0.5.0 source does expose a generic
`WebSocketAcceptor` over `AsyncRead + AsyncWrite`, bounded frame/message limits,
and read-ahead handling. It is a candidate for a request-owned WebSocket layer
once the TLS transport is resolved; its availability alone does not prove the
G4 handshake, cancellation, authentication, or compatibility with the final
TLS owner. The reference sends JSON in binary WebSocket messages; the
experimental sender below preserves that framing and the `secure_transfer`
subprotocol in a synthetic loopback test.
The experimental `unifi_direct::upgrade` boundary now prepares a bounded HTTP
upgrade using Asupersync's WebSocket handshake, checks the untrusted camera-MAC
claim, and preserves read-ahead bytes for the WebSocket owner after a locally
completed response write. Strict mode requires the client to offer the
subprotocol; a separate, explicitly selected compatibility mode matches the
reference emulator's unconditional response. Real-camera support for either
mode has not been established. This boundary performs no network I/O, does
not implement TLS or authentication, and requires the caller to account for
the response write and retire the connection if the write is indeterminate.
Its three targeted synthetic contract tests passed on `hz2` on 2026-11-05 at
base `51bf09a2844a8ad82f03feac6fdb10eb35e1bc96` and overlay
`4e020314ab47fb870038fea5f684acca2f70c6c15e90c3b65b81f2b18e15f3d4`.
Those tests cover strict and compatibility negotiation, bounded invalid input,
and delivery of a pipelined frame to Asupersync. A later run added a native
loopback TCP upgrade/first-frame test and passed all four targeted tests on
`hz2` at overlay
`ca6b66fc6a54af9d3d853887a5ab23e2a3af3944aa3532fb7f1040e0e7cdae7b`.
They do not exercise real TLS, the controller loop, or the G4's upgrade
behavior.
The experimental `unifi_direct::metered` wrapper ties an owned stream to its
registered task and runtime context. It checks scoped network authority on
every poll and retains separately prepaid read and write reservations across
pending polls; unused reservations are not refunded. It must wrap the raw network transport below TLS for
wire-byte accounting; wrapping a buffered or encrypted stream alone does not
bound its underlying wire writes. The experimental `unifi_direct::receive`
owner connects this wrapper and the WebSocket upgrade to the management
message parser, returns bounded observations and explicit retirement facts,
and meters automatic WebSocket ping and close responses. It can prepare hello,
agreement and time-sync messages and bind each exact request to a journal-backed,
one-use management permit and current policy and precondition checks. The old
permitless dispatch API now refuses all writes. A partial, failed or dropped
send fences the connection and returns unresolved state instead of automatically
retrying. It can also dispatch an exact stream-setting request through a
journal-backed, one-use committed camera-setting permit after current policy
and precondition checks. That is a reference boundary, not an adoption or streaming service.
Unknown event payloads are not retained. Four synthetic receive and
dispatch tests passed on `hz3`, base
`955562d03290395612e2bd59eaa8066de79ddd72`, overlay
`80a81cbed45a9b5b9458018de24bd9ad9bc34acbf383e024be7d75932f815ad4`.
They include a real loopback TCP hello exchange and a deliberately dropped
future after a partial write. They do not establish a live G4 management session.
Live remote management effects still need a registered effect contract,
prepared intent, current scoped authority, durable reconciliation, and a
qualified TLS and identity boundary before this owner can drive a camera.
Eight targeted tests across the upgrade, metering and receive contracts passed
on `hz2` at base `51bf09a2844a8ad82f03feac6fdb10eb35e1bc96` and overlay
`f5dde930c646cd820918a2a61d80befdbfbbfe8693f59edf582b7c4c591384b0`.
The native loopback fixture covered a camera-shaped hello, an automatic
ping/pong, an idle timeout followed by time-sync input, and preservation of
unresolved facts on disconnect. After changing reservations to survive pending
polls and adding partial-write and error-forfeiture cases, all ten targeted
tests passed on the same base and worker at overlay
`219eab81e2bdeec37194df351cc03632cd9871a0d6feab9c8abfc6de60d1bec2`.
This fixture is not a live G4 session.
The owner must retain bytes read past the HTTP upgrade header, account for an
interrupted or partially written upgrade response, and keep the WebSocket
receive/close machinery serviced while waiting for the agreement delay. It
must not interpret a local successful write or a claimed MAC address as a
confirmed peer identity or completed camera effect.
The experimental `unifi_direct::intent` binds a prepared stream-settings
request to its exact request digest and caller-supplied identity, peer-admission,
stream-generation, prior-settings and lease-fence preconditions. These are
inert identities, not authentication, a durable effect, or permission to send.
The effect `EFFECT-CAMERA-SETTING-001` already exists in the effect registry
with readback and stream-generation rollover required. The runtime now maps
its own prepare/commit grant pair to that effect. Capability registry v4 and
reference basis v4 preserve v1/v2/v3 pins and refuse old bases as stale; an old
project session must rebase before using the new grants. The effect coordinator
was exercised with a synthetic lease and readback. The UniFi sender now checks
the exact committed request, preconditions, camera resource and lease fence,
and claims a journal-backed permit once before writing. In a synthetic test
using an actual local effect journal, denial and stale preconditions wrote
nothing, a simulated message was sent once, and a second use was refused.
An interrupted variant dropped the dispatch future after one byte, fenced the
controller, and reopened the journal with the operation still committed and
reconciliation-only; it did not recreate a dispatch permit. This fixture
passed on `hz3` with overlay
`846d729383358c49bad45353733ef6df6f6dfef0b7f1c74c994cea0f5ec5a952`.
No camera setting was changed by these tests.
A later encrypted controller-to-media fixture also published two synthetic
segments, reopened their source-linked ledgered archive, and decoded six
frames (two test cases passed on `hz3`). It uses synthetic capture intervals
and synchronous archive calls; it does not establish a production recording
worker, complete stream custody, or live-camera operation. See the
[experiment](../experiments/unifi_tls_05_server_lab/README.md) for the exact
binary and source digests.

On `hz3`, 12 controller, four receive, and seven recording/archive synthetic
tests passed on base `955562d03290395612e2bd59eaa8066de79ddd72`, overlay
`c783fb3ed9e78f9c5c3efa702a31c6ca1ae3b5a675a33006055de764355ece9b`.
Freshly supplied preconditions can now be checked against that exact binding;
12 controller and four receive tests passed on `hz3` with overlay
`3343be5fb32fa8cb93755b123e3ae02168deb5010c979bfe8992de071444e2a5`.
With the new registry and runtime effect included, 12 controller, four receive,
and seven recording/archive tests passed on `hz3`, overlay
`3435c25ad2d45759b0285827888ad2f3a7d7e568ecf1d5a11bc5b1db9dcc5bbb`.
The separate core/runtime compatibility and effect tests passed on overlay
`68d6acb31d89434bbe758170421a48410e5f2b5abab5f11b81c80c6db27a8cb0`,
and all three probe-profile tests passed on overlay
`2b5e9a47563869ac706fcbc22d20d55f8629e825007b0b7ef2f9a91dc778ef9d`.
The journal-backed stream-effect fixture, four receive tests and 30 runtime
tests passed on overlay
`3fa3faec7f2a6bba0af33428173570530803bd8f752528662b6df2dfcf6e69cb`.
The capability checker passed all 27 Python tests. Robot documentation was
regenerated and its freshness check passed. The full schema validator reported
51 existing baseline findings, with identical normalized diagnostics and schema
catalog digest before and after the equivalent description wording change.
Hello association and time synchronization can also change remote state. They
now have a separate management effect and journal-backed dispatch path; the
journal does not by itself authenticate a peer or verify remote state.

The reference stream-start command is a remote settings change, not a passive
subscription: it can also redirect other tracks to a null destination. A
native stream owner must authorize and account for each changed track, avoid
disturbing another active consumer, and preserve uncertain outcomes. Merely
opening a listener does not start a camera push.
The pinned Asupersync TLS source explicitly says an interrupted handshake is
not cancel-safe: the owner must drop that connection, not reuse it. Listener,
handshake, idle, and receive budgets need bounded watchdogs and native-runtime
tests; deterministic in-memory socket tests alone cannot qualify kernel I/O.

## Current code boundary

`fss_packet::extended_flv` provides pure, allocation-free borrowed views of an
FLV header and a structurally valid tag, plus a bounded search for a successor
tag after a vendor trailer. The caller retains the original bytes, sees the
unmodified header and trailer, and must separately bind source offsets, clock,
identity, authority, and continuity. A matching back-reference is a heuristic
candidate: adversarial trailer bytes can contain a fake tag. The conservative
search defers later matches when an earlier candidate is incomplete, so the
result cannot change merely because reads were split differently. An explicit
provisional search can return a later candidate sooner and flags the unresolved
earlier candidate; it may change with more input and must not become a durable
source-boundary claim. The ingress owner must cap buffered bytes, processing
work and time: a malicious peer can otherwise deliberately delay completion.

`fss_packet::extended_flv::avc` adds bounded AVC video header, configuration
and length-prefixed NAL views. SPS, PPS, and sample NALs expose their exact
ranges in the original tag; signed composition offsets are preserved. A sample
is admitted only after its complete NAL-length walk passes. Frame-type flags
and observed IDR NAL type do not prove a complete or decodable picture. The
caller still owns cross-tag camera, stream-generation and configuration-epoch
binding; the structural parser does not validate full H.264 syntax.
`fss_packet::extended_flv::stream` incrementally frames caller-provided
contiguous bytes and returns exact original segments and offsets. Its optional
low-latency mode propagates a provisional marker after any skipped incomplete
candidate; its conservative mode can wait indefinitely on a plausible long
candidate, as observed on the real G4. Neither mode proves a genuine boundary.

The next media owner should bind each tag's range to a retained immutable source
object or an explicit non-retention record before composing tag-relative NAL
ranges with object offsets. It must keep source receive-clock observations
separate from the wrapping FLV timestamp and signed composition offset. A
configuration change or reconnect must fence the old stream/configuration
generation; passing a configuration from an unrelated camera or old epoch to
the pure parser is possible and must be prevented at that owner boundary.
Neither a provisional boundary nor a structurally matched IDR header becomes
a decoded-picture, coverage, authenticated-camera, or source-durability claim.
The recorded-RTP reference offers a useful design precedent: it validates
mapped NAL bytes against the borrowed original, and its import owner separately
stages original source chunks and records publication outcomes. An FLV owner
needs its own stream-offset and retained-object mapping, including the case
where a tag crosses object chunks; RTP sequence numbers and markers do not
exist on that path. Capture intervals must come from the receiving owner, not
from FLV media timestamps.

`fss_reference::unifi_direct` models the hello, time-sync, correlated
parameter-agreement messages, and preparation of a one-track stream-start
settings request without I/O. The caller supplies a stable
controller identity, exact wall-clock values, the monotonic interval after the
hello write, and local transport outcomes. Agreement preparation requires at
least a half second of owner-reported elapsed time; a future runtime must own
the clock and timer rather than inventing this observation.
Only a proven unwritten message may be retried; an indeterminate write retires
the session from automatic progress. Explicit close returns a payload-free
retirement record naming any unresolved prepared message, agreement request,
or time-sync reply; the I/O owner must retain or reconcile those facts. An
agreement reply is an observation, not authentication or adoption proof. The
stream-start reference prepares a literal IPv4 destination, an owner-supplied
stream name and typed channel/codecs; it deliberately omits other tracks. The
caller must authorize the destination and settings, ensure the listener exists,
account for other users and shared camera audio state, and retain the exact
request for reconciliation. A correlated settings response and any status
fields are untrusted observations, not proof of a successful setting or a
live stream. The reference has no WebSocket framing, peer identity, I/O owner,
event handling, or Asupersync-owned network service.
The future I/O owner must resolve the agreement write before feeding a reply
to this state machine, or retain and replay an early reply after resolving the
local write. The reference currently rejects a reply observed before the write
receipt; it does not buffer or silently discard that reply for the owner.

The packet and controller references have no native live controller, incremental
storage owner, media assembly, session-to-sensor custody, or persistence
format. Synthetic tests are not live-camera or security qualification. Do not
replace the running recorder or claim source continuity on this basis.

`fss_runtime::tcp_ingress` is an experimental bounded original-byte reader
for an already accepted Asupersync TCP stream. The explicit registered task
must hold resource-scoped media and network grants, and each read reserves
bounded byte and network budget before touching the socket. A dropped pending
read keeps its reservation with the same unforgeable task binding; a completed
read remains in the owner until the caller moves it or explicitly retires the
owner. The resulting source chunk is not a durable-custody receipt. Listener
authorization, peer authentication, idle supervision, canonical clock
observations, source publication, and binding to a camera/session remain the
caller's responsibilities. `fss_reference::unifi_direct::ingress` composes
that reader with the incremental FLV framer, preserving any incomplete source
at retirement. It is not connected to the controller or a durable recorder.

`fss_reference::unifi_direct::discovery` sends one explicitly scoped v1 UDP
query over Asupersync and returns bounded, unauthenticated UVC candidates. It is
not yet integrated with the general discovery command or a complete automatic
setup service. A one-candidate setup owner now composes a completed discovery
report with an already-admitted camera HTTP session and journaled controller
handoff. Wi-Fi onboarding for unprovisioned devices, TLS and credential custody,
current controller ownership and safe adoption remain independent requirements.
The source now accepts replies from the specified subnet to its directed
broadcast as well as the limited broadcast; point-to-point `/31` and `/32`
targets remain unicast. Its bounded report can flag a missing or invalid MAC,
different MAC claims at one source address, a MAC claim at different source
addresses, conflicting platform/firmware claims, and an unadvertised source
address. These are unauthenticated observations for one window, not proof of
separate devices or permission to adopt them. The experimental CLI's source
emits these flags in `fss.unifi_discovery_lab.v2`; this version is now installed
in the scoped `trj` discovery service, as described below.
On `hz3`, two internal scope/claim tests, four UDP discovery contract tests,
and two CLI argument/escaping tests passed. On `trj`, the separately invoked
owner-camera test found one G4 candidate with no claim issues in each of a
limited-broadcast and a directed-broadcast window. Both reported 1/1 passing;
the shell's trailing exit-status assignment in the first directed-broadcast run
failed because `status` is reserved by zsh. A corrected repeat exited zero,
and the recorder and both timers remained active. The live test executable SHA-256 was
`93a104d8864a1458a0931262d3b1bffefe7dcad33ec41f7f0f326e06de5e1837`.
These windows do not authenticate the device or establish absence of other
cameras.

A fresh service-triggered native discovery window on `trj` on 2026-11-05
completed with `WindowElapsed`, one datagram and one candidate claiming the
platform `UVC G4 Instant`. Its discovery identity was unverified and the CLI
reported setup unavailable; this is not an authenticated device identification
or automatic enrollment. The existing recorder and its firewall, upload and
discovery timers remained active.

### Standalone direct trial

An isolated Rust executable now joins the task-owned controller listener,
experimental TLS, management conversation, supervised media pipeline and one
private MP4 verification output. It does not change a camera's controller
address or provide continuous recording. Process fixtures exercise it with a
synthetic camera. In a separate owner-authorized physical G4 trial on `ts1`, a
journaled camera handoff received a readback that did not match the requested
address; the native connection ended with an unexpected EOF and no clip was
produced. A second bounded trial with stage markers confirmed the camera reached
the controller over TCP, but the experimental TLS handshake ended with EOF.
It does not establish the underlying TLS incompatibility. Both separately
scheduled restoration checks confirmed the existing controller address; fresh
segments were subsequently verified and uploaded by the existing recorder.
In a third limited test, a camera-to-controller packet capture showed the
camera closing its accepted TCP connection before sending any TLS bytes. The
capture therefore cannot establish a TLS version or certificate mismatch;
the interaction with the existing controller remains a possible explanation.
The listener was then extended to accept sequential connections within a
bounded deadline. A real G4 reconnect completed TLS and WebSocket upgrade,
revealing an early camera time-sync frame with a nonzero correlation. An
attempt to answer such frames exhausted the message limit; the controller now
ignores correlated time-sync replies and answers uncorrelated camera requests.
The synthetic process fixture covers that sequence and the existing controller
contracts passed. A later physical test with this code completed TLS and
WebSocket upgrade but retired on a transport error while awaiting hello; no
native clip was produced. The existing controller reasserted its address near
the attempt, but its role in that failure is not established.
The receiver now retains a payload-free WebSocket or I/O failure category,
including the standard I/O error kind, instead of collapsing all such failures
into one transport result. Five receive-contract tests and four encrypted
process fixtures passed remotely; synthetic cases distinguish an unmasked
client frame from a connection reset and ensure I/O error text is not exposed.
This diagnostic cannot identify the earlier failure retroactively. A later
physical G4 attempt reached TLS and WebSocket, then reported an I/O
`UnexpectedEof` while awaiting hello. Its handoff readback again failed to
confirm the requested address and no native clip was produced. This result
does not identify whether the G4 sends masked frames. The existing Scrypted
controller parser accepts either masked or unmasked frames, whereas the Rust
WebSocket server refuses unmasked client frames. This source difference is a
compatibility hypothesis, not an observation of the physical camera or an
explanation of why the connection ended.
The trial listener now permits a bounded reconnect after this exact early EOF
only when no management effect has reached approval; it stops instead if an
effect was prepared. Five process fixtures passed: four encrypted camera cases
and a no-camera deadline. They included a successful synthetic reconnect and
an EOF after a time-sync effect that did not retry. In a subsequent physical
trial, the handoff readback reported the previous controller and the listener
received no connection before its
deadline. Thus the new reconnect path was not exercised by the physical G4,
and this result does not distinguish an unapplied change from a competing
controller restoring the old address. The scheduled restoration check found
the existing address and made no write, the recovery watchdog abstained, and
fresh recorder segments were verified and uploaded afterward.
The handoff owner can now expose a bounded, payload-free HTTP response shape;
its optional boolean and numeric values are untrusted claims and cannot settle
an effect. A laboratory diagnostic samples three readbacks over roughly two
seconds without another setting write. The setup owner also retains that
response shape if a later readback is interrupted, alongside the unresolved
effect permit. Nine independent synthetic HTTPS cases passed, including delayed
and reversed camera claims, and nine handoff-dispatch contracts passed,
including interrupted readback. These fixture cases used synthetic peers.
In a later owner-authorized physical trial, the camera returned HTTP 200 with
an empty response body, then reported the previous controller in all three
readbacks across the diagnostic window. The native listener received no
connection before its deadline. The effect remains unresolved: the result
does not distinguish an unapplied setting from an immediate competing write.
The camera's local status subsequently reported controller port 7442, whereas
the preceding trials listened on 7443. A protected test on port 7442 reached
TLS and WebSocket, but retired with an unexpected EOF before hello; the three
handoff readbacks still reported the previous controller. In another test,
the existing controller's repair address was temporarily held empty under an
independent restoration timer. Before a new setting was written, the camera
reported the temporary controller address, and its connection reached TLS and
WebSocket, but the native conversation timed out before hello. The existing
repair address was restored. This is consistent with a competing repair or a
delayed earlier write, but does not establish which changed the camera's claim.
Neither physical test produced a native clip. The independently scheduled
repair-address and controller restoration checks were no-ops after manual
restoration; the recovery watchdog abstained, and fresh recorder segments were
verified and uploaded afterward.
In a subsequent protected attempt with re-pairing held, one controller-address
write returned an empty HTTP 200 but all three immediate readbacks still showed
the previous address. A separate no-write check did not confirm the intended
address, so the planned camera reboot was skipped and the existing repair
address restored. This further limits the evidence for a successful handoff;
it does not establish whether the camera would apply that request later.
The scheduled repair-address and controller restoration checks later finished
as no-ops, and the recovery watchdog abstained without rebooting the camera.
Fresh recorder files and successful uploads were observed afterward, without
establishing uninterrupted coverage.
The transitional upload program contains a destination-side cleanup that
checks the recording volume is mounted and removes matching regular files
when their modification age reaches 30 days. A digest-pinned copy of that
cleanup, redirected to an owned temporary directory, passed seven synthetic
mount, age, filename and file-type checks on `trj`; the retained test is
`experiments/unifi_https_snapshot_lab/test_retention_cleanup.py`. These checks
do not establish that an actual 30-day-old recording has been deleted or that
the recorder has provided uninterrupted coverage.

An independent local HTTP observation showed that the existing Node-based
controller sends its settings body with chunked transfer encoding; the Rust
handoff previously used a fixed content length. The handoff plan now exposes
an explicit chunked framing choice with a distinct journal-bound request
digest, while preserving the original fixed-length identity. This is a
protocol hypothesis, not an established explanation for the physical camera's
earlier readbacks. A new camera write must not be inferred from this source
change; prior uncertain effects still require reconciliation.
The setup owner accepts this explicit framing choice without automatic replay.
On `ovh-b`, four handoff-plan and twelve dispatch/setup Rust contracts passed,
including framing-bound authorization and a chunked loopback discovery-to-setup
exchange. These use synthetic peers and do not qualify a physical G4 handoff.
The isolated HTTPS handoff binary with SHA-256
`f603556cdd1694661514416312e026428dd54f92febd767acefe3a4e4d157986`
passed ten independent encrypted fixture cases on `hz3`, including one
chunked request. On the owner's G4 it first confirmed the prior controller
without a write. In a protected subsequent attempt with the existing repair
temporarily held, a single journaled chunked write returned an empty HTTP 200;
three readbacks were `Previous`, `Requested`, `Requested`. An independent
no-write check also reported the requested address. The result is consistent
with a delayed change but does not distinguish that write from earlier
unreconciled effects. The Rust listener accepted TCP, TLS and WebSocket, then
its startup conversation timed out without a clip. A bounded read-only
inspection checked the two journal objects' checksums, predecessor link and
event linkage, and found the time-sync operation committed; no hello,
agreement or stream operation was present. This inspection did not use an
independently retained root pin or perform full canonical recovery. A commit
does not prove the reply reached the camera, and the timeout was not
phase-tagged. The original repair setting was restored and a no-write
observation reported the original controller. The scheduled repair and
controller restoration checks were no-ops. The recovery service failed with
an indeterminate error; neither its reboot marker nor the trial reboot marker
was present. A separate recorder-journal classification returned unknown and
took 15.4 seconds, exceeding the watchdog's eight-second journal timeout; this
is a plausible explanation, not a proven cause. Fresh staging writes and
uploads were observed independently after the original controller returned.
A subsequent isolated trial-source change adds payload-free phase reports for
both the conversation deadline and the overall startup deadline. On `ovh-b`,
the lab and its test executable compiled, and two encrypted synthetic
post-time-sync deadline cases passed, one for each deadline scenario. An
initial fixture run failed because the disposable test certificate was marked
as a CA; both cases passed after replacing it with a server certificate. The
resulting trial executable has SHA-256
`04c61d2abca1415ad69951b4a8b1ff6795d91ec3a0c69ac0ba79830b93e0e4cd`.
The matching executable was staged in the private trial directory on `ts1`,
where its hash and dynamic dependencies were checked and its argument parser
started. This diagnostic build has not been used against the camera; the
fixtures do not establish the cause of the physical trial's timeout.
Later laboratory source additionally records whether the management dispatch
authority gate allowed an attempt. A passed gate alone does not establish that
bytes were sent or received. The revised lab compiled on `ovh-b`, and the
same two encrypted deadline fixtures passed with assertions for that gate.
The revised executable's SHA-256 is
`e57156b6cd2831586d73dfb5b2394f952e269b10d24fcc0b07ff2b6ac2a54ca8`;
it was also staged on `ts1`, with its hash, runtime dependencies and argument
parser checked. Neither revised fixture exercised the physical camera.
A separate disposable TLS/WebSocket peer on `ts1` exercised that same staged
executable with an uncorrelated camera time-sync request before hello, both
coalesced with the upgrade and sent sequentially after it. Both synthetic
cases received correlated time-sync and hello replies, observed parameter
agreement and reached a stream request. The peer then stopped the laboratory
process; it did not send video or prove a clip. This rules out message order
alone as a sufficient reproduction of the earlier physical timeout, not other
differences in firmware, timing, delivery or connection state.
An independently repeated run of the
[`prehello_fixture.py`](../experiments/unifi_tls_05_server_lab/prehello_fixture.py)
peer on `ts1` again reached a stream request in both cases and verified the
time-sync reply envelope and wall-clock fields. Its observed time-to-sync-reply
was 94 ms coalesced and 67 ms sequential, measured from the upgrade request;
hello replies arrived at 217 ms and 133 ms respectively.
These are synthetic single-run timings and do not establish the physical
trial's journal latency or response delivery.
The encrypted Rust process fixture was then expanded to cover an uncorrelated
time-sync request immediately before hello, alongside its earlier correlated
time-sync control. On `ovh-b`, both process cases passed: each completed the
controller exchange, received synthetic media, created a private MP4 and
decoded frames from it. The test executable SHA-256 was
`651b18c44d85c1804a1f69208847723f88f8e948538de7d004efa8a42d9b4228`,
and the corresponding trial binary SHA-256 was
`abb4d4f7bfc6ac46ad6ac291093f998d3fecc21b4593f5ebd0196c812f0625e6`.
This is synthetic end-to-end evidence, not a physical-camera video result.
The controller source now also counts uncorrelated time-sync messages,
correlated messages, and correlated messages that explicitly request a
response. These are payload-free, untrusted observations; the conservative
policy still does not answer correlated messages. The isolated trial source
includes the counts in deadline and early-EOF reports. This diagnostic change
and its controller-contract test target passed strict-remote `cargo check` on
`ts1`. A later strict-remote test job completed on `ovh-b` with exit code zero,
a terminal acknowledgment, and source resources released. The retained test
executables were then run directly to recover their detailed output: all 14
controller tests and all 5 receive tests passed. These tests cover the counts
without changing the correlated-message response policy. Earlier targeted
attempts were refused before Cargo started because disk reservations could not
be satisfied. A later strict-remote build of the updated laboratory trial on
`vmi1153651` completed with acknowledgment and source release. Four synthetic
process tests then passed: two deadline cases checked the payload-free
correlation counters, and two cases produced decodable synthetic clips. The
test executable SHA-256 was
`7b3eedccd880c8feac2c3e3143b7d3f1269ba8b304c730e526acb9906a8179c8`;
the trial binary SHA-256 was
`cc00b29d160c96cc1cee25605b873ac2a707e3523c957c72977144db50050e88`.
The trial binary was subsequently staged on `ts1`; its hash matched, dynamic
dependencies resolved, and its argument parser returned the expected usage
error for `--help`. An independent disposable TLS/WebSocket peer on `ts1` then
passed both coalesced and sequential time-sync-before-hello cases, reaching a
stream request in each. The fixture sent no video. The trial has not been
exercised against the G4; these synthetic tests do not establish physical-camera
video.

A separate `discovery_observe_trial` laboratory binary connects a bounded UDP
discovery result, an owner-selected address and MAC claim, a pinned TLS
connection, and `setup::Owner::observe`. Its only setup operation is read-only;
management authority and approvals are denied. A strict-remote build on `ovh-a`
completed with a terminal acknowledgment and released sources. Four independent
disposable UDP/TLS fixture cases passed: normal observation, changed settings,
a mismatched claim, and a rejected pin. The built binary SHA-256 was
`809890bf2486c341ac55be5d55e1cb683bb2f56d6c62e2496ecf4936b47e2d09`.

The same binary was run read-only on `trj` against the physical G4 on 2026-11-05.
A scoped unicast discovery query selected the expected address and neighbor MAC
claim; the pinned TLS session, local login, status and two matching settings
reads completed with a task receipt. The reported controller matched the existing
recorder, and no management effect was attempted. Immediately afterward the
recorder, upload, bulk fallback, and discovery timers remained active, the
recorder restart count remained 53, and the most recent upload had succeeded.
A later staging inspection found a recently closed 60.024-second H.264
segment at 1280x720 that `ffprobe` could read, along with an actively written
segment and an older incomplete segment that lacked an MP4 index. The incomplete
file was preserved; it cannot establish continuous coverage. A later read-only
USB archive check found the volume mounted, 1,328 segment files, a newest file
about five seconds old, and approximately 1.11 TB free. Ten recent segment
sizes imply about 390 GB per 30 days if the one-minute cadence and observed rate
remain stable; other disk use and bitrate changes affect actual capacity.
A separate limited-broadcast discovery window shortly beforehand returned no
datagrams, and a subsequent directed-broadcast trial did not select the camera.
These bounded observations do not prove camera absence or explain the difference.
The certificate
and discovery claims were observed on the same network and do not independently
authenticate the camera. This observation does not establish native streaming,
automatic adoption, or gap-free recording.

The discovery CLI source now accepts up to 64 distinct, subnet-checked
`--target` IPv4 addresses in one window; without them the existing broadcast
behavior is unchanged. This is intended to rediscover an owner-authorized camera
inventory when broadcast replies are absent. Three CLI unit tests passed on
`ovh-a`, including scoped targets and duplicate rejection; the job acknowledged
completion and released its source. The test executable SHA-256 was
`7229757b3b189495b83bd42a212f9cef009ad1fc1c974e11fc2ea0a44df57a66`.
A later strict-remote executable build on `vmi1149989` completed with terminal
acknowledgment and released sources. Its SHA-256 was
`83a9baf9b9618eb92c56b1a3f8b2aba5dfd4e1bf0cb2f48c90e7360a25fb518b`.
Four independent UDP fixture cases passed against that executable, including
two simulated cameras in one window. The identical binary was staged on `trj`
and a bounded read-only unicast run observed the physical G4 as an unverified
claim.

A root-owned authorization record scopes the existing limited broadcast plus
the exact previously authorized G4 unicast target. A versioned wrapper verifies
the record's pinned digest and invokes the tested binary without login or
camera configuration. It passed as the service user before a reversible systemd
drop-in selected it for the existing five-minute discovery service; the old
binary, wrapper and timer remain in place. A manually triggered service run
succeeded and observed the G4, while the recorder, upload, fallback and discovery
timers remained active and the recorder restart count stayed at 53. The timer
subsequently fired on its own at 22:52:36 EST on 2026-11-05; its exact service
invocation succeeded and reported the G4 as an unverified claim. Unknown-address
devices that do not answer broadcast remain undiscovered, and discovery does
not automatically configure or adopt any camera.

The discovery library has a bounded multi-target configuration for up to 64
distinct destinations on the same port, including broadcasts and owner-scoped
unicast destinations. Each query is separately budgeted; a send sequence
interrupted after an earlier query is reported as indeterminate. One report
evaluates conflicting claims across all replies. A strict-remote contract run on
`vmi1264463` passed 8 tests, with one separately authorized live-network test
ignored. The executed cases included two simulated UDP peers, conflicting claims,
and budget exhaustion after one query. The job acknowledged completion and
released its source; the test executable SHA-256 was
`9dd99bcce3391effa74474785081f3f437ee8f2c641f119ecea59939624f878e`.
No automatic camera inventory or setup supervisor consumes the new API.

The external recording volume later disappeared from the Mac's mounted
volumes and several uploads were deferred, with the staging files preserved.
The enclosure was visible over USB but a read-only `diskutil` inventory did
not finish. The volume subsequently remounted without a change by this trial,
and the original uploader reported copying 14 staged segments. A transitional
local fallback on `trj` is now enabled at
`/bulk/unifi_camera_recordings/g4-instant-fallback`; it copies closed staged
files, verifies each new copy by hash, and does not delete the staging source.
The fallback directory is root-owned and private, so reading it requires
appropriate privileged access. Existing published copies are checked by file
metadata on subsequent passes, not rehashed on every pass.
Its private, create-only archive removes matching regular archive files after
30 days and does not follow symlinks. Nine synthetic filesystem tests and a
separate synthetic real-media/open-file probe passed on the revised version,
including an expired staging backlog followed by a recent segment and reporting
of unavailable probes or publication failures. A manual pass of the earlier
version copied ten real segments, and an independent hash and media probe
confirmed one against its still-present staging source. The enabled timer also
completed a scheduled pass on the revised version after the original uploader
resumed; an earlier scheduled pass had no eligible copies. Neither path proves
gap-free recording or an actual 30-day deletion. If the external drive
stays absent, staging originals accumulate because the fallback does not
delete them; free space must be monitored.

The failed recovery helper has a revised version installed separately for
future guarded trials. Its journal read allows 30 seconds, and a timeout or
journal error becomes `unknown`, which abstains from reboot. Six synthetic
tests passed locally and on `trj`. An independent read on `trj` returned
`unknown` after 9.7 seconds, and the new wrapper's prior-marker and invalid-time
checks abstained without touching the camera. A subsequent read-only check of
the helper against the current recorder journal also returned `unknown`; this
alone does not identify why. A separate read-only 24-hour lookback classified
the last relevant recorder event as `recording` in 6.6 seconds. That extended
lookback is outside the helper's one-hour recovery authorization window and
does not establish safe automatic recovery. The failed earlier timer remains a
failure, and the revised helper is not evidence of automatic recovery.

The transitional recorder separately showed several stream exits at roughly
four-minute intervals and another after about 100 seconds, followed by
approximately eleven-second restarts. A
header-only loopback observation saw its local RTSP server send FIN and then
RST immediately before the recorder exited. This identifies the TCP close
direction, not the cause of the server's shutdown or the exact amount of lost
coverage. A later service inspection found `RestartUSec=10s`, accounting for
part of the restart delay without identifying the stream-exit cause. The
service resumed writing and subsequently uploaded a verified
segment. Continuous recording without gaps is not established; do not use a
successful upload or an active service as evidence of continuity.
A second bounded header-only trace observed another restart: the local RTSP
server initiated its close and, within a millisecond, the controller host
also initiated closure of the camera's video-push connection. No camera FIN
or RST preceded those events in that capture, which reported zero kernel
drops. A subsequent bounded header-only observation found camera TCP payload
arriving one millisecond before another local server close, including 12,881
bytes in the preceding second, with zero reported kernel drops. This rules out
complete TCP silence immediately before that close; it does not prove the data
contained decodable video or distinguish local parser, pacing, backpressure,
watchdog or other causes. The temporary traces did not record packet payloads.
With the existing plugin's diagnostic logging temporarily enabled under an
independent restore timer, its own bounded diagnostic reported an output
deadline 7,766 ms late immediately before one restart. The original logging
setting was restored and the private temporary logs removed. This establishes
the plugin's stated trigger, not whether the underlying cause was event-loop
delay, camera timestamps, media parsing, or something else.
A separate 20-second passive sample contained 569 structurally identified
video-tag candidates in one contiguous TCP run. Their first-to-last camera
timestamp span was 18,934 ms and the corresponding TCP prefix-completion span
was 18,937 ms; adjacent candidate timestamps advanced by 33–34 ms. This healthy
window does not cover the failure and uses heuristic tag boundaries, so it
does not prove decoded frames or rule out an intermittent clock jump or host
stall. The capture was processed in memory and only aggregate timing was kept.
A longer observation ending at a server close reported an apparent 7,392 ms
arrival-versus-camera timestamp difference, but its observer reset reassembly
on 26 TCP sequence gaps. The figure is therefore inconclusive: those gaps may
represent reordering, retransmission or incomplete capture rather than camera
clock behavior. Zero kernel capture drops does not resolve that ambiguity.
After adding bounded out-of-order TCP reassembly and synthetic reordering,
duplicate and wraparound checks, a subsequent server-close observation found
no captured camera TCP payload for 8,725 ms before the close. In the preceding
sample, 900 heuristic video-tag candidates covered 29,967 ms of camera time
and 29,916 ms of prefix-completion time; 59 out-of-order segments were
reassembled, one duplicate was discarded, and no gaps or kernel drops remained
at close. This single observation points to an upstream or network interruption
for that event; it neither proves where packets stopped nor explains the earlier
close that had camera payload immediately beforehand. No decoded-picture or
continuous-coverage claim follows from the tag candidates.
After another recorder exit, the camera's HTTPS connection timed out and the
recorder host's neighbor entry reported failure. One of two immediate ICMP
probes then returned, and subsequent ten-probe windows from each of two hosts
received all responses. A later 40-probe window from each host also received
all responses. The recorder reported the camera offline once and
then started again. A later camera status response reported Wi-Fi channel 36,
frequency 5,180 MHz, signal −58 dBm and noise −89 dBm. These are untrusted
point-in-time camera claims; they establish neither stability nor the cause
of the interruption. The observed reachability symptom does not by itself
distinguish Wi-Fi, power, camera or network-device causes.
Another protected trial temporarily stopped the dedicated single-camera
controller to examine that interaction. The native listener received no
camera connection within its window, and the handoff readback did not confirm
the requested address. After the controller restarted, the camera required a
reboot to reconnect, causing a recording gap. A fresh segment was subsequently
verified and uploaded by the existing recorder. This isolated attempt does not
establish the cause of the native failure or automatic setup.
Automatic handoff, peer identity, TLS-provider qualification and native live
recording remain open. See the [trial notes](../experiments/unifi_tls_05_server_lab/README.md).

### Controller TCP listener

`unifi_direct::controller_listener` binds an explicitly scoped IPv4 address,
checks the task network grant and current listener and peer policies, and
returns a task-metered socket. Its policy guard rechecks every raw socket poll
and fences the connection on an observed revocation. The one-shot `accept`
consumes the listener; `accept_next` retains it for sequential attempts under
caller-owned time and retry bounds.
A source address is not camera identity. The accepted socket also returns a
shared admission gate: callers wrap the TLS plaintext stream with that gate and
use `owner::accept_guarded` to bind it to the controller session before any
observation. The guarded session checks it before and after receiving each
message and before preparing or dispatching management effects. The caller is
responsible for associating the gate with the exact same connection; older
unguarded APIs remain available and do not provide these checks. The supervisor
also checks a bound controller gate before each joint poll, so a revoked
controller cannot release a buffered media record on a subsequent
poll. This is not independent revalidation of the media peer's policy after
accept, and an idle revoked session is not guaranteed an immediate wakeup.
TLS, physical camera identity, durable supervision and live-camera
interoperability remain separate work. The task-owned loopback suite passed
4/4 on `hz4`, including denied peers, revoked admission while waiting, fencing
after a connected peer is revoked and later reallowed, and retention of the
received media prefix when a revoked controller stops the supervisor.
The experimental encrypted controller-to-archive fixture also passed both
cases on `hz4` with this listener; its camera and media were synthetic.

### Joint controller and media supervision (loopback only)

`unifi_direct::supervisor` owns an already-admitted controller session and its
media pipeline together. It fairly polls both with a finite wait, returns media
results and any unaccepted original records to its caller, and retains the
original controller retirement facts if the peer closes. Post-start camera
time-sync requests require a distinct caller-provided operation identity and a
journaled, reauthorized management write. A written response proves only local
transport acceptance. Cancelled receives rely on the owners' documented
cancel-safe contracts; no task is detached.

The task-owned loopback test pauses a synthetic stream until a second time-sync
response is received, then reconstructs the input and decodes six frames. An
isolated TLS 1.3 loopback also exercised this supervisor with a fragmented,
encrypted management connection, then published two synthetic segments,
reopened the archive and decoded six frames. Both its normal and revoked-policy
cases passed on `hz4` (2/2); its initial CA-certificate handshake failed before
a corrected leaf-certificate rerun. A later 3/3 encrypted fixture used the
shared raw/plaintext/session gate. It proved an unguarded TLS layer could return
an already-buffered byte after raw policy revocation and the guarded layer
refused it. A task-owned fixture separately supplied a hello already buffered
by the WebSocket upgrade and verified that the guarded session retired before
interpreting it. The TLS provider is the same at both ends,
and media uses a separate plaintext loopback. This does not demonstrate
live-camera operation. Persistent publication, automatic
reconnection, a production nonblocking journal, camera identity and qualified
TLS are still needed before this can replace the existing recorder. A single
step may spend up to the configured wait polling and another configured wait on
a time-sync write.

`unifi_direct::setup` now drives one completed, nonconflicting discovery
candidate through an independently admitted camera session, login, status,
settings, a journaled controller change and readback under one task and total
deadline. It rechecks the candidate policy at each stage and during writes;
the camera HTTP owner separately enforces its transport and operation policy.
An already reported target address returns an untrusted observation without
preparing an effect. After commit, a partial write, timeout or failed readback
returns the permit for reconciliation rather than retrying; a reported target
address does not settle the effect or prove adoption. The caller still supplies
independent peer identity, TLS, credentials, live lease and controller service.
Journal operations are synchronous, and this is not a production supervisor.

On `hz4`, 18 synthetic tests passed across discovery, handoff planning and
handoff dispatch; one live-discovery test was ignored. The setup fixture used
actual UDP discovery and a loopback camera, covering denied admission,
incomplete discovery, already-associated idempotence, successful journaled
readback and a reply timeout with the obligation still committed. No setup or
controller change was sent to the physical G4 in this test.

An independently invoked v2 CLI executable on `trj` also emitted parseable v2
JSON for one G4 candidate, with no claim flags and an unverified identity.
The stripped executable SHA-256 was
`2970705d1ca035da541bbf2b7627c13396da15725b9fa3b8cc9f7234f325c19c`.
The previous installed binary was backed up as
`/usr/local/bin/fss-unifi-discover.backup-923f27fa6714509a`; an automatic
command guard blocked that earlier replacement attempt. A later verified build
was tested and installed as described below.
Discovery now advances its task-clock observation at each send/receive
admission and rechecks authority before accepting a received claim; a packet
consumed at or after the window boundary is counted but not admitted. The
caller must co-observe the initial canonical time and runtime timer, and supply
a completion time in the same domain. A stale-clock regression test failed
against the previous implementation and passed after this change. Six UDP
contract tests and two CLI tests passed on `hz3`; the separately invoked G4
discovery test passed on `trj`, returning one unverified candidate and no
claim flags, with recorder and timers still active. That test executable's
SHA-256 was
`fad70d95b311133a673d547a912f96be3d4b9b8da084888589b3ca02068e75e0`.
An earlier clock-aware CLI build also produced a v2 report for this G4 on
`trj`; its binary SHA-256 was
`c9819e34b1c59598e0f3853029b8a88d9d3040a9fafebf852fb548ccf4f73650`.
That CLI build predates the final setup-window and cancellation checks.
These results do not establish authenticated setup or direct camera streaming.
The experimental `fss-unifi-discover` command exposes this primitive as one
three-second broadcast on an explicitly specified IPv4 interface and prefix.
It requires `--owner-authorized`, an operator principal and an existing
authorization digest; the digest identifies the operator-supplied authorization,
but the command does not independently verify its provenance. Output labels
each candidate as unverified and setup as unavailable. It never enrolls the
device or proves that absent candidates do not exist. It is a standalone lab
projection, not the general discovery command or an automatic setup service.
On 2026-11-05, the command ran on the owner's `trj` LAN interface and returned
one `UVC G4 Instant` candidate from one datagram, with no malformed or
out-of-scope replies and `WindowElapsed`. The camera remained attached to the
existing recorder, which was active after the test. This confirms the command's
live discovery path for this device and network, not identity, authenticated
control, onboarding, stream continuity, or other camera compatibility.
The owner has a separate host-specific systemd timer on `trj`, enabled on
2026-11-05, which runs this command every five minutes on `eno1` only while
that interface has one address in the authorized `192.168.4.0/22` network.
The service logs unverified observations in the system journal. An initial
interface-lookup failure caused by a missing `AF_NETLINK` allowance was fixed;
the subsequent service run found the G4 and exited zero, and the timer was
active with a next run scheduled. This is periodic discovery only; no candidate
is authenticated or configured automatically. The installed host artifacts are
`/usr/local/bin/fss-unifi-discover`, `/usr/local/libexec/fss-unifi-discovery`,
the `fss-unifi-discovery.service` and `.timer` units, and the scope statement at
`/var/lib/fss-unifi-discovery/authorization.txt`. On 2026-11-05 the installed
binary was atomically updated to the newer v2 build after a scoped live test.
The previous binary's SHA-256 was
`923f27fa6714509a6409a78326bfc02de7589240d0531afbb42dcaaf95cf9b54` and it
remains at `/usr/local/bin/fss-unifi-discover.before-v2-923f27fa6714509a`.
The installed stripped binary's SHA-256 is
`3c8ffb6922c2b60d050cf2fdc8eb04ca7d21cc5b673dbdb5387c0bc00aafbd28`.
A subsequent systemd service run exited zero and reported one G4 candidate,
no claim conflicts and `WindowElapsed`; its identity and setup remain
unverified. The recorder and both timers remained active. The Linux build's
remote compiler completed successfully, but the Mac-side artifact retrieval
was refused as incompatible; supported recovery acknowledged exit 102 and
released the worker source, after which the exact stripped Linux executable
was transferred and hash-verified on `trj`. A changed interface name or
network scope requires explicit reconfiguration; a silent report is not proof
that no cameras exist. The temporary source copies are under this task's
`work/unifi-discovery/` directory and are not a general installer.

## Scoped verification and handoff

At base `ec4b6a4c7073321cbd30162783adbbd101c0c0f6`, the three packet source
and test files were tested as a clean overlay on the remote Linux worker
`vmi1156319`: `cargo test -j 1 --locked --offline -p fss-packet --test
extended_flv_contract` passed all six synthetic tests. The clean-overlay
fingerprint was `5e63bbcc1426a47f99a7375ce64fd63ae4c2e530a2202ce0a471dc44ca4e838c`.
A subsequent clean-overlay run on the same worker passed
`cargo test -j 1 --locked --offline -p fss-packet --tests`, including the
extended-FLV and AVC synthetic contract suites and the existing packet tests.
Its source overlay fingerprint was
`a27c18c4eb967dda7814808ea6782fca21fc733a26160cf82aeb311b3eebe01e`.
After that run, the AVC suite gained a test wrapping the repository's generated
H.264 laboratory fixture in FLV tags. It passed all eight targeted tests on the
same worker at overlay fingerprint
`62db80e33c83f2b37ec5a7e5a26d97637d89fd38580660bb4cc24ab16ed26512`.
The test passes original SPS/PPS and one IDR NAL from FLV spans to the existing
bounded H.264 syntax parser; it does not decode the picture or establish
retained evidence.
The direct-controller reference and its seven synthetic contract tests passed
`cargo test -j 1 --locked --offline -p fss-reference --test
unifi_direct_controller_contract` on the same worker using clean overlay
`e31e756f825eb3c5ac4a25a2c9e2f4d742cd2afc6fc878480602154f1340adad`.
That test covers pure negotiation state and local write outcomes, not WebSocket
transport, TLS, camera interoperability, or remote effects.
After the one-track stream-start reference was added, the same command passed
all 11 synthetic controller tests on the same worker using clean overlay
`906b297aca8b8943ebb3efbb8db44455d37e1d5636659fe98bbf27755c423927`.
The extra tests cover serialized fields, selected-track scope, reply correlation,
input refusal, and written/unwritten/uncertain retirement. They do not send a
camera command or establish camera codec or settings compatibility.
At base `c09e0261f435b1bdcddbe5ce1f4c102a43c77098`, the bounded TCP reader and
async task boundary passed five native Linux contract tests plus all 17 existing
synchronous owned-execution tests on `vmi1156319` with clean overlay
`b6bcc47c497b9810b98a5f01cabe8b51a03a763838d5e3b2994d6df4b5170d5d`.
The TCP tests used real loopback sockets and covered a parked read being dropped
and retried, task-binding refusal, missing media authority, source retirement,
and exact byte transfer. They do not establish camera interoperability, live
recording, native async cancellation wakeup, or durable source custody.
The incremental framer passed four stream contracts plus six existing FLV and
eight AVC contracts at base `d229d849a7cfffa422f374d29c10b2423aa57440` and
overlay `854b05cf67a235cecf5d978c4e0f3ff47a91f096edbbba9709cbf8583be3ec29`.
The integrated TCP-to-FLV tests passed two synthetic cases at base
`07e56dd391c33dbb9b9f6b38d4fcb5c1aaa24187` and overlay
`eb2cdd3060d2ec3790992d4dddea18e3e2de25e1abe541a1e83f7702fd1b91ae`; their
separately invoked owner-camera replay test passed on `trj` as described above.
The native discovery target passed two synthetic tests at base
`e569638aa3f490d87b95c06d7cfbf7534442b848` and overlay
`425726a1619d754fe99d85ddbddce13fa74c11386e4373e54cdb28c5043031c2`, followed
by the separately invoked one-test real-device run on `trj` described above.
The discovery CLI's two argument and JSON-escaping unit tests passed on
`vmi1156319` using base `51bf09a2844a8ad82f03feac6fdb10eb35e1bc96` and
overlay `11684f16769ba8cbd79bb191db76138adc6766cfdbc31a2385400b20e707e551`.
For the live CLI run, `cargo build` on that same source completed successfully
on `vmi1156319`, but RCH returned 102 because it rejected delivering the Linux
executable as a macOS artifact. A separately stripped copy was transferred via
a temporary file to `trj`, and the SHA-256 of that copy matched on both hosts:
`923f27fa6714509a6409a78326bfc02de7589240d0531afbb42dcaaf95cf9b54`.
The command exited zero on the owner LAN. This manual transfer is live-test
evidence, not a successful RCH artifact-delivery or release qualification.
This is not a full workspace, release, live-camera, media-decode, or
retention qualification. A separate test attempt on `ts1` timed out before
execution. The semantic-plane checker with doctests skipped reports 690 errors
both on the clean base and on this checkout, with identical findings; the new
module is registered as support and added no finding to that comparison.
Unmodified `fss-packet/src/onvif_metadata/receiver.rs` also has six
`clippy::result_large_err` failures under the requested `-D warnings` run;
the strict Clippy invocation did not pass and this lane makes no wider lint
claim. A second targeted Clippy run passed on `vmi1156319` with
`-D warnings -A clippy::result_large_err`; this exception is scoped to the
diagnostic run and is not a change to the release gate.
After adding the AVC reference, the same scoped Clippy command passed for both
extended-FLV test targets with overlay fingerprint
`637b015a5b31120ba24347ff3358afe994f12054e120b7741c425ef8590887da`;
the later multi-parameter-set test is covered by the full packet test run above.
The latest AVC test target, including the encoded-fixture handoff, also passed
the same scoped Clippy command at overlay fingerprint
`62db80e33c83f2b37ec5a7e5a26d97637d89fd38580660bb4cc24ab16ed26512`.

On the owned G4, a separate standalone laboratory executable compiled the
actual `unifi_direct/metered.rs` source with FSS task and scoped network
authority and completed credential-free TLS handshakes over Asupersync. For
both TLS 1.2 and 1.3, the observed certificate and corresponding key succeeded,
while a mismatched certificate and a different valid public key were rejected:
six of six cases produced completed task receipts. The network meter wrapped
the raw TCP stream, including TLS records; IP and link overhead were outside
its accounting. The exact binary SHA-256 was
`2fdcd55e40d53205342c00ee8835e526d3a924a8d9e936fd0eda7ad4af23a465`, built on
`hz2` with base `955562d03290395612e2bd59eaa8066de79ddd72`, overlay
`7e4777775adc83b1c5dc6875a0faa66629886feb68a6b9fa53812a493a21aabf`, and
transferred to `trj` with matching digest. The currently running recorder,
upload timer, firewall, and discovery timer remained active afterward. This
used a same-network observed certificate without independent identity proof,
an unqualified experimental crypto provider, and no application data. It is
not a production TLS trust decision, live controller session, or recording
qualification. See `experiments/unifi_tls_owned_lab/README.md`.

An independent TLS 1.3 client-side probe using the released `rustls-pure`
0.15.4 provider also completed a credential-free handshake with the G4. Its
changed-certificate and different-key negative controls were rejected; all
three cases returned completed task receipts. The pin came from the same
network and was not independently authenticated. The provider has no outside
security audit and draws randomness outside the required FSS authority boundary;
the camera-to-controller server role has not been tested. A synthetic server
and same-provider client exchanged fixture bytes over metered Asupersync TCP;
this is not independent interoperability. This is not provider admission or a
live controller session. The reproducible lab and exact binary
identity are in `experiments/unifi_tls_pure_lab/README.md`.

Current continuation: qualify the TLS and identity boundary, connect the
management owner to an authorized live session with registered remote effects
and durable reconciliation, and obtain sanitized protocol fixtures without
disrupting the recorder. Complete independently replayable FLV archive
retrieval and source receive-time provenance, then connect these pieces into
a supervised native camera owner.
The active camera, the current transitional recorder, source capture authority,
TLS admission, controller cutover, and eventual deletion/retention proof are
independent open boundaries. The operating recorder must not be stopped merely
to test this parser.

## Next work and qualification

1. Exercise the reference against synthetic and sanitized owned-device traces;
   retain ambiguity and divergence instead of silently choosing convenient
   boundaries. Test maximum tag/trailer bounds and allocation/work budgets.
2. Implement region-owned, explicitly scoped TLS/WebSocket controller and
   camera push ingress after qualifying the exact TLS provider closure. Treat
   management commands as effects and preserve uncertain outcomes.
3. Bind immutable original byte spans and receive-time intervals to parsed
   configuration and compressed access units; build an FLV-source-specific
   recording path. The existing `AvcMuxer` takes `AvcPictureGroup` and emits
   `NalSourceSpan` mappings defined for RTP, so the current public API cannot
   honestly accept FLV source spans unchanged. The FLV-specific mux reference
   now exists; connect and independently qualify its source and archive owners
   while preserving the existing RTP contract and durable formats. RTP packet
   custody cannot be asserted for FLV bytes.
4. Qualify the single-camera vertical slice against the real device with a
   reversible one-controller-at-a-time cutover, then cover gaps, reconnect,
   disk pressure, audio policy, retention, and soak before migration.

### Isolated newer Asupersync acceptor

The standalone `experiments/unifi_tls_acceptor_lab` built Asupersync 0.6.2
with `tls-core` and an explicitly supplied rustls-pure provider, then completed
one disposable, same-provider TLS 1.3 loopback exchange on `trj`. The Linux
normal dependency tree included `getrandom` and did not include `ring` or
`aws-lc-rs`. The experiment used Asupersync's context-aware accept/read/write/
flush, not FSS task authority or metering, and did not connect to the camera.
It establishes a candidate integration path only; the FSS runtime still pins
0.5, and provider review, explicit entropy authority, identity admission, and
native supervised control remain open. The test binary SHA-256 was
`ec200efd45e713868d9bf207194689ce39dcdee3ddc3750b5056d3ac9fc2f3f2`.

An independent OpenSSL 3.5.5 client subsequently completed one disposable
TLS 1.3 loopback exchange with the Asupersync/rustls-pure acceptor, verifying
its fixture certificate and hostname. The client rejected a different CA.
Including the same-provider fixture, three tests passed on `trj`; the binary
SHA-256 was `1f072da45997bf9ee0f0cba4182bcad65309935f3c3af2942d1eff096ecf1c85`.
This does not establish client authentication, actual camera interoperability,
FSS task ownership, or provider admission.

A native-loopback cancellation test also observed a handshake actually park
before requesting context cancellation; it returned `Interrupted` and the
silent peer observed its socket close. The complete four-case fixture run
passed on `trj` (binary SHA-256
`76232b155b8cde120fcc3e921ccbed20ff3e0f1088ece8a488fa434177c1550a`).
This does not establish cancellation across the entire eventual camera owner.
After formatting the experiment source, all four fixture cases passed again;
the resulting binary SHA-256 was
`d0fd9ed46c0e9e253bd26a17ab65be163b27aa9573e60aa655a1eb6914304b33`.

An isolated copy of the dirty source tree was upgraded from Asupersync 0.5.0
to 0.6.2 (and matching Franken dependencies), without enabling TLS or changing
the main workspace. On `hz3`, five `fss-runtime` owned-execution/TCP tests and
19 UniFi reference tests passed; three real-camera ingress tests were ignored.
The UniFi suite covers synthetic ingress, recording, management receive,
effect dispatch and upgrade, not the live camera or whole workspace. Its
source-snapshot SHA-256 was
`37416451e43887af097168eee97689a90c9620791f3fe349d35c8aa99e810713`;
this digest covers 4,516 copied tracked/untracked files, with the upgraded
lockfile and a test-copy source-filter correction, not build outputs. The
first copy omitted a tracked nested `coverage` source due to the RCH exclusion;
the retry included it, and the main workspace filter now excludes only the
root coverage-report directory. This experiment is not a runtime upgrade,
provider admission, or native camera qualification.

A combined disposable fixture then connected the owned task, two metering
layers, Asupersync 0.6 TLS, WebSocket upgrade and UniFi hello observation. An
initial independently anchored version failed intermittently: iteration 111
of a later run returned an authority/budget refusal after an earlier
construction refusal. The errors did not expose the underlying reason. Clock
mapping was a plausible cause; the main source now offers `MeteredClock`, a task-bound mapping shared
by nested meters; deterministic tests reproduce rejection of intentionally
misaligned independent clocks and verify that shared-clock nesting charges
both layers. With the shared clock, the combined fixture completed 250/250
consecutive runs on `trj` (test binary SHA-256
`aed252c4d81832204d5d429dc938c1edc87c56965905b4f08131514cce51be68`).
The client was synthetic and used the same provider, the identity was an
unauthenticated claim, and the provider's explicit entropy and admission
requirements remain open. The retained test and isolated-copy instructions are
in `experiments/unifi_tls_acceptor_lab/fss_owned_tls_session.rs` and its README.

The shared-clock source and its six metering tests also passed on the current
Asupersync 0.5.0 workspace on `hz3`, alongside four management-receive tests
and one journaled stream-effect test (11/11 total). The same six metering tests
passed in the isolated 0.6.2 copy. The metered source SHA-256 for these checks
was `2f96159004b3f539767bb90974293534de2f270bdbc426239c7b479882157d88`.

The task-owned `unifi_direct::owner::accept` composes bounded HTTP header
collection, explicit caller-provided peer-admission policy, response writing
and flush, and transfer into the existing WebSocket session. A single deadline
covers the exchange; invalid and denied requests produce no response, while a
partial or timed-out response retires the stream as indeterminate. Dropping a
pending upgrade also drops its owned stream. On the current Asupersync 0.5
workspace, two owner tests plus four upgrade and four receive tests passed
on `hz3` (10/10). These are synthetic and loopback cases, not peer
authentication, a live camera controller, automatic enrollment, or recording.

The same owner subsequently handled an encrypted disposable loopback in the
isolated Asupersync 0.6.2 workspace: a same-provider client sent the upgrade
and a pipelined UniFi hello, and the task-owned session observed that hello
(1/1 test on `trj`). The fixture callback accepted only a synthetic MAC claim;
it performed no device authentication or remote camera effect. Its binary
SHA-256 was `a7c65c4f0b649dbb6c95859db7a399553a7024bd17a2fa343211c55bcd91c9e6`,
and the retained fixture is
`experiments/unifi_tls_acceptor_lab/fss_owned_tls_upgrade_owner.rs`.

The registered `EFFECT-CAMERA-MANAGEMENT-001` and its capability-v4 grants
cover exact controller-association, agreement and clock messages separately
from stream-setting effects. `unifi_direct::management` binds each prepared
message digest to caller-supplied camera, peer admission, session generation,
prior association/clock claims and lease fence. The management sender checks a
journal-backed one-use permit and current policy; the former permitless sender
now always refuses. A local successful write is not an independently observed
camera outcome. Unknown prior state stays unknown. A fixture dropped a pending
write after one byte, fenced the session, and recovered the committed operation
from an actual file journal in reconciliation-only mode; it did not recreate a
permit.

`TaskCx` now provides controlled effect preparation and commit while its owned
task is running. A loopback fixture receives a camera-shaped hello first, then
derives the exact reply intent, prepares and commits it to an actual file
journal, and sends the reply with its one-use permit. The fixture finishes
indeterminate with the committed operation retained for reconciliation. Two
runtime tests also cover an approval refusal that returns the preparation and
refusal to claim or commit another task's preparation. These are synthetic
peers, not evidence of a physical camera session.

An isolated Asupersync 0.6.2 TLS experiment combined this sequence with a
disposable TLS 1.3 client on `trj` (1/1 passed). It used the same experimental
`rustls-pure` provider at both ends, and made the synchronous file-journal
calls inside the owned task. The compiled test binary SHA-256 was
`54c5015fb189507ef00bac23cf76f624f34f408c6226cd4e0df72e7e3402e011`;
the retained fixture is
`experiments/unifi_tls_acceptor_lab/fss_owned_tls_task_effect.rs`. This is
neither an independent TLS-provider assessment nor a physical-camera test.

The effect coordinator and file journal calls are synchronous: the loopback
fixture exercises them directly, but this is not a nonblocking durable journal
strategy suitable for a latency-sensitive async owner. Production still needs
supervised persistence and cancellation/recovery handling, authenticated
camera identity, live adoption and a safe controller cutover. The version bump
is source-only and has not been deployed; existing v1, v2 and v3 bases must
rebase before using v4 grants.

The management effect lane passed three synthetic tests on `hz3`: exact intent
bindings for hello, agreement and clock replies; policy denial, stale state,
and one-use dispatch with a file journal; and interruption followed by cold
recovery. Four receive tests passed, including both an in-memory and a TCP
loopback refusal of the legacy permitless path. The v4 compatibility lane
passed 44 agent-abstraction, seven capability-row, 23 contract-basis and three
probe-profile Rust tests; the capability registry checker passed 28 Python
tests. A separate runtime test refused a management-prepare/settings-commit
grant pair. These results do not establish device authentication, independent
camera readback, live controller operation or general camera compatibility.
