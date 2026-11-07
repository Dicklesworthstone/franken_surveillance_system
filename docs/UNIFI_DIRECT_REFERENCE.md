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

On 2026-11-06, the same camera HTTP owner was exercised in an experimental
three-snapshot sequence over one authenticated G4 connection. All three
640×360 JPEGs decoded in memory, and each adjacent pair had different JPEG
digests. An independent TLS fixture also tested a disconnect after the first
response. The recorder service remained active. See the
[snapshot lab](../experiments/unifi_https_snapshot_lab/README.md#repeated-direct-snapshots-2026-11-06)
for exact evidence and limitations. This is repeated still-image access, not
proof of capture timestamps, video continuity, native recording or discovery.

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
A subsequent disposable-loopback TLS fixture exercised the revised watchdog
against a synthetic camera with a real private certificate, credential file and
exclusive marker. Six cases passed on the Mac and on `trj`: rejection before
login for a wrong pin, abstention for a different controller or recovered
recorder, a marker before one reboot request, refusal with an existing marker,
and retention of the marker after a dropped reboot response. All three fixture
source files had identical SHA-256 digests on both hosts. The fixture controls
the recorder-state input; it does not exercise systemd scheduling, a real
journal query, device authentication, physical reboot, or recovery from the
prior indeterminate trial. No physical camera was contacted by this fixture.
On `trj`, a separate read-only run of the same revised watchdog source as root
queried the real recorder journal for the preceding hour and returned `unknown`
after 9.58 seconds. It did not connect to the camera. This exceeds the former
eight-second timeout and remains below the revised 30-second limit, but is a
single measurement and does not establish the earlier service failure's cause
or guarantee that future journal queries complete within the new limit. The
prior trial's recovery service still reports failed, with exit status 1.
A later read-only query using the revised watchdog's one-hour, 100-line
journal bounds completed successfully in 10.48 seconds and contained two
recording-start markers and no startup-failure markers among 16 lines. This
is a current healthy-window observation, not a test of the watchdog service,
an effect reconciliation, or proof that automatic recovery will work.
A further read-only check completed in 13.15 seconds with zero journal entries
in the preceding hour, so the actual classifier returned `unknown` as designed.
The recorder unit was active and had been running since 13:46 EST; the Mac and
recorder host clocks differed by about one second. An empty bounded journal
window is not evidence of a stopped recorder or of camera recovery, and this
later observation does not explain the earlier `unknown` result.
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

The current working tree also contains a draft opt-in time-sync policy for a
correlated message that explicitly requests a reply. It ignores messages tied
to one of its own previous time-sync replies and limits the session to eight
time-sync replies in total; the existing conservative default is unchanged. The working
relay answers correlated time-sync messages, but no physical G4 evidence yet
establishes whether this more selective policy resolves the native handshake.
On `ts1`, a strict-remote build of the revised trial completed with terminal
acknowledgment and source release; its executable SHA-256 was
`928698dba130589b5307698ea7c89ec1b75617f7c493da22655ac0dd71f92512`.
An independent loopback TLS/WebSocket peer passed four cases: coalesced and
sequential messages under both the default and explicit-correlated policies.
The opt-in cases also sent a message correlated to the controller's own reply
with `responseExpected: true`; no reply loop occurred and each conversation
reached a stream request. The fixture sent no video. The source snapshot used
the `bcab915a` baseline plus selected overlay files, and the controller,
trial, and fixture files matched the working files by SHA-256. The revised
unit-contract suite and physical G4 handoff remain unqualified; no camera
handoff was performed for this draft.
An additional independent loopback process fixture sent eight eligible
correlated requests and an echo of each reply, then a ninth eligible request.
The same executable sent eight replies, ignored the echoes, and stopped with
`TimeSyncLimit` on the ninth request. The retained
[`sync_quota_fixture.py`](../experiments/unifi_tls_05_server_lab/sync_quota_fixture.py)
had SHA-256 `2a3c1e3b1ad7bb8aeb7f33dbe4aff5a512dc40ea8bd00dcf655576bd67eacf2b`
both locally and on `ts1`. This remains synthetic protocol evidence.

A separate controller project reports a pre-hello clock exchange on a G5 PTZ
where successive messages correlate to the controller's previous reply; it
answers those messages until the camera sends hello. See the pinned
[controller implementation](https://github.com/rjmotion/cuckoo/blob/2e18666e9d9998b31d908e3a8f1d9ebb658c467f/controller.py).
That is a plausible explanation for the earlier G4 timeout, not evidence that
this G4 behaves the same way. The Rust source now has an experimental opt-in
pre-hello policy: after the first message it follows only the latest reply's
correlation, rejects repeated camera message IDs and stops after 32 replies.
Each reply still requires a distinct journaled operation, current admission
and the existing total deadline. The conservative default and its eight-operation
startup bound remain unchanged. The laboratory trial has a separate explicit
flag for the new policy. A scope-filtered build `30096834294711771` on
`vmi1264463` passed all 22 controller contract tests and all six task-effect
tests, with terminal acknowledgment and source release. The latter includes a
12-message correlated exchange over a loopback socket, with a distinct durable
operation for each reply, followed by hello, agreement and a stream request.
The peer is synthetic. This policy has not been exercised on the physical G4;
its numeric bound is a safety limit, not an assertion that 32 rounds are
sufficient for every device. An independent TLS process fixture is retained at
[`clock_chain_fixture.py`](../experiments/unifi_tls_05_server_lab/clock_chain_fixture.py);
it passed both a 12-reply handshake through the stream request and a 32-reply
quota stop on `vmi1149989` using disposable loopback certificates. The trial
binary SHA-256 was
`3e27f6df97042249e451b64915a2825a4266de93f3248720932a072da2dd64d9`.
The scoped laboratory's 24 corresponding source files matched the working tree;
the module entry point and dependencies were deliberately filtered. Cargo build
`30096834294711772` reported exit 0 and source release. After the daemon stopped,
same-ID recovery later acknowledged the exit and release; the daemon had
previously recorded exit 130. The fixture result is independent process
evidence, not a physical-camera test.

The opt-in pre-hello policy was subsequently extended to answer fresh
uncorrelated clock requests as well as the latest correlated chain. The same
32-reply quota, duplicate request-ID refusal, per-reply operation, admission
and deadline remain in force; the conservative default is unchanged. An
isolated source oracle evaluated the time-sync branch of the pinned reference
controller and observed replies to three successive uncorrelated requests.
This establishes a behavioral difference from the old Rust opt-in policy, not
that the G4 sends this pattern or that it explains the physical timeout. The
oracle did not contact the camera or the running recorder. In a scope-filtered
strict-remote state-machine build, job `30098575685845025` passed all 23
controller contracts, including the new uncorrelated quota and replay cases;
terminal result and source release were acknowledged.
The corresponding owned-conversation contract was expanded to exercise a
mixed sequence as well as the existing correlated sequence, but it has not yet
passed on this revision. Initial job `30098575685845027` failed to compile an
outdated isolated media dependency, which was refreshed; its next submission
timed out before admission. Alternate job `30098575685845038` was refused
before compilation by the worker's protected disk reservation. Both remote
jobs reported terminal status and released their sources. The expanded
independent TLS process fixture is also pending; neither attempt establishes
physical G4 interoperability.

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

A later read-only check on 2026-11-06 found the USB archive mounted with 1,528
segment files and a newest file about 42 seconds old. A follow-up SSH connection
to that host timed out before a separate decode check. On `trj`, an independent
FFmpeg check of a closed fallback file decoded one frame from a 60.000326-second
1280x720 H.264 segment without saving an extra media file. This verifies a
playable fallback sample from the existing recorder, not direct Rust recording,
continuous coverage, or 30 days of observed retention.

A separate eight-minute, passive observation on 2026-11-06 watched only the
authorized G4 media connection for a new TCP connection and its original FLV
header and codec configuration. No new connection was observed, so no replay
was attempted and this provides no same-connection configuration evidence. The
camera and recorder were not restarted or reconfigured to produce a connection.
That observer's test-binary digest had a transcription error that was corrected
afterward; its check would have run only after a complete connection start, so
the error did not affect the no-reconnect observation.
The pipeline replay test now labels its input and configuration as
caller-supplied rather than asserting their provenance; its existing compiled
laboratory binary predates that reporting-only correction.

A read-only RTSP `DESCRIBE` of the active recorder's relay session on
2026-11-06 returned two H.264 parameter sets. Both matched, byte for byte, the
parameter sets extracted independently from one recent closed fallback segment.
The stream address and parameter sets remained in memory. This is agreement
between two observations, not proof that the segment and live stream share a
configuration epoch or that the physical camera is authenticated.

In a subsequent read-only test, two `DESCRIBE` observations bracketing a
20-second passive G4 capture returned matching parameter sets from the active
relay. The laboratory synthesized an AVC configuration from those sets using a
four-byte NAL-length field, selected a structurally framed IDR from the capture,
and inserted a synthetic FLV header, configuration tag, and 16-byte trailer.
The previously documented Rust laboratory binary
`2e69f85a813f35208e3d55ec45dd8a27d6fccad42bab28862cf75e7806440d23`
then replayed that input over task-owned Asupersync loopback TCP, producing
three in-memory segments containing 450 samples and decoding nine frames at
1280x720. Parameter sets and video remained in memory. This is fresh real-G4
media, but the selected boundary and configuration are synthetic; matching
observations do not prove the capture's configuration epoch or device identity.
It does not establish a direct camera controller or sustained native recording.
The recorder and its upload, fallback, and discovery timers were active after
the test, with the recorder restart count unchanged at 53.

A separate concurrent comparison then collected complete H.264 video NAL units
from the active relay's interleaved RTP and from a 12-second passive G4 FLV
capture. All 327 distinct captured FLV video NAL digests matched NAL digests
among the 689 distinct relay units observed. Digest and media bytes stayed in
memory; only aggregate counts were retained. This is strong evidence the two
observations carried the same video, not an authenticated camera identity or
proof that either observation establishes a codec-configuration epoch.

A following test combined those checks in one capture: the RTP session's own
SDP supplied parameter sets, and all 329 distinct video NAL digests extracted
from the concurrent passive FLV capture matched among 652 distinct RTP NAL
digests. Selected source bytes from that capture were then replayed through the
same documented Rust laboratory binary, which produced one in-memory segment
with 150 samples and decoded three frames at 1280x720. The test synthesized a
four-byte-length AVC configuration, FLV header and trailer and selected an IDR
boundary. It did not save media and did not authenticate the camera or prove
configuration-epoch identity. It does not establish that the Rust controller can adopt the camera,
receive its own live connection, or record continuously without the relay.
The disposable comparators are retained outside this repository under
`/Users/jemanuel/Documents/Codex/2026-11-04/new-chat/work/`:
`g4-source-rtp-compare.py` SHA-256
`e46aa3b1b668382d36b8edeb15db70d5145b61b1efcba10cf42e44bd7bcee187`
and `g4-rtp-nal-probe.py` SHA-256
`950eb80e5b7baac2183127af251d600211a0800d00884b3689895001427ef920`.
They depend on the local recorder, its current container namespace and the
existing passive-capture helper; they are laboratory tooling, not an installer.
A later read-only check found the USB archive mounted with 1,573 segment files
and its newest file about 17 seconds old. The most recent upload and fallback
service results were successful. This shows recent file activity, not a proof
of gap-free coverage or 30-day retention.

The active relay's SDP advertised an MPEG-4 audio track at 16 kHz, one channel;
its two-byte AudioSpecificConfig reported AAC-LC object type 2, indexed rate 8,
channel configuration 1 and a 1024-sample frame flag. An independent eight-second
passive FLV inspection found 110 AAC raw tags, no configuration tag and no
type-10 tags. A later passive sample was replayed through the new Rust
`extended_flv::aac` parser: it accepted 105 raw AAC tags, checked their original
source ranges across 310 records and retained a 16-byte unparsed tail. The FLV
header and initial boundary were synthetic, and no AAC configuration appeared
in that capture. Audio was neither saved nor played, decoded, muxed, or
associated with an authenticated camera identity.

The parser currently supports bounded, two-byte indexed AAC-LC configurations;
explicit rates, configuration extensions and program-configured channel layouts
are refused rather than guessed. Five synthetic parser contracts passed on
`trj` in an isolated lab using hash-matched copies of the actual packet modules;
the matching test build was acknowledged and its sources released. Its test
binary SHA-256 was
`a4b8e006005c809febe9cdb90224d979ee7e7dedf244a8e6d32abea2c9efcde5`.
This is not a full workspace test, an AAC decoder, or a native A/V recorder.

The source-aware AAC track now carries connection-relative tag and body spans,
configuration epochs and provisional-boundary status; unsupported type-10
audio explicitly fences this AAC track. Ten synthetic parser and track tests
passed on `trj` in a hash-matched isolated packet-module lab; two separately
authorized live replay tests were ignored in that run. RCH build
`30096834294711634` finished with exit zero, terminal acknowledgment and source
release. The track test binary SHA-256 was
`4b75c2114f1d9efc3f004453d8d6809aa469b4f4c308f3f8dd3c39ce7a931841`.
An explicitly invoked subsequent replay of fresh passive G4 bytes passed using
that binary: all 110 observed audio samples remained unconfigured because the
capture contained no original AAC configuration. This correctly avoids
assigning an inferred epoch. The capture used a synthetic FLV header and
initial boundary; audio was not decoded, played or saved.
After a test-helper-only lint cleanup, a second isolated build using matching
current packet modules and tests again passed 10 synthetic cases with the two
live tests ignored. RCH build `30096834294711656` exited zero with terminal
acknowledgment and source release; this did not rerun the camera capture.

The source also adds an opt-in AAC observation slot to the native media
pipeline and supervisor. It stops further reads until each observation is
transferred, returns an undrained observation at retirement, and fences audio
interpretation separately from the video owner. These changes are not yet
qualified for production or deployed. A strict-remote isolated integration build
using the real packet, runtime, container, core and pipeline modules ran on `trj`
as build `30096834294711646`. It hit its external deadline during compilation and
exited 137 with terminal acknowledgment and source release; it produced no test
verdict. An earlier build
`30096834294711632` was cancelled after its test was found to use a gated
Asupersync test constructor; same-ID recovery confirmed exit 137, terminal
acknowledgment and source release. The corrected test uses the runtime-owned
context and canonical cancellation. Both attempts excluded the full workspace
and supervisor integration. Audio muxing, playback, retention and
sustained camera recording remain unimplemented.
The supervisor's admission-revocation scenario and an ignored combined A/V
camera replay were added afterward. Isolated build `30096834294711666` compiled
the supervisor but could not compile the test because that laboratory omitted
its existing H.264 fixture and crate. It exited 101 with terminal acknowledgment
and source release. The lab was amended with those source-matched dependencies;
replacement build `30096834294711680` passed its one selected admission-revocation
case. The entire five-test supervisor fixture subsequently passed in build
`30096834294711682`; both builds had terminal acknowledgment and source release.
Thirteen direct-UniFi modules, the test and its H.264 fixture matched the current
tree. In the same isolated laboratory, build `30096834294711683` passed four
synthetic A/V pipeline tests with the separately invoked camera test ignored;
terminal acknowledgment and source release were confirmed. The independent
`trj` build `30096834294711663` timed out before a test verdict. Its remote
process group was verified dead, and same-ID recovery acknowledged exit 137 and
released the sources; the daemon had earlier reported exit 130. These do not establish
full-workspace qualification. The supervisor
withholds pending observations when its owning task is cancelled or the bound
session's admission is revoked; the cancellation-specific supervisor boundary
has not yet been independently exercised.

A fresh 20-second passive G4 capture was subsequently replayed through that
laboratory's actual Asupersync TCP ingress, audio tracker and video recorder on
`trj`. It yielded three video-only fragments containing 450 video samples and
293 audio observations; no original AAC configuration appeared, so those
observations remained unconfigured. The complete ordered input was accounted
for in returned records, pending source and a 16-byte framing tail. The test
used a synthetic header, a relay-SDP-derived synthetic video configuration and
trailer, and a selected IDR start. Equal relay configurations bracketed the
capture but do not prove the source's identity or configuration epoch. It did
not decode or mux audio, prove sustained capture, or save or play media. The
copied stripped test executable's SHA-256 was
`6bee31a1de253dd0106426c19d03ccc3ed029977b1a7389f74988229975d02ae`;
the source executable built on `vmi1153651` had SHA-256
`4ca89bfeff8d9f4ec1735d19a13d5496f9f5324590a600dc0e18600ffadbe350`.
Only the executable was transferred from the build worker to `trj`; the camera
media remained in memory on the owner-controlled capture and recorder hosts.

The source also includes allocation-free ADTS header generation for an explicitly
supplied AAC-LC configuration and raw tag. It rejects short-frame configurations
and oversized frames. Three ADTS cases plus ten parser and track cases passed in
isolated build `30096834294711688`, with terminal acknowledgment and source
release; two live tests were ignored in that run. The ADTS contract also passed
isolated Clippy with `-D warnings` in acknowledged and released build
`30096834294711694`. The framing profile was checked
against [FFmpeg's ADTS writer](https://github.com/FFmpeg/FFmpeg/blob/master/libavformat/adtsenc.c).
For a separate fresh eight-second passive G4 capture, a laboratory binary using
the new Rust header generator framed 111 raw audio tags using the separately
observed relay SDP configuration. An independent FFmpeg probe and decode reported
111 decoded 16 kHz mono frames without errors. No original AAC configuration
appeared in the capture; the relay configuration matched before and after it but
its epoch and the camera's identity remain unverified. The FLV header and
initial boundary were synthetic; audio was not saved or played. The laboratory
binary built by acknowledged and released job `30096834294711691` had SHA-256
`d824406f96b8918650f492916e2deeb916d7370c0812d04d826d552112c8e7ac`.
The source now additionally permits parsing explicitly supplied two-byte
AudioSpecificConfig bytes directly, with an origin distinguishing them from a
configuration observed inside an FLV tag. The caller must still bind external
bytes to the correct camera, connection and configuration epoch; this parser
does not establish that binding. Scope-filtered job `30097627437596673` passed
14 synthetic parser, framing and track cases, with two live-only cases ignored;
its exit and source release were acknowledged. A separate laboratory executable
used this new parser on another bounded passive G4 capture: it framed 109 raw
samples with the separately observed relay SDP configuration and an independent
decoder accepted 109 frames at 16 kHz mono. No original AAC configuration was
present in that capture, and the relay configuration's connection epoch and
camera identity remain unverified. The FLV header and initial boundary were
synthetic; no audio was saved or played. The executable SHA-256 was
`313dd573338837f77e8fca55017dda3c6592f45ed873db80110dc694cbd5d0e6`;
build `30097629769629697` was acknowledged and released after same-ID recovery
(the daemon earlier reported 130, while recovered delivery reported 0).
The exact laboratory source is retained at
[`unifi_aac_adts_replay.rs`](../experiments/unifi_tls_05_server_lab/src/bin/unifi_aac_adts_replay.rs).
The parser does not itself retain, decode or mux audio.

An experimental source-linked AVC/AAC MP4 path now builds a two-track
initialization and adds an AAC track fragment to an existing FLV AVC fragment.
It retains the original video mapping through an explicit output shift and
records each copied AAC body's source and output ranges. The caller must bind
the audio configuration, connection, epoch and common A/V clock and account
for gaps; the writer does not authenticate the camera, establish those facts,
or publish recordings. It rejects provisional audio records, configuration
mismatch, audio timing inconsistencies and configured sample/source limits.
The initialization also binds the caller-supplied source key, video
configuration ranges and exact AAC configuration bytes; a fragment with a
different binding is refused. Scope-filtered build `30097686090743809` passed four structural tests with one
oracle test ignored; the scoped copy omitted the video decoder portion of an
existing test. Terminal exit 0 and source release were acknowledged. Running
the ignored fixture separately with generated synthetic AAC, an independent
FFmpeg probe and decoder accepted three H.264 video frames and two 16 kHz mono
AAC frames from the Rust-produced MP4. The test executable SHA-256 was
`90e1adf4eccf4c09adc611d57248c2bb4ba12bf2bc7629e9aa78fd66ffc1c121`.
The synthetic oracle is retained at
[`synthetic_av_oracle.py`](../experiments/unifi_tls_05_server_lab/synthetic_av_oracle.py).
The recorder and pipeline now expose A/V initialization; a scope-filtered
recorder test build `30097679933505538` passed six relevant cases, omitting the
unrelated evidence and archive tests. Same-ID recovery acknowledged its exit 0
and source release after the daemon had recorded exit 130.

Two separate bounded passive G4 captures were then replayed through the Rust
recorder and the new A/V writer, using the existing relay and keeping media in
memory. In the first, an independent probe accepted the streams and frame
counts, but the combined decoder emitted errors despite exit 0; that capture
failed the preselected gate and its decoder errors were not retained. A second
fresh capture passed the unchanged gate: the decoder accepted 150 H.264 frames
and 78 AAC frames. The second capture used relay SDP configuration, a synthetic
FLV header and AVC configuration, a synthetic initial boundary and IDR
selection. The reported initial sender-clock audio/video difference was
-113 ms; this is not independently verified synchronization. Configuration
epoch and camera identity remain unverified. Neither capture saved or played
media, changed the camera, or used the new native controller for acquisition.
The executable's original SHA-256 was
`3cff93e299613fb502beb984dccddb196c7db552096cd277c77aa8503f227f00`;
the stripped copy used for the replay was
`5fbae304623319ea8797284c57814149e67ad22ef545ef7a793e5f0eb28c8cb3`.
Its laboratory source is retained at
[`unifi_flv_av_replay.rs`](../experiments/unifi_tls_05_server_lab/src/bin/unifi_flv_av_replay.rs).
These results do not establish sustained recording, independent A/V clock
alignment, recovery, or a native controller handoff.

Three additional fresh captures ran the same binary, acquisition method and
decoder gate, with diagnostic classification added only for any failure. All
three passed: each had 150 decoded video frames, and their audio counts were
78, 78 and 77. Their initial sender-clock audio/video offsets were -120, -120
and -72 ms. Together with the two preceding captures this is four passes and
one decoder-error failure out of five; the first failure's cause remains
unknown. The repetitions used the existing relay, the same synthetic header,
video configuration and boundary selection, and an unverified audio
configuration epoch. They did not save or play media or change the camera.
These short observations do not establish continuous coverage or independent
synchronization.

A separate bounded experiment concatenated consecutive Rust-generated A/V
fragments in one in-memory MP4 while carrying one AAC sample clock across the
fragment boundaries. Two fresh passive G4 captures passed the independent
decoder gate: the first had three fragments, 450 video frames and 234 audio
frames; the second had two fragments, 300 video frames and 155 audio frames.
They used the existing relay, synthetic FLV header/video configuration and
initial IDR selection, and separately observed relay AAC configuration. The
configuration epoch and camera identity remain unverified, and A/V alignment
was inferred from the sender's timestamps rather than independently measured.
No media was saved or played, and the camera was not changed. Build
`30097695737643009` had acknowledged exit 0 and source release. Its original
binary SHA-256 was
`ad2afeffd4fc36beea732fe26fcecde6eb5995c803cca483669972d889fae64a`, and the
stripped binary used for both captures was
`329f374b6be7a790f12c9e602510bf58dc4afffe3e8381bdc5eab70cea42a2b5`.

The production A/V module now also contains a sequential session owner that
checks fragment sequence, video continuity, audio-clock continuity and source
order before advancing its state. It is intended to prevent silent resets and
gaps at fragment boundaries. Scope-filtered remote test job `30097707280367617`
passed five tests, with one external-decoder test ignored; its terminal result
and source release were acknowledged. The scope omitted an independent codec
decoder block, and the two live experiments above used the earlier stateless
fragment API, not this new session owner. Neither path constitutes a continuous
recorder or native camera controller.

The session-enabled laboratory replay initially stopped in the existing
`StructuredTrailer16` framer. A separate, in-memory G4 boundary inspection
found 777 consecutive structurally valid successors at offset 16. The first
seven bytes of the policy's eight-byte padding field were zero throughout;
its last byte was 0 after audio tags and 1 after video and metadata tags. This
does not authenticate the sender or establish the field's meaning. The opt-in
`StructuredTrailer16AvFlag` policy checks that relationship, refuses unobserved
preceding tag kinds, and preserves source bytes and policy identity. The
original, stricter policy remains available. Scoped packet-framer job
`30098049032257593` passed seven tests with no failures or ignored cases;
its terminal result and source release were acknowledged, and both tested
source hashes matched the working tree at that time. The subsequent policy-ID
refactor changes the framer source and is awaiting its own test result.

Source review found that evidence preparation encoded the new policy as ID 3,
but archive reading rejected IDs above 2. The encoder and reader now share a
stable policy-ID conversion, preserving IDs 0–3 and rejecting unknown values.
Scoped packet job `30098049032257657` passed all eight framing tests, including
the compatibility test, with acknowledged exit and source release; its
framer and test source hashes matched the working tree. Full-workspace targeted
job `30098049032257691` passed the archive-record metadata regression, with
2,313 other tests filtered out. Full-workspace job `30098049032257696` then
passed both synthetic ledger publication/readback cases, including a segment
with the G4-style policy, with eight other integration tests filtered out.
Both jobs had acknowledged exit and source release; the archive, evidence,
framer and integration-test source hashes matched the working tree. These
video-only fixtures check source-linked publication, readback and refusal of
unauthorized or corrupted data; they do not establish an A/V archive or actual
camera recording retention. The builds reported unrelated warnings.

Replay build `30097323753209913` succeeded with acknowledged terminal status
and source release; the framer and replay source hashes matched the working
tree at the time. Its unstripped binary SHA-256 was
`2434ad3341445aed50ab58191b4c317a5f5139d0ad6723dbc03368846a1fc704`;
the stripped binary used for both captures was
`b70ba5d4000b4193a851e76e12b1393d45ce59636a9e2c857a03bbd5b5df63fe`.
Two session-enabled passive G4 replays passed independent probe and decode
checks: three consecutive fragments with 450 video and 235 audio frames, then
two fragments with 300 video and 156 audio frames. The initial A/V sender-clock
offsets were -148 ms and -118 ms. The FLV header, AVC configuration and initial
trailer were synthetic; AVC and AAC configuration came separately from the
existing relay, with configuration epoch unverified. Sender identity and A/V
synchronization were not independently verified; no media was saved or played
and the camera was not changed. These brief observations do not establish
continuous recording or native controller handoff.

The reference path also includes a bounded `av_recording::Muxer` that derives
AAC frames from a borrowed `recording::Segment`, maintaining a transactional
clock and sequential A/V session. A refusal preserves the input and does not
advance the clock or session. The caller must bind the audio configuration and
initial clock origin to an epoch and retain or account for original records and
lookahead. This owner does not authenticate a source, measure A/V sync, decode,
publish, or establish continuous recording. The multi-segment laboratory replay
has been changed to exercise it; the two successful captures above exercised
the lower-level session directly, not this owner. Scoped recorder-contract job
`30098049032257609` passed seven synthetic tests with no failures or ignored
cases, with acknowledged exit and source release. Its A/V owner and recorder
source hashes matched the working tree at the time; the owner was subsequently
extended with source binding. The lab AAC-clock source differed by a
later documentation comment, the test source by a later assertion that removes
a warning, and the framing source by the later evidence-ID refactor. The
integration-test build also produced a laboratory replay executable with
SHA-256 `08d281e1a35a1d9b359c80fee3e66245c7873904b0d47345f20d677ee7ce8839`;
its owner, recorder and replay source hashes matched the working tree at the
time; the owner was subsequently extended with source binding. A fresh
passive G4 replay through that owner produced three fragments with 450 video
and 233 audio frames, all accepted by an independent probe and decoder without
reported errors. Its initial sender-clock A/V offset was -91 ms. The source
header, video configuration and initial trailer were synthetic, and video and
audio configuration came separately from the relay. Their epoch, camera
identity and independent A/V synchronization remain unverified. No media was
saved or played and no camera setting was changed. This does not establish
native controller handoff or continuous recording.

The original listener startup waits for a correlated stream-setting reply
before accepting the media connection. The pinned reference sends the setting
without waiting for that reply before media startup; a camera that delays its
reply until media is consumed could therefore stall the original ordering.
An experimental `start_before_reply` path now returns after the journaled
local stream write and accepts media without requiring that reply. The reply
may remain pending on the caller-owned controller session. A supervisor must continue to
poll that same session, observe any later reply, and reconcile the effect; the
local write and a TCP connection do not prove the camera accepted the setting
or produced valid video. While waiting for the initial media connection, the
experimental path now polls the controller as well, answers authorized clock
requests with distinct operations, and returns other bounded observations.
Accumulated observations are returned only after media acceptance; if accept
fails or is cancelled, they can be omitted and the effect requires independent
reconciliation. This revision has not been qualified on the physical G4.
The new opt-in `start_before_reply_tracked` instead records locally observed
dispatch, clock requests and replies, and other bounded management replies in
a caller-owned `StartTrace`. That trace survives an ordinary startup failure or
dropping the startup future. It reserves observation capacity before consuming
the next frame and refuses trace reuse. A missing local dispatch observation
still does not establish that no effect occurred: the effect journal and
independent reconciliation remain authoritative. The legacy convenience API
still discards its private trace on failure. The standalone trial now reports
payload-free trace counts when tracked startup fails. Strict-remote build job
`30098575685845132` compiled the focused fixture, was acknowledged and released
source custody; its executable SHA-256 was
`720b03e868b29e90fb28d0e64e18fb6667cd3889f48cc9353539901b7f2511bd`.
An explicit run of that executable on the worker passed 12/12 tests, including
retention after peer close and caller cancellation and refusal to reuse the
trace. An earlier run failed one cancellation test because its deadline fired
before the fixture reached the intended state; the revised test coordinates
with the synthetic peer. The current listener and test SHA-256 hashes were
`2d31f3d52d22d590f8a07a94e13adc62288e551bbb9db61c6277a61d1af47fa7` and
`62f9206e6b806f8ac85ae6ba8a91d11c6ed46bd03ba7e9c57cd33e1da3217f5f`.
This is a synthetic scoped test, not a full-workspace qualification or a
physical camera session. Separate strict-remote trial-binary build
`30098575685845133` completed with terminal acknowledgment and source release.
It includes trial source SHA-256
`34f3213368136d8f476075a215d6ab37d922a1ebbe8aa75e589e1cbc759aef07` and
produced Linux executable SHA-256
`1233a0161b897f243cb877e733196ae6a8476c8654c1a122e07b67524feedd4e`.
An independent, source-matched TLS loopback fixture passed three cases on that
binary: an early settings reply and no reply each produced a synthetic clip
with three FFprobe-decoded H.264 frames; a peer close after an early reply
retained the trace, reported outstanding reconciliation and produced no clip.
The fixture SHA-256 was
`ab0ac40f761bc370bfcb606d60482d665518dae4f4e52b198c4fed0d6ac19d4c`.
These are synthetic results and do not prove G4 streaming or a settled effect.
Task-owned fixtures that delay the settings reply until after a media read,
or never send it and retain the outstanding request at retirement, passed in
the scoped run described below.
The standalone controller trial also exposes the explicitly selected
`--media-before-reply` mode and records whether a settings reply was observed;
its Rust TLS/process clip test with no settings reply remains unrun; the
independent loopback fixture described below passed. This
mode does not claim that a missing reply is success or that an effect is settled.
In strict-remote job `30098575685845043` the new listener and conversation
code compiled, but the test target failed to compile because the isolated
snapshot had an older container module. That module was refreshed; subsequent
job `30098575685845044` was refused before compilation by the worker's protected
disk reservation. These are not a passing integration result. The compiled
snapshot predates formatting-only changes and a fixture assertion rewrite.
A later refreshed submission, job `30098575685845057`, was also refused at
the protected disk-reservation boundary before compilation; its terminal
result and source release were acknowledged. At that point the no-reply
fixture and trial mode added afterward had no passing run.
Strict-remote job `30098575685845060` subsequently type-checked the current
task-owned integration target, including the delayed- and absent-reply cases;
job `30098575685845072` type-checked the standalone trial binary, and job
`30098575685845073` type-checked a source-extracted process fixture in the
scope-filtered laboratory. All three results were acknowledged and sources
released. The process fixture was extracted from the current test file and
does not qualify the entire original test target. These were `cargo check`
results: no fixture or clip was executed by those jobs. The test harness was
subsequently built and executed as described below.
After the accept loop gained concurrent controller polling, strict-remote job
`30098575685845087` type-checked the source-matched trial binary and job
`30098575685845092` type-checked the expanded task-owned fixture, including
the pre-media clock, early-reply, late-reply and absent-reply cases. Both
results were acknowledged and source release was confirmed. These are still
type-checks, not executed tests or physical-camera evidence.
The current standalone trial was then built as strict-remote job
`30098575685845093`; its terminal result was acknowledged and source released.
The Linux executable SHA-256 was
`0101c02fddb10da047cf20da3482da7b349e87a20a2c5d050f5a94230937d784`.
An independent [loopback TLS peer](../experiments/unifi_tls_05_server_lab/media_before_reply_fixture.py)
then passed two synthetic cases on that exact executable. In both it required a
clock reply before opening media and sent disposable AVC data. One sent the
settings reply before media; the other never sent it. Both produced a private
MP4 which FFprobe independently read as H.264 with three decoded frames; the
trial retained the effect-reconciliation qualification. The fixture source
SHA-256 was `0a8fd9bf2dff84de4596fdc61d2eee048f0e94fb48c76f2f71f222bd5b4b85a4`.
This proves the synthetic process paths only, not live G4 behavior,
authenticated identity, continuous recording or actual effect settlement.
The current task-owned contract was also built in scope-filtered strict-remote
job `30098575685845103`, with terminal acknowledgment and source release.
The resulting Linux test executable, SHA-256
`76a1045ff6b230773403a70509211640e4ec286c8e3bb4ffe1128a37f0a8c1f0`,
was then run explicitly on the worker: all 10 tests passed, none ignored.
These include early, late and absent settings replies; pre-media clock
requests; replay and effect controls; and retained media on admission
revocation. The listener, conversation and test sources matched the working
tree. The scope-filtered build is not a full-workspace qualification.

A second unchanged owner replay produced two fragments with 300 video and 155
audio frames. The independent decoder returned exit 0 but reported a
non-monotonic timestamp diagnostic, and a separate video-only decode also
reported an error; audio-only decode was clean. The gate therefore failed the
run. No packet-level diagnostic was retained for that capture, so the source of
the timestamp warning remains unknown. A third unchanged replay passed with
two fragments, 300 video frames and 156 audio frames; its initial sender-clock
offset was -163 ms. A fourth unchanged replay also passed with two fragments,
300 video and 156 audio frames, and an initial offset of -115 ms. A fifth
replay failed the same strict decoder gate with the non-monotonic video warning;
the independent packet probe found 455 packets, zero non-increasing decode
timestamps and none missing, while video-only passthrough also reported an
error and audio-only decode was clean. That narrows but does not resolve the
warning's cause. A sixth unchanged replay again failed the original gate: 684
packet decode timestamps and 450 decoded-frame best-effort timestamps were all
present and strictly increasing, while the video-only passthrough diagnostic
reported 129 non-monotonic warnings, each involving equal output timestamps.
A video-only null-output diagnostic with a 1/1000-second encoder time base
completed without reported errors; audio-only decoding was also clean. This is
consistent with output time-base rounding in that diagnostic path, but does
not prove that every earlier failure had that cause or establish independent
A/V synchronization. A seventh replay passed the original gate, producing
three fragments, 450 video frames and 234 audio frames with an initial
sender-clock offset of -101 ms. An eighth unchanged replay passed with three
fragments, 450 video frames and 233 audio frames, with an initial offset of
-93 ms. A ninth unchanged replay passed with three fragments, 450 video frames
and 234 audio frames, with an initial offset of -141 ms. A tenth passed with
three fragments, 450 video frames and 234 audio frames, at -125 ms. The original
gate remains unchanged: ten owner replays are seven passes and three failures,
and none qualifies continuous operation.

[FFmpeg's documentation](https://ffmpeg.org/ffmpeg.html) states that its
default video encoder time base is the inverse output frame rate and allows an
explicit encoder time base. That documented output behavior supports the
rounding hypothesis for the instrumented warning; it does not authenticate the
camera stream or explain uninstrumented failures.

When an original in-band AAC configuration is actually observed, the audio
track can now rebind its observation to the exact borrowed source record,
checking the reported spans, format and provisional state. This binds bytes to
the supplied record; it does not authenticate the source or independently prove
the claimed track epoch. Scoped packet job `30098049032257674` passed seven
tests, with one live-capture test ignored, and had acknowledged exit and source
release. Its AAC track and test hashes matched the working tree. Earlier G4
replays observed no original AAC configuration and therefore do not establish
that this new in-band binding has been exercised on that camera.
The A/V owner can now accept such a non-provisional source binding and retain
the claimed epoch, record digest, length, offset and configuration-byte range.
The caller still retains the original record and must establish that the audio
observation and video initialization belong to the same connection and epoch.
The new owner-level integration test is pending; no G4 capture has exercised
this source-binding path. The full-workspace recorder-contract request
`rchw-a87451cd-884c-4ba0-b951-7979b2123b15` exited 103 before admission:
the requested worker had no free slots and local fallback was refused. It did
not run the test and is not a pass.

The ADTS helper now also derives a borrowed source frame directly from an
original FLV `SourceRecord`. It returns a connection-relative body range, the
sender timestamp and the record's provisional-boundary flag, while retaining
the original record with the caller. It explicitly stops on an in-stream
configuration tag so the caller must handle the new epoch; it also refuses
unsupported vendor audio. The helper is stateless: ordering, configuration
provenance, prior provisional configuration, identity and continuity remain the
owner's responsibility. Scope-filtered job `30097635557769217` passed 15
synthetic cases, with two live tests ignored, and its terminal exit and source
release were acknowledged. The relevant source, test and laboratory replay file
hashes matched the working tree. The laboratory executable had SHA-256
`3b412c3eeb2f1fa303d3ddf485e85f39752e587188aa7e7cf22fa671fa2608ae`.
In another eight-second passive G4 capture, that executable validated each
source-body range, framed 108 samples and an independent decoder accepted 108
16 kHz mono frames. The separate relay SDP configuration remained unchanged
before and after the capture, but its exact epoch and the camera's identity
remain unverified; no original AAC configuration was observed. The FLV header
and initial boundary were synthetic, no audio was saved or played, and no
camera settings were changed. The result does not establish audio/video muxing,
continuous retention or a direct native controller session.

The AAC source now has a bounded sample clock that compares each wrapping FLV
timestamp with the exact AAC sample-rate fraction and a caller-selected initial
tick. It rejects repeats, reversals, timestamps outside the configured jitter,
and tolerance at least half a nominal frame; a refusal does not advance the
clock. The jitter bound does not prove that no frame is missing. The owner must
still bind the configuration and connection epoch and
establish the relationship to the video clock. It does not infer UTC, prove
sample completeness, resample drift, or mux audio. Scope-filtered job
`30097641194913793` passed 19 synthetic AAC cases, with two live-only cases
ignored; terminal exit 0 and source release were acknowledged. Four relevant
source and fixture files matched the working tree at that time. A fresh bounded G4 capture
was then processed by the same clock with a preselected 5 ms tolerance: all
110 source audio samples passed the clock check, and an independent decoder
accepted 110 frames at 16 kHz mono. The separate relay SDP configuration's
epoch and sender identity remain unverified, the FLV header and initial
boundary were synthetic, and no media was saved or played. The laboratory
executable SHA-256 was
`b7c5a967444cad3edc868a51e946a104d6f12955a1e6e7a2aee4cfeb357f4e20`.
After a documentation-only source clarification that the tolerance does not
prove completeness, job `30097644634243073` again passed the same 19 synthetic
cases with two ignored; its exit and source release were acknowledged. The
brief live capture does not prove long-term stability or A/V synchronization.

A subsequent bounded RTSP test used the existing transitional Scrypted relay
and a laboratory build of the Rust capture CLI from `f2678a1d`. The laboratory
build changed argument loading so the stream capability was read from a
root-only file rather than exposed in process arguments; its capture and timing
implementation remained the same. The first attempt could not connect from the
host network namespace. The second ran inside the relay's existing network
namespace and completed RTSP setup, received 135,909 bytes, and collected one
source-linked H.264 picture. It stopped with `ERR-CAPTURE-RTSP-TIMING-001`
before publishing any durable picture: the next timestamp did not match the
declared 3,003-tick cadence. The declaration came from an `ffprobe` observation
of a recently archived segment reporting a nominal 30000/1001 frame rate; the
sample alone does not establish exact RTP spacing. No successful recording,
pixel decoding, direct-camera media path, or cadence compatibility is claimed.
Both attempts left their protected archive and journal state for inspection;
the working recorder was not reconfigured.

A third attempt used the same relay and the same laboratory binary, requesting
one picture with the same 3,003-tick declared cadence. It completed with a
normal requested stop, one collected and durable picture, one durable window,
and a published catalog. The terminal receipt reports no pixel decode, no
certified continuity or coverage, and no verified server identity. The sample
is too short to validate inter-picture cadence; it does not overturn the
15-picture timing refusal. This is native Rust capture through the transitional
relay, not a successful Scrypted-free camera session. The root-only journal is
on `trj`, with the protected trial archive under the authorized bulk recording
directory. The recorder, upload, fallback and discovery services remained active.

Another 15-picture attempt declared 3,000 ticks, as a bounded alternative
suggested by an earlier nominal 30 fps observation. It also stopped with the
timing error after one collected picture and no durable picture. In a separate,
short, read-only RTSP session, an independent payload-free diagnostic observed
31 distinct video RTP timestamps: of 30 consecutive differences, 20 were
2,970 ticks and 10 were 3,060 ticks on the 90 kHz clock. This is direct evidence
of nonuniform timestamp spacing in that sample, not a measurement of camera
exposure times or a guarantee about other sessions. The existing fixed-cadence
recording contract cannot represent that sample as-is. A correct variable-
duration design must retain a bounded complete-picture lookahead to derive each
previous duration from a later source timestamp, and must explicitly account
for the unresolved final picture, loss, reordering, source changes, deadlines,
and crash recovery. The default capture bridge holds one picture until timing
is supplied, so simply relaxing its cadence check or inventing durations would
misrepresent the source. A draft opt-in complete-picture lookahead is not yet
wired into the RTSP recorder or qualified against a physical camera. This
fixed-cadence constraint belongs to the RTSP
capture route, not the direct UniFi FLV owner: that owner already derives
sample durations from subsequent source timestamps using bounded lookahead.
Neither path has yet established a native live G4 recording. An instrumented
laboratory rebuild was not produced: two strict-remote jobs failed during
source transfer before Cargo started.

An opt-in draft of complete-picture lookahead was tested on `ts1`: 21 of 22
capture contracts passed, and the EOF case failed because the fixture expected
the unresolved-picture stop before the receiver's metadata-only EOF tail.
The fixture was corrected to require both ownership transfers; that correction
has not yet passed a completed run. A follow-up strict-remote job
`rchw-9a2a4798-70b1-4ff1-8b4d-7cc054460565` (build `30096834294711380`)
timed out on `trj` after 3,630 seconds on 2026-11-06; RCH verified that its
remote process group was dead. Same-ID recovery returned exit 137 with terminal
acknowledgment and source release; it reported an earlier daemon exit of 130,
which differs from the recovered delivery exit.
It used the `bcab915a` baseline with the selected lookahead,
direct-controller and synthetic-recording test overlays. Its snapshot predates
the additional uncertain-time-sync-write test. It did not produce a test
verdict, despite its recovered and released job custody.
Neither the lookahead nor the time-sync option is
an automated production camera setup path.

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

The source now also marks a candidate ambiguous if another reply from the same
address has no usable MAC or fails to advertise that source address. Setup's
existing nonconflicting-claims check consequently refuses that candidate, and
the discovery CLI reports `incomplete_claim_at_address`. A new loopback UDP
fixture and unit cases cover incomplete claims. A strict-remote contract run was submitted on
2026-11-06 at base `88e0195e`; workers `hz4` and `vmi1152480` refused disk
admission before starting, and RCH retried the same invocation on `trj` as
build `30096834294711505`. It exceeded the external deadline during compilation
and exited 137; terminal acknowledgment and source release were confirmed. No
test verdict was produced. The invocation targeted the integration fixture only,
not the CLI or the new unit cases. An independent CLI fixture also checks this
ambiguity; subsequent results and the service installation are described below.
An isolated, scope-filtered reference laboratory copied the current discovery
module and integration fixture. Build `30096834294711714` on `vmi1152480`
passed nine synthetic cases, with one live test ignored; the terminal result
was acknowledged and sources released. Seven relevant source and fixture files
matched the current working tree. A separate isolated build
`30096834294711721` passed the new incomplete-claim unit test and also had
terminal acknowledgment and source release. Build `30096834294711697` on `trj`
exceeded its external compilation deadline and produced no test verdict; the
remote process group was verified dead, and same-ID recovery reported exit 255,
terminal acknowledgment and source release. The daemon had recorded 130. A
stripped copy of the successful test executable, SHA-256
`e18ccb12550b7dc1349646c0f4b4bfafd3c1da56698eb78a3b0f31115e17d021`, was then
run on `trj` under the existing bounded broadcast authorization. It received
one candidate claiming a G4 model, with no flagged claim conflicts, and ended
when its observation window elapsed. This is a live but unauthenticated
discovery claim; the probe performed no camera login or configuration change.
An earlier attempt on `vmi1149989` was refused before Cargo started because
the worker's protected disk reservation could not be satisfied.
The current discovery CLI source was built in a separate scope-filtered
laboratory as `30096834294711722`, with terminal acknowledgment and source
release. Of 212 corresponding Rust files, 210 matched the working tree; the
two laboratory entry modules were deliberately filtered to the relevant UniFi
dependencies. The independently exercised loopback CLI fixture passed 5/5
cases both before and after stripping. The stripped executable's SHA-256 is
`57082bca370a059d73dbaa1b7b391b0e17dc418fab7ef9fcbf5825a68e857cec`.

The exact stripped executable then passed the existing authorized broadcast and
unicast wrapper on `trj`, reporting one unverified G4 claim and no flagged
conflicts. A new root-owned versioned binary and wrapper were staged without
overwriting the prior ones; the wrapper passed again as the service user. A new
systemd drop-in selected the verified wrapper for the existing discovery service,
and a service invocation succeeded with the G4 claim and the new ambiguity
field present. The timer remained active and the recorder restart count remained
53. The original binary, wrapper, scope and earlier drop-in were retained for
rollback. The timer then fired independently at 03:59 EST on 2026-11-06; that
service invocation succeeded and reported one unverified G4 claim with the new
ambiguity field. This is automatic discovery only: it does not authenticate or
adopt the camera.

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

On a later read-only check, `/bulk` was mounted and the recorder, discovery,
upload and fallback units were active. The primary upload destination on the
USB NVMe at `mac-mini-old` contained 2,290 MP4 segments totaling about 10.1 GB;
the newest was 33 seconds old and the oldest about 38 hours old at inspection.
The originally requested `/bulk/unifi_camera_recordings` fallback had no files
modified in the preceding day, consistent with the configured primary upload
path taking precedence. A separate probe of one recently uploaded segment
reported approximately 60 seconds of H.264 video and no audio stream. This is
one sampled file and a point-in-time inventory, not proof of gap-free coverage,
30-day retention or audio absence from every file. No media was played or
modified by the probe. A separate, subsequently selected recent uploaded
segment was decoded to a null sink without reported errors, using one decoder
thread and without playing or copying the media; this is one file, not a
continuity check. Read-only inspection of the uploader found a configured
30-day age check for regular files at the primary destination; that source
inspection is not evidence that deletion has occurred or that every retention
obligation is satisfied.

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

The controller's default observation API still classifies event messages as
`Other`. An opt-in event-claim parser and the established-session supervisor
now recognize `Event*` messages and transfer the exact bounded WebSocket JSON
source to the caller with a digest and untrusted message metadata. A bounded
view interprets selected motion edges and smart-detection descriptors without
claiming detection truth or peer identity. The caller must retain or explicitly
omit that source under its privacy policy. Capture is enabled only when the
session enters the supervisor; events received during startup are still
discarded as `Other`. A camera-requested event reply is exposed but not sent;
the trial stops after explicitly omitting such a source. No event publication,
motion-state lifecycle, audio linkage, physical G4 event, or complete Scrypted
detection parity is claimed. Scope-filtered strict-remote job
`30098575685845154` built the event, controller, receiver and task-owned
contracts and released source custody. Its executables passed **3/3**, **23/23**
and **5/5** event, controller and receiver tests. The first task-owned run
passed 12/13 but its event fixture failed because its synthetic WebSocket
encoder lacked extended lengths. After fixing that test helper, strict-remote
job `30098575685845155` completed with terminal acknowledgment and source
release; its executable SHA-256
`a501fb1b1b04a4e8debf3dfeed2ef13bea58a3fd1f178c49e16bb6033d039da7`
passed **13/13**, including the event and media supervisor path. A prior job
`30098575685845146` failed to compile because the reduced snapshot was missing
ten modules and the then-current receiver used the wrong WebSocket buffer type;
both were corrected before the successful runs. The event and receiver source
SHA-256 hashes were
`efd761ccc9c3c69017c85863ff332dc61876296e119bbca13eafb248fc7a0ddb` and
`c6835ee63edb745e72634bba9f9489c1d7679e684a2b4a80b547203d21ea78d1`.
The filtered main module matched the checkout after only those ten omitted
module declarations were removed; its filtered SHA-256 was
`db23f1fe01165a619c92302537301b06bf934b2817ec3a635c242e631281496a`.
The changed standalone trial has not yet been rebuilt or exercised for this
revision. These are synthetic tests, not a full-workspace qualification or G4 event.

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

The joint supervisor now exposes the pipeline's A/V initialization from its
observed video parameters and caller-supplied AAC configuration. The caller
still owns the configuration and clock binding; the accessor does not establish
either. The updated loopback contract checks absence before video configuration
and the AAC bytes after a segment is available. Its newer revision also feeds
synthetic audio records through the supervisor into the A/V muxer and checks
its writer-profile output. Those synthetic AAC bodies are not claimed to decode
or to be synchronized with the video.
The single loopback case is running as strict-remote job `30098049032257824`
in a scope-filtered lab; its supervisor, earlier test, packet-module and
fixture hashes matched the checkout at transfer. It predates the additional
audio-mux assertions. The worker's disk guard subsequently stopped the build
on a telemetry deadline, before tests ran; it exited 137 with acknowledgment and
source release. The updated full task-effect target was submitted as job
`30098049032257843` on `vmi1152480`, using the same scope-filtered lab. Five
modified source and fixture hashes matched the checkout, but the worker-local
disk guard refused to start Cargo because existing reservations and the protected
floor could not be covered. The job exited 120 with acknowledgment and source
release; no test ran. A subsequent run of the updated full target on
`vmi1264463`, job `30098049032257846`, passed all six tests with terminal
acknowledgment and source release. The supervisor, A/V muxer, AAC clock, test
and fixture hashes matched the checkout on the worker. The lab omits unrelated
reference modules and cannot establish a full-workspace or physical-camera
result.

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

### A/V archive candidate and publication (qualification pending)

A separate A/V graph candidate composes the existing source-linked video graph
with the AAC configuration, two-track initialization, A/V fragment and exact
audio body mappings. When available it retains the original in-band AAC record
and the claimed epoch. It can also retain separately supplied codec bytes while
explicitly labeling their original source and epoch unverified; that mode does
not pretend to have an in-band record. It refuses provisional audio
configuration or sample boundaries, mismatched source bodies, video mappings,
configuration bytes, claimed video connection or configuration ranges, limits,
and an audio configuration that does not precede the segment. The claimed
shared connection and audio epoch remain the caller's
responsibility. The existing retention, cancellation, tombstone, root-last and
ledger gates now have an A/V publication entry point; the A/V child-object reader
checks authorization, the ledgered root, content identities and metadata prefix,
but does not independently replay all source mappings or validate A/V sync. A
separate typed configuration reader returns the stored source class and claimed
epoch; for the in-band case it also verifies the original record, tag and exact
configuration range. The supplied case remains explicitly unverified. A new
video-only readback verifies that the nested video manifest and all its children
belong to the ledgered A/V root, then replays the existing video source and MP4
checks. A separate bounded audio mapping verifier replays the video source graph,
checks every original audio tag against its fragment byte range, and verifies
contiguous supplied AAC decode ticks and forward sender timestamps. It rebuilds
the writer-profile A/V initialization from verified video parameters and the
declared AAC configuration, and checks the fragment's writer-profile audio
sample table and copied video payload. It preserves the configuration's source
class. These are writer-profile and source-byte checks, not an independent MP4
conformance test, audio decode, independent A/V sync, device identity or
continuity. A combined A/V reader now runs these checks before returning the
two-track initialization and fragment, rechecks authorization and content
hashes, and reports whether the AAC configuration was in-band or unverified.
Child-membership checks use the manifest's sorted digest list and charge an
explicit work bound; this change is also awaiting test qualification.
The AAC clock and A/V muxer now expose an explicit, bounded frame-allowance
renewal without resetting the prior sender timestamp, decode origin or drift
checks. This removes the hard 16-million-frame epoch ceiling when a caller
authorizes additional work. At 16 kHz and 1,024 samples per frame, 30 days
requires 40.5 million frames; a synthetic case checks the allowance
arithmetic and a second checks retry after a budget refusal. Renewal does not
prove 30 days of recording, resolve long-term clock drift, or provide a running
recorder service. On `ts1`, job `30098049032257841` compiled the full packet
library with pinned nightly and ran the five packet-clock tests, including
renewal across timestamp wrap and overflow refusal; all five passed, with
terminal acknowledgment and source release. The clock and test hashes matched
the checkout. The A/V retry case remains untested and is not in the earlier
recorder-contract snapshot.
Known-length source, configuration, initialization and fragment reads now use
the spool's per-read bound and charge that bound plus framing overhead before
I/O. An object larger than the committed length is refused; unknown-length
manifest and metadata reads retain the spool-wide ceiling. A synthetic test
sets an end-to-end work budget for small records. A second unrun fixture forges
a shorter initialization length in an otherwise content-addressed, ledgered
graph and requires the precise spool length-bound refusal. This has not been
benchmarked or exercised on a retained physical-camera segment.
An additional synthetic adversarial case creates a fully content-addressed and
ledgered graph with a deliberately wrong audio target that still points to an
identical byte; the reader must refuse it. Additional cases require refusal on
mid-read authorization revocation, an incorrect capture pin and insufficient
work budget. The nested readback, audio mapping verifier, combined reader and
their fault cases have not yet completed a test run.
The live G4 capture has not supplied an original in-band AAC configuration, and
the separately supplied mode has not been exercised on that camera or qualified
for continuous recording. Full-workspace job
`30098049032257703` was refused by a worker disk reservation; its automatic retry
`30098049032257704` failed source namespace initialization before compilation.
Neither attempt is a test pass. The separate scoped evidence test is pending.
The later full-workspace attempt `30098049032257706` also exited 120 at disk
admission before compilation. The separate scoped graph-construction job
`30098049032257705` on `trj` exited 137 when the disk telemetry monitor timed
out during dependency compilation. Its terminal status and source release were acknowledged; it
produced no test verdict and would have covered only the earlier in-band-only
version, not the supplied-configuration mode or archive publication.

A further owner-scoped, read-only G4 connection-start observer was running on
`trj` at 20:10 UTC on 2026-11-06 (local session 9259). It waits at most eight
minutes for a natural reconnect, then may replay up to 20 seconds of source
bytes through the previously pinned video-only Rust laboratory binary. It does
not save media or change the camera. The observer script SHA-256 is
`10a9ef2f9d4dba4cc17fc9a25d4d45ae92ba1b00847ec4e9f83e4d96e503b8c9`.
It exited successfully with no new TCP SYN or complete connection header in
its window, so no native replay ran. This is not evidence that a reconnect
cannot occur, nor proof of native controller handoff, the new A/V evidence code,
or continuous recording.

A separate full-workspace snapshot was assembled from Git baseline `f53e4d5a`
and exact overlays for the A/V candidate, archive, video initialization and
integration test. Its six overlaid source hashes matched the working tree at
submission. The first off-root request failed before admission while `trj`'s
headroom sample needed refreshing; after an explicit read-only worker probe,
strict-remote job `30098049032257717` was admitted on `trj` and began compiling.
Those six source hashes also matched on the worker after transfer. The nested
video readback was added afterward and is not in that snapshot. A disk telemetry
deadline interrupted this job during compilation, and its wrapper retained
source ownership after a source-authority lock timeout. Exact-ID recovery of
`rchw-328f10fd-311b-4504-b971-2bfcb6aa52b6` reported delivery exit 137,
terminal acknowledgment and source release; the daemon had recorded exit 130.
Neither exit is a test verdict. The nested readback remains untested.

### First-time Wi-Fi provisioning: protocol evidence and boundary

Update: the repository now contains first-party X25519 and Poly1305 source in
`fss-tutk`. An isolated [BLE crypto lab](../experiments/unifi_ble_crypto_lab/README.md)
reuses those files and independently compares synthetic packet, cipher, and
key-derivation vectors. It is not an admitted provider and cannot provision a
camera. The earlier statements below describe the state at that earlier point.
The reference's public default key and repeated direction/session nonces do not
establish device identity or a safe boundary for sending real Wi-Fi secrets.

The existing LAN setup owner starts after a camera is network-reachable. It
cannot discover an unprovisioned Bluetooth-only camera or send Wi-Fi settings.
The author of [UniFi BLE Client](https://github.com/zerotypic/unifi-ble-client)
reports a separately reverse-engineered onboarding protocol and tests only a G3
Instant. Its [protocol description](https://github.com/zerotypic/unifi-ble-client/blob/main/doc/protocol.md)
describes a notification byte stream, a write-with-response byte stream,
bounded big-endian packet lengths, a key exchange, authenticated encryption,
ordered packet sequence numbers and an API-message layer. The author also
reports a G3 MTU interoperability problem with strict Linux Bluetooth stacks.
These are third-party observations, not proof that the owned G4 or other models
use the identical behavior. The earlier G4 Bluetooth connection attempts in
this conversation timed out; they did not demonstrate successful BLE provisioning.

A native implementation needs a task-owned, cancellable BLE transport with
explicit adapter and device scope; source-preserving, bounded reassembly that
survives notification fragmentation; independently qualified pure-Rust crypto
and a strict sequence/nonce exhaustion policy; bounded message decoding and
response correlation; and a one-use, journaled Wi-Fi setting effect with secret
inputs that never enter logs or retained packet evidence. A locally observed BLE
address, model name, or use of a protocol default key is not independent camera
identity or owner authorization. An uncertain write must remain indeterminate
until independently reconciled; it cannot be blindly retried or silently
triggered for every broadcast candidate. The current lockfile does not contain
an XSalsa20-Poly1305 implementation or an X25519 API dependency, and the current
FSS source has no UniFi BLE transport. An experimental
`fss_packet::unifi_ble` framer handles the documented two-byte packet length,
preserves incomplete input at retirement, and refuses invalid or oversized
lengths without guessing a new boundary. Its companion write cursor splits an
already-framed packet into bounded characteristic values and tracks explicit
transport outcomes: acknowledged, definitely not submitted, or indeterminate.
An uncertain write fences further writes, and retirement preserves the pending
range for the owner; acknowledgment is not proof of device processing. Four
standalone synthetic tests of the earlier framer passed
on `ts1` in strict-remote job `30098049032257790`, including split and combined
notifications, backpressure, bad lengths and retirement. The tested source
SHA-256 was `0aa441fbfc8bb282684ec89316223bf94698c536e1e2734d645e2406cf329739`;
the worker's result was acknowledged and source custody released. This was not
a full-workspace build or a physical-camera test. A second `ts1` job,
`30098049032257792`, checked all 39 packet-source hashes, compiled the complete
dependency-free packet library with the repository's pinned nightly, and passed
the same four standalone tests. Its result was acknowledged and source custody
released; it did not run the complete workspace tests. Framing alone does not
connect or authenticate a camera. Follow-up pinned-nightly job
`30098049032257796` checked all 39 packet-source hashes, compiled the packet
library, and passed all six standalone tests including write acknowledgment,
retry, indeterminate outcome and cancellation. Its result was acknowledged and
source custody released. The tested current BLE module SHA-256 was
`fc7c36732ea965d92b1d4862c78628d2a251f10aaf6a977a883cc87bd519b5a9`.
The module was then revised to eliminate production `expect` and test `unwrap`
calls. Job `30098049032257815` compiled the packet library from 39 verified
source files, ran the pinned-nightly Clippy driver with `unwrap_used`,
`expect_used` and `panic` denied, and passed all six standalone tests. The
result was acknowledged and source custody released. The revised module hash is
`f29eb822a995496c5fc14d997b2ad05b69fc05dc9fc53a8791e591ce5ebd2340`.
Neither the framer nor the cursor implements crypto or configures Wi-Fi. No real-device success for this
provisioning path is claimed here. The existing working G4 must not be reset or
re-provisioned merely to obtain a fixture.

For eventual Linux Bluetooth access, `fss_packet::dbus_handshake` implements
a bounded restricted profile for D-Bus EXTERNAL authentication, `Hello`, and a
read-only `NameHasOwner` query for `org.bluez`. Unsupported variant types are
explicitly refused; this is not a complete D-Bus client. On `ts1`, strict-remote
job `30098049032257855` compiled the complete packet library, passed five
focused handshake/parser tests with warnings denied, authenticated to the real
local system bus and observed that the BlueZ name had an owner. The probe made
no BlueZ or camera calls. Its result was acknowledged and source released.
The tested module SHA-256 was
`7e669be964ae734e58da1ec56b682dc80d77a6e6ad0e3525a80db89823f821fd`.
After stricter unique-name validation and additional partial/false-response
cases, job `30098049032257859` again compiled the packet library, passed all
five focused tests with warnings denied, and observed the BlueZ name on `ts1`.
The updated module SHA-256 is
`c97c445219aa777ba390885b056ab4953f483e35ec21f163f5db95c1cfb14c86`.
This is a synchronous standalone process probe, not Asupersync transport,
adapter enumeration, BLE communication, or Wi-Fi provisioning. BlueZ's
[adapter API](https://bluez.readthedocs.io/en/latest/adapter-api/) and
[GATT API](https://bluez.readthedocs.io/en/latest/gatt-api/) remain separate
protocol work, as do the previously identified crypto and device-identity
requirements.

After both interrupted jobs were reconciled and their source ownership was
released, `trj` was observed under heavy load and marked unreachable. A fresh
probe found `vmi1264463` healthy with sufficient reported free space. The
snapshot was updated with the nested video readback and its fault cases, then
strict-remote job `30098049032257738` was admitted there for the entire
`unifi_direct_recording_contract` target. The six modified source and test
hashes matched the checkout on the worker after transfer. The worker's disk
guard then refused to start compilation because active reservations and its
protected free-space floor could not be covered together; the job exited 120
with terminal acknowledgment and source release. It produced no test verdict.
A subsequent probe found `vmi1152480` healthy with 46.7 GiB reported free, and
strict-remote job `30098049032257742` was submitted there for the same current
full recorder-contract snapshot. Its disk guard refused to start compilation
because active reservations and the protected free-space floor exceeded the
available space. The job exited 120 with terminal acknowledgment and source
release; it produced no test verdict. Repeating that admission without a
meaningful capacity change would not test the code.

The A/V audio mapping path was subsequently extended to compare its retained
initialization with a reconstruction from the verified video parameters and
AAC configuration, and to check the writer-profile audio fragment table and
copied video payload. Added synthetic cases alter the initialization and audio
sample table. A five-sample `trj` filesystem telemetry check then succeeded
without timeouts, and an explicit worker probe reported healthy. A fresh
strict-remote full recorder-contract request was started against the updated
snapshot (local session 31347, wrapper process 38863); it was later admitted
as build `30098049032257758`, wrapper `rchw-7ecc0e68-19fc-4a0f-adde-5a8e5895445d`.
The combined A/V reader and the video-shift metadata check were added after its
snapshot, so this build cannot qualify them. It has no test verdict yet; check
that exact request and source release before retrying.
Additional unrun fragment-verifier cases now cover truncated container boxes
and impossible target/time values without treating a refusal as a decode test.

A separate generic MP4-box oracle was prepared to inspect a bounded passive G4
replay's track identifiers, `trun` sample extents, AAC decode-tick continuity
and independent `ffprobe` stream types without saving or printing media. Its
local script SHA-256 is
`9751bef17a1133f64084556562a372237ca040634c89a2e282ae343e8c262f35`.
The attempt stopped at its initial binary-presence check: the previously pinned
G4 A/V replay executable was no longer available on `trj`. It did not contact
the camera or produce a media or validation verdict. A new, source-verified
replay executable is required before this oracle can be used.
Three separate in-memory synthetic checks of the oracle passed: two-track
sample extents, rejection of a truncated box, and rejection of a data offset
outside `mdat`. These exercise only the Python oracle, not the Rust reader or
the physical camera.
The prepared replay driver now calls the new Rust initialization and fragment
validators for each derived segment before emitting its in-memory output. Its
source SHA-256 is
`c9c80d4f33e5a24f4a714ca340941112be4bbcc33d0278df2b0294ea944d0bda`.
The box oracle was changed to require a caller-supplied verified binary identity
and that validator-success marker; its new script SHA-256 is
`d7369b81c37a2f777d920e7e7ef9d12830d22ac57e687ab3c780252fd0e889ab`.
The prior three synthetic oracle checks cover the unchanged box parser only.
The current replay driver has not yet been compiled or run. In its scoped lab,
all 19 container and 38 packet Rust source files match the checkout; this does
not assert a full-workspace match.

Continuation order: once build `30098049032257758` has a terminal result and
its source ownership is released, refresh the isolated full-workspace snapshot
with the current archive and integration-test sources and run the entire
recorder-contract target again. Only the later run can qualify the combined
reader, work-budget membership checks and newly added adversarial cases. After
that source custody is released, build the prepared scoped G4 replay driver,
verify its source and binary hashes, and use the passive box oracle. Neither
step authorizes a controller handoff or a camera setting change.

The prepared G4 replay driver was subsequently submitted as strict-remote job
`30098049032257780`, wrapper `rchw-6f0cd48e-1b84-4b0a-9a57-4887f307af31`, on
`trj` in a separate scoped lab. After transfer, the driver and seven key owner,
container, demux and packet source hashes matched the local snapshot. The
existing recorder and upload/discovery timers were active at a contemporaneous
check. The build has no terminal result yet; verify its exact result, source
release and binary hash before attempting the passive oracle. A successful lab
build would not itself establish full-workspace or live-camera qualification.

The full recorder-contract build subsequently reported missing snapshot inputs
`architecture/device_adapters.json` and `models/fss-activity/fss_activity_v1.fmpk`.
They exist in the checkout but were not copied into the isolated snapshot. It
exited 101 with terminal acknowledgment and source release; no contract tests
ran. The snapshot was refreshed with eight current modified Rust files and 95
missing repository-local `include_str!`/`include_bytes!` targets, and strict
remote job `30098049032257804` was submitted to `trj` for the full contract.
Its source transfer timed out before Cargo started. The wrapper returned 103;
the durable job recorded exit 1 with terminal acknowledgment and source release.
It produced no contract-test verdict. A subsequent request for `ts1` was refused
before submission: the worker reported 32 GiB free against 40 GiB required by
its current admission policy. No reservation or protected floor was changed.
On `vmi1264463`, a newly probed worker with approximately 54 GiB free admitted
job `30098049032257812` but its worker-local guard refused to start Cargo because
active reservations and the protected floor could not be covered. It exited
120 with terminal acknowledgment and source release. After a separate read-only
streaming transfer of the 63 MiB snapshot to `trj` succeeded, the latest
snapshot was submitted again there as job `30098049032257817`; its result is
now terminal. After transfer, eight modified source files and the two previously
missing compile-time inputs matched the checkout by SHA-256. During compilation
the worker's free-space telemetry timed out and its disk guard stopped the job.
The wrapper and durable job both recorded exit 137, with terminal acknowledgment
and source release. No contract-test result was produced; the resource guard
was not changed.
After the scope-filtered loopback succeeded on `vmi1264463`, a refreshed full
snapshot was submitted there as strict-remote job `30098049032257857`. It
includes the current A/V retry case and an earlier D-Bus handshake revision;
the archive, A/V evidence, muxer, recorder test, AAC clock and two previously
missing compile-time inputs matched the checkout by worker SHA-256. Its
terminal result is pending and it cannot qualify subsequent source edits.

The prepared passive camera capture helper was also revised to separate TCP
flows, handle wraparound and reordering, reject conflicting retransmissions,
preserve gaps as distinct runs and reject truncated packets or IPv4 fragments.
Two live capture attempts with an initial 2,048-byte snap length were refused;
the second identified a truncated IP packet. The helper was changed to allow
full-sized IPv4 packets while capping the entire capture at 32 MiB and imposing
a deadline; a subsequent read-only 20-second capture produced one contiguous
run. Six synthetic fault tests of the revised helper passed. The helper SHA-256 is
`f27aefcf4be874d1f84e27c336c1792967173d8a20cb57556f0075b780763780`,
and the revised independent oracle using it is
`356e0c6a4084dc1bdfc88a9bc829964b6b91bfe78d008db70e2dc2d9c221e2c3`.
These changes do not authenticate the source or establish complete capture.

The scoped driver build `30098049032257780` completed successfully, with its
terminal result acknowledged and source released. Its executable SHA-256 is
`809c8692dd236e6c42e1a15eb49e5c549268334a045a783640ff8a3fd21fc27f`.
One fresh passive G4-derived replay with the revised helper passed the Rust
writer-profile checks and independent box/stream probe: three A/V fragments,
450 video samples and 235 audio samples. The FLV header, initial AVC tag and
trailer were synthesized; AVC and AAC configurations came from the separate
relay with epoch and source identity unverified. The initial probe recognized
H.264 and AAC but did not decode them. Three subsequent fresh passive captures
passed the same box/stream checks and an independent FFmpeg strict decode of
both tracks, with no decoder stderr. Each produced three fragments with 450
video samples and 233 audio samples. The strict-decode oracle SHA-256 is
`0e9d70e6c4dd7b2889ea6f66946b0d9faf2d4a9908f3773ac5e732effb72739a`.
These bounded trials did not change camera settings or save media. They do not
establish authenticated native controller operation, configuration-epoch
identity, A/V synchronization or continuous recording.
One further fresh strict-decode trial also passed, making this revised series
four passes in four completed trials. A planned continuation was interrupted
while the next capture was in progress after `trj` reported heavy load; that
incomplete capture has no result. These results do not supersede the separate
earlier series of seven passes and three failures.
Afterward, a read-only service check reported the G4 recorder and the upload,
bulk-fallback and discovery timers active; it does not verify recording coverage.

The full recorder-contract snapshot subsequently completed on `vmi1264463`:
job `30098049032257857` passed 12/12 tests, with terminal acknowledgment and
source release. The snapshot included the source-matched A/V archive, evidence,
muxer, recorder contracts and AAC clock described above, but an earlier D-Bus
revision. These fixture results are not a physical native-controller session,
an operational native recorder, or a 30-day retention or continuity proof.

On `ts1`, packet job `30098049032257872` verified all 40 packet source files
against its snapshot, passed 5/5 restricted D-Bus handshake tests under the
pinned nightly Clippy gate, and performed a standalone synchronous system-bus
probe. The local bus reported an owner for `org.bluez`; the probe made no
BlueZ adapter or camera calls. This does not qualify the newer task-owned
asynchronous observation transport or establish Bluetooth device availability.

The task-owned asynchronous BlueZ-name observer passed five scoped Cargo
fixtures on `vmi1264463` (job `30098049032257881`): fragmented traffic,
absent-name observation, stage-specific policy revocation, deadline retirement,
and the signal limit. Its observer, meter, test and then-current packet sources
matched the worker snapshot by SHA-256; the result was acknowledged and source
custody released. This scoped laboratory excludes unrelated reference modules
and is not a full-workspace build. Two earlier requests had timed out before
admission and produced no test result.

A separate read-only Asupersync process using that observer connected to the
system bus on `ts1`, passed its task receipt, observed one skipped signal and
reported that BlueZ had a name owner. It sent no BlueZ adapter or camera call.
The probe source SHA-256 was
`abf6db2e8925c48b376fdda5bb48b5875f6ca60fdb015d4c25282dc5918e38e9`.
On `vmi1264463`, job `30098049032257890` compiled the executable, but its
wrapper returned exit 102 because the Linux binary could not be downloaded as
a Mac artifact. The result was acknowledged and sources released. The compiled
Linux binary, SHA-256
`d92b8d405eb964671a5541b0d9655a9aed3011eb61139c3c9b5d0fd217c5f66c`,
was copied to the intended Linux host and independently hash-verified before
the successful probe. This establishes neither device identity nor camera
discovery, GATT, adoption, or Wi-Fi provisioning.

The next Bluetooth inventory owner needs a longer-lived bus session than this
one-shot observer. The D-Bus [ObjectManager contract](https://dbus.freedesktop.org/doc/dbus-specification.html#standard-interfaces-objectmanager)
describes `GetManagedObjects` and advises installing a signal match before
fetching the snapshot; a one-time snapshot or discarded signals cannot establish
continuous adapter/device coverage. BlueZ's
[adapter API](https://bluez.readthedocs.io/en/latest/adapter-api/) also treats
discovery as a shared session, while its
[GATT API](https://bluez.readthedocs.io/en/latest/gatt-api/) distinguishes
characteristic write modes. Enumerating objects, owning and releasing discovery
sessions, handling signals and reconciling uncertain GATT writes therefore need
separate bounded, task-owned contracts before automated provisioning can claim
success. The present observer deliberately does none of those things.

A read-only `busctl` ObjectManager query on `ts1` returned signature
`a{oa{sa{sv}}}` and reported one `org.bluez.Adapter1` interface. It did not
start discovery, connect to a device, or call a camera; it is a snapshot from
the system's tool, not an execution of the Rust observer. The absence of a
device from that snapshot is not evidence that no camera is nearby.
The adapter's returned property variants included `as`, `b`, `q`, `s`, `u`,
and `y` in that snapshot. This is direct evidence that the present restricted
reply-header decoder is insufficient for parsing the ObjectManager body; it
does not establish that those are the only types BlueZ may return.

An experimental bounded ObjectManager body parser now validates complete nested
values and exposes adapter-path claims without printing them. A separate scoped
Cargo fixture on `trj` (job `30098049032257891`) passed five body tests and
six correlated-handshake tests, with acknowledged exit and source release.
The body parser SHA-256 was
`e505c2b2d9953f658e310f123cfa6665cf6e25251daa17efbc0efb08bcda3bc7`
and the extended handshake SHA-256 was
`7f855fa3abe344591495bac59c8583037c34a4d7b9689899781c8351987319fd`.
The body parser requires a separately correlated and admitted response; its
refusals are not evidence of device absence. A separate synchronous Rust probe
then issued a read-only ObjectManager request to the actual `ts1` system bus,
correlated its reply and parsed two objects including one adapter. It did not
start discovery or call a camera. The diagnostic binary SHA-256 was
`6c9d40521226d55a0c2f90386aa2bf923ef9112dbe4bb21245878cd200e29cf1`;
job `30098049032257892` compiled it on `trj`, but its wrapper returned 102
because the Linux executable was refused as a local Mac artifact. The result
was acknowledged and sources released; the binary was copied to `ts1` and
verified by hash before the probe. This is not a full-workspace qualification
or an asynchronous inventory test. An integration of the parser into the
task-owned asynchronous observer is under test; a first test submission failed
before Cargo started when its source transfer timed out (job
`30098049032257893`, sources released), as did a second submission on the same
worker (`30098049032257897`, sources released). A third submission to `trj`
also timed out in source transfer before Cargo started (`30098049032257900`,
sources released). A local copy of the small source tree was also unusually
slow. Job `30098049032257901` was submitted with an explicit 120-second source
transfer timeout instead of the automatically derived 36-second timeout; disk
and remote-execution guards remained unchanged. Source transfer took 55.9
seconds, then the job passed all eight scoped async tests with acknowledged
exit and released sources. The worker hashes matched the packet entrypoint,
handshake, body parser, async observer and test snapshot. This includes
successful and malformed inventory replies plus missing-service and denied
inventory-request cases, but not continuous discovery. A separate read-only
probe using the same task-owned asynchronous inventory path then connected to
the real `ts1` system bus and parsed two objects including one adapter; it made
no discovery or camera calls. The matching [probe source](../experiments/unifi_https_snapshot_lab/bluez_async_inventory_probe.rs)
is retained outside the experiment's automatic Cargo targets. Its SHA-256 was
`0d2e811c433e6ad9c678e2618bd174d6d4abe9681f3b608cac307a404bb3fa3d`.
Job `30098049032257902` compiled its Linux binary but returned wrapper exit 102
because that foreign binary was not accepted as a local Mac artifact. Its
terminal result was acknowledged and sources released. The compiled binary,
SHA-256 `67909dcd215fe7bc71bec17566dce31210e84be1ff380eb4c3db09a4df0daf50`,
was copied to the intended Linux host and independently hash-verified before
the successful probe. This is one untrusted snapshot, not authentication,
Bluetooth scanning, camera adoption, or a continuous inventory guarantee.
After that probe, the snapshot request was revised to set the D-Bus
`NO_AUTO_START` flag so a service that disappears after the name check is not
started by the request. The revised handshake source SHA-256 is
`6222596f3b1df6ff23882e4b917e37f8a92b570d9804e649f8a6381f3afcc8e7`.
Scoped packet fixture job `30098049032257906` passed six handshake and five
body-parser tests, with matching worker source hashes, terminal acknowledgment
and source release. Scoped async fixture job `30098049032257907` then passed
eight tests, with matching handshake, observer and test hashes, terminal
acknowledgment and source release; the observer SHA-256 was
`5aaccb765f61742805992cc4f3fc9fe0243dcaba03b23e3808c8d96f5a1aca87`.
The resulting async inventory probe was also run read-only on `ts1`: it again
reported two objects, one adapter and one skipped signal, with no discovery or
camera calls. Job `30098049032257908` built the Linux executable and then
returned exit 102 because it refused to download the Linux artifact onto the
Mac; sources were released and the result acknowledged. The binary was copied
to `ts1` and its SHA-256
`e162b2320fd760be1f0453855517e262d0ce9fd08429b8abb34e1a13b25ede29`
matched before execution. The probe source was unchanged from the earlier
async inventory trial. This still does not demonstrate camera discovery or
setup.

The current async frame reader accepts at most 8 KiB per complete message, so
a larger legitimate BlueZ inventory is refused rather than silently truncated.
Parsing is synchronous and structurally bounded, but its CPU work is not yet
separately charged to the task's CPU budget. The observer does not bind the
reply to an independently authenticated BlueZ owner and drops interleaved
signals; neither this snapshot nor an empty result establishes device absence
or continuous discovery coverage.

The standalone ObjectManager body parser passed a scoped Clippy invocation
with warnings denied on `trj` (`30098049032257910`, acknowledged and released).
The broader scope-filtered reference lint with `too_many_arguments` denied did
not pass: job `30098049032257912` reported an existing eight-argument method
in `unifi_direct/conversation.rs`. That failure is retained as a failure of
the broader lint scope, not attributed to or hidden by the BlueZ fixture.
A narrower `-D warnings` observer check also stopped before reaching the
observer: `30098049032257914` reported eight existing Clippy errors in
`fss-runtime`, with acknowledged exit and source release. Observer lint
qualification remains pending. A further `--no-deps` isolated check
(`30098049032257920`) reached the reference crate but failed because that
filtered harness omitted all users of `MeteredIo::runtime_context`, making
the otherwise used method appear dead under `-D warnings`. This is a harness
artifact and not a passing lint result.

The inventory parser and async owner were subsequently extended to retain
untrusted `org.bluez.Device1` paths as well as adapter paths, with payload-free
debug output. Scoped async job `30098049032257916` passed eight tests,
including exact preservation and debug redaction of a synthetic device path;
scoped packet job `30098049032257917` passed five body and six handshake tests.
Both results were acknowledged and source custody released. The worker source
hashes for the body parser, async owner and async tests were respectively
`07a246a724c7909dab5d9af49f2b27defac1f75ecfd78c9cfe4878742bc6bee6`,
`dfb65f2d194575e82b4c8503f87c23545a8988d4322d9ed5cb1b29b65f0c74be`, and
`06d6b177a0273bd15a09691f6148f90a5432dd9c7f4ba37cd7329a50d659a95e`.
The revised body parser also passed scoped Clippy with warnings denied on
`trj` in job `30098049032257919`, with matching source hash, terminal
acknowledgment and source release.

The [device inventory probe](../experiments/unifi_https_snapshot_lab/bluez_async_device_inventory_probe.rs)
used the revised task-owned path against `ts1`'s live system bus and reported
two objects, one adapter and zero cached device objects. It started no scan and
made no camera call; the zero is not evidence that no camera is nearby. The
source SHA-256 was
`ad334007a71b2c504d71162a0d56d8d15b7d0ad1348a40d1648b3fbe76ffc4e7`.
Job `30098049032257918` compiled its Linux executable, then returned exit 102
because the Mac rejected the foreign artifact. Its terminal result was
acknowledged and sources released. The binary was copied to `ts1` and verified
as `e78fc0c21323b26e210d6654b24cb3005da598ddc9870c7091482de5d5e3ad99`
before execution. A cached device path alone does not authenticate the device,
prove reachability, or authorize a connection or Wi-Fi setting.

The BlueZ `Device1.UUIDs` property is now retained as a bounded, untrusted
per-device claim. A missing property remains `None`, while an observed empty
list is distinct; case-insensitive service matching does not identify a device
or prove a current advertisement. A wrong property type refuses the entire
snapshot. The implementation follows BlueZ's documented
[Device API](https://bluez.readthedocs.io/en/latest/device-api/); the G3
Instant UUID noted by the separate UniFi BLE client is not established as a
universal camera identifier.

Scoped packet job `30098049032257921` passed seven ObjectManager body tests and
six handshake tests; scoped async job `30098049032257922` passed eight tests,
including a synthetic device/service claim and debug redaction. Both results
were acknowledged and source custody released. The worker hashes for the
body parser, async owner and async test were respectively
`2fdd0ddea6640b2de7888333a5b233a888f4d5794154a291e86ad753cfe636a5`,
`ee5ea55d7888b688ff4afce9cfce37745271aea4d63be0adf65c08fa7dd04582`, and
`69ee0b46a535cc716bab18f1d5bd4d2525840f5f36b1dd87249ee2f777041b0b`.
A separate build request (`30098049032257923`) was refused by the remote disk
reservation guard before compilation; its result was acknowledged and sources
released. The executable produced during the successful test job, SHA-256
`d312e1814444fdbcc780b4ac5234472b04dc0cefa5aed537ed1215ca851a8d6f`,
was hash-verified on `ts1` and ran the read-only task-owned inventory probe.
It saw one adapter and zero cached device objects, with no scan or camera call.
The real-bus run therefore did not exercise a physical device's UUID property.
The revised body parser also passed scoped Clippy with warnings denied in job
`30098049032257925` on `trj`, with acknowledged exit and released sources.

The packet code is now being extended to retain scoped `InterfacesAdded`,
`InterfacesRemoved` and `PropertiesChanged` signal bodies, including distinct
unchanged, invalidated and present service-list states. A restricted signal
header decoder and a caller-supplied sender/path scope dispatcher are also in
progress. These are not yet a subscription, a scanner or camera onboarding.
The first packet fixture request (`30098049032257930`) was interrupted by a
remote free-space telemetry deadline and initially retained source custody;
it produced no test verdict. Full signal-stream integration remains
unqualified. Two recovery attempts of the same wrapper
(`rchw-e779a461-63a0-4e37-8985-745f5f556c7d`) timed out waiting on the remote
source-authority lock; a later same-ID recovery returned delivery exit 137,
terminal acknowledgment and source release, while the daemon recorded exit
130. Neither exit is a test pass. No manual lock removal or replay was performed.
Independent signal-router test requests `30098049032257935` and
`30098049032257937` were both refused by the remote disk reservation guard
before compilation and have acknowledged terminal results with sources
released. A smaller, separate metadata-only `cargo check --tests` request
(`30098049032257939`) compiled the fixture and test targets on `vmi1264463`,
with matching source hashes, acknowledged exit and source release; it did not
execute the tests. A subsequent direct pinned-nightly `rustc --test` compile
(`30098049032257943`) used one codegen unit and a smaller compiler reservation
without changing the free-space floor. It succeeded with acknowledged exit
and source release. The resulting runner SHA-256 was
`d671efd5ea7731404f0c2ab046c7f733de7a4536804dab29af67b1154dd13a20`.
Executed directly on that Linux worker, three scoped routing tests passed and
the new incremental/redacted signal-header test passed; all other tests were
filtered out. Those tests use synthetic frames and do not resolve the retained
earlier job or prove a live BlueZ subscription. Scoped job
`30098049032257944` also passed Clippy with warnings denied for the three
source-matched packet modules, with acknowledged exit and source release.
After the interrupted older test was reconciled and its source custody
released, the same hash-verified standalone runner executed the nine
ObjectManager body tests on `vmi1264463`; all nine passed, including added,
removed, changed and invalidated synthetic signal bodies. These are scoped
fixtures, not a full-workspace run.

A separate [signal-header probe](../experiments/unifi_https_snapshot_lab/bluez_signal_header_probe.rs)
was built against the matching handshake source on `vmi1264463` using the
pinned nightly (`30098049032257947`, acknowledged and released). Its source
SHA-256 is `19891b434e2cfbf2bf00a38bc2e4d4830cfdcf66e89b6864fb70715572a581fb`.
The retained file is not an automatic Cargo target: the test fixture placed it
under `src/bin` with the matching handshake source at `src/dbus_handshake.rs`.
The Linux binary, SHA-256
`1c6ef43885c0af1722026ca30f89e766737fcab75b4970214ce8d81919cce324`,
was hash-verified on `ts1` and successfully decoded that bus's real
`NameAcquired` signal. This was a synchronous diagnostic, not a BlueZ device
signal, subscription owner, scan or camera call. The full async scanner and
onboarding path remain unimplemented.

The signal-header parser was then tightened to reject duplicate unknown header
fields as well as duplicate known fields. The updated packet source hashes are
`2b0bc9041d0fffbf1e5bd96cde9a0fc3bd0a30f814aacc3e57ff64cc58302903`
for the handshake/signal header,
`cf1bf8912b88859a69998f17f65a5662775550f789de2c3f7cb04ad49812b9b0`
for ObjectManager bodies, and
`9acb83d56789b71c103f4935084a17cb64c7d2cbea786153fa9d03d99f85645e`
for scoped signal dispatch. Pinned-nightly `rustc --test` job
`30098049032257948` compiled these source-matched modules with a one-codegen-
unit budget, acknowledged the result and released sources. The resulting
runner, SHA-256
`15a146676c8cf3ddefb68e5f706ac149135e0322f6a6caacd5a8047e419ad1b9`,
was run on the Linux worker: all 19 focused tests passed. They include
truncation, invalidation, scope separation, duplicate headers and single-byte
corruptions; they are not a full-workspace or live-discovery test.

The retained header probe was rebuilt against this exact handshake source by
job `30098049032257949` (acknowledged and sources released). Its binary SHA-256
`caa79e0304dd9a7188fdff5b305e53a57238783c4743d4467f4fbcc835690418`
was verified on `ts1` before it again decoded a real `NameAcquired` bus signal.
No Bluetooth discovery or camera call was made. The revised packet modules
also passed scoped Clippy with warnings denied in job `30098049032257950`,
with terminal acknowledgment and released sources.
A `cargo check --tests` request for all packet source files under the filtered
laboratory manifest was submitted as job `30098049032257951`; its result is
terminal without a check: source synchronization stalled for 120 seconds and
Cargo did not start. The result was acknowledged and sources released. The
local source comparison found all 42 packet Rust files byte-identical to the
scoped snapshot at submission, but the laboratory manifest and workspace differ
from the project. This is not a packet-crate compile or test pass.

A separate immutable scratch export of all 42 current packet Rust source files
was then compiled as a test binary with the pinned-nightly `rustc --test`, one
codegen unit and the normal compiler disk guard (`30098049032257953`, terminal
acknowledged and sources released). A deterministic aggregate over source paths
and file hashes matched the project and worker:
`c7d7d06512d113668bb5acf2661a7b4727856df4e1300a72bcdb8194d83c2a7d`.
The resulting Linux test binary SHA-256
`0947b43f91df1c54846b73d25353379f76fff3f7b0d4735ecbebb87f88fc1dd5`
was executed on the worker, and all 37 included unit tests passed. This is
direct compiler and unit-test evidence for the packet sources, not the
project's Cargo manifest, integration tests, or full-workspace qualification.

The packet profile now prepares `GetNameOwner` and three fixed `AddMatch`
rules for BlueZ ObjectManager signals, property signals and BlueZ owner changes.
It validates the owner and object paths before constructing rules, rejects rule
injection, and parses correlated empty method returns with either an omitted
or empty signature. Preparing a rule has no effect; sending `AddMatch` creates
a connection-scoped subscription and needs an authorized session owner.
Pinned-nightly compiler job `30098049032257957` built a source-matched test
runner and released its sources; the runner passed all 21 focused packet tests
on `vmi1149989`. The handshake source SHA-256 was
`1bcd46a0235187282a98b4143d0a25d40ca9ad458d29843b4d74f5840237aa35`
and the runner SHA-256 was
`1871e17414f5b6b556248520802c3ae44248862ba84f4cd0659963dec9461966`.

A [short-lived bus subscription probe](../experiments/unifi_https_snapshot_lab/bluez_subscription_probe.rs)
was built with the pinned compiler in job `30098049032257960` (acknowledged and
sources released). Its source SHA-256 was
`02a79b991a07fdd152ad83d96044e9baebd4d515ba3a2993becac08314ecb1b1`;
like the earlier probe, it was compiled in the isolated fixture layout. The
binary SHA-256
`da8eb100e8da1a7646cbb9922f3ba347d4d004c9927a8f86f2d687c98ddb1aff`
was verified on `ts1`, where it resolved BlueZ's owner, received successful
replies to all three subscriptions and rechecked the owner before closing the
bus connection. One unrelated bus signal was observed. It did not start
Bluetooth discovery or call a camera. This synchronous diagnostic does not
provide a production session owner, continuous event coverage or onboarding.
The `trj` recorder was active
during this work, but load rose above
120 and a one-hour journal query timed out, so this is not evidence of recent
recording continuity and no additional workload was intentionally sent there.

The packet-only subscription fixture also passed scoped `cargo clippy --offline
-j 1 --lib -- -D warnings` in remote job `30098049032257965`; its terminal
result was acknowledged and its source lease released. This is a lint result
for that isolated fixture, not the full workspace or the asynchronous owner.

The reference adapter now contains an experimental task-owned `Watch` session.
It resolves a unique BlueZ owner, installs owner-change, ObjectManager and
property matches, checks the owner again, and retains bounded validated changes
interleaved with subscription replies. The caller owns the stream until it
drops the session. Revocation, cancellation, owner changes, malformed or
out-of-scope signals, queue exhaustion, and timeouts retire the stream; a
partly read frame cannot be retried as if no gap occurred. This does not take
an initial snapshot, start a Bluetooth scan, identify a camera, or implement
provisioning. A bounded [asynchronous watch probe](../experiments/unifi_https_snapshot_lab/bluez_async_watch_probe.rs)
was compiled in a source-matched, isolated remote fixture. Job
`30098049032257976` passed all 12 bus contract tests; its terminal result was
acknowledged and its source lease released. The tests include interleaved
changes, an owner-change notification, a 33-event overflow, policy revocation,
and a timeout after a partial frame. The bus source SHA-256 was
`2ebcfc85737366d6cb1608b2b0d8fb3fbe892506f76843cd65ff8e8b9daefd31`.
The resulting probe binary SHA-256
`d656d4af4e669ba8622427ac75b4f967f19bc76338fc72a927625d0ae8bc4549`
matched on `ts1`; there it successfully opened the task-owned subscription and
retired after the bounded wait returned `Interrupted`. No actual BlueZ device
event arrived in that short window. It did not start a scan or call a camera.
These observations do not demonstrate complete event coverage or onboarding.

The task-owned watch can now request an inventory on the subscribed connection,
addressing its independently resolved unique owner and requiring the reply's
sender to match. It retains changes received before the inventory reply and
reports their count as overlap; callers must reconcile them rather than assume
they occurred after the snapshot. Job `30098049032257977` passed 13 scoped bus
contract tests and released its source lease. A hash-matched `ts1` probe observed
one adapter, no cached devices and no overlapping changes. This is not evidence
that no cameras are nearby.

The experimental discovery handle prepares explicit start and stop calls on a
caller-admitted adapter and requires a correlated reply from the selected
unique owner. It treats unconfirmed effects as `DiscoveryUncertain`; dropping a
handle or cancelling an operation is not proof that BlueZ stopped. The owner
must explicitly stop an acquired session. Job `30098049032257979` passed 14
scoped tests. A later equivalent source snapshot passed the same 14 tests in
job `30098049032257981` with acknowledgment and source release. On `ts1`, a
probe first refused to start because its adapter allowlist named the wrong
interface; it then started and immediately stopped an authorized scan on the
correct adapter. The adapter reported `Discovering: no` both before and after.
This confirmed the two method replies, not receipt of a device event or camera
discovery. The rejected attempt did not start a scan.

The packet handshake changes separately passed all 11 source-matched direct
pinned-compiler unit tests. Cargo job `30098049032257978` was refused at disk
admission and did not run; the disk guard was not changed. Job
`30098049032257980` compiled the Linux diagnostic remotely, but its wrapper
returned 102 when it refused to import a Linux binary into the macOS target
directory. The binary used on `ts1` was separately copied and hash-verified.

The discovery handle can also read changes while a scan is active. An idle
deadline keeps the session only if no frame bytes were consumed; a deadline
after a partial frame or a revoked adapter grant reports an uncertain scan
outcome. Adapter authority and bus authority are checked at every transport
poll. Job `30098049032257986` recompiled the exact sources and passed all 15
bus tests, including the idle, partial-frame and adapter-revocation cases; its
terminal result was acknowledged and source lease released. The bus source
SHA-256 was `39f6b059be6eb40c1b096fc26a923f90c6ed9d66eecb0866692faf35393165cd`.

The [bounded live scan probe](../experiments/unifi_https_snapshot_lab/bluez_async_scan_probe.rs)
was compiled in the same isolated fixture and its binary SHA-256
`6a9111c5d0e1a9b86b0fad35896ceba34a6a6c5c0333553e492440f9a50bfb5b`
was matched on `ts1`. It started discovery, processed 32 scoped changes
(31 on device interfaces), then stopped after reaching its event cap; the
adapter reported discovery off afterward. None of those changes claimed the
single candidate service UUID used in the probe. The candidate is illustrated
by the [UniFi BLE client](https://github.com/zerotypic/unifi-ble-client), but
service UUIDs vary by model and a claim is not device identity. This bounded
scan did not prove that the owned G4 is absent or detect that camera, and it
did not contact or configure any camera. The 32 changes are events, not unique
devices. It does not implement continuous discovery or automatic onboarding.

The experimental Asupersync 0.5 TLS server previously stalled when its
underlying writer needed an explicit flush before accepting more ciphertext.
The [buffered transport regression](../experiments/unifi_tls_05_server_lab/tests/buffered_transport.rs)
reproduced the timeout before the fix. After the drain-loop change, all three
bounded-buffer tests passed, including an independent OpenSSL client and a
permanently blocked writer; two existing task-owned OpenSSL trust controls also
passed. See the [TLS laboratory record](../experiments/unifi_tls_05_server_lab/README.md)
for source hashes and precise qualification limits. This fixes an observed
loopback failure, not the unexplained physical G4 controller timeout; provider
admission, entropy authority and direct recording remain open.

The new `unifi_direct::bluez_registry` projects a no-overlap subscribed
inventory and ordered scoped changes into at most 128 path claims for one
adapter. Caller-selected candidate UUIDs are matching policy, not a complete
model list. An absent or invalidated service list is unknown; a removed
interface is only a removal claim. Wrong-owner, inconsistent, malformed or
overflowing changes invalidate the projection, and an externally detected
session gap must be passed to `mark_gap`. Snapshot overlap is refused rather
than replayed as if it happened afterward. It does not authenticate devices,
persist a discovery history, supervise the watch, or provision cameras.

Remote job `30098049032257994` recompiled the final reducer and passed its
three scoped tests, including raw signal add/change/remove, wrong-owner and
malformed-path cases. Job `30098049032257996` passed the 15 bus integration
contracts; both terminal results were acknowledged and source leases released.
The reducer source SHA-256 was
`03d3a9d891599b072f4a128899e409f3f6104dd8d2ca96e517f8e7e8e2be08d6`.
The corresponding probe binary SHA-256
`3925ae005dba44e4d7e47786a73e2862b6206488ccd08d94e17602d73b9e88eb`
matched on `ts1`. Its capped scan processed 32 events into 30 distinct path
claims, with no reported projection gap and no match for the one candidate
UUID; it received an acknowledged stop and the adapter reported discovery off.
No camera was contacted or identified. Counts are bounded claims in one scan,
not a census, a negative detection, or durable evidence.

The task-owned `unifi_direct::bluez_monitor` now holds a scan and registry
together. It obtains a baseline on the subscribed connection, refuses a
snapshot with overlapping changes before starting the scan, updates the
projection on received changes, and marks the retained registry gapped when
the monitor stops or observation fails. On a projection error it attempts a
stop and distinguishes an acknowledged stop from uncertain cleanup. An idle
window leaves the monitor active. Dropping a future can still interrupt an
active scan without an acknowledged stop, and unread events can make the
last processed claims stale. The monitor does not authenticate a camera,
provide a durable scan supervisor, reconnect automatically, or provision one.

Job `30098049032258015` passed all 16 scoped bus/monitor contracts, including
refusal before scan-start on overlapping inventory, retirement of a candidate
claim, projection-error cleanup, and partial-frame uncertainty. Job
`30098049032258014` separately passed all three registry unit tests. Both
terminal results were acknowledged and sources released. The monitor source
SHA-256 was `40aff5dc7b2d84062ad5405494a3c7b0da5bab1a864ec3cf6c6744b07cae344c`.
The matching live probe binary SHA-256
`80792636f342dd861c0616412b944a23c892d2df632da89e182b9e07bc499363`
was verified on `ts1`. Its capped scan processed 32 events into 30 path
claims, with no reported projection gap and no matching claim for the one
candidate UUID. Stop was acknowledged and discovery was off afterward. The
probe neither contacted the camera nor proves any device was absent.
