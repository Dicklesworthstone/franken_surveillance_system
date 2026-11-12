# UniFi TLS server on Asupersync 0.5: isolated experiment

This laboratory drives a `rustls` server state machine over an Asupersync 0.5
`AsyncRead`/`AsyncWrite` transport, so the workspace's existing task metering
and WebSocket owner can be exercised without enabling the runtime's `ring`
TLS feature or changing the workspace's dependency versions. The server
adapter and `rustls-pure` provider are experimental; this crate is not an
admitted FSS dependency and must not be deployed as a camera service.

The standalone trial has an experimental managed archive mode selected by
`--lab-owned-archive --lab-managed-archive` in that order. It prepares up to
eight successor generations; its journal and pin locations share the archive
host and do not establish independent durability. The optional
`--lab-av-history-records=5` forces a small capacity boundary for controlled
tests; it is not a production setting. The archive inspection command assumes
default history limits and does not support inspection of these small-limit
test archives. The trial is bounded and does not establish unattended restart
recovery, 30-day retention, or physical-camera handoff.

`--lab-inband-avc` (after the managed flag, when present) selects the explicit
`avc3` profile for an owned archive. It preserves repeated parameter sets only
when they match the original configuration; changes still refuse. The saved
G4 clip replay required a test-only timestamp adjustment and synthetic audio;
video-only bootstrap and a physical direct-camera session remain unproven.

The handshake future owns its transport and drops it if interrupted. The
adapter bounds work per poll and plaintext buffering, and retains partial TLS
records inside rustls. Its current handshake drains outgoing records before
reading more data; arbitrary full-duplex backpressure and buffered transports
are not qualified. Fatal-alert delivery, full cancellation behavior, server key
custody, client authentication, entropy authority, provider security and the
complete dependency closure remain open. Rustls' provider accesses OS entropy
outside the FSS task boundary. A same-provider fixture is not independent
interoperability evidence.

## Buffered transport regression

The earlier adapter could park forever when its ciphertext writer became full
and needed an explicit flush before accepting more bytes. A disposable TLS
loopback reproduced the failure: the original adapter timed out at the
700-millisecond handshake limit after one blocked write and zero completed
flushes on its 32-byte transport buffer.
The drain loop now attempts a flush when a ciphertext write parks and retries
that write once; if it is still pending, it preserves the write's wake
registration instead of looping on an immediately ready flush.

On `vmi1264463`, strict-remote job `30098049032258006` compiled the scoped
fixture; its terminal result was acknowledged and source lease released. The
three ignored tests were explicitly executed with a disposable certificate and
key: a same-provider client crossed the full buffer and exchanged application
data, an independent OpenSSL client did the same, and a permanently blocked
writer parked without spinning. All 3 passed. The separate task-owned
OpenSSL trusted-server and wrong-CA controls also passed 2/2 after compilation
in acknowledged, released job `30098049032258002`. The buffered tests use a
purpose-built transport and do not themselves exercise FSS task authority.

The adapter source SHA-256 was
`5dc8e6cda63d9ed3a7ddc2cdd4422ba2874aa27e8de6cf87d142ce570631e7ee`;
the buffered test source SHA-256 was
`4acff81a2092bf15453e7adccc1f8cdf0e7e564be2569bb29d3c13963c626b14`;
the corresponding Linux test binary SHA-256 was
`e16f735e695e314869b64b5a45e58e3c91fd39af01a37b87a253b7d101a93b90`.
The isolated fixture does not qualify the entire workspace, arbitrary
full-duplex backpressure, the provider, or a physical camera. No camera or
recorder was contacted or changed for this regression.

The task-owned session fixture now also wraps its metered transport in a
32-byte buffer. It verifies that the journal-backed hello response itself
encounters backpressure and is delivered through the TLS and WebSocket stack.
On `hz2`, all **5/5** ignored session tests passed with a disposable
certificate, including the new case and the interrupted-write fence. The
scope-filtered build was job `30098575685845511`, acknowledged with source
release; the test binary SHA-256 was
`b35667dbf3ea7a31e3716637ebcf255e2c805492dd99a2a0c3982e1c19ec525a`.
As a negative control, the earlier drain behavior was restored only in the
isolated fixture: the same new test timed out during TLS startup. Control job
`30098575685845517` initially returned 102 during artifact transfer; same-ID
recovery returned exit 0, acknowledgment and source release. Its test binary
SHA-256 was
`298b8ce45745b1438ce80dd2505f5453b0a3f7ee9cfbb6e0514c278c70d344b3`.
The fixed source was restored and rebuilt in acknowledged, released job
`30098575685845521`; all five tests passed again with the same fixed binary hash.
The initial build `30098575685845500` failed before tests because the reduced
fixture tried to compile an unrelated excluded ONVIF-dependent binary. The
rerun disabled automatic binary targets only in the fixture manifest. Test
and helper source SHA-256 values were
`7b2f88be2de878ba1f0f876e7b5f871153b65c9cdf5eac87c4ac2b31faa9f403` and
`a2485555ad99e8e5033d3b58656e31ca887f915b64a85ae40b8595315db16c7a`.
This remains synthetic, same-provider evidence and does not establish a native
physical-camera session, ongoing recording, or production TLS admission.

## Media before settings reply

The trial's opt-in `--media-before-reply` mode supervises controller messages
while accepting the media connection. On `vmi1152480`, the independent
`media_before_reply_fixture.py` loopback peer exercised the built trial with
disposable TLS keys and synthetic AVC. It required a clock reply before
opening media, then tested both an early settings reply and no reply. Both
cases produced an MP4 from which FFprobe read three H.264 frames. The exact
binary and fixture hashes, scoped Rust contract results, and remaining
qualification limits are in the [UniFi reference notes](../../docs/UNIFI_DIRECT_REFERENCE.md).
The updated fixture also closes the peer after the settings reply and clock
exchange but before media: the controller reports the retained startup trace
and a reconciliation obligation, and produces no clip. All three cases passed
on the prior source-matched trial binary as detailed in those notes. A fourth
case now sends a synthetic smart-detection event while media is flowing. It
checks the event diagnostic is present, its private test payload is absent,
and the clip remains decodable. All four cases passed on the updated binary;
the event case failed on the previous binary. This is not a physical-camera test.
The next revision adds two pre-hello event cases: one delivers the retained
event after startup, and the other closes before media and verifies explicit
omission accounting. All six cases passed on the source-matched inbox revision;
exact build and fixture hashes are in the reference notes.
With the explicit `--reply-events` option, which requires
`--media-before-reply`, the trial also answers requested events before hello,
while accepting media, and during streaming. It uses separately authorized,
journal-backed operations and preserves startup events without replying twice.
The option is off by default. The expanded loopback fixture passed ten peer
scenarios and one command-line rejection check; seven cases produced clips
with three independently probed H.264 frames each. The remaining peer cases
verify close or reply-denial behavior and produce no clip. The detailed build
identity and scope are recorded in the reference notes.
Run the peer only with a Linux trial binary and the synthetic AVC fixture:

```text
python3 experiments/unifi_tls_05_server_lab/media_before_reply_fixture.py TRIAL_BINARY crates/fss-packet/tests/fixtures/avc/baseline.264
```

The loopback result does not establish physical camera identity, successful
controller handoff, continuous recording, or settlement of a camera effect.

## Finch interoperability laboratory

[`finch_interop.py`](finch_interop.py) runs the independently developed
[Finch synthetic camera](https://github.com/rjmotion/finch) against a supplied
Linux trial executable on IPv4 loopback. It requires clean checkouts at Finch
`97c338adda3d6f9cfa35703c464826c37c12d63d` and pyunifiwire
`ab424de6426826a9fba4cab7b5e20684355fea66`; these Python projects are test
oracles, not production components. The runner creates private disposable
credentials and retains its logs, journal and clip in a private temporary
directory. Do not point Finch at an actual controller for this fixture.

Finch's original pusher sends HEVC; the trial currently requests AVC and
explicitly refuses that HEVC video. For an AVC test only,
[`finch_avc_shim.py`](finch_avc_shim.py) adapts the synthetic elementary
stream and video-tag bodies to AVC. Finch still supplies the TLS client,
WebSocket and control conversation, metadata and extended-FLV framing. The
adapter expects an Annex B synthetic source with one slice per frame and uses
only loopback. Optional synthetic audio is 16 kHz mono AAC-LC in ADTS; the
adapter inserts the audio tags and marks metadata accordingly. This is a
single-stream test adapter, not an upstream Finch feature. The emulated device
is a G5 PTZ, not a G4 Instant; its metadata names video2 even when the test
source has 2K dimensions.

On `ts1`, an older Linux trial binary with SHA-256
`9fae565ed95723ab3d47e0276297d3f81e75176fcbe12e1d45feefea2e401674`
accepted the adapted Finch connection and assembled a 2688 × 1512 synthetic AVC
clip. The trial reported three decoded frames; FFprobe independently counted
15 H.264 frames and FFmpeg decoded the clip. A subsequent 30-fps-source
AVC/AAC run produced 30 video frames and 14 AAC frames, both decoded by
FFmpeg; its video reports `1000/33` fps and a 0.99-second duration because
Finch's test sender uses 33 ms timestamp steps. An unmodified Finch HEVC run
was refused with `UnsupportedVideo` and produced no clip. The
conservative-framing 30-fps-source AVC/AAC and HEVC cases were retained at
`/data/tmp/fss-finch-interop-6d0qs26c` and
`/data/tmp/fss-finch-interop-zieo7j24` on `ts1`. The respective runner
SHA-256 values were
`317cd4783520ba5aeb083f7698874b7746b5657faedba27f27d3b2b5fa9a6a2b` and
`c3695d146258b9f63b2a1aecbb09e77e6c679ec4ddda286e02d5eb489e495f31`.
The AVC adapter SHA-256 was
`ec35e2e3256deaa77cfad4efe73dbb8f819134ddb336d9ba23b255d719b59d5b`;
the adapter also refused a non-loopback destination. A separate parallel
video-only run with the conservative search refused `Framing(BufferLimit)`
without a clip (`/data/tmp/fss-finch-interop-7gd80n2k`); the cause has not
been established. That source's largest AVC picture NAL was 136,769 bytes,
below the 1 MiB framing buffer configured by the current trial source; the
older binary's exact source and the reason for its refusal remain unverified.
One video-only and one A/V case using the explicitly selected
zero-stream-ID assumption passed; that is not proof the buffer-limit failure
is fixed or that the assumption applies to every physical source. The 2K source SHA-256 was
`6a24658b6cb786cee74343eafc5adfb1fe812341686786e6eea369770ed763ff`.
The 30-fps 2K source SHA-256 was
`566f9ed19480010fe1791d12de93d3f248f841e438826cdad96725270b460bcb`.
This is independent control-protocol and adapted synthetic media evidence for
that older binary only; it is not a physical-camera capture, production TLS
qualification, media authentication, continuous recording, or settled effect.

A subsequent full-dependency build of the current source at base
`a978d5dd1bbfdfbba254ced7df493c4f9a73bbcc`, with the eight changed UniFi
source files explicitly overlaid, completed Cargo compilation in strict-remote
job `30103800983322934` on `vmi1264463`. The job was acknowledged and its
source and pair released. The wrapper returned 102 because RCH correctly
refused to transfer a Linux executable to the macOS host; this is not a
successful wrapper result. The source-matched Linux executable, SHA-256
`99200eb5bb3833a22c29114b0708440739e2f39a1f0cb41ec6ac3eca751e5760`, was
copied within the worker to a private directory and run directly there.
The runner selected channel 1, and both the Rust trial and Finch reported that
selection. A video-only case produced 30 FFprobe-counted 2688 × 1512 AVC
frames; an A/V case produced 30 video and 15 AAC frames, independently decoded
by FFmpeg. The latter's synthetic sender-clock hypothesis reported audio and
video both starting at zero; physical synchronization remains unverified. The
retained cases on that worker are `/data/tmp/fss-finch-interop-8uh07tg5` and
`/data/tmp/fss-finch-interop-cbilwt21`. The A/V case used runner SHA-256
`317cd4783520ba5aeb083f7698874b7746b5657faedba27f27d3b2b5fa9a6a2b` and
adapter SHA-256
`191788720ef80ba2656ceb818c22ea5e5d85a981458d66edbad27d1967b50dcb`.
The preceding adapter sent the first audio packet before the first video
packet at the same timestamp; in that separate case the trial reported a
64 ms audio offset and retained 14 audio frames. This ordering difference is
not proof of the behavior of a physical G4. The current-source case uses the
same experimental TLS and leaves its simulated effects for reconciliation;
it does not resolve the earlier conservative-framing refusal or establish
continuous recording or an independently authenticated live camera.

The trial's prior 1 MiB framing buffer was smaller than the 4 MiB tag limit it
configured. A separate Finch case used synthetic 2K AVC
whose picture NALs were 2,523,035, 2,347,779 and 2,646,761 bytes; the earlier
source-matched trial rejected it with `Framing(BufferLimit)` and no clip. The
source SHA-256 is
`58ac99834c0616a2dc382440b601ea8b2d9bed065e42a82708b84d73730673ce`;
the retained negative case on `vmi1264463` is
`/data/tmp/fss-finch-interop-1n5xywv6`. The trial now derives a finite buffer
size from its exact FLV header, trailer and maximum-payload bounds. Separate
parser contract tests cover both a maximum-size tag after the maximum trailer
and an incomplete earlier candidate that cannot be resolved in a 1 MiB
buffer. Strict-remote job `30103800983322953` passed all 12 framing tests,
with terminal acknowledgment and source/pair release; overlay fingerprint
`8334eebc7a2afe1ecc34932fd2239d0d15927eeea3764b548e9e429b7ac3d79e`.
The subsequent full-dependency trial build in strict-remote job
`30103800983322957` completed Cargo compilation and acknowledged/released its
source and pair. Its wrapper returned 102 because RCH refused the Linux-to-Mac
artifact transfer. The Linux trial, SHA-256
`08eb6b6bbb632ef4338e6849ca1fc948ec027e58a4644b4547a9833313f71d35`,
was copied privately within the worker and tested against the same retained
large-picture source. It assembled a two-frame 2688 × 1512 AVC clip, both
decoded by Rust and FFmpeg, where the prior binary had refused. A separate
30-fps-source 2K AVC/AAC case produced 30 video and 15 AAC frames, decoded by
FFmpeg. These cases are retained at `/data/tmp/fss-finch-interop-16h2kguj`
and `/data/tmp/fss-finch-interop-4resyh05` on `vmi1264463`. They used runner
SHA-256 `005de835402542cbcfa5b9ea02eafd807e356c056d983d72db0846d7010da975`
and adapter SHA-256
`191788720ef80ba2656ceb818c22ea5e5d85a981458d66edbad27d1967b50dcb`.
The exact size mismatch is fixed for this bounded trial; this does not establish
the cause of the earlier small-picture failure or qualify a physical camera,
continuous recording, effect reconciliation, or production TLS.

The independent Finch fixture now also drives three consecutive segments
through the same current-source binary on channel 1. A single 2.97-second 2K
clip contained 90 H.264 frames and 46 AAC packets, all decoded by FFmpeg.
FFprobe reported a zero-based 33 ms step for every video packet and 64 ms for
every audio packet across both segment joins. FFmpeg-decoded frame digests
matched all 90 frames against the 60-frame looping synthetic source, and all
46 AAC packet bodies matched the 33-packet looping synthetic input. The
comparison checks rejected a wrong video source, wrong audio source, and wrong
video cadence as negative controls. The retained case on `vmi1264463` is
`/data/tmp/fss-finch-interop-x0y4u4iy`; the runner SHA-256 is
`6e9dccb200870b837c038c20e1d3db2ccb17e6be214ab716789d10eaa6868839` and
the trial and adapter hashes are unchanged from the preceding paragraph.
These checks establish neither physical capture timing nor sustained recording:
they exercise a bounded, simulated controller session, one short source loop,
and a single in-memory clip with effects still requiring reconciliation.
At the trial's maximum of eight segments, the same checks passed on a
7.92-second video: FFprobe counted 240 video frames and 124 AAC packets; all
240 decoded video frame digests and all 124 AAC packet bodies matched the
looping synthetic source, and both packet timelines had the expected cadence.
The trial decoded 24 selected video frames itself. The retained eight-segment
case is `/data/tmp/fss-finch-interop-2joid4fy` on the same worker. It still
omits original source bytes and reports its simulated effects unsettled.

For example, generate a synthetic one-slice AVC input, then run the fixture
with a pinned experimental binary and the clean checkouts:

```text
ffmpeg -f lavfi -i testsrc2=size=2688x1512:rate=15 -t 2 -threads 2 \
  -c:v libx264 -profile:v baseline -pix_fmt yuv420p -preset ultrafast -crf 32 \
  -x264-params keyint=15:min-keyint=15:scenecut=0:repeat-headers=1:aud=1:slices=1 \
  -f h264 synthetic-2k.h264
python3 finch_interop.py --finch /path/to/finch --wire /path/to/pyunifiwire \
  --trial /path/to/unifi_direct_trial --source synthetic-2k.h264 \
  --codec avc --width 2688 --height 1512
```

On a newer trial supporting `--video-channel`, pass `--channel 1` to request
Finch's high-resolution channel and check both peers observed the selection.
The older binary used in the result above does not accept this option.

For the independent HEVC refusal control, supply a synthetic Annex B HEVC
source and `--codec hevc`; the expected result is refusal without a clip.
To exercise A/V, generate synthetic ADTS with `ffmpeg -f lavfi -i
anullsrc=r=16000:cl=mono -t 2 -c:a aac -b:a 24k -f adts synthetic.aac` and
add `--audio-source synthetic.aac`. `--framing zero-stream-id` selects an
explicit laboratory assumption; the default remains conservative. To test
another input cadence, make the source at that cadence and pass `--fps`.
For a synthetic three-segment 30-fps input, add `--fps 30 --channel 1
--segments 3 --min-video-frames 90 --min-audio-frames 40 --check-cadence
--compare-video-source --compare-audio-source`. The source-comparison options
are limited to 1,000 frames or packets and expect the fixture's looping input.

The optional `--lab-aac-config=HEX` argument derives a two-track clip
from completed video segments and AAC records within them.
`HEX` is a caller-supplied two-byte AAC-LC AudioSpecificConfig; its source and
connection epoch are unverified. This laboratory mode places the first audio
sample using its sender timestamp relative to the first video decode timestamp,
with a 5 ms audio clock tolerance and at most two seconds of initial separation.
This mapping assumes a shared sender clock. A separate synthetic segment test
and FFprobe check passed; the updated standalone trial also passed synthetic
10 ms offset checks with both AAC configuration modes. Three later passive
G4-derived replays matched the source sender-time offsets under a simulated
controller. Earlier camera-derived replays used the tick-zero mapping. None
establishes
physical audio/video alignment, completeness, or that the supplied configuration
belongs to the camera. Alternatively, `--lab-aac-source` uses an observed,
non-provisional in-band configuration received before video starts, binding it
to its original source record and claimed connection epoch. The original
record is omitted when this lab finishes; source identity and A/V alignment
remain unverified. Both modes refuse missing audio, a configuration appearing
inside the completed segment and timing violations rather than silently
producing a video-only clip. Source mode also refuses a missing or late initial
configuration. The default remains video-only. This is neither a continuous
recorder nor an audio setup procedure for a physical camera.

With generated 16 kHz mono AAC and synthetic AVC, the updated independent
loopback fixture produced an H.264/AAC clip; FFprobe identified both tracks and
FFmpeg decoded the audio. An in-band configuration case produced a separately
probed two-track clip; missing or late configuration and a second configuration
inside the segment were refused without a clip. Missing audio and a two-sample
timing violation were also refused. The current suite passed 35 synthetic CLI
and loopback checks, including sender-clock offset and excessive-skew cases.
These are results from a scope-filtered build. Build identities, earlier
fixture failures and limits are in the reference notes.

The opt-in `--lab-segments=N` requests one through eight segments in a single
clip (default one), maintaining the same A/V muxer across fragments. The output
is bounded to 32 MiB and is written only after all requested segments assemble;
an early EOF or a later audio clock violation is refused without a completed
clip. This is a bounded laboratory operation, not continuous recording or a
durable segment-retention service. Two passive G4-derived two-segment replays
decoded both tracks through a simulated controller and existing relay; they do
not establish a direct physical camera handoff or measured A/V synchronization.

`--lab-trailer16-av-flag` selects the existing strict 16-byte trailer
heuristic. It is an experimental diagnostic, not a general G4 setting. In two
passive replays using G4-derived media, this policy refused after the first
selected IDR; a later boundary-only observation showed a flag value of 2
where the heuristic expects 1. The reference implementation documents
variable-length trailers after large frames. The default remains the
conservative variable-length search, which also failed to produce a clip in
three bounded passive replays. A separate read-only diagnostic found an earlier
incomplete plausible candidate blocking a later complete candidate; this is a
specific reason to investigate, not a proven explanation for every failure.
See the reference notes for the synthetic boundaries and qualification limits.
`--lab-zero-stream-id` instead uses a conservative variable-trailer search
under an explicit zero-FLV-stream-ID profile. It remains a structural
heuristic; this profile is not established for every camera, and a zero-ID
earlier incomplete candidate still blocks. Do not combine the two framing
options. The default is unchanged. The prior trial passed 25 synthetic
checks. Three subsequent passive G4-derived replays under this profile each
produced an H.264/AAC clip with decoded video and audio. They used a simulated
controller, a synthetic start, and relay-supplied configuration whose epoch
and A/V alignment are unverified. They do not establish a native controller
handoff or continuous recording; see the reference notes for exact boundaries.

## Additional TLS fixtures

The ignored tests require a disposable localhost certificate and PKCS#8 key in
`FSS_LAB_CERT_DER` and `FSS_LAB_KEY_DER`; the OpenSSL controls additionally
require `FSS_LAB_CERT_PEM` and `FSS_LAB_BAD_CERT_PEM`. They must never use
camera credentials or a deployed controller's key.

On 2026-11-05, eight explicitly invoked tests passed on `hz3`: two drove the
full task-owned controller conversation and media pipeline over a fragmented
TLS 1.3 loopback (including a policy-revocation refusal); two used an
independent OpenSSL client with correct and incorrect trust anchors; and four
covered the owned hello reply, an interrupted ciphertext write, a silent-peer
timeout, and an untrusted certificate. The full-pipeline fixture decoded six
synthetic frames; the interruption retained its journaled effect. The same
provider was used at both ends of the controller fixtures, and the media stream
was a separate plaintext loopback, as in the tested protocol profile. No G4 was
connected to this adapter. The Linux normal dependency tree included
`getrandom` and did not include `ring` or `aws-lc`; this is not a complete
dependency or unsafe-code audit.

The Cargo.lock SHA-256 was
`0c1a49024c69b3084fc4fdba48b4c87cdba13058576a3600de58780853fa4a2c`;
the adapter source SHA-256 was
`3662e58d33e88f5f5687842ba1b39c5d5e908b29e31fcbb1e0b9be0176adb0a0`.
The full-pipeline, OpenSSL and owned-session test binaries had SHA-256 values
`d2ef01cbefa092a54257a10d8011296639d2daa9fecf342760c83890f8eb8737`,
`40756ba1b3013df01d0cf971d46116757949676b10a4469fee7861d3f427983c` and
`37864d9fd0c00b18ce99b952b02bf648edbd32b094102b9f4311b4f63823ce59`,
respectively. The lockfile, adapter and three test sources matched the worker
copies after the run. A test success proves only the stated fixture behavior,
not an authenticated real-camera session, native controller service,
continuous recording, or automatic enrollment.

On 2026-11-05 the full-pipeline fixture was extended through archive
publication and restart. After the encrypted controller exchange, the
synthetic media produced two segments; each received fixture-only capture
bounds, was committed through the source-linked archive, reopened from a
fresh deployment handle, and decoded into three frames. The separate
revocation case also passed (2/2 tests on `hz3`). The test's synchronous
archive calls are not a production worker; initial configuration/header and
retirement tails are not all committed as one continuous recording, and
fixture timestamps do not establish physical camera capture time. No camera
was connected to this fixture.

The integration-test source SHA-256 was
`7514ed1bc4fed8a6ca3a2a005975716ae215e90cd089fc260355c66294357a1f`,
the lockfile SHA-256 was
`5d51db4922594ee2722963d1ebf3c7548fbe84bfa939462879724e0df9516a59`,
and the executed Linux test binary SHA-256 was
`c1a4d03bca9ddaf2e48ff55304a2e967f1602629914af0ca6a56c4a596897d95`.
The initial remote invocation compiled but could not see the certificate
environment, so its two tests failed before execution; the same built binary
was explicitly rerun on `hz3` with disposable certificate paths and passed.

On 2026-11-05 the full-pipeline fixture was changed to supervise the
encrypted controller alongside the media pipeline. The synthetic client sent
part of its stream, requested a second time sync, and withheld the remainder
until the separately journaled response arrived. Two source-linked segments
were then published, the archive reopened, and six synthetic frames decoded.
The stream-authority revocation case also passed: 2/2 ignored fixture cases
were explicitly invoked on `hz4`. The first run failed during TLS handshake
because the disposable certificate was generated as a CA; a second run used
a leaf certificate. The encrypted management fixture uses the same TLS
provider at both ends and plaintext loopback media. Its synchronous journal
and archive work and synthetic capture bounds do not establish a production
controller, live-camera operation, or continuous recording.

The executed full-pipeline test source SHA-256 was
`ba789a167bfeddb51fb2ad1f0b437d9df6ee6d9ad0aa18dd1ad3f62217f3254f`
and its Linux test binary SHA-256 was
`ca0fdbbf545a10d1570a4544cb61c69dffe98ad85f7f08b2240b8e6d5d3dcc55`.

The later task-owned controller-listener integration passed both encrypted
fixture cases on `hz4`. The controller listener source SHA-256 was
`16c79d78c56e7620cd79265cde3e3cde92e62f288d76647a5c541fe5177746dc`,
the fixture source SHA-256 was
`3a8524d7f5f52aaaf414540d65bd144d2e70237c59b52057aa799b45e758117a`,
and the test binary SHA-256 was
`fb5339f8eb4767874d8720ca867b6d8ae4a2507312dbeb4ca76f18b2fbde839b`.
These are synthetic loopback results, not camera or release qualification.

A subsequent run passed three encrypted fixture cases on `hz4` with the same
admission gate applied to the raw socket, decrypted stream, and controller
session. The new buffered-data test includes an unguarded control that read a
byte already buffered by TLS after raw admission changed, followed by a guarded
case that refused the byte and stayed fenced after policy restoration. This
does not authenticate a camera, validate the TLS provider, or supervise the
separate media peer.

The latest joint-supervision run passed 4/4 task-owned cases and 3/3 encrypted
loopback cases on `hz4`. The added controller-revocation case retained the
received synthetic media prefix rather than emitting another buffered record.
The encrypted fixture source SHA-256 was
`951a862ad8468ebd684f918b5fc0761b94affb6af47f269c79fd434690a5bb0c`
and its test binary SHA-256 was
`5c344454279ccbc2eed4b891a0583671fc5da4cabce27367957459007ee1048a`.
No physical camera was connected in these tests.

## Bounded standalone trial

`src/bin/unifi_direct_trial.rs` is a one-camera laboratory executable. It
binds a caller-selected interface, admits an expected source address and MAC
claim, runs the experimental TLS/controller exchange and Asupersync media
pipeline, and writes one private, create-only MP4 after in-memory FSS decode.
It prints aggregate counts and explicitly reports omitted source bytes and
unreconciled camera effects. Its inputs include a local TLS certificate and
mode-600 private key. An optional Linux-only setup mode also reads an
owner-supplied camera certificate and private credential file, performs scoped
discovery, and can send one journaled controller-address handoff. That mode
must not be used against a working recorder until a separately verified
restoration path is ready. It is not continuous recording, automatic enrollment,
source custody, independently authenticated identity, or a production TLS
service. File I/O and effect journaling remain synchronous. The caller must
supply a private output directory and a new journal path; an interrupted write
may leave a partial clip or an unresolved effect.

Two process-level fixture cases passed on `hz4`: a synthetic camera negotiated
the control channel, sent media, and produced a private decodable clip; a
no-camera case terminated with the listener deadline and no clip. A stripped
Linux binary with SHA-256
`e9d8f2c09d22da8ec3d0d331e958e830105dfc7dd1008bd174469585792870f4`
was copied to `ts1`, where it bound the selected LAN interface and exited on
the expected one-second no-camera timeout. No physical-camera handoff or
native live stream was performed by that check.

A later owner-authorized physical G4 trial used a separate journaled Rust
handoff and an independently scheduled restoration check. The handoff readback
did not confirm the destination, and the direct trial ended with an unexpected
EOF before producing a clip. The original controller address was observed
again, the scheduled check completed successfully without an additional write,
and the existing recorder verified and uploaded subsequent segments. The trial
binary at that time did not report which connection stage encountered the EOF.
Stage markers were added and both synthetic process cases passed on `hz4`.
An independently protected physical retest then reported TCP acceptance,
followed by EOF during the experimental TLS handshake; it produced no clip.
The specific TLS incompatibility remains unknown. Its handoff readback was
also unconfirmed. A subsequent no-change observation and the scheduled
restoration check found the existing controller address again.

The trial uses the `rustls-pure` 0.15.4 provider, which offers TLS 1.3 and
ECDSA/Ed25519 server keys but not RSA. The reference
[UniFi Direct emulator](https://github.com/xuio/scrypted-unifi-direct/blob/main/src/emulator-tls.ts)
generates an RSA server certificate; it uses Node's HTTPS server. These are
material differences to test, not proof that either caused the G4 EOF. A
competing controller can also alter the camera's association during a trial.

A third owner-authorized, separately protected trial captured only the G4's
traffic to the temporary controller port (11 packets, zero kernel drops). The
camera completed the TCP handshake and then sent FIN before transmitting any
TCP payload; subsequent connection attempts received resets after the trial
listener had exited. Consequently, this trace did not contain a TLS
ClientHello and cannot determine the camera's TLS versions, signature
algorithms or certificate requirements. The camera again did not confirm the
handoff readback and produced no native clip. The existing controller address
was subsequently observed again. The limited private capture is a diagnostic
artifact, not camera-identity or recording proof.

After the listener was updated to allow bounded sequential accepts, the real
G4's reconnect completed both TLS 1.3 and WebSocket upgrade. The subsequent
management conversation rejected a correlated time-sync frame before hello;
answering that frame as a new request then exhausted the message limit. The
controller now ignores correlated time-sync replies and answers uncorrelated
camera requests. Three process fixtures and two targeted Rust controller
contracts passed remotely after one earlier process timeout; the fixture
exercises this ordering as well as the initial reconnect. In the next physical
attempt, TLS and WebSocket completed but the session retired with a transport
error while awaiting hello. There was no native clip. The existing recorder
reasserted its address near the attempt, but this is not proof of the cause.

In a subsequent isolated attempt, the dedicated single-camera controller was
temporarily stopped under independent recovery timers. The Rust listener saw
no camera connection before its deadline and the handoff readback did not
confirm the target. After the existing controller restarted, the camera did
not reconnect until rebooted, causing a recording gap. A fresh camera segment
was subsequently verified and uploaded by the existing recorder. The isolated
test does not prove the cause of the native failure.

Subsequently, the shared receiver began retaining payload-free transport
failure categories. Four process fixtures passed remotely, including an
encrypted client that sends an unmasked frame and observes the precise
retirement category. The separate five-test receive suite also distinguishes
that case from a connection reset without exposing the I/O error's text. These
are synthetic diagnostics and do not retroactively classify the earlier
physical failure. In a subsequent owner-authorized G4 trial with the new
diagnostics, the camera reconnected, completed TLS and WebSocket upgrade, and
the connection ended with I/O `UnexpectedEof` while awaiting hello. The handoff
readback did not confirm its target and no native clip was produced. This
does not establish the cause of the EOF or that the camera sent an unmasked
frame. The existing controller address was later confirmed without a write;
the existing recorder continued to upload verified segments.

The standalone trial subsequently retained its controller listener across an
early WebSocket `UnexpectedEof` in `AwaitHello`, but only if no management
effect had reached approval. The retry count and total startup deadline remain
bounded; other failures and any prepared effect stop for reconciliation. Five
process cases passed on `hz4`, four with encrypted camera sessions: the
synthetic camera reconnected after an early EOF and produced a decoded clip,
while EOF after a time-sync
effect stopped without retrying. The earlier generic retirement and unmasked
frame cases and no-camera deadline also passed. One initial fixture run used
an inappropriate CA certificate as a leaf and failed; the subsequent run used
an end-entity P-256 certificate.

In a later owner-authorized physical G4 attempt with this binary, the handoff
readback reported the previous controller address. The listener received no
camera connection before its deadline, so this attempt did not exercise the
new WebSocket reconnect path and produced no native clip. A no-change
observation subsequently confirmed the existing controller address. The
readback does not establish whether the camera ignored the update or another
controller reversed it. The independently scheduled restoration check found
the existing address and made no change; the one-shot recovery watchdog
abstained and created no reboot marker. Fresh recorder segments were verified
and uploaded after the attempt.

```text
unifi_direct_trial LISTEN_IPV4:PORT CAMERA_IPV4 CAMERA_MAC_HEX CERT_DER KEY_DER JOURNAL_DIR OUTPUT_MP4 CONTROLLER_UUID [WAIT_SECONDS] [--allow-correlated-timesync|--bounded-prehello-clock] [--media-before-reply] [--reply-events] [--reply-startup-requests] [--lab-aac-config=HEX|--lab-aac-source] [--lab-trailer16-av-flag|--lab-zero-stream-id] [--lab-segments=N] [--setup-camera=DISCOVERY_PORT,HTTPS_PORT,CAMERA_CERT_DER,CREDENTIAL_FILE[,chunked]] --owner-authorized
```

The key and clip can contain private material; use an owner-controlled private
directory. This lab does not supply automatic rollback. Do not redirect a
working camera until a separately verified restoration path is ready.

`unifi_controller_restore` is an experimental Linux recovery building block.
It accepts an explicit expected temporary controller and original controller,
requires two matching camera settings observations, and will not write if the
camera reports a third address. It can emit one journaled fixed-length or
chunked restoration request; an indeterminate effect is not retried. An
`--observe-only` mode performs no write or journal creation. The original
destination's identity and availability must be independently verified. A
disposable camera and an independent systemd timer have exercised these paths,
but a real-camera restore or reconnection has not been qualified.

```text
unifi_controller_restore CAMERA_IPV4 HTTPS_PORT CERT_DER CREDENTIAL_FILE EXPECTED_TEMP_IPV4 RESTORE_IPV4 NEW_JOURNAL_DIR [--chunked] [--observe-only] --owner-authorized
```
