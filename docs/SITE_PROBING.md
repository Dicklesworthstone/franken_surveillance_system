# Approved native site probing

`fss site probe` obtains one bounded AVC, HEVC or JPEG observation from an explicitly
selected RTSP camera or NVR channel, or an AVC/HEVC observation from a protected
UniFi Protect selection or protected historical ONVIF handoff. It uses the exact
selected literal peer, authority and permitted RTSP control subtree. An ONVIF
source keeps its management endpoint in the original manifest and independently
pins the RTSP endpoint in its binding. For direct RTSP/NVR sources, successful stdout is
a one-element array of `fss.site_probe_receipt.v1` objects, ready for
`fss site plan --probes`. Select `--output session` for the same receipt plus
native transport and exclusion evidence. UniFi and ONVIF receipts go to a new private file,
with a redacted result on stdout, as described below.

## Preview, review, then probe

First request a preview for a direct RTSP/NVR source. This reads the manifest
only; it opens no socket or credential file.

```sh
fss site probe --manifest /etc/fss/site.json \
  --source camera:front --codec avc \
  --media-index 0 --rtp-channel 0 --observe-frames 6 \
  --timeout-ms 10000 --json
```

The output is a [`fss.site_probe_plan.v1`](../schemas/site_probe_plan.v1.json)
object containing the route, selected codec/media/channel, credential reference,
observation budget and exact approval digest. Review those fields, then repeat
the same command with `--approve sha256:<digest-from-preview>`. For example:

```sh
fss site probe --manifest /etc/fss/site.json \
  --source camera:front --codec avc \
  --media-index 0 --rtp-channel 0 --observe-frames 6 \
  --timeout-ms 10000 --approve sha256:<digest-from-preview> --json
```

The placeholder must be replaced with the complete reviewed digest. A different
manifest, source, codec, media selection, payload, channel, observation count,
deadline, output selection or principal invalidates the approval before network or credential work.
The command never approves itself or retries the camera automatically.

`--codec avc|hevc|jpeg` and `--source` are required. Defaults are media index 0, RTP
channel 0 with RTCP channel 1, a minimum of six native picture groups, ten seconds, and
`principal:local-operator`. `--payload-type 96..127` optionally selects an exact
dynamic payload when SDP offers more than one; JPEG also admits static payload 26. Media indices are 0 through 63;
RTP channels are even values from 0 through 254. Samples allow a requested minimum of 3 through 64
native syntax-confirmed picture groups (or complete reconstructed JPEG frames) and 100 through 60000 milliseconds for the whole operation,
including connection, negotiation, authentication and remote close.

Probe sources one at a time. A default multi-source site plan requires one receipt
for every manifest source. To plan cameras as their probes become available, use
`site plan --source SOURCE_ID` (repeat for several sources) with exactly the
selected receipt array. Keep the original manifest unchanged so its probe
bindings remain valid. See [selected planning](SITE_PLANNING.md#plan-selected-cameras-without-changing-the-manifest).

Combine only successful one-element receipt arrays into the requested inventory.
A failed command returns an object, never a partial successful receipt array.
Save stdout only when the command exits successfully, and handle both previews
and receipts as private deployment metadata because they include exact routing
information.

## Optional measured node-clock evidence

Add `--clock-ntp-peer 127.0.0.1:123` (or another explicit literal loopback
endpoint) to request one basic-mode NTPv4 exchange with an already configured
local time daemon. The option, peer, limits and extra runtime reservation become
part of the preview approval. Preview still contacts no endpoint. Adding,
removing or changing this option requires the approval from the matching preview.

```sh
fss site probe --manifest /etc/fss/site.json \
  --source camera:front --codec avc --observe-frames 6 \
  --clock-ntp-peer 127.0.0.1:123 --output session \
  --timeout-ms 10000 --json
```

Review the returned preview, then repeat that exact selection with
`--approve sha256:<digest-from-preview>`. The command does not configure a daemon,
select an upstream time source, adjust the host clock or retry a failed exchange.
An unavailable or refused time source prevents camera connection and issuance of
a successful receipt. Omit the option for the existing behavior: no time-daemon
contact, no native wall-clock sampling, and no manufactured clock witness.

After approval, the existing owned runtime admits one 48-byte UDP request to the
selected loopback peer from an ephemeral local port. It accepts exactly one
48-byte reply, with matching origin timestamp, supported server mode/version,
valid timing and bounded offset/uncertainty. Kiss-of-death, unsynchronized or
pending-leap responses, unsupported extensions/MACs, malformed or oversized
replies, and an expired exchange refuse. No DNS lookup or remote NTP endpoint is
supported. The exchange has a one-second ceiling within the existing total probe
deadline; polling is bounded and shares the task's cancellation and authority.

The native owner brackets wall-clock samples with its process-local monotonic
clock around the exchange, before and after each probe processing step, and at
completion. Later samples must agree with both the synchronization origin and
the preceding sample. A sampled wall-clock step or monotonic regression refuses
the whole clock-enabled probe; a later apparently good sample cannot revive it.
Compatible samples do not tighten the original interval or renew its age.

The fixed profile admits at most 25 milliseconds for an individual host clock
read and 60 seconds from synchronization. Its explicit drift/slew assumption is
500,000 parts per billion (500 ppm). This is an assumption under which the
reported interval is computed, not a measurement of the oscillator. The result
includes asymmetric network-delay ambiguity, the daemon's declared root distance
and precision, outward-rounded host sampling brackets, drift growth, and the
whole step that first observed the RTP timestamp of the first confirmed picture.
The existing witness limit remains 1 nanosecond through 10 seconds of uncertainty.
Leap seconds and leap smear have no admitted mapping in this profile.

Successful receipts include both `clock_evidence` and
[`clock_observation`](../schemas/site_clock_observation.v1.json). The latter
retains the exact request/reply bytes, literal peer, bracketed host samples,
observation interval, terminal sample and fixed policy. The strict receipt parser
reconstructs the witness and requires exact equality; the receipt digest binds
this complete evidence. Old receipts without the extension retain their existing
canonical bytes. An old caller-supplied witness without a proof remains a supplied
claim and does not acquire native-observation provenance.

`--output session` also exposes a `utc_window` with the explicit basis
`first_picture_node_observation_plus_rtp_duration`. This anchors the existing RTP
cadence span to the node's processing observation. The processing step can
consume previously buffered wire: its bracket does **not** locate kernel packet
arrival, camera exposure, encoder buffering, or the last packet's actual arrival.
Parameter-only predecessor timestamps and later semantic picture confirmation do
not replace the first picture's own observation anchor. Camera/NVR and RTCP time
claims remain separate. The NTP reply is an unauthenticated local-daemon claim;
internal reconstruction is not proof of independently trusted UTC or continuous
absence of an unsampled clock step.

The same option is available on the existing protected UniFi/ONVIF probe path;
its full proof is written with the private receipt, through the existing
create-only writer. This probe functionality does not supply recorder heartbeats,
multi-segment retained-window mapping or a deployment-wide clock discipline.
Those broader VIT-019 requirements remain open.

## Probe a UniFi Protect source

Use the existing [site bindings](SITE_PLANNING.md#unifi-protect-site-bindings)
and [private Protect export](UNIFI_PROTECT.md). The manifest source keeps
`kind: "unifi_protect"`, its exact `unifi_camera_id`, peer and authority, with
no direct `presentation` or `control_root` fields. The binding selects the exact
quality and `published` or `operator-rtsp` endpoint. The selected endpoint must
be plaintext RTSP, and the source must explicitly allow owner-authorized
plaintext access. AVC and HEVC are supported; select the codec explicitly.

On Linux, preview one source with both `--unifi-bindings` and `--receipt-file`:

```sh
fss site probe --manifest /etc/fss/site.json \
  --unifi-bindings /etc/fss/site-unifi-bindings.json \
  --source source:front --codec avc --observe-frames 6 \
  --receipt-file /etc/fss/private/front-probe.json \
  --timeout-ms 10000 --json
```

The receipt path must be absolute, absent, and have an existing parent without
group or other write permission. It must be separate from the bindings, selected
export and credential files. Preview
reads and validates the bindings and selected protected export, checks the
destination, and creates no file. It contacts neither the camera nor the Protect
console and reads no credentials. The export uses the existing private-file
checks: a bounded regular file with owner-read permission, no group/other access,
one hard link, stable identity, and no symlink path.

The `fss.site_probe_plan.v1` preview's `presentation` and `control_root` fields
contain SHA-256 digests of the exact selected resource and control subtree.
Its `unifi` object reports the export digest and file fingerprint, camera
reference digest, view, quality, transport and private output destination.
`receipt_parent_identity` hashes the actual destination parent's device/inode
identity selected before camera contact. Replacing that parent while the probe
runs refuses receipt publication.
Stream capability paths and query strings stay out of stdout and command
arguments. The approval binds the complete original manifest, exact bindings
bytes, selected export bytes and file identity, camera/view/quality/transport,
unchanged route, codec and observation options, and receipt destination.
The destination parent's identity is part of that same approval.
Replacing an export with identical bytes requires a fresh preview because its
file identity changes.

Review that preview and repeat the same command with
`--approve sha256:<digest-from-preview>`. The export lease is revalidated before
network effects, throughout the bounded observation, and before receipt
publication. The default `--output receipts` is the only UniFi output mode;
`--output session` is refused. The file preflight and final writer each have a
separate five-second allowance. `--timeout-ms` bounds the native observation,
including its input and credential checks, connection, negotiation and TEARDOWN.
It does not include those separate file stages.

After successful native observation and acknowledged TEARDOWN, the command
creates a `0600` file containing the ordinary one-element receipt array. The
receipt retains the complete original UniFi manifest digest and exact selected
route. It can be passed directly to `site plan --probes` with the same manifest
and bindings; a site with several sources still needs one receipt per source in
its private combined array. There is no source-kind conversion or manual receipt
construction between probing and planning.

Stdout is `fss.site_unifi_probe_result.v1`, with the receipt path, receipt and
file digests, close facts and `receipt_saved`. The writer synchronizes and reads
back the created file and never overwrites an existing destination. A failed
write can leave a partial file, reported by `receipt_file_may_exist`; preserve
and inspect that outcome before choosing another destination. A completed write
followed by a late request-finalization failure retains `receipt_saved: true`
while returning a failure exit code. The result distinguishes that committed
file from an unsuccessful write; neither condition triggers an automatic retry.

## Probe an ONVIF source

Use an existing [protected ONVIF handoff and site binding](SITE_PLANNING.md#onvif-site-bindings).
The source retains `kind: "onvif"`, its original HTTP peer, authority and
`onvif_service_path`. The binding independently supplies the literal RTSP peer,
exact authority and permitted control subtree, plus the expected historical
onboarding-plan and profile digests. Stable Media1 AVC and indefinite Media2
AVC/HEVC handoffs are supported. The explicitly selected codec must agree with
the handoff and the subsequently observed native SDP and media syntax.

On Linux, preview one source:

```sh
fss site probe --manifest /etc/fss/site.json \
  --onvif-bindings /etc/fss/private/site-onvif-bindings.json \
  --source source:front --codec avc --observe-frames 6 \
  --receipt-file /etc/fss/private/front-probe.json \
  --timeout-ms 10000 --json
```

The binding inventory may contain only the selected source or other valid ONVIF
rows from the same manifest. Every supplied row is validated, but only the
selected handoff is opened. Duplicate, foreign, stale or non-ONVIF rows refuse.
`--onvif-bindings` and `--unifi-bindings` are mutually exclusive. A private
`--receipt-file` is required; `--output session` and JPEG are refused.

Preview reads the protected handoff and checks the absent receipt destination.
It contacts neither endpoint, reads no credential and creates no file. The
`onvif` preview section reports the handoff content and file-identity digests,
expected onboarding/profile, binding digest and destination-parent identity.
`presentation` and `control_root` contain only SHA-256 digests. The actual RTSP
peer and authority are visible for review and may differ from the ONVIF HTTP
endpoint. Known direct-route collisions and inconsistent physical-peer connection
limits refuse before any network admission; other ONVIF media endpoints remain
unknown until independently selected.

Review the preview and repeat the same command with its exact `--approve` digest.
Approval binds the complete unchanged manifest, original source ordinal, selected
profile, handoff content and actual file fingerprint, independent RTSP route,
codec, bounded observation and protected destination. Replacing a handoff with
identical bytes still requires a new approval. The handoff lease is revalidated
before and throughout native I/O and again before publication. The existing
manifest credential policy applies only within the separately approved native
RTSP request. There is no fallback to another endpoint or profile.

The same file-stage limits, acknowledged TEARDOWN requirement, create-only
`0600` writer and late-failure reporting described for UniFi apply. Successful
stdout uses [`fss.site_onvif_probe_result.v1`](../schemas/site_onvif_probe_result.v1.json);
the ordinary receipt array is written only to the private file. Feed that file
directly into the existing planner, retaining the original manifest and binding:

```sh
fss site plan --manifest /etc/fss/site.json \
  --source source:front --probes /etc/fss/private/front-probe.json \
  --onvif-bindings /etc/fss/private/front-onvif-binding.json \
  --archive-root /srv/fss/footage --pins-root /srv/fss/pins \
  --epoch 1 --stop-after-pictures 250 --json
```

For selected planning, the binding file contains exactly the selected source
rows; their original source and handoff values stay unchanged. This native probe
observes the approved RTSP endpoint. It does not repeat ONVIF HTTP discovery or
authenticate the historical handoff's HTTP origin. Both preview and result say
`binding_basis: "operator-bound-historical-consistency"` and
`onvif_http_origin_verified: false`. It grants no subsequent capture authority,
scene-liveness assurance, signed footage rights or continuous recording claim.

## What a successful probe establishes

The native owner performs OPTIONS, DESCRIBE, SETUP and PLAY over one bounded
interleaved TCP connection, then TEARDOWN after the requested sample. It composes
the existing RTSP client, exact-message intake, native TCP transport and strict RTP
observer. The same accepted DESCRIBE body supplies both media negotiation and the
receipt's SDP and parameter-set digests. Selected channels, payload and advertised
SSRC must agree with received RTP. The observed SSRC stays fixed; sequence numbers
must remain contiguous, the native AVC/HEVC assemblers must witness picture
boundaries, and timestamp increments must remain constant under explicit RTP
wrapping. Markers alone cannot create a picture. Field-coded configurations,
unsupported sequence syntax and changed parameter sets refuse the observation.

For JPEG, the same session owner uses the existing RFC 2435 depacketizer. Only a
complete reconstructed frame counts; an RTP marker without its ordered fragments
does not suffice. Fragment offsets, dimensions, type, quantizer mappings and
pending-frame lifetime must satisfy the native reconstruction contract. JPEG has
no external parameter-set digests. Reconstruction checks the transport/header
profile and does not decode or certify the entropy-coded pixels.

The picture target is a minimum: one RTP aggregation packet is processed
atomically and may confirm several groups, subject to the hard 64-picture ceiling.
The observer freezes only the confirmed prefix. A following unverified NAL group
or unfinished fragment is explicitly omitted and counted, without fabricated
EOS or an inferred omitted-frame count.

A receipt is released only after the matching successful TEARDOWN response and
local socket retirement. In-flight media on negotiated channels while closing is
explicitly excluded from the completed sample. RTCP is excluded from observation
and timing claims; the probe does not claim to validate excluded RTCP payloads.
Raw SDP, session tokens, media packets and credentials are not returned or retained.
The reference owner exposes bounded omission and transport counters to callers.
Server identity is an optional header digest, not an authenticated device identity.

The limits are fixed and approval-bound: at most 65536 driver steps and socket
calls, 8 MiB plus 256 KiB of total received wire bytes, and 64 KiB of sent requests.
The strict observer also limits selected RTP to 4096 packets and 8 MiB. Limits
never renew during negotiation or progress. The plan also binds the actual
codec/parser/assembly limit profile (including JPEG dimensions, fragments, pending
lifetime and quantizer cache), exact request/chunk/connect/response limits,
credential bounds, one-millisecond maximum wait, and the complete runtime
allowance. The runtime reserves 64 MiB of logical native working capacity and
4,194,304 metadata operations before effects; this is not a measured allocator or
RSS ceiling. Stable stream identities include the site and selected source, so
same-generation cameras do not share an ingress. No decoder, archive, discovery scan,
device configuration, PTZ operation or parallel source scheduler is invoked.

## Session evidence and integration

For direct RTSP/NVR sources, request the evidence projection in both the preview
and the approved invocation:

```sh
fss site probe --manifest /etc/fss/site.json \
  --source camera:front --codec avc --observe-frames 6 \
  --timeout-ms 10000 --output session --json
```

Review the returned approval, then repeat those exact selections with
`--approve sha256:<digest-from-preview>`. The output selector is approval-bound;
a digest reviewed for `receipts` cannot authorize `session`, or vice versa.
The stronger native policy also invalidates previews from the earlier
marker-observation implementation.

An approved session returns
[`fss.site_probe_session.v1`](../schemas/site_probe_session.v1.json).
Successful output has `status: "measured"`, one element in `receipts`,
the exact receipt digest, and a canonical `completion_digest`. Its
`receipts` member can be saved as the existing `site plan --probes` input.
JPEG reports use `measurement_basis: "native_rfc2435_whole_frame_reconstruction"`;
AVC/HEVC preserve their existing `native_rtsp_picture_syntax` basis and approval
bytes. JPEG has a distinct approval policy that explicitly excludes entropy decoding.
The default `--output receipts` continues to provide that array directly.

The report records actual received/sent bytes, read/write calls, last sent CSeq,
and native observation/exclusion counters. The following counts have different
meanings and must not be summed as if they were independent originals:

| Field | Meaning |
|---|---|
| `discarded_wire_bytes` | Every received wire byte deliberately not retained, including control and unread suffixes. |
| `rtp_bytes` | Whole selected RTP datagrams accepted into the native observation. |
| `rtcp_bytes_excluded` / `closing_bytes_excluded` | Payloads deliberately excluded from observation or received while closing. |
| `unverified_nal_bytes_excluded` | Reconstructed complete NAL bytes in the unverified next group at the cutoff; zero for JPEG. |
| `unfinished_fragment_bytes_excluded` | Reconstructed bytes from an unfinished fragment at the cutoff. |

Reconstructed tail counts overlap received originals. They do not establish how
many pictures were omitted or whether every pixel in a confirmed group can be
decoded. `last_observed_ns` is the last admitted elapsed owner clock, not camera
capture time, synchronized wall time, or total runtime-retirement duration.

The completion digest uses canonical typed fields, not JSON text. It binds the
approved operation, full receipt claim, native transport/cutoff counts and owner
observation time. It is an integrity witness; it supplies no signature,
authenticated camera identity, freshness proof, source-custody root, rights
decision or later capture authority.

If a session fails after admission, the same envelope has `status: "refused"`
or, when the remote session may survive, `status: "indeterminate"`.
Both have empty `receipts`, null receipt/completion digests, and exit code 1.
Known attempt, credential, pending-request and omission facts remain visible.
Unobserved transport or accounting is null, never a fabricated set of zero
measurements. Even an acknowledged TEARDOWN cannot release a receipt after a
late deadline, cancellation or runtime-finalization failure. Invalid scope or
approval still returns the existing preflight diagnostic and exit code 2.

## Credentials and failure behavior

Optional manifest authentication uses the existing Linux private-file credential
lease and Digest implementation. The file format and protections are those of
`fss-capture-rtsp`: private regular file, no final-component symlink, bounded read,
stable identity and continuing revalidation. Credentials and OS cnonce entropy are
accessed only after exact approval. Replacing or modifying the credential file
revokes the operation at the next authority checkpoint. The lease is checked again
before releasing a successful result. The network grant and original deadline
are rechecked after credential metadata work, so a stale admission cannot cover
a later socket effect. The manifest pins the realm and any explicit
legacy MD5/no-qop opt-in; there is no Basic fallback or automatic downgrade.

With default receipt output, failures after probe admission use
[`fss.site_probe_diagnostic.v1`](../schemas/site_probe_diagnostic.v1.json).
Session output uses the richer failure envelope described above.
Diagnostics contain static error identities and explicit facts about connection
and credential access attempts, remote-session uncertainty and acknowledged close.
They contain no peer, URI, credential path, password, session token or wire payload.
Stale approval or invalid probe scope exits with code 2; native execution refusal
exits with code 1. Manifest-file and CLI-grammar failures retain the existing site
and typed CLI diagnostic contracts.

Local cancellation, revoked authority, EOF or timeout closes local resources
without an unapproved cleanup exchange. A SETUP that may have reached the server,
or a lost TEARDOWN acknowledgement, can leave `remote_session_may_exist: true`.
No successful receipt is issued in that case. The command does not infer remote
closure from EOF or silently reacquire the stream.

## Scope and remaining work

This supplies the native RTSP/NVR and protected UniFi producer portions of VIT-003. It is a short
observation, not continuous recording, decoded-picture validation or a liveness
certificate. Plaintext LAN/VPN routes and explicit AVC/HEVC/JPEG selections are the
direct profile; UniFi supports explicit AVC/HEVC over the selected plaintext route.
ONVIF site-route resolution, automatic Protect export acquisition, TLS/RTSPS, automatic
all-source probing, authenticated/fresh receipt envelopes and a site recorder
remain separate work. Native and recorded JPEG probes now supply receipts
accepted by the existing JPEG capture planner.

This is a standalone owner-approved reference capability, suitable for an owner's
lab. Customer collection under the [Vittles plan](VITTLES_FOOTAGE_PLANE_PLAN.md)
also requires a current FLDT rights lease, including for framing-only probes.
That VIT-010 admission gate is not implemented here. An exact local approval,
manifest rights reference or `owner_authorized` declaration does not supply it;
the preview explicitly reports `rights_verdict_verified: false`.

The existing v1 receipt remains an observational claim. Its digest detects changes;
it does not authenticate a file's author, establish physical camera identity or
prove later capture uses the same SDP. `site plan` grants no capture authority.
Native capture still requires its own independently reviewed approval. Neither
loopback tests nor successful receipt parsing constitutes hardware or release
qualification.

The implementation is in `fss_reference::site::live_probe` and
`fss_cli::site_probe`. Focused contracts are in `site_live_probe_contract.rs` and
`site_probe_cli_contract.rs`; consult the [implementation status](../IMPLEMENTATION_STATUS.md)
for the tests actually executed.
