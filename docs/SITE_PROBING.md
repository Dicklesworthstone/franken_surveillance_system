# Approved native site probing

`fss site probe` obtains one bounded AVC, HEVC or JPEG observation from an explicitly
selected RTSP camera or NVR channel. It uses the manifest's exact literal peer,
authority and permitted RTSP control subtree. By default, successful stdout is a
one-element array of `fss.site_probe_receipt.v1` objects, ready for
`fss site plan --probes`. Select `--output session` for the same receipt plus
native transport and exclusion evidence.

## Preview, review, then probe

First request a preview. This reads the manifest only; it opens no socket or
credential file.

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

Probe sources one at a time. A multi-source site plan requires one receipt for
every manifest source; combine only successful one-element arrays into a single
array. Preserve their source and manifest identities. A failed command returns an
object, never a partial successful receipt array. Save stdout only when the command
exits successfully, and handle both previews and receipts as private deployment
metadata because they include exact routing information.

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

Request the evidence projection in both the preview and the approved invocation:

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

This supplies the native RTSP/NVR producer portion of VIT-003. It is a short
observation, not continuous recording, decoded-picture validation or a liveness
certificate. Plaintext LAN/VPN routes and explicit AVC/HEVC/JPEG selections are the
supported profile. ONVIF/UniFi route resolution, TLS, automatic
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
