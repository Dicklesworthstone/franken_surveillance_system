# Approved native site probing

`fss site probe` obtains one bounded AVC or HEVC observation from an explicitly
selected RTSP camera or NVR channel. It uses the manifest's exact literal peer,
authority and permitted RTSP control subtree. Successful stdout is a one-element
array of `fss.site_probe_receipt.v1` objects, ready for `fss site plan --probes`.

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
deadline or principal invalidates the approval before network or credential work.
The command never approves itself or retries the camera automatically.

`--codec avc|hevc` and `--source` are required. Defaults are media index 0, RTP
channel 0 with RTCP channel 1, six marked picture boundaries, ten seconds, and
`principal:local-operator`. `--payload-type 96..127` optionally selects an exact
dynamic payload when SDP offers more than one. Media indices are 0 through 63;
RTP channels are even values from 0 through 254. Samples allow 3 through 64
marked boundaries and 100 through 60000 milliseconds for the whole operation,
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
must remain contiguous, marker boundaries complete, and timestamp increments
constant under explicit RTP wrapping.

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
never renew during negotiation or progress. No decoder, archive, discovery scan,
device configuration, PTZ operation or parallel source scheduler is invoked.

## Credentials and failure behavior

Optional manifest authentication uses the existing Linux private-file credential
lease and Digest implementation. The file format and protections are those of
`fss-capture-rtsp`: private regular file, no final-component symlink, bounded read,
stable identity and continuing revalidation. Credentials and OS cnonce entropy are
accessed only after exact approval. Replacing or modifying the credential file
revokes the operation at the next authority checkpoint. The lease is checked again
before releasing a successful result. The manifest pins the realm and any explicit
legacy MD5/no-qop opt-in; there is no Basic fallback or automatic downgrade.

Failures after probe admission use
[`fss.site_probe_diagnostic.v1`](../schemas/site_probe_diagnostic.v1.json).
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
certificate. Plaintext LAN/VPN routes and explicit AVC/HEVC selections are the
supported profile. JPEG live probing, ONVIF/UniFi route resolution, TLS, automatic
all-source probing, authenticated/fresh receipt envelopes and a site recorder
remain separate work. JPEG capture planning accepts valid supplied JPEG receipts
through its existing contract.

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
