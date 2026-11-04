# Site manifests and native capture planning

`fss site validate` admits a bounded site manifest. `fss site plan` combines that
manifest with a complete inventory of supplied probe receipts and produces one
deterministic site preview containing the existing native RTSP capture plans.
This removes the need to hand-invent sensor, stream, ingress, clock, authority,
journal and destination identities for every camera and operation.

This is the direct RTSP/NVR, AVC/HEVC portion of VIT-001 and VIT-002 in
[the footage-plane plan](VITTLES_FOOTAGE_PLANE_PLAN.md). Planning reads the named
control documents; it does not contact devices, read credentials, create archives,
verify signed rights leases or start recording. No `site run`, `site probe` or
site-wide approval executor is available. The reference implementation remains
unqualified, with no real-camera measurement implied by a successful plan.

## Try the complete synthetic example

The checked-in example describes two documentation-range peers, one AVC camera
and one HEVC NVR channel. Its receipts are synthetic test data, not observations
of reachable devices. The commands below perform no network access.

```sh
cargo run --locked -p fss-cli --bin fss -- site validate \
  --manifest fixtures/site/manifest.v1.json --json

cargo run --locked -p fss-cli --bin fss -- site plan \
  --manifest fixtures/site/manifest.v1.json \
  --probes fixtures/site/probes.v1.json \
  --archive-root /srv/fss/footage \
  --pins-root /srv/fss/pins \
  --epoch 1 --stop-after-pictures 250 --json
```

The output parents do not have to exist for planning. Their existence and native
storage protections are checked only by a separately approved native capture.
The planner will not inspect either directory. Use separate, nonnested absolute
parents, with no `.` or `..` components. Credentials must be outside both output
namespaces. One operation is limited to 1 through 4096 pictures per source and to
the native deadline ceiling; slower cadence can lower the effective picture cap.

`--principal principal:local-operator` is the default audit label. An alternative
principal must be explicit; a label does not authenticate its author. `--epoch`
is a positive operation generation that the caller must advance for a new
capture. The compiler has no state from which to allocate or remember epochs.

## Manifest contract

The strict input schema is
[`fss.site_camera_manifest.v1`](../schemas/site_camera_manifest.v1.json).
The top-level fields are `schema`, `site_id`, positive `generation`,
`network_route` (`lan` or `vpn`) and an ordered `sources` array. A manifest admits
1 through 64 uniquely identified sources. A source identity is stable across
address changes; a source generation identifies its requested configuration.

Each source declares the following scope:

| Field | Meaning |
| --- | --- |
| `source_id`, `generation` | Stable source name and positive configuration generation. |
| `kind` | `rtsp`, `nvr_channel`, `onvif`, or `unifi_protect`. The compiler currently accepts the first two. |
| `peer` | Canonically spelled literal IP and nonzero port, including bracketed IPv6 when needed. No DNS lookup. |
| `authority` | Exact RTSP authority label. An explicit port or literal address must agree with `peer`. |
| `presentation`, `control_root` | Required RTSP/NVR path and allowed control subtree. No embedded credentials, traversal, redirect or credential-bearing query fields. |
| `onvif_service_path` | Required only for an ONVIF source; cannot substitute for RTSP presentation fields. |
| `unifi_camera_id` | Required only for a UniFi source; cannot substitute for RTSP presentation fields. |
| `stream_role` | Explicit `main` or `sub` rendition declaration. The supplied route must already select it. |
| `authentication` | Optional private credential-file reference and exact Digest policy. No inline username or password. |
| `retention_class`, `rights_verdict_ref` | Bounded opaque references, included in identity; neither activates retention nor grants rights. |
| `zones`, `payment_masks` | Explicit image geometry. Empty arrays are allowed; masks are never silently dropped. |
| `max_connections` | Declared device limit from 1 through 16, preserved in manifest identity. This planner does not schedule connections. |
| `owner_authorized`, `plaintext`, `retain_originals` | Required booleans. Each must be true before compiling the current native capture path. They are declarations, not authenticated grants. |

Optional route fields may be omitted or null. Unknown fields, duplicate JSON
members, duplicate source/zone IDs, noncanonical numbers and inconsistent route
fields refuse. Whole inputs are limited to 1 MiB. Stable identifiers are bounded
ASCII strings beginning with an alphanumeric character, with `._:-` also allowed.

An authentication declaration has this shape:

```json
{
  "credential_file": "/etc/fss/private/front-camera.credentials",
  "realm": "front-camera",
  "legacy_md5": false,
  "legacy_no_qop": false
}
```

The file is not opened during validation or planning. Actual Digest capture uses
the existing Linux private-file checks and independently approved native command.
SHA-256 with `qop=auth` remains the default. Legacy no-qop requires an explicit
MD5 opt-in as well; there is no automatic downgrade or Basic-auth fallback.

Zone vertices are integer `[x,y]` pairs in normalized millionths, from 0 through
1,000,000. Polygons have 3 through 64 distinct vertices, nonzero area and no
nonadjacent-edge intersections. Payment masks have positive width and height and
must fit within the same coordinate range. A source has at most 32 zones and 32
masks; a whole site has at most 8192 polygon vertices.

The compiler refuses any source with a payment mask or a `payment`,
`payment_terminal` or `lane_pay` zone. The current original-byte capture path
cannot apply a payment privacy floor before retaining source bytes. A declared
mask alone cannot make that capture permissible.

## Supplied probe receipts

The `--probes` document is a JSON array of
[`fss.site_probe_receipt.v1`](../schemas/site_probe_receipt.v1.json) objects.
Each manifest source must have exactly one receipt. Input receipt order is
irrelevant; output always follows manifest source order. Missing, duplicate,
foreign or stale receipts refuse the whole plan.

A receipt binds the exact manifest digest and source generation, literal peer,
authority, presentation/control subtree, selected SDP media index, RTP/RTCP
channels, SDP digest, codec, payload type, SSRC and observed timing. It also
contains ordered parameter-set digests and a bounded server-identity claim.
AVC requires SPS/PPS hashes; HEVC requires VPS/SPS/PPS hashes. JPEG can be
represented by the receipt contract but is refused by this compiler.

Timing must use the native 90 kHz clock and a positive constant frame duration
of at most 90,000 ticks. At least two picture observations are required. The
declared first/last timestamps must agree with the cadence and observation count
under explicit 32-bit RTP wrapping. SSRC zero is a valid exact pin; it does not
select automatic discovery. Video payload selection and consecutive even/odd
interleaved channels are explicit.

The parser establishes consistency of these claims. It does not authenticate
their producer, inspect raw SDP or media, or establish current camera liveness.
Changing the manifest, even only its policy references, invalidates its previous
receipts. Replacing their manifest hashes without making fresh observations does
not turn them into evidence of the changed source. A native bounded probe producer
and authenticated/fresh receipt handling remain separate work.

## What the plan binds

The complete output follows
[`fss.site_capture_plan.v1`](../schemas/site_capture_plan.v1.json). Each source
includes an `argv` array for `fss-capture-rtsp`, the exact native `native_approval`
and the native `native_plan` JSON. The arguments contain no `--approve`. The
compiler invokes the same production planning source as the native binary;
defaults, resource limits and approval encoding have one implementation.

The site `approval` hashes the complete canonical manifest, operation epoch,
ordered receipt digests and every native plan digest. JSON whitespace and object
member order do not affect identities. Manifest source order is significant;
receipt array order is not. Any change to a camera route, credential reference,
policy, timing claim, output parent or other native operation input changes the
relevant enclosing approval. An invalid later source returns no successful
prefix and starts no effects.

Sensor and stream identities derive from the stable site/source pair. Per-source
archive and journal paths, authority anchor, receive-clock and journal identities
also bind the manifest and operation epoch. The timing identity additionally binds
the exact probe receipt. Sources and epochs receive distinct output namespaces;
the compiler rejects an ingress identity collision instead of silently aliasing it.

These derived labels identify the declared operation. They are not measurements
of a physical clock or proofs of authorization. The SDP and parameter-set hashes
remain bound receipt claims; this planning command does not compare them against
a future live negotiation. Native capture retains its existing protocol checks.

The site approval is reviewable today, but there is no executor that consumes it.
An operator who elects to execute an emitted native command must review that
individual plan and use the existing native approval flow. That performs one
bounded capture, not site recording, retention scheduling or an always-on service.

## Refusal and disclosure boundaries

Both commands require `--json`. Validation emits
[`fss.site_validation.v1`](../schemas/site_validation.v1.json), with the canonical
manifest digest and a small source inventory. Successful planning includes the
private routing and path references needed to review the native command; handle
that report as deployment configuration. No credential file contents are read.

Runtime input or plan refusal emits
[`fss.site_diagnostic.v1`](../schemas/site_diagnostic.v1.json) and exit code 2.
Diagnostics contain a stable error ID, a static reason and, when available, a
zero-based manifest source index. They do not echo input payloads, camera URIs,
credential references or input filenames. CLI grammar errors use the existing
typed CLI diagnostic contract.

Only explicitly named control files may be read. Reads are bounded, refuse
nonregular files and final-component symlinks, and check file identity and
metadata before and after reading. Linux/macOS opens also refuse a raced
final-component symlink and avoid blocking on a replacement FIFO. These are
control-file admission checks, not cryptographic provenance or a trusted parent
directory guarantee.

No command infers success for an unsupported source. ONVIF/UniFi onboarding,
RTP/JPEG site compilation, live probing, automatic discovery, TLS/RTSPS, signed
rights-lease verification, site execution, retention rings and agent footage
queries remain outside this implementation. Existing standalone native tools
retain their separately documented capabilities.

## Code and verification entrypoints

- `fss_reference::site` owns strict admission, typed validation and canonical
  manifest/source/receipt identities.
- `fss_cli::capture_plan::prepare_rtsp` exposes the existing pure native planner.
- `fss_cli::site_plan::compile` atomically compiles a whole site without I/O.
- `fss_cli::site_cmd` owns CLI parsing, bounded input-file authority and reports.
- `crates/fss-cli/tests/site_cli_contract.rs` exercises emitted native plans,
  deterministic identity changes and whole-site refusal through command processes.

The usual integrated test commands are:

```sh
cargo test --locked -p fss-reference --lib site::
cargo test --locked -p fss-cli --test native_capture_plan_api
cargo test --locked -p fss-cli --test site_cli_contract
```

Consult the dated [implementation status](../IMPLEMENTATION_STATUS.md) for the
tests actually executed in this environment and its full-build limitations.
