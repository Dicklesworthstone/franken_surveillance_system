# Site manifests and native capture planning

`fss site validate` admits a bounded site manifest. `fss site plan` combines that
manifest with an exact inventory of supplied probe receipts and produces one
deterministic preview containing the existing native RTSP capture plans. By
default this covers every manifest source. Repeated `--source` options select an
explicit subset while preserving the full manifest and its existing receipt bindings.
This removes the need to hand-invent sensor, stream, ingress, clock, authority,
journal and destination identities for every camera and operation.

This covers direct RTSP/NVR AVC/HEVC/JPEG planning and protected UniFi/ONVIF AVC/HEVC
site compilation from VIT-001, VIT-002 and VIT-004 in
[the footage-plane plan](VITTLES_FOOTAGE_PLANE_PLAN.md). Planning reads the named
control documents; it does not contact devices, read credentials, create archives,
verify signed rights leases or start recording. An independently approved
[`site probe`](SITE_PROBING.md) can produce an AVC/HEVC/JPEG receipt from one native
RTSP/NVR session or a protected AVC/HEVC receipt from a selected UniFi export.
No `site run` or site-wide approval executor is available. The reference implementation remains
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

For direct RTSP/NVR planning, the output parents do not have to exist. Their existence and native
storage protections are checked only by a separately approved native capture.
The planner will not inspect either directory. Use separate, nonnested absolute
parents, with no `.` or `..` components. Credentials must be outside both output
namespaces. AVC/HEVC captures accept 1 through 4096 pictures per source; JPEG
captures accept 1 through 256. The same requested count applies to every included source,
so a requested inventory containing JPEG also has a 256-picture ceiling. A request above
any included source's limit refuses the whole plan; it is never silently reduced. The
native deadline ceiling also applies, and slower cadence can lower the effective
picture cap. The existing JPEG planner additionally requires a nonzero SSRC and
media index 0 through 15. A supplied JPEG receipt outside those native limits
refuses; the compiler does not replace its selected stream. AVC/HEVC retain their
existing exact-zero SSRC behavior.

For a mixed AVC/JPEG example, keep the same manifest and use the alternate
synthetic receipt inventory:

```sh
cargo run --locked -p fss-cli --bin fss -- site plan \
  --manifest fixtures/site/manifest.v1.json \
  --probes fixtures/site/probes-avc-jpeg.v1.json \
  --archive-root /srv/fss/footage \
  --pins-root /srv/fss/pins \
  --epoch 1 --stop-after-pictures 250 --json
```

JPEG plans emit the existing `fss-capture-rtsp jpeg` command. It retains original
RTP/RTCP datagrams in its source archive and uses the native JPEG prefix custody
contract. It does not use the AVC/HEVC independent pin journal. The site command
still requires and binds `--pins-root` and shows it as `reserved_pins_root` for
JPEG sites, so the complete destination declaration is reviewable, including for
an all-JPEG site. Actual JPEG capture's prefix receipts must still be retained
independently as documented in [the native JPEG guide](rtsp_jpeg_capture_cli.md).

`--principal principal:local-operator` is the default audit label. An alternative
principal must be explicit; a label does not authenticate its author. `--epoch`
is a positive operation generation that the caller must advance for a new
capture. The compiler has no state from which to allocate or remember epochs.

## Plan selected cameras without changing the manifest

A camera can be probed and planned before every other source is ready. Repeat
`--source` for exactly the cameras to include:

```sh
fss site plan --manifest /etc/fss/site.json \
  --probes /etc/fss/front-and-back.probes.json \
  --source source:front --source source:back \
  --archive-root /srv/fss/footage --pins-root /srv/fss/pins \
  --epoch 2 --stop-after-pictures 250 --json
```

The receipt array must contain exactly one receipt for each selected source and
no others. Each receipt still binds the complete original manifest digest and
its original source generation. Do not remove other cameras from the manifest
to create a one-camera plan: changing the manifest invalidates its receipts.
For a single camera, pass its ordinary receipt array and one `--source`.

Selection order does not change the result. Sources are emitted in original
manifest order, with their original `source_index`. Duplicate, foreign or empty
source selections refuse. Every selected source must pass; there is no automatic
fallback that drops a failed camera. Omitting `--source` keeps the existing
all-source behavior and exact v1 output/approval bytes.

Explicit selection emits
[`fss.site_capture_plan.v2`](../schemas/site_capture_plan.v2.json). It identifies
`selection_mode: "explicit"`, the complete `manifest_source_count`, and the
`selected_source_ids` and `unselected_source_ids`. Its approval has a distinct
v2 domain, including when every source was explicitly selected. The per-camera
native plan and operation identities remain the same as for that camera in a
complete plan with identical inputs; selecting it twice does not create a new
capture epoch or output namespace.

An unselected camera may remain unprobed, use an unsupported onboarding kind,
or be ineligible for original retention. The complete manifest must still be
valid. Credential references from **every** source must remain outside the
selected capture output namespaces, so selection cannot hide a credential
collision. A selected source with a payment mask or missing permission
declaration still refuses.

For selected UniFi or ONVIF sources, provide the corresponding `--unifi-bindings`
or `--onvif-bindings` document; mixed selections can use both. Each document must
name exactly the selected sources of its kind and no others, and still pin the
complete manifest digest. Unselected private exports and handoffs are neither
needed nor opened. Existing file fingerprint, route, camera/view/profile and
output isolation checks apply to the selected inputs. Actual selected routes
are also checked against known unselected direct RTSP routes; excluded protected
routes are not inferred. No selection grants recording authority; each emitted
native capture still requires its own exact approval.

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
| `kind` | `rtsp`, `nvr_channel`, `onvif`, or `unifi_protect`. The compiler accepts RTSP/NVR directly and UniFi/ONVIF with their exact protected bindings. Live site probing supports RTSP/NVR and UniFi. |
| `peer` | Canonically spelled literal IP and nonzero port, including bracketed IPv6 when needed. No DNS lookup. |
| `authority` | Exact RTSP authority label. An explicit port or literal address must agree with `peer`. |
| `presentation`, `control_root` | Required RTSP/NVR path and allowed control subtree. No embedded credentials, traversal, redirect or credential-bearing query fields. |
| `onvif_service_path` | Required only for an ONVIF source; cannot substitute for RTSP presentation fields. |
| `unifi_camera_id` | Required only for a UniFi source; cannot substitute for RTSP presentation fields. |
| `stream_role` | Explicit `main` or `sub` rendition declaration. The supplied route must already select it. |
| `authentication` | Optional private credential-file reference and exact Digest policy. No inline username or password. |
| `retention_class`, `rights_verdict_ref` | Bounded opaque references, included in identity; neither activates retention nor grants rights. |
| `zones`, `payment_masks` | Explicit image geometry. Empty arrays are allowed; masks are never silently dropped. |
| `max_connections` | Declared device limit from 1 through 16, preserved in manifest identity. Sources sharing a canonical literal IP must declare the same ceiling, including across ports and IPv4-mapped IPv6 spellings. This planner does not schedule connections. |
| `owner_authorized`, `plaintext`, `retain_originals` | Required booleans. Each must be true before compiling the current native capture path. They are declarations, not authenticated grants. |

Optional route fields may be omitted or null. Unknown fields, duplicate JSON
members, duplicate source/zone IDs, duplicate RTSP/NVR routes, noncanonical
numbers and inconsistent route fields refuse. Duplicate route checks bind the
canonical peer IP, port, normalized authority host and validated presentation;
changing a source ID, stream role or control subtree cannot create another
acquisition of the same route. Unreserved percent escapes and escaped hex case
are normalized only for comparison; reserved delimiters, query ordering, values
and original wire spellings retain their meaning. Authority comparison normalizes
DNS host case and IPv6 text while preserving port declarations. Distinct presentation paths
and virtual-host authorities remain valid. Shared IP connection declarations are
conservative limits, not an assertion that all sources belong to one physical
camera. Whole inputs are limited to 1 MiB. Stable identifiers are bounded
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

The compiler refuses to include a source with a payment mask or a `payment`,
`payment_terminal` or `lane_pay` zone. The current original-byte capture path
cannot apply a payment privacy floor before retaining source bytes. A declared
mask alone cannot make that capture permissible.

## Supplied probe receipts

The `--probes` document is a JSON array of
[`fss.site_probe_receipt.v1`](../schemas/site_probe_receipt.v1.json) objects.
Each requested source must have exactly one receipt: every manifest source by
default, or exactly the explicit `--source` selection. Input receipt order is
irrelevant; output always follows manifest source order. Missing, duplicate,
foreign, unselected or stale receipts refuse the whole plan.

A receipt binds the exact manifest digest and source generation, literal peer,
authority, presentation/control subtree, selected SDP media index, RTP/RTCP
channels, SDP digest, codec, payload type, SSRC and observed timing. It also
contains ordered parameter-set digests and a bounded server-identity claim.
AVC requires SPS/PPS hashes; HEVC requires VPS/SPS/PPS hashes. JPEG requires an
empty parameter-set array and payload type 26 or an explicitly selected dynamic
payload type. The exact receipt, including its cadence and SDP claims, contributes
to the site approval and the JPEG retention-evidence identity. This identity does
not grant retention rights or authenticate those claims. Native JPEG capture
does not enforce a cadence pin; the supplied cadence sizes the timeout and stays
bound to the declared receipt.

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
not turn them into evidence of the changed source. To derive receipts from recorded
DESCRIBE responses and RTPdump samples, use
[`fss site probe-file`](SITE_PROBE_MEASUREMENT.md). It measures native AVC/HEVC
picture syntax or whole-frame JPEG reconstruction and constant cadence under
exact input pins. The separately approved `site probe` supports live RTSP/NVR
measurements and protected UniFi AVC/HEVC observations with the bindings below.
Authenticated/fresh receipt handling remains separate work; the UniFi compiler
validates supplied receipts against the exact selected private route.

## UniFi Protect site bindings

Add `--unifi-bindings /etc/fss/site-unifi-bindings.json` when the manifest contains
`unifi_protect` sources. Keep the existing manifest v1 shape: each source declares
its exact `unifi_camera_id`, literal stream peer and RTSP authority, and omits
`presentation`, `control_root` and `onvif_service_path`. The peer is the selected
stream endpoint, not an inferred Protect API address. Source permission,
retention, payment-zone, receipt-generation and connection declarations retain
the same checks as direct capture.

The separate strict binding document uses
[`fss.site_unifi_bindings.v1`](../schemas/site_unifi_bindings.v1.json):

```json
{
  "schema": "fss.site_unifi_bindings.v1",
  "manifest_digest": "sha256:<exact canonical site manifest digest>",
  "sources": [
    {
      "source_id": "source:front",
      "source_file": "/etc/fss/private/front-protect.json",
      "source_digest": "sha256:<SHA-256 of the complete private export bytes>",
      "quality": "high",
      "stream_transport": "operator-rtsp"
    }
  ]
}
```

Replace both illustrated digest placeholders with 64 lowercase hexadecimal
characters. `site validate` reports the canonical manifest digest. The source
pin hashes the complete independently obtained private export, including its
whitespace. See [the Protect handoff guide](UNIFI_PROTECT.md) for its exact
`camera`, `streams` and optional `rtsp` shape. Bindings never contain URLs, API
keys, credentials or peer overrides. Every included UniFi source requires exactly one
row: all by default, or exactly the explicit plan selection. Missing, duplicate,
foreign, unselected and direct-source rows refuse the complete requested plan.
Row ordering does not affect the plan.

Obtain a live receipt for one selected UniFi source using the same bindings:

```sh
fss site probe --manifest /etc/fss/site.json \
  --unifi-bindings /etc/fss/site-unifi-bindings.json \
  --source source:front --codec avc --observe-frames 6 \
  --receipt-file /etc/fss/private/front-probe.json \
  --timeout-ms 10000 --json
```

This is a preview. Review it and repeat with its exact `--approve sha256:HEX`.
The Linux protected export reader and selected route are shared with the existing
UniFi handoff. Preview reads only the selected private export, checks an absent
absolute receipt destination, and contacts no camera or console. Route fields on
stdout are SHA-256 digests; approval binds the original manifest, exact bindings,
export bytes and file fingerprint, selection, route and receipt destination.
The preview's `receipt_parent_identity` also binds the destination parent's
device/inode identity before camera contact; a replacement parent refuses output.
Successful probing writes the ordinary one-element receipt array to a new `0600`
file and reports its digests through `fss.site_unifi_probe_result.v1`. It never
overwrites a receipt, and UniFi `--output session` is unsupported. See
[protected UniFi probing](SITE_PROBING.md#probe-a-unifi-protect-source) for the
separate file-stage deadlines and how to interpret a partial or committed file
after a failure.

For a one-source manifest, use `/etc/fss/private/front-probe.json` directly as
`--probes`. For several sources, privately combine their successful arrays into
one complete inventory, preserving every original manifest and source identity:

```sh
fss site plan --manifest /etc/fss/site.json \
  --probes /etc/fss/site-probes.json \
  --unifi-bindings /etc/fss/site-unifi-bindings.json \
  --archive-root /srv/fss/footage --pins-root /srv/fss/pins \
  --epoch 1 --stop-after-pictures 250 --json
```

UniFi planning reads the named protected exports on Linux. The existing private
file owner requires a nonempty regular file, owner-read permission, no group or
other permissions, exactly one hard link and no symlink path. Each export is at
most 256 KiB; the complete request admits at most 8 MiB of protected export bytes
and 64 bindings. The read request has a five-second deadline, a 16,384-operation metadata
allowance and a 32 MiB declared logical working reservation. That reservation
accounts for bounded input and coexisting report representations; it is not
measured process RSS. Both output parents must already exist for the native
canonical overlap check. Exports must be outside both output namespaces and
separate from every credential reference. No capture destination is created, and no credential file is read. All export leases and destination overlaps are rechecked before
the complete plan is released; a failed finalization yields no plan.

Selection is exact: `high`, `medium`, `low` or `package`, with explicit
`published` or `operator-rtsp` transport. Missing and disabled qualities refuse.
Package selection requires the camera's reported package capability. Published
RTSPS remains unsupported by the native capture owner; the compiler never
rewrites a scheme, port, path or query, chooses another quality, or infers a
plaintext endpoint. The exported camera ID must match the manifest. Each receipt
must match the selected peer, authority, presentation and exact control root;
the root defaults to that selected path without its query. Codec and cadence
come from the receipt, never the vendor camera model. UniFi capture supports
AVC/HEVC; a UniFi JPEG receipt refuses. Direct JPEG and UniFi sources can share
a site, subject to every source's native limits.

Generated arguments use `from-unifi --unifi-source ... --unifi-digest ...
--quality ... --stream-transport ... --capture-mode single` and the ordinary
native capture options. They contain no selected stream URL, presentation or
control-root argument. The nested report is the existing redacted native
wrapper preview; `native_approval` is its **outer** approval, ready for that
command's independent native approval flow. Replacing the private file changes
that approval even when its content bytes are identical. Execution reopens and
checks the file again. No site-wide executor is added.

UniFi sensor and stream identities also bind the exact camera-ID digest and
`main` or `package` view. Operation destinations and clock/journal coordinates
bind that view too. High/medium/low remain renditions of the main view; assigning
separate source IDs distinguishes simultaneous renditions. Package selection
cannot reuse a main-view identity or output namespace. Once private routes are
resolved, the existing normalized-route collision validator checks the entire
mixed site. Changing a source name or kind cannot create a duplicate acquisition.
Existing direct-only plans and native UniFi wrapper approval encodings retain
their previous bytes.

This command consumes supplied historical receipts. It neither authenticates
those observations nor obtains new ones, contacts Protect, starts recording,
verifies signed rights or claims hardware qualification.

The existing receipt format includes its selected presentation and control route.
Treat a UniFi `--probes` document as private operator input because those fields
can contain a stream capability. It uses the existing bounded control-document
reader; only the separately bound exports use the stronger private-file lease.
The compiler never copies receipt route fields into its generated UniFi arguments
or report. The live UniFi producer preserves this boundary with its create-only
private receipt artifact and separate redacted stdout contract. Raw capability
routes remain inside the protected export and receipt inputs.

## ONVIF site bindings

Add `--onvif-bindings /etc/fss/private/site-onvif-bindings.json` for `onvif`
sources. It can be used together with `--unifi-bindings` in a mixed site. The
original manifest retains the ONVIF HTTP peer, authority and service path; its
`presentation`, `control_root` and `unifi_camera_id` remain absent. The selected
RTSP endpoint is declared independently in the binding document because its
address, port and authority can differ from the HTTP service.

First obtain a private stable Media1 AVC or indefinite Media2 AVC/HEVC handoff
through the separately approved [ONVIF onboarding flow](ONVIF_ONBOARDING.md).
The strict [`fss.site_onvif_bindings.v1`](../schemas/site_onvif_bindings.v1.json)
input has this shape:

```json
{
  "schema": "fss.site_onvif_bindings.v1",
  "manifest_digest": "sha256:<exact canonical site manifest digest>",
  "sources": [
    {
      "source_id": "source:front",
      "source_file": "/etc/fss/private/front-onvif.json",
      "source_digest": "sha256:<SHA-256 of the complete private handoff bytes>",
      "onboarding_plan": "sha256:<independently expected onboarding plan digest>",
      "profile_digest": "sha256:<SHA-256 of the exact selected profile token>",
      "rtsp_peer": "192.0.2.10:554",
      "rtsp_authority": "192.0.2.10",
      "control_root": "/owner-approved-track-subtree"
    }
  ]
}
```

Replace digest placeholders with 64 lowercase hexadecimal characters. Supply one
row per included ONVIF source: all by default, or exactly the explicit `--source`
selection. Missing, duplicate, unknown, unselected or non-ONVIF rows refuse the
whole requested plan. The handoff's complete bytes, expected onboarding/profile identities,
peer, exact authority and codec must agree. A supplied receipt must bind the
**original** manifest, source ID and generation, and match the selected RTSP
peer, authority, exact presentation, codec and explicit control root. Renaming a
source or rewriting its manifest kind to RTSP is not part of this workflow.

```sh
fss site plan --manifest /etc/fss/site.json \
  --probes /etc/fss/private/site-probes.json \
  --onvif-bindings /etc/fss/private/site-onvif-bindings.json \
  --archive-root /srv/fss/footage --pins-root /srv/fss/pins \
  --epoch 1 --stop-after-pictures 250 --json
```

The separately approved [`site probe --onvif-bindings`](SITE_PROBING.md#probe-an-onvif-source)
produces a native AVC/HEVC receipt from the exact protected handoff's independently
pinned RTSP endpoint and saves it to a private file for this planner. The recorded
`probe-file` producer remains direct RTSP/NVR only. Planning checks the supplied
receipt inventory's consistency; it does not claim to authenticate the HTTP origin
of the handoff. The handoff format does not
record the HTTP device path or current site generation. The report therefore
states `onvif_selection_provenance: "operator-bound-historical-consistency"` and
`onvif_http_origin_verified: false`. Matching digests do not establish current
liveness, physical-camera identity or capture-time truth.

Linux planning holds actual private-file leases on the handoffs and revalidates
their identities before releasing the complete mixed-site result. Each retained
handoff is at most 8 KiB, the aggregate at most 512 KiB, and the binding document
at most 1 MiB with 64 sources. The existing private-file requirements apply:
canonical absolute path, regular file, owner-read permission, no group/other
permissions, and exactly one hard link. Both output parents must exist; handoffs
must be separate from output and credential namespaces. No credential is read,
camera contacted, output created or capture started by planning.

Generated commands begin `from-onvif --onvif-source ... --onvif-digest ...
--capture-mode single`. Their outer native approval binds the actual file
fingerprint and complete native capture plan. The explicit control root is
represented only by `--onvif-control-root-digest`: the native reader matches its
SHA-256 to exactly one query-free ancestor of the protected presentation path,
preserving original spelling and refusing a mismatch. Existing root syntax
remains strict, including its refusal of percent-escaped control roots. It never guesses a
broader subtree. Neither the selected path/query nor the control root appears
in generated arguments or native previews. The existing standalone
`--control-root` form and its approval bytes remain supported.

Keep the bindings and receipts private: their control and presentation fields
can contain capabilities. They use bounded control-document reads; the stronger
private-file lease applies to the handoff itself. Existing receipt validation
still refuses sensitive query keys such as `token`, `password` and `session`;
the integration does not broaden that grammar. Accepted opaque path values and
safe query spellings remain exact. ONVIF JPEG, expiring handoffs, route/codec
fallback and TLS/RTSPS remain unsupported.

ONVIF sensor identities retain the stable site/source coordinate across profile
changes. Stream identities additionally bind the selected profile digest.
Operation coordinates also bind the complete manifest, epoch, handoff and
onboarding plan. Resolved routes across direct, UniFi and ONVIF sources must be
unique, and sources sharing the selected RTSP IP must agree on connection caps.
Planning does not schedule those connections. Existing direct-only and UniFi-only
report and approval bytes are unchanged.

## What the plan binds

The default complete-site output follows
[`fss.site_capture_plan.v1`](../schemas/site_capture_plan.v1.json); explicit
`--source` selection follows the additive v2 contract described above. Each source
includes an `argv` array for `fss-capture-rtsp`, the exact native `native_approval`
and the native `native_plan` JSON. JPEG argument arrays start with `jpeg`; their
native report uses `fss.rtsp_jpeg_capture_cli.v1`, while direct AVC/HEVC reports
retain `fss.rtsp_capture_cli.v1`. UniFi argument arrays start with `from-unifi`;
their `fss.rtsp_from_unifi_plan.v1` report wraps the actual native AVC/HEVC plan
with its URI fields redacted and its original URI digests intact. ONVIF arguments
start with `from-onvif` and use the existing `fss.rtsp_from_onvif_plan.v1` wrapper
with the same private native projection. The arguments contain no `--approve`. The
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

No command infers success for an unsupported source. Automatic ONVIF HTTP onboarding,
automatic UniFi export acquisition, automatic all-source probing, TLS/RTSPS, signed
rights-lease verification, site execution, retention rings and agent footage
queries remain outside this implementation. Existing standalone native tools
retain their separately documented capabilities.

## Code and verification entrypoints

- `fss_reference::site` owns strict admission, typed validation and canonical
  manifest/source/receipt identities.
- `fss_cli::capture_plan::{prepare_rtsp, prepare_jpeg, prepare_unifi}` expose the existing pure
  native planners. They refuse execution approval and JPEG replay requests.
- `fss_cli::site_plan::compile` atomically compiles a whole site without I/O.
- `fss_cli::site_plan::compile_with_unifi` adds exact borrowed private export
  observations without I/O; `fss_cli::site_unifi` owns their protected reads and
  final revalidation through the existing request runtime.
- `fss_cli::site_plan::compile_with_protected` also admits exact borrowed ONVIF
  handoffs. `site_onvif` validates their bindings and holds native private-file
  leases inside the same mixed-input request owner. `onvif_plan` shares the
  existing standalone handoff parser, private selection and approval encoding.
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


## Native RTP probe observation component (VIT-003)

The pure `fss_reference::site::probe_observation::RtspProbeObserver` API accepts one
already-negotiated AVC/HEVC/JPEG SDP selection and validates the complete native codec
configuration. It shares the recorded-probe depacketizers, picture assemblers and
cadence measurement. SSRC, payload, packet order, immutable parameter sets and
constant 90 kHz picture timing must agree. RTP markers alone cannot create an
observation. Field-coded configurations, malformed media, discontinuities and
variable cadence refuse the sample.

A strict `finish()` requires witnessed boundaries for the supplied sample.
Live callers use `freeze_prefix()` followed by `finish_prefix()` to deliberately
exclude the unverified next group or fragment without fabricating EOF/EOS.
Excluded reconstructed NAL/fragment bytes are reported separately from original
wire omissions; they do not assert an omitted-frame count or pixel completeness.
One RTP aggregation packet is processed atomically, so a minimum picture target
may be exceeded, subject to the hard 64-picture bound.

The [`site probe`](SITE_PROBING.md) command and its
`site::live_probe::LiveSiteProbe` owner feeds this observer from its actual
accepted DESCRIBE/SETUP/PLAY session, supplies current scoped TCP authority and
monotonic time, freezes the measured prefix, and releases its receipt only after
the matching successful TEARDOWN response. Local cancellation or EOF cannot
substitute for that acknowledgement. Close uncertainty remains explicit.

Neither the pure observer nor a matching remote close authenticates the physical
camera, proves current scene freshness, certifies every slice/macroblock, grants
rights, or establishes source custody. The returned metadata uses the existing
site probe receipt contract. See the implementation status for the exact
qualification limits of the changed observer and real-media loopback tests.
