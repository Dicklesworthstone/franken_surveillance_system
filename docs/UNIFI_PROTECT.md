# UniFi Protect camera selection and native recording

`fss-capture-rtsp from-unifi` selects one exact camera view from a private
UniFi Protect export and enters the existing native AVC/HEVC recording path.
It retains original RTP, independent recovery pins, durable recording windows,
catalogs, and the existing import and cold-decode workflow. Camera names are
not a codec, timing, geometry, or capability database: a newly released or
unknown model can be represented without changing an allowlist.

The current capture transport is explicitly authorized plaintext RTSP over
interleaved TCP. The integration understands both `rtsp://` and `rtsps://`
endpoints, but the recorder does **not** implement TLS. A published RTSPS URL
produces an explicit transport refusal. FSS never converts its scheme or port,
removes a query parameter, or substitutes another quality. An independently
verified plaintext endpoint can be supplied separately in the private file.

This is implemented integration, not qualification of physical Ubiquiti
cameras, firmware versions, or every codec profile. The
[native capture guide](rtsp_capture_cli.md) describes the underlying recording
and timing limits; this guide explains the Protect-specific handoff.

## Compile a complete site

`fss site plan --unifi-bindings BINDINGS.json` composes these exact private
selections with a site manifest and supplied probe receipts. It generates the
existing single-session `from-unifi` command and its outer native approval,
using the same selection and approval implementation as this standalone binary.
It binds the actual export-file identity, checks camera and receipt-route
agreement, keeps capability tokens out of arguments/reports, and separates main
and package source identities. Direct RTSP/NVR and JPEG sources can coexist in
the same atomic plan. Follow [the site binding workflow](SITE_PLANNING.md#unifi-protect-site-bindings).

Before planning capture, `fss site probe` can measure the selected stream using
the same manifest and bindings:

```sh
fss site probe --manifest /etc/fss/site.json \
  --unifi-bindings /etc/fss/site-unifi-bindings.json \
  --source source:front --codec avc --observe-frames 6 \
  --receipt-file /etc/fss/private/front-probe.json \
  --timeout-ms 10000 --json
```

Preview reads the selected protected export and checks the absent absolute
receipt destination, without network or credential access. Review the exact
plan and repeat with its `--approve sha256:HEX`. The native probe measures SDP,
parameter sets, RTP sender and cadence, then requires successful TEARDOWN before
saving a `0600` one-element receipt array. Its original manifest identity passes
directly into `site plan --probes` with the same bindings. This removes the need
to construct UniFi probe receipts by hand.

Both preview and stdout keep the selected capability route private: preview
route fields are SHA-256 digests, and success returns
`fss.site_unifi_probe_result.v1` with file/receipt digests. The exact export bytes,
file fingerprint, selection, route, output path and observation options are
approval-bound. UniFi probes support explicit AVC/HEVC and `--output receipts`;
`--output session` is refused. The writer never replaces an existing file, and a
failure can leave a partial file or an already committed receipt. Follow
[the live probing guide](SITE_PROBING.md#probe-a-unifi-protect-source) for the
result flags and separate five-second file-stage budgets.

Site planning consumes those receipts without device contact. Neither command
acquires Protect exports automatically, enables a stream, verifies signed rights
or executes a site-wide capture approval. RTSPS and ONVIF site probing remain
unsupported, and sources are probed one at a time. The standalone capture and
reconnect capabilities below retain their existing independent approval and
private-file revalidation.

## Export the selected camera and its existing streams

Use the owner's authenticated Protect interface or API workflow to obtain:

| Official operation | Private source field | Purpose |
| --- | --- | --- |
| [`GET /v1/cameras`](https://developer.ui.com/protect/v7.3.60/get-v1cameras) or [`GET /v1/cameras/{id}`](https://developer.ui.com/protect/v7.3.47/get-v1camerasid) | `camera` | One camera object, including its exact `id` and reported `hasPackageCamera` capability |
| [`GET /v1/cameras/{id}/rtsps-stream`](https://developer.ui.com/protect/v7.3.70/get-v1camerasidrtsps-stream) | `streams` | The existing `high`, `medium`, `low`, and `package` URL values, each nullable |
| Independently verified owner configuration | Optional `rtsp` | Exact plaintext URLs explicitly approved by the operator; this is an FSS field, not a Protect API response |

The local Protect integration API is under `/proxy/protect/integration` and
uses `X-API-Key` authentication. The public
[Protect API reference](https://developer.ui.com/protect) also documents the
UniFi Connector route. FSS does not fetch these responses, authenticate to
Protect, enable streams, or change camera settings. Keep API keys, cookies,
passwords, and Authorization headers out of the handoff and command line.
The source file needs only the returned camera metadata and stream URLs.

Wrap the unchanged selected camera object and its stream response as follows.
The following values are public placeholders; the two sets of URL tokens are
deliberately independent. Substitute actual exported objects and independently
verified plaintext endpoints through a private workflow.

```json
{
  "camera": {
    "id": "OWNER_CAMERA_ID",
    "modelKey": "camera",
    "name": "Porch",
    "type": "OWNER_REPORTED_MODEL",
    "state": "CONNECTED",
    "hasPackageCamera": true
  },
  "streams": {
    "high": "rtsps://192.168.1.10:7441/PROTECT_MAIN_TOKEN?enableSrtp",
    "medium": null,
    "low": null,
    "package": "rtsps://192.168.1.10:7441/PROTECT_PACKAGE_TOKEN?enableSrtp"
  },
  "rtsp": {
    "high": "rtsp://192.168.1.10:7447/OWNER_VERIFIED_MAIN_TOKEN",
    "package": "rtsp://192.168.1.10:7447/OWNER_VERIFIED_PACKAGE_TOKEN"
  }
}
```

The example camera object shows the fields relevant to selection. Preserve
other vendor fields in a real export; the parser tolerates and retains additive
camera metadata and stream-response fields. The FSS wrapper itself accepts
only `camera`, `streams`, and optional `rtsp`, and the operator `rtsp` map accepts
only the four known quality names. Duplicate JSON keys, unexpected types, and
trailing document data are refused.

Store the file at an absolute path, for example
`/owner/private/porch-protect.json`. The Linux file reader requires a nonempty
regular file, owner-read permission, no group or other permissions, exactly one
hard link, and no symbolic-link path. A typical file mode is `0600`. The
file must remain outside both recording destinations. Compute its SHA-256
over the exact bytes, including whitespace, and use `sha256:HEX` as
`--unifi-digest`. For example, `sha256sum /owner/private/porch-protect.json`
reports the hex portion without exposing the file contents.

The CLI accepts up to 256 KiB for this one-camera handoff. The pure integration
parser separately accepts documents up to 1 MiB and catalogs up to 512 cameras.
Both use the shared strict JSON parser with depth, node, and string bounds.
Endpoint syntax is bounded to 4,096 bytes in the integration core; native
capture further restricts it to 2,048 bytes and its existing control-URI rules.

## Select a quality and transport explicitly

`--quality high|medium|low|package` is required. Selection has no fallback:

| Exported state | Result |
| --- | --- |
| Selected key contains a valid URL | Use that exact endpoint |
| Selected key is `null` | Refuse the disabled/unavailable quality |
| Selected key is absent | Refuse the missing quality; do not treat omission as `null` |
| `package` requested without `hasPackageCamera: true` | Refuse unsupported or unproven package capability, even if a package URL is present |
| Camera state is disconnected, connecting, missing, or unknown | Preserve that metadata; permit an explicitly selected attempt because the export may have aged |

The official
[stream creation endpoint](https://developer.ui.com/protect/v7.3.70/post-v1camerasidrtsps-stream)
documents `package` as available only for cameras reporting
`hasPackageCamera: true`. FSS consumes existing streams and never calls the
creation endpoint. A missing or disabled quality must be resolved in the
owner's Protect workflow, followed by a refreshed private export.

The default `--stream-transport published` selects from `streams`. An RTSPS
endpoint stays secure in the parsed representation and is refused by this
plaintext recorder. `--stream-transport operator-rtsp` instead selects the
same requested quality from `rtsp`; that map must contain an actual `rtsp://`
URL. It cannot contain RTSPS and never falls back to `streams`.

Ubiquiti's current
[Required Ports Reference](https://help.ui.com/hc/en-us/articles/218506997-Required-Ports-Reference)
lists TCP 7441 for outgoing RTSPS and TCP 7447 for outgoing RTSP. Those port
assignments do not authorize changing a particular exported endpoint. Verify
the actual plaintext route on the owner's deployment before supplying it.
FSS does not derive a plaintext URL by changing `7441` to `7447`, deleting the
`s`, or removing `?enableSrtp`.

Supply a literal `--peer IP:PORT`. Its port must equal the selected endpoint's
explicit port, or RTSP port 554 if omitted. An IP-literal URL host must equal
the peer IP. A hostname remains an exact authority mapped to the supplied peer;
FSS performs no DNS lookup. IPv6 URI authorities use brackets, and the peer
uses the usual `[IPv6]:PORT` syntax. Credentials in URI userinfo, fragments,
invalid authorities, malformed escapes, and control characters are refused.

## Preview and record one view

Start from the [native capture arguments](rtsp_capture_cli.md), remove
`--authority` and `--presentation`, and add the private source, its digest,
the exact quality, and an explicit codec. The endpoint supplies authority and
presentation internally, so tokens do not enter the shell's argument list.
`from-unifi` requires `--codec avc|hevc`; a model label or quality name does not
select it.

For an independently verified AVC endpoint configured to send payload 96 at
25 pictures per second, this example reviews one bounded main-view recording.
Set the digest variables to the actual nonzero owner identities described in
the native guide, and set `UNIFI_DIGEST` to the exact private-file digest.
Create the parent directories in advance; both destination directories must
be new and independent.

```sh
fss-capture-rtsp from-unifi \
  --unifi-source /owner/private/porch-protect.json \
  --unifi-digest "$UNIFI_DIGEST" \
  --quality high --stream-transport operator-rtsp \
  --peer 192.168.1.10:7447 --codec avc --payload-type 96 \
  --root /owner/private/porch-main-archive \
  --pins /owner/recovery/porch-main-pins \
  --sensor-id sensor:porch-main --stream-id stream:porch-main \
  --generation 1 --ingress 1 --ssrc auto \
  --anchor "$SOURCE_ANCHOR" --receive-clock "$RECEIVE_CLOCK" \
  --timing-evidence "$TIMING_EVIDENCE" --journal-id "$JOURNAL_ID" \
  --frame-duration-ticks 3600 --stop-after-pictures 50 \
  --owner-authorized yes --plaintext yes --retain-originals yes
```

Without `--approve`, the command reads and validates the protected source and
destination parents, then prints a redacted plan. It creates no recording
directories and contacts no camera. The plan's schema is
`fss.rtsp_from_unifi_plan.v1`; it shows the chosen view and quality, a hashed
camera reference, transport choice, native capture plan, and an **outer**
approval. Its `hardware_qualified` and `effects_started` fields are false.
Both presentation and control-root URIs are redacted even when a private
stream token occurs only in the path and has no query.

Review that plan and repeat exactly with `--approve sha256:HEX` using its outer
approval, not the nested native approval. Approval binds the source bytes,
file identity, quality, transport, capture mode, and underlying capture plan.
The file's contents, identity, and permissions are rechecked before native
capture. Replacing a file with identical bytes changes its identity and needs
a new preview and approval. Changes to mode, codec, timing, peer, source
identities, destinations, or limits also require a new approval.

The default control root is the selected endpoint's exact path without its
query. The RTSP client honors a scoped `Content-Base` or `Content-Location`
and resolves the selected SDP control URI within that subtree. In particular,
an endpoint ending in `/TOKEN` is not rewritten to `/TOKEN/`; a server can
advertise the latter as its control base. A relative track that resolves
outside the approved subtree is refused. If the deployment needs a different
subtree, provide an independently reviewed `--control-root` explicitly. Do
not broaden it merely to bypass a refusal.

### SSRC selection

An RTP synchronization-source identifier can be chosen by the RTSP server per
session. `--ssrc auto` learns it once from the selected SETUP response, or from
the first structurally valid RTP packet on the selected interleaved channel
with the expected payload type when SETUP omits it. The actual observed SSRC
is retained in the recorded source keys and reported as `source_binding`.
The peer, channel, payload, ingress, and generation remain independently
constrained. A later sender change terminates the attempt; no rebinding occurs.
This establishes stream identity, not authentication of the camera.

Automatic SSRC selection is supported only for single AVC/HEVC capture. It is
refused for reconnect and source-first `retain-source` modes. For those modes,
provide the independently known numeric SSRC. A numeric `--ssrc N`, including
zero, remains an exact pin and is never interpreted as automatic selection.

### Package views, HEVC, and frame timing

The high, medium, and low qualities are renditions of the main view. Package
is a distinct camera view, not a fourth resolution of the same scene. Use
separate owner-assigned sensor/stream identities and recording destinations
for main and package captures. The core preserves `(camera id, main)` versus
`(camera id, package)` as distinct view identities; camera IDs remain scoped
to their originating Protect console and are not global FSS sensor IDs.

Choose codec, payload, cadence, generation, source anchor, and clock evidence
for the selected view. Neither the camera name nor `hasPackageCamera` supplies
these values. For example, Ubiquiti's
[G6 Entry specifications](https://techspecs.ui.com/unifi/physical-security/uvc-g6-entry)
describe a portrait main camera up to 30 FPS and a package camera up to 3 FPS.
The [G6 180 specifications](https://techspecs.ui.com/unifi/physical-security/uvc-g6-180)
describe a 7680 by 2160 panoramic image up to 20 FPS. These are product maxima,
not proof of a particular configured stream or bitstream's compatibility.

At a 90,000 Hz RTP clock, a confirmed fixed cadence of 3 FPS uses
`--frame-duration-ticks 30000`; confirmed 20, 25, and 30 FPS use 4500, 3600,
and 3000 ticks respectively. Do not copy the main-view cadence to a package
view. A missing interval, cadence drift, or timestamp discontinuity is a
capture refusal, not permission to fabricate timing.

For a confirmed HEVC stream, use `--codec hevc` and `--payload-type` with the
actual advertised payload. Native capture selects that exact mapping even
when SDP offers several H.265 payloads; it does not switch to another offer
or borrow that offer's parameter sets. Selected SDP must provide a compatible
VPS/SPS/PPS, or the operator must supply the exact tuple
using `--hevc-vps`, `--hevc-sps`, and `--hevc-pps` as described in the native
guide. FSS does not change camera encoding settings or transcode to AVC.
Audio, PTZ control, two-way talk, motion events, and multisensor stitching are
not provided by this recording handoff.

## Reconnect, retained media, and diagnostics

`--capture-mode reconnect` delegates to the existing bounded reconnect owner
with its explicit attempt, duration, watchdog, retry, and retention options.
It requires a numeric SSRC and the wrapper's own outer approval. See
`fss-capture-rtsp reconnect --help` for the exact options and independently
bounded attempt paths. Recovery uses the existing separately approved
recovery protocol; it never resumes camera capture. Changing the private
source or selecting another quality does not silently redirect a running
capture.

Preserve the archive, independent pin journal, and complete runtime JSONL
receipts. Only `window_durable` and `catalog_published` references name
ordinary retained media. Import those exact references using
[`fss-import-rtsp`](rtsp_recording_import.md) or the
[whole-catalog importer](RTSP_CATALOG_IMPORT.md), selecting the actual codec.
The native importer verifies original source custody and supports verification
and decode after the capture archive is offline. A partial attempt can leave
a useful durable prefix; a failure or early socket EOF is not complete coverage.

| Error code | Meaning and next action |
| --- | --- |
| `ERR-CAPTURE-UNIFI-SOURCE-001` | Invalid source shape, digest, arguments, or URI for the native profile. Inspect the private file and exact command without printing private URLs. |
| `ERR-CAPTURE-UNIFI-TRANSPORT-001` | RTSPS needs secure transport, or the separately selected operator RTSP map is missing or invalid. FSS performed no downgrade. |
| `ERR-CAPTURE-UNIFI-ROUTE-001` | The endpoint port or IP-literal host differs from the explicit peer. Correct the owner-approved route. |
| `ERR-CAPTURE-UNIFI-STREAM-MISSING-001` | The selected quality key was omitted. Refresh the export or explicitly select another available quality. |
| `ERR-CAPTURE-UNIFI-STREAM-DISABLED-001` | The selected quality is `null`. Resolve stream enablement in Protect and refresh the export. |
| `ERR-CAPTURE-UNIFI-PACKAGE-001` | The camera did not explicitly report package capability. Use a supported main quality or refresh the capability export. |
| `ERR-CAPTURE-UNIFI-APPROVAL-001` | File identity, selection, or native plan changed. Preview again and approve the complete current plan. |
| `ERR-ONVIF-PRIVATE-FILE-001` | The shared private-file reader refused the source's permissions, links, identity, size, or I/O. The historical error family is shared with ONVIF handoffs. |

Native protocol, codec, timing, storage, and recovery errors retain their
existing error contracts. Keep their receipts and use the native capture
guide to assess durable media and unsettled work. Synthetic integration
fixtures exercise exact selected request targets, private-token redaction,
main/package AVC and package HEVC recording, cold decode, transport/quality
refusals, and file revalidation. Physical-camera qualification remains an
independent deployment task.

## Run the focused regression suites

Use the repository's pinned toolchain and locked dependency closure:

```sh
cargo test --locked --offline -p fss-core --lib json_input::
cargo test --locked --offline -p fss-reference --lib unifi::
cargo test --locked --offline -p fss-reference --test rtsp_ssrc_selection_contract
cargo test --locked --offline -p fss-cli --bin fss-capture-rtsp automatic_ssrc
cargo test --locked --offline -p fss-cli --test capture_rtsp_cli unifi::
cargo test --locked --offline -p fss-cli --test capture_rtsp_cli ssrc
```

The last two commands require the real capture, import, and file-decode binaries.
They run loopback camera fixtures and verify retained source and cold decoding;
parser/protocol tests alone do not establish that end-to-end result. These tests
also do not replace `scripts/qualify.sh` or physical-device qualification.
