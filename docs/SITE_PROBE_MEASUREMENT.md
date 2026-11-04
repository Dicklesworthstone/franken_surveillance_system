# Measure site probes from recorded RTSP/RTP evidence

`fss site probe-file` produces a site probe receipt from one complete recorded RTSP
DESCRIBE response and a bounded RTPdump sample. It derives codec configuration,
payload type, SSRC, picture count and RTP cadence through the existing native
protocol parsers, depacketizers and picture assemblers. These values can feed
[`fss site plan`](SITE_PLANNING.md) without hand-authoring media observations.

This is the offline measurement portion of VIT-003 in
[the footage-plane plan](VITTLES_FOOTAGE_PLANE_PLAN.md). It accepts direct RTSP and
NVR-channel sources using supported frame-only AVC, 8-bit HEVC with field
sequences excluded, or native RFC 2435 JPEG reconstruction. The separately
approved [live probe](SITE_PROBING.md) shares these media observers. Device
discovery, ONVIF/UniFi negotiation and a site recorder remain outside this command.
No network connection or credential read occurs.

## Run the retained example

The fixtures contain real picture syntax from the repository's existing synthetic
codec corpora. They use documentation-range addresses and do not represent a
camera observation. Build the normal `fss` binary with the pinned toolchain, then:

```sh
probe_manifest_pin="sha256:$(sha256sum fixtures/site_probe/manifest.v1.json | cut -d ' ' -f 1)"
probe_describe_pin="sha256:$(sha256sum fixtures/site_probe/avc.describe.rtsp | cut -d ' ' -f 1)"
probe_rtp_pin="sha256:$(sha256sum fixtures/site_probe/avc.rtpdump | cut -d ' ' -f 1)"

cargo run --locked -p fss-cli --bin fss -- site probe-file --json \
  --manifest fixtures/site_probe/manifest.v1.json \
  --manifest-digest "$probe_manifest_pin" \
  --source source:front --codec avc \
  --describe-response fixtures/site_probe/avc.describe.rtsp \
  --describe-digest "$probe_describe_pin" \
  --rtp-dump fixtures/site_probe/avc.rtpdump \
  --rtp-dump-digest "$probe_rtp_pin" > probe-observation.json

python3 - <<'PY'
import json
from pathlib import Path

report = json.loads(Path('probe-observation.json').read_bytes())
assert report['schema'] == 'fss.site_probe_observation.v1'
assert report['status'] == 'measured'
Path('probe-receipts.json').write_text(json.dumps(report['receipts']) + '\n')
PY

cargo run --locked -p fss-cli --bin fss -- site plan --json \
  --manifest fixtures/site_probe/manifest.v1.json \
  --probes probe-receipts.json \
  --archive-root /srv/fss/footage --pins-root /srv/fss/pins \
  --epoch 1 --stop-after-pictures 4
```

For HEVC, select `--codec hevc`, use `hevc.describe.rtsp` and `hevc.rtpdump`, and
compute their own exact byte pins. The expected AVC result is 23 RTP packets and
4 pictures; HEVC is 14 RTP packets and 3 pictures. For JPEG, select `--codec jpeg`,
use `jpeg.describe.rtsp` and `jpeg.rtpdump`, and compute their exact byte pins. Its
six fragmented packets reconstruct three frames on static payload 26. All measure 3600 ticks per
picture on the 90 kHz media clock, including sequence and timestamp wrapping.
Generation and provenance are documented in
[`fixtures/site_probe/README.md`](../fixtures/site_probe/README.md).

The three SHA-256 options are mandatory pins of complete file bytes. The example
computes them from the checked-in fixtures to make the command reproducible. For
retained evidence, supply independently retained expected hashes; hashing an
untrusted file immediately before reading it does not authenticate its origin.
The manifest's raw byte pin is distinct from its canonical typed identity.

## Inputs, scope and output

| Input or selection | Contract |
| --- | --- |
| `--manifest`, `--manifest-digest` | One complete strict site manifest, at most 1 MiB, and its exact raw SHA-256. |
| `--source` | One exact source ID in that manifest. No nearest match or route discovery. |
| `--describe-response`, `--describe-digest` | One complete RTSP 1.0 success response including headers and SDP body, at most 128 KiB, and its raw SHA-256. An SDP body alone is insufficient. |
| `--rtp-dump`, `--rtp-dump-digest` | One complete standard rtptools RTPdump, at most 8 MiB and 32768 records, and its raw SHA-256. |
| `--codec` | Explicit `avc`, `hevc` or `jpeg`; no fallback based on device branding. |
| `--media-index` | Exact SDP media index from 0 through 63; default 0. |
| `--rtp-channel` | Proposed even interleaved channel from 0 through 254; default 0, with RTCP on the next channel. RTPdump does not contain this transport observation. |

The file authority opens only the three named existing regular files. It checks
size, identity and metadata around the read, refuses final-path symlinks and
special files, and has a finite byte/operation budget. The current safe file-open
profile supports Linux and macOS; other targets refuse. It never creates capture
outputs or opens a referenced credential file.

A successful report follows
[`fss.site_probe_observation.v1`](../schemas/site_probe_observation.v1.json).
It includes all input digests, canonical manifest identity, evidence digest,
packet/picture counts and one `receipts` array. The array uses the existing
[`fss.site_probe_receipt.v1`](../schemas/site_probe_receipt.v1.json) contract.
Combine separately measured arrays only when they bind the same complete
manifest; the default site planner requires exactly one receipt for every source.
Use repeated `site plan --source SOURCE_ID` options with exactly the selected
receipts to plan a subset against that same unchanged manifest.
Successful receipts retain declared routes for planning and are private operator
metadata, even though raw banners, credentials and media bytes are omitted.

The evidence digest binds the canonical manifest/source selection, exact raw
response and dump digests, derived receipt, optional Server-header digest,
packet counts and measurement-policy bounds. SDP is hashed as received. Parameter
sets are hashed in native codec order. A Server header contributes only the
SHA-256 of its parsed, trimmed value; raw device banners never appear in output.
The complete response digest still binds every original header byte. If no
Server header exists, the report says so rather than inventing a device identity.

## Conditions for a measured receipt

At least three native syntax-grouped picture observations, or complete RFC 2435
JPEG reconstructions, with witnessed
boundaries must yield the same positive RTP timestamp delta, with at most 4096
observations. Each delta is limited
to 90000 ticks. Arithmetic supports 16-bit sequence and 32-bit timestamp wrapping.
All RTP packets must have the selected payload type and one stable SSRC, in exact
contiguous sequence order. RTCP framing is validated without promoting it into
synchronized capture time.

Malformed/truncated responses or dump records, extra response bytes, ambiguous
SDP/control routes, authentication challenges, packet loss, duplicates, reordering,
stream changes, codec-configuration drift and unfinished fragments or pictures
refuse the complete observation. RTP marker bits alone cannot prove a picture
boundary. Interlaced AVC, field-coded HEVC, variable cadence and picture timestamp
reordering are outside this profile; timestamps are not sorted and a favorable prefix is not
silently selected. The HEVC fixture closes its final picture with explicit EOS. JPEG must finish every
fragmented frame; offset gaps, missing markers, stale or conflicting quantizers,
unsupported types and inconsistent dimensions refuse the full recording. JPEG
receipts have an empty external-parameter digest array. The native reconstruction
profile does not decode or certify the image entropy.

Execution refusals use `fss.site_diagnostic.v1`, stable error IDs and exit code 2.
They contain no accepted receipt prefix, raw media, private paths or server banner.
Argument grammar errors use the existing CLI diagnostic contract.

## What the observation establishes

The observer establishes consistency of the supplied protocol bytes with the
declared source and selected native measurement profile. Witnessed picture
boundaries do not prove that every slice or macroblock is present. It does not
decode pixels, prove recording completeness, correlate the response with an actual
request, authenticate the sender, verify custody or establish current liveness.
The peer and route come from the manifest; the interleaved channel is explicitly
operator-selected. Neither is a newly measured network fact.

The report keeps device contact, credential access, origin authentication,
current-liveness verification, custody verification, clock synchronization,
rights verification and capture authorization false. Signed rights checks,
payment privacy enforcement and live negotiation remain the responsibility of
their existing or future owners. The resulting site plan still requires separate
native approvals and does not start recording.
