# Use captured RTP/JPEG images through retained media owners

`fss-import-rtsp jpeg` reconstructs the complete JPEG images in an exact saved
RTSP datagram prefix and publishes an ordinary retained MJPEG import. Existing
native JPEG decoding, image features and scene reconstruction can then consume
the returned import identity. The destination keeps the original datagram roots,
metadata and payloads alongside the reconstructed media and its origin proof.
Later source verification works with the capture archive offline.

This is a finite offline import. Use
[native JPEG capture](rtsp_jpeg_capture_cli.md) to acquire the source first. The
import command opens no camera connection and grants no event or alert action.
The AVC/HEVC window and catalog import contracts remain unchanged.

## Select the source and declare its physical camera mapping

Keep the independent capture receipts. Supply the original transport scope,
the exact four-field prefix pin, the accepted configuration evidence and the
explicit native replay interpretation. The prefix begins at observation one;
earlier quantization tables cannot be skipped when selecting later images.

The transport scope names a connection, generation and asserted RTP source.
It does not authenticate a physical camera. Supply the destination `--sensor-id`
and `--stream-id` separately, with `--mapping-evidence` naming the owner's
declaration that connects this source to those identities. This evidence is
an explicit owner assertion, not a device certificate or clock calibration.

```sh
fss-import-rtsp jpeg \
  --archive /owner/private/porch-jpeg-source \
  --root /owner/private/deployment --site site:home \
  --peer 192.168.1.40:554 --authority 192.168.1.40:554 \
  --ingress 41 --generation 1 --ssrc 7 \
  --rtp-channel 0 --rtcp-channel 1 \
  --receive-clock "${RECEIVE_CLOCK:?supply the original clock identity}" \
  --retention-evidence "${RTP_RTCP_RETENTION:?supply the source retention identity}" \
  --prefix-scope "${SAVED_SCOPE:?supply the independently saved scope digest}" \
  --prefix-head "${SAVED_HEAD:?supply the exact durable prefix head}" \
  --prefix-datagrams "${SAVED_DATAGRAMS:?supply its complete observation count}" \
  --prefix-bytes "${SAVED_PAYLOAD_BYTES:?supply its complete payload byte count}" \
  --configuration-evidence "${SAVED_CONFIGURATION:?supply accepted configuration evidence}" \
  --payload-type 26 --reduced-rtcp no \
  --sensor-id sensor:porch --stream-id stream:porch-jpeg \
  --mapping-evidence "${CAMERA_MAPPING:?supply explicit physical camera mapping evidence}" \
  --receive-time-ns 5000000000 \
  --owner-authorized yes --read-originals yes --retain-originals yes
```

Use the original source's actual channel pair, RTP payload and RTCP mode. The
route fields identify historical source; no network access follows from them.
Replay bounds are part of the declared interpretation. Changing them creates
a different request even when they happen to produce the same image bytes.

Without `--approve`, the command emits a complete JSON plan without filesystem,
clock or network access. Review that plan and repeat the exact request with its
approval digest. Any changed source, mapping, destination, interpretation or
bound requires the corresponding new approval. The original archive must exist;
source and destination paths must be absolute, distinct and non-nested.

## What remains in destination custody

The origin proof and publication retain:

- Every selected original datagram root, canonical metadata and original payload,
  including RTCP, probation, duplicate and unusable observations.
- The exact selected source scope and prefix, independent configuration evidence,
  complete replay limits and deterministic interpretation identity.
- Each complete reconstructed JPEG and its native source-map identity, including
  actual admitted packet dependencies, generated headers and earlier cached
  quantizer definitions.
- Original packet gaps, image refusals and incomplete-image retirement accounting;
  a later complete image retains an explicit preceding gap.
- The separate physical sensor/stream declaration and unknown capture-time state.

Generated interchange-JPEG headers remain derived bytes. A reconstructed image
digest does not imply that the camera sent that exact file, that its entropy is
valid, or that pixels have already been decoded. Native downstream decoding
establishes pixel validity under its own limits and current privacy policy.

Prefix exhaustion never becomes camera EOF. The owner does not invent a future
timer to flush an incomplete image. Malformed inputs and codec omissions remain
explicit; a receiver restart or terminal source refusal cannot be relabeled as
a completed import of the whole selected prefix. A prefix yielding no complete
image is refused, with no quiet-scene inference.

## Timing and downstream use

This initial import profile always preserves **unknown capture time**. Each
capsule has the conservative interval from zero through the independently
declared destination receive time and an estimated clock basis. Historical
packet receive timestamps drive deterministic replay only. RTP timestamps and
uncalibrated RTCP do not establish physical capture times. No frame-rate or
capture-origin option is accepted by this profile.

Success returns the retained import identity, publication root, manifest and
origin-proof pins. Use that identity with existing owners:

```sh
fss-file verify \
  --root /owner/private/deployment --site site:home \
  --import-id "${IMPORT_ID:?supply the completed retained import identity}"

fss-file decode \
  --root /owner/private/deployment --site site:home \
  --import-id "${IMPORT_ID:?supply the completed retained import identity}" \
  --segment 0 --segment-count 1 --interpretation ycbcr
```

Choose an actual retained segment range. Source-dependent reads verify native
packet ancestry from destination custody. Current sensor masks and deletion
authority still apply. Time-dependent consumers must retain their own timing
admission rules; this import supplies no synchronized-camera or continuous
presence claim.

## Independent limits and exact retries

The complete request has separate ceilings for selected datagrams and source
payload bytes, original closure bytes, reconstructed MJPEG bytes, complete images,
replay steps, cumulative custody reads and work. JPEG/reorder limits separately
bound packets, fragments, image dimensions, frame bytes, quantizer cache and
historical timers. A narrower ceiling refuses the complete operation; the
importer does not silently truncate frames or reset allowances per object.

| Option | Default | Maximum | Meaning |
|---|---:|---:|---|
| `--max-datagrams` | 8,192 | 8,192 | Complete selected source observations, including unusable ones |
| `--max-source-bytes` | 67,108,864 | 67,108,864 | Sum of original datagram payload bytes |
| `--max-original-bytes` | 67,108,864 | 67,108,864 | Complete original closure, including canonical roots and metadata |
| `--max-media-bytes` | 67,108,864 | 67,108,864 | Reconstructed MJPEG bytes, independently bounded |
| `--max-read-bytes` | 536,870,912 | 536,870,912 | Import-managed original/custody verification payload reservations |
| `--max-frames` | 256 | 4,096 | Complete reconstructed images; excess refuses the import |
| `--max-steps` | 100,000 | 262,144 | Native replay progress calls, including drains and timer advances |
| `--max-work` | 1,000,000,000,000 | 1,000,000,000,000,000 | Shared finite work allowance |
| `--timeout-ms` | 30,000 | 600,000 | Cooperative deadline at native ownership boundaries |

Each original also has independently bounded root/metadata/payload reads. A large
payload allowance alone cannot authorize unbounded metadata or repeated reads.
One JSON result is limited to 65,536 bytes. The plan lists the complete packet,
reorder and JPEG interpretation, the selected operation bounds and the fixed
source-storage ceilings. The v1 owner also imposes an intrinsic ceiling of
16,000,000,000 native replay work units, both when importing and when verifying
retained originals. A larger `--max-work` cannot bypass that ceiling; this keeps
an accepted import within the same replay contract used by downstream readers.

The read-reservation axis covers import-managed source verification and explicit
destination custody comparisons, including conservative complete source namespace
passes. It is not a total filesystem-I/O measurement: internal publisher recovery,
journal and metadata work retain their own native limits. Shared work and storage
admission remain additional bounds; the reported reservation is not a calibrated
latency, syscall or memory estimate.

Publication uses the existing retained-file root-last owner. An interrupted
attempt may have staged objects or durable progress. Preserve the exact request
and rerun its approval to reconcile that state. An exact completed retry returns
the same identities without duplicate import authority. Damage or deletion of
committed evidence is refused rather than repaired from reconstructed JPEGs.

Import retries require the selected source archive. Once completed, downstream
verification and analysis need only the retained destination. Local originals
remain unencrypted, with the existing private-storage and disclosure rules.
