# Automatic scene reconstruction from retained camera frames

`fss-scene-fuse retained-match` discovers image correspondences directly from two
authenticated retained camera frames and reconstructs conditional stationary
points in the imported property twin. It connects the existing retained source,
native JPEG/AVC/HEVC decode and current privacy owners to native FAST/BRIEF,
symmetric descriptor association, nominal epipolar gates and point fusion.

```sh
fss-scene-fuse retained-match \
  --root deployment --site site:example \
  --twin property.fsstwin --rig cameras.json --query retained-pair.json \
  --report-out reconstructed.json
```

The source selection names original recordings and segments. No manually
exported images, supplied feature coordinates or trained detector are needed.
The result preserves every candidate pair, ambiguous feature, selected point
and geometric refusal. It is a derived report; camera calibration, world
publication, physical identity, events and effects are not activated.

For **three through eight retained camera frames**, use
[`retained-multimatch`](RETAINED_MULTICAMERA_MATCHING.md). It reuses these exact
source contracts and adds complete camera-pair evidence, explicit correspondence
components and joint static geometry.

## Select exact retained evidence

The deployment must already exist and contain completed imports. The original
input path may be gone; the command opens retained custody and any required
original HTTP/RTSP provenance. A published root without completed import
authority, missing original bytes, a stale privacy binding or an incomplete
video range refuses the request.

The existing native decode command now prints the selection identities needed
by this workflow, without requiring a pixel export:

```sh
fss-file decode --root deployment --site site:example \
  --import-id sha256:IMPORT_HEX --segment 12 --interpretation ycbcr
```

Its `source_import_identity`, `source_segment`, `source_capsule_digest`,
`source_encoded_digest`, `source_sensor_id`, `source_stream_id` and
`source_clock_basis` lines identify the actual selected source. JPEG decoding
retains its ordinary derivative; AVC/HEVC decode prints those identities for
each emitted frame of the explicitly requested range. For video, select by
original coding segment, not by display/output index.

All source pins are checked against retained capsule metadata **before** the
matching command enters the decoder. The native owner then authenticates the
actual bytes. Hashes select and verify content; they do not validate camera
placement, clock alignment or a physical landmark association.

## Strict query

The schema is `schemas/scene_feature_match_retained_query.v1.json`. The top-level
matching choices are the same explicit choices documented for
[local JPEG matching](SCENE_FEATURE_MATCHING.md). Replace all symbolic digest
placeholders below with complete, independently selected SHA-256 identities:

```json
{
  "schema": "fss.scene_feature_match_retained_query.v1",
  "camera_rig_digest": "sha256:RIG_HEX",
  "privacy_domain": "1",
  "clock": "1",
  "clock_evidence": "sha256:COMMON_CLOCK_BASIS_HEX",
  "association_basis": "sha256:STATIC_SCENE_BASIS_HEX",
  "reference_time_ns": "1500000000",
  "max_capture_span_ns": "100000000",
  "motion": "static_during_capture_hull",
  "left": {
    "camera": "1",
    "image_domain_digest": "sha256:LEFT_IMAGE_DOMAIN_HEX",
    "mapping_basis": "sha256:LEFT_CAMERA_MAPPING_HEX",
    "sigma_pixels": 0.5,
    "source": {
      "codec": "jpeg",
      "import_identity": "sha256:LEFT_IMPORT_HEX",
      "segment": "12",
      "capsule_digest": "sha256:LEFT_CAPSULE_HEX",
      "encoded_source_digest": "sha256:LEFT_JPEG_HEX",
      "sensor_id": "sensor:left",
      "component_interpretation": "ycbcr"
    },
    "alignment": {
      "import_identity": "sha256:LEFT_IMPORT_HEX",
      "stream_id": "stream:left:g1",
      "clock_basis": "estimated",
      "offset_ns": ["0", "0"],
      "basis": "sha256:LEFT_CLOCK_ALIGNMENT_HEX"
    }
  },
  "right": {
    "camera": "2",
    "image_domain_digest": "sha256:RIGHT_IMAGE_DOMAIN_HEX",
    "mapping_basis": "sha256:RIGHT_CAMERA_MAPPING_HEX",
    "sigma_pixels": 0.5,
    "source": {
      "codec": "jpeg",
      "import_identity": "sha256:RIGHT_IMPORT_HEX",
      "segment": "9",
      "capsule_digest": "sha256:RIGHT_CAPSULE_HEX",
      "encoded_source_digest": "sha256:RIGHT_JPEG_HEX",
      "sensor_id": "sensor:right",
      "component_interpretation": "ycbcr"
    },
    "alignment": {
      "import_identity": "sha256:RIGHT_IMPORT_HEX",
      "stream_id": "stream:right:g1",
      "clock_basis": "estimated",
      "offset_ns": ["-1000000", "1000000"],
      "basis": "sha256:RIGHT_CLOCK_ALIGNMENT_HEX"
    }
  },
  "extraction": {"threshold": 20, "maximum_features": 64, "separation": 5},
  "matching": {
    "maximum_hamming_distance": 48,
    "ratio_percent": 80,
    "maximum_epipolar_distance_pixels": 1.5
  }
}
```

Unknown, duplicate, missing or malformed fields refuse. Exact integer fields
accept canonical decimal numbers or decimal strings; strings avoid rounding
large nanosecond values in JSON clients. Native validation checks the complete
integer range, rejects fractional/exponent spellings and negative zero, and
never narrows time through floating point.

The optional `triangulation` object has the same bounded settings as local
matching. Both selected views must support each point (`min_views: 2`,
`max_outliers: 0`). The declared rig must use the same privacy namespace and
common clock as the query. Native source dimensions must equal its camera mode.
The two sources must have distinct retained sensor IDs, source byte identities
and exposures. Repeating a retained sensor under another camera label refuses;
those IDs alone do not independently certify physical camera placement.

### AVC and HEVC selection

For AVC, replace a view's source object with:

```json
{
  "codec": "h264",
  "import_identity": "sha256:IMPORT_HEX",
  "segment": "12",
  "capsule_digest": "sha256:CAPSULE_HEX",
  "encoded_source_digest": "sha256:ACCESS_UNIT_HEX",
  "sensor_id": "sensor:left",
  "first_segment": "8",
  "segment_count": "8"
}
```

Use `h265` for HEVC. AVC ranges must start at an admitted IDR and HEVC ranges at
an admitted IRAP. `segment_count` is 1–64 and the selected coding segment must
lie in the checked range. AVC/HEVC use the existing native YCbCr interpretation;
the JPEG-only `component_interpretation` field is rejected. Existing Annex-B,
MP4 and Matroska source formats follow their native retained decoder support.

The complete range must decode successfully, including later or buffered
pictures. A selected frame followed by a malformed access unit cannot escape
as a successful partial result. A skipped/non-output coding segment does not
become a guessed image. Container structure and parameter-set custody are
rechecked during final validation.

## Privacy, image domains and timing

The current retained policy supplies the allowed-pixel mask. Every complete
33×33 descriptor footprint must be allowed; replacing a private pixel with a
public constant does not authorize using a feature supported by that region.
There is no caller-provided mask or `all_allowed` override in this query.
The explicit no-current-policy binding is also retained and revalidated.

`image_domain_digest` and `mapping_basis` declare that the source pixels belong
to the selected **undistorted pinhole** camera mode. This command does not
silently correct lens distortion, apply Exif orientation, fit a crop or promote
a nominal rig into measured calibration. An incompatible mode refuses.

The source capsule supplies its complete original capture interval and clock
basis. The alignment declaration supplies an additive interval, applied as a
checked Minkowski sum: `[earliest + offset_min, latest + offset_max]`. For
example, `[1000,1010] + [-10,20]` becomes `[990,1030]`. Negative scene times and
overflow refuse. The full aligned intervals must fit camera validity, and their
complete hull must fit the declared span and contain the requested scene time.
The span is at most one second. An `estimated` source clock remains estimated;
an offset digest does not establish measured synchronization.

## Output and revalidation

The `fss.scene_feature_match_retained.v1` envelope hashes the exact UTF-8 report
body. Its immutable analysis contains the original query, entry and final
authority anchors, exact twin/rig identities, all source capsules and native
receipt bytes, current privacy bindings, selected features, all Cartesian
descriptor/epipolar decisions and every point estimate/refusal. The original
capture intervals and the separately aligned intervals are both present.

JPEG's existing decode publication can advance the deployment anchor or finish
before a later matching refusal. The report therefore records both entry and
post-decode anchors. The first frame remains valid when decoding the second
publishes another ordinary derivative; its original source and privacy pins
still must match. `--expected-anchor` checks the entry anchor. `--expected-input`
checks the exact query document before source work.

After building the complete source-dependent analysis, the sealed owners reopen
the selected source ranges and current privacy. Missing/tampered/deleted source,
changed privacy, a wrong authority context or resource exhaustion refuses the
whole report. Only bounded wrapping of the immutable analysis and final cost
counters follows this check. No partial geometry or image is returned on failure.

Geometry reports conditional pixel-noise covariance, residuals, ray angles,
conditioning and nominal mesh occlusion conflicts. Camera/map/clock errors,
shared failure modes, motion and correspondence error are not included in that
covariance. Custody does not establish live coverage or physical identity.

## Bounded work and outputs

The independent cumulative resource axes are:

| Axis | Command allowance |
|---|---|
| Original source reads, including original HTTP/RTSP provenance and final checks | 4 GiB |
| JPEG native decoder work | 500,000,000 units |
| Video encoded-byte admission | 256 MiB |
| Video coded-luma capacity admission | 536,870,912 units |
| Geometry, masks, feature extraction and report work | Default 2 billion; configurable up to 5 billion |
| Decoded image | At most 4,096 per axis and 4,194,304 pixels |
| Features and complete pair inventory | At most 128 per view and 16,384 pair rows |
| Complete report | At most 8 MiB, including newline |

These are separate accounting models. Video capacity includes buffered, skipped
and unsuccessful work; it is not a measurement of decoded output pixels or CPU
time. Cloning a source allowance or opening another range does not renew it.
The report includes final source-read costs and labels CPU time, energy and
peak memory as unmeasured.

The default timeout is 30 seconds; the maximum is one hour. Owned source probes,
JPEG work charges and geometry work charges check cancellation/deadlines.
Video additionally uses the existing context checkpoints and native access-unit
boundaries. No detached timer or background runtime is created.

`--report-out` exclusively creates a new private file with the same bytes as
stdout. Existing files and symlinks refuse. A final write error can leave a
partial new file, and stdout failure can follow a completed report file; neither
is reported as success. Exit 0 means at least one reconstructed point and no
selected geometric refusals; exit 3 means no reconstruction or some selected
refusals; exit 2 means an input, custody, privacy, authority, resource or I/O failure.

This is a source-backed static-feature slice of FSS-099, not closure of its
moving-object association or field-quality requirements. See
`IMPLEMENTATION_STATUS.md` for the exact executed-test and command-build evidence.
