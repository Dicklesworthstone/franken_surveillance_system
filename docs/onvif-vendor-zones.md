# Source-verified ONVIF vendor zones

`fss-onvif-metadata zones` evaluates retained vendor bounding boxes against an
explicit rectangle policy. It returns complete source-linked observations and
changes between observations. It reuses the original tracklet identities, retains
unknown evidence, and applies no coordinate transform or physical calibration.

The native command and retained owner are implemented. The actual production-source
geometry, policy, projector and inner renderer passed **24 tests**. Native owner
and complete CLI execution remain unestablished after the genuine Asupersync
dependency builds were killed before FSS diagnostics; see validation below.

## Query existing sources

Use exact identities and publication roots from existing XML, PullPoint, RTP-file
or finite native RTP capture receipts:

```sh
fss-onvif-metadata tracks \
  --root /absolute/path/to/deployment \
  --site site:lab \
  --xml-source "${IMPORT_ID}@${PUBLICATION_ROOT}" > tracks.json

fss-onvif-metadata zones \
  --root /absolute/path/to/deployment \
  --site site:lab \
  --xml-source "${IMPORT_ID}@${PUBLICATION_ROOT}" \
  --policy /absolute/path/to/zone-policy.json
```

Use `--rtp-source` for an RTP source. Both source flags can repeat in the requested
order, with at most 32 distinct identities. Each independently supplied pin remains
a continuity boundary. The original import file is unnecessary: the query reads
and verifies retained originals, including native original observations where present.

The deployment must already exist. Normal exclusive publisher opening may perform
recovery housekeeping; this is the existing retained-source owner, not a forensic
mount. The command does not initialize a missing deployment, acquire camera data,
publish a derived root, or reconcile pending external effects.

## Declare the coordinate domain

The [policy schema](../schemas/onvif_vendor_zone_policy.v1.json) is closed and
requires 1–16 zones. Every zone pins four values from the original tracks report:

| Policy field | Original report field |
|---|---|
| `scope` | Selected frame's `scope`, binding its sensor/device/profile/parser/transport generation |
| `module_digest` | Selected frame's non-null `module_digest` |
| `frame_transform_digest` | Selected frame's `transformation_digest` |
| `object_transform_digest` | Selected occurrence's `transformation_digest` |

The transform digests identify the exact declarations, including absence. They
do not cause a transform to be applied. Missing scale, translation, image dimensions,
axis direction or calibration is never filled in with an assumed default.

Coordinates use `raw_vendor_object_millionths`: **1,000,000 integer subunits per
raw vendor coordinate unit**. Supply `min` and `max` as strict numeric-axis bounds
and `margin` as a nonnegative expansion of the complete claimed box. Each bound
must lie between −10^15 and +10^15 subunits; margin is at most 10^15. Zone IDs are
unique, 1–64 ASCII letters/digits/hyphens/underscores. Unknown fields, fractional
or exponent-spelled policy numbers, duplicate IDs, zero/malformed pins, and
degenerate rectangles are refused.

This example derives all four pins from a selected occurrence. Set its numeric
bounds to the intended region in your source's raw coordinates. The illustrated
unit square does not imply a normalized image or an image-wide region.

```sh
python3 - tracks.json /absolute/path/to/zone-policy.json <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    tracks = json.load(source)
occurrence = tracks["occurrences"][0]  # Select the intended source/module occurrence.
frame = tracks["frames"][occurrence["frame_ordinal"]]
if frame["module_digest"] is None:
    raise SystemExit("Select an occurrence from a named analytics module")
policy = {
    "schema": "fss.onvif_vendor_zone_policy.v1",
    "coordinates": "raw_vendor_object_millionths",
    "zones": [{
        "id": "loading_area",
        "scope": frame["scope"],
        "module_digest": frame["module_digest"],
        "frame_transform_digest": frame["transformation_digest"],
        "object_transform_digest": occurrence["transformation_digest"],
        "min": [0, 0],
        "max": [1_000_000, 1_000_000],
        "margin": 0,
    }],
}
with open(sys.argv[2], "w", encoding="utf-8") as target:
    json.dump(policy, target, indent=2)
    target.write("\n")
PY
```

The command reads one regular UTF-8 policy file of at most 64 KiB under the native
request's deadline and cancellation owner. Its separate 65,537-byte reservation
includes the trailing probe used to detect growth after the file-size check. The
policy is parsed before opening retained source custody.

## Interpret complete boxes conservatively

The geometry helper reads the original decimal lexemes and computes exact outward
rounding onto the millionth grid using bounded integer arithmetic. It handles
negative values, significant tails and exponents without converting through binary
floating point. Margin arithmetic uses `i128`. The original frozen wire parser
still owns its finite-number and lexical-range admission rules.

| Relation | Meaning |
|---|---|
| `inside` | The complete outward-rounded, margin-expanded box is strictly inside the declared rectangle |
| `outside` | The complete expanded box is strictly separated from the rectangle on at least one numeric axis |
| `boundary` | Touching, intersecting, or within rounding/margin uncertainty |
| `unavailable` | The coordinate domain or complete supported geometry cannot be established |

Unavailable reasons distinguish wrong scope/module/frame/object transformation,
missing module/appearance/shape, uninterpreted source or opaque frame/object/shape
content, and unsupported coordinates. Unknown content remains unknown even when
some useful-looking numeric fields are present. No unavailable observation is
counted as outside or as physical absence.

Every supplied occurrence has one cell for every requested zone. Every supplied
frame also has a sample for every zone, including empty and wrong-domain frames.
Zero counts mean zero admitted observations in that row; they do not certify that
a physical region was empty or covered by a camera.

## Track changes between observations

Transitions stay within one unchanged original vendor tracklet and one zone:

| Kind | Meaning |
|---|---|
| `observed_inside` | First definite inside observation after no established side |
| `entered_between_observations` | A definite outside observation is followed by a definite inside observation |
| `left_between_observations` | A definite inside observation is followed by a definite outside observation |
| `observation_interrupted` | Previously established side support becomes unavailable |

Every transition names its current original occurrence, original tracklet identity,
and previous definite occurrence where applicable. Boundary observations establish
no side; a later transition refers to the actual preceding definite observation.
Unavailable observations clear that state. Original tracklet breaks still prevent
continuity across source, generation, transport, time, missing-object or opaque
lifecycle boundaries. No trajectory, crossing instant, capture clock or dwell
duration is interpolated.

Lifecycle and zone queries have independent versioned semantics. To correlate their
rows, require the same `analysis.tracklet_report_digest` and use the exact original
occurrence references. A lifecycle explanation does not rewrite old tracklets or
grant a missing geometry basis. Neither query creates an authority event or effect
permission, and neither establishes physical identity or departure.

## Complete result and commitments

The [report schema](../schemas/onvif_vendor_zones_report.v1.json) describes one
complete JSON document, bounded to 32 MiB:

| Field | Contents |
|---|---|
| `tracklets` | Complete original source receipts, authority anchor, groups, occurrences, frame handles and cumulative source/work usage |
| `analysis.policy` | Complete operator policy in declared zone order |
| `analysis.cells` | Every occurrence × zone classification and explicit unavailable reason |
| `analysis.frame_samples` | Every frame × zone accounting row, including empty frames |
| `analysis.transitions` | All admitted side changes/interruption observations with original occurrence references |
| `snapshot_digest` | Source-verified snapshot binding original custody, semantic policy, complete result and limits |
| `policy_input` | Exact policy-file SHA-256, byte length and separate read reservation |
| `query_digest` | Snapshot plus exact policy-file digest/length |

The semantic policy digest ignores JSON whitespace and object-key order. Exact
policy-file bytes remain separately committed, so a whitespace-only edit changes
`query_digest` while preserving the semantic result. Original tracklet groups,
occurrence identities and pure report digest stay unchanged; the enclosing snapshot
and usage include additional zone-query work.

Raw vendor module names, integer ObjectIds and timestamps are withheld by default.
`--include-values yes` releases those original values in the nested tracks report.
The zone projection itself contains source indices, relations and the explicitly
supplied operator policy. Operator zone names and coordinates are always reported.

## Bounds and source verification

Both complete original-source and zone-projection passes use one nonrenewing
indexed read and work allowance. They must produce identical complete results,
followed by durable ledger-head and effect-store verification after the final
admission callback. Each zone projection replays the genuine frozen tracklet
projector and requires full equality before consuming any associations. The
comparison, geometry input commitment, complete matrix and canonical serialization
are separately charged; final owner commitment work is prepaid within the passes.

Defaults are 32 Mi work units for the complete source query and 4,000,000 for each
zone projection, including its original tracklet replay allowance. The pure
ceilings are 65,536 cells, 16,384 frame samples, 65,536 transitions and 8 MiB
canonical output. These are independent ceilings: a large request can need larger
work allowances even while its row counts fit. A limit refusal produces no
successful prefix or hidden top-k result.

All `tracks` options are accepted. `--max-analysis-work` and
`--max-analysis-bytes` control the zone projection. Impossible two-pass work
policies fail before source I/O. Policy-file bytes cannot enlarge the installed
source-spool byte/read limits. Opening recovery and metadata/open syscalls retain
the existing deployment bounds outside indexed-source counters. Work units are
deterministic conservative accounting, not CPU timing measurements.

## Validation scope

The pinned actual production-source zones target passed **24/24**: 20 new cases
and four existing embedded wire tests. It used the genuine current `fss-core`,
production ONVIF parser, original tracklet projector, exact geometry, zone policy
parser/projector, JSON primitives and inner renderer. Cases cover signed/tiny
decimal rounding, source/report tampering, every domain pin, complete empty and
multi-zone matrices, missing/opaque geometry, transitions, exact work/output
limits, cancellation and privacy. Independent source review found no remaining
blocking geometry, source-pairing or accounting issue.

Seven genuine native owner tests, two CLI argument tests and three actual-process
tests are authored and source-reviewed. Both process-test harnesses typechecked
with the pinned compiler and genuine core library. **Native owner/CLI compilation
and process execution are not established.** Earlier full dependency builds were
killed inside unchanged Asupersync before FSS diagnostics; no replacement owner,
runtime or dependency was introduced.

Pinned recursive rustfmt checks resolve and parse both complete CLI and reference
metadata module trees. They exposed and fixed explicit child-path wiring for the
tracks/lifecycle/zones wrappers. Whitespace checks and schema JSON/structure/source
consistency checks pass. No installed standard JSON Schema validator was available;
formal schema validation and release/device qualification remain unclaimed.

```sh
cargo test --locked --offline -j1 -p fss-core --test onvif_vendor_zones_contract
cargo test --locked --offline -j1 -p fss-reference --test onvif_metadata_zones_custody
cargo test --locked --offline -j1 -p fss-cli --bin fss-onvif-metadata
cargo test --locked --offline -j1 -p fss-cli --test onvif_metadata_zones_cli
```
