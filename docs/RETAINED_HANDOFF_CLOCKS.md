# Retained handoffs with native clock replay

`fss-scene-fuse retained-handoffs` accepts the explicit
`fss.scene_handoffs_retained_query.v2` selection profile. It connects the existing
cross-session clock validator to authenticated retained detector tracks and the native
anonymous handoff planner. Existing v1 selections retain their declared additive offsets
and unchanged report format.

The v2 path derives common-clock capture intervals by rerunning an independently pinned
original `fss.clock_validation_query.v1` document. It retains **every declared offset/rate
hypothesis** in each time envelope, including hypotheses that fail every validation session.
The handoff planner tests its transit constraints against those complete intervals. A good
score for one clock hypothesis cannot quietly make a transition appear feasible.

```sh
fss-scene-fuse retained-handoffs \
  --root /path/to/existing/deployment --site site:example \
  --selection handoff-clock-selection.json \
  --report-out handoff-clock-report.json \
  --work-units 50000000
```

The command reconstructs native tracks from existing retained package detections. It does
not execute a detector, reacquire source files, publish an event or activate a clock. Original
source custody, current privacy and the full deployment anchor are revalidated by the same
opaque source owner immediately before output. Startup retains the deployment's existing
recovery behavior described in [the retained handoff workflow](RETAINED_HANDOFFS.md).

## Construct the selection

The top-level v2 fields are `schema`, `session`, `generation`, `cost_unit`, `birth_cost`,
`end_cost`, `k`, `selections`, `transitions` and `clock_validation`. The objective and transit
fields keep their v1 meanings. Costs are declared objective units, not probabilities, and
the full implicit alternative family accompanies the displayed ranked prefix.

Each selected track has `id`, `report_digest`, `label`, `tracking`, `track` and `source`.
The `source` value is exactly `reference` or `target`. It replaces v1's per-track calibration
and offset fields: those are taken from the explicit shared source binding. At least one
track from each of the two streams must be selected. There may be up to 32 tracks from four
native `(report, label, tracking recipe)` analyses, with at most 64 frames per analysis.

The `clock_validation` object contains:

| Field | Meaning |
| --- | --- |
| `query_path` | Original clock-validation query, at most 1 MiB. Relative paths resolve beside the selection file. |
| `query_digest` | Independent SHA-256 of those exact bytes, including their original whitespace and final newline. A saved success report cannot replace the original query. |
| `world_basis` | Exact declared world pin from the original query. |
| `reference` | Declared association between the original query's reference camera/clock and one exact retained source stream. |
| `target` | Corresponding association for the original target camera/clock. |
| `projections` | Complete one-to-one mapping from unique selected target capsule digests to original clock projection IDs. |

Each source binding has exactly these fields:

```json
{
  "camera": 1,
  "clock_generation": 10,
  "import_identity": "sha256:ACTUAL_RETAINED_IMPORT",
  "sensor_id": "sensor:entry",
  "stream_id": "stream:entry-generation",
  "clock_basis": "estimated",
  "calibration_digest": "sha256:ORIGINAL_CLOCK_CAMERA_CALIBRATION",
  "image_domain": "sha256:ORIGINAL_CLOCK_CAMERA_IMAGE_DOMAIN"
}
```

Replace the digest placeholders with actual 64-digit SHA-256 values. Reference and target
must name distinct cameras, clock generations, imports, sensors and stream generations.
Camera IDs, clock IDs, calibration pins and image-domain pins must match the original clock
query. The original clock camera's dimensions must match the actual retained images.

A projection entry is `{ "capsule_digest": "sha256:ACTUAL_CAPSULE", "projection_id": 1 }`.
The original clock query must contain exactly the declared projection IDs. Every selected
target observation, including tentative and interior track samples, must have a matching
entry. The original projection's full target interval must equal the capsule's original
`[earliest, latest]` interval exactly. Repeated observations of one capsule may share its one
projection; duplicate declarations, absent capsules, unused projections and interval
narrowing are refused. There can be at most 128 unique selected target capsules.

The parser-only example at
`tests/fixtures/continuity/retained_clock_selection.json` shows the complete shape. Its
source identifiers are synthetic and do not name available custody. The companion
`fixtures/clock-alignment/retained_handoffs_clock.json` is a synthetic clock query with a
32-by-16 image mode for native integration tests, not a deployment calibration.

## Preserve the original and derived times separately

The existing package source owner constructs its ordinary sealed projection using identity
offsets. This preserves original local captures and leaves its durable format unchanged.
The v2 report labels this section `source_projection` with
`time_interpretation: identity_mapping_preserves_original_local_capture_only`. Its old
`aligned_capture` fields are identity mappings of local captures; they are not the new
common-clock intervals.

`derived_clock_bindings` separately reports every observation's capsule, original capture,
derived common capture, projection ID and containing clock-session IDs. Reference captures
remain unchanged. Target captures become the outward-rounded hull across all original
clock candidates. The original query, both declared stream associations and the complete
native replay appear under `clock_validation`.

`clock_validation.original_query_json` is an escaped JSON string containing the exact original
UTF-8 bytes, including whitespace and its final newline. Decode that string and hash its UTF-8
bytes to recover `query_digest`. The adjacent `original_query` object is the parsed presentation;
serializing that object again need not recover the original byte pin.

The actual native handoff solver receives a separate query using these derived intervals.
Its start and end values are the first and last actual matched captures in native display
order. Every original and derived lower and upper endpoint must be nondecreasing throughout
the track; reordered or discontinuous interior intervals refuse the entire query. Thus an
interior interval cannot fall outside the track's reported time span while only its endpoints
pass the transit gate. The original authenticated projection is never edited.

The derived projection digest uses the new domain `fss.package_handoff_clock_projection.v1`.
It binds the exact selection, original source projection, original clock query, world pin,
native solver input and every derived observation. It is a derived cognition identity and
grants no source, calibration, clock, event or effect authority.

## What remains conditional

Source custody verification authenticates the retained package observations and their
original capsule intervals. It does **not** authenticate the clock query's separate image
observations or prove that the declared camera/clock association is physically correct.
Calibration and image-domain pins are checked for consistent declared scope; this command
does not adopt a physical calibration. All those limitations remain explicit in the report.

Clock validation retains its original frozen hypothesis inventory and separated sessions.
An empty `containing_session_ids` list explicitly reports algebraic extrapolation. Session
containment is not a coverage witness or proof that a physical clock obeyed the model.
`clock_activated`, `clock_observation_custody_verified` and
`physical_identity_established` are always false.

## Bounds and failures

Admission, original clock parsing and replay, observation mapping, rendering preparation
and the certified handoff solve share one nonrefillable work allowance. The native planner
receives only the allowance remaining after clock work, and its actual operation count is
charged back to the same parent budget. Cancellation stays live through replay, mapping,
solver work, complete-report rendering and final source revalidation.

The command reserves both 1 MiB control-file ceilings inside its existing 4 GiB source-read
ceiling. The unchanged source owner receives `4 GiB - 2 MiB` for retained original-byte
reads; initial reconstruction and final revalidation share that counter. No extra source
allowance is created by the v2 path.

The entire report, including original clock query, native replay, source projection and
handoff certificates, must fit 4 MiB including its final newline. There is no successful
prefix on a missing projection, stale/deleted/private source, source mismatch, arithmetic
overflow, work exhaustion, cancellation or report-size failure. Report files are created
exclusively only after successful final revalidation.

The returned report owner keeps the exclusive deployment guard alive through both file and
stdout publication. The original deadline is checked before the file write and again before
stdout. If cancellation or the deadline arrives after a complete file write, the command
refuses further stdout publication and the completed file remains available.

Native tests exercise real first-party tiny model inference, retained JPEG imports and
package tracking followed by clock replay and handoff solving. They target composition and
custody semantics; they make no detector accuracy, synchronization quality or physical
identity claim.
