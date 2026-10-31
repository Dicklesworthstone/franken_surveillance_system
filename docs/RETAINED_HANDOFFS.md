# Handoffs from retained package tracks

`fss-scene-fuse retained-handoffs` connects the existing retained detector and native tracker
to the conditional anonymous continuity planner. It reconstructs selected native tracks from
their real package-detection custody, preserves every actually assigned observation, and
supplies the planner with the first and last capture intervals from each selected track.

```sh
fss-scene-fuse retained-handoffs \
  --root /path/to/existing/deployment --site site:example \
  --selection handoff-selection.json --report-out handoff-report.json
```

The command requires an existing deployment. The detector reports must already have been
retained by `fss-infer package-detect --retain yes`. The command reads retained evidence and
rebuilds native tracks; it does not load or execute a detector package, fetch a loose source
file, publish an event, create an identity, activate an effect, or modify the authority ledger.

Opening the existing deployment still performs its normal native recovery: it may reconcile
interrupted root publication, remove a stale layout temporary file, or mark a previously
committed effect journal entry indeterminate after restart. This inherited recovery does not
redispatch effects or create handoff events. The command is not a promise of zero filesystem
writes during deployment startup.

## Select existing native tracks

Use the existing package analysis command to discover exact native track identities and the
tracking configuration that generated them:

```sh
fss-event report --root /path/to/existing/deployment --site site:example \
  --package-report sha256:REPORT_DIGEST --label person \
  --confirmation-hits 2 --maximum-missed-frames 1 --minimum-iou-ppm 100000 \
  --report-out package-analysis.bin
```

`REPORT_DIGEST` is the actual digest returned by retained package detection. A selection uses
that report digest, one exact label, the same tracker configuration, and the returned native
track digest. The original package-analysis export is not needed during handoff execution:
the owner reconstructs it from retained custody. Selection aliases such as `entry` and `yard`
are local names for the current query and do not establish physical identity.

The selection document uses schema `fss.scene_handoffs_retained_query.v1`. This example is a
template: replace every uppercase digest placeholder with a real 64-digit SHA-256 value and
the source stream/import pins with the actual retained identities.

```json
{
  "schema": "fss.scene_handoffs_retained_query.v1",
  "session": "session:example-review",
  "generation": "sha256:DECLARED_ANALYSIS_GENERATION",
  "clock": "sha256:DECLARED_COMMON_CLOCK",
  "cost_unit": "declared-cost",
  "birth_cost": 10,
  "end_cost": 10,
  "k": 4,
  "selections": [
    {
      "id": "entry",
      "report_digest": "sha256:RETAINED_REPORT_A",
      "label": "person",
      "tracking": {
        "confirmation_hits": 2,
        "maximum_missed_frames": 1,
        "minimum_iou_ppm": 100000
      },
      "track": "sha256:NATIVE_TRACK_A",
      "calibration": "sha256:DECLARED_CALIBRATION_A",
      "alignment": {
        "import_identity": "sha256:ACTUAL_IMPORT_A",
        "stream_id": "stream:actual-entry-generation",
        "clock_basis": "estimated",
        "offset_ns": [-1000000, 1000000],
        "basis": "sha256:DECLARED_ALIGNMENT_A"
      }
    },
    {
      "id": "yard",
      "report_digest": "sha256:RETAINED_REPORT_B",
      "label": "person",
      "tracking": {
        "confirmation_hits": 2,
        "maximum_missed_frames": 1,
        "minimum_iou_ppm": 100000
      },
      "track": "sha256:NATIVE_TRACK_B",
      "calibration": "sha256:DECLARED_CALIBRATION_B",
      "alignment": {
        "import_identity": "sha256:ACTUAL_IMPORT_B",
        "stream_id": "stream:actual-yard-generation",
        "clock_basis": "estimated",
        "offset_ns": [-2000000, 2000000],
        "basis": "sha256:DECLARED_ALIGNMENT_B"
      }
    }
  ],
  "transitions": [
    {
      "from": "entry",
      "to": "yard",
      "transit": [1000000000, 10000000000],
      "cost": 1,
      "basis": "sha256:DECLARED_TRANSIT_AND_COST_BASIS"
    }
  ]
}
```

The parser refuses unknown fields, duplicate object keys, invalid digests, nonintegral numbers
and malformed identities. Sensor identities, model comparison keys, capture endpoints,
detector rows, source generations and privacy bindings are obtained from custody; the input
format cannot override them. Native track aliases cannot select the same track twice. Even
different tracker recipes cannot reuse the same assigned `(capsule, detector row, class)` as
two selected pieces of evidence.

## What the source owner authenticates

For each distinct `(report, label, tracking configuration)`, the owner calls the existing
`PackageAnalysisReport::read`. That reader verifies the exact retained package record, report
payload, root manifest, source import, current mask compatibility, every selected source
capsule and the original encoded source bytes. It then runs the existing native tracker with
its actual global assignments and discontinuity resets. Unmatched source frames are also
checked because they affect tracking, confirmation and retirement decisions.

Every selected observation is joined back to the exact retained frame and assigned detector
row/class, including original score bits, clipped source-grid bounds, inference identity,
output tensor digest and detector report digest. A nearby box cannot replace the actual
assignment. Each track retains its native display order, including when compressed-video
display order differs from source-segment numbering.

| Report data | Origin and meaning |
| --- | --- |
| Current full anchor | Exact deployment authority at projection and final revalidation. |
| Original retention anchor | Exact package-detection retention batch; remains distinct from the current head. |
| Sensor, stream and dimensions | Actual source capsule and retained decoded-frame facts. |
| Camera generation | Domain-separated digest of actual sensor, stream generation and image dimensions. |
| Model comparison key | Exact package, manifest, model, graph, head contract, model identifier/generation, label and class index. Equal weight digests alone do not make two outputs comparable. |
| Original capture and clock basis | Exact capsule interval in signed 128-bit nanoseconds and original `ClockBasis`. |
| Capture time label | The retained import's `unknown` or `operator_assumption` label. |
| Current privacy | Actual current per-sensor mask binding, including explicit absence of a mask policy. The query binds their canonical aggregate and current privacy epoch. |
| Native assignment and confirmation | Exact retained row/class, original score bits and coordinates, plus confirmation at that observation. Later hits do not relabel earlier tentative samples. |

The opaque `PackageHandoffProjection` can only be constructed through the retained owner.
Its public `contract` module contains deterministic transformations that can be tested without
the I/O runtime. Creating those public data shapes or calling a pure transformation does not
authenticate source custody.

## Clock and calibration assumptions remain visible

Every import requires an explicit alignment declaration pinned to its real import identity,
stream generation and original clock basis. Every selected capsule must match those pins.
One query cannot apply contradictory mappings to the same import.

For an original capture interval `[c_min, c_max]` and declared offset interval
`[o_min, o_max]`, the mapped interval is:

```text
[c_min + o_min, c_max + o_max]
```

The owner performs checked signed 128-bit arithmetic and refuses results outside the native
planner's signed 64-bit nanosecond range. It preserves the complete uncertainty interval and
the original interval. An offset never narrows an unknown capture window, establishes clock
synchronization, or changes an `estimated` clock into UTC.

The common clock digest, analysis generation, calibration handles, transit durations, costs
and their basis digests remain operator declarations. This path does not load an authenticated
metric calibration or infer physical travel time from a scene mesh. A digest naming an
assumption does not turn the assumption into measured evidence.

The planner uses the first actual observation's mapped interval as track start and the last
actual observation's mapped interval as track end. A union event interval is not substituted
for either endpoint. A directed handoff is admitted only when every possible endpoint choice
proves strict forward order and satisfies the declared transit range. Widening the uncertainty
can remove admissible handoffs. It cannot create a robust edge that the narrower intervals
forbade.

## Complete conditional alternatives

The outer `fss.scene_handoffs_retained.v1` report includes the input-document digest, complete
projection digest, full current anchor and its digest, all source bindings and observations,
and explicit assumption semantics. Its `conditional_analysis` is the existing
`fss.scene_handoffs.v1` planner report, with the original pure-handle provenance semantics
preserved. The authenticated outer projection supplies the source facts; it does not rewrite
the lower-level planner as a custody checker.

The existing solver ranks complete anonymous path covers by declared integer costs. It
preserves the complete admitted alternative family implicitly, includes the explicit
all-singleton alternative, and displays an exact bounded prefix. The complete family is
relative to the selected tracks and declared transitions. It is not a claim to enumerate
unseen physical people, trajectories or future observations. The costs and uncalibrated
detector scores are not association probabilities or identity confidence.

If any requested source, native track or required custody is missing, corrupt, deleted,
privacy-stale or inconsistent, the whole retained query refuses. It never substitutes a
zero-valued interval, silently omits a track, or represents custody failure as an authenticated
singleton.

## Final revalidation and bounds

Before returning the report, the CLI reopens and rebuilds all selected retained analyses and
compares the exact projection again. The original deployment root, principal and full anchor
must still match. Durable-head checks reject an externally advanced or damaged ledger;
current privacy and source reads reject withdrawals or damaged bytes even when the selected
identities have not changed. This is an ephemeral read result, not persistent authorization
to release it after a later authority change.

The optional `--expected-anchor sha256:HEX` pins SHA-256 of the canonical full anchor before
source reconstruction. `--expected-input sha256:HEX` pins the exact selection file bytes.
Neither pin replaces final custody revalidation.

| Dimension | Bound |
| --- | --- |
| Selection document | 1 MiB, bounded regular file. |
| Selected tracks | 1–32; no silent truncation. |
| Distinct analysis recipes | At most four. |
| Frames per retained analysis | At most 64. |
| Original source segments verified per pass | At most 256; final revalidation repeats the bounded pass. |
| Source import size | Existing retained reader ceiling of 512 MiB per import. |
| Chunk and assembled segment | Existing 16 MiB ceilings. Repeated chunk reads consume resources again. |
| Cumulative original-byte reads | Hard 4 GiB across all recipes, initial reconstruction and every revalidation; includes HTTP/RTSP original-provenance reads. Cloning or retrying the same projection never resets the allowance. |
| Tracking hits and maximum misses | Each 1–64; minimum IoU 0–1,000,000 ppm. |
| Explicit transitions | At most 992 ordered non-self pairs. |
| Displayed path alternatives | 1–32; implicit admitted family remains complete. |
| Solver work | Default 2,000,000 units, maximum 50,000,000. |
| Deadline | Default 30 seconds, maximum one hour. |
| Complete report | At most 4 MiB including the final newline; no partial report is emitted. |

The deadline probe surrounds bounded source-owner calls and checks each projection join. The
existing native source and tracker owners also honor their `ReplayCx` cancellation checkpoints.
A deadline does not interrupt an already running synchronous source read or tracker call at an
arbitrary instruction. Cancellation, exhausted allowances, arithmetic overflow and output
limits all refuse a complete result rather than returning an unverified prefix. The source
allowance reserves bytes before native custody reads through the existing `SourceReadBudget`
and `VerifiedChunkCache`. Loaded chunks may be reused within one analysis; final revalidation
uses fresh caches under the same shared reservation counter. Reservations are not refunded
after an unsuccessful read. Library callers can select a smaller nonzero allowance with
`read_with_source_limit` and inspect `source_bytes_read`.

`--report-out` creates a new private file and refuses an existing destination. Its bytes,
including the final newline, equal stdout. See [SCENE_HANDOFFS.md](SCENE_HANDOFFS.md) for the
underlying conditional solver, certificates and robust transition rules.

## Verification scope

`crates/fss-reference/tests/package_handoffs_contract.rs` exercises the actual native source
and package path using the existing tiny first-party FMPK/JPEG fixture. The cases cover exact
two-camera observation projection and the native planner, cold reconstruction without loose
source/model files, bad source/clock pins, missing tracks, aliases and duplicate assigned
evidence under different tracker recipes, corruption of package records/reports/capsules/raw
chunks, principal/current-anchor/privacy withdrawal, cancellation and cumulative source-byte
refusal across recipes, cloned projections and repeated revalidation. These numeric fixtures
make no trained-detector quality claim. Execution results and environment limitations belong
in the session's verification record rather than being implied by this test inventory.
