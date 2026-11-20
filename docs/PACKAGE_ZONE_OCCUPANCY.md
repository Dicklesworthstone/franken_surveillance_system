# Source-verified sampled class occupancy

`fss-event package-zones occupancy` reads a retained package-zone report and returns a
count for every original source frame and declared zone. Counts use actual confirmed
class-selected detector assignments whose complete boxes lie strictly inside the zone.
The view also returns the supporting anonymous track identities and the samples excluded
as tentative, missing, boundary, clipped, masked, or unavailable under source-health policy.

This is a usable first observation view for VIT-012. Its observation kind is
`sampled_class_occupancy`, separate from the security event taxonomy. It creates no event,
alert approval, new retained report, standing capture authority, or model-quality claim.

## Choose the observation view

Use this command to inspect complete sampled counts and exclusion reasons for an
existing v1 or v2 package-zone report. It preserves the report's original health
policy; v1 remains explicitly unassessed. For role-annotated queue/register areas,
sampled dwell and ordered lane-stage observations, use
[`fss-event qsr`](QSR_OBSERVATIONS.md), which requires a retained, historically
screened v2 source. This diagnostic view does not satisfy or relax that requirement. When comparing
outputs, join rows by `(frame, zone)`: occupancy is frame-major, while QSR is
zone-major.

## Read an existing retained report

First produce and retain the desired class/zone analysis through the existing
[package-zone workflow](PACKAGE_ZONES.md). That workflow performs the exact source,
model, privacy and tracking checks and requires explicit approval to retain its report.
Then select its `report_digest`:

```sh
fss-event package-zones occupancy \
  --root /path/to/deployment --site site:restaurant \
  --report-digest "${ZONE_REPORT_DIGEST:?supply the retained zone report identity}"
```

The command accepts `--principal` in the same way as `package-zones read`. Class, tracking,
zone and health-policy overrides are refused: they require another native analysis and
its own retained report. An unretained preview is not a valid input.

It also accepts `--max-read-bytes N` and `--max-read-objects N`. These bound one complete
read, including final verification; the defaults are 1 GiB and 1,000,000 payload read
attempts, with maximum values of 4 GiB and 4,000,000 attempts. Reading an object again
uses another attempt and consumes its bytes again.

Output uses `fss.package_zone_occupancy.v1`. The source section binds the exact zone report
and provenance root, native analysis, retained detection report, import and original root,
sensor, package, model identity and generation, detection contract, selected class, privacy
binding, capture-time interpretation and clock basis. `policy_generation` and `policy_digest`
identify the occupancy interpretation. `report_digest` binds that interpretation, the
complete source report and root, and every output row in canonical order.

The existing source frames retain their original capsule digests, conservative capture
intervals, image dimensions, time-reliability flags and source discontinuities. Timestamp
endpoints remain exact decimal strings, including values beyond JSON integer precision.
No wall-clock coordinate, duration, interpolation or coverage between frames is inferred.

## Interpret each row

`samples` is ordered by source frame, then by the source report's canonical zone order.
There is one row for every frame and zone, including when no track was ever created.

| State | `observed_count` | Meaning |
|---|---|---|
| `observed_positive` | Positive integer | This many actual confirmed inside assignments support this source sample. |
| `no_positive_observation` | `0` | There was no usable positive assignment. This does not establish that the physical zone was empty. |
| `masked` | `null` | A current source privacy mask overlaps this zone; its count is unavailable. |
| `health_excluded` | `null` | The retained historical screening policy withholds positive support. |

Each counted assignment names its exact anonymous `supporting_tracks` digest. A track is a
model-derived trajectory, not a physical identity. Overlapping zones can count the same
track; adding their counts would double-count it. Adding frame counts does not count unique
visitors or establish how long anyone was present.

`confirmed_outside` records actual confirmed outside assignments. The `excluded` object
accounts for tentative, boundary, partial, unobserved, masked and health-excluded samples.
These categories are disjoint: masking and missing assignments take precedence, then
per-sample confirmation, then geometry and positive-support screening. A coasting tracker
does not supply an observation, and later confirmation does not retroactively confirm an
earlier tentative sample. Boundary and clipped boxes do not become inside observations.

Privacy applies even to an empty track inventory. A masked zone with no track cells still
has `observed_count: null`, rather than a misleading zero.

## Historical source health

The view preserves the selected report's policy:

- An unscreened v1 report produces `health: "unassessed"`. Its original positive-observation
  policy remains usable, with no assertion that the camera is healthy.
- A screened v2 report permits positive observations only for matching, complete, finite
  diagnostics with `health: "screened_without_findings"`.
- Missing diagnostics, incomplete screening, and findings keep their distinct health states
  and produce unavailable counts. Raw underlying assignments remain in the retained source
  report; they are not promoted to positive occupancy support.

A historical screen is not a current camera-health certificate. Empty and positive rows both
carry `absence_certified: false` and `continuous_occupancy_established: false` in the report's
semantics. `coverage_witness` is explicitly `null`: this first view does not implement a
coverage or absence certificate. Counts are uncalibrated model observations, not population
lower/upper bounds, queue length, wait time, register staffing, or lane-stage duration.

## Source ownership and bounds

The command cold-reconstructs the native retained zone report. It does not trust exported
JSON, take caller-supplied track samples, run another inference pass, or require loose model
and footage files. After all rows and JSON have been constructed, it revalidates original
source custody, current privacy, deletion, the principal, the durable ledger head and retained
proof. Historical-health allowances are shared across initial reconstruction and final
revalidation. Cancellation or any changed/unavailable proof returns no successful projection;
the reader never repairs or publishes missing custody.

One sealed immutable retained source owns the initial snapshot, all source and diagnostic
reads, metadata revalidation, selected payload rereads and final publication/authority
checks. They share the original aggregate allowance. Output remains private until every
check succeeds. A changed head, privacy generation, selected object or journal tail refuses
the complete result; a later retry opens a new snapshot. The 60-second deadline is
cooperative at read admissions, rather than an interruptible filesystem timeout.

Limits apply to the complete result: at most 64 source frames, 16 zones, 8,192
track/zone/frame cells, 1,024 output rows and 4 MiB of JSON. A duplicate or missing cell,
foreign track, inconsistent assignment, or multiple tracks claiming the same detector row
within a frame/zone is refused. No selection, ranking or silent truncation makes an oversized
result fit. The projection creates no new report; source retention and deletion policy
remain with their existing owners.

The command can run while capture holds the deployment writer. It does not acquire a
publisher lock, initialize a deployment, recover publication state, remove temporary files
or reconcile effects. Successful reads and refusals leave deployment contents unchanged.
Approved source-report retention remains a separate operation with its existing exclusive
publisher and recovery contract.

## Verification scope

Reducer and renderer regressions exercise exact complete inventories, per-sample confirmation,
missing observations, boundary/clipped boxes, overlapping zones, empty-track privacy and
health exclusions, canonical ordering, exact timestamps, overflow bounds and cancellation.
Native integration cases use the existing first-party numeric FMPK/JPEG fixture, actual
retained detector/zone owners, cold reopen and source/privacy/deletion withdrawal. CLI cases
extend the existing subprocess fixture and validate the new schema. The numeric fixture
tests semantics and custody; it supplies no detection-quality evaluation.

The shared immutable package-zone contracts additionally keep a writer open throughout
the read, compare the complete native projection, preserve unresolved effects and recovery
artifacts, enforce exact aggregate allowances and withhold output on final cancellation,
late selected-report corruption or torn journals.

Queue/wait definitions, register-role interpretation, vehicle stage sequencing, continuous
coverage witnesses, population calibration and FLDT consumption remain outside this slice.
