# Optical health admission for recorded events

Short recorded `fss-event watch` and `fss-event corroborate` now accept an explicit
`--sensor-health conservative-optical-v1` policy. It combines the existing
conservative temporal screen with native integer blur and highlight-glare
measurements. Findings affect event support and coverage, not just diagnostics.

## Operator use

For an existing retained import, add the policy to the ordinary short watch request:

```sh
fss-event watch \
  --root DEPLOYMENT --site SITE --principal principal:local-operator \
  --import-id sha256:IMPORT --interpretation ycbcr \
  --zone door:64,0,32,32 \
  --sensor-health conservative-optical-v1
```

The same policy options apply to an otherwise complete short `corroborate` request.
A preview does not publish events. The normal explicit approval and coverage
retention commands remain required, and their emitted rerun includes every policy
argument exactly.

| Option | Default | Meaning |
| --- | --- | --- |
| `--min-laplacian-variance-x1000` | `50000` | Interior four-neighbour Laplacian variance below this integer threshold is suspected severe blur; values are scaled by 1000. |
| `--glare-luma-min` | `250` | Luma samples at or above this value count as saturated highlights; range 0 through 255. |
| `--max-glare-ppm` | `150000` | A saturated-highlight share at or above this threshold is suspected glare; range 0 through 1000000 parts per million. |

Thresholds require the explicit optical policy. The CLI accepts canonical unsigned
decimal integers and refuses overflow, signs, leading zeroes and out-of-range
glare values. Dimensions smaller than 3 by 3 produce an insufficient-resolution
finding and withhold admission. A zero glare-share threshold intentionally finds
glare on every frame. Threshold choice depends on scene content; a textureless but
valid scene can be suspected blur.

## Resulting event and coverage behaviour

Measurements use the same decoded, privacy-transformed luma admitted to the
recorded pipeline. A frame with any temporal or optical finding is recorded in the
source-linked health receipt but is not fed into the foreground model, tracker,
zone-entry gate or selected classifier support. Temporal findings still withdraw
their complete qualifying runs. Tracks touching an affected run are discarded,
and their dependent spans cannot become absence evidence.

The first later admissible frame restarts the tracker and background model.
Coverage resumes only after the ordinary warm-up and confirmation requirements.
Optical-only tracking recovery does not pretend that the native decoder restarted
or require a new IDR picture.

The report's `sensor_health` object identifies `conservative-optical-v1` and contains
the exact thresholds, per-frame `optical_observations`, and cumulative
`optical_sample_reads`. Each metric binds the source generation, original segment,
capsule digest, decoded-luma digest and dimensions. Findings are suspicion signals;
a clear screen does not certify sensor health, absence, tampering or continuity.

## Retention and bounded work

The new `fss.recorded_sensor_health.v2` receipt retains the optical policy and one
metric per conservative observation. Decoding verifies exact policy identity,
source alignment, dimensions, count/range consistency, derived findings,
cumulative work and canonical bytes. Existing version-7 coverage receipts can
carry this validated summary without a new coverage wire version.

The retained `fss.recorded_sensor_health.optical_policy.v1` object binds the existing
temporal policy, all optical thresholds and the admission rule. Changing any
threshold changes the analysis plan and approval identity. Legacy
`conservative-v1` and unscreened operation preserve their existing identities.

One whole-analysis allowance bounds optical work to at most
`frames * 7 * MAX_HEALTH_PIXELS` scalar sample reads. Before visiting pixels, each
frame reserves `2 * width * height + 5 * (width - 2) * (height - 2)` reads, with
saturating interior dimensions. Gaps and recovery never replenish this allowance.
Cancellation or an invalid receipt prevents publication of a partial result.

## Scope and verification

This increment supports short entry watch and short corroboration. Stream watch,
stream corroboration, dwell and incremental dwell requests explicitly refuse the
optical policy; their current temporal policy remains available. Long-recording
optical diagnostics remain a separate read path.

The new contracts cover native exact-policy custody, threshold-sensitive
identities, source/metric tamper refusal, cumulative work and cancellation,
degraded coverage and recovery, retained MJPEG event suppression and explicitly
approved publication. CLI contracts cover exact threshold parsing, unsupported-mode
refusal and equality between native and immutable previews beside an active writer.

These new optical contracts received independent source/API review but were not
executed: the pinned execution host disconnected before the reference targets
could compile. The passing FLV container/probe component results do not cover this
feature. Full Cargo/workspace qualification remains pending.
