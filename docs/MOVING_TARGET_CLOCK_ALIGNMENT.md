# Moving-target clock hypotheses

`fss-clock-align` composes native temporal triangulation and full-interval
validation into a finite cross-camera clock search. This is a reference subset
of `fss-x8j0v`, not completion of site calibration. It performs no camera I/O,
source hydration, durable publication, calibration activation, coverage or effects.

The command accepts two explicitly versioned query profiles. The original
`fss.clock_alignment_query.v1` searches constant offsets and keeps its existing
report format. `fss.clock_drift_query.v1` searches affine offset/rate pairs and
returns `fss.clock_drift_response.v1` with `fss.clock_drift_report.v1`. Unknown
schemas or fields refuse; the profiles are not silently converted at the boundary.

## Run the synthetic examples

The fixtures contain synthetic labels, not retained camera footage. They are
reproducible with `python scripts/clock_alignment_fixtures.py --write`; omitting
`--write` verifies exact bytes. All labels are full SHA-256 values. This revision
regenerates the original offset example and adds the drift example from the same
deterministic generator; the input pins below bind their new exact bytes.

Constant 50 ms target-minus-reference offset:

```sh
cargo run --locked -p fss-cli --bin fss-clock-align -- \
  --input fixtures/clock-alignment/moving_feature.json \
  --input-digest sha256:907cd0fb6229bc8fc4a6be79230502611da9b29f924bb290e44b791e13e61d2a \
  --work-units 100000000
```

Target clock 50 ms ahead at its anchor and running 500 ppm faster:

```sh
cargo run --locked -p fss-cli --bin fss-clock-align -- \
  --input fixtures/clock-alignment/drifting_feature.json \
  --input-digest sha256:b4ebc36a73b26eaf4456e3fdb63c7c97fb0f2846c59d6c3712f95399cdf035ee \
  --work-units 100000000
```

The drift fixture spans twenty seconds. Its three explicitly supplied rate
hypotheses are -500000, 0 and 500000 parts per billion. No implicit grid, search
resolution or continuous optimum is invented.

## Exact time mapping

The constant-offset convention remains `reference = target - offset`. For the
affine profile, `offset_ns` means target minus reference **at the declared target
anchor**, and `skew_ppb` means target ticks per reference tick minus one:

```text
reference = target_anchor - offset_ns
          + (target - target_anchor) * 1000000000 / (1000000000 + skew_ppb)
```

Positive skew means the target clock runs faster. Every candidate shares the
same exact target anchor. Arithmetic uses checked relative signed integers, never
floating-point epochs. Offsets are bounded to +/-60 seconds, skew to +/-1000000
ppb (1000 ppm), and target input times to +/-60 seconds of the target anchor.
The native motion fitter separately enforces its sixty-second observation span.

Exact rational results may lie between integer nanoseconds. Training uses nearest
integer times, with exact half ties choosing the earlier integer. Every original
time, nominal mapped time and exact floor/ceiling enclosure is reported, including
on unresolved trials. **Rounding uncertainty is not propagated into the fitted
pixel-noise covariance.** Training times remain nominal caller assumptions.

Validation intervals round earliest downward and latest upward, preserving the
complete interval. They are never reduced to a midpoint or clipped to fit. Any
rounding-induced duplicate training time, overlapping holdout or fit/holdout
collision remains an unresolved trial instead of being deduplicated.

## Admission and source boundaries

Input must be an explicitly named, bounded regular file and match the caller's
independently supplied SHA-256 pin. The schemas are
`schemas/clock_alignment_query.v1.json` and `schemas/clock_drift_query.v1.json`.
JSON shape validation is not native semantic admission: integer ranges, proper
rotations, fixed camera models, exact clock generations and observation membership
are checked by the Rust readers and geometry owners.

Two fixed pinhole cameras must already share one qualified world frame and depict
one already-associated physical feature. Camera IDs, clock generations, calibration
and image-mode digests, world basis and association evidence remain caller
assertions. Hashing the query does not authenticate these asserted sources.

At least three training and one validation observation per camera are required.
Each row supplies a pixel, assumed pixel noise, exposure, source and evidence pin.
Within a camera, source hashes and exposure labels cannot repeat; evidence hashes
cannot repeat anywhere. Same-camera temporal membership cannot overlap between
training and validation. These checks do not prove statistical independence.

Both profiles admit at most 64 hypotheses, 128 training rows and 128 validation
rows. Hypotheses must be unique; textual and numeric aliases are checked after
integer decoding. Duplicate JSON keys, trailing data, unknown fields, nonfinite
values, invalid fit policies and mapping overflow refuse. One nonrefillable work
budget covers admission, all mappings and all native fit/validation calls.
Cancellation, allocation refusal or exhausted work returns no successful prefix.

## Diagnostics and non-claims

Every requested hypothesis survives in canonical order, including ambiguous
intervals, contradictory residuals, absent visibility and numerical refusals.
Static features can support multiple offsets and rates; this is ambiguity, not
synchronization. Numerical failure means unresolved, not an impossible clock.

Reports retain original source inventory, nominal motion, conditional pixel-noise
covariance, full residual and validation inventories, all hypothesis parameters
and per-trial/aggregate work. The response digest hashes the exact compact report
object UTF-8 bytes, excluding the wrapper and final newline. It is integrity only.

Exit 0 means a complete inventory with at least one all-times-supported hypothesis;
it can still be ambiguous. Exit 3 means a complete inventory with none. Exit 2
means invalid/incomplete execution or I/O/output refusal. No successful report is
emitted after an admission or work failure; failed stdout write/flush is nonzero.

The sampled hypotheses do not certify continuous offset/rate uniqueness. Rate
variation, timestamp/rounding uncertainty, camera error, rolling shutter,
acceleration, wrong association and shared causes are outside fitted covariance.
Validation observations are held out from fitting the trajectory but participate
in searching the clock. They are **not independent qualification of a selected
clock**. The report explicitly denies clock activation, independent clock
validation, authenticated custody, physical calibration and effect authority.

## Validation checkpoint

The original offset path has twelve geometry, five command-unit and three process
contracts. The affine extension adds eleven geometry, four command-unit and three
process contracts, including zero-rate compatibility, signed fractional rounding,
exact half ties, huge epochs, static ambiguity, complete inventory, malformed
policy, shared work exhaustion and cancellation. These native Rust contracts have
**not been executed in this authoring environment: no Rust toolchain is available**.

Executed independent laboratory checks: 20000 exact-rational mapping cases,
signed half ties and monotonicity; deterministic fixture byte reproduction; drift
JSON Schema validation; and numerical fitting of the twenty-second example.
The independent numerical oracle gives maximum training residuals of approximately
0.0134005, 0.00669812 and 0 pixels for -500000, 0 and 500000 ppb, respectively,
against a 0.001-pixel gate. These are not native Rust execution or device evidence.

```sh
python scripts/clock_alignment_fixtures.py
cargo test --locked -p fss-geometry --test temporal_alignment_contract --test clock_drift_contract
cargo test --locked -p fss-cli --bin fss-clock-align --test clock_alignment_cli --test clock_drift_cli
```

The broad calibration bead remains open for continuous estimation, retained-source
verification, independently held-out qualification, full uncertainty propagation,
operator-reviewed activation and measured real-site accuracy.
