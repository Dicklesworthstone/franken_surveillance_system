# Moving-target clock-offset hypotheses

`fss-clock-align` connects the native temporal triangulation and full-interval
validation owners to an explicit, finite cross-camera clock-offset search. This
is a reference slice of `fss-x8j0v`, not completion of site calibration.

A static landmark cannot establish camera timing. Supply observations already
associated with one moving physical feature, two fixed pinhole cameras in the same
owner-resolved world frame, and distinct source clock generations. For each
requested offset, the command maps target times into the reference clock, fits
position and velocity from nominal training observations, and checks separate
validation observations over their **entire** capture intervals.

Every requested hypothesis survives in the output, including ambiguous intervals,
contradictory residuals, missing visibility and numerical refusals. No best-score
selection hides alternatives. Static input can support all offsets; this is
ambiguity, not a synchronization certificate. A numerical failure remains
unresolved, not proof that an offset is impossible. The search covers only its
explicit finite inventory, not the continuous interval between sampled offsets.

## Execute the synthetic example

The checked-in example has a target clock 50 ms ahead of the reference. Its
source/calibration hashes are synthetic labels, not hashes of retained camera
footage. The exact fixture digest is:

```text
sha256:6b7e46d1828ca576be37c60b9486176078074f355804b8ab1280cbc11d635b11
```

```sh
cargo run --locked -p fss-cli --bin fss-clock-align -- \
  --input fixtures/clock-alignment/moving_feature.json \
  --input-digest sha256:6b7e46d1828ca576be37c60b9486176078074f355804b8ab1280cbc11d635b11 \
  --work-units 100000000
```

The offset convention is **target minus reference**. A `50000000` ns hypothesis
subtracts 50 ms from every target capture time and from both ends of every target
validation interval. Reference times remain unchanged. Integer nanoseconds remain
exact even at large timestamp epochs; conversion overflow refuses the entire scan.
The output's timestamp and identity strings avoid consumer floating-point loss.

## Input contract

`schemas/clock_alignment_query.v1.json` defines the strict input shape.
`registries/clock_alignment_cli.json` freezes the operational interpretation.
Unknown fields, duplicate JSON keys, trailing input, changed clock generations,
invalid camera geometry and nonfinite numeric values refuse. The caller must
supply an independently selected SHA-256 digest of the entire input file.

Each camera names its logical ID, source-clock generation, calibration and image
mode digests, pinhole intrinsics, proper world-to-camera rotation and world-space
camera center. The query names a world basis and common-feature association pin.
These remain owner assertions. The command does not read the media or authenticate
any of these pins, and mathematical camera validation is not physical calibration.

Every source row names its camera, exact clock generation, exposure, source and
evidence digests, image point and assumed pixel noise. Training rows declare a
nominal timestamp. Validation rows declare an inclusive earliest/latest interval.
At least three training and one validation observation per camera are required.
Within a camera, source hashes and exposure labels cannot repeat; evidence hashes
cannot repeat anywhere. This conservative rule also refuses byte-identical source
frames rather than admitting them as independent validation. Same-camera temporal
membership cannot overlap between training and validation.

The caller supplies **every** candidate offset, with no implicit search range or
spacing. At most 64 unique offsets in [-60 s, +60 s] are accepted, with at most 128
training and 128 validation rows. The native motion fit has its existing 60-second
window and bounded iteration policy. One nonrefillable work allowance covers
admission, all time mappings and every native fit/validation call. Exhaustion or
cancellation refuses the whole scan, not just the remaining hypotheses.

## Output and authority boundaries

The response contains the complete `fss.clock_alignment_report.v1` object and its
SHA-256 digest. The digest hashes the exact compact report object bytes, excluding
the outer response and final newline; it is an integrity commitment, not authority.
The report preserves the original source inventory, all mapped fit times and
validation intervals, every reprojection check, conditional pixel-noise covariance,
per-trial work and the complete offset inventory in ascending order.

Exit 0 means the complete scan has at least one all-times-supported hypothesis;
it can still be ambiguous. Exit 3 means the complete scan has none. Exit 2 means
invalid/incomplete execution. No successful inventory is emitted on an admission
or work failure. A stdout write or flush failure is nonzero.

No result activates a clock or calibration, certifies coverage, associates people,
or grants effects. Constant offset does not estimate clock drift. Training times
remain nominal; their uncertainty is not included in the fit covariance. Fixed
camera error, rolling shutter, acceleration, wrong feature association and common
causes remain outside this model. The validation rows are held out from fitting
the trajectory but participate in searching the clock; they are **not independent
qualification of the selected offset**. Independent observations and separately
approved calibration activation remain future work.

## Validation checkpoint

Twelve geometry contracts, five command unit contracts and three real-process
contracts were added. They cover moving and stationary fixtures, large epochs,
permutations, interval ambiguity, one-unit-short budgets, cancellation, duplicate
hypotheses, stale clock/camera bindings, evidence reuse, overflow and output claims.
The query schema and synthetic input were validated with a JSON Schema validator.
An independent numerical oracle confirms that the synthetic 50 ms hypothesis has
zero residual while the 0 and 100 ms hypotheses exceed the 0.05-pixel gate.

The authoring environment has no Rust toolchain. **The Rust contracts and binary
have not been executed here.** Neither the independent oracle nor source review
substitutes for the pinned native run or physical-device qualification:

```sh
cargo test --locked -p fss-geometry --test temporal_alignment_contract
cargo test --locked -p fss-cli --bin fss-clock-align --test clock_alignment_cli
```

The broad calibration bead remains open for continuous offset/drift estimation,
retained-source hydration and independent qualification, uncertainty propagation,
operator-reviewed activation and measured field accuracy.
