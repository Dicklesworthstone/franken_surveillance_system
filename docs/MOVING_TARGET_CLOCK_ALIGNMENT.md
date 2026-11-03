# Moving-target clock hypotheses

`fss-clock-align` composes native temporal triangulation and full-interval
validation into a finite cross-camera clock search. This is a reference subset
of `fss-x8j0v`, not completion of site calibration. It performs no camera I/O,
source hydration, durable publication, calibration activation, coverage or effects.

The command accepts three explicitly versioned query profiles. The original
`fss.clock_alignment_query.v1` searches constant offsets and keeps its existing
report format. `fss.clock_drift_query.v1` searches affine offset/rate pairs and
returns `fss.clock_drift_response.v1` with `fss.clock_drift_report.v1`. Unknown
schemas or fields refuse; the profiles are not silently converted at the boundary.
`fss.clock_validation_query.v1` checks the frozen offset/rate inventory across
additional capture sessions and projects complete target intervals through every
hypothesis. It returns `fss.clock_validation_response.v1` with the strict
`fss.clock_validation_report.v1` projection. The original two profiles keep their
existing query and response bytes.

## Run the synthetic examples

The fixtures contain synthetic labels, not retained camera footage. They are
reproducible with `python scripts/clock_alignment_fixtures.py --write`; omitting
`--write` verifies exact bytes. All labels are full SHA-256 values. This revision
preserves the original offset and drift example bytes and adds a disjoint-session
example from the same deterministic generator; the input pins below bind their
exact bytes.

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

### Validate separate passages and project conservative time intervals

```sh
cargo run --locked -p fss-cli --bin fss-clock-align -- \
  --input fixtures/clock-alignment/validated_sessions.json \
  --input-digest sha256:b3bf2bfd082908a7d9a918ddfc6cd6cb5a310ae1a4f8d18fdcfff8901288f254 \
  --work-units 100000000
```

This example starts with a stationary feature: all three rate hypotheses support
that original search. Two later moving passages provide new constraints under the
same camera and clock generations. They support the +500000 ppb candidate under
the declared motion model, while all three candidates remain in every projected
time envelope. The epoch is `2^100` nanoseconds; decimal strings preserve it exactly.

The query carries the original drift fields plus two required arrays:

- `sessions`: one through eight objects containing `id`, `association_evidence`,
  `training`, and `validation`. IDs are distinct nonzero integers; session zero
  names the original search. Each session has its own asserted association pin
  and feature trajectory. Camera models, clock generations, world basis, fit
  gates, target anchor and complete hypothesis inventory are shared and cannot
  be overridden by a session.
- `projections`: zero through 128 objects containing a distinct nonzero `id` and
  a complete inclusive `target_interval_ns` pair. Every candidate maps both
  endpoints with outward rounding. The output envelope is the hull across **all
  requested candidates**, including unsupported and unresolved ones.

Session windows must be disjoint on both source clocks, and their ordering must
agree between cameras. A camera reset or changed mode needs a new scope, not a
session override. Source and evidence digests cannot repeat anywhere in the new
profile's observation inventory; exposure labels cannot repeat within a camera
across any session. Distinct labels are insufficient if source pins repeat.
These are membership checks, not authentication or proof of independent errors.

The report includes the original search, every additional session's full native
fits and refusals, per-hypothesis support in every session, and every candidate's
mapped intervals. `containing_session_ids` names the declared target-clock windows
that contain an entire request. An empty list is explicitly labelled
`outside_declared_sessions`; the algebraic projection then extrapolates beyond
observed passage windows. It does not imply measured clock validity there.

For this profile, exit 0 requires a hypothesis supported by the original search
**and every additional session**. Exit 3 retains the complete report when none
has that support. Neither exit selects or activates a clock. Hypotheses that lose
support still contribute to every projection hull.

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
`schemas/clock_alignment_query.v1.json`, `schemas/clock_drift_query.v1.json`, and
`schemas/clock_validation_query.v1.json`. The new response and report shapes are
`schemas/clock_validation_response.v1.json` and `schemas/clock_validation_report.v1.json`.
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

All profiles admit at most 64 hypotheses, 128 training rows and 128 validation
rows per passage. Hypotheses must be unique; textual and numeric aliases are checked after
integer decoding. Duplicate JSON keys, trailing data, unknown fields, nonfinite
values, invalid fit policies and mapping overflow refuse. One nonrefillable work
budget covers admission, all mappings and all native fit/validation calls.
Cancellation, allocation refusal or exhausted work returns no successful prefix.

In the disjoint-session profile, the real command's existing `ReplayCx`
cancellation probe reaches every native geometry work charge and report-construction
checkpoint. Wrapped cancellation retains `ERR-CLOCK-ALIGNMENT-CANCELLED-001` and
the `cancelled` error outcome. Report construction enforces the 8 MiB limit while
adding complete fields and reserves the response wrapper and final newline. An
over-limit report refuses in full before stdout is touched; no later session is
dropped to make an earlier result fit.

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
Additional disjoint passages do not remove those limitations: the new profile
checks frozen hypotheses under additional asserted observations, without proving
statistical independence or physical timing accuracy.

## Use the complete clock hull in retained motion matching

`fss-scene-fuse retained-motion-match` accepts an opt-in
`fss.scene_feature_motion_match_retained_query.v2` consumer. It pins and replays
the original validation query through the shared `clock_alignment` owner, under
the scene command's same work allowance and cancellation probe. It verifies the
actual scene rig, prepared image domains and source sensor/stream/clock bindings,
then requires each original projection request to match one selected retained
target capsule's complete interval. The resulting all-hypothesis hull becomes
the actual input to native motion matching. Unsupported candidates are retained;
overwide mapped intervals still fail the caller's uncertainty and span gates.

The scene report embeds `fss.clock_validation_replay_response.v1` and its
`fss.clock_validation_replay_report.v1` body. Those profiles have the same complete
native diagnostic inventory; their work allowance is the remaining parent
allowance at replay entry, which can exceed the standalone command's limit.
The original query bytes and all selected exposure mappings are included. The
existing standalone response profiles and bytes remain unchanged. See
[retained temporal matching](RETAINED_TEMPORAL_MATCHING.md#replay-clock-uncertainty-into-the-motion-reconstruction)
for the exact v2 declarations, limits and authority boundaries.

## Validation checkpoint

The original offset path has twelve geometry, five command-unit and three process
contracts. The affine extension adds eleven geometry, four command-unit and three
process contracts, including zero-rate compatibility, signed fractional rounding,
exact half ties, huge epochs, static ambiguity, complete inventory, malformed
policy, shared work exhaustion and cancellation. The original authoring checkpoint
did not execute those native Rust contracts because it lacked a Rust toolchain;
the independent laboratory results below describe that earlier checkpoint.

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
cargo test --locked -p fss-geometry --test clock_validation_contract
cargo test --locked -p fss-cli --bin fss-clock-align --test clock_validation_cli
cargo test --locked -p fss-cli --lib clock_alignment
```

The cross-session command adds native command tests for static-search ambiguity,
complete time envelopes, aliased evidence, scope overrides, disjointness and order,
exact work accounting, early and late owner cancellation, output limits, and
unresolved trials. Real-process tests cover a complete read-only run, the distinct
exit-3 result, refusal without a successful JSON prefix, and help discovery.

At the cross-session implementation checkpoint, the canonical native geometry
`clock_validation_contract` passed all ten tests. A scratch-only harness compiled
the exact command analysis, input, rendering and unit-test sources against the
native `fss-core` and `fss-geometry` libraries: all 26 tests passed, including the
nine new session tests. It excluded `execute`, `main` and `ReplayCx`; this is
owner-logic evidence, **not executable or process qualification**. Its generated
supported, unsupported and unresolved responses passed full Draft 2020-12 query,
report and wrapper validation and exact digest checks. Original offset and drift
response bytes matched the prior owner byte for byte and are pinned in unit tests.
The full CLI build was blocked when dependency compilation hit the host memory
limit; the real-process contracts above still require execution.

The broad calibration bead remains open for continuous estimation, retained-source
verification, independently held-out qualification, full uncertainty propagation,
operator-reviewed activation and measured real-site accuracy.
