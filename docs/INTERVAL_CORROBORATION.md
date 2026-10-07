# Interval-native cross-camera corroboration

Status: implemented reference behavior, not production-qualified. This repairs temporal
admission in the existing recorded corroboration path; it does not add a new effect surface.

## The lost-alternative problem

Consider one east-camera entry at time `[0, 0]` and two west-camera entries, with a time gate
of 10. The closest west entry spans `[-20, 20]`; another, slightly farther entry spans `[0, 0]`.
Both midpoints are zero. Selecting the closest entry first and rejecting its uncertainty only
after global assignment produces no pair, even though the second entry passes every gate.

`cross_camera::intervals::associate_intervals` constructs the entire candidate graph with the
worst-case interval gate already applied. The uncertain favorite cannot consume a counterpart.
The same admissible graph is used for the best assignment and every ambiguity/exclusion solve.
The surviving pair remains conditional on the declared gates; it is not physical identity proof.

## Semantics

Each observation retains its original inclusive `CaptureInterval` with signed 128-bit endpoints.
Every Cartesian edge reports its exact minimum and maximum possible absolute time separation:

- `Within`: the maximum is at or below the gate; the temporal requirement is met.
- `Uncertain`: some possible separations meet the gate and some do not; no admission.
- `Outside`: even the minimum exceeds the gate; no admission and no proof of scene absence.

Among admitted edges, the existing midpoint/geometry ranking is unchanged. The midpoint is
computed without narrowing to 64 bits or overflowing subtraction. Endpoint `abs_diff` yields
full unsigned-128 separation, including the distance from `i128::MIN` to `i128::MAX`.

The existing Hungarian solver, per-left unmatched choices, global ambiguity margin, and
quantization guard are shared with the point API. Ties among admissible alternatives remain
unresolved. Uncertain edges stay in the complete diagnostic graph but do not compete as if
they were admissible. The interval API therefore does not claim stability over all possible
physical-world associations; it reports stability over the declared admissible graph only.

## Recorded workflow

The existing `fss-event corroborate` workflow now uses this interval-native adapter for ordinary,
detector-assisted and decode-recovered analyses. No additional flag or manual timestamp
conversion is needed. A source-gap-unreliable capture hint remains excluded before association,
independently of its apparent temporal or geometric score. Class evidence cannot repair it.

An entry with no admissible counterpart but a midpoint/geometry-compatible, time-uncertain
counterpart is reported as `time_gate_uncertain`. When it also has a stable admissible match,
that match is used; when admissible alternatives tie, it remains `ambiguous`. Original entry
records and capture intervals are not rewritten to obtain a match.

Analysis remains read-only. An associated pair prepares the existing event proposal; exact
operator approval is still necessary to publish it. Event publication does not prepare or send
an alert. The two-sensor policy, custody, privacy projection, coverage retention, and recovery
boundaries remain unchanged. A missing pair does not certify absence or an empty scene.

## Shared failures constrain the event decision

Two camera identities alone do not establish physical independence. Supply known common causes
to the same corroboration request with repeated declarations using its camera labels:

```sh
# Add these arguments to the ordinary two-camera corroboration command.
--failure-domain power:circuit-1=east,west \
--failure-domain network:east-lan=east \
--failure-domain network:west-lan=west
```

The supported kinds are `network`, `power`, `clock`, `host`, `model`, `calibration` and `replay`.
Each declaration names one or both cameras. At most 32 declarations are accepted; identifiers
are bounded to 128 bytes, domain names and camera members cannot repeat, and unknown cameras
are refused before deployment I/O. A domain can name a shared model family, calibration source
or replay origin when it could explain correlated entry observations. Optional detector class
scores are neutral evidence in this policy and do not establish extra independent support.

Every camera also retains its intrinsic sensor domain. The reference contracts overlapping
causes transitively: cameras connected through any cause belong to one supporting component.
The example's separate networks do not undo its shared power dependency. An associated pair in
one component remains an observed `Witnessed` event with the `hold` action, and its individual
entry observations remain available. It offers no alert command; a direct `fss-event alert`
request for the published event is refused as `ERR-ALERT-NOT-ELIGIBLE-001`.

The report's dependency assessment lists complete declarations, source-bound camera mappings,
components, and their content digests. Declarations and the rederivable assessment are retained
in the approved event's provenance graph. Changing a declaration changes its candidate and
approval identities, even when the component count happens to stay the same. Argument/member
ordering does not change those identities. Exact rerun commands carry every declaration through
publication and any coverage reanalysis.

With no declarations, existing unscreened event bytes retain the sensor-only reference rule.
The report explicitly labels this `sensor_only_assumption`. With declarations, the basis is
`owner_assertion_not_verified_topology`. Both report independence as unknown and
`independence_certified: false`: disjoint declared components do not certify the absence of
unlisted dependencies. This feature constrains the existing event rule; it supplies neither
measured calibration nor a production independence certificate. Ground visibility and absence
witnesses retain their own separate qualification boundaries.

Health-screened corroboration also fingerprints its final evidence closure, including the
screen's neutral `RequiredBy` edges. The stored alert decision therefore agrees with the
preview. A separate health-decision generation gives corrected candidates new identities;
older published events and approvals are not silently rewritten or promoted.

## Compatibility and bounds

The point API's scoring, candidate table, assignment costs, alternatives and numerical behavior
are preserved. Degenerate interval inputs in its supported timestamp range produce the same
results. Clean nonzero-width intervals retain the previous midpoint rankings too.

Unchanged recorded associations retain their plan, entry, candidate and proposal encodings.
Analyses affected by the old post-filter bug must be rerun and their newly proposed pairings
reviewed; no existing event revision is automatically amended or deleted. A different pair has
its own existing association-derived identity and cannot use the old pair's approval.

There are at most 64 observations per camera and a complete, bounded Cartesian candidate table.
Input validation, allocation failures, cooperative cancellation and work exhaustion return an
error rather than a partial public report. Interval diagnostics add bounded arithmetic and
storage work; the existing caller-owned work budget also covers assignment and ambiguity solves.

The Rust interval API retains full-width timestamps. Existing recorded JSON fields remain JSON
integers for compatibility: consumers must parse them without rounding through binary64.
No string-encoding migration of the existing report is claimed by this change.

Capture times remain operator import assertions, not authenticated clock measurements. Ground
homographies remain owner assertions, not calibration certificates. These changes do not prove
clock alignment, sensor independence beyond the existing policy, detection quality or release
readiness.

## Reproducible checks

```sh
python3 crates/fss-reference/tests/fixtures/interval_association_model.py
cargo test -p fss-reference --lib ingest::cross_camera
cargo test -p fss-reference --lib ingest::recorded_corroboration
cargo test -p fss-reference --test interval_corroboration_contract
cargo test -p fss-cli --test corroborate_cli_contract
```

The independent Python oracle was executed: 36,864 interval/geometry/global-assignment cases,
the lost-alternative counterexample, and signed-128 extremes passed. It compares interval
formulas with enumeration of actual instants and every optional one-to-one assignment. It is
not execution of the Rust implementation or a production qualification receipt.

The original interval-matching implementation added 24 Rust regressions for core matching,
the recorded-entry adapter and retained JPEG-to-event publication. Those tests were not run
in that original authoring environment, which lacked a Rust toolchain.

### Common-cause and stored-decision validation (2026-10-07)

The 13 `corroborate_cli_contract` tests and 2 `corroboration_dependencies_contract` tests
passed natively. They exercise shared-cause holds, declaration-order identity, exact approvals,
retained dependency reconstruction, unchanged coverage boundaries, stored health-screened
alert eligibility, and later intrinsic or declared-domain tamper blocking. All 8
`recorded_health_cli_contract`, 7 `recorded_health_coverage_contract`, 6
`guarded_coverage_currency_contract` and 8 `fusion_cli` tests also passed.

Required CLI binaries and production libraries were built with the pinned Cargo toolchain.
The unchanged integration-test sources were compiled with the same pinned `rustc --test`,
the exact Cargo artifacts and required CLI binary paths. The seven dependency-helper unit
regressions and the full workspace qualification lane were not executed in this session.
These checks do not certify physical independence, real-camera recall or deployment calibration.
