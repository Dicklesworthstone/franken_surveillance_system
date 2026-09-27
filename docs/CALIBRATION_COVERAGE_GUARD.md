# Full camera uncertainty at the coverage boundary

## Operator behavior

`fss-event corroborate --calibration FILE --calibration-digest sha256:HEX ...`
now runs an additional full-camera covariance screen automatically. No new flag,
model package, device connection or third-party dependency is required. The CLI
now uses the already-present first-party `fss-geometry` crate as a normal dependency
instead of only as a development dependency; the lockfile closure is unchanged. The screen
reuses the verified calibration object, the exact planned ground rectangles and
sampling grid, and each recording sensor's current retained privacy mask.

The existing six-dimensional pose sigma-point assessment does not include lens
uncertainty or pose/lens covariance. The additional screen propagates the complete
camera marginal covariance through projection, including those cross terms and
optical-axis depth uncertainty. At each existing ground-grid sample, it checks a
radius-three local linearized contour's axis-aligned enclosure against the
half-open image domain and the sensor's half-open privacy rectangles. The enclosure
is inclusive: touching a mask's left/top edges counts, while touching only its
excluded right/bottom edges does not.

The screen is conservative: every sampled point must be inside the image, in
front of the camera plane and clear of the mask, even when the nominal visibility
threshold is lower than 100%. It may withhold otherwise useful partial coverage.
It cannot promote an uncovered interval or authorize an absence claim.

When a screened zone both requests abstention and carries a nominal witness,
the command withholds the entire two-camera coverage proposal. Its `coverage`
member is an explicit `fss.calibration_coverage_refusal.v1` object with `status:
blocked`, `knowledge_state: not_observable`, no records, and null approval digest
and command. The new `calibration_uncertainty_guard` member preserves bounded
per-camera/per-zone reason counts, exact input and privacy-binding digests, and
work accounting. It emits no new raw media, point coordinates or mask rectangles.

Positive event proposals and their approval identities are unchanged. A preview,
or a request approving positive events without asking to retain coverage, can
still finish with coverage withheld. A request that combines event approvals and
`--retain-coverage` is rejected **before either publication** when this guard
blocks: it cannot partly publish events and only then discover the coverage denial.
Remove the retention request to inspect the full preview and its reasons. Improve
calibration or choose supported ground zones rather than ignoring the denial.

Passing this screen leaves the existing coverage proposal and all its other gates
unchanged. Without a pinned calibration, existing command output stays unchanged.
Raw owner `--pose` arguments still have no full covariance to propagate.

## Scope and compatibility

This is a reference **linearized, conditional screen**, not a confidence guarantee,
a calibrated posterior, detection-quality evidence or a physical currency check.
The world point, surveyed geometry, gauge and held lens parameters remain exact
conditioning assumptions. Nonlinear tails, joint camera/landmark covariance,
physical camera changes, timing, actual observability and model misspecification
remain outside this screen. Existing mesh occlusion and pose-sigma checks still
apply independently. A radius of three is not a probability claim.

Previously retained coverage is **not retracted or rewritten**; the output says
`existing_coverage_retracted: false`. This addition blocks newly requested CLI
retention and presentation of rejected nominal proposals. Lower-level legacy
`CorroborationReport` APIs retain their documented pose-only behavior; callers of
those APIs must explicitly apply the additional screen. No durable coverage format,
legacy decoder or canonical event history is changed by this interlock.

The new output formats are specified in
`schemas/calibration_coverage_guard.v1.json`; the standalone registry row is
`registries/calibration_coverage_guard.json`. An unknown refusal format must never
be interpreted as an ordinary coverage proposal. No production gate, release
qualification, central algorithm promotion or bead completion is claimed.

## Bounds and validation

The library input is at most 12 camera parameters, 16 zones and a 32-by-32 grid.
The command supplies one 64,000,000-unit work budget shared by its cameras. Each
camera preflights the worst-case charge before starting; computation charges work
and observes a caller-supplied `WorkBudget` cancellation flag when present. Command
context checkpoints surround camera assessment. Budget exhaustion or malformed
covariance is an explicit refusal, not an apparently clear partial report.

The input digest includes the complete consumed covariance and its parameter
partition, camera generations, image mode and pose, calibrated parent identity,
sensor identity, mask digest and generation, ground geometry and screening policy.
Ordering of zones is canonicalized. The privacy binding must agree with its policy
payload, sensor and image resolution. Distorted nominal camera models are refused
rather than silently treated as undistorted.

Thirteen library regressions and five command-boundary regressions cover lens-only
uncertainty, opposite pose/lens correlations, mask-boundary contact, overlapping
masks, camera-plane crossings, invalid covariance even behind the camera, source
binding, deterministic inputs, budgeting, cancellation and approval withholding.
These tests were authored but **not executed** in the authoring environment, which
has no Rust toolchain. Independent Python mathematical checks passed seven ground
zone cases, four mask edge cases and 16,000 sampled linearized-contour points; that
is not Rust or end-to-end command execution.

Required native checks, on the repository's pinned toolchain:

```sh
cargo test -p fss-geometry uncertainty
cargo test -p fss-reference calibration_coverage
cargo test -p fss-cli --bin fss-event calibration_coverage
cargo test -p fss-cli --test site_calibration_cli_contract
cargo test -p fss-cli --test coverage_cli_contract
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

Run the applicable repository qualification lanes before any deployment claim.
