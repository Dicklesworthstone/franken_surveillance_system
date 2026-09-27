# Retained full-camera coverage screening

Reference implementation for fss-x8j0v. Not production-qualified. The native
Rust build, tests and qualification must run before this receives a qualification
claim; the independent Python model is not Rust execution.

## Version 6 and lossless abstention

`apply_calibration_coverage` applies an actual `CalibrationCoverageAssessment`
to one validated nominal, sigma-point coverage record. It returns a new record;
neither the caller's original record nor deployment authority is mutated.

A rejected ground zone loses only its nominal witnesses. Each former witness's
exact segment range and outer capture hull becomes a `calibration_uncertainty`
interval. Existing decode refusals, missing segments, source-time uncertainty,
privacy, warm-up, latency and positive-entry intervals are preserved unchanged.
Accepted zones keep their witness ranges, domains, generations and anchors;
the pipeline digest and negative predicate are rebound to the full-camera screen.
No new interval is certified and no gap is repaired by assumption.

A complete, disjoint partition of each record's declared segment range is
required before and after projection. Validation uses interval endpoints, not
iteration over a possibly enormous segment range. Exceeded input, work, output
or cancellation bounds fail atomically, without partially modifying the caller.

The new analysis identity, ledger object, pipeline digest and approval distinguish
screened coverage from its nominal precursor. A pre-screen approval cannot retain
a newly screened proposal. Reapplying exactly the same assessment is idempotent;
a changed assessment requires a fresh nominal analysis.

## Embedded receipt

The `PoseUncertainty::SigmaPointsGuarded` variant retains the existing pose
marginal and a bounded `CalibrationCoverageReceipt`. The receipt binds the full
screen's input digest, exact calibration and camera generations, sensor digest,
import identity/root, privacy binding and generation, nominal analysis identity,
pose-marginal bits, and each zone's exact geometry/grid/threshold binding, nominal
pipeline and seven mutually exclusive sample counts.

The receipt is embedded directly in `CoverageRecord` version 6, not left only in
stdout or conversation. Its digest is carried by every surviving negative
predicate. The ordinary decoder and validator reject changed source/calibration,
zone geometry, pipeline or analysis bindings; missing/duplicate zones; witnesses
in rejected zones; inconsistent refusal reasons; malformed counts, unknown
versions, nonfinite pose bits and noncanonical/trailing bytes.

A receipt proves which conditional computation the producer recorded. Its
input digest is not a replacement for the original calibration artifact when
independently recomputing the full covariance screen. It is not authentication,
a calibrated confidence level, evidence of physical currency, nonlinear
visibility proof or evidence of detector quality.

## Binary layout

Existing `FSSCOV01` framing and record domain are retained. Version 6 uses the
version-5 layout, with the uncertainty spelling
`sigma_points_with_full_camera_guard`, the unchanged pose sigma-point policy and
36 covariance values, then the full-camera receipt. Per-zone robustness blocks
remain present. The additional uncovered spelling is `calibration_uncertainty`.
Versions 1–5 keep their exact encodings and historical read semantics; a reader
without version-6 support refuses the newer record instead of dropping its guard.

Receipt fields use the existing `CanonicalEncoder`: UTF-8/bytes with big-endian
u64 length; tagged 32-byte SHA-256 digests; big-endian unsigned integers; f64
values represented by their exact u64 bits. The exact field order is frozen in
`registries/calibration_coverage_receipt.json`. No hash domain is repurposed.

## Bounds and reproduction

At most 16 zones, 1024 samples per zone, 512 witnesses and 512 uncovered intervals
per zone, an 8192-byte receipt, and a 4-MiB coverage record are admitted. Borrowed
strings and collections are bounded before validation, cloning and encoding.
Work is charged before transformation; budget exhaustion is not truncation.

Run `cargo test -p fss-reference calibration_coverage --locked --offline` for the
native contracts. Run `python3 scripts/calibration_coverage_receipt_model.py` for
the separate standard-library interval/receipt model. The latter exhaustively
checks 6561 eight-segment partitions, 4096 seeded partitions including u64 edge
coordinates, every receipt zone count, and 25584 truncated receipt prefixes.

The initial receipt layer is available to library callers. Existing nominal
entrypoints remain unchanged until a caller explicitly applies this projection;
this layer alone does not retrofit source/privacy currency revalidation at the
retention boundary or retract historical records.
