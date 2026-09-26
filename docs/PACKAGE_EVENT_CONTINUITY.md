# Source-verified package events and exact track observations

Package-event analysis now uses the tracker's actual one-to-one assignment rather
than guessing which detection overlaps a filtered box most closely. It also reopens
the exact source custody and starts fresh tracking epochs at discontinuities. These
changes apply to the existing `fss-event report --package-report` / `prepare` /
`publish` path, including retained sentinel child reports. No additional activation
flag or alternative event publisher is introduced.

## Actual assignment, not a second association

`MultiObjectTracker::try_step_assigned` returns the existing motion-state output and
an ordered list of `(track_id, original_detection_index)` observations. The index
addresses the caller's original slice, not the internally sorted detections. It is
recorded at the actual update or new-track creation. Lost/coasting tracks have no
observation. A refused bounded step returns neither changed state nor a partial
witness. The existing `step`, `try_step`, and `TrackerOutput` remain available.

The witness adds O(detections) storage and a bounded ordering pass, not another
Hungarian solve. The numerical algorithm remains `fss.reference.kalman_global_iou.v1`.
Package observations use the exact assigned row, score and bounds; their integer
filtered-box IoU is descriptive geometry, not permission to substitute another row.
An independent arithmetic counterexample demonstrates why this matters: the only
feasible full assignment is `(0, 1)`, but selecting the nearest detection after the
Kalman update reconstructs `(0, 0)`. Identical boxes with different scores are another
case where the former package-event code attributed the higher-scoring row twice.

## Source custody and discontinuities

Before new detection retention, and on every reopen used by analysis/preparation/
publication, the existing bounded retained reader verifies original source bytes.
The record must bind the exact import root, format, capsule digest, sensor and capture
interval. Missing/corrupt source is refused without a model rerun or automatic repair.
All requested segments must exist exactly once. Duplicate capsules, duplicate head
rows, invalid class indices, nonfinite scores, invalid boxes and incomplete ranges
are refused before tracking. Valid v1 detection-record bytes remain unchanged.

Source capsules are examined in source-segment order. An explicit `gap_before`, a
non-successor sequence, or changed image dimensions starts a fresh tracker and
confirmation run. Reasons are independent and retained in `PackageTrackingBoundary`.
The first requested frame starts a new analysis; a gap before that frame is not
mistaken for a bridge to observations outside the request. Sensor or clock changes
are refused. Analysis-local track ids never recycle across epochs, even when the old
track was only tentative or already deleted.

Native display order is preserved within an epoch. A display sequence that returns
across a source discontinuity is refused rather than sorted into a false continuous
trajectory. Empty detection frames remain misses, not source gaps or absence proofs.
New tracks can confirm normally after sufficient observations inside the new epoch.
For example, with a three-hit confirmation policy, two observations before a gap and
two after it produce two unconfirmed tracks, not one confirmed four-hit trajectory.

`PackageAnalysisReport::boundaries()` and `RetainedPackageDetection::boundaries()`
expose every boundary. The canonical analysis export includes those boundaries and
all reasons; its digest binds them along with the exact observations. The existing
CLI text summary still lists confirmed tracks; detailed boundary inspection is through
the typed API and canonical v2 export, not a new human-only authority surface.

Custody revalidation uses the existing default read ceilings: at most 64 selected
segments, 16 MiB per segment/chunk and a 512 MiB source import. Segments are verified
sequentially, not buffered as a decoded range. This introduces source-read work on
reopen, not model work; physical I/O, latency and throughput have not been benchmarked.
Custody consistency is not numerical inference attestation, model accuracy, or a
claim that previously derived detections represent the current live scene.

## Version and approval compatibility

The machine contract is `registries/package_event_tracking.json`. New analyses are
`fss.package_analysis_report.v2`, magic `FSSPANR2`, binary version 2. The event policy
and track-identity domain also advance to v2. Existing detection reports, retained
`fss.package_detection_record.v1` records and already published events are not rewritten.

Old `FSSPANR1` analyses are recognized and explicitly refused for new publication;
they are not silently reinterpreted or sent to the luma-report parser. Regenerate the
analysis from its retained detection report, inspect the new tracks and prepare a new
proposal. Old approvals cannot silently carry over to the new assignment/continuity
semantics. Unknown policy generations and altered, self-consistently rehashed exports
are refused. Verification rebuilds the entire report from retained custody.

```sh
fss-event report --root /path/to/deployment --site site:home \
  --package-report "$RETAINED_PACKAGE_REPORT_DIGEST" --label person \
  --confirmation-hits 3 --report-out analysis-v2.bin
```

Use the returned report digest and confirmed track identity with the existing
`prepare`, review, and exact-digest `publish` workflow. Events remain unclassified,
indeterminate and single-sensor. Nothing here grants alert authority or turns a
model label into corroboration, identity, intent, or certified absence.

## Validation boundaries

Executed in the implementation environment: an independent Python assignment
counterexample, 874 original-row permutation/bijection cases, 8,184 epoch-confirmation
cases, and 34,406 display-order/discontinuity cases. Python fixture syntax was checked.
These execute mathematical models, **not the Rust implementation**.

Added Rust tests cover exact assignments, identical boxes, caller reordering, lost
tracks, failed admission, legacy state equality, record structure, independent
boundary reasons, gap-separated confirmation, id allocation, display reordering,
cancellation and capacity refusal. The new real-binary test imports a six-frame
recording with a retained gap, checks separate confirmation runs, rejects altered
and legacy-magic analyses, corrupts source custody between prepare and publish, checks
refusal without repair, explicitly restores test-owned bytes, then exercises approved
publication and its idempotent retry. Static color bars and the package's `tie` outputs
are plumbing fixtures, not classification or incident-recall evidence.

```sh
python3 crates/fss-reference/tests/fixtures/track_assignment_model.py
python3 crates/fss-reference/tests/fixtures/package_epoch_model.py
cargo test -p fss-reference --lib ingest::tracker
cargo test -p fss-reference --lib ingest::package_event
cargo test -p fss-cli --test package_continuity_cli_contract
cargo test -p fss-cli --test sentinel_detection_cli_contract
```

**Rust compilation, Rust/native CLI tests, rustfmt and Clippy were not run: this
session has no Rust toolchain or built binaries.** No release gate or production
qualification is promoted. Always-on live service integration and deployment-level
model quality remain separate unfinished work.
