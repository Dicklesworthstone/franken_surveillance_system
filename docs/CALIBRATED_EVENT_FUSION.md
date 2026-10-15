# Calibrated class advice in recorded event analysis

`fss-event watch` and `fss-event corroborate` can now attach the existing native
`fss-fusion` bridge's calibrated class advice to a short-window entry report.
This is the public-command integration for Bead `fss-808pm`, not a replacement
for the detector, tracker, event policy, coverage records, or approval mechanism.

## Run the same analysis with a pinned profile

Start with a working, read-only short-window `watch` or `corroborate` command that
already selects a retained recording, zones, and an explicitly pinned detector
package. Keep its normal arguments and add:

```text
--fusion-profile /absolute/path/to/profile.json
--fusion-digest sha256:EXACT_PROFILE_FILE_SHA256
```

These are separate-value options, not `--option=value` options. Both are required.
The detector must still be selected explicitly with all three existing options:

```text
--detector-package /absolute/path/to/model.fss
--detector-digest sha256:EXACT_MODEL_PACKAGE_SHA256
--detector-max-inferences N
```

The uppercase values above are placeholders, not runnable digests or a suggested
inference allowance. Keep the detector's actual package pin and bounded allowance.
The two-camera command shares its existing cascade allowance across both cameras.
No additional model runner or external inference process is introduced.

The profile must be a regular file, not a symlink, and at most 256 KiB. Its exact
SHA-256 is verified before JSON parsing and before retained media is decoded.
Unknown profile fields, unsupported schemas, malformed intervals, mismatched
analysis pins, and invalid calibration tables are refusals, not fallback to
uncalibrated advice. Omitting **both** fusion options retains the old command path.

## A profile describes one exact analysis

The schema is `fss.event_class_fusion_profile.v1`. The profile's binding fields are
`plan_digest`, `cascade_digest`, and `coverage_digests`; they must describe the
native analysis being advised. In particular, changing the source range, detector
configuration, visibility/privacy/health context, or resulting coverage must not
be handled by reusing an unrelated profile. Use the exact digests exposed by the
native analysis and its coverage records; do not hash displayed report JSON as a
substitute for those semantic identities.

The remaining profile inputs select the class (`class_index`), prior log-odds
interval (`prior`), fusion `policy`, `severity`, sequential `looks`, `now_ns`, and
per-sensor `calibrations`. The parser and field contract live in
`crates/fss-cli/src/event_fusion/input.rs`; programmatic construction uses
`EventFusionProfile::new(ClassFusionSpec)` in `fss_cli::event_fusion`.

A sensor calibration binds a score-calibration table and explicit
`failure_domains`. A calibrated table uses `fss.score_calibration.v1`, its
`generation`, semantic `digest`, count `bins`, and the interval label
`wilson_z2_per_bin_not_simultaneous`. Each count bin contains `lo_ppm`,
`true_positives`, and `false_positives`.

**The outer profile file SHA-256 and the nested calibration digest are different
kinds of pin.** The former identifies exact input bytes. The latter identifies the
native `CalibrationCounts` value. Use the native calibration types rather than
inventing a digest from an arbitrary JSON serialization.

Build calibration counts from appropriately labeled data for the sensor, task,
model, and operating conditions. The synthetic tables in unit tests demonstrate
serialization and refusal behavior; they are not a deployment calibration.
Detector scores are not probabilities. A pinned profile proves which inputs were
used, not that those inputs are empirically appropriate for a camera installation.

## Read the complete advice, without changing event authority

The output preserves the native report and adds a top-level
`calibrated_class_advice` object. It contains the bridge's complete report,
including source-linked evidence, the reproducible fusion query, dependency-aware
decision, and counterfactuals. It is not just a single confidence number. Shared
models, declared failure domains, and other common causes must not be mistaken
for independent camera votes.

The native proposal identities and approval hints remain unchanged. Missing class
support is not proof of absence, and a candidate-only detector cascade does not
turn a gap into a coverage witness. The fusion bridge revalidates its source and
authority basis; the command revalidates retained source custody again before
output. The combined native-and-advisory JSON, including its final newline, is
bounded to 2 MiB. An oversized complete report is refused rather than truncated.

For reproducibility, preserve the exact profile bytes and pin, native command
arguments, retained source references, and complete advisory report. Rerunning the
same read-only command with the same profile asks the native bridge to rebuild its
query from the current validated source and authority basis. A changed basis or
context can require new analysis; a saved report is not permission to bypass
current custody, privacy, or authority checks. This integration does not add a
standalone report-replay subcommand or a retained fusion-proof authority record.

## Publication is a separate invocation

A fusion request cannot be combined with any of:

- `--approve`
- `--retain-coverage`
- `--retain-health`

The parser and execution path both enforce this restriction. Exporting the derived
report with `--report-out` is still supported under the existing export rules.
To publish an original native proposal, review and run its exact native approval
hint in a **separate** invocation. Those hints deliberately omit the two fusion
options while keeping the source, detector, and other native analysis options.
They do not approve the advisory fusion result or confer new alert authority.

## Full-camera calibration and final guarded coverage

Short-window `corroborate` accepts both the pinned site-calibration options and the
pinned fusion profile. First run the normal read-only calibrated detector command
without fusion to obtain the final screened coverage identities. Pin those exact
record digests in `coverage_digests`, together with the native plan and cascade
identities. Reuse the same camera, calibration, detector, zone and analysis options
when adding the fusion profile. Nominal pre-screen coverage pins are not accepted
as a substitute for the final records.

The native guard preserves an exact, immutable, ordered lineage from the complete
original camera records to the screened set. The bridge verifies this lineage,
including an uncalibrated companion camera, before composing any advice. It then
revalidates retained source custody, privacy bindings and calibration adoption on
both sides of fusion; the command repeats these checks before report delivery.
Changed or unavailable dependencies cause refusal, never a nominal fallback.

The combined output contains both `calibration_uncertainty_guard` and
`calibrated_class_advice`. Rejected geometric samples still withhold coverage;
calibrated class advice cannot restore the removed witnesses or certify absence.
Positive event proposals and native approval hints are unchanged. A calibration
pin or an owner adoption remains a conditional input, not proof of physical
calibration accuracy. Coverage wire formats and exact retention approvals are
unchanged by this integration.

Library callers use `EventFusionReport::corroborate_guarded` with the native
`CorroborationReport`, its detector cascade, a `GuardedCoverageSet`, and explicit
retained-read limits. The nominal-only `corroborate` API rejects site-calibrated
coverage, preventing callers from bypassing the full-camera context selection.

## Explicit limits of this increment

Fusion is currently admitted only for short-window entry analysis. Dwell,
`--stream-watch`, `--stream-dwell`, and `--stream-corroborate` refuse a requested
fusion profile instead of silently ignoring it. The Bead remains open for those
integrations and native qualification; guarded-context wiring is not a claim of
physical calibration qualification.

## Regression checks

The command modules contain parser, mode/authority, output-composition, and exact
report-size tests. `crates/fss-cli/tests/event_fusion_cli.rs` additionally launches
the real binary for rejected requests: missing or malformed pins, duplicate flags,
authority writes, unsupported streaming/dwell, and invalid or incomplete site-
calibration pins. Full-camera fusion admission still refuses every authority-write
combination. These cases require the specific admission error, no stdout report, no deployment-root
creation, and no report export. They do not execute model inference.

Run with the repository's pinned Rust toolchain:

```sh
cargo test -p fss-cli --test event_fusion_cli
cargo test -p fss-cli --bin fss-event fusion
cargo test -p fss-cli --lib event_fusion
cargo test -p fss-reference --lib calibrated_coverage
cargo fmt --all --check
```

These commands were **not executed in the implementation session**: the editing
container lacked Rust and could not download a toolchain. Source/API and static
diff review are not substitutes for native compilation or passing tests.
