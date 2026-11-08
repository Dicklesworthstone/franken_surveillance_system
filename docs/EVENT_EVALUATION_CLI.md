# Offline event evaluation

`fss-evaluate` exposes the existing `fss_reference::evaluation` event-level scorer as a
bounded command. The interchange mode compares explicitly supplied candidate events with
labelled clips. The `retained-package` mode derives candidates from actual retained native
detector tracks and verifies their source custody before returning scores. Both emit one
derived JSON report without running inference, certifying camera coverage, sending alerts,
or activating a threshold.

## Run the synthetic example

From the repository root, using the pinned Rust toolchain:

```sh
cargo run -p fss-cli --bin fss-evaluate -- \
  --labels fixtures/evaluation/cli-smoke/labels.tsv \
  --candidates fixtures/evaluation/cli-smoke/candidates.tsv \
  --pipeline-generation synthetic-pipeline \
  --model-generation synthetic-model \
  --policy-generation synthetic-policy \
  --max-false-alerts 0 \
  --per-observed-ns 1000
```

This hand-authored fixture has one observed truth event, one truth event inside an explicit
sensor gap, one true-positive candidate, one false-positive candidate, and one candidate
inside the gap. Expected observed duration is 900 ns, full-set precision is 1/2, and observable
recall is 1/1. At the selected zero-false-alert operating point, the threshold is 900000 ppm
and the false-positive count is zero. Time to detect the observed event is 10 ns.

The synthetic AUPRC is 1000000 ppm because the one true positive ranks above the false
positive. That number is a scoring example, **not evidence of detector quality**, a real
camera trial, calibration, or a release qualification result.

Substitute `all-gap-labels.tsv` to exercise an entirely unobservable clip. Its operating point
must be `no_observed_time`, not a successful false-alert-budget result. The
`unknown-clip-candidates.tsv` file intentionally contains an invalid reference and must fail.

## Input contract

Files are UTF-8 with literal TAB-separated fields. The first line must be the exact schema
header. Blank lines and lines starting with `#` are allowed after the header. LF and CRLF are
accepted. Row order does not affect normalized report identity. No fields are silently
ignored. There is no escaping or quoting within a field.

Labels begin with `fss-evaluation-labels.v1` and accept these rows:

```text
clip<TAB>CLIP_ID<TAB>DURATION_NS
truth<TAB>EVENT_ID<TAB>CLIP_ID<TAB>CLASS<TAB>ZONE_OR_-<TAB>START_NS<TAB>END_NS
gap<TAB>CLIP_ID<TAB>START_NS<TAB>END_NS<TAB>REASON
```

Candidates begin with `fss-evaluation-candidates.v1` and accept:

```text
candidate<TAB>CANDIDATE_ID<TAB>CLIP_ID<TAB>CLASS<TAB>ZONE_OR_-<TAB>DETECT_NS<TAB>SCORE_PPM
```

Replace the displayed `<TAB>` markers with actual tab characters. The checked-in fixtures
already contain tabs. `-` means no zone; it cannot also be used as a literal zone identifier.
Gap reasons are `sensor_down`, `occluded`, `uncalibrated`, and `other`. A clip spans
`[0,duration)`; truth and gap intervals are closed. Times are non-negative integer nanoseconds;
scores are integer parts per million in `0..=1000000`. IDs and references are validated by the
existing evaluation library. Optional `--early-tolerance-ns` and `--late-tolerance-ns` default
to zero. The false-alert period must be positive. Unknown, duplicate, and missing flags fail.

Each input file is limited to 16 MiB and must be a regular file; each row is limited to 1024
bytes. The library's clip, truth-event, candidate, interval, and identifier limits still apply.
Inputs are treated as immutable snapshots, not streams. The adapter adds no dependencies.

## Interchange report and authority boundary

The JSON schema is `fss.evaluation.cli.v1`. Reports retain pipeline/model/policy generation
labels, normalized label-set and candidate-set digests, the canonical report digest, full-set
counts, durations, AUPRC, exact precision/recall ratios, the threshold curve, the budget-selected
operating point, time-to-detect summaries, and every truth/candidate disposition.

Nanoseconds and 64-bit budget fields are decimal JSON strings to avoid rounding in consumers
that use floating-point JSON numbers. Counts and ppm values are JSON numbers. Undefined metrics
carry a reason; they are not converted to zero or perfect performance. Full-set counts are
separate from the selected operating-point counts.

In interchange mode, coverage and generation labels are **caller declarations**, not independently verified evidence.
The report explicitly says `derived_only: true`, `threshold_activated: false`, and
`coverage_basis: "caller_declared"`. Digests bind the normalized evaluator inputs and result;
they are not signatures or attestations of the label source. Omitting a real coverage gap from
the labels can invalidate the interpretation. This command does not create a `CoverageWitness`
or provide negative evidence to the authority ledger.

For existing native package output, use the source-verified workflow below. Other pipelines,
including `fss-event watch`, still use the explicit candidate interchange format. Per-frame
detections are not independent ground-truth events. Threshold selection is descriptive and
does not change notification policy; neither mode supplies a real labelled quality corpus.

Success exits 0 and writes a report to stdout. Input, validation, and scoring failures exit 2,
leave stdout empty, and write a single `fss.evaluation.cli_error.v1` diagnostic to stderr with
an error code, an optional source line, and `effect_started: false`. Diagnostics omit source
rows and local file paths. Output-write failure exits 1. `--help` alone prints usage and exits 0.

## Evaluate retained native package tracks

First retain a complete native detection report using the existing `fss-file import` and
`fss-infer package-detect --retain yes` workflow. Use the exact report digest printed in
`package_detection_retained`. Evaluation reopens that report from the deployment; it accepts
neither a loose exported report nor caller-supplied track or candidate rows. The original
loose recording and model package are unnecessary once their native results and source
custody are retained.

```sh
fss-evaluate retained-package \
  --root /absolute/deployment --site site:home \
  --package-report sha256:EXACT_RETAINED_DETECTION_REPORT \
  --label person --labels garden-labels.tsv --clip-id garden-01 \
  --clip-origin-ns 1000000000 --stream-id stream:garden-recording \
  --clock-basis estimated \
  --confirmation-hits 2 --maximum-missed-frames 1 --minimum-iou-ppm 100000 \
  --max-false-alerts 1 --per-observed-ns 3600000000000
```

The uppercase digest is a placeholder. The stream generation, clock basis, origin, and class
must match the actual retained recording. Valid clock tokens are `utc_disciplined`,
`device_monotonic`, `host_monotonic`, and `estimated`; choosing a token never converts or
certifies the source clock. `--clip-origin-ns` is a signed integer on that clock. It is
subtracted from the native first-confirmation capture instant using checked arithmetic.

Use the existing labels TSV schema with exactly one matching `clip` row. Truth rows must use
the exact selected native label and `-` for the zone. A class-only track cannot establish
zone quality, so zoned or different-class truths are refused. Negative clips are supported:
provide the clip row and any declared gaps, with no truth rows. An empty native track set
still retains that clip's declared observed-time denominator.

### Timing and candidate policy

This initial native profile requires at least two analysed frames with strictly increasing,
singleton capture instants in actual native display order. The original import must label
its capture timing `operator_assumption`; unknown time, nonzero capture uncertainty,
non-container source omissions, or source/sequence gaps affecting the analysed range are
refused. Explicit file-import capture hints remain operator assumptions. In particular,
setting `--capture-uncertainty-ns 0` is a declaration, not a hardware-clock measurement.

The caller-declared half-open clip interval must fit inside
`[first_analysed_capture, last_analysed_capture + 1)`. A shorter subwindow is allowed. For
example, a one-second labelled clip may use a longer analysed recording containing a sample
at or after the clip's exclusive end. The owner does not guess cadence or add a final-frame
tail to make a longer clip fit. It reports the exact analysed sample hull and chosen window.
Label gaps still determine observability; sample timestamps do not create a `CoverageWitness`.

Every native track is accounted for. A track emits at most one candidate, at its **first
actually confirmed observation**, using that observation's actual assigned detection row.
Its score is `floor(exact_binary32_score * 1000000)`; the original F32 bits are also retained.
No later maximum score or retrospective confirmation changes the candidate. If the first
confirmation lies outside the selected clip, the track is reported as excluded and no later
observation replaces it. Tentative tracks are reported explicitly. Native tracking epoch
boundaries and IDs are preserved; tracks are not stitched across a reset.

The curve is conditional on the retained detector floor, native head/NMS contract, selected
class, and tracker recipe. It cannot recover detections already discarded by the detector.
Scores remain uncalibrated. This mode deliberately accepts no caller generation labels,
manual track selection, candidate file, or calibration-generation flags. Model, pipeline,
and extraction-policy identities are derived from the actual immutable package/model/graph/
head generation pins and the exact applied recipe.

### Native result, bounds, and authority

The outer schema is `fss.retained_package_evaluation.v1`. Its `evaluation` field contains the
unchanged `fss.evaluation.cli.v1` scoring report. Full provenance includes the current and
retention authority anchors, principal and site, import/manifest/package/model/graph/head
digests, current privacy binding, complete source frame facts, clock mapping, original scores,
and the disposition of every native track. Nanoseconds and 64-bit counters are decimal JSON
strings. The result digest binds the canonical projection digest, evaluator digest, and
source-read accounting; digests are not signatures or attestations of the label source.

The limits are 64 analysed frames, 128 tracks, 128 truth events, 128 declared gaps, 16,384
candidate-by-truth matching cells, and 1 MiB of complete JSON output. Excess input is refused,
not truncated. `--maximum-source-bytes` may reduce the default 4 GiB allowance; one shared,
nonrenewing counter covers both the initial source verification and the final independent
source pass, including upstream original-byte reads. Cancellation, missing/deleted/corrupt
source, changed current privacy, and final revalidation failure return no successful report.

The root must be an existing complete deployment at an absolute path. Its absence never
creates a store. The local process and filesystem authorize access; `--principal` is its
audit label, not remote authentication. Opening retains the publisher's existing local
housekeeping/recovery behavior, so this mode is not a promise of zero filesystem writes.
It skips pending-effect restart reconciliation and never returns that internal deployment to
the caller. Evaluation publishes no event, score, calibration, threshold, or external effect.
The output is a verified derived snapshot at its recorded authority anchor, not a continuing
claim that source custody or privacy can never change after completion.

## Regression entrypoints

```sh
cargo test -p fss-cli --bin fss-evaluate
cargo test -p fss-cli --test evaluation_cli
cargo test -p fss-core --test evaluation_budget_contract
cargo test -p fss-core --test package_evaluation_contract
cargo test -p fss-reference --test retained_package_evaluation_contract
cargo test -p fss-cli --test retained_package_evaluation_cli
```

The existing interchange tests cover scoring, deterministic execution, coverage loss, invalid
numbers/budgets, dangling references, missing input, and help. The core-only targets embed the
actual production extraction, record, confirmation, and evaluation sources without the async
runtime dependency; they establish pure policy behavior, not retained custody. The native
integration targets use a real first-party numeric package and actual file import, retention,
source reads, privacy withdrawal, cancellation, and process execution. These are test
entrypoints, not retained qualification receipts. A successful synthetic run cannot establish
real-world recall, camera compatibility, or release readiness. Run status must identify which
targets were actually executed; authored native custody tests are not implied by a passing
core-only lane.
