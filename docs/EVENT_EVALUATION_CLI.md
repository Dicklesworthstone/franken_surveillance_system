# Offline event evaluation

`fss-evaluate` exposes the existing `fss_reference::evaluation` event-level scorer as a
bounded, read-only command. It compares explicitly supplied candidate events with labelled
clips and emits one JSON report. It does not run inference, read deployment authority,
certify camera coverage, send alerts, or activate a threshold.

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

## Report and authority boundary

The JSON schema is `fss.evaluation.cli.v1`. Reports retain pipeline/model/policy generation
labels, normalized label-set and candidate-set digests, the canonical report digest, full-set
counts, durations, AUPRC, exact precision/recall ratios, the threshold curve, the budget-selected
operating point, time-to-detect summaries, and every truth/candidate disposition.

Nanoseconds and 64-bit budget fields are decimal JSON strings to avoid rounding in consumers
that use floating-point JSON numbers. Counts and ppm values are JSON numbers. Undefined metrics
carry a reason; they are not converted to zero or perfect performance. Full-set counts are
separate from the selected operating-point counts.

Coverage and generation labels are **caller declarations**, not independently verified evidence.
The report explicitly says `derived_only: true`, `threshold_activated: false`, and
`coverage_basis: "caller_declared"`. Digests bind the normalized evaluator inputs and result;
they are not signatures or attestations of the label source. Omitting a real coverage gap from
the labels can invalidate the interpretation. This command does not create a `CoverageWitness`
or provide negative evidence to the authority ledger.

There is no automatic import from `fss-event watch` or `fss-infer package-detect` reports yet.
Supply event candidates in the explicit interchange format; do not treat per-frame detections
as distinct ground-truth events or claim this adapter closes the real-labelled-corpus gap.
Threshold selection here is descriptive only and does not change notification policy.

Success exits 0 and writes a report to stdout. Input, validation, and scoring failures exit 2,
leave stdout empty, and write a single `fss.evaluation.cli_error.v1` diagnostic to stderr with
an error code, an optional source line, and `effect_started: false`. Diagnostics omit source
rows and local file paths. Output-write failure exits 1. `--help` alone prints usage and exits 0.

## Regression entrypoints

```sh
cargo test -p fss-cli --bin fss-evaluate
cargo test -p fss-cli --test evaluation_cli
```

The binary contains seven parser/scorer/report tests; the integration target contains six
executable tests covering fixture scoring, deterministic read-only execution, complete coverage
loss, invalid numbers/budgets, dangling references/missing input, and help. These are test
entrypoints, not retained qualification receipts. A successful synthetic run cannot establish
real-world recall, camera compatibility, source authenticity, or release readiness.
