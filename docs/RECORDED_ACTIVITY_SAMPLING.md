# Recorded activity and sentinel sampling

This is an opt-in deterministic reference slice of FSS-078 / WP-090, not a
qualified event-recall policy or a live camera service. The all-frame recording
pipeline remains the default. Sampling never authorizes access or effects.

`ingest::activity::ActivitySampler` consumes existing verified `RecordedFrame`s
and uses the existing `PixelChangeDetector`; it does not duplicate JPEG decoding,
pixel measurement, source custody, or model inference. `ActivityPolicy` freezes
exact change thresholds, a positive sentinel stride (at most 256 input frames),
and a post-activity burst (at most 256 additional frames).

Every frame has an immutable, history-linked `SamplingDecision`, including frames
not selected for inference. Fixed sentinels occur at ordinals 0, stride, twice
stride, and so on. Motion cannot shift that phase. First input, source/geometry/
interpretation resets, motion, outstanding burst frames, and explicit required
frames all force inclusion. Simultaneous reasons are retained. An optional
required-frame basis is a provenance-bearing inclusion constraint, not a grant.

Comparison-budget exhaustion forces inference and records
`ComparisonBudgetFloor`; it never fabricates zero motion. Model budget exhaustion
must instead stop the caller with explicit incomplete progress. Cancellation and
invalid input remain errors. Gaps cannot refill comparison budgets. Repeating the
same frame with the same inclusion basis is idempotent; changing that basis on a
retry or reading the same recording backwards is refused.

The decision encoding (`FSSASMP1`, version 1) binds the exact source import,
segment, decoded publication root, policy, predecessor decision, inclusion basis,
measurement/reset information, all inclusion reasons, and remaining burst count.
The decoded root binds the original source, capture-time uncertainty, and codec
receipt. A digest is integrity evidence, not authentication or scene truth.

Sentinel distance is measured in inspected source frames, not time. This policy
cannot promise to observe an event between frames. A skipped model invocation is
an explicit analysis omission, never a negative detection or coverage witness.
Sparse detector/tracker reconstruction must retain its existing gap resets;
sampling must not join trajectories through omitted frames or erase uncertainty.

Validation added: exhaustive supported-stride schedule tests, exact burst expiry,
fixed sentinel phase, simultaneous inclusion reasons, mandatory-frame and missing-
measurement floors, and invalid policy rejection. These Rust tests have not been
executed in the editing environment, which has no Rust toolchain. Hardware,
held-out recall/quality, resource profiles, full qualification, and live-runtime
integration remain open; this does not close the full FSS-078 acceptance contract.

## Recording-to-report execution

`recording_pipeline::sampling::SamplingPlan::new` freezes an exact import,
interpretation and contiguous source range from a `RecordingRequest`, the activity
policy, comparison allowance, and bounded required-frame constraints. Constraint
order is normalized at construction; duplicate or out-of-range constraints are
rejected. Loading a plan requires exact canonical ordering and a digest match.

`run_sampled_recording` uses the same runner as `run_recording`. All requested
frames reach retained-source decoding/revalidation. A selection happens before
inference, and only selected frames consume model-work allowance. Required frames,
sentinels and comparison-budget fallback must execute or produce an explicit
failure; exhausted model work never changes them into skips. The existing
cumulative model reservation/reuse and detector/tracker budgets are unchanged.

The result contains a `SampledReport` and existing `RecordingProgress`. Its
`analysis()` is the existing canonical sparse `AnalysisReport`, not a second
tracking format. The enclosing `FSSASRP1` report records every decision and the
self-contained `FSSASPL1` recipe. Source gaps remain tracker resets; this reference
does not infer continued object presence across an intentionally omitted frame.
An owner that requires an uninterrupted investigation must include those exact
frames in `required_frames` or retain the unchanged all-frame mode.

`SampledReport::verify` is read-only: it reopens all decoded publications,
recomputes the full sampling trace (including skipped frames), and invokes the
existing analysis replay verifier. It rejects a rehashed altered skip decision,
missing/corrupt custody, changed source binding, unsupported versions, truncated
or extended envelopes, and comparison/frame/output budgets it was not granted.
It does not rerun JPEG or model kernels, but comparison and postprocessing work
are real and remain separately accounted. The comparison allowance is frozen
because conservative budget fallback can change selection; it is per attempt,
not an automatically refilled mission-wide resource grant.

On failure, `SampledRecordingFailure` retains decoded/inference progress, the
complete decision prefix, and consumed comparison work. A selected final decision
may have an unfinished inference: it is not a completion receipt. Retry the same
original range and frozen plan; successful numeric work is revalidated and reused.
The report bytes remain caller-owned until explicitly retained/exported. Returning
a report does not create another ledger, publish an event or grant effect authority.

Ten public-API fixture contracts cover quiet-frame inference reduction, mandatory
inclusions, comparison-pressure fallback, unchanged all-frame analysis, restart
reuse, read-only report verification, selected-model budget failure/retry,
cancellation, malformed plans, rehashed skip tampering, and sampler idempotency.
They use the repository's real retained JPEG and frozen-model fixtures. They were
added but have not been executed in this environment.
