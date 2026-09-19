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
