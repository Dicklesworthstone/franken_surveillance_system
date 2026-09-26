# Whole-session HTTP RGB history replay

Status: implemented reference behavior; not production-qualified. The existing ordered RGB
history now drives its own complete native reconstruction through
`ingest::http_rgb_history_replay`. A saved history is a recipe, not evidence that a model ran.
This path actually executes the original graph/JPEG/head and both temporal stages, then checks
every result against the committed per-frame fingerprints.

## Selection and authority

Use `inspect_history` to recover the committed and pending recipes from a session identity.
Inspection reads only history metadata and does not invoke a model. To execute, call
`replay_history` with the exact returned `HttpRgbHistoryTip` (session, root and revision).
A changed latest committed tip is stale; a durable root awaiting its reachability batch is
reported separately, never silently promoted, executed or repaired.

Four independent adapters authorize history reads, original HTTP disclosure, source-closed
model/JPEG disclosure, and execution of this exact model for this exact session. Permission
to read a recipe does not authorize computation. Every native source or evidence boundary
also keeps its existing checks. The named sensor comes from the committed configuration;
select its current policy in the history deployment or an explicitly supplied external
deployment. The stored mask digest and generation must match the current retained policy.
A successful replay is not a new acquisition, model activation or effect grant.

## Native reconstruction

The driver loads the exact original wire inventory, runs the existing HTTP/MIME cursor, and
matches each original ordinal, JPEG digest, exposure and historical wire prefix. Identical
JPEG bytes in two parts do not become one exposure. It restores each ledgered source-closed
RGB envelope, reimports its exact graph and weights, decodes under current privacy policy,
executes the native inference and head, and compares their fingerprints. It constructs the
existing `RgbZoneTracker` from the persisted configuration and assimilates every observation
in order, requiring both tracking and zone fingerprints to match too.

Only one frame's original/model/result buffers are needed at a time. The result returns all
bounded fingerprint/count rows and the actual reconstructed native temporal owner, not a
caller-written tracker snapshot. A failure returns no partial successful result or owner;
all native work counters already charged remain inspectable on the caller's `ReplayBudget`.
There is no network access, root publication, ledger append, repair, event change or alert.

For a committed complete history, the original pin must exactly match its completion pin.
The native ending and frame count are verified again after all frames are transferred. A
close-delimited recording needs its actual retained EOF witness; exhausted bytes alone cannot
create EOF. Fixed-length and chunked endings are checked against the same completion record.

For a prefix, successful reconstruction stops after its committed frames, without executing
lookahead parts or claiming the stream ended. By default the original tip is the last stored
frame's pin. If additional original reads exist, supply their independently retained tip
explicitly; the original archive never silently follows a newer head. All historical frame
pins must be members of the selected tip. Empty configuration-only histories execute no frame.

## Bounds and cost

The existing 64-frame history bound remains. Parser, archive, importer, output and per-attempt
native execution limits are independently supplied. `ReplayBudget` owns cumulative source,
copy/hash, import, HTTP/MIME, JPEG, head, temporal, cursor and inference-attempt allowances.
No counter refills when another frame starts or the caller retries a failed invocation.

Before each numerical attempt the driver reserves the sum of its preprocessing and execution
operation ceilings. This is conservative admission, not measured work: failed native kernels
cannot return complete usage. Successful frame rows separately report actual preprocessing
and graph operations. Native per-attempt buffer limits still apply; no whole-process peak RSS,
energy, latency or hard real-time guarantee is asserted. Source inventory verification repeats
at native ownership boundaries and has bounded but potentially substantial session-level cost.
The semantic result digest excludes work counters and read fragmentation.

The canonical history selection and its custody are rechecked before return. Original custody
is also reverified; a later external filesystem mutation is not excluded by an earlier receipt.
Open operations retain their existing exclusive locks and recovery synchronization behavior;
read-only replay is not a claim that filesystem open performs no synchronization.

## Verification and boundaries

```sh
cargo test -p fss-reference --lib ingest::http_rgb_history_replay
cargo test -p fss-reference --test http_rgb_history_replay_contract
```

The authored tests exercise exact source selection, cumulative admission, overflow refusal,
actual live recording and ledgered history, all owners closing before replay, three HTTP
framing modes, read-size invariance, duplicate JPEG/distinct exposure handling, stale tips,
metadata-only authority, disclosure denial, cancellation, exhausted inference retries and
prefix-versus-complete semantics. Synthetic coefficients and loopback frames test wiring,
not real-camera detection quality. Rust compilation and native execution were attempted but
could not start because `cargo` is absent; rustfmt and Clippy are also unverified.

Existing model, source, archive, history and temporal encodings remain unchanged. Native model
or privacy generation incompatibility is a refusal, not permission to regenerate stored truth.
This consumes histories already produced by the RGB recording/history library workflow.
It does not convert a raw `fss-capture http` archive into a detector history, create missing
capture timestamps, infer health/absence, or run continuous monitoring.
