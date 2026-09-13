# Incremental source-contact tracking

`fss_twin::stream::ContactTrack` composes native contact projection and source-pair
motion fitting for an ongoing sequence of owner-supplied observations. It is an
implemented synchronous integration slice of BTI-005/008, not a decoder, detector,
identity association service, autonomous effect loop, or live-camera qualification.

## Ingestion and state

Construct a track with the imported twin, nonzero upstream track/clock/session
handles, the complete admitted camera snapshots, and bounded policy. Submit each
`ContactObservation` to `ingest`. Camera projection comes from the frozen registry,
not a replacement pose attached to each observation. New camera calibration, crop,
world, or clock state requires owner invalidation and a new session epoch.

The first supported observation seeds the state. A subsequent sufficiently separated
source observation establishes all motion support-pairs through `fit_world_motion`.
Overlapping capture intervals, excessive gaps, unsupported terrain, hidden contact,
and unassociated camera transitions receive distinct accepted-source dispositions.
They clear usable current velocity. A missing support or detection is not an observed
absence; an old velocity is not silently carried forward as a new measurement.

Updates are transactional in memory: complete projection, fitting, allocation and
cancellation checks precede mutation. An exhausted update can be retried without
losing its source frame. Exact retries return the original acknowledgement without
rolling the current state back. Conflicting evidence/exposure/association retries
fail. Receipts are bounded; after eviction, old capture times fail the monotone
lower-capture watermark instead of being accepted again. The owner must reorder
late inputs explicitly; this module neither buffers indefinitely nor overwrites
history to accommodate them.

`snapshot(expected_revision)` borrows an exact active revision. It retains the latest
source projection and optional motion separately. The borrow prevents mutation while
it is being consumed. Owned downstream results still need epoch/revision checks when
used later. `invalidate` latches immediately even without spare computation budget;
it does not silently activate replacement calibration. The latest receipt remains
available for reconciliation. Epoch uniqueness across process lifetimes belongs to
the existing canonical owner, not this process-local adapter.

## Runtime and privacy boundary

The caller admits authorized source data and property/camera views before construction.
The receipt window is not a custody ledger or durable evidence store. No filesystem,
clock read, network call, secret access, worker, or alternative async runtime exists
here. Asupersync can own the instance, invoke synchronous bounded work and own its
cancellation flag. Recorded and live admitted observations use the same entrypoint;
actual video decoding and detector integration remain upstream.

## Verification

`cargo test --locked --offline -p fss-twin --test stream_contract` contains twelve
contracts covering source-to-motion composition, exact revisions, old retries,
conflicting identities, eviction, hidden contact, missing support, gaps, clock
ambiguity, association, stale inputs, cancellation/work rollback and complete-mode
limits. The Rust suite has not executed in this authoring environment: no Rust
compiler is installed and network DNS prevented installing one. Source review is
not compilation or field qualification. Broad BTI-005/008 gates remain open.
