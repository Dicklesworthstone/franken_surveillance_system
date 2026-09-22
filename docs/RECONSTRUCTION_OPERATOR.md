# Execute a retained recording recipe as one bounded local operation

`rtsp::recording_recipe::storage::operation` connects independently selected recipe
custody to complete native execution and explicit publication. It reuses the existing
source archive, canonical recipe, planned replayer, recording publisher and root-last
object store. It does not create a camera connection, media runtime, catalog format,
canonical lineage entry, or new effect authority.

## Cold startup from stored instructions

`LoadedRecordingRecipe::load` takes the exact canonical recipe identity, its complete
graph root, and an independently accepted `DatagramScope`. Only that pinned metadata
is consulted to discover the requested source prefix. Before reading, it checks the
actual spool allocation ceiling. It then verifies the entire source inventory and
runs `load_recording_recipe`, including the exact child set, canonical byte decoding,
original source hashes and all current componentwise resource ceilings. A header is
not permission to read, an authenticated latest pointer, or proof of complete input.

This version requires the recovered source namespace to equal the recipe's exact
prefix. Later source descendants are refused rather than included silently. Keep
source epochs and recipe selection explicit; this operation neither truncates nor
repairs a newer source history. Missing, broken, deleted, corrupt and wrong-scope
inputs are errors. The caller supplies the authorized exclusive storage owner and
live cancellation probe; a digest or stored retention claim does not grant access.

## Complete native execution precedes every output write

`PreparedReconstruction::prepare` executes `PlannedRecordingReplay` under current
source-byte, step, work, clock, window-count and cumulative output-byte limits. It
retains bounded ordinary `PreparedRecording` values without writing output objects
or roots. Only a real `FinishedPrefix` with every timing decision applied can create
a prepared operation. A mismatch in a later picture cannot leave an earlier window
published by this API. Failure returns completed windows, the native failure state,
and any output withheld after a bound, deadline or cancellation check.

The current clock is an explicit `ReconstructionClock` capability, sampled between
bounded native steps. It never replaces historical receive time or explicit media
timing. At most one million steps are admitted. All current deadlines and limits are
external to the stored recipe. Native creation of the next window has its own bounded
workspace; the aggregate retained-output limit is checked when that window is returned.
The bound is not a promise that native peak allocation equals retained output size.

Original observations consumed while preparing remain independently retrievable
through their retained source prefix. The complete native terminal remainder is
returned by `retained()`. The bounded summary distinguishes invalid RTCP, unselected
startup pictures/packets, unsealed source, queued packets/NALs, incomplete fragments
and incomplete pictures. These categories can refer to the same underlying source;
they must not be summed as independent observations or bytes of lost footage.

A prefix ending within a fragment can successfully execute to zero output windows
with a nonzero incomplete remainder. Successful recipe execution is NOT complete
capture, successful decoding, source continuity, or physical absence. No codec EOF
is synthesized to turn a tail into a final frame.

## Explicit publication and exact retry

`PreparedReconstruction::publish` revalidates the original recipe and source before
writing. Each window uses `RecordingPublication` at a deterministic slot derived
from the recipe graph root and its original output ordinal. After every output root
is durable, the operation publishes a `rtsp_recording_reconstruction_v1` manifest
referencing the source-closed recipe, all output roots, and hand-written canonical
summary metadata. That completion root is always last. Its encoding explicitly
sets the capture-complete assertion to false and excludes current runtime clocks.

Unexpected, malformed, conflicting or broken output slots and unresolved temporary
roots in this result namespace refuse publication. No different root is overwritten.
The same immutable plan and exact independent pin can be retried after appropriate
publisher reopening/reconciliation. Existing output roots return the native
`AlreadyPublished` receipt instead of being renumbered. The final root therefore
resolves a lost complete-result acknowledgement without duplicating recordings.

Writes are not an all-or-nothing filesystem transaction. Failure retains all window
acknowledgements already observed and the original typed storage error. A failed
window or completion write may already have committed. Retain the original candidate
pin and storage; do not treat an error as proof of no side effects, delete remnants,
or automatically retry a poisoned publisher. The plan continues to own every output.
A successful final commit returns its actual receipt without a later cancellation
check hiding it. Disclosure of that result remains separately authorized.

These derived slots are NOT the ordinary camera archive namespace or discovery
catalog. The result root is a proof of this reconstruction operation, not automatic
indexing, replication, retention closure or a canonical evidence-ledger publication.

## Verification

Ten authored native/filesystem integration tests cover cold startup, byte-identical
multi-window execution, complete-before-write behavior, late recipe mismatch,
zero-window incomplete fragments, output bounds, scope/configuration refusal,
cancellation/deadlines/work, unexpected slots, all four window-root crash cuts,
and lost final-root acknowledgements with exact retry.

```sh
cargo test -p fss-reference --test reconstruction_operation
cargo test -p fss-reference --test recording_recipe
```

Rust compilation, tests, rustfmt and Clippy have not run in this editing environment,
which lacks a Rust toolchain. Source/hash and lexical checks are not compiled-Rust
validation or a qualification promotion. Hardware throughput, raw unpersisted TCP,
automatic live timing journaling and production service integration remain outside
this reference operation.
