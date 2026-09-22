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

The recipe now selects an immutable `DatagramPrefix` from the verified current
source chain. Valid later observations do not invalidate older recipes and are
never silently added to their input. The full current chain is verified first;
only the exact selected metadata is exposed to native replay. No live writer or
stored history is truncated. `observed_source_head()` reports the complete head
verified at load, separately from `pin().source`, which remains the recipe input.

Before preparation and publication, the full current chain is revalidated against
that observed head. Growth is permitted; rollback, forks, missing or corrupt
originals, tombstones and unresolved source writes are not hidden by selecting an
older recipe. Current datagram/byte/work bounds cover the whole namespace, including
verified descendants. Recipe graph limits still apply only to its selected source
roots. The caller supplies the authorized exclusive storage owner and live probe;
no checksum or stored retention field grants access. Independently retained anchors
are still necessary to detect rollback after all later trusted state is lost.

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
This exact retry remains valid when source capture grows between executions. The
source snapshot, recipe bytes, media timing, output routes and result encoding all
remain pinned to the original selection; later packets cannot alter its root or
repair a fragment that was incomplete at that historical boundary.

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

Eleven authored native/filesystem integration tests cover cold startup, byte-identical
multi-window execution, complete-before-write behavior, late recipe mismatch,
zero-window incomplete fragments, output bounds, scope/configuration refusal,
cancellation/deadlines/work, unexpected slots, all four window-root crash cuts,
lost final-root acknowledgements with exact retry, and original corruption between
preparation and publication.

```sh
cargo test -p fss-reference --test reconstruction_operation
cargo test -p fss-reference --test recording_recipe
```

Rust compilation, tests, rustfmt and Clippy have not run in this editing environment,
which lacks a Rust toolchain. Source/hash and lexical checks are not compiled-Rust
validation or a qualification promotion. Hardware throughput, raw unpersisted TCP,
automatic live timing journaling and production service integration remain outside
this reference operation.

## Executable operator path

The existing `fss-archive` executable exposes the same implementation, with no
second reconstruction or publication algorithm:

```sh
fss-archive check-recipe \
  --root "$ARCHIVE_DIRECTORY" \
  --recipe-id "$RECIPE_ID" --recipe-root "$RECIPE_ROOT" \
  --ingress "$INGRESS" --generation "$GENERATION" --ssrc "$SSRC" \
  --peer "$ORIGINAL_IP_PORT" --authority "$ORIGINAL_RTSP_AUTHORITY" \
  --rtp-channel "$RTP_CHANNEL" --rtcp-channel "$RTCP_CHANNEL" \
  --receive-clock "$RECEIVE_CLOCK" --retention-evidence "$RETENTION_EVIDENCE"
```

Those source fields describe the original independently accepted source scope.
They do not initiate DNS, RTSP, socket or camera activity. The recipe must match
their exact interpretation. The command executes native replay and produces the
same candidate result root as the Rust API, but publishes no output objects or
roots. `result_status: "not_requested"` makes no claim about whether an earlier
run published that candidate; it is not an absence assertion.

Use the same arguments with `reconstruct-recipe --commit yes` to explicitly publish
all reconstructed windows and the completion root. Commit consent is required;
`check-recipe` rejects mutation flags. No output recording is published until the
entire timing program succeeds. An error or lost stdout after publication does not
prove that nothing committed: keep the original recipe selection, reopen/reconcile
uncertain storage, then retry the same command. Successful retries distinguish
`published` from `already_durable` and new windows from reused window roots.

The existing root, roots/tombstones/spool subdirectories, verification holds and
lock files must already exist as non-symlink entries. Missing owners are not created
or migrated. The publisher's real process lock is acquired; normal open recovery
verification and synchronization still occur. Thus checking is not forensic read-only
access. Directory ancestors must be trusted: this is not a hostile-filesystem sandbox.

Whole-operation timeout, step/work allowances, datagram/source limits, recipe
size/timing counts, output window/byte ceilings, root scans, spool object/allocation
limits and total storage capacity have explicit finite bounds. `--help` lists their
flags. Stored receiver/collector settings must fit the current API's default
component ceilings; the CLI does not silently change them or activate a new profile.
The total retained-output bound does not replace native per-window workspace bounds.
`--max-datagrams` can bound the full current chain up to 65,536 observations. The
selected recipe's direct source graph must independently fit the existing manifest
child ceiling. Raising the namespace scan bound does not relax that graph limit.

The bounded JSON report includes exact recipe, source, interpretation and candidate
or durable result identities, every category in `ReconstructionSummary`, and actual
publication counts. `source_head`, `source_datagrams` and `source_bytes` continue
to describe only the selected historical input. The additional
`observed_source_head_at_load` and `observed_source_datagrams_at_load` fields report
the full chain verified at startup, not observations processed by this recipe or
a fresh post-publication latest-head query. Capture completeness and archive
indexing remain false. It emits
no source bytes, endpoints, credentials, paths or per-window dumps. Unknown, duplicate,
overflowing and incomplete options fail before storage access without echoing values.
Errors emit no success JSON. An output-stream failure uses the existing bounded
writer and is not reported as successful acknowledgement.

Nine additional authored process tests (one Unix-only) cover API/CLI result identity,
check-without-write, lost-stdout exact retry, multi-window publication, incomplete
fragments, late mismatches, consent, execution limits, missing owners, secret-free
errors, actual cross-process locking, argument rejection and symlink roots.

```sh
cargo test -p fss-cli --test reconstruction_recipe_process
cargo test -p fss-reference --test reconstruction_operation
```

These executable tests, like the native tests above, have not been run in the editing
environment. No production or qualification result is inferred from their existence.

## Historical-growth regressions

Eight additional native integration tests cover unchanged media/index/source and
result identities after growth, lost acknowledgements followed by append and cold
retry, growth between individual API stages, old incomplete fragments with later
completion packets, independently executable old/new recipes on one source chain,
post-prepare descendant corruption, observed-head rollback, full-chain bounds, and
late timing mismatches. Three process tests exercise unchanged check output identity,
separate selected/observed counts, no-write checks, resumed exact publication and
independent namespace ceilings. All eleven are authored, not executed results.

```sh
cargo test -p fss-reference --test historical_reconstruction
cargo test -p fss-cli --test historical_recipe_process
cargo test -p fss-reference --lib rtsp::datagram_archive::prefix
```
