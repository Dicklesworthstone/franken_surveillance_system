# Cold inspection and native replay of whole-recording events

Published `event:long-watch:` and `event:long-corroborated:` candidates can be reopened by
identity, without the original command, exported report or input file. The reader recovers the
committed event and its retained analysis closure. A separate explicit verification operation
decodes the retained source and reruns the native computation.

These operations are reference features. A reproducible result is not a certificate of
physical truth, recognition accuracy, camera independence, health, absence or alert delivery.

## Inspect a committed event

```sh
fss-event read \
  --root /path/to/deployment --site site:home \
  --event-id "${EVENT_ID:?supply a published whole-recording event ID}"
```

The root must already be an existing deployment of the supplied site. The reader takes its
normal exclusive locks and allows its normal restart recovery. It does not append event,
import, verification or effect authority.

The complete JSON response includes:

- `status: "inspected_not_replayed"` and `native_replayed: false`;
- the exact committed event JSON and event publication root;
- the event revision digest, actual candidate provenance root, analysis roots and digests;
- the current authority basis and read accounting;
- an exact `verification_command` with both required pins and the chosen execution ceilings.

The actual provenance root is distinct from a corroborated event's decision fingerprint. Use
the returned `provenance_root` for the replay pin; neither a proposal digest nor a decision
fingerprint can substitute for it.

Inspection checks the retained metadata, capsule authority and source closure without
performing native image decoding. A stored analysis is not reported as an executed replay.
For a detector-backed watch event, the response also includes `retained_detector`: the package,
manifest, model, recipe and threshold-contract digests, kernel generation and inference
selection bounds. The complete archived package and every class-evidence record must be in
the analysis closure. Entry and class-frame capsule digests must match the exact retained
coding segments, rather than merely naming some valid capsule from the same camera.
Missing custody, corrupted metadata, stale privacy or a reviewed successor revision is refused.
This reader currently owns the original whole-recording candidate revisions; it does not
reinterpret a later human review as that original computation.

## Explicitly verify the computation

Review the inspection and execute its emitted `verification_command`, or supply its exact
selection pins:

```sh
fss-event verify \
  --root /path/to/deployment --site site:home \
  --event-id "${EVENT_ID:?supply the inspected whole-recording event ID}" \
  --expected-event-revision "${REVISION_DIGEST:?supply the inspected revision digest}" \
  --expected-provenance-root "${PROVENANCE_ROOT:?supply the inspected provenance root}" \
  --execute-perception yes
```

Both pins and the execution acknowledgement are mandatory. Changing an event revision or
provenance root invalidates the selection. The command accepts no source path, saved report,
threshold, zone, interpretation, health-policy or publication override.

Verification opens the exact retained imports, applies current sensor privacy, decodes the
selected MJPEG, H.264 or H.265 recording in native display order, and reruns the complete
foreground/tracker analysis. Watch replay preserves the original selected subrange and
absolute entry position. Corroboration replay runs both complete camera scans and reconstructs
their ground transforms, association gates, common-cause declarations and optional health
screen.

Detector-backed watch replay additionally loads the exact retained package archive, verifies
its manifest, model, threshold contract and kernel generation, and runs the original bounded
native RGB inference and class association. The original model file can be deleted after
publication. No loose package path or model/threshold/backend substitution is accepted.
Selected frames, refused frames, inference attempts, completed inferences and additional
source/JPEG/pixel work are part of the reproduced analysis.

The full analyses, candidate provenance and committed event must match. A matching event alone
cannot hide a changed background scan or omitted frame. Divergence or a bound failure returns
an error without success JSON. Success reports `status: "native_replay_matched"`, frame and
source-read accounting and the unchanged event. It writes no persistent verification record,
changes no candidate state and grants no alert permission.

### What configuration was retained

Whole-recording corroboration publications retain a complete canonical owner recipe, including
both imports, geometry, perception settings, native decoder identities, codec/read limits,
whole-scan bounds, dependencies and health policy. Replay restores that exact recipe and
checks it against the caller's current safety ceilings.

Historical whole-recording watch publications retain their semantic plan and five aggregate
budgets, but not every original per-object read or codec ceiling. Watch replay restores those
retained settings and uses the caller's current bounded native codec/read limits. It then
compares the complete native output with the retained analysis. The response describes this
scope explicitly; it does not invent missing historical settings or change the stored format.

Detector-backed whole-recording watch publications add a canonical recipe with the complete
original native scan ceilings and package settings. Replay checks every numeric reservation
against current caller ceilings and restores the original values. Model-free historical
publications keep their existing bytes and interpretation. The JSON identifies the complete
detector recipe separately from the historical five-budget watch recipe.

## Resource and output bounds

All numeric options require positive unsigned decimal values. Source, pixel, assignment,
trace and JPEG-work execution ceilings apply separately to each camera's complete recording.
They never refill at frame or chunk boundaries. For corroboration the complete two-camera
reservation is therefore twice the selected per-camera reservation.
For detector-backed watch, source, JPEG and pixel ceilings span both native passes. The
retained package archive is charged to the cumulative metadata-read bound. The recipe's
inference allowance remains global to the recording; at most 64 selected frames can enter
the native inference pipeline. Cooperative cancellation is checked at frame and inference
boundaries; one admitted model call retains its explicit internal work limits.

| Option | Default | Hard maximum |
|---|---:|---:|
| `--max-metadata-bytes` | 67,108,864 | 268,435,456 |
| `--max-report-bytes` | 1,048,576 | 16,777,216 |
| `--source-read-bytes` | 536,870,912 | 536,870,912 |
| `--pixel-budget` | 1,073,741,824 | 68,719,476,736 |
| `--assignment-work` | 1,073,741,824 | 68,719,476,736 |
| `--trace-bytes` | 8,388,608 | 8,388,608 |
| `--decode-work` | 100,000,000 | 1,000,000,000,000 |
| `--max-dimension` | 4,096 | 4,096 (minimum 16) |
| `--max-pixels` | 4,194,304 | 4,194,304 |
| `--max-segment-bytes` | 16,777,216 | 67,108,864 |

Inspection accepts the same execution ceilings so its generated command binds the operator's
chosen limits. Lower ceilings can refuse replay; they cannot rewrite the retained computation
to make it fit. Metadata reads, whole-scan source reads and codec work have separate accounting.
These limits do not claim total operating-system I/O, latency or memory accounting.

Optional `--event-out FILE` and `--report-out FILE` write complete create-only exports outside
the deployment. Existing files are not overwritten. An export failure may leave a partial
external file, but neither export success nor failure changes event authority.

The ordinary short-watch/corroboration and package-event readers retain their existing
contracts. Long-dwell uses its existing `fss-replay-dwell` workflow.

## Focused validation

New library and real-binary regression cases cover cold recovery, exact pins, complete native
matching, shared causes, source damage, privacy drift, subranges, invalid bounds and create-only
exports. After recovering the pinned `nightly-2026-08-31` toolchain and repairing a missing
trait import, all 24 focused native tests pass: ten reference cases, eight CLI parser/output
cases and six real-process integration cases. Compilation and execution used the exact source
at `68821e4062acb52dcdfc16636d1eb7850dc6e6df` plus that import correction.

```sh
cargo test -p fss-reference --lib long_event_replay
cargo test -p fss-cli --bin fss-event --test long_event_replay_cli
```

The integration builds used `--locked --offline -j 1`, disabled test debug information and
disabled incremental compilation to fit the transient build store. Debug assertions and the
pinned compiler remained unchanged. These focused results do not claim full-workspace tests,
Clippy, a workspace formatting pass, device quality or release qualification.

The detector-backed extension was then validated on 2026-10-10 with 58 passing native tests:
16 whole-recording reference contracts, 31 focused CLI tests and 11 current cold replay library
cases. The latter rerun all ten historical library cases and add a wrong-segment capsule-binding
regression. The CLI cases include native verification after loose source/model removal and
refusal after the retained model archive itself is removed. All tests passed without failures
or ignored cases. The test-only cold reader now imports its watch report type explicitly rather
than relying on a removed parent-module import.

```sh
cargo test -p fss-reference --test long_watch_contract
cargo test -p fss-reference --lib ingest::long_event_replay
cargo test -p fss-cli --test watch_stream_detector_cli --test watch_stream_entry_cli --test detector_cascade_cli_contract
cargo test -p fss-cli --test long_event_replay_cli
cargo test -p fss-cli --bin fss-event replay::
```

These runs used the same pinned native compiler, offline dependencies, one Cargo job, disabled
test debug information and incremental compilation, and a local serial frontend/backend
setting for the large reference crate. The serial setting resolved shared build-memory kills;
it changes neither the retained inference backend nor the project's toolchain or dependencies.
