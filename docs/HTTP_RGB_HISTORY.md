# Ordered HTTP RGB perception history

`ingest::http_rgb_history` retains the missing session-level replay ingredients:
the source scope, named sensor, explicit validity, anonymous episode, detector/head
identities, selected class, full tracker policy, coordinate basis, normalized zone
polygons and temporal policy, together with every ordered per-frame evidence pin.
A caller can recover the latest committed prefix using one configuration/session
identity rather than reconstructing a list of pins and assumptions from memory.

The history is an immutable **derived recipe**, not another journal, a tracker
checkpoint, a scene-truth claim or effect authority. It uses the existing object
spool and `LedgeredRootPublisher` / `local_root_reachability` batches. Models and
images remain in the existing RGB archive and are referenced, not copied into the
history record. Original HTTP custody remains in its separate original publisher;
wire and completion pins are explicitly external source references, not local
manifest children masquerading as available bytes.

## Record and recover

Construct `HttpRgbHistoryConfig` from an explicit `HttpRgbHistorySpec`. Native
`ImageTracker` and `ImageZoneMonitor` constructors validate the policy and polygons;
their actual initial chain identities are retained, not supplied by the caller.
Use `config.tracker(&head, work)` to create the live temporal owner with those exact
inputs. Configuration changes produce a different session identity.

Publish `HttpRgbHistory::new(config)` before starting the connection. For every
`HttpRgbEvidenceRecording` result, retain its detector evidence normally, then
prepare `history.appended(&recording, work, cx)` **while the native result is held**.
The history checks the actual model, detector, class, normalized zone configuration,
and both tracker/zone predecessor chains. Save `next.tip()` and publish that exact
tip before allowing the existing recording's `take_result`. Skipping a frame,
changing an episode, changing privacy generations, or filling a gap with a nearby
observation is refused. Identical JPEGs in distinct parts remain distinct exposures.

Once the native recording has delivered every result and actually published its
HTTP/MIME completion, `history.completed(&recording, cx)` prepares a separate final
revision. A prefix is never silently sealed by a timeout, a frame count, or an empty
detection result. There is no claim of continuous visibility or certified absence.

`read_latest_history(deployment, session, ...)` scans the bounded canonical ledger,
verifies every expected immutable prefix, and returns `HistoryRecovery` with the
observed authority anchor. `committed` contains the latest complete ledgered prefix;
`pending` separately identifies the next durable root whose reachability batch is
missing. Reading never repairs or appends. To reconcile pending work, explicitly
publish its exact tip under current retention authority. A missing/retracted prefix,
changed metadata or conflicting immutable slot is refused rather than skipped.
After a publisher crash, reopen through its existing recovery contract first.

History metadata read/write permission and original-model/JPEG disclosure permission
are separate explicit policy adapters. Neither a session ID nor a saved root is a
grant. Publication rechecks the predecessor under the exclusively owned deployment,
reopens the referenced RGB archives, and uses the existing root-last then ledger
commit boundary. Exact old-prefix retries cannot duplicate a batch or repair corrupt
source. Concurrent competing extensions cannot overwrite the same revision slot.

## Bounds and current qualification

A reference history has at most 64 frames, 16 zones and 32 vertices per zone. Its
configuration and complete prefix records are bounded by 16 KiB and 64 KiB. Every
prefix is self-contained; all earlier prefix identities are checked on recovery.
The deliberate bounded implementation has quadratic total metadata/custody-check
work over a fully appended session, not an unbounded streaming-performance claim.
Work budgets accumulate; originals are restored sequentially, not decoded into an
unbounded frame buffer. Larger sessions require a separately declared episode.

The schema and exact bounds are registered in `registries/http_rgb_history.json`.
Native tests cover canonical roundtrips/truncation, identity binding, malformed
policies, gap/duplicate/order/privacy refusal, complete-set bounds, cold header
recovery, idempotent retry and durable-root/missing-ledger reconciliation.

```sh
cargo test -p fss-reference --lib ingest::http_rgb_history
```

Rust compilation, native tests, rustfmt and Clippy have not run in this session:
the execution environment has no Rust toolchain. Lexical/delimiter and source/hash
checks are not a substitute for native execution. No release or quality gate is
promoted. This is library functionality; no camera daemon or automatic alert is added.
