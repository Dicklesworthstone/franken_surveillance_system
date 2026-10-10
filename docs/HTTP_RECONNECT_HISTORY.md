# Durable HTTP reconnect boundaries

`fss_reference::http_reconnect_history::DurableReconnectRecording` composes the
existing native reconnect recorder with the existing immutable object-graph publisher.
It has no mutable inner-recorder escape, new append journal, mutable current-head file,
network retry policy, inferred generation, camera timestamp or event authority.

Each ended connection yields `BoundaryPrepared(pin)`. Save the exact expected pin,
then call `commit_boundary`. The writer re-verifies the selected predecessor history
and every original read of the ended connection, stages bounded canonical metadata,
and publishes its root last. After an actual durable acknowledgement, the owner yields
`BoundaryDurable(pin)`. `release_boundary` re-verifies the entire history after any
external delay before releasing the native recorder's barrier. Failed storage,
output, cancellation or verification never permits the next connection.

The original raw recorder API is unchanged. The wrapper exposes only a shared borrow
of that recorder for statistics; it owns all mutable source/transfer operations. Its
poll budget remains the native recorder's budget. Native source/framing allowances
are unchanged, and a separately declared history-work allowance covers all history
reads/publications across the complete run. Neither allowance resets at a reconnect.

## Immutable format

A boundary is `http_reconnect_boundary_v1`, with canonical metadata beginning with
`FSSHRB01`, version 1 and `fss.http_reconnect_boundary.v1`. Its slot is
`fsshrb1-<64 hex digits of plan identity>-<connection ordinal>`.
Every manifest directly includes its metadata, its predecessor boundary (except the
first), and every original-read root of the current generation. The exact read roots
are never replaced by only a count or the last digest.

Metadata binds the acquisition plan digest, connection ordinal, predecessor root,
source generation, receive-clock and original-retention scope, complete original
prefix, native outcome class, local network counters, terminal admission time,
reserved next generation, backoff and stop reason. Original payload-free failure
text is retained as bounded **uninterpreted diagnostic data**: readers must not parse
Rust diagnostic wording to make a retry, authorization or classification decision.
Control-bearing outcome and stop tags have fixed versioned encodings.

Setup failures with no accepted response bytes are still real boundaries. Once their
root is published, the session namespace is occupied even though no wire-read root
exists. A new recorder refuses occupied/broken/orphaned session slots before the
first TCP attempt. Later reserved slots are rechecked while awaiting connection,
not leased indefinitely by an earlier empty check.

The constructor takes an explicit admission time and the existing native plan's
absolute deadline. All generation/clock integers retain their complete 64-bit values.
No policy, budget or clock value is recovered by guessing from a prior capture.

## Cold verification

`VerifiedReconnectHistory::load` takes an independently saved `(session, root,
connections)` pin, live original-custody read authority and caller-owned work budget.
It traverses at most 32 boundaries iteratively. Every selected boundary's family,
metadata, canonical encoding, source prefix and exact direct children are checked.
Parent ordinals, planned next generations and backoff order must agree. Source reads
and bytes are aggregated before any complete result is returned. Independent limits
cap the history at 8192 reads and 512 MiB, with a bounded per-generation source reader.
A missing parent, changed metadata/source, tombstone or budget failure rejects the
whole result. No successful partial history or inferred latest head is returned.

Verification means that the selected local archive-writer statements and original
source are retrievable through the existing publisher. It is not a signature or proof
that a foreign writer was honest. The caller must select the trusted root independently.
A verified prefix does not prove that the run ended, that there was no later attempt,
or that a reserved next source was actually connected. A native-complete boundary is
not an `HttpCompletionPin` and cannot authorize replay to invent socket EOF.

A requested frame-count stop, process death or failure before a native boundary can
leave only an earlier history prefix plus a current wire prefix. These are reported
separately, never collapsed into complete capture or continuous physical coverage.
Original HTTP headers/media remain private unencrypted local custody. History neither
exports nor encrypts them and never grants access, resumes acquisition or changes
retention/deletion policy. Retire transfers all unfinished source and the exact pending
boundary identity without extra I/O. Reconcile an ambiguous pin against storage; do not
reacquire the same generation or silently discard an orphaned publication.

## Operator capture workflow

`fss-capture-reconnect` can now select this durable owner with
`--durable-history yes`. Its normal bounded generation list, route, retry policy,
deadline, original-read custody, and optional privacy-masked decoding still apply.
The following example uses independently assigned SHA-256 identity variables:

```sh
fss-capture-reconnect \
  --root /srv/fss/front-camera-originals \
  --peer 192.0.2.44:80 --host camera.invalid --target /stream \
  --source "$SOURCE_SHA256" --generations 40,41,42 \
  --receive-clock "$RECEIVE_CLOCK_SHA256" \
  --retention-evidence "$RETENTION_SHA256" \
  --owner-authorized yes --plaintext yes --retain-originals yes \
  --after-complete yes --durable-history yes \
  --max-history-work 1000000000000 --recoverable yes
```

The first invocation is a pure preview: it reads no files, clock, or network.
Review the exact route, generation reservations, original-retention scope, and work
ceilings, then repeat with `--approve` set to its `approval_digest`. Preserve the
JSONL output independently while the approved run is active.

The new mode wraps the existing approval in
`fss.http_durable_reconnect_capture_plan.v1`. Its history-work allowance is separate
from native source/framing work and applies to the **whole run**, including failed
operations and every predecessor verification. The default is 1,000,000,000,000
units and the maximum is 1,000,000,000,000,000. Passing `--max-history-work` without
`--durable-history yes` is refused. Existing approvals and output remain unchanged
when durable history is disabled.

For each connection that reaches a native terminal boundary:

1. `history_prepared` reports the exact `(session, root, connections)` expected pin
   before the history publication begins. Its publication remains unconfirmed.
2. The existing history owner verifies the predecessor and original prefixes,
   stages canonical boundary metadata, and publishes its root last.
3. `history_durable` reports the acknowledged durable pin. The connection is still
   held while that output is accepted.
4. The owner re-verifies the selected history and original source before releasing
   the next generation. Output refusal, expired authority, missing source, or a
   depleted work allowance prevents reconnect.

The `finish` record adds `durable_history.last_durable`, an exact
`pending_boundary` with its publication-acknowledgement state, and consumed/remaining
history work. A requested frame-count stop or other interruption may leave the
current wire prefix outside ended-connection history. It stays in `prefixes` and
`pending_wire`; the CLI does not fabricate a terminal boundary to include it.

After restart, `VerifiedReconnectHistory::load` can verify an independently saved
pin, including a prepared pin whose publication acknowledgement was lost. A cold
verification never resumes a socket or invents a newer generation. Starting the
same occupied session refuses before TCP. Further acquisition needs a new explicit
plan with fresh source generations. A frame/byte/work limit ends the current run;
it does not silently roll over into another reservation.

Capture still publishes no event or alert. Source prefixes can be copied into a
separate retained deployment using `fss-import-http` with its independent original
access/retention approval, sensor binding, and explicit capture-time assumptions.
The durable history pin is a selected acquisition prefix, not continuous physical
coverage or a socket-EOF replay grant.

## Validation

Native tests cover real loopback truncation followed by a fresh generation, durable
barriers, cancellation before publication, idempotent publication, cold reopening,
exact verification-work limits, corrupt metadata preventing reconnect, byte-empty
setup failure, malformed metadata, every truncated encoding, parent/generation drift
and integer extremes. Run:

```sh
cargo test -p fss-reference http_reconnect_history --locked --offline
cargo test -p fss-cli --bin fss-capture-reconnect --locked --offline
```

The capture CLI's native cases cover exact approval, complete and truncated
connections, cold reopening, occupied-session refusal, output failure before and
after history publication, original-byte damage during the output/release boundary,
history-budget exhaustion before TCP, and separation of a requested frame stop from
ended-connection history. These cases establish the tested reference behavior; they
do not establish device, detection, timing, availability, or production qualification.
