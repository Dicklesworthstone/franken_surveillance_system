# Durable session and work-claim coordination

The FSS-226 reference coordinator can now share the existing `DurableSessionStore` journal.
`agent_session::checkpoint::journal::coordination::CoordinationCommand` exposes bounded acquire,
inspect, historical inspect, update, expiry, transfer, and reclaim. It does not add a public
`fss/1` verb, authenticate credentials, or grant domain effect authority.

## One owner, one commit boundary

The trusted runtime creates or opens a `DurableSessionStore`, then explicitly calls
`enable_coordination(WorkClaimLimits)`. Initialization is committed once. An exact retry is a
no-op; resetting the coordinator or changing its stored ceilings is refused. Session lifecycle,
aliases, hydration charges, claim commands, and owner closures share one hash-linked journal.
No mutable reference to either authority store is exposed.

`coordinate(principal, session, command, now)` stages both stores privately, executes the existing
reference coordinator, prepares a bounded record, and synchronizes its commit before returning.
Even a refused work request can advance clocks or tombstone an expired session. Those changes
are recorded before the refusal is delivered. Work reads also consume journal capacity because
they can change these authority watermarks. A byte/record/checkpoint limit cannot be bypassed by
calling the operation a read.

After any ambiguous append, **both** session and coordination operations are fenced. Existing
`reconcile_pending` classifies that exact record as committed or not committed. A committed
transfer installs the new fence exactly once; a noncommitted transfer leaves the original owner.
Neither path redelivers the withheld response, retries effects, or refunds a committed charge.

## Recovery re-derives claims

The private reference journal uses three record kinds:

| Kind | Payload |
|---|---|
| `0x5353` | Existing exact session checkpoint |
| `0x5749` | `fss.reference_coordination_init.v1`: immutable work limits and session checkpoint witness |
| `0x5743` | `fss.reference_coordination_record.v1`: typed command, before/after session checkpoint witnesses, outcome fingerprint |

The command is `fss.reference_coordination_request.v1`, encoded with the existing handwritten
canonical encoder: big-endian integers, explicit enum tags, algorithm-qualified digests,
length-prefixed UTF-8 and bytes, sorted unique dependencies, and exact version strings. Records
have a hard 1 MiB ceiling. IDs, privacy classes, dependency counts, and persisted store limits
are bounded before allocation. Unknown tags/versions, duplicate or unsorted dependencies,
trailing bytes, malformed lengths, and incompatible ceilings are rejected, not normalized.
Journal framing supplies the content checksum, predecessor root, and commit marker.

Replay starts from the existing session history, initializes claims once, and re-executes every
claim command under the session authority at that point. It compares the exact success-revision
or refusal fingerprint and both session-state witnesses. It does not deserialize a caller's
asserted owner, fence, completion, or revision history and call that authority. The reference
state machine reconstructs those values, including terminal scope reservations, dependency
checks, failed-read watermarks, and all historical revision links.

Refusal fingerprints use private exhaustive outer tags and version-bound nested error identities;
raw error text is not persisted in the receipt. Changes to this replay interpretation require
an explicit compatibility decision/version, not silent normalization.

## Compatibility and trust

`open_existing_with_coordination(path, expected_root, session_limits, claim_ceilings)` recovers
one exact root. Ceilings supplied at recovery may be stricter but never widen the stored limits.
A missing, empty, truncated, foreign, or divergent history is not a new store. A repeated
initialization is rejected even when the surrounding hashes are valid.

Unmodified session-only journals retain their original bytes and behavior. Old/session-only
readers reject the new kinds rather than ignoring claims. Normal session checkpoint records
may follow claim records; replay preserves the coordinator across them. There is no downgrade
or delete-history operation.

The expected root must be independently trusted, not copied from the same untrusted file.
Checksums establish integrity, not authentication or rollback resistance by themselves. The
journal and parent directory must be protected and exclusively owned, as for the existing
session journal. This is not a cross-process locking service, hostile-filesystem defense,
FrankenSQLite/ATP integration, or a production release claim. Root custody, Asupersync ownership,
full HandoffCapsule publication, and integration into the deployment's canonical publisher
remain separate requirements.

## Bounds and verification

Replay deliberately prioritizes reference semantics over speed. Its work includes session
checkpoint hashing at each coordination record and the existing claim revision/dependency
checks; retained history, session bytes, claim/revision counts, command bytes, and journal
records all have explicit ceilings. Compaction cannot discard fences or tombstones and is not
implemented here.

Focused coverage includes restart after transfer, exact acquisition retries, owner closure and
orphan reclaim, refusal-side clocks and expiry tombstones, dependency completion, terminal scope
reservations, old-reader refusal, initialization reset attempts, hash-valid fabricated outcomes,
revocation, all command variants, every record truncation point, and pre-allocation bounds.

```sh
cargo test -p fss-reference agent_session::checkpoint::journal
```

Rust compilation, tests, rustfmt, and clippy were not executable in the editing environment.
Lexical/delimiter and uploaded-blob identity checks are not substitutes for these gates.
The feature remains an unqualified deterministic/durable reference slice of FSS-226.

## Cold recovery after the writer process is lost

Losing an in-memory pending append no longer requires deleting or replacing the journal.
`recover_existing_with_coordination(path, expected_root, session_limits, claim_ceilings,
tail_policy)` returns the recovered store and a `SessionRecoveryReceipt`. `recover_existing`
provides the equivalent path for an unchanged session-only journal.

The exact independently authorized root, complete journal checksums, all semantic command
outcomes, and session-state witnesses are checked **before** any truncation. `Reject` leaves a
torn suffix untouched. `Truncate` removes only an incomplete final append; it never drops a
complete record to make an older root match. In particular, a fully written transfer with a
lost acknowledgement must be recovered at its new committed root. The predecessor is refused,
not treated as permission to restore the old fence.

Recovery rechecks the complete prefix on the descriptor being trimmed, synchronizes the file
(even when no truncation was needed), validates the resulting prefix again, and only then
installs a writer. Missing files are not created. Complete corruption, semantic replay drift,
foreign records, symlinks, reset attempts, incompatible bounds, and root mismatches produce no
usable store. A failure after truncation or synchronization still requires inspection; the
API does not claim the original suffix remains or that an unacknowledged operation failed.

The receipt identifies the full pre-recovery bytes, the digest and length of any discarded
incomplete suffix, and the exact synchronized root/session checkpoint/record count. It contains
no raw private commands. Its digest is an audit identity, not authentication, an effect grant,
or an instruction to retry. It does not claim to have observed whether the old process returned
a response. Restore the independently authorized prefix, inspect the current owner/revision,
and issue a fresh explicit mutation only when still valid.

Fault tests exercise BodyWrite, BodySync, CommitWrite, and CommitSync failures in both live and
cold recovery, with simultaneous session/claim fencing, owner closure versus reclaim, stale
root refusal, hash-valid forged outcomes before torn tails, complete-record corruption, capacity
exhaustion, legacy journals, missing/empty paths, and symlink refusal. These tests were added but
not executed in the compiler-less editing environment.
