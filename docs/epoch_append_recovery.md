# Epoch writer ownership and ambiguous append recovery

`MerkleEpochLedger::open` acquires an exclusive OS lock on `ledger/LOCK` before
checkpoint inspection, epoch recovery, or tail truncation. Ownership lasts until the
ledger is dropped. A second cooperating writer receives `EpochLedgerError::WriterLocked`
and cannot rewrite the active writer's tail. Do not unlink or replace the lock file
while a writer is alive; advisory ownership does not protect against hostile inode replacement.

## Append outcomes

A normal `CommitReceipt` names the canonical sequence, batch identity, anchor, and
history root after the record durability barriers.

`AppendIndeterminate` means a body write, body sync, commit-trailer write, or commit sync
failed after append began. The writer retains the exact attempted bytes and validated
successor. New preparation, appends, checkpoints, and full-chain verification are fenced
until that attempt is reconciled. Reads of the last published head remain available;
they do not establish the uncertain append's outcome.

`reconcile_pending` verifies the previously committed boundary and compares the observed
tail against the exact attempted record. A complete matching record is synced and adopted
with its original receipt. A proven incomplete prefix is preserved in quarantine before
truncation when `IncompleteTailPolicy::Truncate` is explicitly selected. Reject mode
preserves an incomplete tail and retains the fence. Changed bytes or unexpected lengths
are never truncated as a guessed repair. Every failed reconciliation retains the pending
identity so that reconciliation can be retried without redispatching the evidence.

Successful reconciliation returns `Committed(receipt)` or `NotCommitted { sequence }`.
The storage adapter maps these to its existing recovery outcome and caches a committed
identity before permitting subsequent duplicate observation.

## Checkpoint failure after a durable commit

`CommittedCheckpointFailed` is a distinct outcome: the canonical batch is already durable,
and its exact receipt is carried in the error. Optional periodic checkpoint maintenance
failed after that publication. Do not infer rollback or submit the same evidence as a
new operation.

`MerkleEpochStorage::force_checkpoint` provides cancellation- and authority-checked repair
on the same adapter handle. Its retained duplicate identity remains intact. An unresolved
append still fences this repair. The lower-level ledger exposes its existing
`force_checkpoint` for callers that own its authority boundary.

The direct pack/ledger/projection combiner uses the durable receipt to apply the batch
when a periodic ledger checkpoint fails. After successful projection, each submitter and
the daemon storage caller receive the commit identity and a separate checkpoint diagnostic.
If projection also fails, `CommittedProjectionFailed` carries the original ledger receipt,
the projection error, and any ledger checkpoint diagnostic. Recover the projection against
that receipt before submitting further evidence.

## Verification boundary

Thirteen focused recovery test functions cover exclusive ownership (including a child
process), append and reconciliation phases, torn-prefix quarantine, altered-candidate
refusal, rollover, handle loss, authorized adapter recovery, and checkpoint failure after
commit. They are source-reviewed regression coverage, not retained execution evidence:
the session's native build was killed in unchanged `fss-core`, and the execution environment
then became unavailable before the changed ledger tests could run.

Run the focused tests and existing epoch/storage-adapter regressions on the pinned toolchain
before claiming qualification:

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-ledger --test merkle_writer_recovery_contract -- --test-threads=1
```
