# Forwarded delta retries and recovery

The daemon's production forwarded-batch writer retains retry identity beneath
`forwarded-requests/` in the deployment root. These records are operation bookkeeping.
The evidence ledger remains the only canonical world history.

An idempotency key binds the exact canonical batch bytes, approval digest, deployment,
contract basis, principal, and normalized granted capability set. Connection and request
correlation IDs are excluded. The storage backend independently binds the actual batch
bytes so direct callers cannot substitute a different batch under an old request digest.

## Publication and retry behavior

A fresh request first creates and syncs an immutable reservation. Only then may it enter
the existing pack/ledger/projection commit path. A successful commit publishes a second
immutable record containing the verified sequence, history root, and state root. The
daemon syncs the record and its parent directory before returning success.

Forwarding preserves the original v2 `EvidenceDeltaBatch` identity, complete basis and
successor anchors, deltas, and declared child closure. It does not rebase stale inputs.
Declared children and delta payload/witness bytes must already be retained and verified
within the bounded source-read budget before canonical publication.

An exact completed retry returns the original receipt after verifying that it belongs to
the current canonical history, including after reopening storage. A changed request using
the same key returns `ERR-IDEMPOTENCY-CONFLICT-001`. A saved completion must match the
proven sequence, history root, and state root. Matching batch bytes and state alone are
insufficient: different histories can apply the same batch and reach the same state.
A copied receipt from another history is refused without changing its custody records.

A valid reservation without a completion is a pending outcome, never permission to
dispatch again. An identical retry can reconstruct its missing completion even after
startup coverage or ordinary ingest advances the canonical head. The writer checks:

- The stored reservation binds the same key, normalized request, and exact batch bytes.
- The batch is canonical and its digest recomputes from its complete contents.
- The committed batch index binds the exact batch ID, sequence, and digest, with no
  unresolved append fence.
- For a historical target, retained epoch framing and checksums, exact target bytes,
  adjacent full anchors, and the v2 history chain verify through the current trusted
  canonical head.
- The projection uses the v2 history mode and its sequence, authority root, history root,
  and high-water batch digest match that current head.

The current-head fast path uses the writer's already verified head and performs no disk
reads. Historical proofs locate the target by probing epoch headers backward from the
known active epoch, then verify the canonical suffix through the current head. They do
not enumerate the archive or infer a receipt from current object generations. The default
budget is 16 distinct epochs, 32,768 records, and 128 MiB of cumulative reads. Header
probes and records before the target count toward these limits, and read sizes are
checked before record allocation. The native ledger and combiner APIs accept an explicit
`ReceiptProofBudget` and return consumed work in `ReceiptProofUsage`; the daemon retry
path uses the default budget. These limits also apply to completed retries: retaining
an old completion record does not bypass the need for retained canonical evidence within
the allowed work budget.

This observation runs under the existing commit mutex and performs no canonical append.
On a proven pending outcome, it restores the immutable completion, syncs the record and
its parent directory, and returns the original roots and sequence with `replayed: true`.
An identical competing completion or lost sync acknowledgement is settled by verifying
and syncing the existing exact record, never by overwriting it. The local generation
cache catches up monotonically so a newer generation cannot be replaced by the recovered
older one.

Missing or archived epochs, corrupt history, an exhausted proof budget, incomplete
projection publication, and unresolved append fences leave the request unresolved.
Budget exhaustion is an explicit error, not evidence that a batch was absent. No such
failure falls through to another dispatch. Legacy forwarded batches whose identities
were rewritten or coalesced are not inferred from similar object state. This also applies
to a legacy saved completion whose reserved request differs from the canonical coalesced
batch: the old receipt remains unresolved instead of bypassing historical verification.

Corrupt, truncated, oversized, mismatched, orphaned, and unsupported retry records fail
closed even when the caller presents a batch matching the current head. Historical
proofs establish canonical ledger/projection publication; they do not require historical
payload bytes to remain in the hot store after authorized retention, assert current media
retrievability, or prove a separate external device or notification effect.

There is currently no general operator command to repair missing history, raise the
daemon's proof budget, or reconcile unsupported legacy outcomes. Preserve the deployment
and original request for inspection. Deleting a reservation or inventing a replacement
key is not a supported recovery procedure: either can repeat an effect whose outcome is
still unknown.

## Storage scope

Each key has at most two bounded records (512 bytes each), distributed across 256 digest
shards. Directories are owner-only and records use owner-only creation modes on Unix.
Symlinks and broader permissions are refused. The bounded in-memory cache is only an
optimization; production eviction does not discard durable retry identity.

Records are retained without automatic garbage collection. Capacity planning must include
filesystem allocation overhead as well as record bytes. This path serves forwarded
mutations, not individual captured frames.

Treat the retry directory and its canonical deployment history as one recovery unit.
Existing backup formats are not extended by this change; a backup that omits these records
does not retain this retry guarantee. These receipt checks detect
conflicting canonical history but do not qualify arbitrary mixed-generation backups or
provide a complete backup profile for the daemon's epoch, pack, and retry stores.

Bounded camera/control intake now retains separate durable lifecycle bookkeeping; see
[durable control recovery](durable_control_recovery.md). Recovered commands remain inert,
and neither acceptance nor dispatch establishes semantic completion. Forwarding retry
keys do not add retry deduplication to bounded-control requests.
