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

An exact completed retry returns the original receipt, including after reopening storage.
A changed request using the same key returns `ERR-IDEMPOTENCY-CONFLICT-001`. A completion
ahead of the current canonical head, or inconsistent with its roots at the same sequence,
is refused. Older receipts assume the retained history and retry records belong to the
same deployment lineage; these checks do not certify arbitrary mixed backup generations.

A valid reservation without a completion is a pending outcome, never permission to
dispatch again. An identical retry can reconstruct its missing completion only when
the original batch is still the exact, fully published canonical head. The writer checks:

- The stored reservation binds the same key, normalized request, and exact batch bytes.
- The batch is canonical and its digest recomputes from its complete contents.
- The full successor anchor and committed batch ID/sequence/digest match the verified
  ledger head, with no unresolved append fence.
- The projection sequence, authority root, history root, and high-water batch digest
  match that same commit.

This bounded observation runs under the existing commit mutex and performs no historical
scan or canonical append. It restores the immutable completion, syncs the record and its
parent directory, and returns the original roots and sequence with `replayed: true`.
An identical competing completion or lost sync acknowledgement is settled by verifying
and syncing the existing exact record, never by overwriting it. The local generation
cache catches up monotonically so a newer generation cannot be replaced by the recovered
older one.

If unrelated writes have advanced the canonical head, the pending request remains
`ERR-OP-RECONCILIATION-REQUIRED-001`. Startup coverage or ingest can cause that advance;
this mechanism is therefore exact-current-head receipt recovery, not general historical
pending-request reconciliation. Legacy forwarded batches whose identities were rewritten
or coalesced are not inferred from similar object state. A projection gap or append fence
must be resolved separately before this path can prove completion.

Corrupt, truncated, oversized, mismatched, orphaned, and unsupported records fail closed
even when the caller presents a batch matching the current head. No recovery failure falls
through to another dispatch. These receipts establish canonical ledger/projection
publication; they are not evidence of a separate external device or notification effect.

There is currently no general operator command that reconciles a pending forwarded
reservation outside this exact-head case. Preserve the deployment and original request
for inspection against canonical history. Deleting the reservation or inventing a
replacement key is not a supported recovery procedure: either can repeat an effect
whose outcome is still unknown.

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
does not retain this retry guarantee. Cross-generation restoration and general historical
pending-request resolution remain separate work.

This change does not make queued camera/control commands durable. Their shutdown
disposition remains explicitly process-local, and accepting or dispatching a control
command does not establish semantic completion.
