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

An exact completed retry returns the original receipt, including after reopening storage.
A changed request using the same key returns `ERR-IDEMPOTENCY-CONFLICT-001`. A completion
ahead of the current canonical head, or inconsistent with its roots at the same sequence,
is refused. Older receipts assume the retained history and retry records belong to the
same deployment lineage; these checks do not certify arbitrary mixed backup generations.

A reservation without a valid completion returns
`ERR-OP-RECONCILIATION-REQUIRED-001`. This includes the cut where the ledger committed but
the process lost its completion receipt. The daemon does not automatically redispatch
that request or infer that it failed. Corrupt, truncated, oversized, mismatched, and
unsupported records also fail closed.

There is currently no operator command that reconciles a pending forwarded reservation.
Preserve the deployment and original request for inspection against canonical history.
Deleting the reservation or inventing a replacement key is not a supported recovery
procedure: either can repeat an effect whose outcome is still unknown.

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
does not retain this retry guarantee. Cross-generation restoration and pending-request
resolution remain separate work.

This change does not make queued camera/control commands durable. Their shutdown
disposition remains explicitly process-local, and accepting or dispatching a control
command does not establish semantic completion.
