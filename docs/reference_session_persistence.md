# Reference session persistence

The reference session authority now has exact checkpoints and a synchronous journal-backed adapter. This implements restart persistence for session lifecycle state; it is not production authentication, a multi-writer database, or a replacement for the canonical evidence ledger.

## Entry points

```rust
use fss_reference::agent_session::checkpoint::journal::{
    DurableSessionLimits, DurableSessionStore,
};
```

Use `DurableSessionStore::create(path, limits)` only for an explicitly new, exclusively owned journal. It uses create-new semantics and will not overwrite or adopt an existing path. Retain `committed_root()` in independently trusted custody after every operation, including a session refusal: a refusal can persist a clock watermark or an expiry tombstone.

Use `DurableSessionStore::open_existing(path, expected_root, limits)` to recover the exact trusted history. Recovery refuses missing or empty files, symlinks, nonregular files, oversized histories, corrupt records, unsupported record kinds, torn tails, and a tip that differs from the supplied root. It never silently creates a replacement session store. `inspect` is read-only diagnostic verification; accepting whatever root it discovers is not rollback protection.

The adapter exposes the existing typed `open`, `session`, `bind`, `resolve`, `rotate_symbols`, `refresh`, `close`, `remaining_token_budget`, and `hydrate` operations. The runtime must authenticate principals, project authority, and supply trusted time exactly as for `ReferenceSessionStore`.

## What survives restart

Checkpoints preserve original opening digests, exact current session and contract basis, narrowed grants, original lease bounds, symbol-table generation and slots, exact descriptor and subject digests, cumulative token charges, acknowledged situation fingerprints, clock watermarks, and closed/expired identity tombstones. Recovery does not renew a lease, replenish a budget, widen authority, recycle an identity, or follow an implicit latest descriptor. Restored aliases still undergo current catalog, principal, capability, privacy, and availability checks.

A checkpoint's hard size ceiling is 16 MiB. The journal has a 64 MiB hard ceiling and defaults to 4,096 retained records. Runtime limits can be lower. Capacity exhaustion never compacts away tombstones or acknowledges an uncommitted mutation. This snapshot-per-change reference implementation favors inspectable semantics over production throughput.

For owners with their own protected storage, `ReferenceSessionStore::checkpoint` and `ReferenceSessionStore::restore_checkpoint` expose the same canonical format without performing I/O. The expected checkpoint digest must be pinned independently of the bytes being loaded. A digest stored next to untrusted bytes is not authentication.

## Failure and delivery rules

Session mutations are staged and appended through `fss_ledger::Journal` before the corresponding result is returned. Mutations caused by errors are included: observing expiry durably closes the session before returning unavailable. Same-state retries do not consume another journal record.

An ambiguous append fences the handle. No later session result is released until exact reconciliation. `reconcile_pending(IncompleteTailPolicy::Reject)` preserves a torn tail; explicit `Truncate` can remove only the incomplete attempted suffix after complete records have been validated. A committed checkpoint is installed once; a proven uncommitted candidate is discarded. Definite capacity or integrity failures also fence the handle and require explicit owner recovery/reopening, not an automatic retry loop.

Hydration stages the separately owned catalog and withholds the response until the quoted session token charge is committed. On append failure, the caller's catalog remains unchanged. A committed-but-unacknowledged hydration can conservatively retain its charge without delivering bytes. Reconciliation does not refund or automatically redeliver it; an explicit later delivery may incur another charge.

**Catalog cursor issuance and consumption are not made durable by this adapter.** Their replay tombstones must be independently retained or recovered. This implementation does not claim exactly-once delivery across a joint catalog/session crash. Persistent catalog custody and a coupled delivery receipt protocol remain separate work.

## Ownership and qualification boundary

The journal and its parent directory require exclusive trusted ownership. There is no cross-process writer lock or protection against a hostile process racing replacement of owned paths. Creation synchronizes the file and parent directory; platforms that cannot perform that synchronization fail rather than claiming durability. `verify_storage` checks the entire bounded history; normal operations use the existing journal's committed-tail check.

The implementation adds 12 checkpoint tests and 13 journal tests, including real hydration charge recovery and injected failures after body write, body synchronization, commit write, and commit synchronization. One journal test is Unix-specific. The fault tests retain uniquely named journals rather than deleting files.

Authoring validation: source and Git diff review only. Rust compilation, tests, rustfmt, clippy, and repository qualification were **NOT RUN** because no Rust toolchain was available in the authoring environment. The test additions are not passing-test receipts or a production-readiness claim.

Focused execution in a configured checkout:

```sh
cargo test -p fss-reference agent_session::checkpoint
```
