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

## Durable follow delivery

The deployment adapter now supports explicit session-owned `session.follow` delivery. This is a bounded synchronous local reference profile: each invocation returns at most one page of one adjacent retained ledger or effect-journal transition. The caller decides when to invoke it again. It does not start a background subscription task or renew a session lease.

Open a mission-scoped session with `fss session open`, retain its session identity and a verified deployment anchor, and register a named subscription:

```sh
fss session follow --json --root /srv/fss \
  --since '<original-anchor>' --session '<session-id>' \
  --subscription overnight --view pulse --max-entries 64
```

The returned envelope and MeaningfulDelta share a `continuation:follow-ack:sha256:...` continuation. Its `follow-delivery:sha256:...` proof pointer names the exact retained receipt. After processing that complete page, acknowledge its digest explicitly:

```sh
fss session follow --json --root /srv/fss \
  --since '<original-anchor>' --session '<session-id>' \
  --subscription overnight --view pulse --max-entries 64 \
  --acknowledge 'sha256:<exact-delivery-receipt>'
```

Keep the original `--since`, session, subscription, view and page size unchanged. The durable owner retains the native item cursor internally; clients cannot combine this profile with `--continuation` or `--wait-ms`. MCP `session_follow` exposes the same opt-in `session`, `subscription` and `acknowledge` fields and uses the same parser, native owner and response envelope. Ordinary follow and bounded waits retain their existing read-only behavior.

### Delivery and recovery semantics

A subscription has exactly one pending page, retained in the existing session journal before response release. Rendering a page is never an acknowledgement. Repeating a request without a new ACK reconstructs that page and returns the same receipt, including after process restart or a switch between CLI and local MCP. If a response to an ACK is lost, repeating the latest committed ACK returns the successor without consuming it again. A wrong, older or differently scoped receipt refuses.

Acknowledging an item page advances only its page cursor. The acknowledged deployment anchor advances only after the final page of that adjacent transition. The replay horizon stays fixed while its pages are outstanding; later appends cannot replace that interval. Ledger and effect records have separate retained orders. When both journals advance in a requested interval, this profile returns an explicit resnapshot refusal because no total interleaving is retained. It never sorts timestamps to invent one.

Before accepting a new ACK, the owner reconstructs the pending page and revalidates source history, authority generations and semantic scope. Before returning a successor, its basis must match the persisted acknowledged situation fingerprint. Changed custody, deletion, privacy or unsupported semantic state therefore cannot silently rewrite an acknowledged observation. An ACK may already be durable when a later publication or response release fails; the typed failure includes any definitely committed receipt and describes possible prior journal writes. Failure does not roll back a committed ACK.

Registration, delivery and ACK are additive versioned records in the existing journal. They are replayed under the session authority and retained byte-for-byte by the existing deployment backup path. Old readers reject the new record kind explicitly. The bounded inventory permits at most 256 retained subscriptions total and 16 per session, including closed-session history; one command is limited to 64 KiB. Capacity exhaustion cannot evict an outstanding receipt or silently recycle an identity.

### Scope and remaining gaps

This first durable profile supports deployment/effect continuity for monitoring sessions. It conservatively refuses retained case or work-claim history, unsupported agent publications and noninitial workspace revisions. It also pins the retained semantic journal and publication set, so a protected facet created and closed between polls cannot disappear silently. A resnapshot refusal requires an explicit fresh orientation and admissible session/subscription scope; continuing the old cursor across the gap is not permitted. Complete mission-history replay remains unimplemented.

Each invocation permits at most two native comparisons, each with at most two bounded snapshots. Native response counters describe the returned comparison; journal verification/publication, history revalidation and reconstruction of a previously acknowledged page are additional bounded work and are not represented as free. Full runtime cost accounting, an Asupersync subscription owner, authenticated remote transport and in-flight MCP cancellation remain separate work.

Focused contracts are `follow_replay_contract`, `follow_session_delivery_contract`, the `agent_session::checkpoint::journal::follow::tests` fault suite, and CLI `follow_subscription_cli_contract`. They exercise intermediate effect uncertainty, pagination, exact cold replay, lost ACKs, journal append crash cuts, semantic drift, cancellation and changed acknowledged custody. Their existence is not a release-qualification claim.

## Ownership and qualification boundary

The journal and its parent directory require exclusive trusted ownership. There is no cross-process writer lock or protection against a hostile process racing replacement of owned paths. Creation synchronizes the file and parent directory; platforms that cannot perform that synchronization fail rather than claiming durability. `verify_storage` checks the entire bounded history; normal operations use the existing journal's committed-tail check.

The implementation adds 12 checkpoint tests and 13 journal tests, including real hydration charge recovery and injected failures after body write, body synchronization, commit write, and commit synchronization. One journal test is Unix-specific. The fault tests retain uniquely named journals rather than deleting files.

Authoring validation: source and Git diff review only. Rust compilation, tests, rustfmt, clippy, and repository qualification were **NOT RUN** because no Rust toolchain was available in the authoring environment. The test additions are not passing-test receipts or a production-readiness claim.

Focused execution in a configured checkout:

```sh
cargo test -p fss-reference agent_session::checkpoint
```
