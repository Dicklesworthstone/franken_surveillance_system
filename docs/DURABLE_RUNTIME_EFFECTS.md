# Durable runtime effects

`EffectCoordinator` can retain its complete preparation and transition history across process
restarts. The opt-in file backend is `fss_object::effect_journal::FileEffectJournal`; the runtime
depends only on the explicit `EffectJournalStore` capability. `EffectCoordinator::new()` keeps
its existing in-memory behavior.

This closes the gap between caller-handle recovery and process recovery. It does not replace
the deployment's existing domain journals or make a stored receipt proof of a provider outcome.

## Create a live owner

Create the parent directory under the application's existing filesystem authority. Pass an
absolute journal path, explicit storage/read ceilings, and the application's `SpoolIo` capability:

```rust,ignore
use fss_object::effect_journal::{EffectJournalLimits, FileEffectJournal};
use fss_runtime::effect::EffectCoordinator;

let store = FileEffectJournal::create(&journal_path, EffectJournalLimits::default(), io)?;
let mut effects = EffectCoordinator::with_journal(Box::new(store))?;
```

The existing prepare/approve/revalidate/commit API is unchanged. Every accepted preparation,
commit, observation, reconciliation and cancellation is appended before its live result is
published. A successful commit still returns exactly one non-cloneable `CommittedEffect`.
Preparation retries and exact terminal retries do not append duplicate records.

The canonical log retains the original intent, principal, capability pair, context authority,
region, resource, fence, obligation and terminal predicate. Each event binds the preceding and
resulting core journal roots. Replay applies the current core state-machine rules; it does not
use legacy transition compatibility or replace the original principal with a system principal.

Retain `effects.durable_pin()` and the preparation's `digest()` in an independent trusted
checkpoint. A pin contains a one-based sequence and the storage envelope's digest. A local
checksum chain cannot detect a rollback to a valid old prefix without such an independent pin.

## Recover after process loss or an ambiguous write

1. Stop using the old coordinator and release its storage owner. In particular, an append error
   must never be interpreted as permission to dispatch or retry the external operation.
2. Open the same physical journal with an independently retained minimum pin. Recovery verifies
   the complete contiguous chain, retaining any newer committed record whose acknowledgement
   was lost.
3. Give the recovered coordinator a freshly created, explicitly authorized region. For each
   operation, call `adopt_recovered` with its exact original preparation digest.
4. Reconcile the outcome from independently obtained provider evidence. Cancel a preparation
   that never committed, or record observation and then verify the same proof. An unknown
   outcome remains unresolved; an adapter acknowledgement alone is not success.

```rust,ignore
let store = FileEffectJournal::open(&journal_path, limits, io, saved_pin)?;
let mut recovered = EffectCoordinator::recover(Box::new(store), saved_pin)?;
let handle = recovered.adopt_recovered(
    &fresh_authority, &mut fresh_tree, &operation, original_preparation_digest, now,
)?;
// Use recovered.reconcile(...) with independently obtained outcome evidence.
```

A recovered coordinator is permanently **reconciliation-only**. It rejects `prepare` and
`commit`, including a recovered operation whose durable state is still `Prepared`. Recovery
never recreates a live lease, grant, process identity or dispatch permit. Fresh authority must
preserve the original principal, scope operation, region, anchor, generation, privacy and
retention; capabilities, budgets and deadlines may only narrow. The canonical obligation,
including an indeterminate reconciliation note, is attached to the fresh tree exactly as saved.

New external work needs a separately authorized live owner and a new operation identity after
the old operation's outcome is understood. Opening a different empty journal does not itself
authorize repetition of an existing external intent.

## Failures and bounds

An ambiguous append freezes the live coordinator. `persistence_needs_recovery()` reports this;
further mutations refuse until a fresh verified open. The last acknowledged pin can lag a
record that actually reached disk. The in-memory journal and region obligation remain unchanged
on storage failure, while cold replay decides which complete records exist.

Admission also checks space for a bounded cancellation or observation/verification path for
every outstanding operation. New preparations cannot consume another operation's remaining
terminal space. This is a storage-capacity preflight, not a guarantee against future I/O failure
or an unlimited allowance for intermediate/repeated observations. A capacity refusal before
writing leaves the owner usable for permitted reconciliation.

The default file limits are 4,096 records, 512 KiB per record, 64 MiB total retained payload
including storage envelopes and staging, and 256 MiB cumulative reads per open owner. Explicit
limits may be lower, subject to their validated hard ceilings. No operation or history record is
silently evicted. Incomplete staging is retained and charged but never replayed as committed.

The file backend uses an exclusive spool lock and binds records to the original absolute path,
directory and lock identities. Missing predecessors, forks, corrupt records, a replaced lock,
or copying/renaming the physical journal refuse. It requires filesystem identity support and
the caller's explicit I/O capability; it cannot protect against hostile replacement within one
system call. Relocating or restoring a journal is not implicitly trusted migration.

Every append rechecks all retained records, including predecessors, against their content
digests. These reads consume the same cumulative allowance as cold recovery; an unacknowledged
or over-budget append never silently resets that allowance.

## Contract coverage

`fss-runtime/tests/durable_effect_contract.rs` exercises semantic replay, preparation identity,
fresh authority narrowing, a lost commit acknowledgement, storage refusal before dispatch,
terminal-write ambiguity, exact retries and multi-operation capacity. The file-backend contract
suite adds real cold reopening, filesystem faults, namespace checks and a lost-acknowledgement
runtime recovery through `FileEffectJournal`.
