# Owned multipart upload and reconciliation

`fss-object::uploader::StagedUpload` prepares and retains the actual `ObjectStore` child authority,
its reserved budget, a pending drain obligation and its multipart session. Preparation performs no
provider I/O. The first `start` or `upload_chunks` call initiates a stable intent binding the operation,
exact resource, full canonical chunk plan and final manifest root.

Every transport call receives an admitted `TransportCx` for that same child. Admission verifies the
canonical region tree and operation, resource-scoped object/network grants, caller time, deadline,
cancellation and available budget. Payload and requests are charged before dispatch; adapters can
charge framing/response I/O through the same context. The parent retains the full reservation until
terminal child quiescence, after which only unused allowance is returned.

Provider ETags are opaque tokens. Each part receipt separately binds its exact index and SHA-256
content digest. A replay with changed bytes, plan, cost row, root or resource cannot silently replace
the original intent. Complete publication requires every part, in canonical order, and the exact
root selected at preparation.

## Lost acknowledgements remain owned

Initiation, part upload, completion and abort failures leave an explicit `Uncertain` phase. The
caller retains its session and upload owner; these methods borrow rather than consume them. New
effects are refused until a read-only, intent-bound reconciliation produces a conclusive observation.

| Provider observation | Permitted outcome |
|---|---|
| `Unknown` | Keep uncertainty, owner and pending obligation |
| `NotStarted` after uncertain initiation | Retry only the same stable intent |
| Exact `Active` inventory | Resume the same upload, retaining all acknowledged part identities |
| Exact `Completed` after uncertain completion | Return the bound completion receipt and settle the child |
| Exact `Aborted` after uncertain abort | Return the abort receipt and settle the child |

An eventually consistent listing, partial inventory, missing object or timeout does not establish a
terminal outcome. It must remain `Unknown`. A lost completion acknowledgement never authorizes a
blind abort. A cancellation request is explicitly nonterminal until staging is conclusively released.

New work preserves an operation for cleanup. Bounded abort and reconciliation remain possible after
cancellation or deadline expiry, subject to the same scoped grants and remaining allowance. Read-only
reconciliation may use the final request to establish the outcome of a prior effect. The published
minimum budget covers the payload and initiation, completion, reconciliation, abort and a final
reconciliation; real adapters must separately reserve wire framing and any additional retries.
Exhausted allowance leaves visible pending work and never fabricates a successful drain receipt.

Only a conclusive terminal receipt resolves the child's obligation, drains/finalizes that actual
child and refunds its exact parent's unused reservation. Dropping an unfinished handle leaves a
pending canonical child obligation that prevents a false parent shutdown claim.

## Explicit local settlement when the provider outcome stays unknown

An uncertain upload can outlive its available reconciliation allowance or an unreachable provider.
`StagedUpload::settle_indeterminate(tree, now, note, reference_digest)` records that unresolved
outcome and closes the local owner without inventing a provider result. The caller supplies a
bounded follow-up note and a nonzero SHA-256 reference to the independent reconciliation record
it will retain. The returned `IndeterminateUploadReceipt` binds those inputs to the exact original
intent, child region, obligation and uncertain operation.

This transition is available only after an uncertain dispatch. The canonical obligation stays
`Indeterminate`, and its reconciliation note remains attached to the closed child. The protocol
phase stays uncertain. Recording the settlement prevents every further provider call through this
handle, even if local finalization initially refuses. An exact retry finishes local cleanup and
returns the same receipt; a changed note or reference refuses. Successful closure refunds only
unused allowance, preserving charges for every attempted request and byte.

The receipt establishes local ownership settlement. It does not establish provider completion,
abort, rollback or the authenticity of the supplied follow-up reference. The caller must retain
the receipt and follow up through an independently authorized owner. In-memory tree retention
alone does not provide persistence across process loss; attach the durable journal below before
the first provider operation when restart recovery is required.

All staged operations check the original obligation and reconciliation state before source access
or transport dispatch. An altered obligation cannot silently become permission for another effect.
Owner lifecycle timestamps also bound execution. A transport checkpoint that observes a later time
retains that observation even when deadline or cancellation checks refuse, preventing a subsequent
call from moving execution back before that observed boundary.

## Durable restart recovery

`FileUploadJournal` retains canonical upload checkpoints in the existing explicitly authorized
local `StagingSpool`. `StagedUpload::attach_journal` attaches it to an already prepared owner,
before the first provider dispatch. Attachment writes the original intent, complete chunk plan,
manifest root, authority restrictions, original budget and deadline, and pending obligation.
The caller retains the returned `UploadJournalPin` independently of the journal, together with
the expected `UploadIntent`. Checkpoint bytes are inert data; they never contain a reusable
`AuthorityCx` or reconstruct permission to contact a provider.

Every provider dispatch first persists its uncertain phase, intended part checksum and consumed
request/payload allowance. `TransportCx::charge_io` also persists additional framing and response
charges before admitting that I/O. A valid provider acknowledgement is persisted before the owner
reports success. A crash after a provider effect but before its acknowledgement therefore recovers
an uncertain operation, and requires intent-bound reconciliation rather than blindly repeating it.
Even when provider reconciliation reports an empty active inventory, a part's first dispatched
checksum remains fixed.

The recovery sequence is explicit:

1. Open the same journal with `FileUploadJournal::open(root, limits, io, minimum_pin)`. The root
   must be an absolute path with a pre-existing parent. The journal holds an exclusive lock and
   validates every record's digest, predecessor, canonical encoding and semantic transition.
2. Read an inert `MultipartRecovery` from that journal and the independently retained minimum.
   The journal must contain that exact pin; a newer valid descendant may be selected. Missing
   records, a fork, changed intent, removed receipts, decreased spend or broadened authority refuse.
3. Call `StagedUpload::recover` with a fresh caller-owned parent/tree, transport, journal, decoded
   recovery, independently saved expected intent and explicit child authority. Its budget must
   equal the recorded remaining allowance, and its scope and deadline may only narrow.
4. Reconcile any uncertain provider operation before continuing. Exact completed or aborted
   observations allow local closure without repeating that effect. Original cancellation and
   grant revocations survive restart; expired work can only perform authorized cleanup and
   reconciliation. `cumulative_consumed()` includes earlier execution epochs.

The recovered child reserves only the original unspent allowance. Historical charges remain in
the checkpoint and cannot become spendable or refundable through the new parent. Terminal and
explicitly indeterminate ownership records reach the journal before canonical obligation
resolution, child closure or refund. If local finalization is blocked after that record is durable,
an exact retry can finish it without contacting the provider again.

Use `narrow_grants_durable` for a journaled owner's grant changes. The legacy in-memory
`narrow_grants` method refuses on durable owners. `checkpoint(tree, now)` records externally
observed cancellation or other narrower authority and returns a new pin for independent retention.
Cancellation changes made directly to an external runtime tree become restart evidence only when
checkpointed; callers must persist that boundary before treating the change as durably recorded.

Any ambiguous append failure blocks further provider effects and refunds through that owner.
The child, reservation and pending work remain retained. Drop the failed journal handle and cold
open against a previously saved pin to establish whether the append reached durable storage.
If initial attachment failed before producing any pin, no provider effect was dispatched; the
live owner still holds its reservation. Do not reinterpret that failure as successful cleanup.

The file backend defaults to 4,096 records, 512 KiB per checkpoint, 64 MiB of retained record and
orphan bytes, and 256 MiB of read work per handle. All are explicit bounds; exhaustion refuses
instead of pruning history or replenishing provider allowance. Recognized torn staging remnants
remain charged and are never admitted as checkpoints. Corrupt committed objects and foreign
entries refuse recovery. Symlink components and changed directory/lock identities refuse; current
file identity support is Unix, with unsupported platforms refusing explicitly. Advisory locking
coordinates cooperating local writers, rather than defending against an actor that can arbitrarily
rewrite the same filesystem.

A pin is a commitment to known history, not authentication. It detects a missing or replaced
prefix at or below that retained anchor, but cannot reveal a lost newer suffix that the caller
never independently pinned. Persist pins outside the upload journal according to the caller's
existing authority and custody policy.

## Scope and verification

This implements the injected multipart protocol, in-process ownership, and optional durable local
restart recovery for FSS-063/FSS-064/FSS-130. It does not implement a native network S3 transport,
byte encryption or independent archive retrievability verification. A real provider adapter
must enforce intent idempotency and checksum conditions, use the admitted context at its actual I/O
boundary, and return `Unknown` when its consistency guarantees cannot resolve an uncertain effect.

```sh
cargo test --locked --offline -p fss-object --test multipart_family --test uploader_family --test durable_upload_contract
```

The focused fault-injection targets cover lost acknowledgements at all four effect boundaries,
opaque ETags, altered bytes/root/plan, incomplete or forged reconciliation, actual child authority,
grant revocation, cancellation, deadlines, minimum cleanup allowance, framing I/O, exact refunds,
duplicate preparation, wrong trees and parent quiescence.

The additional unresolved-settlement and owner-integrity contracts cover exhausted recovery,
task-blocked local finalization, exact retained receipts and notes, altered obligations,
backdated preparation and cleanup, and refused transport/source clock boundaries. The pinned
nightly passed 50 focused tests and 337 tests across the full object crate (one existing test
requires an unprivileged process and remains explicitly ignored). The durable contract suite uses fresh file, transport and region
owners across abrupt after-effect exits, minimum-pin and semantic-rewind checks, filesystem fault
cuts, original cumulative budgets, authority restrictions and terminal/refund recovery.
