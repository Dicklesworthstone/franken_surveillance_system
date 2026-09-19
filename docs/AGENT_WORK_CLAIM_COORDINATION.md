# Session-authorized work-claim coordination

`fss_reference::agent_session::work_claims` implements the single-owner reference lane for
FSS-226. It uses the existing `fss.agent_work_claim.v1` record; it does not add a public `fss/1`
verb, authenticate credentials, dispatch effects, or publish canonical ledger truth.

## Ownership and identity

The runtime retains one `ReferenceWorkClaimStore` alongside its `ReferenceSessionStore` and
supplies trusted `TimestampNs` values. Callers cannot supply a replacement record, owner, state,
or fence. Admission resolves the live session from the session owner and rechecks
`CAP-AGENT-WORK-CLAIM-001`, principal, mission, and privacy grants before exposing a record.
A claim ID is stable and never recycled. Its exact work scope is the tuple
`(principal, mission, case, privacy class, work root)`.

The work root must name an immutable scope already compiled and authorized by the owning
subsystem. The reference coordinator detects **exact** duplicate scopes, not overlap between
different descriptions. Different roots/classes are not proof of semantic disjointness. There is
no cross-principal delegation or hidden-domain scope discovery in this reference interface.

## Lifecycle

`acquire` reserves a scope once and returns `Claimed`. An exact live opening retry returns the
**current** revision without resetting progress, restoring grants, or renewing the lease.
Dependencies must already exist in the authorized mission. This prevents forward-reference
cycles; activation and completion additionally require completed dependencies at the exact
session anchor and ContractBasis.

`update` takes an exact `WorkClaimRevision`. The complete revision digest, owner session, live
lease, anchor, and ContractBasis are checked before any new revision is appended. Supported
changes are activation, blocked/progress publication, completion, release, and explicit renewal.
Progress/result inputs are content digests, not arbitrary JSON. Renewals strictly extend expiry,
remain inside both the configured duration and session expiry, and advance the fencing incarnation.
Completion records a work result, **not** a verified observation or external effect outcome.

Revisions are immutable and hash-linked. `inspect` and `inspect_revision` expose authorized audit
state; they never renew or reactivate it. `lease_covers(now)` is a time/lifecycle projection,
not permission to bypass fresh session admission and CAS. Expiry is exclusive: a writer at the
exact expiry instant is refused even before an explicit expiry revision is recorded.

## Handoff and orphan recovery

`recover` has three explicit modes:

- `Expire` records elapsed lease expiry while retaining the work reservation and progress.
- `Transfer` requires the current owner and a separately admitted recipient session of the same
  principal/mission/privacy domain. It advances the fence, never extends the remaining lease,
  preserves progress/dependencies, and returns to `Claimed` for explicit activation.
- `Reclaim` acquires released/expired work or a live lease whose known owner session is closed,
  expired, revoked, or no longer compatible with its basis. It advances the existing fence rather
  than allocating a replacement identity. A missing owner record alone cannot establish an orphan.

Reclaim and transfer do not silently rebase an old work description after world/contract drift.
Completed results never reopen. Competing recoveries require the same exact predecessor; only the
first successful append can win. A stale owner cannot write even after reading the new head.
Progress roots and dependency references survive recovery, including references to unresolved
work. No external obligation is transferred, erased, settled, or retried: its semantic owner must
perform its own separately authorized cancellation/reconciliation protocol.

## Bounds and qualification boundary

Claim count includes terminal reservations. Revision count includes retained history. Dependency
count and requested lease duration have explicit ceilings; zero is no capacity. Exhaustion refuses
new state instead of evicting fences/history. Clock watermarks do not rewind. Failed mutations
append no claim revision, although session admission may advance clocks or close expired sessions.

The tests include competing claim/transfer/reclaim schedules, stale writes, lost-opening-ACK
retries, exact expiry, clock regression, authority narrowing, basis drift, dependency readiness,
missing-owner refusal, capacity/overflow, progress preservation, and deterministic revision replay.
Run the focused suite with:

```sh
cargo test -p fss-reference agent_session::work_claims
```

This store is **in-memory reference behavior**, not crash recovery, Asupersync integration,
distributed locking, full HandoffCapsule publication, or GATE-115 qualification. Production owners
must persist revisions/fences and their session authority in the canonical publication path before
acknowledging them. Dropping the store and creating an empty one is not recovery. Rust build/tests,
rustfmt, and clippy were not executable in the editing environment; lexical and blob-identity
checks do not substitute for those gates.
