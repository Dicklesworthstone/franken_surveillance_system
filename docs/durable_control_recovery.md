# Durable daemon control intake and recovery

The production daemon retains bounded control intake under `control-history/` and
its separately checked local checkpoints under `control-history-pins/` in the
deployment root. It verifies this custody before connecting camera drivers.
These records are operation bookkeeping; the evidence ledger remains the
canonical world history.

An IPC `Queued` acknowledgement follows durable retention of the exact operation,
target, approval digest, principal, contract basis, granted capability names, and
request/connection correlations. Operation IDs bind the deployment scope and
original journal sequence, so a new daemon process cannot reuse an old ID.
Correlation IDs are diagnostic facts, **not idempotency keys**. Reissuing an IPC
request creates a new operation; this feature does not authorize blind retries
after a lost acknowledgement.

## Execution boundaries

| Retained progress | What it establishes |
|---|---|
| `never_started` | Intake was retained, but no dispatch fence was retained. |
| `dispatch_started` | A durable fence preceded the subsystem call; a crash or failure can leave its outcome indeterminate. |
| `subsystem_returned` | The subsystem returned successfully. Its own completion and verification contracts still apply. |
| `cancelled_before_execution` | The owner cancelled the command before invoking its subsystem. |

The supervisor writes a dispatch fence before transferring a camera command to
its executor. Scrub commands remain unstarted while waiting for maintenance;
their dispatch fences are retained immediately before that phase. A failed or
ambiguous journal append closes admission and requires cold recovery. A command
whose subsystem may have changed state is never automatically retried.

Graceful shutdown persists cancellation of queued and deferred unstarted work.
The existing shutdown disposition remains a separately digested receipt with its
original encoding. It does not replace the journal or claim that a subsystem
return proves completion of a snapshot, scrub, reconnect, or device effect.

A crash or allocation failure after durable intake but before queue insertion or
acknowledgement retains the original request as `never_started`. Recovery does
not discard that request or infer that the client received its acknowledgement.

## Restart and inspection

Cold startup verifies complete journal and local checkpoint history. Recovered
commands remain inert: no queue, grant, capability, or dispatch permit is restored.
New fully approved requests can enter the current process with new stable IDs.

While the daemon is stopped, inspect the newest 1,024 retained commands with:

~~~sh
fss-daemon control-history --root /absolute/deployment --site-id site-id --json
~~~

The report names the exact verified journal head, total and omitted entry counts,
original request bindings, and each retained execution boundary. It never starts
camera drivers or appends a control record. The existing journal owners do take
exclusive locks and sync recovered filesystem names, so this is offline recovery
inspection rather than a live status query. The in-process
`DaemonSupervisor::control_history` getter exposes the same bounded report without
transferring command ownership.

Missing or mismatched pins, partial bootstrap, corrupt history, illegal state
transitions, a different deployment/contract scope, and a journal ahead of its
retained checkpoint all fail closed. Preserve both directories for investigation;
deleting a checkpoint or creating a replacement history is not reconciliation.
This slice provides no automatic redispatch or general operator repair command.

## Custody and bounds

The backend reuses `FileEffectJournal`, `FileTrustedRootPinRetainer`, and
`PinRetainedEffectJournal` with explicit filesystem capabilities and bounded
canonical records. Intake preflights room for all remaining execution boundaries
of live requests. History is retained without automatic pruning, bounded to
16,384 journal records, 16 KiB per record, 256 MiB of payload custody, and a 16 GiB
cumulative read allowance per opened owner. Each command normally consumes an
intake and at most two transition records; bootstrap and checkpoint history also
consume capacity. Exhaustion refuses new intake while preserving existing work.

Replay uses a bounded operation index, requiring O(records log admissions) state
validation work after custody verification. A report copies at most 1,024 entries
and states how many older entries it omitted. An output bound never permits
verification of only a suffix of the retained history.

The local pin directory is an explicit trusted-storage boundary. Keeping it beside
the journal supports ordinary process-crash recovery and detects disagreement
between the two histories. It cannot establish that both were not rolled back
together to the same valid earlier generation. Independently retained external
pins are needed for a stronger rollback guarantee. Existing backup formats are
not extended: retain both directories with their original deployment lineage.

The public `ControlPlaneShared::new` constructor remains process-local for embedded
callers and fixtures. Production `DaemonSupervisor` uses durable custody by
default. Physical-device qualification remains separate.
