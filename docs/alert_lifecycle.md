# Operator alert lifecycle control

`fss-alert` exposes the durable operation/obligation identities independently of the original
`fss-event alert` dispatch arguments. It provides **read-only status** and **exact-approved
cancellation before commitment**, not provider reconciliation, redelivery, or a delivery claim.

## Inspect before acting

```sh
fss-alert status --root /path/to/deployment --site site:home
fss-alert status --root /path/to/deployment --site site:home --operation-id operation:example
```

Status reads a bounded snapshot of `LAYOUT` and the authority and effect journals. It never
creates a deployment, rewrites history, contacts a relay or reclassifies a committed operation.
Results carry the authority anchor, committed effect-journal root,
operation and obligation states, request/precondition/receipt/proof digests, exact timestamps
as decimal strings, and explicit journal-tail warnings. The inventory is complete only for
the named committed snapshot with both journals present and both tails clean.
An absent journal or an uncommitted tail remains unknown, not proof that no dispatch occurred.
A requested operation absent from a complete committed inventory is refused. If either journal
is absent or has an uncommitted tail, a missing match instead reports the requested identity and
`operation_lookup: "unknown_beyond_committed_prefix"`; the command cannot prove its absence.

Lost or corrupt event, source-media or proof objects cannot hide the durable operation identity
needed for recovery. This inventory deliberately reports `source_custody: "not_inspected"` and
`terminal_proof_custody: "not_inspected"`. A recorded `verified`, `failed` or `cancelled` state is
the journal's state; status does not certify that its referenced proof remains available.

Both journals pass strict framing verification over the entire bounded input before their
existing typed-semantic replay checks. Corrupt complete records and foreign trailing bytes
refuse the command with no JSON prefix; a genuinely incomplete final record remains explicitly
outside the committed inventory. Every input file is read again before returning,
and a changed layout or history refuses the read. This does not acquire a deployment lock,
perform restart recovery, inspect source custody, or authorize a mutation.

## Cancel an unsent prepared alert

```sh
fss-alert cancel --root /path/to/deployment --site site:home --operation-id operation:example
```

The preview emits an `approval_digest` and a shell-quoted `approve_command`. Inspect the target
operation, obligation, prepared-record digest and principal, then execute that exact command:

```sh
fss-alert cancel --root /path/to/deployment --site site:home \
  --operation-id operation:example --approve sha256:EXACT_APPROVAL_FROM_PREVIEW
```

No current event, source media, model, channel or relay address is needed for cancellation.
The entire immutable prepared effect is recovered from its owning journal. A newer event
revision or unrelated later journal record does not prevent retiring the old, unsent alert.
Approval is bound to the full preparation, its recorded effect authority, the cancelling actor,
the site and both physical journal store pins. A byte-copied deployment cannot inherit it.
The library additionally requires explicit `CAP-AGENT-CANCEL-001` authority at every call.

`--principal` is a local audit identity, not remote authentication or a privilege-escalation
mechanism. The CLI assumes execution by the deployment's authorized local owner; its process
supplies the cancellation capability. The reference library fails closed for platforms without
physical store pins and for finite-deadline context delegation without an independent clock
owner. No new dispatch, provider, or camera-control capability is granted.

The locked cancellation path uses `ReferenceDeployment::open`, which may perform the existing
restart recovery: a committed operation whose dispatch died with another process becomes
explicitly indeterminate. The CLI reports this possibility. The library preview itself writes
nothing, but the command does not claim that opening the deployment is always mutation-free.
Use `status` for a strictly read-only inspection.

## Retained cause, terminal proof, and exact retry

A cancellation request is published root-last with ledgered custody before the terminal
transition. Its evidence binds the site, cancelling principal and **whole** prepared-record
digest. The existing v3 journal then atomically records the cancellation and discharges its
obligation with the bound `EffectCancellationRecord` proof. The situation guard recognizes this
proof only alongside the exact ledger-published request and a ledger-grounded alert plan.

Stopping after request publication leaves the operation prepared, not falsely cancelled. An
exact retry resumes without publishing a second request. Stopping after the terminal journal
commit cannot erase success. A cold exact retry returns `already_cancelled` and appends nothing;
a different actor or a different cancellation cause cannot claim that result as its own retry.
The retained request is not itself a terminal outcome, nor is a model or human assertion proof
of external delivery. The normal canonical alert-outcome publication remains a distinct owner.

Once committed, accepted, observed or indeterminate, an alert is **not cancellable** through
this path. It needs independent provider evidence and the appropriate reconciliation owner.
No `--force`, resend, fake failure, fake delivery or acknowledgement override exists here.
The status report preserves the recorded uncertainty and never interprets HTTP acceptance as
human delivery. This slice does not implement native independent-provider reconciliation.

## Bounds and validation

### Owner-attested reconciliation

The canonical operation-addressed reconciliation path is available separately:

```sh
fss commit --json --root /path/to/deployment \
  --reconcile delivered --operation operation:example \
  --evidence sha256:OWNER_EVIDENCE_DIGEST --statement 'Recipient confirmed receipt'
```

Inspect the preview and repeat the exact request with its `--approve` digest. The alternative
outcome is `not_delivered`. This is an explicit owner attestation with `operator_asserted`
provenance; it does not contact the provider, resend the alert, or turn relay acceptance into
independent delivery evidence.

Before appending a reconciliation transition, and before reporting an exact prior reconciliation
as successful, the owner re-reads and verifies the canonical attestation record and its one-child
manifest against the exact ledgered publication. Reads use the expected canonical byte lengths
as allocation ceilings. A missing, corrupt or oversized record or manifest refuses with
`ERR-ALERT-AUTHORITY-001`, even when the effect journal already names its digest. The refusal
does not append an effect transition, republish the request, or erase the existing terminal state.
Repairing the retained bytes permits the original approved retry to resume.

The reconciliation integration contract covers both outcomes, cold exact retry, cancellation
after request publication, interrupted `observed` delivery, and lost/corrupt custody before or
after terminal commitment:

```sh
cargo test -p fss-reference --test alert_reconciliation_contract --locked --offline
```

### Cancellation and status bounds

Requests admit at most 4096 operations/obligations and at most 64 MiB per journal. Status admits
a 4096-byte layout and checks each file's metadata before allocating its contents; a bounded
read also catches growth beyond the limit. A complete JSON report is bounded by 8 MiB.
Size/refusal errors produce no JSON prefix. Low-level deployment open,
publication and journal owners retain their own existing allocation, I/O and recovery contracts;
the new counters are not a replacement whole-system storage budget.

```sh
cargo test -p fss-reference --lib alert_control
cargo test -p fss-reference --test alert_operation_status_contract --locked --offline
cargo test -p fss-cli --test alert_lifecycle_cli --locked --offline
```

Nine library tests cover exact approval, state races, actor and store-pin substitution, cold
retry, interrupted publication, cancellation cut points, and the real reference situation
guard. Four operation-inventory integration tests cover exact journal-root compatibility,
read-only committed-state inspection, changed inputs, pre-allocation size bounds and absent or
torn journals. Nine real-process tests exercise status, preview/commit/retry, committed-state
refusal, lost/corrupt event objects, missing cancellation evidence, journal corruption, absent
journals, uncommitted-tail warnings, malformed requests and actor mismatch. Fixtures use
durable local journals and synthetic reference events; no live provider or device is contacted.

The implementation remains `implemented_not_qualified`; production qualification and native
provider reconciliation remain open.
