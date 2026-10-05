# Operator alert lifecycle control

`fss-alert` exposes the durable operation/obligation identities independently of the original
`fss-event alert` dispatch arguments. It provides **read-only status** and **exact-approved
cancellation before commitment**, not provider reconciliation, redelivery, or a delivery claim.

## Inspect before acting

```sh
fss-alert status --root /path/to/deployment --site site:home
fss-alert status --root /path/to/deployment --site site:home --operation-id operation:example
```

Status uses the existing read-only deployment snapshot reader, not the locked open/recovery
path. It never creates a deployment, rewrites history, contacts a relay or reclassifies a
committed operation. Results carry the authority anchor, committed effect-journal root,
operation and obligation states, request/precondition/receipt/proof digests, exact timestamps
as decimal strings, and explicit journal-tail warnings. The inventory is complete only for
the named committed snapshot with both journal tails clean and the effect journal present.
An absent journal or an uncommitted tail remains unknown, not proof that no dispatch occurred.
An unknown requested operation is refused rather than reported as a successful cancellation.

This reuses the existing snapshot reader's custody and size checks. Corrupt deployment evidence
can refuse status; the command does not silently discard those errors to return a partial list.

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

Requests admit at most 4096 operations/obligations and at most 64 MiB per journal at CLI
preflight; status retains the snapshot reader's existing limits too. A complete JSON report is
bounded by 8 MiB. Size/refusal errors produce no JSON prefix. Low-level deployment open,
publication and journal owners retain their own existing allocation, I/O and recovery contracts;
the new counters are not a replacement whole-system storage budget.

```sh
cargo test -p fss-reference --lib alert_control
cargo test -p fss-cli --test alert_lifecycle_cli
```

Nine library tests cover exact approval, state races, actor and store-pin substitution, cold
retry, interrupted publication, cancellation cut points, and the real reference situation
guard. Six real-process tests exercise status, preview/commit/retry, committed-state refusal,
uncommitted-tail warnings, malformed requests and actor mismatch. Fixtures use durable local
journals and synthetic reference events; no live provider or device is contacted.

Native compilation, Rust test execution and rustfmt were unavailable in the editing environment
when these changes were authored. These executable tests are not retained passing receipts.
The implementation remains `implemented_not_qualified`; production qualification and native
provider reconciliation remain open.
