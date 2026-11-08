# Operator alert lifecycle control

`fss-alert` exposes the durable operation/obligation identities independently of the original
`fss-event alert` dispatch arguments. It provides **read-only status and retained-wire
inspection**, **exact-approved cancellation before commitment**, and **owner-attested
reconciliation after dispatch**.
Reconciliation records an explicit operator assertion; independent provider verification remains
a separate capability.

## Runtime-owned dispatch

Both `fss-event alert` and the canonical `fss commit` path execute their single approved webhook
attempt through the same `fss-runtime` task owner. The owner retains the caller's principal,
original deadline and finite resource limits, then scopes the alert and network grants to the
exact approved operation, route and durable journal. The original effect authority recorded at
preparation is preserved; it is distinct from the approving CLI principal.

The owned path checks admission around source validation, clocks, waits, socket operations and
durable observation recording. Source-read allowances are finite and cumulative. Every admitted
socket call reserves its maximum byte allowance before I/O, including failed or blocked calls.
A timeout or cancellation cannot replenish the allowance or admit another network attempt.
Network work stops at the earlier of the approved dispatch deadline and the original authority
deadline, including the native connection timeout. A separate finite cleanup allowance is
reserved before commitment for recording the result, intersected with any earlier original
authority deadline; it never extends network authority or overrides revoked I/O authority.

Dispatch approval now uses `fss.cli_alert_dispatch_approval.v2` and binds the fixed
`local-root-last-exact-http-wire-v1` retention policy shown in the preview. Obtain the current
preview's approval digest; a v1 dispatch approval cannot silently authorize the added retained
bytes. The prepared route and event authority remain bound to their original operation.

The shared native path retires the socket, retains the exact finalized wire observation through
the existing root-last publisher and canonical reachability ledger, then records its digest and
outcome in the effect journal. Preflight reserves custody work and bounded history reads before
network commitment and refuses known insufficient configured object/root capacity. Source
validation preserves 256 KiB of custody byte headroom and its storage-read allowance. A later
storage failure leaves an explicit recovery requirement; it never authorizes a resend.

The native dispatched report includes `runtime` metadata: the task receipt, subtree quiescence
proof when available, consumed and remaining budgets, network admissions, source-read
reservations and attempts, and any local recording or retirement error. The canonical commit
envelope includes the dispatch's budget consumption and runtime accounting in its execution
boundary. Source byte and latency amounts are conservative reservations; dispatch storage
accounting includes source-read admissions, bounded history reads, the custody allowance and
prepaid journal transitions. It does not count every filesystem syscall. Deployment opening,
CPU, allocation peaks and journal serialization bytes remain outside these meters. These
fields do not claim whole-process resource accounting.

If the operation committed but custody, recording or runtime retirement fails, the command
preserves the original operation receipt and observed network evidence, reports recovery as required, and
exits nonzero. A cold retry reads the durable operation and never resends it. A missing receipt
or quiescence proof is explicit; neither is fabricated from an HTTP response. Runtime closure
only proves that the local attempt retired. Relay acceptance still leaves the independent
delivery obligation pending, and an unacknowledged send remains indeterminate.

A post-dispatch deployment refresh failure also returns the retained receipt and accounting,
using the explicitly marked pre-dispatch anchor and an overall indeterminate result that requires
recovery. A valid local runtime proof does not resolve that later snapshot failure. For native
dispatch, the result is written and flushed to stdout before optional report export; an export
collision or storage failure still exits nonzero, while preserving the available dispatch report.

The immediate `AlertDispatch.retained_evidence` value records the custody snapshot taken
**before** the following effect-result append. Its `journal_observation_recorded()` getter can
remain false even when that append succeeds. Code handling the completed dispatch should use
`AlertDispatch.recorded.result_digest` to check the later receipt against the retained digest,
or use the cold evidence command below. The immediate CLI report uses the later receipt for
its flag; cold inspection checks matching transitions in the verified historical journal.

```sh
cargo test -p fss-cli --lib alert_effect --locked --offline
cargo test -p fss-cli --test agent_effect_cli_contract --locked --offline
cargo test -p fss-cli --test corroborate_cli_contract --locked --offline
```

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

## Inspect the original retained webhook observation

```sh
fss-alert evidence --root /path/to/deployment --site site:home \
  --operation-id operation:example
```

The command requires one operation identity and emits metadata-only JSON. Its `wire_evidence`
contains the observation digest, manifest root, publication slot, original prepared-record
digest, commitment root, route digest, outcome, request hash, request/sent/response-prefix byte
counts, I/O count and exact admission times. Raw HTTP request/response bytes, including arbitrary
response headers or body text, are not printed. The optional `--principal` identifies the
authorized local inspection actor; it does not grant a new dispatch capability.

The reader does not open the deployment's mutation/recovery owner, create lock files, fsync,
rewrite journals, contact the relay, or change `Committed` to `Indeterminate`. It verifies the
complete bounded authority and effect histories and the selected canonical publication, exact
root record, manifest, observation envelope and verification holds. Every metadata/read call is
charged before I/O. Observed files and absences are rechecked before returning; this detects
observed changes without claiming an atomic filesystem snapshot.

The publication slot is bound to the site, operation and original preparation. Its identity
survives later owner reconciliation, even when the latest result digest now names an attestation.
`journal_observation_recorded: true` means a matching local observation transition exists in
verified history. `false` identifies a retained observation that has not been matched to that
transition, including a crash after root-last publication but before result recording. The
command suggests inspecting and reconciling the existing obligation; neither value authorizes
a resend or proves human delivery. An operator assertion that merely cites a digest cannot
manufacture a retained transport observation.

`wire_evidence: null` means this existing alert operation has no admitted published wire
observation. Staged bytes alone are insufficient. Use `fss-alert status` to inspect the durable
operation before acting. A published root missing its canonical reachability, missing or corrupt
custody, a retracted publication, pending root/tombstone markers, or an incomplete/corrupt
journal instead refuses the command with nonzero exit and no partial JSON. The command does not
repair evidence or silently report these failures as absence.

Cold inspection admits a 4096-byte layout, at most 64 MiB per journal, a 512-byte manifest and a
32 KiB encoded observation. The CLI also imposes finite cumulative read-byte and physical I/O
budgets. The retained response prefix itself is at most 16 KiB. Details of the dispatch policy,
authority boundaries and crash ordering are in [native HTTP alert dispatch](NATIVE_ALERT_WEBHOOK.md).

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

Native webhook preparation revalidates retained source authority before commitment. If that
validation fails, an automatic local cancellation needs a fresh admission from the same webhook
owner immediately before the journal transition. A cancelled, expired or exhausted source-read
owner cannot authorize that write merely because source validation failed. The operation remains
`prepared`, the effect journal is unchanged, and no socket is contacted. A still-authorized owner
retains the existing durable cancellation behavior for stale source evidence. Later recovery or
explicit cancellation must obtain its own live authority; failure never silently grants it.

The native webhook tests exercise both paths:

```sh
cargo test -p fss-reference --lib alert::webhook:: --locked --offline -- --test-threads=1
```

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
this path. It needs the appropriate reconciliation owner and an explicit delivery observation.
No `--force`, resend, fake failure, fake delivery or acknowledgement override exists here.
The status report preserves the recorded uncertainty and never interprets HTTP acceptance as
human delivery. This slice does not implement native independent-provider reconciliation.

## Bounds and validation

### Owner-attested reconciliation

Use the source-independent operation command when old event or media custody is unavailable:

```sh
fss-alert reconcile --root /path/to/deployment --site site:home \
  --operation-id operation:example --outcome delivered \
  --evidence sha256:OWNER_EVIDENCE_DIGEST --statement 'Recipient confirmed receipt'
```

Inspect its `plan.approve_command`, then execute that exact command to retain the attestation
and settle the existing obligation. The alternative outcome is `not_delivered`. The command
opens the existing deployment under its exclusive owner and verifies the physical journals and
original preparation. It does not orient through old events, read source media, open a session
or plan file, resolve a relay route, or dispatch again. Preview may perform the existing
conservative restart recovery; use `status` for strictly read-only inspection.

The report explicitly labels `provenance: "operator_asserted"`,
`provider_receipt_verified: false`, and `cited_evidence_custody: "not_inspected"`. The cited
evidence digest is the operator's reference, not a claim that the command inspected those bytes.
The newly retained attestation has its own verified record and root. A prepared, undispatched
operation refuses reconciliation. Exact cold retries return `already_reconciled` without
appending another effect transition; a different actor, statement, evidence or outcome cannot
reuse the old approval.

The canonical agent command remains available when its orientation inputs are intact and uses
the same reconciliation plan and approval identity:

```sh
fss commit --json --root /path/to/deployment \
  --reconcile delivered --operation operation:example \
  --evidence sha256:OWNER_EVIDENCE_DIGEST --statement 'Recipient confirmed receipt'
```

Inspect the preview and repeat the exact request with its `--approve` digest. This is an
explicit owner attestation with `operator_asserted`
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

The source-independent reconciliation cases additionally exercise both attested outcomes after
event-source loss/corruption, exact retries, changed attestations and actors, missing retained
proof, malformed or missing journals, prepared/unknown operations, capability denial, and
approval equivalence with the canonical library. Native execution of these added cases is
pending: the session's pinned compiler attempts were stopped by shared-memory exhaustion and
full storage before reaching the changed crate. Formatting and source review do not replace
those tests.

The implementation remains `implemented_not_qualified`; production qualification and native
provider reconciliation remain open.

### Durable wire retention and cold-inspection validation

The wire-retention change adds sixteen tests: eight reference recovery cases in
[`alert_recovery_tests/webhook_evidence.rs`](../crates/fss-reference/src/alert_recovery_tests/webhook_evidence.rs)
and eight CLI/cold-reader cases in
[`alert_lifecycle_cli/webhook_evidence.rs`](../crates/fss-cli/tests/alert_lifecycle_cli/webhook_evidence.rs).
They cover actual bounded loopback observations, root-last crash gaps, restart without resend,
exact custody retries, historical lookup after terminal owner reconciliation, metadata-only
inspection without writes, corrupt bytes and real publication tombstones, exact physical I/O
budget exhaustion, and input changes during the final read pass. Fixtures use local journals
and synthetic events; the CLI inspection fixture retires its attempt before any socket I/O.

```sh
cargo test -p fss-reference --lib alert_recovery_tests::webhook_evidence --locked --offline
cargo test -p fss-cli --test alert_lifecycle_cli webhook_evidence --locked --offline
```

These sixteen new cases were authored and source-reviewed, and formatting/diff checks passed.
They have **not run natively**: compilation was killed by `SIGKILL` while building `asupersync`,
before these suites could run. The separately reported 57 passing activation tests
validate different model work and do not establish webhook execution or qualification. The
retention and inspection workflow remains `implemented_not_qualified`; real provider delivery,
physical-camera operation and production qualification were not exercised by this change.
