# Indefinite evidence holds

Status: implemented reference semantics, not production-qualified. Native regression commands
are listed below; dated execution results are in the [implementation status](../IMPLEMENTATION_STATUS.md). No legal
compliance, storage durability beyond the existing journal, or evidence-quality claim is made.

## Operator workflow

`fss-hold` operates on an existing owner-authorized local deployment. Place a hold on an exact
completed import, not a filename, sensor alias, person, or event:

```sh
fss-hold place --root "$ROOT" --site "$SITE" \
  --hold-id incident-2026-09 --import-id "$IMPORT" \
  --reason 'Preserve evidence for owner review'
```

This prints a proposed record and `result.approval_digest`, without changing retention. Review
its import, reason, principal, site and basis. Repeat the same command with
`--approve "$APPROVAL"` to commit that exact record. No default approval exists.

```sh
fss-hold list --root "$ROOT" --site "$SITE"
fss-event delete plan --root "$ROOT" --site "$SITE" --import-id "$IMPORT"
```

Deletion planning includes an `evidence_hold` blocker. Commit revalidation independently
rebuilds the same hold state and closure. A deletion approval obtained before hold placement
becomes stale. Passing a new approval for a blocked plan does not override the hold.

Release is a separate operation and approval:

```sh
fss-hold release --root "$ROOT" --site "$SITE" \
  --hold-id incident-2026-09 --import-id "$IMPORT" \
  --reason 'Owner review complete'
```

Review and repeat with the newly proposed release approval. Release does not delete anything;
it only removes this hold's blocker. Other holds and open-effect blockers still apply. Prepare
a fresh deletion plan separately. A released identifier is terminal and cannot be reused.

## Read current holds during ingest

`fss-hold list` and [`fss-hold due`](RETENTION_DEADLINES.md) inspect existing retained authority
while an ingest process holds the deployment writer lock. They do not initialize a missing
deployment, acquire that lock, repair journals, recover unfinished work, or read original media.
Both commands preserve the existing `fss.evidence_hold_cli.v1` output and include terminal
records. The native history checks still verify placement, predecessor and release/expiry
records; missing custody cannot become an empty list or an implied release.

Each CLI invocation has fixed inspection ceilings:

| Allowance | Default and maximum |
|---|---|
| Aggregate payload bytes | 268,435,456 bytes (256 MiB) |
| Aggregate payload read attempts | 65,536 |
| Cooperative elapsed-time deadline | 60 seconds |

The same allowance covers opening metadata, reconstructing records and final verification.
Read attempts count bounded payload reads, including metadata and final rereads, rather than
filesystem syscalls. No result JSON is released until metadata, record custody and both journal
heads pass the final checks. Cancellation, exhaustion, damaged history or an intervening
authority change refuses the complete result; retry against a stable head after resolving the
cause. These commands have no CLI flags to enlarge the inspection ceilings.

Inspection uses `CAP-RETENTION-PREPARE-001` and the `ADP-REPLAY-001` read context. It requires
matching principal, site and root authority, without granting retention commit or media access.
Library callers use `deletion::inspection::inspect_holds` with a read-only `ReplayCx`; they may
narrow `inspection_limits()` within their supplied authority budget. The result includes the
verified anchor, native records and aggregate read usage. A successful inspection verifies the
retention metadata; it does not certify that the referenced recording remains intact.

## Preservation and authority

A hold covers the named import's current retained derivative closure, recalculated at deletion
time. A shared derivative can block deletion of a different import. Derivatives created after
placement are covered too. The existing deterministic closure walk supplies object, root and
ledger-object relationships; uncertainty in retained hold custody refuses deletion rather than
being interpreted as no hold.

The lifecycle has two generations: `held` then `released`. There is no automatic expiry and no
wall-clock inference. Placement and release records are permanent authority history; deleting
an import after release does not erase the retention audit trail. Current records, including
releases, are listed in stable hold-ID order.

Preparation requires `CAP-RETENTION-PREPARE-001`; committing an approved change additionally
requires `CAP-RETENTION-COMMIT-001`, a matching site universe and I/O root, and an exact
principal/anchor/request-bound approval. Generic authority append rejects both the
`evidence_hold` family and its reserved
object namespace. History reads verify each canonical record, generation, predecessor, batch,
children and current ledger object. This is not an authentication server: the local CLI runs
with the invoking process's filesystem access, and `--principal` is an audit label, not a way
to gain remote access. Do not place secrets, unnecessary personal details, or media in a reason.

The deployment's exclusive writer lock serializes hold changes with deletion. Once a deletion record
is committed and incomplete, new hold changes are refused; the system cannot promise to
preserve bytes whose removal has already begun. Resume or reconcile that deletion first.
Cancellation before authority append leaves no effective hold or release. A post-commit
cancellation still reports the committed transition. Exact retries of the current request use
its original approval and never append twice.

## Bounds, compatibility and remaining gaps

There are at most 256 lifetime hold identifiers, 32 simultaneous active holds, and 8 KiB per
record. Exhaustion refuses new work; it never evicts or releases a hold. Hold IDs use 1–64 ASCII
letters, digits, underscores or hyphens; reasons are at most 512 UTF-8 bytes without controls.
The reference deletion cost adds a bounded hold-history scan and up to 32 held-closure walks
per candidate import. This has not been performance-qualified.

No-hold deletion plans retain their existing encoding. All deletion writers must be upgraded
together before holds are relied upon. Older binaries do not enforce this new authority
family; mixed-version downgrade, direct filesystem tampering and malicious raw journal edits
are outside this implementation's boundary. The existing plan still reports local unlinking,
not cryptographic erasure.

Remote replicas, backups, retention schedules, event/subject scopes, and universal agent/MCP
hold operations remain open. This command does not certify that source evidence is intact,
that replicas are protected, or that a statutory preservation obligation has been satisfied.
The contract and error identities are in `registries/evidence_holds.json`.

## Native regression commands

```sh
cargo test -p fss-reference --lib deletion::holds
cargo test -p fss-reference --test evidence_hold_contract
cargo test -p fss-reference --test retention_cohort_contract inspection::
cargo test -p fss-reference --lib deletion::inspection::tests
cargo test -p fss-cli --bin fss-hold
cargo test -p fss-cli --test evidence_hold_cli_contract
```

The integration cases exercise real generated JPEG imports, authority journals, writer
reservations, shared derivatives, cold reopen, deletion, stale approvals, independent releases,
and cancellation/retry cut points. Immutable inspection cases additionally cover an active
writer, absent source media, damaged history, shared final-read budgets and changes after
reconstruction. Their presence is not a claim that these commands have run.
