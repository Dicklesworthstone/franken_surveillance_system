# Minimum-retention deadlines

Status: implemented reference behavior, not production-qualified. These operations extend
`fss-hold` and the existing local deletion guard; they do not introduce a parallel deletion
service. They are for owner-authorized, completed retained imports.

## Operator workflow

A minimum-retention deadline is an explicit absolute time in signed Unix nanoseconds. The
operator chooses it; there is no default duration, media-timestamp inference, automatic expiry,
or automatic deletion.

Preview a deadline hold:

```sh
fss-hold retain --root "$ROOT" --site "$SITE" \
  --hold-id minimum-retention --import-id "$IMPORT" \
  --until-ns "$DEADLINE_NS" --reason 'Preserve the retained evidence until owner review'
```

The preview changes no retention authority. Review its record, import, principal, deadline and
basis anchor, then repeat the exact command with `--approve "$APPROVAL"`, using the returned
`result.approval_digest`. Intervening authority changes require a new preview, except exact
retries of an already committed current request.

Evaluate readiness using an explicit owner-attested current-time interval:

```sh
fss-hold due --root "$ROOT" --site "$SITE" \
  --attested-now-ns "$EARLIEST_NOW_NS:$LATEST_NOW_NS"
```

The interval endpoints are inclusive and must be ordered. Both endpoints and the deadline are
signed 128-bit integer nanoseconds. JSON uses decimal strings so clients cannot silently round
them through binary64 numbers. This command reads the current hold records and writes no
retention transition. It keeps indefinite and terminal records visible too.

| Readiness | Meaning |
|---|---|
| `not_due` | Even the latest attested time is before the deadline. |
| `time_uncertain` | The interval straddles the deadline; expiry is refused. |
| `eligible_for_expiry` | The earliest attested time has reached the deadline; approval is still required. |
| `explicit_release_required` | An indefinite hold cannot expire by a clock assertion. |
| `terminal` | The identifier already has a committed release or expiry. |

An eligible hold still reports `deletion_blocking: true`. To preview expiry:

```sh
fss-hold expire --root "$ROOT" --site "$SITE" \
  --hold-id minimum-retention --import-id "$IMPORT" \
  --until-ns "$DEADLINE_NS" \
  --attested-now-ns "$EARLIEST_NOW_NS:$LATEST_NOW_NS" \
  --reason 'The owner-attested time has reached the retention deadline'
```

Review and repeat with the new expiry approval. The original deadline must match exactly; the
placement approval cannot approve expiry, and changing either time endpoint invalidates an
expiry approval. `release` cannot bypass a deadline hold. Neither expiry nor release deletes
bytes. Obtain a fresh `fss-event delete plan` and separate deletion approval afterward.

## Clock and authority boundary

The supplied current-time bounds are an **operator assertion, not an authenticated clock
measurement**. The system cannot detect a dishonest time assertion. It makes no clock accuracy,
statutory retention or legal-compliance claim. It never substitutes a camera timestamp,
receive timestamp, process clock, midpoint, or prediction for this explicit assertion.

Eligibility compares the earliest bound directly with the deadline, with no overflow-prone
subtraction. An uncertain interval never becomes permission. Deletion consults committed hold
state, not elapsed wall time: merely passing a deadline or running `due` changes nothing.

The existing retention prepare/commit capabilities, exact principal/site/anchor/request-bound
approvals, reserved authority family and object namespace, and exclusive deployment writer
lock remain the boundary. The local process supplies the CLI capabilities; `--principal` is
an audit label, not remote authentication. All other hold restrictions remain, including no
new mutation during incomplete deletion and no reuse of terminal identifiers.

A cancelled pre-append expiry leaves preservation active. A cancellation after authority append
must still report the committed transition. Retried exact committed requests do not append a
second record. Every expiry retains the predecessor deadline, both attested time bounds, actor,
reason, site and basis; the records remain authority history after later deletion.

## Shared evidence, limits and compatibility

Timed and indefinite holds share the same deletion-closure protection. An active timed hold
covers later-created and shared retained derivatives, including derivatives reached through
another import's deletion. Expiring one hold does not remove another deadline or indefinite
hold, nor an unrelated deletion blocker.

The existing limits remain: 32 active holds, 256 lifetime identifiers, 8 KiB per record. Merely
previewing expiry does not free an active slot; committing expiry does. Terminal audit records
consume lifetime capacity and are never silently evicted. This is not a scalable automatic ring
retention scheduler or a policy that automatically attaches to future imports.

Indefinite holds retain their exact version-1 encodings, approvals and object identities. Timed
holds use version 2 and `fss.evidence_hold.v2`, with distinct state tags. Version-1 hold-aware
readers reject these records rather than treat them as released. Binaries predating hold support
do not enforce any hold: upgrade every deletion writer together before relying on preservation.
No mixed-version downgrade safety is claimed. The existing `evidence_hold` family is unchanged.

Remote replicas, backups, event/subject scopes, automatic policy application, authenticated
clock acquisition, automatic expiry/deletion and agent/MCP exposure remain out of scope. Local
deletion still means filesystem unlinking, not cryptographic erasure.

## Reproducible checks

```sh
python3 crates/fss-reference/tests/fixtures/retention_deadline_model.py
cargo test -p fss-reference --lib deletion::holds
cargo test -p fss-reference --test evidence_hold_contract --test retention_deadline_contract
cargo test -p fss-cli --bin fss-hold
cargo test -p fss-cli --test evidence_hold_cli_contract --test retention_deadline_cli_contract
```

The independent Python oracle was executed: 139,425 interval cases and 1,024 lifecycle pairs,
plus timestamp extremes, passed. This is not execution of the Rust implementation. New Rust
regressions cover v1 byte preservation, v2 decoding, full-width time, approval binding, cold
reopen, shared/later derivatives, independent holds, cancellation, active-capacity accounting,
and actual binary retain/due/expire/deletion composition. Rust compilation, those native tests,
`rustfmt` and Clippy were not run in the authoring environment because no Rust toolchain was
available. No qualification status is promoted by the presence of these tests.
