# Expiry cleanup of retained review media

The explicit `fss-event delete review-expiry-plan` and `review-expiry-commit`
commands remove expired local review derivatives while retaining the source
recordings. They use the immutable expiry in each review grant and an exact
owner-attested current-time interval. This closes the physical cleanup step
after a grant has expired; it does not install a scheduler or grant standing
deletion authority.

## Preview and approve one exact cleanup

Use the existing deployment, the sensor recorded in the review grant, and time
bounds in the same clock coordinates as the grant's issuance and expiry.
The command does not read the host wall clock or calibrate the assertion.

```bash
fss-event delete review-expiry-plan \
  --root "$FSS_ROOT" --site "$FSS_SITE" \
  --sensor-id "$SENSOR_ID" \
  --attested-now-ns "$NOW_EARLIEST_NS:$NOW_LATEST_NS" \
  --principal "$OWNER_PRINCIPAL"
```

The preview includes every inspected current review for that sensor, its source
import, immutable expiry, and disposition:

| Disposition | Meaning |
|---|---|
| `expired` | The grant expires at or before the earliest attested current time; its unblocked closure is selected. |
| `not_due` | The entire asserted interval precedes expiry. |
| `expiry_uncertain` | The asserted interval crosses expiry; the derivative remains retained. |
| `closure_blocked` | The grant is certainly expired, but its trial closure has a hold or another deletion blocker. |

Inspect the complete selected roots, blockers, bytes to unlink, shared bytes to
retain, ledger tombstones and root retractions. The nested deletion plan's
`imports` array is empty. A `nothing_eligible` or wholly `blocked` preview has no
deletion plan. Preview emits no partial result if inventory or work bounds are
exceeded and does not stage a plan or delete content.

As with the existing deletion commands, opening the deployment first runs its
normal recovery owner. The preview's `writes: none` refers to expiry/deletion
planning; recovery can reconcile pre-existing interrupted operations.

For a planned result, use the returned `approve_command`, or supply the same
request with the exact nested `plan_digest` and `approval_digest`:

```bash
fss-event delete review-expiry-commit \
  --root "$FSS_ROOT" --site "$FSS_SITE" \
  --sensor-id "$SENSOR_ID" \
  --attested-now-ns "$NOW_EARLIEST_NS:$NOW_LATEST_NS" \
  --principal "$OWNER_PRINCIPAL" \
  --plan "$DELETION_PLAN_DIGEST" --approve "$DELETION_APPROVAL_DIGEST"
```

Approval binds the whole canonical selection, exact time assertion, source
sensor, selected review roots, current authority and complete deletion closure.
A changed inventory, new hold, changed time assertion or changed principal
cannot reuse the preview. Re-preview after a refusal. The generated command is
omitted for a non-UTF-8 deployment path rather than replacing path bytes; the
explicit argument interface preserves the original operating-system path.

## What cleanup preserves

The closure begins at the selected review publication and issuance. It never
seeds the original import. The original recording, source metadata, source root
and other current review roots remain retained. Source holds protect their
review descendants; this command cannot release a hold. The existing closure
planner retains any media or receipt bytes still referenced by a retained
sibling review, even when the expired and current reviews have identical media.

The bounded canonical issuance record remains available as audit metadata after
deletion. `fss-export review-show` then returns `fss.review_media_deleted.v1`,
including the exact deletion plan and completion state, with media access denied.
Explicit grant revocation is reported separately. A deleted review cannot become
readable by presenting a time assertion from before expiry.

Deletion records become durable before root retractions and file unlinking.
Readers therefore refuse a tombstoned review throughout an interrupted cleanup.
An exact repeated commit resumes the retained plan after reopening; a completed
retry returns `already_complete` with the same completion digest. The request's
original time and selected scope must still match. Recovery does not need the
already removed derivative bytes and never invents a new approval.

## Bounds and remaining limits

One inventory examines at most 256 retained reviews across the deployment and
one million ledger entries; blocker findings and canonical selection size are
also bounded. Existing deletion object, byte, closure, hold and cancellation
limits still apply. Overflow refuses the entire assessment rather than silently
selecting a smaller inventory.

Cleanup uses the existing `filesystem_unlink` mechanism. It makes no
cryptographic-erasure claim and cannot recall previously delivered copies,
backups, remote replicas or recorder originals outside this deployment. Expiry
remains owner-attested; authentication of a remote recipient and an automated
retention worker remain outside this command.

Canonical plans and completions use the distinct v4 domains and scope tag 5.
Original import v1, sensor/event v2 and retention v3 encodings are unchanged.
Contract coverage lives in `review_media_contract` and
`review_expiry_cli_contract`; actual results are recorded in
`IMPLEMENTATION_STATUS.md`.
