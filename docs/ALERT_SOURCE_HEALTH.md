# Retained source-health findings at alert dispatch

Native alerts now recheck retained historical-health diagnostics at the shared effect boundary.
A previously corroborated event cannot dispatch using matching source support that a retained
diagnostic has identified as degraded or incompletely screened. The event and its original
evidence remain immutable; the check changes current eligibility to dispatch that event.

## Exact source matching

The guard starts with supporting event edges that name both a source capsule and its sensor
identity. It verifies retained diagnostic metadata through the historical-health owner and
joins the exact capsule to the diagnostic's source import, publication root and segment range.
Sensor names or overlapping timestamps alone never connect different recordings.

Privacy interpretation is historical. The guard finds the earliest appearance of each complete
supporting edge in the same event's verified revision lineage, then reconstructs that source's
privacy policy and generation at that point. Reviewing an event after a mask change cannot
silently reinterpret carried-forward observations or erase an earlier matching finding.

Native import publication membership, source-capsule identity, diagnostic provenance and current
deletion authority are checked. Partitioned file imports retain their exact part-root ordering
and publication membership. The guard reads metadata; it does not decode media, rerun inference
or replay the health trace.

## Eligibility and uncertainty

A matching diagnostic with findings or an incomplete scan refuses dispatch. Withholding covers
the diagnostic's finite requested scan, including the interval before a repetition threshold
was reached. It is not an estimate of a camera's physical failure start or recovery time.
A later complete screen without findings cannot erase an earlier matching adverse result.

No matching diagnostic means unknown screening coverage. A complete finite screen without
findings records only that historical heuristic result. Neither grants a present-health,
continuous-coverage, absence or delivery certificate.

Reference-policy observations without capsule coordinates retain their existing eligibility
checks and remain outside this native source-health qualification. This guard does not upgrade
those observations or replace the existing policy, corroboration and tamper checks.

Corrupt or unavailable required metadata, changed durable authority, invalid source bindings and
exhausted limits refuse the check. Deleted diagnostic metadata is not reopened. If deletion has
made its original scope unverifiable, the guard refuses native dispatch rather than silently
dropping a potentially adverse finding. Verified unrelated diagnostics do not withdraw support.

## Effect-state behavior

The shared gate runs during dispatch revalidation and before the webhook connects or writes.
It covers the durable reference dispatch API and the native webhook attempt used by both CLI
and agent-driven effects. The payload reader is supplied by the explicit authority owner.

A source-health refusal before commitment preserves the exact `Prepared` operation and its
pending obligation. A diagnostic is not evidence that the event revision was displaced, so the
guard does not manufacture the stale-event cancellation proof. The owner can inspect the retained
operation with `fss-alert status` or preview and explicitly approve `fss-alert cancel`.

After commitment, an interrupted webhook keeps the existing conservative effect lifecycle.
Recording a source-health interruption does not prove that no bytes reached the relay; uncertain
delivery remains indeterminate and cannot authorize a resend. Already committed or indeterminate
operations retain their historical receipts for inspection and reconciliation.

The CLI maps the dedicated `ReferenceError::AlertSourceHealth` refusal to the existing
`ERR-ALERT-NOT-ELIGIBLE-001` identity. Refreshing an approval alone cannot restore withdrawn
source support. Evidence review or an explicit cancellation is required as appropriate.

## Bounds and verification

One check admits at most 128 retained diagnostic identities, 64 unique supporting capsules,
2,048 metadata reads and 32 MiB of accepted metadata. A production callback bounds each payload
to 16 MiB before allocation. Independent finite ceilings cover event edges, history comparisons
and source matching; an exhausted check returns a refusal instead of omitting findings.

The durable ledger head is checked around the read. Every payload read verifies its requested
digest. Production reads also pass the calling context's cancellation checkpoint. These are
metadata bounds for this check; existing deployment-open, event, journal and network limits
remain independently applicable.

Focused owner regression command:

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference --lib alert::source_health::
```

Source review and pinned formatting checks do not establish runtime qualification. Test execution
and the repository's controlled native qualification remain separate proof obligations.
