# Retained source-health findings at alert preparation and dispatch

Native alerts check retained historical-health diagnostics before proposing or preparing an
alert and recheck them at the shared effect boundary. A previously corroborated event cannot
dispatch using matching source support that a retained
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

## Preparation and operator-facing behavior

Both `fss-event alert` and the canonical `fss plan --intent alert` path check source-health
eligibility before returning a new proposal or preparing a durable intent. Exact plan approval
does not bypass this check: the owner rechecks immediately before durable preparation. The MCP
plan and commit tools delegate to the same agent command implementation and inherit these gates.

An existing `Prepared` operation also passes the health check before a fresh plan or dispatch
approval is presented. A retained adverse finding therefore blocks both a newly requested alert
and an already prepared alert that has not reached commitment. Refusal does not publish a usable
proposal, prepare another operation or connect to the relay.

Already committed, indeterminate or otherwise non-prepared operations retain their report-only
inspection path without a new health preflight. Reporting those durable receipts does not reuse
old authority or send the alert again. Preparation admission is not a lasting health grant; the
shared dispatch owner revalidates current source-health eligibility before commitment.

Agent refusals use `ERR-ALERT-NOT-ELIGIBLE-001`, with `never_unchanged` recovery and no safe retry.
The guidance calls for inspecting retained diagnostic evidence and investigating withdrawn
support. Control-plan preconditions describe revalidation of applicable exact-source diagnostics;
unknown coverage is not presented as a health certificate or an invented proof witness.

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

Focused native CLI integration command:

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --test agent_effect_cli_contract historical_health::
```

The native fixtures use retained JPEG decoding, tracking and two-camera corroboration. They
exercise frozen and incompletely screened support at preview, approved preparation and prepared
dispatch; retained operation inspection and explicit cancellation; unrelated imports and disjoint
scan ranges; later clear screens; corrupt or missing metadata; and carried-forward support after
a privacy-generation change. Eligible unrelated support reaches actual loopback relay acceptance.

Source review and pinned formatting checks do not establish runtime qualification. Test execution
and the repository's controlled native qualification remain separate proof obligations.
