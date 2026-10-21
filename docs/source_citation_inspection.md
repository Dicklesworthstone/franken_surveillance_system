# Inspect a committed source citation without reacquiring evidence

A lost citation acknowledgement is not a reason to read source again. The acquisition charge and
case link are separate commits: retrying acquisition can spend another source budget, while source
may have legitimately expired or been deleted since the original citation. The reference owner now
provides exact historical receipt inspection rather than guessing from the case's latest evidence set.

## Entry points and exact selection

Both `DurableSessionStore` and `DurableDisclosureStore` expose `inspect_source_citation` with a live
principal/session, the ORIGINAL `SourceCitationTarget`, the original hydration request digest, a
maximum receipt-byte allowance, and trusted service time. The target includes the case, original
predecessor revision, hypothesis and supporting/contradicting side. A replacement request digest,
latest case revision, other hypothesis or different evidence side is not treated as the same operation.

Open or recover the journal at an independently trusted exact root before inspection. A fenced writer
must first reconcile its actual pending append. Inspection does not adopt a root found in an
untrusted file, truncate a suffix, automatically retry a link, or create a second journal owner.

The result, `SourceCitationInspection`, reports the inspected journal root and, when found, the exact
citation commit root plus the existing `SourceCitationReceipt`. The original historical case revision
is returned even if later changes advanced, closed or rebased the case. Receipt and revision digests
and re-encoded record bytes are checked against the semantically validated history. Duplicate
matches refuse rather than selecting a convenient result. No new durable schema or receipt dialect
is introduced; the inspection result has no canonical decoder and is not a bearer capability.

## Current authorization, historical meaning

Complete bounded journal validation occurs before the native case Inspect admission is appended.
That existing operation checks live session, principal, investigation capability, mission and case
privacy, retaining its normal clock and expiry behavior. Inspection is therefore not a read-only
filesystem operation: it can consume a journal record and can fail for capacity or append uncertainty.
It does not debit source tokens or change the case revision. Historical visibility does not establish
current applicability, physical truth, calibrated confidence or effect permission.

The source object, current descriptor and source alias are not needed for historical inspection.
A new authorized session in the same principal and mission can inspect the old session's receipt
without reviving the old session or obtaining source-read capability. Missing source is not fabricated
or restored. The shared disclosure wrapper delegates to the native investigation owner without
mutating the catalog, source requirements, active cursors or consumed-cursor tombstones.

## No committed link is not proof of no charge

An absent receipt means only that this exact target/request has no committed citation in the inspected
prefix. Acquisition may have succeeded and been charged before its case link failed. The existing
charge-only checkpoint does not persist every acquisition field; this operation cannot reconstruct an
acquisition witness that never reached a citation record. The result must not be used to refund,
reacquire, retry a link, or assert that source was never read. A caller that retained a charged Link
error still owns that evidence of the earlier acquisition. The two-stage transaction is unchanged.

An uncertain inspection append returns no historical receipt and fences the same shared writer used
for claims, cases and disclosures. Ordinary reconciliation restores the committed outcome without
redelivering source or changing charges. After that, another explicit inspection may be attempted;
its normal case-read journal capacity is not silently refunded.

## Bounds and native regression contracts

The complete scan is bounded by the journal's existing byte and record limits and the retained case
history limits. The supplied receipt ceiling counts the saved citation record plus the complete
canonical case revision, not just a digest. Oversize results refuse without partial output. Encoding
a revision is independently bounded by the existing investigation maximum; the result ceiling is not
a preemptive allocation, CPU, elapsed-time or physical-I/O meter.

Nine native citation tests cover later case progress and absent source, exact matching, the exact
output-size boundary, all four link append fault phases, current authorization, replacement sessions,
corrupt committed history, inspection acknowledgement loss, and a charged but unlinked restart.
Six shared-owner integration tests cover an empty rebuilt catalog, active and consumed continuations,
replacement session visibility, joint append fencing, charge-only history, and a torn later work
append followed by cold recovery. Fixtures use exclusive synthetic journals, native publication and
existing fault injection. No source bytes are written into the citation/session journal.

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference \
  --lib coordination::investigations::journal::source_citation
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference \
  --lib disclosure::recovery::coordinated::tests::citation
```

The existing `scripts/test_belief_provenance.sh` now includes the native citation module; its disclosure
selection also includes the six integration tests. At publication, native execution of this increment
has not been observed: the editing environment has no Rust toolchain and the first hosted run is
queued. Source review, authored tests and matching Git blobs are not compilation or release evidence.
Repository qualification gates remain unchanged. This is a reference-library recovery operation,
not a new CLI grammar, an authentication/privacy service or wholesale migration of existing callers.
