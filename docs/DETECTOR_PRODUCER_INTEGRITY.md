# Native detector report integrity

`run_package_detection` returns source-linked, uncalibrated model proposals. Retaining those
proposals makes them available to tracking and recorded-event publication, so a report's public
fields and a caller-recomputed JSON hash cannot establish that the native producer computed it.

## Producer boundary

The shared `finish_report` path used by ordinary detection, sentinel bursts and long sentinel
bursts mints a private in-process binding before returning the report. It binds:

- the exact canonical detection record, including package, model, contract, source import/root,
  range, thresholds, labels, capsule identities, inference identities, output/head digests and
  every surviving detection;
- the exact rendered JSON digest, including frame metadata and semantic claim flags;
- each complete source capsule's metadata digest, including fields outside the record projection;
- the complete privacy policy binding and generation applied to the computation.

The binding has no public constructor, setter or decoding path. Report fields remain readable
and mutable for API compatibility, but changing their bound values makes conversion and retention
fail with `ERR-PACKAGE-EVENT-MISMATCH-001`. `PackageDetectionRecord::from_report` rebuilds the
canonical projection and checks it against the original binding. `retain_package_detection`
performs that conversion before object staging, root publication or ledger mutation. Long
sentinel retention also uses the checked conversion for its native child reports.

This prevents genuine inference/head outputs from being transplanted between capsules, and
prevents edited JSON from being accepted by recomputing its public SHA-256. A valid content hash
proves byte consistency; the private binding additionally preserves the native producer's
original source-to-result association.

## Compatibility and scope

Honest report JSON, report digests, detection-record bytes and retained schemas are unchanged.
Exact retries remain idempotent. Existing retained reports continue to reopen through their
authority-ledger and custody verification; the in-process binding is not serialized and does not
retroactively attest historical results. An application constructing `PackageDetectReport` with
a struct literal must instead obtain it from the native detector API.

This is one producer boundary under the Stage B work in Bead `fss-gefi6`, not a system-wide evidence
origin registry. It does not qualify detector accuracy, calibrate scores, establish independent
corroboration, authorize effects or remove existing source-custody/current-privacy checks.

## Regression evidence

`native_producer_binding_rejects_transplanted_results_and_rehashed_json` in
`crates/fss-reference/tests/package_event_reader_contract.rs` runs the real bundled detector on
two retained frames. It tests separate and paired inference/head swaps, capsule-metadata
mutation, forged inference JSON and an altered effects-authority flag with valid recomputed
hashes. Both conversion and retention must refuse without changing staged objects, visible roots
or the authority anchor. Restoring the untouched native report must preserve exact bytes,
successful retention, idempotent retries and custody reads.
