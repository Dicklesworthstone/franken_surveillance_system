# Inspect and restore archive work from its independent pin journal

The existing `fss-archive` executable now uses the same `ArchivePinJournal` and
`restore_work` API as the protected archive owner. There is no second restoration
algorithm, inferred work-root lookup, new model/runtime dependency or camera access.
These are local operator commands, not an `fss/1` agent transport or permission grant.

## Inspect saved references without opening footage

```sh
fss-archive inspect-pins \
  --pin-root "$PIN_DIRECTORY" \
  --journal-id "$JOURNAL_EPOCH" \
  --expected-namespace "$ARCHIVE_NAMESPACE"
```

The directory must already exist and have the exact accepted journal epoch and
archive namespace. All complete record framing, canonical transitions and scope
are verified under explicit bounds. The native process lock is acquired; complete
history is synchronized on open. An incomplete final record is refused, never
truncated or implicitly repaired. No media owner is opened by inspection.

The bounded JSON report includes the journal sequence/root, current candidate and
last confirmed work references. `work_custody: "not_checked"` is intentional:
confirmations record historical work verification, not current retrievability or
proof that normal archive publication finished. Inspection can therefore describe
a missing candidate without silently dropping it or reporting successful restoration.
No source bytes, credentials or filesystem paths appear in the report.

## Restore exactly the selected original work

```sh
fss-archive restore-pins \
  --pin-root "$PIN_DIRECTORY" \
  --journal-id "$JOURNAL_EPOCH" \
  --expected-namespace "$ARCHIVE_NAMESPACE" \
  --root "$EXISTING_ARCHIVE_DIRECTORY" \
  --commit yes
```

Restoration requires explicit commit consent and separately located existing
journal/media directories. Equal or nested owners and symlink roots are refused.
Missing archives are not created or migrated. Native storage locks and normal
source recovery/verification apply; these commands are not forensic read-only opens.
The operator must protect each directory and its ancestors independently. Different
paths alone do not establish different physical failure domains or authentication.

The current candidate takes precedence. Its full original source/work graph is
verified before appending confirmation. When there is no candidate, the last
confirmed work is selected and reverified. A missing, corrupt, deleted, conflicting
or superseded selected root fails: the command never silently tries an older pin.
An empty journal has no work to restore.

After candidate confirmation synchronizes, the existing restoration API publishes
the original prepared catalog, then the original pending recording at its reserved
ordinal. No additional catalog page, recording, remux, or camera generation is
invented. Actual publication receipts distinguish `published` from
`already_durable`. The report gives current durable/indexed/page counts and
`indexing_remaining`; restoring an unindexed recording does not claim full indexing.
A journaled archive writer can subsequently protect and publish the remaining page.

A process interruption or lost stdout can occur after confirmation or either
normal archive root commits. Keep both stores, inspect/reconcile any uncertain
owner, then retry the same command. It selects the same recorded work and re-verifies
already durable roots instead of duplicating them. A command error emits no success
JSON and never cleans up partial storage, changes ordinal, or erases a candidate.
`operation_complete` describes this restoration only; `capture_complete` is always
false, and no coverage, physical absence, replication or retention claim is made.

## Independent prefix and resource ceilings

An independently retained minimum journal prefix may be supplied to either command:

```sh
  --minimum-sequence "$ACCEPTED_SEQUENCE" --minimum-root "$ACCEPTED_JOURNAL_ROOT"
```

Both flags must appear together. Verified descendants can recover a lost
acknowledgement, but an older or different prefix is rejected before restoration.
Without this pair, trust rests in the protected directory's selected identity and
history. A checksum from that same untrusted directory would not prevent rollback.

Common limits are `--timeout-ms`, `--max-pin-records` and `--max-pin-bytes`.
Restoration additionally accepts the existing work/inventory ceilings:
`--max-windows`, `--max-pages`, `--max-scan-roots`, `--max-page-windows`,
`--max-pending-bytes`, `--max-graph-objects`, `--max-new-bytes`, `--max-objects`,
and `--max-total-bytes`. Limits never cause truncation, silent partial output or
automatic compaction. Unknown, duplicate, incomplete and inapplicable flags are
refused before storage opens, without echoing their values.

Both commands use a request-owned monotonic clock and propagate its cancellation
probe. Existing owner open and individual filesystem syscalls are not preemptible;
a timeout after a write may still leave a committed root. Output is bounded to
8192 bytes and emitted only after full operation success. No per-root progress is
printed as an overall successful report.

## Regression coverage and boundaries

Eleven authored executable tests (one Unix-only) use the actual binary boundary,
source-linked AVC fixtures, native journals and existing filesystem publisher.
They cover inspection with media offline, cold candidate restoration, lost stdout,
exact retry, commit consent, independent prefix mismatch, capacity limits, missing
source work, corrupt source, incomplete/corrupt journals, real cross-process locking,
strict argument handling, secret-free errors, and symlink/nested-owner refusal.

```sh
cargo test -p fss-cli --test archive_pin_process
cargo test -p fss-reference --test archive_pin_pipeline
cargo test -p fss-reference --lib rtsp::archive_pins
```

Rust compilation, executable tests, rustfmt and Clippy have not run in the editing
environment, which lacks cargo/rustc. Static source/hash checks do not establish
passing Rust tests or production storage qualification. Raw ingress and pictures
lost before a complete work checkpoint commits remain unprotected. References
cannot reconstruct unpersisted bytes, and neither command resets that obligation.
