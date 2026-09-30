# Operator-approved HTTP source recovery

Status: implementation awaiting native compilation and qualification. This closes a cold source
publication lifecycle, not camera reconnection, event analysis or automatic capture resume.

## Preserve a key during capture

Add `--recoverable yes` to `fss-capture-reconnect` before previewing and approving the acquisition.
Every `wire_prepared` row then contains `detail.recovery_key`. Preserve the complete row outside the
capture process **before allowing publication**. The capture driver flushes the row before calling
`commit_wire`; a failed writer prevents that publication. A successful flush is acceptance by that
writer, not proof of an external durable checkpoint.

The flag is opt-in. Its absence, or `--recoverable no`, preserves existing raw and masked-decode
approval bytes and normal output. Enabling it wraps the existing complete acquisition approval in
`fss.http_recoverable_capture_plan.v1`; an old acquisition approval cannot authorize the changed
workflow. The key has its own exact versioned encoding. This does not change source generations,
network retry rules, privacy masks or any allowance.

No automatic key directory or hidden journal is created. Keys emitted after a publication attempt
would not protect a lost process, so they are deliberately emitted beforehand. A key proves no
capture and grants no authority. It can recover only originals and metadata already in custody.

## Preview recovery without I/O

```sh
fss-recover-http \
  --root /absolute/path/to/existing-camera-archive \
  --recovery-key hex:KEY_FROM_THE_PREPARED_ROW \
  --owner-authorized yes --retain-originals yes
```

Replace the placeholder with the full lowercase key. Preview performs no filesystem, network or
clock access. Review the root, predecessor/expected pins, actor, limits and proposed operation.
Repeat exactly with `--approve sha256:APPROVAL_FROM_THIS_RECOVERY_PREVIEW` to execute.
The acquisition approval is not a recovery approval. The archive and its `spool`, `roots` and
`tombstones` directories must already exist; a mistyped path does not create a new archive.

The command receives no route or network capability. It performs a fresh complete predecessor and
staged-byte verification, emits `verified_before_recovery`, re-verifies again after output delay,
and uses the existing root-last publisher. Only the exact pending temporary record can be
reconciled; conflicts or missing custody are refusals, not a request to reacquire the generation.

## Read the outcome correctly

`fss.http_wire_recovery_operator.v1` emits bounded JSONL:

* `admitted` identifies the exact approved plan, not success.
* `verified_before_recovery` identifies observed `staged` or `durable` custody, not a future lease.
* `recovered` contains the exact durable prefix and charged work. Parser acknowledgement, capture
  resumption, stream completion, event publication and coverage remain explicitly false.
* `refused` preserves the source subsystem's payload-free error and stage. It does not claim to
  roll back staged/visible work or erase the possibility of a lost successful publication.

A failed prepublication output sink prevents root publication. A failed final sink can happen
**after** durability. Preserve the key and complete earlier rows; an exact recovery rerun can
resolve the latter case without another network read. Native source errors are not flattened into
success, scene absence, a zero-byte response or a newly empty archive.

## Resource and privacy boundary

`--timeout-ms`, `--max-work`, `--max-reads`, `--max-source-bytes`, `--max-scan-roots` and
`--max-object-bytes` are part of the exact approval. One work budget covers inspection plus actual
recovery. Exhaustion does not replenish it or partially truncate the predecessor chain. Normal
publisher open performs its existing bounded recovery scans, locks and directory synchronization;
this is not forensic read-only access or a hard real-time guarantee for blocking filesystem I/O.

Only metadata and hashes are printed. Original headers and encoded media remain private local
**unencrypted** custody. No pixel decoding/export, retention-policy change, deletion, general
filesystem repair or automatic capture restart is implemented. Existing captures that did not
preserve a key are not silently upgraded; a plain expected pin cannot reconstruct absent metadata.

## Native checks

```sh
cargo test -p fss-cli --bin fss-recover-http --locked --offline
cargo test -p fss-cli --bin fss-capture-reconnect --locked --offline
```

Added tests include real loopback capture -> prepared JSONL -> each injected publication crash ->
destroyed live owner -> recovery from disk only, opt-in compatibility, successful two-generation
key replay, exact recovery approval, stale approval, missing custody, failed output before and
after publication, and bounded interrupted writes. These tests were **not run** in the toolchain-
less implementation environment. No bead, native gate, or production-readiness claim is closed.
