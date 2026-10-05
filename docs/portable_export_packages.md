# Portable approved export packages

`fss-export-package` turns an already committed redacted `fss-export event` root into a
portable file. A recipient can verify that file offline without access to the deployment,
source recordings, models, or a network service.

This is **event metadata only**, not playable footage. It preserves the existing approved
`event-summary-redacted-v1` record and its single-child manifest identity. It does not hydrate
source, device, zone, track, model, or archive references. Approved free-text fields such as
purpose and uncertainty are preserved verbatim; this is not a general free-text secret scrubber.
Review the original export before approval.

## Owner workflow

First preview and approve the existing `fss-export event` request. That command binds the
reviewed event revision, recipient, purpose, expiry and principal and returns `export_root`.
A preview-only root, or a root published without the reserved export authority record, cannot
be packaged. This new command does not approve an event export on your behalf.

Prepare a private output directory outside the deployment, then preview the file handoff:

```sh
install -d -m 700 /path/to/handoffs
fss-export-package pack \
  --root /path/to/deployment --site site:home \
  --principal principal:local-operator \
  --export-root "${APPROVED_EXPORT_ROOT:?supply the committed export root}" \
  --recipient recipient:case-7 \
  --attested-now-ns "${EARLIEST_NOW_NS:?supply earliest current time}:${LATEST_NOW_NS:?supply latest current time}" \
  --out /path/to/handoffs/case-7.fssp
```

The principal must be the original export's approving principal, and the recipient label must
match exactly. Both export capabilities are required by the library. The local CLI assumes
execution by the authorized deployment owner; `--principal` is an audit identity, not remote
authentication or a privilege-escalation mechanism.

Preview creates no output file. It reports `approval_digest`, the package identity and an exact
shell-quoted `approve_command`. After reviewing the recipient and destination, execute that
command, or repeat the same arguments with `--approve` and that file-approval digest. This is a
**separate approval from the original event-export approval**. It binds the package, actor, site,
recipient, time assertion, canonical OS-byte destination path, and physical destination directory.
Changing any of those values invalidates it. For non-UTF-8 paths, the command string and display
path are null rather than lossy; repeat the original OS arguments with the supplied digest.

The source deployment stays locked throughout packaging and output publication. Existing
`ReferenceDeployment::open` can perform its normal restart reconciliation, so the command does
not claim that opening the deployment is mutation-free. Package preparation itself appends no
record. Tombstoned export custody is refused even when interrupted deletion has not yet removed
its bytes; the current authority head and reserved export object are rechecked.

## Recipient workflow and trust boundary

Obtain the expected export root through a trusted channel **independent of the package**:

```sh
fss-export-package verify \
  --input /path/to/received/case-7.fssp \
  --export-root "${TRUSTED_EXPORT_ROOT:?supply the independently trusted root}" \
  --recipient recipient:case-7 \
  --attested-now-ns "${EARLIEST_NOW_NS}:${LATEST_NOW_NS}"
```

Verification opens one bounded regular input file, creates nothing, opens no deployment and
contacts no provider. It verifies the complete envelope, checksum, canonical redacted record,
and reconstructed existing export manifest against the supplied root before returning JSON.
Truncation, trailing bytes, unsupported versions, oversized lengths, altered records and root
substitution fail without a JSON prefix. Recomputing an envelope checksum cannot make a changed
record match the independently pinned export root.

A successful result means **these exact bytes match the supplied root**. It does not establish
that the root was genuinely approved unless the independent channel establishes that provenance.
No signature is verified. It does not prove physical truth, detection accuracy, current ledger
membership, recipient authentication or delivery. The record's indeterminate event state remains
indeterminate. The recipient label is a scope check, not a credential.

## Expiry and copies

Both commands require an explicit signed-128-bit current-time interval in the record's declared
clock coordinates. No ambient wall clock is read. The latest possible current time must be
strictly before the export's exclusive expiry. An interval overlapping expiry is refused as
`expiry_overlaps_attested_time`; one entirely at or after expiry is refused as
`expired_under_attested_time`. Point intervals are accepted. Comparisons do not calculate a
midpoint or subtract timestamps, so signed extremes do not wrap.

Time bounds are caller assertions, not independently verified clock evidence. Supplying a false
old time is not prevented. The file is plaintext, and expiry does not erase, encrypt or revoke
existing copies. Offline verification cannot discover a subsequent deletion or revocation. The
copy is not registered in deployment custody; existing deletion reports continue to classify
operator exports as outside their enumerable closure. Secure transport and independent root
delivery remain the owner's responsibility. No network send occurs here.

## File publication and restart

Writing is supported only on Linux x86-64/aarch64 with `/proc/self/fd` and hard-link support.
Other writer platforms fail closed; the bounded verifier remains usable without the writer.
The output parent must already exist outside the deployment and must not be group- or
world-writable. The writer holds its directory descriptor and binds its device/inode identity
into approval. A path replacement cannot redirect publication into the replacement directory.
This is not a sandbox against privileged mount changes or a malicious process with the same
owner's filesystem privileges.

New files use mode `0600`. A same-directory create-new temporary file receives the complete
package, is synced and read back, then is hard-linked to the final name without replacement.
A preexisting different file, directory or dangling symlink is never overwritten. An exact-byte
retry verifies and syncs the existing final file and returns `already_present`, keeping its inode.
Cancellation before publication creates no partial final file. After final-name visibility,
cancellation cannot erase success; an I/O acknowledgement or directory-identity failure is
reported as publication indeterminate rather than falsely claiming rollback. Verify any existing
output before retrying. A failed stdout write can likewise occur after publication.

Normal cleanup removes only this attempt's own temporary inode. A process crash or cleanup
failure may leave a private `.fss-export-package-*.tmp` name; it is not a final package and is
never blindly adopted. Successful publication with incomplete temporary cleanup reports
`temporary_cleanup_pending: true`. No global temporary-file deletion or overwrite option exists.

## Binary format and bounds

The version-1 file is exactly:

| Offset | Field |
|---|---|
| 0 | Eight literal magic bytes `FSSXPK01` |
| 8 | Big-endian unsigned 32-bit version, exactly `1` |
| 12 | 32 raw SHA-256 bytes of the existing approved export manifest root |
| 44 | Big-endian unsigned 32-bit canonical record length |
| 48 | Exactly that many canonical `EventExportRecord::to_bytes()` bytes |
| End minus 32 | SHA-256 of every preceding envelope byte |

The payload is nonempty and at most 65,536 bytes; the entire file is at most 65,616 bytes.
It contains no filename table, compression, optional child graph, extraction path, appended
certificate or deployment journal. The manifest is reconstructed by the existing export owner,
not accepted as arbitrary package input. New incompatible layouts require a version change.
The complete package digest hashes the envelope including its checksum.

File approval uses canonical domain `fss.export_package_file_approval.v1`. Machine reports use
`fss.export_package_report.v1` and `fss.export_package_file_report.v1`; all error identities reuse
the existing export families, with narrower `reason` strings. No existing durable export layout,
capability row, effect state machine, dependency or default export profile is changed.

## Validation boundary

```sh
cargo test -p fss-reference --lib export_package
cargo test -p fss-cli --bin fss-export-package
cargo test -p fss-cli --test export_package_cli
```

Ten library tests cover real export authority, strict framing, independent-root forgery,
recipient/expiry bounds, cancellation and cold readback. Nine filesystem tests cover no-overwrite
publication, private permissions, checkpoints, competing files, directory substitution and
bounded reads. Six process tests cover preview/copy/retry/offline verification, changed approvals,
recipient/root/time refusals, corruption and malformed requests.

These Rust tests and `rustfmt` were **not executed in the authoring environment**, which lacked
the Rust toolchain. Separate Python/filesystem checks exercised descriptor-pinned hard-link
publication, no-replacement behavior, directory replacement, and envelope arithmetic; those are
not a compilation or test run of the Rust implementation. This slice remains unqualified.
