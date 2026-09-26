# Local archive operator utility

`fss-archive` exposes the existing AVC and HEVC archive recovery and range-read
engines to an operator. It is a standalone reference-storage utility, not a new
fss/1 operation or an alternate agent authorization protocol. It does not open
camera sockets, guess stream scope, create a missing archive, publish new archive
roots, repair orphaned state, delete objects, or change retention policy.

## Inspect, pin, select, verify

Supply the exact storage root and all scope/clock identities used by the archive
writer. A process-local ingress handle, RTP timestamp or receive clock cannot be
substituted for the declared decode clock. The codec is chosen explicitly; neither
file contents nor a catalog label can select a fallback verifier.

```sh
COMMON=(--root "$ARCHIVE_ROOT" --codec hevc --sensor "$SENSOR" --stream "$STREAM"
        --generation "$GENERATION" --anchor "$ANCHOR" --receive-clock "$RECEIVE_CLOCK"
        --decode-clock "$DECODE_CLOCK" --time-scale 90000)
fss-archive inspect "${COMMON[@]}"
# Copy the exact snapshot identity from that report into SNAPSHOT.
fss-archive query "${COMMON[@]}" --expected-snapshot "$SNAPSHOT" --start 0 --end 90000
fss-archive verify "${COMMON[@]}" --expected-snapshot "$SNAPSHOT" --start 0 --end 90000
```

`inspect` recovers and source-replays the bounded inventory, returning durable
and indexed counts, pages, the snapshot identity, and every descriptor with an
explicit indexed flag. A durable unindexed tail is not silently treated as
searchable. `query` selects against the pinned inventory under whole-window byte
and count limits; it does not claim that a range-read request completed. `verify`
additionally drives the existing cross-page reader, rechecking catalogs and
source-replaying each selected window before returning its object identities and
aggregate completion. A changed inventory refuses the old snapshot pin.

Ranges are half-open **decode ticks**, not wall/capture time. Even a one-tick
intersection charges the whole independently decodable window. Unindexed intervals
remain explicit and are never evidence of camera coverage or event absence. A
successful metadata selection is distinguished from a successful range read.
Source replay establishes byte relationships, not full HEVC decode completeness.

Output uses `fss.local_archive_operator_report.v1`. It includes the exact codec,
scope, clocks, snapshot, counts, limits' outcome, and verification level. It is an
operator report, not a canonical ledger receipt, signature or authority grant.
No report is returned on command failure. Stdout failures may leave truncated
transport output, which must never be interpreted as a complete JSON report.

## Verified whole-window export

```sh
fss-archive export "${COMMON[@]}" --expected-snapshot "$SNAPSHOT" \
  --start 0 --end 90000 --output-dir ./case-001 --allow-whole-windows yes \
  --privacy-root ./deployment --site "$SITE" \
  --max-output-windows 64 --max-output-bytes 268435456 --max-export-bytes 536870912
```

Original packets cannot be masked without re-encoding. `--privacy-root DIR --site SITE`
names the deployment that retains the archive sensor's privacy-mask authority
(`fss-event privacy-mask declare`); when that sensor has a current retained mask, or
when no deployment is named, the export is refused before the archive is opened or
any output exists (`ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001`; no override exists).
For an unmasked sensor the exported files are unchanged.

The destination must be a **new directory outside the archive**, under an existing
operator-controlled parent. Export never overwrites, merges with, or implicitly
resumes an existing destination. Canonicalized parent aliases into the archive
are refused. On Unix, the new directory is mode 0700 and files are mode 0600
(subject to further restriction by umask). Other platforms inherit parent ACLs;
these permissions do not replace operator authorization or encryption.

`--allow-whole-windows yes` acknowledges disclosure of the entire selected
recordings, including original packets, configuration and **source-only boundary
lookahead**. A requested subinterval is NOT a crop or a redaction. Source-only
lookahead can reach past the last returned media sample. The report retains both
the requested overlap and full media decode interval and flags this boundary.

After scope/snapshot and complete-selection budget checks, each window passes
the existing native source-replay reader before export. Six deterministic files
are written per window, named by ordinal and full recording-root hash:

- `source.bin`, `init.mp4`, `media.m4s`, `index.bin`: exact four recording objects.
- `root.bin`: the exact canonical root manifest linking those objects.
- `playback.mp4`: that window's **unchanged initialization followed by unchanged
  media**, not a transcode or a concatenation of multiple independent windows.

The playback file retains original timestamps, sample flags and codec bytes.
It depends on a player's codec support; export is not a new decode qualification.
The report includes hashes and sizes for every file, so original roots and
RTP-to-media provenance remain independently auditable. Shared lookahead/source
objects are copied per selected window; no export deduplication hides ownership.

`--max-export-bytes` separately bounds written payload, including duplicate
playback bytes and reports. Before creating the directory the utility reserves
twice the catalog's whole-window payload sum plus 4 MiB for completion and 4 KiB
for intent. This is deliberately conservative and may refuse a small reservation
that would have fit the actual payload. Every individual write checks the actual
remaining reservation too. Filesystem metadata/blocks are not included. Between
windows only descriptors and the bounded report remain in memory; playback adds
at most one bounded 32 MiB buffer. Short writes and reads are supported, with at
most eight consecutive interrupted I/O attempts and clock checks between chunks.

`REQUEST.json` records the original pinned intent. Every data file is created
exclusively, written, fsynced, and compared byte-for-byte through its open handle.
Only after the archive reader's aggregate completion, metadata revalidation and
all payload checks does the utility write and verify `COMPLETE.json.pending`,
sync the directory, and atomically create the `COMPLETE.json` hard link without
replacing any existing name. The pending name remains the same file under a second
link, not another success receipt. The directory is synced after linking.
Filesystems without the required hard-link/directory-sync support fail explicitly.

A partial directory, `REQUEST.json`, or even a fully written pending receipt is
**not** successful export. No cancellation, corrupt later source, failed write,
or budget refusal deletes earlier output or retracts archive custody. Errors
explicitly classify a possibly partial export. A failure after the completion-link
commit (for example directory-sync failure or lost stdout) may leave a valid
completion file but does not establish acknowledged durability: reconcile the
existing output instead of rerunning over it. External modifications after return
invalidate the point-in-time hashes; no ongoing integrity/availability is claimed.

## I/O, work and privacy boundaries

The root must already contain real `roots`, `tombstones`, `spool`, spool-object,
staging and verification-hold directories and regular lock files. A missing or
legacy layout is refused before calling the existing owner. Final symlink roots
and symlink layout components are refused. Ancestor aliases are canonicalized;
the caller must control the archive path hierarchy against concurrent hostile
replacement. This utility is not an OS sandbox or descriptor-relative path jail.

Opening takes the existing exclusive storage locks and invokes normal recovery,
verification holds and directory synchronization. Thus this is **not a forensic
read-only open**. No private reconstruction of the spool format or alternate
recovery algorithm is used. Broken or indeterminate state retains the existing
owner's refusal/reconciliation semantics.

Count and byte quotas apply before recovery. Defaults: 4,096 windows, 1,024 pages,
16,384 root inventory entries, 65,536 objects, 1 GiB total spool bytes, and the
existing 32 MiB per-object/window bound. Query defaults are 64 whole windows and
256 MiB returned-window payload. The JSON report is capped at 4 MiB. Explicit
options can narrow these limits or enlarge them only within the fixed ceilings.
Recovery may read all admitted objects, including other namespaces; query-output
limits are not disk-I/O, CPU or resident-memory budgets.

An explicit timeout owns one monotonic clock. It is checked around open and at
existing recovery/read cancellation probes. The existing owner-open API has no
cancellation parameter, and an individual filesystem syscall/native replay unit
is not preempted. The utility does not promise a hard real-time deadline. It adds
no worker, signal handler, asynchronous runtime or detached cancellation tree.

Metadata is sensitive too. Running the local utility asserts the operator's
existing permission to read that root and requested scope. It does not create
an agent capability, authorize a third-party camera or apply a privacy filter.
Errors and Debug omit private paths and raw media. No output payload is deleted
or any durable source root retracted after a later failure.

## Validation

```sh
cargo test -p fss-cli --lib archive_cmd::
cargo test -p fss-cli --test archive_operator_process
cargo run -p fss-cli --bin fss-archive -- help
```

Authored tests use real retained synthetic HEVC source windows and actual local
publication/catalog APIs. They cover strict arguments, native paths, missing
roots, exact pins, multi-page queries, unindexed tails, whole-window budgets,
expired requests, corrupt source, reopening and bounded reporting. Rust execution
was unavailable in the editing environment; these tests are not a passing
compilation or qualification receipt. Export contracts additionally cover exact
MP4 and canonical-object bytes, create-only output/completion, symlink scope,
whole-window approval, independent budgets, interrupted and short I/O, deadline
retirement, corrupt later media with partial output, empty selections and Unix
privacy modes. Executable contracts check help, strict diagnostics and refusal to
create a misspelled archive. No release gate is changed.
