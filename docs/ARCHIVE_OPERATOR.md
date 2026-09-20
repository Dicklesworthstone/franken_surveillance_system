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
cargo test -p fss-cli --lib archive_cmd::tests
cargo run -p fss-cli --bin fss-archive -- help
```

Authored tests use real retained synthetic HEVC source windows and actual local
publication/catalog APIs. They cover strict arguments, native paths, missing
roots, exact pins, multi-page queries, unindexed tails, whole-window budgets,
expired requests, corrupt source, reopening and bounded reporting. Rust execution
was unavailable in the editing environment; these tests are not a passing
compilation or qualification receipt. No release gate is changed.
