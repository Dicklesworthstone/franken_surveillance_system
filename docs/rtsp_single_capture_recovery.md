# Recover an interrupted single native RTSP capture

`fss-capture-rtsp --recover yes` restores protected pending work from an ordinary
single capture. `--recover index` separately completes its recovered catalog tail.
Both modes use the existing reconnect recovery owner and native AVC/HEVC verifiers;
they do not create a reconnect plan, rewrite paths, increment generations, rehash
receive clocks, or start another camera session.

This is an explicit storage-recovery workflow, not automatic crash resume. Retain
both the original archive and the independently protected pin journal. Missing
stores remain unobserved, and restored work never establishes capture completion,
scene coverage, successful pixel decoding, or evidence of absence.

## Keep the exact original capture scope

Repeat the original capture options, including all explicitly selected native
limits, source identities, cadence, codec, optional HEVC parameter sets, and optional
progress supervision. Keep the original `--root` and `--pins` paths **without** adding
`.attempt-0001`. Keep the original generation and clock identities.

Remove the original `--approve` value. An approval for capture cannot authorize
restoration or indexing. An approval for restoration cannot authorize indexing.
Likewise, none of these recovery approvals can be delegated to camera intake.

When the original command selected Digest authentication, preserve the credential
file reference and realm options as part of its plan identity. Recovery does not
open that file, acquire a secret lease, read entropy, resolve a peer, or contact the
camera. The credential file need not remain available for storage recovery.

## Restore protected work first

Given a shell array `original` holding the exact original capture arguments but no
`--approve`, preview recovery with:

```sh
fss-capture-rtsp "${original[@]}" --recover yes
```

Unlike ordinary capture preview, this explicit recovery preview reads protected
journal metadata. It does **not** read original media or publish anything. Review
the exact paths, selected candidate/confirmed work, current journal anchors, source
generation, capture-plan identity, and limits in the returned report.

Repeat with that preview's separate approval:

```sh
fss-capture-rtsp "${original[@]}" --recover yes --approve "$WORK_APPROVAL"
```

The existing owner locks the journal, validates the current observed-store approval,
verifies selected original work, and restores only its original pending window or
catalog slot. A missing/damaged newer candidate is not replaced by older work.
There is no new directory, input epoch, extra picture, or implicit catalog-tail flush.

`--recovery-timeout-ms` defaults to 30,000 and accepts 1 through 3,600,000. It bounds
the entire recovery operation, independently of the original capture deadline.
It does not alter native per-attempt resource ceilings. Include the same recovery
timeout in preview and execution; changing it invalidates the approval.

## Complete catalog discovery under a separate approval

Once protected work is settled, request a source-reading index preview:

```sh
fss-capture-rtsp "${original[@]}" --recover index
```

This mode verifies the observed archive and prices its exact next catalog page.
It reads original media even during preview, but does not publish in preview.
Unsettled work refuses and must use `--recover yes` first.

After reviewing the source-verified inventory and proposed page, execute using the
index preview's approval:

```sh
fss-capture-rtsp "${original[@]}" --recover index --approve "$INDEX_APPROVAL"
```

Publication follows the existing independent journal/work/confirmation/catalog
barriers. Original recording windows do not change. The `attempt_index` report
exposes source scope, decode clock, time scale, and exact catalog slots/roots for
`fss-import-rtsp`. A single capture is represented as one exact attempt in these
shared report schemas; it is not renamed or converted into a reconnect epoch.

The established `fss.rtsp_reconnect_recovery_cli.v1` and
`fss.rtsp_reconnect_index_cli.v1` report formats are reused deliberately. Their
`capture_plan` field is the exact original single-capture approval identity,
including progress supervision when selected. Existing reconnect approvals,
canonical encodings, and report layouts remain unchanged.

## Interruptions and uncertainty

A changed journal tip, replaced directory, partial layout, stale approval, missing
original, exhausted work allowance, or failed output stops progression. Preserve
all stores, preview their current state again, and approve the new preview before
retrying. Earlier durable writes are not rolled back or recaptured. Original slots
retry idempotently, and a settled index retry reports the existing catalog pins
without adding another page.

`operation_complete` describes the requested storage operation only.
`capture_complete` remains false. There is no camera reconnection, inferred physical
EOF, unobserved-tail repair, cross-epoch merge, or automatic scene-health conclusion.

## Focused validation

The patch adds parser/approval contracts and native filesystem/HEVC fixtures for
single-capture restoration and catalog completion. Run them with the repository's
pinned toolchain and dependency closure:

```sh
cargo test --locked --offline -p fss-cli --bin fss-capture-rtsp
cargo clippy --locked --offline -p fss-cli --bin fss-capture-rtsp -- -D warnings
```

The implementation-session environment did not provide `cargo` or `rustc`, so these
Rust tests were **not executed in that session**. Verified original source hashes,
source-preservation checks, and patch application checks are not native execution,
physical-camera qualification, or release authority. The broader FSS-047/FSS-048/FSS-049
work remains open.
