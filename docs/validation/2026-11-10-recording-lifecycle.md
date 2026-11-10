# Recorder replay and review expiry verification — 2026-11-10

The session implements native HEVC recorder playback, exact source-preserving
review expiry, and approved review reissue after completed expiry. Verification
below distinguishes source inspection, local execution limits and hosted native
execution. Hosted checks are supplementary; repository-owned DSR qualification
remains the release authority.

## Local baseline

The unchanged initial dependency closure could not complete:

```bash
cargo check --locked --offline -p fss-cli --lib
```

The exact `nightly-2026-08-31` toolchain reported
`rustc 1.100.0-nightly (908501772 2026-08-30)`. The task-local Cargo cache and
target directory were on disk. Environment controls were `CARGO_BUILD_JOBS=1`,
`CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0`, and `RUSTFLAGS=-Zthreads=1`.

| Result | Observed value |
|---|---:|
| Cargo exit | 101 |
| Elapsed time | 111.02 seconds |
| Maximum child RSS | 1,979,316 KiB |
| Compiler termination | Signal 9, SIGKILL, in unchanged `asupersync 0.5.0` |
| FSS source diagnostics reached | None |

This is a blocked baseline, not a passing native check. Dependencies, feature
sets, source semantics and pins were not substituted. No further whole-build
retry was made against the same unresolved local resource constraint.

Pinned rustfmt parsed the replay changes; the five previously clean replay files
were formatted and checked, while existing compact formatting in other files
was preserved. Changed expiry and CLI files passed formatting before the
workspace reconnection. Independent source reviews covered codec-pinned native
loaders, approval and closure boundaries, source holds, tombstone recovery and
completed-expiry-only reissue. `git diff --check` is a separate whitespace check,
not compilation or runtime evidence.

After the executor reconnected, the formatter was restored from the exact
official nightly components with their manifest SHA-256 values verified. The
five reissue Rust files passed that pinned formatter's check. A possible fresh
local Cargo attempt was abandoned before compiler installation or execution
when the workspace ran out of disk space. Only reproduced component downloads
and duplicate formatter extraction files were removed; the source work and
existing Cargo cache were preserved. No second Cargo result is claimed.

## Focused native runner

The repository-owned command is:

```bash
bash scripts/check_recording_lifecycle.sh all
```

The `replay` and `review-expiry` selectors also run independently. The script
keeps the pinned toolchain and `--locked --offline` policy, continues to later
focused targets after a failure, and returns failure if any target fails.
It covers the native receipt/RTSP/HEVC owners, real capture and archive CLI
processes, review lifecycle, deletion effect recovery, retention cohorts,
legacy deletion encodings, new expiry wire bounds and command admission.

The first independent run is
[42758095012](https://github.com/Dicklesworthstone/franken_surveillance_system/actions/runs/42758095012)
at `c83974f1f1ee1a23c1e712b01616175215f0a619`. It was queued without a runner
when the reissue correction was prepared. The earlier broad reference workflow
was occupied by a preceding commit; the independent workflow avoids that
concurrency group while preserving every existing full-suite step and gate.
Native results for the correction are pending and must be recorded before
claiming focused execution success. No local full-build, whole-repository pass,
DSR receipt or production qualification is asserted.
