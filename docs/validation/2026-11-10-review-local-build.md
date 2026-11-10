# Local retained-review compilation attempts — 2026-11-10

Both final local Cargo attempts stopped while compiling the unchanged, locked
`asupersync 0.5.0` dependency. Cargo exited **101** after its `rustc` child received
**signal 9 (SIGKILL)**. Neither attempt emitted an FSS source diagnostic or
completed the requested CLI check. They are environment-blocked attempts, not
passing feature-validation or qualification receipts.

The compiler was the repository's exact `nightly-2026-08-31` toolchain:
`rustc 1.100.0-nightly (908501772 2026-08-30)`, commit
`90850177249efe0321573c569aec5d12b257f8d6`, LLVM `23.1.0`. Its task-local
`cargo`, `rustc`, and `rustfmt` binary hashes matched the installed pinned
toolchain. Dependencies, features, source files and repository pins were not
substituted. The compiler and registry cache resided on disk rather than tmpfs.

## Exact command environment

```bash
export PATH="/workspace/scratch/0bca9ff0b013/rust-build-cache/nightly-2026-08-31-x86_64-unknown-linux-gnu/bin:$PATH"
export CARGO_HOME=/workspace/scratch/0bca9ff0b013/rust-build-cache/cargo-home
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUSTFLAGS=-Zthreads=1

# Default MIR optimization; no allocator override.
cargo check -p fss-cli --bin fss-export --offline --locked

# One subsequent allocator-only retry, with the same flags and cached artifacts.
MALLOC_CONF=narenas:1,dirty_decay_ms:0,muzzy_decay_ms:0 \
  cargo check -p fss-cli --bin fss-export --offline --locked
```

Both commands ran from the repository root. Durations and maximum child-process
RSS were measured using Python `time.monotonic()` and
`resource.getrusage(resource.RUSAGE_CHILDREN)` around the Cargo process:

| Attempt | Cargo exit | Duration | Maximum child RSS | Final compiler result |
| --- | ---: | ---: | ---: | --- |
| Default MIR, serial compiler | 101 | 955.11 s | 2,146,820 KiB | `asupersync` rustc: signal 9, SIGKILL |
| Same build, allocator-only override | 101 | 28.00 s | 3,093,432 KiB | `asupersync` rustc: signal 9, SIGKILL |

Before the allocator retry, the exact compiler's `-vV` invocation under
`MALLOC_CONF=abort_conf:true,confirm_conf:true,narenas:1,dirty_decay_ms:0,muzzy_decay_ms:0`
exited zero and explicitly confirmed all settings. These controls change
allocator behavior, not the compiled program's features or semantics; their
meaning is documented in the [jemalloc manual](https://jemalloc.net/jemalloc.3.html).
The differing observed RSS peaks do **not** establish an allocator regression:
the available memory and point of termination varied on the shared host.

No further local resource retries were attempted. The `fss-event` check and
focused review runtime tests remain blocked through this local Cargo dependency
path. Actual direct component tests and pinned-runner CI results are recorded
separately; this note makes no claim about their outcome.
