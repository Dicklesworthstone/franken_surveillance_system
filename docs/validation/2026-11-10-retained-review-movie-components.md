# Retained review movie component validation — 2026-11-10

**25 tests passed, with no failures**, using the pinned
`rustc 1.100.0-nightly (908501772 2026-08-30)` compiler and the actual production
Rust sources. The three existing test targets now include the shared movie
output and timing implementations from `fss-reference/src/review_media/render`.

| Existing target | Passed | Failed | Exercised behavior |
| --- | ---: | ---: | --- |
| `movie_output_contract` | 10 | 0 | Actual AVC/HEVC pictures, presentation order, repeated edits, source/frame lineage, cache limits, cancellation, invalid inputs and missing requested RASL pictures |
| `movie_timing_contract` | 8 | 0 | Exact rational endpoint conversion, partial trims, explicit holes, duration limits and cancellation |
| `rtsp_movie_timeline_contract` | 7 | 0 | Actual AVC/HEVC RTP → fragmented MP4 → selected native pixels → timed Matroska, including independent windows, reordered pictures and gaps |

## Executed method

The initial offline Cargo attempt was:

```bash
PATH=/workspace/scratch/0bca9ff0b013/rust-build-cache/nightly-2026-08-31-x86_64-unknown-linux-gnu/bin:$PATH \
CARGO_HOME=/workspace/scratch/0bca9ff0b013/rust-build-cache/cargo-home \
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 \
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
RUSTFLAGS='-Zthreads=1 -Zmir-opt-level=0' \
cargo test -p fss-container \
  --test movie_output_contract \
  --test movie_timing_contract \
  --test rtsp_movie_timeline_contract \
  --offline --locked
```

That attempt exited 101 because its `fss-core` compiler process was killed with
SIGKILL. It produced no test results. Its verbatim output is in
[`2026-11-10-retained-review-movie-components.log`](2026-11-10-retained-review-movie-components.log).

The successful execution reused the actual `fss-core` rlib already compiled by
the pinned compiler for the grant tests. Its source command and provenance are
in [`2026-11-10-review-grant-tests.log`](2026-11-10-review-grant-tests.log).
The actual `fss-packet`, `fss-container`, `fss-ledger`, `fss-codec-h264` and
`fss-codec-h265` libraries were then compiled sequentially from their normal
`src/lib.rs` entry points with `--edition 2024 --crate-type rlib
-C debuginfo=0 -Zthreads=1`. This successful lane retained the compiler's default
MIR optimization settings. Each of the three unchanged integration test source
files was compiled with `--test`, linked to those actual libraries, and executed
with `--test-threads=1`.

Every exact compiler/linker invocation, compiler warning, exit code and test
result is preserved in
[`2026-11-10-retained-review-movie-components-direct.log`](2026-11-10-retained-review-movie-components-direct.log).
No runtime, codec, canonical encoder, authority contract or tested helper was
substituted, and production dependencies and features were not changed.

## What these results establish

The extracted helpers preserve the tested native movie selection, pixel,
lineage and timing behavior used by the existing CLI exporter. The native RTP
component tests also pass through the actual packet parser, muxer, demuxer,
codecs and timed Matroska writer.

These results do **not** execute retained custody, current privacy owners,
review grants in the durable lifecycle, filesystem publication/recovery,
recipient delivery, CLI processes or Asupersync. The seven new renderer unit
tests and the new review lifecycle integration tests require the complete
`fss-reference` build and were not executed by this component lane. The
resource-blocked full build remains a separate validation limitation.

`rustfmt --edition 2024 --check` also passed for `render.rs`, `render/output.rs`,
`render/timing.rs` and `render/tests.rs`.
