# Performance ledger

Every entry MUST bind:

- implementation commit and dirty state;
- exact device/model/platform/accelerator generations;
- replay/corpus digest and workload distribution;
- baseline and candidate commands;
- semantic-equivalence evidence;
- latency/throughput/queue/energy/cost distributions;
- sample count, variance, and warm/cold state;
- changed operation-cost terms;
- retained benchmark artifacts;
- regressions and excluded conditions.

A lower wall-clock number without the same semantic work and output quality is not a win.

## PERF-001 — YOLOX-Nano optimized CPU executor (fss-bd99t)

- **Commit:** the `perf(exec)` commit carrying this entry (base `2c0cc07`), clean tree at
  measurement except for this ledger/status text.
- **Model:** `models/yolox-nano/yolox_nano.fmpk` (`sha256:5b656875…8c74`), 416x416, 286 IR nodes,
  522,553,408 Conv2d MACs, 8.38 M SiLU elements.
- **Workload:** the three pinned conformance inputs (`tests/yolox_support/cases.rs`:
  `synthetic_pattern`, `jpeg_colorbars`, `silhouette`), preprocessed exactly as in
  `tests/yolox_nano_conformance.rs`; graph execution only (preprocessing and NMS excluded).
- **Host:** rch worker `vmi1227854`, `AMD EPYC Processor (with IBPB)`, 10 logical CPUs, shared VPS;
  single-threaded; release profile, default target (x86-64 baseline, SSE2; no `target-cpu`).
  Baseline and candidate ran in the same process on the same worker.
- **Command:**
  `RCH_REQUIRE_REMOTE=1 rch exec -- cargo run --release --locked --offline --example yolox_profile -p fss-reference -- 5`
- **Samples:** 5 warm runs per case per backend (15 per backend).

| Backend | per-case medians (ms) | median of 15 (ms) | min (ms) |
|---|---|---|---|
| scalar reference (`ScalarExecutor::run`) | 3085.4 / 2775.7 / 3330.3 | 3085.4 | 2666.0 |
| optimized (`OptimizedGraph::run`) | 203.5 / 171.2 / 193.6 | 193.2 | 166.8 |

End-to-end speedup: **16.0x** (median of 15 vs median of 15). Predeclared target was >= 5x.
The shared worker is noisy: scalar samples span 2666–3462 ms, optimized 167–238 ms. An earlier
run of the unchanged scalar path on worker `ovh-a` gave 4069–4188 ms medians; numbers from
different workers are not comparable.

**Profile before (scalar, one-node programs, min of 3):** Conv2d 2073 ms (78.5%), SiLU 330 ms
(12.5%), Slice 126 ms, Concat 56 ms, rest < 25 ms each.
**Profile after (optimized, per-node programs incl. fused Conv2d+SiLU, min of 3; includes per-program
copy overhead, so it sums to 426 ms against 193 ms whole-graph):** Conv2d+SiLU 268 ms (104 fused
nodes), Slice 61 ms, Concat 49 ms, Add 11 ms, unfused Conv2d 10 ms, rest < 9 ms each.

**Semantic equivalence (countermetric 1):** maximum absolute deviation from the scalar reference is
**0** — outputs are bit-identical (`output_bits` digests equal for all three cases:
`db5d26e8…`, `eb2d10df…`, `f4784387…`). Certified in-tree by
`optimized_executor/tests.rs` (randomized differential tests, tolerance 0 ULP) and by
`tests/yolox_nano_conformance.rs` (both executors, identical output bits and post-NMS detections,
unchanged 1e-3 oracle tolerance).

**Memory (countermetric 2):** optimized measured peak live activation payload 4,849,024 bytes
(+27,648 bytes scratch) per run, plus 7,280,600 bytes resident prepared constants/packed weights
(prepared once at load, 21.7 ms). The scalar liveness plan's peak is 11,274,908 bytes, and the
scalar `ScalarExecutor::run` path materializes all 107,511,620 cumulative tensor bytes and copies the
~3.6 MB of weights into tensors per inference.

**Changed cost terms:** Conv2d via packed-weight 4x8 register tiles (vectorized, SSE2), 1x1
convolutions flattened to one GEMM row, depthwise row accumulation, bias+SiLU fused into the
convolution epilogue, SiLU series evaluated 8 elements at a time with exact power-of-two
reciprocals, direct strided layout copies, liveness release. Work units (`executed_macs`) and
cumulative-byte accounting are unchanged.

**Excluded:** multi-threading, `std::simd`, architecture intrinsics, `target-cpu` flags, and any
reassociation or approximation (all would change bits or policy). Arm64 not measured.

## PERF-002 — Scoped multi-threaded Conv2d in the optimized executor (fss-zczw0)

- **Commits:** `f2995fb` (implementation, 2^21 per-thread work floor) and `0ce4d65` (2^23 floor,
  profiler spawn-latency and CPU/wall output). The primary table was measured from the clean Git
  baseline of `0ce4d65` (`--clean-overlay --no-overlay`), i.e. no working-tree state.
- **Change:** `OptimizedGraph::run_threaded(inputs, budget, ExecThreads, cx)`. A Conv2d step's
  output units (`(n, group, MR-block)` or depthwise `(n, channel)` planes, contiguous in NCHW)
  are cut into `3 * threads` contiguous chunks with `split_at_mut`; the caller and `threads - 1`
  `std::thread::scope` workers take whole chunks from one bounded local queue. A step is split
  only when it carries at least 2^23 multiply-accumulate equivalents per thread (fused SiLU counted
  as 24 per element). All other operators, and `threads = 1`, run the unchanged loop on the
  calling thread.
- **Model/workload:** as PERF-001 (`models/yolox-nano/yolox_nano.fmpk`, 416x416, the three pinned
  conformance inputs, graph execution only).
- **Command (primary):**
  `RCH_REQUIRE_REMOTE=1 rch exec --base 0ce4d65 --clean-overlay --no-overlay -- cargo run --release --locked --offline --example yolox_profile -p fss-reference -- 7 --threads 1,2,4,8`
- **Host (primary):** rch worker `ovh-a`, `AMD Ryzen 7 5800X 8-Core Processor`, 16 logical CPUs,
  shared; `/proc/loadavg` 1-minute load **70–84** throughout (the host was oversubscribed about
  5x). Release profile, default x86-64 target. One process; the thread counts ran back to back.
- **Samples:** 7 warm runs per case per thread count (21 per count); one scalar run per case as
  the bit-identity oracle.

| Threads | per-case medians (ms) | median of 21 (ms) | min (ms) | process CPU / wall | max threads used by a step |
|---|---|---|---|---|---|
| 1 | 221.4 / 226.0 / 237.9 | 233.8 | 210.6 | 0.89 | 1 |
| 2 | 223.0 / 219.5 / 221.0 | 219.7 | 198.5 | 0.97 | 2 |
| 4 | 243.5 / 223.4 / 235.2 | 232.0 | 207.8 | 0.92 | 4 |
| 8 | 233.1 / 223.2 / 246.0 | 231.0 | 211.0 | 0.91 | 4 |

**Result: no wall-time speedup was measured.** Every difference is inside the spread of the
single-thread samples. Process CPU per wall time below 1.0 shows that this process did not
get even one full CPU. Scoped spawn latency on this host (`spawn_latency_us`, 200 spawns):
median 130 µs from spawn to thread start (max 19.6 ms); spawn plus join median 427 µs (max
20.0 ms). A split convolution step runs for about 1–20 ms, so each spawn costs a noticeable
fraction of the work it takes on.

**Other runs (same caveat, all on shared hosts under load):**

- `f2995fb` (2^21 floor), same command with `--base f2995fb`, `ovh-a`, load 62–63: medians
  214.1 / 228.4 / 258.4 / 272.2 ms for 1 / 2 / 4 / 8 threads, so more threads were slower.
- Working tree whose library matched `f2995fb` (only the profiler differed), plain
  `rch exec -- cargo run …`, worker `vmi1156319` (8 logical CPUs, load 6–9): medians
  184.6 / 361.0 / 419.8 / 369.9 ms. Process CPU per wall was 1.00 / 1.12 / 1.29 / 1.68 and total
  process CPU rose from 4.66 s to 15.5 s for the same 21 inferences. That is the overhead the
  2^23 floor removes.
- Supplementary run, not on rch: the rch-built `0ce4d65` example binary (same kernel generation
  `sha256:493514f6…`) executed on the local host (`AMD EPYC-Genoa Processor`, 16 logical CPUs,
  load 20–21): medians 171.7 / 172.3 / 169.0 / 167.2 ms for 1 / 2 / 4 / 8 threads, CPU/wall
  0.99 / 1.05 / 1.07 / 1.05, spawn start median 840 µs.

**Semantic equivalence:** `output_bits` digests are identical for every thread count and equal to
the scalar reference (`db5d26e8…`, `eb2d10df…`, `f4784387…`), and `bit_identical_outputs` is
`true` for 1, 2, 4 and 8 threads. In-tree certification: `optimized_executor/tests.rs`
(the seeded random-geometry generator of PERF-001 plus fused/uneven cases, threads
1, 2, 3, 4, 7 and 8, work floor disabled so that even tiny geometries split; 0 ULP) and
`tests/yolox_nano_conformance.rs::optimized_executor_is_bit_identical_for_every_thread_count`
(identical bits, output digest, inference identity, model digest, backend descriptor and
post-NMS detections for 1, 2, 3, 4, 7 and 8 threads).

**Memory:** peak live payload 4,849,024 bytes (1 thread) → 4,852,480 (2) → 4,859,392 (4 and 8);
scratch 27,648 → 44,032 bytes (one input panel per worker). Resident prepared bytes are unchanged
(7,280,600).

**Identity:** the thread count is not bound into the plan digest, the kernel labels, the model
digest, inference identities or receipts. It appears only in `OptimizedRunReport`
(`threads_requested`, `threads_used`). The kernel generation changed, as it does on every source
edit, and it is the same for every thread count.

**Decision:** multi-threading ships as an opt-in capability that is bit-identical by
construction (`fss-infer package-detect --threads N|auto`). The default stays 1 thread, because
no host available for this measurement showed a gain. Any speedup claim needs a measurement on an
uncontended host.

**Excluded / next:** a scoped worker set that lives for the whole inference would pay the spawn
cost once instead of per step, but the brief ruled out pools, so that needs an owner decision.
Other open items: a spatial (column-tile) partition for 1x1 convolutions, which avoids repacking
input panels per channel chunk, and threading the non-convolution steps (Slice, Concat, Add).

## PERF-003 — Verified custody chunks reused across sequential retained reads

- **Commit:** the `perf(retained)` commit carrying this entry (base `fb8441b`), measured on the
  working tree that commit records; release profile, default target (x86-64 baseline).
- **Host:** the session's cloud container, 4 logical CPUs, shared and loaded (load average
  2–3 during measurement); single-threaded decode. Numbers from other hosts are not comparable.
- **Workload:** FFmpeg `testsrc2` 1920x1080, 30 fps, libx264 High (`keyint=60:bframes=2`, 6 Mb/s),
  20 s, 600 access units, 15,030,081 bytes Annex-B: one 16 MiB custody chunk. Imported with
  `fss-file import --media-format annexb` (default limits), then
  `fss-file decode --segment 0 --segment-count 60 --interpretation ycbcr` (first 60 frames,
  every frame's luma/I420/Cb/Cr digests and receipt). One cold-process wall-clock sample per
  arm; the effect (3x) far exceeds the run-to-run spread observed on this host (< 10%).

| Arm | 60 frames (s) | per frame (ms) |
|---|---|---|
| baseline (`fb8441b`, every segment read re-reads and re-hashes its whole chunk) | 16.46 | 274 |
| candidate (`VerifiedChunkCache`, each chunk verified once per sequential range) | 5.54 | 92 |

**Context (same host):** the codec alone (`fss-codec-h264` `decode_annex_b`, no custody or
digests) decodes this content at 18.4 fps (54 ms/frame; H.265 Main equivalent 25.0 fps); a
1.5 MB import of the same picture size decoded at 116 ms/frame before the change, since its whole
chunk is only 1.5 MB. First-party SHA-256 measured about 200 MB/s here, so the four per-frame
receipt digests (about 6.2 MB) cost about 28 ms/frame; an unrolled SHA-256 variant gained only
5–25% within noise and was not adopted.

**Semantic equivalence:** identical `frame_i420_sha256` lines for all 60 frames between the two
arms. Every chunk is still digest- and length-verified before first use and every assembled
segment is still checked against its own digest; the cache is keyed by verified chunk digest and
length, so it can never serve other bytes (unit test
`a_verified_chunk_cache_reads_each_chunk_once_and_never_substitutes_bytes`). Root availability
and authority are still rechecked on every read.

**Changed cost terms:** SHA-256 over custody chunks per range drops from
`segments x chunk_bytes` to `touched chunks x chunk_bytes`; memory rises by at most two chunks
(32 MiB at the 16 MiB default) per open sequential reader. Applied to the H.264/H.265 range
decoders and the MJPEG readers of watch, the detector cascade, sensor health, package detection
and tolerant decode. Single-segment reads are unchanged.

**Excluded:** decoder parallelism, SIMD and SHA-256 changes. The remaining per-frame overhead
(receipt digests, privacy masking, I420 assembly, per-read authority revalidation) is not
optimized here.

**Finding (not changed):** a callgrind profile of `fss-file decode --segment-count 10` on this
import attributes 73% of all instructions to SHA-256. About 22% is `ReferenceDeployment::open`:
publication recovery (`LocalRootPublisher::recover` -> `check_reference` -> `StagingSpool::verify`)
re-reads and re-hashes every object a published root references, twice, so every CLI invocation
costs time proportional to all retained bytes (about 100 s per invocation for 10 GB at the
measured 200 MB/s). A further 29% is spool reads verifying the durable object format, which the
chunk check then hashes again. Changing verify-on-open or the double check alters the root-last
publication and custody contracts, so it is recorded here for the owners, not optimized.

## PERF-004 — H.264 inter prediction from a per-block reference window

- **Commit:** the `perf(retained)` commit carrying this entry (base `fb8441b`).
- **Host and workload:** as PERF-003. Codec-only harness: `fss_codec_h264::Decoder::decode_annex_b`
  plus `finish` over FFmpeg `testsrc2` 1920x1080 libx264 High (`keyint=60:bframes=2:threads=1`):
  a 2 s, 60-frame stream for wall time and a 0.5 s, 15-frame stream for callgrind.
- **Change:** `predict_4x4` evaluated every quarter-sample luma value with per-tap clamped,
  bounds-checked reads (up to 36 six-tap intermediates per centre sample). It now loads the
  block's 9x9 reference window once (direct row copies inside the picture, 8-228/8-229 clamping
  only near edges), evaluates the same 8.4.2.2.1 formulas from it with one shared grid of
  horizontal intermediates for the centre positions, copies full-sample vectors directly, and
  reads chroma from a 3x3 window.

| Metric | before | after |
|---|---|---|
| callgrind instructions, 15 frames | 7,143,087,136 | 4,314,563,563 (-40%) |
| codec wall time, 60 frames (best of 3, loaded host) | 18.4 fps | 27.3 fps |

**Semantic equivalence:** bit-exact. The per-sample clamped predictor stays in the crate as the
test-only reference (`predict_block`), and `windowed_prediction_equals_the_per_sample_reference`
compares the two on 12,000 random pictures, positions and vectors (including blocks far outside
the picture); all FFmpeg-oracle conformance fixtures still match frame for frame.

**Excluded:** a line-at-once deblocking rewrite measured 3% more instructions and was not kept;
partition-level (8x8/16x16) prediction, SIMD and threading are not attempted. End-to-end retained
decode is dominated by SHA-256 (PERF-003 finding), so its wall time moved only from 5.54 s to
5.39 s for the PERF-003 workload.

## PERF-005 — H.265 inter interpolation from a per-block reference window

- **Commit:** the `perf(h265)` commit carrying this entry (base `11e941d`).
- **Host and workload:** as PERF-004, with FFmpeg `testsrc2` 1920x1080 libx265 Main
  (`keyint=60:bframes=2:pools=1:frame-threads=1`): 2 s / 60 frames for wall time, 0.5 s / 15
  frames for callgrind, decoded by `fss_codec_h265::Decoder::decode_nal` over every NAL.
- **Change:** `interpolate` read every filter tap through a clamped closure and selected the
  luma/chroma coefficient table per tap. It now loads the `(w + taps - 1) x (h + taps - 1)`
  reference window once per block (row copies inside the picture, 8-228/8-229 clamping only near
  edges), filters with the selected coefficient rows by plain indexed loops, and applies the
  block's weighted-prediction rule (8.5.3.3.4) through one monomorphised per-block store instead
  of a per-sample dispatch.

| Metric | before | after |
|---|---|---|
| callgrind instructions, 15 frames | 6,423,933,962 | 5,345,121,393 (-17%) |
| codec wall time, 60 frames (loaded host, best of 3) | 25.0 fps | 26.7 fps |

**Semantic equivalence:** bit-exact. The previous interpolation stays as the test-only
`interpolate_reference`; `windowed_interpolation_equals_the_per_sample_reference` compares them on
6,000 random planes, block shapes and vectors (including blocks far outside the picture), and all
FFmpeg-oracle conformance fixtures still match.

**Remaining profile:** inter prediction is 44% of instructions (inherently the 8-tap separable
filter in scalar 32-bit arithmetic; the x86-64 baseline has no 32-bit SIMD multiply), SAO 20%,
inverse transform 9%. Not attempted: SIMD, i16 first-pass arithmetic, partition scratch reuse.

## PERF-006 — H.265 SAO interior fast path and row-wise inverse transform

- **Commit:** the `perf(h265)` commit carrying this entry; host and workload as PERF-005.
- **Changes:** (1) SAO (8.7.3): a sample whose four neighbours lie inside its own CTB, in a CTB
  with no PCM or transquant-bypass block, skips the per-sample `no_filter`, picture-boundary and
  slice-boundary checks, which cannot apply there (one CTB belongs to one slice and lies inside
  the picture); every other sample takes the unchanged full path. (2) The 1-D inverse transform
  accumulates each nonzero input's matrix row into exact `i64` sums instead of re-scanning all
  inputs per output; integer addition makes the order irrelevant and the bound
  (|coefficient| <= 90, |input| < 2^31, n <= 32) excludes overflow.

| Metric | before (PERF-005) | after |
|---|---|---|
| callgrind instructions, 15 frames | 5,345,121,393 | 4,683,435,588 (-12%; -27% vs 6,423,933,962 before PERF-005) |

**Semantic equivalence:** bit-exact. The previous SAO stays as the test-only `apply_reference`;
`fast_sao_equals_the_per_sample_reference` compares them on 300 random pictures with random SAO
types, offsets, classes and band positions, random raster slice layouts with and without
cross-slice filtering, and random unfiltered blocks. All FFmpeg-oracle conformance fixtures
(SAO, slices, PCM, lossless) still match.

## PERF-007 — Lazily sealed H.264/H.265 frame receipts

- **Commit:** the `perf(decode)` commit carrying this entry (base `41fa9a0`); host as PERF-003.
- **Workload:** FFmpeg `color` 1920x1080 30 fps background with one 160x160 white box moving
  80 px/s (libx264 High, `keyint=60:bframes=2`, MP4, 300 frames), imported with a capture hint;
  `fss-event watch --stream-dwell --segment-count 150 --interpretation ycbcr` over the whole
  frame. Release builds of the base and candidate, alternated twice each.
- **Change:** every decoded inter-coded picture computed four SHA-256 receipt digests (luma,
  packed I420 built by concatenating the planes, Cb, Cr), about 6 MB hashed per 1080p frame,
  although streaming analysis, watch, sensor health, tolerant decode and skipped cascade frames
  never read them. The frame now keeps the receipt's other fields and seals the digests from
  its served planes on the first `receipt()` call (`OnceLock`; I420 through a streaming hasher,
  no concatenation). Cheap `segment_index`, `capsule`, `capsule_digest` and `dimensions`
  accessors serve those consumers.

| Arm | 150 frames (s), two runs |
|---|---|
| base | 14.64, 14.60 |
| candidate | 9.40, 9.82 (-35%) |

**Semantic equivalence:** identical `analysis_digest`; the sealed receipt is a pure function of
the frame, so receipt bytes are unchanged wherever they are read (all FFmpeg-oracle digest
tests read sealed receipts). Frame equality compares the receipt fields and planes, never the
sealing state (`lazily_sealed_receipts_are_identical_and_do_not_affect_equality`).
`fss-file decode`, which prints every digest, is unchanged in cost.
