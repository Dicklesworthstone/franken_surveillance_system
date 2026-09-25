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
