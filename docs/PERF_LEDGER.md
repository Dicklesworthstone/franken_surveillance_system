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
