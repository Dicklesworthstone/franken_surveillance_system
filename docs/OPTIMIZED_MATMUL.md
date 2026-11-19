# Bounded tiled native MatMul

## Behavior

The optimized CPU executor prepares nonempty rank-two-or-higher F32 MatMul
operators as `matmul.tiles4x8.v1`. It supports both runtime operands, either or
both constant operands, and right-aligned broadcasting across all native batch
dimensions. A vector imported from ONNX reaches this path after the importer's
explicit vector-to-matrix reshapes.

The kernel visits four output rows and eight output columns together. Those 32
accumulators are independent: every output starts at positive zero and consumes
its reduction dimension in increasing order using the reference multiply/add
sequence. It introduces no reduction reassociation, explicit fused multiply-add,
padding multiplication, foreign library or worker thread. Partial tiles evaluate
only valid output cells. Empty dimensions retain the existing scalar behavior.

Preparation checks complete shape products and computes broadcast strides once.
Execution retains the existing graph binding validation, cumulative MAC and
logical tensor-byte budgets, liveness schedule and output publication behavior.
Cancellation is checked before work, after bounded chunks of at most 256
reduction terms per output cell, and before success. An error returns no graph
outputs. The stack accumulator payload is 128 bytes and participates in the
scratch report; logical tensor-byte accounting remains comparable to scalar
execution. Scratch reporting is payload accounting, not measured process RSS.

The optimized kernel-generation digest includes this source and its row/column
tile dimensions. Native graph bytes, model parameters, operator identifiers and
the scalar implementation remain unchanged. Existing model/backend evidence must
still bind the actual kernel-generation identity.

## Regression cases and measurement

Eight ordinary authored tests cover uneven row/column/reduction dimensions,
broadcasts through rank eight, all constant/runtime operand combinations,
independent expected batch values, shared input aliases, empty shapes, exact
budgets, cancellation inside a long single-output reduction, and malformed
payload lengths. Differential checks use the actual production scalar and
optimized executors. Non-NaN results compare exact F32 bits, including signed
zero; NaN classification and position compare without claiming a portable NaN
payload contract.

The existing focused target includes both production executor modules:

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-model-ir --test onnx_attention_execution optimized_executor::matmul
```

One ignored experiment runs scalar and optimized arms in the same executable,
on identical inputs, with one warmup and seven alternating measurements. It emits
each observation, preparation time, output digest, operation/byte counts, scratch
and kernel-generation identity. Cases include projections, batched attention,
broadcast projections and a small one-row product. Use a release build:

```sh
cargo +nightly-2026-08-31 test --release --locked --offline -p fss-model-ir --test onnx_attention_execution profile_matmul_same_binary -- --ignored --nocapture
```

**2026-11-16 verification boundary:** the implementation and tests received
independent source/API review. The execution environment became unavailable after
baseline test compilation was killed for memory use. The changed code has not
been compiled, formatted by rustfmt or executed in this session. No measured
speedup, runtime equivalence certificate, release qualification or trained-model
quality claim follows from this source checkpoint. Execute the differential
suite before relying on it, and retain same-binary observations before making
a performance claim.

This advances FSS-142 (`fss-x4a.14.13`) and FSS-139
(`fss-x4a.14.10`). Those broader Beads remain open.
