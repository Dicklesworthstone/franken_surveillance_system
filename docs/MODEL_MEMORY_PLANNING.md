# Model memory planning

`fss_model_ir::MemoryPlan` implements the materializing liveness portion of
FSS-140 (shape/layout/liveness scratch planning, `fss-x4a.14.11`). It uses the
existing frozen IR validator, inferred shapes/dtypes and canonical node order.
It does not activate a model, add an operator, execute inference or change a
source/effect authority boundary.

A plan retains every graph input for the whole invocation: caller-owned weights
are not freed merely because their environment entries are removed. Every node
output is materialized before last-use inputs are released. Branches, repeated
references, graph outputs that feed later nodes, unused outputs, scalar tensors
and zero-element shapes all have explicit lifetimes. Graph outputs are pinned.
No dead-code elimination hides a failing operator or changes work accounting.
View-like operators are conservatively modeled as copies, not in-place aliases.

The plan reports logical input bytes, cumulative tensor bytes, output bytes,
peak simultaneously live tensor bytes, and complete per-node production/release
boundaries. `peak_with_scratch` adds a backend's extra scratch at the corresponding
node, rather than adding unrelated maxima. Backend scratch, actual backing storage
of strided input views, allocator overhead and process RSS are not established by
this IR-only plan. No reusable arena or accelerator qualification is claimed.

Plan identity binds the exact graph and materializing schedule. All fields are
private and constructed from validated inference. Caller admission ceilings are
not semantic identity. Limits are capped at 4,096 nodes, 16,384 values, 65,536
references and 4 MiB of logical metadata before graph validation. Every individual
tensor must fit the existing tensor storage ceiling. Arithmetic is checked and
planning has cooperative cancellation; the shared validator itself is bounded
but not internally interruptible.

Public regression target:

```sh
cargo test -p fss-model-ir --test memory_plan_contract --locked --offline
```

The tests include a 1,000-DAG independent future-consumer oracle, branch and output
retention, materialization overlap, byte/scratch bounds, canonical ordering,
malformed graphs and cancellation at every planning checkpoint. Rust compilation,
test execution, rustfmt and Clippy were unavailable in the editing environment.
Independent algorithm checks do not replace the repository's native qualification.
The aggregate FSS-140 bead and model release gates remain open.

## Executable scalar plans

`fss_reference::planned_scalar::CompiledScalarPlan` now executes the schedule
using the existing `ScalarExecutor` kernels. `ScalarExecutor::plan_memory` is
the reusable entry point; `ScalarExecutor::run_peak` compiles and executes once. It compiles validated, canonical
one-node IR programs once, admits the whole graph's work and peak/scratch payload
before the first kernel, then executes those programs in the original order.
The backend's shape, generation, output count, work and cumulative byte accounting
are checked against the compiled contract at each node. Node argument Arc clones
are dropped before last-use values are removed. All declared outputs remain
pinned and are returned together; dead nodes still execute and can refuse.

There is no parallel implementation of convolution, activations, normalization,
layout, matrix arithmetic or integer embedding. Per-node IR validation adds
reference-path overhead; this is not a fused/arena/optimized inference engine.
The existing scalar entry point and its cumulative budget semantics are unchanged.
Existing camera and recorded-model execution defaults are not silently switched.

```rust,ignore
use fss_model_ir::MemoryPlanLimits;
use fss_reference::ScalarExecCx;
use fss_reference::planned_scalar::{CompiledScalarPlan, PeakExecBudget};

let cx = ScalarExecCx::new();
let compiled = CompiledScalarPlan::compile(&graph, MemoryPlanLimits::default(), &cx)?;
let result = compiled.run(
    &inputs,
    PeakExecBudget::new(100_000_000, 64 * 1024 * 1024, 16 * 1024 * 1024),
    &cx,
)?;
let (execution, memory_receipt) = result.into_parts();
```

The immutable compiled plan can be reused with new, exactly compatible inputs.
`minimum_requirements()` describes tightly backed inputs, not permission to ignore
larger backing buffers. Run admission adds the excess of each actual input's full
storage over its logical payload. Shared backing is conservatively counted per
named binding. Unknown, duplicate, missing, wrong-shape, wrong-dtype and
wrong-generation inputs are refused before any kernel.

Scratch is an additional, conservative payload bound for each existing kernel:
logical input copies plus the output vector, while the new output Tensor is
already charged to live memory. Softmax additionally reserves its axis buffer,
even when an outer dimension is zero. Integer embedding instead reads strided
indices/table values directly and transfers its one output byte buffer into the
Tensor, so it needs no additional payload scratch. Small metadata structures,
allocator capacity/overhead and process RSS are explicitly outside this measure;
planning metadata has its own hard limits. Allocation reuse is by normal Rust
lifetime/allocator behavior, not an FSS-owned reusable arena.

For the authored 100-layer, four-element ReLU regression, cumulative tensor volume
is 1,616 bytes, the maximum live tensor payload is 48 bytes, and the conservative
live-plus-scratch reservation is 80 bytes. These are exact model/test expectations,
not measured production memory or executed Rust benchmark results.

`ScalarMemoryReceipt` reports the source graph, compiled plan, source-implementation
profile, required work, actual-input backing reservation, verified environment
high-water mark, maximum scratch, cumulative tensor volume and released value
count. Its digest is a resource witness, not a claim that particular input/output
contents have custody or model quality. Existing enclosing model/source receipts
remain responsible for input/output identity, privacy and authority.

The plan profile binds this driver, its budget model, the unchanged scalar backend,
the liveness implementation and tensor/storage/view/dtype/shape/stride source.
No old model generation or recorded run is relabeled as the new execution profile.
The whole result is withheld on cancellation, late invalid embedding indices or
backend disagreement. A refusal does not mutate the reusable plan or caller inputs.

Additional regression target:

```sh
cargo test -p fss-reference --test planned_scalar_contract --locked --offline
```

Eighteen authored contracts cover all 22 frozen operator families, a convolution /
residual / pooling pipeline, 512 generated branched graphs, exact budget edges,
strided and oversized-backed inputs, repeated operands, pass-through outputs and
duplicate-output refusal, zero-work reshape, zero-element softmax scratch, whole-graph
integer admission, cancellation and late kernel refusal. These Rust tests have
NOT been compiled or executed in this editing environment. Aggregate FSS-140
acceptance still needs native execution/qualification, allocator arena/reuse,
optimized dispatch and integration of the new explicit profile into public
operator/camera/recorded-model workflows.
