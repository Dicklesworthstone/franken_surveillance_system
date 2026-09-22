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
