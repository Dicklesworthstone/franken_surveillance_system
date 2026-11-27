# fss-graph-integer

Standalone no-dependency exact-integer graph algorithms. This package has no `fss-core` dependency and is intentionally outside the FSS workspace so downstream consumers can use it without the surveillance dependency tree.

`max_flow_min_cut` implements a deterministic, explicitly budgeted, checked-`i128` directed maximum-flow/min-cut solver. The result includes per-arc flows, source partition, cut arcs, residual scan count, and augmentation count. Negative capacities and overflow fail closed. The graph and capacity units are supplied by the caller; the API never mixes or converts units.

Run `cargo test --manifest-path standalone/fss-graph-integer/Cargo.toml` for focused tests. This is a partial step toward repository issue #2; it does not extract or requalify the existing certified `fss-graph-algorithms` crate, add signed assignment or temporal reachability, or claim publishing/tagging.

The assignment module supplies a bounded deterministic Hungarian minimum-cost perfect matching over complete square signed-i128 cost matrices. Its result includes checked primal and dual optimality witnesses. Sparse and rectangular policies, and parity with the existing registered FSS algorithm, remain separate work.
