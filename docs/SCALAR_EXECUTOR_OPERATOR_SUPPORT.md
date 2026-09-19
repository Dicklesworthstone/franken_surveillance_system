# Scalar executor operator support

The existing `ScalarExecutor::run` now executes five additional operators already present in
frozen Model IR v1: Transpose, Squeeze, Unsqueeze, Concat and Slice. No graph dialect,
operator ID, attribute schema, model activation rule, foreign runtime or dependency is added.
The recorded inference and recording-analysis paths use this same executor automatically.

## Layout semantics

Transpose implements the exact supplied permutation, defaulting to reversed axes. Squeeze
removes specified singleton axes, or all singleton axes when the attribute is absent;
an explicitly empty axes list removes none. Unsqueeze inserts singleton axes at positions
in the final output rank. Concat preserves input order and repeated input references and
supports the frozen IR's negative-axis convention. Slice follows the existing strict IR:
nonnegative starts/ends/axes, positive steps, bounded ranges, no clipping, negative-index
interpretation or hidden padding. Layout kernels preserve element bits rather than doing
arithmetic on copied values. Empty outputs expose no fabricated data.

The graph validator remains the authority for dimensions, generations and attributes. The
executor still requires F32 inputs and outputs and validates the entire graph before any
kernel executes. Every node output remains part of the whole-graph tensor-byte preflight.
New kernels check cancellation at entry, in bounded copy/gather chunks and before returning.
The executor also checks after the final node and before exposing graph outputs.

## Work accounting and compatibility

The existing `max_macs` bucket already counts reference work for non-MAC operations such as
pooling comparisons and activations. Layout work is explicit in that same bucket: Transpose
and Slice charge `output_elements * (output_rank + 1)`; Squeeze, Unsqueeze and Concat charge
one unit per output element. Products and cumulative charges are checked for overflow.
These are deterministic reference-work units, not measured hardware MACs, time or energy.
Tensor-byte accounting is not a promise about total process peak memory: temporary vectors,
serialized evidence and graph metadata are additional, as in the existing executor.

Recorded inference fingerprints the complete scalar source file. Consequently this code
change produces a different execution profile and new run identities. Old-profile runs are
not silently relabeled as reproducible by this implementation; use their retained compatible
implementation or explicitly rerun the frozen model under the new profile.

## Validation and remaining boundary

`cargo test -p fss-reference --test scalar_layout_execution` covers exact values, every rank-3
permutation, scalar and empty tensors, bit-preserving singleton-axis changes, repeated/empty
Concat inputs, strided Slice, huge singleton steps, invalid metadata, exact work/byte boundaries,
cancellation, dtype/generation refusals and a graph composing all five operators with MatMul.
The independent Python layout reference matched NumPy on 9,000 generated comparisons.
The Rust tests were added but not executed in the editing environment, which has no Rust
compiler. Local pinned-toolchain qualification remains required; this is not model admission
or a detector-quality claim. GELU, SiLU, Tanh, LayerNorm, RMSNorm and Embedding remain refused
by this executor at this increment.
