# Scalar executor operator support

The existing `ScalarExecutor::run` executes 21 of the 22 frozen Model IR v1
operators on its F32 path. The original convolution, pooling, matrix arithmetic,
reshape, ReLU, sigmoid and softmax kernels are joined by Transpose, Squeeze,
Unsqueeze, Concat, Slice, LayerNorm, RMSNorm, SiLU, Tanh and both GELU modes.
Embedding remains unsupported; integer-index semantics are not guessed through
F32 inputs. No graph dialect, operator ID, attribute schema, model activation rule,
foreign runtime or dependency is added. Retained inference uses this same executor.

The numeric contracts for the new kernels are in `SCALAR_NORMALIZATION.md` and
`SCALAR_ACTIVATIONS.md`. Their tests exercise the public executor and composed
model graphs, including restart and replay through retained JPEG inference.

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

Recorded inference fingerprints the complete scalar source file. Consequently changes to
this implementation produce a different execution profile and new run identities. Old-profile
runs are not silently relabeled as reproducible by this implementation; use their retained
compatible implementation or explicitly rerun the frozen model under the new profile.

## Validation and remaining boundary

Run the `scalar_layout_execution`, `scalar_normalization_execution` and
`scalar_activation_execution` test targets in `fss-reference` on the pinned toolchain.
They cover numerical and layout values, scalar/empty tensors, strict metadata,
work/byte boundaries, cancellation, dtype/generation isolation and composed graphs.
Independent Python algorithm checks are documented separately from Rust execution.
The Rust tests were added but not executed in the editing environment, which has no
Rust compiler. Local qualification remains required; operator coverage alone is not
trained-model admission, a detector-quality claim or a production runtime certificate.
