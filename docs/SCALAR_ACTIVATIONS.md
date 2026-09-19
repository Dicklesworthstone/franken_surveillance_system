# Scalar nonlinear activation execution

The existing scalar Model IR executor now executes SiLU, Tanh and both GELU modes.
It uses the same frozen v1 operator IDs, attributes, graph validation, generation
checks, resource preflight and retained-inference pipeline. No pretrained model,
new execution runtime, dependency, or automatic activation policy is introduced.

SiLU evaluates `x / (1 + exp(-x))`. GELU's absent or `none` approximation setting
uses `x * Phi(x)`, where Phi is the standard normal cumulative distribution.
The separate `tanh` setting evaluates the registered approximation
`0.5*x*(1+tanh(sqrt(2/pi)*(x+0.044715*x^3)))`. These modes are not aliases. Unknown
modes are refused by the frozen IR validator before graph execution.

## Numeric implementation

The new private kernels use ordered binary64 arithmetic and round their result
once to binary32. They do not use host exp, tanh or erf functions. Exponentials
use ln(2) range reduction, a fixed 16-term residual series and an exact power-of-two
scale. GELU's normal tail uses a 20-term integrated-density series for |x| <= 1
and a 256-level Laplace continued fraction above 1. These are bounded numerical
evaluations of the selected formula, not a claim of exact transcendental bits.

Negative GELU and SiLU tails are computed directly, avoiding cancellation from
subtracting a nearly unit CDF and premature binary32 exponential underflow. Small
Tanh inputs preserve their values, including signed zero and subnormals. Very
large finite inputs saturate before forming powers or unsafe exponent ranges.
Both signed zeros are preserved by all three operators.

NaNs are canonicalized to `0x7fc00000`. Tanh maps negative/positive infinity to
-1/+1. SiLU and both GELU modes map positive infinity to itself and negative
infinity to canonical NaN. Nonfinite output is still refused by the existing
retained-inference publisher; propagation inside the numeric executor is not a
successful evidence-publication claim.

## Bounds and provenance

Whole-graph preflight charges 80 reference-work units per SiLU or Tanh element,
896 per default/none GELU element and 96 per tanh-GELU element. These conservative
bounds include the fixed scalar loops. The existing `max_macs` field carries
reference work for non-MAC operators as well; these are not CPU-time, energy or
hardware-throughput measurements. Empty outputs cost zero. Work products and
whole-graph tensor bytes remain checked before operator execution.

Owner cancellation is polled at entry, every 64 activation elements and before
returning a complete tensor. The continued fraction has a fixed inner bound.
No partial tensor is exposed. Temporary vectors remain additional to the existing
cumulative tensor-byte accounting; it is not total process peak-memory accounting.

The complete scalar source is already bound by recorded execution profiles. This
implementation therefore changes run identities without changing model or receipt
formats. Old runs require their compatible executable or an explicit rerun; they
are never silently relabeled as results from the new implementation.

## Tests and scope

`cargo test -p fss-reference --test scalar_activation_execution` includes independent
numeric goldens, formula-mode distinction, signed zeros, negative tails, extreme
finite values, nonfinite behavior, invalid metadata, scalar/empty shapes, exact
work/byte boundaries, cancellation, dtype/generation checks and a six-node
LayerNorm-MatMul-GELU-SiLU-RMSNorm-Tanh graph. A retained-JPEG integration test also
freezes a graph using all five new operators, publishes its result, deletes the
original file, restarts, replays and checks zero-MAC idempotent recovery.

A literal Python translation matched SciPy/NumPy rounded binary32 reference values
on 110,010 finite inputs for each of the four operator/mode combinations, within
two ULPs. This checks the numerical algorithm, not the compiled Rust. Rust tests,
formatting and full pinned-toolchain qualification were not run in the editing
environment. No global correctly-rounded guarantee, model quality or production
qualification is implied by these sampled checks.

With the normalization and layout additions, 21 of the 22 frozen operators have
an F32 execution path. Embedding remains explicitly unsupported: integer indices
must not be reinterpreted as float inputs to evade that boundary. Mixed-dtype
execution and trained-model admission remain separate work.
