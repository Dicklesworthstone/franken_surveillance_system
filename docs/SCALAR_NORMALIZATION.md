# Scalar normalization execution

The existing `ScalarExecutor::run` now executes the frozen Model IR v1 `LayerNorm`
and `RMSNorm` operators. This is the same executor used by retained inference,
not a parallel model runtime. No operator table, model serialization or activation
rule changes, and no dependency is added.

Normalization covers the trailing `normalized_shape`, inferred from the weight
shape when supplied, otherwise the final input dimension. The frozen validator
owns shape/dtype/generation and affine-flag admission. Missing optional weights
mean identity scale and missing bias means zero; disabled affine flags cannot
silently consume provided parameter tensors. RMSNorm has no bias input.

LayerNorm uses population variance: `mean((x - mean(x))^2)`, not a sample variance
or `mean(x*x) - mean(x)^2`. RMSNorm uses `mean(x*x)` without subtracting a mean.
Both divide by `sqrt(statistic + epsilon)`; the default epsilon is the frozen
v1 value `1e-5`. Epsilon remains binary64, including positive values outside the
binary32 range. Mean, squared deviations and affine operations use ordered
binary64 arithmetic, then round each final value to binary32. The square root
is Rust's IEEE-754 correctly rounded `f64::sqrt` primitive. No exp, pow, external
math framework, fused multiply-add or parallel reduction is introduced.

A nonfinite source sample makes its entire reduction row canonical quiet NaN
(`0x7fc00000`), without contaminating other rows. Nonfinite affine results follow
IEEE arithmetic with canonicalized NaNs. This is numeric propagation, not a
successful recorded inference: the retained inference owner rejects nonfinite
outputs. Empty outputs perform no reduction and never divide by an empty axis.

Whole-graph resource preflight charges `8*N + 4*R` reference work units, where
N is the number of output elements and R the number of nonempty reduction rows.
The same conservative schedule is used for both operators, within the existing
`max_macs` reference-work bucket. Empty outputs charge zero. All products are
checked. Every reduction/affine pass polls owner cancellation at most 1024 samples
apart; no partial tensor is returned. Temporary input/parameter vectors are
additional to the existing cumulative tensor-output accounting, not an assertion
about whole-process peak memory.

The complete scalar file is included in recorded execution profiles. This change
therefore creates a new execution profile: old runs need their compatible binary
or an explicit rerun, not relabeling or mutation of retained history.

Run `cargo test -p fss-reference --test scalar_normalization_execution` on the
pinned toolchain. Tests cover independent rows, population variance, RMS, affine
parameters, inferred/explicit multi-axis shape, empty tensors, extreme finite
values, nonfinite propagation, epsilon range, invalid metadata, exact budgets,
cancellation and a LayerNorm–MatMul–RMSNorm graph. Tests were added but not run in
the editing environment. This is execution functionality, not trained-model
admission, detection quality, or release qualification.
