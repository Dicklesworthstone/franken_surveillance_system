# Global cross-camera association

The `fss-reference::ingest::cross_camera` API now solves the complete two-camera
assignment instead of accepting locally best pairs greedily. This implements the
numeric association capability requested in `fss-nfae2`; it does not close the
broader calibration, identity, event-publication, or qualification contracts.

## Example: the match greedy assignment loses

For simultaneous one-dimensional observations, use a distance gate of 1.5 and a
minimum confidence of 0.1. Left tracks are at 0 and 1; right tracks are at 0.2 and
-0.6. The highest individual score links 0 to 0.2, stranding the second left
track. Global assignment instead links 0 to -0.6 and 1 to 0.2. Their summed score
is about 1.066667, better than the greedy result's 0.866667.

The numerical solver is the existing bounded Hungarian implementation in
`fss-twin::image_tracking`. Its new `assignment::solve` interface validates a
rectangular matrix of finite optional integer costs and delegates to the same
implementation. Existing image-tracker code, costs, receipts and work charges
are unchanged; only a child-module declaration was added to its source file.

## Complete result, not forced identity

`associate_detailed(config, margin_units, left, right, budget)` returns:

- Both original inputs in stable camera-local track order and their exact gates.
- Every Cartesian candidate with its gate exclusion or original/quantized score.
- Stable matched, unresolved, or no-candidate dispositions for every observation.
- A complete competing assignment for each ambiguous selected pair, including
  explicit unmatched choices. Stable pairs remain usable in another component.

`report.stable_pairs(budget)` copies only the resolved conditional pairs.
Neither an accepted pair nor a no-candidate result is person identity, independent
corroboration, an absence certificate, or permission to generate an alert. Clock
alignment and positions in a common calibrated ground plane are caller inputs;
this point-observation API does not pretend to certify their uncertainty.

The compatibility `associate(config, left, right)` API now delegates to this
path. It returns `AmbiguousAssignment` rather than flattening unresolved ties
into arbitrary pairs or an empty success. Use the detailed report to retain both
partial stable matches and alternatives. Input struct fields remain compatible;
output pairs are ordered by left track ID rather than descending individual score.

## Objective and bounds

One confidence point is 1,000,000 integer units. Each admitted score is rounded
to nearest; each left row has its own unmatched option with zero score. Minimizing
`left_count * scale - selected_score_sum` maximizes total quantized score, not
cardinality. A complete exclusion solve for every selected real edge proves
whether that edge is stable within the declared global margin.

The effective margin includes one unit per left row to cover the difference of
two rounded score sums. The report exposes both the requested and effective
margins. Quantization therefore cannot silently resolve an underlying-score tie.
A gate-boundary zero-score pair remains ambiguous with leaving it unmatched.

Both inputs are bounded at 64 observations, each from one camera, with unique
nonzero track IDs and camera identities of at most 256 UTF-8 bytes. Non-finite
coordinates, invalid identities, mixed cameras, duplicate tracks, or oversized
inputs are refused, never truncated. Timestamp distance uses unsigned `abs_diff`;
spatial distance uses `hypot` to avoid intermediate square overflow/underflow.

All solver, candidate, copying and sorting work is charged to the caller's
`WorkBudget`, which supports cooperative cancellation. Errors expose no partial
report. The compatibility wrapper uses a finite 100,000,000-unit budget; a
conservative 64-by-64 worst-case bound for this implementation is below 36 million
units. No runtime, dependency, network operation, or effect authority is added.

## Verification

Added 13 public perception integration tests and four shared-solver tests. All
eight original association scenarios remain, with their assertions retained or
strengthened and fallible test functions replacing `unwrap`. The shared tests
include all 6,561 two-row matrices over zero, positive and forbidden edges, each
with three exclusion choices, checked against exhaustive injective assignments.

Independent Python transcriptions executed 19,683 exhaustive solver checks,
1,000 randomized solver checks and 206 perception/oracle cases. The original
image-tracker blob was hash-verified; only the module hook changes its bytes.
These checks are not execution of Rust. Rust compilation, the new/existing Rust
tests, rustfmt, Clippy and native qualification were NOT RUN because the authoring
environment has no Rust toolchain or rch. No bead or gate is promoted.

On the pinned native toolchain, run:

```sh
cargo test -p fss-twin --lib image_tracking
cargo test -p fss-reference --lib ingest::cross_camera
cargo test -p fss-reference --test cross_camera_global_contract
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
```
