# `MOD-FSS-ACTIVITY-001` — first-party activity model (`model:fss-activity:v1`)

`fss_activity_v1.fmpk` is an immutable `FMPK` v1 model package (fss-2h5zq.49). Its builder is
`build_activity_package` in `crates/fss-reference/src/executor_activity_package.rs`, and the
committed bytes must equal the builder's output exactly
(`crates/fss-reference/tests/activity_model_contract.rs`). The whole-archive SHA-256 is pinned as
`ACTIVITY_PACKAGE_V1_SHA256` in the same module.

| Artifact | Content |
|---|---|
| manifest | `MOD-FSS-ACTIVITY-001`, `model:fss-activity:v1`, `cal:uncalibrated:none`, license `LicenseRef-FSS-First-Party` with a text digest |
| `graph.fssir` | canonical FSS Model IR: `MatMul(Reshape((frame - reference)^2, [1, 1024]), mean_weights)` |
| `weights.safetensors` | `mean_weights`, `[1024, 1]` F32, every entry `2^-10` (a literal constant; no training) |
| `activity_spec.bin` | `fss.executor_activity_package_spec.v1`: 32x32 unit luma, nearest stretch resize, port names, label `unknown_activity:pixel_change:uncalibrated` |
| `LICENSE` | first-party license text |

The score is the mean squared change in unit luma between a frame and an earlier reference frame of
the same recording. It is an uncalibrated pixel-change measure. It is not a probability or a
person, intrusion or object detector. Nothing is activated: receipts keep the
`activationGeneration` sentinel and stay reference-only.

Loading goes only through `VerifiedActivityPackage::load`. That path checks, in order: the pinned
archive digest, the archive structure and per-artifact digests, the model id and generation, the
license policy (surveillance-monitoring default plus the explicit first-party identity), the
artifact bindings, the exact spec, the graph digest against the in-tree definition, and the literal
weights.

A changed graph, weights or spec is a new model and needs a new generation and a new package. Do
not rebuild this file in place. Regenerating it is legitimate only when the builder changes
deliberately; in that case trace the change, and the contract test prints the rebuilt digest and
bytes.
