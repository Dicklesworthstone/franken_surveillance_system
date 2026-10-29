# Calibrated class advice for whole-recording dwell

`fss-event watch --stream-dwell` can now consume an exact version-four fusion
profile after completing native dwell analysis. It uses the classifier observations
already attached to each qualifying episode. It performs no additional decoding or
model inference for fusion, and preserves the native analysis, episode inventory,
proposal digests and approval commands.

This is single-camera class advice about sampled dwell episodes. It does not prove
continuous occupancy, identify a person, corroborate an episode across cameras,
certify class absence, or authorize an alert. The existing native event stays
unclassified, indeterminate and Hold. The original explicit publication command
remains a separate operation.

## Prepare an exact complete analysis

Run the normal [whole-recording dwell](long_recording_dwell.md) command with an
explicit duration/gap rule and verified detector package. For example:

```sh
fss-event watch --root "$DEPLOYMENT" --site "$SITE" \
  --import-id "$IMPORT_ID" --interpretation gray --zone porch:0,0,48,32 \
  --stream-dwell --dwell-for-ns 20000000000 --dwell-max-gap-ns 100000000 \
  --dwell-min-observations 3 \
  --detector-package "$MODEL_FILE" --detector-digest "$MODEL_DIGEST" \
  --detector-max-inferences 8 --report-out native-dwell.json
```

Use a zone and explicit image interpretation that describe the actual retained
recording. Completed MJPEG, AVC and HEVC scans keep their existing admission,
capture-time, decoding, masking and display-order rules. AVC/HEVC use `ycbcr`
and their existing supported random-access ranges.

Preserve these fields from the complete report:

| Profile input | Native report field |
|---|---|
| `--analysis-digest` | `analysis_digest`, including the complete temporal scan and classifier outcome |
| `--analysis-roots` | Exactly one `analysis_root` |
| `--detector-recipe-digest` | `detector_cascade.recipe_digest`, including the verified model, selection policy and resource ceilings |

The smaller input `plan_digest`, a model archive digest, an entry-analysis root
and a checkpoint digest are not substitutes for these three identities. A change
to the dwell rule, source, classifier selection or execution allowance changes the
applicable complete analysis or recipe.

## Author a dwell-scoped profile

Use the existing [labelled-count authoring format](fusion_profile_cli.md). Counts,
class index, calibration generation and sensor applicability must describe the
intended detector/camera setting. Prior, decision policy, severity, look count and
evidence-clock value remain explicit owner inputs; authoring does not measure or
validate their real-world applicability.

```sh
fss-fusion-profile --scope dwell \
  --counts-digest "$COUNTS_DIGEST" --analysis-digest "$DWELL_ANALYSIS_DIGEST" \
  --detector-recipe-digest "$DETECTOR_RECIPE_DIGEST" \
  --analysis-roots "$DWELL_ANALYSIS_ROOT" < counts.json > dwell-profile.json
```

This produces `fss.event_class_fusion_profile.v4`, with the dedicated
`long_dwell_analysis_root` field and an empty `coverage_digests` set. Native
calibration intervals and semantic identities are reconstructed from the admitted
counts. Existing short, whole-watch and paired-entry profile formats remain
unchanged and cannot stand in for this temporal scope.

Repeat the same inputs with `--format report` to obtain the exact
`profile_file_digest`. It includes the profile command's trailing newline.
Use that file digest for `--fusion-digest`; the profile's semantic
`profile_digest` is a different identity.

## Request advice without changing the native event

Repeat the original analysis command, replace the output path with a fresh path
if exporting, and add:

```text
--fusion-profile dwell-profile.json --fusion-digest sha256:EXACT_FILE_DIGEST
```

The response contains the original native report plus
`calibrated_class_advice`, with schema `fss.event_class_fusion_report.v4`.
The advice binds the profile, complete analysis digest/root, detector recipe,
current authority basis, native proposal and original provenance for every
episode. It includes calibrated score intervals or explicit unknown/refused
observations, common-cause clusters, decision reasons and the existing
leave-one-cluster-out counterfactuals.

Repeated observations from the same sensor, model, package or pipeline do not
become independent confirmations. The shared fusion engine handles those common
causes. Budget-skipped, cascade-skipped, unsupported and unmatched observations
remain in the admitted evidence inventory; they are not silently converted to
negative observations. An empty episode inventory remains an empty result with
no class-absence certificate.

The output explicitly retains `effect_authority:false`,
`event_policy_changed:false`, `published:false`,
`class_absence_certified:false`, and `continuous_occupancy_certified:false`.
No calibrated advice replaces the original native event approval.

## Bounds, custody and refusal

The adapter admits at most the native owner's **32 dwell episodes** and one
shared allowance of **256 observations**, charging even episodes or observations
without calibrated support. It admits the entire inventory or refuses; it does
not emit a successful prefix. The existing complete JSON output limit is 2 MiB,
including the native report and advice at the CLI boundary. Profile input remains
bounded to 256 KiB.

The native owner validates the original deployment, site, principal and exact
authority basis; full source and capsule custody; current privacy; and any
requested whole-scan health gate before and after derived work. The CLI rechecks
those bindings before file export and again before stdout. These rules apply to
zero-candidate reports as well. Missing custody is never repaired from a cached
report. A health-blocked scan cannot produce calibrated advice.

Fusion cannot be combined with `--approve`, `--retain-health` or
`--retain-coverage`. Parsing and execution both enforce that rule. The explicit
`--dwell-step-frames` path can defer native trained classification until the complete temporal
boundary. An already complete checkpoint can then produce read-only calibrated advice; see
[completed-checkpoint advice](incremental_dwell.md#calibrated-advice-from-a-completed-checkpoint).
Use the complete response's `event_report` identities to author the profile, then append its
exact file pins to that response's continuation command. The original checkpoint is cold
reconstructed and the terminal classifier executes under the original remaining ceilings;
fusion consumes those class records without another inference pass. The invocation advances
zero new positions and appends no checkpoint or event. Partial prefixes have no complete
episode inventory and are refused even when one more step could finish them. Screened checkpoints
preserve the exact health policy, native finding fence and separate logical/restoration health
work. Findings or incomplete screening refuse both the terminal classifier and derived advice;
removing screening from a resumed request is an identity mismatch. The complete
progress wrapper contains `event_report.calibrated_class_advice` and is subject to the same
2 MiB output bound, including its final newline. Existing dwell publication, checkpoint
advancement, short sampled dwell, whole-recording entry fusion and paired-entry corroboration
keep their separate owners.

The real-process contracts cover late MJPEG episodes beyond frame 128, AVC and
HEVC display-order scans, exact native work and proposal preservation, skipped
inferences, empty inventory, changed source/recipe/rule/sensor pins, cross-scope
refusal before model I/O, health and native-budget refusal, output preflight, and
unchanged authority/effect journals. Synthetic scenes and the packaged model
exercise implementation contracts; they do not qualify deployment accuracy.
