# Author source-bound fusion profiles without writing Rust

`fss-fusion-profile` turns explicit operator-labelled counts into the existing
whole-recording fusion profile formats. It reads only standard input and writes
only standard output/diagnostics. It never opens a deployment, model, original
recording, credential file or camera, and has no publication or effect capability.

Supply a complete `fss.event_class_fusion_counts.v1` document. Every prior, policy,
severity/consequence, look count and evidence-clock value is mandatory. Each sensor
binding includes `sensor`, `failure_domains` and a
`fss.score_calibration_counts.v1` table with its generation and bins (`lo_ppm`,
`true_positives`, `false_positives`). Use measured counts applicable to the selected
class and camera mode, not the synthetic test counts as deployment calibration.
The native calibration owner rebuilds every interval and calibration digest.

## Generate a profile

First preserve the complete native analysis report. Set `ANALYSIS` to its
`analysis_digest` and `RECIPE` to `detector_cascade.recipe_digest`, not to the
smaller input plan or the model archive. For a single-camera whole-recording
watch or sampled dwell, set `ROOTS` to `analysis_root`. For two-camera corroboration, join
`cameras[0].analysis_root` and `cameras[1].analysis_root` with a comma in native
camera order. Roots must be distinct, nonzero SHA-256 digests. The counts file
cannot override these separately supplied scope identities.

```sh
COUNTS="sha256:$(sha256sum counts.json | cut -d ' ' -f 1)"
fss-fusion-profile --scope corroborate \
  --counts-digest "$COUNTS" --analysis-digest "$ANALYSIS" \
  --detector-recipe-digest "$RECIPE" --analysis-roots "$ROOTS" \
  < counts.json > paired-profile.json
```

Select the scope of that native analysis:

| Scope | Native analysis | Profile schema | Roots |
|---|---|---|---|
| `watch` | `watch --stream-watch` | `fss.event_class_fusion_profile.v2` | One `analysis_root` |
| `corroborate` | `corroborate --stream-corroborate` | `fss.event_class_fusion_profile.v3` | Both camera roots, in native order |
| `dwell` | `watch --stream-dwell` | `fss.event_class_fusion_profile.v4` | One `analysis_root` |

Dwell profiles bind the complete sampled-occupancy rule and detector analysis;
they cannot be substituted for entry-watch profiles. See
[whole-recording dwell](long_recording_dwell.md#calibrated-class-advice).
Default output is a complete profile
plus **one newline**, directly readable by the native fusion consumer. Input is
bounded to 256 KiB and digest-checked before JSON parsing. Unknown/duplicate
options, missing assumptions, count tampering, extra roots, duplicate roots and
attempts to insert source pins or derived calibration values into counts refuse.
No input data is echoed in an error and no successful output prefix is emitted
for a validation refusal.

## Obtain the exact file hash

Repeat the same inputs with `--format report` to receive
`fss.fusion_profile_authoring.v1`. Its `profile_file_digest` hashes the exact bytes
emitted by `--format profile`, **including the final newline**. This differs from
`profile_digest`, the profile's semantic identity. The report also embeds the
profile object, exact file byte count and original count-document digest. Do not
hash a pretty-printed or reformatted extraction and expect the original file hash.

The generated profile can be supplied with `--fusion-profile paired-profile.json`
and `--fusion-digest` set to that exact file digest. Native consumers still verify
actual source/recipe scope and custody; producing this inert document does not
prove either. `source_scope_verified`, `published` and `effect_authority` remain
false. The optional principal is an audit label, not camera authentication.

This is a reference operator workflow, not deployment calibration, certified
absence, independent-verifier qualification or an activated event/alert policy.
Both input/output byte bounds and interruption retry limits are enforced under an
explicit local authority. Input supplied through a pipe may wait for its producer;
there is no ambient clock or implicit wall-time guarantee.
