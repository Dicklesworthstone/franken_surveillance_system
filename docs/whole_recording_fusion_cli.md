# Calibrated class advice for two complete recordings

`fss-event corroborate --stream-corroborate` accepts the existing
`--fusion-profile FILE --fusion-digest sha256:HEX` options. This connects the
native complete-recording fusion adapter to the operator CLI. It does not replace
ground-entry association, activate a classifier, or grant alert authority.

## Prepare the complete native analysis

Run the ordinary whole-recording corroboration command with both retained imports,
explicit image-to-ground mappings, zones, timing/distance gates and detector-package
options. Preserve its complete JSON report. Existing source custody, privacy,
geometry, health-screening and whole-recording work limits still apply.

Three pieces of that exact result bind a paired version-three profile:

- `analysis_digest`: the combined complete analysis, not the smaller `plan_digest`;
- `detector_cascade.recipe_digest`: the complete detector recipe, not its package hash;
- `cameras[0].analysis_root` and `cameras[1].analysis_root`, in native camera order.

The profile must use schema `fss.event_class_fusion_profile.v3` and an empty
`coverage_digests` array. Complete source-analysis roots are not coverage witnesses.
A single-camera version-two profile, swapped roots, a foreign source, a different
analysis/recipe or an unrelated sensor calibration refuses instead of falling back.

## Author the profile from explicit labelled counts

Use the separate [profile authoring command](fusion_profile_cli.md). Supply counts
applicable to the selected class and camera mode, along with explicit prior,
policy, consequence, look-count and evidence-clock assumptions. Synthetic fixture
counts are not deployment calibration.

```sh
fss-fusion-profile --scope corroborate \
  --counts-digest "$COUNTS_DIGEST" --analysis-digest "$ANALYSIS_DIGEST" \
  --detector-recipe-digest "$RECIPE_DIGEST" \
  --analysis-roots "$FIRST_ANALYSIS_ROOT,$SECOND_ANALYSIS_ROOT" \
  < counts.json > paired-profile.json
```

The default output is reusable profile JSON plus one newline. Repeating unchanged
inputs with `--format report` returns `profile_file_digest`, the SHA-256 of those
exact file bytes including the newline. It is distinct from the semantic
`profile_digest` and from the hash of the enclosing authoring report.

## Request read-only advice

Repeat the original `fss-event corroborate --stream-corroborate` invocation with
all its original native analysis options, adding:

```sh
  --fusion-profile paired-profile.json --fusion-digest "$PROFILE_FILE_DIGEST"
```

Do not include `--approve`, `--retain-coverage` or `--retain-health`. Both parsing
and runtime admission reject those combinations before analysis. Publication and
retention remain separate explicitly approved invocations. The original native
proposal identities and displayed publication commands do not acquire fusion
options or extra authority.

The result retains the complete original native JSON and adds
`calibrated_class_advice` with schema `fss.event_class_fusion_report.v3`. Advice
includes exact source and score bindings, calibrated likelihood intervals,
common-cause clusters, posterior bounds, exclusions and counterfactuals. The
existing fusion engine performs the arithmetic; the adapter runs no additional
model inference. Sharing a model, processing recipe, calibration or other failure
domain does not create independent corroboration merely because two cameras ran.

The exact profile is hash-checked before geometry, model and source-analysis work.
The complete combined output is bounded before delivery. Both retained sources,
the original owner/authority anchor and current privacy/health/geometric guards
are revalidated around derived use and again before output. A validation refusal
emits no successful JSON prefix or report export.

A missing or budget-skipped inference stays explicit rather than becoming a zero
score. An empty candidate inventory stays empty, not evidence of class absence.
`class_absence_certified`, `event_policy_changed`, `published`,
`coverage_witness_supplied` and `effect_authority` remain false in the advice.

## Reference validation boundary

The real-process contracts run both complete 170-frame synthetic recordings,
including entries after frame 150, and exercise the authoring-command-to-analysis
path. They compare native JSON, inference counts, proposals, provenance and
separate approval commands with and without advice. Further cases cover empty
scans, one shared inference allowance, scope substitution, forbidden authority
writes and corrupted profile bytes. Existing AVC/HEVC and cold-replay tests remain
in the parent test target.

These checks establish reference wiring, deterministic scope and refusal behavior,
not physical-camera accuracy, measured verifier independence, deployment-calibration
applicability, persistent sequential-look accounting or DSR release qualification.
Calibrated class advice remains derived cognition; it does not automatically
advance event or alert policy.
