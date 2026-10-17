# Calibrated class advice for complete two-camera recordings

The library entry point `EventFusionReport::long_corroborate` consumes a native
`LongCorroborationReport` and its verified detector package. It does not run another
model or reconstruct associations from caller-supplied JSON scores. The existing
`fss-fusion` engine computes likelihood intervals, common-cause clusters, decisions
and counterfactuals from the exact class records attached to the native pairs.

This is read-only derived advice. Native event kinds, proposal digests, publication
approvals and evidence roots do not change. Neither calibrated advice nor two camera
names grant alert authority or certify absence. Shared model/package/pipeline,
calibration and native dependency domains remain common causes.

## Bind the complete analysis

Use `EventFusionProfile::for_long_corroboration(spec, [first_root, second_root])`
or `from_long_corroboration_counts_json` to author the profile. Every field is an
explicit owner choice. Its scope differs from short-window coverage and from a
whole-recording single-camera watch:

| Profile field | Required source |
|---|---|
| `schema` | `fss.event_class_fusion_profile.v3` |
| `plan_digest` | The complete paired report's **analysis digest**, not its input plan |
| `cascade_digest` | The retained whole-recording detector recipe's digest |
| `coverage_digests` | An empty array; analysis roots are not coverage witnesses |
| `long_corroboration_analysis_roots` | Exactly two distinct, nonzero SHA-256 roots in native camera order |
| `calibrations[].sensor` | A retained sensor from those exact two scans, not a camera alias |

`LongCorroborationReport::source_cameras()` exposes the exact native summaries and
analysis roots. The report JSON already exposes each camera's `analysis_root` and
its `detector_cascade.recipe_digest`. Reordering the roots changes the profile and
is refused when it no longer matches the native report. Missing, foreign, duplicated
or substituted scopes never fall back to another profile interpretation.

The remainder of the profile uses the existing explicit class index, prior,
consequence assumptions, policy, look count, evidence time and labelled-count
calibration tables. Tables are independently rebuilt before use; supplied derived
likelihoods and digests must agree. An owner asserting applicability to an exact
plan is not the same as qualifying calibration in a deployment. The look count
remains owner-declared, not a persistent sequential observation counter.

The profile's `to_json()` emits the complete input document. Its byte hash is
separate from `profile.digest()`, which is the canonical semantic identity.
Version-one short-window and version-two single-camera profile encodings retain
their existing identities. Cross-version scope substitution fails closed.

## Preserve both source closures

The native owner revalidates its original deployment, principal and authority anchor,
then both cameras' retained source guards, current privacy generations, requested
health screening and geometric dependencies. These checks run before and after
fusion, including for a zero-candidate report. A camera-two failure cannot be hidden
behind an intact camera-one report or an empty candidate set. Cancellation remains
a cancellation, not a successful empty analysis.

Only actually associated entries contribute class records. A missing association,
budget-exhausted inference, detector refusal or another class remains explicit; it
never becomes a calibrated negative observation. A late entry is not truncated at
the short-watch 128-frame boundary. Both scans retain the native shared inference
budget rather than receiving one fresh allowance each.

At most 64 paired candidates and 256 evidence entries are accepted across the whole
report. Missing inputs spend that same evidence budget. Every native candidate must
fit; an over-budget report fails instead of returning a successful prefix. Complete
JSON is bounded to 2 MiB before delivery. Version-three output retains the ordered
analysis roots, full replayable engine queries, exact score/source links, common-cause
hulls, exclusions and counterfactual decisions.

## Reference validation boundary

The new tests exercise real native retained-source scans, a late two-camera pair in
170-frame recordings, a shared one-inference budget, exact source/proposal bindings,
zero-candidate source checks, camera-two corruption, privacy drift, requested health
screening, cancellation and profile schema isolation. Synthetic fixtures establish
these contracts, not real-camera compatibility, detector quality, measured verifier
independence, field calibration or release qualification.
