# Score calibration at the fusion CLI boundary

The reference `fss-fuse` command accepts several measured score calibrations in one query. Each raw
score selects an exact artifact by its generation and content digest. This prevents argument order
or a single global table from silently deciding which score space an observation belongs to.

This adapter remains read-only. It produces a proposed decision and provenance; it does not publish
an event, activate a threshold, prepare an alert, or grant effect authority. See
[FUSION_REFERENCE.md](FUSION_REFERENCE.md) for the kernel's common-cause model and qualification limits.

## Loading and selecting calibrations

Pass `--calibration` once per artifact, up to sixteen times:

```sh
fss-fuse --query query.json \
  --calibration detector-a-evaluation.json \
  --calibration detector-b-evaluation.json
```

Each file may be a `fss-evaluate --calibration-bins` report with a nested
`score_calibration` object, or a standalone `fss.score_calibration.v1` object.
The adapter rebuilds every calibration from its labelled bin counts and compares the result with
the declared digest before using it. Supplying one artifact twice is refused. Reusing one generation
name for different contents is also refused.

Use the generation and digest reported by the actual calibration artifact. The following is a
schema fragment; replace the placeholder with that artifact's complete digest:

```json
{
  "id": "cam-a/candidate-1",
  "sensor": "cam-a",
  "failure_domains": ["model-family:detector-a", "illumination:driveway"],
  "observability": "observed",
  "calibration": {
    "score_ppm": 980000,
    "generation": "detector-a:cam-a:day:v1",
    "digest": "sha256:<digest from the calibration artifact>"
  }
}
```

Scores must be integers in `0..=1000000`. An unknown digest, mismatched generation, missing binding,
or an object mixing `score_ppm` with `llr` or `uncalibrated` is a typed refusal.
A valid score outside the artifact's supported bins remains uncalibrated.

Use query schema `fss.fusion_query.v2` for new inputs. Version 1 remains readable for explicitly
bound scores, caller-supplied LLR intervals, and declared uncalibrated observations. An old raw
`{"score_ppm": N}` input must acquire a generation and digest; the adapter deliberately refuses
the former implicit global binding.

## Choosing a prior

An explicit prior interval remains `[lo, hi]`, in integer millibans. A prior derived from a
calibration names the same two identity fields:

```json
{
  "prior": {
    "generation": "detector-a:cam-a:day:v1",
    "digest": "sha256:<digest from the calibration artifact>"
  }
}
```

The shorthand `"prior": "calibration"` is accepted only when exactly one artifact is loaded.
With multiple artifacts it is ambiguous and is refused. Command-line order never chooses a prior.

The prior computed by this reference calibration describes the labelled evaluation population.
It is not automatically a deployment base rate; transporting it to a different scene, operating
mode, event population, or sampling procedure requires separate justification.

## Common causes

Every score derived from the same calibration receives a
`calibration:sha256:<artifact digest>` failure domain. Reusing one measured artifact across
two cameras therefore creates one dependency cluster and cannot corroborate itself.

The kernel also inserts the producing `sensor:<sensor>` domain. Repeated frames from one camera
remain dependent even if optional caller labels change. Callers must still declare other relevant
shared causes, including model family, pipeline, scene conditions, and replay origin.

Different generation names or digests do **not** prove verifier independence. Renaming the same
model or recalculating a table does not establish independent physical evidence. The identity
checks prevent accidental score-space substitution; they are not deployment qualification.

## Output provenance

The existing `query_digest` and `decision_digest` describe the normalized kernel query and its
decision. Score conversion discards the exact raw value inside a bin, and two distinct calibrations
can have the same numerical prior. The adapter preserves those distinctions separately:

| Output field | Meaning |
| --- | --- |
| `score_calibrations` | All loaded generation/digest pairs, in digest order. |
| `prior_calibration` | The selected prior's generation and digest, or null for a numerical prior. |
| `score_calibration_bindings` | Every scored evidence ID, exact score in ppm, and selected calibration, in evidence-ID order. |
| `input_binding_digest` | Canonical digest binding the normalized query, selected prior identity, and exact scored-input bindings. |
| `score_calibration_digest` | Compatibility field: the digest when exactly one calibration is loaded; otherwise null. |

The `fss.fusion.calibrated_input.v1` encoding uses the repository's checked canonical encoder:
domain text, query digest, prior-presence flag and optional generation/digest, then a u64 score
count and each evidence ID, u32 raw score, generation, and digest. Output order is independent of
calibration argument order. The adapter digest supplements the kernel digests; it does not change
their encoding.

## Remaining qualification work

Calibration generations are caller declarations. The adapter does not establish provenance from a
signed model package, representative labelled deployment data, generation currency, calibration
transport validity, or the independence of different models. Caller-supplied
`{generation, llr: [lo, hi]}` observations remain assertions rather than artifact-verified scores.

A detector's object-class score is not a calibrated probability of intrusion or threat. This work
does not promote raw watch or corroboration class scores into event confidence. Measured event
calibration and deployment-qualified common-cause declarations remain required for that integration.
The broad `FUSION-CALIBRATION-001` and `MODEL-INDEPENDENCE-001` beads remain open.
