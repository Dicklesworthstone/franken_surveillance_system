# Anonymous familiarity on retained event reads

`fss-event read` can attach a deterministic household familiarity assessment to a
cold-verified recorded-luma or `event:package:` event. The assessment describes
possible familiar activity while identity remains unresolved. It leaves the
canonical event, policy decision, publication authority and alerts unchanged.

This is the initial advisory portion of `fss-x4a.16.11` / PRIVACY-FAMILIARITY-001.
It does not complete retained signal ingestion, automatic benign suppression,
live-device qualification or measured false-alert reduction. Whole-recording
`event:long-watch:`, `event:long-dwell:` and `event:long-corroborated:` inspection
does not accept these options.

## Read, annotate and assess

Start with an existing published event and obtain an exact context template:

```sh
fss-event read --root "$ROOT" --site "$SITE" --event-id "$EVENT" \
  --familiarity-template yes > familiarity-read.txt
sed -n 's/^familiarity_context_template=//p' familiarity-read.txt \
  > familiarity-context.json
```

The template pins the current authority root, site, local-file privacy scope,
event revision and event policy generation. It starts with unknown coverage,
threat actions and sensor integrity, and an empty signal list. It therefore
cannot recommend familiar activity. `familiarity_evaluation_time_hint_ns` reports
the event's latest possible capture time as a historical evaluation hint. Choose
an explicit logical evaluation time in that same clock domain; it is not a wall
clock or a freshness certificate.

Add only context the operator intends to assert, using
[`event_familiarity_context.v1.json`](../schemas/event_familiarity_context.v1.json).
Keep identity and personal information out of domain labels. The input supports
authorized-door, path-continuity, opt-in trusted-device, opt-in appearance,
routine and operator-confirmation cues. Each cue requires an evidence digest,
source generation, declared failure domains, validity interval, polarity and
revocation state. Appearance additionally requires a model receipt already
referenced by the canonical event.

For example, one cue has this shape (replace digest placeholders and times):

```json
{
  "evidence_digest": "sha256:EVIDENCE_HEX",
  "source_generation": "sha256:GENERATION_HEX",
  "kind": "authorized_door",
  "supports": true,
  "failure_domains": ["door:local-entry"],
  "valid_from_ns": "1000000000",
  "expires_at_ns": "3000000000",
  "revoked": false,
  "opted_in": false,
  "model_receipt": null
}
```

Bind the exact edited file bytes and request assessment:

```sh
CONTEXT_DIGEST="sha256:$(sha256sum familiarity-context.json | cut -d ' ' -f 1)"
fss-event read --root "$ROOT" --site "$SITE" --event-id "$EVENT" \
  --familiarity-context familiarity-context.json \
  --familiarity-digest "$CONTEXT_DIGEST" --familiarity-at-ns "$EVALUATION_TIME_NS"
```

All three assessment options are required together; template and assessment
options are mutually exclusive. The context file is bounded to 64 KiB and read
with the existing regular-file, no-symlink, exact-digest reader. Invalid context
or stale pins refuse the complete read before any successful output or export.
The native retained source, privacy and authority checks still run, including
final revalidation. A later authority commit requires a fresh template and
review of the assertions; do not merely replace a stale root to bypass review.

## What the result means

The `familiarity_advice` line contains `fss.event_familiarity_advice.v1` JSON.
It includes every supplied cue and its applicability, raw and semantic context
digests, exact event and authority pins, an advisory-policy digest, explicit
evaluation time, expiry bound, blockers and unknowns. Semantic context and
decision digests are stable under signal/domain ordering changes.

`possible_familiar_activity` requires at least two applicable cue kinds across
two declared disjoint failure-domain groups, including authorized door or path
continuity. Coverage and both risk screens must be explicitly asserted clear.
Shared domains are merged transitively, including expired or revoked bridging
cues, so repeated observations or a stale bridge cannot manufacture another
support group. A single cue, device presence alone, or routine alone is
insufficient.

The declared groups remain unverified. Context digests bind supplied bytes;
they do not verify an assertion's truth, source generation, opt-in status or
independence. `referenced_by_native_event` means only that the event contains the same
digest. Signal evidence is not hydrated by this path. Every assessment retains
`context_assertions_unverified`, `source_independence_unverified`,
`coverage_not_certified` and `identity_unresolved` as unknowns. Native event
uncertainty also remains visible.

Threat or high-consequence context and canonical perimeter-breach,
covert-approach or sensor-tamper kinds override familiar support. Native
contradicting/invalidating evidence and any supplied negative cue block a
familiar recommendation, including expired or revoked negative cues. Degraded
coverage or sensor-integrity concern also blocks it. Unknown guard conditions
cannot produce a familiar recommendation.

Positive cues must cover the event's entire uncertainty interval and remain
valid at the explicit evaluation time. Expiry is exclusive. Revoked,
not-yet-valid, expired, opted-out and mismatched-model cues remain in the report
without contributing support. The bounded reference policy caps signal lifetime
at 24 hours, appearance at 15 minutes, 32 cues and 8 domains per cue. These are
reference evaluator limits, not a change to deployment retention policy.

Every result states `alert_suppression_authorized=false`,
`absence_certifiable=false`, `effects_authorized=false` and
`event_unchanged=true`. The advisory does not identify anyone, create a whitelist,
certify absence, authorize an effect or clear a threat.
