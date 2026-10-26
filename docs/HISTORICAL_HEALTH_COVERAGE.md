# Historical camera-health findings and retained coverage

Retaining a sensor-health diagnostic now changes how existing recorded coverage is interpreted.
A quiet-looking frozen recording can no longer keep supporting an absence claim after a matching
retained diagnostic identifies degradation. This applies automatically to cold `fss orient`
and `fss follow` reads; it requires no new read-side flag.

## Exact source binding

The guard considers only verified diagnostics in the selected committed history prefix. A finding
can withdraw a witness only when all of these match:

- The imported source identity and retained import root.
- The sensor identity.
- The privacy policy digest and its exact generation at the coverage analysis's original anchor.
- An overlapping source segment range.

An identical sensor name or capture timestamp does not connect different imports. Reissuing an
identical mask after another policy does not make the two privacy generations interchangeable.
A later policy is never substituted for the policy that produced the retained coverage.

## What is withdrawn

The projection removes each affected witness before joining the surviving coverage intervals.
It preserves the original coverage record and source bytes. Independent unaffected witnesses
can still establish a covered interval.

A screen finding records when its threshold becomes satisfied, which may follow the beginning of
the implicated run. The guard therefore uses the diagnostic's finite requested scan as the
conservative matching range. An overlapping witness is withheld as a whole; this is not an
estimate of the physical outage's start or end. Conflict metadata separately retains the actual
threshold finding interval and the scan/witness intersection.

A later `no_findings` result is a separate bounded observation. It does not erase an earlier
adverse result. Findings on disjoint source segments do not withdraw an otherwise valid witness.

## Operator-visible results

If no valid witnesses remain, the affected zone is `not_observable`, the withdrawn witness
identities are absent from the supporting evidence, and absence is not certified. Named gaps
carry the original coverage record, witness, diagnostic and provenance-root identities.
The coverage knowledge cell includes the diagnostic as contradicting evidence.

If independent witnesses preserve the interval, the zone remains covered and names those
surviving witnesses. Its explanation still describes the excluded source, without marking the
valid independent coverage claim as contradicted.

Follow projections preserve the sensor-health change and any coverage loss. The withdrawn
evidence cannot support a certified-silence result. Reading an earlier committed prefix keeps
the interpretation supported at that prefix; current deletion authority still applies.

## Bounds and custody

This read-side operation consumes verified retained metadata. It does not reopen native media,
decode new frames, rewrite diagnostic or coverage objects, or dispatch effects. Damaged retained
metadata refuses the cold read rather than restoring the old absence claim.

Aggregate comparison limits bound historical privacy reconstruction and diagnostic matching.
Exhaustion refuses the projection rather than silently dropping contradictory evidence.

The historical screen is a heuristic assessment of the recording. It is not a statement about
the camera's present physical health, a recovery certificate, or proof of live continuity.

## Regression targets

```sh
cargo test --locked --offline -p fss-reference --test historical_health_coverage_contract
cargo test --locked --offline -p fss-cli --test historical_health_cli
```

The reference cases exercise immutable history and historical prefixes, disjoint ranges,
different imports with equal sensor/time metadata, independent overlapping witnesses, later
no-findings, threshold latency, corrupted retained metadata, and repeated policy bytes across
privacy generations. The CLI case uses actual orient/follow processes and checks their existing
JSON coverage, contradiction, delta and silence fields.

These focused tests do not replace the repository's native qualification lanes.

## Source-level diagnostic assessment

`ingest::historical_health::exposure::HealthExposureCatalog` supplies the same conservative
source binding to native consumers that already verified an original observation. Its one
bounded read admits the current diagnostic catalog, exact retained metadata and deletion
authority. Repeated `assess` calls share the original comparison and output allowances.

`HealthExposureSource` names the exact import identity and root, sensor, source segment,
privacy policy digest and privacy generation. A matching finding withholds support throughout
the diagnostic's finite requested scan, including threshold latency. The returned exposure keeps
every matching diagnostic, original publication anchor, provenance root, trace identity, finding
interval and withholding interval. A later clear diagnostic cannot erase an earlier finding.

The four states are `no_matching_diagnostic`, `screened_without_findings`,
`screening_incomplete` and `findings`. The first is unknown health. A completed screen without
findings records only that finite heuristic result. Findings and incomplete screening withhold
support conservatively; none of these states establishes the camera's present physical health,
an outage duration, a recovery, continuous coverage or absence.

The catalog verifies retained metadata and provenance. It does not read or replay the complete
native trace or media; the downstream native source owner retains that responsibility. Corrupt
or missing nondeleted metadata, authority drift and exhausted bounds refuse the operation.
Explicitly deleted diagnostic metadata remains accounted for as a deletion exclusion.

The source-exposure regressions use actual retained native JPEG screens, including cold reopen,
exact-frame repetition, threshold latency, incomplete decode, unrelated source/privacy bindings,
multiple diagnostics, cancellation, cumulative work, corruption and current deletion:

```sh
cargo test --locked --offline -p fss-reference --lib ingest::historical_health::exposure::
```

