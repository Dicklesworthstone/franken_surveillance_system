# Schema registry

| ID | Schema | File | Authority | Compatibility rule |
|---|---|---|---|---|
| `SCHEMA-SENSOR-CAPSULE-001` | `fss.sensor_capsule.v1` | `schemas/sensor_capsule.v1.json` | authority | append/supersede; no silent timestamp/source reinterpretation |
| `SCHEMA-EVENT-HYPOTHESIS-001` | `fss.event_hypothesis.v1` | `schemas/event_hypothesis.v1.json` | authority | immutable revisions; evidence required after hypothesis |
| `SCHEMA-EVIDENCE-BUNDLE-001` | `fss.evidence_bundle.v1` | `schemas/evidence_bundle.v1.json` | authority/export | old proof bundles remain replayable or explicitly unsupported |
| `SCHEMA-OPERATION-RECEIPT-001` | `fss.operation_receipt.v1` | `schemas/operation_receipt.v1.json` | effect truth | state monotonicity; idempotency identity preserved |
| `SCHEMA-CALIBRATION-CERT-001` | `fss.calibration_certificate.v1` | `schemas/calibration_certificate.v1.json` | authority | generation immutable; invalidation creates new state |
| `SCHEMA-CAPABILITIES-001` | `fss.capabilities.v1` | CLI output | product boundary | additions compatible; changed meaning requires new schema |
| `SCHEMA-DOCTOR-001` | `fss.doctor.v1` | CLI output | diagnostics | bounded and secret-free |
| `SCHEMA-STATUS-001` | `fss.status.v1` | CLI output | product boundary | status fields cannot imply unsupported readiness |

Future binary media/ledger formats require magic, version, limits, canonical encoding, migration
fixtures, corruption tests, and a format owner before implementation.
