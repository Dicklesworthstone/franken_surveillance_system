# Schema registry

| ID | Schema | File | Authority | Compatibility rule |
|---|---|---|---|---|
| `SCHEMA-SENSOR-CAPSULE-001` | `fss.sensor_capsule.v1` | `schemas/sensor_capsule.v1.json` | authority | append/supersede; no silent timestamp/source reinterpretation |
| `SCHEMA-EVENT-HYPOTHESIS-001` | `fss.event_hypothesis.v1` | `schemas/event_hypothesis.v1.json` | authority | immutable revisions; evidence required after hypothesis |
| `SCHEMA-EVIDENCE-BUNDLE-001` | `fss.evidence_bundle.v1` | `schemas/evidence_bundle.v1.json` | authority/export | old proof bundles remain replayable or explicitly unsupported |
| `SCHEMA-OPERATION-RECEIPT-001` | `fss.operation_receipt.v1` | `schemas/operation_receipt.v1.json` | effect truth | state monotonicity; idempotency identity preserved |
| `SCHEMA-CALIBRATION-CERT-001` | `fss.calibration_certificate.v1` | `schemas/calibration_certificate.v1.json` | authority | generation immutable; invalidation creates new state |
| `SCHEMA-EVIDENCE-ANCHOR-001` | `fss.evidence_anchor.v1` | `schemas/evidence_anchor.v1.json` | authority | no mixed generations; additions require new epoch semantics |
| `SCHEMA-COVERAGE-WITNESS-001` | `fss.coverage_witness.v1` | `schemas/coverage_witness.v1.json` | authority/query | absence claims require declared domain and stop reason |
| `SCHEMA-TRANSFER-MANIFEST-001` | `fss.transfer_manifest.v1` | `schemas/transfer_manifest.v1.json` | authority/transfer | root-last; object and closure identities immutable |
| `SCHEMA-GRAPH-WITNESS-001` | `fss.graph_algorithm_witness.v1` | `schemas/graph_algorithm_witness.v1.json` | derived/evidence | algorithm/projection/policy identity and output digest preserved |
| `SCHEMA-DECISION-CARD-001` | `fss.decision_card.v1` | `schemas/decision_card.v1.json` | policy/evidence | hard constraints and alternatives retained; no silent rewrite |
| `SCHEMA-RELEASE-RECEIPT-001` | `fss.release_qualification_receipt.v1` | `schemas/release_qualification_receipt.v1.json` | release custody | same source/sibling/toolchain identity required for aggregation |
| `SCHEMA-ADAPTER-CERT-001` | `fss.adapter_compatibility_certificate.v1` | `schemas/adapter_compatibility_certificate.v1.json` | compatibility | exact tuple only; invalidator transitions revoke/degrade |
| `SCHEMA-CANCEL-DRAIN-001` | `fss.cancellation_drain_certificate.v1` | `schemas/cancellation_drain_certificate.v1.json` | runtime evidence | terminal/indeterminate outcome and outstanding effects preserved |
| `SCHEMA-EVIDENCE-DELTA-001` | `fss.evidence_delta_batch.v1` | `schemas/evidence_delta_batch.v1.json` | authority/version universe | basis/new anchors and ordered delta identities preserved |
| `SCHEMA-TRANSFER-RECEIPT-001` | `fss.transfer_receipt.v1` | `schemas/transfer_receipt.v1.json` | transfer evidence | path, repair, closure, publication, and retrievability states remain distinct |
| `SCHEMA-MODEL-PACKAGE-001` | `fss.model_package_manifest.v1` | `schemas/model_package_manifest.v1.json` | model authority/package | immutable package root; operator/tensor/preprocess/numeric/license identities preserved |
| `SCHEMA-MODEL-RECEIPT-001` | `fss.model_execution_receipt.v1` | `schemas/model_execution_receipt.v1.json` | derived/model evidence | input/model/plan/backend/numeric/budget/outcome and output identities preserved |
| `SCHEMA-RELEASE-BUILD-001` | `fss.release_build_receipt.v1` | `schemas/release_build_receipt.v1.json` | release custody | native target/toolchain/source/lock/manifest/smoke identities immutable |
| `SCHEMA-RELEASE-STAGE-001` | `fss.release_stage_verification.v1` | `schemas/release_stage_verification.v1.json` | release custody | stage inventory and content digests preserved exactly |
| `SCHEMA-SOURCE-MANIFEST-001` | `fss.source_manifest.v1` | `schemas/source_manifest.v1.json` | source custody | clean tracked source identity and executable bits preserved |
| `SCHEMA-LICENSE-INVENTORY-001` | `fss.license_inventory.v1` | `schemas/license_inventory.v1.json` | supply-chain evidence | package identity/source/license fields remain auditable |
| `SCHEMA-QUALIFICATION-ROOT-002` | `fss.qualification_root.v2` | `schemas/release_qualification_root.v2.json` | aggregate release custody | primary/support artifact digests, claim boundary, and signing state immutable |
| `SCHEMA-CAPABILITIES-001` | `fss.capabilities.v1` | `CLI output` | product boundary | additions compatible; changed meaning requires new schema |
| `SCHEMA-DOCTOR-001` | `fss.doctor.v1` | `CLI output` | diagnostics | bounded and secret-free |
| `SCHEMA-STATUS-001` | `fss.status.v1` | `CLI output` | product boundary | status fields cannot imply unsupported readiness |

Binary media, ledger, search-segment, graph-run, and release formats additionally require magic, version, bounded lengths, canonical encoding, migration fixtures, corruption tests, and a named format owner before implementation.
