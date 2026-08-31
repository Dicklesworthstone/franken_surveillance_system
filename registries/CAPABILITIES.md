# Capability registry

Capabilities are positive, narrow authority. Absence is denial. A capability is bound to a
principal, scope, generation, budget, expiry, and optional lease fence.

| ID | Capability | Scope | Plane | Default |
|---|---|---|---|---|
| `CAP-OBSERVE-STATUS-001` | read system/sensor health | property or sensor set | authority read | operator/agent read role |
| `CAP-OBSERVE-EVENT-001` | query event revisions and bounded evidence | event/zone/time | authority read | operator/agent read role |
| `CAP-READ-MEDIA-001` | read private source/proxy media | object/event/time | authority read | denied |
| `CAP-READ-GEOMETRY-001` | read detailed property twin | property/zone | authority read | denied to generic agent |
| `CAP-ADAPTER-AUTH-001` | resolve one adapter secret handle | device/account | boundary | adapter host only |
| `CAP-ADAPTER-NET-001` | contact registered device/vendor endpoints | destination allowlist | boundary | adapter host only |
| `CAP-MEDIA-DECODE-001` | decode designated source object | object + transform plan | cognition | codec host only |
| `CAP-MODEL-INFER-001` | invoke exact model generation | model + inputs + budget | cognition | model router |
| `CAP-LEDGER-APPEND-001` | append canonical revision/receipt | table family | authority write | owning service only |
| `CAP-OBJECT-STAGE-001` | stage encrypted/content objects | namespace + quota | authority write | publisher |
| `CAP-OBJECT-PUBLISH-001` | publish root after child proof | reserved root | authority write | publisher |
| `CAP-ALERT-PREPARE-001` | prepare alert intent | event + channel | effect | policy/operator |
| `CAP-ALERT-COMMIT-001` | commit exact prepared alert | plan digest | effect | explicit grant |
| `CAP-PTZ-PREPARE-001` | prepare reversible PTZ plan | camera + pose bounds | effect | denied |
| `CAP-PTZ-COMMIT-001` | commit exact PTZ plan | plan digest + lease | effect | explicit grant |
| `CAP-RETENTION-PREPARE-001` | preview retention mutation | policy/object scope | effect | admin |
| `CAP-RETENTION-COMMIT-001` | commit exact retention mutation | plan digest | effect | strong approval |
| `CAP-EXPORT-PREPARE-001` | build redacted evidence-export plan | event + recipient + fields | effect | denied |
| `CAP-EXPORT-COMMIT-001` | publish exact export | plan digest | effect | strong approval |
| `CAP-DELETE-PREPARE-001` | compute deletion closure plan | subject/object/event | effect | admin/data subject path |
| `CAP-DELETE-COMMIT-001` | execute sealed deletion plan | plan digest | effect | strong approval |
| `CAP-CALIBRATE-001` | run calibration computation | session root + sensors | cognition | operator |
| `CAP-DRONE-CAPTURE-001` | ingest manually piloted drone capture | session/device | authority read | operator |
| `CAP-DRONE-FLIGHT-001` | command drone motion | mission/airspace | effect | disabled in v1 |
| `CAP-REPAIR-PREPARE-001` | generate sealed repair plan | subsystem/object scope | authority read | operator |
| `CAP-REPAIR-COMMIT-001` | apply exact repair plan | plan digest | effect | strong approval |

Capabilities cannot be synthesized from prose, model outputs, vendor metadata, or inherited ambient
process privileges.
