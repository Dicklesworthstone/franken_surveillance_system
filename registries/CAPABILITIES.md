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
| `CAP-AGENT-SESSION-WRITE-001` | create/supersede mission, session, and workspace revisions | mission + session | agent continuity write | explicit agent-session role |
| `CAP-AGENT-SITUATION-READ-001` | read capability-projected SituationFrames, deltas, and obligations | deployment/mission/zone/time | cognition read | agent read role |
| `CAP-AGENT-QUERY-001` | compile and execute bounded semantic queries | authorized resources + anchor | cognition read | agent read role |
| `CAP-AGENT-INVESTIGATE-001` | create/advance immutable investigation and hypothesis revisions | case + evidence domain | cognition write | explicit investigation role |
| `CAP-AGENT-PLAN-PREPARE-001` | compile and seal a witnessed contingent plan | mission + objective + target domain | cognition/prepare | explicit planner role |
| `CAP-AGENT-PLAN-COMMIT-001` | submit an exact prepared plan to domain effect authorities | plan digest + fences | effect orchestration | denied unless explicit; never substitutes for domain effect capabilities |
| `CAP-AGENT-CANCEL-001` | request cancellation/drain/reconciliation of owned work | session/task/plan/obligation | lifecycle effect | owner or delegated supervisor |
| `CAP-AGENT-EXPLAIN-001` | read minimal evidence/decision subgraphs and counterfactuals | authorized decision/evidence domain | cognition read | agent read role |
| `CAP-AGENT-HANDOFF-WRITE-001` | publish a redacted root-last handoff capsule | mission/workspace + recipient scope | agent continuity write | explicit delegation |
| `CAP-AGENT-HANDOFF-READ-001` | accept and rebase an authorized handoff capsule | exact handoff root + recipient | agent continuity read | named recipient/delegate |
| `CAP-AGENT-FEEDBACK-001` | append correction, adjudication, outcome, or learning proposal | episode/event/case | advisory write | scoped agent/operator role |
| `CAP-AGENT-WORK-CLAIM-001` | reserve a bounded multi-agent work scope under a lease | mission/case/subgraph | coordination write | agent collaborator role |
| `CAP-AGENT-EVIDENCE-HYDRATE-001` | hydrate a stable evidence handle to an allowed level | object + hydration level | authority/cognition read | separately scoped by privacy class |
| `CAP-AGENT-SESSION-OPEN-001` | open a mission-scoped agent session | deployment + mission + principal | agent control | denied unless negotiated |
| `CAP-AGENT-SESSION-READ-001` | read/resume exact workspace or handoff revisions | mission/session/workspace root | agent control | session principal |
| `CAP-AGENT-CASE-WRITE-001` | create/revise investigations, hypotheses, probes, and findings | mission/case scope | agent cognition | explicit mission role |
| `CAP-AGENT-FINDING-WRITE-001` | publish immutable evidence-linked finding | mission/case + evidence scope | coordination | explicit mission role |

Capabilities cannot be synthesized from prose, model outputs, vendor metadata, or inherited ambient
process privileges.
