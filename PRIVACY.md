# Privacy constitution

## 1. Principle

A security system should not require indiscriminate cloud surveillance. FSS is local-first,
minimizes collection, distinguishes observation from identity, and makes retention/deletion
mechanical. Privacy is an authority boundary, not a UI preference.

## 2. Default posture

- local acquisition, cognition, geometry, event ledger, and operator UI;
- remote archive opt-in and client-side encrypted;
- audio disabled unless explicitly configured for a zone and purpose;
- face identification disabled;
- cross-property identity linkage forbidden;
- no public facial/biometric database lookup;
- privacy masks applied before unauthorized model or cloud boundary;
- non-event media retained only by explicit bounded ring-buffer policy;
- bystander/public/neighbor regions masked or minimized;
- model prompts and diagnostics contain references/summaries rather than raw private content where
  possible.

## 3. Data classes

| Class | Examples | Default handling |
|---|---|---|
| `P0 operational` | sensor health, process metrics, non-identifying errors | local; longer retention permitted |
| `P1 structural` | camera topology, coarse zones, calibration residuals | local encrypted; restricted export |
| `P2 media-derived` | boxes, tracks, embeddings, captions | short TTL unless event-linked; rebuildable |
| `P3 private media` | household video/audio/images | encrypted, minimum retention, explicit access |
| `P4 sensitive identity` | face/voice/gait/appearance enrollment, household routine | disabled or explicit opt-in; strongest controls |
| `P5 evidence export` | event package for insurer/law enforcement/counsel | explicit recipient, scope, chain of custody, expiry |
| `P6 secrets` | credentials and encryption keys | separate secret domain; never evidence/model/log data |

## 4. Privacy zones and masks

Masks are versioned geometry/pixel transforms with evidence and preview. They can represent:

- always-excluded regions;
- neighbor windows/yards;
- public sidewalk beyond a configured boundary;
- indoor rooms not needed for perimeter security;
- screens/documents;
- audio exclusion zones where localization permits;
- model-only versus archive-only redaction.

A mask change is a durable effect with prepare/preview/commit. The preview shows affected current
coverage; increasing privacy may legitimately create a blind spot, which the coverage certificate
must expose. A model cannot relax a mask.

## 5. Identity without surveillance creep

The system often needs to avoid alerting when a resident takes out trash. It should combine
multiple contextual signals before resorting to persistent biometrics:

- continuity from an authorized door/zone transition;
- opt-in trusted-device presence;
- operator schedule/context;
- short-lived local appearance embedding for one session;
- path and action consistency;
- immediate operator confirmation;
- independent sensor state.

A track is not a person. Appearance embeddings default to short TTL and property-local scope.
Persistent face/voice/gait profiles require explicit enrollment, per-person consent where
appropriate, purpose, retention, deletion, and measured necessity. They never leave the property
by default.

## 6. Data minimization

- preserve original source only for the configured ring/event windows;
- remux rather than create redundant transcodes;
- use manifests referencing ranges instead of copying clips;
- sample analysis frames by candidate demand;
- delete transient model inputs after receipt publication;
- store embeddings only when they improve a declared task;
- quantize/coarsen geometry outside protected zones;
- avoid recording audio by default;
- do not collect vendor-account data unrelated to the selected camera operation;
- do not send private media to a public inference API in the default architecture.

## 7. Retention

Retention is policy-driven by class, event status, legal hold, and archive state. Each object has:

- retention class and policy generation;
- earliest deletion time;
- legal/operational hold identities;
- current locations and encryption state;
- derived-object reachability;
- deletion obligation and completion proof.

Suggested deployment presets can exist, but source code must not pretend one duration fits every
home or jurisdiction. Changing retention is a prepared durable effect.

## 8. Deletion and cryptographic erasure

A delete request traverses canonical and derived reachability. Completion distinguishes:

- physically deleted;
- cryptographically erased by destroying a unique data key;
- expired and queued at provider;
- retained under explicit hold;
- blocked/indeterminate with reason.

Indexes, thumbnails, model caches, reports, memory entries, backup generations, and remote mirrors
are part of closure. A deleted SQL row alone is not success.

## 9. Model/data governance

- no household footage is used for general model training by default;
- deployment-specific fine-tuning requires an explicit dataset root, consent, purpose, license,
  holdout, and removal path;
- research-only model hosts cannot retain or transmit inputs outside their declared capability;
- prompts/outputs are private derived data;
- human labels and feedback preserve event/evidence provenance;
- exported benchmarks use synthetic or deliberately consented/de-identified data;
- privacy leakage and memorization tests are model-admission evidence.

## 10. Operator transparency

The operator can query:

- what is currently recording and why;
- which zones/audio channels are enabled;
- effective retention and remote archive state;
- which models processed an event;
- which identities/embeddings exist and expire when;
- who/what accessed or exported evidence;
- which deletions are incomplete;
- how a privacy mask affects security coverage.

The system must not hide vendor-cloud dependence or model data flow behind a generic “local” badge.

## 11. Household and bystander controls

FSS should support:

- visible recording indicators where hardware permits and policy requires;
- guest/worker temporary privacy modes;
- indoor sensor disable schedules with explicit coverage impact;
- fast “privacy pause” that records the authority event without retaining private content;
- selective evidence export and redaction;
- child/neighbor/public-zone stricter defaults;
- per-sensor audio enablement rather than global audio-on.

Privacy pause cannot silently pretend the property remained fully observed.

## 12. Agent boundary

Agents receive the minimum projection needed: event summaries, crops, tracks, or evidence handles.
Raw streams, full geometry, persistent identity profiles, and exports require explicit capability.
Untrusted text in camera metadata, OCR, audio transcript, or model output is data, not an
instruction. Agent context packs redact secrets and minimize bystander content.
