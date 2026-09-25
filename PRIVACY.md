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

### 4.1 What is enforced today (fss-bgqkd, fss-g9gml, reference, unqualified)

Implemented for retained file imports (`fss-file import`, fss-bgqkd) and for the live, recording
and replay decode paths (fss-g9gml):

- **Declaration.** `fss-event privacy-mask declare` retains an owner-declared, versioned policy
  per sensor: the declared stream resolution and 1..32 axis-aligned rectangles
  (`transform:bounding_box_redact` regions). Preview, then exact approval over the sensor's
  current policy; one `privacy_mask_policy` authority generation per approval; stale approvals are
  refused before any write. Policies can be replaced, never silently relaxed by a model; there is
  no removal command.
- **Enforcement at decode.** Every retained decode path (JPEG/MJPEG luma and RGB, H.264, H.265,
  video RGB) fills masked pixels (luma 16, chroma 128, RGB 16,16,16) before the foreground model,
  tracker, zone gate, detector package, cascade, PGM export or any other consumer sees them. The
  receipts bind the policy digest or an explicit no-policy marker; lineages of different mask
  generations never share an identity.
- **Honest coverage.** A zone with any masked pixel carries no coverage witness: its frames are
  uncovered with reason `privacy_masked`, and `fss orient` reports it `not_observable` (the
  coverage model has no sub-zone domain, so a partly masked zone is not observable as a whole;
  draw the visible part as its own zone). A masked area is never absence evidence. A
  corroborate ground zone is masked when its conservative image preimage or any of its in-view
  geometric visibility samples touches a masked pixel; a tolerant decode masks every frame it
  does decode, and a refused segment stays `decode_refused` (docs/RECORDED_EVENT_WORKFLOW.md).
- **Typed transform.** Watch reports, candidates, package-detection reports and `fss-file decode`
  name the applied transform (`transform:bounding_box_redact`) and policy digest; a published
  watch event carries the retained policy as a `required_by` evidence edge.
- **Unmasked access refused.** Raw source export of a masked sensor and decodes retained under no
  or a superseded policy are refused (`ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001`). There is no
  override capability.
- **Live, recording and replay paths (fss-g9gml).** Live HTTP acquisition (the learned HOG
  composition and the RGB neural composition), archived HTTP RGB replay, HTTP recording decode,
  `fss-archive check-http`, RGB evidence replay and retained MJPEG sensor-health screening apply
  the named sensor's *current* retained policy with the same enforcement function and fills. The
  owner names the sensor (`SensorMask`: the sensor plus the deployment retaining its authority;
  `check-http --privacy-root DIR --site SITE --sensor ID`); each consumer resolves the policy when
  it decodes a frame. HOG: the decoded luma is filled before rectification, screening, foreground,
  the learned scan, tracking, zones and every decoded-plane digest (`fss-twin` redaction hook);
  RGB: the native decode is masked and re-receipted before the permission projection and the
  graph. The owner permission grid and any frozen background must already exclude the masked
  pixels, or the frame is refused before acceptance (`ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001`); a
  decode naming no sensor is refused the same way (framing-only checks read no pixels). A masked
  frame's luma digest equals the retained decode's digest of the same frame.
- **Identity rule.** Without a policy every live receipt, completion digest, check frame chain
  and RGB evidence recipe keeps its pre-masking bytes (golden-pinned) and carries the explicit
  no-policy marker as a typed field; with a policy the binding is folded into the identity
  (`fss.privacy_mask_lineage.v1`) and RGB evidence uses recipe version 2
  (`fss.rgb_source_evidence.recipe.v2`).
- **Policy change mid-capture.** The new generation applies from the next decoded frame and is
  recorded on it; earlier receipts are never rewritten. A frame whose owner grid or frozen
  background still reflects the old generation is refused; a running trajectory episode is bound
  to one permission grid, so it refuses (typed, retained) the first frame under a new grid until
  the owner starts a new episode. RGB evidence replays only under the binding it was recorded
  with, and only while that binding is the sensor's current one.
- **Custody versus derivation.** Original source custody (retained HTTP wire reads, completion
  records, RTSP live archives, the original JPEG inside an RGB evidence envelope) stays unmasked
  custody; every pixel derivation from it is masked. RTSP live capture and archiving decode no
  pixels at all (a source-scan test pins that capture and custody modules name no pixel decoder).

Not enforced yet: raw custody export of RTSP recordings (`fss-archive export`, which emits
original packets, not pixels) and of archived HTTP wire reads is not refused for a masked sensor
(the analogous `fss-file extract` is); the synthetic laboratory twin; polygons, audio exclusion,
archive-only versus model-only redaction, deletion closure (unmasked source and superseded
decodes remain in local custody), retention schedules, and biometric controls beyond the absence
of any biometric feature.
Not enforced yet: masks on live HTTP/RTSP capture paths and the laboratory twin (they take a
caller-supplied permission mask or none), polygons, audio exclusion, archive-only versus
model-only redaction, retention schedules, and biometric controls beyond the absence of any
biometric feature. Unmasked source and superseded decodes remain in local custody until the
owner deletes the import (section 8.1).

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

### 8.1 What is enforced today (fss-x4a.9.7, FSS-037, reference, unqualified)

Implemented for retained file imports (`fss-file import`) of one local deployment:

- **Plan (`CAP-DELETE-PREPARE-001`, read-only).** `fss-event delete plan --import-id sha256:…`
  scans every retained spool object once for embedded SHA-256 digests (raw or hex) and walks
  every ledger batch and visible root. A unit joins the closure when it holds, names or embeds a
  digest the import (or an earlier closure unit) owns: import custody (segments, chunks,
  capsules), decoded frames and receipts, analyses and reports, coverage records,
  package-detection records, event provenance roots and attributable staging leftovers. The
  plan names each unit and the reference that reached it, every object removed with its bytes,
  every closure object retained and why (`shared_with_retained_authority`: another retained unit
  still holds it; `authority_history`: event revisions, tamper status and alert outcomes), the
  tombstone batch, the blockers and the unknown copies. It is canonical and digest-bound
  (`fss.deletion_plan.v1`), bounded and deterministic, and binds the authority head and the
  effect-journal root.
- **Commit (`CAP-DELETE-COMMIT-001`).** `delete commit --plan … --approve …` recomputes the plan
  against the current head; any change is a stale plan and any blocker refuses; nothing is
  written. Then the deletion record is appended first: a `deletion_record` delta whose payload is
  the plan, a `deletion_tombstone` successor for every ledger object only closure content wrote,
  and a `local_root_retraction` successor for every retracted root. The ledger is append-only:
  no batch is rewritten, and batches that named deleted content stay. Only then are root records
  and spool objects unlinked (each hold before its object) and absence verified; the completion
  record (`fss.deletion_completion.v1`) is appended last. A rerun after an interruption at any
  cut point resumes and completes exactly once; from the moment the record is durable every
  deleted digest reads `deleted`, never content.
- **Reads after deletion.** Decode, read, verify, re-import and plan of the import report
  `ERR-EVIDENCE-DELETED-001` (hydration availability `deleted`, not a missing-object error); a
  deleted import identity is never reused. `fss orient` names each deletion and `fss explain`
  names each deleted evidence handle of an event.
- **Events keep their history.** No new event revision is minted: a revision is a decision
  under a decision path, deletion changes custody, and availability stays orthogonal to
  knowledge state. The event's revision objects are retained authority history; its evidence
  handles resolve to `deleted`.
- **Blockers.** An open or indeterminate alert effect whose precondition binds a closure event
  (`open_effect`), a root that failed verification, a conflicting root claim, an earlier
  incomplete deletion, or a tombstone batch over the bound. There is no hold registry yet, so no
  hold can be placed or block (`hold_registry: absent`).
- **Unknown copies are named, not ignored.** The original input file (the deployment never owned
  it), unrecorded operator exports (`--report-out`, `--event-out`, receipts, PGM and segment
  extracts), and every alert that may have been transmitted to a relay. They are listed as not
  proven deleted in the completion record; they do not block local deletion.
- **What the proof says.** Bytes are unlinked from the local filesystem (`filesystem_unlink`) and
  every removed name is verified absent from the spool. The spool is not encrypted, so this is
  not cryptographic erasure; filesystem-level recovery, snapshots, backups and storage-device
  remanence are out of scope and stated so in every plan and completion record. The plan and
  completion records keep digests, identities and sizes of deleted objects, never content.

Not enforced yet: a hold registry and retention schedules, subject- or event-scoped plans,
remote archive, replica and repair-symbol deletion, cryptographic erasure, and deletion of agent
memory that does not embed an evidence digest.

## 9. Model/data governance

- no household footage is used for general model training by default;
- deployment-specific fine-tuning requires an explicit dataset root, consent, purpose, license,
  holdout, and removal path;
- research-only model oracles cannot retain or transmit fixture inputs outside their declared laboratory capability;
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

## 13. Agent workspace, context, and handoff data

`WorldEnvelope` alternatives and adversarial residuals may themselves reveal sensitive routines, blind spots, or inferred occupancy. They inherit the strictest privacy, retention, export, legal-hold, and deletion class of their supporting evidence and cannot be reconstructed for a less-authorized principal through counts, ranking, or omitted-world metadata.

Agent-derived artifacts can be more privacy-sensitive than a single source frame because they
aggregate identities, routines, locations, hypotheses, uncertainty, and operational conclusions.
The following are privacy-governed derived data:

- missions, objective contracts, session/workspace capsules, aliases, and cursors;
- situation capsules/frames, knowledge cells, attention frontiers, and context packs;
- investigation cases, hypotheses, predictions, findings, contradictions, and counterfactuals;
- affordance frontiers, plans, work claims, obligations, episodes, feedback, and learning proposals;
- explanations, semantic-compression receipts, experience capsules, and handoff capsules.

Each object names the privacy generation and authorization projection under which it was produced.
A later reader receives a newly projected/redacted view; prior broad authority is never inherited
from the object's existence. Counts, graph topology, aliases, absence, ranking, omissions, and
continuation tokens are treated as potential side channels.

Context selection minimizes privacy exposure as an explicit budget dimension. The system prefers
semantic cells and bounded redacted artifacts over raw media when they are decision-equivalent. It
must not conceal the epistemic cost of masking or redaction: affected claims become `redacted`,
`unknown`, or `not_observable` as appropriate rather than retaining unearned confidence.

A handoff is published root-last only after child-by-child privacy, retention, legal-hold, and
capability checks. It carries the minimum sufficient continuity state, an expiry, allowed recipient
scope, and deletion-closure identity. Handoff, context, episode, and learning graphs participate in
graph-complete export and deletion, including derived indexes, caches, repair symbols, replicas,
journals, and stale continuations.

Operational memory is advisory and applicability-scoped. It must not create cross-household or
cross-property identity linkage, silently preserve deleted personal facts, or make a historical
observation appear current. Harmful/privacy-violating transfer is part of the trauma-guard and
`QL-AGENT-001` evaluation.
