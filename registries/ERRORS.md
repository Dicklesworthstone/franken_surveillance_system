# Stable error registry

Errors are machine identities with structured fields. Human text can improve without changing the
contract. Cancellation and panic remain distinct outcome channels; indeterminate effects are
operation states rather than generic errors.

| ID | Meaning | Retry policy |
|---|---|---|
| `ERR-AUTH-DENIED-001` | principal lacks exact capability | do not retry without new authority |
| `ERR-SECRET-UNAVAILABLE-001` | secret handle cannot be resolved | repair/rotate; bounded retry if provider transient |
| `ERR-DEVICE-UNSUPPORTED-001` | exact product/firmware/app tuple not certified | fail closed or explicit import-only mode |
| `ERR-FIRMWARE-DRIFT-001` | observed device generation differs from registry | disable/move to shadow; no optimistic retry |
| `ERR-ADAPTER-PROTOCOL-001` | adapter response violates typed protocol | terminate adapter generation; retain fixture |
| `ERR-STREAM-NO-FIRST-FRAME-001` | adapter accepted but no decodable frame before budget | reconnect or fail; never claim coverage |
| `ERR-STREAM-CONTINUITY-001` | gaps/jitter exceed contract | degrade coverage; bounded recovery |
| `ERR-CLOCK-UNCERTAIN-001` | capture interval too wide for requested operation | degrade/abstain/recalibrate |
| `ERR-CLOCK-STATE-UNKNOWN-001` | clock synchronization state unknown when synchronised evidence required | obtain synchronisation certificate or abstain |
| `ERR-CLOCK-UNSYNCHRONISED-001` | clock unsynchronised or drift bound exceeds tolerance | synchronise clock or bound monotonic drift |
| `ERR-OPERATION-UNREGISTERED-001` | surveillance operation not registered in time uncertainty budget catalog | register operation tolerance before evaluation |
| `ERR-TIME-INTERVAL-INVERTED-001` | capture or transit interval earliest bound exceeds latest bound | correct interval bounds before evaluation |
| `ERR-CLOCK-BASIS-MISMATCH-001` | comparison or association between incompatible clock bases | convert to common basis or synchronise to UTC |
| `ERR-CLOCK-BASIS-UNKNOWN-NAME-001` | clock basis name is unrecognized | supply a registered clock basis name |
| `ERR-ARITHMETIC-OVERFLOW-001` | arithmetic overflow in timestamp or uncertainty calculation | bound timestamp values within addressable range |
| `ERR-NON-MONOTONE-NARROWING-001` | attempted non-monotone uncertainty narrowing violating FORMAL-010 | preserve monotone widening; retain sync evidence |
| `ERR-DECODE-001` | media decode failed | preserve source; alternate decoder only if registered |
| `ERR-DECODE-BOUNDS-001` | media exceeds declared bounds | fail closed |
| `ERR-DECODE-UNSUPPORTED-MEDIA-001` | retained import's media format is not admitted by the requested decode operation (single-frame JPEG decode/reopen of an Annex-B or HEVC import, H.264 range decode of a JPEG or HEVC import, or H.265 range decode of a JPEG or H.264 import) | use the format's decode operation; do not retry unchanged |
| `ERR-DECODE-INTERPRETATION-001` | operator component interpretation contradicts the media (admitted H.264 and H.265 are always YCbCr 4:2:0) | resubmit with the correct explicit interpretation |
| `ERR-DECODE-SOURCE-UNAVAILABLE-001` | requested import, segment or range is absent or its retained custody cannot be recovered | name an existing completed import and an in-range segment; repair custody before retry |
| `ERR-DECODE-H264-RANGE-NOT-IDR-001` | requested H.264 decode range does not begin at an IDR access unit, so its first picture would predict from references outside the range | start the range at an IDR segment |
| `ERR-DECODE-H264-RANGE-GAP-001` | a retained source gap lies inside the requested H.264 range; inter prediction cannot bridge omitted bytes | split the range at the gap and start after it at an IDR |
| `ERR-DECODE-H264-UNSUPPORTED-001` | H.264 stream uses a profile or coding tool outside the admitted set (progressive 8-bit 4:2:0 Baseline, Main and High); no approximate pixels are produced | transcode in the laboratory or wait for a registered decoder; do not retry unchanged |
| `ERR-DECODE-H265-RANGE-NOT-IRAP-001` | requested H.265 decode range does not begin at an IRAP (IDR, CRA or BLA) access unit, so its first picture would predict from references outside the range | start the range at an IRAP segment |
| `ERR-DECODE-H265-RANGE-GAP-001` | a retained source gap lies inside the requested H.265 range; inter prediction cannot bridge omitted bytes | split the range at the gap and start after it at an IRAP segment |
| `ERR-DECODE-H265-UNSUPPORTED-001` | H.265 stream uses a profile, sample format or coding tool outside the admitted set (Main and Main Still Picture, 8-bit 4:2:0; no range extensions, tiles, dependent slices or long-term references); no approximate pixels are produced | transcode in the laboratory or wait for a registered decoder; do not retry unchanged |
| `ERR-INGEST-FORMAT-AMBIGUOUS-001` | an Annex-B file's first NAL unit header is valid as both H.264 and H.265 and no media format was declared; the importer never guesses the codec | re-import with the explicit media format (`annexb` for H.264, `hevc` for H.265) |
| `ERR-INGEST-FORMAT-CONFLICT-001` | the declared media format contradicts the file's signature (e.g. `hevc` declared for a stream whose first header is only valid H.264) | declare the format the file actually holds; do not retry unchanged |
| `ERR-WATCH-PLAN-INVALID-001` | model-free watch plan is outside its bounds (range 1..128 frames, 1..16 zones, zone ids, detector/tracker thresholds) | correct the plan; do not retry unchanged |
| `ERR-WATCH-SOURCE-GAP-001` | a retained source gap lies inside the watch range; background and track continuity cannot bridge omitted frames | split the range at the gap |
| `ERR-WATCH-LIMIT-001` | watch candidate, detection or active-track bound reached; nothing is silently dropped | narrow the range or zones, or raise thresholds |
| `ERR-WATCH-APPROVAL-STALE-001` | an approval digest matches no candidate proposal of this exact analysis; nothing was published | rerun without approval and review the current proposal digests |
| `ERR-WATCH-001` | model-free watch refused by the foreground, tracker, zone gate, event contract or storage owner | inspect the cause; retry only after repair |
| `ERR-MODEL-PACKAGE-DIGEST-001` | model package bytes differ from the independently pinned whole-archive SHA-256 (tampered, truncated or wrong file); refused before parsing | obtain the exact package; never re-pin to accept unknown bytes |
| `ERR-MODEL-PACKAGE-INVALID-001` | model package archive, manifest, artifact set, package spec, IR graph, weights or head contract is malformed, inconsistent or outside its bounds | rebuild the package with the offline importer; do not retry unchanged |
| `ERR-MODEL-PACKAGE-LICENSE-001` | model package license record refused by the license policy (surveillance-monitoring profile, license-text digest required) | review the license; do not load the package |
| `ERR-MODEL-PACKAGE-CANCELLED-001` | model package load cancelled by its owner before a complete verified package existed | retry when the owner permits; nothing was loaded |
| `ERR-PACKAGE-DETECT-REQUEST-001` | package detection range, frame count (1..64) or retained media format outside the operation contract; refused before decode | correct the request; do not retry unchanged |
| `ERR-PACKAGE-DETECT-001` | package detection refused at a named segment by retained custody, decode, preprocessing, model execution or head projection; no partial report | inspect the cause; retry only after repair or with adequate bounds |
| `ERR-PACKAGE-DETECT-CANCELLED-001` | package detection cancelled by its owner; no partial report | rerun the same range |
| `ERR-DETECTOR-CASCADE-PLAN-001` | detector-cascade policy outside its bounds (frames per track 1..8, max inferences 1..64, association IoU and score threshold at most 1000000 ppm) or a threshold the package refuses; refused before any source is read | correct the cascade options; do not retry unchanged |
| `ERR-DETECTOR-CASCADE-BUDGET-001` | a frame the cheap watch gate selected was not inferred because the explicit `--detector-max-inferences` budget was exhausted; a typed per-frame outcome in the report and a non-supporting evidence record, never a silent drop and never evidence of absence | raise the budget or narrow the range if the frame matters |
| `ERR-PACKAGE-EVENT-REQUEST-001` | package report/event request outside its contract (label not in the package vocabulary, tracking policy out of bounds, or bytes that are not a package analysis report) | correct the request; do not retry unchanged |
| `ERR-PACKAGE-EVENT-UNAVAILABLE-001` | the deployment retains no package detection with this report digest (only `fss-infer package-detect --retain yes` retains one) | retain the detection first, then rerun |
| `ERR-PACKAGE-EVENT-MISMATCH-001` | retained package-detection custody, its canonical record, or an exported package analysis report disagrees with the rebuild from custody | do not trust the bytes; investigate custody and re-export |
| `ERR-PACKAGE-EVENT-TRACK-001` | the selected package-report track does not exist or was never confirmed | choose a confirmed track from the report output |
| `ERR-PACKAGE-EVENT-APPROVAL-STALE-001` | the approval digest is not the freshly prepared package-event proposal; nothing was published | prepare again and review the current proposal digest |
| `ERR-PACKAGE-EVENT-CANCELLED-001` | package retention, report, preparation or publication cancelled by its owner; committed provenance may remain, no success is claimed | rerun; exact reruns resume without duplicates |
| `ERR-PACKAGE-EVENT-001` | package retention or event publication refused by the tracker, event contract or storage owner | inspect the cause; retry only after repair |
| `ERR-CORROBORATE-PLAN-INVALID-001` | two-sensor corroboration plan is outside its bounds (camera names, 1..16 ground zones, time gate 1..60 s, finite positive distance gate, recordings of 1..128 frames) | correct the plan; do not retry unchanged |
| `ERR-CORROBORATE-HOMOGRAPHY-INVALID-001` | an owner-supplied image-to-ground homography is non-finite, singular, or maps an observed foot point to or beyond the ground horizon; it is an owner assertion, never a calibration certificate | supply a valid homography for that camera; do not retry unchanged |
| `ERR-CORROBORATE-SAME-SENSOR-001` | both recordings come from one sensor (or are one import); one failure domain can never corroborate itself | name recordings from two distinct sensors |
| `ERR-CORROBORATE-TIME-UNKNOWN-001` | a recording has no operator capture-time hint, so its capture time is unknown and cannot be aligned by assumption | re-import with explicit capture hints or abstain |
| `ERR-CORROBORATE-TIME-UNALIGNED-001` | the two recordings' conservative capture spans do not overlap: clocks are unaligned or the recordings cover different periods | supply recordings of one period on an aligned time base or abstain |
| `ERR-CORROBORATE-APPROVAL-STALE-001` | an approval digest matches no corroborated proposal of this exact analysis; nothing was published | rerun without approval and review the current proposal digests |
| `ERR-CORROBORATE-POSE-INVALID-001` | an owner calibrated camera pose (`--pose`) is refused for ground-zone visibility: its intrinsics describe another image size than the decoded frames, or it disagrees with the camera's ground homography over a zone; a pose is an owner assertion, never a calibration certificate | supply a pose consistent with the decoded frames and the homography, or omit it (coverage is then homography-frustum-only); do not retry unchanged |
| `ERR-CORROBORATE-VISIBILITY-001` | geometric ground-zone visibility could not be assessed: the sampling policy is outside its registered bounds, the owner scene-mesh package was refused (digest, format, references, limits), or a visibility query was degenerate or over its geometry budget; nothing was analysed and no coverage is claimed | correct the policy or supply the exact scene-mesh package and digests; do not retry unchanged |
| `ERR-CORROBORATE-001` | two-sensor corroboration refused by association, the event/policy contract or the storage owner | inspect the cause; retry only after repair |
| `ERR-SITE-CALIBRATION-INPUT-INVALID-001` | a site calibration request or camera observation file (fss.site_camera_observations.v1) is malformed or out of bounds: camera count outside 2..16, duplicate names or handles, a missing or repeated header line, a zero handle or generation, a non-finite number, a pixel outside the image, a feature or tie limit, or mixed descriptor generations; nothing was calibrated or written | correct the observation files or options; do not retry unchanged |
| `ERR-SITE-CALIBRATION-BASIS-001` | the owner twin or atlas package was refused before any localization: a digest differs from its owner pin, the format or references are invalid, the atlas was built against another twin, or its descriptor generation differs from the observations'; nothing was written | supply the exact twin and atlas packages with their pinned digests |
| `ERR-SITE-CALIBRATION-LOCALIZATION-FAILED-001` | one camera could not be localized alone against the atlas (too few mutual descriptor matches, a geometric pose failure, no candidate in any focal sample, or exhausted work); no joint refinement ran and nothing was written | supply more or better correspondences or intrinsics for that camera; do not retry unchanged |
| `ERR-SITE-CALIBRATION-CONTROL-POINTS-001` | fewer than three atlas control points (or only collinear ones) constrain the joint solve under the control policy, so the metric gauge is not fixed; nothing was written | observe more surveyed landmarks or relax --control-max-error; never fabricate control points |
| `ERR-SITE-CALIBRATION-DISCONNECTED-001` | a camera shares no tie-point path with the other cameras, so a joint refinement would not couple it; nothing was written | add tie points that camera shares with a connected camera, or calibrate it separately |
| `ERR-SITE-CALIBRATION-REFINEMENT-001` | the joint bundle refinement refused (degenerate tie rays, non-finite observation, adjuster refusal, non-convergence, budget or limit); no calibration was written | inspect the cause; correct inputs or raise --work-units within bounds |
| `ERR-SITE-CALIBRATION-FORMAT-001` | a site calibration file is not a canonical FSSCAL01 record (wrong magic, length, truncated, non-finite, unregistered value, trailing bytes or noncanonical encoding); it was not used | regenerate it with fss-event calibrate; never hand-edit a calibration |
| `ERR-SITE-CALIBRATION-DIGEST-001` | a site calibration's bytes do not match its trailing fss.site_calibration.v1 identity, or the identity differs from the owner-pinned --calibration-digest (tampered or another calibration); nothing was read or analysed | pin the exact digest printed by calibrate for the exact file |
| `ERR-SITE-CALIBRATION-DISTORTED-001` | a calibrated camera carries radial distortion, which a pinhole ground-visibility consumer cannot represent; nothing was analysed | calibrate that camera with a pinhole model or supply undistorted geometry; do not retry unchanged |
| `ERR-SITE-CALIBRATION-CAMERA-UNBOUND-001` | the supplied calibration names none of the corroborated cameras, so it would bind no pose; nothing was analysed | use the calibration of these cameras (matching names) or omit --calibration |
| `ERR-SITE-CALIBRATION-FRAME-MISMATCH-001` | the calibration's world frame (its twin package) is not the supplied --scene-mesh package, so poses and mesh may not share a frame; nothing was analysed | use the scene mesh the calibration was made against, or recalibrate |
| `ERR-CORROBORATE-POSE-SOURCE-CONFLICT-001` | a corroborated camera received a pose from both --pose and --calibration; exactly one pose source per camera is allowed; nothing was analysed | drop the --pose for that camera or use a calibration that does not name it |
| `ERR-COVERAGE-APPROVAL-STALE-001` | a `--retain-coverage` approval digest matches neither the fresh analysis's coverage proposal (which binds the authority anchor it read) nor the coverage already retained for that analysis; nothing was retained | rerun without the approval and review the current coverage approval digest |
| `ERR-COVERAGE-001` | a coverage record could not be built, validated, staged or committed (witness domain/predicate/generation mismatch, unknown capture time with a witness, storage refusal) | inspect the cause; retry only after repair; no absence is certified |
| `ERR-GRAPH-INPUT-INVALID-001` | a graph projection or request is outside the strict graph policy (empty, oversized or control-character node identity, duplicate node, unknown endpoint or root, self-loop, parallel edge, or node/edge limit); nothing was analysed | correct the projection; inputs are refused, never repaired; do not retry unchanged |
| `ERR-GRAPH-BUDGET-EXHAUSTED-001` | a declared graph budget (operations or output entries) ran out before the exact answer was complete; no partial answer or witness was produced | raise the budget within the registered bound or narrow the projection |
| `ERR-GRAPH-COMPLEXITY-BOUND-001` | an observed graph operation counter exceeded the registered complexity or output bound for the input size, at run time or when a witness is re-checked; no answer is trusted | treat as an implementation defect or tampered witness; do not retry unchanged |
| `ERR-GRAPH-RESULT-INCONSISTENT-001` | a projection-level answer derived from a graph run disagrees with the projection's structural invariant (for example coverage single points versus the witnessed observers); nothing was reported | treat as an implementation defect; do not retry unchanged |
| `ERR-PRIVACY-MASK-POLICY-001` | a declared privacy mask policy is outside its contract (resolution 1..4096 per dimension, 1..32 non-empty duplicate-free rectangles inside the declared resolution) | correct the declaration; do not retry unchanged |
| `ERR-PRIVACY-MASK-APPROVAL-STALE-001` | a `privacy-mask declare --approve` digest matches neither this declaration over the sensor's current retained policy nor the approval that retained it; nothing was written | rerun without the approval and review the current approval digest |
| `ERR-PRIVACY-MASK-RESOLUTION-001` | decoded frame dimensions differ from the sensor's retained privacy mask resolution; no pixel is served unmasked | declare a policy for the actual stream resolution; do not retry unchanged |
| `ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001` | the request would serve or analyse pixels the sensor's current retained privacy mask does not mask (raw retained source export: `fss-file extract` of a masked sensor, and `fss-archive export` of original RTSP packets of a masked sensor or naming no privacy deployment; a decode retained under no or a superseded mask policy; a live, recording, replay or `check-http` decode naming no sensor; an owner permission grid or frozen background admitting masked pixels; RGB evidence recorded under another binding); no override capability exists | decode again under the current policy, naming the sensor; exclude masked pixels from the permission grid and refreeze the background; raw source of a masked sensor has no export path |
| `ERR-ALERT-ROUTE-INVALID-001` | alert relay route is not admissible (exact IP:PORT, plain absolute path, nonzero plaintext-route approval) | supply an admissible explicit route; no DNS, redirect or TLS downgrade is attempted |
| `ERR-ALERT-AUTHORITY-001` | the event is absent, or its current authority, prepared plan or receipt cannot be read and verified against the ledger | inspect or repair the deployment; never dispatch from unverified authority |
| `ERR-ALERT-NOT-ELIGIBLE-001` | policy, corroboration or sensor-integrity gates refuse an alert for this event (not corroborated, held, or open tamper) | do not retry; obtain independent corroboration or resolve the integrity risk |
| `ERR-ALERT-APPROVAL-STALE-001` | an alert plan or dispatch approval digest does not match the current plan, route, principal, prepared record or deadline; nothing was prepared or sent | rerun without the stale approval and review the reported digests |
| `ERR-ALERT-CLOCK-001` | the admission clock is unavailable or behind the effect journal's last transition | repair the host clock; nothing was committed |
| `ERR-ALERT-DISPATCH-001` | the durable effect journal or live webhook authority refused before any network I/O, or the observation could not be recorded | inspect the journal; a committed operation is never resent automatically |
| `ERR-CANONICAL-TRUNCATED-001` | canonical bytes declare more collection elements than the bytes that remain (truncated buffer) | re-fetch the complete canonical bytes; do not retry unchanged |
| `ERR-MODEL-UNAVAILABLE-001` | model generation not runnable | route to registered fallback or degrade |
| `ERR-MODEL-OUTPUT-001` | malformed/out-of-bounds model output | reject output; terminate/quarantine generation |
| `ERR-MODEL-GENERATION-001` | mixed or stale model/index generation | rebuild/retry at coherent generation |
| `ERR-CALIBRATION-INVALID-001` | certificate expired/invalidated/residual failure | no geometry-dependent negative evidence |
| `ERR-COVERAGE-UNKNOWN-001` | effective observability cannot be established | abstain/escalate health alert |
| `ERR-EVIDENCE-MISSING-001` | canonical root references unavailable required evidence | repair; no adjudication requiring it |
| `ERR-PUBLICATION-PARTIAL-001` | child staging incomplete; root not visible | idempotent retry or collect children |
| `ERR-ARCHIVE-UNREACHABLE-001` | remote archive unavailable | local spool obligation; bounded retry |
| `ERR-ARCHIVE-VERIFY-001` | published object failed retrieval/integrity check | quarantine/repair/escalate |
| `ERR-IDEMPOTENCY-CONFLICT-001` | same key used with different request digest | reject permanently |
| `ERR-EFFECT-INDETERMINATE-001` | dispatch outcome cannot be determined | reconcile before retry |
| `ERR-LEASE-STALE-001` | effect lease fence is not current | re-prepare under fresh lease |
| `ERR-PRECONDITION-STALE-001` | plan anchor changed before commit | re-plan; never auto-commit changed intent |
| `ERR-PRIVACY-MASK-001` | required redaction could not be applied | fail closed at restricted boundary |
| `ERR-HYDRATION-INVALID-PRIVACY-CLASS-001` | H2 decision artifact privacy class is not `private:property`, the only privacy class fss-core uses; raw or unredacted media included (code `invalid_privacy_class`) | supply the authorized privacy class; do not retry unchanged |
| `ERR-HYDRATION-INVALID-REDACTION-TRANSFORM-001` | H2 redaction transform is not a recognized `transform:*` token or is incompatible with the artifact kind (code `invalid_redaction_transform`) | apply a recognized transform compatible with the artifact kind |
| `ERR-DELETION-BLOCKED-001` | deletion closure blocked by hold/backend/offline copy; realized by `fss-event delete commit` (FSS-037): the sealed plan names an open or indeterminate effect that references the evidence (`open_effect`), a root that failed verification (`broken_root_unclassified`), a conflicting root claim, an earlier incomplete deletion, or a tombstone batch over the bound; nothing was written (the reference deployment has no hold registry yet) | report exact blockers and obligation; resolve them, plan again, approve the new plan |
| `ERR-HOLD-REQUEST-001` | an `fss-hold` request is outside its contract: invalid bounded request, unknown hold on release, identifier already bound to another import or placement, or a released identifier reused; nothing was written | correct the request; identifiers are never reused |
| `ERR-HOLD-APPROVAL-STALE-001` | an `fss-hold --approve` digest no longer names the exact prepared transition over the current authority head; nothing was written | rerun without the approval and approve the printed digest |
| `ERR-HOLD-DELETION-IN-PROGRESS-001` | a deletion of the import is committed but not complete, so preservation can no longer be promised; retention mutations are refused | finish or reconcile the deletion first |
| `ERR-HOLD-BOUND-001` | retained hold history or active held-closure bounds are exhausted (registries/evidence_holds.json limits); holds are never evicted | release holds or raise the reviewed bound |
| `ERR-HOLD-CANCELLED-001` | the hold operation was cancelled cooperatively, including before a staged record was appended | retry the same request; approvals stay exact |
| `ERR-HOLD-STORAGE-001` | hold authority is missing, corrupt, shadowed or inconsistent, or an underlying ledger, spool, import or deletion-history read failed; never treated as no hold | repair the deployment; do not delete while unresolved |
| `ERR-RETENTION-NOT-ELAPSED-001` | `fss-hold expire` names an earliest owner-attested time before the hold's minimum-retention deadline (or an uncertain time); the hold stays active | retry after the deadline with a new attested time |
| `ERR-EVIDENCE-DELETED-001` | the requested import (or its derivative) was deleted under a committed deletion record; availability `deleted`, not missing; a deleted import identity is never re-imported | do not retry; the record names the deletion plan |
| `ERR-DELETION-IMPORT-UNKNOWN-001` | `delete plan` names no completed, retained import | check the import identity; do not retry unchanged |
| `ERR-DELETION-SCOPE-EMPTY-001` | `delete plan --sensor-id` or `--event-id` reaches no completed, retained import: no retained import's capsules name the sensor, no committed event has the identity, or every member import is already deleted (fss-x4a.30.86.20); nothing was written | check the sensor or event identity; a deleted member reads `ERR-EVIDENCE-DELETED-001` by `--import-id` |
| `ERR-DELETION-PLAN-STALE-001` | no deletion plan recomputed against the current head has the given digest (the deployment changed after planning, or the plan is unknown); nothing was written | plan again and approve the new plan; never commit a changed plan |
| `ERR-DELETION-APPROVAL-001` | the approval is not the exact approval of this deletion plan for this principal; nothing was written | approve the printed approval digest of the current plan |
| `ERR-DELETION-BOUND-001` | a deletion plan or record exceeded a hard bound | split the deployment's retained history; do not retry unchanged |
| `ERR-DELETION-INCOMPLETE-001` | a deletion commit was interrupted after its record became durable, or a removed name is still present; completion was not claimed and every deleted digest already reads `deleted` | rerun the same `delete commit`; it resumes and completes exactly once |
| `ERR-DELETION-STORAGE-001` | deployment custody, ledger or publication storage failed during a deletion plan or commit | repair storage (`fss doctor`), then rerun the same command |
| `ERR-BUDGET-EXHAUSTED-001` | declared work budget exhausted | return bounded partial/abstention |
| `ERR-REPLAY-DIVERGED-001` | semantic decision fingerprint differs from proof | block claim/release |
| `ERR-QUIESCENCE-001` | region/process failed to drain | block shutdown/upgrade claim; force isolation path |
| `ERR-SCHEMA-UNSUPPORTED-001` | input durable schema version unsupported | migrate with registered path or reject |
| `ERR-INTERNAL-PANIC-001` | boundary converted an internal panic to structured crash receipt | quarantine, preserve support bundle |
| `ERR-AGENT-SESSION-STALE-001` | session, workspace, or resumed handoff basis no longer satisfies required anchor/generation/freshness semantics | rebase and enumerate every invalidated assumption, alias, grant, lease, plan, continuation, and affordance before proceeding |
| `ERR-AGENT-AMBIGUOUS-001` | natural-language request has multiple materially different interpretations | return interpretations; choose only a registered safe-read default or request clarification |
| `ERR-AGENT-CONTEXT-INCOMPLETE-001` | requested decision-complete context cannot fit or lacks required evidence | return bounded partial with omissions/expansion handles; never imply completeness |
| `ERR-AGENT-HANDOFF-INVALID-001` | handoff root is incomplete, expired, unauthorized, schema/generation-incompatible, or cannot be safely rebased | reject, migrate, or open a new session with an explicit invalidation report; never silently resume |
| `ERR-AGENT-WORK-CLAIM-CONFLICT-001` | requested multi-agent work scope overlaps an incompatible live claim, lease, or fence | narrow, wait, delegate, release, or supersede with explicit authority; never last-writer-wins |
| `ERR-AGENT-NO-AFFORDANCE-001` | no safe, authorized, useful next action exists under current evidence/budget | explain blocking clamps and return wait/escalate/stop reason |
| `ERR-AGENT-LEARNING-UNSUPPORTED-001` | learning proposal lacks evidence, applicability, counterexamples, or validation path | retain as rejected/advisory; do not activate |
| `ERR-AGENT-TRANSPORT-DIVERGED-001` | CLI/MCP/TUI/report semantic payload or digest differs for equivalent input | block affected surface/release and retain differential transcript |
| `ERR-AGENT-RESUME-INDETERMINATE-001` | external effects/obligations prevent a truthful resumed terminal state | resume in reconciliation mode; no effect retry before lookup/proof |
| `ERR-AGENT-RESNAPSHOT-001` | continuation cannot advance coherently from its exact basis | request a fresh situation capsule; do not splice generations |
| `ERR-AGENT-AFFORDANCE-INVALIDATED-001` | recommended next move lost a precondition, capability, lease, or validity interval | refresh/replan; never execute cached recommendation |
| `ERR-AGENT-CASE-BUDGET-001` | investigation cannot discriminate remaining hypotheses within declared budget | return residual uncertainty and explicit next probe/approval options |
| `ERR-AGENT-PROTOCOL-001` | presentation attempted an unregistered verb/view or changed semantic meaning | reject and repair registry/transport drift |
| `ERR-AGENT-HIDDEN-STATE-001` | required mission state exists only in conversation or caller memory | persist typed mission/workspace/case/plan/finding/handoff state before proceeding |
| `ERR-AGENT-EVENT-NOT-FOUND-001` | explain named an event identity that no committed `event_revision` delta publishes at the evaluated anchor | orient to list published events; retry only after the ledger head advances |
| `ERR-AGENT-FOLLOW-ANCHOR-FOREIGN-001` | follow named an anchor token whose site lineage is another deployment's | orient this deployment and follow from the anchor token it emits |
| `ERR-AGENT-FOLLOW-ANCHOR-AHEAD-001` | follow named an anchor token past the deployment's committed ledger head or effect-journal records | orient again and follow from the current anchor token; never follow from a position the history has not committed |
| `ERR-AGENT-FOLLOW-ANCHOR-UNKNOWN-001` | follow named an anchor token whose binding does not match the deployment's committed history at its position (altered token or divergent history) | orient again and follow from the anchor token it emits; never rebase silently onto another history |
| `ERR-AGENT-SESSION-NOT-FOUND-001` | session handoff named a session that is unknown, closed, expired, or held by another principal in the deployment's agent-session journal (deliberately indistinguishable) | open a session with `fss session open` or resume a published handoff; never guess another principal's session |
| `ERR-AGENT-HANDOFF-NOT-FOUND-001` | session resume named a handoff identity that no root in the deployment's agent publications holds (never published, or its publication was interrupted before the root became visible) | resume only a handoff identity `fss handoff` returned for this deployment, or hand off again |
| `ERR-AGENT-SESSION-STORE-LOCKED-001` | another session command holds the deployment's agent-session store lock | retry after the other command finishes; the store is never shared by two writers |
| `ERR-AGENT-SESSION-STORE-INVALID-001` | the deployment's agent-session store failed verification (journal rollback or foreign journal against its pinned root, an incomplete append, an orphaned publication temporary, or a missing mission record) | inspect `agent/` under the deployment root; the store is never repaired, truncated, or re-pinned implicitly |
| `ERR-AGENT-FOLLOW-CONTINUATION-001` | follow continuation is not a cursor of the exact stream (altered, issued for another anchor, view, or page size, or issued before the head advanced) | follow again without the continuation to receive the first page of the current delta |
| `ERR-AGENT-BASIS-BAD-MAGIC-001` | ContractBasis binary envelope magic header does not match CONTRACT_BASIS_MAGIC | verify binary envelope format or use canonical encoder |
| `ERR-AGENT-BASIS-VERSION-001` | ContractBasis binary envelope format version is unsupported | upgrade client or server to matching format version |
| `ERR-AGENT-BASIS-TRUNCATED-001` | ContractBasis binary envelope ended prematurely before declared length or minimum envelope size | retransmit complete binary envelope without truncation |
| `ERR-AGENT-BASIS-OVERSIZED-001` | ContractBasis binary payload or envelope exceeds maximum permitted byte limit | reduce payload size within configured bound or check framing |
| `ERR-AGENT-BASIS-TRAILING-BYTES-001` | ContractBasis binary envelope contains unexpected trailing bytes after declared payload | strip extraneous trailing bytes and ensure canonical framing |
| `ERR-AGENT-BASIS-CHECKSUM-MISMATCH-001` | ContractBasis binary envelope trailing checksum verification failed | recompute checksum or retransmit uncorrupted envelope |
| `ERR-AGENT-BASIS-INVALID-ID-001` | ContractBasis identifier field failed pattern, length, or character set validation | provide identifier matching ^[A-Za-z0-9][A-Za-z0-9:._+/-]*$ within length limit |
| `ERR-AGENT-BASIS-ALGORITHM-001` | ContractBasis registry digest specifies unsupported algorithm (Blake3 prohibited; Sha256 required) | compute registry digest with canonical SHA-256 algorithm |
| `ERR-CLI-UNKNOWN-COMMAND-001` | command token is not a recognized CLI command or verb | do not retry without valid command name |
| `ERR-CLI-UNKNOWN-OPTION-001` | option flag is unrecognized for binary or active command | do not retry without valid option flag |
| `ERR-CLI-MISSING-VALUE-001` | required option or positional argument value is missing | provide required value before retry |
| `ERR-CLI-DUPLICATE-OPTION-001` | option flag was specified more than once | specify option at most once |
| `ERR-CLI-MALFORMED-VALUE-001` | option or argument value cannot be parsed into expected domain | provide valid typed value before retry |
| `ERR-CLI-INVALID-UNICODE-001` | command-line argument contains invalid UTF-8 bytes | encode command-line arguments in UTF-8 |
| `ERR-CLI-UNEXPECTED-POSITIONAL-001` | positional argument provided to command taking no positionals | remove unexpected positional argument |
| `ERR-CLI-TRAILING-ARGUMENT-001` | extra argument provided after command grammar is satisfied | remove trailing argument before retry |
| `ERR-CLI-RUNTIME-FAILURE-001` | runtime error occurred during validated command execution | inspect diagnostic and address failure cause |
| `ERR-OP-EXECUTION-FAILED-001` | operation execution failed with expected domain error | inspect error details and apply recovery guidance |
| `ERR-OP-PRECONDITION-FAILED-001` | tombstone: superseded by `ERR-PRECONDITION-STALE-001` | historical duplicate preserved for audit; canonical target is `ERR-PRECONDITION-STALE-001` |
| `ERR-OP-INDETERMINATE-001` | tombstone: superseded by `ERR-EFFECT-INDETERMINATE-001` | historical duplicate preserved for audit; indeterminate outcomes must use Indeterminate variant |
| `ERR-OP-UNAUTHORIZED-001` | tombstone: superseded by `ERR-AUTH-DENIED-001` | historical duplicate preserved for audit; canonical target is `ERR-AUTH-DENIED-001` |
| `ERR-OP-NOT-OBSERVABLE-001` | tombstone: superseded by `ERR-COVERAGE-UNKNOWN-001` | historical duplicate preserved for audit; canonical target is `ERR-COVERAGE-UNKNOWN-001` |
| `ERR-OP-TIMEOUT-001` | operation budget or deadline expired before completion | retry with higher budget or backoff |
| `ERR-OP-RECONCILIATION-REQUIRED-001` | pending unresolved operation must be reconciled before further mutation | reconcile pending sequence before retry |
| `ERR-OP-ID-MALFORMED-001` | error identity does not conform to stable ERR pattern | fix error identity to match stable registry format |
| `ERR-OP-INVALID-OUTCOME-001` | operation outcome state transition or representation is invalid | inspect outcome payload and repair state machine |
| `ERR-LEDGER-LENGTH-OVERFLOW-001` | journal byte offset or file length exceeds addressable 64-bit bounds | archive or rotate journal; no in-place append possible |
| `ERR-LEDGER-ORACLE-INVALID-CONFIG-001` | ledger oracle limit or site lineage outside its admitted range | repair configuration; do not retry unchanged |
| `ERR-LEDGER-ORACLE-BOUND-001` | batch delta count, child count, or text field exceeds the canonical batch bound | reject input; split or repair the producer |
| `ERR-LEDGER-ORACLE-NON-CANONICAL-001` | batch deltas or child roots are not in strictly increasing canonical order | reject input; re-prepare canonically |
| `ERR-LEDGER-ORACLE-DIGEST-MISMATCH-001` | declared batch digest does not match batch content | reject input; never retry unchanged |
| `ERR-LEDGER-ORACLE-DUPLICATE-BATCH-001` | exact batch is already committed at the reported sequence | no retry; batch is already canonical |
| `ERR-LEDGER-ORACLE-BATCH-ID-CONFLICT-001` | committed batch identity reused with different content | reject input; stable batch IDs are never reused |
| `ERR-LEDGER-DURABLE-BATCH-ID-CONFLICT-001` | durable ledger batch identity already committed with different content | reject input; stable batch IDs are never reused |
| `ERR-LEDGER-SEALED-NAMESPACE-001` | batch writes the sealed publication-lineage namespace (a lineage or proof-marker family or object) outside record_reference_publication, or the gated writer was handed an unsealed batch | reject input; record publications only through record_reference_publication |
| `ERR-LEDGER-ORACLE-CAPACITY-001` | committed-batch capacity of the oracle is exhausted | archive or rotate before appending |
| `ERR-LEDGER-ORACLE-SEQUENCE-GAP-001` | batch basis is beyond the head; predecessor batches are missing | supply predecessors in canonical order, then retry |
| `ERR-LEDGER-ORACLE-BASIS-FORKED-001` | batch basis anchor is not the committed anchor at its sequence | reject input; foreign lineage, epoch, or state root |
| `ERR-LEDGER-ORACLE-SUCCESSOR-CONFLICT-001` | another batch already committed on the same basis (first committer wins) | rebase onto the current head and prepare a new batch |
| `ERR-LEDGER-ORACLE-INVALID-SUCCESSOR-001` | successor anchor lineage, epoch, or sequence does not follow its basis | reject input; re-prepare against the head |
| `ERR-LEDGER-ORACLE-SEQUENCE-EXHAUSTED-001` | commit sequence space is exhausted | archive or rotate; no in-place append possible |
| `ERR-LEDGER-ORACLE-DUPLICATE-OBJECT-001` | one batch carries more than one delta for the same object | reject input; merge or split deltas |
| `ERR-LEDGER-ORACLE-GENERATION-CONFLICT-001` | delta generations do not follow the committed object generation | reject input; re-prepare against the head |
| `ERR-LEDGER-ORACLE-OBJECT-CAPACITY-001` | batch would exceed the live-object capacity of the oracle | archive or rotate before appending |
| `ERR-LEDGER-ORACLE-STATE-ROOT-MISMATCH-001` | declared successor state root does not match the applied deltas | reject input; never retry unchanged |
| `ERR-LEDGER-ORACLE-STALE-STAGE-001` | staged batch was validated against a head that has since moved or another history | stage again against the current head |
| `ERR-LEDGER-ORACLE-ENCODING-001` | canonical encoding of a digest input exceeded its encoder bound | reject input; repair the oversized field |
| `ERR-LEDGER-ORACLE-READ-BEYOND-HEAD-001` | anchor-pinned read requested a sequence beyond the committed head | wait for commit or read at a committed anchor |
| `ERR-LEDGER-ORACLE-READ-ANCHOR-MISMATCH-001` | anchor-pinned read named an anchor that is not committed in this history | resnapshot from a committed anchor of this lineage |
| `ERR-PUBLICATION-LOCAL-INVALID-CONFIG-001` | local publication limits are zero, inconsistent, or above a format maximum | repair configuration; do not retry unchanged |
| `ERR-PUBLICATION-LOCAL-SLOT-INVALID-001` | publication slot name is empty, too long, or outside the slot grammar | reject input; choose a registered slot name |
| `ERR-PUBLICATION-LOCAL-BOUND-001` | manifest child count or directory entry count exceeds the configured bound | reject input; split the manifest or repair the layout |
| `ERR-PUBLICATION-LOCAL-CAPACITY-001` | configured root or tombstone capacity of the local publisher is exhausted | archive or rotate before publishing |
| `ERR-PUBLICATION-LOCAL-CORRUPT-REFERENCE-001` | a referenced object failed digest verification; root not visible | repair or restage the named object, then retry idempotently |
| `ERR-PUBLICATION-LOCAL-TOMBSTONED-REFERENCE-001` | a referenced object carries a durable tombstone; root not visible | reject input; tombstoned objects are never republished |
| `ERR-PUBLICATION-LOCAL-UNAVAILABLE-001` | custody of a referenced object could not be determined; root not visible | reopen to reconcile storage, then retry idempotently |
| `ERR-PUBLICATION-LOCAL-SLOT-CONFLICT-001` | slot already holds a different visible root | reject input; publish the new root under a new slot |
| `ERR-PUBLICATION-LOCAL-BROKEN-ROOT-001` | slot holds a root record that failed reopen verification | repair or quarantine the broken record; never overwrite it |
| `ERR-PUBLICATION-LOCAL-ORPHAN-TEMP-001` | an orphaned temporary record from an interrupted publication occupies the path | discard classified orphans, then retry idempotently |
| `ERR-PUBLICATION-LOCAL-MANIFEST-MISMATCH-001` | manifest root does not match its canonical body or its staged read-back | reject input; rebuild the manifest canonically |
| `ERR-PUBLICATION-LOCAL-SPOOL-001` | the staging spool refused an object stage, verify, or read | follow the nested spool failure; no root was made visible |
| `ERR-PUBLICATION-LOCAL-IO-001` | a publication filesystem operation failed before the root rename | bounded retry after repairing storage; nothing is visible |
| `ERR-PUBLICATION-LOCAL-LOCKED-001` | another owner holds the exclusive publication lock | wait for the owner to close; never share the root |
| `ERR-PUBLICATION-LOCAL-LAYOUT-001` | a publication directory or record path has the wrong file type or is occupied unexpectedly | repair the layout; nothing is overwritten |
| `ERR-PUBLICATION-LOCAL-INDETERMINATE-001` | root was renamed into place but its directory fsync failed; durability unknown | reopen to reconcile before any retry |
| `ERR-PUBLICATION-LOCAL-ROOT-VISIBILITY-INDETERMINATE-001` | root rename was reported failed and rolling back the possibly renamed record failed; visibility unknown, slot marked indeterminate | reopen to reconcile; the slot is refused until its record and indeterminate marker are repaired |
| `ERR-PUBLICATION-LOCAL-TOMBSTONE-VISIBILITY-INDETERMINATE-001` | tombstone rename was reported failed and rolling back the possibly renamed record failed; visibility unknown | reopen to reconcile; the tombstone is refused until its record and indeterminate marker are repaired |
| `ERR-PUBLICATION-LOCAL-CLEANUP-001` | removing a temporary publication file failed after an earlier error; both errors are carried | repair storage, discard orphaned temps, then retry idempotently |
| `ERR-PUBLICATION-LOCAL-INJECTED-CRASH-001` | a fault-injection cut point fired and the instance behaves as a dead process | reopen to reconcile |
| `ERR-PUBLICATION-LOCAL-CANCELLED-001` | publication was cancelled before the root rename; nothing is visible | retry idempotently when resumed |
| `ERR-PUBLICATION-LOCAL-POISONED-001` | publisher observed a crash or indeterminate outcome and refuses further work | reopen to reconcile |
| `ERR-PUBLICATION-LOCAL-DELETION-AUTHORITY-001` | tombstone record lacks a deletion authority witness | supply a verified deletion authority witness |
| `ERR-PUBLICATION-LOCAL-TOMBSTONE-CONFLICT-001` | a different tombstone record is already durable for the object | reject input; tombstones are immutable |
| `ERR-PUBLICATION-LOCAL-TOMBSTONE-REACHABLE-001` | object is reachable from a visible root and cannot be tombstoned locally | run deletion closure through its owner; no silent unpublish |
| `ERR-PUBLICATION-LOCAL-CORRUPT-TOMBSTONE-001` | a durable tombstone record failed verification on open | repair the tombstone store; open fails closed |
| `ERR-PUBLICATION-LOCAL-ENCODING-001` | canonical encoding of a publication record exceeded its encoder bound | reject input; repair the oversized field |
| `ERR-PUBLICATION-LEDGER-SLOT-IDENTITY-001` | slot cannot be expressed as a stable ledger object or batch identity | reject input; choose a slot within the ledgered slot bound |
| `ERR-PUBLICATION-LEDGER-NOT-DURABLE-001` | slot holds no durable root; its reachability is never committed to the ledger | publish durably or reopen to reconcile first |
| `ERR-PUBLICATION-LEDGER-CONFLICT-001` | canonical ledger already names a different root or family for the slot; nothing appended | repair the ledger identity explicitly; never overwrite either record |
| `ERR-PUBLICATION-LEDGER-PREPARED-MISMATCH-001` | offered batch is not the reachability batch of the slot's durable root | reject input; prepare against the durable root |
| `ERR-PUBLICATION-LEDGER-ALREADY-LEDGERED-001` | root reachability is already canonical; nothing to prepare | no retry; root is already ledgered |
| `ERR-PUBLICATION-LEDGER-UNLEDGERED-001` | root is durable but the ledger refused or could not prepare its reachability batch; explicit pending-ledger state | follow the nested cause, then retry the idempotent ledger commit |
| `ERR-PUBLICATION-LEDGER-INDETERMINATE-001` | root is durable and its reachability append became indeterminate | reconcile the ledger append before any retry |
| `ERR-PUBLICATION-LEDGER-RECONCILIATION-REQUIRED-001` | an indeterminate ledger append must be reconciled before root-ledger work | reconcile the pending ledger append |
| `ERR-PUBLICATION-LEDGER-RECONCILE-001` | reconciling an indeterminate ledger append failed | repair ledger storage, then reconcile again |
| `ERR-PUBLICATION-LEDGER-INJECTED-CRASH-001` | a root-ledger fault-injection cut point fired after the root became durable | reopen both owners to reconcile |
| `ERR-FROZEN-REGISTRY-DRIFT-001` | public operation or resource was added, removed, renamed, or renumbered without a new registry generation | bump the registry generation and update the frozen public registry |
| `ERR-FROZEN-STABLE-ID-REUSED-001` | stable operation or resource identifier was reused for a different entity | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-FROZEN-TOMBSTONE-RESURRECTED-001` | tombstoned operation or resource was resurrected into active registry | allocate a new identifier; tombstoned entries remain permanently retired |
| `ERR-FROZEN-DIGEST-MISMATCH-001` | frozen public registry digest does not match canonical encoding of sorted rows | recompute canonical freeze digest over sorted rows |
| `ERR-FROZEN-UNREGISTERED-OP-001` | crosswalk or presentation surface references an unregistered operation | register operation in frozen registry or correct surface reference |
| `ERR-CAPABILITY-REGISTRY-DRIFT-001` | capability registry row drift between architecture JSON and markdown | synchronize architecture/capabilities.json and registries/CAPABILITIES.md |
| `ERR-CAPABILITY-UNKNOWN-PLANE-001` | capability specifies an unknown or unregistered semantic plane | assign a recognized semantic plane to the capability row |
| `ERR-CAPABILITY-MISSING-DEFAULT-001` | capability row lacks a default role or default grant policy | declare an explicit default role or default denial in the capability row |
| `ERR-CAPABILITY-STABLE-ID-REUSED-001` | capability stable identifier was reused or renumbered for a different entity | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-CAPABILITY-DIGEST-MISMATCH-001` | capability registry digest does not match canonical encoding of sorted rows | recompute canonical capability registry digest |
| `ERR-CAPABILITY-CORRUPT-FILE-001` | capability registry or markdown documentation file is missing or corrupt | repair or restore capability registry file |
| `ERR-KSTATE-REGISTRY-DRIFT-001` | knowledge state registry row drift between machine registry and markdown | synchronize architecture/knowledge_states.json and registries/AGENT_CONTRACTS.md |
| `ERR-KSTATE-STABLE-ID-REUSED-001` | knowledge state stable identifier was reused or renumbered for a different entity | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-KSTATE-MISSING-FIELD-001` | knowledge state row lacks a mandatory field or is empty/corrupt | declare all mandatory fields in knowledge state row |
| `ERR-KSTATE-CORRUPT-FILE-001` | knowledge state registry or markdown documentation file is missing or corrupt | repair or restore knowledge state registry file |
| `ERR-KSTATE-DIGEST-MISMATCH-001` | knowledge state registry digest does not match canonical encoding of metadata and rows | recompute canonical knowledge state registry digest |
| `ERR-KSTATE-FREEZE-DIVERGENCE-001` | knowledge state registry digest diverged from pinned baseline freeze digest | restore frozen knowledge state registry or bump generation |
| `ERR-KSTATE-GENERATION-MISMATCH-001` | knowledge state registry generation diverged from baseline generation | assign expected generation to knowledge state registry |
| `ERR-KSTATE-ILLEGAL-IRREVERSIBLE-AUTH-001` | non-known knowledge state illegally authorizes irreversible effect | restrict irreversible effect authorization strictly to known state |
| `ERR-PROV-REGISTRY-DRIFT-001` | provenance registry row drift between machine registry and markdown | synchronize architecture/provenance_classes.json and registries/AGENT_CONTRACTS.md |
| `ERR-PROV-STABLE-ID-REUSED-001` | provenance class stable identifier was reused or renumbered for a different entity | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-PROV-MISSING-FIELD-001` | provenance class row lacks a mandatory field or is empty/corrupt | declare all mandatory fields in provenance class row |
| `ERR-PROV-CORRUPT-FILE-001` | provenance registry or markdown documentation file is missing or corrupt | repair or restore provenance registry file |
| `ERR-PROV-DIGEST-MISMATCH-001` | provenance registry digest does not match canonical encoding of metadata and rows | recompute canonical provenance registry digest |
| `ERR-PROV-FREEZE-DIVERGENCE-001` | provenance registry digest diverged from pinned baseline freeze digest | restore frozen provenance registry or bump generation |
| `ERR-PROV-GENERATION-MISMATCH-001` | provenance registry generation diverged from baseline generation | assign expected generation to provenance registry |
| `ERR-PROV-SEMANTIC-INVARIANT-001` | provenance semantic invariant violation: non-permissible irreversible authorization, missing anchors, or score flattening | enforce provenance orthogonality and class-specific evidence/authorization gates |
| `ERR-PROV-LAUUNDERING-UNWIRED-001` | evidence-laundering refusal has no non-test caller on any production path | call `KnowledgeCell::verify_no_evidence_laundering` from at least one non-test production path (fss-2nwxm) |
| `ERR-OP-REGISTRY-DRIFT-001` | operation registry row drift between machine registry and markdown mirror | synchronize architecture/agent_operations.json and registries/AGENT_OPERATIONS.md |
| `ERR-OP-STABLE-ID-REUSED-001` | operation stable identifier was reused, duplicated, or renumbered outside AOP-001..AOP-014 | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-OP-MISSING-FIELD-001` | operation row or registry metadata lacks a mandatory field or is empty/corrupt | declare all mandatory fields in the operation row |
| `ERR-OP-CORRUPT-FILE-001` | operation registry, frozen public registry, or markdown documentation file is missing or corrupt | repair or restore the operation registry file |
| `ERR-OP-SEMANTIC-INVARIANT-001` | operation semantic invariant violation: effect/mode contradiction, durability contradiction, or unregistered view/payload/capability/gate/retry spelling | enforce the registered operation mode table and row invariants |
| `ERR-OP-RUST-DRIFT-001` | typed Rust operation table drifted from or is missing versus the machine registry | regenerate crates/fss-core/src/agent_operation.rs canonical rows from architecture/agent_operations.json |
| `ERR-VW-REGISTRY-DRIFT-001` | view registry row drift between machine registry and markdown mirror | synchronize architecture/agent_views.json and registries/AGENT_VIEWS.md |
| `ERR-VW-STABLE-ID-REUSED-001` | view stable identifier was reused, duplicated, or renumbered outside AVIEW-001..008 | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-VW-MISSING-FIELD-001` | view row or registry metadata lacks a mandatory field or is empty/corrupt | declare all mandatory fields in the view row |
| `ERR-VW-CORRUPT-FILE-001` | view registry or markdown documentation file is missing or corrupt | repair or restore the view registry file |
| `ERR-VW-SEMANTIC-INVARIANT-001` | view semantic invariant violation: token bound contradiction, unregistered gate/status, or operation default view foreign-key miss | enforce the registered view row invariants and default-view foreign keys |
| `ERR-VW-RUST-DRIFT-001` | typed Rust view table drifted from or is missing versus the machine registry | regenerate crates/fss-core/src/agent_view.rs canonical rows from architecture/agent_views.json |
| `ERR-ADAPTER-REGISTRY-DRIFT-001` | adapter registry row drift between machine registry and markdown | synchronize architecture/device_adapters.json and registries/DEVICE_ADAPTERS.md |
| `ERR-ADAPTER-STABLE-ID-REUSED-001` | adapter stable identifier was reused, renumbered, or resurrected | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-ADAPTER-SEMANTIC-INVARIANT-001` | adapter row violates semantic invariants (tier, state, gate) | fail closed; enforce normative row definitions |
| `ERR-ADAPTER-CORRUPT-FILE-001` | device adapter registry file is corrupt or missing mandatory fields | repair or restore device adapter registry file |
| `ERR-ADAPTER-DIGEST-MISMATCH-001` | device adapter canonical freeze digest does not match pinned generation digest | recompute canonical device adapter registry digest or bump generation |
| `ERR-ADAPTER-GENERATION-MISMATCH-001` | adapter generation does not match current system generation | fail closed; assign expected generation to device adapter registry |
| `ERR-ADAPTER-INVALID-TIER-001` | adapter tier is invalid or violates promotion rules | fail closed; reject unsupported tier |
| `ERR-ADAPTER-REPLAY-DIVERGED-001` | deterministic replay adapter produced state root or audit hash diverging from reference proof | fail closed; reject diverged replay output and quarantine bundle |
| `ERR-GRAPH-UNREGISTERED-PROJECTION-001` | graph algorithm specifies an unregistered or nonexistent graph projection ID | update algorithm projection to a registered projection ID from docs/GRAPH_ALGORITHM_ATLAS.md |
| `ERR-GRAPH-MISSING-TIE-BREAK-001` | graph algorithm row lacks a deterministic CGSE tie-break rule | specify a deterministic CGSE tie-break policy in graph algorithm registry |
| `ERR-GRAPH-MISSING-COMPLEXITY-WITNESS-001` | graph algorithm row lacks declared complexity witness operations | declare dominant operation complexity witness in graph algorithm registry |
| `ERR-GRAPH-MISSING-OUTPUT-WITNESS-001` | graph algorithm row lacks declared output-size witness with bounds | declare output-size witness with bounds or record explicit owner drift |
| `ERR-GRAPH-PROJECTION-MISMATCH-001` | graph algorithm projections differ between machine source and registry markdown mirror | reconcile machine source and registry markdown projections |
| `ERR-GRAPH-STABLE-ID-DRIFT-001` | graph algorithm stable identifier renumbered or superseded row not tombstoned | restore stable algorithm identity and retain superseded rows as tombstones |
| `ERR-NEG-MISSING-COVERAGE-001` | negative evidence entry lacks a certifying coverage witness | provide a valid certifying coverage witness; absence without witness is never evidence |
| `ERR-NEG-COVERAGE-GAP-001` | negative evidence evaluated during an uncertified coverage gap | ensure continuous coverage witness; absence during gap is never evidence |
| `ERR-NEG-UNCERTIFIED-COVERAGE-001` | coverage witness does not certify complete negative predicate absence | verify coverage domain and predicate certification |
| `ERR-NEG-UNKNOWN-VERSION-001` | negative evidence binary ledger format version is unknown or unsupported | refuse unknown version; never guess ledger encoding format |
| `ERR-NEG-CHECKSUM-MISMATCH-001` | negative evidence binary ledger corrupt magic, checksum, or truncated data | repair corrupt ledger binary or restore from canonical backup |
| `ERR-NEG-NON-CANONICAL-ORDER-001` | negative evidence ledger entries are not in strictly increasing canonical order | sort entries strictly by stable ID |
| `ERR-NEG-DUPLICATE-ID-001` | negative evidence ledger contains duplicate stable entry identifier | allocate unique stable entry identifier; never duplicate IDs |
| `ERR-NEG-INPUT-OVERSIZED-001` | negative evidence entry or field exceeds declared capacity limit | bound entry string length or shared failure domain count |
| `ERR-NEG-ENTRY-TOMBSTONED-001` | attempted operation on or with a permanently tombstoned negative entry | do not operate on tombstoned negative-evidence entries |
| `ERR-NEG-REVIVAL-UNMET-001` | candidate retry or promotion attempted without meeting revival condition | satisfy documented revival condition before promoting candidate |
| `ERR-NEG-VALIDATION-FAILED-001` | negative evidence entry semantic validation failed | provide valid required fields conforming to negative evidence contract |
| `ERR-NEG-MALFORMED-ENTRY-001` | negative evidence ledger entry bytes carry an unknown tag, an invalid value, or a count beyond its declared bound | restore the ledger from a canonical backup; never guess field values |
| `ERR-NEG-MISSING-PROOF-001` | locally certified negative evidence lacks a proof hash, a retained evidence reference, or the evidence its knowledge state requires | supply the proof hash and retained evidence reference, or record the entry as not locally certified |
| `ERR-NEG-LEDGER-EXISTS-001` | negative evidence ledger init target already exists | choose a new path; init never overwrites a ledger |
| `ERR-NEG-LEDGER-NOT-FOUND-001` | negative evidence ledger file does not exist | create the ledger with `fss negative-evidence init` before appending |
| `ERR-NEG-LEDGER-LOCKED-001` | negative evidence ledger lock file is held by another writer or was left stale by a crashed writer | retry after the other writer finishes; remove a stale lock only after confirming no writer is running |
| `ERR-NEG-CONCURRENT-MODIFICATION-001` | negative evidence ledger changed between read and publish on every bounded attempt | identify the concurrent writer, then retry the append explicitly |
| `ERR-NEG-LEDGER-HARD-LINKED-001` | negative evidence ledger file has a link count other than one, so an atomic publish would update only one of its names | keep the ledger under a single name (use a symlink for aliases) before appending |
| `ERR-NEG-LEDGER-FORKED-001` | after the atomic rename the old negative-evidence ledger inode is still linked by another name holding the pre-append ledger | reconcile the fork by hand: keep exactly one name and re-run the append |
| `ERR-NEG-LEDGER-TEMP-EXISTS-001` | temporary negative-evidence ledger file already exists before the append created it | remove the stale temporary file or investigate before appending |
| `ERR-DEP-REGISTRY-DRIFT-001` | dependency registry row drift between machine registry and markdown mirror | synchronize architecture/dependencies.json and registries/DEPENDENCIES.md |
| `ERR-DEP-STABLE-ID-REUSED-001` | dependency class stable identifier was reused, duplicated, renumbered, or tombstoned | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-DEP-MISSING-FIELD-001` | dependency class row or root metadata lacks a mandatory field or is empty/corrupt | declare all mandatory fields in dependency class row |
| `ERR-DEP-CORRUPT-FILE-001` | dependency registry or markdown documentation file is missing or corrupt | repair or restore dependency registry file |
| `ERR-DEP-DIGEST-MISMATCH-001` | dependency registry digest does not match canonical encoding of metadata and rows | recompute canonical dependency registry digest |
| `ERR-DEP-FREEZE-DIVERGENCE-001` | dependency registry digest diverged from pinned baseline freeze digest | restore frozen dependency registry or bump generation |
| `ERR-DEP-GENERATION-MISMATCH-001` | dependency registry generation diverged from baseline generation | assign expected generation to dependency registry |
| `ERR-DEP-CONST-INVARIANT-001` | dependency constitution semantic invariant violated | enforce constitutional admission rule and production closed-universe invariants |
| `ERR-DEP-CONST-METADATA-VIOLATION-001` | Cargo metadata violates constitutional language or stdlib requirements for DEP-CLASS-F0, or names a workspace member that is not declared in architecture/crate_topology.json and listed explicitly in the root [workspace].members | ensure all workspace crates compile under rust-2024 without foreign links, and declare every member in the crate topology and the explicit workspace member list |
| `ERR-DEP-CONST-DRIFT-001` | dependency constitution drift between machine registry and markdown documentation, or between DEPENDENCY_CONSTITUTION.md and its docs/ copy | synchronize architecture/dependency_constitution.json and docs/DEPENDENCY_CONSTITUTION.md, and keep docs/DEPENDENCY_CONSTITUTION.md byte-identical to DEPENDENCY_CONSTITUTION.md |
| `ERR-DEP-EXEC-FAILED-001` | a toolchain command required for DEP-CLASS-F0 verification (rustc -Vv or cargo metadata) could not run, timed out, exited non-zero, or produced unparseable output | restore the pinned toolchain and offline cargo inputs and rerun; an execution failure is never reported as a corrupt file |
| `ERR-DEP-UNSTABLE-FEATURE-001` | the repository enables a nightly unstable feature (#![feature(...)] including inside cfg_attr, -Z rustflags in .cargo/config or checked-in env/shell files, a cargo [unstable] table, cargo-features, or a -Z literal in a build script) while no unstable-feature allowlist is registered | remove the feature gate or flag, or register an unstable-feature allowlist with owner and removal plan before enabling it |
| `ERR-DEP-ALLOWLIST-DIGEST-DIVERGED-001` | architecture/dependency_allowlist.toml bytes diverged from the checker's pinned allowlist digest | review the allowlist change and update the pinned digest in scripts/dependency_authority.py in the same commit |
| `ERR-DEP-PENDING-DECISION-001` | a crate recorded under an open owner decision (dependency_allowlist.toml [pending_owner_decisions], e.g. fss-ndxis) reached a manifest, lockfile, or resolved closure | keep the crate out of the closure until the owner records the decision; it is neither admitted nor rejected meanwhile |
| `ERR-DEP-TRACE-UNRESOLVED-001` | a dependency registry row's owner, producer, consumer, ContractBasis link, or a dependency checker diagnostic code does not resolve | name existing repository files and allowlist tables that reference the row, and register every emitted code in registries/ERRORS.md |
| `ERR-DEP-TOMBSTONE-INVALID-001` | a dependency or dependency-class tombstone/supersession record is malformed, contradictory, dangling, or missing | record status, successor, and tombstone decision consistently in architecture/dependencies.json and architecture/stable_id_resolution.json |
| `ERR-AGT-REGISTRY-DRIFT-001` | agent abstraction registry row drift between machine registry and markdown mirror | synchronize architecture/agent_abstraction_stack.json and registries/AGENT_ABSTRACTIONS.md |
| `ERR-AGT-STABLE-ID-REUSED-001` | agent abstraction layer stable identifier was reused, duplicated, renumbered, or tombstoned | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-AGT-MISSING-FIELD-001` | agent abstraction layer row or root metadata lacks a mandatory field or is empty/corrupt | declare all mandatory fields in agent abstraction layer row |
| `ERR-AGT-CORRUPT-FILE-001` | agent abstraction registry or markdown documentation file is missing or corrupt | repair or restore agent abstraction registry file |
| `ERR-AGT-DIGEST-MISMATCH-001` | agent abstraction registry digest does not match canonical encoding of metadata and rows | recompute canonical agent abstraction registry digest |
| `ERR-AGT-FREEZE-DIVERGENCE-001` | agent abstraction registry digest diverged from pinned baseline freeze digest | restore frozen agent abstraction registry or bump generation |
| `ERR-AGT-GENERATION-MISMATCH-001` | agent abstraction registry generation diverged from baseline generation | assign expected generation to agent abstraction registry |
| `ERR-AGT-INVARIANT-VIOLATION-001` | agent abstraction layer invariant or prohibition violated | enforce layer semantic invariants and constitutional prohibitions |
| `ERR-AGT-ILLEGAL-AUTHORITY-001` | derived beliefs or non-authority abstraction layer illegally claims authority or authorizes effects | preserve cognition plane boundary; derived layers cannot claim authority or authorize effects |
| `ERR-CLAIM-ASSUMPTIONS-MISSING-001` | promoted proof or bounded_model claim declares no assumptions, or an assumption lacks a non-empty id and statement | declare every named assumption before promotion; no retry without them |
| `ERR-CLAIM-PROOF-FORMAL-MODEL-UNBOUND-001` | proof claim declares no formal model, or its retained fss.formal_model.v1 manifest or source is missing, unreadable, digest-unbound, or not bound to the claim id | retain the declared formal model bound to the claim id before promotion |
| `ERR-CLAIM-PROOF-MODEL-GENERATION-MISMATCH-001` | proof claim formal model generation differs from the claim generation, the declared model reference, or the check receipt | re-check the proof at the claim generation; never splice generations |
| `ERR-CLAIM-PROOF-THEOREM-UNBOUND-001` | proof claim theorem statement is missing, bound to another claim, or differs from the statement the check receipt checked | bind the exact theorem statement to the claim and re-check |
| `ERR-CLAIM-PROOF-FORMAL-ARTIFACT-MISSING-001` | proof claim formal artifact is absent, not on disk, empty, digest-unbound, or not written in the declared checker language | retain the exact checked formal artifact before promotion |
| `ERR-CLAIM-PROOF-TESTS-ONLY-001` | proof claim is backed only by tests (test-runner toolchain, test source, or test results) instead of a formal artifact | demote the claim or supply a machine-checked formal proof |
| `ERR-CLAIM-PROOF-TOOLCHAIN-UNBOUND-001` | proof claim formal checker identity is missing, unregistered, latest-aliased, or differs between bundle and check receipt | pin the exact registered formal checker and version in bundle and receipt |
| `ERR-CLAIM-PROOF-CHECK-RECEIPT-INVALID-001` | proof check receipt is missing, malformed, non-passing, or not bound to the claim, formal model, and formal artifact digest | re-run the formal checker and retain a passing bound receipt |
| `ERR-CLAIM-BOUND-DERIVATION-UNBOUND-001` | bounded_model claim derivation is missing, not on disk, digest-unbound, malformed, stepless, or not bound to the claim id and generation | retain the fss.bound_derivation.v1 derivation bound to the claim before promotion |
| `ERR-CLAIM-BOUND-EXPRESSION-UNBOUND-001` | bounded_model claim bound expression, comparator, or value is missing, non-finite, bound to another claim, or differs from the derivation | bind the exact derived bound expression to the claim |
| `ERR-CLAIM-BOUND-UNITS-MISSING-001` | bounded_model claim bound or derivation declares no units, or the claimed units differ from the derivation units | declare identical explicit units in claim and derivation; never convert implicitly |
| `ERR-CLAIM-BOUND-TIGHTER-THAN-DERIVATION-001` | bounded_model claimed bound is tighter than the analytically derived bound | claim at most the derived bound or retain a derivation supporting the tighter one |
| `ERR-CLAIM-BOUND-SENSITIVITY-MISSING-001` | bounded_model derivation declares no sensitivity analysis or no invalidators | retain sensitivity analysis and invalidators with the derivation |
| `ERR-CLAIM-BOUND-VALUE-OUT-OF-DOMAIN-001` | bounded_model claimed, derived, or input value lies outside its registered unit domain (negative, above 100 percent, above 1 auprc) | correct the value or its unit |
| `ERR-CLAIM-BOUND-DERIVATION-NOT-RECOMPUTABLE-001` | bounded_model derivation records no usable inputs or arithmetic formula, the formula is not its expression right-hand side, or it does not recompute the derived value | record every input with value and units and the exact arithmetic yielding the derived value |
| `ERR-CLAIM-BOUND-DIMENSION-MISMATCH-001` | bounded_model derivation formula is dimensionally inconsistent (+ or - of different units, or propagated units differ from the derivation units) | correct the formula or input units; units are never converted implicitly |
| `ERR-CLAIM-SLO-TARGET-UNBOUND-001` | slo claim target cannot be resolved to exactly one numeric threshold of its registries/SLOS.md row, the measurement declares no or a different unit, or the measurement restates a target that differs from the authoritative row (a non-canonical target key is ERR-CLAIM-EVIDENCE-FIELD-UNKNOWN-001) | claim only an SLO row with a registered numeric threshold; measure in its exact unit and never restate or relax the target |
| `ERR-CLAIM-SLO-COMPARATOR-OVERRIDE-001` | slo measurement declares a comparator that differs from the comparator of its registries/SLOS.md row | remove the comparator from the measurement; the SLO row alone defines the comparison |
| `ERR-CLAIM-SLO-ACTUAL-INVALID-001` | slo measurement has no single canonical numeric 'actual': it is missing, non-numeric, boolean, negative, overflowing, or rounded-only (an actual-like key is ERR-CLAIM-EVIDENCE-FIELD-UNKNOWN-001) | retain exactly one finite, non-negative numeric 'actual' in the SLO unit; never report only a rounded value |
| `ERR-CLAIM-SLO-GENERATION-UNBOUND-001` | slo bundle or measurement declares no generation, or the measurement declares no operation-cost registry generation | bind the bundle and measurement to one explicit generation and to the operation-cost registry generation measured against |
| `ERR-CLAIM-SLO-FRESHNESS-BOUND-UNSET-001` | an operation-cost row listing the slo claim's SLO declares no measurement_max_age_days (the strictest bound over all such rows applies), so the freshness bound is unset | a user decision: set the bound on every such row; the checker never assumes a default |
| `ERR-CLAIM-SLO-WINDOW-INVALID-001` | slo measurement validity window is missing, unparseable, zone-less, empty, finished before it started, or lies in the future | retain a zone-qualified ISO-8601 measurement window that ended before the evaluation instant |
| `ERR-CLAIM-EVIDENCE-FIELD-UNKNOWN-001` | an evidence document the claim checker reads declares a key outside its exact field set: the proof bundle, an artifact entry, an assumption, the theorem, the toolchain identity, the formal model reference, manifest, or model source, the proof check receipt, the bound, the derivation, a derivation input, a sensitivity entry, an slo measurement, or its measurement_window; or a qualification receipt declares a case, whitespace, or format-character variant of a field the checker relies on. Keys are compared byte for byte (no case folding, stripping, or normalization) | remove the key or spell it exactly as the document's field set names it; unknown fields are never ignored |
| `ERR-CLAIM-EVIDENCE-DUPLICATE-KEY-001` | a JSON document the claim checker reads (proof bundle, qualification receipt, retained evidence document, or registry, including every architecture/*.json the stable-ID tombstone index reads, which leaves the index unavailable) declares the same key twice in one object, at any nesting level; with a plain parser the last value would silently win | declare every key once; a document that says two things is never read as one of them |
| `ERR-CLAIM-PROOF-BUNDLE-SCHEMA-INVALID-001` | a proof bundle's schema is missing or not exactly `fss.proof_bundle.v1`, or its bundle_id is present but not an exact token | declare the schema byte for byte and, when present, a bundle_id of printable ASCII with no whitespace |
| `ERR-CLAIM-SLO-STATISTIC-MISMATCH-001` | slo measurement's declared statistic is not exactly the statistic its SLO target names (missing, different, not byte-exact, or declared for a target naming none; a statistic-like key is ERR-CLAIM-EVIDENCE-FIELD-UNKNOWN-001) | declare the single canonical 'statistic' exactly as the SLO target names it, or none when it names none |
| `ERR-CLAIM-SLO-CONJUNCT-INCOHERENT-001` | the measurements behind one slo claim come from different operations, or their validity windows share no common instant | measure every conjunct of the SLO target on the same operation within overlapping validity windows |
| `ERR-CLAIM-SLO-MEASUREMENT-NOT-PASSED-001` | slo measurement status is missing or anything other than 'passed' | re-run the measurement; a failed, partial, or unlabelled run never supports an slo claim |
| `ERR-CLAIM-SLO-ENVIRONMENT-UNRETAINED-001` | slo claim retains no single digest-bound fss.environment_manifest.v1 artifact, or the measurement is not bound to that manifest's digest | retain the exact environment manifest and bind the measurement to its digest |
| `ERR-CLAIM-SLO-REGISTRY-INVALID-001` | the SLO registry (registries/SLOS.md) or operation-cost registry (architecture/operation_cost_registry.toml) consulted for an slo claim is missing, unreadable, empty, malformed, or declares no rows or generation | repair the registry under the audited root; slo claims are never checked against a silently skipped registry |
| `ERR-CLAIM-CLASS-UNRESOLVED-001` | a promoted proof bundle's claim id is bound to a claim class by no registry (SLO ids by registries/SLOS.md, invariant ids by architecture/invariants.json); a row Class column or the bundle never resolves it | bind the claim id in its owning registry; no retry until one does |
| `ERR-CLAIM-CLASS-REGISTRY-INVALID-001` | a registry binding claim ids to classes (architecture/invariants.json) declares an inexact id or one id more than once | give every stable id exactly one row |
| `ERR-CLAIM-CLASS-EVIDENCE-UNINSPECTED-001` | promoted claim of a class the checker does not realize with evidence inspection (only slo, proof, bounded_model are realized) | realize the class row or keep the claim unpromoted |
| `ERR-CLAIM-PROOF-STALE-GENERATION-001` | proof bundle references a stale, superseded, tombstoned, expired, or latest-aliased generation, or a generation other than its claim row's current one | re-qualify at the current generation; never splice generations |
| `ERR-CLAIM-PROOF-UNPROVEN-PLACEHOLDER-001` | proof claim formal artifact contains, outside comments and strings, an unproven placeholder (Lean sorry, sorryAx, admit, stop or a confusable lookalike; TLAPS OMITTED in any case) | complete the proof; a placeholder is never a checked proof |
| `ERR-CLAIM-PROOF-UNSOUND-ESCAPE-001` | proof claim formal artifact contains a known unsound escape (Lean axiom, compiler trust, lcProof, kernel bypass, metaprogramming, a #-command, an import outside Init/Std/Lean; TLA+ AXIOM, ASSUMPTION or non-sequent ASSUME, or EXTENDS/INSTANCE of a non-standard module) | remove the escape; declare assumptions in the bundle and model |
| `ERR-CLAIM-PROOF-PROVER-RUN-REQUIRED-001` | promoted proof bundle passed the static pre-filter, but a proof is verified only by a qualification receipt from running the prover, and no such receipt mechanism is defined yet | a user decision: define the prover-run receipt; until then no proof claim is verified |
| `ERR-CLAIM-GENERATION-UNBOUND-001` | promoted proof or bounded_model claim is cited by no claim row declaring its current generation (Generation column), or its citing rows conflict | declare the claim row's current generation and bind the bundle to exactly it |
| `ERR-CLAIM-ID-REUSED-001` | A claim class ID is duplicated, renumbered, or reused across different claim classes | give every stable id exactly one row; never reuse or renumber stable ids |
| `ERR-CLAIM-MISSING-FIELD-001` | A claim class entry in the registry is missing required normative fields (id, meaning, minimum_evidence, requiredEvidence) or a table row lacks required columns | declare all required normative fields for each claim class row |
| `ERR-CLAIM-PROOF-BUNDLE-NOT-FOUND-001` | A claim cites a proof bundle, or a bundle declares an artifact, that does not exist on disk, has forbidden traversal ('..'), is absolute, resolves outside the repository root, is not a regular file, or cannot be verified locally | retain the cited proof bundle at the declared path before promotion |
| `ERR-CLAIM-PROOF-CLAIM-BINDING-MISMATCH-001` | A proof bundle binds no claim ID or a different claim than the one citing it, a promoted claim row has no claim ID, or a claim cites a qualification receipt (which binds no claim) | bind the proof bundle to the exact claim id that cites it |
| `ERR-CLAIM-PROOF-DIGEST-MISMATCH-001` | A proof bundle's content digest or an artifact digest is missing, ambiguous, malformed, or does not match the actual computed cryptographic digest | declare one content digest per artifact and recompute it after any edit |
| `ERR-CLAIM-PROOF-EMPTY-INPUT-001` | An input file is empty (0 bytes or empty text), contains an empty JSON collection, or a required claim surface declares no claim table | provide non-empty inputs; empty files or collections are not evidence |
| `ERR-CLAIM-PROOF-INVALID-CLASS-001` | A proof bundle declares no claim class, a claim class not recognized in architecture/claims.json, or no claim-class registry was supplied | declare a claim class registered in architecture/claims.json |
| `ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001` | A claim level (e.g. achieved, qualified, verified) is higher than its retained proof supports, the proof is non-passing, or required evidence for the claim class is missing | retain proof evidence for every claimed level before raising the level |
| `ERR-CLAIM-PROOF-PROHIBITED-PROMOTION-001` | A claim attempts a promotion explicitly prohibited by architecture/claims.json | remove the prohibited promotion; claim only what the retained evidence supports |
| `ERR-CLAIM-PROOF-TOMBSTONE-INDEX-UNAVAILABLE-001` | The stable-ID tombstone index (architecture/stable_id_resolution.json plus the repository stable-ID index) is missing, unreadable, empty, corrupt, or has the wrong schema, so tombstoned identities cannot be refused | restore or rebuild architecture/stable_id_resolution.json and the registry tombstone rows |
| `ERR-CLAIM-PROOF-UNREADABLE-INPUT-001` | An input file or directory could not be read (including a file over the per-file byte cap, MAX_INPUT_BYTES), decoded, or parsed as valid JSON/Markdown, or is structurally malformed (including a qualification receipt that violates schemas/release_qualification_receipt.v1.json) | make every input readable and within the per-file byte bound |
| `ERR-CLAIM-PROOF-UNRECOGNIZED-STATE-001` | A claim status, bundle status, supported level, retention state, expiry marker, or readiness registry state is outside the closed vocabulary | use a recognized status/level/retention spelling from the closed vocabularies |
| `ERR-CLAIM-REGISTRY-DRIFT-001` | The machine-readable claims registry (architecture/claims.json) and its human-readable markdown source (registries/CLAIMS.md) differ in claim class IDs, ordering, meaning, minimum evidence, or row count | synchronize architecture/claims.json and registries/CLAIMS.md |
| `ERR-ROBOT-DOCS-STALE-001` | robot documentation diverges from authoritative machine registries | regenerate robot docs with scripts/generate_robot_docs.py |
| `ERR-ROBOT-DOCS-MISSING-001` | generated robot documentation markdown or json artifact missing | generate robot docs with scripts/generate_robot_docs.py |
| `ERR-ROBOT-DOCS-DRIFT-001` | cataloged operations, views, or resources drift across registries | reconcile registry definitions before generating docs |
| `ERR-ROBOT-DOCS-CORRUPT-001` | malformed JSON syntax, duplicate keys, or encoding corruption in robot docs or registry | repair malformed input; ensure canonical encoding |
| `ERR-ROBOT-DOCS-UNREGISTERED-001` | documented operation references unregistered capability, schema, or error identity | register referenced entity in authoritative registry before generating docs |
| `ERR-ROBOT-DOCS-SECRET-DETECTED-001` | suspected secret, credential, token, or local filesystem path detected in registry text | remove sensitive data and sanitize registry text |
| `ERR-SOURCE-EVIDENCE-MISSING-ANCHOR-001` | source evidence record missing authoritative anchor | attach authoritative anchor; do not retry unchanged |
| `ERR-SOURCE-EVIDENCE-OMISSION-REQUIRED-001` | not-retained source evidence must declare an explicit omission reason | supply explicit omission reason; do not retry unchanged |
| `ERR-SOURCE-EVIDENCE-RETAINED-WITH-OMISSION-001` | retained source evidence cannot declare an omission reason | remove omission reason or mark not-retained |
| `ERR-SOURCE-EVIDENCE-NOT-RETAINED-WITH-CAPSULE-BYTES-001` | not-retained source evidence capsule cannot claim non-zero source bytes, non-zero frame count, or non-zero source digest | zero capsule bytes/digest/frames or mark retained |
| `ERR-SOURCE-EVIDENCE-BYTE-COUNT-MISMATCH-001` | capsule source bytes does not match custody source bytes | align capsule and custody byte count |
| `ERR-SOURCE-EVIDENCE-EMPTY-STORAGE-HANDLE-001` | retained source custody storage handle is empty | provide non-empty sanitized storage handle |
| `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-TRAVERSAL-001` | retained source custody storage handle has a `.` or `..` segment | remove path traversal components from storage handle |
| `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-ABSOLUTE-PATH-001` | retained source custody storage handle contains forbidden absolute path or url | provide relative or content-addressed storage handle |
| `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-MALFORMED-001` | tombstoned, no longer emitted: superseded by the EMPTY-SEGMENT, OVER-LENGTH and DISALLOWED-CHARACTER storage handle identities | not applicable; retained so the stable ID is never reused |
| `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-EMPTY-SEGMENT-001` | retained source custody storage handle has an empty segment (doubled or trailing `/`) | remove the empty segment; do not retry unchanged |
| `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-OVER-LENGTH-001` | retained source custody storage handle exceeds 4096 bytes | shorten the storage handle to at most 4096 bytes |
| `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-DISALLOWED-CHARACTER-001` | retained source custody storage handle contains a character outside ASCII `[A-Za-z0-9._-]` and `/` (including space, control, bidi, format and non-ASCII characters) | supply a handle made only of allow-listed characters |
| `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-PERCENT-ENCODING-REFUSED-001` | retained source custody storage handle contains `%`; percent-encoding is refused rather than decoded | supply the literal allow-listed handle without percent-encoding |
| `ERR-SOURCE-EVIDENCE-RAW-WIRE-PACKETS-WITH-CAPSULE-001` | raw wire packets classification cannot carry a sensor capsule payload | omit capsule or change classification |
| `ERR-SOURCE-EVIDENCE-STATEMENT-MALFORMED-001` | source evidence statement is empty or exceeds 512 bytes | constrain statement to 1..=512 UTF-8 bytes |
| `ERR-SOURCE-EVIDENCE-CAPSULE-REQUIRED-001` | sensor capsule classification requires a sensor capsule payload | provide sensor capsule or change classification |
| `ERR-SOURCE-EVIDENCE-WITNESS-REQUIRED-001` | continuity witness classification requires a continuity witness digest | provide continuity witness or change classification |
| `ERR-SOURCE-EVIDENCE-WITNESS-EQUALS-SOURCE-DIGEST-001` | continuity witness cannot equal source digest | supply distinct continuity witness |
| `ERR-SOURCE-EVIDENCE-NOT-RETAINED-WITH-WITNESS-001` | source evidence not retained cannot bind a continuity witness | omit witness or retain source evidence |
| `ERR-SOURCE-EVIDENCE-UNKNOWN-CLASSIFICATION-001` | unknown source evidence classification string token | supply a registered classification token |
| `ERR-SOURCE-EVIDENCE-UNKNOWN-OMISSION-REASON-001` | unknown omission reason string token | supply a registered omission reason token |
| `ERR-SOURCE-EVIDENCE-UNKNOWN-CUSTODY-TAG-001` | unknown source custody binary wire tag | supply a registered custody tag |
| `ERR-SOURCE-EVIDENCE-UNSUPPORTED-VERSION-001` | unsupported source evidence binary wire format version | encode with current supported format version |
| `ERR-DOCTOR-ATTENTION-REQUIRED-001` | doctor inspection detected deployment conditions requiring attention | inspect doctor report and follow next affordance |
| `ERR-DOCTOR-NOT-A-DEPLOYMENT-001` | target directory is not a recognized reference deployment root | provide a valid reference deployment root |
| `ERR-LAB-ROOT-NOT-EMPTY-001` | laboratory target root directory already contains files | choose an empty or new target root directory |



## Subordinate dependency audit diagnostic registry (DEP-AUD)

The `DEP-AUD-*` namespace provides stable, structured diagnostics emitted during repository policy,
dependency auditing, and build gate qualification (`GATE-000`, `QL-POLICY-001`). Unlike runtime
agent operational errors (`ERR-*`), `DEP-AUD-*` diagnostics identify static configuration, manifest,
target root, or resolved dependency closure violations before compilation and release qualification.

Every `DEP-AUD` finding has a reviewed canonical definition, stable severity, parameter schema,
triggering condition, affected qualification gate, remediation guidance, and exit behavior. Unknown
or drifted IDs are rejected by the policy lane (`scripts/check-policy.py`).

| ID | Severity | Trigger condition | Remediation guidance | Gate effect | Retry policy |
|---|---|---|---|---|---|
| `DEP-AUD-001` | error | required-true dependency-policy key is absent or not true | correct the reviewed allowlist policy value or amend the constitution; never weaken the check | `GATE-000`, `QL-POLICY-001` | repair configuration before re-running qualification |
| `DEP-AUD-002` | error | required-false dependency-policy key is absent or not false | remove the prohibited allowance or complete a reviewed constitutional change; never weaken the check | `GATE-000`, `QL-POLICY-001` | repair configuration before re-running qualification |
| `DEP-AUD-010` | error | a declared workspace member manifest is missing | restore/correct the exact member manifest and source fence before dependency claims | `GATE-000`, `QL-POLICY-001` | restore missing Cargo.toml before re-running qualification |
| `DEP-AUD-011` | error | a dependency section is not a TOML table | repair the manifest shape; do not ignore or coerce malformed dependency declarations | `GATE-000`, `QL-POLICY-001` | reformat dependency section before re-running qualification |
| `DEP-AUD-012` | error | a path dependency escapes the frozen repository or sibling closure | move it into the authorized closure or explicitly admit and pin the dependency | `GATE-000`, `QL-POLICY-001` | retarget path dependency before re-running qualification |
| `DEP-AUD-013` | error | a Git dependency lacks an exact 40-hex revision | pin an immutable reviewed commit and retain source/provenance evidence | `GATE-000`, `QL-POLICY-001` | pin 40-hex git revision before re-running qualification |
| `DEP-AUD-014` | error | a build dependency is present without constitutional admission | remove it or complete the explicit dependency/ADR/security admission; no implicit build scripts | `GATE-000`, `QL-POLICY-001` | remove build-dependencies before re-running qualification |
| `DEP-AUD-015` | error | a direct dependency names a forbidden crate | remove the forbidden crate and repair the design without an unsafe/foreign substitute | `GATE-000`, `QL-POLICY-001` | remove forbidden crate before re-running qualification |
| `DEP-AUD-016` | error | a direct external dependency is outside the closed allowlist | remove it or add a reviewed exact allowlist/DEP/ADR admission with closure proof | `GATE-000`, `QL-POLICY-001` | admit or remove dependency before re-running qualification |
| `DEP-AUD-017` | error | an external dependency does not disable default features | set default-features=false and explicitly admit only audited features | `GATE-000`, `QL-POLICY-001` | set default-features = false before re-running qualification |
| `DEP-AUD-018` | error | workspace-inherited dependency resolution failure or missing workspace key | define the dependency in [workspace.dependencies] or remove workspace = true | `GATE-000`, `QL-POLICY-001` | configure workspace dependency before re-running qualification |
| `DEP-AUD-019` | error | an undeclared non-member path crate was detected within the repository tree | declare the path crate in workspace members or remove it from the repository tree | `GATE-000`, `QL-POLICY-001` | declare member or remove crate before re-running qualification |
| `DEP-AUD-020` | error | a crate has no inspectable Rust target root | restore/register the target root so unsafe and production-boundary policy is verifiable | `GATE-000`, `QL-POLICY-001` | add target root before re-running qualification |
| `DEP-AUD-021` | error | a Rust target root lacks unconditional forbid unsafe_code | add the unconditional crate-level prohibition; no local exception path exists | `GATE-000`, `QL-POLICY-001` | add #![forbid(unsafe_code)] before re-running qualification |
| `DEP-AUD-022` | error | FSS Rust source contains a forbidden production construct | remove unsafe, native/dynamic/foreign runtime, second executor, or prohibited construct | `GATE-000`, `QL-POLICY-001` | remove forbidden construct before re-running qualification |
| `DEP-AUD-023` | error | a serde-family codec crate or Serde derive/path/attribute is present in FSS manifests, Cargo.lock, or Rust source | remove it and encode durable bytes with the first-party canonical codec; no non-durable serde admission path exists (FSS-110) | `GATE-000`, `QL-POLICY-001` | replace the Serde use with the canonical codec before re-running qualification |
| `DEP-AUD-024` | error | workspace membership duplicate or ambiguous across glob and explicit patterns | ensure each member directory and crate name is uniquely declared once in workspace.members | `GATE-000`, `QL-POLICY-001` | eliminate duplicate members before re-running qualification |
| `DEP-AUD-025` | error | declared workspace root manifest lacks [workspace] table | add [workspace] table to root Cargo.toml or correct the workspace path | `GATE-000`, `QL-POLICY-001` | add [workspace] table before re-running qualification |
| `DEP-AUD-026` | error | a build script contains a network-capable construct on the static deny-list | remove the network access; build scripts must run offline and stay refused by DEP-AUD-031 (static deny-list, not proof of absence) | `GATE-000`, `QL-POLICY-001` | remove network access from the build script before re-running qualification |
| `DEP-AUD-027` | error | a qualification script (scripts/qualify.sh or scripts/release_qualify.sh) does not seal Cargo and rustup offline (missing top-level CARGO_NET_OFFLINE=true or RUSTUP_AUTO_INSTALL=0 export, an override, a cargo invocation without --offline, or a network-fetching rustup command such as rustup install/update, rustup toolchain install, or rustup run --install) | export CARGO_NET_OFFLINE=true and RUSTUP_AUTO_INSTALL=0 at top level and pass --offline to every cargo invocation in scripts/qualify.sh and scripts/release_qualify.sh, and never install or update toolchains, components, or targets there; this is Cargo/rustup sealing, not OS network isolation | `GATE-000`, `QL-POLICY-001` | seal scripts/qualify.sh and scripts/release_qualify.sh offline before re-running qualification |
| `DEP-AUD-028` | error | the rust lane of the qualification entrypoint has no recorded cargo test --workspace --doc step, so doctests (never run by --all-targets) are unqualified | add a recorded `run doctest ... cargo test --locked --offline --workspace --doc` step inside rust_lane() in scripts/qualify.sh (fss-tgwit) | `GATE-000`, `QL-POLICY-001` | add the doctest step before re-running qualification |
| `DEP-AUD-030` | error | a forbidden package is reachable in resolved Cargo metadata | remove it from the entire transitive closure and regenerate locked evidence | `GATE-000`, `QL-POLICY-001` | remove transitive forbidden dependency before re-running qualification |
| `DEP-AUD-031` | error | a resolved package has a custom build target | remove or constitutionally admit the build script with exact offline/security proof; pure-Rust production | `GATE-000`, `QL-POLICY-001` | remove or admit build script before re-running qualification |
| `DEP-AUD-032` | error | a resolved package declares native links | remove native linkage or complete a constitutional architecture change; pure-Rust production | `GATE-000`, `QL-POLICY-001` | eliminate native links before re-running qualification |
| `DEP-AUD-033` | error | a resolved Git package source is not commit-resolved | pin and lock an immutable exact commit with source/provenance evidence | `GATE-000`, `QL-POLICY-001` | lock exact commit revision before re-running qualification |
| `DEP-AUD-040` | error | required pinned-nightly offline Cargo metadata is unavailable | restore exact toolchain/cache/lock/sibling closure and rerun; policy-only execution cannot certify release | `GATE-000`, `QL-POLICY-001` | restore toolchain/cache before re-running qualification |
| `DEP-AUD-041` | warning | target census drift between reference model and cargo metadata | reconcile target roots with cargo metadata to ensure no target is hidden or missing | `GATE-000`, `QL-POLICY-001` | reconcile target roots before re-running qualification |
| `DEP-AUD-042` | error | unclassified crate in Cargo.lock or resolved dependencies | classify crate into an authorized dependency class before qualification | `GATE-000`, `QL-POLICY-001` | classify crate before re-running qualification |
| `DEP-AUD-043` | error | misclassified crate reachable from production or invalid scope boundary | ensure laboratory and oracle crates are not reachable from production | `GATE-000`, `QL-POLICY-001` | correct dependency classification before re-running qualification |
| `DEP-AUD-044` | warning | dependency class row has no active consumer in repository | verify dependency class usage or record explicit consumer drift | `GATE-000`, `QL-POLICY-001` | reconcile dependency consumer status before re-running qualification |
| `DEP-AUD-045` | warning | fundamental crate is pending owner decision fss-ndxis | keep crate quarantined until user decision fss-ndxis is resolved; never admit as production authority | `GATE-000`, `QL-POLICY-001` | await decision fss-ndxis before re-running qualification |
| `DEP-AUD-046` | error | a dependency-class census input (Cargo.lock, architecture/franken_imports.json, or the dependency authority) is missing, empty, oversized, or structurally invalid | restore a valid locked Cargo.lock and valid dependency authority files; the class census fails closed without them | `GATE-000`, `QL-POLICY-001` | restore the census inputs before re-running qualification |
| `DEP-AUD-047` | error | a crate recorded under an open owner decision in dependency_allowlist.toml [pending_owner_decisions] is declared in a manifest or present in Cargo.lock or resolved metadata | keep the crate out of every manifest and Cargo.lock until the owner decision (for example fss-ndxis) is recorded; it is neither admitted nor rejected meanwhile | `GATE-000`, `QL-POLICY-001` | await the owner decision before re-running qualification |
| `DEP-AUD-048` | error | a [patch] or [replace] entry in a Cargo manifest or .cargo/config points at a path outside the repository or at a git source | remove the out-of-repo or git [patch]/[replace] entry; the frozen closed universe admits only in-repository path sources and the pinned registry | `GATE-000`, `QL-POLICY-001` | await the owner decision before re-running qualification |

## Process exit identity registry (EXIT)

Stable process exit identities map command-line interface outcomes to deterministic exit codes and registered identities.

| Exit ID | Code | Meaning | Recovery guidance |
|---|---|---|---|
| `EXIT-OK-000` | 0 | successful execution | no recovery needed |
| `EXIT-CLI-RUNTIME-FAILURE-001` | 1 | runtime execution failure | inspect error output and address underlying cause |
| `EXIT-CLI-UNKNOWN-COMMAND-002` | 2 | unknown command specified | consult help and run a registered command |
| `EXIT-CLI-UNKNOWN-OPTION-002` | 2 | unknown option specified | consult help and provide registered options |
| `EXIT-CLI-MISSING-VALUE-002` | 2 | missing value for option | provide required parameter value |
| `EXIT-CLI-DUPLICATE-OPTION-002` | 2 | duplicate option specified | specify option at most once |
| `EXIT-CLI-MALFORMED-VALUE-002` | 2 | malformed value specified | supply value matching required format and bounds |
| `EXIT-CLI-INVALID-UNICODE-002` | 2 | invalid UTF-8 argument | supply valid UTF-8 argument bytes |
| `EXIT-CLI-UNEXPECTED-POSITIONAL-002` | 2 | unexpected positional argument | remove unexpected positional arguments |
| `EXIT-CLI-TRAILING-ARGUMENT-002` | 2 | trailing argument after grammar exhaustion | remove trailing arguments |
| `EXIT-DOCTOR-ATTENTION-REQUIRED-003` | 3 | doctor inspection detected deployment conditions requiring attention | inspect doctor JSON output for failing checks and follow recommended next affordances |
| `EXIT-DOCTOR-NOT-A-DEPLOYMENT-004` | 4 | target directory is not a recognized reference deployment root | verify root path points to a deployment directory initialized with fss reference layout |
| `EXIT-AGENT-REFUSED-005` | 5 | an agent read (orient, explain, follow) was refused; the response envelope carries the registered error identity | read `errorId` and `degradation` in the envelope and follow the refused operation's recovery class |

## Contract error codes (`fss-core`)
Canonical machine error codes returned by `ContractError::code()` (AGT-LAYER-002, INV-003):
| Error code | Meaning | Stable identity |
|---|---|---|
| `source_evidence_missing_anchor` | Source evidence record missing authoritative anchor | `ERR-SOURCE-EVIDENCE-MISSING-ANCHOR-001` |
| `source_evidence_omission_required` | Not-retained source evidence must declare an explicit omission reason | `ERR-SOURCE-EVIDENCE-OMISSION-REQUIRED-001` |
| `source_evidence_retained_with_omission` | Retained source evidence cannot declare an omission reason | `ERR-SOURCE-EVIDENCE-RETAINED-WITH-OMISSION-001` |
| `source_evidence_not_retained_with_capsule_bytes` | Not-retained source evidence capsule cannot claim non-zero source bytes, non-zero frame count, or non-zero source digest | `ERR-SOURCE-EVIDENCE-NOT-RETAINED-WITH-CAPSULE-BYTES-001` |
| `source_evidence_byte_count_mismatch` | Capsule source bytes does not match custody source bytes | `ERR-SOURCE-EVIDENCE-BYTE-COUNT-MISMATCH-001` |
| `source_evidence_empty_storage_handle` | Retained source custody storage handle is empty, whitespace, or contains invalid characters | `ERR-SOURCE-EVIDENCE-EMPTY-STORAGE-HANDLE-001` |
| `source_evidence_statement_malformed` | Source evidence statement is empty or exceeds 512 bytes | `ERR-SOURCE-EVIDENCE-STATEMENT-MALFORMED-001` |
| `source_evidence_capsule_required` | Sensor capsule classification requires a sensor capsule payload | `ERR-SOURCE-EVIDENCE-CAPSULE-REQUIRED-001` |
| `source_evidence_witness_required` | Continuity witness classification requires a continuity witness digest | `ERR-SOURCE-EVIDENCE-WITNESS-REQUIRED-001` |
| `source_evidence_witness_equals_source_digest` | Continuity witness cannot equal source digest | `ERR-SOURCE-EVIDENCE-WITNESS-EQUALS-SOURCE-DIGEST-001` |
| `source_evidence_not_retained_with_witness` | Source evidence not retained cannot bind a continuity witness | `ERR-SOURCE-EVIDENCE-NOT-RETAINED-WITH-WITNESS-001` |
| `source_evidence_unsupported_version` | Unsupported source evidence binary wire format version | `ERR-SOURCE-EVIDENCE-UNSUPPORTED-VERSION-001` |
| `unknown_source_evidence_classification` | Unknown source evidence classification string token | `ERR-SOURCE-EVIDENCE-UNKNOWN-CLASSIFICATION-001` |
| `unknown_omission_reason` | Unknown omission reason string token | `ERR-SOURCE-EVIDENCE-UNKNOWN-OMISSION-REASON-001` |
| `unknown_source_custody_tag` | Unknown source custody binary wire tag | `ERR-SOURCE-EVIDENCE-UNKNOWN-CUSTODY-TAG-001` |
| `unknown_clock_basis_name` | Clock basis name is unrecognized | `ERR-CLOCK-BASIS-UNKNOWN-NAME-001` |
| `source_evidence_storage_handle_traversal` | Storage handle for retained source evidence contains forbidden directory traversal sequence | `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-TRAVERSAL-001` |
| `source_evidence_storage_handle_absolute_path` | Storage handle for retained source evidence contains forbidden absolute path or url | `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-ABSOLUTE-PATH-001` |
| `source_evidence_storage_handle_malformed` | Storage handle for retained source evidence is malformed, over-length, or contains invalid characters | `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-MALFORMED-001` |
| `source_evidence_raw_wire_packets_with_capsule` | Raw wire packets classification cannot carry a sensor capsule payload | `ERR-SOURCE-EVIDENCE-RAW-WIRE-PACKETS-WITH-CAPSULE-001` |
