# Implementation status

**As of:** 2026-09-23 (reality check; earlier sections written 2026-09-03)  
**Project state:** pre-release deterministic reference implementation; not production-qualified  
**Release authority:** repository-owned local qualification and retained DSR receipts, not hosted CI

## Executive summary

Franken Surveillance System now has a coherent, dependency-light Rust reference spine from immutable source evidence through canonical authority state, guarded external effects, agent situation projection, meaningful deltas, exact continuation, and progressive semantic hydration. The repository is no longer merely an architecture corpus or crate skeleton.

It is also not a complete surveillance product. Native device adapters, production media/model/graph/storage services, persistent distributed operation, every human and agent surface, complete qualification matrices, and the aggregate release root remain open. Status below distinguishes implemented reference semantics from production completion.

## Trained detector evidence for whole recordings (2026-10-10, reference)

`fss-event watch --stream-watch` now accepts the explicit digest-pinned detector package and
shared inference allowance already available to short watch. It keeps native foreground and
tracking state across the complete bounded recording, selects confirmed entries and later
actual matches, then runs a bounded masked-RGB pass for MJPEG, AVC and HEVC. Entries after
frame 128 can receive native trained class evidence without splitting the recording or
resetting the tracker. Predictions, source gaps and different tracker epochs cannot supply
matching class evidence. Source bytes, JPEG work and pixels are accounted across both passes;
the inference allowance never replenishes per entry or frame.

Publication retains the exact model archive, canonical execution recipe, bounded outcome and
all class associations in the shared evidence closure. Cold `fss-event read` verifies their
custody and exact frame-to-capsule bindings; explicit `fss-event verify` reloads the retained
model and reruns the original native computation without the loose model file. The recipe
pins the package, model, threshold, backend generation, RGB decoders and complete original
resource settings. A changed recipe or source/privacy generation invalidates the approval.

Pipeline attempts and completed model-plus-head results are reported separately, including
explicit model-stage or head refusals. The evidence remains uncalibrated and same-sensor:
events stay unclassified, indeterminate, probability `[0,1]` and Hold. This adds neither an
absence certificate nor alert authority. Existing model-free watch publications retain their
bytes and historical replay semantics. See [the workflow and bounds](docs/long_recording_watch.md)
and [retained-model replay](docs/long_event_replay.md).

Focused native validation on the pinned toolchain passes all 58 selected tests: 16
whole-recording reference contracts, 31 CLI regressions and 11 cold replay library cases.
They include native YOLOX execution, MJPEG/AVC/HEVC, exact
publication/retry, cold replay after loose model removal, missing retained-package refusal,
complete recipe recovery, same-camera capsule substitution refusal, privacy, both cancellation
owners and aggregate budgets. These
fixture results establish the implemented workflow, without production or detection-quality
qualification.

## Source-preserving RTSP recording import (2026-10-10, reference, focused native tests passed)

`fss-import-rtsp` closes the gap between native RTSP recording custody and retained media
analysis for AVC and HEVC. An exact owner-approved window slot/root/scope is replay-verified
through its packet-to-NAL-to-MP4 mapping, then imported with the original recording root,
RTP source pack, index, initialization, fragment and canonical origin proof in destination
custody. Existing decode, motion, watch and corroboration consume its ordinary retained import
identity and verify the original ancestry, including decoder parameter reads. Completed
destination analysis works with the capture archive offline. Exact import retries still verify
the selected archive and reconcile partial/completed publication without duplicate authority.

Native MP4 presentation offsets, including composition reordering, are preserved. Absolute
capture origin/uncertainty is optional and explicitly an operator assumption; absent origin
remains unknown. Current sensor privacy, independent original/media limits, bounded source
caches and deletion closure remain enforced. Per-read exact chunk bounds are checked before
allocation. This command opens no network connection and creates no event or alert authority.

Focused validation now passes on pinned `nightly-2026-08-31`: ten native RTSP contracts,
two spool-bound tests, one retained chunk-bound unit test, five CLI parser tests and three
real-binary CLI tests (21 total). They include both codecs, offline decode, cold retry, damage,
scope/budget refusal, masks, timestamp overflow and interrupted publication. Native testing
exposed missing trait imports and a refusal-path defect: constructing destination authority
created its directory before rejecting a missing archive. The importer now checks required
source directories and canonical destination separation under the approved authority first;
missing-source and overlapping/invalid destination refusals leave the destination absent.
These focused tests do not provide camera, release or full-workspace qualification.
See [the importer workflow](docs/rtsp_recording_import.md).

## Cold whole-recording event recovery (2026-10-10, reference, focused native tests passed)

Published `event:long-watch:` and `event:long-corroborated:` candidates now have a cold
`fss-event read` path and an explicit `fss-event verify` path. Inspection verifies the current
revision, provenance/analysis closure, all selected source capsules and current privacy without
running perception. Its JSON provides exact revision/provenance pins and a verification command.
Verification decodes retained MJPEG/H.264/H.265 and reruns the complete native computation,
comparing both full camera analyses and the committed candidate. Shared causes, source gaps,
capture assumptions and optional health screening retain their original semantics. Both paths
append no authority or effects and refuse reviewed successors rather than relabelling them.

Corroboration restores the full retained canonical owner recipe. Historical long-watch restores
its semantic settings and five retained aggregate budgets, with explicitly current bounded
codec/read ceilings for fields that were not saved. No old identity or stored format changes.
The new reference tests include cold native inter-coded replay, late entries, privacy/source
failure, subranges, cancellation, shared causes and a self-consistent forged trace that only
actual native execution rejects. New CLI tests exercise exact generated commands and exports.
Focused native validation now passes on pinned `nightly-2026-08-31`: ten reference tests,
eight CLI parser/output tests and six real-binary integration tests (24 total). This includes
actual retained MJPEG/AVC/HEVC replay and two-camera corroboration. A missing `CanonicalDecode`
trait import found by compilation was repaired. The original authoring environment outage is
resolved for these tests; full qualification, Clippy and a workspace-wide formatting run are
not claimed. See [the command and bounds](docs/long_event_replay.md).

## Acquisition continuity recovery (2026-10-10, reference, unqualified)

`fss-jsiq8`: core acquisition sessions can recover the same stream generation after an explicitly
accounted degraded sequence window. An additive canonical `WindowedDegradationEvidence` binds
the complete request, exact preceding witness, unavailable sequence span and unchanged v1
degradation evidence. Consecutive gaps remain recorded; only the immediately following clean
window can verify. Request replay, changed custody, overlapping/skipped spans and sequence
overflow are refused before mutation, including through indeterminate-state reconciliation.
The recorded RTP driver now emits and retains these wrappers, allowing clean packet/NAL windows
after loss or jitter to verify without inventing a new stream generation. Its 21 native contract
tests cover exact replay and permanent exclusion of the earlier gaps; core validation passed
1,230 tests, 22 doctests and all-target Clippy with warnings denied. The RTP E2E runner remains
unexecuted because its required `rch` command is unavailable.

The old interval-free absence API stays refused after a gap. A new scoped check returns the
current continuity witness only for a contained generation/sequence/PTS scope and an independently
certifying coverage witness; it makes no time-only or clock-continuity claim. Recorded RTP's
estimated-clock coverage remains uncertified. See [the recovery contract and
limits](docs/ACQUISITION_CONTINUITY_RECOVERY.md).

## Graph intelligence, evidence fusion and score calibration (2026-10-07, reference, unqualified)

- **Certified graph families (WP-170):** 15 of the 27 registered graph algorithms are now
  implemented (`fss-graph-algorithms`): `ALG-BRIDGE-001` plus SCC/condensation, topological
  order with CPM critical path, dominators/post-dominators, lexicographic shortest paths and
  multi-source distance, certified max-flow/min-cut (arc cut or minimum-weight node failure set),
  Gomory-Hu (Gusfield) tree, min-cost flow certified by the no-negative-cycle condition, Hungarian
  assignment self-certified by duality with an exact lexicographic tie-break, Murty k-best
  assignments, Kruskal spanning forest, Yen k-shortest diverse paths, exact integer-interval
  temporal reachability (`reachable` / `temporally_infeasible` / `no_path`) and offline dynamic
  connectivity. Every run is budgeted, bound-checked and witness-carrying, and each family is
  certified against an independent brute-force oracle on thousands of seeded inputs. Projections
  are caller-built: no retained-record builder exists yet for the plan, evidence, failure,
  track or archive projections, and no `INT-FNX-001` differential or qualification lane exists.
- **Evidence fusion (`fss-fusion`, fss-x4a.16.9):** deterministic reference fusion over integer
  log-odds intervals with common-cause dependency clusters. Producing-sensor identity is
  intrinsic, so repeated frames cannot become independent support by omitting domain labels.
  The cluster hull models one admissible member per dependency cluster; it is not a bound on
  arbitrary dependent joint evidence. Certified rejection requires complete coverage and
  nonempty calibrated evidence without excluded, uncalibrated or conflicted inputs. Urgent
  single-domain alerts also require calibrated support. Sequential-v2 binds these semantics,
  bounded decisions and leave-one-cluster-out counterfactuals into implementation-specific
  query/decision identities. See [the reference model and limits](docs/FUSION_REFERENCE.md).
- **Score calibration:** `fss-evaluate --calibration-bins` turns an evaluation's true/false
  positives into a digest-bound per-bin likelihood calibration (exact integer Wilson bounds
  and bounded log10 conversion). `fss-fuse` accepts up to sixteen `--calibration` artifacts,
  rebuilds them from their counts and requires every raw score to name its exact generation
  and digest. One artifact cannot corroborate itself; ambiguous priors and conflicting
  generations are refused. Exact raw scores and selected prior identity remain separately
  digest-bound even when their numerical intervals coincide. See the
  [input migration and provenance contract](docs/FUSION_CALIBRATION.md).
  All eight native calibration-adapter CLI regressions pass on the pinned Rust toolchain. No detector has
  a measured deployment calibration, and fusion is not yet wired into
  `fss-event watch`/`corroborate` (their probability stays `[0, 1]`).
## Media, perception and I/O added since 2026-09-03 (reference, unqualified)

All of this is tested only on generated fixtures (FFmpeg `testsrc` encodes, procedural JPEGs,
synthetic scenes). None of it has been measured on real camera footage.

Separately, the owner-authorized vendor lanes (2026-10-07/09) carry live-LAN evidence rather than
fixture-only proof: the TUTK/IOTC NEW-protocol lane for Wyze-class cameras (wire, cryptography,
session, ingest adapter) is live-proven against owner devices; and the Tuya 3.4/3.5 lane for the
AOSU homebase fleet now has a first-party `fss-tuya` crate (55AA/6699 framing, AES-128-ECB/GCM,
HMAC-SHA256 session negotiation, oracle byte-exact vectors), a deterministic homebase simulator,
a sans-IO client, and the ingest/event-semantics mapper with battery/event-driven coverage
honesty, all differentially tested client-versus-simulator (32/32 + 7/7 green). The AOSU live
session remains blocked on the owner local_key (NEG-003); the Yi IPC is ONVIF-gated behind
one-time vendor-app provisioning (NEG-006) with the yi-hack owner-flash path documented.

- **Ingest and capture:** file import with custody for Annex-B/MJPEG/rtpplay and indexed MP4
  with an H.264 `avc1` (`mp4avc`) or H.265 `hvc1`/`hev1` (`mp4hevc`) track: one segment per
  sample with exact source spans, every other byte typed container structure, `avcC`/`hvcC`
  parameter sets read back from custody; indexed, fragmented (`moof`/`trun`) and QuickTime
  (`.mov`) files; Matroska/WebM with one H.264 or H.265 track (`mkvavc`/`mkvhevc`, CRC-32
  verified, known or unknown-size Segments and Clusters, frames byte-identical to the MP4
  samples); decode
  bit-exact against FFmpeg on moov-first, interleaved-audio moov-last and fragmented fixtures,
  including CRA-led H.265 ranges, and FSS's own fragment muxer output reads back exactly
  (`ingest::file_adapter`, `fss-file import`); RTSP negotiation, Digest authentication and interleaved-TCP capture
  (`rtsp::*`, `std::net::TcpStream`); native HTTP MJPEG capture (`ingest::http_camera`); local
  capture archives with checkpoints, recovery, pins and verify/export (`fss-archive`).
- **Durable HTTP reconnect capture:** `fss-capture-reconnect --durable-history yes` now
  drives the existing durable history owner. Each ended generation emits its exact prepared
  history pin before publication, then retains the source-closed boundary root before allowing
  another connection. Reconnect release rechecks original custody after output delays. A
  separate whole-run history allowance is bound into the opt-in approval; incomplete current
  prefixes stay separate from completed history. The selected history can be verified after
  restart; acquisition still uses an explicit finite generation plan. See
  [durable reconnect history](docs/HTTP_RECONNECT_HISTORY.md).
- **Media:** RTP H.264/H.265 depacketization (`fss-packet`); baseline JPEG/MJPEG decode, gray and
  YCbCr 4:4:4/4:2:2/4:2:0 (`fss-codec-mjpeg`, `fss-file decode`); fragmented-MP4 remux for AVC/HEVC
  (`fss-container`); H.264 pixel decode for Baseline, Main and High profile (CABAC and CAVLC,
  I/P/B slices in display order, 8x8 transform, scaling matrices, weighted prediction), bit-exact
  against FFmpeg on 31 fixtures (`fss-codec-h264`), wired into retained decode (`fss-file decode`
  on Annex-B imports, ranges starting at an IDR). H.265/HEVC Main-profile pixel decode
  (intra, P/B inter, deblocking, SAO, WPP, slices, scaling lists) is bit-exact against FFmpeg on 39
  fixtures (`fss-codec-h265`), wired into ingest: `fss-file import` retains HEVC Annex-B as
  `hevc` (explicit `--media-format hevc`; auto-detection only for an unambiguous first NAL header,
  otherwise a typed refusal) with H.265 access-unit splitting, and `fss-file decode`,
  `fss-event watch` and `fss-event corroborate` decode IRAP-led ranges (a CRA-led range skips its
  RASL pictures and lists them). HEVC long-term reference pictures (the "smart codec"
  pattern) decode bit-exactly against FFmpeg on two rewritten-reference fixtures. Not
  implemented: HEVC Main 10/RExt, tiles, dependent slices; interlaced and 4:2:2/4:4:4/10-bit
  H.264.
- **Motion over retained video (fss-21vpr):** `fss-file motion` now accepts H.264/H.265
  Annex B and supported MP4, QuickTime, fragmented MP4 and Matroska imports. Native range
  decoders feed luma comparisons in display order while preserving original source segments,
  capsules and canonical frame receipts. Video reports use v2 and explicitly identify frames
  as unpublished; JPEG reports keep v1. Decode admission and pixel comparisons have cumulative
  limits, partial reports preserve successful observations and explicit RASL exclusions, and
  recovery replays the original IDR/IRAP range. Pixel change remains unclassified activity,
  never a person, intrusion or absence claim. See [the workflow](docs/MEDIA_ANALYSIS_WORKFLOW.md).
- **Pipeline and evaluation:** `fss-event watch` runs decode -> foreground -> Kalman -> zone
  eventgen over a retained import and publishes approval-gated, unclassified, single-sensor
  candidates. `fss-event corroborate` associates two sensors' ground-zone entries (owner
  homographies, not calibration; operator capture hints; worst-case interval time gate) into
  approval-gated corroborated events, and `fss-event alert` prepares, then commits and sends one
  plaintext webhook per corroborated event under separate exact approvals (2xx = relay acceptance
  only; lost ack = indeterminate; no resend). Proven on synthetic scenes and a loopback relay
  only, not on real cameras or detection quality. `evaluation` scores candidates against labels (AUPRC, recall at a false-alert
  budget, time to detect, not_observable). No real labelled corpus exists yet.
- **Common-cause-aware event corroboration:** `fss-event corroborate --failure-domain
  KIND:ID=CAMERA[,CAMERA...]` binds declared network, power, clock, host, model, calibration
  and replay dependencies to retained sensor identities. Overlapping causes form transitive
  supporting components. Matching entries in one component remain `Witnessed`/`hold` and
  cannot prepare an alert; their observations are retained. Canonical declarations and the
  rederivable source-bound assessment are retained with each approved event and bind its exact
  proposal. The report exposes the complete decomposition and states that undeclared causes
  and physical independence remain unknown. With no declarations the existing sensor-only
  reference rule remains, explicitly labelled as an assumption. Health-screened proposals also
  fingerprint all final evidence edges, so preview and stored alert eligibility agree; corrected
  health candidates use new identities. See [the workflow](docs/INTERVAL_CORROBORATION.md).
- **Verified package-event recovery (fss-xsz23):** `fss-event read --event-id event:package:...`
  reopens a published package candidate and can export its canonical event and analysis without
  the original source, model package or loose report files. The reader verifies the actual
  revision chain, retained proof graph, detections and source custody; exact retries preserve
  the original root, revision and anchor. Damaged/deleted evidence, changed successors and stale
  computation/privacy bindings are refused without repair. Seven reference recovery tests and
  two CLI recovery/continuity tests pass natively. Existing valid durable encodings remain
  unchanged. See [package-event continuity](docs/PACKAGE_EVENT_CONTINUITY.md).
- **Coverage witnesses (fss-fnrgr):** ordinary `fss-event watch` / `fss-event corroborate` reports
  proposes a coverage record: one fss-core `CoverageWitness` per (sensor, zone, maximal contiguous
  interval) decoded without gap or skipped segment, past background warm-up (4 frames) and
  confirmation latency, image zone inside the frame, capture time an operator hint and no source
  gap earlier in the import, bound to the exact pipeline generation; every other frame is a
  typed uncovered interval (zone entries name their event). Only `--retain-coverage <approval>`
  retains it (`coverage_witness` ledger family); unknown capture time never yields a witness.
  Proven on synthetic MJPEG scenes only; the witness certifies what the uncalibrated pipeline
  would have emitted, not detection quality.
- **HTTP archive to retained recording:** `fss-import-http` replays an exact captured HTTP/MJPEG
  prefix through the native parser and imports every complete JPEG under an explicit camera and
  timing declaration. The reconstructed MJPEG, original HTTP bytes, root metadata, frame maps and
  source capsules share one retained publication closure. Native decode, inference and watch can
  then use the returned identity after the independent archive is removed. Current target-sensor
  masks still apply; unknown capture times and incomplete source endings stay explicit. The
  no-I/O plan binds source, destination, principal and bounds; committed retries verify original
  custody before continuing. This implementation profile adds no live-device certification.
  See [the import workflow](docs/http_archive_import.md).
- **Restartable HTTP history analysis:** `fss-watch-http-history` verifies an independently saved
  durable reconnect history and explicitly binds every selected generation to a sensor, stream,
  receive time and capture-time assumption. One original-retention approval reconciles all
  source-closed recording imports, then runs native whole-recording entry analysis with fresh
  tracking per reconnect. Exact retries reuse verified completed imports and recompute reports;
  empty responses and prefixes without a complete JPEG remain explicit. All per-generation
  processing reservations are summed before I/O, source/framing budgets remain shared, and the
  selected original history is reverified before output. Current masks and optional health
  screening apply. Eligible proposals include separate exact event-publication commands that
  need only retained destination custody. This finite synchronous workflow creates no daemon,
  reconnect authority, automatic event or absence claim. See [the workflow](docs/HTTP_HISTORY_WATCH.md).
- **Whole-recording zone observations:** `fss-event watch --stream-watch` follows one native
  foreground model and tracker across up to 65,536 retained MJPEG, AVC or HEVC segments, including
  the former 128-frame boundary. Each tracker epoch can produce one unclassified entry candidate
  per track and zone, only from a confirmed actual match strictly inside the zone. Source gaps
  and tolerated decoder refusals restart tracking. Source reads (including inter-coded recovery
  probes), pixels, assignment work and trace bytes have aggregate limits; none reset at chunk or
  decoder boundaries. Approvals bind the complete scan, limits and exact privacy generation.
  Optional conservative health screening blocks publication for the whole scan on findings or
  incomplete screening. This mode grants neither absence certification nor alerts. Native
  synthetic integration cases cover late entries, gaps, codecs, resource refusals, privacy,
  retained custody and recovery; qualification status must come from an executed run.
  See [the workflow](docs/long_recording_watch.md).
- **Whole-recording two-camera corroboration:** `fss-event corroborate --stream-corroborate`
  scans up to 65,536 native MJPEG, AVC or HEVC segments per camera with persistent tracking.
  Confirmed actual samples can enter an owner ground zone after the former 128-frame boundary;
  recovery epochs cannot be bridged. Complete retained camera analyses and owner transforms,
  zones and thresholds support exact proposals under worst-case interval/distance gates and
  existing common-cause contraction. Current masks apply before perception; degraded whole-scan
  health blocks publication. Separate scan budgets, explicit exclusions, exact source/privacy
  revalidation and cold retries preserve the existing authority boundaries. Detector, pose and
  coverage-retention modes require their existing contracts and are refused in this new mode.
  See [the workflow](docs/long_recording_corroboration.md).
- **Cached analysis publication:** short watch, two-camera corroboration and streaming
  modes revalidate their original deployment, principal, current privacy generation, source
  deletion state, retained source bytes and analyzed capsule payloads before publication,
  including exact retries. Short watch and corroboration apply the same check before coverage
  retention. A changed mask, deleted source or damaged quiet-frame capsule cannot be revived by
  an old in-memory report. Historical short-watch, corroboration and dwell encodings stay stable.
- **Whole-recording dwell for inter-coded video:** `fss-event watch --stream-dwell` (long dwell,
  up to 65,536 frames in one pass) now accepts H.264 and H.265 imports (Annex-B, MP4,
  QuickTime, Matroska) as well as MJPEG: frames come from streaming IDR/IRAP-led range decoders in display
  order, dwell positions are display positions bound to coding segments in the trace, opt-in
  tolerance restarts at the next IDR/IRAP, and inter-coded scans bind their own analysis
  policy. Proven on a synthetic 300-frame B-picture MP4 (library and CLI, preview through
  publication); an Annex-B B-picture stream timed by coding order is refused, not reordered.
- **Opt-in recorded visual screening:** `fss-event watch --sensor-health conservative-v1`
  and `fss-event corroborate --sensor-health conservative-v1` screen already decoded,
  privacy-masked pixels for exact frame repetition, sustained dark/bright clipping and contrast
  collapse. Suspect runs cannot support candidates or coverage witnesses; the report and
  retained coverage carry source-bound measurements, complete qualifying-run
  `sensor_health_degraded` intervals and `sensor_health_dependent_track` exclusions for withdrawn
  track histories, preventing an earlier positive entry from becoming false absence.
  Each corroboration camera is screened separately. Clear results explicitly say
  `clear_screen_not_health_evidence`; policy and measurements bind approvals, including
  post-publication coverage reanalysis. Existing unscreened bytes remain unchanged. The
  128-frame recorded bound remains; streaming dwell keeps its separate whole-scan gate, and
  short non-stream dwell with screening is refused. All eight native recorded-health CLI
  regressions pass, targeting the admission and authority boundary. No physical-health or
  tamper-detection claim.
  See [the screening workflow](docs/long_recording_health.md).
- **Geometric ground-zone coverage (fss-2h5zq.53):** corroborate ground zones are sampled on the
  ground plane (8x8 grid by default), projected through the owner homography or an owner
  calibrated pose (checked against the homography), and, with an owner fss-twin scene mesh and a
  pose, ray-tested for occlusion; the record keeps the visible fraction, sampling and occlusion
  model, and a zone below the registered threshold is `occluded`/`outside_frustum` with no
  witness. Without a mesh the claim is explicitly frustum-only (`occlusion_unknown`) in the
  witness predicate and in orient. Grid, threshold, pose and mesh digest are bound into the
  pipeline generation. Proven on synthetic scenes and a synthetic two-object mesh through the
  binaries; no real camera calibration, lens model or real owner mesh has been exercised, and
  `watch` has no ground zones (its image-zone coverage is byte-identical, pinned).
- **Site calibration (fss-x8j0v, open):** a first-party bundle adjuster (fss-geometry: Schur-
  complement Levenberg-Marquardt, typed intrinsics refinement, explicit or control-point gauge,
  covariance, generation invalidators) and joint multi-camera refinement against an owner atlas
  (fss-twin). `fss-event calibrate` builds a digest-bound calibration (`FSSCAL01/02`) from owner
  correspondence files or still JPEG frames (native FAST-9/BRIEF features, cross-camera ties);
  `fss-event calibration adopt|show` retains approval-gated adoptions; `corroborate --calibration`
  uses the calibrated poses, refuses stale or unadopted calibrations, binds pose provenance into
  coverage records, and withholds absence witnesses for zones whose visibility changes under the
  calibration covariance. Proven on synthetic scenes only; per-camera time offset and real-footage
  accuracy are open, and adoption is owner authority, not an observation of the camera.
- **Decode refusals as coverage gaps (fss-fnrgr follow-up):** `watch --tolerate-decode-refusals`
  (opt-in) records a mid-recording refusal or source gap as `decode_refused` intervals with the
  error id, resumes H.264/H.265 at the next IDR/IRAP, restarts tracking (no bridging) and never
  lets a witness or a follow silence certificate span the gap. Default behaviour is unchanged.
  Not wired into `corroborate`; the detector cascade is refused over a gapped range.
- **Privacy masks (fss-bgqkd):** `fss-event privacy-mask declare` retains an owner-declared,
  per-sensor rectangle mask (declared stream resolution, 1..32 `transform:bounding_box_redact`
  regions) only with its exact approval (`privacy_mask_policy` ledger family, one generation per
  approval, stale approvals refused). Every retained decode (JPEG/MJPEG luma and RGB, H.264, H.265,
  video RGB) fills masked pixels before any consumer; receipts bind the policy or an explicit
  no-policy marker; lineages of different mask generations never share identities; zones with
  any masked pixel are `privacy_masked` / `not_observable`; raw export and superseded-lineage
  reads are refused. Retained file imports only: live capture paths, deletion closure, retention
  and biometric controls remain open (PRIVACY.md 4.1). Composes with geometric ground zones (a
  sample on a masked pixel is `privacy_masked`, counted once; version-3 coverage records) and
  with tolerant decode (decoded frames masked; `decode_refused` precedes `privacy_masked`).
- **Certified graph family (fss-w96u7, FSS-165):** `ALG-BRIDGE-001`
  (articulation points and bridges) in the new `fss-graph-algorithms` crate: an iterative Tarjan
  DFS over a canonical immutable undirected simple graph (stable identities, registered tie-break
  `tie:stable-node-identity-then-stable-edge-identity:v1`), plus the nodes each cut vertex or
  bridge separates from a declared root. Every run emits the fss-core `GraphAlgorithmWitness`
  (`fss.graph_algorithm_witness.v1`, now an implemented schema) and checks its counters against
  the registered bound (`n` visits, `2m` scans, `2m + n` low-link updates) in the runtime path; a
  violation or exhausted budget fails closed with no answer. Certified against a brute-force
  removal oracle on 4,000 seeded graphs (random, trees, paths, cycles, stars, cliques, barbells,
  lollipops, grids, disjoint unions, coverage shapes) plus insertion-order, orientation and
  relabelling metamorphic tests. `fss-event graph single-points --root DIR --site SITE` projects
  retained coverage records into a `SensorCoverageGraph` (plane, sensors, zone scopes; a
  sensor-zone edge per retained witness) and reports, read-only, each zone's observers and the
  sensors whose single loss leaves it without any retained witness. Proven on synthetic
  deployments built through `fss-file import` and `fss-event watch`. Not qualified: no
  FrankenNetworkX differential (gate `INT-FNX-001`), snapshot-invalidation, capability
  noninterference or incremental/full lanes; witness intervals are not intersected and no failure
  domain beyond the sensor itself (network, power, clock, host) is modelled; the other 26
  registered algorithms remain `specified`.
  reads are refused. Composes with geometric ground zones (a sample on a masked pixel is
  `privacy_masked`, counted once; version-3 coverage records) and with tolerant decode (decoded
  frames masked; `decode_refused` precedes `privacy_masked`). Live, recording and replay paths
  (fss-g9gml): live HTTP HOG and RGB acquisition, archived HTTP RGB replay, HTTP recording decode,
  `fss-archive check-http` (`--privacy-root/--site/--sensor`), RGB evidence replay and retained
  MJPEG health screening apply the named sensor's current policy per decoded frame; owner grids or
  backgrounds admitting masked pixels and decodes naming no sensor are refused; no-policy bytes
  are golden-pinned; RTSP live capture decodes no pixels. Raw custody export is refused for a
  masked sensor (`fss-file extract`, `fss-archive export --privacy-root --site`; fss-nswce);
  archived HTTP wire reads have no export command. Biometric controls remain open (PRIVACY.md 4.1).
- **Deletion closure (fss-x4a.9.7, FSS-037; scopes fss-x4a.30.86.20/21):** `fss-event delete plan
  --import-id | --sensor-id | --event-id` computes the graph-complete closure of one retained
  import, or of the union of retained imports of one sensor or reachable from one event (scoped
  plans are `fss.deletion_plan.v2`, binding the scope; objects shared outside the scope are kept
  and listed) (every ledger batch and visible root that holds,
  names or embeds a digest of its derivatives: custody, decoded frames and receipts, coverage and
  package-detection records, event provenance, attributable staging leftovers) as a sealed,
  digest-bound plan; `delete commit --plan --approve` revalidates it against the current head,
  appends the deletion record first (`deletion_record`, one `deletion_tombstone` successor per
  exclusively deleted ledger object, one `local_root_retraction` per root), unlinks root records
  and spool objects, verifies absence and appends the completion record; it resumes exactly once
  after an interruption at any cut point. Events keep their revision history (no new revision);
  their evidence and the import read as `deleted` (`ERR-EVIDENCE-DELETED-001`), and orient/explain
  say so. An open or indeterminate alert on the evidence blocks the commit. Local unlinking only:
  not cryptographic erasure (the spool is not encrypted); filesystem recovery, backups, the input
  file and operator exports are named out of scope or unknown copies. Owner evidence holds and
  minimum-retention deadlines (`fss-hold place|release|retain|due|expire`) block deletion of a held
  import and its derivatives, including every member of a scoped plan. No automatic retention
  policy, no remote archive or replica deletion, no person/data-subject scope (none exists), and
  `PUB-DELETE-001` stays `specified` (PRIVACY.md 8.1).
- **Models:** scalar executor over the FSS IR (Conv2d, MatMul, pooling, norms, activations) with
  Safetensors weights (`scalar_executor`, `fss-infer`). One trained detector package ships:
  YOLOX-Nano COCO-80 (`models/yolox-nano/`, `MOD-YOLOXNANO-001`, Apache-2.0), imported offline
  from the pinned upstream ONNX by a first-party importer, loaded only through the digest-verified
  package path (`ingest::rgb_package`), and run over retained MJPEG/H.264/H.265 imports by
  `fss-infer package-detect` (H.264/H.265 in real colour: decoded luma and chroma through a
  declared BT.601 limited-range transform whose Y/Cb/Cr planes reassemble FFmpeg's `yuv420p`
  oracle frames). The scalar executor matches the onnxruntime lab oracle within 3e-5 (tolerance
  1e-3) with identical detections on three pinned inputs; it takes ~3 s per 416x416 frame in
  release. **Detection cascade (fss-704tz):** `fss-event watch`/`corroborate`
  `--detector-package ... --detector-max-inferences N` run the package only on frames the
  foreground/Kalman/zone gate selected (entry, confirmation, following frames; explicit budget,
  typed budget exhaustion), associate detections to tracks by IoU and attach uncalibrated class
  evidence (label, score, package digest/generation, frame and capsule digests); candidates stay
  `Unclassified` and single-sensor, the corroboration policy event is unchanged, and coverage
  binds the detector generation. `fss-infer package-detect --retain yes` -> `fss-event report
  --package-report` -> `prepare`/`publish` records unclassified, indeterminate package-track
  events. Proven on a synthetic silhouette scene (one inference per test), not on real footage;
  no quality, recall or calibration is claimed on any deployment data. The other trained weights
  are the OpenCV HOG people SVM (`fss-twin`), with no claimed recall.
  `fss-infer package-detect` (H.264/H.265 as grayscale: retained decode is luma-only). The scalar
  executor matches the onnxruntime lab oracle within 3e-5 (tolerance 1e-3) with identical detections
  on three pinned inputs. `RgbDetectorPackage::load` now defaults to the optimized CPU executor
  (`optimized_executor`, fss-bd99t), certified bit-identical to the scalar reference by in-tree
  differential tests and the conformance test; measured median 193 ms vs 3085 ms scalar per
  416x416 frame on one shared worker (docs/PERF_LEDGER.md PERF-001). The scalar reference stays
  selectable (`load_with_backend`, `fss-infer package-detect --kernels scalar-reference`), and the
  selected kernel generation is bound into the model digest. Optional deterministic
  multi-threaded Conv2d (fss-zczw0): `ExecThreads` / `--threads N|auto` (default 1) splits
  convolution outputs into contiguous per-thread chunks on `std::thread::scope` workers. It is
  certified bit-identical for 1, 2, 3, 4, 7 and 8 threads (random geometries and the YOLOX
  conformance inputs), and the count reaches no identity. On the shared, oversubscribed hosts
  measured it gave no wall-time gain (PERF-002, e.g. 233.8 vs 231.0 ms median at 1 vs 8 threads
  under load 70-84 on 16 CPUs), so no speedup is claimed. x86-64 SSE2 baseline only; not measured
  on arm64. No quality, recall or
  calibration is claimed on any deployment data, and `fss-event report` cannot yet consume these
  detections. The other trained weights are the OpenCV HOG people SVM (`fss-twin`), with no claimed
  recall.
- **Perception:** running-variance foreground detection, HOG multiscale scan, Kalman
  constant-velocity tracking with Hungarian assignment, global cross-camera assignment over
  caller-supplied ground-plane points, zone-gated event candidates (`ingest::{foreground, tracker,
  cross_camera, eventgen}`). Event quality (AUPRC, recall at a false-alert budget) is not measured.
- **Effects:** a native plaintext HTTP webhook transport behind durable authorization gates
  (`alert::webhook`), driven by `fss-event alert` for events corroborated by two independent
  sensors (`fss-event corroborate`). Only plaintext relays, no TLS, no retries; a 2xx proves relay
  acceptance only. Sensor independence rests on operator-declared sensor identities.
- **Operations:** `fss doctor --json --root <dir>` inspects a deployment read-only; `fss-lab` runs
  its six scenarios on `ReferenceDeployment` (mock model and simulated alert provider).
- **Agent reads (fss/1, CLI only):** `fss session orient` (AOP-003, alias `fss orient`),
  `fss explain` (AOP-011), and `fss session follow` (AOP-004, alias `fss follow`) answer read-only in the registered `AgentResponseEnvelope`. Every
  orientation emits a content-bound anchor token (site, commit, effect-journal records, and a
  binding over the anchor, ledger root, and effect-journal root); `fss follow --since <token>`
  compiles the situation as of that anchor from the committed ledger and effect-journal prefix
  alone and returns the reference `MeaningfulDelta` engine's delta to the head, paged through an
  exact `follow_stream` continuation (every page carries the full class set; protected items
  first; unknown, foreign, and ahead anchors and altered or wrong-stream continuations are typed
  refusals). Orientations now carry one local-state effect cell per durable operation, so a
  prepared alert surfaces as protected obligation and effect-uncertainty classes. Orient assesses
  every objective zone as `covered`, `not_observable` or `stale` from retained coverage records
  and is `complete` only when every zone is covered over its declared window; then a follow whose
  basis and head are the same committed position returns the engine's silence certificate bound
  to the witnesses. Across a ledger advance no silence is certified yet (the frame binds
  commit-specific statements; drift entry in `architecture/agent_contracts.json`), and without
  coverage the persisting gap stays protected `coverage_loss`. There is no long-lived
  subscription, wake, or MCP transport; follow is one bounded read per call.
- **Agent sessions (fss/1, CLI only):** `fss session open` (AOP-001) opens a durable
  mission-scoped session and its revision-zero workspace at the current orient anchor through the
  existing `DurableSessionStore` (a session journal under `<root>/agent/sessions/` with an
  atomically replaced pinned root; a rollback or foreign journal is refused, never repaired) and
  publishes the mission statement root-last under `<root>/agent/publications/`; an identical open
  is an exact retry. `fss handoff` (AOP-012, alias `fss session handoff`) seals the situation as of the session's
  anchor with the existing handoff sealing code and publishes a root-last handoff record (plus the
  session and workspace revision as `agent_session.v1`/`agent_session_capsule.v1`); a crash at
  any publication cut point leaves the handoff absent or complete. `fss session resume` (AOP-002)
  refuses unknown, tampered, expired, unauthorized, and foreign handoffs, compares the situation
  as of the handoff anchor with the head through the reference `MeaningfulDelta` engine, lists
  every invalidated assumption, action, and anchor-bound fact, and rebases the session and
  workspace onto the head in one atomic journal command. Only agent-plane state is written; the
  authority ledger, effect journal, and deployment spool stay byte-identical. Leases and handoff
  lifetimes run on the deployment evidence clock; there is no authentication (principals are
  audit labels) and no MCP transport. Open drifts: `architecture/agent_contracts.json`.
- **Agent operation grammar completed on the CLI (fss/1, 2026-10-06):** all 14 registered
  operations now have an `fss` surface. `fss investigate` (AOP-006) projects the existing durable
  case engine onto deployment roots: open (draft at the session's exact anchor and contract
  basis, deadline on the evidence clock), inspect, list, activate, cite, assess, set-state,
  conclude, rebase, readmit, expand; dispositions stay orthogonal to knowledge states, every
  change is an optimistic CAS on the exact revision digest, refusals are typed, and the
  session-bound situation lists one `affordance:investigate:<case>` per open case (inside the
  capsule identity) and fills `activeInvestigations` in situation and handoff payloads. After a
  `session resume`, open cases are listed as invalidated and refused as stale until rebased; old
  citations then need readmission. `fss plan --intent alert` (AOP-007) publishes a witnessed
  `fss.agent_control_plan.v1` DAG (observe, decide, prepare, commit, record, reconcile) bound to
  the session situation's frame and WorldEnvelope digests, naming the activity worlds the commit
  serves and the artifact worlds where it is a false alarm; with the operator's exact plan
  approval it durably prepares. `fss commit` (AOP-008) revalidates the plan and both approvals,
  commits before any I/O and sends exactly one webhook (2xx = relay acceptance only; a lost
  acknowledgement is indeterminate and never resent). `fss wait` (AOP-009) is a bounded
  read-only poll; `fss cancel` (AOP-010) previews and then cancels a still-prepared operation
  under exact approval. A published plan is mission state, not conversation: until its
  operation is terminal in the head's effect journal it appears in the session-bound situation as
  a blocked `affordance:plan:<plan>` (inside the capsule identity) and in `activePlans` of
  situation and handoff payloads. `fss plan --close` (the AOP-007 close intent family,
  AGT-LAYER-009, FSS-230) closes a terminal plan by publishing its immutable execution episode
  root-last: predictions with their observed states (delivery, event revision, and a never
  observed "warranted" prediction), step and effect receipts, the obligation, outcome
  predicates, measured resource use only, attribution hypotheses (rule-derived plus the
  principal's feedback about the plan, operation, or event, under an explicitly uniform prior),
  and residual uncertainty; one episode per plan, never rewritten. A compiled plan that was
  never prepared closes as *withdrawn* (an episode with no effect receipts) under the deployment
  lock, and its exact approval then never prepares it. A terminal plan stays in
  `activePlans` (as a probe affordance) until closed. Because the frozen public registry lets
  AOP-007 answer only the control plan, the episode rendering is hydrated through proof pointers
  (open drift in `architecture/agent_contracts.json`). Work claims (FSS-226) are the
  work-claiming intent family of `fss investigate` (`--transition claim|claim-inspect|claim-list|
  claim-activate|claim-progress|claim-block|claim-complete|claim-release|claim-renew|
  claim-expire|claim-transfer|claim-reclaim`): a claim reserves one exact unit of case work (the
  case, or one hypothesis, discriminator, or probe of it) for one session through the journaled
  coordination engine, so the same work claimed by another session is a typed
  `ERR-AGENT-WORK-CLAIM-CONFLICT-001`; only the holder changes it (CAS on the exact revision),
  dependents activate only after their dependencies complete, transfers need explicit
  activation, and leases (on the evidence clock, at most 300 s) appear as claim affordances and
  in the handoff's `leases`. Claims coordinate cognition only and confer no effect authority.
  Claim answers and the case `list` are the registered `fss.agent_cognitive_envelope.v1`
  (AOP-006 allowlists only it and the investigation state); a handoff's identity binds the
  situation fingerprint, so a re-handoff after agent-plane changes at the same anchor is a new
  handoff. Shared findings (FSS-227) are the case-board intent family of `fss investigate`
  (`--transition finding|finding-withdraw|finding-list`): an immutable, root-last,
  evidence-linked claim about a case (optionally a hypothesis) with its own knowledge state,
  published with a hydratable `fss.agent_finding.v1` rendering; a later finding may supersede
  (one successor each, only while active), withdraw, or explicitly disagree with findings of the
  same case. Two active findings in disagreement are both reported `conflicted` (their recorded
  states kept), the situation lists one probe per disputed finding, and the conflict stays until a
  supersession or withdrawal ends it; superseded and withdrawn findings stay readable as `stale`.
  Handoffs carry the active findings (no longer a hard-coded empty list). A handoff's
  obligations, prepared operations, and indeterminate effects are read from
  the head's effect journal (live state), not from the session's older anchor. The first
  end-to-end agent rehearsal (FSS-240, `agent_rehearsal_contract`) drives one mission through
  the real binaries: orient, explain, session open, case open/activate, probe claim, cite and
  assess, plan on the case, approve, handoff, resume (which names the new obligation), commit
  (one dispatch), wait, owner-attested reconcile, close (episode), advisory feedback citing the
  episode, case conclusion, and a final handoff with nothing active, validating every answer
  against its schema and retaining a JSON-lines transcript (`FSS_REHEARSAL_TRANSCRIPT`).
  `fss feedback` (AOP-013) publishes grounded, evidence-linked advisory
  proposals (`activePolicyMutation: false`). `fss-event alert` and the agent grammar share one
  alert core (`fss_cli::alert_effect`), so an operation prepared by either is the same operation.
  The MCP adapter adds only the read-only `wait` tool. `fss commit --reconcile
  delivered|not_delivered` (the AOP-008 reconcile intent) discharges a dispatched alert's
  obligation on the owner's attestation (evidence digest and statement, bound to the exact
  receipt): the attestation is published root-last to the ledger first, then the journal moves
  `indeterminate`/`adapter_accepted` to `observed` and `verified`, or to `failed`; preview, then
  exact approval; never a resend; explicitly `operator_asserted`, not a provider receipt. Limits:
  alert is the only plan intent; no provider lookup exists for webhook relays; probes are
  recorded, never executed; no learning proposals or
  promotion, ExperienceCapsule, or multi-agent schedule qualification yet; proven on synthetic fixtures and a
  loopback relay only (`investigate_cli_contract`, `agent_effect_cli_contract`,
  `work_claim_cli_contract`, `finding_cli_contract`, `agent_rehearsal_contract`).

Architectural deviations to resolve: device and alert I/O use blocking `std::net` rather than
Asupersync (owner decision `fss-x4a.8.1` is open), and the workspace has zero third-party crates.

## Implemented deterministic reference spine

### Canonical authority, evidence, and custody

- Stable typed identities and canonical encoding.
- Content digests and root-closed object manifests.
- Immutable sensor capsules and capture-time uncertainty intervals.
- Coverage witnesses and explicit negative-evidence boundaries.
- Ordered `EvidenceDeltaBatch` authority history and exact `LedgerAnchor` succession.
- Durable reference journal recovery with incomplete-tail policy.
- Child-first, root-last publication into the reference ledger.
- Deterministic virtual acquisition, transport mutation, replay bundles, and mock-model execution.

### Events, policy, and effects

- Evidence-linked event hypotheses with explicit lifecycle state.
- Reference unknown-presence policy that requires independent failure domains before alert preparation.
- Separate alert prepare, commit, provider observation, reconciliation, and terminal publication stages.
- Idempotency identities, operation receipts, obligations, and indeterminate-effect retention.
- Guarded situation projection: only an exact local `Prepared` receipt preserves commit; missing or later operation state exposes status/reconciliation.
- Rejection of forged, structurally inconsistent, stale, or mismatched effect receipts.

### Agent situation and control membrane

- `ContractBasis`, `KnowledgeCell`, `PossibleWorld`, `WorldEnvelope`, `ActionAffordance`, `SituationFrame`, `SituationCapsule`, and root-closed handoff contracts.
- Conservative distinction among known, estimated, unknown, conflicted, stale, not observable, redacted, indeterminate, and not applicable state.
- Retention of protected high-consequence worlds rather than rank-only pruning.
- Categorized control envelope for robust, conditional, information-gathering, wait, blocked, and unavailable affordances.
- Full multidimensional resource state and action cost, including latency, tokens, bytes, model calls, CPU, accelerator, energy, network, storage operations, privacy exposure, and operator attention.
- Proof-bearing semantic context packs and compression receipts with critical-preservation checks and priced expansion handles.
- Deterministic reference situation publications binding situation, control, resources, context, compression, and proof roots.

### Meaningful change and continuation

- Deterministic `MeaningfulDelta` comparison between exact situation publications.
- Protected non-coalescible classes for contradictions, coverage loss, plan invalidation, obligation change, external-effect uncertainty, authority/policy change, and terminal transitions.
- Explicit tracking of known-premise removal and contradiction resolution.
- Separation of resource pressure from material world change.
- Silence certificates proving no decision-relevant change, including across harmless successor commits.
- Exact continuation streams with content-bound entries, page digests, monotone positions, expiry, stream identity, contract basis, anchor, view, and session checks.
- Exposed read-only through `fss session follow` (AOP-004) over real deployments, comparing an as-of-anchor orientation (committed prefix only) with the head's under the registered `meaningfulDeltaComparison` rules, so a harmless successor commit over complete coverage yields a certified silence (`coverage_cli_contract.rs`).
- Used by `fss session resume` (AOP-002) to list what changed and what was invalidated between a handoff anchor and the head.
- Lineage-bound terminal classification is pinned to the stores compiled against (fss-1s6ac): a byte copy of the authority ledger or effect journal can neither record nor vouch for the original's lineage or discharge its obligations (typed fork refusals), and the publication lineage is a sealed namespace written only by `record_reference_publication` (`ERR-LEDGER-SEALED-NAMESPACE-001`; readers refuse unsealed lineage writes). Store pins are filesystem identities, so in-place rewrites by a filesystem-level writer and platforms without file identities remain outside the boundary (SECURITY.md 14.1).

### Semantic handles and H0–H4 hydration

The FSS-210 deterministic reference slice is implemented:

- immutable `SemanticHandle` identity over the exact subject;
- independently versioned descriptor digests for delivery policy and availability;
- contiguous H0–H4 hydration ladders;
- exact per-level capability and full-vector cost maps;
- distinct privacy class and transform identity;
- typed available, superseded, deleted, expired, corrupt, privacy-transformed, and not-observable states;
- exact `HydrationRequest`, `HydrationArtifact`, `HydrationReceipt`, and `HydrationResponse` contracts;
- deterministic reference descriptor/artifact catalog;
- exact descriptor lookup rather than silent “latest” substitution;
- capability, privacy, H4-purpose, and resource enforcement;
- explicit lower-level downgrade only when permitted;
- proof-root closure and exact progressive continuation;
- tamper, rebinding, cursor-misuse, deletion, expiry, denial, downgrade, and deterministic-replay tests;
- external-consumer coverage of the public `fss-core` API.

FSS-210 remains **in progress**, not complete. Machine schemas/registries, persistent custody and retention proofs, every public surface, fault schedules, aggregate qualification, and GATE-115 evidence remain outstanding.

## Qualification currently represented in the repository

The repository contains executable policy, Rust, agent-reference, manifest, dependency, and release-assembly lanes. The implemented Rust contracts include focused unit, integration, adversarial, durability, replay, effect-fault, situation-projection, meaningful-delta, continuation, compression, and hydration tests.

A passing developer run demonstrates the exact checked tree only. It does not by itself establish production claims, hardware interoperability, model quality, privacy compliance under every deployment, or aggregate release qualification. Those require retained lane receipts and the declared qualification roots.

## Work packages still materially open

### Production runtime and boundaries

- Asupersync-owned production service topology, cancellation/drain evidence, and bounded concurrency across all processes.
- Native camera discovery, transport, codec/media, calibration, archive, drone, notification, and vendor-boundary implementations.
- Persistent FrankenSQLite/FrankenFS/ATP integration beyond the deterministic in-process reference stores.
- Production pure-Rust model runtime, package verification, generation management, batching, calibration, and fallback.
- Certified graph/search kernels and incremental graph intelligence (17 families are implemented and oracle-certified, see "Graph intelligence" above; the other registered algorithms, retained-record projection builders and every graph qualification lane remain open).

### Agent operating system

- Durable mission/objective/session/workspace stores and complete state machines.
- Session-local symbol tables with stale-alias recovery and non-disclosure.
- Attention frontier, investigation/hypothesis workspace, information-value acquisition, contingent planning, execution episodes, outcome attribution, and learning promotion.
- Multi-agent work claims, leases, transfer, duplicate-work prevention, cancellation, and orphan-obligation recovery.
- First-class binding of every context-pack expansion reference to a published semantic-handle descriptor.
- Equivalent typed payloads and decision digests across Rust API, CLI, MCP, TUI, reports, subscriptions, and handoffs.

### Security, privacy, retention, and deletion

- End-to-end capability/privacy projection over every hydration, export, retention, and effect path.
- Automatic retention-policy application, graph-complete deletion beyond local retained imports (remote archive, replicas, indexes, agent memory), and cryptographic erasure. Local deletion closure (import, sensor or event scope) with a completion record, and owner evidence holds with minimum-retention deadlines, exist.
- Secret-bearing boundary isolation, key management, audit export, incident response, and recovery drills.
- Complete stale/rollback/downgrade and one-version-universe enforcement across deployed binaries and stored objects.

### Qualification and release

- Remaining deterministic reference, property, metamorphic, differential, fault, crash, cancellation, lost-acknowledgement, disconnect, multi-agent, pressure, migration, upgrade, rollback, and full mission rehearsals.
- Complete `TEST-AGENT-*`, adapter, model, graph, storage, security, privacy, and performance families.
- QL-AGENT aggregate thresholds for correctness, calibration, hazardous-action rate, evidence use, handoff continuity, operator burden, and full resource cost.
- GATE-115 agent qualification and the later native platform/release gates.
- Locally produced, root-last GATE-120 release qualification root.

## Requirement-status guidance

- **Implemented reference slice:** deterministic code and focused executable tests exist for the named semantics.
- **In progress:** important acceptance dimensions remain, such as schemas, other surfaces, persistent integration, fault evidence, or aggregate qualification.
- **Qualified:** every required lane has retained proof for the exact source, dependency, toolchain, platform, and artifact identity.
- **Released:** the complete local release root has been published after artifact custody, native matrix, canary, upgrade, rollback, and public verification.

No task should be closed solely because a neighboring type, schema, shared helper, or happy-path demo exists.

## Immediate optimal sequence

1. Finish FSS-210 schema/registry and context-pack binding without weakening immutable-handle semantics.
2. Implement the next session-oriented contract on top of exact continuation and hydration rather than inventing another cursor or expansion dialect.
3. Extend the reference mission rehearsal through typed hydration, handoff, stale descriptor, lost acknowledgement, and cancellation outcomes.
4. Establish cross-surface canonical payload equivalence before multiplying presentation-specific features.
5. Integrate persistent custody/retention and deletion proofs before claiming H3 source-evidence production readiness.
6. Accumulate retained QL-AGENT evidence and only then advance GATE-115 status.

## Known status limitations

- Repository integrity manifests must be regenerated whenever tracked source or documentation changes; a stale manifest is a repository-policy failure, not an ignorable cosmetic difference.
- Hosted workflow results are supplementary and may be queued or cancelled by concurrency. They are not substitutes for local retained receipts.
- The large bead graph encodes complete program acceptance. This document summarizes implementation state and does not override bead dependencies, registries, schemas, ADRs, or qualification gates.
