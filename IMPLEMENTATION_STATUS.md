# Implementation status

**As of:** 2026-11-03 (dated feature sections retain their original verification scope)
**Project state:** pre-release deterministic reference implementation; not production-qualified  
**Release authority:** repository-owned local qualification and retained DSR receipts, not hosted CI

## Executive summary

Franken Surveillance System now has a coherent, dependency-light Rust reference spine from immutable source evidence through canonical authority state, guarded external effects, agent situation projection, meaningful deltas, exact continuation, and progressive semantic hydration. The repository is no longer merely an architecture corpus or crate skeleton.

It is also not a complete surveillance product. Native device adapters, production media/model/graph/storage services, persistent distributed operation, every human and agent surface, complete qualification matrices, and the aggregate release root remain open. Status below distinguishes implemented reference semantics from production completion.

## Clock replay with currently adopted camera calibration (2026-11-03)

`fss-scene-fuse retained-calibrated-match` now accepts the explicit retained-motion
query v2 profile. It independently replays the pinned original clock query against
the semantic FSSCAL identity, currently adopted sensors, actual poses and intrinsics,
and prepared pinhole or native radial-rectification image domain. Every original
clock candidate remains in the complete mapped capture intervals. Source identity,
interval inventory, uncertainty, validity, span and requested time are checked before
JPEG decoding; final source, privacy and adoption/withdrawal revalidation remains
mandatory and the deployment guard survives actual report publication.

The separate `fss.scene_feature_match_adopted.v3` report retains the complete clock
replay, exact original query text and source mappings alongside the adopted
calibration, native motion geometry and read/work accounting. The 1 MiB sidecar
reserve comes from the existing 4 GiB source allowance. Existing adopted v1/v2
inputs retain their previous reports and semantics. Temporal features remain
ineligible for static atlas publication. Replaying clock observations does not
authenticate their source custody or associations, establish physical synchronization,
or activate a camera clock, calibration, identity or effect.

Five new tests execute the actual retained-import, calibration-adoption, source-owner,
runtime and publication paths. They pass pinhole/radial success, exact scope binding,
altered sidecar and full-interval refusal, unsupported-hypothesis hull widening,
current adoption/source custody, shared work, cancellation and complete-output limits.
Both emitted native report variants also pass full Draft 2020-12 schema validation.
The complete focused calibrated command/input/report/atlas regression run passes
71 tests, including the five new clock tests and the temporal atlas refusal.

## Validated clock hypotheses in retained motion reconstruction (2026-11-03)

The explicit `fss.scene_feature_motion_match_retained_query.v2` profile now bridges
native clock validation into actual retained multi-camera motion matching. A shared
strict owner independently pins and replays the original clock-query document; a
serialized success report cannot substitute for its observations. Every original
candidate, including unsupported and unresolved alternatives, contributes to the
conservative capture-time hull consumed by the native temporal association and fit.

The adapter binds the original twin/world digest, exact camera pose and intrinsics,
prepared image domain, rig calibration/image generations and declared sensor,
stream and clock bases. Each selected target capsule must match a complete original
projection interval. Zero additive offsets prevent a second timestamp adjustment.
The full mapped inventory must satisfy camera validity, per-exposure uncertainty,
capture-span and requested-time policy before source decoding. Final owner snapshots
repeat the binding and current privacy/source checks after report serialization.

One parent work account covers parsing, native replay and motion reconstruction.
The clock sidecar reserves its 1 MiB maximum from the existing 4 GiB source-read
allowance. Separate v2 motion and embedded-replay schemas preserve version1 bytes
and standalone clock-report limits. Output includes the exact original clock-query
text, every native trial and projection, and all original-to-common source interval
mappings. The source-clock association remains declared; replay does not establish
physical synchronization, authenticate clock-query observations or activate a clock.

An exact-source harness linked native core, geometry, twin, graph and MJPEG libraries
and passed 85 tests, including seven new clock-to-motion adapter regressions and
three shared-owner replay regressions. It executes strict input admission, actual
native scans, full retained-view binding, temporal matching and rendering. Scope
substitution, narrowed original intervals, unsupported-candidate hull widening,
uncertainty refusal, shared-work exhaustion and live cancellation are covered.
Two real retained-owner regressions were also authored for successful replay and
pre-derivative pin/interval refusals. Their runtime/source I/O execution remains
pending behind the Asupersync memory limit; the limited harness does not qualify
deployment authority, command dispatch, retained custody or filesystem export.

## Source-once fusion in the supervisor (2026-11-03)

`fss-event supervise --root DIR --site SITE --plan PLAN --unique-sources N`
now selects the explicit bounded source-once profile, with one through 4096 declared
source identities over the complete process lifetime. The typed
`run_unique_source_supervisor` API uses the same execution path. Repeated or renamed
calibrated evidence contributes no second signed likelihood increment, including
after resets. Exact original sensor, label and unbinned score commitments prevent a
source from being reinterpreted even when two scores occupy the same calibration bin.
Raw and numerical inventories commit together after complete admission, survive
resets and refuse capacity overflow without exporting an accepted prefix.

The separately versioned output includes complete source accounting, every original
and effective query commitment, inner fusion history, raw detector commitments and
configuration. Empty runs and immediate cancellation still bind the configuration
and source allowance. Nonnumeric diagnostics retain explicit absent source keys;
reset windows do not consume observations they never execute. Default and existing
transcript-only output remain unchanged. This mode consumes caller declarations;
retained source custody and qualified statistical independence remain separate.

A limited harness compiled the actual private strategy, verbatim pure per-window
transformation and original report/serializer code against native core/fusion.
Replay, same-bin reinterpretation, transactional conflict/capacity refusal, resets,
neutral diagnostics, zero-transition configuration and receipt substitution checks
pass. Default and transcript-only bytes exactly match the prior original renderers.
Eight emitted new wrappers, eleven nested source receipts, eleven nested fusion
transcripts and both legacy transcript wrappers pass full Draft 2020-12 validation,
with five negative mutation controls. Authored CLI/E2E contracts cover selector
errors and refusal after an accepted prefix without report export. Those process
contracts remain unexecuted behind the recorded Asupersync memory limit; the limited
harness excludes outer authority, work/cancellation, deployment, CLI dispatch and
filesystem export and is not full runtime qualification.

## Bounded source-once sequential fusion (2026-11-03)

The opt-in native `UniqueSourceEProcess` prevents a declared source from adding a
second signed likelihood increment under a new observation alias or after a numeric
regime reset. It validates the complete original query and exact binding inventory
before filtering. Positive, negative and zero calibrated observations each consume
one canonical source identity; neutral diagnostics may explicitly lack a source.
Conflicting immutable source semantics or an exhausted lifetime allowance refuse
the whole step without changing numerical state, either receipt chain, or inventory.

The selected allowance is one through 4096 sources and is never evicted or refunded.
Every original alias receives explicit admitted, already-admitted or nonnumeric
accounting. Receipts bind original/effective queries, all bindings/dispositions,
complete inventory, capacity and independently bounded inner state. Empty inventories
also have an inspectable capacity-bound identity. Historical `SequentialEProcess`
constructors and numerical bytes are unchanged. This is declared-source replay
control, not physical custody, independent errors or statistical qualification.

All 32 native fusion unit tests and 16 contract tests pass, including twelve new
source-once regressions for renamed/repeated evidence, signed increments, conflicting
aliases, neutral observations, source limits, resets, marker aliases and receipt
identity. The new receipt meta-schema also passes full Draft 2020-12 validation.
This advances the sequential fusion work in `fss-x4a.16.9` without closing it.

## Fail-closed agent decision identities (2026-11-03)

World envelopes, situation frames and situation capsules now propagate canonical
encoding refusal through their already-fallible digest APIs. Previously an oversized
text field could make distinct validated-looking objects return the successful
SHA-256 identity of an empty byte string. These identities feed control plans,
situation seals and meaningful deltas. Knowledge-cell admission now also verifies
that disclosed claim/statement and nested state-basis text can be encoded before
its infallible component digest becomes available.

Valid canonical bytes and domains remain unchanged. Exact text-size boundaries and
large aggregates of individually valid cells remain admitted and identity-distinct.
Withheld statements retain their fixed redaction marker without inspecting their
private content or length. Two native baseline regressions reproduced the old
failures; after the fix all 182 core library tests and 186 tests across six affected
core contract targets pass. Two reference regressions cover effect seals, projection,
publication and meaningful-delta refusal, but remain unexecuted behind the previously
recorded Asupersync build limit. This hardens live decision identities; it does not
complete producer-origin authentication in `fss-gefi6`.

## Cross-session clock validation through the operator CLI (2026-11-03)

`fss-clock-align` now accepts the additive `fss.clock_validation_query.v1` profile
and calls the existing native cross-session validator. One frozen camera/clock,
world, fit and hypothesis inventory is evaluated against the original search and
one through eight additional disjoint passages. Global source/evidence reuse,
per-camera exposure reuse, scope overrides, overlapping passages and reversed
clock ordering refuse the complete request.

The report preserves every native trial, unresolved or unsupported alternative,
per-session support and up to 128 requested interval projections. Every time hull
includes all supplied hypotheses; favorable validation cannot prune uncertainty.
Projections outside the declared capture windows remain explicitly marked. A single
native work account and the real owner cancellation probe cover all sessions and
bounded report construction. The complete wrapper and newline share the 8 MiB
output ceiling; no partial successful report is emitted. Exit 0 requires shared
support, exit 3 retains a complete unsupported inventory, and exit 2 is refusal.

Native geometry clock-validation contracts pass 10/10. An exact-source harness
compiling the original parsers, analysis/rendering functions and tests passes
26/26, including nine new validation cases. Three actual supported, unsupported
and unresolved response examples pass all nine full Draft 2020-12 query/report/
response checks and exact digest checks. Both old offset/drift fixture responses
match the previous owner bytes exactly; their hashes are now regression assertions.
The four new process contracts and full CLI runtime execution remain pending after
the Asupersync build was killed at the shared memory limit. This advances
`fss-x8j0v` without closing operational calibration: input custody, associations and
calibration remain caller assertions; physical clock activation, retained timeline
integration, continuous coverage and effect authority are not established.

## Explicit supervisor transcript output (2026-11-03)

`fss-event supervise --root DIR --site SITE --plan PLAN --transcript yes` selects
`fss.supervisor_transcript_report.v1`: the unchanged historical report, ordered
fusion/reset transcripts, and an independently bound deterministic supervisor
receipt. The default JSON and numerical receipt bytes remain unchanged. The new
receipt includes exact report context, window identity, degradation/occlusion and
cancellation details while excluding wall latency. Other supervision modes refuse
the selector. This remains the caller-score simulation, not retained source proof.

A scratch harness compiled the exact original report types, complete sealer and
renderers, JSON primitives and transcript module against native core/fusion. Source
substitution, deterministic replay, reset ancestry, cancellation, oversized context
and every serialized binding passed; default output exactly matches the baseline
`e2eb5ce` renderer. Full Draft 2020-12 validation passed three emitted wrappers and
nine nested transcripts, including negative schema cases. These checks exclude the
execution function, deployment and CLI dispatch. The native supervisor E2E contract
was extended, but remains unexecuted: both a one-job runtime test build and a
one-job metadata-only CLI check were killed in the shared Asupersync dependency
before reaching the changed CLI code. Full runtime/process qualification remains
pending; no successful full build is claimed.

## Evidence-bound sequential fusion transcripts (2026-11-03)

`SequentialEProcess` now refuses an observation for another hypothesis before any
state change. Every accepted observation or explicit reset publishes an immutable
transcript binding its predecessor, actual fusion query/decision or reset arguments,
full hypothesis/configuration/numerical state, and complete supporting-domain
inventory. Reset clears the active numerical regime while retaining history.

Historical numerical step digests retain their original bytes. The separate state
and transcript domains use fixed-width fields, exact text hashes and constant-size
inventory folds, preserving context even when an oversized reset exceeds the old
encoder's text ceiling. Exact ordered input replay reconstructs the transcript.
This advances `fss-x4a.16.9`; it establishes neither source custody nor a qualified
test-supermartingale, and supplies no effect authority. The Ville formula remains
conditional on its separately established statistical assumptions.

All 20 native fusion unit tests and 16 contract tests pass. Eleven new regressions
cover hypothesis/refusal isolation, source and policy substitution, ordering and
replay, reset ancestry, historical numeric golden hashes, and oversized reset
arguments preserving hypothesis, configuration and subsequent numerical state.

## Order-independent provenance transition checks (2026-11-03)

`KnowledgeCell::verify_no_evidence_laundering` now checks every recorded origin of
each shared canonical content identity. Reordering duplicate digest references,
dropping a restrictive origin, changing both the cell class and its origin label,
or toggling the legacy noncanonical laboratory flag can no longer conceal reuse.
Unchanged origin sets, ordinary derivation, fresh evidence and distinct digest
algorithms retain their previous meanings. Existing canonical bytes are unchanged.

The three original exploit regressions failed against the previous implementation;
the complete native `provenance_contract` target now passes all 79 tests. Two further
regressions cover both production delta-classification entry points; their native
execution remains pending after the shared environment killed the larger
Asupersync dependency build. The provenance registry checker and pinned formatting
also pass. This advances `fss-gefi6` without closing it: producer-authenticated
origin catalogs and negotiated wire propagation remain separate unfinished work.

## Requested-count detection from continuous HTTP MJPEG (2026-11-03)

`fss-capture-reconnect sentinel-prefix` now handles an HTTP camera that keeps its
multipart response open. Under its separate exact outer approval it acquires one
generation until the requested number of complete JPEG parts is acknowledged, then
closes the socket and analyzes only the first N frames. It does not wait for peer EOF,
manufacture an ended history, infer capture time or renew a source reservation.

The new native `HttpPrefixSentinelPlan` composes the existing HTTP importer and
long-sentinel detector/retention owners. Every received original byte remains in
source custody, including additional complete read-ahead frames and a partial tail.
The independent import ceiling covers all those originals; read-ahead is explicitly
reported outside the selected range. Native framing completion, if already present
in the pinned bytes, remains separate from acquisition completion or peer EOF.
Release rechecks the original archive, every imported capsule, full destination source
closure and current privacy. Native model calls remain capped at 64 with shared pools.

A typed durable-import observer emits the exact import identity and offline analysis
argv before the first model call. Sink refusal stops before analysis while preserving
the cold-verifiable import. Source-prefix, import, analysis and retained replay handles
support explicit offline continuation without camera reacquisition. These are new
bounded invocations, not replenishment of the live process's remaining budget. The
ordinary importer's pure parser/approval/preview is now reused without changing its
existing bytes or execution behavior. `fss-infer package-detect` and `sentinel-replay`
also accept the selected bounded model-output ceiling; default native limits remain
unchanged and both cold continuations carry the original selection.

Eight native core regressions, three real-process open-socket contracts, two parent
admission/continuation cases and native CLI output-reservation regressions cover
source/pending/count refusal, first-N/read-ahead separation, current authority/privacy,
unsampled-tail corruption, progress sink failure, exact retries and replay after loose
inputs disappear. Source/API reviews and pinned formatting passed; native execution of
this new prefix composition remains pending. The full public schema catalog resolves
134 schemas and 2200 references with no metadata/reference errors. This implements a
bounded live-capture/perception slice of FSS-049/FSS-078, without qualifying detector
quality, continuous coverage, event/effect authority or production operation.
See `docs/HTTP_PREFIX_CAPTURE_SENTINEL.md`.

## Live ended HTTP capture into retained native detection (2026-11-03)

`fss-capture-reconnect sentinel` now composes the actual native camera owner with
HTTP-history trained detection and retained cold replay. One exact outer approval
binds the original capture plan, explicit camera/time assumptions for every reserved
generation, pinned model, destination, sampling and effective resource bounds. Model
and selected contract validation and canonical path admission precede camera contact.
The deployment is not created during model preflight. Existing archive paths refuse
live recapture; no transcript parser or subprocess joins the native owners.

A typed capture receipt authenticates every started connection, exact original prefix,
durable/released history boundary, source/clock/retention/generation inventory and
terminal state. Pending publication, unpublished bytes, an unfinished prefix or failed
output cannot produce a consumable history. Only satisfied settled capture advances
automatically. Earlier failed generations stay explicit when a later native retry
satisfies the request; a terminal failed request instead emits unapproved offline argv.
Unused reserved generations are omitted without refilling any analysis allowance.

The command publishes exact offline-history continuation argv before imports and
per-generation retained `fss-infer sentinel-replay` argv after complete analysis. Its
model/preflight/import work, framing and archive-read accounts remain nonrenewing
across capture and processing. The native capture still owns its independent network
deadline and any approved storage-only grace. Parent deadlines are cooperative at
phase/I/O boundaries, not preemption of native work.

Five parent admission/continuation/output tests, extended typed-receipt cut-point
contracts and three real-process loopback contracts cover complete stationary capture,
wrong approval/model before I/O, partial source refusal with durable continuation,
no-recapture admission, retained replay without loose inputs and CLI JSON schemas.
Source/API review and pinned formatting passed; native execution of this new composed
path remains pending. The existing failed-prefix HTTP sentinel fixture now expects
three fully delimited originals, preserving the native importer's truncation behavior.
This is a finite ended-response slice of FSS-049/FSS-078; it does not claim continuous
camera coverage, detector quality, event/effect permission or production qualification.
See `docs/HTTP_CAPTURE_SENTINEL.md` for commands and recovery boundaries.

## Explicit learning recovery by replacement sessions (2026-11-03)

`fss explain --learning-root` and the equivalent MCP request now make a retained
learning capture accessible to a currently admitted replacement session of the same
principal and immutable mission. The original session may be cancelled or expired.
Both complete mission publications must agree on principal, stable mission identity,
site, mission statement and objective. Possession of a learning root or a matching
mission label supplies no authority.

The existing selected-source reader verifies the original session, workspace, plan,
episode, feedback and learning custody under fresh current explanation/read/privacy
admission. It preserves the original captured session and evidence position separately
from the current response session and anchor. Reads do not reopen the original owner,
write or rebase a workspace, refill budgets, promote learning, or broaden automatic
orientation/handoff discovery into other sessions.

Three real-process regressions cover cancelled and expired original owners, exact
CLI/MCP parity and byte-stable cold retries, current-vs-historical provenance, immutable
read-only stores, same-label/wrong-objective and foreign-principal refusal, revoked
grants/privacy, closed or expired replacement sessions, and missing current mission
custody. The existing selected-learning regression retains missing/corrupt historical
closure checks. Native execution at `3348842` passed the expired-original recovery,
current owner/mission/grant/custody refusal, existing exact selected-learning explanation
and cold captured-learning CLI/MCP recovery cases. The cancelled-original regression
successfully read its selected capture, then failed because the fixture asked for a
nonexistent `anchor` field. That fixture now checks the registered `inputAnchor` and
`basisAnchor`, including equality with the authenticated retained experience basis;
its full native rerun remains pending. Evidence: run `41655137973`, job `125983315450`.
The broader agent-effects target had 27 passes and three failures, including that fixture;
these scoped results are not a complete gate pass. Source review, pinned formatting and
staged manifest checks passed. This is the explicit historical-read slice of FSS-232,
not automatic discovery or learning promotion.
See `docs/historical_learning.md` for exact commands and admission requirements.

## Motion-independent trained detection across HTTP histories (2026-11-03)

`fss-sentinel-http-history` now connects an exact ended HTTP reconnect history to the
native RGB detector without requiring a foreground-motion candidate. It imports every
complete original JPEG first, then allocates whole detection bursts round-robin across
actual imported recordings under one whole-history inference allowance. Separate
bursts and reconnects retain independent tracking; stationary images can reach the
model, while class scores remain uncalibrated.

Every selected connection stays visible, including empty and failed responses,
incomplete JPEG prefixes, recordings too short for a burst and recordings skipped by
the inference ceiling. Source, pixel, JPEG, detection-head and native report resources
share one residual pool; no reconnect refills it. All imports precede model work and
all computations precede optional retention. Current original HTTP, destination media,
source capsules and privacy are rechecked before the complete result is released,
including entirely unsampled recordings and suffixes.

The pure CLI preview binds exact source/model pins, explicit sensor/capture assumptions,
paths, principal, sampling, retention, native backend and resource limits. Approved
retention uses the existing complete native report/model/recipe owner and emits cold
`fss-infer sentinel-replay` commands that work from verified destination custody after
the capture archive and loose model go offline. Interrupted imports and retentions
reconcile through those existing owners on exact retry. The motion-based HTTP watch
formats and existing RTSP sentinel resource semantics are preserved.

The pinned native run at `6ff59b8` compiled this implementation and passed all 13
sentinel binary contracts, the real-process capture/import/inference/cold-replay
contract, both shared-pool contracts, all eight legacy HTTP-watch core contracts and
its CLI contract, and all 17 RTSP campaign sentinel/HEVC/plan contracts. Nine of ten
new core contracts passed; the remaining assertion expected a fourth frame after a
truncated MIME delimiter, while the native importer correctly released only the three
fully delimited frames. That fixture expectation is now corrected without changing
the importer; its native rerun is pending. Evidence: run `41598188819`, job `125794756307`. The workflow was
cancelled after these groups completed; these are scoped results, not a full gate pass.
Independent source reviews, pinned formatting and a narrow pinned-rustc report-format
check also passed. No live-camera, detector-quality, event, absence,
continuous-coverage or production qualification is claimed.
The two strict public projection schemas match the actual source renderers; the
offline catalog resolves 132 schemas and 2077 references with zero metadata/reference
errors. Representative positive/negative shape checks passed. The separate schema
constitution gate still reports existing registry drift.
See `docs/HTTP_HISTORY_SENTINEL.md` for the complete operator workflow and limits.

## Durable operator cancellation of agent sessions (2026-11-03)

`fss cancel --session` and the MCP `cancel` session target now expose AOP-010 session
revocation under fresh owner authority and an exact preview approval. The bounded
preview preserves clocks, journals, pins and spent allowances. Approval atomically
retains the complete original request and the session's closure tombstone in one
private journal command, clearing aliases and preventing old handoffs from reopening
the identity. Existing prepared-operation cancellation remains a separate target.

An exact cold retry recovers the original approval and cancellation receipt even after
later journal entries, without appending a new tombstone. A verified lagging ROOT pin
can be repaired only by an approved invocation. Expiry does not substitute for an
owner-approved cancellation. Current owner, capability, contract basis, site lineage,
source custody and exclusive writer admission remain mandatory.

Plans, pending external obligations, follow progress, coordination and work history
remain retained. The response identifies the outstanding inventory at the original
approval position; session revocation does not settle an effect or prove delivery.
An admitted same-mission replacement session can reclaim a closed owner's live work
claim with a new fencing incarnation and the existing progress intact.

The pinned native run at `6ff59b8` passed all four journal contracts, the MCP request
mapping contract and five of six real-process owner contracts. The remaining contract
exposed a separate MCP server dispatch gate that omitted `CancelSession`, despite
accepting its request. That gate now routes both preview and exact approval to the
same native owner, with a server regression proving notifications cannot execute the
operation. The real-process helper exposes transport refusals directly. The original
authority, exclusive-target, retained-obligation and approval contracts remain intact.
The post-fix native run at `6c876d2` passed all four journal contracts, all six
CLI/MCP integration contracts (including the formerly failing parity case), and both
MCP mapping/actual-dispatch contracts. Evidence: run `41651088223`, job `125969111863`.
The overall workflow later timed out/cancelled in other groups; these are the exact
completed cancellation results, not aggregate qualification. Independent source review
and pinned formatting also passed. See
`docs/session_cancellation.md` for the operator workflow and reference bounds.

## Exact learning recovery across handoff rebases (2026-11-03)

An exact plan-targeted `create_learning_proposal` retry now recovers its original
feedback, experience and learning roots after a handoff advances the session anchor.
Recovery searches only the bounded, currently admitted native learning inventory and
this session's retained workspace anchors. It authenticates the original source closure,
principal, mission and contract basis; changed statements, evidence or dispositions
remain distinct requests with the current anchor.

Missing or corrupt historical custody cannot cause a replacement publication. Missing
learning custody reports the original retained feedback as partial; missing feedback
custody refuses. Current session, feedback capability and private-scope checks still
apply before discovery or disclosure. Captured learning remains advisory and grants
no effect or policy-promotion authority.

The existing real-process CLI/MCP learning contract now covers normalized evidence,
exact root stability after rebase, missing feedback/learning slots, revoked current
admission, and materially different requests. Two independent source reviews and the
pinned formatter passed. Native reference and CLI targets compiled in hosted run
`41596340186`, job `125784472561`, with custody, cold-supervision, event-recovery and
multipart-upload groups passing. The expanded learning-specific regression passed
in the subsequent native run at `6ff59b8` (`41598188819`, job `125794756307`, 12.12s).
The earlier local Asupersync dependency build exceeded this shared host's available
memory headroom and was stopped before project diagnostics. The prior main revision's
native run reproduced the exact-retry defect; no production qualification is claimed.

## Multipart recording continuation (2026-11-03)

Incremental dwell now accepts completed partitioned MJPEG, AVC and HEVC imports.
A version-four checkpoint binds a bounded canonical inventory of the exact original
import identity, aggregate root, metadata and ordered part roots. Each part remains an
independently ledgered publication; the inventory adds one checkpoint child without
combining a long recording into an oversized publication batch. Flat-source v1/v2/v3
recipe and checkpoint bytes remain unchanged.

Hot steps and cold process continuations preserve the original cumulative source,
pixel, tracking and optional health allowances. Native video completion still requires
validated decoder drain. Cold opening reconstructs the exact inventory from current
retained source authority, and missing or changed inventory, source parts, original
principal or recipe refuse. Cached owners cannot reconstruct deleted custody. The
existing deletion closure reaches the inventory, checkpoints and original part roots.

Eight native regressions and two real-process CLI contracts cover codec continuation,
whole-recording report/proposal identity, delayed output, temporal gaps, exact retries,
resource and authority refusal, forged inventories, missing custody and deletion.
All ten new regressions passed in the pinned native hosted run, together with all
82 long-dwell and 34 watch-stream CLI contracts. The core implementation also passed
independent code review and the pinned formatter. The overall workflow failed in
other existing ONVIF, learning and policy checks; these scoped results do not establish
production qualification. Evidence: GitHub Actions run `41563222067`, job `125695702425`.
See `docs/incremental_dwell.md` for formats and operator commands.

## Alert reconciliation after source loss (2026-11-02)

`fss-alert reconcile` exposes the existing operation-addressed owner-attestation contract
without rebuilding an agent orientation from old media. An intact preparation and durable
effect/obligation journals can now be reconciled after the original event source is missing or
corrupt. Preview returns the exact plan and approval command; approval retains the attestation
root-last before settling the existing obligation. Exact cold retries append no duplicate
transition, and changed actor, statement, evidence or outcome cannot reuse the approval.

The output preserves `operator_asserted` provenance, reports that cited evidence custody was
not inspected, and does not claim independent provider verification. It performs no network
dispatch. Prepared operations, stale or missing authority, corrupted journals and unavailable
retained reconciliation proof still refuse. The prior canonical agent command and its approval
identity remain unchanged. See `docs/alert_lifecycle.md` for the operator workflow.

All seven new real-process contracts passed in the pinned native hosted run, as did the
complete 16-test alert CLI group and three owner-contract tests. Source formatting and
independent review also passed. Evidence: GitHub Actions run `41563222178`, job
`125700093921`. Other workflow checks failed; these scoped results do not qualify a
provider or production release.

## Retained RTP/JPEG imports for native analysis (2026-11-02)

`fss-import-rtsp jpeg` connects an independently pinned native datagram prefix to
the ordinary retained MJPEG, pixel, feature and scene owners. The destination
retains every selected original root, metadata record and payload alongside the
reconstructed images, exact native frame source maps and replay diagnostics.
Current retained reads recover that original chain and reproduce the native
JPEG stream; an intact derived image cannot replace missing or damaged original
packet evidence. Completed imports remain usable with the source archive offline.

The request explicitly binds the physical sensor/stream and mapping evidence,
complete source prefix, configuration and replay interpretation, destination
receive time and independent operation bounds. Capture time remains unknown.
Packet gaps, discarded images, cached quantizer ancestry and incomplete tails
remain visible. Prefix exhaustion grants no EOF or coverage claim, and JPEG
entropy validity remains the downstream decoder's responsibility. Existing
AVC/HEVC and HTTP contracts are unchanged.

Publication uses the existing ledgered root-last file owner, including typed
multipart publication and exact interrupted retries. Source and current import
authority revalidate before publication; exact retries verify committed custody
without repairing damaged originals. Preview is pure and opens no storage or
network. Approved execution requires the exact plan digest, an existing source
store and a distinct destination store. Current destination privacy still governs pixels.

All **11/11** genuine public-owner integration tests pass with the pinned runtime.
The import command passes **27/27** tests (six new JPEG cases and 21 existing
regressions), all **5/5** new actual-process JPEG tests, and all **3/3** existing
RTSP import process regressions. They execute actual packet publication, cold
retained verification and native
pixel decoding, including independent luma-oracle comparison after source archive
removal, current masks, quantizer ancestry, gap/tail accounting, limits and
cancellation, source corruption, and forced multipart interruption/recovery.
The production importer command and new CLI integration test pass strict scoped
Clippy against the actual compiled dependencies. The full importer bin test
configuration retains five unrelated existing test lint findings.
Initial import and later cold verification share the same intrinsic replay-work
ceiling. Read reservations describe import-managed original/custody payloads,
not total filesystem I/O or a calibrated memory/latency measurement.

All four actual plan/import/retry/partial-tail JSON outputs pass the strict
Draft 2020-12 operator schema. Exact retry root, manifest, origin proof and
interpretation identities agree, as do plan-to-receipt request and approval pins.
The offline catalog resolves **130 schemas and 1,995 references with zero
errors**; the separate constitution scan retains the same 43 existing findings.
See `docs/RTSP_JPEG_IMPORT.md` for the complete workflow and operational limits.

## Native JPEG replay from copied original custody (2026-11-02)

`DetachedDatagramPrefix` verifies an independently pinned complete datagram
chain from original objects retained outside the capture publisher. Every
canonical root, metadata record, payload, predecessor coordinate, channel and
receive ordering is checked under explicit reader authority and finite bounds.
The sealed owner caches only metadata; subsequent original reads revisit
current custody. `DatagramJpegReplay::new_detached` and `step_detached` use the
existing native scheduler, receiver and provenance binding without changing
source or interpretation identities. Cached quantizers, duplicates, timers and
incomplete-prefix accounting remain exact. Canonical frame source-map bytes can
also be exported through the existing encoder with frame/hash/work checks.

The complete native JPEG target passes **118/118 tests**, including nineteen
new detached/source-map cases. The genuine reference datagram-archive suite also
passes **55/55 tests** with the pinned runtime. Publisher-backed and detached
replay agree on
all native events, reconstructed images and provenance, including cached
quantizers, sequence wrap, reordering, duplicate originals, RTCP and partial
tails. Missing or modified original objects, malicious reader returns, exhausted
work, cancellation, deadlines and wrong pins refuse. Strict scoped Clippy reports
one preexisting `explicit_counter_loop` finding in unchanged `rtsp/message.rs`;
the new source has no reported lint findings. This primitive verifies selected
copied bytes, not original publication durability, later capture observations,
physical camera identity or calibrated time. The retained MJPEG command bridge
uses this sealed owner; see `docs/RTSP_JPEG_IMPORT.md` and
`docs/jpeg_datagram_reconstruction.md`.

## Adopted radial reconstruction and atlas export (2026-11-02, command integration)

The adopted-camera commands now execute native radial correction before stereo,
multi-camera and moving-feature reconstruction, and before static localization
atlas export. An explicit `fss.scene_camera_rig_adopted.v2` selects this profile;
every declared source matrix, original domain, semantic lens basis and two-term
Brown coefficient vector must match the sealed current calibration exactly.
All maps compile before decoding. Actual corrected domains, dimensions, maps,
exposures and privacy receipts bind back to those plans before geometry runs.
The target grid remains the refined original camera grid. Mixed rigs may retain
direct images only for zero-radial cameras. Original v1 contracts and FSATLAS1
remain unchanged.

New v2 reports and atlas manifests preserve original and corrected provenance,
conditional camera covariance, coverage exclusions, all native alternatives and
unresolved components. Full interpolation and descriptor support must be allowed
by current privacy. Original-source, current-privacy and adoption/withdrawal
checks still precede publication under the exclusive deployment owner. Absolute
camera and landmark error remain unknown; these outputs activate no calibration,
twin revision, identity or effect.

Genuine pinned-runtime execution now passes **267 tests** across the reference
calibration owner (**20**), adopted rig library (**4**) and complete scene command
binary (**243**). This closes the earlier execution gap for retained adopted
matching and atlas command owners. The final report-helper source also passes
its **14-test** focused rerun, a subset of the scene suite, and scoped strict
Clippy passes. The new command cases exercise real retained JPEG/adoption paths,
model mismatch and folding refusals, privacy, changed authority, source
corruption, bounded work/output, cancellation and exclusive publication.

Independent distorted JPEG fixtures produce 49 solved stereo points, 56 solved
multi-camera components (40 complete triples, one unresolved component), and
49 solved stationary trajectories (30 unresolved components). Unresolved cases
retain the existing non-success analysis outcome. At authored depth 10, maximum
nominal depth error is 0.666667 source units; maximum absolute stationary velocity
component is below `1.46e-13`. These fixture measurements do not establish physical
accuracy. The static atlas contains 49 landmarks, two references and 98 bindings
in 13,841 bytes and passes native decode and exact re-encoding. Privacy controls
exclude 640 interpolated output pixels while retaining original exposures.

All four complete actual command reports and the exact atlas manifest validate
against the new schemas, including exact serialized body/manifest digest checks.
The catalog resolves **129 schemas and 1,958 references with zero errors**;
all v1 schemas remain unchanged. See `docs/ADOPTED_LENS_RECONSTRUCTION.md` for
the complete model declarations, compatibility and reconstruction/export workflow.

## Adopted radial camera geometry (native integration)

The sealed calibration owner now has an explicit
`NativeRadialRectification` image profile. The new
`resolve_scene_calibration_for_rectification` entrypoint verifies the same exact
FSSCAL01/02 bytes, original camera inputs, physical sensors, current adoptions
and withdrawal history as the existing pinhole resolver. Its
`rectification_spec` derives the two-term Brown model `[k1, k2, 0]`, zero
tangential terms, original source image domain and semantic calibration pin.
Both source and target matrices/grids are the refined original camera values;
radius and luma interpretation remain explicit owner declarations.

`SceneRig::from_retained_rectified_calibration` projects that matching profile
into fixed virtual pinhole geometry. The original resolver, rig constructor and
semantic identity bytes remain strict original-pinhole contracts. Cross-profile
use refuses even for zero-radial coefficients. Native map compilation, actual
pixel/privacy receipt binding and final source/adoption revalidation remain the
caller's responsibility; this API does not certify raw pixels as corrected.
Local covariance stays conditional and absolute camera error remains unknown.

The genuine reference owner suite executes successfully: **20/20 tests pass**,
including all six new radial controls and fourteen prior original-profile
regressions. These cover exact model derivation against independent scalar
projection, native folding/radius admission, current authority and withdrawal,
original-input/receipt custody, profile separation, cumulative allowances and
cancellation. The genuine CLI library also executes all **4/4 typed-rig
regressions** successfully, covering virtual geometry, mode handles, basis and
full-inventory checks. Both suites use the pinned compiler and real runtime;
no substituted dependency or authority owner is involved. The command-level v2
integration above binds this owner to actual corrected pixels. See
`docs/RETAINED_SCENE_CALIBRATION_API.md` for the native ownership contract.

## Localization atlas from adopted cameras (2026-11-02, command integration)

`fss-scene-fuse retained-calibrated-atlas` connects currently adopted FSSCAL01/02
camera geometry to the existing native reconstruction-atlas producer and
FSATLAS1 localization consumer. Static pair and 3–8-camera queries can export
explicitly selected points and actual reference descriptors without an authored
pose rig. The exact adopted-rig and static selection contracts are reused;
moving-feature queries and invalid twin feature ordinals refuse before decoding.
The original calibrated pinhole image profile remains required.

The new strict report and exact-byte manifest retain complete current calibration
and covariance provenance, original camera inputs, source/privacy records, all
native scene alternatives, static eligibility declarations and member bindings.
Absolute camera/landmark error remains unknown. Original source, current privacy
and adoption/withdrawal custody revalidate after construction; the exclusive
deployment owner stays alive through archive, report and stdout publication.
Final independent cost axes include revalidation and final report serialization.
The archive format, existing consumer and nominal atlas command remain unchanged.

Ten new pure production serializer contracts pass, including exact manifest/body
hashes, archive inventory pins, complete diagnostics, final cost accounting,
output bounds and cancellation; their scoped strict Clippy gate also passes.
Five genuine native reconstruction/archive/localization contracts pass again.
An additional actual JPEG oracle executes native decoding, extraction, stereo
and three-camera reconstruction, FSATLAS1 encoding/decoding and localization
from newly generated pixels: both atlases supply 26 matches and recover the
synthetic fresh camera center `[0.5, 0, 0]` within `7.3e-12` source units, with
RMS below `4.9e-12` pixels. These deterministic fixtures qualify the native
computation, not real-world camera accuracy or retained custody.

Ten real command-owner contracts are added for actual retained JPEG/adoption
exports and fresh-image consumption, changed adoption/privacy, corrupt or missing
custody, exact selection pins, temporal refusal, resource limits, cancellation
and deployment ownership through successful/failing stdout. Genuine
`cargo check --locked --offline -p fss-cli --bin fss-scene-fuse --tests` passes
with the pinned compiler and real runtime, including the new command and all
new owner tests. Runtime execution of these owner contracts remains pending.
The offline schema catalog resolves 125 schemas and 1,771 references with zero
errors; the two new schemas pass Draft 2020-12 validation. Six actual native
pair/multi-camera geometry fixtures validate in the manifest, while all three
temporal fixtures correctly refuse its static-only contract. Existing
constitution findings remain unchanged. See
`docs/ADOPTED_RECONSTRUCTION_ATLAS.md` for the complete preview, selection,
export and localization workflow.

## Reconstruction from adopted calibration (2026-11-01, command integration)

`fss-scene-fuse retained-calibrated-match` connects existing FSSCAL01/02 site
calibration and retained adoption to stereo, multi-camera and moving-feature
reconstruction. It accepts the established five retained query schemas and a
strict adopted-rig document. Intrinsics and poses come exclusively from the
exact current calibration; selected source sensors, original camera inputs,
image domains and decoded grids must agree with that authority. The first
profile requires original pinhole images and explicitly refuses nonzero radial
distortion or rectification declarations.

The complete native correspondence graph, fitted points/trajectories, alternatives,
refusals and nominal visibility remain in the report. Calibration identities,
atlas/control/tie provenance, original image modes, all joint camera generations,
current receipts and full conditional camera covariance are retained. Absolute
camera error remains unknown; calibration covariance is never substituted for
physical accuracy or silently folded into the native pixel-noise covariance.
The new report's strict outcome consistently includes nominal occlusion conflicts
across all three modes; existing nominal report contracts remain unchanged.

All source-dependent analysis precedes final original-source/current-privacy and
adoption/withdrawal revalidation. The exclusive deployment owner remains alive
through report file/stdout release. Calibration input bytes, authority-read
reservations, verified authority bytes, original reads and decoder axes are
separately bounded and reported, including final revalidation. A generic FSSCAL
hash algorithm cannot be relabeled as SHA-256 image provenance. Outputs remain
private, create-only and complete; no calibration, world revision, persistent
track, event or effect is activated.

Twenty-three new exact-production contracts execute successfully: thirteen
adopted-rig/query parser tests and ten native geometry/envelope tests. Eight
shared JSON-reader regressions also pass, and the scoped native geometry harness
passes strict Clippy. The parser harness uses unchanged production readers with
only the unrelated adopted-owner extension omitted; it substitutes no custody
or calibration authority. Nine real retained-command contracts are also added,
covering actual JPEG stereo, multi-camera and repeated-exposure geometry, current
adoption/withdrawal, original mode/pins, privacy/corrupt custody, resource and
publication limits, cancellation and the deployment guard through stdout.
Genuine `cargo check --locked --offline -p fss-cli --bin fss-scene-fuse --tests`
passes with the pinned compiler and real runtime, including every new command,
parser and native test. Genuine `cargo check --locked --offline -p fss-reference
--tests` also passes, including all fourteen resolver owner contracts. A missing
JPEG arm in an existing RTSP keepalive fixture was repaired after that broad gate
reported the non-exhaustive match; runtime behavior and gates are unchanged.
The new schemas pass standard Draft 2020-12 validation; the complete offline
catalog resolves 123 schemas and 1,739 references with zero errors. Nine actual
native geometry fixtures (pair/multi/temporal, each clear/occluded/empty) validate
against the strict new geometry schema and its existing diagnostic references.
These are actual native solver/serializer outputs, not fabricated owner reports.
Runtime execution of the nine new command-owner tests remains pending at this checkpoint.
See `docs/ADOPTED_CALIBRATION_RECONSTRUCTION.md` for exact inputs, report
interpretation, limits and operational failures.

## Retained adopted camera geometry (2026-11-01, native integration)

`fss_reference::ingest::scene_calibration` now resolves the existing FSSCAL01/02
records and retained camera adoptions into a sealed owner for scene reconstruction.
It checks exact twin package/source, original camera-input bytes and image mode,
physical sensor, camera handle/name, both calibration generations and the selected
current adoption. Missing, superseded, withdrawn or corrupt authority refuses;
sensor aliases cannot bypass another camera's adoption. The initial profile
requires the original calibrated pinhole image domain.

The owner preserves complete calibration/covariance provenance and revalidates
current adoption/withdrawal custody after analysis. Unrelated ledger descendants
are allowed; changed lineage, divergent prefixes or selected receipts refuse.
Input, complete authority traversal, source reads and final revalidation have
cumulative byte/work limits and cancellation checkpoints. The CLI library's
`SceneRig::from_retained_calibration` derives native camera poses and intrinsics
from this sealed owner while leaving clock/privacy/validity declarations explicit.
Local covariance never becomes a deterministic projection bound or physical
accuracy claim; absolute camera error remains unknown.

Fourteen real deployment owner contracts are added, covering adoption, native
stereo geometry, original image lineage, supersession/withdrawal, corrupt custody,
aliases, hash-algorithm provenance, exact work/read limits and cancellation.
The genuine reference test configuration and scene-fuse production/test
configuration pass with the pinned compiler and real Asupersync. These new
owner tests remain unexecuted at this checkpoint: initial full-codegen and
default metadata attempts exceeded this environment's memory; serializing the
compiler frontend/backend completed the genuine metadata checks. Subsequent
available headroom remained below the measured heavy compiler requirement,
so no doomed full-codegen retry was started. The existing native check script
includes this owner target; no runtime substitute or weakened gate was used.
The retained command integration is described above.
See `docs/RETAINED_SCENE_CALIBRATION_API.md`.

## Retained moving-feature reconstruction (2026-11-01, command integration)

`fss-scene-fuse retained-motion-match` now connects the native temporal feature
associator to authenticated retained JPEG/AVC/HEVC sources. Four through sixteen
original exposures from two through eight fixed cameras produce common-time
3D positions and constant velocities in the imported property twin. This closes
the automatic-correspondence gap between static retained image matching and
moving-scene fusion with manually supplied correspondences. Native direct and
lens-corrected image paths use the existing sealed source/privacy owners.

The strict query binds each exposure's original custody, camera mapping, image
model and clock alignment. Repeated cameras keep fixed sensor/stream, geometry
and image declarations; aliases cannot multiply original exposure support.
Capture hull, interval uncertainty, actual feature inventory and numerical fit
limits are bounded. Source rows map to the exact original exposure rather than
the first observation of a camera. Full descriptor tables, every nearest tie,
incomplete/conflicting components, native motion refusals, all 36 covariance
terms and nominal per-exposure mesh visibility remain in the report. The one
requested scene time is preserved; unsupported components never extrapolate.

Every image plan is admitted before decoding. Complete source-dependent analysis
serialization precedes final original-source/current-privacy revalidation and
the authority-anchor check. Work includes final revalidation, complete reports
are bounded without truncating alternatives, and file output is private and
create-only. Deadline/cancellation checks cover report construction and file
publication. Exit 3 preserves a complete analysis with no fit or unresolved
nontrivial components. No persistent track, calibration or landmark is activated.

**59 exact-production parser/image/binding tests pass**, including 14 new
temporal contracts and a six-exposure, two-moving-point native reconstruction
with unchanged geometry under source/query permutations. **5 exact-production
renderer tests pass**, covering all component/descriptor states, complete maximum
inventories, high-epoch times, covariance, byte/work limits and cancellation.
Both scoped harnesses pass strict Clippy. Nine emitted production geometry
fixtures validate against the new standard Draft 2020-12 schema; the catalog
resolves 121 schemas and 1,585 references with zero errors.

An independent genuine native JPEG decode/extract/associate/render execution
recovers 26 stationary depth-10 trajectories across four original-grid exposures
and 16 with the repeated left camera cropped and the right camera direct. Maximum
depth error is below 3e-13 and absolute velocity components below 1.3e-13 in these
synthetic fixtures. Their 12/32 unresolved components and all 6,144 Cartesian
descriptor rows remain explicit. This is pure native pipeline execution, not
execution of the retained deployment owner or physical field qualification.

Eight real retained-command owner tests cover original custody, exact
exposure mapping, native image correction, permutations, current privacy,
corrupt/missing sources, admission/work/cancellation/output limits and private
publication. Subsequent [hosted execution of exact commit 03d1b97](https://github.com/Dicklesworthstone/franken_surveillance_system/actions/runs/41319017296/job/124892258104)
compiled the real source-owner runtime and passed **all 177 scene-fuse tests**,
including **all eight temporal owner tests and all ten atlas owner tests**.
The overall workflow failed in other ONVIF/agent-learning/policy checks; this
focused execution does not establish whole-workspace or release qualification.
No runtime substitute or weakened gate was used. See
`docs/RETAINED_TEMPORAL_MATCHING.md` for input/report fields and operational limits.

## Native temporal feature association (2026-11-01, moving-scene bridge)

`fss_twin::temporal_feature_association` now automatically connects native image
features across repeated camera exposures and feeds complete supported groups
to the existing joint 3D position/velocity solver. Four through sixteen original
exposures, two through eight fixed logical cameras and at most 256 actual selected
features produce a complete bounded descriptor graph. Static epipolar screening
is not applied to staggered moving observations. Every Cartesian descriptor row,
nearest alternative, selected link and unresolved component remains available.

Repeated cameras retain their fixed calibration/mode and original exposures.
Direct support from every member pair and one feature per exposure are required;
open chains and conflicting cycles never become transitive identity assertions.
Each successful fit uses every observation, the exact global requested scene time
and the original capture-time midpoints; unsupported reference times refuse instead
of silently clamping or extrapolating. Full capture intervals, source masks,
camera/map/clock assumptions, all 6x6 covariance terms and nominal occlusion
conflicts remain explicit. No persistent track, static landmark or calibration
is activated. See `docs/TEMPORAL_FEATURE_ASSOCIATION.md`.

**22 new native tests execute successfully**: 17 source/graph/admission/resource
contracts and 5 independent reconstruction pipelines. Native grayscale feature
extraction across four staggered exposures reconstructs depth 10 and velocity
[1, 0.5, 0], while the stationary epipolar matcher rejects those moving pairs.
Independent crossing trajectories, descriptor aliases, incompatible acceleration,
exact times near u64::MAX, full covariance propagation, permutations, all bounded
inventories, budget-minus-one and terminal cancellation pass. Strict Clippy for
the library and both new test targets also passes. These are synthetic contract
results, not physical field accuracy, identity confirmation or release authority.

The direct retained-perception check now executes the actual scene-fuse test
binary after retained localization. Two missing imports in an existing RTSP test
module, observed as compiler errors in hosted checks, are repaired without runtime
behavior changes. Existing qualification lanes and release authority are unchanged.

## Retained reconstruction atlas export (2026-11-01, command integration)

`fss-scene-fuse retained-atlas` now reconstructs an existing exact retained pair
or multi-camera v1/v2 query and exports explicitly selected points/descriptors
as the unchanged FSATLAS1 format. The existing `fss-file localize` consumer
accepts the resulting archive and report-provided package/provenance pins.
The selection pins the entire original association and requires distinct
landmark/physical-group IDs, existing twin feature ordinals and enduring-static
support. It cannot override coordinates, descriptors, source facts or error bounds.

Every original source, including unused views, remains in the complete manifest
along with original/rectified image lineage, camera/clock/privacy declarations,
all native pair/component alternatives and the producer admission receipt.
Exact source-record bytes are hashed independently. The manifest includes the
semantic atlas, excludes the final package hash, and is itself pinned by the
archive. The final report embeds the exact manifest UTF-8 string plus archive
and report-body identities, avoiding recanonicalization and circular hashing.
A dedicated bounded report reader handles that long string without changing
ordinary intent or supervisor-report limits.

Complete geometry, manifest and archive serialization precedes final original
source/current-privacy revalidation. Analysis failures create no atlas/report.
Output is private and create-only; archive synchronization precedes report
publication. Cancellation is checked after the archive commit and before stdout.
Publication I/O failures can leave newly created files for explicit inspection.
No calibration or canonical world revision is activated, and unknown absolute
landmark error remains separate from conditional pixel covariance.

**45 exact-source adapter/image tests pass**, including 12 new selection,
dispatch and actual binding contracts. **8 strict JSON reader tests pass**,
including 3 new report-capacity/identity tests. **4 actual production atlas
serializer tests pass**, covering all six eligibility dispositions, complete
alternatives, unused views, source/receipt identities, exact output/work bounds
and initial/terminal cancellation. Eight emitted receipt/geometry fixtures and
their actual selection rows pass standard Draft 2020-12 validation. The catalog
resolves 119 schemas and 1,521 references with zero errors. Strict adapter/reader
Clippy passes. The separate renderer harness's strict lint check reports two
existing unchanged helper warnings; it reports none in the new renderer/tests.

Ten real retained CLI tests are added for stereo and three-camera export,
archive/provenance roundtrip, v2 cropping, source corruption, current privacy,
preflight, resource/cancellation refusal and private/exclusive publication.
At initial publication, these owner tests and the current CLI had not completed
genuine typechecking or execution because shared memory pressure killed the
local reference build and ordinary disk capacity was exhausted. Subsequent
[hosted checks of exact commit 6a85bb0](https://github.com/Dicklesworthstone/franken_surveillance_system/actions/runs/41279511798/job/124770256145)
**compiled the production scene-fuse binary** and executed all **33 retained
localization owner tests**, including the 12 rectified-feature contracts, plus
the existing retained-localization CLI integration test. Those jobs did not run
the scene-fuse test binary, so the ten atlas owner tests remain unexecuted at
this checkpoint. The overall hosted workflow failed on other test/qualification
issues and is not release authority. No runtime substitute or weakened gate was
used. See `docs/RECONSTRUCTED_LOCALIZATION_ATLAS.md` for selection/report fields,
consumer handoff and publication recovery.

## Native reconstructed localization atlas (2026-11-01, producer/consumer bridge)

`fss-twin::reconstruction_atlas` now turns actual native pair or multi-camera
reconstruction into the existing `LocalizationAtlas` and `FSATLAS1` archive
contract. This closes the missing native producer between reconstructed image
features and image-to-map camera registration; the existing localizer consumes
its output unchanged.

The bounded producer requires the exact entire association, complete original
source-record pins and explicit per-point landmark/physical-group/twin-feature/
enduring-static declarations. It copies actual solved positions and native
descriptors, retains every member-view binding and complete participating frames,
and preserves all unused sources and candidate dispositions in its receipt.
Unknown, refused, unresolved, aliased or nominally occluded selections fail
atomically. A capture-window stationarity assertion does not establish enduring
landmark eligibility. Conditional pixel covariance remains diagnostic; absolute
landmark error is always unknown, including when the twin has a declared map
error. No calibration, source-access authority or physical identity is activated.

**21 new native tests execute successfully:** 16 admission/lineage/ordering/
work/cancellation contracts and 5 independent reconstruction/archive/localization
contracts. Both pair and three-camera cases reconstruct twelve independently
authored nonplanar points, round-trip the real archive and recover a fresh
rotated/translated camera within the explicit 1e-7 center/reprojection fixture
tolerance. A separate real masked-grayscale pipeline executes extraction,
stereo/multi-view reconstruction, archival and fresh-image localization; it
recovers the expected depth-10 plane and camera center [0.5, 0, 0] while preserving
planar alternatives. Replay-exposure laundering and descriptor-alias support
controls pass. All 59 existing library tests and strict Clippy for the library
and both new targets also pass. These are synthetic contract results, not field
accuracy or production qualification.

The pure API performs no source reopening or publication. Retained integration
must bind complete original source/rig/image/clock records and revalidate custody
and current privacy after serialization. `docs/RECONSTRUCTED_ATLAS_API.md`
documents this ownership boundary, unknown-error semantics and archive handoff.
The native API is compiled and executed; the earlier resource limitation for
current retained-owner/CLI integration checks remains separate. Broad FSS-097
and geometry qualification remain open.

## Retained scene matching with lens correction (2026-11-01, command integration)

`fss-scene-fuse retained-match` and `retained-multimatch` now accept exact v2
queries that explicitly select direct pinhole input or native lens correction
per retained camera. Brown–Conrady, central fisheye and pinhole crop/resize use
the sealed rectified-feature owner below. Mixed corrected/direct cameras are
supported. The source grid and lens/range declaration come from the query; the
target pinhole intrinsics come only from the pinned rig. The native plan computes
the actual corrected image domain. All selected lens plans are admitted before
any native source decode can publish a JPEG derivative. Existing v1 wire fields,
direct feature identities and successful report shapes remain unchanged.

V2 reports preserve original retained capsule, decoder, native dimensions and
pixel identities and add separate corrected-image lineage. Each view exposes
its actual output grid, full model, sampling-map digest, propagated mask and
complete mapping/privacy accounting. Original exposure remains unchanged.
Current privacy is applied to positive-weight source interpolation taps and the
full corrected descriptor footprint; complete original custody/current privacy
is revalidated before releasing the analysis. Compilation, resampling and report
work share the existing cumulative geometry allowance. All maps are released
after extraction. Output-pixel noise and omitted interpolation/lens/camera error
remain explicit assumptions rather than calibrated accuracy claims.

**33 exact-source native adapter/report tests execute successfully:** 18 existing
pair/multi-camera cases, 12 new v2 declaration/model/receipt-binding cases and
3 production image-report cases. Strict scoped Clippy passes. Actual direct,
pinhole-corrected, Brown and fisheye image-processing outputs each pass standard
Draft 2020-12 validation against both v2 report schemas. The complete schema
catalog resolves 116 schemas and 1,439 references with zero errors.

Separate original-JPEG native geometry controls execute decoding, rectification,
extraction, matching and geometry reporting: two corrected sources recover
24 stereo points at depth 10; mixed corrected/direct sources recover 16; a
three-camera scene with only its third camera corrected recovers 13 complete
triples and 14 pairs, with no unresolved components. These zero-distortion crop
controls have maximum depth error below 2e-14. The independently rendered
nonzero-lens controls and their looser integer-feature tolerance are described
in the native section below; these fixture results do not establish field accuracy.

Five new real pair-command tests and two multi-camera command tests cover source
composition, corrected/native identity separation, current privacy, later-view
lens preflight, source-grid mismatch, cancellation and work/output limits.
**The current new reference/CLI integration has not completed genuine metadata
checking or runtime execution:** the updated reference metadata build was killed
by shared memory pressure before owner tests, so a dependent CLI build was not
repeated. Earlier dated typecheck results below cover their earlier revisions,
not these new owner or command changes. No substitute runtime or weakened gate
was used. `docs/RETAINED_LENS_MATCHING.md` documents exact v2 declarations,
resource limits and remaining calibration/motion boundaries. Aggregate FSS-097
and FSS-099 qualification remains open.

## Retained raw-lens feature extraction (2026-11-01, native composition)

The sealed retained feature owner now exposes
`extract_recorded_rectified_features` alongside the unchanged direct-pinhole
entry point. A caller compiles an exact native `RectificationPlan`, then the
owner authenticates retained JPEG/AVC/HEVC, applies the current source privacy
mask, corrects lens/crop/resize geometry and extracts actual target-grid features.
The small native `extract_raw_features` composition is independently executable.
Both entry points return the same sealed source owner and require final original
custody/current-privacy revalidation before downstream release.

Source luma/dimensions/native decoder receipts retain their original meaning.
Corrected pixel/domain/dimensions/mask identities and complete native mapping
receipts are separate. Original exposure is preserved. Brown–Conrady, central
fisheye, explicit pinhole crop/resize and declared full/video luma transfer reuse
the existing native rectifier. Every positive-weight source interpolation tap
must be allowed before the full descriptor-footprint check. Folded or unsupported
models refuse. No lens estimation, measured calibration or effect activation is
implied. Direct feature v1 digest/work behavior and existing localization receipt
encoding remain unchanged; corrected features have a separate versioned identity.

**61 native tests execute successfully:** 8 new rectified-feature contracts plus
13 rectification, 6 rectified-localization, 17 pair-association and 17 multi-camera
association regressions. Independently rendered Brown, fisheye and mixed-lens
images each recover at least 12 stereo and 8 three-view points on a known z=10
plane within the explicit integer-feature/resampling fixture tolerance. Exact
crop/resize feature equality, source-mask noninterference, full footprint privacy,
exposure/domain binding and early/late resource cancellation also pass. Strict
scoped native Clippy passes.

Twelve new real retained-source owner tests cover JPEG/AVC/HEVC lineage, cropping,
replay, later JPEG publications, raw/native custody corruption, privacy withdrawal,
invalid modes, work/source limits, cancellation and frozen direct-v1 compatibility.
The new genuine pinned Cargo check was SIGKILLed while compiling reference-library
metadata under shared memory pressure, before reaching these test bodies. Thus
current owner metadata/typechecking and runtime execution remain unverified;
the executed native tests above do not substitute for those integration checks.
Cleanup of an obsolete task-owned build cache recovered disk space, but measured
reclaimable-adjusted memory headroom remained below the retry threshold.
`docs/RETAINED_FEATURE_EXTRACTION.md` documents the public
API, complete source/derived distinction and independent resource axes. This
advances the imaging-model contract; broader calibration and association gates
remain open.

## Joint reconstruction across retained cameras (2026-10-31, static-feature integration)

`fss-scene-fuse retained-multimatch` now connects **3–8 authenticated retained
JPEG/AVC/HEVC views** to a complete native correspondence graph and joint static
point reconstruction. Each original source uses the sealed feature owner and
strict source/rig/image/clock/privacy contract introduced by `retained-match`.
The shared parser preserves the pair interface. Actual selected features are
bounded to 128 per view and 256 total before complete pair expansion; excess
inventory refuses without hidden truncation.

Every camera pair retains all descriptor and epipolar decisions, feature outcomes,
point estimates and refusals. Connected selected links become explicit components.
A joint solve requires one feature per camera, complete direct support between
every pair of members and all participating views with zero outlier removal.
Repeated-camera conflicts and incomplete cycles preserve the entire component
without greedy reassignment. A third view can resolve weak pair geometry while
the original pair refusal remains visible. Unmatched singleton features remain
diagnostics. Components can use only two views; the report names their actual
support rather than crediting every selected camera.

Full scene and subset capture hulls remain intact. Original requested scene time
and the time clamped into each subset hull are explicit and evidence-bound under
the declared static-scene assumption. No clock synchronization or motion is
inferred. The complete source-dependent analysis is serialized before all owners
revalidate original custody and current privacy. Entry/final anchors distinguish
ordinary JPEG publications. The report includes every source capsule/native
receipt, current masks, all alternatives and final resource counters. No camera
calibration, physical identity, world revision, event or effect is activated.

Native association passes **17 new and 17 existing pair contracts**. Coverage
includes independent 3/4/8-camera coordinates, actual extracted image crops,
conflicting/incomplete cycles, joint inconsistency despite pair solutions,
third-view recovery, exact maximum inventory, empty-view validation, staggered
times near u64 limits, budget/cancellation and evidence sensitivity. The shared
retained binding passes **18 executed tests**: 11 unchanged pair and 7 new
multi-camera cases. The new renderer passes **11 executed tests**, preserving
all 28,672 pair decisions and 1,792 pair-specific feature outcomes at the
maximum inventory. Strict scoped native/parser/renderer Clippy passes; scratch
harness exclusions apply only to previously existing unrelated helper warnings.

An original synthetic three-camera JPEG oracle executed native decoding,
feature extraction, association and reporting: **26 three-camera points and
6 two-camera points**, all at independently specified depth 10, with 6 unmatched
features. Its third source explicitly models a different camera center and
principal point over the authored plane; it makes no physical-independence claim.
Ten actual production geometry reports, including conflict/refusal/empty/time
and maximum-inventory cases, pass standard Draft 2020-12 JSON Schema validation.
The complete catalog resolves **112 schemas and 1,142 references** without errors.

The production scene/file commands and complete CLI test configuration pass
genuine pinned, locked/offline Cargo check, including **eight new real retained
owner tests** for source pins/custody, privacy, permutation, complete timing,
budgets/cancellation and private exclusive output. These owner tests are
typechecked, **not runtime-executed**: the earlier genuine Asupersync object
build exceeded the shared memory ceiling, and no substitute runtime or repeated
object attempt was used. See `docs/RETAINED_MULTICAMERA_MATCHING.md` for exact
inputs, component outcomes, 32 MiB complete output and cumulative resource bounds.
Field association quality, moving-object identity and aggregate FSS-099
qualification remain open.

## Automatic matching of retained native camera frames (2026-10-31, integration)

`fss-scene-fuse retained-match` now connects authenticated retained JPEG, AVC
and HEVC frames to automatic masked native feature extraction and existing
cross-camera static-point reconstruction. It closes the gap between local-JPEG
matching and retained fusion that still required supplied pixel correspondences.
No exported frame or detector package is required. The existing `fss-file decode`
output now exposes exact capsule/source/sensor/stream selection pins for this path.

The strict query pins original import/capsule/encoded bytes/sensor/stream and
native coding-segment selection. All pins are checked before decoding. Complete
video ranges are bounded to 64 segments; a later malformed or skipped selected
picture cannot produce a partial successful result. The sealed native feature
owner reuses the existing decoders and derives dimensions, exposure, source
capture interval and current privacy from retained custody. Full descriptor
footprints must be allowed; the query cannot substitute pixels, timestamps,
dimensions or masks. Camera/source mapping, an undistorted pinhole image domain,
additive interval clock alignment and stationary common features remain explicit
assumptions. Distinct retained sensor IDs do not independently certify a physical
camera placement.

The complete report preserves every candidate pair and selected feature, source
capsule and native decoder receipt, successful 3D estimate and geometric refusal.
Source owners revalidate original ranges and current privacy after analysis;
JPEG also reopens its exact retained pixels/receipt without regenerating damaged
custody. Ordinary JPEG derivative publication can advance the ledger, so entry
and final anchors remain separate and the second valid decode does not stale
the first source. No event, identity, camera calibration or world revision is
activated. Shared original-read accounting includes final validation and original
HTTP/RTSP provenance. JPEG work, video byte/luma admission and geometry work are
separate bounded axes, with final costs in the report.

The exact-source pure parser/binding suite passes **11 tests**, including full
interval/offset propagation, source/camera/privacy/clock mismatch refusals and
native geometry recovering an independent expected depth of 5. The existing
matching parser/pipeline/report harness passes its **16 production tests** plus
one fixture emitter; all five original emitted report hashes remain unchanged
after sharing the complete pair/feature/hypothesis serializer. Seven genuine
reference-owner tests and nine real CLI-owner tests cover source removal,
JPEG/AVC/HEVC custody, privacy withdrawal, later decode publications, corruption,
budgets/cancellation and private exclusive output. The seven reference tests,
production scene/file commands and all current CLI test configurations pass
genuine pinned Cargo check. Runtime owner tests have not executed: the prior
Asupersync object build hit the shared 8 GiB ceiling, and no substitute runtime
or repeated object-build attempt was used. The 110-schema catalog resolves all
1,006 references without errors.

See `docs/RETAINED_SCENE_MATCHING.md` for source discovery, exact input examples,
limits, original/declared timing and report interpretation. This implements a
bounded static-feature portion of FSS-099; field association quality, moving
object identity and aggregate qualification remain open.

## Native raw DFL detector-head conversion (2026-10-31, detector compatibility)

`fss-infer import-onnx` recipe version 3 now converts an explicitly declared
static anchor-free DFL distance head into decoded pixel-corner boxes. This
closes a detector-package gap that previously required predecoded coordinates.
The new output uses the existing package detector's source projection, privacy,
score/objectness interpretation, candidate bounds and NMS. The original raw
output, unrelated source outputs, source weights and complete ONNX bytes remain
retained; no foreign inference runtime, new operator or FMPK wire format appears.

The profile requires batch one, explicit rows/channels layout, 2–32 bins per
left/top/right/bottom side, and 1–8 ordered unique feature strides. Exact grid
rows derive from the declared divisible image dimensions, with fixed half-cell
centers. Native Softmax and ascending-bin MatMul compute expected distances;
F32 multiplication by stride precedes pixel-center subtraction/addition. Scores
are copied unchanged and sigmoid is not silently applied twice. The converted
output has a new explicit name, rows layout and pixel-corner semantics. Invalid
shapes, names, grid counts, vocabulary or unsupported conventions refuse.

The original import quotas continue to cover all added work, nodes, tensors,
parameters and retained compile-time controls, including preceding normalization.
Rows are bounded to 32,768 and the explicit head allowance. The decoder adds
13 native nodes, or 14 for channel-layout input, and three parameter arrays
containing exactly `4 * (3 * rows + bins)` bytes. Cancellation cannot yield a
partially converted graph. V1/v2 recipes retain their original semantics.

The complete model regression passed **253 tests**. The focused DFL target
passed **14 tests**, including 12 independent new numerical/artifact/resource
contracts and two included scalar-executor smoke tests. Final-source focused
tests and strict scoped Clippy passed after the name-length preflight adjustment.
Independent F64 oracles cover uniform, asymmetric and extreme logits, both
layouts, rectangular multilevel grids, unsorted stride order, maximum score
fields, exact raw/source/score preservation and actual graph/Safetensors reload.
The original 1,900-byte RGB-dependent raw-head fixture also has real package
projection/privacy/NMS tests; the seven-test reference target passes genuine
Cargo typechecking. Production inference and the complete CLI test configurations
also pass genuine Cargo check against the pinned runtime. The 108-schema
catalog resolves all 893 references without errors.

The matching, retained-fusion and ONNX package command tests remain separately
tracked from native numeric execution. A single serialized runtime object build
was killed by SIGKILL while compiling genuine Asupersync at the shared 8 GiB
memory ceiling; no command tests executed in that attempt. The full production
and CLI test configurations do typecheck against the real pinned runtime.
See `docs/ONNX_PACKAGE_IMPORT.md` for the exact recipe and arithmetic boundary.

## Automatic native JPEG correspondences and 3D scene points (2026-10-31, integration)

`fss-scene-fuse match` now connects two exact local JPEG sources to native masked
FAST/BRIEF extraction, automatic symmetric descriptor association, nominal
bidirectional epipolar gates and existing twin-based static-point fusion. It
removes the need to supply individual pixel correspondences for this profile.
The complete inventory includes every Cartesian pair and selected feature,
all equal nearest alternatives, native 3D estimates and geometric refusals.
Appearance ambiguity is evaluated before geometry, and a missing runner-up or
tied best descriptor cannot become a unique match by discarding competitors.

The strict query binds original JPEG bytes, exact rig, image-domain mapping,
explicit full-pixel or pinned exclusion-mask policy, shared clock/privacy and
complete capture intervals. Full 33×33 descriptor footprints must be allowed.
Decoded grids must match the authored nominal undistorted rig. Stationary common
features, camera placement, capture-clock alignment and physical mapping remain
explicit assumptions; local byte verification does not claim retained custody
or physical identity. Unknown calibration error and mesh occlusion conflicts
remain visible beside conditional pixel-noise covariance.

Both baseline and progressive JPEG use the existing native decoder. One bounded
work allowance and borrowed cancellation/deadline probe cover decoding, feature
extraction, geometry and complete-report construction. The match-specific default
is 2 billion units and maximum 5 billion: paired fully allowed 1080p feature detection
alone needs over 1.27 billion. Previous supplied-point fusion limits stay unchanged.
At most 128 features/view produce 16,384 pair rows; the complete report stays within
8 MiB or refuses without trimming rows. Existing outputs are refused, new reports
are private, and stdout/file bytes agree. No scene activation or effect occurs.

The native kernel passes **17 actual Cargo tests** and strict scoped Clippy.
The exact production parser/JPEG-pipeline/report source passes **16 tests**, and
**three** decoder-probe contracts pass. Original separately encoded JPEG crops
recover the independent expected depth 10 without manual correspondences. Five
actual emitted query/report profiles cover complete/empty/geometry-refused/
epipolar-unobservable/maximum-inventory outcomes; the maximum 128/view example
retains 16,384 pairs and 112 points in a 3,783,946-byte complete report. Every profile
passes a labeled local structural comparison to the schemas; no independent
JSON Schema standards validator was available. The 107-schema catalog resolves
all 880 references without errors.

The genuine production scene and inference commands and all current CLI test
configurations pass Cargo check against the pinned Asupersync runtime; the
previous retained-fusion custody tests now typecheck too. Actual command-owner
execution remains unverified: the runtime object build was killed at the shared
8 GiB memory ceiling before executing tests.
This is a bounded static-feature slice of FSS-099, not field association-quality
qualification or closure of the broader cross-camera association bead.
See `docs/SCENE_FEATURE_MATCHING.md` for exact semantics and an example query.

## Explicit detector channel order and normalization (2026-10-31, native provisioning)

ONNX RGB package recipes now have an explicit version2 for models requiring BGR
input or channel-specific mean/standard-deviation normalization. Native image
masking, resizing and optional unit scaling still run first. The converter then
freezes the declared channel reorder and separate F32 `(x - mean) / std` operations
into the immutable graph through existing Slice/Concat/Sub/Div operators. Means
and divisors are in model-input channel order. No external inference runtime or
new operator encoding is introduced; original source bytes, parameters and output
names remain available for provenance. Version1 stays strict and unchanged.

Finite-value and full RGB-range checks reject invalid or overflowing transforms.
Generated nodes, tensors and parameters share the original import ceilings,
including consumed compile-time controls. Every source branch consuming the image
is rewired; a directly exported image input refuses rather than aliasing names.
The privacy mask is applied before normalization, including nonzero normalized
masked values. Decoder head interpretation and class labels remain explicit.

The complete native model suite passed **239 tests**. Its new focused target
passed **12 tests**, covering independent RGB/BGR and raw/unit pixel oracles,
nonzero detector-head values, resize, canonical graph/Safetensors reload, source
provenance, exact F32 division order, name collisions, quota exhaustion and
cancellation. Strict scoped Clippy passed. The real package integration test target also
passed Cargo check against the pinned runtime. Command and package execution
remain unverified after a serialized Asupersync object build was killed at the
shared 8 GiB memory ceiling; the additional integration tests are present.
See `docs/ONNX_PACKAGE_IMPORT.md` for recipe versions and conversion examples.

## Retained native detections in the property scene (2026-10-31, integration)

`fss-scene-fuse retained-fuse` connects actual retained package detections and
native tracks to the existing property twin, camera rig and multi-view solvers.
It reconstructs static points, points with supplied velocity, or position and
constant velocity inferred from staggered observations. The strict selection
names exact native track/segment/detector-row/capsule identities; feature
rectangles must remain inside their actual source detector bounds.

The source owner authenticates complete retained custody and current privacy.
Source-derived sensor identity, image dimensions, model comparison generation
and full conservative capture intervals cannot be replaced by query fields.
Explicit source-to-rig, undistorted-image, additive-clock and common-feature
declarations remain assumptions. One physical source cannot masquerade as
multiple scene cameras. Query-local aliases preserve original full identities
without truncating content digests into synthetic persistent identities.

The complete bounded report retains every original selected observation, full
authority anchor, exact declarations, native geometric results and individual
refusals. The sealed source owner revalidates all retained source bytes and
privacy after geometry and report construction, before any report is released.
A borrowed cancellation/deadline probe now reaches every geometry work charge
without a detached timer. No event, calibration certificate or effect is activated.

An exact-source native harness passed **14 tests**: eleven adapter/geometry
contracts and three cancellation/Send+Sync contracts. It reconstructs a known
point from three cameras and position/velocity from six staggered observations,
and covers pins, image bounds, full timing uncertainty, source-camera consistency,
visibility refusals, deterministic aliases and assumption-sensitive evidence.
The complete current-source Cargo geometry/fusion suites passed **201 tests**;
all **23** parser/rig/adapter tests also passed in the exact-source harness.
The seven real-custody CLI tests now typecheck against genuine pinned
Asupersync metadata, together with the full current CLI test configuration.
Earlier metadata builds were killed under shared host pressure; a later
serialized metadata build succeeded. A later object build was killed at the
shared 8 GiB memory ceiling, so command execution remains unverified. The pure
harness does not substitute for deployment recovery,
custody or output tests.
The 104-schema catalog resolves all 801 references without errors; the broader
constitution scan retains 43 existing findings and none for this feature.
See `docs/RETAINED_SCENE_FUSION.md` for the command, schema and validation boundary.

## ONNX average pooling through native execution (2026-10-31, native model import)

The opset-13 importer now admits static F32 `AveragePool-11` and
`GlobalAveragePool-1` through the existing native graph executor. Two-dimensional
AveragePool supports positive kernels/strides, explicit bounded padding and both
padding divisor rules. GlobalAveragePool preserves output rank for ranks three
through eight. Unsupported automatic padding, ceiling mode, dilation and dynamic
shapes refuse explicitly.

The lowering uses depthwise Conv2d with exact one weights followed by Div with
exact integer counts, preserving native row-major F32 accumulation before the
mean. It avoids reciprocal-weight rounding changes and introduces no new operator
IDs, graph encoding, runtime dependency or execution backend. Generated tensors,
parameters and nodes are admitted against cumulative limits before allocation;
cancellation reaches generated-value construction and ordinary graph admission.

The complete `fss-model-ir` suite passed **227 tests**, including **12** new
pooling execution/artifact tests. The numeric checks use an independent coordinate
oracle across 84 pooling profiles, rank-three-through-eight global pooling and
subnormal/overflow/reduction-order cases. An immutable 830-byte synthetic Conv →
AveragePool → GlobalAveragePool → Flatten → Gemm → Sigmoid fixture reproduces
its output after canonical graph/Safetensors export and reload. Existing operator
ID, graph-byte and other importer regressions passed. This qualifies bounded
import and native execution, not trained detector quality or universal ONNX support.
See `docs/onnx_import.md` for the exact admitted schema and numeric contract.

## Unfused ONNX inference BatchNormalization (2026-10-31, native model import)

The opset-13 importer now accepts the one-output inference form of
BatchNormalization-9 with static F32 data and immutable channel parameters.
This closes a concrete import gap for convolutional backbones and detector
exports that retain their normalization nodes. The lowering uses the existing
native Sub, Div, Mul and Add operators in declared F32 order; only the constant
`sqrt(variance + epsilon)` denominator is evaluated at import. Immutable channel
views avoid extra runtime reshapes or spatial weight replication. No foreign
runtime, new operator ID or canonical graph byte format is introduced.

Ranks one through eight, shared initializer/Constant parameters, source-output
preservation and channel-specific broadcasting are admitted under the existing
cumulative tensor, parameter, node and work quotas. Training, dynamic statistics,
unsupported attributes, nonfinite values and invalid denominators refuse.
Cancellation reaches every channel calculation and ordinary graph admission.

The complete `fss-model-ir` suite passed **215 tests**, including the new native
execution/artifact target's **10 tests** and its 66 numeric profiles. The retained
857-byte synthetic Conv → BatchNormalization → detector-head fixture matches
independent formulas before and after actual canonical graph/Safetensors reload.
Strict targeted Clippy and changed-file formatting passed. Existing operator-ID
and legacy graph-byte regressions also passed. This qualifies the import/execution
seam, not trained detector accuracy or the full asynchronous package/CLI matrix.
See `docs/onnx_import.md` for the exact admitted schema and numeric contract.

## Live native RTSP/JPEG reception and image output (2026-10-31, reference)

The JPEG lane now composes the existing RTSP session, Digest authentication,
exact TCP framing and native socket owner with the new RTP/JPEG receiver and
actual native luma/RGB decoder. Negotiation preserves the selected media ordinal,
URI subtree, CSeq, Session, channels and expected SSRC. Static payload 26 may omit
rtpmap; dynamic payloads require an exact JPEG/90000 offer. Conflicting mappings,
unsupported selected parameters and ambiguous selection refuse.

`LiveJpegConnection` owns one explicitly authorized, caller-resolved TCP route.
Every operation probes live authority and independent transport/protocol/media
bounds. Original accepted TCP chunks transfer before interpreted events; original
RTP/RTCP frames remain available through failures, reordering and cancellation.
Those frames fit the existing `DatagramArchive::prepare_frame` publication path
without a JPEG-specific archive format. Complete reconstructed images pass through
the actual digest-checking, cancellable native pixel decoder. A decode refusal
returns the intact reconstruction and source maps without partial pixels.

The focused exact-production-source target passed **67 native tests**: ten new
JPEG protocol/pixel contracts, five new real TCP contracts, six existing ONVIF
metadata-selection cases and 46 existing authentication, AVC/HEVC session, SDP
and native TCP cases. Real loopback checks exercise one-byte/17-byte/4096-byte
delivery, partial writes, original-wire ordering, Digest challenge and unsent-request
ownership on queue refusal, complete pixels, actual socket EOF and exactly one
terminal retirement. Final scoped Clippy passed with only the independently
identified unchanged `message.rs` counter-loop lint isolated; all new code remained
subject to fatal warnings, with no source/configuration allowance added.

`fss-capture-rtsp jpeg` now supplies one bounded native connection, original
RTP/RTCP publication before further media progress, complete native luma
validation, and exact cold replay. Frame provenance binds actual source packets
and earlier cached quantizers. Capture time stays unknown; saved-prefix
exhaustion never invents EOF.

Production and test targets typecheck against genuine runtime/storage. The earlier
67 protocol tests ran before these additions; the new custody, replay and
CLI/runtime tests have not executed because shared host capacity blocked native
code generation. No dependency or qualification gate was replaced. Physical-camera
and full release qualification remain open.
See `docs/rtsp_jpeg_capture_cli.md` and `docs/jpeg_datagram_reconstruction.md`.

## Handoffs from authenticated retained package tracks (2026-10-31, integration)

`fss-scene-fuse retained-handoffs` now joins existing retained detector custody,
native tracking and the conditional anonymous continuity planner. An exact
selection names at most 32 tracks across four report/label/tracker recipes.
The source owner reconstructs actual native assignments and verifies retained
records, reports, manifests, capsules, original source bytes and current privacy.
Camera generations and model comparison keys come from those source facts;
the input cannot inject replacement sensors, detections or capture endpoints.

Every assigned observation remains present with its original signed 128-bit
capture interval, clock basis, score bits, source-grid bounds, inference/head
identities and confirmation state. First/last actual observations supply track
endpoints in native display order. Declared clock offsets use conservative
checked interval addition and cannot upgrade an estimated clock. Calibration,
common-clock identity, transit and costs remain explicit assumptions.

The command binds the complete current authority anchor and every retained
source binding around the unchanged complete planner report. Duplicate native
aliases, reused assigned observations, incompatible generations, missing or
damaged custody and privacy withdrawal refuse rather than omitting evidence.
The sealed owner reopens the selected analyses before release and compares
the full projection, anchor, root and principal. One shared 4 GiB original-byte
allowance spans all recipes, clones and revalidations, including original
HTTP/RTSP provenance reads. Cancellation, arithmetic and complete-output bounds
remain explicit. Existing deployment startup retains its normal recovery behavior;
the handoff operation creates no identity, event or effect authority.

The exact production contract, parser, planner adapter and renderer passed
**13 native tests**; all **12 existing handoff-adapter tests** passed again.
The emitted 15,858-byte typed-fixture report passed the scoped instance checker,
and 16 invalid mutations refused. Four schemas resolve 168 references with no
findings under the repository's offline validator. Scoped Clippy passed with
only the four independently established pre-existing graph lint categories
isolated; no source or configuration allowance was added.

Six real retained-owner integration cases and five command/context cases were
added and independently source-reviewed, but **have not executed**: the full
asynchronous reference build still exceeds this shared host's memory allowance.
The native transform fixture does not establish authenticated I/O execution,
trained-detector quality, physical identity accuracy or release qualification.
See `docs/RETAINED_HANDOFFS.md` for the executable command, exact source contract,
assumptions and these verification boundaries.

## Native RTP/JPEG reconstruction and pixels (2026-10-31, reference)

The first-party packet owner now reconstructs complete RFC 2435 baseline JPEG
images from ordered RTP, including 4:2:2/4:2:0 sampling, restart intervals,
computed quality tables, immutable cached Q=128..254 tables and fresh Q=255
tables. It composes with the existing sequence/reorder owner and preserves the
original datagram, exact copied image spans, interpreted header dependencies
and generated JPEG ranges. Reused tables keep their original packet provenance.

Bounds cover derived image bytes, fragments, cache entries, dimensions and an
unrenewable pending-image lifetime. Gaps, malformed offsets, parameter drift,
expiration, cancellation and end of input retire incomplete images without
publishing a prefix. Transport completion is separate from entropy validity:
the actual native JPEG decoder must validate the reconstructed image before
releasing luma or RGB. No foreign production dependency or new runtime is added.

The focused native verification passed **45 tests**: 20 packet contracts,
eight new actual RTP/JPEG pixel cases and 17 existing baseline JPEG cases. The
final 28 new cases passed again after completing output ownership. Six retained
synthetic images cover both sampling layouts, extreme quantizers, restart
markers and edge blocks; native luma agrees with independent retained FFmpeg
6.1.1 reference output within the existing one-sample tolerance, and native
luma/RGB agree with native decode of the original JPEG. Scoped Clippy passed
with only the independently identified existing `result_large_err` category
isolated; no allowance was added to repository configuration or source.

This checkpoint qualifies the bounded packet reconstruction and native pixel
path, not a physical camera, live transport, capture synchronization, durable
custody or the release matrix. See `docs/RTP_JPEG_REFERENCE.md`.

## Static ONNX detector shape programs (2026-10-31, reference)

The native importer now evaluates source-authored static shape programs instead of
requiring an external graph simplifier for these bounded detector heads. `Shape-13`
reads validated dimensions; constant INT64 `Gather`, `Squeeze`, `Unsqueeze`, `Concat`,
`Identity`, `Add`, `Sub`, `Mul` and `Div` build exact scalar/vector controls for existing
reshape and split lowering. Negative indices, scalar-versus-vector broadcasting and
truncation toward zero retain their ONNX semantics. Overflow, division by zero, dynamic
integer data and unsupported schema attributes refuse. The profile admits at most eight
control elements and charges every generated value to the cumulative import allowances.

No runtime integer operator, new frozen IR encoding or foreign production dependency is
introduced. Metadata-only parameter uses can disappear from runtime weights; simultaneous
data uses and all runtime input bindings remain. A retained 1,416-byte synthetic Conv/head
fixture computes its reshape and channel partitions from the original shape subgraph,
lowers to seven existing data operators and two F32 weights, and executes through the
actual scalar executor before and after canonical graph/Safetensors artifact reload.

The focused native target passed **19 tests** (17 new cases and two executor smoke tests),
including independent output oracles, exact 328-byte aggregate admission, values above
2^53, signed division, negative/repeated indices, malformed/unused controls, source-name
collisions, all truncated prefixes and cancellation checkpoints. Strict scoped library,
shape-target and previous detector-target Clippy passed without allowances. The full model
package regression was not rerun for this checkpoint; no full CLI, trained-detector or
release qualification is claimed. See `docs/onnx_import.md` and `docs/ONNX_PACKAGE_IMPORT.md`.

## Retained in-band recording replay (2026-10-31, integration)

File ingestion and codec sniffing now select the added native `avc3`/`hev1` profile.
An explicit versioned omission marker retains the complete original sample entry,
while every sample and all remaining source bytes keep their exact custody tiling.
Current H.264/H.265 ranges bootstrap from that retained entry and the selected IDR/IRAP,
then carry bounded parameter state through later samples. Cold replay can therefore
recover a later configuration generation without reopening the original input path or
silently substituting first-GOP parameters.

New in-band reconstructions bind distinct `mp4-inband-bootstrap:v3` decoder identities
in the existing frame-receipt slot. Native publication/cold reads, pixel-change output,
direct file/video decoding and video approval plans carry the actual reconstruction
generation. Conforming historical static-source receipt bytes remain unchanged.
Fixed watch/corroboration/long-dwell/cascade/health/tolerant recipes select historical
range aliases and explicitly refuse the added import marker. Malformed multi-picture
or incomplete-picture samples now refuse in both generations; no compatibility promise
preserves incorrect source attribution. Any range failure clears staged outputs and
makes the range terminal, including cancellation and source-read failure.

The shared sample-boundary implementation is the exact production code exercised by
the native media tests, whose full **413-case** regression passed. Scoped container and
codec Clippy passed without allowances; the final model detector target also passed
16 cases and strict scoped Clippy. The new retained-custody/publication and complete
CLI tests are authored and source-reviewed but **have not executed**: building the full
asynchronous reference dependency exceeded this shared host's memory limit. Native
boundary verification does not establish end-to-end retained-runtime qualification.
See `docs/RETAINED_DECODE_WORKFLOW.md` and `docs/MP4_INBAND_CONFIGURATION.md`.

## Native in-band MP4 configuration and atomic sample boundaries (2026-10-31, reference)

The opt-in `AvcMp4::parse_inband*` entrypoints now admit bounded `avc3` and actual
in-band `hev1` configuration, including empty/partial sample entries, same-ID SPS/PPS
replacement and later entry-only PPS activation. Indexed and fragmented recordings share
the checked sample/configuration join. Exact referenced parameter bytes, original spans,
sample ticks and configuration generations survive extraction. Every selected random-access
range and following GOP must obtain each definition from the original entry or within that
range; an earlier GOP cannot silently supply a missing dependency. The historical parser
entrypoints and conforming static-source extraction bytes retain their existing behavior.

`InbandSampleEntry` provides cold bootstrap from the original entry and selected sample.
Its bounded owned streaming configuration handles subsequent tuple changes, accumulates
input/NAL/table/sample allowances and becomes terminal after failure or cancellation.
The shared native access-unit driver stages output until exactly one complete picture is
validated, with a precise leading-RASL exception for HEVC. Non-flushing pending-picture
queries catch a complete picture followed by an incomplete second picture. Early refusal
of a second picture also bounds temporary surfaces. Display-order reordering remains intact.

All **413 native media tests passed**: 88 container, 165 H.264 and 160 H.265, including 27
in-band configuration tests, nine tests of the exact production sample-boundary driver
and six codec boundary tests. Sixteen synthetic recordings match strict independent
FFmpeg 6.1.1 pixel oracles across resolution changes, multiple parameter IDs, B ordering,
multiple/dependent slices, fragmented/indexed layouts and 1/2/4-byte NAL lengths.
Removing the required entry-only PPS makes both dedicated oracle recordings fail.
The Rust tests invoke only native implementations. Main10 metadata admission does not
upgrade the native HEVC pixel profile. See `docs/MP4_INBAND_CONFIGURATION.md`.

## Executable anonymous handoff query (2026-10-31, reference)

`fss-scene-fuse handoffs` now exposes the native continuity planner through a strict,
bounded owner-local JSON query. It retains every declared tracklet and ordered-pair
disposition, ranked globally consistent path covers, the complete admitted implicit
family, the all-singleton explanation and both full native certificates. Source, clock,
calibration and model handles remain explicit caller assertions; this standalone path
does not fabricate source authentication or a deployment ledger anchor.

The command accepts an exact input-document SHA-256 pin, shared solver-work allowance,
deadline and complete-report byte limit. Cancellation and native budget errors preserve
their typed stable codes. A requested report is exclusively created as a private file
after complete computation; its newline-terminated bytes match stdout. Existing paths,
symlinks, unknown/duplicate fields, coercive integer spellings and truncated answers
refuse. The existing simultaneous scene-reconstruction interface remains available.

The complete graph package passed **238 tests** (208 prior, 18 continuity and 12 actual
production parser/adapter/renderer tests). The final 12 adapter cases and scoped graph
lint passed again after typed-error integration. A real native invocation produced the
9,270-byte three-camera report with two cost-22 alternatives, five admitted links, twelve
pair dispositions and the cost-40 all-singleton cover. Both schemas pass the offline
reference validator (102 references, zero new findings); the exact report passes the
scoped instance checker and all twelve invalid report mutations refuse. The four CLI
file/context tests are authored but not executed: full CLI/reference compilation remains
blocked by the asynchronous dependency's shared-host memory demand. See
`docs/SCENE_HANDOFFS.md`; this is not release or authenticated-association qualification.

## Global anonymous tracklet handoff paths (2026-10-31, reference)

The native `continuity` planner composes up to 32 camera-local tracklets into globally
consistent anonymous paths using the existing certified Hungarian/Murty assignment
implementation. It prices declared links and path births/ends, retains every original
tracklet, and returns all ordered-pair dispositions with complete source/generation pins.
Missing, invalidated and redacted support disables incident links while retaining the
member as a singleton. A shared property/session/privacy/clock scope and compatible
model generations are mandatory; same-camera links also preserve camera/calibration
generations. These inputs remain owner declarations, not authenticated source custody.

Full capture intervals must prove strictly forward order and satisfy the transit window
for every locally valid endpoint choice. Widening uncertainty cannot add an admitted
link. Failure of this conservative gate means a link is not established by this profile;
it does not prove physical impossibility. The complete admitted DAG and in/out-degree
constraints preserve the exact implicit family, including an explicit all-singleton
explanation. Displayed alternatives are an exact ordered prefix with conservative
exhaustion reporting. No path or cost becomes a physical identity or probability.

Eighteen native continuity contracts and all 208 prior graph tests passed. The new tests
include 256 exhaustive small edge-subset cases/permutations, 96 interval-widening cases,
every cancellation checkpoint, exact shared operation/output budgets, numeric extremes,
and the maximum 32-tracklet/992-declaration input. The actual paired query adapter also
passed 12 native tests. Scoped kernel/test Clippy passed with only four independently
confirmed pre-existing graph lint categories; the full strict baseline remains unchanged.
The additive assignment cancellation wrappers preserve successful legacy outputs and
counters. See `architecture/continuity_reference.json`; source authentication, simultaneous
multiview fusion, identity accuracy and full association qualification remain open.

## ONNX detector branches and padded spatial pooling (2026-10-31, reference)

The source-preserving ONNX importer now admits static opset-13 `Split` with up to
eight outputs, including equal and explicit positive partitions and negative axes.
Each branch lowers to the frozen native `Slice` operator and preserves source output
order and exact F32 bits. Embedded partition controls remain import-only; all emitted
nodes, tensors and copied controls consume the existing cumulative admission budgets.
Other operators retain their one-output restriction. The importer also admits explicit
nonzero `MaxPool` padding under the existing floor-mode, dilation-one native geometry
contract. Every admitted window overlaps real input, so padding cannot inject zeros
into negative-valued feature maps.

This supplies detector channel branches and spatial-pyramid pooling without adding
runtime operators, changing the frozen IR or acquiring a foreign production runtime.
A retained synthetic Conv/Split/three-pool/Concat/head fixture executes through the
actual native scalar executor both before export and after canonical graph/Safetensors
reload. Independent array oracles cover partitions, signed-zero/extreme bits, asymmetric
padding, strides and negative-only pooling. Malformed controls, source collisions,
unsupported profiles, cancellation and exact aggregate limits refuse without a graph.
The complete model-IR package passed **186 native tests**, including the 16-test detector
block target and the unchanged canonical baseline fixture. This verifies the admitted
blocks, not a newly qualified trained detector or full asynchronous package CLI.
See `docs/onnx_import.md` for the precise profile and fixture identity.

## Retained-source stream capacity and failover command (2026-10-30, reference)

`fss-event graph capacity` now exposes the native capacity planner against one retained
site/window snapshot. Operators declare camera rates, directed named links, recorder
acceptance limits, rate/cost units and failed nodes/links. Every selected sensor must be
known in the retained projection; positive whole-window coverage is reported separately
and never creates or suppresses a declared demand. An optional expected coverage digest
rejects stale source selection before solving. The complete strict JSON report carries
every camera shortfall, link/recorder flow, typed cut, source witness, composition witness
and both full certified solver proofs. Reordering declarations preserves the report;
changing a topology or failure assumption changes its bound identity.

The command is bounded and read-only. Source support is selected in one cancellable pass;
source read/projection bounds remain independent of the shared native solver allowance.
Unknown declarations, stale source, cancellation, overflow or oversized complete output
refuse without a partial report. Schema/reference validation passed with zero new findings;
the catalog retains its 39 unrelated existing findings. Six CLI adapter tests and one cold
retained-custody process test cover replay, source-path deletion, changed windows, failover,
zero-support sensors, stale pins and unchanged storage, but are **authored and unexecuted**
under the existing asynchronous dependency build limit. Independent API/source review and
scoped formatting passed; the underlying graph package's 208 native tests passed separately.
This command plans aggregate splittable capacity and does not measure throughput or activate
streams. See `docs/STREAM_CAPACITY_PLANNING.md` and `schemas/stream_capacity.v1.json`.

## Native HEVC Main tile decoding and retained generations (2026-10-30, reference)

The native H.265 decoder now admits bounded uniform and explicit tile layouts for Main
and Main Still Picture 8-bit 4:2:0. Raster/tile-scan conversion, escaped substream entry
offsets, CABAC/QP resets, spatial predictor isolation and independent deblock/SAO tile
boundaries are implemented. Logical slices and every dependent segment must separately
satisfy tile-containment rules. Minimum tile geometry counts padded final CTBs, admitting
partial picture edges correctly. Tiles with WPP and unsupported profiles still refuse;
incomplete pictures never publish partial surfaces and recover only through the existing
IRAP boundary.

Current recorded/media/container owners reach the tile-capable decoder. An explicit v1
constructor/range alias preserves historical tile refusals for fixed watch, tolerant,
whole-recording/incremental dwell, cascade and health recipes. Untiled input histories keep
their exact receipt bytes; accepting a tiled PPS selects the new generation for subsequent
frames. Publication, pixel-change and reports bind actual frame identities; current video
plans bind the expanded admission generation.

The complete native HEVC package passed **157 tests**, including 29 new tile contracts.
Nineteen positive authored streams match independent strict FFmpeg I420 digests, covering
nonzero residuals/QP, nonzero P motion, two-dimensional/unequal tiles, partial CTBs,
dependent slices, emulation prevention and visibly active deblock/SAO boundaries. A separate
nonconforming segment fixture verifies normative refusal even though FFmpeg tolerates it.
Strict all-target Clippy passed without allowances. Independent core/specification and
retained-caller review passed after correcting two conformance defects. Cold-publication,
legacy-byte and operator-plan regressions are authored and reviewed but unexecuted under
the existing reference/CLI dependency memory limit. See `docs/hevc_tiles.md` for the exact
profile, bounds, generation behavior and oracle provenance; no Main10 or production
qualification is claimed.

## Native ONNX detector feature-map upsampling (2026-10-30, reference)

The generic importer now lowers static Resize-13 nearest-neighbor upsampling of rank-four
NCHW feature maps into the existing frozen Reshape/Concat operators. Spatial integer scales
1..64 may be supplied as exact F32 scales or INT64 output sizes; batch/channel dimensions
remain fixed. Both asymmetric/floor and the default half-pixel/round-prefer-floor profiles
produce the mathematically identical repeated samples under this restriction. Exporter
Constant nodes, empty optional ROI/scales and shared control/data values are handled without
creating empty runtime tensors or dropping execution parameters. Unsupported interpolation,
coordinate profiles, fractional/downsampling scales and dynamic controls explicitly refuse.

All **170 native model-IR tests** passed. The new nine-test target includes 100 combinations
checked against an independent coordinate-formula oracle after actual canonical graph and
Safetensors reload through production scalar execution. A convolution/upsampling/dense-head
case, exact F32 bit preservation, naming collisions, quota boundaries and cancellation are
also covered. Strict library/Resize-target Clippy passed without allowances. Source bytes,
frozen operator IDs and prior canonical graph encodings are preserved; the distinct importer
identity commits the new lowering. No claim of arbitrary Resize or trained-detector quality
is made. See `docs/onnx_import.md` for the precise profile.

## Native camera-stream capacity and failover planning (2026-10-30, reference)

`fss_graph_algorithms::stream_capacity` now composes the existing certified maximum-flow
and minimum-cost-flow owners into an exact operational planning query: maximize aggregate
camera delivery, then minimize declared routing cost. Inputs explicitly name directed links,
parallel-link identities, positive camera demands, recorder acceptance limits, rate/cost units
and failed nodes/links. Every camera demand remains present even when its attachment fails.
Complete camera, link and recorder rows retain delivery/shortfall, inactive declarations,
the typed limiting cut and both full solver proofs. Final conservation and cut saturation are
checked against the cost-optimal flow under one work/output allowance and cancellation probe.

All **208 native graph tests** passed, including 18 new capacity contracts. Independent integral
flow enumeration checks 256 tiny networks and failure variants on 64 seeded networks; further
cases verify parallel routes, recorder bottlenecks, zero-cost cycles, permutation identities,
numeric extremes, every cancellation checkpoint and exact shared budget boundaries. Existing
successful solver outputs, counters and identities are preserved by additive cancellation
wrappers; signed intermediate cost arithmetic is checked. Focused Clippy passed with only four
unchanged baseline lint categories allowed. Strict all-target Clippy still reports those same
existing findings. The bounded composition contract is `architecture/stream_capacity_reference.json`.
This is conditional aggregate splittable routing, without measured throughput, per-camera
fairness, individual-session multipath support, stream activation or production qualification.

## Static ONNX constants and detector-head shape operations (2026-10-30, reference)

The general opset-13 importer now admits finite F32 Constant nodes and exact embedded
INT64 controls for Reshape, Squeeze, Unsqueeze and positive-stride Slice. Controls support
negative axes, inferred/copied reshape dimensions, clamped Slice endpoints and empty vectors
where the operator permits them. Compile-time integers and empty vectors never become
runtime tensors; control-only values are excluded from exported parameters. Runtime data
uses remain bound, and the complete original ONNX source remains available for provenance.
Source ordering, namespace collisions, aggregate byte/work quotas and cancellation are
enforced across initializers, constants and generated native nodes. Existing frozen operator
IDs and canonical graph encodings are unchanged.

The full native model-IR package passed **161 tests**. A frozen convolution-to-dense-head
fixture executes through the unchanged production scalar executor and exports its native
graph/weights; additional tests cover raw/typed constants, scalar/empty controls, negative
axes, extreme slice indices/steps, malformed fields, source order, truncation and limits.
Strict library and structural/export-target Clippy passed without allowances. This extends
the existing package import profile; runtime integer/dynamic shapes, reverse-stride Slice,
other ONNX opsets and trained-model qualification remain outside the admitted contract.
The full asynchronous reference/CLI build remains subject to its existing memory limit.
See `docs/onnx_import.md` for the precise conversion and execution scope.

## Native progressive JPEG and generation-aware retained replay (2026-10-31, reference)

The existing native JPEG luma/RGB entrypoints now decode self-contained 8-bit Huffman SOF2
grayscale and YCbCr 4:4:4/4:2:2/4:2:0, including spectral scans, DC/AC refinement, EOB runs,
restart intervals and odd dimensions. Coefficients are bounded to 32 MiB, scans to 256, and
all work is cancellable and charged before complete-image publication. Progressive decoding
reaches retained file decode, direct package/RGB inference and direct HTTP RGB capture.

Baseline entropy/parser/transform sources, pixels, actual work, keys and decoder identities
remain unchanged. Progressive outcomes have distinct source-bound generations; retained
success/refusal keys use their actual receipt identity. Historical unsupported-SOF2 refusals
can reopen/replay explicitly while a new progressive success coexists. Existing temporal,
detector/sentinel/cascade, calibration and HTTP/reconnect recipes retain explicit baseline
entrypoints, preserving old refusal-as-gap behavior without silently changing their generations.
The lab command reports actual completed generations and explicit uncompleted work.

The full native codec package passed **99 tests**, including 12 progressive contracts; strict
all-target Clippy passed. All eight independently encoded progressive fixtures reproduce their
baseline partners' native luma and RGB exactly, with separately retained FFmpeg luma within
one sample value. Existing malformed-media gauntlets still pass. Native twin MJPEG and HTTP
pipeline contracts also passed **11 tests**. Reference cold-replay and lab-report regressions
are authored but unexecuted under the existing asynchronous dependency build limit. No
arithmetic/12-bit/hierarchical JPEG support or production qualification is claimed. Generation
preimages and the exact supported scope are in `crates/fss-codec-mjpeg/BASELINE_GENERATION.md`.

## ONNX-to-detector-package provisioning command (2026-10-31, reference)

`fss-infer import-onnx` now connects the admitted general ONNX profile to the existing FMPK
RGB detector package format used by `package-detect` and its sampling workflows. Independently
pinned local source, recipe, license and notice inputs produce a deterministic archive retaining
the complete original ONNX. Explicit NCHW input, preprocessing, decoded-head layout, class labels,
generations and license decisions are required. Shape/field mismatches, unapproved licenses,
oversized metadata, wrong pins and exhausted bounds refuse. The existing package/license/CPU
loader verifies the archive before an exclusive new output file is opened; nothing is activated.

The conversion path is supported by the **139 passing native model-IR tests** described below,
including actual production Safetensors parsing and scalar execution of a rank-four RGB input
through a batched dense head. Six package/CLI tests additionally cover archive round trips,
retained-JPEG inference, refusals, output pins and overwrite protection, but remain **unexecuted**:
the locked Asupersync dependency exceeds this environment's build memory limit. Independent
source review and scoped formatting passed; schemas have no new validator findings. The native
artifact tests do not establish full CLI/runtime qualification or trained-model quality. Existing
opset-11 YOLOX conversion is unchanged. See `docs/ONNX_PACKAGE_IMPORT.md` for the exact command,
recipe, supported profile, source-retention contract and remaining limits.

## Camera placement under shared dependency failures (2026-10-31, reference)

`fss-cover placement --failure-action ID=COST=SENSOR[,SENSOR...]` now evaluates camera
additions against declared common power, network, host or other dependency losses alongside
individual sensor losses. Each selected action is charged once and overlapping memberships
are unioned. Proposed cameras participate only when installed. The exact optimum returns
typed failure actions, affected sensors and an unseen-path witness under explicit cost units,
one cumulative work budget and cooperative cancellation. Unknown members and partial optima
refuse. Existing individual-loss mode and canonical bytes remain unchanged.

The full native graph package passed **190 tests**, including 11 new shared-failure contracts
and 160 seeded tiny cases checked against independent simple-path/set-cover enumeration.
Focused Clippy passed with four unchanged baseline lint categories allowed; strict all-target
Clippy still reports those existing findings. Six CLI unit cases and a retained-custody process
extension are authored but unexecuted because of the existing asynchronous dependency build
limit. Required schema/domain registrations remove all new-feature scanner findings; 39
unrelated existing findings remain. This is exact conditional advice about declared failures,
not measured reliability, installation authority or production qualification. See
`docs/robust_camera_placement.md` and `architecture/shared_failure_placement_reference.json`.

## Source-preserving native ONNX artifact export (2026-10-30, reference)

The general ONNX importer now exports its validated graph and exact finite F32 parameters
to the existing canonical Model IR and Safetensors formats, retaining the complete original
ONNX bytes and their independent source pin. Generated Gemm parameters remain bound; tensor
names are escaped losslessly; graph/header/weights/aggregate byte limits are checked before
output allocation. Cumulative work includes the original import, and cancellation never
returns partial artifacts. Existing graph/operator identities and canonical bytes are unchanged.

The pinned native `fss-model-ir` suite passed all **139 tests**, including 12 new export cases
and two included production executor tests. New cases read exported weights through the actual
production Safetensors parser and execute the decoded graph through the actual production scalar
executor, including an RGB-shaped dense-head graph. Exact quotas, cancellation, generated weights,
escaped names and signed-zero/subnormal bits are covered; the frozen legacy Add bytes still match.
Scoped Clippy passed with only the pre-existing parser `chunks_exact_to_as_chunks` allowance.
This validates conversion artifacts, not the full asynchronous reference runtime, package CLI,
model quality, activation or release qualification. See `docs/onnx_import.md`.

## Native HEVC dependent slice segments (2026-10-30, reference)

The Main-profile 8-bit 4:2:0 decoder now reconstructs dependent slice segments.
Picture-local header inheritance, CABAC probability and QP continuation, wavefront
snapshot precedence and shared logical slice tags preserve prediction, reference maps
and filtering across segment cuts. Every segment consumes the existing bound. Active
parameter and picture-identity fences reject mixed contexts; identical parameter
retransmissions remain valid. Early malformed NALs now clear unfinished state so the
next good IRAP can recover immediately. Skipped RASL headers retain only bounded
inheritance and never become decoded pixels. Receipt formats and labels are unchanged.

All 128 native H.265 tests pass on pinned `nightly-2026-08-31`, including all 48 old
pixel-conformance cases, 20 dependent-segment cases, six skipped-RASL contracts and
the existing hostile/malformed-media gauntlets. Ten authentic encoded fixtures yield
11 independently frozen FFmpeg frames; coalesced controls, QP changes, deblocking,
wavefront cuts and a real IDR-to-P-skip sequence all match. Weighted P/B header fields
are checked separately; a dependent B-picture pixel oracle is not claimed. Fixture
regeneration is byte-exact. This advances WP-060's native media path; Main 10, tiles,
physical-device interoperability and full release qualification remain open. See
[HEVC dependent segments](docs/hevc_dependent_segments.md).

## Native ONNX Gemm import and execution (2026-10-30, reference)

The offline digest-pinned ONNX importer now lowers Gemm-13 into the frozen native
Transpose, MatMul, Mul and Add operators. It admits rank-two matrices, any nonzero
signed transpose flags, finite F32 alpha/beta and an optional bias that broadcasts
into the fixed result shape. Matrix multiplication precedes alpha scaling to retain
F32 evaluation order. All source names are reserved before expansion, and generated
nodes, intermediates and scalar parameters consume the existing import allowances.
No operator, dependency, source initializer or Model IR v1 encoding changes.

All 125 native Model IR tests pass on pinned `nightly-2026-08-31`. Fourteen added
feature cases execute the actual unchanged production scalar executor, including
dense-head replay, 25 transpose combinations, seven bias forms, exact rounding,
collision/forward-reference refusals, expansion budgets and cancellation. A literal
legacy Add graph remains byte-exact. Scoped formatting and the narrow new-target
lint check pass; strict all-target Clippy retains its existing parser/test findings.
This advances FSS-138 / WP-080's offline library importer, not an ONNX CLI workflow,
model activation or full runtime qualification. See [ONNX import](docs/onnx_import.md).

## Native H.264 type-1 picture ordering (2026-10-30, reference)

The pure-Rust AVC decoder now admits picture-order-count type 1 within its existing
progressive 8-bit 4:2:0 profile. Bounded reference-offset cycles, signed slice deltas,
non-reference pictures, frame-number wrap and IDR/MMCO 5 reset feed the existing
reference-picture and display-order machinery. Inconsistent multi-slice identity,
overflow and invalid headers refuse without a partial successful picture. Retained
file and native RTSP consumers use this same decoder; existing type-0/type-2 pixels,
receipt encodings and decoder labels remain unchanged.

All 162 native codec tests pass on pinned `nightly-2026-08-31`, including three new
real encoded streams with 19 independently frozen FFmpeg frame hashes, eleven
focused ordering/bounds tests, and two actual RTP-to-decoder integrations covering
fragmentation, packet reordering, sequence wrap and exact source byte spans. The
previous pixel corpus and 2,000-mutant malformed-media gauntlet also pass. This closes
the specific FSS-124 decoder admission gap, not its aggregate physical-device or
release qualification. See [native H.264 picture ordering](docs/h264_picture_order.md).

## Durable ONVIF Create responses and cold recovery (2026-10-30, reference)

Native PullPoint capture now commits every admitted complete final Create response
before HTTP/SOAP, correlation, endpoint or later clock refusal can discard it. The
additive `create-outcome` record keeps the exact body, transport observations and
original intent closure, including malformed, refused and empty replies. A raw response
alone grants no poll, cleanup or retry authority. Transport loss before a complete
response still leaves an unresolved intent and an unknown camera result.

`fss-onvif-metadata control recover-created` explicitly reconstructs the unchanged
successful Created v1 marker from exact usable raw custody after restart. It verifies
the original source/root/intent, current access and deletion state, strict correlation
and approved endpoint scope before local publication. It sends no network requests and
cannot reset the existing operation fence. Exact retries preserve identities; known
receipts survive post-commit refusal and output failure. Catalog, holds and deletion
include raw outcomes without rewriting legacy control or batch encodings. See
[ONVIF metadata recovery](docs/onvif-metadata.md#recover-an-interrupted-created-marker).

Eighteen new named regressions cover raw-custody refusal/corruption matrices, crash and
cancellation cuts, exact legacy Created reconstruction, real TCP ordering, cold native
recovery, operation-fence preservation and strict CLI approval parsing. Independent
source review and scoped formatting pass. Native execution remains pending because the
shared environment killed pinned compilation of the unchanged Asupersync dependency.
Physical-device/Profile M interoperability, the FSS-046 aggregate and release
qualification remain open.

## Exact robust camera-placement analysis (2026-10-30, reference)

The registered `ALG-INTERDICT-001` now includes a bounded exact camera-addition mode.
It chooses among explicitly declared candidates to maximize the minimum sensor-loss
cost needed to open an unobserved entry-to-target route, subject to separate named
installation units, cost and count limits. Baseline and defended paths, removal sets,
canonical ties and work/output witnesses remain visible. Every nested search shares
one cancellable allowance; an exhausted request refuses without an approximate optimum.
Existing interdiction formats and identities remain unchanged.

`fss-cover placement` exposes the same solver over committed deployment coverage.
Baseline support requires one positive retained witness spanning the whole requested
window; proposed camera coverage, directed movement and both cost scales remain explicit
hypothetical declarations. Complete JSON reports include the original anchor and source
witness, unsupported zones, selected additions and baseline/defended removal paths.
Stale source pins, exhausted work, cancellation and insufficient output bounds refuse
without a partial optimum. Six focused command cases and a native cold-custody/schema
contract are added. Their execution remains pending: the pinned native CLI build was
killed by the shared environment's memory limit in the unchanged Asupersync dependency.
All 94 JSON schemas and 453 references validate; this is not full qualification.

All 11 focused native tests passed on pinned `nightly-2026-08-31`, including 180 seeded
comparisons with independent exhaustive placement using the existing interdiction
oracle, cancellation, budgets, output limits and numeric/input failures. The result is
advice under explicit coverage and movement assumptions; physical sight lines, current
health, shared-failure independence and effect authority are not established. The
aggregate bead and qualification remain open. See [robust camera placement](docs/robust_camera_placement.md).

## Health-screened trained-package zones (reference)

An explicit `fss-event package-zones analyze --require-health-screening yes` now combines exact
retained class-selected geometry with native historical-health diagnostics. The additive v2 path
loads one bounded catalog and assesses each distinct source frame once. Raw assigned boxes,
geometric relations and confirmation remain visible, while missing, incomplete or suspect
screening interrupts positive zone/crossing/dwell support. A clear finite screen is not a healthy
camera or coverage certificate, and unavailable screening cannot imply departure or absence.

The retained report closes over matching diagnostic records and traces alongside its original
source. Cold reads and retention revalidate relevant current health/privacy/deletion custody;
later findings or missing proof refuse the selected report without rewriting old evidence.
Current-operation catalog/read/trace work is separately bounded and reported. Existing unscreened
v1 behavior and canonical bytes remain unchanged. Six new native integration cases, a temporal
gate case and the actual CLI fixture cover unknown, partial, clear and frozen screening, late
diagnosis, source/privacy changes, corruption, budgets and legacy compatibility. The pinned native
run at `67266b1` passed all 12 package-zone integrations, all six observation units and all four
source-shape regressions ([run 41093354674](https://github.com/Dicklesworthstone/franken_surveillance_system/actions/runs/41093354674)).
The real CLI exposed a shared nested-schema reference resolver defect; that resolver now retains
the document root and all 28 validator regressions pass. Full CLI re-execution remains pending.
See [package zones](docs/PACKAGE_ZONES.md).

## Native AVC/HEVC incremental dwell (reference)

Supported flat H.264 and H.265 imports can now use bounded hot continuation and retained cold
recovery through the existing native decoder, foreground, tracker, dwell and optional health
owners. Scheduling boundaries preserve buffers and original cumulative allowances. New v3
checkpoints bind exact source/codec/policy identities, coding consumption, processed display
frames, explicit HEVC RASL omissions and native drain state. A decoder that consumed every input
but still holds a display frame remains incomplete; cold recovery reproduces the exact saved
prefix and drain before continuation. Checkpoint validity covers the complete consumed capture
interval hull, including reordered B pictures.

The CLI exposes these distinctions in `fss.incremental_dwell_progress.v2`; MJPEG checkpoint and
progress bytes remain unchanged. Final detector, health, fusion and event publication keep their
existing native admission. Partitioned sources and tolerant inter-coded continuation remain
explicit refusals. This is sampled unclassified dwell, not continuous physical presence or an
absence certificate. Seven focused native regressions and actual CLI/process schema fixtures
cover hot/cold equivalence, reordering, CRA/RASL, budgets, cancellation and publication. The
pinned native run at `67266b1` passed all seven new video cases and all 75 long-dwell tests
([run 41093354674](https://github.com/Dicklesworthstone/franken_surveillance_system/actions/runs/41093354674)).
The actual unscreened 300-frame AVC CLI also passed cold continuation, schema validation and
publication/retry. Its screened 300-frame oracle correctly refused the existing complete
finding-run bound; the CLI fixture now requires that refusal and exercises screened success on
a bounded 32-frame prefix. Screened AVC and HEVC CLI re-execution remains pending. Source,
format and schema checks pass; no release qualification is claimed. See
[incremental dwell](docs/incremental_dwell.md).

## Authenticated native probe evidence in investigation cases (reference)

A retained `investigate --transition probe` can now explicitly cite its native result to an
existing case, exact predecessor revision and selected hypothesis, with support or counterevidence
chosen by the caller. Linking also requires the exact pre-work subscription-state digest. The
native owner compares that digest while holding its journal writer before reserving source work
or performing an action. A blind retry after native publication or case linkage therefore cannot
silently spend another attempt or attach a different result.

Native publication, case citation and output charging are separate durable stages. The citation
authenticates the immediately preceding native Publish/Release record, full subscription progress,
original pending/report/payload identities, native session and authority, and the case CAS. Replay
verifies physical adjacency before restoring state or repairing an incomplete tail. The case
continues to distinguish explicit evidence use from a hypothesis assessment or authorized effect;
the original native delivery root and the later citation root remain separate.

Native ledger and effect heads preserve the canonical SHA-256 zero root for empty histories,
so an investigation can cite a retained probe before the first effect has occurred. Evidence,
publication, request and authority-state identities still require nonzero digests; exact custody
and cold replay comparisons are unchanged.

`probe-citation` provides an explicit historical lookup after restart or lost output. A currently
authorized case reader can recover the original receipt after the source session closes, without
reopening its recipe, revalidating source or charging a native attempt. The projection identifies
historical custody and does not substitute a same-name subscription owned by the current reader.
An absent link never proves that native work did not occur or authorizes an automatic retry.

If a complete context cannot be delivered after a stage commits, a bounded registered response
preserves the known native, case and charge receipts, exact historical lookup coordinates and
remaining uncertainty. Its cognitive payload and compression receipt are explicitly absent.
The requested view is unchanged, and no truncated cognitive result or implicit ACK is returned.

Fourteen native citation-owner regressions, all nine real-deployment admission contracts and
all four probe-output units passed in the pinned `67266b1` native run. They cover cold recovery,
forged custody, case/source scope, exact CAS, partial append cuts and retry fencing. The real
Case-view overflow workflow also passed. Two complete linked Forensic replies then exposed
redundant summary bytes beyond the registered ceiling: successful linked responses now carry
all detail once in their required context pack, leaving the optional proposition summary empty.
Compaction does not drop or alter required pack items or widen the registered output ceilings;
refusal and historical-lookup summaries are preserved. Native re-execution of that compaction
and the remaining CLI/MCP recovery contracts is pending.
See [retained investigation probes](docs/investigation_retained_probes.md).

## Agent investigation of retained native probes (reference)

`fss investigate` and MCP `investigate` now expose explicit probe, inspect, exact-receipt ACK,
discard and adjacent-window advance transitions over an already registered retained-source
supervision subscription. The agent surface shares the companion supervisor's stored recipe
decoder, actual native evaluator, source validation, durable reservations and pending-delivery
owner. It checks the live session, investigation grant and explicitly supplied authority root
before work and rechecks the native delivery against current protected session context.

The additive cognitive-envelope V2 carries its actual typed context pack and compression receipt.
The required pack preserves every admitted native decision, window, observation, calibration
qualification, common-cause cluster, counterfactual, exclusion and health warning. A concise
summary refers to exact matching pack items; detailed evidence is carried once. Packaging
completeness applies to the admitted projection, while source omissions and uncertainty remain
explicit. No implicit ACK, case assessment, provider registration or external effect is performed.

Complete serialized responses are priced before release and durably debited from the existing
session allowance. The default 5000-token Case ceiling remains unchanged; complete reports can
explicitly select the existing 16000-token Forensic view. There is no silent view promotion.
Oversized output refuses without hiding a retained pending receipt or refunding spent native
work. A separate
probe contract profile admits the new payload without changing legacy basis bytes, public-row
encodings, session recovery or the closed V1 schema.

The pinned compiler executed all 178 core unit tests successfully, including the V2 proof-pair
and legacy/probe profile regressions. The 182 focused registry/robot-document Python tests pass.
Real CLI/MCP retained-supervision integration fixtures cover current admission, native inventory
preservation, full-wire accounting, restart, replay, exact ACK, scheduled advance, deletion and
complete-output refusal; execution of those dependency-bearing native fixtures is pending.
See [retained investigation probes](docs/investigation_retained_probes.md).

## Retained detector-class zones and sampled dwell (reference)

`fss-event package-zones analyze` now derives complete image-zone observations from an exact
retained trained-package analysis and one selected vocabulary label. The native owner uses each
track's actual assigned detector box and its confirmation state at that sample. Predictions,
earlier tentative samples, clipped silhouettes, privacy-masked areas and missing observations
cannot count as inside occupancy. Observed boundary crossings remain distinct from a continuous
presence claim, and explicit capture-time assumptions are required for sampled dwell.

The complete report preserves every source frame and track/zone/frame cell, observed transitions,
interruptions and qualifying dwell run. Processing admits at most 16 zones, 64 source frames,
8192 total cells and 16384 events, with complete canonical and JSON byte ceilings. Source custody
is verified through the existing package owner; no inference is rerun and no foreground proxy
substitutes for the selected detector class.

An exact principal/report/root approval retains configuration, analysis and complete derivation
through existing root-last publication and cognition custody. `package-zones read` reconstructs
the selected report after restart, including current source, privacy and deletion checks; exact
retry preserves its original retention anchor and damaged custody is never repaired implicitly.
Reports do not grant calibrated classification, physical identity, continuous occupancy, absence
or effects, and explicitly state that this operation has not independently screened source health.

Six native integration contracts, native temporal/geometry tests, an actual-tracker lifecycle
comparison and a cross-process CLI/schema workflow cover these boundaries. Positive fixtures run
a synthetic numeric FMPK model through real JPEG/Conv2d/Reshape execution; the bundled trained
YOLOX model independently exercises clipped-box refusal. Scoped formatting, Python syntax and
schema checks pass; native Rust execution is pending. See [package zones](docs/PACKAGE_ZONES.md).

## Cold continuation after a retained RTSP retryable failure (reference)

The native campaign owner now derives a sealed continuation summary from the exact retained
finish chain: spent attempt ordinals, remaining original attempts, durable pictures, successful
attempts and the first failure. An explicitly approved retry-history continuation can use that
summary without erasing a shortfall or recreating an earlier capture epoch. The original attempt
schedule, generation, output paths and limits remain pinned; cold history verification is
separately bounded, and the original backoff is repeated before the next attempt. Ordinary
reconnect still stops at its first later success; an all-attempt campaign still fails when an
earlier required attempt failed. Both preserve the historical failure and aggregate totals.

Continuation checks the live publication namespace for any later start, finish, broken root or
unfinished publication before adoption and again before starting another attempt. An older
historical prefix remains inspectable but cannot authorize replay of an already used ordinal.
Unfinished attempts, unknown outcomes, unresolved recovery/control work, exhausted schedules and
terminal campaigns refuse. Existing campaign, attempt and success-only continuation encodings
remain unchanged; retry-history adoption uses its own approval domain.

Native history contracts, controller contracts and two actual loopback subprocess restart fixtures
cover exact failure accounting, stale-prefix refusal, immutable prior stores and no extra capture
after an ordinary reconnect succeeds. Pinned formatting and diff checks pass; native execution of this new
slice is pending. See [RTSP capture campaigns](docs/rtsp_capture_campaign.md).

## Original footage after reviewing trained-detector events (2026-10-30, reference)

Original-footage export now also accepts current operator-reviewed package events through the
additive FSSEXM01 version-four profile. The existing review owner authenticates every retained
successor; only its sealed lineage admits the exact original package analysis and source proof.
The current operator decision and complete review pins remain distinct from the original native
candidate's indeterminate, unclassified and uncalibrated interpretation. No inference is rerun.

The existing whole-source permission, exact source/root membership, destination-bound approval,
current privacy/deletion checks and final release revalidation apply. Further review invalidates
an older approval. Missing original or intermediate evidence refuses without output or repair.
V1/V2/V3 bytes remain unchanged; the separate V4 policy/domain/profile prevents reinterpretation.
Reference and real CLI regressions cover cold multi-review export, proof corruption, forged
native probability, cancellation, exact retry and independent offline verification. All 23
native export contracts and 14 CLI contracts passed in the
[supplementary reference run](https://github.com/Dicklesworthstone/franken_surveillance_system/actions/runs/40980790547),
including every new reviewed-package case. The CLI workflow also passed independently in the
[native capture run](https://github.com/Dicklesworthstone/franken_surveillance_system/actions/runs/40980790535).
See [reviewed original-footage export](docs/ORIGINAL_MEDIA_EXPORT.md).

## Closed-episode citations through captured learning (2026-10-30, reference)

The semantic execution-episode digest returned by `plan --close` now works as evidence in the
existing plan-targeted learning capture. Both capture and cold recovery recompute the identity
from the exact authenticated target episode. A genuinely retained sibling episode remains an
invalid citation, including when the two plans share one terminal operation. The extra identity
is included only when explicitly cited, preserving existing captures' evidence vectors and bytes.

This repairs the real plan/verify/close/feedback/learn integration failure without changing
promotion, policy or effect authority. Regression coverage preserves exact retry, cold inspection
and the retained-feedback boundary on refusal. The retained-calibration negative fixture also
reverifies its exact staged children so it reaches the intended historical withdrawal gate.
The native rehearsal reached durable feedback and learning publication, then correctly refused
to omit protected context from its 1,600-token Brief view. The rehearsal now explicitly requests
the registered EpistemicMap view and verifies all six recovered proof pins with zero critical
omissions. The strict instance validator now supports the registered numeric exclusive bounds
used by experience decay; its 23 tests pass, including malformed-bound refusal. Full native
rehearsal and legacy learning recovery are awaiting execution of these integration repairs.
See [captured episode experience](docs/AGENT_EXPERIENCE_REFERENCE.md).

## Durable follow with bounded waiting (2026-10-29, reference)

Owned follow subscriptions can now combine their exact durable cursor and explicit ACK with
`--wait-ms` in CLI and MCP. Pending pages and every real adjacent history transition return
immediately, including harmless transitions. Only a fresh source-verified quiet comparison at
the acknowledged current head may park; it creates no hidden pending page or implicit ACK.
The session writer is released before waiting, then live authority and the pinned semantic
scope are reacquired. Protected transitions still pass through adjacent replay.

History admissions, writer opportunities, comparisons and source-custody work accumulate across
the invocation. Timeout, cancellation, closed/changed session, source loss, invalid clock and
ambiguous history order return explicit failure with any already committed registration/ACK.
No response substitutes an old comparison for current truth or refunds prior work. Existing
immediate receipt formats remain unchanged; the read-only wait API refuses owned subscriptions
instead of dropping their durable scope.

Nine native contracts plus CLI/MCP subprocess and rendering cases cover pending replay,
ACK/cancellation/cold retry, released locks, adjacent wakes and bounded failure. All nine native
contracts, six CLI library cases and two MCP cases passed in the
[combined native run](https://github.com/Dicklesworthstone/franken_surveillance_system/actions/runs/40978826772).
Eight of nine subprocess integrations passed. The remaining fixture advanced with an unpublished
source, changing the current doctor verdict and correctly invalidating exact pending-page replay.
Its successful advance now uses canonical root-last publication and checks healthy custody;
a separate regression preserves resnapshot and an unconsumed pending receipt when unpublished
data changes the current diagnostic. Native execution of these fixture repairs remains pending.
The repository-owned native
entrypoint now includes the new follow, ONVIF reconciliation, original-footage and checkpoint
health workflows while preserving all existing checks and their failure status.
See [durable acknowledged waits](docs/AGENT_FOLLOW_WAIT.md).

## Terminal ONVIF capture obligations and cold reconciliation (2026-10-29, reference)

New stable capture reservations now pin their exact future Create intent in the original
immutable preparation. Dispatch requires that intent to have been freshly published in the
same local authority history after reservation; old, foreign-store and duplicate-bound intent
handles refuse. Successful retained cleanup can then verify the operation and close its generic
effect obligation. The source-free consumed-ID fence survives deletion and never permits replay.

`fss-onvif-metadata control reconcile-operation` completes interrupted operations from exact
retained Unsubscribe custody, including a verified successful raw outcome when final marker
publication failed. It needs neither credentials nor network access. Proof binds original owner,
preparation, physical stores and complete Create/cleanup ancestry. Acceptance/observation/verify
crash cuts resume under the same proof; terminal retries append nothing. Legacy unbound records
retain their bytes and cannot borrow an unrelated terminal receipt. Late cancellation or runtime
retirement failure preserves the terminal receipt with `verified_with_error` and a nonzero exit.

Ten native recovery regressions, native-hook/cold-owner cuts and a subprocess command workflow
were added. Independent review found and repaired cross-store intent freshness and late-receipt
loss before delivery. The combined native run passed all 17 capture-operation contracts,
61 CLI unit tests and the new cold reconciliation subprocess workflow. Three existing capture
fixtures incorrectly hashed the spool envelope as the source payload; they now use the public
verified payload reader and preserve the exact source hash and native decode assertions.
Execution of those repaired capture fixtures is pending.
This closes one capture-obligation lifecycle, without qualifying live devices or continuous
operation. See [ONVIF recovery commands](docs/onvif-metadata.md).

## Independent health retention from completed checkpoints (2026-10-29, reference)

Completed screened dwell checkpoints now expose the same independently approvable historical
health receipt as a whole-recording scan. Their exact continuation can retain it through the
existing diagnostic owner, including frozen footage, incomplete screening and zero candidates.
Cold retention reconstructs the saved bounded prefix and reports that cost separately; it
advances no source positions, republishes no checkpoint, opens no detector package and changes
no event or effect state. Fresh/partial checkpoints, wrong approvals and changed custody refuse.
Exact retries verify the original retained receipt/trace and append nothing.

The complete enclosing output is admitted before retention, with checkpoint/policy custody
reopened before retention and delivery. Screened fusion reports now preserve the independently
retainable diagnostic too; the native comparison retains exact receipt/provenance equality
while allowing the distinct one-shot and checkpoint command hints. Added subprocess contracts
exercise emitted commands, a deliberately absent detector, frozen/empty candidates, cold
health verification and non-advancing partial refusal. The combined native run passed all
31 dwell CLI contracts, 68 incremental dwell contracts and eight historical-health catalog
contracts, including the new independent completed-checkpoint retention cases.
See [completed checkpoint health retention](docs/incremental_dwell.md#retain-a-completed-checkpoints-health-diagnostic).

## Original footage for retained trained-detector events (2026-10-29, reference)

`fss-export media` now accepts current native retained package-track events. The existing
package owner reopens the exact event, reconstructs retained tracking and verifies original
detection/source custody without inference or loose model/source files. The selected import
must actually belong to that event. Export retains whole-source disclosure, unclassified and
indeterminate event semantics, exact destination approval and independent original-media read
authority. Current masks, deletion, source/provenance damage and event successors refuse.

The additive FSSEXM01 version-three profile binds the package-event provenance and retained
detection root under a distinct policy/domain; earlier native and reviewed formats retain their
bytes. Four native contracts and one real CLI workflow cover cold recovery, exact source/profile
binding, post-approval invalidation, repeat delivery and independent offline verification.
The native export contract stage passed in [the supplementary reference run](https://github.com/Dicklesworthstone/franken_surveillance_system/actions/runs/40976559961),
and all 13 media-export CLI contracts passed in [the native capture run](https://github.com/Dicklesworthstone/franken_surveillance_system/actions/runs/40977388102),
including the new cold package export and offline verifier. These are supplementary results,
not release qualification. See [original-footage export](docs/ORIGINAL_MEDIA_EXPORT.md).

## Calibrated advice from screened dwell checkpoints (2026-10-29, reference)

An already complete incremental dwell checkpoint with `--sensor-health conservative-v1` can
now produce read-only calibrated class advice through the existing fusion profile workflow.
Cold restoration reproduces the original temporal and health owners; classification, fusion
and output retain the native finding/incomplete-screen fence. Removing screening changes the
saved recipe and refuses. Partial checkpoints cannot advance inside an advice invocation.

The progress wrapper preserves separate original and cold-restoration health work. Terminal
delivery reopens the exact checkpoint graph and retained health policy before report export
and stdout, without another frame scan or checkpoint publication. Added real-process contracts
compare screened cold advice with a same-anchor whole-recording analysis, preserve exact retry
output and journal bytes, and refuse frozen-source advice or removal of the screening option.
Pinned formatting and independent source review passed; runtime tests remain unverified under
the shared build constraints described below. See [completed checkpoint advice](docs/incremental_dwell.md#calibrated-advice-from-a-completed-checkpoint).

## Retained event health through session recovery (2026-10-29, reference)

Explicit and discovered package-event supervision now apply the same source-bound historical
health constraints as direct detector supervision. Frozen or incompletely screened footage
retains its exact native rows and scores but contributes neither positive nor negative class
support. Repeated selections share one assessment and remain deduplicated.

Discovery seals each selected event's exact health interpretation, including unknown diagnostic
coverage. Cold pending-report delivery and first acknowledgement revalidate that interpretation
under current authority. New relevant findings refuse reuse while preserving the original report
for inspection or discard. Additive journal tag 9 and a distinct receipt domain retain legacy
encoding identity; selected legacy reports without health pins require reevaluation. Regression
cases cover freeze/clear/incomplete screens, unrelated diagnostics, cold replay/ACK invalidation,
publication crash cuts and pin tampering. Runtime execution remains unverified because of the
shared build environment's memory limit. See [retained event supervision](docs/RETAINED_EVENT_SUPERVISOR.md#historical-source-health).

The shared health catalog also recognizes deletion-owner-verified tombstones as successors to
their original diagnostic instead of rejecting the whole catalog after legitimate deletion.
Original diagnostic and deletion counts remain separate, deleted payloads stay unread, and an
orphan or forged tombstone still refuses. This repairs the functional deletion failure observed
in the existing privacy-generation regression; its new refusal coverage remains subject to
native test execution.

## Lost deployment journal refusal (2026-10-29, reference)

Opening a deployment now refuses to create a missing authority or effect journal over
surviving durable state. The check runs before initialization and under the publisher
lock; only a strict empty initialization skeleton can resume journal creation. This
preserves original alert idempotency and unresolved effect history through operator
recovery instead of silently treating lost history as a new deployment.

Doctor keeps publication linkage, import completeness and obligations unknown when
their journal is unavailable. Agent orientation refuses absent authority history and
marks absent effect history unknown, so follow cannot turn missing effect history into
a silence certificate. Focused regressions cover fresh-process refusal without source
mutation, exact-journal restoration, interrupted initialization, retained unpublished
custody, unknown siblings and recovery diagnostics. The implementation and tests passed
format/whitespace checks; local compilation was blocked by the shared environment
killing the existing Asupersync dependency for memory pressure. No test-pass or release
qualification claim is made for this slice. See [recovery guidance](docs/deployment_backup.md#missing-canonical-history).

## ONVIF RTP metadata reconstruction and custody (2026-10-28, reference)

The production packet owner now reconstructs uncompressed ONVIF metadata from
bounded, reordered RTP packets, using marker boundaries rather than timestamp
changes. It preserves original packet spans and preceding boundary witnesses,
and explicitly retires incomplete state after loss, deadlines, malformed or
conflicting source, truncation, cancellation and stream restart.

`fss-onvif-metadata import-rtp` retains one original `#!rtpplay1.0` file, a frozen
owner/configuration recipe, complete replay report, completed XML candidates and
accepted vendor-event/analytics projections in one immutable ledgered root.
Rejected XML and unprocessed source remain retained even when no usable document
survives. `inspect-rtp` and `verify-rtp` reconstruct the original packet source
and compare every derivative, source map, publication and ledger link without
the input file. Whole-import hold/deletion closure refuses deleted-source
rebinding. Default output withholds raw private values; selected document
inspection can expose its exact packet map and explicitly opted-in vendor values.

This advances the packet transport and retained replay portion of FSS-046.
Live RTSP metadata-track negotiation/acquisition, continuous recovery, cross-frame
tracking and physical-device/Profile M qualification remain open. Existing XML
and PullPoint generations remain unchanged. See the
[recorded RTP operator workflow](docs/onvif-metadata.md#import-recorded-rtp-metadata).

## Source-retained reconnect recovery (2026-10-19, reference)

`fss-capture-rtsp reconnect --recover yes` and `--recover index` now accept the
original source-retention options. A separate approval binds the exact observed
recording archive, independent work journal and complete datagram source chain
for every original attempt. All journal minima pass before original source reads;
all selected native work and original RTP byte/time witnesses pass before the
first media restoration. Source owners remain locked throughout the operation,
and custody is checked again before restoration and catalog publication.

Optional `--minimum-source-pins` binds independently saved original-attempt source
prefixes by exact datagram count, payload bytes and head. Missing/partial stores,
corrupt newer source, unmatched packets and replaced roots refuse. All three
unobserved stores remain unknown. Repeated checks share the original per-attempt
source work ceiling. Recovery creates no camera connection or source writes and
uses the existing native AVC/HEVC recovery and publication owners.

The focused capture binary contracts cover exact retries, independent minima,
source-only boundary packets, corruption, owner locks, output-cut revalidation,
and cumulative work/cancellation. See [the operator workflow](docs/rtsp_source_recovery.md).
This closes the source-retention recovery refusal; it does not authenticate
cameras, recover continuous coverage or qualify physical devices and release gates.

## Durable multipart restart recovery (2026-10-20, reference)

The authority-owned uploader can now attach a bounded `FileUploadJournal` before
its first provider operation. Canonical checkpoints retain the original intent,
complete chunk plan, manifest root, provider identity, first dispatched part
hashes, confirmed receipts, uncertainty, original authority/deadline, cumulative
consumption, narrowed grants, cancellation and local settlement evidence.
Every dispatch and dynamic framing/response charge reaches the journal before
provider I/O; acknowledged outcomes reach it before success is reported.

Cold recovery validates the entire linked history against an independently saved
minimum pin and the caller's original expected intent. A fresh caller-owned child
reserves only the remaining allowance. Historical costs never become refundable
or spendable again, changed part bytes refuse, and an uncertain provider effect
requires reconciliation before retry. Terminal and indeterminate records precede
canonical closure/refund, so a blocked local finalization can resume without
repeating a provider effect.

The file backend uses the existing explicit spool I/O capability and exclusive
lock, rehashes canonical records, rejects forks/gaps/corruption and semantic
rewinds, bounds storage and read work, and retains torn staging without admitting
it. Any ambiguous append blocks further effects until cold reopen. Directory and
lock identities are checked on supported Unix filesystems. Pins are commitments
to known history, not provider authentication or detection of unpinned newer loss.

This supplies the missing persist-intent-before-dispatch and restart boundary in
FSS-064. Native S3 transport, provider qualification, byte encryption, independent
retrievability and the aggregate release gates remain separate work. Existing
in-memory APIs remain available. See [owned multipart uploads](docs/OWNED_ARCHIVE_UPLOADS.md)
for the attachment, independent pin, recovery and durable revocation contracts.

The pinned nightly passed all 50 focused multipart/uploader/restart contracts,
including 17 new cold-reopen and filesystem-fault tests. The complete object
crate passed 337 tests with one existing permission test ignored because it
requires an unprivileged process. Tests include actual after-effect crashes,
lost acknowledgements, dynamic budget charges through repeated restarts, corrupt
and forked records, owner replacement, tightened deadlines, persistence refusal,
and completion/indeterminate finalization without provider replay or double refund.

The follow-on durable cancellation API persists a stop request before live runtime
cancellation or a successful acknowledgment. It retains the pending owner and
reservation, blocks new source/provider work across restart, and preserves abort,
reconciliation, indeterminate settlement and known terminal receipts. Five further
contracts cover the committed-record-before-live-mutation cut, persistence refusal,
Prepared/Uploading/Uncertain owners, exact retries and durable publication-grant
revocation; the final focused run passed all 55 tests, including 22 durable contracts.
The supplementary reference workflow executes these restart contracts alongside
the existing multipart and uploader tests.

Further recovery now durably retains accepted later times, narrowed deadlines and
revoked grants before a fresh owner can escape. File journals preflight room for
provider acknowledgements and local terminal/follow-up records, while known
terminal recovery can use its reserved final slot and already durable settlement
can close without another append. New v2 records bind the original path/root/lock;
copied, renamed or lock-replaced journals refuse. V1 history stays readable and
requires explicit original-authority namespace adoption before writes.
`fss-archive upload-inspect` provides a bounded, metered, read-only status projection
from the complete verified history and an independent minimum pin. It retains
unknown outcomes, cancellation, expiry and indeterminate follow-up references while
excluding private provider tokens and notes. It performs no provider operation and
makes no independent retrievability claim.
The follow-on pinned validation passed all 73 focused object contracts and five
fresh-process archive inspection tests against the normal production binary.

## Multipart unresolved-outcome recovery (2026-10-20, reference)

The authority-owned multipart uploader now supports explicit local settlement of
an uncertain upload when provider reconciliation remains unavailable or its
bounded allowance is exhausted. `settle_indeterminate` retains a typed receipt
binding the original intent, actual child region and obligation, uncertain
operation, bounded operator note and independent follow-up reference. The
canonical obligation remains `Indeterminate`, with its exact reconciliation note;
the receipt never claims provider completion, abort or rollback.

Local finalization failures retain that receipt for an exact retry. Recording the
unresolved settlement disables further provider calls immediately. Successful
child closure returns only unused allowance to its original parent, while every
attempted request and byte remains charged. Changed notes or references refuse.
The caller must preserve the receipt and arrange independent provider follow-up.
Without an attached durable upload journal this remains an in-memory boundary;
the optional restart path above persists the receipt before local closure.

Every staged source or transport boundary also checks the original obligation and
reconciliation state. Altered obligations cannot authorize additional publication.
Lifecycle timestamps and the latest observed transport clock bound subsequent
work, including a later timestamp at which a transport checkpoint refused.
Prepared local aborts bind the same operation and owner as initiated sessions.
See [owned multipart uploads](docs/OWNED_ARCHIVE_UPLOADS.md).

The pinned nightly passed all 33 focused uploader/multipart tests, including 12
new regressions. The complete `fss-object --all-targets --all-features` suite
passed 320 tests with one existing ignored test. Runtime effect, RTSP capture,
native dwell and agent rehearsal checks also passed in this session; these do
not replace provider qualification or crash-persistence work.

## Runtime effect evidence and recovery (2026-10-20, reference)

`fss-runtime::EffectCoordinator` retains a canonical `fss-core::EffectJournal`
and the original preparation bindings independently of caller handles. Preparation
binds the operation, idempotency key, request and precondition digests, obligation,
terminal predicate, authority, owner region, resource, fence and registered
prepare/commit grant pair. Exact preparation retries recover an inert handle;
only the first successfully approved commit issues a dispatch permit. Dropping a
handle cannot erase the receipt, authorize another dispatch or discharge an
outstanding obligation.

Adapter acceptance remains distinct from observation. Verification requires the
same evidence digest recorded by observation; failure requires evidence and a
reason, and cancellation uses the core cancellation-proof binding. A recovered
inert handle can reconcile canonical state without regaining dispatch authority.
Terminal settlement validates a candidate journal before resolving the matching
region obligation, preserving state and caller tokens when authority, proof or
region checks refuse. Indeterminate outcomes retain reconciliation provenance.

The authority, lifecycle and effect-proof contract suites exercise duplicate
requests, exact approval and precondition mismatches, all six registered effect
families, wrong owner/tree/lease boundaries, dropped handles, proof mismatches,
terminal retries and reconciliation after uncertainty. This coordinator is bounded
to 4,096 retained operations in memory; it does not provide crash-persistent effect
storage, authenticate adapter evidence or replace the existing durable effect
owners. The pinned nightly passed all 117 runtime tests with `cargo test --locked --offline -p fss-runtime --all-targets --all-features`, including 63 tests in the affected contract suites. Repository qualification and native DSR receipts remain release authority.

## Runtime authority core (2026-10-18, reference)

`fss-runtime` is enrolled as the program's runtime/authority core: `AuthorityCx`
composes asupersync's detached `Cx<cap::None>` with `fss-core`'s `RegionTree`
with explicit construction everywhere and no ambient access. Scope-down enforces
kind legality (`Process → Property → …`) and narrowing-only authority (child
`trace_id` is inherited; budget widening is a typed refusal). Cancellation is the
four-valued import vocabulary (Completed / Drained / Failed / Indeterminate),
idempotent, never rewinds, and cascades through the scope chain. Obligations are
owned by the region tree (`register_obligation`/`resolve_obligation` per region,
with Indeterminate resolutions requiring durable reconciliation notes); the
runtime crate supplies only the constructor and the leak-oracle facade mapping
`ObligationTerminal` onto `ObligationState`. The typed `Budget` ledger refuses
overdrafts and never clamps silently.

Verified by a 27-test contract suite (`crates/fss-runtime/tests/runtime_contract.rs`)
and a deterministic end-to-end script (`examples/authority_lifecycle.rs`,
`RCH_SHIM_LOCAL_IDE=1 cargo run -p fss-runtime --example authority_lifecycle`)
emitting one bounded structured JSONL transition per step, terminating in
`Completed` with zero leaked obligations. Capability grants and resource scopes (FSS-025),
leases/epochs/fencing (FSS-026), the two-phase effect coordinator (FSS-027),
the deterministic crash/cancellation cut-point harness (FSS-030), and TLA+
models for root-last publication (FSS-029) and effect idempotency (FSS-028,
`proofs/tla/`, TLC-checked with negative controls) have since landed.
Laboratory schedule control (FSS-024) and the INT-AS-001 / TEST-SCHEDULE-001 /
GATE-020 qualification bundle remain open under the runtime epic's sibling
beads.

## Native HEVC capture operator workflow (2026-10-12, reference)

`fss-capture-rtsp --codec hevc` now carries one owner-approved camera session through
selected-SDP configuration, native HEVC collection, protected archive publication and
immutable catalog reporting. Codec-specific configuration, reconstruction, assembly and
source-witness limits participate in the pure approval. Default or explicit AVC retains
its established plan and decode-clock identity; switching to HEVC requires its own approval
and selects only native HEVC recording, archive and recovery verifiers.

The operator driver supports the existing scoped Digest credential/entropy lease, validates
fixed 90 kHz cadence, and starts final storage draining before the final window's checkpoint.
It distinguishes source-only boundary witnesses, released active buffers, unpublished tails,
confirmed recovery work and normal durable samples. Early source termination remains a
failing shortfall even when its source-closed prefix is importable. Physical TCP EOF remains
a separate observation from HEVC end-of-bitstream or explicit owner stop.

Real-process contracts cover exact codec approvals, selected-SDP refusal before SETUP,
authenticated capture without retained secrets, one- and two-window source custody,
unverified tails, cadence refusal, catalog import and cold native pixel decode with the
original capture archive offline. Five independent recovery-command contracts cover the
operator's cold work/pin path. See [the complete capture workflow](docs/rtsp_capture_cli.md)
and [retained HEVC import](docs/rtsp_recording_import.md). This closes a reference workflow
gap; reconnect, arbitrary HEVC profiles/timing and camera/field qualification remain open.

## Native selected-SDP HEVC live archiving (2026-10-12, reference)

`JournaledLiveHevcArchive` connects the native TCP/Digest session, HEVC picture capture,
bounded recording collector and independently journaled archive writer. It validates the
exact expected H265 payload and one coherent VPS/SPS/PPS tuple from the selected SDP before
SETUP or PLAY. Source timing remains explicit, configuration limits apply before collection,
and real picture-boundary packets remain part of the original source closure.

Storage pauses input. An explicit final stop closes TCP before the admitted window's first
checkpoint; actual EOF starts final draining as soon as the complete prefix is sealed.
Both paths drain already-owned media under independent publication limits after the live
network lease expires or is revoked. Live revocation still refuses new input and preserves
its original pending work. Actual EOF and owner stop retain different completion causes;
markers, local stop and EOF never manufacture a complete HEVC picture.

Native loopback contracts cover these ownership transitions, selected-description refusal,
an unverified lone-IDR tail, protected work restoration and authentication challenges before
automatic credential use. The reference path remains a bounded single plaintext session;
reconnect, deployment-camera compatibility and field qualification remain open.

## Protected HEVC archive work and cold restoration (2026-10-12, reference)

Native HEVC recordings now pass through the same bounded source-first, root-last work
protection and independently synchronized pin journal as AVC. Concrete HEVC writer and
journal types select sealed HEVC recording/catalog verifiers and distinct work, retirement
and journal domains; existing AVC bytes and routes remain unchanged. Candidate metadata
commits before pending footage, confirmation commits before a normal window or catalog,
and every failure returns the original pending media and exact recovery references.

Storage-only restoration reopens the independently retained candidate, replays original RTP
through native HEVC verification, and restores only the original pending window/page slots.
Lost work or restoration acknowledgements keep their original identities. Missing or damaged
newer work cannot fall back to an older confirmation; bounds, cancellation and a changed
journal tip fence progression. Picture-boundary witness packets remain source-only where
appropriate, including when adjacent windows share a witness without sharing media samples.

The operator commands `fss-archive inspect-work`, `restore-work`, `inspect-pins` and
`restore-pins` accept an explicit `--codec hevc`. Their typed recovery path preserves the
original pending slots and minimum journal anchor, supports exact lost-reply retries, and
refuses damaged originals or cross-codec substitution before confirmation. Omitting the codec
keeps the established AVC command and report behavior. Pin inspection remains metadata-only
and can inspect independent protection while the media archive is offline.

Native contracts cover both durability barriers, cold pixel decode, exact restoration retry,
confirmation-budget exhaustion, cross-codec refusal, damaged originals and protected-tip
fencing. This advances the reference acquisition/HEVC slices of FSS-047, FSS-048 and FSS-114;
camera compatibility, reconnect, field continuity and full media qualification remain open.

## Geometry support for whole-recording corroboration (2026-10-12, reference)

`fss-event corroborate --stream-corroborate` accepts explicit poses, exact site calibration,
scene meshes and visibility settings across both complete native recordings. Owner homographies
remain the actual observation projection. The optional geometry owner checks decoded dimensions,
native pose/homography consistency, current privacy, frustum/mesh visibility, calibrated pose
perturbations and the full camera covariance guard. Unsupported observations stay in the
inventory with explicit dispositions but cannot support cross-camera association. Work ceilings
span all zones of each camera rather than replenishing per zone.

Shared calibration and scene packages become declared common causes under the existing
witnessed-activity/`Hold` policy. Exact camera parameter bits, generations and adoption receipts
are bound into a canonical recipe. Adoption changes, including newly adopting an owner-asserted
camera or moving a sensor to another camera, invalidate the old analysis/approval basis.
Calibration/scene archives and native geometry receipts become camera-root custody children;
publication checks current adoption and cannot repair a completed event's missing custody from
loose files. Cold inspection restores archives and recomputes support under current authority;
explicit verification additionally reruns both original pixel scans.

The extension composes with whole-recording trained annotations and historical health screening.
With no geometry options, prior recipe/report/event identities remain unchanged. Sampling and
covariance guards are conditional support checks, not physical calibration currency, calibrated
threat probabilities, detection recall or absence evidence. Broad site/field calibration and
fusion qualification remain open. See [the geometry workflow](docs/long_recording_corroboration.md)
and [cold retained-event verification](docs/long_event_replay.md).

The [pinned native feature run](https://github.com/Dicklesworthstone/franken_surveillance_system/actions/runs/38189039297)
passed all eight geometry process contracts, including covariance-based support withdrawal and
combined trained-detector/health/geometry publication followed by cold replay. Existing stream
corroboration (8), trained-detector (5), historical-health corroboration (4), cold-event CLI (6),
and native long-corroboration/watch/replay (48) checks also passed, along with capture/event CLI
Clippy. That run separately exposed a catalog deletion test's incorrect local-tombstone assertion;
its follow-up checks the authoritative deletion index and retained-read refusal. These are
supplementary native fixture results, not a camera, site-calibration or release qualification.

## Scoped Digest authentication for native RTSP capture (2026-10-12, reference)

`fss-capture-rtsp` can now capture from an owner-authorized Digest camera using an
explicit private credential-file reference and exact realm. The pure plan binds the
credential path, authentication policy, Linux secret/entropy backends and their bounds;
preview never opens the file. Approved execution validates the bounded two-record file
before creating either archive destination or connecting. Its identity, permissions,
size and change timestamps remain a live lease at every TCP authorization checkpoint.
Replacing, editing, removing or exposing the file stops subsequent network progress.

The existing native authentication state machine now owns challenge responses and all
subsequent signed requests, including keepalive. SHA-256/SHA-256-sess with `qop=auth`
are the default; MD5 and no-qop require separate explicit legacy opt-ins. Linux's verified
random device supplies fresh 128-bit cnonces. Wrong realms, replay, downgrade and
exhausted retries refuse. Structured reports retain counts and refusal categories,
without credentials, Authorization headers or challenge text in reports or recordings.

This is an operator-facing reference slice of FSS-047. It preserves original-RTP custody,
independent pin barriers, import and cold native decode. The optional secret/entropy
backend is Linux-only. Plaintext transport, unauthenticated server identity, bounded
single-session operation and the current approved blocking-I/O reference boundary remain
explicit; camera qualification, reconnect/fallback and the broad adapter bead remain open.
Validation passed 30 capture unit cases and 14 real-process cases on pinned
`nightly-2026-08-31`, locked offline dependencies and debug assertions. The process
fixtures independently verify SHA-256/SHA-256-sess responses and exercise fresh/stale
nonces, revocation, replay/downgrade/retry refusal, secret-free retained custody and
capture → import → cold native decode. The exact published increment also passed the
supplementary [RTSP smoke run](https://github.com/Dicklesworthstone/franken_surveillance_system/actions/runs/38187584523):
109 native tests across capture, AVC/HEVC recording, payload selection and catalog custody,
plus feature formatting and capture CLI Clippy. See [capture authentication and its limits](docs/rtsp_capture_cli.md).

## Native RTSP/AVC capture operator command (2026-10-11, reference)

`fss-capture-rtsp` composes the native live recording and journaled archive owners into a
bounded camera-to-retained-import path. A pure preview binds the route, source generation,
timing assumptions, new archive and independent pin-journal destinations, all native ceilings
and requested picture count. Approved execution sequences DESCRIBE, SETUP, PLAY and keepalive
on one literal-IP plaintext TCP session. Authentication challenges without explicit Digest
authority, cadence drift, source changes and exhausted bounds refuse explicitly. The owner-selected payload is carried
into live DESCRIBE selection and packet collection; multiple AVC offers do not pick an
implicit alternative. Each durable catalog row exposes its exact source, slot/root and
decode clock for complete-page retained import and whole-recording analysis.

Selected original RTP and its native remux mapping reach source-verified, root-last recording
windows; independent pin synchronization precedes work-publication acknowledgement.
The final sealed window's admission closes the socket and starts the reserved storage-drain
allowance before checkpoint, window and catalog publication, without fabricating EOF. Early EOF remains incomplete even when its complete prefix is importable. Protocol
faults and unpublished tails retain distinct accounting and recovery references. Canonical
parent checks reject aliased or nested archive/journal destinations before creation.

Parser/approval and timing tests accompany real-process loopback capture → import → cold
native decode contracts, including stale approval, secret-free authentication refusal,
early EOF, malformed media, wrong cadence, symlink-parent separation, exact payload selection
and multi-window catalog import. Pinned native checks have passed 22 capture unit cases,
12 live-recording cases and seven plain/Digest payload-selection cases. Catalog composition
renumbers only the derived MP4 fragment sequence fields; every original window remains
unchanged, and cold proof replay applies the same deterministic composition. The focused
supplementary GitHub smoke check includes both process and catalog regressions; this is not
a production-camera or release qualification. See [the capture workflow](docs/rtsp_capture_cli.md).

## Retained historical sensor-health diagnostics (2026-10-11, reference)

Whole-recording corroboration now exposes independent diagnostics for both cameras through
`historical_health`. One exact `--retain-health` approval retains only its selected camera,
even with zero ground entries/pairs or health-blocked publication. Camera labels resolve by
source import identity. A fully refused camera can retain its zero-screened, incomplete result
under the explicit decode-refusal option, with requested-hint scope and no association samples.
Cold verification reproduces the selected raw masked scan independently of trained event
annotations. Ground association, shared-cause declarations and event approvals retain their
existing owners; a later clear camera receipt cannot replace the earlier camera's findings.

The corroboration extension passed 39 focused native tests under the same pinned Linux
profile: new per-camera process contracts (4), existing streaming corroboration CLI (8),
trained-detector CLI (5), single-camera historical-health CLI (6), and whole-recording
corroboration contracts (16). Coverage includes exact emitted commands, independent retries,
stale recipe/approval refusal, zero-pair and zero-screened-frame retention, native cold replay,
and unchanged event-publication gates. Camera summaries and nested receipts are checked
against their exact source identities and frame counts.

Screened whole-recording watch and dwell reports now offer an independent `--retain-health`
approval. A recording can retain its diagnosis when there is no event candidate or when a
health finding blocks event publication. The canonical receipt binds original source custody,
capture assumptions, the exact native scan and decoder/read limits, privacy generation,
bounded finding runs, trace identity and actual work. Root-last retention revalidates source
and privacy before the final diagnostic commit; exact retries preserve the original anchor.
All-refused screened ranges remain explicit incomplete diagnostics with zero screened frames
and a labeled source-capsule-hint fallback, never a fabricated screened interval.

`fss-event health read` checks retained diagnostic metadata after restart without reading media
or trace payloads. `health verify` separately admits native execution against exact receipt
and provenance pins, reruns the retained masked scan and compares the complete receipt and
trace. Current privacy changes, deleted/damaged selected custody, exhausted bounds and
divergence refuse. The default CLI admission covers both native-library and watch-CLI producer
profiles, while explicit smaller ceilings refuse the original recipe without rewriting it.

Normal operator/agent orientation exposes literal historical results and exact proof handles;
meaningful changes classify them as `SensorHealth`. A later `no_findings` receipt cannot clear
an earlier suspicion. Current deletion fences bytes even in historical reads and remains a
visible custody transition for sensor-health subscribers. Complete expansion inventories
respect the existing 256-handle schema bound instead of truncating diagnostics or emitting
an invalid response. Event, coverage, current tamper and alert authority are unchanged.

Eighty-two focused native tests passed on Linux x86_64 with pinned `nightly-2026-08-31`,
locked offline dependencies and debug assertions: historical retention/projection (12),
additional meaningful-delta and expansion-bound cases (2), new real-process CLI (6),
existing health-gated CLI (6), watch-entry CLI (8), whole-recording watch (16),
whole-recording corroboration (16), and cold native event replay (16). These cover quiet and
all-refused recordings, exact retries, privacy changes, damaged custody, graph-complete
deletion, cancellation, old canonical replay identities and the unchanged Pulse budget.

The additional agent-surface run at `3348842` (run `41655137973`, job `125983315450`)
passed native frozen/incomplete refusal, post-preparation refusal with explicit cancellation,
and carried-forward privacy support. Two fixtures reached valid refusals but expected the wrong
contract: unrelated canonical writes made the original event receipt stale, and damaged diagnostic
custody prevented constructing an admitted agent envelope. The corrected fixtures preserve both
refusals, require read-only source-health checks, explicitly publish unchanged native support in a
successor event before dispatch, and validate the strict pre-admission execution diagnostic with
unchanged authority, effect and session journals. Their native rerun remains pending.

This is a retained reference slice of NS-3 / DOC-059. Live outage supervision, physical camera
movement attribution, authorized restoration and measured field accuracy remain open.
See [the operator workflow and limits](docs/historical_sensor_health.md).

## Current-format core deployment recovery (2026-10-11, reference, focused native tests passed)

`fss-backup plan/create/inspect/restore` adds bounded recovery for exact local deployment
originals. A separately pinned canonical manifest retains full deployment limits, both
journals, spool objects including valid unreferenced records, publication roots and
tombstones. Native owners check custody, linkage, hold history and deletion state. Dirty
staging, partial journals/deletions, denied originals still present, unsafe links, changed
pins, existing destinations and unsupported populated stores refuse. Independent agent
state is explicitly outside this profile and cannot be silently omitted.

Bundles remain inert. Restore preserves the historical authority prefix and exact effect
journal, creates fresh physical store identities, and appends an irreversible alert-effect
fence before LAYOUT activation. Saved or rehydrated preparations cannot dispatch from the
copy or acquire a false terminal cancellation merely because they were Prepared at capture.
Pending obligations remain unresolved. Original-read and destination-retention grants are
separate from the execution context and remain live throughout bounded transfer.

This is `reference-core-local-v1`, with no implicit schema migration, populated agent-store
recovery, external archive/secret-store backup, unfence, automatic reconciliation or failover.
The scope and commands are in [deployment recovery](docs/deployment_backup.md).
Fifty-six focused native tests passed on Linux x86_64 with pinned `nightly-2026-08-31`
and locked, offline dependencies: backup contracts (11), real-process CLI (4), alert
recovery (15), injected destination-parent replacement (1), existing holds (7), retention
deadlines (5), and deployment contracts (13). These exercise exact custom-capacity
roundtrips, source-side dispatch after capture, saved-plan and webhook fencing, live
revocation, cancellation, invalid hold history and deletion denial. Create/restore writers
support Linux x86_64 and aarch64; this run qualifies only the exercised reference/process
paths, without a broad FSS-035 or release qualification claim.

## Explicit forensic explanation budgets (2026-10-11, reference, focused native tests passed)

`fss explain` accepts `--view forensic` and an exact `--budget-tokens` under registered view
limits. It can serve complete support and checked-custody explanations which cannot fit the
compact 1800-token view, while retaining that default and refusing explicit smaller caps
without widening or truncating them. Orientation, support and custody share the requested
semantic allowance; errors retain the requested view and cap. Combined graph work and all
counterevidence remain bounded and visible. Thirty-eight focused native tests passed on
pinned `nightly-2026-08-31`, including exact aggregate admission, one-token-short refusal,
unchanged compact behavior, custody fault preservation and existing parser/schema contracts.
See [the explanation workflow](docs/AGENT_EVIDENCE_EXPLANATION.md).

## Trained detector evidence for whole-recording corroboration (2026-10-11, reference)

`fss-event corroborate --stream-corroborate` now accepts an exact trained detector package and
annotates ground entries from both complete native recordings, including entries after frame
128. Ground entry and following actual matches are selected within the same camera/epoch/local
track. The RGB engine shares one inference allowance and one detection-head work budget across
both cameras; admitted refusals consume their slot. Per-camera source, JPEG and pixel bounds
span foreground and RGB passes. Reports distinguish selections admitted, pipeline attempts,
completed model/head results, refusals and work consumed.

Publication retains the full archive, exact component and ground-selection recipes, both
outcomes, shared-budget counters and all source/class associations. Cold inspection checks the
two ground observations, selected-pair class lists, complete camera closures and common-cause
policy. Explicit native verification reruns both recordings and the retained model after loose
sources and the model file are gone. Same-camera capsule substitution, missing class/model
custody and inconsistent global accounting are refused. Watch and corroboration readers also
bind entry capture intervals to their exact source capsules. Model-free canonical identities remain
unchanged. Class results stay uncalibrated annotations in provenance; they add no policy votes,
independent domains, event classifications, probability calibration, absence or alert authority.
See [the two-camera workflow](docs/long_recording_corroboration.md) and
[cold recovery](docs/long_event_replay.md).

Validation: 80 distinct focused native tests passed on pinned `nightly-2026-08-31` with
locked, offline dependencies: `long_watch_contract` (16), `long_corroboration_contract` (16),
`corroborate_stream_detector_cli` (5), `ingest::long_event_replay::tests` (16),
`corroborate_stream_cli` (8), the upstream `evidence_availability_contract` (11), and
`fss-event`'s `replay::tests` (8). The reference and CLI crates also rebuilt successfully
against the combined main tree after the additive upstream evidence-availability API arrived.
The cold group retains all five exact legacy identity pins and exercises fully rehashed source
capsule/capture substitutions, shared head work consumed before refusal, current privacy,
cancellation and missing model/class custody. These are focused reference and CLI results;
whole-workspace, deployment-quality and release qualification remain open.

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
  All eight native calibration-adapter CLI regressions pass on the pinned Rust toolchain. No detector
  has a measured deployment calibration. Calibrated fusion is wired into `fss-event watch` and
  `fss-event corroborate` as digest-pinned, read-only advice: it names the exact detector package and
  fusion profile and never changes the native approval or report.
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
- **Exact RTSP campaign analysis (2026-10-22, reference):** `fss-watch-rtsp-campaign` verifies
  an independently saved history prefix and binds every selected start to its complete native
  catalogs or an explicit no-catalog state. Source-closed imports span independent archives;
  native watch runs at one final destination anchor with separate tracking per attempt. Failed,
  empty, unavailable, start-only and unindexed-picture observations stay explicit. Shared work
  and lifetime source-IO ceilings apply; exact retries reuse imports, and native watch reruns
  work with source archives offline. The focused native run passed 12 core, 4 scoped-publication,
  10 new CLI, 7 existing selected-watch and 4 real-process tests. This grants no automatic event,
  capture resume, cross-attempt continuity, absence or field qualification. See the
  [workflow and focused proof](docs/rtsp_campaign_watch.md).
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
  revalidation and cold retries preserve the existing authority boundaries. Trained packages
  annotate both recordings under global inference/head work limits and retain full cold replay
  custody. Pose and coverage-retention modes remain outside this streaming composition.
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
  `fss-event calibration adopt|invalidate|show` retains approval-gated adoptions and immutable
  owner withdrawals of exact current adoptions. Withdrawn bases cannot authorize new coverage
  or current orientation/graph/timeline/follow witnesses; historical-prefix queries preserve
  their earlier state. Recovery requires a different calibration digest, a strictly newer camera
  generation with neither lower, and fresh approval bound to the withdrawal. Adoption and
  withdrawal authority survive source deletion. `corroborate --calibration`
  uses the calibrated poses, refuses stale or unadopted calibrations, binds pose provenance into
  coverage records, and withholds absence witnesses for zones whose visibility changes under the
  calibration covariance. Proven on synthetic scenes only; per-camera time offset and real-footage
  accuracy are open, and adoption/withdrawal are owner authority, not observations of the camera.
  The invalidation codec has four passing native exact-source tests; the added reference and CLI
  contracts remain unexecuted in the resource-constrained build environment. The bounded
  `calibration monitor|monitor-replay` path now measures frozen-pose residuals from independent
  retained native exposures and retains approved replayable observations. Continuous physical
  monitoring and deployment accuracy remain open (FSS-091); see the scoped implementation below.
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
- **Agent reads (fss/1, reference CLI and local read-only MCP):** `fss session orient` (AOP-003, alias `fss orient`),
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
  to the witnesses. The registered semantic comparison also permits certified silence across
  harmless successor commits; without coverage the persisting gap stays protected
  `coverage_loss`. Optional `--wait-ms 1..10000` (native MCP `wait_ms`) parks only on a
  validated certified-quiet exact head, within 41 attempted native reads. Initial protected or
  material context returns immediately. A harmless initial anchor mismatch or any complete
  authority/effect anchor advance after a park returns `ERR-AGENT-RESNAPSHOT-001`, both exact
  anchor proofs, and a null payload; intervening protected transitions are not silently
  coalesced. Deadline/cancellation/source failures also return no interval silence claim, with
  checked cumulative known costs and explicit unmetered-work disclosure. Caller-owned control
  checkpoints guard reads, hydration, time and sleep; evidence time and cursor/session leases
  never renew. No durable subscription, universal request-envelope ingress, in-flight MCP
  cancellation or follow-latency SLO is claimed. See [bounded follow waiting](docs/AGENT_FOLLOW_WAIT.md).
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
  The synchronous stdio MCP adapter (`fss-mcp`) exposes the full 14-operation `fss/1` surface
  (`session_open`, `session_resume`, `handoff`, `session_orient`, `explain`, `session_follow`,
  `query`, `investigate` with work claims and findings, `plan` with `--close`, `commit` with
  `--reconcile`, `wait`, `cancel`, `feedback`, and `doctor`). `fss commit --reconcile
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
- Certified graph/search kernels and incremental graph intelligence (19 families are implemented and oracle-certified, see "Graph intelligence" above; the other 8 registered algorithms, retained-record projection builders beyond `SensorCoverageGraph` / `EvidenceClaimGraph`, and every graph qualification lane remain open).

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

## Retained ONVIF analytics v2 — scoped implementation (2026-10-27)

The FSS-046 local metadata-import subset now includes bounded VideoAnalytics frames,
object occurrences, coarse shape, vendor class candidates and explicit optional
transformations alongside events. `retain` and CLI imports default to
`gen:fss1:onvif-vendor-analytics-v2`. Explicit `events-v1` imports support old retries;
cold inspect/verify dispatch from the stored recipe and preserve frozen v1 bytes,
roots and opaque analytics semantics. V2 uses separate recipe/projection/notification
domains and source-bound frame identities. Unknown or mixed generation tuples refuse.

CLI output withholds supported private values unless `--include-values yes` is
requested. Biometric/identity extensions remain opaque, coordinates/classes remain
uncalibrated, and no tracking, coverage, absence or effect authority is created.
Successful durable import receipts survive late cancellation/deadline/finalization
errors with `post_commit_error`/`finalization_error` and suppressed optional values.
Stdout write/flush failures return nonzero and emit only the mandatory custody
receipt on stderr; ordinary reads never fabricate a durable-import receipt.
Independent v1 canonical fixtures and parser, custody, privacy and late-failure
regressions accompany the implementation; see `docs/onvif-metadata.md` for scope and
reproducible test commands.

On the pinned toolchain, direct exact-source suites passed: analytics 24/24,
events 21/21, wire 32/32 and output-failure handling 5/5. Integrated Cargo test
and check attempts were killed while compiling Asupersync. A narrower custody
build compiled its real dependencies but exhausted disk before producing its
runner; none of its 20 custody cases executed. Native custody/CLI execution and
integrated compilation remain unverified. This is not full FSS-046 qualification. Live subscriptions,
RTP metadata ingestion, physical-device/Profile M interoperability, calibrated
interpretation and aggregate release evidence remain outside this slice.

## Native ONVIF PullPoint capture — scoped implementation (2026-10-28)

The FSS-046 acquisition subset now has an explicit Linux-native
`fss-onvif-metadata capture` command: one finite Create/PullMessages/Unsubscribe
lifecycle, independently pinned literal peer/HTTP authority/service subtree,
optional exact-realm HTTP Digest, fresh logical WS-Addressing request identities,
and a cleanup time/step reserve. Read-only media routes cannot authorize event
subscriptions. Complete empty and duplicate-bearing responses are retained before
the next poll; earlier durable batch handles survive later transport, custody,
cancellation or cleanup refusal. Output distinguishes NotCreated, Indeterminate,
Active and confirmed Unsubscribed and preserves bounded receipts on stdout failure.

Live custody uses its own recipe domain, the frozen event projection, both request
identities and ordered local Create/poll intervals. Each retained batch includes
the exact Create SOAP as a fourth immutable child. Cold reads verify both source
bodies, correlations and exact ledger custody. File-import v1/v2 bytes and the
analytics-v2 default remain unchanged. Device-event subscriptions have no profile
filter: profile pins remain owner attribution, and no coverage/absence/identity
or effect authority follows from vendor notifications.

Exact production-source validation passed: 16 real-TCP PullPoint contracts,
23 existing ONVIF onboarding contracts, 14 HTTP unit tests, 5 UsernameToken
contracts and 117 RTSP contracts. The PullPoint tests exposed and now cover a
serializer action-dispatch omission. A separate exact-source canonical/source
harness passed 10 tests (6 recipe/source checks plus 4 shared wire checks),
including frozen v1 fixtures, unchanged v1/v2 encodings and live request/time/
correlation binding. The coordinator's fixture sink proves transport/control
behavior, not durable deployment publication. The expanded 25-case deployment
custody suite and native CLI were not executed: full-reference code generation
and real Asupersync compilation remain resource-blocked in this environment.

Remaining material limits: the CLI has no standalone durable control receipt if
Create succeeds but zero batches reach custody; network deadlines and batch
admission do not preempt every synchronous reference-storage checkpoint;
continuous renewal/reconnect recovery, HTTPS/UsernameToken in this capture lane,
RTP metadata and physical-device/Profile M qualification remain unfinished.
FSS-046 remains open. See `docs/onvif-metadata.md` for executable commands and
precise failure/reconciliation behavior.

## Retained ONVIF holds and deletion (2026-10-28)

Verified ONVIF metadata imports now join import/sensor/event deletion closure and
evidence holds through the existing lifecycle owner. Candidate publication names
never establish membership: exact retained source, projection, manifest and owner
sensor binding must verify. Active holds, shared objects, exact approvals and
crash-resumable deletion keep their existing semantics.

Metadata reads and publication retries consult durable deletion authority before
serving or staging content, including incomplete unlink operations and metadata
removed as another import's derivative. A different owner binding cannot restore
a deleted recipe/source/projection/root. Native PullPoint imports additionally
fence their retained Create/subscription response. File v1/v2 and native recipe
bytes remain unchanged.

Seven new contracts cover holds/release, restart, wrong approval, tombstone crash
cuts, cross-binding resurrection, mixed scopes/shared bytes, counterfeit custody,
derivative deletion, native subscription-source reuse and vendor-claim scope isolation.
The lifecycle boundary returns only a verified owner-bound sensor; deletion and hold
effects cannot inspect vendor cognition or derive approval from it. The contracts are formatted and
reviewed but remain unexecuted because full-reference dependencies cannot be built
within the current environment. This closes the retained metadata lifecycle gap;
it does not add remote/device erasure or continuous subscription recovery.

## Native metadata storage admission — implementation follow-up

`ReplayCx` and its I/O authority can now carry a borrowed live owner callback using a default generic parameter, preserving existing replay callers. Native metadata import and inspection attach the current request scope. The first cancellation, deadline, capability, budget, reentrancy or unwind refusal closes admission permanently across context and I/O-authority views. Known durable receipts survive post-commit refusal, with original owner errors retained and optional private values withheld. The bridge covers cooperative replay/publication checkpoints; it does not preempt a running syscall.

Nine exact-production context/publication tests passed on the pinned toolchain against genuine core, ledger, object-spool and publication implementations, including borrowed callbacks, explicit authority, sticky refusal, recursion, unwind and concurrent access. Twelve repository regressions were added; three full deployment/metadata contracts remain unexecuted. A genuine low-memory Cargo metadata check was killed while compiling real Asupersync; full CLI integration remains unexecuted. No whole-workspace or release qualification is claimed.

## Durable PullPoint control and restart recovery — library implementation (2026-10-28)

The native coordinator can now acknowledge a durable Create intent before connection admission, retain the exact Create SOAP and scoped endpoint before polling, and retain an exact Unsubscribe response with the original parent custody. Zero-poll failure no longer has to lose its subscription source. A cold intent or exact storage retry never grants remote redispatch. The cleanup-only API accepts an independently current owner, sends no Create/PullMessages, rejects reuse of the original Create MessageID before connecting, and preserves the observed remote cleanup state if subsequent terminal storage refuses.

Progress callbacks distinguish a known durable receipt from a refusal to continue. A committed batch and its counters survive a storage-budget refusal; polling stops while independently admitted cleanup remains available. All prior control and event handles survive later cancellation, deadline, publication, cleanup or request-retirement failures.

Bounded control discovery checks both visible roots and canonical ledger references, preserving distinct observations and refusing unexplained missing/corrupt/unledgered records. Existing holds, sensor/import deletion, derivative closure, and tombstone-first restart rules now cover intent/Created/terminal custody; only native-proven deletion permits catalog omission. New durable control records require explicit namespace-correct matching RelatesTo; older optional live-parser behavior remains unchanged. Historical receipts never establish current remote activity or fresh effect authority.

Executed validation: all 28 native TCP coordinator contracts passed against unchanged production coordinator/HTTP/client/SOAP/RTSP source and genuine core/ledger/TUTK plus selected real spool/publication implementations, including twelve new crash-window, cancellation, post-commit, strict-correlation and cleanup-only regressions. Twenty-nine deployment custody/deletion contracts were added and formatted but remain unexecuted. Full Cargo compilation was killed in real Asupersync before project diagnostics; no full workspace, CLI, physical-device or Profile M qualification is claimed. FSS-046 / fss-x4a.11.4 remains open for continuing recovery/qualification work.

## Executable PullPoint recovery commands (2026-10-28)

Native capture now uses the durable control callbacks and progress receipts above. It reports separate intent, Created and Unsubscribe identities/roots, retains Create source before the first poll, stops polling after a post-commit storage refusal, and preserves every known handle outside request retirement and output. Exact existing intent custody never authorizes another Create dispatch.

The CLI adds `control list`, `control inspect` and `control unsubscribe`. Cold listing verifies a complete bounded catalog (default 64, maximum 1024); inspection verifies an exact kind/identity and optional root. Cleanup requires a mandatory selected Created identity/root, fresh explicit owner/plaintext/Unsubscribe approval, matching independent sensor/device/profile/peer/origin/path/subtree/generation pins, current credentials/entropy and a new receive origin. It sends no Create or PullMessages. Its report separates historical remote cleanup success from durable terminal custody and preserves known receipts on failure.

Catalog storage allowance now includes the complete three-root ancestry of every terminal record, while retaining finite history, record, byte, report and time limits. Human reports contain hashes and observed state, with current remote state explicitly unknown. Local deletion of these receipts does not unsubscribe a device.

Validation: seven pure cleanup/capture plan tests passed against the complete production Plan/AuthPlan and actual CLI validation helpers with genuine core/reference protocol dependencies. They cover explicit fresh approvals, action isolation, selected identity/root binding, exact/default canonical arguments, authentication parsing, invalid handles and unchanged legacy capture approval. Independent source reviews found no concrete API/borrow or receipt-preservation defect in capture/control integration. Rustfmt parsed the changed CLI sources. These results do not replace a full CLI runtime or deployment-custody run: Asupersync compilation was SIGKILLed before project diagnostics, and the 29 new deployment custody/deletion contracts plus three bridge/deployment contracts remain unexecuted.

Follow the executable recovery examples and failure semantics in `docs/onvif-metadata.md`. Automatic renewal/reconnect, HTTPS/UsernameToken in this capture lane, RTP metadata and physical-device/Profile M qualification remain open; no full FSS-046 completion or release qualification is claimed.

## Bounded PullPoint renewal with durable custody (2026-10-28)

Native capture now supports explicitly approved `--max-renewals 1..4`; omission
keeps renewal disabled and preserves the existing capture approval bytes. Renewal
uses the original subscription route and requested lifetime, reserves cleanup
time/steps, and cannot extend the original session deadline or poll count. It
requires a new logical request identity and a durable intent before dispatch.
The batch-only library API refuses renewal because it cannot acknowledge control
custody. No renewal failure triggers a new subscription or an automatic retry of
an ambiguous request; one explicitly challenged HTTP Digest retry remains bounded.

Successful and unusable complete renewal responses have immutable, independently
inspectable receipts. HTTP refusal, wrong content type, malformed or uncorrelated
SOAP, and missing completion-clock observations retain their complete private body
without activating a lease. Transport loss leaves the prior intent unresolved.
Progress preserves known durable handles and successful observations across a
late refusal, while stopping further polling. Metadata batches remain linked to
the original Create source and request identity.

`control list` and `control inspect --kind renew-intent|renewed` cold-verify the
exact renewal-attempt parent, original Create ancestry, source, root and ledger.
These records participate in existing sensor/import deletion, holds and
tombstone-first recovery, including unusable response bodies. Reports disclose
hashes and historical observations; current remote state remains unknown.

Eight new native TCP regressions, four durable-custody regressions, two lifecycle
regressions and two CLI admission regressions cover the new contract. Twenty-four
existing exact-source PullPoint wire tests passed on the pinned toolchain.
Rustfmt and scoped whitespace/registry checks passed. The full locked, offline
Cargo check of `fss-onvif-metadata` was killed with SIGKILL while compiling genuine
Asupersync metadata, before reaching project diagnostics; the new native runtime
and deployment suites therefore remain unexecuted at this checkpoint. No full
workspace, device interoperability or release qualification is claimed. Continuous
capture/reconnect, stable owner operation
IDs for ambiguous Create recovery, HTTPS/UsernameToken and RTP metadata remain
open. FSS-046 / fss-x4a.11.4 remains open.


## Retained calibration residual monitoring — scoped implementation

`fss-event calibration monitor` now connects the native frozen-pose monitor to exact retained
JPEG/AVC/HEVC localization custody, original hash-pinned calibration input and a current camera
adoption. It replays the actual native decoder, privacy handling, feature extractor and atlas
matching, then measures those features against the frozen adopted pose. A newly fitted pose
cannot conceal drift by becoming the comparison baseline. Original fit and atlas-reference
exposures/pixels are refused. Exact sensor, image, model, twin, atlas and adoption pins must agree.

The bounded observation reports `pass_under_policy`, `contradicted` or `indeterminate`, with
capture interval, residuals, support, image span and work accounting. Preview publishes nothing;
explicit approval retains the observation, original calibration/input bytes and the complete
native localization replay graph. `monitor-replay` reproduces it without external source files.
Historical replay checks adoption at the observation's publication prefix while still enforcing
current source and privacy custody, so later owner withdrawal does not erase the audit path.
It reports this historical scope explicitly and grants no present calibration currency.

A contradiction recommends a separately approved owner withdrawal using `residual_drift` and
the exact same-sensor evidence capsule. No monitor response automatically changes adoption,
geometry, coverage, calibration generations or effect authority. Existing calibration v1/v2 and
localization receipt bytes remain unchanged. This first slice requires undistorted pinhole
calibration and the retained-localization v1 flat-source scope, and measures one recorded exposure.
Continuous scheduling, physical camera-movement diagnosis and site accuracy remain open.

Validation: the exact production replay-recipe codec test passed against the real `fss-core`
library. Native retained-JPEG lifecycle, original-input compatibility and CLI pin/argument
contracts are added but remain unexecuted because the full reference/runtime build is blocked by
shared memory pressure. Formatting and source checks do not establish integrated execution or
release qualification. See `docs/RETAINED_CALIBRATION_MONITOR.md` for the executable workflow.


## Durable ONVIF cleanup attempts and terminal reconciliation — scoped implementation

Recorded capture and explicit cold cleanup now publish an Unsubscribe intent before dispatch,
binding the original Created receipt, current route/approval, fresh logical request, exact SOAP
request digest and verified cleanup-state witness. Exact custody retries cannot redispatch;
another explicit attempt requires fresh review, request identity and approval. Complete final
HTTP responses reach raw outcome custody before success interpretation, including malformed,
empty, refused and uncorrelated bodies. Transport-admitted completion and known durable handles
survive later clock, cancellation and storage refusals.

`control inspect --kind created` reports the current cleanup witness. `control unsubscribe`
requires it through `--expected-control` and binds it into a separate v2 owner approval. Known
successful raw outcomes or existing successful v1 terminal receipts return `already_unsubscribed`
before credentials, entropy or network work. A missing final marker therefore cannot cause a
second request. A targeted bounded history query verifies selected source closures, with at
most 1024 catalog records and 64 cleanup attempts. The existing hold/deletion owner handles
both new record kinds; deleted custody remains unavailable to reads and exact retries.

Existing successful control formats, metadata recipes, mandatory correlation, bounded renewal,
network ceilings and explicit legacy batch-only capture compatibility remain unchanged. Raw
Create outcomes before semantic validation, stable owner operation IDs for ambiguous Create,
continuous capture/reconnect and device qualification remain open; FSS-046 stays open.

Validation: 24 exact current-production PullPoint wire tests passed with the pinned compiler.
Eight new native TCP regressions, seven new deployment custody/lifecycle regressions and CLI
control-witness admission cases are added but unexecuted under the full-reference build resource
constraint. Scoped formatting, source review and manifest checks do not substitute for that
integrated execution or physical-device qualification. See `docs/onvif-metadata.md` for recovery.

## Stable native ONVIF capture operations and explicit durable authority (2026-10-28)

`fss-onvif-metadata capture --operation-id ID` now consumes a stable owner operation in the existing effect journal before a fresh Create intent can permit network dispatch. Site plus supplied ID determines the internal key; changed owner, effective route/authentication scope, attribution pins or capture limits conflict at that same key. Fresh receive origins, MessageIDs and argument ordering cannot obtain another dispatch. Only the newly reserved live guard can commit, after exact wire intent custody and a fresh observed commit time. Every existing state refuses reuse, including a pre-dispatch crash's Prepared state. The source-free fence survives native ONVIF source deletion.

`control operation --operation-id ID` inspects the fence locally without credentials or network access. Optional `--minimum-journal-root` requires an independently saved root in verified bounded history. Full rollback before an unpinned reservation cannot be detected from that old snapshot alone. Fence snapshots express dispatch intent, while existing control custody owns Create/cleanup observations; the fence does not complete the generic effect obligation or assert current remote state.

The underlying explicit-authority Prepare transition is additive tag 6 under current V3 journal records; prior tags/default preparation behavior remain unchanged. Explicit retries bind the complete intent, authority, obligation and terminal predicate before append. Runtime recovery continues to reject generic preparations outside its richer bound-preparation envelope.

Validation: the pinned compiler built the complete actual fss-core crate and all 169 unit tests passed, including 13 effect tests. The current production-source PullPoint wire target also passed all 24 tests. New real-file durable authority, source-free fence/deletion/cancellation, runtime envelope, CLI argument and native custody-hook tests were added and statically reviewed. Those reference/runtime/CLI targets remain unexecuted: the genuine Asupersync dependency build was killed previously, no usable compiled dependency artifacts exist, and this session's ordinary filesystem remains full. No dependency facades, camera/Profile M qualification or full integrated release pass is claimed.
