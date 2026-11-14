#![forbid(unsafe_code)]
//! Synchronous MCP reference adapter for native reads and durable agent-session continuity.
//! No network listener or second runtime.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, BufRead, Write};

use fss_cli::session_cmd::SessionCommand;
use fss_cli::{ExitIdentity, FssCommand, escape_json_str, execute_fss_with_exit, parse_fss_args};
use fss_reference::deployment_session::{
    MAX_MISSION_BYTES, MAX_NOTE_BYTES, MAX_OBJECTIVE_BYTES, MAX_SESSION_TOKEN_BUDGET,
};

use super::json::{self, MAX_FRAME_BYTES, Value};

const PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_TOOL_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_BUDGET_TOKENS: u64 = 4096;
const MAX_PAGE_ENTRIES: u64 = 4096;
/// Read-only follow/wait calls block at most this long; approved dispatch retains its native deadline.
const MAX_WAIT_MS: u64 = 10_000;

const CORE_TOOLS: &str = r#"{"name":"session_open","description":"AOP-001: open a durable mission-scoped session and its initial workspace in the fixed deployment. Mission and objective are literal text; no mission file is read. Returns the unchanged native fss/1 envelope with session, mission and anchor identities. A retry at the same full head returns the existing session; an advanced head can create a new session. budget_tokens is a cumulative session budget, separate from response view limits.","inputSchema":{"type":"object","properties":{"mission":{"type":"string","minLength":1,"maxLength":8192,"description":"Literal mission statement; at most 8192 UTF-8 bytes, never a file path to read."},"objective":{"type":"string","minLength":1,"maxLength":4096},"view":{"type":"string","enum":["pulse","brief","epistemic_map"]},"budget_tokens":{"type":"integer","minimum":1,"maximum":1000000,"description":"Cumulative session budget; defaults to the selected view's registered maximum."}},"required":["mission","objective"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}},
{"name":"session_resume","description":"AOP-002: verify and resume an existing handoff for the fixed principal. Returns the unchanged native fss/1 envelope and explicitly reports assumptions invalidated by world drift before rebasing the workspace. Native lease, authority, closure and budget checks remain in force. Resuming does not implicitly acknowledge or transfer a follow subscription.","inputSchema":{"type":"object","properties":{"handoff":{"type":"string","minLength":1,"maxLength":128}},"required":["handoff"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}},
{"name":"handoff","description":"AOP-012: publish a root-last native handoff of one existing session in the fixed deployment. Preserves mission, workspace, uncertainty, obligations and native proof handles. Repeated requests at the same full head and semantic state retain their identity; changed state can produce a new handoff. Writes agent continuity state only and grants no effect authority.","inputSchema":{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128},"note":{"type":"string","minLength":1,"maxLength":4096,"description":"Optional literal handoff note, at most 4096 UTF-8 bytes."}},"required":["session"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}},
{"name":"session_orient","description":"Read-only AOP-003: inspect an existing deployment through its anchor-pinned SituationCapsule. Returns the existing fss/1 AgentResponseEnvelope unchanged, including coverage gaps, uncertainty, obligations and affordances. Optional session reads the current situation for that owned durable session, preserving its mission and workspace without rebasing or writing a journal. No affordance is executed.","inputSchema":{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"description":"Optional existing session owned by the fixed principal; omitted for deployment-only orientation."},"view":{"type":"string","enum":["pulse","brief","epistemic_map"]},"budget_tokens":{"type":"integer","minimum":1,"maximum":4096}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
{"name":"explain","description":"Read-only AOP-011: explain one published event, or inspect one exact captured-learning publication under a currently admitted session of the same principal and immutable mission; the source session may be closed. Learning reads preserve the literal candidate, applicability, counterexamples, validation, expiry and uncertainty after verifying complete custody; no original feedback request, promotion or effect is required. Returns the existing native fss/1 AgentResponseEnvelope unchanged. Explicit question=what_changed compares the exact current event revision with its immediately preceding committed revision after immutable metadata custody verification; complete before/after records and field changes are returned without source-media reads or lifecycle/effect changes. Explicit question=what_if computes complete hypothetical declared failure-domain loss from an exact current revision, explicit raw scores and verified calibration counts; the original event and every numerical assumption remain visible, current metadata is revalidated, and missing physical coverage remains a gap.","inputSchema":{"type":"object","properties":{"event_id":{"type":"string","minLength":1,"maxLength":128},"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"learning_root":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71},"view":{"type":"string","enum":["decision_diff","forensic"]},"budget_tokens":{"type":"integer","minimum":1,"maximum":16000},"at":{"type":"string","minLength":1,"maxLength":256,"description":"Event-only exact historical anchor; current restrictions apply."},"custody":{"type":"string","enum":["yes","no"],"description":"Event-only option; selected learning custody is always verified."},"question":{"type":"string","enum":["why","what_changed","what_if"],"description":"Defaults to why. what_changed requires both exact adjacent revision digests. what_if requires one complete inline counterfactual object and an event_id; arbitrary causal interventions and why_not are not admitted."},"from_revision_digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"not":{"const":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"description":"Exact immediately preceding revision digest."},"to_revision_digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"not":{"const":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"description":"Exact current committed revision digest."},"counterfactual":{"description":"A bounded inline caller-declared numerical sensitivity request for one exact retained event revision. The native owner enforces at most 32768 UTF-8 bytes before parsing and after canonical normalization, exact calibration reconstruction, integer token spelling without decimal fractions or exponents, and semantic constraints that JSON Schema cannot express. No path, historical-decision replay, source-custody claim or effect authority is admitted.","type":"object","additionalProperties":false,"required":["schema","event_revision_digest","without_domains","score_calibration","domain_scores_ppm"],"properties":{"schema":{"const":"fss.event_counterfactual_request.v1"},"event_revision_digest":{"type":"string","pattern":"^sha256:(?!0{64}$)[0-9a-f]{64}$","description":"Exact nonzero lowercase SHA-256 content identity.","minLength":71,"maxLength":71},"without_domains":{"type":"array","minItems":1,"maxItems":16,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":256,"pattern":"^[^\\u0000-\\u001f\\u007f-\\u009f]+(?![\\s\\S])","description":"Nonempty control-free declaration identity, at most 256 UTF-8 bytes in the native parser. JSON Schema maxLength is a necessary character bound only and does not replace the stricter byte bound. Exact retained event membership is verified during computation."},"description":"Simultaneous exact contributing declared failure-domain losses. Every selector must be present in domain_scores_ppm and the source event; source/sensor aliases and synthetic common-cause collisions are refused by the owner."},"score_calibration":{"type":"object","additionalProperties":false,"required":["schema","generation","digest","bins"],"properties":{"schema":{"const":"fss.score_calibration.v1"},"generation":{"type":"string","minLength":1,"maxLength":184,"pattern":"^[^\\u0000-\\u001f\\u007f-\\u009f]+(?![\\s\\S])","description":"Caller-declared detector/mode/scene/pipeline calibration generation. The native projection accepts at most 184 UTF-8 bytes so '@' plus the 71-byte digest fits its 256-byte calibrated generation. Character maxLength is only a necessary upper bound."},"digest":{"type":"string","pattern":"^sha256:(?!0{64}$)[0-9a-f]{64}$","description":"Exact nonzero lowercase SHA-256 content identity.","minLength":71,"maxLength":71},"true_positives":{"type":"integer","minimum":1,"maximum":999999},"false_positives":{"type":"integer","minimum":1,"maximum":999999},"prior_log_odds_millibans":{"type":"array","minItems":2,"maxItems":2,"prefixItems":[{"type":"integer","minimum":-100000,"maximum":100000},{"type":"integer","minimum":-100000,"maximum":100000}],"items":false,"description":"Optional computed summary. The owner requires two lexical JSON integers exactly equal to its outward-rounded reconstruction from the bin counts."},"interval":{"const":"wilson_z2_per_bin_not_simultaneous"},"bins":{"type":"array","minItems":1,"maxItems":64,"items":{"type":"object","additionalProperties":false,"required":["lo_ppm","true_positives","false_positives"],"properties":{"lo_ppm":{"type":"integer","minimum":0,"maximum":1000000},"hi_ppm":{"type":"integer","minimum":0,"maximum":1000000},"true_positives":{"type":"integer","minimum":0,"maximum":999999},"false_positives":{"type":"integer","minimum":0,"maximum":999999},"llr_millibans":{"type":"array","minItems":2,"maxItems":2,"prefixItems":[{"type":"integer","minimum":-100000,"maximum":100000},{"type":"integer","minimum":-100000,"maximum":100000}],"items":false,"description":"Optional computed summary. The owner requires two lexical JSON integers exactly equal to its outward-rounded reconstruction from the bin counts."}}},"description":"Bin lower edges start at zero, strictly ascend and cover 0..=1000000. Both positive and negative totals must be nonzero and their sum at most 1000000. Optional hi_ppm and likelihood bounds must reproduce exactly; the native owner verifies these cross-field constraints and the digest."}},"description":"The native fss.score_calibration.v1 counts artifact. Counts-only input or the complete fss-evaluate projection is accepted. Every supplied derived summary is checked, never trusted. Calibration applicability to the event remains an explicit caller assumption."},"domain_scores_ppm":{"type":"object","minProperties":1,"maxProperties":256,"propertyNames":{"type":"string","minLength":1,"maxLength":256,"pattern":"^[^\\u0000-\\u001f\\u007f-\\u009f]+(?![\\s\\S])","description":"Nonempty control-free declaration identity, at most 256 UTF-8 bytes in the native parser. JSON Schema maxLength is a necessary character bound only and does not replace the stricter byte bound. Exact retained event membership is verified during computation."},"additionalProperties":{"type":"integer","minimum":0,"maximum":1000000},"description":"Exactly one explicit JSON integer score for every source event domain on Supports or Contradicts evidence edges. No missing, unused, ordinal or alias entries. The parser rejects numeric strings, decimal fractions and exponent notation even when a JSON Schema validator regards their values as integers. Noncontributing source edges remain unchanged in source_event."},"fusion_policy":{"type":"string","pattern":"^(?:0|-?[1-9][0-9]{0,4}|-?100000),(?:0|-?[1-9][0-9]{0,4}|-?100000),(?:0|-?[1-9][0-9]{0,4}|-?100000)(?![\\s\\S])","default":"1000,0,-1000","description":"Canonical signed decimal alert,retain,reject milliban thresholds, each in [-100000,100000], with reject < retain <= alert. The owner verifies ordering. Fixed remaining policy: two independent supporting clusters, no urgent exception, zero wait and look penalty, no operator confirmation."}}}},"oneOf":[{"required":["event_id"],"not":{"anyOf":[{"required":["session"]},{"required":["learning_root"]}]}},{"required":["session","learning_root"],"not":{"anyOf":[{"required":["event_id"]},{"required":["at"]},{"required":["custody"]}]}}],"additionalProperties":false,"allOf":[{"if":{"required":["question"],"properties":{"question":{"const":"what_changed"}}},"then":{"required":["event_id","from_revision_digest","to_revision_digest"],"not":{"anyOf":[{"required":["session"]},{"required":["learning_root"]},{"required":["at"]},{"required":["custody"]},{"required":["counterfactual"]}]}},"else":{"not":{"anyOf":[{"required":["from_revision_digest"]},{"required":["to_revision_digest"]}]}}},{"if":{"required":["question"],"properties":{"question":{"const":"what_if"}}},"then":{"required":["event_id","counterfactual"],"not":{"anyOf":[{"required":["session"]},{"required":["learning_root"]},{"required":["at"]},{"required":["custody"]},{"required":["from_revision_digest"]},{"required":["to_revision_digest"]}]}},"else":{"not":{"required":["counterfactual"]}}}]},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
{"name":"session_follow","description":"AOP-004: return one exact page of meaningful changes in the unchanged fss/1 envelope. Ordinary follow is read-only; wait_ms bounds synchronous waiting on certified quiet. With session and subscription, retain pending adjacent-history delivery in the agent journal and advance only with its exact acknowledge receipt. Unacknowledged pages survive disconnect and restart. wait_ms also waits at the acknowledged head without a parked journal lock or an implicit acknowledgement; every adjacent history transition returns immediately. Both journals advancing without retained interleaving requires resnapshot; no transition order is invented.","inputSchema":{"type":"object","properties":{"since":{"type":"string","minLength":1,"maxLength":256},"view":{"type":"string","enum":["pulse","brief"]},"max_entries":{"type":"integer","minimum":1,"maximum":4096},"continuation":{"type":"string","minLength":1,"maxLength":256},"wait_ms":{"type":"integer","minimum":1,"maximum":10000},"session":{"type":"string","minLength":1,"maxLength":128},"subscription":{"type":"string","minLength":1,"maxLength":128},"acknowledge":{"type":"string","minLength":71,"maxLength":71}},"required":["since"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
{"name":"query","description":"AOP-005: bounded retained record metadata. Default events; footage returns imported H0 metadata. Native recordings require an operator-bound archive and exact source/clock pins, plus explicit catalog pins or namespace discovery. Choose either decode-clock ticks or an exact retained clock companion and a UTC nanosecond interval. UTC candidates use declared node observation metadata; unannotated windows remain clock_unavailable. Catalog queries perform no source replay or hydration. Trusted clock, camera exposure and physical absence remain unknown. Native FSS envelopes pass through unchanged. Events alone accept historical at; events/footage/tracks/reports support continuation. All 64-bit recording values are exact canonical decimal strings. Decode-clock or retained-clock UTC queries can instead pin up to eight catalogs with catalogs:[{slot,root}]; source/clock scope and request budgets are shared and duplicate window handles retain every membership. Recording discovery verifies all canonical catalog pages in one explicit source/clock namespace without media reads; selected results are complete or refused. UTC discovery also accepts discover_catalogs:true with the exact retained clock companion and UTC bounds; the complete namespace inventory is verified under one allowance, while only selected-page details are projected. UTC session unions accept sessions:[{codec,sensor,stream,generation,source_anchor,receive_clock,decode_clock,time_scale,catalogs:[{slot,root}],clock_slot,clock_root}] with aggregate UTC bounds. Each session preserves independent clock evidence and conditional gaps; all sessions share one budget and complete current deletion checks. ONVIF uses ordered sources:[{kind:xml|rtp,identity,root}], analysis:tracks|lifecycle|zones, and an inline zone_policy only for zones. It never initializes, recovers, writes or locks the deployment. Raw vendor strings and original bytes remain redacted. max_entries bounds every source, frame, object, tracklet and selected analysis row; the complete result is returned or refused, without continuation or physical identity/occupancy/absence claims. Recorder UTC is a distinct mode: replay_root, replay_request, explicit ntp_era and exact utc_start_ns/utc_end_ns strings verify the pinned original AVC/HEVC packet closures only when the server operator launched with --allow-replay-source-verification. Clients cannot grant source reads. Every matching, unknown and source-only row consumes max_query_results (default 32, maximum 128); complete output is limited to 256 KiB or refused. Recorder clock assertions retain rounding uncertainty and do not establish trusted UTC or absence. No original media is disclosed; no publisher lock, recovery or mutation is performed. An explicit retained_import selects completed deployment custody and needs no archive root; the same launcher source-verification grant remains mandatory. QSR requires report_digest for one exact retained screened package-zone report and the separate --allow-qsr-source-verification launcher grant. Optional inline zone_roles annotate area/queue/register zones; lane_stages explicitly orders two to sixteen existing zones. One immutable read owner verifies original encoded evidence and current custody/privacy/deletion without initialization, publisher recovery, locks, inference, pixel decode, network acquisition or publication. It returns complete byte-free epistemic source/frame/zone/sample/dwell/transition/interruption observations and exact handles in the unchanged native cognitive envelope; the protected response must fit 256 KiB or it refuses. Unknown samples remain unknown; observed track counts never certify physical queue length, wait time, service, continuous coverage or absence. No discovery, continuation or at selector. Tracks requires report_digest, an exact model-vocabulary label and the separate --allow-tracks-source-verification launcher grant. It rebuilds the existing native tracker without inference and returns actual matched rows, per-sample confirmation, exact source/model provenance and explicit continuity resets; no predicted-only samples or physical identity claim. Confirmation/miss/IoU recipe values are JSON integers. Reports discovers exact retained detection, zone-report and completed scalar model-run receipt metadata without model, tensor or source-media reads or a source-verification grant. Optional family and source-native declared interval filters apply only after complete bounded index verification. Report discovery max_query_results is a canonical decimal string (1..4096), distinct from recorder result bounds. Both targets preserve protected context, current authority/effect prefixes, exact continuations, one cumulative payload allowance and complete-output refusal at 256 KiB. Discovery does not establish source availability or QSR eligibility. Evidence-hydration expands one exact retained event revision at H0 or H1 through an existing durable session. Require session, exact generation string, event_id, revision_digest, current anchor and level. H1 additionally pins the H0 descriptor_digest; continuation is the complete native cursor JSON string. The server supplies no client-selected grants. It writes only agent session aliases, quoted token charges and replay-protection state; authority/effect/source records remain read-only. Charges synchronize before payload release and are not refunded after a lost response. Non-continuation retries charge again. Open a session with enough cumulative tokens (H0 5000, H1 16000); H2/H3/H4, raw media and source-read grants are not supported by this target. The complete registered hydration objects accompany protected cognitive context, within 256 KiB or payload-free refusal. Existing read-only targets retain their original behavior; the tool-level annotations account for this new durable target. The sources target exposes a complete verified retained capsule inventory through bounded stream pages, exact sensor/stream selection and native continuations. Complete inventory limits apply before filters; protected historical health and deployment context remain visible. No media access, live health, physical coverage, writer lock or recovery is implied.","inputSchema":{"type":"object","properties":{"target":{"type":"string","enum":["events","footage","recordings","onvif","qsr","tracks","reports","evidence-hydration","sources"],"default":"events","description":"events: event records; footage: completed import metadata; recordings: explicitly pinned native AVC/HEVC catalog metadata by decode-clock ticks or retained node-clock UTC candidates. Catalog-set modes union only explicitly selected indexes. onvif: exact retained XML/RTP vendor metadata with tracks, lifecycle or explicitly declared raw-coordinate zone analysis. qsr: complete derived sampled observations over one exact retained screened package-zone report, with separate launcher source-verification authority. tracks: source-verified matched observations over one exact retained detector report and tracking recipe. reports: metadata-only discovery of retained detector and zone-report handles. evidence-hydration: session-owned exact H0/H1 event metadata with durable disclosure charging. sources: metadata-only retained sensor/stream inventory and historical continuity, with current health and source availability explicitly unknown."},"sensor":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$","description":"Footage filter or required exact native recording identity."},"stream":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$","description":"Footage filter or required exact native recording identity."},"event_id":{"type":"string","minLength":1,"maxLength":128},"kind":{"type":"string","enum":["perimeter_breach","covert_approach","sensor_tamper","unknown_presence","benign_routine","unclassified"]},"state":{"type":"string","enum":["hypothesized","witnessed","corroborated","adjudicated","alert_delivered","resolved","indeterminate","rejected"]},"zone":{"type":"string","minLength":1,"maxLength":64},"from_ns":{"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","maxLength":40},"through_ns":{"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","maxLength":40},"max_entries":{"type":"integer","minimum":1,"maximum":32,"description":"Events, footage, tracks and reports page bound, or ONVIF complete semantic-row bound. ONVIF refuses excess without truncation."},"at":{"type":"string","minLength":1,"maxLength":256,"description":"Event-only exact retained historical anchor; mutually exclusive with the current-head anchor precondition. Current deletion restrictions apply. Footage refuses historical at."},"anchor":{"type":"string","minLength":1,"maxLength":256,"description":"Optional exact current deployment token. For recordings this is distinct from source_anchor."},"continuation":{"type":"string","minLength":1,"maxLength":16384,"description":"Existing paginated targets accept their exact token (at most256 bytes). Evidence-hydration accepts the full native receipt cursor JSON string (at most16KiB). Target branches enforce distinct contracts."},"codec":{"type":"string","enum":["avc","hevc"],"description":"Recordings only: exact native codec family."},"catalog_slot":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[a-z0-9][a-z0-9_-]*(?![\\s\\S])","description":"Recordings only: exact publication slot; never a filesystem path."},"catalog_root":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"description":"Recordings only: Exact immutable catalog root."},"source_anchor":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"description":"Recordings only: Historical recording source anchor, independent of current deployment anchor."},"receive_clock":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"description":"Recordings only: Exact historical receive-clock identity."},"decode_clock":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"description":"Recordings only: exact native decode-clock identity, required for both tick and UTC modes; never inferred from UTC."},"generation":{"type":"string","pattern":"^(0|[1-9][0-9]*)$","maxLength":20,"description":"Recordings require a nonzero source generation; evidence-hydration requires the exact retained session generation, including zero. Canonical u64 decimal string."},"start_tick":{"type":"string","pattern":"^(0|[1-9][0-9]*)$","maxLength":20,"description":"Recordings only: Inclusive decode-clock interval start, at most 18446744073709551615."},"end_tick":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":20,"description":"Recordings only: Exclusive interval end, greater than start_tick and at most 18446744073709551615."},"max_hydration_bytes":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":20,"description":"Recordings only: Quoted later whole-window hydration budget, at most 2147483648; this query reads no media payload.","default":"1073741824"},"time_scale":{"type":"integer","minimum":1,"maximum":4294967295,"description":"Recordings only: exact decode-clock ticks per second."},"max_windows":{"type":"integer","minimum":1,"maximum":32,"default":32,"description":"Recordings only: complete result bound. UTC candidates and clock-unavailable windows both consume it; excess refuses without truncation."},"clock_slot":{"type":"string","minLength":1,"maxLength":128,"pattern":"^fssrc1-(avc|hevc)-[0-9a-f]{64}(?![\\s\\S])","description":"Recordings UTC mode only: exact published clock companion slot derived from codec and source/decode scope. Requires clock_root, start_utc_ns and end_utc_ns; excludes tick bounds."},"clock_root":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"description":"Recordings UTC mode only: exact immutable retained clock companion root; no latest lookup or source replay."},"start_utc_ns":{"type":"string","pattern":"^(0|[1-9][0-9]*)$","maxLength":20,"description":"Recordings UTC mode only: inclusive UTC nanoseconds, at most 18446744073709551615. Compares declared closed node observation envelopes; never camera exposure time."},"end_utc_ns":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":20,"description":"Recordings UTC mode only: exclusive UTC nanoseconds, greater than start_utc_ns and at most 18446744073709551615."},"catalogs":{"type":"array","minItems":1,"maxItems":8,"uniqueItems":true,"description":"Recordings only: one to eight exact catalog pins sharing all source/clock pins, with either decode-clock bounds or retained-clock UTC bounds. Mutually exclusive with catalog_slot/catalog_root and discovery. One shared request budget, atomic result, unique-window hydration quote; no ambient discovery.","items":{"type":"object","properties":{"slot":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[a-z0-9][a-z0-9_-]*(?![\\s\\S])","description":"Exact published slot in the explicit catalog set."},"root":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"description":"Exact immutable catalog root in the set."}},"required":["slot","root"],"additionalProperties":false}},"discover_catalogs":{"type":"boolean","const":true,"description":"Recordings only: discover the complete canonical namespace under exact source/decode-clock pins, with either decode-clock or retained-clock UTC bounds. Excludes manual catalog pins; a changed or incompletely indexed namespace refuses."},"sessions":{"type":"array","minItems":1,"maxItems":8,"items":{"type":"object","properties":{"codec":{"type":"string","enum":["avc","hevc"],"description":"Recordings only: exact native codec family."},"sensor":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$","description":"Footage filter or required exact native recording identity."},"stream":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$","description":"Footage filter or required exact native recording identity."},"generation":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":20,"description":"Recordings only: Nonzero source generation, at most 18446744073709551615."},"source_anchor":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"description":"Recordings only: Historical recording source anchor, independent of current deployment anchor."},"receive_clock":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"description":"Recordings only: Exact historical receive-clock identity."},"decode_clock":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"description":"Recordings only: exact native decode-clock identity, required for both tick and UTC modes; never inferred from UTC."},"time_scale":{"type":"integer","minimum":1,"maximum":4294967295,"description":"Recordings only: exact decode-clock ticks per second."},"catalogs":{"type":"array","minItems":1,"maxItems":8,"uniqueItems":true,"description":"Recordings only: one to eight exact catalog pins sharing all source/clock pins, with either decode-clock bounds or retained-clock UTC bounds. Mutually exclusive with catalog_slot/catalog_root and discovery. One shared request budget, atomic result, unique-window hydration quote; no ambient discovery.","items":{"type":"object","properties":{"slot":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[a-z0-9][a-z0-9_-]*(?![\\s\\S])","description":"Exact published slot in the explicit catalog set."},"root":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"description":"Exact immutable catalog root in the set."}},"required":["slot","root"],"additionalProperties":false}},"clock_slot":{"type":"string","minLength":1,"maxLength":128,"pattern":"^fssrc1-(avc|hevc)-[0-9a-f]{64}(?![\\s\\S])","description":"Exact retained clock publication slot for this capture session; the aggregate UTC interval is supplied at query level."},"clock_root":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"description":"Recordings UTC mode only: exact immutable retained clock companion root; no latest lookup or source replay."}},"required":["codec","sensor","stream","generation","source_anchor","receive_clock","decode_clock","time_scale","catalogs","clock_slot","clock_root"],"additionalProperties":false},"description":"Recordings UTC only: one to eight independently pinned capture sessions of the same sensor and stream, possibly different generations or codecs. One aggregate read/output allowance; no inferred clock equivalence. All source/catalog/clock pins are inside each item; legacy top-level recording selectors are forbidden."},"analysis":{"type":"string","enum":["tracks","lifecycle","zones"],"description":"ONVIF only: unchanged vendor tracklets or additive lifecycle/raw-coordinate zone interpretation."},"sources":{"type":"array","minItems":1,"maxItems":32,"uniqueItems":true,"description":"ONVIF only: exact ordered existing sources; source identities must be unique across the complete request. No filesystem path or discovery selector.","items":{"type":"object","properties":{"kind":{"type":"string","enum":["xml","rtp"]},"identity":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"not":{"const":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}},"root":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"not":{"const":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}}},"required":["kind","identity","root"],"additionalProperties":false}},"zone_policy":{"description":"ONVIF zones only: complete inline operator policy; never a file path. Typed semantic policy identity is independent of JSON whitespace or object-key order. Native validation also enforces exact integer spellings, strict min/max and unique zone IDs.","type":"object","additionalProperties":false,"required":["schema","coordinates","zones"],"properties":{"schema":{"const":"fss.onvif_vendor_zone_policy.v1"},"coordinates":{"const":"raw_vendor_object_millionths"},"zones":{"type":"array","minItems":1,"maxItems":16,"items":{"type":"object","additionalProperties":false,"required":["id","scope","module_digest","frame_transform_digest","object_transform_digest","min","max","margin"],"properties":{"id":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[A-Za-z0-9_-]+$","not":{"pattern":"[^A-Za-z0-9_-]"}},"scope":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","not":{"const":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"minLength":71,"maxLength":71},"module_digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","not":{"const":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"minLength":71,"maxLength":71},"frame_transform_digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","not":{"const":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"minLength":71,"maxLength":71},"object_transform_digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","not":{"const":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"minLength":71,"maxLength":71},"min":{"type":"array","minItems":2,"maxItems":2,"items":{"type":"integer","minimum":-1000000000000000,"maximum":1000000000000000}},"max":{"type":"array","minItems":2,"maxItems":2,"items":{"type":"integer","minimum":-1000000000000000,"maximum":1000000000000000}},"margin":{"type":"integer","minimum":0,"maximum":1000000000000000}},"description":"The complete claimed box is expanded by margin before classification. Numeric axis minima/maxima have no implied image orientation. The native parser requires strict min < max on both axes and a unique ID across the complete policy."},"uniqueItems":true}}},"replay_root":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"description":"Exact native replay receipt root."},"replay_request":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"description":"Exact request digest retained by the replay receipt."},"ntp_era":{"type":"integer","minimum":0,"maximum":4294967295,"description":"Explicit caller-selected NTP era; never inferred from the query interval."},"utc_start_ns":{"type":"string","pattern":"^(0|[1-9][0-9]*)$","maxLength":39,"description":"Exact recorder UTC nanoseconds, 0 through year 9999, interpreted with the explicit NTP era. Half-open interval; preserved without floating-point conversion."},"utc_end_ns":{"type":"string","pattern":"^(0|[1-9][0-9]*)$","maxLength":39,"description":"Exact recorder UTC nanoseconds, 0 through year 9999, interpreted with the explicit NTP era. Half-open interval; preserved without floating-point conversion."},"max_query_windows":{"type":"integer","minimum":1,"maximum":64},"max_query_samples":{"type":"integer","minimum":1,"maximum":16384},"max_query_packets":{"type":"integer","minimum":1,"maximum":262144},"max_query_results":{"anyOf":[{"type":"integer","minimum":1,"maximum":128,"default":32,"description":"Complete matching, unknown and source-only row inventory; output overflow refuses the whole result."},{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":4,"default":"4096","description":"Complete supported-family report-index ceiling, 1..4096, applied before family/time filtering and pagination. A smaller filter never bypasses verification or truncates an over-budget index. Native traversal separately admits at most 65536 ledger objects and committed batches."}],"description":"Recorder replay uses an integer row bound; report discovery uses a canonical decimal string complete-index bound. Each target enforces its own type and range."},"max_query_source_bytes":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":20,"description":"Exact canonical decimal bound in 1..2147483648; no floating-point conversion."},"max_query_read_bytes":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":20,"description":"Recorder replay or QSR only: exact canonical decimal whole-request payload-byte ceiling in 1..4294967296. Immutable source modes share this allowance through history, metadata, original encoded evidence and final revalidation; no refill between stages."},"max_query_io_calls":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":20,"description":"Exact canonical decimal bound in 1..4000000; no floating-point conversion."},"retained_import":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"description":"Exact completed destination import identity; excludes external archive/catalog selectors. Original replay pins remain independently required."},"max_query_read_objects":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":20,"description":"Retained recorder replay or QSR only: cumulative payload-read attempts in 1..4000000, including history, original evidence and revalidation; excludes archive max_query_io_calls."},"report_digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"not":{"const":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"description":"Exact retained report identity: screened package-zone report for qsr, original package-detection report for tracks. Never a file path or latest selector."},"zone_roles":{"type":"array","maxItems":16,"uniqueItems":true,"description":"Optional annotations on existing source zones. Native admission requires unique zone IDs and refuses unknown zones or conflicts with lane_stages. Unannotated zones default to area; lane_stage roles are derived only from lane_stages.","items":{"type":"object","additionalProperties":false,"required":["zone","role"],"properties":{"zone":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[A-Za-z0-9_-]+(?![\\s\\S])"},"role":{"enum":["area","queue","register"]}}}},"lane_stages":{"type":"array","maxItems":16,"uniqueItems":true,"anyOf":[{"maxItems":0},{"minItems":2}],"items":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[A-Za-z0-9_-]+(?![\\s\\S])"},"description":"Empty or two to sixteen distinct existing source-zone IDs in explicit lane order. Preserves conservative adjacent-stage endpoint observations and typed interruptions; no crossing time, queue wait, transaction or physical-identity claim."},"label":{"type":"string","minLength":1,"maxLength":512,"pattern":"^[^\u0000-\u001f-]+(?![\\s\\S])","description":"Exact case-sensitive model-vocabulary member. Native admission enforces a 512 UTF-8-byte bound and refuses unknown labels; no class normalization or physical classification is inferred."},"confirmation_hits":{"type":"integer","minimum":1,"maximum":4294967295,"default":2,"description":"Native association hits required for confirmation. The exact resulting value is bound into the analysis and continuation. Confirmation is not corroboration."},"maximum_missed_frames":{"type":"integer","minimum":1,"maximum":4294967295,"default":1,"description":"Native consecutive-miss retirement policy. Missed-frame predictions are not returned as actual observations."},"minimum_iou_ppm":{"type":"integer","minimum":0,"maximum":1000000,"default":100000,"description":"Native predicted-box association threshold in integer parts per million. Actual assigned source rows are preserved without nearby-row substitution."},"family":{"enum":["package_detection_record","package_zone_report","model_invocation_receipt"],"description":"Exact existing cognition family; omission selects all supported families. Detector rows expose the original package-detection report digest accepted by tracks queries. Zone rows retain v1 versus v2 metadata identity; discovery does not certify QSR eligibility. Model rows describe native fss-infer RecordedInference runs and name the stored receipt SHA; model_run.run_identity is the separate native --run-id. Generic executor-activity receipt schemas are outside this catalog. Model, tensor and source payloads are not read or verified."},"session":{"type":"string","minLength":1,"maxLength":128,"description":"Exact retained session. The fixed server principal must own it and its query/hydration/privacy grants must remain live."},"revision_digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"not":{"const":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"description":"Exact current event revision digest returned by query or explain; never a source-media digest."},"level":{"enum":["H0","H1"],"description":"H0 discovers exact identity, availability and prices; H1 delivers a semantic synopsis of retained metadata. No H2/H3/H4 or media disclosure."},"descriptor_digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"not":{"const":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"description":"Exact H0 descriptor digest, required for H1 and progressive continuation."},"budget_tokens":{"type":"integer","minimum":1,"maximum":16000,"description":"Per-request token ceiling. Native conservative quotes are H0=5000 and H1=16000; the session lifetime budget must also suffice. Charge is durable before disclosure."}},"additionalProperties":false,"oneOf":[{"properties":{"target":{"const":"events"},"max_query_results":{"type":"integer","minimum":1,"maximum":128,"default":32,"description":"Complete matching, unknown and source-only row inventory; output overflow refuses the whole result."},"continuation":{"type":"string","minLength":1,"maxLength":256}},"not":{"anyOf":[{"required":["sensor"]},{"required":["stream"]},{"required":["codec"]},{"required":["catalog_slot"]},{"required":["catalog_root"]},{"required":["generation"]},{"required":["source_anchor"]},{"required":["receive_clock"]},{"required":["decode_clock"]},{"required":["time_scale"]},{"required":["start_tick"]},{"required":["end_tick"]},{"required":["max_windows"]},{"required":["max_hydration_bytes"]},{"required":["clock_slot"]},{"required":["clock_root"]},{"required":["start_utc_ns"]},{"required":["end_utc_ns"]},{"required":["catalogs"]},{"required":["discover_catalogs"]},{"required":["sessions"]},{"required":["analysis"]},{"required":["sources"]},{"required":["zone_policy"]},{"required":["replay_root"]},{"required":["replay_request"]},{"required":["ntp_era"]},{"required":["utc_start_ns"]},{"required":["utc_end_ns"]},{"required":["max_query_windows"]},{"required":["max_query_samples"]},{"required":["max_query_packets"]},{"required":["max_query_source_bytes"]},{"required":["max_query_results"]},{"required":["max_query_read_bytes"]},{"required":["max_query_io_calls"]},{"required":["retained_import"]},{"required":["max_query_read_objects"]},{"required":["report_digest"]},{"required":["zone_roles"]},{"required":["lane_stages"]},{"required":["confirmation_hits"]},{"required":["family"]},{"required":["label"]},{"required":["maximum_missed_frames"]},{"required":["minimum_iou_ppm"]},{"required":["session"]},{"required":["revision_digest"]},{"required":["descriptor_digest"]},{"required":["level"]},{"required":["budget_tokens"]}]}},{"properties":{"target":{"const":"footage"},"max_query_results":{"type":"integer","minimum":1,"maximum":128,"default":32,"description":"Complete matching, unknown and source-only row inventory; output overflow refuses the whole result."},"continuation":{"type":"string","minLength":1,"maxLength":256}},"required":["target"],"not":{"anyOf":[{"required":["event_id"]},{"required":["kind"]},{"required":["state"]},{"required":["zone"]},{"required":["at"]},{"required":["codec"]},{"required":["catalog_slot"]},{"required":["catalog_root"]},{"required":["generation"]},{"required":["source_anchor"]},{"required":["receive_clock"]},{"required":["decode_clock"]},{"required":["time_scale"]},{"required":["start_tick"]},{"required":["end_tick"]},{"required":["max_windows"]},{"required":["max_hydration_bytes"]},{"required":["clock_slot"]},{"required":["clock_root"]},{"required":["start_utc_ns"]},{"required":["end_utc_ns"]},{"required":["catalogs"]},{"required":["discover_catalogs"]},{"required":["sessions"]},{"required":["analysis"]},{"required":["sources"]},{"required":["zone_policy"]},{"required":["replay_root"]},{"required":["replay_request"]},{"required":["ntp_era"]},{"required":["utc_start_ns"]},{"required":["utc_end_ns"]},{"required":["max_query_windows"]},{"required":["max_query_samples"]},{"required":["max_query_packets"]},{"required":["max_query_source_bytes"]},{"required":["max_query_results"]},{"required":["max_query_read_bytes"]},{"required":["max_query_io_calls"]},{"required":["retained_import"]},{"required":["max_query_read_objects"]},{"required":["report_digest"]},{"required":["zone_roles"]},{"required":["lane_stages"]},{"required":["confirmation_hits"]},{"required":["family"]},{"required":["label"]},{"required":["maximum_missed_frames"]},{"required":["minimum_iou_ppm"]},{"required":["session"]},{"required":["revision_digest"]},{"required":["descriptor_digest"]},{"required":["level"]},{"required":["budget_tokens"]}]}},{"properties":{"target":{"const":"recordings"},"max_query_results":{"type":"integer","minimum":1,"maximum":128,"default":32,"description":"Complete matching, unknown and source-only row inventory; output overflow refuses the whole result."},"generation":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":20}},"required":["target"],"not":{"anyOf":[{"required":["event_id"]},{"required":["kind"]},{"required":["state"]},{"required":["zone"]},{"required":["from_ns"]},{"required":["through_ns"]},{"required":["max_entries"]},{"required":["at"]},{"required":["continuation"]},{"required":["analysis"]},{"required":["sources"]},{"required":["zone_policy"]},{"required":["report_digest"]},{"required":["zone_roles"]},{"required":["lane_stages"]},{"required":["confirmation_hits"]},{"required":["family"]},{"required":["label"]},{"required":["maximum_missed_frames"]},{"required":["minimum_iou_ppm"]},{"required":["session"]},{"required":["revision_digest"]},{"required":["descriptor_digest"]},{"required":["level"]},{"required":["budget_tokens"]}]},"oneOf":[{"required":["codec","sensor","stream","generation","source_anchor","receive_clock","decode_clock","time_scale","start_tick","end_tick","catalog_slot","catalog_root"],"not":{"anyOf":[{"required":["clock_slot"]},{"required":["clock_root"]},{"required":["start_utc_ns"]},{"required":["end_utc_ns"]},{"required":["catalogs"]},{"required":["discover_catalogs"]},{"required":["sessions"]},{"required":["replay_root"]},{"required":["replay_request"]},{"required":["ntp_era"]},{"required":["utc_start_ns"]},{"required":["utc_end_ns"]},{"required":["max_query_windows"]},{"required":["max_query_samples"]},{"required":["max_query_packets"]},{"required":["max_query_source_bytes"]},{"required":["max_query_results"]},{"required":["max_query_read_bytes"]},{"required":["max_query_io_calls"]},{"required":["retained_import"]},{"required":["max_query_read_objects"]}]}},{"required":["codec","sensor","stream","generation","source_anchor","receive_clock","decode_clock","time_scale","clock_slot","clock_root","start_utc_ns","end_utc_ns","catalog_slot","catalog_root"],"not":{"anyOf":[{"required":["start_tick"]},{"required":["end_tick"]},{"required":["catalogs"]},{"required":["discover_catalogs"]},{"required":["sessions"]},{"required":["replay_root"]},{"required":["replay_request"]},{"required":["ntp_era"]},{"required":["utc_start_ns"]},{"required":["utc_end_ns"]},{"required":["max_query_windows"]},{"required":["max_query_samples"]},{"required":["max_query_packets"]},{"required":["max_query_source_bytes"]},{"required":["max_query_results"]},{"required":["max_query_read_bytes"]},{"required":["max_query_io_calls"]},{"required":["retained_import"]},{"required":["max_query_read_objects"]}]}},{"required":["codec","sensor","stream","generation","source_anchor","receive_clock","decode_clock","time_scale","catalogs","start_tick","end_tick"],"not":{"anyOf":[{"required":["catalog_slot"]},{"required":["catalog_root"]},{"required":["clock_slot"]},{"required":["clock_root"]},{"required":["start_utc_ns"]},{"required":["end_utc_ns"]},{"required":["discover_catalogs"]},{"required":["sessions"]},{"required":["replay_root"]},{"required":["replay_request"]},{"required":["ntp_era"]},{"required":["utc_start_ns"]},{"required":["utc_end_ns"]},{"required":["max_query_windows"]},{"required":["max_query_samples"]},{"required":["max_query_packets"]},{"required":["max_query_source_bytes"]},{"required":["max_query_results"]},{"required":["max_query_read_bytes"]},{"required":["max_query_io_calls"]},{"required":["retained_import"]},{"required":["max_query_read_objects"]}]}},{"required":["codec","sensor","stream","generation","source_anchor","receive_clock","decode_clock","time_scale","discover_catalogs","start_tick","end_tick"],"not":{"anyOf":[{"required":["catalogs"]},{"required":["catalog_slot"]},{"required":["catalog_root"]},{"required":["clock_slot"]},{"required":["clock_root"]},{"required":["start_utc_ns"]},{"required":["end_utc_ns"]},{"required":["sessions"]},{"required":["replay_root"]},{"required":["replay_request"]},{"required":["ntp_era"]},{"required":["utc_start_ns"]},{"required":["utc_end_ns"]},{"required":["max_query_windows"]},{"required":["max_query_samples"]},{"required":["max_query_packets"]},{"required":["max_query_source_bytes"]},{"required":["max_query_results"]},{"required":["max_query_read_bytes"]},{"required":["max_query_io_calls"]},{"required":["retained_import"]},{"required":["max_query_read_objects"]}]}},{"required":["codec","sensor","stream","generation","source_anchor","receive_clock","decode_clock","time_scale","catalogs","clock_slot","clock_root","start_utc_ns","end_utc_ns"],"not":{"anyOf":[{"required":["catalog_slot"]},{"required":["catalog_root"]},{"required":["start_tick"]},{"required":["end_tick"]},{"required":["discover_catalogs"]},{"required":["sessions"]},{"required":["replay_root"]},{"required":["replay_request"]},{"required":["ntp_era"]},{"required":["utc_start_ns"]},{"required":["utc_end_ns"]},{"required":["max_query_windows"]},{"required":["max_query_samples"]},{"required":["max_query_packets"]},{"required":["max_query_source_bytes"]},{"required":["max_query_results"]},{"required":["max_query_read_bytes"]},{"required":["max_query_io_calls"]},{"required":["retained_import"]},{"required":["max_query_read_objects"]}]}},{"required":["codec","sensor","stream","generation","source_anchor","receive_clock","decode_clock","time_scale","discover_catalogs","clock_slot","clock_root","start_utc_ns","end_utc_ns"],"not":{"anyOf":[{"required":["catalogs"]},{"required":["catalog_slot"]},{"required":["catalog_root"]},{"required":["start_tick"]},{"required":["end_tick"]},{"required":["sessions"]},{"required":["replay_root"]},{"required":["replay_request"]},{"required":["ntp_era"]},{"required":["utc_start_ns"]},{"required":["utc_end_ns"]},{"required":["max_query_windows"]},{"required":["max_query_samples"]},{"required":["max_query_packets"]},{"required":["max_query_source_bytes"]},{"required":["max_query_results"]},{"required":["max_query_read_bytes"]},{"required":["max_query_io_calls"]},{"required":["retained_import"]},{"required":["max_query_read_objects"]}]}},{"required":["sessions","start_utc_ns","end_utc_ns"],"not":{"anyOf":[{"required":["codec"]},{"required":["sensor"]},{"required":["stream"]},{"required":["generation"]},{"required":["source_anchor"]},{"required":["receive_clock"]},{"required":["decode_clock"]},{"required":["time_scale"]},{"required":["catalog_slot"]},{"required":["catalog_root"]},{"required":["catalogs"]},{"required":["discover_catalogs"]},{"required":["clock_slot"]},{"required":["clock_root"]},{"required":["start_tick"]},{"required":["end_tick"]},{"required":["replay_root"]},{"required":["replay_request"]},{"required":["ntp_era"]},{"required":["utc_start_ns"]},{"required":["utc_end_ns"]},{"required":["max_query_windows"]},{"required":["max_query_samples"]},{"required":["max_query_packets"]},{"required":["max_query_source_bytes"]},{"required":["max_query_results"]},{"required":["max_query_read_bytes"]},{"required":["max_query_io_calls"]},{"required":["retained_import"]},{"required":["max_query_read_objects"]}]}},{"required":["codec","sensor","stream","generation","source_anchor","receive_clock","decode_clock","time_scale","replay_root","replay_request","ntp_era","utc_start_ns","utc_end_ns"],"not":{"anyOf":[{"required":["catalog_slot"]},{"required":["catalog_root"]},{"required":["catalogs"]},{"required":["sessions"]},{"required":["discover_catalogs"]},{"required":["clock_slot"]},{"required":["clock_root"]},{"required":["start_tick"]},{"required":["end_tick"]},{"required":["start_utc_ns"]},{"required":["end_utc_ns"]},{"required":["max_windows"]},{"required":["max_hydration_bytes"]},{"required":["retained_import"]},{"required":["max_query_read_objects"]}]}},{"required":["codec","sensor","stream","generation","source_anchor","receive_clock","decode_clock","time_scale","replay_root","replay_request","ntp_era","utc_start_ns","utc_end_ns","retained_import"],"not":{"anyOf":[{"required":["catalog_slot"]},{"required":["catalog_root"]},{"required":["catalogs"]},{"required":["sessions"]},{"required":["discover_catalogs"]},{"required":["clock_slot"]},{"required":["clock_root"]},{"required":["start_tick"]},{"required":["end_tick"]},{"required":["start_utc_ns"]},{"required":["end_utc_ns"]},{"required":["max_windows"]},{"required":["max_hydration_bytes"]},{"required":["max_query_io_calls"]}]}}]},{"properties":{"target":{"const":"onvif"},"max_query_results":{"type":"integer","minimum":1,"maximum":128,"default":32,"description":"Complete matching, unknown and source-only row inventory; output overflow refuses the whole result."}},"required":["target","analysis","sources"],"not":{"anyOf":[{"required":["sensor"]},{"required":["stream"]},{"required":["event_id"]},{"required":["kind"]},{"required":["state"]},{"required":["zone"]},{"required":["from_ns"]},{"required":["through_ns"]},{"required":["at"]},{"required":["continuation"]},{"required":["codec"]},{"required":["catalog_slot"]},{"required":["catalog_root"]},{"required":["source_anchor"]},{"required":["receive_clock"]},{"required":["decode_clock"]},{"required":["generation"]},{"required":["start_tick"]},{"required":["end_tick"]},{"required":["max_hydration_bytes"]},{"required":["time_scale"]},{"required":["max_windows"]},{"required":["clock_slot"]},{"required":["clock_root"]},{"required":["start_utc_ns"]},{"required":["end_utc_ns"]},{"required":["catalogs"]},{"required":["discover_catalogs"]},{"required":["sessions"]},{"required":["replay_root"]},{"required":["replay_request"]},{"required":["ntp_era"]},{"required":["utc_start_ns"]},{"required":["utc_end_ns"]},{"required":["max_query_windows"]},{"required":["max_query_samples"]},{"required":["max_query_packets"]},{"required":["max_query_source_bytes"]},{"required":["max_query_results"]},{"required":["max_query_read_bytes"]},{"required":["max_query_io_calls"]},{"required":["retained_import"]},{"required":["max_query_read_objects"]},{"required":["report_digest"]},{"required":["zone_roles"]},{"required":["lane_stages"]},{"required":["confirmation_hits"]},{"required":["family"]},{"required":["label"]},{"required":["maximum_missed_frames"]},{"required":["minimum_iou_ppm"]},{"required":["session"]},{"required":["revision_digest"]},{"required":["descriptor_digest"]},{"required":["level"]},{"required":["budget_tokens"]}]},"oneOf":[{"properties":{"analysis":{"enum":["tracks","lifecycle"]}},"not":{"required":["zone_policy"]}},{"properties":{"analysis":{"const":"zones"}},"required":["zone_policy"]}]},{"properties":{"target":{"const":"qsr"},"max_query_results":{"type":"integer","minimum":1,"maximum":128,"default":32,"description":"Complete matching, unknown and source-only row inventory; output overflow refuses the whole result."}},"required":["target","report_digest"],"propertyNames":{"enum":["target","report_digest","zone_roles","lane_stages","anchor","max_query_read_bytes","max_query_read_objects"]},"not":{"anyOf":[{"required":["sensor"]},{"required":["stream"]},{"required":["event_id"]},{"required":["kind"]},{"required":["state"]},{"required":["zone"]},{"required":["from_ns"]},{"required":["through_ns"]},{"required":["max_entries"]},{"required":["at"]},{"required":["continuation"]},{"required":["codec"]},{"required":["catalog_slot"]},{"required":["catalog_root"]},{"required":["source_anchor"]},{"required":["receive_clock"]},{"required":["decode_clock"]},{"required":["generation"]},{"required":["start_tick"]},{"required":["end_tick"]},{"required":["max_hydration_bytes"]},{"required":["time_scale"]},{"required":["max_windows"]},{"required":["clock_slot"]},{"required":["clock_root"]},{"required":["start_utc_ns"]},{"required":["end_utc_ns"]},{"required":["catalogs"]},{"required":["discover_catalogs"]},{"required":["sessions"]},{"required":["analysis"]},{"required":["sources"]},{"required":["zone_policy"]},{"required":["replay_root"]},{"required":["replay_request"]},{"required":["ntp_era"]},{"required":["utc_start_ns"]},{"required":["utc_end_ns"]},{"required":["max_query_windows"]},{"required":["max_query_samples"]},{"required":["max_query_packets"]},{"required":["max_query_results"]},{"required":["max_query_source_bytes"]},{"required":["max_query_io_calls"]},{"required":["retained_import"]},{"required":["confirmation_hits"]},{"required":["family"]},{"required":["label"]},{"required":["maximum_missed_frames"]},{"required":["minimum_iou_ppm"]},{"required":["session"]},{"required":["revision_digest"]},{"required":["descriptor_digest"]},{"required":["level"]},{"required":["budget_tokens"]}]}},{"properties":{"target":{"const":"tracks"},"report_digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"not":{"const":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"description":"Exact retained fss.package_detection_report.v1 digest, not a canonical record payload, loose path or latest selector. Metadata-only reports discovery returns this handle without granting source verification."},"label":{"type":"string","minLength":1,"maxLength":512,"pattern":"^[^\u0000-\u001f-]+(?![\\s\\S])","description":"Exact case-sensitive model-vocabulary member. Native admission enforces a 512 UTF-8-byte bound and refuses unknown labels; no class normalization or physical classification is inferred."},"confirmation_hits":{"type":"integer","minimum":1,"maximum":4294967295,"default":2,"description":"Native association hits required for confirmation. The exact resulting value is bound into the analysis and continuation. Confirmation is not corroboration."},"maximum_missed_frames":{"type":"integer","minimum":1,"maximum":4294967295,"default":1,"description":"Native consecutive-miss retirement policy. Missed-frame predictions are not returned as actual observations."},"minimum_iou_ppm":{"type":"integer","minimum":0,"maximum":1000000,"default":100000,"description":"Native predicted-box association threshold in integer parts per million. Actual assigned source rows are preserved without nearby-row substitution."},"max_entries":{"type":"integer","minimum":1,"maximum":32,"default":16,"description":"Complete matched observations per page, ordered by native track id then observation display order. All source-frame metadata and source-continuity boundaries remain visible on every page."},"anchor":{"type":"string","minLength":1,"maxLength":256,"description":"Optional exact current deployment authority/effect-history precondition, separate from the historical source anchor."},"continuation":{"type":"string","minLength":1,"maxLength":256,"description":"Exact native continuation returned by the preceding page. It binds complete analysis, current authority/effect prefix, label, recipe, principal, grant privacy/retention scope, page size and read allowance. A changed head requires a fresh query; no offset or silent rebase."},"max_query_read_bytes":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":10,"default":"1073741824","description":"One whole-page payload-byte ceiling, 1..4294967296, covering history, retained metadata, original encoded source verification and final rereads. Failed reads invalidate the remaining balance. Not a filesystem-framing or CPU measurement."},"max_query_read_objects":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":7,"default":"1000000","description":"One whole-page payload-read-attempt ceiling, 1..4000000, shared through final revalidation. Not a filesystem syscall quota; no refill between stages."}},"required":["target","report_digest","label"],"propertyNames":{"enum":["target","report_digest","label","confirmation_hits","maximum_missed_frames","minimum_iou_ppm","max_entries","anchor","continuation","max_query_read_bytes","max_query_read_objects"]}},{"properties":{"target":{"const":"reports"},"family":{"enum":["package_detection_record","package_zone_report","model_invocation_receipt"],"description":"Exact existing cognition family; omission selects all supported families. Detector rows expose the original package-detection report digest accepted by tracks queries. Zone rows retain v1 versus v2 metadata identity; discovery does not certify QSR eligibility. Model rows describe native fss-infer RecordedInference runs and name the stored receipt SHA; model_run.run_identity is the separate native --run-id. Generic executor-activity receipt schemas are outside this catalog. Model, tensor and source payloads are not read or verified."},"from_ns":{"type":"string","pattern":"^(0|-?[1-9][0-9]*)(?![\\s\\S])","maxLength":40,"description":"Optional inclusive lower endpoint as a canonical i128 decimal string. Selects closed overlap with the declaration's source-native validity interval. No UTC conversion, cross-source clock alignment or physical timing claim."},"through_ns":{"type":"string","pattern":"^(0|-?[1-9][0-9]*)(?![\\s\\S])","maxLength":40,"description":"Optional inclusive upper endpoint as a canonical i128 decimal string. Native admission requires from_ns <= through_ns when both are supplied."},"max_entries":{"type":"integer","minimum":1,"maximum":32,"default":16,"description":"Complete report metadata handles per page, in native family then report-digest order."},"anchor":{"type":"string","minLength":1,"maxLength":256,"description":"Optional exact current deployment authority/effect-history precondition. Historical report declarations do not select historical authority."},"continuation":{"type":"string","minLength":1,"maxLength":256,"description":"Exact native continuation from the preceding page, bound to principal, filters, page size, complete verified index, all limits and the current authority/effect prefix. No offset, discovery bypass or silent rebase."},"max_query_read_bytes":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":9,"default":"268435456","description":"Shared metadata payload-byte ceiling, 1..268435456, covering current history, native manifests, retained records/reports and final rereads. Original source media is not read; failed reads invalidate the remaining balance."},"max_query_read_objects":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":5,"default":"65536","description":"Shared metadata payload-read-attempt ceiling, 1..65536, including final revalidation. Not an archive filesystem syscall quota."},"max_query_results":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":4,"default":"4096","description":"Complete supported-family report-index ceiling, 1..4096, applied before family/time filtering and pagination. A smaller filter never bypasses verification or truncates an over-budget index. Native traversal separately admits at most 65536 ledger objects and committed batches."}},"required":["target"],"propertyNames":{"enum":["target","family","from_ns","through_ns","max_entries","anchor","continuation","max_query_read_bytes","max_query_read_objects","max_query_results"]}},{"properties":{"target":{"const":"evidence-hydration"},"session":{"type":"string","minLength":1,"maxLength":128,"description":"Exact retained session. The fixed server principal must own it and its query/hydration/privacy grants must remain live."},"generation":{"type":"string","pattern":"^(0|[1-9][0-9]{0,19})$","maxLength":20,"description":"Exact retained session symbol-table generation as a canonical u64 decimal string, including initial generation zero."},"event_id":{"type":"string","minLength":1,"maxLength":128},"revision_digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"not":{"const":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"description":"Exact current event revision digest returned by query or explain; never a source-media digest."},"anchor":{"type":"string","minLength":1,"maxLength":256,"description":"Required full current authority/effect-history token; a changed head requires explicit session rebase."},"level":{"enum":["H0","H1"],"description":"H0 discovers exact identity, availability and prices; H1 delivers a semantic synopsis of retained metadata. No H2/H3/H4 or media disclosure."},"descriptor_digest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71,"not":{"const":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"description":"Exact H0 descriptor digest, required for H1 and progressive continuation."},"budget_tokens":{"type":"integer","minimum":1,"maximum":16000,"description":"Per-request token ceiling. Native conservative quotes are H0=5000 and H1=16000; the session lifetime budget must also suffice. Charge is durable before disclosure."},"continuation":{"type":"string","minLength":1,"maxLength":16384,"description":"The complete exact receipt.continuation JSON object encoded as a string, including privacyEpoch in both anchors. H1 only. Native durable issuance/consumption verification refuses replay; a bare cursor token is insufficient."}},"required":["target","session","generation","event_id","revision_digest","anchor","level"],"propertyNames":{"enum":["target","session","generation","event_id","revision_digest","anchor","level","descriptor_digest","budget_tokens","continuation"]},"allOf":[{"if":{"properties":{"level":{"const":"H1"}},"required":["level"]},"then":{"required":["descriptor_digest"]}},{"if":{"required":["continuation"]},"then":{"properties":{"level":{"const":"H1"}},"required":["descriptor_digest"]}}]},{"properties":{"target":{"const":"sources"},"max_entries":{"type":"integer","minimum":1,"maximum":32,"default":16,"description":"Complete stream inventory rows per page, ordered by sensor then stream identity."},"anchor":{"type":"string","minLength":1,"maxLength":256,"description":"Optional exact current deployment authority/effect-history precondition. Historical source metadata never selects historical authority."},"continuation":{"type":"string","minLength":1,"maxLength":256,"description":"Exact native continuation from the preceding page, bound to principal, filters, page size, complete verified inventory, all limits and current authority/effect prefix. No offset, discovery bypass or silent rebase."},"max_query_read_bytes":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":9,"default":"268435456","description":"Shared metadata payload-byte ceiling, 1..268435456, covering current history, retained capsule metadata and final rereads. Original source media is not read; failed reads invalidate the remaining balance."},"max_query_read_objects":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":5,"default":"65536","description":"Shared metadata payload-read-attempt ceiling, 1..65536, including final revalidation. Not an archive filesystem syscall quota."},"max_query_results":{"type":"string","pattern":"^[1-9][0-9]*$","maxLength":4,"default":"1024","description":"Complete retained stream-inventory ceiling, 1..1024, applied before sensor/stream filtering and pagination. Filtering never bypasses verification or truncates an over-budget inventory. Native traversal separately bounds ledger objects and capsule metadata."},"sensor":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$","description":"Exact retained sensor identity. Omission selects all sensors. Selection follows complete inventory verification."},"stream":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$","description":"Exact retained stream identity. Sensor and stream filters are conjunctive. Selection follows complete inventory verification."}},"required":["target"],"propertyNames":{"enum":["target","max_entries","anchor","continuation","max_query_read_bytes","max_query_read_objects","max_query_results","sensor","stream"]}}]},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}},
{"name":"investigate","description":"AOP-006: maintain a durable investigation in one existing session. Supports open, inspect, list, activate, cite, assess, set-state, conclude, rebase, readmit and expand. Draft and expansion are literal objects, never files. Mutations require the exact expected case revision; native evidence, authority, deadline and rebase/readmission checks remain in force. Returns the native fss/1 envelope. Ordinary case transitions record cognition only and execute no probe, plan or external effect. Also coordinates native work claims and immutable findings, with exact revision/lease fences and verified retry receipts; these intents grant no effect authority. Explicit probe transitions recover one existing retained-source supervision subscription: complete cognitive context in the explicit case (default, 5000 tokens) or forensic (16000 tokens) view, exact pending receipts, explicit ACK/discard/adjacent advance, cumulative source work and durable quoted session-token charges. No recipe registration, live acquisition, automatic assessment or effect. Optional exact case linkage requires case, expected, hypothesis, side and subscription_state. probe-citation recovers that historical link without source work; missing linkage never authorizes retry.","inputSchema":{"type":"object","oneOf":[{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"type":"string","enum":["open","inspect","list","activate","cite","assess","set-state","conclude","rebase","readmit","expand"]},"draft":{"type":"object","properties":{"caseId":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"question":{"type":"string","minLength":1,"maxLength":8192},"decisionInformed":{"type":"string","minLength":1,"maxLength":1024},"hypotheses":{"type":"array","minItems":2,"maxItems":64,"items":{"type":"object","properties":{"hypothesisId":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"description":{"type":"string","minLength":1,"maxLength":8192},"epistemicState":{"type":"string","enum":["known","estimated","unknown","conflicted","stale","not_observable","redacted","indeterminate","not_applicable"]},"predictions":{"type":"array","maxItems":256,"items":{"type":"string","minLength":1,"maxLength":1024}}},"required":["hypothesisId","description"],"additionalProperties":false}},"knowns":{"type":"array","maxItems":256,"items":{"type":"object","properties":{"statementId":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"text":{"type":"string","minLength":1,"maxLength":8192},"epistemicState":{"type":"string","enum":["known","estimated","unknown","conflicted","stale","not_observable","redacted","indeterminate","not_applicable"]},"basis":{"type":"array","maxItems":256,"items":{"type":"string","minLength":1,"maxLength":1024}}},"required":["statementId","text"],"additionalProperties":false}},"unknowns":{"type":"array","maxItems":256,"items":{"type":"object","properties":{"statementId":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"text":{"type":"string","minLength":1,"maxLength":8192},"epistemicState":{"type":"string","enum":["known","estimated","unknown","conflicted","stale","not_observable","redacted","indeterminate","not_applicable"]},"basis":{"type":"array","maxItems":256,"items":{"type":"string","minLength":1,"maxLength":1024}}},"required":["statementId","text"],"additionalProperties":false}},"discriminators":{"type":"array","maxItems":128,"items":{"type":"object","properties":{"discriminatorId":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"description":{"type":"string","minLength":1,"maxLength":8192},"separates":{"type":"array","maxItems":64,"items":{"type":"string","minLength":1,"maxLength":128},"minItems":2},"expectedOutcomes":{"type":"array","maxItems":64,"items":{"type":"string","minLength":1,"maxLength":1024},"minItems":2}},"required":["discriminatorId","description","separates","expectedOutcomes"],"additionalProperties":false}},"probes":{"type":"array","maxItems":128,"items":{"type":"string","minLength":1,"maxLength":1024}},"stopRules":{"type":"array","maxItems":64,"items":{"type":"string","minLength":1,"maxLength":1024},"minItems":1},"decisionDeadlineNs":{"anyOf":[{"type":"integer"},{"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","maxLength":40}],"description":"Exact signed 128-bit nanoseconds; decimal strings preserve full precision."},"decisionWindowNs":{"anyOf":[{"type":"integer"},{"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","maxLength":40}],"description":"Exact signed 128-bit nanoseconds; decimal strings preserve full precision."}},"required":["caseId","question","decisionInformed","hypotheses","stopRules"],"additionalProperties":false,"oneOf":[{"required":["decisionDeadlineNs"],"not":{"required":["decisionWindowNs"]}},{"required":["decisionWindowNs"],"not":{"required":["decisionDeadlineNs"]}}]},"expansion":{"type":"object","properties":{"hypothesis":{"type":"object","properties":{"hypothesisId":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"description":{"type":"string","minLength":1,"maxLength":8192},"epistemicState":{"type":"string","enum":["known","estimated","unknown","conflicted","stale","not_observable","redacted","indeterminate","not_applicable"]},"predictions":{"type":"array","maxItems":256,"items":{"type":"string","minLength":1,"maxLength":1024}}},"required":["hypothesisId","description"],"additionalProperties":false},"discriminator":{"type":"object","properties":{"discriminatorId":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"description":{"type":"string","minLength":1,"maxLength":8192},"separates":{"type":"array","maxItems":64,"items":{"type":"string","minLength":1,"maxLength":128},"minItems":2},"expectedOutcomes":{"type":"array","maxItems":64,"items":{"type":"string","minLength":1,"maxLength":1024},"minItems":2}},"required":["discriminatorId","description","separates","expectedOutcomes"],"additionalProperties":false},"probe":{"type":"string","minLength":1,"maxLength":1024}},"required":["hypothesis","discriminator","probe"],"additionalProperties":false},"case":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"revision":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"hypothesis":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"evidence":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"side":{"type":"string","enum":["support","contradiction"]},"disposition":{"type":"string","enum":["supported","disfavored","refuted"]},"state":{"type":"string","enum":["awaiting_evidence","awaiting_approval","blocked","indeterminate","cancelled","closed"]},"reason":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"conclusion":{"type":"string","enum":["resolved","refuted"]},"stop_rule":{"type":"string","minLength":1,"maxLength":1024},"assessment":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"residual_unknowns":{"type":"array","maxItems":256,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},"witness":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["session","transition"],"additionalProperties":false,"oneOf":[{"properties":{"transition":{"const":"open"}},"required":["draft"],"propertyNames":{"enum":["session","transition","draft"]}},{"properties":{"transition":{"const":"inspect"}},"required":["case"],"propertyNames":{"enum":["session","transition","case","revision"]}},{"properties":{"transition":{"const":"list"}},"required":[],"propertyNames":{"enum":["session","transition"]}},{"properties":{"transition":{"const":"activate"}},"required":["case","expected"],"propertyNames":{"enum":["session","transition","case","expected"]}},{"properties":{"transition":{"const":"cite"}},"required":["case","expected","hypothesis","evidence","side"],"propertyNames":{"enum":["session","transition","case","expected","hypothesis","evidence","side"]}},{"properties":{"transition":{"const":"assess"}},"required":["case","expected","hypothesis","disposition","evidence"],"propertyNames":{"enum":["session","transition","case","expected","hypothesis","disposition","evidence"]}},{"properties":{"transition":{"const":"set-state"}},"required":["case","expected","state","reason"],"propertyNames":{"enum":["session","transition","case","expected","state","reason"]}},{"properties":{"transition":{"const":"conclude"}},"required":["case","expected","conclusion","stop_rule","assessment","residual_unknowns"],"propertyNames":{"enum":["session","transition","case","expected","conclusion","stop_rule","assessment","residual_unknowns"]}},{"properties":{"transition":{"const":"rebase"}},"required":["case","expected"],"propertyNames":{"enum":["session","transition","case","expected"]}},{"properties":{"transition":{"const":"readmit"}},"required":["case","expected","hypothesis","evidence","side","witness"],"propertyNames":{"enum":["session","transition","case","expected","hypothesis","evidence","side","witness"]}},{"properties":{"transition":{"const":"expand"}},"required":["case","expected","expansion"],"propertyNames":{"enum":["session","transition","case","expected","expansion"]}}]},{"type":"object","oneOf":[{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim"},"case":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"work":{"type":"string","minLength":1,"maxLength":270,"pattern":"^(case|(hypothesis|discriminator|probe):[\\s\\S]{1,256})$","description":"Exact native work spelling: case or <kind>:<literal work item>. The item is bounded to 256 UTF-8 bytes and must exist in the visible case."},"lease_ms":{"type":"integer","minimum":1,"maximum":300000,"default":60000,"description":"Evidence-clock milliseconds, bounded by the native session expiry. Supply an unsigned decimal JSON integer without fractional or exponent notation."},"depends":{"type":"array","maxItems":64,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}}},"required":["session","transition","case","work"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-inspect"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},"required":["session","transition","claim"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-list"}},"required":["session","transition"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-activate"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["session","transition","claim","expected"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-release"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["session","transition","claim","expected"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-expire"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["session","transition","claim","expected"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-progress"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"artifact":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["session","transition","claim","expected","artifact"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-block"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"artifact":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["session","transition","claim","expected","artifact"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-complete"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"result":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["session","transition","claim","expected","result"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-renew"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"lease_ms":{"type":"integer","minimum":1,"maximum":300000,"default":60000,"description":"Evidence-clock milliseconds, bounded by the native session expiry. Supply an unsigned decimal JSON integer without fractional or exponent notation."}},"required":["session","transition","claim","expected"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-reclaim"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"lease_ms":{"type":"integer","minimum":1,"maximum":300000,"default":60000,"description":"Evidence-clock milliseconds, bounded by the native session expiry. Supply an unsigned decimal JSON integer without fractional or exponent notation."}},"required":["session","transition","claim","expected"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-transfer"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"recipient":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},"required":["session","transition","claim","expected","recipient"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"finding"},"case":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"claim":{"type":"string","minLength":1,"maxLength":8192,"description":"Literal statement, at most 8192 UTF-8 bytes; never a host-file path to read."},"state":{"type":"string","enum":["known","estimated","unknown","conflicted","stale","not_observable","redacted","indeterminate","not_applicable"]},"supporting":{"type":"array","maxItems":256,"uniqueItems":true,"items":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"minItems":1},"contradicting":{"type":"array","maxItems":256,"uniqueItems":true,"items":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"hypothesis":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"follow_up":{"type":"array","maxItems":64,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},"disagrees_with":{"type":"array","maxItems":64,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},"supersedes":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},"required":["session","transition","case","claim","state","supporting"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"finding-withdraw"},"finding":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"claim":{"type":"string","minLength":1,"maxLength":8192,"description":"Literal statement, at most 8192 UTF-8 bytes; never a host-file path to read."},"supporting":{"type":"array","maxItems":256,"uniqueItems":true,"items":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"minItems":1}},"required":["session","transition","finding","claim","supporting"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"finding-list"},"case":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},"required":["session","transition"],"additionalProperties":false}]},{"type":"object","oneOf":[{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"probe"},"subscription":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"authority_root":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"view":{"type":"string","enum":["case","forensic"],"default":"case","description":"Explicit output view; full proof-bearing reports may require forensic. Never promoted automatically."}},"required":["session","transition","subscription","authority_root"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"probe-inspect"},"subscription":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"authority_root":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"view":{"type":"string","enum":["case","forensic"],"default":"case","description":"Explicit output view; full proof-bearing reports may require forensic. Never promoted automatically."}},"required":["session","transition","subscription","authority_root"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"probe-ack"},"subscription":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"authority_root":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"receipt":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"view":{"type":"string","enum":["case","forensic"],"default":"case","description":"Explicit output view; full proof-bearing reports may require forensic. Never promoted automatically."}},"required":["session","transition","subscription","authority_root","receipt"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"probe-discard"},"subscription":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"authority_root":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"receipt":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"view":{"type":"string","enum":["case","forensic"],"default":"case","description":"Explicit output view; full proof-bearing reports may require forensic. Never promoted automatically."}},"required":["session","transition","subscription","authority_root","receipt"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"probe-advance"},"subscription":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"authority_root":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"window_index":{"type":"integer","minimum":1,"maximum":31},"after_receipt":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"view":{"type":"string","enum":["case","forensic"],"default":"case","description":"Explicit output view; full proof-bearing reports may require forensic. Never promoted automatically."}},"required":["session","transition","subscription","authority_root","window_index","after_receipt"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"probe"},"subscription":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"authority_root":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"view":{"type":"string","enum":["case","forensic"],"default":"case","description":"Explicit output view; full proof-bearing reports may require forensic. Never promoted automatically."},"case":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"hypothesis":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"side":{"type":"string","enum":["support","contradiction"]},"subscription_state":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["session","transition","subscription","authority_root","case","expected","hypothesis","side","subscription_state"],"additionalProperties":false,"description":"One existing native probe with exact case/hypothesis/predecessor and pre-work subscription-state. Case link is separate from native work and never implies assessment or ACK."},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"probe-citation"},"subscription":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"authority_root":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"view":{"type":"string","enum":["case","forensic"],"default":"case","description":"Explicit output view; full proof-bearing reports may require forensic. Never promoted automatically."},"case":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"hypothesis":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"side":{"type":"string","enum":["support","contradiction"]}},"required":["session","transition","subscription","authority_root","case","expected","hypothesis","side"],"additionalProperties":false,"description":"Exact historical case-link metadata under current case-reader authority; no native source work, retry, relink or original-session renewal."}]}]},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}},
{"name":"wait","description":"Read-only AOP-009: wait, bounded to 10 s, until one effect operation leaves its current state, polling the committed effect journal without writing or locking. Returns the unchanged fss/1 AgentResponseEnvelope carrying the operation receipt; an unchanged operation at the deadline is a partial answer with ERR-OP-TIMEOUT-001 (silence is not completion). Never prepares, commits, resends or cancels anything.","inputSchema":{"type":"object","properties":{"operation_id":{"type":"string","minLength":1,"maxLength":128},"deadline_ms":{"type":"integer","minimum":1,"maximum":10000}},"required":["operation_id","deadline_ms"],"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
{"name":"doctor","description":"Read-only AOP-014 reference diagnosis of the fixed deployment. Returns the existing fss.doctor.v1 report, not an AgentResponseEnvelope. Does not repair, create directories, acquire locks or execute affordances.","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}"#;

fn tools_list() -> String {
    format!(
        "{{\"tools\":[{CORE_TOOLS},{},{},{},{}]}}",
        super::control::PLAN_TOOL,
        super::control::COMMIT_TOOL,
        super::control::CANCEL_TOOL,
        super::feedback::FEEDBACK_TOOL,
    )
    .replace('\n', "")
}

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    New,
    AwaitingInitialized,
    Ready,
}

pub(super) struct Server {
    root: OsString,
    principal: String,
    archive_root: Option<OsString>,
    allow_replay_source_verification: bool,
    allow_qsr_source_verification: bool,
    allow_tracks_source_verification: bool,
    phase: Phase,
}

impl Server {
    pub(super) fn new(root: OsString, principal: String) -> Self {
        Self {
            root,
            principal,
            archive_root: None,
            allow_replay_source_verification: false,
            allow_qsr_source_verification: false,
            allow_tracks_source_verification: false,
            phase: Phase::New,
        }
    }

    /// The launcher canonicalizes this existing directory before serving requests.
    /// Client arguments never supply or replace this binding.
    pub(super) fn with_archive(mut self, archive_root: OsString) -> Self {
        self.archive_root = Some(archive_root);
        self
    }

    /// Launcher-owned source-read grant. Client tool arguments cannot construct this grant.
    pub(super) fn with_replay_source_verification(mut self) -> Self {
        self.allow_replay_source_verification = true;
        self
    }

    /// Separate launcher-owned grant for immutable QSR source verification.
    /// A recorder grant or client request never enables this capability.
    pub(super) fn with_qsr_source_verification(mut self) -> Self {
        self.allow_qsr_source_verification = true;
        self
    }

    /// Separate launcher-owned grant for immutable detector-track source verification.
    pub(super) fn with_tracks_source_verification(mut self) -> Self {
        self.allow_tracks_source_verification = true;
        self
    }

    pub(super) fn handle(&mut self, text: &str) -> Option<String> {
        self.handle_with(text, execute_fss_with_exit)
    }

    fn handle_with(
        &mut self,
        text: &str,
        mut execute: impl FnMut(FssCommand) -> (String, ExitIdentity),
    ) -> Option<String> {
        let value = match json::parse(text) {
            Ok(value) => value,
            Err(()) => return Some(error("null", -32700, "Invalid or over-budget JSON")),
        };
        let Some(request) = value.object() else {
            return Some(error(
                "null",
                -32600,
                "A single JSON-RPC object is required",
            ));
        };
        if request.get("jsonrpc").and_then(Value::text) != Some("2.0") {
            return Some(error("null", -32600, "Invalid JSON-RPC version"));
        }
        let Some(method) = request.get("method").and_then(Value::text) else {
            return Some(error("null", -32600, "A method string is required"));
        };
        let id = match request.get("id") {
            None => {
                // Notifications never invoke a tool, including malformed tools/call notifications.
                if method == "notifications/initialized"
                    && self.phase == Phase::AwaitingInitialized
                    && params(request).is_ok_and(|p| only(p, &["_meta"]))
                {
                    self.phase = Phase::Ready;
                }
                return None;
            }
            Some(Value::Text(id)) if id.len() <= 128 => quote(id),
            Some(Value::Number(id)) if integer_id(id) => id.clone(),
            _ => return Some(error("null", -32600, "Invalid request id")),
        };
        let p = match params(request) {
            Ok(p) => p,
            Err(()) => return Some(error(&id, -32602, "Parameters must be an object")),
        };
        let result = match method {
            "initialize" => self.initialize(p),
            "ping" if only(p, &["_meta"]) => Ok("{}".to_owned()),
            "ping" => Err((-32602, "Unexpected ping parameters")),
            _ if self.phase != Phase::Ready => Err((-32002, "Complete initialization first")),
            "tools/list" if only(p, &["_meta"]) => Ok(tools_list()),
            "tools/list" => Err((-32602, "This complete tool list has no continuation cursor")),
            "tools/call" => self.call(p, &mut execute),
            _ => Err((-32601, "Method not found")),
        };
        Some(match result {
            Ok(result) => format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{result}}}"),
            Err((code, message)) => error(&id, code, message),
        })
    }

    fn initialize(&mut self, p: &BTreeMap<String, Value>) -> RpcResult {
        if self.phase != Phase::New {
            return Err((-32600, "Already initialized"));
        }
        if !only(
            p,
            &["protocolVersion", "capabilities", "clientInfo", "_meta"],
        ) || p
            .get("protocolVersion")
            .and_then(Value::text)
            .is_none_or(str::is_empty)
            || p.get("capabilities").and_then(Value::object).is_none()
        {
            return Err((
                -32602,
                "Expected protocolVersion, capabilities and clientInfo",
            ));
        }
        let info = p
            .get("clientInfo")
            .and_then(Value::object)
            .ok_or((-32602, "Expected clientInfo object"))?;
        if info
            .get("name")
            .and_then(Value::text)
            .is_none_or(str::is_empty)
            || info
                .get("version")
                .and_then(Value::text)
                .is_none_or(str::is_empty)
        {
            return Err((-32602, "Expected clientInfo name and version"));
        }
        self.phase = Phase::AwaitingInitialized;
        Ok(format!(
            "{{\"protocolVersion\":\"{PROTOCOL_VERSION}\",\"capabilities\":{{\"tools\":{{\"listChanged\":false}}}},\"serverInfo\":{{\"name\":\"fss-mcp\",\"version\":\"{}\"}},\"instructions\":\"Local reference adapter, not production-qualified. The launching operator fixes the deployment root, optional native archive root and principal audit label. Recording queries require that archive binding and exact source/catalog pins; they disclose metadata only. Tool results retain existing FSS evidence and uncertainty semantics. Sessions, investigations, claims, findings and explicit durable follow update agent continuity state. Alert controls require native exact approval; plans and recommendations grant no effect authority. After response loss inspect retained operations with wait and follow native reconciliation guidance before acting again. No remote authentication or in-flight cancellation is implemented.\"}}",
            env!("CARGO_PKG_VERSION")
        ))
    }

    fn call(
        &self,
        p: &BTreeMap<String, Value>,
        execute: &mut impl FnMut(FssCommand) -> (String, ExitIdentity),
    ) -> RpcResult {
        if !only(p, &["name", "arguments", "_meta"]) {
            return Err((-32602, "Unexpected tool call field"));
        }
        let name = p
            .get("name")
            .and_then(Value::text)
            .ok_or((-32602, "Expected tool name"))?;
        let empty = BTreeMap::new();
        let args = match p.get("arguments") {
            None => &empty,
            Some(Value::Object(args)) => args,
            _ => return Err((-32602, "Tool arguments must be an object")),
        };
        if name == "investigate" {
            let transition = args
                .get("transition")
                .and_then(Value::text)
                .ok_or((-32602, "Expected investigation transition"))?;
            let command = if super::coordination::selects(transition) {
                super::coordination::command(&self.root, &self.principal, args)?
            } else {
                super::investigate::command(&self.root, &self.principal, args)?
            };
            return execute_admitted(command, execute);
        }
        if matches!(name, "plan" | "commit" | "cancel") {
            let command = super::control::command(name, &self.root, &self.principal, args)?;
            return execute_admitted(command, execute);
        }
        if name == "feedback" {
            let command = super::feedback::command(&self.root, &self.principal, args)?;
            return execute_admitted(command, execute);
        }
        let mut argv = match name {
            "session_open" => {
                if !only(args, &["mission", "objective", "view", "budget_tokens"]) {
                    return Err((-32602, "Unexpected session-open argument or scope override"));
                }
                let mission = bounded_text(args.get("mission"), MAX_MISSION_BYTES)?;
                let objective = bounded_text(args.get("objective"), MAX_OBJECTIVE_BYTES)?;
                let mut argv = self.session_args("open");
                // The literal-only canonical option never stats or reads a mission-named file.
                argv.push(format!("--mission-text={mission}").into());
                argv.push(format!("--objective={objective}").into());
                if let Some(value) = args.get("view") {
                    let view = bounded_text(Some(value), 32)?;
                    if !matches!(view, "pulse" | "brief" | "epistemic_map") {
                        return Err((-32602, "Unsupported session view"));
                    }
                    argv.push(format!("--view={view}").into());
                }
                if let Some(value) = args.get("budget_tokens") {
                    let budget = positive_integer(value, MAX_SESSION_TOKEN_BUDGET)?;
                    argv.push(format!("--budget-tokens={budget}").into());
                }
                argv
            }
            "session_resume" => {
                if !only(args, &["handoff"]) {
                    return Err((
                        -32602,
                        "Unexpected session-resume argument or scope override",
                    ));
                }
                let handoff = bounded_text(args.get("handoff"), 128)?;
                let mut argv = self.session_args("resume");
                argv.push(format!("--handoff={handoff}").into());
                argv
            }
            "handoff" => {
                if !only(args, &["session", "note"]) {
                    return Err((-32602, "Unexpected handoff argument or scope override"));
                }
                let session = bounded_text(args.get("session"), 128)?;
                let mut argv = self.base_args("handoff");
                argv.push(format!("--session={session}").into());
                if let Some(value) = args.get("note") {
                    let note = bounded_text(Some(value), MAX_NOTE_BYTES)?;
                    argv.push(format!("--note={note}").into());
                }
                argv
            }
            "session_orient" => {
                if !only(args, &["session", "view", "budget_tokens"]) {
                    return Err((-32602, "Unexpected orientation argument"));
                }
                let mut argv = self.base_args("orient");
                if let Some(value) = args.get("session") {
                    let session = bounded_text(Some(value), 128)?;
                    argv.push(format!("--session={session}").into());
                }
                if let Some(view) = args.get("view") {
                    let view = view.text().ok_or((-32602, "Expected view string"))?;
                    if !matches!(view, "pulse" | "brief" | "epistemic_map") {
                        return Err((-32602, "Unsupported orientation view"));
                    }
                    argv.push(format!("--view={view}").into());
                }
                if let Some(value) = args.get("budget_tokens") {
                    let n = positive_integer(value, MAX_BUDGET_TOKENS)?;
                    argv.push(format!("--budget-tokens={n}").into());
                }
                argv
            }
            "explain" => {
                if !only(
                    args,
                    &[
                        "event_id",
                        "session",
                        "learning_root",
                        "view",
                        "budget_tokens",
                        "custody",
                        "at",
                        "question",
                        "from_revision_digest",
                        "to_revision_digest",
                        "counterfactual",
                    ],
                ) {
                    return Err((-32602, "Unexpected explanation argument"));
                }
                let mut argv = self.base_args("explain");
                let question = match args.get("question") {
                    None => "why",
                    Some(value) => value
                        .text()
                        .filter(|value| matches!(*value, "why" | "what_changed" | "what_if"))
                        .ok_or((-32602, "Explanation question must be why, what_changed or what_if"))?,
                };
                if args.contains_key("question") {
                    argv.push(format!("--question={question}").into());
                }
                if question != "what_if" && args.contains_key("counterfactual") {
                    return Err((-32602, "Counterfactual input requires question what_if"));
                }
                if question == "what_if" {
                    if [
                        "session", "learning_root", "at", "custody",
                        "from_revision_digest", "to_revision_digest",
                    ].iter().any(|key| args.contains_key(*key)) {
                        return Err((-32602, "what_if requires current event metadata and one inline scenario"));
                    }
                    let event = bounded_text(args.get("event_id"), 128)?;
                    let value = args.get("counterfactual")
                        .filter(|value| value.object().is_some())
                        .ok_or((-32602, "what_if requires a complete counterfactual object"))?;
                    let scenario = counterfactual_argument(value)?;
                    argv.push(format!("--event-id={event}").into());
                    argv.push(format!("--counterfactual={scenario}").into());
                } else if question == "what_changed" {
                    if ["session", "learning_root", "at", "custody"]
                        .iter()
                        .any(|key| args.contains_key(*key))
                    {
                        return Err((
                            -32602,
                            "what_changed requires current adjacent event metadata without historical, learning or custody options",
                        ));
                    }
                    let event = bounded_text(args.get("event_id"), 128)?;
                    argv.push(format!("--event-id={event}").into());
                    for (field, flag) in [
                        ("from_revision_digest", "from-revision-digest"),
                        ("to_revision_digest", "to-revision-digest"),
                    ] {
                        let value = bounded_text(args.get(field), 71)?;
                        argv.push(format!("--{flag}={value}").into());
                    }
                } else if let Some(root) = args.get("learning_root") {
                    if ["event_id", "at", "custody"]
                        .iter()
                        .any(|key| args.contains_key(*key))
                    {
                        return Err((
                            -32602,
                            "Learning inspection cannot use event-only arguments",
                        ));
                    }
                    let root = bounded_text(Some(root), 71)?;
                    let session = bounded_text(args.get("session"), 128)?;
                    argv.push(format!("--learning-root={root}").into());
                    argv.push(format!("--session={session}").into());
                } else {
                    if args.contains_key("session") {
                        return Err((
                            -32602,
                            "Learning inspection requires learning_root and session",
                        ));
                    }
                    let event = bounded_text(args.get("event_id"), 128)?;
                    argv.push(format!("--event-id={event}").into());
                    if let Some(value) = args.get("at") {
                        let token = bounded_text(Some(value), 256)?;
                        argv.push(format!("--at={token}").into());
                    }
                    if let Some(custody) = args.get("custody") {
                        let custody = custody.text().ok_or((-32602, "Expected custody string"))?;
                        if !matches!(custody, "yes" | "no") {
                            return Err((-32602, "Unsupported custody option"));
                        }
                        argv.push(format!("--custody={custody}").into());
                    }
                }
                if question != "what_changed"
                    && ["from_revision_digest", "to_revision_digest"]
                        .iter()
                        .any(|key| args.contains_key(*key))
                {
                    return Err((
                        -32602,
                        "Revision comparison digests require question what_changed",
                    ));
                }
                let view = if let Some(value) = args.get("view") {
                    let name = value.text().ok_or((-32602, "Expected view string"))?;
                    let view = match name {
                        "decision_diff" => fss_core::AgentView::DecisionDiff,
                        "forensic" => fss_core::AgentView::Forensic,
                        _ => return Err((-32602, "Unsupported explanation view")),
                    };
                    argv.push(format!("--view={name}").into());
                    view
                } else {
                    fss_core::AgentView::DecisionDiff
                };
                if let Some(value) = args.get("budget_tokens") {
                    let n = positive_integer(value, u64::from(view.maximum_tokens()))?;
                    argv.push(format!("--budget-tokens={n}").into());
                }
                argv
            }
            "session_follow" => {
                if !only(
                    args,
                    &[
                        "since",
                        "view",
                        "max_entries",
                        "continuation",
                        "wait_ms",
                        "session",
                        "subscription",
                        "acknowledge",
                    ],
                ) {
                    return Err((-32602, "Unexpected follow argument"));
                }
                let since = bounded_text(args.get("since"), 256)?;
                let mut argv = self.base_args("follow");
                argv.push(format!("--since={since}").into());
                if let Some(view) = args.get("view") {
                    let view = view.text().ok_or((-32602, "Expected view string"))?;
                    if !matches!(view, "pulse" | "brief") {
                        return Err((-32602, "Unsupported follow view"));
                    }
                    argv.push(format!("--view={view}").into());
                }
                if let Some(value) = args.get("max_entries") {
                    let n = positive_integer(value, MAX_PAGE_ENTRIES)?;
                    argv.push(format!("--max-entries={n}").into());
                }
                if let Some(value) = args.get("continuation") {
                    let token = bounded_text(Some(value), 256)?;
                    argv.push(format!("--continuation={token}").into());
                }
                if let Some(value) = args.get("wait_ms") {
                    let n = positive_integer(
                        value,
                        fss_reference::agent_follow::wait::MAX_FOLLOW_WAIT_MS,
                    )?;
                    argv.push(format!("--wait-ms={n}").into());
                }
                for (field, option, maximum) in [
                    ("session", "--session", 128),
                    ("subscription", "--subscription", 128),
                    ("acknowledge", "--acknowledge", 71),
                ] {
                    if let Some(value) = args.get(field) {
                        let text = bounded_text(Some(value), maximum)?;
                        argv.push(format!("{option}={text}").into());
                    }
                }
                // The canonical parser and follow engine validate spelling, lineage, binding,
                // freshness, stream identity and the wait/continuation exclusion. The transport
                // never manufactures an anchor or renews a lease.
                argv
            }
            "query" if args.get("target").and_then(Value::text) == Some("onvif") => {
                super::onvif::arguments(args, self.base_args("query"))?
            }
            "query" if args.get("target").and_then(Value::text) == Some("qsr") => {
                super::qsr::arguments(
                    args,
                    self.allow_qsr_source_verification,
                    self.base_args("query"),
                )?
            }
            "query" if args.get("target").and_then(Value::text) == Some("recordings") => {
                super::recordings::arguments(
                    args,
                    self.archive_root.as_deref(),
                    self.allow_replay_source_verification,
                    self.base_args("query"),
                )?
            }
            "query" if args.get("target").and_then(Value::text) == Some("tracks") => {
                super::tracks::arguments(
                    args,
                    self.allow_tracks_source_verification,
                    self.base_args("query"),
                )?
            }
            "query" if args.get("target").and_then(Value::text) == Some("reports") => {
                super::report_catalog::arguments(args, self.base_args("query"))?
            }
            "query" if args.get("target").and_then(Value::text) == Some("sources") => {
                super::sources::arguments(args, self.base_args("query"))?
            }
            "query" if args.get("target").and_then(Value::text) == Some("evidence-hydration") => {
                super::event_hydration::arguments(args, self.base_args("query"))?
            }
            "query" => {
                if !only(
                    args,
                    &[
                        "target",
                        "sensor",
                        "stream",
                        "event_id",
                        "kind",
                        "state",
                        "zone",
                        "from_ns",
                        "through_ns",
                        "max_entries",
                        "anchor",
                        "at",
                        "continuation",
                    ],
                ) {
                    return Err((-32602, "Unexpected query argument or scope override"));
                }
                let mut argv = self.base_args("query");
                for (key, flag, bound) in [
                    ("target", "target", 7),
                    ("sensor", "sensor", 128),
                    ("stream", "stream", 128),
                    ("event_id", "event-id", 128),
                    ("kind", "kind", 64),
                    ("state", "state", 64),
                    ("zone", "zone", 64),
                    ("from_ns", "from-ns", 40),
                    ("through_ns", "through-ns", 40),
                    ("anchor", "anchor", 256),
                    ("at", "at", 256),
                    ("continuation", "continuation", 256),
                ] {
                    if let Some(value) = args.get(key) {
                        let value = bounded_text(Some(value), bound)?;
                        // Inline values remain data; the native CLI parser validates every
                        // target, field combination, enum, integer, interval and token without
                        // a parallel interpretation. In particular historical at is event-only.
                        argv.push(format!("--{flag}={value}").into());
                    }
                }
                if let Some(value) = args.get("max_entries") {
                    let count = positive_integer(
                        value,
                        u64::from(fss_reference::agent_query::MAX_QUERY_ENTRIES),
                    )?;
                    argv.push(format!("--max-entries={count}").into());
                }
                argv
            }
            "wait" => {
                if !only(args, &["operation_id", "deadline_ms"]) {
                    return Err((-32602, "Unexpected wait argument"));
                }
                let operation = bounded_text(args.get("operation_id"), 128)?;
                let deadline = positive_integer(
                    args.get("deadline_ms")
                        .ok_or((-32602, "Expected deadline_ms integer"))?,
                    MAX_WAIT_MS,
                )?;
                let mut argv = self.base_args("wait");
                argv.push(format!("--operation={operation}").into());
                argv.push(format!("--deadline-ms={deadline}").into());
                argv
            }
            "doctor" => {
                if !args.is_empty() {
                    return Err((-32602, "Doctor accepts no scope overrides"));
                }
                self.base_args("doctor")
            }
            _ => return Err((-32602, "Unknown or unavailable tool")),
        };
        if name != "doctor" {
            argv.push(format!("--principal={}", self.principal).into());
        }
        let command = parse_fss_args(argv)
            .map_err(|_| (-32602, "Arguments refused by the canonical CLI parser"))?;
        execute_admitted(command, execute)
    }

    fn session_args(&self, subcommand: &str) -> Vec<OsString> {
        let mut argv = self.base_args("session");
        argv.insert(1, subcommand.into());
        argv
    }

    fn base_args(&self, command: &str) -> Vec<OsString> {
        vec![
            command.into(),
            "--json".into(),
            "--root".into(),
            self.root.clone(),
        ]
    }
}

/// Every tool, including typed authored intents, passes the same closed native command clamp.
fn execute_admitted(
    command: FssCommand,
    execute: &mut impl FnMut(FssCommand) -> (String, ExitIdentity),
) -> RpcResult {
    // A final typed clamp remains even if command parsing gains new operations.
    if !matches!(
        command,
        FssCommand::Orient(_)
            | FssCommand::Explain(_)
            | FssCommand::Follow(_)
            | FssCommand::Query(_)
            | FssCommand::FootageQuery(_)
            | FssCommand::OnvifQuery(_)
            | FssCommand::QsrQuery(_)
            | FssCommand::TracksQuery(_)
            | FssCommand::ReportCatalogQuery(_)
            | FssCommand::SourcesQuery(_)
            | FssCommand::EventHydrationQuery(_)
            | FssCommand::RecordingQuery(_)
            | FssCommand::RecordingReplayQuery(_)
            | FssCommand::RetainedRecordingReplayQuery(_)
            | FssCommand::RecordingSetQuery(_)
            | FssCommand::RecordingDiscoveryQuery(_)
            | FssCommand::RecordingUtcQuery(_)
            | FssCommand::RecordingUtcSetQuery(_)
            | FssCommand::RecordingUtcDiscoveryQuery(_)
            | FssCommand::RecordingUtcSessionsQuery(_)
            | FssCommand::Investigate(_)
            | FssCommand::Probe(_)
            | FssCommand::Claim(_)
            | FssCommand::Finding(_)
            | FssCommand::Feedback(_)
            | FssCommand::Doctor(_)
    ) && !matches!(
        &command,
        FssCommand::Effect(effect)
            if matches!(
                effect.as_ref(),
                fss_cli::effect_cmd::EffectCommand::Plan(_)
                    | fss_cli::effect_cmd::EffectCommand::Close(_)
                    | fss_cli::effect_cmd::EffectCommand::Mission(_)
                    | fss_cli::effect_cmd::EffectCommand::Commit(_)
                    | fss_cli::effect_cmd::EffectCommand::Reconcile(_)
                    | fss_cli::effect_cmd::EffectCommand::Cancel(_)
                    | fss_cli::effect_cmd::EffectCommand::CancelSession(_)
                    | fss_cli::effect_cmd::EffectCommand::Wait(_)
            )
    ) && !matches!(
        &command,
        FssCommand::Session(
            SessionCommand::Open(_) | SessionCommand::Handoff(_) | SessionCommand::Resume(_)
        )
    ) {
        return Err((-32603, "Admitted command boundary refused dispatch"));
    }
    let (output, exit) = execute(command);
    Ok(tool_result(&output, exit.code != 0))
}

type RpcResult = Result<String, (i32, &'static str)>;

fn params(request: &BTreeMap<String, Value>) -> Result<&BTreeMap<String, Value>, ()> {
    // The static empty map avoids allocations on notification and ping paths.
    static EMPTY: BTreeMap<String, Value> = BTreeMap::new();
    match request.get("params") {
        None => Ok(&EMPTY),
        Some(Value::Object(p)) if p.get("_meta").is_none_or(|v| v.object().is_some()) => Ok(p),
        _ => Err(()),
    }
}

/// Serialize already bounded transport values without changing integer precision. The shared
/// native parser then verifies and normalizes the complete inline numerical assumptions.
fn counterfactual_argument(value: &Value) -> Result<String, (i32, &'static str)> {
    fn encode(value: &Value, out: &mut String) {
        match value {
            Value::Null => out.push_str("null"),
            Value::Boolean(value) => out.push_str(if *value { "true" } else { "false" }),
            Value::Number(value) => out.push_str(value),
            Value::Text(value) => out.push_str(&quote(value)),
            Value::Array(values) => {
                out.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 { out.push(','); }
                    encode(value, out);
                }
                out.push(']');
            }
            Value::Object(values) => {
                out.push('{');
                for (index, (key, value)) in values.iter().enumerate() {
                    if index != 0 { out.push(','); }
                    out.push_str(&quote(key));
                    out.push(':');
                    encode(value, out);
                }
                out.push('}');
            }
        }
    }
    let mut input = String::new();
    encode(value, &mut input);
    fss_cli::event_counterfactual::EventCounterfactualRequest::parse(&input)
        .map(|request| request.canonical_request_json())
        .map_err(|_| (-32602, "Invalid bounded event counterfactual assumptions"))
}

fn only(fields: &BTreeMap<String, Value>, names: &[&str]) -> bool {
    fields.keys().all(|key| names.contains(&key.as_str()))
}

fn positive_integer(value: &Value, maximum: u64) -> Result<u64, (i32, &'static str)> {
    let Value::Number(text) = value else {
        return Err((-32602, "Expected positive integer"));
    };
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err((-32602, "Expected positive integer"));
    }
    text.parse::<u64>()
        .ok()
        .filter(|n| *n > 0 && *n <= maximum)
        .ok_or((-32602, "Integer is outside the admitted budget"))
}

fn bounded_text(value: Option<&Value>, maximum: usize) -> Result<&str, (i32, &'static str)> {
    value
        .and_then(Value::text)
        .filter(|s| !s.is_empty() && s.len() <= maximum)
        .ok_or((-32602, "Expected a non-empty bounded token string"))
}

fn integer_id(text: &str) -> bool {
    // Never round IDs through f64. Integer spelling is preserved even beyond IEEE-754 precision.
    text.parse::<i64>().is_ok() && !text.contains(['.', 'e', 'E'])
}

fn quote(text: &str) -> String {
    format!("\"{}\"", escape_json_str(text))
}

fn error(id: &str, code: i32, message: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":{code},\"message\":{}}}}}",
        quote(message)
    )
}

fn tool_result(output: &str, failed: bool) -> String {
    let (output, failed) = if output.len() > MAX_TOOL_OUTPUT_BYTES {
        (
            "FSS response exceeded the MCP byte ceiling. No response was truncated. Native state or an effect may already be committed. Inspect retained operations with wait and follow native reconciliation or retry guidance before further action. Request a smaller view or page.",
            true,
        )
    } else {
        (output, failed)
    };
    format!(
        "{{\"content\":[{{\"type\":\"text\",\"text\":{}}}],\"isError\":{failed}}}",
        quote(output)
    )
}

fn read_frame(reader: &mut impl BufRead) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unterminated MCP frame",
                ))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |at| at + 1);
        if take > MAX_FRAME_BYTES - bytes.len() {
            // Terminate rather than allocate or drain an unbounded attacker-controlled line.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP frame exceeds byte ceiling",
            ));
        }
        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            return Ok(Some(bytes));
        }
    }
}

pub(super) fn serve(
    server: &mut Server,
    mut input: impl BufRead,
    mut output: impl Write,
) -> io::Result<()> {
    while let Some(frame) = read_frame(&mut input)? {
        let response = match std::str::from_utf8(&frame) {
            Ok(text) => server.handle(text),
            Err(_) => Some(error("null", -32700, "Invalid UTF-8")),
        };
        if let Some(response) = response {
            output.write_all(response.as_bytes())?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
    const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;

    fn server() -> Server {
        Server::new(
            "/owner/deployment".into(),
            "principal:local-operator".to_owned(),
        )
    }

    fn ready() -> Server {
        let mut server = server();
        assert!(
            server
                .handle(INIT)
                .is_some_and(|r| r.contains(PROTOCOL_VERSION))
        );
        assert_eq!(server.handle(READY), None);
        server
    }

    #[test]
    fn investigation_dispatch_is_native_scoped_and_notification_safe() {
        let mut server = ready();
        let expected = r#"{"operation":"investigate","decisionFingerprint":"sha256:unchanged","payload":{"unknowns":["coverage unavailable"]}}"#;
        let call = r#"{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"investigate","arguments":{"session":"session:owner","transition":"list"}}}"#;
        let mut calls = 0;
        let response = server.handle_with(call, |command| {
            calls += 1;
            let FssCommand::Investigate(args) = command else {
                unreachable!("investigate must use its native typed command");
            };
            assert_eq!(args.root, std::path::PathBuf::from("/owner/deployment"));
            assert_eq!(args.principal.as_str(), "principal:local-operator");
            assert_eq!(args.session.as_str(), "session:owner");
            assert_eq!(
                args.action,
                fss_reference::deployment_session::investigation::CaseAction::List
            );
            (expected.to_owned(), ExitIdentity::AGENT_REFUSED)
        });
        assert!(response.is_some_and(|text| {
            text.contains(&quote(expected)) && text.contains("\"isError\":true")
        }));
        assert_eq!(calls, 1);
        for request in [
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"investigate","arguments":{"session":"session:owner","transition":"activate","case":"case:one","expected":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}}"#,
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"investigate","arguments":{"session":"session:owner","transition":"open","draft":{}}}}"#,
        ] {
            assert_eq!(
                server.handle_with(request, |_| {
                    calls += 1;
                    (String::new(), ExitIdentity::SUCCESS)
                }),
                None
            );
        }
        for extra in [
            r#","root":"/outside""#,
            r#","principal":"principal:other""#,
            r#","case_file":"/private/intent""#,
            r#","draft":{}"#,
        ] {
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{{"name":"investigate","arguments":{{"session":"session:owner","transition":"list"{extra}}}}}}}"#
            );
            assert!(
                server
                    .handle_with(&request, |_| {
                        calls += 1;
                        (String::new(), ExitIdentity::SUCCESS)
                    })
                    .is_some_and(|reply| reply.contains("-32602"))
            );
        }
        assert_eq!(calls, 1);
    }

    #[test]
    fn coordination_dispatch_preserves_native_scope_and_refusals() {
        let mut server = ready();
        let expected = r#"{"operation":"investigate","decisionFingerprint":"sha256:unchanged","payload":{"conflicts":["retained"]}}"#;
        let mut calls = 0;
        for transition in ["claim-list", "finding-list"] {
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":32,"method":"tools/call","params":{{"name":"investigate","arguments":{{"session":"session:owner","transition":{}}}}}}}"#,
                quote(transition)
            );
            let response = server.handle_with(&request, |command| {
                calls += 1;
                match command {
                    FssCommand::Claim(args) if transition == "claim-list" => {
                        assert_eq!(args.root, std::path::PathBuf::from("/owner/deployment"));
                        assert_eq!(args.request.principal.as_str(), "principal:local-operator");
                        assert_eq!(args.request.session_id.as_str(), "session:owner");
                        assert!(matches!(
                            args.request.action,
                            fss_reference::deployment_session::claims::ClaimAction::List
                        ));
                    }
                    FssCommand::Finding(args) if transition == "finding-list" => {
                        assert_eq!(args.root, std::path::PathBuf::from("/owner/deployment"));
                        assert_eq!(args.request.principal.as_str(), "principal:local-operator");
                        assert_eq!(args.request.session_id.as_str(), "session:owner");
                        assert!(matches!(
                            args.request.action,
                            fss_reference::deployment_session::findings::FindingAction::List {
                                case_id: None
                            }
                        ));
                    }
                    _ => unreachable!("coordination must use the exact native typed command"),
                }
                (expected.to_owned(), ExitIdentity::AGENT_REFUSED)
            });
            assert!(response.is_some_and(
                |text| text.contains(&quote(expected)) && text.contains("\"isError\":true")
            ));
            let notification = request.replace("\"id\":32,", "");
            assert_eq!(
                server.handle_with(&notification, |_| {
                    calls += 1;
                    (String::new(), ExitIdentity::SUCCESS)
                }),
                None
            );
            for extra in [
                r#","root":"/outside""#,
                r#","principal":"principal:other""#,
                r#","grant":"effect""#,
                r#","draft":{}"#,
            ] {
                let invalid = format!(
                    r#"{{"jsonrpc":"2.0","id":33,"method":"tools/call","params":{{"name":"investigate","arguments":{{"session":"session:owner","transition":{}{extra}}}}}}}"#,
                    quote(transition)
                );
                assert!(
                    server
                        .handle_with(&invalid, |_| {
                            calls += 1;
                            (String::new(), ExitIdentity::SUCCESS)
                        })
                        .is_some_and(|reply| reply.contains("-32602"))
                );
            }
        }
        assert_eq!(calls, 2);
    }

    #[test]
    fn investigation_discovery_advertises_exact_actions_without_effect_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        use fss_cli::json_input::{self as input, Value as Input};
        use std::collections::BTreeSet;

        let discovery = input::parse(&tools_list())?;
        let tool = discovery
            .object()
            .and_then(|root| root.get("tools"))
            .and_then(Input::array)
            .ok_or("tool list")?
            .iter()
            .filter_map(Input::object)
            .find(|tool| tool.get("name").and_then(Input::text) == Some("investigate"))
            .ok_or("investigate tool")?;
        let families = tool
            .get("inputSchema")
            .and_then(Input::object)
            .and_then(|schema| schema.get("oneOf"))
            .and_then(Input::array)
            .ok_or("investigation intent families")?;
        assert_eq!(families.len(), 3);
        let mut transitions = BTreeSet::new();
        let mut probe_shapes = BTreeSet::new();
        for (index, family) in families.iter().enumerate() {
            let family = family.object().ok_or("intent family")?;
            let variants = family
                .get("oneOf")
                .and_then(Input::array)
                .ok_or("action variants")?;
            assert_eq!(variants.len(), [11, 15, 7][index]);
            if index == 0 {
                assert_eq!(
                    family.get("additionalProperties").and_then(Input::boolean),
                    Some(false)
                );
                let properties = family
                    .get("properties")
                    .and_then(Input::object)
                    .ok_or("case properties")?;
                for forbidden in ["root", "principal", "case_file", "expansion_file", "grant"] {
                    assert!(!properties.contains_key(forbidden), "{forbidden}");
                }
            }
            for variant in variants {
                let variant = variant.object().ok_or("variant")?;
                let properties = variant
                    .get("properties")
                    .and_then(Input::object)
                    .ok_or("variant properties")?;
                let transition = properties
                    .get("transition")
                    .and_then(Input::object)
                    .and_then(|value| value.get("const"))
                    .and_then(Input::text)
                    .ok_or("transition")?;
                let inserted = transitions.insert(transition);
                if index == 2 && transition == "probe" {
                    let required = variant
                        .get("required")
                        .and_then(Input::array)
                        .ok_or("probe required fields")?
                        .iter()
                        .map(|field| field.text().ok_or("probe field"))
                        .collect::<Result<BTreeSet<_>, _>>()?;
                    assert!(probe_shapes.insert(required), "duplicate probe shape");
                } else {
                    assert!(inserted, "duplicate transition {transition}");
                }
                if index >= 1 {
                    assert_eq!(
                        variant.get("additionalProperties").and_then(Input::boolean),
                        Some(false)
                    );
                    for forbidden in ["root", "principal", "case_file", "expansion_file", "grant"] {
                        assert!(!properties.contains_key(forbidden), "{forbidden}");
                    }
                }
            }
        }
        assert_eq!(
            probe_shapes,
            BTreeSet::from([
                BTreeSet::from(["session", "transition", "subscription", "authority_root"]),
                BTreeSet::from([
                    "session",
                    "transition",
                    "subscription",
                    "authority_root",
                    "case",
                    "expected",
                    "hypothesis",
                    "side",
                    "subscription_state",
                ]),
            ])
        );
        assert_eq!(
            transitions,
            BTreeSet::from([
                "open",
                "expand",
                "inspect",
                "list",
                "rebase",
                "readmit",
                "activate",
                "cite",
                "assess",
                "set-state",
                "conclude",
                "claim",
                "claim-inspect",
                "claim-list",
                "claim-activate",
                "claim-progress",
                "claim-block",
                "claim-complete",
                "claim-release",
                "claim-renew",
                "claim-expire",
                "claim-transfer",
                "claim-reclaim",
                "finding",
                "finding-withdraw",
                "finding-list",
                "probe",
                "probe-inspect",
                "probe-ack",
                "probe-discard",
                "probe-advance",
                "probe-citation",
            ])
        );
        let annotations = tool
            .get("annotations")
            .and_then(Input::object)
            .ok_or("annotations")?;
        for key in [
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        ] {
            assert_eq!(annotations.get(key).and_then(Input::boolean), Some(false));
        }
        Ok(())
    }

    #[test]
    fn session_open_keeps_literal_text_scope_and_cumulative_budget() {
        let mut server = ready();
        let mission = "/owner/private-note\n--principal=principal:other";
        let objective = "Retain uncertainty and recover after a disconnect.";
        let expected = r#"{"operation":"session.open","sessionId":"session:opened","payload":{"coverage":"not_observable"}}"#;
        let mut calls = 0;
        for (extra, view, budget) in [
            (
                "",
                fss_core::AgentView::Brief,
                u64::from(fss_core::AgentView::Brief.maximum_tokens()),
            ),
            (
                r#","view":"epistemic_map","budget_tokens":1000000"#,
                fss_core::AgentView::EpistemicMap,
                MAX_SESSION_TOKEN_BUDGET,
            ),
        ] {
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{{"name":"session_open","arguments":{{"mission":{},"objective":{}{extra}}}}}}}"#,
                quote(mission),
                quote(objective)
            );
            let response = server.handle_with(&request, |command| {
                calls += 1;
                let FssCommand::Session(SessionCommand::Open(args)) = command else {
                    unreachable!("session open must use the native session command");
                };
                assert_eq!(args.root, std::path::PathBuf::from("/owner/deployment"));
                assert_eq!(args.principal.as_str(), "principal:local-operator");
                assert_eq!(args.mission, mission);
                assert_eq!(args.objective, objective);
                assert_eq!(args.view, view);
                assert_eq!(args.budget_tokens, budget);
                (expected.to_owned(), ExitIdentity::SUCCESS)
            });
            assert!(response.is_some_and(|text| {
                text.contains(&quote(expected)) && text.contains("\"isError\":false")
            }));
        }
        assert_eq!(calls, 2);

        let conflict = parse_fss_args(
            [
                "session",
                "open",
                "--json",
                "--root=/owner/deployment",
                "--mission=/owner/private-note",
                "--mission-text=literal",
                "--objective=Inspect retained coverage",
            ]
            .map(OsString::from),
        );
        assert!(conflict.is_err_and(|error| {
            error
                .to_string()
                .contains("choose exactly one of --mission or --mission-text")
        }));
    }

    #[test]
    fn session_handoff_and_resume_preserve_native_identity_and_refusals() {
        let mut server = ready();
        let note = "Keep \"coverage unknown\" explicit.\n--root=/other";
        let expected = r#"{"operation":"handoff","payload":{"handoffId":"handoff:retained"},"proofPointers":["sha256:unchanged"]}"#;
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{{"name":"handoff","arguments":{{"session":"session:owner","note":{}}}}}}}"#,
            quote(note)
        );
        let mut calls = 0;
        let response = server.handle_with(&request, |command| {
            calls += 1;
            let FssCommand::Session(SessionCommand::Handoff(args)) = command else {
                unreachable!("handoff must use the native session command");
            };
            assert_eq!(args.root, std::path::PathBuf::from("/owner/deployment"));
            assert_eq!(args.principal.as_str(), "principal:local-operator");
            assert_eq!(args.session.as_str(), "session:owner");
            assert_eq!(args.note.as_deref(), Some(note));
            (expected.to_owned(), ExitIdentity::SUCCESS)
        });
        assert!(response.is_some_and(|text| {
            text.contains(&quote(expected)) && text.contains("\"isError\":false")
        }));

        let expected = r#"{"operation":"session.resume","outcome":"refused","errorId":"ERR-AGENT-HANDOFF-INVALID-001","payload":null}"#;
        let response = server.handle_with(
            r#"{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"session_resume","arguments":{"handoff":"handoff:retained"}}}"#,
            |command| {
                calls += 1;
                let FssCommand::Session(SessionCommand::Resume(args)) = command else {
                    unreachable!("resume must use the native session command");
                };
                assert_eq!(args.root, std::path::PathBuf::from("/owner/deployment"));
                assert_eq!(args.principal.as_str(), "principal:local-operator");
                assert_eq!(args.handoff.as_str(), "handoff:retained");
                (expected.to_owned(), ExitIdentity::AGENT_REFUSED)
            },
        );
        assert!(response.is_some_and(|text| {
            text.contains(&quote(expected)) && text.contains("\"isError\":true")
        }));
        assert_eq!(calls, 2);
    }

    #[test]
    fn session_lifecycle_refuses_unowned_scope_and_never_executes_notifications() {
        let mut server = ready();
        let mut calls = 0;
        let mut refused = vec![
            ("session_open", r#"{"mission":"literal"}"#.to_owned()),
            ("session_open", r#"{"objective":"literal"}"#.to_owned()),
            (
                "session_open",
                r#"{"mission":true,"objective":"literal"}"#.to_owned(),
            ),
            (
                "session_open",
                r#"{"mission":"literal","objective":""}"#.to_owned(),
            ),
            (
                "session_open",
                r#"{"mission":"literal","objective":"literal","root":"/other"}"#.to_owned(),
            ),
            (
                "session_open",
                r#"{"mission":"literal","objective":"literal","principal":"principal:other"}"#
                    .to_owned(),
            ),
            (
                "session_open",
                r#"{"mission":"literal","objective":"literal","mission_file":"/other"}"#.to_owned(),
            ),
            (
                "session_open",
                r#"{"mission":"literal","objective":"literal","capabilities":["effect:commit"]}"#
                    .to_owned(),
            ),
            (
                "session_open",
                r#"{"mission":"literal","objective":"literal","view":"forensic"}"#.to_owned(),
            ),
            (
                "session_open",
                r#"{"mission":"literal","objective":"literal","budget_tokens":0}"#.to_owned(),
            ),
            (
                "session_open",
                r#"{"mission":"literal","objective":"literal","budget_tokens":1000001}"#.to_owned(),
            ),
            (
                "session_open",
                r#"{"mission":"literal","objective":"literal","budget_tokens":1e3}"#.to_owned(),
            ),
            (
                "session_open",
                r#"{"mission":"literal","objective":"literal","budget_tokens":"1000"}"#.to_owned(),
            ),
            ("handoff", r#"{"session":"--root=/other"}"#.to_owned()),
            (
                "handoff",
                r#"{"session":"session:owner","note":""}"#.to_owned(),
            ),
            (
                "handoff",
                r#"{"session":"session:owner","root":"/other"}"#.to_owned(),
            ),
            (
                "handoff",
                r#"{"session":"session:owner","principal":"principal:other"}"#.to_owned(),
            ),
            ("session_resume", r#"{"handoff":""}"#.to_owned()),
            (
                "session_resume",
                r#"{"handoff":"handoff:owner","root":"/other"}"#.to_owned(),
            ),
            (
                "session_resume",
                r#"{"handoff":"handoff:owner","principal":"principal:other"}"#.to_owned(),
            ),
        ];
        refused.push((
            "session_open",
            format!(
                r#"{{"mission":{},"objective":"literal"}}"#,
                quote(&"x".repeat(MAX_MISSION_BYTES + 1))
            ),
        ));
        refused.push((
            "session_open",
            format!(
                r#"{{"mission":"literal","objective":{}}}"#,
                quote(&"x".repeat(MAX_OBJECTIVE_BYTES + 1))
            ),
        ));
        refused.push((
            "handoff",
            format!(
                r#"{{"session":"session:owner","note":{}}}"#,
                quote(&"x".repeat(MAX_NOTE_BYTES + 1))
            ),
        ));
        for (name, arguments) in refused {
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":23,"method":"tools/call","params":{{"name":{},"arguments":{arguments}}}}}"#,
                quote(name)
            );
            let response = server.handle_with(&request, |_| {
                calls += 1;
                ("{}".to_owned(), ExitIdentity::SUCCESS)
            });
            assert!(
                response.is_some_and(|text| text.contains("-32602")),
                "{name}: {arguments}"
            );
        }
        for (name, arguments) in [
            (
                "session_open",
                r#"{"mission":"literal","objective":"literal","budget_tokens":100000}"#,
            ),
            ("handoff", r#"{"session":"session:owner","note":"literal"}"#),
            ("session_resume", r#"{"handoff":"handoff:owner"}"#),
        ] {
            let request = format!(
                r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":{},"arguments":{arguments}}}}}"#,
                quote(name)
            );
            let response = server.handle_with(&request, |_| {
                calls += 1;
                ("{}".to_owned(), ExitIdentity::SUCCESS)
            });
            assert_eq!(response, None);
        }
        assert_eq!(calls, 0);
    }

    #[test]
    fn session_lifecycle_discovery_preserves_native_bounds_and_retry_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        use fss_cli::json_input::{self as input, Value as Input};

        let discovery = input::parse(&tools_list())?;
        let tools = discovery
            .object()
            .and_then(|object| object.get("tools"))
            .and_then(Input::array)
            .ok_or("tool list")?;
        assert_eq!(tools.len(), 14);
        for name in ["session_open", "session_resume", "handoff"] {
            let tool = tools
                .iter()
                .filter_map(Input::object)
                .find(|tool| tool.get("name").and_then(Input::text) == Some(name))
                .ok_or("session lifecycle tool")?;
            let annotations = tool
                .get("annotations")
                .and_then(Input::object)
                .ok_or("tool annotations")?;
            for field in [
                "readOnlyHint",
                "destructiveHint",
                "idempotentHint",
                "openWorldHint",
            ] {
                assert_eq!(
                    annotations.get(field).and_then(Input::boolean),
                    Some(false),
                    "{name}: {field}"
                );
            }
            let schema = tool
                .get("inputSchema")
                .and_then(Input::object)
                .ok_or("tool input schema")?;
            assert_eq!(
                schema.get("additionalProperties").and_then(Input::boolean),
                Some(false)
            );
            let properties = schema
                .get("properties")
                .and_then(Input::object)
                .ok_or("tool properties")?;
            assert!(!properties.contains_key("root"));
            assert!(!properties.contains_key("principal"));
            if name == "session_open" {
                let budget = properties
                    .get("budget_tokens")
                    .and_then(Input::object)
                    .ok_or("session budget")?;
                assert_eq!(
                    budget.get("maximum").and_then(Input::integer),
                    Some(i128::from(MAX_SESSION_TOKEN_BUDGET))
                );
                let mission = properties
                    .get("mission")
                    .and_then(Input::object)
                    .ok_or("literal mission")?;
                assert_eq!(
                    mission.get("maxLength").and_then(Input::integer),
                    Some(MAX_MISSION_BYTES as i128)
                );
            }
        }
        Ok(())
    }

    #[test]
    fn query_dispatch_preserves_native_filters_precision_and_scope() {
        let mut server = ready();
        let token = format!("anchor:{}:0:none:{}", "a".repeat(16), "b".repeat(64));
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"query","arguments":{{"kind":"unclassified","zone":"door","from_ns":"-170141183460469231731687303715884105728","through_ns":"170141183460469231731687303715884105727","max_entries":1,"anchor":{},"continuation":"continuation:page-2"}}}}}}"#,
            quote(&token)
        );
        let mut calls = 0;
        let response = server.handle_with(&request, |command| {
            calls += 1;
            let FssCommand::Query(args) = command else {
                unreachable!("not the native query command");
            };
            assert_eq!(args.root, std::path::PathBuf::from("/owner/deployment"));
            assert_eq!(args.request.principal.as_str(), "principal:local-operator");
            assert_eq!(
                args.request.filter.kind,
                Some(fss_core::EventKind::Unclassified)
            );
            assert_eq!(args.request.filter.zone.as_deref(), Some("door"));
            assert_eq!(args.request.filter.from_ns, Some(i128::MIN));
            assert_eq!(args.request.filter.through_ns, Some(i128::MAX));
            assert_eq!(
                args.request
                    .expected_anchor
                    .as_ref()
                    .map(|anchor| anchor.as_str()),
                Some(token.as_str())
            );
            assert_eq!(
                args.request.continuation.as_deref(),
                Some("continuation:page-2")
            );
            assert_eq!(args.request.max_entries, 1);
            (
                "unchanged semantic answer".to_owned(),
                ExitIdentity::SUCCESS,
            )
        });
        assert_eq!(calls, 1);
        assert!(response.is_some_and(|text| text.contains(&quote("unchanged semantic answer"))));
    }

    #[test]
    fn footage_query_dispatch_equals_native_command_and_preserves_exact_response()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut server = ready();
        let token = format!("anchor:{}:0:none:{}", "a".repeat(16), "b".repeat(64));
        let native = parse_fss_args(
            [
                "query",
                "--json",
                "--root",
                "/owner/deployment",
                "--principal",
                "principal:local-operator",
                "--target",
                "footage",
                "--sensor",
                "sensor:register",
                "--stream",
                "stream:main",
                "--from-ns",
                "-170141183460469231731687303715884105728",
                "--through-ns",
                "170141183460469231731687303715884105727",
                "--max-entries",
                "32",
                "--anchor",
                &token,
                "--continuation",
                "continuation:footage-page-2",
            ]
            .map(OsString::from),
        )?;
        assert!(matches!(native, FssCommand::FootageQuery(_)));
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{{"name":"query","arguments":{{"target":"footage","sensor":"sensor:register","stream":"stream:main","from_ns":"-170141183460469231731687303715884105728","through_ns":"170141183460469231731687303715884105727","max_entries":32,"anchor":{},"continuation":"continuation:footage-page-2"}}}}}}"#,
            quote(&token)
        );
        let expected = r#"{"schema":"fss.agent_response_envelope.v1","warnings":["declared clock basis only"],"payload":{"hydrationLevel":"H0","mediaBytes":false}}"#;
        let mut calls = 0;
        let response = server.handle_with(&request, |command| {
            calls += 1;
            assert_eq!(command, native);
            (expected.to_owned(), ExitIdentity::SUCCESS)
        });
        assert_eq!(calls, 1);
        assert!(response.is_some_and(|text| {
            text.contains(&quote(expected)) && text.contains("\"isError\":false")
        }));
        Ok(())
    }

    #[test]
    fn explicit_event_target_matches_the_default_native_command()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut server = ready();
        let native = parse_fss_args(
            [
                "query",
                "--json",
                "--root",
                "/owner/deployment",
                "--principal",
                "principal:local-operator",
                "--kind",
                "unclassified",
                "--max-entries",
                "1",
            ]
            .map(OsString::from),
        )?;
        assert!(matches!(native, FssCommand::Query(_)));
        let mut calls = 0;
        for arguments in [
            r#"{"kind":"unclassified","max_entries":1}"#,
            r#"{"target":"events","kind":"unclassified","max_entries":1}"#,
        ] {
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":91,"method":"tools/call","params":{{"name":"query","arguments":{arguments}}}}}"#
            );
            let response = server.handle_with(&request, |command| {
                calls += 1;
                assert_eq!(command, native);
                ("event metadata".to_owned(), ExitIdentity::SUCCESS)
            });
            assert!(response.is_some_and(|text| text.contains("\"isError\":false")));
        }
        assert_eq!(calls, 2);
        Ok(())
    }

    #[test]
    fn footage_query_invalid_targets_combinations_and_values_never_execute() {
        let mut server = ready();
        let mut calls = 0;
        for arguments in [
            r#"{"target":"Footage"}"#,
            r#"{"target":"unknown"}"#,
            r#"{"target":"footage "}"#,
            r#"{"target":null}"#,
            r#"{"target":1}"#,
            r#"{"sensor":"sensor:register"}"#,
            r#"{"stream":"stream:main"}"#,
            r#"{"target":"events","sensor":"sensor:register"}"#,
            r#"{"target":"events","stream":"stream:main"}"#,
            r#"{"target":"footage","event_id":"event:one"}"#,
            r#"{"target":"footage","kind":"unclassified"}"#,
            r#"{"target":"footage","state":"hypothesized"}"#,
            r#"{"target":"footage","zone":"door"}"#,
            r#"{"target":"footage","at":"anchor:aaaaaaaaaaaaaaaa:0:none:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#,
            r#"{"target":"footage","sensor":""}"#,
            r#"{"target":"footage","stream":"stream:main\nsecret"}"#,
            r#"{"target":"footage","sensor":["sensor:register"]}"#,
            r#"{"target":"footage","stream":false}"#,
            r#"{"target":"footage","from_ns":9007199254740993}"#,
            r#"{"target":"footage","through_ns":"170141183460469231731687303715884105728"}"#,
            r#"{"target":"footage","from_ns":"-170141183460469231731687303715884105729"}"#,
            r#"{"target":"footage","from_ns":"-0"}"#,
            r#"{"target":"footage","from_ns":"01"}"#,
            r#"{"target":"footage","from_ns":"1e3"}"#,
            r#"{"target":"footage","from_ns":"2","through_ns":"1"}"#,
            r#"{"target":"footage","max_entries":0}"#,
            r#"{"target":"footage","max_entries":33}"#,
            r#"{"target":"footage","max_entries":1.0}"#,
            r#"{"target":"footage","max_entries":"1"}"#,
            r#"{"target":"footage","anchor":"latest"}"#,
            r#"{"target":"footage","root":"/other"}"#,
            r#"{"target":"footage","principal":"principal:other"}"#,
            r#"{"target":"footage","hydrate":"H3"}"#,
            r#"{"target":"footage","target":"events"}"#,
        ] {
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":92,"method":"tools/call","params":{{"name":"query","arguments":{arguments}}}}}"#
            );
            let response = server.handle_with(&request, |_| {
                calls += 1;
                (String::new(), ExitIdentity::SUCCESS)
            });
            assert!(
                response.is_some_and(|text| text.contains("\"error\"")),
                "{arguments}"
            );
        }
        assert_eq!(
            server.handle_with(
                r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"query","arguments":{"target":"footage","sensor":"sensor:register"}}}"#,
                |_| {
                    calls += 1;
                    (String::new(), ExitIdentity::SUCCESS)
                },
            ),
            None
        );
        assert_eq!(calls, 0);
    }

    #[test]
    fn query_discovery_names_typed_targets_and_preserves_scope_bounds()
    -> Result<(), Box<dyn std::error::Error>> {
        use fss_cli::json_input::{self as input, Value as Input};

        let discovery = input::parse(&tools_list())?;
        let tool = discovery
            .object()
            .and_then(|value| value.get("tools"))
            .and_then(Input::array)
            .ok_or("tool list")?
            .iter()
            .filter_map(Input::object)
            .find(|tool| tool.get("name").and_then(Input::text) == Some("query"))
            .ok_or("query tool")?;
        let annotations = tool
            .get("annotations")
            .and_then(Input::object)
            .ok_or("query annotations")?;
        assert_eq!(
            annotations.get("readOnlyHint").and_then(Input::boolean),
            Some(false)
        );
        assert_eq!(
            annotations.get("destructiveHint").and_then(Input::boolean),
            Some(false)
        );
        assert_eq!(
            annotations.get("idempotentHint").and_then(Input::boolean),
            Some(false)
        );
        let schema = tool
            .get("inputSchema")
            .and_then(Input::object)
            .ok_or("query input schema")?;
        assert_eq!(
            schema.get("additionalProperties").and_then(Input::boolean),
            Some(false)
        );
        assert_eq!(
            schema.get("oneOf").and_then(Input::array).map(<[_]>::len),
            Some(9)
        );
        let properties = schema
            .get("properties")
            .and_then(Input::object)
            .ok_or("query properties")?;
        let target = properties
            .get("target")
            .and_then(Input::object)
            .ok_or("query target")?;
        assert_eq!(target.get("default").and_then(Input::text), Some("events"));
        assert_eq!(
            target.get("enum").and_then(Input::array),
            Some(
                [
                    Input::Text("events".into()),
                    Input::Text("footage".into()),
                    Input::Text("recordings".into()),
                    Input::Text("onvif".into()),
                    Input::Text("qsr".into()),
                    Input::Text("tracks".into()),
                    Input::Text("reports".into()),
                    Input::Text("evidence-hydration".into()),
                    Input::Text("sources".into()),
                ]
                .as_slice()
            )
        );
        let catalog_schema = input::parse(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/agent_report_catalog_query.v1.json"
        )))?;
        let documented_family = catalog_schema
            .object()
            .and_then(|value| value.get("properties"))
            .and_then(Input::object)
            .and_then(|value| value.get("family"))
            .ok_or("documented report family")?;
        assert_eq!(properties.get("family"), Some(documented_family));
        let report_properties = schema
            .get("oneOf")
            .and_then(Input::array)
            .ok_or("query variants")?
            .iter()
            .filter_map(Input::object)
            .filter_map(|variant| variant.get("properties"))
            .filter_map(Input::object)
            .find(|properties| {
                properties
                    .get("target")
                    .and_then(Input::object)
                    .and_then(|target| target.get("const"))
                    .and_then(Input::text)
                    == Some("reports")
            })
            .ok_or("reports variant")?;
        assert_eq!(report_properties.get("family"), Some(documented_family));
        assert!(
            documented_family
                .object()
                .and_then(|value| value.get("enum"))
                .and_then(Input::array)
                .is_some_and(|families| families
                    .iter()
                    .any(|family| family.text() == Some("model_invocation_receipt")))
        );
        for key in ["sensor", "stream"] {
            let value = properties
                .get(key)
                .and_then(Input::object)
                .ok_or("footage identity")?;
            assert_eq!(value.get("maxLength").and_then(Input::integer), Some(128));
        }
        for key in ["from_ns", "through_ns"] {
            let value = properties
                .get(key)
                .and_then(Input::object)
                .ok_or("time endpoint")?;
            assert_eq!(value.get("type").and_then(Input::text), Some("string"));
        }
        assert!(!properties.contains_key("root"));
        assert!(!properties.contains_key("principal"));
        assert!(!properties.contains_key("hydrate"));
        Ok(())
    }


    #[test]
    fn sources_query_schema_matches_closed_native_selector()
    -> Result<(), Box<dyn std::error::Error>> {
        use fss_core::json_input::{Value as Input, parse};
        let tools = parse(&format!("[{CORE_TOOLS}]"))?;
        let query = tools
            .array()
            .ok_or("tools array")?
            .iter()
            .filter_map(Input::object)
            .find(|tool| tool.get("name").and_then(Input::text) == Some("query"))
            .ok_or("query tool")?;
        let schema = query
            .get("inputSchema")
            .and_then(Input::object)
            .ok_or("query schema")?;
        let source = schema
            .get("oneOf")
            .and_then(Input::array)
            .ok_or("query variants")?
            .iter()
            .filter_map(Input::object)
            .find(|variant| {
                variant.get("properties")
                    .and_then(Input::object)
                    .and_then(|properties| properties.get("target"))
                    .and_then(Input::object)
                    .and_then(|target| target.get("const"))
                    .and_then(Input::text) == Some("sources")
            })
            .ok_or("sources variant")?;
        let documented = parse(include_str!(
            "../../../../../schemas/agent_sources_query.v1.json"
        ))?;
        let documented = documented.object().ok_or("documented source schema")?;
        assert_eq!(source.get("properties"), documented.get("properties"));
        assert_eq!(source.get("required"), documented.get("required"));
        let allowed = source.get("propertyNames")
            .and_then(Input::object)
            .and_then(|names| names.get("enum"))
            .and_then(Input::array)
            .ok_or("closed source keys")?;
        assert_eq!(allowed.len(), 9);
        for forbidden in ["root", "principal", "sources", "at", "hydrate", "verify_source"] {
            assert!(!allowed.iter().any(|key| key.text() == Some(forbidden)));
        }
        Ok(())
    }

    #[test]
    fn query_invalid_types_scope_overrides_and_notifications_never_execute() {
        let mut server = ready();
        let mut calls = 0;
        for arguments in [
            r#"{"root":"/other"}"#,
            r#"{"principal":"principal:other"}"#,
            r#"{"max_entries":0}"#,
            r#"{"max_entries":33}"#,
            r#"{"max_entries":1e1}"#,
            r#"{"from_ns":9007199254740993}"#,
            r#"{"from_ns":"-0"}"#,
            r#"{"from_ns":"2","through_ns":"1"}"#,
            r#"{"kind":"person"}"#,
            r#"{"anchor":"latest"}"#,
            r#"{"commit":true}"#,
            r#"{"zone":"door\nwindow"}"#,
        ] {
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{{"name":"query","arguments":{arguments}}}}}"#
            );
            let response = server.handle_with(&request, |_| {
                calls += 1;
                ("{}".to_owned(), ExitIdentity::SUCCESS)
            });
            assert!(
                response.is_some_and(|text| text.contains("-32602")),
                "{arguments}"
            );
        }
        let response = server.handle_with(
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"query"}}"#,
            |_| {
                calls += 1;
                ("{}".to_owned(), ExitIdentity::SUCCESS)
            },
        );
        assert_eq!(response, None);
        assert_eq!(calls, 0);
    }

    #[test]
    fn historical_reads_dispatch_through_the_canonical_cli_parser() {
        let token = format!("anchor:{}:0:none:{}", "a".repeat(16), "b".repeat(64));
        for name in ["query", "explain"] {
            let mut server = ready();
            let event = if name == "explain" {
                r#","event_id":"event:historical""#
            } else {
                ""
            };
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{{"name":{},"arguments":{{"at":{}{event}}}}}}}"#,
                quote(name),
                quote(&token),
            );
            let mut calls = 0;
            let response = server.handle_with(&request, |command| {
                calls += 1;
                let at = match &command {
                    FssCommand::Query(args) => args.at.as_ref(),
                    FssCommand::Explain(args) => args.at.as_ref(),
                    _ => unreachable!("historical read dispatched to another operation"),
                };
                assert_eq!(at.map(|at| at.as_str()), Some(token.as_str()));
                ("native historical answer".to_owned(), ExitIdentity::SUCCESS)
            });
            assert_eq!(calls, 1);
            assert!(response.is_some_and(|text| text.contains(&quote("native historical answer"))));
        }
    }

    #[test]
    fn query_native_refusal_bytes_and_error_flag_survive_transport() {
        let mut server = ready();
        let expected = r#"{"schema":"fss.agent_response_envelope.v1","outcome":"refused","warnings":["continuation_wrong_stream"],"payload":null}"#;
        for target in ["events", "footage"] {
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{{"name":"query","arguments":{{"target":"{target}","continuation":"continuation:wrong-stream"}}}}}}"#
            );
            let response = server.handle_with(&request, |_| {
                (expected.to_owned(), ExitIdentity::AGENT_REFUSED)
            });
            assert!(response.is_some_and(
                |text| text.contains(&quote(expected)) && text.contains("\"isError\":true")
            ));
        }
    }

    #[test]
    fn event_counterfactual_discovery_matches_the_closed_native_request_schema()
    -> Result<(), Box<dyn std::error::Error>> {
        use fss_cli::json_input::{self as input, Value as Input};
        fn expanded(value: &Input, definitions: &BTreeMap<String, Input>) -> Input {
            match value {
                Input::Object(fields) => {
                    if let Some(reference) = fields.get("$ref").and_then(Input::text) {
                        let key = reference.strip_prefix("#/$defs/").expect("local schema definition");
                        return expanded(&definitions[key], definitions);
                    }
                    Input::Object(fields.iter()
                        .filter(|(key, _)| !matches!(key.as_str(), "$defs" | "$schema" | "$id" | "title"))
                        .map(|(key, value)| (key.clone(), expanded(value, definitions))).collect())
                }
                Input::Array(values) => Input::Array(values.iter().map(|value| expanded(value, definitions)).collect()),
                value => value.clone(),
            }
        }
        let native = input::parse(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"), "/../../schemas/event_counterfactual_request.v1.json"
        )))?;
        let definitions = native.object().and_then(|fields| fields.get("$defs"))
            .and_then(Input::object).ok_or("native schema definitions")?;
        let discovery = input::parse(&tools_list())?;
        let explain = discovery.object().and_then(|fields| fields.get("tools"))
            .and_then(Input::array).ok_or("tool list")?.iter()
            .filter_map(Input::object)
            .find(|fields| fields.get("name").and_then(Input::text) == Some("explain"))
            .ok_or("explain tool")?;
        let schema = explain.get("inputSchema").and_then(Input::object).ok_or("explain schema")?;
        let properties = schema.get("properties").and_then(Input::object).ok_or("explain properties")?;
        assert_eq!(properties.get("counterfactual"), Some(&expanded(&native, definitions)));
        assert_eq!(schema.get("additionalProperties").and_then(Input::boolean), Some(false));
        assert!(!properties.contains_key("root"));
        assert!(!properties.contains_key("principal"));
        assert!(!properties.contains_key("score_calibration"));
        assert_eq!(
            explain.get("annotations").and_then(Input::object)
                .and_then(|fields| fields.get("readOnlyHint")).and_then(Input::boolean),
            Some(true),
        );
        Ok(())
    }

    #[test]
    fn event_counterfactual_dispatch_is_inline_scoped_and_notification_safe()
    -> Result<(), Box<dyn std::error::Error>> {
        use fss_cli::json_output::{object, string};
        use fss_cli::event_counterfactual::EventCounterfactualRequest;
        let calibration = fss_fusion::ScoreCalibration::from_counts(
            "test-inline-event-counterfactual", &[0, 500_000], &[(10, 990), (990, 10)],
        )?;
        let revision = fss_core::ContentDigest::sha256(b"exact current event");
        let scenario = object(&[
            ("schema", string("fss.event_counterfactual_request.v1")),
            ("event_revision_digest", string(&revision.to_text())),
            ("without_domains", r#"["camera:a"]"#.to_owned()),
            ("domain_scores_ppm", r#"{"camera:a":900000}"#.to_owned()),
            ("score_calibration", object(&[
                ("schema", string("fss.score_calibration.v1")),
                ("generation", string(&calibration.generation)),
                ("digest", string(&calibration.digest.to_text())),
                ("bins", r#"[{"lo_ppm":0,"true_positives":10,"false_positives":990},{"lo_ppm":500000,"true_positives":990,"false_positives":10}]"#.to_owned()),
            ])),
        ]);
        let expected_scenario = EventCounterfactualRequest::parse(&scenario)?.canonical_request_json();
        let arguments = object(&[
            ("event_id", string("event:one")),
            ("question", string("what_if")),
            ("counterfactual", scenario),
            ("view", string("forensic")),
            ("budget_tokens", "16000".to_owned()),
        ]);
        let call = |arguments: &str, with_id: bool| format!(
            r#"{{"jsonrpc":"2.0",{}"method":"tools/call","params":{{"name":"explain","arguments":{arguments}}}}}"#,
            if with_id { r#""id":71,"# } else { "" },
        );
        let mut server = ready();
        let mut calls = 0;
        let native_reply = r#"{"operation":"explain","payload":null,"errorId":"ERR-AGENT-RESNAPSHOT-001"}"#;
        let response = server.handle_with(&call(&arguments, true), |command| {
            calls += 1;
            let FssCommand::Explain(args) = command else { panic!("native explain owner required"); };
            assert_eq!(args.root, std::path::PathBuf::from("/owner/deployment"));
            assert_eq!(args.principal.as_str(), "principal:local-operator");
            assert_eq!(args.budget_tokens, Some(16_000));
            assert!(args.at.is_none() && !args.custody && args.score_calibration.is_none());
            let fss_cli::orient_cmd::ExplainTarget::EventCounterfactual { event_id, scenario } = &args.target
                else { panic!("exact counterfactual request required"); };
            assert_eq!(event_id.as_str(), "event:one");
            assert_eq!(scenario, &expected_scenario);
            (native_reply.to_owned(), ExitIdentity::AGENT_REFUSED)
        });
        assert!(response.is_some_and(|reply| reply.contains(&quote(native_reply)) && reply.contains("\"isError\":true")));
        assert_eq!(calls, 1);
        assert_eq!(server.handle_with(&call(&arguments, false), |_| {
            calls += 1;
            (String::new(), ExitIdentity::SUCCESS)
        }), None);
        for extra in [
            r#""root":"/other""#, r#""principal":"principal:other""#,
            r#""session":"session:other""#, r#""at":"anchor:old""#,
            r#""custody":"yes""#, r#""score_calibration":"/private/file""#,
            r#""from_revision_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111""#,
        ] {
            let invalid = format!("{},{}{}", &arguments[..arguments.len() - 1], extra, "}");
            assert!(server.handle_with(&call(&invalid, true), |_| {
                calls += 1;
                (String::new(), ExitIdentity::SUCCESS)
            }).is_some_and(|reply| reply.contains("-32602")));
        }
        assert_eq!(calls, 1, "scope overrides and notifications must never reach execution");
        Ok(())
    }

    #[test]
    fn lifecycle_and_discovery_match_the_registry() {
        let mut server = server();
        let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        assert!(server.handle(list).is_some_and(|r| r.contains("-32002")));
        assert!(
            server
                .handle(INIT)
                .is_some_and(|r| r.contains("capabilities"))
        );
        assert!(server.handle(list).is_some_and(|r| r.contains("-32002")));
        assert_eq!(server.handle(READY), None);
        assert!(
            server
                .handle(list)
                .is_some_and(|r| r.contains("session_orient"))
        );
        assert!(
            server
                .handle(INIT)
                .is_some_and(|r| r.contains("Already initialized"))
        );
        for name in [
            "session_open",
            "session_resume",
            "session_orient",
            "session_follow",
            "investigate",
            "plan",
            "commit",
            "cancel",
            "handoff",
            "feedback",
            "explain",
            "doctor",
            "query",
            "wait",
        ] {
            assert!(fss_cli::lookup_by_mcp_tool_name(name).is_some());
        }
        // Discovery is an outbound catalog, separate from the 64 KiB inbound frame limit.
        assert!(fss_cli::json_input::parse(&tools_list()).is_ok());
    }

    #[test]
    fn feedback_uses_the_fixed_native_owner_and_notifications_cannot_execute() {
        let mut server = ready();
        let digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{{"name":"feedback","arguments":{{"session":"session:owner","target":"case:case:east-door","kind":"correction","statement":"Preserve the counterexample.","supporting":["{digest}"]}}}}}}"#
        );
        let expected = r#"{"operation":"feedback","errorId":"ERR-AUTH-DENIED-001","payload":null}"#;
        let mut calls = 0;
        let response = server.handle_with(&request, |command| {
            calls += 1;
            let FssCommand::Feedback(args) = command else {
                unreachable!("feedback must retain its native proposal owner");
            };
            assert_eq!(args.root, std::path::Path::new("/owner/deployment"));
            assert_eq!(args.request.principal.as_str(), "principal:local-operator");
            assert_eq!(args.request.session_id.as_str(), "session:owner");
            assert_eq!(args.request.target.id(), "case:east-door");
            assert_eq!(args.request.supporting.len(), 1);
            assert!(args.request.contradicting.is_empty());
            (expected.to_owned(), ExitIdentity::RUNTIME_FAILURE)
        });
        assert!(response.is_some_and(
            |reply| reply.contains(&quote(expected)) && reply.contains("\"isError\":true")
        ));
        assert_eq!(
            server.handle_with(&request.replace("\"id\":41,", ""), |_| {
                calls += 1;
                (String::new(), ExitIdentity::SUCCESS)
            }),
            None
        );
        assert_eq!(calls, 1);
    }

    #[test]
    fn control_calls_use_native_owners_and_notifications_cannot_execute() {
        use fss_cli::effect_cmd::EffectCommand;

        let mut server = ready();
        let expected = r#"{"operation":"commit","errorId":"ERR-EFFECT-INDETERMINATE-001","payload":{"state":"indeterminate"}}"#;
        let digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let cases = [
            (
                "plan",
                format!(
                    r#"{{"intent":"alert","session":"session:owner","event_id":"event:one","relay":"127.0.0.1:9","path":"/alert","plaintext_approval":"{digest}","deadline_ms":5000}}"#
                ),
                "plan",
            ),
            (
                "plan",
                r#"{"intent":"close","session":"session:owner","plan":"plan:one"}"#.to_owned(),
                "close",
            ),
            (
                "commit",
                format!(r#"{{"intent":"dispatch","plan":"plan:one","approve":"{digest}"}}"#),
                "commit",
            ),
            (
                "commit",
                format!(
                    r#"{{"intent":"reconcile","operation_id":"operation:one","outcome":"delivered","evidence":"{digest}","statement":"Literal owner attestation."}}"#
                ),
                "reconcile",
            ),
            (
                "cancel",
                r#"{"operation_id":"operation:one"}"#.to_owned(),
                "cancel",
            ),
        ];
        let mut calls = 0;
        for (name, arguments, kind) in cases {
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":40,"method":"tools/call","params":{{"name":{},"arguments":{arguments}}}}}"#,
                quote(name)
            );
            let response = server.handle_with(&request, |command| {
                calls += 1;
                let FssCommand::Effect(effect) = command else {
                    unreachable!("control must retain its native effect owner");
                };
                let (actual, root, principal) = match effect.as_ref() {
                    EffectCommand::Plan(args) => ("plan", &args.root, &args.principal),
                    EffectCommand::Close(args) => ("close", &args.root, &args.principal),
                    EffectCommand::Mission(args) => ("mission", &args.root, &args.principal),
                    EffectCommand::Commit(args) => ("commit", &args.root, &args.principal),
                    EffectCommand::Reconcile(args) => ("reconcile", &args.root, &args.principal),
                    EffectCommand::Cancel(args) => ("cancel", &args.root, &args.principal),
                    _ => unreachable!("unrequested native operation"),
                };
                assert_eq!(actual, kind);
                assert_eq!(root, std::path::Path::new("/owner/deployment"));
                assert_eq!(principal.as_str(), "principal:local-operator");
                (expected.to_owned(), ExitIdentity::RUNTIME_FAILURE)
            });
            assert!(response.is_some_and(
                |reply| reply.contains(&quote(expected)) && reply.contains("\"isError\":true")
            ));
            let notification = request.replace("\"id\":40,", "");
            assert_eq!(
                server.handle_with(&notification, |_| {
                    calls += 1;
                    (String::new(), ExitIdentity::SUCCESS)
                }),
                None
            );
        }
        assert_eq!(calls, 5);
    }

    #[test]
    fn session_cancellation_reaches_native_owner_and_notifications_cannot_execute() {
        use fss_cli::effect_cmd::EffectCommand;

        let mut server = ready();
        let digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let expected = r#"{"operationId":"AOP-010","outcome":"ok"}"#;
        let mut calls = 0;
        for approval in [None, Some(digest)] {
            let approved =
                approval.map_or_else(String::new, |digest| format!(r#", "approve":"{digest}""#));
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":43,"method":"tools/call","params":{{"name":"cancel","arguments":{{"session":"session:owner"{approved}}}}}}}"#
            );
            let response = server.handle_with(&request, |command| {
                let FssCommand::Effect(effect) = command else {
                    unreachable!("session cancellation must retain its native effect owner");
                };
                let EffectCommand::CancelSession(args) = effect.as_ref() else {
                    unreachable!("session cancellation cannot change its native target");
                };
                assert_eq!(args.session.as_str(), "session:owner");
                assert_eq!(args.root, std::path::Path::new("/owner/deployment"));
                assert_eq!(args.principal.as_str(), "principal:local-operator");
                assert_eq!(
                    args.approve.map(|digest| digest.to_text()).as_deref(),
                    approval
                );
                calls += 1;
                (expected.to_owned(), ExitIdentity::SUCCESS)
            });
            assert!(response.is_some_and(|reply| {
                reply.contains(&quote(expected)) && reply.contains("\"isError\":false")
            }));
            assert_eq!(
                server.handle_with(&request.replace("\"id\":43,", ""), |_| {
                    calls += 1;
                    (String::new(), ExitIdentity::SUCCESS)
                }),
                None,
            );
        }
        assert_eq!(calls, 2);
    }

    #[test]
    fn wait_dispatches_only_the_bounded_read_and_controls_require_complete_intents() {
        let mut server = ready();
        let mut seen = Vec::new();
        let reply = server.handle_with(
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"wait","arguments":{"operation_id":"operation:alert:abc","deadline_ms":250}}}"#,
            |command| {
                seen.push(command);
                ("{}".to_owned(), ExitIdentity::SUCCESS)
            },
        );
        assert!(reply.is_some_and(|r| r.contains("\"isError\":false")));
        assert_eq!(seen.len(), 1);
        assert!(matches!(
            seen.pop(),
            Some(FssCommand::Effect(effect)) if matches!(
                effect.as_ref(),
                fss_cli::effect_cmd::EffectCommand::Wait(args)
                    if args.operation.as_str() == "operation:alert:abc" && args.deadline_ms == 250
            )
        ));
        let mut calls = 0;
        for text in [
            r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"wait","arguments":{"operation_id":"operation:alert:abc","deadline_ms":60000}}}"#,
            r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"wait","arguments":{"operation_id":"operation:alert:abc"}}}"#,
            r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"plan","arguments":{}}}"#,
            r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"cancel","arguments":{}}}"#,
            r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"investigate","arguments":{}}}"#,
        ] {
            let _ = server.handle_with(text, |_| {
                calls += 1;
                ("{}".to_owned(), ExitIdentity::SUCCESS)
            });
        }
        assert_eq!(calls, 0);
    }

    #[test]
    fn notifications_incomplete_sessions_and_unapproved_controls_never_execute() {
        let mut server = ready();
        let mut calls = 0;
        for text in [
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"session_orient"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"commit"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"session_open"}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"session_orient","arguments":{"root":"/elsewhere"}}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"session_orient","arguments":{"principal":"principal:other"}}}"#,
        ] {
            let _ = server.handle_with(text, |_| {
                calls += 1;
                ("{}".to_owned(), ExitIdentity::SUCCESS)
            });
        }
        assert_eq!(calls, 0);
    }

    #[test]
    fn canonical_dispatch_and_envelope_are_not_reimplemented() {
        let mut server = ready();
        let envelope = r#"{"schema":"fss.agent_response.v1","coverage":"not_observable","effect":"indeterminate","affordances":["reconcile"]}"#;
        let response = server.handle_with(
            r#"{"jsonrpc":"2.0","id":"read-1","method":"tools/call","params":{"name":"session_orient","arguments":{"view":"pulse","budget_tokens":128}}}"#,
            |command| {
                assert!(matches!(&command, FssCommand::Orient(_)));
                if let FssCommand::Orient(args) = command {
                    assert_eq!(args.root, std::path::PathBuf::from("/owner/deployment"));
                    assert!(args.session.is_none());
                }
                (envelope.to_owned(), ExitIdentity::SUCCESS)
            },
        );
        assert!(
            response
                .is_some_and(|r| r.contains(&quote(envelope)) && r.contains("\"isError\":false"))
        );
    }

    #[test]
    fn session_orientation_uses_native_scope_and_keeps_fixed_authority() {
        let mut server = ready();
        let mut calls = 0;
        let response = server.handle_with(
            r#"{"jsonrpc":"2.0","id":"bound-read","method":"tools/call","params":{"name":"session_orient","arguments":{"session":"session:owned","view":"brief","budget_tokens":1200}}}"#,
            |command| {
                calls += 1;
                let FssCommand::Orient(args) = command else {
                    unreachable!("session orientation must use the canonical native command");
                };
                assert_eq!(args.session.as_ref().map(|id| id.as_str()), Some("session:owned"));
                assert_eq!(args.root, std::path::PathBuf::from("/owner/deployment"));
                assert_eq!(args.principal.as_str(), "principal:local-operator");
                assert_eq!(args.budget_tokens, Some(1200));
                ("{}".to_owned(), ExitIdentity::SUCCESS)
            },
        );
        assert_eq!(calls, 1);
        assert!(response.is_some_and(|r| r.contains("\"isError\":false")));
    }

    #[test]
    fn ids_types_and_invalid_json_fail_closed() {
        let mut server = ready();
        for text in [
            r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":true,"method":"ping"}"#,
            r#"[]"#,
        ] {
            assert!(server.handle(text).is_some_and(|r| r.contains("-32600")));
        }
        assert!(
            server
                .handle(r#"{"jsonrpc":"2.0","id":9007199254740993,"method":"ping"}"#)
                .is_some_and(|r| r.contains("\"id\":9007199254740993"))
        );
        assert!(
            server
                .handle(r#"{"jsonrpc":"2.0","id":"a\"b","method":"ping"}"#)
                .is_some_and(|r| r.contains(r#""id":"a\"b""#))
        );
        assert!(
            server
                .handle(r#"{"id":1,"id":2}"#)
                .is_some_and(|r| r.contains("-32700"))
        );
    }

    #[test]
    fn invalid_budget_or_flag_injection_never_reaches_backend() {
        let mut server = ready();
        let mut calls = 0;
        for args in [
            r#"{"budget_tokens":0}"#,
            r#"{"budget_tokens":4097}"#,
            r#"{"budget_tokens":1e2}"#,
            r#"{"budget_tokens":"128"}"#,
            r#"{"view":"--root=/other"}"#,
            r#"{"session":""}"#,
            r#"{"session":null}"#,
            r#"{"session":12}"#,
            r#"{"session":"--root=/other"}"#,
            r#"{"session":"session:owned","root":"/other"}"#,
            r#"{"session":"session:owned","principal":"principal:other"}"#,
            r#"{"session":"session:owned","at":"anchor:unowned"}"#,
        ] {
            let text = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"session_orient","arguments":{args}}}}}"#
            );
            assert!(
                server
                    .handle_with(&text, |_| {
                        calls += 1;
                        ("{}".to_owned(), ExitIdentity::SUCCESS)
                    })
                    .is_some_and(|r| r.contains("-32602"))
            );
        }
        assert_eq!(calls, 0);
    }

    #[test]
    fn failures_and_output_ceiling_are_explicit() {
        let mut server = ready();
        let response = server.handle_with(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"explain","arguments":{"event_id":"event:missing"}}}"#,
            |_| (r#"{"error_id":"ERR-AGENT-EVENT-NOT-FOUND-001"}"#.to_owned(), ExitIdentity::RUNTIME_FAILURE),
        );
        assert!(response.is_some_and(
            |r| r.contains("ERR-AGENT-EVENT-NOT-FOUND-001") && r.contains("\"isError\":true")
        ));
        let bounded = tool_result(&"x".repeat(MAX_TOOL_OUTPUT_BYTES + 1), false);
        assert!(bounded.len() < 1024 && bounded.contains("\"isError\":true"));
    }

    #[test]
    fn framing_is_bounded_and_never_accepts_partial_requests() {
        assert!(read_frame(&mut io::Cursor::new(b"{}".to_vec())).is_err());
        assert!(read_frame(&mut io::Cursor::new(vec![b'x'; MAX_FRAME_BYTES + 1])).is_err());
        assert_eq!(
            read_frame(&mut io::Cursor::new(b"{}\r\n".to_vec())).ok(),
            Some(Some(b"{}".to_vec()))
        );
        assert_eq!(
            read_frame(&mut io::Cursor::new(Vec::<u8>::new())).ok(),
            Some(None)
        );
        let input =
            format!("{INIT}\n{READY}\n{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}}\n");
        let mut output = Vec::new();
        assert!(serve(&mut server(), io::Cursor::new(input), &mut output).is_ok());
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 2);
    }

    #[test]
    fn follow_preserves_exact_anchor_cursor_page_and_protected_payload() {
        let mut server = ready();
        let anchor = format!("anchor:{}:0:none:{}", "a".repeat(16), "b".repeat(64));
        let cursor = "continuation:exact-page-2";
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"session_follow","arguments":{{"since":{},"view":"brief","max_entries":1,"continuation":{}}}}}}}"#,
            quote(&anchor),
            quote(cursor)
        );
        let envelope = r#"{"classes":["coverage_loss","external_effect_uncertainty"],"continuation":"continuation:exact-page-3","completeness":"partial"}"#;
        let mut called = false;
        let response = server.handle_with(&request, |command| {
            called = true;
            assert!(matches!(&command, FssCommand::Follow(_)));
            if let FssCommand::Follow(args) = command {
                assert_eq!(args.since.as_str(), anchor);
                assert_eq!(args.continuation.as_deref(), Some(cursor));
                assert_eq!(args.max_entries, 1);
                assert_eq!(args.view, fss_core::AgentView::Brief);
            }
            (envelope.to_owned(), ExitIdentity::SUCCESS)
        });
        assert!(called);
        assert!(response.is_some_and(|r| r.contains(&quote(envelope))));
        assert_eq!(
            MAX_PAGE_ENTRIES,
            u64::from(fss_reference::agent_follow::MAX_FOLLOW_ENTRIES)
        );
    }

    #[test]
    fn follow_never_invents_a_basis_or_accepts_malformed_cursor() {
        let mut server = ready();
        let anchor = format!("anchor:{}:0:none:{}", "a".repeat(16), "b".repeat(64));
        let mut calls = 0;
        for arguments in [
            "{}".to_owned(),
            r#"{"since":"latest"}"#.to_owned(),
            format!(
                r#"{{"since":{},"continuation":"--root=/other"}}"#,
                quote(&anchor)
            ),
            format!(r#"{{"since":{},"max_entries":4097}}"#, quote(&anchor)),
            format!(r#"{{"since":{},"view":"epistemic_map"}}"#, quote(&anchor)),
            format!(r#"{{"since":{},"wait_ms":0}}"#, quote(&anchor)),
            format!(r#"{{"since":{},"wait_ms":10001}}"#, quote(&anchor)),
            format!(r#"{{"since":{},"wait_ms":1.5}}"#, quote(&anchor)),
            format!(r#"{{"since":{},"wait_ms":"100"}}"#, quote(&anchor)),
            format!(
                r#"{{"since":{},"wait_ms":100,"continuation":"continuation:exact"}}"#,
                quote(&anchor)
            ),
        ] {
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"session_follow","arguments":{arguments}}}}}"#
            );
            let response = server.handle_with(&request, |_| {
                calls += 1;
                ("{}".to_owned(), ExitIdentity::SUCCESS)
            });
            assert!(response.is_some_and(|r| r.contains("-32602")));
        }
        assert_eq!(calls, 0);
    }

    #[test]
    fn follow_wait_keeps_fixed_scope_and_typed_resnapshot_envelope() {
        let mut server = ready();
        let anchor = format!("anchor:{}:0:none:{}", "a".repeat(16), "b".repeat(64));
        let request = format!(
            r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"session_follow","arguments":{{"since":{},"wait_ms":10000,"view":"brief"}}}}}}"#,
            quote(&anchor)
        );
        let envelope = r#"{"outcome":"partial","errorId":"ERR-AGENT-RESNAPSHOT-001","payload":null,"resnapshotRequired":true}"#;
        let mut called = false;
        let response = server.handle_with(&request, |command| {
            called = true;
            let FssCommand::Follow(args) = command else {
                unreachable!("follow command");
            };
            assert_eq!(args.root, std::path::PathBuf::from("/owner/deployment"));
            assert_eq!(args.since.as_str(), anchor);
            assert_eq!(args.wait_ms, Some(10_000));
            assert_eq!(args.continuation, None);
            (envelope.to_owned(), ExitIdentity::AGENT_REFUSED)
        });
        assert!(called);
        assert!(
            response.is_some_and(|response| response.contains(&quote(envelope))
                && response.contains("\"isError\":true"))
        );
    }

    #[test]
    fn durable_follow_preserves_owned_ack_scope_and_native_delivery_or_refusal()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut server = ready();
        let anchor = format!("anchor:{}:0:none:{}", "a".repeat(16), "b".repeat(64));
        let receipt = fss_core::ContentDigest::sha256(b"exact pending follow delivery");
        let envelope = format!(
            r#"{{"schema":"fss.agent_response_envelope.v1","sessionId":"session:watch-owner","classes":["coverage_loss","effect_uncertainty"],"continuation":"continuation:follow-ack:{}","proofPointers":["follow-delivery:{}"]}}"#,
            receipt.to_text(),
            receipt.to_text(),
        );
        let refused = format!(
            r#"{{"outcome":"partial","errorId":"ERR-AGENT-RESNAPSHOT-001","payload":null,"resnapshotRequired":true,"proofPointers":["follow-acknowledged:{}"]}}"#,
            receipt.to_text(),
        );
        let mut calls = 0;
        for (ack, wait_ms, expected, exit) in [
            (None, None, envelope.as_str(), ExitIdentity::SUCCESS),
            (
                Some(receipt),
                None,
                refused.as_str(),
                ExitIdentity::AGENT_REFUSED,
            ),
            (None, Some(10_000), envelope.as_str(), ExitIdentity::SUCCESS),
            (
                Some(receipt),
                Some(10_000),
                refused.as_str(),
                ExitIdentity::AGENT_REFUSED,
            ),
        ] {
            let acknowledgement = ack.map_or_else(String::new, |value| {
                format!(",\"acknowledge\":{}", quote(&value.to_text()))
            });
            let wait = wait_ms.map_or_else(String::new, |value| format!(",\"wait_ms\":{value}"));
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{{"name":"session_follow","arguments":{{"since":{},"session":"session:watch-owner","subscription":"overnight:door","view":"brief","max_entries":1{acknowledgement}{wait}}}}}}}"#,
                quote(&anchor),
            );
            let response = server
                .handle_with(&request, |command| {
                    calls += 1;
                    let FssCommand::Follow(args) = command else {
                        unreachable!("durable follow uses the canonical command");
                    };
                    assert_eq!(args.root, std::path::PathBuf::from("/owner/deployment"));
                    assert_eq!(args.principal.as_str(), "principal:local-operator");
                    assert_eq!(args.since.as_str(), anchor);
                    assert_eq!(args.view, fss_core::AgentView::Brief);
                    assert_eq!(args.max_entries, 1);
                    assert_eq!(args.continuation, None);
                    assert_eq!(args.wait_ms, wait_ms);
                    let Some(scope) = args.subscription.as_ref() else {
                        unreachable!("durable subscription scope");
                    };
                    assert_eq!(scope.session_id.as_str(), "session:watch-owner");
                    assert_eq!(scope.subscription_id, "overnight:door");
                    assert_eq!(scope.acknowledge, ack);
                    (expected.to_owned(), exit)
                })
                .ok_or("missing tool response")?;
            let wire = fss_cli::json_input::parse(&response)?;
            let result = wire
                .object()
                .and_then(|value| value.get("result"))
                .and_then(fss_cli::json_input::Value::object)
                .ok_or("tool result")?;
            assert_eq!(
                result
                    .get("isError")
                    .and_then(fss_cli::json_input::Value::boolean),
                Some(ack.is_some())
            );
            let content = result
                .get("content")
                .and_then(fss_cli::json_input::Value::array)
                .ok_or("content")?;
            assert_eq!(content.len(), 1);
            assert_eq!(
                content[0]
                    .object()
                    .and_then(|value| value.get("text"))
                    .and_then(fss_cli::json_input::Value::text),
                Some(expected)
            );
        }
        assert_eq!(
            calls, 4,
            "the transport does not replay or acknowledge on its own"
        );

        let tools = fss_cli::json_input::parse(&tools_list())?;
        let follow = tools
            .object()
            .and_then(|value| value.get("tools"))
            .and_then(fss_cli::json_input::Value::array)
            .ok_or("tool list")?
            .iter()
            .filter_map(fss_cli::json_input::Value::object)
            .find(|tool| {
                tool.get("name").and_then(fss_cli::json_input::Value::text)
                    == Some("session_follow")
            })
            .ok_or("follow tool")?;
        let annotations = follow
            .get("annotations")
            .and_then(fss_cli::json_input::Value::object)
            .ok_or("annotations")?;
        assert_eq!(
            annotations
                .get("readOnlyHint")
                .and_then(fss_cli::json_input::Value::boolean),
            Some(false)
        );
        let properties = follow
            .get("inputSchema")
            .and_then(fss_cli::json_input::Value::object)
            .and_then(|schema| schema.get("properties"))
            .and_then(fss_cli::json_input::Value::object)
            .ok_or("follow properties")?;
        for required in ["session", "subscription", "acknowledge"] {
            assert!(
                properties.contains_key(required),
                "discoverable durable field {required}"
            );
        }
        Ok(())
    }

    #[test]
    fn durable_follow_never_acknowledges_notifications_or_unowned_scope() {
        let mut server = ready();
        let anchor = format!("anchor:{}:0:none:{}", "a".repeat(16), "b".repeat(64));
        let receipt = fss_core::ContentDigest::sha256(b"explicit pending delivery").to_text();
        let mut calls = 0;
        for extra in [
            r#", "session":"session:owner""#.to_owned(),
            r#", "subscription":"watch""#.to_owned(),
            format!(r#", "acknowledge":{}"#, quote(&receipt)),
            r#", "session":"session:owner", "subscription":"watch", "continuation":"continuation:unowned""#.to_owned(),
            r#", "session":"session:owner", "subscription":"watch", "wait_ms":0"#.to_owned(),
            r#", "session":"session:owner", "subscription":"watch", "acknowledge":"sha256:invalid""#.to_owned(),
            r#", "session":"--root=/other", "subscription":"watch""#.to_owned(),
            r#", "session":"session:owner", "subscription":"watch", "principal":"principal:other""#.to_owned(),
            r#", "session":"session:owner", "subscription":"watch", "root":"/other""#.to_owned(),
        ] {
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{{"name":"session_follow","arguments":{{"since":{}{extra}}}}}}}"#,
                quote(&anchor),
            );
            let response = server.handle_with(&request, |_| {
                calls += 1;
                ("{}".to_owned(), ExitIdentity::SUCCESS)
            });
            assert!(response.is_some_and(|reply| reply.contains("-32602")), "{extra}");
        }
        let notification = format!(
            r#"{{"jsonrpc":"2.0","method":"tools/call","params":{{"name":"session_follow","arguments":{{"since":{},"session":"session:owner","subscription":"watch","acknowledge":{}}}}}}}"#,
            quote(&anchor),
            quote(&receipt),
        );
        assert_eq!(
            server.handle_with(&notification, |_| {
                calls += 1;
                ("{}".to_owned(), ExitIdentity::SUCCESS)
            }),
            None
        );
        assert_eq!(
            calls, 0,
            "invalid scope and no-response notifications never reach durable ACK state"
        );
    }

    #[test]
    fn doctor_is_pinned_and_attention_required_is_not_hidden() {
        let mut server = ready();
        let response = server.handle_with(
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"doctor"}}"#,
            |command| {
                assert!(matches!(&command, FssCommand::Doctor(_)));
                if let FssCommand::Doctor(args) = command {
                    assert_eq!(
                        args.root,
                        Some(std::path::PathBuf::from("/owner/deployment"))
                    );
                }
                (
                    r#"{"verdict":"attention_required"}"#.to_owned(),
                    ExitIdentity::DOCTOR_ATTENTION_REQUIRED,
                )
            },
        );
        assert!(response.is_some_and(|r| r.contains("attention_required") && r.contains("\"isError\":true")));
    }

    #[test]
    fn negotiation_and_bad_initialization_do_not_grant_dispatch() {
        let mut server = server();
        assert!(
            server
                .handle(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
                .is_some_and(|r| r.contains("-32602"))
        );
        assert_eq!(server.handle(READY), None);
        assert!(
            server
                .handle(&INIT.replace(PROTOCOL_VERSION, "2099-01-01"))
                .is_some_and(|r| r.contains(PROTOCOL_VERSION) && !r.contains("2099-01-01"))
        );
        assert_eq!(server.handle(READY), None);
        assert!(
            server
                .handle(r#"{"jsonrpc":"2.0","id":8,"method":"resources/list"}"#)
                .is_some_and(|r| r.contains("-32601"))
        );
    }
}

#[cfg(test)]
#[path = "recording_tests.rs"]
mod recording_tests;

#[cfg(test)]
#[path = "onvif_tests.rs"]
mod onvif_tests;

#[cfg(test)]
#[path = "qsr_tests.rs"]
mod qsr_tests;
