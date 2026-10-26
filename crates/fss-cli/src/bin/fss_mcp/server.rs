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
{"name":"explain","description":"Read-only AOP-011: explain one published event, or inspect one exact captured-learning publication under its owning session. Learning reads preserve the literal candidate, applicability, counterexamples, validation, expiry and uncertainty after verifying complete custody; no original feedback request, promotion or effect is required. Returns the existing native fss/1 AgentResponseEnvelope unchanged.","inputSchema":{"type":"object","properties":{"event_id":{"type":"string","minLength":1,"maxLength":128},"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"learning_root":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","minLength":71,"maxLength":71},"view":{"type":"string","enum":["decision_diff","forensic"]},"budget_tokens":{"type":"integer","minimum":1,"maximum":16000},"at":{"type":"string","minLength":1,"maxLength":256,"description":"Event-only exact historical anchor; current restrictions apply."},"custody":{"type":"string","enum":["yes","no"],"description":"Event-only option; selected learning custody is always verified."}},"oneOf":[{"required":["event_id"],"not":{"anyOf":[{"required":["session"]},{"required":["learning_root"]}]}},{"required":["session","learning_root"],"not":{"anyOf":[{"required":["event_id"]},{"required":["at"]},{"required":["custody"]}]}}],"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
{"name":"session_follow","description":"AOP-004: return one exact page of meaningful changes in the unchanged fss/1 envelope. Ordinary follow is read-only; wait_ms bounds synchronous waiting on certified quiet. With session and subscription, retain pending adjacent-history delivery in the agent journal and advance only with its exact acknowledge receipt. Unacknowledged pages survive disconnect and restart. Both journals advancing without retained interleaving requires resnapshot; no transition order is invented.","inputSchema":{"type":"object","properties":{"since":{"type":"string","minLength":1,"maxLength":256},"view":{"type":"string","enum":["pulse","brief"]},"max_entries":{"type":"integer","minimum":1,"maximum":4096},"continuation":{"type":"string","minLength":1,"maxLength":256},"wait_ms":{"type":"integer","minimum":1,"maximum":10000},"session":{"type":"string","minLength":1,"maxLength":128},"subscription":{"type":"string","minLength":1,"maxLength":128},"acknowledge":{"type":"string","minLength":71,"maxLength":71}},"required":["since"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
{"name":"query","description":"Read-only AOP-005: exact conjunctive query of verified committed event records at the current head or explicit historical at token. Returns the unchanged CLI AgentResponseEnvelope with protected context. Empty matches never certify physical absence. Nanosecond endpoints are canonical decimal strings to preserve signed 128-bit precision. Continuations require unchanged filters, principal, page size and selected authority/effect-history prefix.","inputSchema":{"type":"object","properties":{"event_id":{"type":"string","minLength":1,"maxLength":128},"kind":{"type":"string","enum":["perimeter_breach","covert_approach","sensor_tamper","unknown_presence","benign_routine","unclassified"]},"state":{"type":"string","enum":["hypothesized","witnessed","corroborated","adjudicated","alert_delivered","resolved","indeterminate","rejected"]},"zone":{"type":"string","minLength":1,"maxLength":64},"from_ns":{"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","maxLength":40},"through_ns":{"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","maxLength":40},"max_entries":{"type":"integer","minimum":1,"maximum":32},"at":{"type":"string","minLength":1,"maxLength":256,"description":"Optional exact retained historical anchor; mutually exclusive with the current-head anchor precondition. Current deletion restrictions apply."},"anchor":{"type":"string","minLength":1,"maxLength":256},"continuation":{"type":"string","minLength":1,"maxLength":256}},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
{"name":"investigate","description":"AOP-006: maintain a durable investigation in one existing session. Supports open, inspect, list, activate, cite, assess, set-state, conclude, rebase, readmit and expand. Draft and expansion are literal objects, never files. Mutations require the exact expected case revision; native evidence, authority, deadline and rebase/readmission checks remain in force. Returns the unchanged native fss/1 envelope and records cognition only: no probe, plan or external effect is executed. Also coordinates native work claims and immutable findings, with exact revision/lease fences and verified retry receipts; these intents grant no effect authority.","inputSchema":{"type":"object","oneOf":[{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"type":"string","enum":["open","inspect","list","activate","cite","assess","set-state","conclude","rebase","readmit","expand"]},"draft":{"type":"object","properties":{"caseId":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"question":{"type":"string","minLength":1,"maxLength":8192},"decisionInformed":{"type":"string","minLength":1,"maxLength":1024},"hypotheses":{"type":"array","minItems":2,"maxItems":64,"items":{"type":"object","properties":{"hypothesisId":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"description":{"type":"string","minLength":1,"maxLength":8192},"epistemicState":{"type":"string","enum":["known","estimated","unknown","conflicted","stale","not_observable","redacted","indeterminate","not_applicable"]},"predictions":{"type":"array","maxItems":256,"items":{"type":"string","minLength":1,"maxLength":1024}}},"required":["hypothesisId","description"],"additionalProperties":false}},"knowns":{"type":"array","maxItems":256,"items":{"type":"object","properties":{"statementId":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"text":{"type":"string","minLength":1,"maxLength":8192},"epistemicState":{"type":"string","enum":["known","estimated","unknown","conflicted","stale","not_observable","redacted","indeterminate","not_applicable"]},"basis":{"type":"array","maxItems":256,"items":{"type":"string","minLength":1,"maxLength":1024}}},"required":["statementId","text"],"additionalProperties":false}},"unknowns":{"type":"array","maxItems":256,"items":{"type":"object","properties":{"statementId":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"text":{"type":"string","minLength":1,"maxLength":8192},"epistemicState":{"type":"string","enum":["known","estimated","unknown","conflicted","stale","not_observable","redacted","indeterminate","not_applicable"]},"basis":{"type":"array","maxItems":256,"items":{"type":"string","minLength":1,"maxLength":1024}}},"required":["statementId","text"],"additionalProperties":false}},"discriminators":{"type":"array","maxItems":128,"items":{"type":"object","properties":{"discriminatorId":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"description":{"type":"string","minLength":1,"maxLength":8192},"separates":{"type":"array","maxItems":64,"items":{"type":"string","minLength":1,"maxLength":128},"minItems":2},"expectedOutcomes":{"type":"array","maxItems":64,"items":{"type":"string","minLength":1,"maxLength":1024},"minItems":2}},"required":["discriminatorId","description","separates","expectedOutcomes"],"additionalProperties":false}},"probes":{"type":"array","maxItems":128,"items":{"type":"string","minLength":1,"maxLength":1024}},"stopRules":{"type":"array","maxItems":64,"items":{"type":"string","minLength":1,"maxLength":1024},"minItems":1},"decisionDeadlineNs":{"anyOf":[{"type":"integer"},{"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","maxLength":40}],"description":"Exact signed 128-bit nanoseconds; decimal strings preserve full precision."},"decisionWindowNs":{"anyOf":[{"type":"integer"},{"type":"string","pattern":"^(0|-?[1-9][0-9]*)$","maxLength":40}],"description":"Exact signed 128-bit nanoseconds; decimal strings preserve full precision."}},"required":["caseId","question","decisionInformed","hypotheses","stopRules"],"additionalProperties":false,"oneOf":[{"required":["decisionDeadlineNs"],"not":{"required":["decisionWindowNs"]}},{"required":["decisionWindowNs"],"not":{"required":["decisionDeadlineNs"]}}]},"expansion":{"type":"object","properties":{"hypothesis":{"type":"object","properties":{"hypothesisId":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"description":{"type":"string","minLength":1,"maxLength":8192},"epistemicState":{"type":"string","enum":["known","estimated","unknown","conflicted","stale","not_observable","redacted","indeterminate","not_applicable"]},"predictions":{"type":"array","maxItems":256,"items":{"type":"string","minLength":1,"maxLength":1024}}},"required":["hypothesisId","description"],"additionalProperties":false},"discriminator":{"type":"object","properties":{"discriminatorId":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"description":{"type":"string","minLength":1,"maxLength":8192},"separates":{"type":"array","maxItems":64,"items":{"type":"string","minLength":1,"maxLength":128},"minItems":2},"expectedOutcomes":{"type":"array","maxItems":64,"items":{"type":"string","minLength":1,"maxLength":1024},"minItems":2}},"required":["discriminatorId","description","separates","expectedOutcomes"],"additionalProperties":false},"probe":{"type":"string","minLength":1,"maxLength":1024}},"required":["hypothesis","discriminator","probe"],"additionalProperties":false},"case":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"revision":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"hypothesis":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"evidence":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"side":{"type":"string","enum":["support","contradiction"]},"disposition":{"type":"string","enum":["supported","disfavored","refuted"]},"state":{"type":"string","enum":["awaiting_evidence","awaiting_approval","blocked","indeterminate","cancelled","closed"]},"reason":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"conclusion":{"type":"string","enum":["resolved","refuted"]},"stop_rule":{"type":"string","minLength":1,"maxLength":1024},"assessment":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"residual_unknowns":{"type":"array","maxItems":256,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},"witness":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["session","transition"],"additionalProperties":false,"oneOf":[{"properties":{"transition":{"const":"open"}},"required":["draft"],"propertyNames":{"enum":["session","transition","draft"]}},{"properties":{"transition":{"const":"inspect"}},"required":["case"],"propertyNames":{"enum":["session","transition","case","revision"]}},{"properties":{"transition":{"const":"list"}},"required":[],"propertyNames":{"enum":["session","transition"]}},{"properties":{"transition":{"const":"activate"}},"required":["case","expected"],"propertyNames":{"enum":["session","transition","case","expected"]}},{"properties":{"transition":{"const":"cite"}},"required":["case","expected","hypothesis","evidence","side"],"propertyNames":{"enum":["session","transition","case","expected","hypothesis","evidence","side"]}},{"properties":{"transition":{"const":"assess"}},"required":["case","expected","hypothesis","disposition","evidence"],"propertyNames":{"enum":["session","transition","case","expected","hypothesis","disposition","evidence"]}},{"properties":{"transition":{"const":"set-state"}},"required":["case","expected","state","reason"],"propertyNames":{"enum":["session","transition","case","expected","state","reason"]}},{"properties":{"transition":{"const":"conclude"}},"required":["case","expected","conclusion","stop_rule","assessment","residual_unknowns"],"propertyNames":{"enum":["session","transition","case","expected","conclusion","stop_rule","assessment","residual_unknowns"]}},{"properties":{"transition":{"const":"rebase"}},"required":["case","expected"],"propertyNames":{"enum":["session","transition","case","expected"]}},{"properties":{"transition":{"const":"readmit"}},"required":["case","expected","hypothesis","evidence","side","witness"],"propertyNames":{"enum":["session","transition","case","expected","hypothesis","evidence","side","witness"]}},{"properties":{"transition":{"const":"expand"}},"required":["case","expected","expansion"],"propertyNames":{"enum":["session","transition","case","expected","expansion"]}}]},{"type":"object","oneOf":[{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim"},"case":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"work":{"type":"string","minLength":1,"maxLength":270,"pattern":"^(case|(hypothesis|discriminator|probe):[\\s\\S]{1,256})$","description":"Exact native work spelling: case or <kind>:<literal work item>. The item is bounded to 256 UTF-8 bytes and must exist in the visible case."},"lease_ms":{"type":"integer","minimum":1,"maximum":300000,"default":60000,"description":"Evidence-clock milliseconds, bounded by the native session expiry. Supply an unsigned decimal JSON integer without fractional or exponent notation."},"depends":{"type":"array","maxItems":64,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}}},"required":["session","transition","case","work"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-inspect"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},"required":["session","transition","claim"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-list"}},"required":["session","transition"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-activate"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["session","transition","claim","expected"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-release"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["session","transition","claim","expected"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-expire"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["session","transition","claim","expected"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-progress"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"artifact":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["session","transition","claim","expected","artifact"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-block"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"artifact":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["session","transition","claim","expected","artifact"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-complete"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"result":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"required":["session","transition","claim","expected","result"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-renew"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"lease_ms":{"type":"integer","minimum":1,"maximum":300000,"default":60000,"description":"Evidence-clock milliseconds, bounded by the native session expiry. Supply an unsigned decimal JSON integer without fractional or exponent notation."}},"required":["session","transition","claim","expected"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-reclaim"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"lease_ms":{"type":"integer","minimum":1,"maximum":300000,"default":60000,"description":"Evidence-clock milliseconds, bounded by the native session expiry. Supply an unsigned decimal JSON integer without fractional or exponent notation."}},"required":["session","transition","claim","expected"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"claim-transfer"},"claim":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"expected":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"recipient":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},"required":["session","transition","claim","expected","recipient"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"finding"},"case":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"claim":{"type":"string","minLength":1,"maxLength":8192,"description":"Literal statement, at most 8192 UTF-8 bytes; never a host-file path to read."},"state":{"type":"string","enum":["known","estimated","unknown","conflicted","stale","not_observable","redacted","indeterminate","not_applicable"]},"supporting":{"type":"array","maxItems":256,"uniqueItems":true,"items":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"minItems":1},"contradicting":{"type":"array","maxItems":256,"uniqueItems":true,"items":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71}},"hypothesis":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"follow_up":{"type":"array","maxItems":64,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},"disagrees_with":{"type":"array","maxItems":64,"uniqueItems":true,"items":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},"supersedes":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},"required":["session","transition","case","claim","state","supporting"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"finding-withdraw"},"finding":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"claim":{"type":"string","minLength":1,"maxLength":8192,"description":"Literal statement, at most 8192 UTF-8 bytes; never a host-file path to read."},"supporting":{"type":"array","maxItems":256,"uniqueItems":true,"items":{"type":"string","pattern":"^sha256:[0-9a-fA-F]{64}$","minLength":71,"maxLength":71},"minItems":1}},"required":["session","transition","finding","claim","supporting"],"additionalProperties":false},{"type":"object","properties":{"session":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"},"transition":{"const":"finding-list"},"case":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9._:-]+$"}},"required":["session","transition"],"additionalProperties":false}]}]},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}},
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
    phase: Phase,
}

impl Server {
    pub(super) fn new(root: OsString, principal: String) -> Self {
        Self {
            root,
            principal,
            phase: Phase::New,
        }
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
            "{{\"protocolVersion\":\"{PROTOCOL_VERSION}\",\"capabilities\":{{\"tools\":{{\"listChanged\":false}}}},\"serverInfo\":{{\"name\":\"fss-mcp\",\"version\":\"{}\"}},\"instructions\":\"Local reference adapter, not production-qualified. The launching operator fixes the deployment root and principal audit label. Tool results retain existing FSS evidence and uncertainty semantics. Sessions, investigations, claims, findings and explicit durable follow update agent continuity state. Alert controls require native exact approval; plans and recommendations grant no effect authority. After response loss inspect retained operations with wait and follow native reconciliation guidance before acting again. No remote authentication or in-flight cancellation is implemented.\"}}",
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
                    ],
                ) {
                    return Err((-32602, "Unexpected explanation argument"));
                }
                let mut argv = self.base_args("explain");
                if let Some(root) = args.get("learning_root") {
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
            "query" => {
                if !only(
                    args,
                    &[
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
                        // enum, integer, interval and token without a parallel interpretation.
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
            | FssCommand::Investigate(_)
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
        assert_eq!(families.len(), 2);
        let mut transitions = BTreeSet::new();
        for (index, family) in families.iter().enumerate() {
            let family = family.object().ok_or("intent family")?;
            let variants = family
                .get("oneOf")
                .and_then(Input::array)
                .ok_or("action variants")?;
            assert_eq!(variants.len(), if index == 0 { 11 } else { 15 });
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
                assert!(
                    transitions.insert(transition),
                    "duplicate transition {transition}"
                );
                if index == 1 {
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
        let response = server.handle_with(
            r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"query","arguments":{"continuation":"continuation:wrong-stream"}}}"#,
            |_| (expected.to_owned(), ExitIdentity::AGENT_REFUSED),
        );
        assert!(response.is_some_and(
            |text| text.contains(&quote(expected)) && text.contains("\"isError\":true")
        ));
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
        assert!(json::parse(&tools_list()).is_ok());
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
        for (ack, expected, exit) in [
            (None, envelope.as_str(), ExitIdentity::SUCCESS),
            (Some(receipt), refused.as_str(), ExitIdentity::AGENT_REFUSED),
        ] {
            let acknowledgement = ack.map_or_else(String::new, |value| {
                format!(",\"acknowledge\":{}", quote(&value.to_text()))
            });
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{{"name":"session_follow","arguments":{{"since":{},"session":"session:watch-owner","subscription":"overnight:door","view":"brief","max_entries":1{acknowledgement}}}}}}}"#,
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
                    assert_eq!(args.wait_ms, None);
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
            calls, 2,
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
            r#", "session":"session:owner", "subscription":"watch", "wait_ms":1"#.to_owned(),
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
