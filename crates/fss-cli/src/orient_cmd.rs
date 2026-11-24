#![forbid(unsafe_code)]
//! `fss orient` (AOP-003 `session.orient`) and `fss explain` (AOP-011 `explain`): read-only agent
//! reads of an existing deployment root, answered as the registered `AgentResponseEnvelope`.
//!
//! Stateless reads and deterministic replay open no file for writing. Live session-bound reads
//! persist clock admission/expiry under the journal lock while authenticating a coherent
//! snapshot; they do not change evidence, workspace or effects. The situation is compiled by
//! [`fss_reference::agent_orient`]; this module only decodes arguments, binds the compiled typed
//! values into [`AgentResponseEnvelope`] (and, for explain, [`AgentCognitiveEnvelope`]) through
//! their validated constructors, and renders them with [`crate::agent_json`]. Affordances are
//! listed, never executed.

#[path = "orient_cmd/args.rs"]
mod args;
#[path = "orient_cmd/capsule_json.rs"]
mod capsule_json;
#[path = "orient_cmd/cognitive.rs"]
mod cognitive;
#[path = "orient_cmd/custody.rs"]
mod custody;
#[path = "orient_cmd/diagnostics.rs"]
mod diagnostics;
#[path = "orient_cmd/evidence.rs"]
mod evidence;
#[path = "orient_cmd/explain_exec.rs"]
mod explain_exec;
#[path = "orient_cmd/explain_options.rs"]
mod explain_options;
#[path = "orient_cmd/fusion.rs"]
mod fusion;
#[path = "orient_cmd/history.rs"]
pub(crate) mod history;
#[path = "orient_cmd/learning_explain.rs"]
mod learning_explain;
#[path = "orient_cmd/orient_exec.rs"]
mod orient_exec;
#[path = "orient_cmd/response.rs"]
mod response;
#[path = "orient_cmd/what_changed.rs"]
mod what_changed;
#[path = "orient_cmd/what_if.rs"]
mod what_if;

#[cfg(test)]
use fss_core::{AgentView, ContentDigest, EventId, PrincipalId};
#[cfg(test)]
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_orient::CAPABILITY_EXPLAIN;
#[cfg(test)]
use fss_reference::agent_orient::{OrientLimits, read_deployment};

pub use args::{
    DEFAULT_PRINCIPAL, ERR_AGENT_CONTEXT_INCOMPLETE, ERR_AGENT_EVENT_NOT_FOUND, ExplainArgs,
    ExplainTarget, ORIENT_VIEWS, OrientArgs, parse_explain_args, parse_orient_args,
};
pub(crate) use args::{
    collect_options, collect_options_with_repeatable, principal, required_root, take,
};
pub(crate) use capsule_json::{CapsuleOverrides, contexts, situation_capsule_payload};
pub(crate) use cognitive::{CognitiveParts, CognitivePayload, cognitive_payload};
use cognitive::{EVENT_PRIVACY_CLASS, cognitive_payload_with_budget};
#[cfg(test)]
use diagnostics::sanitize_diagnostic_text;
pub(crate) use diagnostics::{
    RenderError, execution_diagnostic, internal_failure, read_only_boundary, read_refusal,
    rendered, request_identity,
};
#[allow(unused_imports)]
pub(crate) use diagnostics::{execution_diagnostic_with_detail, internal_failure_with_detail};
pub use explain_exec::execute_explain;
pub(crate) use explain_exec::execute_explain_with_control;
#[allow(unused_imports)]
pub(crate) use explain_exec::execute_explain_with_time;
use explain_exec::{cancelled_explanation, cancelled_explanation_at};
pub use orient_exec::execute_orient;
pub(crate) use orient_exec::execute_orient_with_control;
#[allow(unused_imports)]
pub(crate) use orient_exec::{budget_refusal, execute_orient_with_time};
pub(crate) use response::{
    ResponseParts, build_event_hydration_response, build_footage_response,
    build_localizations_response, build_onvif_response, build_probe_response, build_qsr_response,
    build_recording_replay_response, build_recording_response, build_recording_utc_response,
    build_report_catalog_response, build_response, build_response_with_resnapshot,
    build_retained_recording_replay_response, build_sources_response, build_tracks_response,
};

use crate::agent_json;
#[cfg(test)]
use crate::error::ExitIdentity;

#[cfg(test)]
#[path = "orient_cmd/cancellation_tests.rs"]
mod cancellation_tests;
