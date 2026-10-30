#![forbid(unsafe_code)]
//! AOP-006 retained-source probes over existing session-owned native supervision.
//!
//! One invocation recovers an immutable recipe and performs one explicit bounded action.
//! The companion command and this path share the same evaluator, source checks and journal.

use std::path::PathBuf;

use fss_core::{
    AgentView, BudgetVector, ContentDigest, ContextAuthority, DigestAlgorithm, OperationId,
    RootAuthoritySpec, SessionId,
};
use fss_reference::ReplayCx;
use fss_reference::agent_session::checkpoint::journal::coordination::investigations::ProbeCitationTarget;
use fss_reference::deployment_session::DeploymentSessionError;
use fss_reference::deployment_session::probe::case::CaseProbeAction;
use fss_reference::deployment_session::probe::{
    ProbeCharge, ProbeContext, ProbeRequest, admit_probe, charge_probe_delivery,
};
use fss_reference::deployment_session::supervision::{
    SupervisionAction, SupervisionRecoveryRequest, SupervisionSessionDelivery,
    SupervisionSessionError, SupervisionSessionFailure, SupervisionSessionRequest,
};

use crate::error::{CliError, ExitIdentity};
use crate::orient_cmd::{collect_options, principal, rendered, required_root, take};
use crate::session_cmd::{Operation, refuse};
use crate::supervisor::retained::session::{
    execute_native_supervision, recover_native_supervision,
};
use crate::token::ArgToken;

mod case;
mod compression;
mod projection;
mod render;
#[cfg(test)]
mod tests;

pub(crate) const COMMAND: &str = "investigate";
pub(crate) const CAPABILITY: &str = "CAP-AGENT-CASE-WRITE-001";
pub(crate) const SCHEMA: &str = "fss.agent_cognitive_envelope.v2";
/// Absolute complete response ceiling. The explicitly selected view adds its registered quote cap.
pub const MAX_PROBE_OUTPUT_BYTES: usize = 256 * 1024;

/// Typed request shared by CLI and MCP; callers cannot provide a recipe or native score.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeArgs {
    /// Existing deployment namespace.
    pub root: PathBuf,
    /// Existing subscription and one exact native action.
    pub request: ProbeRequest,
    /// Optional exact case use or metadata-only historical citation recovery.
    pub case: Option<CaseProbeAction>,
}

impl ProbeArgs {
    /// Exact transport intent, including explicit case/pre-work state when selected.
    pub fn digest(&self) -> ContentDigest {
        self.case.as_ref().map_or_else(
            || self.request.digest(),
            |action| action.digest(&self.request),
        )
    }

    /// Stable semantic transition; a citation inspection is never labelled a native poll.
    pub fn name(&self) -> &'static str {
        self.case
            .as_ref()
            .map_or_else(|| self.request.name(), CaseProbeAction::name)
    }

    fn validate(&self) -> Result<(), DeploymentSessionError> {
        self.case.as_ref().map_or_else(
            || self.request.validate(),
            |action| action.validate(&self.request),
        )
    }
}

/// True only for the explicit retained-probe transition family.
#[must_use]
pub fn selects_probe(tokens: &[ArgToken]) -> bool {
    tokens.iter().enumerate().any(|(index, token)| {
        token
            .as_str()
            .strip_prefix("--transition=")
            .or_else(|| {
                (token.as_str() == "--transition")
                    .then(|| tokens.get(index + 1).map(ArgToken::as_str))
                    .flatten()
            })
            .is_some_and(|value| value == "probe" || value.starts_with("probe-"))
    })
}

fn malformed(option: &str, raw: &str, reason: &str, index: usize) -> CliError {
    CliError::MalformedValue {
        option: option.to_owned(),
        value: raw.to_owned(),
        reason: reason.to_owned(),
        command: Some(COMMAND.to_owned()),
        index,
    }
}

fn required<'a>(
    values: &'a [(String, String, usize)],
    option: &str,
) -> Result<&'a (String, String, usize), CliError> {
    take(values, option).ok_or_else(|| CliError::MissingValue {
        option: option.to_owned(),
        command: Some(COMMAND.to_owned()),
        expected: "an explicit retained-probe identity or precondition".to_owned(),
    })
}

fn digest(values: &[(String, String, usize)], option: &str) -> Result<ContentDigest, CliError> {
    let (_, raw, index) = required(values, option)?;
    ContentDigest::parse(raw)
        .ok()
        .filter(|value| value.algorithm() == DigestAlgorithm::Sha256 && value.bytes() != [0; 32])
        .ok_or_else(|| malformed(option, raw, "expected a nonzero SHA-256 digest", *index))
}

/// Parse one existing-subscription operation, refusing recipe, scope and mixed-action overrides.
pub fn parse_probe_args(tokens: &[ArgToken]) -> Result<ProbeArgs, CliError> {
    let values = collect_options(
        COMMAND,
        tokens,
        &[
            "--root",
            "--principal",
            "--session",
            "--transition",
            "--subscription",
            "--authority-root",
            "--view",
            "--receipt",
            "--window-index",
            "--after-receipt",
            "--case",
            "--expected",
            "--hypothesis",
            "--side",
            "--subscription-state",
        ],
    )?;
    let root = required_root(COMMAND, &values)?;
    let principal = principal(COMMAND, &values)?;
    let (_, raw, index) = required(&values, "--session")?;
    let session_id = SessionId::parse(raw.as_str())
        .map_err(|_| malformed("--session", raw, "invalid session identity", *index))?;
    let (_, subscription_id, index) = required(&values, "--subscription")?;
    fss_core::validate_id(subscription_id).map_err(|_| {
        malformed(
            "--subscription",
            subscription_id,
            "invalid subscription identity",
            *index,
        )
    })?;
    let expected_authority_root = digest(&values, "--authority-root")?;
    let view = match take(&values, "--view") {
        None => AgentView::Case,
        Some((_, raw, _)) if raw == "case" => AgentView::Case,
        Some((_, raw, _)) if raw == "forensic" => AgentView::Forensic,
        Some((_, raw, index)) => {
            return Err(malformed(
                "--view",
                raw,
                "expected case or forensic; larger output requires an explicit forensic selection",
                *index,
            ));
        }
    };
    let (_, transition, index) = required(&values, "--transition")?;
    let (action, extra): (SupervisionAction, &[&str]) = match transition.as_str() {
        "probe" => (SupervisionAction::Poll, &[]),
        "probe-inspect" | "probe-citation" => (SupervisionAction::Inspect, &[]),
        "probe-ack" => (
            SupervisionAction::Acknowledge(digest(&values, "--receipt")?),
            &["--receipt"],
        ),
        "probe-discard" => (
            SupervisionAction::Discard(digest(&values, "--receipt")?),
            &["--receipt"],
        ),
        "probe-advance" => {
            let (_, raw, at) = required(&values, "--window-index")?;
            let index = raw
                .parse::<u32>()
                .ok()
                .filter(|n| (1..32).contains(n) && n.to_string() == *raw)
                .ok_or_else(|| {
                    malformed(
                        "--window-index",
                        raw,
                        "expected the next zero-based window index from 1 through 31",
                        *at,
                    )
                })?;
            (
                SupervisionAction::Advance {
                    target_count: index + 1,
                    after_receipt: digest(&values, "--after-receipt")?,
                },
                &["--window-index", "--after-receipt"],
            )
        }
        _ => {
            return Err(malformed(
                "--transition",
                transition,
                "expected probe, probe-inspect, probe-ack, probe-discard, probe-advance or probe-citation",
                *index,
            ));
        }
    };
    let case_fields = [
        "--case",
        "--expected",
        "--hypothesis",
        "--side",
        "--subscription-state",
    ];
    let case = if transition == "probe-citation"
        || values
            .iter()
            .any(|(key, _, _)| case_fields.contains(&key.as_str()))
    {
        if transition != "probe" && transition != "probe-citation" {
            return Err(malformed(
                "--transition",
                transition,
                "case linkage is admitted only for probe or probe-citation",
                *index,
            ));
        }
        let (_, case_id, _) = required(&values, "--case")?;
        let (_, hypothesis, _) = required(&values, "--hypothesis")?;
        let (_, side, side_index) = required(&values, "--side")?;
        let contradicts = match side.as_str() {
            "support" => false,
            "contradiction" => true,
            _ => {
                return Err(malformed(
                    "--side",
                    side,
                    "expected support or contradiction",
                    *side_index,
                ));
            }
        };
        let target = ProbeCitationTarget {
            case_id: case_id.clone(),
            expected: digest(&values, "--expected")?,
            hypothesis: hypothesis.clone(),
            contradicts,
        };
        if transition == "probe" {
            Some(CaseProbeAction::Cite {
                target,
                expected_subscription_state: digest(&values, "--subscription-state")?,
            })
        } else {
            Some(CaseProbeAction::InspectCitation(target))
        }
    } else {
        None
    };
    for (key, raw, index) in &values {
        if ![
            "--root",
            "--principal",
            "--session",
            "--transition",
            "--subscription",
            "--authority-root",
            "--view",
        ]
        .contains(&key.as_str())
            && !extra.contains(&key.as_str())
            && !(case.is_some()
                && case_fields.contains(&key.as_str())
                && (key != "--subscription-state" || transition == "probe"))
        {
            return Err(malformed(
                key,
                raw,
                "option is not admitted for this exact probe action",
                *index,
            ));
        }
    }
    let args = ProbeArgs {
        root,
        request: ProbeRequest {
            session_id,
            principal,
            subscription_id: subscription_id.clone(),
            expected_authority_root,
            view,
            action,
        },
        case,
    };
    args.validate().map_err(|_| {
        malformed(
            "--transition",
            transition,
            "invalid exact probe/case profile",
            *index,
        )
    })?;
    Ok(args)
}

pub(super) struct ProbeFailure {
    pub identity: &'static str,
    pub reason: String,
    pub journal_may_have_changed: bool,
    pub attempts_reserved: Option<u32>,
    pub acknowledged: Option<ContentDigest>,
    pub discarded: Option<ContentDigest>,
    pub advanced: Option<ContentDigest>,
}

impl ProbeFailure {
    fn stage(identity: &'static str, reason: impl ToString, changed: bool) -> Self {
        Self {
            identity,
            reason: reason.to_string(),
            journal_may_have_changed: changed,
            attempts_reserved: None,
            acknowledged: None,
            discarded: None,
            advanced: None,
        }
    }

    fn native(failure: &SupervisionSessionFailure) -> Self {
        Self {
            identity: native_identity(&failure.error),
            reason: failure.error.to_string(),
            journal_may_have_changed: failure.journal_may_have_changed,
            attempts_reserved: Some(failure.attempts_reserved),
            acknowledged: failure.acknowledged,
            discarded: failure.discarded,
            advanced: failure.advanced,
        }
    }
}

fn native_identity(error: &SupervisionSessionError) -> &'static str {
    match error {
        SupervisionSessionError::ChangedAuthority | SupervisionSessionError::StaleAuthority => {
            "ERR-AGENT-SESSION-STALE-001"
        }
        SupervisionSessionError::Session(DeploymentSessionError::SessionUnknown) => {
            "ERR-AGENT-SESSION-NOT-FOUND-001"
        }
        SupervisionSessionError::Session(DeploymentSessionError::StoreLocked) => {
            "ERR-AGENT-SESSION-STORE-LOCKED-001"
        }
        SupervisionSessionError::Denied(_) => "ERR-AUTH-DENIED-001",
        SupervisionSessionError::Evaluation(_) => "ERR-EVIDENCE-MISSING-001",
        SupervisionSessionError::Store(_) | SupervisionSessionError::InvalidRequest => {
            "ERR-OP-PRECONDITION-FAILED-001"
        }
        SupervisionSessionError::Session(_) => "ERR-AGENT-SESSION-STORE-INVALID-001",
    }
}

fn refusal(args: &ProbeArgs, error: DeploymentSessionError) -> (String, ExitIdentity) {
    refuse(
        &Operation {
            command: COMMAND,
            name: COMMAND,
            capability: CAPABILITY,
            payload_schema: fss_core::AgentCognitiveEnvelope::SCHEMA,
            view: args.request.view,
            root: args.root.clone(),
            principal: args.request.principal.clone(),
            request: args.digest().to_text().into_bytes(),
        },
        error,
    )
}

fn fail(
    args: &ProbeArgs,
    context: &ProbeContext,
    delivery: Option<&SupervisionSessionDelivery>,
    failure: &ProbeFailure,
) -> (String, ExitIdentity) {
    fail_after_charge(args, context, delivery, None, failure)
}

fn fail_after_charge(
    args: &ProbeArgs,
    context: &ProbeContext,
    delivery: Option<&SupervisionSessionDelivery>,
    charge: Option<&ProbeCharge>,
    failure: &ProbeFailure,
) -> (String, ExitIdentity) {
    rendered(
        render::response(args, context, delivery, None, charge, Some(failure))
            .map(|prepared| prepared.text)
            .or_else(|_| render::progress_refusal(args, context, delivery, charge, failure, None)),
        ExitIdentity::AGENT_REFUSED,
        COMMAND,
        &args.root,
    )
}

fn run(args: &ProbeArgs, cx: &ReplayCx) -> (String, ExitIdentity) {
    if let Err(error) = cx.checkpoint("investigate_probe:admit") {
        return refusal(args, DeploymentSessionError::Internal(error.to_string()));
    }
    let before = match admit_probe(&args.root, &args.request) {
        Ok(context) => context,
        Err(error) => return refusal(args, error),
    };
    if args.case.is_some() {
        return case::run(args, cx, before);
    }
    let recovery = SupervisionRecoveryRequest {
        session_id: args.request.session_id.clone(),
        subscription_id: args.request.subscription_id.clone(),
        expected_authority_root: args.request.expected_authority_root,
    };
    let (native, registration) =
        match recover_native_supervision(&args.root, &args.request.principal, &recovery, cx) {
            Ok(result) => result,
            Err(error) => {
                return fail(
                    args,
                    &before,
                    None,
                    &ProbeFailure::stage(native_identity(&error), error, true),
                );
            }
        };
    if native.template().spec().site_lineage
        != before.oriented.orientation.capsule().anchor.site_lineage
    {
        return fail(
            args,
            &before,
            None,
            &ProbeFailure::stage(
                "ERR-OP-PRECONDITION-FAILED-001",
                "stored native probe belongs to another site",
                true,
            ),
        );
    }
    let command = SupervisionSessionRequest {
        registration,
        expected_authority_root: args.request.expected_authority_root,
        action: args.request.action,
    };
    let delivery = match execute_native_supervision(
        &args.root,
        &args.request.principal,
        &command,
        &native,
        true,
        cx,
    ) {
        Ok(delivery) => delivery,
        Err(error) => return fail(args, &before, None, &ProbeFailure::native(&error)),
    };
    let mut context = match cx
        .checkpoint("investigate_probe:current_context")
        .map_err(|error| DeploymentSessionError::Internal(error.to_string()))
        .and_then(|()| admit_probe(&args.root, &args.request))
    {
        Ok(context)
            if context.oriented.session == delivery.session
                && context.oriented.orientation.capsule().anchor == delivery.head.anchor
                && context.ledger_root == delivery.head.ledger_root
                && context.effect_root == delivery.head.effect_root
                && context.oriented.journal_root == delivery.journal_root =>
        {
            context
        }
        Ok(_) => {
            return fail(
                args,
                &before,
                Some(&delivery),
                &ProbeFailure::stage(
                    "ERR-AGENT-SESSION-STALE-001",
                    "session, subscription or deployment changed before probe projection; inspect retained progress",
                    true,
                ),
            );
        }
        Err(error) => {
            return fail(
                args,
                &before,
                Some(&delivery),
                &ProbeFailure::stage("ERR-AGENT-SESSION-STALE-001", error, true),
            );
        }
    };
    context.session_bytes_read = context
        .session_bytes_read
        .saturating_add(before.session_bytes_read);
    let prepared = match render::response(
        args,
        &context,
        Some(&delivery),
        Some(&native),
        None,
        None,
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            return fail(
                args,
                &context,
                Some(&delivery),
                &ProbeFailure::stage(
                    "ERR-AGENT-CONTEXT-INCOMPLETE-001",
                    format!(
                        "Complete probe projection withheld: {error}. The exact pending receipt and spent work remain retained."
                    ),
                    true,
                ),
            );
        }
    };
    if let Err(error) = cx.checkpoint("investigate_probe:charge_projection") {
        return fail(
            args,
            &context,
            Some(&delivery),
            &ProbeFailure::stage("ERR-OP-PRECONDITION-FAILED-001", error, true),
        );
    }
    let charge = match charge_probe_delivery(
        &args.root,
        &args.request,
        &context,
        &delivery,
        prepared.quoted_tokens,
    ) {
        Ok(charge) => charge,
        Err(failure) => {
            return fail_after_charge(
                args,
                &context,
                Some(&delivery),
                failure.committed.as_ref(),
                &ProbeFailure::stage(
                    "ERR-OP-PRECONDITION-FAILED-001",
                    format!(
                        "Probe delivery charge or final boundary refused: {failure}; inspect the session balance before retry. Any committed charge is retained."
                    ),
                    true,
                ),
            );
        }
    };
    if let Err(error) = cx.checkpoint("investigate_probe:release_projection") {
        return fail_after_charge(
            args,
            &context,
            Some(&delivery),
            Some(&charge),
            &ProbeFailure::stage("ERR-OP-PRECONDITION-FAILED-001", error, true),
        );
    }
    match render::response(
        args,
        &context,
        Some(&delivery),
        Some(&native),
        Some(&charge),
        None,
    ) {
        Ok(prepared) => (prepared.text, ExitIdentity::SUCCESS),
        Err(error) => fail_after_charge(
            args,
            &context,
            Some(&delivery),
            Some(&charge),
            &ProbeFailure::stage(
                "ERR-AGENT-CONTEXT-INCOMPLETE-001",
                format!(
                    "Complete charged projection withheld: {error}; the exact native receipt and charge remain durable."
                ),
                true,
            ),
        ),
    }
}

/// Execute one explicitly selected existing retained probe; never register, auto-ACK or retry.
#[must_use]
pub fn execute_probe(args: &ProbeArgs) -> (String, ExitIdentity) {
    if let Err(error) = args.validate() {
        return refusal(args, error);
    }
    if !std::fs::symlink_metadata(&args.root).is_ok_and(|m| m.file_type().is_dir())
        || !std::fs::symlink_metadata(args.root.join("LAYOUT"))
            .is_ok_and(|m| m.file_type().is_file())
    {
        return refusal(args, DeploymentSessionError::SessionUnknown);
    }
    let context = (|| -> Result<ReplayCx, Box<dyn std::error::Error>> {
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:investigate-retained-probe".to_owned(),
            operation_id: OperationId::parse("operation:investigate-retained-probe")?,
            principal: args.request.principal.as_str().to_owned(),
            capabilities: vec!["ADP-REPLAY-001".to_owned()],
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
            privacy_scope: "privacy:local-authorized-files".to_owned(),
            retention_scope: "retention:existing-deployment-policy".to_owned(),
            anchor_universe: args.request.expected_authority_root,
            generation: 1,
        })?;
        Ok(ReplayCx::from_context_authority(
            &authority,
            args.root.clone(),
        )?)
    })();
    match context {
        Ok(cx) => {
            let result = run(args, &cx);
            cx.drain_and_finalize();
            result
        }
        Err(error) => refusal(args, DeploymentSessionError::Internal(error.to_string())),
    }
}
