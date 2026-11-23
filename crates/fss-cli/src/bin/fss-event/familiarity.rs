#![forbid(unsafe_code)]
//! Optional anonymous context advice on an exact cold-verified retained event.

use fss_cli::agent_json::{array, object, string};
use fss_core::familiarity::{
    ADVICE_SCHEMA, CONTEXT_SCHEMA, FamiliarityBasis, FamiliarityContext, MAX_CONTEXT_BYTES,
    assess_familiarity,
};
use fss_core::{EventHypothesis, TimestampNs};
use fss_reference::retained_source::RetainedSource;

use super::*;

/// Shared with the native immutable reader's actual local authority.
pub(super) const PRIVACY_SCOPE: &str = "privacy:local-authorized-files";

#[derive(Debug)]
pub(super) enum Request {
    Template,
    Assess(AssessmentRequest),
}

#[derive(Debug)]
pub(super) struct AssessmentRequest {
    context: PathBuf,
    digest: ContentDigest,
    at_ns: TimestampNs,
}

pub(super) fn parse(values: &Values) -> Result<Option<Request>, String> {
    let keys = [
        "--familiarity-context",
        "--familiarity-digest",
        "--familiarity-at-ns",
    ];
    if values.contains_key("--familiarity-template") {
        if text(values, "--familiarity-template")? != "yes" {
            return Err("--familiarity-template requires yes".into());
        }
        if keys.iter().any(|key| values.contains_key(*key)) {
            return Err(
                "familiarity template and assessment options are mutually exclusive".into(),
            );
        }
        return Ok(Some(Request::Template));
    }
    if !keys.iter().any(|key| values.contains_key(*key)) {
        return Ok(None);
    }
    if !keys.iter().all(|key| values.contains_key(*key)) {
        return Err("familiarity advice requires --familiarity-context, --familiarity-digest and --familiarity-at-ns together".into());
    }
    let at = text(values, "--familiarity-at-ns")?;
    let at_ns = at
        .parse::<i128>()
        .map_err(|_| "invalid familiarity evaluation time")?;
    if at != at_ns.to_string() {
        return Err("familiarity evaluation time requires canonical integer nanoseconds".into());
    }
    Ok(Some(Request::Assess(AssessmentRequest {
        context: PathBuf::from(value(values, "--familiarity-context")?),
        digest: digest(values, "--familiarity-digest")?,
        at_ns: TimestampNs(at_ns),
    })))
}

pub(super) fn append(
    options: &Options,
    deployment: &dyn RetainedSource,
    event: &EventHypothesis,
    cx: &ReplayCx,
    output: &mut impl Write,
) -> RunResult<()> {
    let Some(request) = &options.familiarity else {
        return Ok(());
    };
    let Request::Assess(request) = request else {
        let template = object(&[
            ("schema", string(CONTEXT_SCHEMA)),
            ("site_lineage", string(deployment.site_lineage())),
            (
                "authority_root",
                string(&deployment.current_anchor().state_root.to_text()),
            ),
            ("privacy_scope", string(PRIVACY_SCOPE)),
            ("event_id", string(event.event_id.as_str())),
            (
                "event_revision_digest",
                string(&event.revision_digest().to_text()),
            ),
            (
                "event_policy_generation",
                string(&event.decision_path.policy_generation.to_text()),
            ),
            ("coverage", string("unknown")),
            ("threat_actions", string("unknown")),
            ("sensor_integrity", string("unknown")),
            ("high_consequence", "false".to_owned()),
            ("signals", "[]".to_owned()),
        ]);
        writeln!(output, "familiarity_context_template={template}")?;
        writeln!(
            output,
            "familiarity_evaluation_time_hint_ns={}",
            event.interval.latest.0
        )?;
        return Ok(());
    };
    let bytes = load(&request.context, MAX_CONTEXT_BYTES, request.digest, cx)?;
    let context = FamiliarityContext::from_json(std::str::from_utf8(&bytes)?)?;
    cx.checkpoint("event_cli:familiarity")?;
    let assessment = assess_familiarity(
        event,
        &context,
        FamiliarityBasis {
            site_lineage: deployment.site_lineage(),
            authority_root: deployment.current_anchor().state_root,
            privacy_scope: PRIVACY_SCOPE,
            at_ns: request.at_ns,
        },
    )?;
    let signal_rows = assessment
        .signals
        .iter()
        .map(|row| {
            let signal = &row.signal;
            object(&[
                ("evidence_digest", string(&signal.evidence_digest.to_text())),
                (
                    "source_generation",
                    string(&signal.source_generation.to_text()),
                ),
                ("kind", string(signal.kind.as_str())),
                ("provenance", string("operator_asserted")),
                ("supports_familiarity", signal.supports.to_string()),
                ("assessment", string(row.validity.as_str())),
                (
                    "referenced_by_native_event",
                    row.referenced_by_event.to_string(),
                ),
                ("evidence_hydrated", "false".to_owned()),
                (
                    "failure_domains",
                    array(
                        &signal
                            .failure_domains
                            .iter()
                            .map(|domain| string(domain))
                            .collect::<Vec<_>>(),
                    ),
                ),
                ("valid_from_ns", string(&signal.valid_from_ns.0.to_string())),
                ("expires_at_ns", string(&signal.expires_at_ns.0.to_string())),
                ("revoked", signal.revoked.to_string()),
                ("opted_in", signal.opted_in.to_string()),
                (
                    "model_receipt",
                    signal
                        .model_receipt
                        .map_or_else(|| "null".into(), |digest| string(&digest.to_text())),
                ),
            ])
        })
        .collect::<Vec<_>>();
    let report = object(&[
        ("schema", string(ADVICE_SCHEMA)),
        ("site_lineage", string(deployment.site_lineage())),
        (
            "authority_sequence",
            string(&deployment.current_anchor().commit_sequence.to_string()),
        ),
        (
            "authority_root",
            string(&deployment.current_anchor().state_root.to_text()),
        ),
        ("privacy_scope", string(PRIVACY_SCOPE)),
        ("event_id", string(event.event_id.as_str())),
        (
            "event_revision_digest",
            string(&event.revision_digest().to_text()),
        ),
        (
            "event_policy_generation",
            string(&event.decision_path.policy_generation.to_text()),
        ),
        ("event_state", string(event.state.as_str())),
        ("event_kind", string(event.kind.as_str())),
        (
            "native_decision_fingerprint",
            string(&event.decision_path.fingerprint.to_text()),
        ),
        ("context_input_digest", string(&request.digest.to_text())),
        (
            "context_semantic_digest",
            string(&assessment.context_digest.to_text()),
        ),
        (
            "advisory_policy_digest",
            string(&assessment.advisory_policy_digest.to_text()),
        ),
        (
            "decision_digest",
            string(&assessment.decision_digest.to_text()),
        ),
        ("evaluated_at_ns", string(&request.at_ns.0.to_string())),
        ("time_basis", string("explicit_operator_evaluation_time")),
        (
            "valid_until_ns",
            assessment
                .valid_until_ns
                .map_or_else(|| "null".into(), |time| string(&time.0.to_string())),
        ),
        ("disposition", string(assessment.disposition.as_str())),
        ("identity", string("unresolved")),
        ("context_provenance", string("operator_asserted")),
        ("coverage", string(context.coverage.as_str())),
        ("threat_actions", string(context.threat_actions.as_str())),
        (
            "sensor_integrity",
            string(context.sensor_integrity.as_str()),
        ),
        ("high_consequence", context.high_consequence.to_string()),
        (
            "declared_support_groups",
            assessment.declared_support_groups.to_string(),
        ),
        ("independence_verified", "false".to_owned()),
        (
            "support_kinds",
            array(
                &assessment
                    .support_kinds
                    .iter()
                    .map(|kind| string(kind.as_str()))
                    .collect::<Vec<_>>(),
            ),
        ),
        (
            "blockers",
            array(
                &assessment
                    .blockers
                    .iter()
                    .map(|reason| string(reason))
                    .collect::<Vec<_>>(),
            ),
        ),
        (
            "unknowns",
            array(
                &assessment
                    .unknowns
                    .iter()
                    .map(|reason| string(reason))
                    .collect::<Vec<_>>(),
            ),
        ),
        ("signals", array(&signal_rows)),
        ("event_unchanged", "true".to_owned()),
        ("alert_suppression_authorized", "false".to_owned()),
        ("absence_certifiable", "false".to_owned()),
        ("effects_authorized", "false".to_owned()),
    ]);
    // The caller buffers the entire native read and advice, then revalidates source, privacy
    // and authority before releasing either. A failed context never leaks a partial report.
    writeln!(output, "familiarity_advice={report}")?;
    Ok(())
}
