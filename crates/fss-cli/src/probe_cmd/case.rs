#![forbid(unsafe_code)]
//! Explicit native-work preconditions and recoverable case linkage, without automatic retries.

use fss_reference::deployment_session::probe::case::{
    CaseProbeAction, ProbeCaseInspection, ProbeCaseLink, charge_linked_probe_delivery,
    charge_probe_case_inspection, commit_probe_case, inspect_probe_case, preflight_probe_case,
};

use super::*;
use crate::supervisor::retained::session::{
    NativeSupervisionRequest, execute_native_supervision_at,
};
use render::CaseProjection;

type Answer = (String, ExitIdentity);

pub(super) fn fail(
    args: &ProbeArgs,
    context: &ProbeContext,
    delivery: Option<&SupervisionSessionDelivery>,
    case: Option<CaseProjection<'_>>,
    charge: Option<&ProbeCharge>,
    failure: &ProbeFailure,
) -> Answer {
    rendered(
        render::response_with_case(
            args,
            context,
            delivery,
            None,
            charge,
            Some(failure),
            case.as_ref(),
        )
        .map(|prepared| prepared.text)
        .or_else(|_| {
            render::progress_refusal(args, context, delivery, charge, failure, case.as_ref())
        }),
        ExitIdentity::AGENT_REFUSED,
        COMMAND,
        &args.root,
    )
}

/// Execute exactly the selected case action. A failed/lost linked poll must use explicit
/// `probe-citation` or inspect native state before choosing a new pre-work state; no fallback
/// revalidation or automatic link is inferred from an absent citation.
pub(super) fn run(args: &ProbeArgs, cx: &ReplayCx, before: ProbeContext) -> Answer {
    match args.case.as_ref() {
        Some(CaseProbeAction::Cite {
            target,
            expected_subscription_state,
        }) => {
            let recovery = SupervisionRecoveryRequest {
                session_id: args.request.session_id.clone(),
                subscription_id: args.request.subscription_id.clone(),
                expected_authority_root: args.request.expected_authority_root,
            };
            let (native, registration) = match recover_native_supervision(
                &args.root,
                &args.request.principal,
                &recovery,
                cx,
            ) {
                Ok(value) => value,
                Err(error) => {
                    return fail(
                        args,
                        &before,
                        None,
                        None,
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
                    None,
                    None,
                    &ProbeFailure::stage(
                        "ERR-OP-PRECONDITION-FAILED-001",
                        "stored native probe belongs to another site",
                        true,
                    ),
                );
            }
            if let Err(error) = cx.checkpoint("investigate_probe:case_preflight") {
                return fail(
                    args,
                    &before,
                    None,
                    None,
                    None,
                    &ProbeFailure::stage("ERR-OP-PRECONDITION-FAILED-001", error, true),
                );
            }
            let admission = match preflight_probe_case(
                &args.root,
                &args.request,
                target,
                *expected_subscription_state,
                &registration,
                native.template().spec().hypothesis_id.as_str(),
            ) {
                Ok(admission) => admission,
                Err(error) => {
                    return fail(
                        args,
                        &before,
                        None,
                        None,
                        None,
                        &ProbeFailure::stage(
                            "ERR-OP-PRECONDITION-FAILED-001",
                            format!(
                                "Case probe preflight refused: {error}. Recover any committed link with probe-citation; inspect native progress before explicitly selecting a new subscription-state."
                            ),
                            true,
                        ),
                    );
                }
            };
            let command = SupervisionSessionRequest {
                registration,
                expected_authority_root: args.request.expected_authority_root,
                action: args.request.action,
            };
            let guarded = match execute_native_supervision_at(
                &args.root,
                &args.request.principal,
                &command,
                &native,
                *expected_subscription_state,
                cx,
            ) {
                Ok(delivery) => delivery,
                Err(error) => {
                    return fail(
                        args,
                        &before,
                        None,
                        None,
                        None,
                        &ProbeFailure::native(&error),
                    );
                }
            };
            if let Err(error) = cx.checkpoint("investigate_probe:case_commit") {
                return fail(
                    args,
                    &before,
                    Some(guarded.delivery()),
                    None,
                    None,
                    &ProbeFailure::stage(
                        "ERR-OP-PRECONDITION-FAILED-001",
                        format!(
                            "Native result is retained but case linkage did not start: {error}. Original subscription-state cannot authorize a fresh retry."
                        ),
                        true,
                    ),
                );
            }
            let link = match commit_probe_case(&args.root, &admission, &guarded) {
                Ok(link) => link,
                Err(failure) => {
                    return fail(
                        args,
                        &before,
                        Some(guarded.delivery()),
                        failure.committed.as_ref().map(CaseProjection::Linked),
                        None,
                        &ProbeFailure::stage(
                            "ERR-OP-PRECONDITION-FAILED-001",
                            format!(
                                "Case linkage boundary refused: {}. The native result remains pending; inspect probe-citation before any new work.",
                                failure.error
                            ),
                            true,
                        ),
                    );
                }
            };
            deliver_link(args, cx, before, guarded.delivery(), &native, &link)
        }
        Some(CaseProbeAction::InspectCitation(target)) => {
            if let Err(error) = cx.checkpoint("investigate_probe:case_inspect") {
                return fail(
                    args,
                    &before,
                    None,
                    None,
                    None,
                    &ProbeFailure::stage("ERR-OP-PRECONDITION-FAILED-001", error, false),
                );
            }
            let inspected = match inspect_probe_case(&args.root, &args.request, target) {
                Ok(inspected) => inspected,
                Err(failure) => {
                    return fail(
                        args,
                        &before,
                        None,
                        failure.inspected.as_ref().map(CaseProjection::Inspected),
                        None,
                        &ProbeFailure::stage("ERR-OP-PRECONDITION-FAILED-001", failure.error, true),
                    );
                }
            };
            deliver_inspection(args, cx, before, &inspected)
        }
        None => refusal(
            args,
            DeploymentSessionError::Internal(
                "case probe route lacks an explicit target".to_owned(),
            ),
        ),
    }
}

fn current_context(
    args: &ProbeArgs,
    cx: &ReplayCx,
    before: &ProbeContext,
    expected_root: ContentDigest,
) -> Result<ProbeContext, DeploymentSessionError> {
    cx.checkpoint("investigate_probe:case_current_context")
        .map_err(|error| DeploymentSessionError::Internal(error.to_string()))?;
    let mut context = admit_probe(&args.root, &args.request)?;
    if context.oriented.journal_root != expected_root {
        return Err(DeploymentSessionError::SessionStale(
            "case probe journal changed before complete projection".to_owned(),
        ));
    }
    context.session_bytes_read = context
        .session_bytes_read
        .saturating_add(before.session_bytes_read);
    Ok(context)
}

fn deliver_link(
    args: &ProbeArgs,
    cx: &ReplayCx,
    before: ProbeContext,
    delivery: &SupervisionSessionDelivery,
    native: &NativeSupervisionRequest,
    link: &ProbeCaseLink,
) -> Answer {
    let context = match current_context(args, cx, &before, link.journal_root()) {
        Ok(context) => context,
        Err(error) => {
            return fail(
                args,
                &before,
                Some(delivery),
                Some(CaseProjection::Linked(link)),
                None,
                &ProbeFailure::stage("ERR-AGENT-SESSION-STALE-001", error, true),
            );
        }
    };
    let projected = CaseProjection::Linked(link);
    let prepared = match render::response_with_case(
        args,
        &context,
        Some(delivery),
        Some(native),
        None,
        None,
        Some(&projected),
    ) {
        Ok(value) => value,
        Err(error) => {
            return fail(
                args,
                &context,
                Some(delivery),
                Some(projected),
                None,
                &ProbeFailure::stage(
                    "ERR-AGENT-CONTEXT-INCOMPLETE-001",
                    format!(
                        "Complete linked probe withheld: {error}. Case link and pending native result remain durable."
                    ),
                    true,
                ),
            );
        }
    };
    if let Err(error) = cx.checkpoint("investigate_probe:case_charge") {
        return fail(
            args,
            &context,
            Some(delivery),
            Some(projected),
            None,
            &ProbeFailure::stage("ERR-OP-PRECONDITION-FAILED-001", error, true),
        );
    }
    let charge = match charge_linked_probe_delivery(
        &args.root,
        &args.request,
        &context,
        delivery,
        link,
        prepared.quoted_tokens,
    ) {
        Ok(charge) => charge,
        Err(failure) => {
            return fail(
                args,
                &context,
                Some(delivery),
                Some(projected),
                failure.committed.as_ref(),
                &ProbeFailure::stage(
                    "ERR-OP-PRECONDITION-FAILED-001",
                    format!(
                        "Linked probe output charge refused: {}. The case link and any committed charge remain durable.",
                        failure.error
                    ),
                    true,
                ),
            );
        }
    };
    if let Err(error) = cx.checkpoint("investigate_probe:case_release") {
        return fail(
            args,
            &context,
            Some(delivery),
            Some(projected),
            Some(&charge),
            &ProbeFailure::stage("ERR-OP-PRECONDITION-FAILED-001", error, true),
        );
    }
    match render::response_with_case(
        args,
        &context,
        Some(delivery),
        Some(native),
        Some(&charge),
        None,
        Some(&projected),
    ) {
        Ok(value) => (value.text, ExitIdentity::SUCCESS),
        Err(error) => fail(
            args,
            &context,
            Some(delivery),
            Some(projected),
            Some(&charge),
            &ProbeFailure::stage(
                "ERR-AGENT-CONTEXT-INCOMPLETE-001",
                format!(
                    "Complete charged linked projection withheld: {error}; case link, pending result and charge remain durable."
                ),
                true,
            ),
        ),
    }
}

fn deliver_inspection(
    args: &ProbeArgs,
    cx: &ReplayCx,
    before: ProbeContext,
    inspection: &ProbeCaseInspection,
) -> Answer {
    let context = match current_context(args, cx, &before, inspection.journal_root()) {
        Ok(context) => context,
        Err(error) => {
            return fail(
                args,
                &before,
                None,
                Some(CaseProjection::Inspected(inspection)),
                None,
                &ProbeFailure::stage("ERR-AGENT-SESSION-STALE-001", error, true),
            );
        }
    };
    let projected = CaseProjection::Inspected(inspection);
    let prepared = match render::response_with_case(
        args,
        &context,
        None,
        None,
        None,
        None,
        Some(&projected),
    ) {
        Ok(value) => value,
        Err(error) => {
            return fail(
                args,
                &context,
                None,
                Some(projected),
                None,
                &ProbeFailure::stage(
                    "ERR-AGENT-CONTEXT-INCOMPLETE-001",
                    format!(
                        "Complete citation inspection withheld: {error}. No native work or relink occurred."
                    ),
                    true,
                ),
            );
        }
    };
    if let Err(error) = cx.checkpoint("investigate_probe:citation_charge") {
        return fail(
            args,
            &context,
            None,
            Some(projected),
            None,
            &ProbeFailure::stage("ERR-OP-PRECONDITION-FAILED-001", error, true),
        );
    }
    let charge = match charge_probe_case_inspection(
        &args.root,
        &args.request,
        &context,
        inspection,
        prepared.quoted_tokens,
    ) {
        Ok(charge) => charge,
        Err(failure) => {
            return fail(
                args,
                &context,
                None,
                Some(projected),
                failure.committed.as_ref(),
                &ProbeFailure::stage("ERR-OP-PRECONDITION-FAILED-001", failure.error, true),
            );
        }
    };
    if let Err(error) = cx.checkpoint("investigate_probe:citation_release") {
        return fail(
            args,
            &context,
            None,
            Some(projected),
            Some(&charge),
            &ProbeFailure::stage("ERR-OP-PRECONDITION-FAILED-001", error, true),
        );
    }
    match render::response_with_case(
        args,
        &context,
        None,
        None,
        Some(&charge),
        None,
        Some(&projected),
    ) {
        Ok(value) => (value.text, ExitIdentity::SUCCESS),
        Err(error) => fail(
            args,
            &context,
            None,
            Some(projected),
            Some(&charge),
            &ProbeFailure::stage(
                "ERR-AGENT-CONTEXT-INCOMPLETE-001",
                format!(
                    "Charged historical projection withheld: {error}; committed charge remains retained, no native work occurred."
                ),
                true,
            ),
        ),
    }
}
