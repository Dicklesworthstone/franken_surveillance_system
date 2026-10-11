#![forbid(unsafe_code)]
//! Bounded historical recovery rendering. These records are not live admission responses.

use fss_cli::agent_json::{
    agent_session, array, digests, evidence_anchor, object, optional_string, session_capsule,
    string, strings,
};
use fss_core::ContractError;
use fss_reference::deployment_backup::{AgentPublicationState, AgentRecoveryState};
use fss_reference::deployment_session::AgentRecoveryRecord;

fn rows<T>(
    values: &[T],
    used: &mut usize,
    render: impl Fn(&T) -> Result<String, ContractError>,
) -> Result<String, ContractError> {
    let mut out = Vec::new();
    for value in values {
        let row = render(value)?;
        *used = used
            .checked_add(row.len().saturating_add(1))
            .ok_or(ContractError::CountBoundExceeded)?;
        if *used > super::MAX_REPORT_BYTES {
            return Err(ContractError::CountBoundExceeded);
        }
        out.push(row);
    }
    Ok(array(&out))
}

fn publication(value: &AgentPublicationState) -> Result<String, ContractError> {
    let record = match &value.record {
        AgentRecoveryRecord::Mission(record) => object(&[
            ("mission_id", string(record.mission_id.as_str())),
            ("session_id", string(record.session_id.as_str())),
            ("principal", string(record.principal.as_str())),
            ("site_lineage", string(&record.site_lineage)),
            ("mission", string(&record.mission)),
            ("objective", string(&record.objective)),
            ("opening_anchor_token", string(&record.opening_anchor_token)),
            ("view", string(record.view.id())),
            ("token_budget", record.token_budget.to_string()),
            ("created_at_ns", record.created_at.0.to_string()),
        ]),
        AgentRecoveryRecord::Handoff(record) => object(&[
            ("handoff_id", string(record.capsule.handoff_id.as_str())),
            ("mission_id", string(record.capsule.mission_id.as_str())),
            ("session_id", string(record.capsule.source_session_id.as_str())),
            ("principal", string(record.capsule.source_principal_id.as_str())),
            ("anchor", evidence_anchor(&record.capsule.anchor)),
            ("anchor_token", string(&record.anchor_token)),
            ("workspace_revision", record.workspace_revision.to_string()),
            ("workspace_digest", string(&record.workspace_digest.to_text())),
            ("session_digest", string(&record.session_digest.to_text())),
            ("mission_digest", string(&record.mission_digest.to_text())),
            ("note", optional_string(record.note.as_deref())),
            ("assumptions", strings(&record.assumptions)),
            ("invalidated_assumptions", strings(&record.invalidated_assumptions)),
            ("unknowns", strings(&record.unknowns)),
            ("obligations", strings(&record.obligations)),
            ("indeterminate_effects", strings(&record.indeterminate_effects)),
            ("prepared_operations", strings(&record.prepared_operations)),
            ("recommended_affordances", strings(&record.recommended_affordances)),
            ("invalidators", strings(&record.invalidators)),
            ("created_at_ns", record.capsule.created_at.0.to_string()),
            ("expires_at_ns", record.capsule.expires_at.0.to_string()),
        ]),
        AgentRecoveryRecord::Plan(record) => object(&[
            ("plan_id", string(&record.plan_id)),
            ("session_id", string(record.session_id.as_str())),
            ("mission_id", string(record.mission_id.as_str())),
            ("principal", string(record.principal.as_str())),
            ("anchor_token", string(&record.anchor_token)),
            ("intent", string(&record.intent)),
            ("event_id", string(&record.event_id)),
            ("event_revision", string(&record.event_revision.to_text())),
            ("operation_id", string(&record.operation_id)),
            ("obligation_id", string(&record.obligation_id)),
            ("plan_approval", string(&record.plan_approval.to_text())),
            ("control_plan_digest", string(&record.control_plan_digest.to_text())),
            ("route", object(&[
                ("relay", string(&record.route.relay)),
                ("path", string(&record.route.path)),
                ("plaintext_approval", string(&record.route.plaintext_approval.to_text())),
                ("deadline_ms", record.route.deadline_ms.to_string()),
            ])),
            ("case", record.case.as_ref().map_or_else(
                || "null".to_owned(),
                |(id, digest)| object(&[
                    ("case_id", string(id)),
                    ("revision", string(&digest.to_text())),
                ]),
            )),
            ("created_at_ns", record.created_at.0.to_string()),
        ]),
        AgentRecoveryRecord::Episode(record) => object(&[
            ("plan_id", string(&record.plan_id)),
            ("mission_id", string(record.mission_id.as_str())),
            ("principal", string(record.principal.as_str())),
            ("operation_id", string(&record.operation_id)),
            ("terminal_state", string(record.terminal_state.as_str())),
            ("episode", fss_cli::episode_cmd::episode_json(&record.episode)),
            ("recorded_at_ns", record.recorded_at.0.to_string()),
        ]),
        AgentRecoveryRecord::Finding(record) => fss_cli::finding_cmd::finding_json(record)?,
        AgentRecoveryRecord::Feedback(record) => fss_cli::feedback_cmd::feedback_json(record),
    };
    Ok(object(&[
        ("slot", string(&value.slot)),
        ("kind", string(&value.kind)),
        ("root", string(&value.root.to_text())),
        ("metadata_digest", string(&value.metadata_digest.to_text())),
        ("children", digests(&value.children)),
        ("record", record),
    ]))
}

pub(super) fn report(state: &AgentRecoveryState) -> Result<String, ContractError> {
    // Leave room for the fixed envelope and summary before accumulating potentially large
    // cognition. Refuse a complete over-budget report; never skip a revision or truncate text.
    let mut used = 4096;
    let sessions = rows(&state.sessions.sessions, &mut used, |retained| {
        Ok(object(&[
            ("session", agent_session(&retained.session, &retained.basis)),
            ("opening_digest", string(&retained.opening_digest.to_text())),
            ("closed", retained.closed.to_string()),
            ("spent_tokens", retained.spent_tokens.to_string()),
            ("last_observed_at_ns", retained.last_observed_at.0.to_string()),
        ]))
    })?;
    let workspaces = rows(&state.sessions.workspace_revisions, &mut used, |revision| {
        Ok(object(&[
            ("digest", string(&revision.digest().to_text())),
            ("parent_digest", optional_string(
                revision.parent_digest().map(|digest| digest.to_text()).as_deref(),
            )),
            ("workspace", session_capsule(
                revision.capsule(),
                revision.contract_basis(),
                revision.invalidated_actions(),
            )),
        ]))
    })?;
    let claims = rows(&state.sessions.claims, &mut used, |revision| {
        let claim = revision.claim();
        Ok(object(&[
            ("claim_id", string(&claim.claim_id)),
            ("case_id", optional_string(claim.case_id.as_deref())),
            ("state", string(claim.state.as_str())),
            ("owner_session_id", string(&claim.owner_session_id)),
            ("principal", string(revision.principal().as_str())),
            ("mission_id", string(revision.mission().as_str())),
            ("work_root", string(&revision.work_root().to_text())),
            ("revision", revision.revision().to_string()),
            ("revision_digest", string(&revision.digest().to_text())),
            ("lease_incarnation", claim.lease_incarnation.to_string()),
            ("expires_at_ns", claim.expires_at_ns.to_string()),
            ("changed_at_ns", revision.changed_at().0.to_string()),
            ("dependencies", strings(&claim.dependencies)),
            ("progress_json", string(&claim.progress_json)),
            ("result_root", optional_string(claim.result_root.as_deref())),
            ("lease_admitted", "false".to_owned()),
        ]))
    })?;
    let cases = rows(&state.sessions.cases, &mut used, |revision| {
        Ok(fss_cli::investigate_cmd::investigation_json(revision))
    })?;
    let publications = rows(&state.publications, &mut used, publication)?;
    let report = object(&[
        ("format", string(super::FORMAT)),
        ("status", string("agent-inspected")),
        ("profile", string(fss_reference::deployment_backup::AGENT_BACKUP_PROFILE)),
        ("source_anchor", evidence_anchor(&state.source_anchor)),
        ("historical_only", "true".to_owned()),
        ("restore_fence_present", state.restored.to_string()),
        ("authority_granted", "false".to_owned()),
        ("agent_state", super::agent_summary(&state.summary)),
        ("sessions", sessions),
        ("workspace_revisions", workspaces),
        ("claims", claims),
        ("cases", cases),
        ("publications", publications),
    ]);
    if report.len() > super::MAX_REPORT_BYTES {
        return Err(ContractError::CountBoundExceeded);
    }
    Ok(report)
}
