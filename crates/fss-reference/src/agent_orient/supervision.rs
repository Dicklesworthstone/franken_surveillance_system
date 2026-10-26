#![forbid(unsafe_code)]
//! Session-owned recovery facts remain protected context, separate from native source evidence.

use super::*;

const CLAIM: &str = "claim:session:supervision-inventory";
const AFFORDANCE: &str = "affordance:session:supervision-inventory";

#[cfg(test)]
mod tests;

#[derive(Default)]
pub(super) struct Projection {
    pub cells: Vec<KnowledgeCell>,
    pub proof_roots: BTreeSet<ContentDigest>,
    pub unknown: Vec<String>,
    pub at_risk: Vec<String>,
    pub warnings: Vec<String>,
    pub affordances: Vec<ActionAffordance>,
}

fn same_generations(left: &LedgerAnchor, right: &LedgerAnchor) -> bool {
    left.site_lineage == right.site_lineage
        && left.ledger_epoch == right.ledger_epoch
        && left.adapter_registry_epoch == right.adapter_registry_epoch
        && left.schema_epoch == right.schema_epoch
        && left.policy_epoch == right.policy_epoch
        && left.privacy_epoch == right.privacy_epoch
}

/// Rebase only the comparison flags to the explicitly admitted orientation anchor. The owner
/// inventory compares against its live session, which may still precede this snapshot while
/// resume is preparing a workspace rebase. Historical anchors and retained state never change.
pub(super) fn inventory_at(
    entries: &[SupervisionInventoryEntry],
    anchor: &LedgerAnchor,
) -> Vec<SupervisionInventoryEntry> {
    let mut projected = entries.to_vec();
    for entry in &mut projected {
        entry.reservation_generations_current = entry.reservation.as_ref()
            .map(|reservation| same_generations(reservation.anchor(), anchor));
        if let Some(pending) = &mut entry.pending {
            pending.generations_current = same_generations(&pending.anchor, anchor);
        }
    }
    projected
}

/// Project journal-verified metadata only. A receipt here never establishes current source
/// custody, acquisition coverage, report delivery, or permission to act on an old report.
pub(super) fn project(
    snapshot: &DeploymentSnapshot,
    request: &OrientRequest,
    binding: Option<&OrientSessionBinding>,
) -> Result<Projection, ContractError> {
    let mut result = Projection::default();
    let Some(binding) = binding else { return Ok(result); };
    let Some(entries) = &binding.supervisions else {
        result.unknown.push(
            "Durable supervision inventory is unavailable in this projection; no absence of pending work is established."
                .to_owned(),
        );
        return Ok(result);
    };
    if entries.is_empty() { return Ok(result); }
    if entries.len() > crate::agent_session::checkpoint::journal::supervision::MAX_SESSION_SUPERVISION_SUBSCRIPTIONS {
        return Err(ContractError::BudgetExhausted);
    }
    // Workspace unknowns are conserved across transitions. Keep this boundary stable; exact
    // pending receipts and changing counters belong to the protected current-state summaries.
    result.unknown.push("Current validity of retained supervision report sources is unverified.".to_owned());
    // This derived metadata root binds every immutable state root and the current authority
    // comparisons. It deliberately excludes the enclosing journal root: ordinary reads and
    // workspace publication must not create a perpetual semantic change at a fixed state.
    let root = digest_of("fss.reference_orient_supervision_inventory.v1", |encoder| {
        binding.session_id.encode_canonical(encoder);
        encoder.u64(entries.len() as u64);
        for entry in entries {
            encoder.digest(entry.state_digest);
            encoder.bool(entry.authority_current);
            encoder.bool(entry.reservation.is_some());
            if let Some(reservation) = &entry.reservation {
                encoder.bool(same_generations(reservation.anchor(), &snapshot.anchor));
            }
            encoder.bool(entry.pending.is_some());
            if let Some(pending) = &entry.pending {
                encoder.bool(same_generations(&pending.anchor, &snapshot.anchor));
            }
        }
    });
    result.proof_roots.insert(root);
    let mut summaries = Vec::with_capacity(entries.len());
    for entry in entries {
        let mut status = format!(
            "Supervision {}: {}/{} attempts reserved ({} remain), {} bytes/{} reads charged",
            entry.subscription_id, entry.attempts_reserved, entry.maximum_attempts,
            entry.maximum_attempts.saturating_sub(entry.attempts_reserved),
            entry.reserved_bytes, entry.reserved_read_attempts,
        );
        if let Some(schedule) = &entry.schedule {
            status.push_str(&format!(", window {}/{}", schedule.active_window_count(), schedule.total_windows()));
            if let Some(receipt) = schedule.resolved_receipt() {
                status.push_str(&format!(", {} {}",
                    if schedule.resolved_acknowledged() == Some(true) { "ACK" } else { "discard" }, receipt));
            }
        }
        if let Some(pending) = &entry.pending {
            status.push_str(&format!(", pending {}", pending.receipt));
            if !same_generations(&pending.anchor, &snapshot.anchor) {
                status.push_str(" (historical generations differ)");
            }
        }
        if let Some(reservation) = &entry.reservation {
            status.push_str(&format!(", unfinished charged attempt {}", reservation.ordinal()));
            if !same_generations(reservation.anchor(), &snapshot.anchor) {
                status.push_str(" (historical reservation generations differ)");
            }
        }
        if !entry.authority_current {
            status.push_str(", original authority differs; existing work is not executable under these grants");
        }
        status.push('.');
        // The normal selector treats risks as critical. Pending work, receipts, progress and
        // spent budgets therefore cannot disappear just because a shorter view is requested.
        result.at_risk.push(status.clone());
        summaries.push(status);
    }
    result.cells.push(cell(KnowledgeCellParams {
        claim_id: CLAIM.to_owned(), statement: summaries.join(" "),
        knowledge_state: KnowledgeState::Known, provenance: ProvenanceClass::Derived,
        hypothesis: None, evidence: vec![root], contradictions: Vec::new(),
        valid_until: None, state_basis: None,
    })?);
    result.warnings.push(
        "Supervision metadata is current session state; retained reports remain historical. Listing and handoff do not validate sources, acknowledge reports, advance windows, refund charges or grant effects."
            .to_owned(),
    );
    // One metadata expansion covers all bounded entries, including interrupted or exhausted
    // subscriptions. The native command independently checks live grants and current history.
    result.affordances.push(ListedAffordance {
        affordance_id: AFFORDANCE.to_owned(), operation: "session.orient",
        target: format!("fss://deployment/{}",
            short_identity(ContentDigest::sha256(snapshot.site_lineage.as_bytes()))),
        rationale: format!(
            "Discover complete recovery metadata with `fss-event supervise --list yes --root ROOT --site SITE --principal {} --session {} --authority-root CURRENT_ROOT`. Requires live session generations. Use the returned label with `--resume yes --subscription LABEL` for a separately admitted inspect, poll, exact ACK/discard or schedule advance; no action is automatic. Read cost conservatively covers repeated journal verification; filesystem metadata and synchronization overhead are not metered.",
            request.principal.as_str(), binding.session_id.as_str(),
        ),
        class: AffordanceClass::Probe, supported_worlds: BTreeSet::new(),
        required_capability: CAPABILITY_SITUATION_READ,
        cost: read_cost(
            (crate::agent_session::checkpoint::journal::MAX_SESSION_JOURNAL_BYTES as u64)
                .saturating_mul(8)
                .saturating_add(snapshot.bytes_read.saturating_mul(3)),
            snapshot.files_read.saturating_mul(3).saturating_add(8),
        )?,
    }.build());
    Ok(result)
}
