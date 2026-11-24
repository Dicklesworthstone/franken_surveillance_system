#![forbid(unsafe_code)]
//! Event explanation (AOP-011) and committed-deletion warning formatting for [`super`].

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    ContentDigest, EventId, EventState, EvidenceEdgeRelation, ExplainQuestion, ExplainReceipt,
    PossibleWorld,
};

use super::events::event_section;
use super::frontier::explain_affordance;
use super::types::{
    AFFORDANCE_REORIENT, DeploymentOrientation, DeploymentSnapshot, EventExplanation, OrientError,
    RetainedEvent, read_cost,
};

/// Explains one published event against a compiled orientation of the same snapshot.
///
/// The event's cells and worlds are compiled from its committed revision directly, so every
/// published event is explainable whether or not the orientation carried it inline. Returns
/// `Ok(None)` when no committed `event_revision` delta names `event_id`.
pub fn explain_event(
    snapshot: &DeploymentSnapshot,
    orientation: &DeploymentOrientation,
    event_id: &EventId,
) -> Result<Option<EventExplanation>, OrientError> {
    explain_event_with_question(snapshot, orientation, event_id, ExplainQuestion::Why)
}

/// Explains one published event for an explicit registered [`ExplainQuestion`] (`Why` or `WhyNot`).
///
/// For [`ExplainQuestion::WhyNot`], the explanation binds an `ExplainQuestion::WhyNot` receipt and
/// enumerates every exact evidence/policy/coverage/tamper blocker explaining why the event was not
/// corroborated, alerted, rejected, or certified absent.
pub fn explain_event_with_question(
    snapshot: &DeploymentSnapshot,
    orientation: &DeploymentOrientation,
    event_id: &EventId,
    question: ExplainQuestion,
) -> Result<Option<EventExplanation>, OrientError> {
    let Some(retained) = snapshot.event(event_id) else {
        return Ok(None);
    };
    let Some(hydration) = orientation
        .hydration
        .iter()
        .find(|slot| slot.event_id == *event_id)
        .cloned()
    else {
        return Ok(None);
    };
    let section = event_section(retained, snapshot.retained_absences.get(event_id.as_str()))?;
    let capsule = orientation.capsule();
    let worlds: Vec<PossibleWorld> = section.worlds().cloned().collect();
    let residual_ids = section
        .residuals
        .iter()
        .map(|world| world.world_id.clone())
        .collect();
    let explain_cost = read_cost(snapshot.bytes_read, snapshot.files_read)?;
    let mut affordances = vec![explain_affordance(
        retained,
        worlds.iter().map(|world| world.world_id.clone()).collect(),
        explain_cost,
    )];
    affordances.extend(
        capsule
            .affordances
            .iter()
            .filter(|candidate| candidate.affordance_id == AFFORDANCE_REORIENT)
            .cloned(),
    );
    affordances.sort_by(|left, right| left.affordance_id.cmp(&right.affordance_id));
    let next_actions: Vec<String> = affordances
        .iter()
        .map(|candidate| candidate.affordance_id.clone())
        .collect();

    let event = &retained.event;
    let domains = retained.failure_domains();
    let mut would_change = Vec::new();
    if !retained.corroborated() {
        would_change.push(format!(
            "Supporting evidence from a failure domain other than [{}] would allow corroboration.",
            domains.iter().cloned().collect::<Vec<_>>().join(",")
        ));
    }
    would_change.push(
        "A contradicting evidence edge in a new revision would make the presence claim conflicted."
            .to_owned(),
    );
    would_change.push(
        "A complete continuous CoverageWitness over the zone would be required before absence \
         could be certified."
            .to_owned(),
    );
    if event.state == EventState::Indeterminate {
        would_change.push(
            "A policy revision adjudicating the candidate would replace the indeterminate state."
                .to_owned(),
        );
    }
    if retained.tamper.has_open_tamper() {
        would_change.push(
            "Evidenced integrity restoration would retire the open sensor-tamper report."
                .to_owned(),
        );
    }
    let mut assumptions = vec![
        format!(
            "Revision {} is the latest committed revision at commit {}.",
            event.revision, capsule.anchor.commit_sequence
        ),
        "Failure domains are independent only when their names differ.".to_owned(),
    ];
    let mut warnings = section.warnings;
    warnings.extend(deleted_evidence_warnings(snapshot, retained));

    if question == ExplainQuestion::WhyNot {
        let supporting_domains: BTreeSet<&str> = event
            .evidence
            .iter()
            .filter(|edge| edge.counts_as_support() && !edge.failure_domain.is_empty())
            .map(|edge| edge.failure_domain.as_str())
            .collect();
        let contradiction_count = event
            .evidence
            .iter()
            .filter(|edge| edge.relation == EvidenceEdgeRelation::Contradicts)
            .count();
        if !retained.corroborated() {
            would_change.insert(
                0,
                format!(
                    "Why not corroborated: event {} has {} distinct supporting failure domain(s) ([{}]), state is '{}'; independent corroboration requires >= 2 distinct supporting sensors, capture roots, and failure domains without contradictions or open tamper.",
                    event_id.as_str(),
                    supporting_domains.len(),
                    supporting_domains
                        .iter()
                        .copied()
                        .collect::<Vec<_>>()
                        .join(","),
                    event.state.as_str(),
                ),
            );
        }
        if retained.tamper.has_open_tamper() {
            would_change.insert(
                0,
                format!(
                    "Why not alert-eligible: {} open sensor-tamper record(s) veto corroboration and alert dispatch until evidenced integrity restoration is committed.",
                    retained.tamper.open_tamper_records.len(),
                ),
            );
        }
        if contradiction_count > 0 {
            would_change.insert(
                0,
                format!(
                    "Why not escalated: {} contradicting evidence edge(s) keep the presence hypothesis conflicted.",
                    contradiction_count,
                ),
            );
        }
        if !snapshot.retained_absences.contains_key(event_id.as_str()) {
            would_change.push(
                "Why not certified absent: no complete continuous certifying CoverageWitness backs an absence ruling for this event revision."
                    .to_owned(),
            );
        }
        if event.probability.lower == 0.0 && event.probability.upper == 1.0 {
            would_change.push(
                "Why not narrowed to a calibrated probability: the committed revision carries the maximally conservative [0, 1] unit interval with no bound score calibration."
                    .to_owned(),
            );
        }
        assumptions.push(
            "Non-occurrence diagnostics (`why_not`) reflect only committed metadata at this anchor; unretained observations or external actions outside the ledger are not asserted absent."
                .to_owned(),
        );
    }

    let mut subgraph = vec![retained.event_root, retained.revision_digest];
    subgraph.extend(event.evidence.iter().map(|edge| edge.digest));
    subgraph.extend(event.model_receipts.iter().copied());
    let handles = vec![
        hydration.handle.clone(),
        format!("fss://event/{}/coverage", event_id.as_str()),
    ];
    let receipt =
        ExplainReceipt::compile(question, retained.revision_digest, subgraph, handles, 16)?;
    Ok(Some(EventExplanation {
        event: retained.clone(),
        receipt,
        cells: section.cells,
        worlds,
        residual_ids,
        affordances,
        next_actions,
        would_change,
        assumptions,
        warnings,
        hydration,
    }))
}

/// Deletions listed in an orientation before a summary line takes over.
const MAX_LISTED_DELETIONS: usize = 3;

/// Orientation warnings naming every committed deletion: deleted evidence is `deleted`, never
/// silently missing.
pub(super) fn deletion_warnings(snapshot: &DeploymentSnapshot) -> Vec<String> {
    let entries = snapshot.deletions.entries();
    let mut warnings: Vec<String> = entries
        .iter()
        .take(MAX_LISTED_DELETIONS)
        .map(|entry| {
            format!(
                "{} was deleted under deletion plan {} ({} object(s), {} byte(s) unlinked \
                 from local custody, not cryptographically erased; completion {}): its evidence \
                 handles resolve to `deleted`, not missing; {} event(s) keep their revision \
                 history over deleted evidence.",
                deleted_subject(&entry.plan, "Import"),
                entry.plan_digest,
                entry.plan.deletable.len(),
                entry.plan.deletable_bytes(),
                if entry.is_complete() {
                    "durable"
                } else {
                    "pending (rerun the same commit)"
                },
                entry.plan.events.len()
            )
        })
        .collect();
    if entries.len() > MAX_LISTED_DELETIONS {
        warnings.push(format!(
            "{} further committed deletion(s) are not listed; their evidence handles also \
             resolve to `deleted`.",
            entries.len() - MAX_LISTED_DELETIONS
        ));
    }
    warnings
}

/// What a committed deletion removed: `<Import> sha256:...` for an import scope, or the sensor
/// or event scope with its member imports.
fn deleted_subject(plan: &crate::deletion::DeletionPlan, import_word: &str) -> String {
    match &plan.scope {
        crate::deletion::DeletionScope::Import(import) => format!("{import_word} {import}"),
        crate::deletion::DeletionScope::ReviewExpiry(selection) => {
            let roots: Vec<String> = selection
                .roots()
                .iter()
                .map(|root| root.to_text())
                .collect();
            format!(
                "{} scope {} (review root(s) {}; source imports retained)",
                if import_word == "Import" {
                    "The"
                } else {
                    "the"
                },
                plan.scope.text(),
                roots.join(", ")
            )
        }
        scope => {
            let members: Vec<String> = plan.imports.iter().map(|d| d.to_text()).collect();
            format!(
                "{} scope {} (import(s) {})",
                if import_word == "Import" {
                    "The"
                } else {
                    "the"
                },
                scope.text(),
                members.join(", ")
            )
        }
    }
}

/// Explanation warnings for an event whose cited evidence a committed deletion removed.
fn deleted_evidence_warnings(
    snapshot: &DeploymentSnapshot,
    retained: &RetainedEvent,
) -> Vec<String> {
    let event = &retained.event;
    let object = format!("object:event:{}", event.event_id.as_str());
    let mut cited: BTreeMap<ContentDigest, ContentDigest> = BTreeMap::new();
    for digest in event
        .evidence
        .iter()
        .flat_map(|edge| [Some(edge.digest), edge.capsule_digest])
        .flatten()
        .chain(event.model_receipts.iter().copied())
    {
        if let Some(entry) = snapshot.deletions.object(digest) {
            cited.insert(digest, entry.plan_digest);
        }
    }
    let mut warnings: Vec<String> = cited
        .iter()
        .map(|(digest, plan)| {
            format!(
                "Evidence {digest} of {} is deleted (deletion plan {plan}); its availability is \
                 `deleted`, not missing, and the revision history is retained unchanged.",
                event.event_id.as_str()
            )
        })
        .collect();
    for entry in snapshot.deletions.entries() {
        if entry
            .plan
            .events
            .iter()
            .any(|reference| reference.object_id == object)
        {
            warnings.push(format!(
                "{} cites evidence of {}, which deletion plan {} removed; the event keeps \
                 every committed revision and no new revision was minted.",
                event.event_id.as_str(),
                deleted_subject(&entry.plan, "import"),
                entry.plan_digest
            ));
        }
    }
    warnings
}
