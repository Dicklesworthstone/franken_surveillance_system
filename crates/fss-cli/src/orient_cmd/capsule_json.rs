#![forbid(unsafe_code)]
//! JSON serialization of `fss.agent_situation_frame.v1` and `fss.situation_capsule.v1` payloads
//! from a compiled [`DeploymentOrientation`].

use fss_core::{ContentDigest, LedgerAnchor};
use fss_reference::agent_orient::{
    CAPABILITY_SITUATION_READ, DeploymentOrientation, ZoneCoverageState,
};

use super::diagnostics::RenderError;
use super::response::privacy_projection;
use crate::agent_json;

/// Rendering context of one orientation's cells and affordances.
pub(crate) fn contexts(
    orientation: &DeploymentOrientation,
) -> (
    agent_json::CellContext<'_>,
    agent_json::AffordanceContext<'_>,
) {
    let capsule = orientation.capsule();
    (
        agent_json::CellContext {
            anchor: &capsule.anchor,
            mission_id: capsule.mission_id.as_str(),
            invalidators: &orientation.validity.invalidators,
        },
        agent_json::AffordanceContext {
            anchor: &capsule.anchor,
            world_envelope_id: &capsule.frame.world_envelope.envelope_id,
            expires_at_ns: orientation.validity.valid_until.0,
            invalidators: &orientation.validity.invalidators,
        },
    )
}

/// Domains the frame cannot observe: the site outside retained evidence, and every objective zone
/// that is not covered.
fn not_observable_domains(orientation: &DeploymentOrientation) -> String {
    let mut domains = vec!["site activity outside retained evidence".to_owned()];
    if let Some(assessment) = &orientation.coverage {
        domains.extend(
            assessment
                .zones
                .iter()
                .filter(|zone| zone.state != ZoneCoverageState::Covered)
                .map(|zone| format!("{} ({})", zone.label(), zone.state.as_str())),
        );
    }
    agent_json::strings(domains)
}

/// Registered bound of the frame's `coverage.gaps` and `coverage.witnessIds`.
const MAX_FRAME_GAPS: usize = 512;
const MAX_FRAME_WITNESS_IDS: usize = 512;

/// Every gap when they fit the registered bound; otherwise the first 511 and one explicit
/// statement of how many more exist and where they hydrate (never a silent drop).
fn bounded_gaps(mut gaps: Vec<String>) -> Vec<String> {
    if gaps.len() > MAX_FRAME_GAPS {
        let more = gaps.len() - (MAX_FRAME_GAPS - 1);
        gaps.truncate(MAX_FRAME_GAPS - 1);
        gaps.push(format!(
            "{more} further coverage gap(s) are named by the per-zone coverage knowledge cells."
        ));
    }
    gaps
}

/// The frame's `coverage` block: `uncertified` without retained coverage, otherwise the declared
/// domains of the covered zones, their witness digests, and every named gap.
fn frame_coverage(orientation: &DeploymentOrientation) -> String {
    let capsule = orientation.capsule();
    let Some(assessment) = &orientation.coverage else {
        return agent_json::object(&[
            ("status", agent_json::string("uncertified")),
            (
                "domains",
                agent_json::strings([capsule.anchor.site_lineage.as_str()]),
            ),
            ("witnessIds", "[]".to_owned()),
            (
                "gaps",
                agent_json::strings(["No CoverageWitness is retained for the site."]),
            ),
            ("absenceClaimsCertified", "false".to_owned()),
        ]);
    };
    let complete = assessment.complete();
    let any_covered = assessment
        .zones
        .iter()
        .any(|zone| zone.state == ZoneCoverageState::Covered);
    let status = if complete {
        "complete_for_declared_domain"
    } else if any_covered {
        "bounded_partial"
    } else {
        "not_observable"
    };
    let mut domains = assessment.declared_domains();
    if domains.is_empty() {
        domains.push(capsule.anchor.site_lineage.clone());
    }
    let mut witness_ids: Vec<String> = assessment
        .witness_digests()
        .into_iter()
        .map(ContentDigest::to_text)
        .collect();
    let mut gaps = assessment.gaps();
    if witness_ids.len() > MAX_FRAME_WITNESS_IDS {
        let more = witness_ids.len() - MAX_FRAME_WITNESS_IDS;
        witness_ids.truncate(MAX_FRAME_WITNESS_IDS);
        gaps.push(format!(
            "{more} further coverage witness digest(s) exceed the 512-entry frame witnessIds bound \
             and remain bound in retained coverage_witness ledger records."
        ));
    }
    agent_json::object(&[
        ("status", agent_json::string(status)),
        ("domains", agent_json::strings(domains)),
        ("witnessIds", agent_json::strings(witness_ids)),
        ("gaps", agent_json::strings(bounded_gaps(gaps))),
        ("absenceClaimsCertified", complete.to_string()),
    ])
}

/// The capsule's `situationFrame` as `fss.agent_situation_frame.v1`.
fn situation_frame(orientation: &DeploymentOrientation) -> Result<String, RenderError> {
    let capsule = orientation.capsule();
    let frame = &capsule.frame;
    let (cell_context, _) = contexts(orientation);
    let cells: Vec<String> = frame
        .knowledge_cells
        .iter()
        .map(|cell| agent_json::knowledge_cell(cell, &cell_context))
        .collect();
    let receipt = &orientation.publication.compression_receipt;
    let entities: Vec<String> = orientation
        .hydration
        .iter()
        .filter(|slot| {
            slot.cells_inline || orientation.headline_event.as_ref() == Some(&slot.event_id)
        })
        .map(|slot| {
            agent_json::object(&[
                ("entityId", agent_json::string(slot.event_id.as_str())),
                ("kind", agent_json::string("event")),
                ("relevance", slot.consequence_severity.to_string()),
                ("state", agent_json::string(slot.physical_state.as_str())),
                ("provenance", agent_json::string("derived")),
                ("summary", agent_json::string(&slot.summary)),
                (
                    "evidenceHandles",
                    agent_json::strings([slot.handle.as_str()]),
                ),
            ])
        })
        .collect();
    let summarized_cells: usize = orientation
        .hydration
        .iter()
        .filter(|slot| !slot.cells_inline)
        .map(|slot| slot.cell_count)
        .sum();
    let selected = frame.knowledge_cells.len();
    let hard: Vec<&str> = frame
        .knowledge_cells
        .iter()
        .filter(|cell| agent_json::can_change_action(cell))
        .map(|cell| cell.claim_id())
        .collect();
    let mut decision_changing: Vec<String> = orientation.contradictions.clone();
    if let Some(top) = &orientation.headline_event {
        decision_changing.push(top.as_str().to_owned());
    }
    let world_stop = if orientation.aggregated_world_count > 0 {
        "per-event worlds aggregated per kind; members hydrate through event handles"
    } else {
        "complete"
    };
    let frame_digest = frame
        .frame_digest()
        .map_err(|_| RenderError("frame digest"))?;
    Ok(agent_json::object(&[
        ("schema", agent_json::string("fss.agent_situation_frame.v1")),
        ("frameId", agent_json::string(&frame.frame_id)),
        ("objectiveId", agent_json::string(&frame.objective_id)),
        ("anchor", agent_json::evidence_anchor(&frame.anchor)),
        ("priorFrameId", "null".to_owned()),
        (
            "worldEnvelope",
            agent_json::world_envelope(
                &frame.world_envelope,
                &capsule.affordances,
                &frame.knowledge_cells,
                &agent_json::WorldSelection {
                    candidate_world_count: orientation.candidate_world_count,
                    stop_reason: world_stop,
                },
            ),
        ),
        ("knowledgeCells", agent_json::array(&cells)),
        ("salientEntities", agent_json::array(&entities)),
        ("changes", agent_json::strings(&frame.changed)),
        (
            "contradictions",
            agent_json::strings(&orientation.contradictions),
        ),
        ("unknowns", agent_json::strings(&frame.unknown)),
        ("notObservableDomains", not_observable_domains(orientation)),
        ("coverage", frame_coverage(orientation)),
        (
            "obligations",
            agent_json::strings(capsule.obligations.iter().map(|id| id.as_str())),
        ),
        (
            "evidenceHandles",
            agent_json::strings(&frame.evidence_handles),
        ),
        ("selectedHypothesisWorkspaceId", "null".to_owned()),
        ("activePlanId", "null".to_owned()),
        (
            "selectionWitness",
            agent_json::object(&[
                ("candidateCount", (selected + summarized_cells).to_string()),
                ("selectedCount", selected.to_string()),
                ("omittedCount", summarized_cells.to_string()),
                ("hardInclusions", agent_json::strings(hard)),
                (
                    "decisionChangingItems",
                    agent_json::strings(&decision_changing),
                ),
                (
                    "stopReason",
                    agent_json::string(receipt.stop_reason.as_str()),
                ),
                ("outputDigest", agent_json::string(&frame_digest.to_text())),
            ]),
        ),
    ]))
}

/// The orient payload: the capsule as `fss.situation_capsule.v1` with every verified
/// publication section for the view.
pub(super) fn orient_payload(
    orientation: &DeploymentOrientation,
) -> Result<String, Box<dyn std::error::Error>> {
    situation_capsule_payload(orientation, &CapsuleOverrides::default())
}

/// What a durable-session answer adds to an orientation's `fss.situation_capsule.v1` payload.
#[derive(Default)]
pub(crate) struct CapsuleOverrides<'a> {
    /// The anchor a resumed session was handed off at.
    pub(crate) previous_anchor: Option<&'a LedgerAnchor>,
    /// The rendered `agent_meaningful_delta.v1` since that anchor.
    pub(crate) meaningful_delta: Option<String>,
    /// Rendered epistemic-debt items appended after the orientation's own.
    pub(crate) extra_debt: Vec<String>,
    /// The durable session's symbol-table generation.
    pub(crate) symbol_table_generation: u64,
}

/// An orientation as `fss.situation_capsule.v1`, with a durable session's `overrides`.
pub(crate) fn situation_capsule_payload(
    orientation: &DeploymentOrientation,
    overrides: &CapsuleOverrides<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    let publication = &orientation.publication;
    let capsule = orientation.capsule();
    let (_, affordance_context) = contexts(orientation);
    let affordances = capsule
        .affordances
        .iter()
        .map(|candidate| agent_json::affordance(candidate, &affordance_context))
        .collect::<Option<Vec<_>>>()
        .ok_or(RenderError("unregistered affordance operation"))?;
    let objective = agent_json::objective_contract(&orientation.objective)
        .ok_or(RenderError("objective contract"))?;
    let attention: Vec<String> = orientation
        .attention
        .iter()
        .map(|item| {
            agent_json::object(&[
                ("itemId", agent_json::string(&item.item_id)),
                ("kind", agent_json::string(item.kind)),
                ("priorityClass", agent_json::string(item.priority_class)),
                ("missionRelevance", format!("{}", item.mission_relevance)),
                ("decisionImpact", format!("{}", item.decision_impact)),
                ("reason", agent_json::string(&item.reason)),
                ("handle", agent_json::string(&item.handle)),
            ])
        })
        .collect();
    let mut debt: Vec<String> = orientation
        .epistemic_debt
        .iter()
        .map(|item| {
            agent_json::object(&[
                ("debtId", agent_json::string(&item.debt_id)),
                ("assumption", agent_json::string(&item.assumption)),
                ("deferredReason", agent_json::string(&item.deferred_reason)),
                (
                    "dependentDecisions",
                    agent_json::strings(&item.dependent_decisions),
                ),
                (
                    "consequenceIfWrong",
                    agent_json::string(&item.consequence_if_wrong),
                ),
                ("cheapestTest", agent_json::string(&item.cheapest_test)),
                ("reviewTrigger", agent_json::string(&item.review_trigger)),
            ])
        })
        .collect();
    debt.extend(overrides.extra_debt.iter().cloned());
    let validity = &orientation.validity;
    let mission_progress = orientation.mission_progress.as_ref();
    Ok(agent_json::object(&[
        ("schema", agent_json::string("fss.situation_capsule.v1")),
        (
            "contractBasis",
            agent_json::contract_basis(&capsule.contract_basis),
        ),
        ("capsuleId", agent_json::string(&capsule.capsule_id)),
        ("revision", capsule.revision.to_string()),
        ("missionId", agent_json::string(capsule.mission_id.as_str())),
        // An explicitly enrolled execution objective has its own retained revisions; the
        // original prose-only MissionRecord remains immutable. Historical revisions keep
        // their identity here while protected context explains assessment freshness.
        (
            "missionRevision",
            mission_progress
                .map_or(0, |progress| progress.revision.revision())
                .to_string(),
        ),
        ("sessionId", agent_json::string(capsule.session_id.as_str())),
        (
            "principalId",
            agent_json::string(capsule.principal_id.as_str()),
        ),
        ("anchor", agent_json::evidence_anchor(&capsule.anchor)),
        (
            "previousAnchor",
            overrides
                .previous_anchor
                .map_or_else(|| "null".to_owned(), agent_json::evidence_anchor),
        ),
        ("objectiveContract", objective),
        (
            "effectiveCapabilities",
            agent_json::strings([CAPABILITY_SITUATION_READ]),
        ),
        (
            "privacyProjection",
            privacy_projection(&capsule.anchor).capsule_json(),
        ),
        (
            "decisionDeadlineNs",
            mission_progress.map_or_else(
                || "null".to_owned(),
                |progress| {
                    progress
                        .revision
                        .criterion()
                        .decision_deadline
                        .0
                        .to_string()
                },
            ),
        ),
        ("situationFrame", situation_frame(orientation)?),
        // Without a previous anchor no change is claimed.
        (
            "meaningfulDelta",
            overrides
                .meaningful_delta
                .clone()
                .unwrap_or_else(|| "null".to_owned()),
        ),
        ("attentionFrontier", agent_json::array(&attention)),
        (
            "activeInvestigations",
            agent_json::strings(&orientation.active_investigations),
        ),
        ("activeHypotheses", "[]".to_owned()),
        (
            "activePlans",
            agent_json::strings(&orientation.active_plans),
        ),
        (
            "obligations",
            agent_json::strings(capsule.obligations.iter().map(|id| id.as_str())),
        ),
        (
            "indeterminateEffects",
            agent_json::strings(
                orientation
                    .indeterminate_effects
                    .iter()
                    .map(|id| id.as_str()),
            ),
        ),
        ("epistemicDebt", agent_json::array(&debt)),
        (
            "resourceState",
            agent_json::resource_state(&publication.resource_state),
        ),
        ("affordances", agent_json::array(&affordances)),
        (
            "controlEnvelope",
            agent_json::control_envelope(&publication.control_envelope),
        ),
        (
            "contextPack",
            agent_json::context_pack(&publication.context_pack),
        ),
        (
            "compressionReceipt",
            agent_json::compression_receipt(&publication.compression_receipt),
        ),
        // Context items carry no aliases; the generation is the durable session's (0 for a
        // read-only orientation, whose symbol table is never rotated).
        (
            "symbolTableGeneration",
            overrides.symbol_table_generation.to_string(),
        ),
        (
            "validity",
            agent_json::object(&[
                ("validUntilNs", validity.valid_until.0.max(0).to_string()),
                ("invalidators", agent_json::strings(&validity.invalidators)),
                (
                    "reanchorRequiredOn",
                    agent_json::strings(&validity.reanchor_required_on),
                ),
            ]),
        ),
        (
            "continuation",
            agent_json::optional_string(publication.context_pack.continuation.as_deref()),
        ),
        (
            "decisionFingerprint",
            agent_json::string(&capsule.decision_fingerprint()?.to_text()),
        ),
        ("createdAtNs", capsule.created_at.0.max(0).to_string()),
    ]))
}
