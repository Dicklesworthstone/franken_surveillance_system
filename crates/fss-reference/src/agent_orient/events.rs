#![forbid(unsafe_code)]
//! Event knowledge-cell compilation, consequence ranking, world aggregation, hydration slots, and
//! source-omission accounting for [`super`].

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    AgentView, BudgetVector, CompressionLossClass, CompressionTransform, CompressionTransformKind,
    ContentDigest, ContractError, EventState, ExpansionHandle, KnowledgeCell, KnowledgeCellParams,
    KnowledgeState, PossibleWorld, ProvenanceClass,
};

use super::types::{
    CLAIM_COVERAGE, CLAIM_EVENTS, DIRECT_EVENT_EXPANSION_LIMIT, DeploymentSnapshot, EventHydration,
    OrientRequest, RetainedEvent, SOURCE_CLASS_EVENT_DETAIL, SOURCE_CLASS_WORLD_DETAIL,
    WORLD_EVENTS_PREFIX, WORLD_PROTECTED_SUMMARY, WORLD_UNOBSERVED_ACTIVITY, cell, event_claim,
    inline_event_budget, plural, read_cost, short_identity,
};
use crate::ReferenceError;
use crate::ingest::source_coverage::RetainedAbsence;
use crate::situation::{
    physical_knowledge_state, physical_statement, policy_hypothesis, reconciliation_basis_for,
    sensor_integrity_cell,
};
use crate::situation_sections::{SourceOmission, SourceOmissions};

/// Knowledge cells, worlds, and statements contributed by one published event.
pub(super) struct EventSection {
    pub(super) cells: Vec<KnowledgeCell>,
    pub(super) alternatives: Vec<PossibleWorld>,
    pub(super) residuals: Vec<PossibleWorld>,
    pub(super) lifecycle_claim: String,
    pub(super) unknown: Vec<String>,
    pub(super) at_risk: Vec<String>,
    pub(super) warnings: Vec<String>,
    pub(super) proof_roots: Vec<ContentDigest>,
    /// Knowledge state of the event's physical-presence claim.
    pub(super) physical_state: KnowledgeState,
    /// Whether any of the event's cells carries contradicting evidence.
    pub(super) contradicted: bool,
}

impl EventSection {
    pub(super) fn worlds(&self) -> impl Iterator<Item = &PossibleWorld> {
        self.alternatives.iter().chain(&self.residuals)
    }

    /// Highest consequence severity among the event's protected worlds.
    pub(super) fn protected_severity(&self) -> u8 {
        self.worlds()
            .filter(|world| world.protected)
            .map(|world| world.consequence_severity)
            .max()
            .unwrap_or(0)
    }
}

pub(super) fn event_section(
    retained: &RetainedEvent,
    absence: Option<&RetainedAbsence>,
) -> Result<EventSection, ReferenceError> {
    let event = &retained.event;
    let id = &event.event_id;
    let lifecycle_claim = event_claim(id, "lifecycle");
    let physical_claim = event_claim(id, "unknown-presence");
    let corroboration_claim = event_claim(id, "corroboration");
    let supporting: Vec<_> = event
        .evidence
        .iter()
        .filter(|edge| edge.counts_as_support())
        .map(|edge| edge.digest)
        .collect();
    let contradicting: Vec<_> = event
        .evidence
        .iter()
        .filter(|edge| edge.counts_as_contradiction())
        .map(|edge| edge.digest)
        .collect();
    let domains = retained.failure_domains();
    let mut cells = vec![cell(KnowledgeCellParams {
        claim_id: lifecycle_claim.clone(),
        statement: format!(
            "Event {} is published at revision {} as kind {} in state {} (commit {}, zones [{}]).",
            id.as_str(),
            event.revision,
            event.kind.as_str(),
            event.state.as_str(),
            retained.committed_sequence,
            event.zone_ids.join(",")
        ),
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![retained.event_root, retained.revision_digest],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    })?];

    let computed = physical_knowledge_state(event.state, &supporting, &contradicting);
    let physical_state = if retained.tamper.has_open_tamper() && computed == KnowledgeState::Known {
        KnowledgeState::Unknown
    } else {
        computed
    };
    cells.push(cell(KnowledgeCellParams {
        claim_id: physical_claim.clone(),
        statement: format!(
            "{} ({} candidate.)",
            physical_statement(event.state),
            event.kind.as_str()
        ),
        knowledge_state: physical_state,
        provenance: ProvenanceClass::Derived,
        hypothesis: Some(policy_hypothesis(event.state)),
        evidence: supporting.clone(),
        contradictions: contradicting.clone(),
        valid_until: None,
        state_basis: reconciliation_basis_for(physical_state, retained.revision_digest),
    })?);

    let corroborated = retained.corroborated();
    cells.push(cell(KnowledgeCellParams {
        claim_id: corroboration_claim,
        statement: if corroborated {
            format!(
                "Independent corroboration across {} is committed.",
                plural(domains.len(), "failure domain", "failure domains")
            )
        } else {
            format!(
                "Not corroborated: evidence names {} ([{}]); a single sensor cannot corroborate itself.",
                plural(domains.len(), "failure domain", "failure domains"),
                domains.iter().cloned().collect::<Vec<_>>().join(",")
            )
        },
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: vec![retained.revision_digest],
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    })?);
    if let Some(integrity) = sensor_integrity_cell(id.as_str(), event, &retained.tamper)? {
        cells.push(integrity);
    }

    let mut alternatives = Vec::new();
    let mut residuals = Vec::new();
    let mut unknown = Vec::new();
    let mut at_risk = Vec::new();
    let mut warnings = Vec::new();
    let world = |suffix: &str| format!("world:event:{}:{suffix}", id.as_str());
    match event.state {
        EventState::Corroborated => {
            alternatives.push(PossibleWorld {
                world_id: world("present"),
                description:
                    "The corroborated activity is physically present in the retained interval."
                        .to_owned(),
                claim_ids: BTreeSet::from([lifecycle_claim.clone(), physical_claim.clone()]),
                evidence: vec![retained.revision_digest],
                consequence_severity: 5,
                protected: true,
            });
            residuals.push(PossibleWorld {
                world_id: world("common-mode-error"),
                description: "The corroborating sources share a spoofing, failure, or environmental artifact.".to_owned(),
                claim_ids: BTreeSet::from([lifecycle_claim.clone()]),
                evidence: vec![retained.event_root],
                consequence_severity: 4,
                protected: true,
            });
        }
        EventState::Rejected => {
            alternatives.push(PossibleWorld {
                world_id: world("candidate-rejected"),
                description: "The candidate is rejected within the evaluated evidence.".to_owned(),
                claim_ids: BTreeSet::from([lifecycle_claim.clone()]),
                evidence: vec![retained.event_root],
                consequence_severity: 1,
                protected: false,
            });
            if let Some(absence) = absence {
                // The protected residual is retracted only for a stated, verified reason: the
                // committed coverage record the rule accepted, named in the cell.
                cells.push(cell(KnowledgeCellParams {
                    claim_id: event_claim(id, "absence-certification"),
                    statement: absence.statement(),
                    knowledge_state: KnowledgeState::Known,
                    provenance: ProvenanceClass::Derived,
                    hypothesis: Some(fss_core::HypothesisDisposition::Refuted),
                    // The record, and each frame's analysis result, so the certification can be
                    // hydrated from the cell itself (fss-f8jls review D4).
                    evidence: [
                        retained.revision_digest,
                        absence.witness_digest,
                        absence.record_digest,
                    ]
                    .into_iter()
                    .chain(
                        absence
                            .analysis
                            .iter()
                            .flat_map(|analysis| analysis.results.values().copied()),
                    )
                    .collect(),
                    contradictions: Vec::new(),
                    valid_until: None,
                    state_basis: None,
                })?);
            } else {
                residuals.push(PossibleWorld {
                    world_id: world("absence-uncertified"),
                    description: "Activity outside the evaluated evidence remains possible; no CoverageWitness certifies absence.".to_owned(),
                    claim_ids: BTreeSet::from([lifecycle_claim.clone(), CLAIM_COVERAGE.to_owned()]),
                    evidence: vec![retained.revision_digest],
                    consequence_severity: 5,
                    protected: true,
                });
                unknown.push(format!(
                    "Rejection of {} is not a certified negative read.",
                    id.as_str()
                ));
            }
        }
        EventState::Hypothesized
        | EventState::Witnessed
        | EventState::Indeterminate
        | EventState::Adjudicated
        | EventState::AlertDelivered
        | EventState::Resolved => {
            alternatives.push(PossibleWorld {
                world_id: world("activity-live"),
                description:
                    "Real activity in the named zone remains possible under the retained evidence."
                        .to_owned(),
                claim_ids: BTreeSet::from([lifecycle_claim.clone(), physical_claim.clone()]),
                evidence: vec![retained.revision_digest],
                consequence_severity: 5,
                protected: true,
            });
            residuals.push(PossibleWorld {
                world_id: world("artifact-live"),
                description:
                    "A benign, artifact, or erroneous detection explanation remains possible."
                        .to_owned(),
                claim_ids: BTreeSet::from([lifecycle_claim.clone()]),
                evidence: vec![retained.event_root],
                consequence_severity: 4,
                protected: true,
            });
            unknown.push(format!(
                "Whether {} reflects real activity is {}.",
                id.as_str(),
                physical_state.as_str()
            ));
        }
    }
    if !corroborated {
        warnings.push(format!(
            "{} is single-sensor and not corroborated; it grants no alert or effect authority.",
            id.as_str()
        ));
    }
    if !contradicting.is_empty() {
        unknown.push(format!(
            "{} carries {} contradicting evidence root(s).",
            id.as_str(),
            contradicting.len()
        ));
    }
    let tamper_roots = &retained.tamper.open_tamper_roots;
    if !tamper_roots.is_empty() {
        at_risk.push(format!(
            "Sensor tamper is reported for {} by {} retained root(s).",
            id.as_str(),
            tamper_roots.len()
        ));
        residuals.push(PossibleWorld {
            world_id: world("sensor-tamper"),
            description: "A contributing sensor is tampered with, so retained evidence may conceal or fabricate activity.".to_owned(),
            claim_ids: BTreeSet::from([lifecycle_claim.clone()]),
            evidence: tamper_roots.clone(),
            consequence_severity: 5,
            protected: true,
        });
    }
    let mut proof_roots = vec![retained.event_root, retained.revision_digest];
    if let Some(absence) = absence {
        proof_roots.extend([absence.witness_digest, absence.record_digest]);
    }
    proof_roots.extend(event.evidence.iter().map(|edge| edge.digest));
    proof_roots.extend(event.model_receipts.iter().copied());
    proof_roots.extend(tamper_roots.iter().copied());
    let contradicted = cells.iter().any(|cell| !cell.contradictions().is_empty());
    Ok(EventSection {
        cells,
        alternatives,
        residuals,
        lifecycle_claim,
        unknown,
        at_risk,
        warnings,
        proof_roots,
        physical_state,
        contradicted,
    })
}

/// One published event, compiled and ranked for a view.
pub(super) struct PlannedEvent<'a> {
    pub(super) retained: &'a RetainedEvent,
    pub(super) section: EventSection,
    /// Whether the event's knowledge cells are inline in the view's capsule.
    pub(super) inline: bool,
}

impl PlannedEvent<'_> {
    pub(super) fn id(&self) -> &str {
        self.retained.event.event_id.as_str()
    }
}

/// Consequence order: highest protected severity, open tamper, unresolved, most recently
/// committed, then event identity (deterministic).
fn consequence_order(left: &PlannedEvent<'_>, right: &PlannedEvent<'_>) -> std::cmp::Ordering {
    let key = |event: &PlannedEvent<'_>| {
        (
            std::cmp::Reverse(event.section.protected_severity()),
            std::cmp::Reverse(event.retained.tamper.has_open_tamper()),
            std::cmp::Reverse(!matches!(
                event.retained.event.state,
                EventState::Resolved | EventState::Rejected
            )),
            std::cmp::Reverse(event.retained.committed_sequence),
        )
    };
    key(left)
        .cmp(&key(right))
        .then_with(|| left.id().cmp(right.id()))
}

pub(super) fn planned_events<'a>(
    snapshot: &'a DeploymentSnapshot,
    view: AgentView,
) -> Result<Vec<PlannedEvent<'a>>, ReferenceError> {
    let mut planned = Vec::with_capacity(snapshot.events.len());
    for retained in &snapshot.events {
        planned.push(PlannedEvent {
            section: event_section(
                retained,
                snapshot
                    .retained_absences
                    .get(retained.event.event_id.as_str()),
            )?,
            retained,
            inline: false,
        });
    }
    planned.sort_by(consequence_order);
    let budget = inline_event_budget(view);
    for (rank, event) in planned.iter_mut().enumerate() {
        // Contradictions and open tamper are non-droppable: those events are always inline.
        event.inline =
            rank < budget || event.section.contradicted || event.retained.tamper.has_open_tamper();
    }
    Ok(planned)
}

/// Class key of one per-event world: `world:event:<id>:<kind>` → `<kind>`.
fn world_kind<'w>(world: &'w PossibleWorld, event: &str) -> &'w str {
    world
        .world_id
        .strip_prefix(&format!("world:event:{event}:"))
        .unwrap_or(world.world_id.as_str())
}

/// Aggregate of one world kind across events.
pub(super) struct WorldClass {
    pub(super) residual: bool,
    pub(super) description: String,
    pub(super) members: Vec<String>,
    pub(super) severity: u8,
    pub(super) protected: bool,
}

/// Aggregates every per-event world into one world per kind, preserving the maximum severity and
/// protection of its members.
pub(super) fn aggregate_worlds(
    planned: &[PlannedEvent<'_>],
) -> (
    BTreeMap<String, WorldClass>,
    BTreeMap<String, BTreeSet<String>>,
) {
    let mut classes: BTreeMap<String, WorldClass> = BTreeMap::new();
    let mut memberships: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for event in planned {
        let lists = [
            (false, &event.section.alternatives),
            (true, &event.section.residuals),
        ];
        for (residual, worlds) in lists {
            for world in worlds {
                let kind = world_kind(world, event.id()).to_owned();
                let class_id = format!("{WORLD_EVENTS_PREFIX}{kind}");
                let class = classes
                    .entry(class_id.clone())
                    .or_insert_with(|| WorldClass {
                        residual,
                        description: world.description.clone(),
                        members: Vec::new(),
                        severity: 0,
                        protected: false,
                    });
                class.members.push(world.world_id.clone());
                class.severity = class.severity.max(world.consequence_severity);
                class.protected |= world.protected;
                memberships
                    .entry(event.id().to_owned())
                    .or_default()
                    .insert(class_id);
            }
        }
    }
    (classes, memberships)
}

/// `1 indeterminate, 2 rejected` over the latest committed revisions.
pub(super) fn state_counts(planned: &[PlannedEvent<'_>]) -> String {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for event in planned {
        *counts
            .entry(event.retained.event.state.as_str())
            .or_default() += 1;
    }
    counts
        .iter()
        .map(|(state, count)| format!("{count} {state}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The hydration slot of every published event, in consequence-rank order.
pub(super) fn event_hydration(
    snapshot: &DeploymentSnapshot,
    planned: &[PlannedEvent<'_>],
) -> Result<Vec<EventHydration>, ContractError> {
    let synopsis_cost = BudgetVector::builder()
        .tokens(u64::from(AgentView::DecisionDiff.maximum_tokens()))
        .bytes(snapshot.bytes_read)
        .storage_operations(snapshot.files_read)
        .build()
        .map_err(|_| ContractError::BudgetExhausted)?;
    planned
        .iter()
        .map(|event| {
            let retained = event.retained;
            Ok(EventHydration {
                event_id: retained.event.event_id.clone(),
                handle: format!(
                    "fss://event/{}/revision/{}",
                    event.id(),
                    retained.event.revision
                ),
                revision_digest: retained.revision_digest,
                world_ids: event
                    .section
                    .worlds()
                    .map(|world| world.world_id.clone())
                    .collect(),
                protected_world_ids: event
                    .section
                    .worlds()
                    .filter(|world| world.protected)
                    .map(|world| world.world_id.clone())
                    .collect(),
                cells_inline: event.inline,
                cell_count: event.section.cells.len(),
                physical_state: event.section.physical_state,
                consequence_severity: event.section.protected_severity(),
                summary: format!(
                    "Revision {} in state {}; physical presence {}; {}.",
                    retained.event.revision,
                    retained.event.state.as_str(),
                    event.section.physical_state.as_str(),
                    if retained.corroborated() {
                        "corroborated"
                    } else {
                        "not corroborated"
                    }
                ),
                synopsis_cost,
                source_cost: read_cost(retained.object_bytes, retained.object_reads)?,
            })
        })
        .collect()
}

/// What this view compiled out at the source, and its bounded, priced expansion paths.
pub(super) fn source_omissions(
    snapshot: &DeploymentSnapshot,
    request: &OrientRequest,
    planned: &[PlannedEvent<'_>],
    hydration: &[EventHydration],
    aggregated_worlds: usize,
    world_classes: usize,
    folded_worlds: Option<ExpansionHandle>,
) -> Result<SourceOmissions, ContractError> {
    if planned.is_empty() {
        return Ok(SourceOmissions::default());
    }
    let grouped = planned.len() > DIRECT_EVENT_EXPANSION_LIMIT;
    let expansion = if grouped {
        "the exact-anchor paginated metadata inventory enumerates every event identity and H0 \
         proof root; separate H1 explanations must be checked against the returned inventory anchor"
    } else {
        "each event's cells hydrate through its handle"
    };
    let mut omissions = Vec::new();
    let summarized = planned.iter().filter(|event| !event.inline).count();
    if summarized > 0 {
        omissions.push(SourceOmission {
            class: SOURCE_CLASS_EVENT_DETAIL.to_owned(),
            omitted_count: summarized as u64,
            transform: CompressionTransform {
                kind: CompressionTransformKind::Summarize,
                scope: "published events".to_owned(),
                loss_class: CompressionLossClass::DecisionPreserving,
                details: Some(format!(
                    "{summarized} of {} events are summarized by {CLAIM_EVENTS} and the \
                     per-state epistemic boundaries; {expansion}.",
                    planned.len()
                )),
            },
        });
    }
    let folded = folded_worlds.is_some();
    omissions.push(SourceOmission {
        class: SOURCE_CLASS_WORLD_DETAIL.to_owned(),
        // Folding also represents the deployment's unobserved-activity world.
        omitted_count: aggregated_worlds as u64 + u64::from(folded),
        transform: CompressionTransform {
            kind: CompressionTransformKind::Aggregate,
            scope: "per-event possible worlds".to_owned(),
            loss_class: CompressionLossClass::DecisionPreserving,
            details: Some(if grouped && folded {
                format!(
                    "{aggregated_worlds} per-event worlds and {WORLD_UNOBSERVED_ACTIVITY} are \
                     folded into {WORLD_PROTECTED_SUMMARY}, keeping the maximum severity and \
                     protection; {expansion}."
                )
            } else if grouped {
                format!(
                    "{aggregated_worlds} per-event worlds are aggregated into {world_classes} \
                     class worlds keeping each class's maximum severity and protection; \
                     {expansion}."
                )
            } else if folded {
                format!(
                    "{aggregated_worlds} per-event worlds and {WORLD_UNOBSERVED_ACTIVITY} are \
                     folded into {WORLD_PROTECTED_SUMMARY}, keeping the maximum severity and \
                     protection; every member hydrates through its handle."
                )
            } else {
                format!(
                    "{aggregated_worlds} per-event worlds are aggregated into {world_classes} \
                     class worlds keeping each class's maximum severity and protection; every \
                     member hydrates through its event's handle."
                )
            }),
        },
    });
    let mut handles: Vec<ExpansionHandle> = hydration
        .iter()
        .enumerate()
        .filter(|(rank, slot)| !grouped || *rank == 0 || slot.cells_inline)
        .map(|(_, slot)| ExpansionHandle {
            handle: slot.handle.clone(),
            purpose: format!(
                "H1 synopsis of {} (`fss explain --event-id {}`): knowledge cells and worlds {}.",
                slot.event_id.as_str(),
                slot.event_id.as_str(),
                slot.world_ids.join(", ")
            ),
            estimated_cost: slot.synopsis_cost,
        })
        .collect();
    if grouped {
        let anchor = crate::agent_follow::snapshot_anchor_token(snapshot);
        let site = short_identity(ContentDigest::sha256(snapshot.site_lineage.as_bytes()));
        // This registered resource shape labels the exact scope. The explicit CLI command is
        // its expansion path; no URI dispatcher, source-byte read or automatic H1 is claimed.
        handles.push(ExpansionHandle {
            handle: format!("fss://deployment/{site}/anchor/{anchor}"),
            purpose: format!(
                "Exact metadata inventory of all {} events and H0 proof roots; every per-event \
                 world belongs to an inventoried event. The estimated cost is per metadata page. \
                 At the SAME root run `fss query --json --root ROOT \
                 --principal {} --anchor {anchor} --max-entries 32` without filters; repeat \
                 with returned --continuation until exhausted. This is metadata, not H1/source \
                 hydration. For separate `fss explain --event-id ID` results, compare their \
                 returned anchor to this inventory anchor; if changed, obtain a new inventory.",
                planned.len(),
                request.principal.as_str(),
            ),
            estimated_cost: BudgetVector::builder()
                .tokens(u64::from(AgentView::Case.maximum_tokens()))
                .bytes(snapshot.bytes_read)
                .storage_operations(snapshot.files_read)
                .build()
                .map_err(|_| ContractError::BudgetExhausted)?,
        });
    }
    handles.extend(folded_worlds);
    Ok(SourceOmissions { omissions, handles })
}
