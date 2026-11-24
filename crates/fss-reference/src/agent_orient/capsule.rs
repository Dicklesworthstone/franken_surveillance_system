#![forbid(unsafe_code)]
//! Anchor-pinned [`SituationCapsule`] compilation for [`super`].

use std::collections::{BTreeMap, BTreeSet};

use fss_core::{
    AgentView, BudgetVector, CanonicalEncode, Completeness, ContentDigest, ContractError,
    EffectState, EventId, EventState, ExpansionHandle, IndeterminateEffectReason, KnowledgeCell,
    KnowledgeCellParams, KnowledgeState, MissionId, ObligationId, OperationId, PossibleWorld,
    ProvenanceClass, SessionId, SituationCapsule, SituationFrame, WorldEnvelope,
};

use super::coverage::CoverageAssessment;
use super::coverage_cells::{assess_coverage, site_coverage_cell};
use super::events::{
    aggregate_worlds, event_hydration, planned_events, source_omissions, state_counts,
};
use super::explain::deletion_warnings;
use super::frontier::{
    AffordanceAssembly, attention_frontier, build_capsule_affordances, epistemic_debt,
};
use super::pulse_rollup::{
    PulseRollupContext, PulseRollupSink, append_coverage_zones, append_historical_health,
    append_sensor_liveness,
};
use super::types::{
    AttentionItem, CLAIM_COVERAGE, CLAIM_EFFECT_JOURNAL, CLAIM_EVENTS, CLAIM_IMPORTS,
    CLAIM_LEDGER_HEAD, DIRECT_EVENT_EXPANSION_LIMIT, DeploymentSnapshot, EpistemicDebtItem,
    EventHydration, OrientError, OrientRequest, OrientSessionBinding, ProjectionPurpose,
    UNBOUND_SESSION_DEGRADATION, WORLD_EVENTS_PREFIX, WORLD_PROTECTED_SUMMARY,
    WORLD_UNOBSERVED_ACTIVITY, cell, digest_of, obligation_state_str, plural, read_cost,
    severity_rank, short_identity,
};
use super::{historical_health, learning, liveness, mission, supervision, trauma_guard};
use crate::deployment_session::trauma_guard::AntiPatternWarning;
use crate::doctor::DoctorVerdict;
use crate::situation_guard::{
    INDETERMINATE_REASON_UNRECORDED_CLAIM_PREFIX, local_state_effect_cell,
};
use crate::situation_sections::{SourceOmission, SourceOmissions};

/// The capsule, its proof roots, and the answer metadata compiled before projection.
pub(super) struct CompiledSituation {
    pub(super) capsule: SituationCapsule,
    pub(super) proof_roots: BTreeSet<ContentDigest>,
    pub(super) degradation: Vec<String>,
    pub(super) warnings: Vec<String>,
    pub(super) source: SourceOmissions,
    pub(super) hydration: Vec<EventHydration>,
    pub(super) headline_event: Option<EventId>,
    pub(super) candidate_world_count: usize,
    pub(super) aggregated_world_count: usize,
    pub(super) epistemic_state: KnowledgeState,
    pub(super) contradictions: Vec<String>,
    pub(super) attention: Vec<AttentionItem>,
    pub(super) epistemic_debt: Vec<EpistemicDebtItem>,
    /// Local-state effect cells of every durable operation, bound before projection.
    pub(super) effect_cells: Vec<(OperationId, EffectState, KnowledgeCell)>,
    /// Reusable anchor token of the snapshot's committed position.
    pub(super) anchor_token: String,
    /// Per-zone coverage.
    pub(super) coverage: Option<CoverageAssessment>,
}

pub(super) fn compile_capsule(
    snapshot: &DeploymentSnapshot,
    request: &OrientRequest,
    session: Option<&OrientSessionBinding>,
    advisory_warnings: Option<&[AntiPatternWarning]>,
    workspace_invalidations: &[String],
    purpose: ProjectionPurpose,
) -> Result<CompiledSituation, OrientError> {
    let cases = session.map_or(&[][..], |binding| binding.cases.as_slice());
    let plans = session.map_or(&[][..], |binding| binding.plans.as_slice());
    let claims = session.map_or(&[][..], |binding| binding.claims.as_slice());
    let findings = session.map_or(&[][..], |binding| binding.findings.as_slice());
    let heartbeat = request.view == AgentView::Pulse;
    let anchor = snapshot.anchor.clone();
    let site = snapshot.site_lineage.as_str();
    let site_digest = ContentDigest::sha256(site.as_bytes());
    let mission_context = mission::project(snapshot, request, session)?;
    let objective_id = mission_context
        .objective_id
        .clone()
        .unwrap_or_else(|| format!("objective:orient:{site_digest}"));
    let mission_id = MissionId::parse(format!("mission:orient:{site_digest}"))?;
    let session_id = SessionId::parse(format!(
        "session:orient:{}",
        digest_of("fss.reference_orient_session.v1", |encoder| {
            encoder.text(site);
            request.principal.encode_canonical(encoder);
        })
    ))?;
    let basis = match purpose {
        ProjectionPurpose::AdmittedProbe => fss_core::contract_basis::probe_contract_basis(),
        ProjectionPurpose::Orientation | ProjectionPurpose::AdmittedWorkspace => {
            fss_core::reference_contract_basis()
        }
    };
    let deployment_handle = format!("fss://deployment/{}", short_identity(site_digest));

    let mut degradation = vec![UNBOUND_SESSION_DEGRADATION.to_owned()];
    let mut warnings = Vec::new();
    let mut unknown = Vec::new();
    let mut at_risk = Vec::new();
    let mut why = Vec::new();
    let mut proof_roots = BTreeSet::from([anchor.state_root, snapshot.effect_journal_digest]);
    proof_roots.extend(mission_context.proof_roots);
    unknown.extend(mission_context.unknown);
    // Workspace drift is protected uncertainty, not an optional presentation warning.
    unknown.extend(workspace_invalidations.iter().cloned());
    let ledger_evidence = if snapshot.batch_count == 0 {
        anchor.state_root
    } else {
        proof_roots.insert(snapshot.ledger_root);
        snapshot.ledger_root
    };
    // Facts derived from published events cite the record root of the last event-bearing batch,
    // and the unobserved-activity residual cites the last batch that retained source evidence or
    // coverage: each root chains every earlier record it rests on and stays put when an unrelated
    // batch commits, so a harmless successor commit re-derives identical facts (only the
    // registered anchor-position cell restates the head; `anchor_position_restatement`).
    let event_evidence = snapshot.event_ledger_root.unwrap_or(ledger_evidence);
    proof_roots.insert(event_evidence);
    let residual_evidence = snapshot.evidence_ledger_root.unwrap_or(anchor.state_root);
    proof_roots.insert(residual_evidence);

    let planned = planned_events(snapshot, request.view)?;
    let headline = planned.first();
    let coverage = assess_coverage(snapshot)?;

    // Deployment-state cells: exactly what the committed bytes establish.
    let families = if snapshot.family_counts.is_empty() {
        "none".to_owned()
    } else {
        snapshot
            .family_counts
            .iter()
            .map(|(family, count)| format!("{family}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let known_cell = |claim: &str, statement: String, evidence: Vec<ContentDigest>| {
        cell(KnowledgeCellParams {
            claim_id: claim.to_owned(),
            statement,
            knowledge_state: KnowledgeState::Known,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence,
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        })
    };
    let mut cells = vec![
        known_cell(
            CLAIM_LEDGER_HEAD,
            format!(
                "The authority ledger holds {} at commit {} (ledger epoch {}); committed deltas: {families}.",
                plural(snapshot.batch_count, "committed batch", "committed batches"),
                anchor.commit_sequence,
                anchor.ledger_epoch
            ),
            vec![ledger_evidence],
        )?,
        known_cell(
            CLAIM_IMPORTS,
            format!(
                "{} retained at this anchor.{}",
                plural(
                    snapshot.completed_imports.len(),
                    "completed file import is",
                    "completed file imports are"
                ),
                if snapshot.deletions_committed == 0 {
                    String::new()
                } else {
                    format!(
                        " {} committed; deleted imports and their evidence resolve to `deleted`.",
                        plural(snapshot.deletions_committed, "deletion is", "deletions are")
                    )
                }
            ),
            if snapshot.completed_imports.is_empty()
                || heartbeat
                || snapshot.completed_imports.len() > 8
                || planned.len() > DIRECT_EVENT_EXPANSION_LIMIT
            {
                // The retained-import count is replay-derived metadata. The complete ledger
                // prefix binds all imports and later deletions; listing every import payload
                // would exceed bounded pulse/brief context budgets on real multi-window sites.
                // This does not advertise import identity or source-byte hydration.
                vec![ledger_evidence]
            } else {
                snapshot.completed_imports.clone()
            },
        )?,
        cell(KnowledgeCellParams {
            claim_id: CLAIM_EFFECT_JOURNAL.to_owned(),
            statement: if snapshot.effect_journal_present {
                format!(
                    "The durable effect journal holds {} and {} ({} open).",
                    plural(snapshot.operations.len(), "operation", "operations"),
                    plural(snapshot.obligations.len(), "obligation", "obligations"),
                    snapshot.open_obligations().len()
                )
            } else if heartbeat {
                "Effect journal unavailable; prior effects/obligations unknown.".to_owned()
            } else {
                "Durable effect history is unavailable at this anchor; a missing journal does not establish that no effects or obligations existed."
                    .to_owned()
            },
            knowledge_state: if snapshot.effect_journal_present {
                KnowledgeState::Known
            } else {
                KnowledgeState::Unknown
            },
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: if snapshot.effect_journal_present {
                vec![snapshot.effect_journal_digest]
            } else {
                Vec::new()
            },
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        })?,
        site_coverage_cell(coverage.as_ref(), ledger_evidence, heartbeat)?,
    ];
    cells.extend(mission_context.cells);
    let mut pulse_source_omissions: Vec<SourceOmission> = Vec::new();
    let mut pulse_source_handles: Vec<ExpansionHandle> = Vec::new();
    let brief_expansion_cost = BudgetVector::builder()
        .tokens(u64::from(AgentView::Brief.maximum_tokens()))
        .bytes(snapshot.bytes_read)
        .storage_operations(snapshot.files_read)
        .build()
        .map_err(|_| ContractError::BudgetExhausted)?;
    let rollup_ctx = PulseRollupContext {
        heartbeat,
        anchor: &anchor,
        ledger_evidence,
        deployment_handle: &deployment_handle,
        brief_expansion_cost,
    };
    let historical_health = historical_health::project(&snapshot.historical_health)?;
    proof_roots.extend(historical_health.proof_roots);
    degradation.extend(historical_health.degradation);
    let sensor_liveness = liveness::project(&snapshot.sensor_liveness)?;
    proof_roots.extend(sensor_liveness.proof_roots);
    {
        let mut sink = PulseRollupSink {
            cells: &mut cells,
            unknown: &mut unknown,
            at_risk: &mut at_risk,
            omissions: &mut pulse_source_omissions,
            handles: &mut pulse_source_handles,
        };
        if let Some(assessment) = &coverage {
            append_coverage_zones(assessment, &rollup_ctx, &mut sink)?;
        }
        append_historical_health(
            snapshot.historical_health.len(),
            historical_health.cells,
            historical_health.unknown,
            historical_health.at_risk,
            &rollup_ctx,
            &mut sink,
        )?;
        append_sensor_liveness(
            snapshot.sensor_liveness.len(),
            sensor_liveness.cells,
            sensor_liveness.unknown,
            sensor_liveness.at_risk,
            &rollup_ctx,
            &mut sink,
        )?;
    }
    let supervision = supervision::project(snapshot, request, session)?;
    cells.extend(supervision.cells);
    proof_roots.extend(supervision.proof_roots);
    unknown.extend(supervision.unknown);
    at_risk.extend(supervision.at_risk);
    warnings.extend(supervision.warnings);
    let learning = learning::project(session)?;
    cells.extend(learning.cells);
    proof_roots.extend(learning.proof_roots);
    unknown.extend(learning.unknown);
    at_risk.extend(learning.at_risk);
    let memory = trauma_guard::project(advisory_warnings)?;
    cells.extend(memory.cells);
    proof_roots.extend(memory.proof_roots);
    let heartbeat_memory_note = if heartbeat && advisory_warnings.is_none() {
        // Preserve the unavailable-advisory boundary inside mandatory `frame.now[0]` in `Pulse`
        // mode so heartbeat projections stay under the 300-token cap without paying a separate
        // 126-byte hashed `context:unknown` envelope; `Brief` and `EpistemicMap` keep the
        // standalone `unknown` item unchanged.
        (!memory.unknown.is_empty())
            .then_some("Advisory memory unavailable (no absence of harmful history).")
    } else {
        unknown.extend(memory.unknown);
        None
    };
    at_risk.extend(memory.at_risk);
    warnings.extend(memory.warnings);
    let mut nominal = BTreeSet::from([CLAIM_LEDGER_HEAD.to_owned(), CLAIM_IMPORTS.to_owned()]);
    if snapshot.effect_journal_present {
        nominal.insert(CLAIM_EFFECT_JOURNAL.to_owned());
    } else {
        if !heartbeat {
            unknown.push("Prior effects and outstanding obligations cannot be determined without their durable journal.".to_owned());
            at_risk.push("Durable effect history is unavailable; restore or reconcile that history before preparing or resending effects.".to_owned());
        }
        degradation.push("The effect journal is unavailable at this anchor; empty operation lists are not evidence of no prior effects.".to_owned());
    }

    let corroborated = planned
        .iter()
        .filter(|event| event.retained.corroborated())
        .count();
    let tampered = planned
        .iter()
        .filter(|event| event.retained.tamper.has_open_tamper())
        .count();
    if let Some(top) = headline {
        nominal.insert(CLAIM_EVENTS.to_owned());
        cells.push(known_cell(
            CLAIM_EVENTS,
            format!(
                "{}: {}; {corroborated} corroborated; {tampered} with open sensor tamper; highest \
                 consequence: {}.",
                plural(planned.len(), "published event", "published events"),
                state_counts(&planned),
                top.id()
            ),
            vec![event_evidence],
        )?);
    }

    // Worlds: one aggregate per world kind across every published event, keeping the maximum
    // severity and protection of its members; the per-event worlds hydrate through the handles.
    let (world_classes, memberships) = aggregate_worlds(&planned);
    let aggregated_world_count: usize = world_classes
        .values()
        .map(|class| class.members.len())
        .sum();
    let mut alternatives = Vec::new();
    let mut residuals = vec![PossibleWorld {
        world_id: WORLD_UNOBSERVED_ACTIVITY.to_owned(),
        description: "Activity outside retained evidence remains possible.".to_owned(),
        claim_ids: BTreeSet::from([CLAIM_COVERAGE.to_owned()]),
        evidence: vec![residual_evidence],
        consequence_severity: 4,
        protected: true,
    }];
    for (class_id, class) in &world_classes {
        let world = PossibleWorld {
            world_id: class_id.clone(),
            description: format!(
                "{} of {}: {}",
                class.members.len(),
                plural(planned.len(), "event", "events"),
                class.description
            ),
            claim_ids: BTreeSet::from([CLAIM_EVENTS.to_owned()]),
            evidence: vec![event_evidence],
            consequence_severity: class.severity,
            protected: class.protected,
        };
        if class.residual {
            residuals.push(world);
        } else {
            alternatives.push(world);
        }
    }

    if heartbeat && !planned.is_empty() {
        // The heartbeat folds every protected world into one summary world; the per-kind worlds
        // are inline in brief. Source omissions retain direct event handles or the exact-anchor
        // metadata inventory with separate, basis-checked explanations.
        let severity = alternatives
            .iter()
            .chain(&residuals)
            .filter(|world| world.protected)
            .map(|world| world.consequence_severity)
            .max()
            .unwrap_or(0);
        let folded = alternatives
            .iter()
            .chain(&residuals)
            .filter(|world| world.protected)
            .count();
        residuals = vec![PossibleWorld {
            world_id: WORLD_PROTECTED_SUMMARY.to_owned(),
            description: format!(
                "{folded} protected world kinds (max sev {severity}): unobserved + \
                 {aggregated_world_count} event worlds."
            ),
            claim_ids: BTreeSet::from([CLAIM_COVERAGE.to_owned(), CLAIM_EVENTS.to_owned()]),
            evidence: vec![ledger_evidence],
            consequence_severity: severity,
            protected: true,
        }];
        alternatives = Vec::new();
    }

    // Aggregated epistemic boundaries: one statement per physical knowledge state.
    let mut by_state: BTreeMap<&str, usize> = BTreeMap::new();
    for event in &planned {
        if event.section.physical_state != KnowledgeState::Known {
            *by_state
                .entry(event.section.physical_state.as_str())
                .or_default() += 1;
        }
    }
    for (state, count) in by_state.iter().filter(|_| !heartbeat) {
        unknown.push(format!(
            "Whether {} real activity is {state}.",
            plural(
                *count,
                "published event reflects",
                "published events reflect"
            )
        ));
    }
    let rejected = planned
        .iter()
        .filter(|event| event.retained.event.state == EventState::Rejected)
        .count();
    if rejected > 0 {
        unknown.push(format!(
            "{} not a certified negative read.",
            plural(rejected, "rejection is", "rejections are")
        ));
    }
    warnings.extend(deletion_warnings(snapshot));
    let uncorroborated = planned.len() - corroborated;
    if uncorroborated > 0 {
        warnings.push(format!(
            "{} single-sensor and not corroborated; none grants alert or effect authority.",
            plural(uncorroborated, "published event is", "published events are")
        ));
    }

    let mut coverage_handles = BTreeSet::from([format!("{deployment_handle}/coverage")]);
    if !heartbeat && let Some(assessment) = &coverage {
        coverage_handles.extend(
            assessment
                .witness_digests()
                .into_iter()
                .map(|digest| format!("fss://coverage/{digest}")),
        );
    }
    let mut inline_ids = Vec::new();
    let mut contradictions = Vec::new();
    let mut epistemic_state = KnowledgeState::Known;
    for event in &planned {
        if severity_rank(event.section.physical_state) > severity_rank(epistemic_state) {
            epistemic_state = event.section.physical_state;
        }
        contradictions.extend(
            event
                .section
                .cells
                .iter()
                .filter(|cell| {
                    !cell.contradictions().is_empty()
                        || cell.knowledge_state() == KnowledgeState::Conflicted
                })
                .map(|cell| cell.claim_id().to_owned()),
        );
        // Legacy projections retain every event root individually. Larger complete catalogues
        // cite the event-bearing ledger record root (which chains all preceding revisions) and
        // expose every individual root through an exact-anchor query. Inline and headline
        // events retain direct proof roots; no conflict or tamper detail is grouped away.
        if planned.len() <= DIRECT_EVENT_EXPANSION_LIMIT
            || event.inline
            || headline.is_some_and(|top| top.id() == event.id())
        {
            proof_roots.insert(event.retained.event_root);
            proof_roots.insert(event.retained.revision_digest);
        }
        if !event.inline {
            continue;
        }
        inline_ids.push(event.id().to_owned());
        nominal.insert(event.section.lifecycle_claim.clone());
        cells.extend(event.section.cells.iter().cloned());
        proof_roots.extend(event.section.proof_roots.iter().copied());
        if event.section.contradicted || event.retained.tamper.has_open_tamper() {
            unknown.extend(event.section.unknown.iter().cloned());
            at_risk.extend(event.section.at_risk.iter().cloned());
        }
        coverage_handles.insert(format!("fss://event/{}/coverage", event.id()));
    }
    contradictions.sort();
    contradictions.dedup();

    // Every durable operation, in journal order, as the exact local-state effect cell the guarded
    // reference situation compiles from a receipt (fss-deir9): a prepared operation has not crossed
    // the boundary (`unknown`), a dispatched non-terminal one may already have produced its effect
    // (`indeterminate`), and only a terminal local state is `known`. `orient_deployment` binds each
    // cell to its receipt and seals the situation, so no cell can be dropped or relabeled.
    let mut effect_cells = Vec::with_capacity(snapshot.operations.len());
    for operation in &snapshot.operations {
        let digest = operation.receipt_digest();
        let effect = local_state_effect_cell(operation)?;
        proof_roots.insert(digest);
        cells.push(effect.clone());
        effect_cells.push((
            operation.intent.operation_id.clone(),
            operation.state,
            effect,
        ));
        // A legacy (v1) operation that entered `indeterminate` without a reason keeps the typed
        // `unknown` marker the guarded path projects, never silently dropped (fss-deir9).
        if operation.indeterminate_reason == Some(IndeterminateEffectReason::Unrecorded) {
            let operation_id = operation.intent.operation_id.as_str();
            cells.push(cell(KnowledgeCellParams {
                claim_id: format!("{INDETERMINATE_REASON_UNRECORDED_CLAIM_PREFIX}{operation_id}"),
                statement: format!(
                    "The legacy effect journal recorded no reason when operation {operation_id} \
                     entered indeterminate."
                ),
                knowledge_state: KnowledgeState::Unknown,
                provenance: ProvenanceClass::Derived,
                hypothesis: None,
                evidence: vec![digest],
                contradictions: Vec::new(),
                valid_until: None,
                state_basis: None,
            })?);
        }
    }

    let open_obligations = snapshot.open_obligations();
    let indeterminate = snapshot.indeterminate_operations();
    for obligation in &open_obligations {
        at_risk.push(format!(
            "Obligation {} for operation {} is {}.",
            obligation.obligation_id,
            obligation.operation_id,
            obligation_state_str(obligation.state)
        ));
    }
    for operation in &indeterminate {
        at_risk.push(format!(
            "Operation {} may have occurred; reconcile before any resend.",
            operation.intent.operation_id
        ));
    }
    if snapshot.doctor_verdict == DoctorVerdict::AttentionRequired {
        if snapshot.doctor_inspected {
            // Preserve the canonical ordinary-orientation output and its existing fingerprints.
            at_risk.push("fss doctor: attention_required.".to_owned());
            degradation.push(
                "The deployment doctor reports attention_required; only the committed prefix was read."
                    .to_owned(),
            );
        } else {
            at_risk
                .push("Deployment health is not inspected by this metadata-only read.".to_owned());
            degradation.push(
                "The full spool doctor was not run; the attention verdict is conservative. Only committed metadata was verified."
                    .to_owned(),
            );
        }
    }
    if snapshot.ledger_tail_uncommitted || snapshot.effect_tail_uncommitted {
        at_risk.push("A journal ends with bytes beyond its committed prefix.".to_owned());
    }

    // Affordances: listed with class, capability, and cost; never executed by orient.
    let all_worlds: BTreeSet<String> = alternatives
        .iter()
        .chain(&residuals)
        .map(|world| world.world_id.clone())
        .collect();
    let deployment_read = read_cost(snapshot.bytes_read, snapshot.files_read)?;
    let anchor_token = crate::agent_follow::snapshot_anchor_token(snapshot);
    let (affordances, next, heartbeat_degradation) =
        build_capsule_affordances(AffordanceAssembly {
            heartbeat,
            deployment_handle: &deployment_handle,
            deployment_read,
            all_worlds,
            planned: &planned,
            memberships: &memberships,
            cases,
            plans,
            claims,
            findings,
            indeterminate: &indeterminate,
            supervision_affordances: supervision.affordances,
        })?;
    if let Some(line) = heartbeat_degradation {
        degradation.push(line);
    }

    let mut obligation_ids: Vec<ObligationId> = open_obligations
        .iter()
        .map(|obligation| obligation.obligation_id.clone())
        .collect();
    obligation_ids.sort();
    obligation_ids.dedup();

    let headline_summary = match headline {
        Some(top) if heartbeat => format!(
            "{} ({}), {corroborated} corr, {} open; top: {}.",
            plural(planned.len(), "event", "events"),
            state_counts(&planned),
            plural(obligation_ids.len(), "obligation", "obligations"),
            top.id()
        ),
        Some(top) => format!(
            "{} ({}), {corroborated} corroborated, {} open; top: {}.",
            plural(planned.len(), "event", "events"),
            state_counts(&planned),
            plural(obligation_ids.len(), "obligation", "obligations"),
            top.id()
        ),
        None => format!(
            "0 events, {}, {} open.",
            plural(snapshot.completed_imports.len(), "import", "imports"),
            plural(obligation_ids.len(), "obligation", "obligations"),
        ),
    };
    // The first frame item is mandatory in every ContextPack. Keep the full requested
    // mission and objective here; a smaller budget must refuse instead of forgetting the goal.
    let mut summary_line = match mission_context.protected_summary {
        Some(mission) => format!("{mission}\n{headline_summary}"),
        None => headline_summary,
    };
    if let Some(note) = heartbeat_memory_note {
        summary_line.push(' ');
        summary_line.push_str(note);
    }
    let now = vec![summary_line];
    why.push(format!(
        "Compiled read-only from the committed ledger prefix (root {}) and effect journal.",
        snapshot.ledger_root
    ));

    let envelope_identity = digest_of("fss.reference_orient_worlds.v2", |encoder| {
        encoder.text(&objective_id);
        anchor.encode_canonical(encoder);
        encoder.u64(alternatives.len() as u64);
        for world in alternatives.iter().chain(&residuals) {
            world.encode_canonical(encoder);
        }
    });
    let world_envelope = WorldEnvelope {
        envelope_id: format!("worlds:{}", short_identity(envelope_identity)),
        objective_id: objective_id.clone(),
        anchor: anchor.clone(),
        certified_core_claim_ids: nominal.clone(),
        nominal_claim_ids: nominal,
        alternatives,
        adversarial_residuals: residuals,
        common_invariants: BTreeSet::from([
            "invariant:evidence-provenance-retained".to_owned(),
            "invariant:no-alert-authority-from-model-output-alone".to_owned(),
            "invariant:orient-is-read-only".to_owned(),
        ]),
        coverage_boundary_handles: coverage_handles,
    };
    let mut evidence_handles: BTreeSet<String> = proof_roots
        .iter()
        .map(|digest| format!("fss://proof/{digest}"))
        .collect();
    // A deleted receipt remains addressable as an unavailable reference; only its verified
    // deletion plan is proof material for the literal custody claim.
    evidence_handles.extend(historical_health.reference_handles);
    let identity = digest_of("fss.reference_orient_capsule.v2", |encoder| {
        encoder.digest(basis.basis_digest());
        encoder.text(request.view.id());
        encoder.text(&objective_id);
        request.principal.encode_canonical(encoder);
        anchor.encode_canonical(encoder);
        encoder.digest(envelope_identity);
        for cell in &cells {
            encoder.digest(cell.cell_digest());
        }
        for affordance in &affordances {
            affordance.encode_canonical(encoder);
        }
        for obligation in &obligation_ids {
            obligation.encode_canonical(encoder);
        }
    });
    let frame = SituationFrame {
        frame_id: format!("frame:{}", short_identity(identity)),
        objective_id,
        anchor: anchor.clone(),
        world_envelope,
        knowledge_cells: cells,
        now,
        changed: Vec::new(),
        why,
        unknown,
        at_risk,
        next,
        evidence_handles,
    };
    let capsule = SituationCapsule {
        capsule_id: format!("situation:{identity}"),
        revision: anchor.commit_sequence,
        contract_basis: basis,
        mission_id,
        session_id,
        principal_id: request.principal.clone(),
        anchor,
        previous_anchor: None,
        frame,
        obligations: obligation_ids,
        affordances,
        completeness: if coverage.as_ref().is_some_and(CoverageAssessment::complete) {
            Completeness::Complete
        } else {
            Completeness::Partial
        },
        created_at: snapshot.latest_evidence_time,
        mission_state: mission_context.state,
    };
    capsule.validate()?;
    for cell in &capsule.frame.knowledge_cells {
        if severity_rank(cell.knowledge_state()) > severity_rank(epistemic_state) {
            epistemic_state = cell.knowledge_state();
        }
    }

    let hydration = event_hydration(snapshot, &planned)?;
    let folded_worlds = if heartbeat && !planned.is_empty() {
        let cost = BudgetVector::builder()
            .tokens(u64::from(AgentView::Brief.maximum_tokens()))
            .bytes(snapshot.bytes_read)
            .storage_operations(snapshot.files_read)
            .build()
            .map_err(|_| ContractError::BudgetExhausted)?;
        Some(ExpansionHandle {
            handle: format!("{deployment_handle}/worlds"),
            purpose: format!(
                "Per-kind protected worlds ({WORLD_UNOBSERVED_ACTIVITY} and {WORLD_EVENTS_PREFIX}*) \
                 via `fss orient --view brief`."
            ),
            estimated_cost: cost,
        })
    } else {
        None
    };
    let mut source = source_omissions(
        snapshot,
        request,
        &planned,
        &hydration,
        aggregated_world_count,
        world_classes.len(),
        folded_worlds,
    )?;
    source.omissions.extend(historical_health.source.omissions);
    source.handles.extend(historical_health.source.handles);
    source.omissions.extend(pulse_source_omissions);
    source.handles.extend(pulse_source_handles);
    let candidate_world_count = aggregated_world_count + 1;
    let mut attention =
        attention_frontier(snapshot, &planned, &deployment_handle, coverage.as_ref());
    attention.extend(historical_health.attention);
    attention.extend(sensor_liveness.attention);
    attention.truncate(128);
    let epistemic_debt = epistemic_debt(snapshot, &planned, coverage.as_ref());
    Ok(CompiledSituation {
        capsule,
        proof_roots,
        degradation,
        warnings,
        source,
        hydration,
        headline_event: headline.map(|top| top.retained.event.event_id.clone()),
        candidate_world_count,
        aggregated_world_count,
        epistemic_state,
        contradictions,
        attention,
        epistemic_debt,
        effect_cells,
        anchor_token,
        coverage,
    })
}
