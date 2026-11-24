#![forbid(unsafe_code)]
//! Lossless pulse-view rollup helpers for zone coverage, historical sensor health, and sensor
//! network liveness inside [`super::capsule`].

use fss_core::{
    BudgetVector, CompressionLossClass, CompressionTransform, CompressionTransformKind,
    ContentDigest, ExpansionHandle, KnowledgeCell, KnowledgeCellParams, KnowledgeState,
    LedgerAnchor, ProvenanceClass,
};

use super::coverage::{CoverageAssessment, ZoneCoverageState};
use super::coverage_cells::zone_coverage_cell;
use super::types::{CLAIM_COVERAGE, OrientError, cell};
use crate::situation_sections::SourceOmission;

pub(super) struct PulseRollupContext<'a> {
    pub(super) heartbeat: bool,
    pub(super) anchor: &'a LedgerAnchor,
    pub(super) ledger_evidence: ContentDigest,
    pub(super) deployment_handle: &'a str,
    pub(super) brief_expansion_cost: BudgetVector,
}

pub(super) struct PulseRollupSink<'a> {
    pub(super) cells: &'a mut Vec<KnowledgeCell>,
    pub(super) unknown: &'a mut Vec<String>,
    pub(super) at_risk: &'a mut Vec<String>,
    pub(super) omissions: &'a mut Vec<SourceOmission>,
    pub(super) handles: &'a mut Vec<ExpansionHandle>,
}

fn known_rollup_cell(
    claim: &str,
    statement: String,
    evidence: Vec<ContentDigest>,
) -> Result<KnowledgeCell, OrientError> {
    Ok(cell(KnowledgeCellParams {
        claim_id: claim.to_owned(),
        statement,
        knowledge_state: KnowledgeState::Known,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence,
        contradictions: Vec::new(),
        valid_until: None,
        state_basis: None,
    })?)
}

pub(super) fn append_coverage_zones(
    assessment: &CoverageAssessment,
    ctx: &PulseRollupContext<'_>,
    sink: &mut PulseRollupSink<'_>,
) -> Result<(), OrientError> {
    let total_zone_witnesses: usize = assessment
        .zones
        .iter()
        .map(|zone| zone.witnesses.len())
        .sum();
    let total_zone_gaps: usize = assessment.zones.iter().map(|zone| zone.gaps.len()).sum();
    let has_zone_conflicts = assessment.zones.iter().any(|zone| {
        !zone.health_conflicts.is_empty() || !zone.calibration_invalidations.is_empty()
    });
    let compact_multi_zone = !has_zone_conflicts
        && ((ctx.heartbeat && assessment.zones.len() > 1)
            || (assessment.zones.len() > 5 && (total_zone_witnesses > 16 || total_zone_gaps > 8)));
    if compact_multi_zone {
        let mut stale_count = 0_usize;
        let mut not_observable_count = 0_usize;
        let mut non_covered_labels = Vec::new();
        for zone in &assessment.zones {
            match zone.state {
                ZoneCoverageState::Covered => {}
                ZoneCoverageState::Stale => {
                    stale_count += 1;
                    non_covered_labels.push(format!("{} (stale)", zone.label()));
                }
                ZoneCoverageState::NotObservable => {
                    not_observable_count += 1;
                    non_covered_labels.push(format!("{} (not_observable)", zone.label()));
                }
            }
        }
        let summary_state = if not_observable_count > 0 {
            KnowledgeState::NotObservable
        } else if stale_count > 0 {
            KnowledgeState::Stale
        } else {
            KnowledgeState::Known
        };
        // `site_coverage_cell` already carries the rolled-up zone counts and worst-case
        // epistemic state as a mandatory `epistemic_boundary` item; for non-heartbeat views
        // also preserve every non-covered zone label in `unknown` so no gap is ever hidden.
        if !ctx.heartbeat && !non_covered_labels.is_empty() {
            sink.unknown.push(format!(
                "Activity in {} non-covered zone(s) is uncertified ({}); inspect coverage witnesses.",
                non_covered_labels.len(),
                non_covered_labels.join(", ")
            ));
        }
        sink.omissions.push(SourceOmission {
            class: "zone_coverage_detail".to_owned(),
            omitted_count: assessment.zones.len() as u64,
            transform: CompressionTransform {
                kind: CompressionTransformKind::Aggregate,
                scope: "per-zone coverage assessments".to_owned(),
                loss_class: CompressionLossClass::DecisionPreserving,
                details: Some(format!(
                    "{} per-zone coverage cells ({total_zone_witnesses} witnesses) rolled up into {CLAIM_COVERAGE} preserving worst-case epistemic state ({}); hydrate via coverage witnesses.",
                    assessment.zones.len(),
                    summary_state.as_str()
                )),
            },
        });
        sink.handles.push(ExpansionHandle {
            handle: format!("{}/coverage", ctx.deployment_handle),
            purpose: format!(
                "Per-zone coverage detail for {} zones ({total_zone_witnesses} witnesses).",
                assessment.zones.len()
            ),
            estimated_cost: ctx.brief_expansion_cost,
        });
    } else {
        for zone in &assessment.zones {
            sink.cells.push(zone_coverage_cell(zone, ctx.anchor)?);
            if zone.state != ZoneCoverageState::Covered {
                sink.unknown.push(format!(
                    "Activity in {} is {}.",
                    zone.label(),
                    zone.state.as_str()
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn append_historical_health(
    count: usize,
    cells: Vec<KnowledgeCell>,
    unknown: Vec<String>,
    at_risk: Vec<String>,
    ctx: &PulseRollupContext<'_>,
    sink: &mut PulseRollupSink<'_>,
) -> Result<(), OrientError> {
    if ctx.heartbeat && count > 1 {
        let has_findings = !at_risk.is_empty();
        sink.cells.push(known_rollup_cell(
            "claim:historical-sensor-health:summary",
            format!(
                "{count} retained historical health diagnostics ({}); hydrate via brief.",
                if has_findings {
                    "findings/deletions present"
                } else {
                    "no findings reported"
                }
            ),
            vec![ctx.ledger_evidence],
        )?);
        // `historical_health::project` already aggregates risk/unknown boundaries into at most
        // one compact summary line carrying exact finding counts and the `no_findings clears no
        // earlier finding` epistemic guardrail; preserve it verbatim rather than discarding it.
        sink.unknown.extend(unknown);
        sink.at_risk.extend(at_risk);
        sink.omissions.push(SourceOmission {
            class: "historical_health_summary_detail".to_owned(),
            omitted_count: count as u64,
            transform: CompressionTransform {
                kind: CompressionTransformKind::Summarize,
                scope: "per-receipt historical sensor health".to_owned(),
                loss_class: CompressionLossClass::DecisionPreserving,
                details: Some(format!(
                    "{count} historical health cells summarized in pulse; hydrate via `--view brief`."
                )),
            },
        });
        sink.handles.push(ExpansionHandle {
            handle: format!("{}/historical-health", ctx.deployment_handle),
            purpose: format!(
                "Per-receipt historical sensor-health details for {count} diagnostics via `fss orient --view brief`."
            ),
            estimated_cost: ctx.brief_expansion_cost,
        });
    } else {
        sink.cells.extend(cells);
        sink.unknown.extend(unknown);
        sink.at_risk.extend(at_risk);
    }
    Ok(())
}

pub(super) fn append_sensor_liveness(
    total_sensors: usize,
    cells: Vec<KnowledgeCell>,
    unknown: Vec<String>,
    at_risk: Vec<String>,
    ctx: &PulseRollupContext<'_>,
    sink: &mut PulseRollupSink<'_>,
) -> Result<(), OrientError> {
    if ctx.heartbeat && total_sensors > 0 {
        let degraded_sensors = at_risk.len();
        let observable_sensors = total_sensors.saturating_sub(degraded_sensors);
        sink.cells.push(known_rollup_cell(
            "claim:sensor-liveness:summary",
            format!(
                "{total_sensors} sensors: {observable_sensors} observable, {degraded_sensors} degraded/unobserved; hydrate via brief."
            ),
            vec![ctx.ledger_evidence],
        )?);
        if degraded_sensors > 0 {
            sink.at_risk.push(format!(
                "{degraded_sensors} of {total_sensors} sensors report degraded or unobserved network liveness."
            ));
        }
        sink.omissions.push(SourceOmission {
            class: "sensor_liveness_detail".to_owned(),
            omitted_count: total_sensors as u64,
            transform: CompressionTransform {
                kind: CompressionTransformKind::Aggregate,
                scope: "per-sensor network liveness observations".to_owned(),
                loss_class: CompressionLossClass::DecisionPreserving,
                details: Some(format!(
                    "{total_sensors} per-sensor liveness cells rolled up in pulse ({degraded_sensors} degraded/unobserved preserved); hydrate via `--view brief`."
                )),
            },
        });
        sink.handles.push(ExpansionHandle {
            handle: format!("{}/liveness", ctx.deployment_handle),
            purpose: format!(
                "Per-sensor historical network liveness for {total_sensors} sensors via `fss orient --view brief`."
            ),
            estimated_cost: ctx.brief_expansion_cost,
        });
    } else {
        sink.cells.extend(cells);
        sink.unknown.extend(unknown);
        sink.at_risk.extend(at_risk);
    }
    Ok(())
}
