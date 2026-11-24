#![forbid(unsafe_code)]
//! Site- and zone-level coverage knowledge-cell compilation for [`super`].

use std::collections::BTreeSet;

use fss_core::{
    ContentDigest, ContractError, KnowledgeCell, KnowledgeCellParams, KnowledgeState,
    KnowledgeStateBasis, LedgerAnchor, ProvenanceClass, StaleBasis,
};

use super::coverage::{self, CoverageAssessment, ZoneAssessment, ZoneCoverageState};
use super::types::{CLAIM_COVERAGE, DeploymentSnapshot, cell};

/// The coverage assessment of `snapshot`'s retained records, if any.
pub(super) fn assess_coverage(
    snapshot: &DeploymentSnapshot,
) -> Result<Option<CoverageAssessment>, ContractError> {
    let event_zones: BTreeSet<String> = snapshot
        .events
        .iter()
        .flat_map(|retained| retained.event.zone_ids.iter().cloned())
        .collect();
    let published: BTreeSet<String> = snapshot
        .events
        .iter()
        .map(|retained| retained.event.event_id.as_str().to_owned())
        .collect();
    coverage::assess(
        &snapshot.coverage,
        &snapshot.source_coverage,
        &snapshot.sensor_newest_evidence,
        snapshot.coverage_evidence_unattributed,
        &event_zones,
        &published,
        &snapshot.historical_health,
    )
}

/// Maximum inline gap statements or byte span in a single coverage knowledge cell before
/// compacting to a lossless summary pointing at `situationFrame.coverage.gaps` and the committed
/// `coverage_witness` ledger records. Keeps critical epistemic-boundary items well below
/// `SemanticContextPack`'s 16 KiB item ceiling and within `brief`/`epistemic_map` token budgets.
const MAX_INLINE_COVERAGE_GAPS: usize = 3;
const MAX_INLINE_COVERAGE_TEXT_BYTES: usize = 1024;
const MAX_SINGLE_INLINE_GAP_BYTES: usize = 320;
const MAX_INLINE_COVERAGE_WITNESS_DIGESTS: usize = 16;

fn clip_utf8_bytes(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes.saturating_sub(3);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

fn summarize_coverage_list(
    items: &[String],
    separator: &str,
    overflow_noun: &str,
    hydration_hint: &str,
) -> String {
    if items.is_empty() {
        return String::new();
    }
    let joined_len = items.iter().map(String::len).sum::<usize>().saturating_add(
        separator
            .len()
            .saturating_mul(items.len().saturating_sub(1)),
    );
    if items.len() <= MAX_INLINE_COVERAGE_GAPS && joined_len <= MAX_INLINE_COVERAGE_TEXT_BYTES {
        return items.join(separator);
    }
    let shown = items.len().min(2);
    let preview: Vec<String> = items
        .iter()
        .take(shown)
        .map(|item| clip_utf8_bytes(item, MAX_SINGLE_INLINE_GAP_BYTES))
        .collect();
    let remaining = items.len().saturating_sub(shown);
    if remaining == 0 {
        preview.join(separator)
    } else {
        format!(
            "{}{separator}(+{remaining} further {overflow_noun} omitted from this cell summary; {hydration_hint}.)",
            preview.join(separator)
        )
    }
}

/// The site coverage cell: `not_observable` without retained coverage or while any objective
/// zone is not covered; `known` only when every objective zone is covered over its declared
/// window (the declared domain; activity elsewhere stays unobserved and protected).
pub(super) fn site_coverage_cell(
    coverage: Option<&CoverageAssessment>,
    ledger_evidence: ContentDigest,
    heartbeat: bool,
) -> Result<KnowledgeCell, ContractError> {
    let Some(assessment) = coverage else {
        return cell(KnowledgeCellParams {
            claim_id: CLAIM_COVERAGE.to_owned(),
            statement: if heartbeat {
                "No CoverageWitness retained: site not observable (not absence).".to_owned()
            } else {
                "No CoverageWitness is retained: site activity is not observable, and a \
                 missing event is not absence."
                    .to_owned()
            },
            knowledge_state: KnowledgeState::NotObservable,
            provenance: ProvenanceClass::Derived,
            hypothesis: None,
            evidence: Vec::new(),
            contradictions: Vec::new(),
            valid_until: None,
            state_basis: None,
        });
    };
    let covered = assessment
        .zones
        .iter()
        .filter(|zone| zone.state == ZoneCoverageState::Covered)
        .count();
    let total = assessment.zones.len();
    let complete = assessment.complete();
    let witness_digests = assessment.witness_digests();
    let compact_witness_basis =
        heartbeat || witness_digests.len() > MAX_INLINE_COVERAGE_WITNESS_DIGESTS;
    let evidence = if compact_witness_basis {
        vec![ledger_evidence]
    } else {
        witness_digests.clone()
    };
    let witness_note = if heartbeat {
        String::new()
    } else if compact_witness_basis {
        format!(
            " {} retained witness(es) are indexed in situationFrame.coverage.witnessIds and \
             bound by the committed authority ledger.",
            witness_digests.len()
        )
    } else {
        String::new()
    };
    let statement = if heartbeat {
        if complete {
            format!(
                "CoverageWitness covers {total} zone(s); activity elsewhere remains unobserved."
            )
        } else {
            let stale = assessment
                .zones
                .iter()
                .filter(|zone| zone.state == ZoneCoverageState::Stale)
                .count();
            let not_observable = assessment
                .zones
                .iter()
                .filter(|zone| zone.state == ZoneCoverageState::NotObservable)
                .count();
            format!(
                "{total} zones: {covered} covered, {stale} stale, {not_observable} not_observable (not absence)."
            )
        }
    } else if complete {
        let domains = assessment.declared_domains();
        let domains_summary = summarize_coverage_list(
            &domains,
            "; ",
            "covered zone domain(s)",
            "inspect situationFrame.coverage.domains and per-zone coverage cells",
        );
        format!(
            "Retained CoverageWitness records cover all {total} objective zone(s) over their \
             declared windows ({domains_summary}); absence of confirmed zone entries is \
             certified only there, and activity outside those zones and windows remains \
             unobserved. Provenance: {}.{witness_note}",
            assessment
                .zones
                .iter()
                .map(ZoneAssessment::provenance)
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join("; ")
        )
    } else {
        format!(
            "{covered} of {total} objective zone(s) are covered by retained CoverageWitness \
             records; the rest are not observable or stale, and a missing event there is not \
             absence.{witness_note}"
        )
    };
    cell(KnowledgeCellParams {
        claim_id: CLAIM_COVERAGE.to_owned(),
        statement,
        knowledge_state: if complete {
            KnowledgeState::Known
        } else {
            KnowledgeState::NotObservable
        },
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence,
        contradictions: assessment
            .health_contradictions()
            .into_iter()
            .chain(assessment.calibration_contradictions())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        valid_until: None,
        state_basis: None,
    })
}

/// One zone's coverage cell: `known` (covered), `not_observable`, or `stale` against the
/// anchor its most recent record was analysed at.
pub(super) fn zone_coverage_cell(
    zone: &ZoneAssessment,
    anchor: &LedgerAnchor,
) -> Result<KnowledgeCell, ContractError> {
    let (knowledge_state, state_basis) = match zone.state {
        ZoneCoverageState::Covered => (KnowledgeState::Known, None),
        ZoneCoverageState::NotObservable => (KnowledgeState::NotObservable, None),
        ZoneCoverageState::Stale => match &zone.basis {
            Some(basis) => (
                KnowledgeState::Stale,
                Some(KnowledgeStateBasis::Stale(StaleBasis::OlderAnchor {
                    valid_at: Box::new(basis.clone()),
                    current: Box::new(anchor.clone()),
                })),
            ),
            None => (KnowledgeState::NotObservable, None),
        },
    };
    let statement = match (zone.state, zone.window) {
        (ZoneCoverageState::Covered, Some(window)) => format!(
            "{} is covered over [{}, {}] ns by {} retained witness(es) of pipeline generation {}: \
             no confirmed zone entry other than published candidates. Provenance: {}.{}",
            zone.label(),
            window.earliest.0,
            window.latest.0,
            zone.witnesses.len(),
            zone.pipeline_generation
                .map_or_else(|| "unknown".to_owned(), |generation| generation.to_text()),
            zone.provenance(),
            match zone.visibility.as_ref() {
                Some(visibility) if visibility.frustum_only() => format!(
                    " The claim is frustum-only: occlusion_unknown ({}).",
                    visibility.summary()
                ),
                Some(visibility) => format!(
                    " Geometric visibility: {}; mesh occlusion covers the owner mesh only.",
                    visibility.summary()
                ),
                None => String::new(),
            }
        ),
        (state, _) => format!(
            "{} is {}: {}",
            zone.label(),
            state.as_str(),
            summarize_coverage_list(
                &zone.gaps,
                " ",
                "coverage gap(s)",
                "inspect situationFrame.coverage.gaps and retained coverage_witness records"
            )
        ),
    };
    let statement = if zone.state == ZoneCoverageState::Covered && !zone.health_conflicts.is_empty()
    {
        let conflict_descriptions: Vec<String> = zone
            .health_conflicts
            .iter()
            .map(|conflict| conflict.describe(&zone.label()))
            .collect();
        format!(
            "{statement} {} source-exact health conflict(s) withheld other witnesses; the \
             declared window rests only on the independent unaffected witnesses listed here. {}",
            zone.health_conflicts.len(),
            summarize_coverage_list(
                &conflict_descriptions,
                " ",
                "health conflict detail(s)",
                "inspect situationFrame.coverage.gaps and retained health diagnostics"
            )
        )
    } else {
        statement
    };
    let statement =
        if zone.state == ZoneCoverageState::Covered && !zone.calibration_invalidations.is_empty() {
            let invalidations: Vec<String> = zone
                .calibration_invalidations
                .iter()
                .map(ToString::to_string)
                .collect();
            format!(
                "{statement} Calibration invalidation(s) {} withdrew other historical witnesses; \
             this window uses only the unaffected witnesses listed here.",
                summarize_coverage_list(
                    &invalidations,
                    ", ",
                    "calibration invalidation digest(s)",
                    "inspect retained calibration invalidation records"
                ),
            )
        } else {
            statement
        };
    // Only a posed zone names its pose source, so other statements keep their exact text.
    let statement = format!("{statement}{}", zone.pose_clause().unwrap_or_default());
    cell(KnowledgeCellParams {
        claim_id: zone.claim_id(),
        statement,
        knowledge_state,
        provenance: ProvenanceClass::Derived,
        hypothesis: None,
        evidence: zone.witnesses.clone(),
        contradictions: if zone.state == ZoneCoverageState::Covered {
            Vec::new()
        } else {
            zone.health_conflicts
                .iter()
                .map(|conflict| conflict.diagnostic)
                .chain(zone.calibration_invalidations.iter().copied())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        },
        valid_until: None,
        state_basis,
    })
}
