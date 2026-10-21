#![forbid(unsafe_code)]
//! Retained deployment event heads -> certified EvidenceClaimGraph.
//!
//! The graph-algorithm crate already owns the exact active-support incidence semantics. This module
//! supplies the missing authority bridge: it selects only event revisions that were read and
//! rehashed by DeploymentSnapshot, pins the run to that snapshot's committed LedgerAnchor, and
//! never follows a historical evidence reference to a newer revision. The result is structural
//! cognition only; unexpanded references are not source custody, independence, truth, absence, or
//! effect authority.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use fss_core::{EventHypothesis, EventId, LedgerAnchor};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::dominators;
use fss_graph_algorithms::evidence::{
    EvidenceClaimAnalysis, EvidenceClaimProjection, EvidenceProjectionError,
    EvidenceProjectionLimits,
};

use crate::agent_orient::{
    DeploymentReadError, DeploymentSnapshot, OrientLimits, RetainedEvent, read_deployment,
};

/// Certified support-structure report over exact retained current event heads.
#[derive(Clone, Debug, PartialEq)]
pub struct RetainedEvidenceClaimReport {
    /// Site lineage of the selected authority snapshot.
    pub site: String,
    /// Exact committed authority anchor.
    pub anchor: LedgerAnchor,
    /// Number of retained current revisions selected.
    pub selected_events: usize,
    /// Immutable complete-record projection.
    pub projection: EvidenceClaimProjection,
    /// Registered dominator analysis and witness.
    pub analysis: EvidenceClaimAnalysis,
}

/// Refusal before any graph answer is returned.
#[derive(Debug, PartialEq)]
pub enum RetainedEvidenceClaimError {
    /// Deployment root or committed history could not be read.
    Read(DeploymentReadError),
    /// Caller requested a different site lineage.
    SiteMismatch { expected: String, actual: String },
    /// Exact requested current event is absent at this snapshot.
    EventNotFound(EventId),
    /// Projection or registered algorithm refused.
    Projection(EvidenceProjectionError),
}

impl fmt::Display for RetainedEvidenceClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(error) => write!(f, "deployment read failed: {error}"),
            Self::SiteMismatch { expected, actual } => write!(
                f,
                "deployment site lineage {actual:?} is not requested lineage {expected:?}"
            ),
            Self::EventNotFound(event) => write!(f, "retained current event not found: {event}"),
            Self::Projection(error) => write!(f, "retained evidence graph refused: {error}"),
        }
    }
}
impl std::error::Error for RetainedEvidenceClaimError {}

impl From<EvidenceProjectionError> for RetainedEvidenceClaimError {
    fn from(error: EvidenceProjectionError) -> Self { Self::Projection(error) }
}

/// Analyze every current event head in one already-verified deployment snapshot.
///
/// No event is silently truncated to satisfy the projection limits. Large deployments must use
/// the exact-selection API below.
pub fn retained_evidence_claims(
    snapshot: &DeploymentSnapshot,
    limits: EvidenceProjectionLimits,
) -> Result<RetainedEvidenceClaimReport, RetainedEvidenceClaimError> {
    analyze_retained(
        &snapshot.site_lineage,
        &snapshot.anchor,
        snapshot.events.iter(),
        limits,
    )
}

/// Analyze an exact set of current event heads from one verified snapshot.
///
/// Every requested EventId must exist. Selection is stable by EventId because the input is a
/// BTreeSet and the snapshot itself is event-identity ordered. Historical revisions remain only
/// inside RetainedEvent audit history; they are never substituted for the selected current head.
pub fn retained_evidence_claims_selected(
    snapshot: &DeploymentSnapshot,
    events: &BTreeSet<EventId>,
    limits: EvidenceProjectionLimits,
) -> Result<RetainedEvidenceClaimReport, RetainedEvidenceClaimError> {
    let mut selected = Vec::with_capacity(events.len());
    for event_id in events {
        selected.push(
            snapshot
                .event(event_id)
                .ok_or_else(|| RetainedEvidenceClaimError::EventNotFound(event_id.clone()))?,
        );
    }
    analyze_retained(
        &snapshot.site_lineage,
        &snapshot.anchor,
        selected.into_iter(),
        limits,
    )
}

/// Read a deployment at its committed head and analyze an exact event selection.
///
/// An empty selection is explicit and produces the graph's synthetic frontier only; it is never
/// an absence certificate.
pub fn read_retained_evidence_claims_selected(
    root: &Path,
    site: &str,
    events: &BTreeSet<EventId>,
    orient_limits: &OrientLimits,
    graph_limits: EvidenceProjectionLimits,
) -> Result<RetainedEvidenceClaimReport, RetainedEvidenceClaimError> {
    let snapshot = read_deployment(root, orient_limits).map_err(RetainedEvidenceClaimError::Read)?;
    if snapshot.site_lineage != site {
        return Err(RetainedEvidenceClaimError::SiteMismatch {
            expected: site.to_owned(),
            actual: snapshot.site_lineage,
        });
    }
    retained_evidence_claims_selected(&snapshot, events, graph_limits)
}

fn analyze_retained<'a>(
    site: &str,
    anchor: &LedgerAnchor,
    retained: impl Iterator<Item = &'a RetainedEvent>,
    limits: EvidenceProjectionLimits,
) -> Result<RetainedEvidenceClaimReport, RetainedEvidenceClaimError> {
    let events: Vec<EventHypothesis> = retained.map(|item| item.event.clone()).collect();
    let projection = EvidenceClaimProjection::build(&events, limits)?;
    let bound = dominators::bound(
        projection.graph().node_count() as u64,
        projection.graph().arc_count() as u64,
    );
    let analysis = projection.analyze(anchor.clone(), Budget::registered(&bound))?;
    Ok(RetainedEvidenceClaimReport {
        site: site.to_owned(),
        anchor: anchor.clone(),
        selected_events: events.len(),
        projection,
        analysis,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::{
        CaptureInterval, ContentDigest, DecisionPath, EventEvidence, EventKind, EventState,
        EvidenceClass, EvidenceEdgeRelation, ProbabilityInterval, SensorTamperStatus, TimestampNs,
    };
    use fss_graph_algorithms::evidence::{SupportReachability, object_node};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn edge(digest: ContentDigest, relation: EvidenceEdgeRelation) -> EventEvidence {
        EventEvidence {
            digest,
            class: EvidenceClass::Observed,
            failure_domain: "failure-domain:test".to_owned(),
            supports: relation.required_supports_flag(),
            relation,
            capsule_digest: None,
            identity_digest: Some(ContentDigest::sha256(b"identity")),
        }
    }

    fn event(name: &str, revision: u64, evidence: Vec<EventEvidence>) -> TestResult<EventHypothesis> {
        let policy = ContentDigest::sha256(b"policy");
        let event = EventHypothesis {
            schema: EventHypothesis::SCHEMA.to_owned(),
            event_id: EventId::parse(name)?,
            revision,
            supersedes: None,
            state: EventState::Hypothesized,
            kind: EventKind::Unclassified,
            interval: CaptureInterval::new(TimestampNs(0), TimestampNs(1))?,
            uncertainty_reason: Some("structural graph fixture".to_owned()),
            zone_ids: vec![],
            track_ids: vec![],
            probability: ProbabilityInterval {
                lower: 0.0,
                upper: 1.0,
                calibration_generation: None,
            },
            evidence,
            model_receipts: vec![],
            decision_path: DecisionPath {
                policy_generation: policy,
                fingerprint: policy,
                abstained: true,
                abstention_reason: Some("structural only".to_owned()),
            },
        };
        event.verify()?;
        Ok(event)
    }

    fn retained(event: EventHypothesis, history: Vec<EventHypothesis>) -> RetainedEvent {
        let revision_digest = event.revision_digest();
        RetainedEvent {
            event,
            revisions: history,
            event_root: ContentDigest::sha256(b"retained-event-root"),
            revision_digest,
            committed_sequence: 1,
            tamper: SensorTamperStatus::default(),
            object_bytes: 0,
            object_reads: 0,
        }
    }

    #[test]
    fn retained_bridge_pins_exact_snapshot_anchor_and_current_heads() -> TestResult {
        let source = ContentDigest::sha256(b"retained source");
        let a = event("event:a", 1, vec![edge(source, EvidenceEdgeRelation::Supports)])?;
        let b = event(
            "event:b",
            1,
            vec![edge(a.revision_digest(), EvidenceEdgeRelation::Supports)],
        )?;
        let anchor = LedgerAnchor::genesis("site:retained-evidence");
        let records = vec![retained(a.clone(), vec![a]), retained(b.clone(), vec![b])];
        let report = analyze_retained(
            "site:retained-evidence",
            &anchor,
            records.iter(),
            EvidenceProjectionLimits::default(),
        )?;
        assert_eq!(report.selected_events, 2);
        assert_eq!(report.analysis.witness.anchor(), &anchor);
        assert_eq!(report.analysis.claims[1].revision, b.revision_digest());
        assert_eq!(
            report.analysis.claims[1].reachability,
            SupportReachability::RootedInUnexpandedReference
        );
        Ok(())
    }

    #[test]
    fn historical_support_reference_is_never_redirected_to_current_head() -> TestResult {
        let old = event("event:a", 1, vec![])?;
        let mut current = event("event:a", 2, vec![])?;
        current.supersedes = Some(old.revision_digest());
        current.verify()?;
        let dependent = event(
            "event:b",
            1,
            vec![edge(old.revision_digest(), EvidenceEdgeRelation::Supports)],
        )?;
        let records = vec![
            retained(current.clone(), vec![old.clone(), current]),
            retained(dependent.clone(), vec![dependent]),
        ];
        let report = analyze_retained(
            "site:retained-evidence",
            &LedgerAnchor::genesis("site:retained-evidence"),
            records.iter(),
            EvidenceProjectionLimits::default(),
        )?;
        assert_eq!(report.projection.unexpanded_support(), &[old.revision_digest()]);
        assert_ne!(
            object_node(old.revision_digest()),
            object_node(report.analysis.claims[0].revision)
        );
        Ok(())
    }

    #[test]
    fn compiler_limits_refuse_whole_retained_selection_without_partial_answer() -> TestResult {
        let a = event("event:a", 1, vec![])?;
        let records = vec![retained(a.clone(), vec![a])];
        let limits = EvidenceProjectionLimits {
            max_events: 0,
            ..EvidenceProjectionLimits::default()
        };
        assert!(analyze_retained(
            "site:retained-evidence",
            &LedgerAnchor::genesis("site:retained-evidence"),
            records.iter(),
            limits,
        ).is_err());
        Ok(())
    }
}
