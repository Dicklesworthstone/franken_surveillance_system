#![forbid(unsafe_code)]
//! Explicit sensor/failure-domain loss, recomputed from the original evidence graph.
//!
//! A dependency cluster is not a sensor. Removing one member can split a transitive
//! cluster, change its hull, or leave other members usable. This owner applies a
//! bounded, simultaneous loss scenario to evidence and future observation choices,
//! then runs the unchanged fusion rule over the resulting query. It never subtracts
//! a cluster's likelihood from a posterior or changes the live policy.

use std::collections::BTreeSet;

use fss_core::{CanonicalEncoder, ContentDigest};

use crate::model::valid_text;
use crate::{Coverage, FusionError, FusionOutcome, FusionQuery, Observability, fuse};

/// Maximum simultaneous sensor/domain exclusions in one counterfactual.
pub const MAX_ABLATION_TARGETS: usize = 16;
/// Canonical receipt domain; independent of the original query/decision identities.
pub const FUSION_ABLATION_DOMAIN: &str = "fss.fusion.ablation.v1";
/// Complete derived counterfactual JSON projection.
pub const FUSION_ABLATION_SCHEMA: &str = "fss.fusion_ablation.v1";
/// Interpretation of the loss scenario, not a physical outage or independence certificate.
pub const FUSION_ABLATION_IMPLEMENTATION: &str =
    "fss-fusion:ablation:unavailable-evidence:recluster:coverage-gap:v1";

const UNAVAILABLE: &str = "counterfactual sensor or failure domain unavailable";
const COVERAGE_GAP: &str = "counterfactual source loss has no replacement coverage witness";

/// One exact declared identity to make unavailable. A set is one simultaneous
/// scenario, not a sequence of fresh looks and not independent leave-one-out cases.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AblationTarget {
    /// The producing sensor and any explicit `sensor:<id>` dependencies.
    Sensor(String),
    /// An exact declared domain, including intrinsic `sensor:<id>` domains.
    FailureDomain(String),
}

impl AblationTarget {
    /// Stable selector spelling.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Sensor(_) => "sensor",
            Self::FailureDomain(_) => "failure_domain",
        }
    }

    /// Exact sensor or domain identity.
    #[must_use]
    pub fn identity(&self) -> &str {
        match self {
            Self::Sensor(identity) | Self::FailureDomain(identity) => identity,
        }
    }

    fn matches(&self, sensor: Option<&str>, domains: &BTreeSet<String>) -> bool {
        match self {
            Self::Sensor(identity) => {
                sensor == Some(identity.as_str()) || domains.contains(&format!("sensor:{identity}"))
            }
            Self::FailureDomain(domain) => {
                domains.contains(domain)
                    || sensor.is_some_and(|sensor| domain == &format!("sensor:{sensor}"))
            }
        }
    }
}

/// Measured selector work and the two bounded calls to the reference fusion rule.
/// This is not a CPU-time or complete internal fusion-operation measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AblationWork {
    /// Every selector is checked against every evidence/opportunity/probe row.
    pub selector_item_checks: u64,
    /// Full baseline and counterfactual evaluations, including their cluster counterfactuals.
    pub fusion_evaluations: u32,
}

/// Immutable, replayable explanation of one explicit source-loss scenario.
/// Current source custody, physical coverage and statistical validity are not established
/// by this pure computation; the caller retains the original source/authority context.
#[derive(Clone, Debug)]
pub struct FusionAblation {
    targets: Vec<AblationTarget>,
    original: FusionQuery,
    baseline: FusionOutcome,
    counterfactual: FusionQuery,
    outcome: FusionOutcome,
    unavailable_evidence: Vec<String>,
    removed_opportunities: Vec<String>,
    removed_probes: Vec<String>,
    work: AblationWork,
    digest: ContentDigest,
}

impl FusionAblation {
    /// Canonically ordered, unique simultaneous exclusions.
    #[must_use]
    pub fn targets(&self) -> &[AblationTarget] {
        &self.targets
    }
    /// Complete original query, normalized only to canonical row order.
    #[must_use]
    pub const fn original_query(&self) -> &FusionQuery {
        &self.original
    }
    /// Recomputed original decision, not a caller-supplied mutable outcome.
    #[must_use]
    pub const fn baseline(&self) -> &FusionOutcome {
        &self.baseline
    }
    /// Complete replay input after the explicit losses; prior/policy/time/looks are unchanged.
    #[must_use]
    pub const fn counterfactual_query(&self) -> &FusionQuery {
        &self.counterfactual
    }
    /// Fresh clusters, hulls, uncertainty, decision and leave-one-cluster-out explanations.
    #[must_use]
    pub const fn outcome(&self) -> &FusionOutcome {
        &self.outcome
    }
    /// Matching evidence identities. Existing redacted/stale/not-observable states stay intact.
    #[must_use]
    pub fn unavailable_evidence(&self) -> &[String] {
        &self.unavailable_evidence
    }
    /// Future observations excluded because their producing sensor or declared domain failed.
    #[must_use]
    pub fn removed_opportunities(&self) -> &[String] {
        &self.removed_opportunities
    }
    /// Probes excluded by their declared dependencies. No undeclared independence is inferred.
    #[must_use]
    pub fn removed_probes(&self) -> &[String] {
        &self.removed_probes
    }
    /// Exact bounded selector accounting; inner fusion arithmetic has its existing bounds.
    #[must_use]
    pub const fn work(&self) -> AblationWork {
        self.work
    }
    /// Binds selectors, both complete queries/decisions, affected inventories and work.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
}

/// Recompute one simultaneous sensor/failure-domain-loss counterfactual.
///
/// Matching observed rows become explicitly not observable; other missingness is preserved.
/// No evidence row, score or original uncertainty is silently discarded. Future choices using
/// the failed identities are removed. Coverage never improves: an existing gap is preserved,
/// and complete/degraded coverage becomes a gap because no replacement witness was supplied.
/// Remaining usable evidence is re-clustered from scratch by the ordinary fusion owner.
///
/// # Errors
///
/// [`FusionError::InvalidInput`] for an invalid query, empty/oversized/duplicate selector set,
/// invalid identity or a selector that names no declared input or future choice. Every selector
/// must match even when another selector overlaps it. No state or input is mutated on refusal.
pub fn ablate(
    query: &FusionQuery,
    targets: &[AblationTarget],
) -> Result<FusionAblation, FusionError> {
    if targets.is_empty() || targets.len() > MAX_ABLATION_TARGETS {
        return Err(FusionError::InvalidInput(
            "ablation target count".to_owned(),
        ));
    }
    let mut targets = targets.to_vec();
    targets.sort();
    if targets.iter().any(|target| !valid_text(target.identity()))
        || targets.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(FusionError::InvalidInput(
            "ablation target identities".to_owned(),
        ));
    }
    query.validate()?;
    let mut original = query.clone();
    original.evidence.sort_by(|a, b| a.id.cmp(&b.id));
    original.opportunities.sort_by(|a, b| a.id.cmp(&b.id));
    original.probes.sort_by(|a, b| a.id.cmp(&b.id));
    let mut counterfactual = original.clone();
    let mut matched = vec![false; targets.len()];
    let mut selector_item_checks = 0_u64;
    let mut affected = |sensor: Option<&str>, domains: &BTreeSet<String>| {
        let mut any = false;
        for (index, target) in targets.iter().enumerate() {
            selector_item_checks += 1;
            if target.matches(sensor, domains) {
                matched[index] = true;
                any = true;
            }
        }
        any
    };
    let mut unavailable_evidence = Vec::new();
    for item in &mut counterfactual.evidence {
        if affected(Some(&item.sensor), &item.failure_domains) {
            unavailable_evidence.push(item.id.clone());
            if item.observability == Observability::Observed {
                item.observability = Observability::NotObservable {
                    reason: UNAVAILABLE.to_owned(),
                };
            }
        }
    }
    let mut removed_opportunities = Vec::new();
    counterfactual.opportunities.retain(|opportunity| {
        let remove = affected(Some(&opportunity.sensor), &opportunity.failure_domains);
        if remove {
            removed_opportunities.push(opportunity.id.clone());
        }
        !remove
    });
    let mut removed_probes = Vec::new();
    counterfactual.probes.retain(|probe| {
        let remove = affected(None, &probe.failure_domains);
        if remove {
            removed_probes.push(probe.id.clone());
        }
        !remove
    });
    if matched.iter().any(|matched| !matched) {
        return Err(FusionError::InvalidInput(
            "ablation target absent from declared inputs and choices".to_owned(),
        ));
    }
    if !matches!(counterfactual.coverage, Coverage::Gap { .. }) {
        counterfactual.coverage = Coverage::Gap {
            reason: COVERAGE_GAP.to_owned(),
        };
    }
    let baseline = fuse(&original)?;
    let outcome = fuse(&counterfactual)?;
    let work = AblationWork {
        selector_item_checks,
        fusion_evaluations: 2,
    };
    let mut encoder = CanonicalEncoder::new();
    encoder.text(FUSION_ABLATION_DOMAIN);
    encoder.text(FUSION_ABLATION_IMPLEMENTATION);
    encoder.digest(baseline.query_digest);
    encoder.digest(baseline.decision_digest);
    encoder.u32(targets.len() as u32);
    for target in &targets {
        encoder.text(target.kind());
        encoder.text(target.identity());
    }
    for rows in [
        &unavailable_evidence,
        &removed_opportunities,
        &removed_probes,
    ] {
        encoder.u32(rows.len() as u32);
        for identity in rows {
            encoder.text(identity);
        }
    }
    encoder.digest(outcome.query_digest);
    encoder.digest(outcome.decision_digest);
    encoder.u64(work.selector_item_checks);
    encoder.u32(work.fusion_evaluations);
    let digest =
        ContentDigest::sha256(&encoder.finish_checked().map_err(|_| {
            FusionError::InvalidInput("ablation receipt encoding bounds".to_owned())
        })?);
    Ok(FusionAblation {
        targets,
        original,
        baseline,
        counterfactual,
        outcome,
        unavailable_evidence,
        removed_opportunities,
        removed_probes,
        work,
        digest,
    })
}
