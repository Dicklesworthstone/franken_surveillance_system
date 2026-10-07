//! The reference fusion and sequential decision rule.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{
    Calibration, Cluster, ClusterDirection, Counterfactual, Coverage, Decision, FusionError,
    FusionOutcome, FusionQuery, LlrInterval, Observability, Reason,
};
use crate::probability::{PPM, probability_ppm};

const NS_PER_SECOND: u128 = 1_000_000_000;

/// Admitted clusters plus what was set aside, with reasons.
struct Partition {
    clusters: Vec<Cluster>,
    excluded: Vec<(String, String)>,
    uncalibrated: Vec<String>,
}

/// A caller's declaration cannot remove the producing sensor's common-cause identity.
/// The same spelling is used for evidence and future observations, so repeated frames cannot
/// become independent corroboration by changing the optional domain labels.
fn effective_domains(sensor: &str, declared: &BTreeSet<String>) -> BTreeSet<String> {
    let mut domains = declared.clone();
    domains.insert(format!("sensor:{sensor}"));
    domains
}

fn partition(query: &FusionQuery) -> Partition {
    let mut items: Vec<_> = query.evidence.iter().collect();
    items.sort_by(|a, b| a.id.cmp(&b.id));
    let mut excluded = Vec::new();
    let mut uncalibrated = Vec::new();
    let mut admitted = Vec::new();
    for item in items {
        match (&item.observability, &item.calibration) {
            (Observability::NotObservable { reason }, _) => {
                excluded.push((item.id.clone(), format!("not_observable: {reason}")));
            }
            (Observability::Redacted, _) => excluded.push((item.id.clone(), "redacted".to_owned())),
            (Observability::Stale, _) => excluded.push((item.id.clone(), "stale".to_owned())),
            (Observability::Observed, Calibration::Uncalibrated { .. }) => {
                uncalibrated.push(item.id.clone());
            }
            (Observability::Observed, Calibration::Calibrated { llr, .. }) => admitted.push((
                item,
                *llr,
                effective_domains(&item.sensor, &item.failure_domains),
            )),
        }
    }
    // Union-find over shared failure domains; roots are the smallest admitted index.
    let mut parent: Vec<usize> = (0..admitted.len()).collect();
    fn root(parent: &mut [usize], mut node: usize) -> usize {
        while parent[node] != node {
            parent[node] = parent[parent[node]];
            node = parent[node];
        }
        node
    }
    let mut first_holder: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, (_, _, domains)) in admitted.iter().enumerate() {
        for domain in domains {
            match first_holder.get(domain.as_str()) {
                Some(&other) => {
                    let (a, b) = (root(&mut parent, index), root(&mut parent, other));
                    if a != b {
                        parent[a.max(b)] = a.min(b);
                    }
                }
                None => {
                    first_holder.insert(domain.as_str(), index);
                }
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for index in 0..admitted.len() {
        let group = root(&mut parent, index);
        groups.entry(group).or_default().push(index);
    }
    let clusters = groups
        .values()
        .enumerate()
        .map(|(label, indices)| {
            let mut llr = admitted[indices[0]].1;
            let mut domains = BTreeSet::new();
            let mut members = Vec::with_capacity(indices.len());
            for &index in indices {
                let (item, item_llr, item_domains) = &admitted[index];
                llr = llr.hull(*item_llr);
                domains.extend(item_domains.iter().cloned());
                members.push(item.id.clone());
            }
            let direction = if llr.lo() > 0 {
                ClusterDirection::Supports
            } else if llr.hi() < 0 {
                ClusterDirection::Contradicts
            } else if llr.lo() < 0 && llr.hi() > 0 {
                ClusterDirection::Conflicted
            } else {
                ClusterDirection::Neutral
            };
            Cluster {
                label: label as u32,
                members,
                failure_domains: domains,
                llr,
                direction,
            }
        })
        .collect();
    Partition {
        clusters,
        excluded,
        uncalibrated,
    }
}

/// Posterior and counts over a set of clusters.
struct Assessment<'a> {
    posterior: LlrInterval,
    support: u32,
    contra: u32,
    conflicted: bool,
    clusters: Vec<&'a Cluster>,
}

fn assess<'a>(
    prior: LlrInterval,
    clusters: Vec<&'a Cluster>,
) -> Result<Assessment<'a>, FusionError> {
    let (mut lo, mut hi) = (prior.lo(), prior.hi());
    let (mut support, mut contra, mut internal) = (0, 0, false);
    for cluster in &clusters {
        lo = lo
            .checked_add(cluster.llr.lo())
            .ok_or(FusionError::Overflow("posterior lower bound"))?;
        hi = hi
            .checked_add(cluster.llr.hi())
            .ok_or(FusionError::Overflow("posterior upper bound"))?;
        match cluster.direction {
            ClusterDirection::Supports => support += 1,
            ClusterDirection::Contradicts => contra += 1,
            ClusterDirection::Conflicted => internal = true,
            ClusterDirection::Neutral => {}
        }
    }
    Ok(Assessment {
        posterior: LlrInterval::unchecked(lo, hi),
        support,
        contra,
        conflicted: internal || (support > 0 && contra > 0),
        clusters,
    })
}

fn ceil_log2(value: u32) -> i64 {
    if value <= 1 {
        0
    } else {
        i64::from(32 - (value - 1).leading_zeros())
    }
}

/// Worst-case decision loss of deciding now (alert or not) over the posterior interval: the
/// value of perfect information, an upper bound on what any observation can save.
fn robust_loss_now(query: &FusionQuery, posterior: LlrInterval) -> u64 {
    let (p_lo, p_hi) = probability_ppm(posterior.lo(), posterior.hi());
    let ppm = u128::from(PPM);
    let alert_loss = u128::from(PPM - p_lo) * u128::from(query.severity.false_alert_cost) / ppm;
    let hold_loss = u128::from(p_hi) * u128::from(query.severity.expected_harm) / ppm;
    u64::try_from(alert_loss.min(hold_loss)).unwrap_or(u64::MAX)
}

fn delay_loss(query: &FusionQuery, delay_ns: u64) -> u64 {
    let loss =
        u128::from(query.severity.delay_cost_per_second) * u128::from(delay_ns) / NS_PER_SECOND;
    u64::try_from(loss).unwrap_or(u64::MAX)
}

/// An observation independent of every fused cluster, whose positive outcome would alert or
/// whose negative outcome would retain.
fn decision_relevant(
    query: &FusionQuery,
    assessment: &Assessment<'_>,
    threshold: i64,
    domains: &BTreeSet<String>,
    positive: LlrInterval,
    negative: LlrInterval,
) -> bool {
    let independent = assessment
        .clusters
        .iter()
        .all(|cluster| cluster.failure_domains.is_disjoint(domains));
    if !independent {
        return false;
    }
    let posterior = assessment.posterior;
    let new_support = assessment.support + u32::from(positive.lo() > 0);
    let alerts = posterior.lo().saturating_add(positive.lo()) >= threshold
        && new_support >= query.policy.min_independent_support;
    let retains = posterior.hi().saturating_add(negative.hi()) < query.policy.retain_threshold;
    alerts || retains
}

/// The decision over one assessment, and the reasons it adds.
fn decide(
    query: &FusionQuery,
    assessment: &Assessment<'_>,
    threshold: i64,
    uncertified_evidence: bool,
) -> (Decision, Vec<Reason>) {
    let policy = &query.policy;
    let posterior = assessment.posterior;
    let complete = query.coverage == Coverage::Complete;
    let mut reasons = Vec::new();
    let single_domain;
    if posterior.lo() >= threshold {
        reasons.push(Reason::AboveAlertThreshold);
        if assessment.support >= policy.min_independent_support {
            if complete {
                return (Decision::Alert, reasons);
            }
            reasons.push(Reason::CoverageNotComplete);
            return (Decision::AlertDegradedCoverage, reasons);
        }
        reasons.push(Reason::InsufficientIndependentSupport);
        single_domain = assessment.support > 0;
    } else if posterior.hi() <= policy.reject_threshold {
        reasons.push(Reason::BelowRejectThreshold);
        if complete
            && !uncertified_evidence
            && !assessment.clusters.is_empty()
            && !assessment.conflicted
        {
            return (Decision::Reject, reasons);
        }
        if !complete {
            reasons.push(Reason::CoverageNotComplete);
        }
        reasons.push(Reason::AbsenceNotCertified);
        return (Decision::RetainSilently, reasons);
    } else if posterior.hi() < policy.retain_threshold {
        reasons.push(Reason::BelowRetainThreshold);
        return (Decision::RetainSilently, reasons);
    } else {
        reasons.push(Reason::Undecided);
        single_domain =
            assessment.support >= 1 && assessment.support < policy.min_independent_support;
        if single_domain {
            reasons.push(Reason::InsufficientIndependentSupport);
        }
    }

    let evpi = robust_loss_now(query, posterior);
    let horizon = query.now_ns.saturating_add(policy.max_wait_ns);
    let mut best_wait: Option<(u64, &str, u64)> = None;
    for opportunity in &query.opportunities {
        if opportunity.window_end < query.now_ns || opportunity.window_start > horizon {
            continue;
        }
        if !decision_relevant(
            query,
            assessment,
            threshold,
            &effective_domains(&opportunity.sensor, &opportunity.failure_domains),
            opportunity.positive,
            opportunity.negative,
        ) {
            continue;
        }
        let deadline = opportunity.window_end.min(horizon);
        let loss = delay_loss(query, deadline - query.now_ns);
        if evpi <= loss {
            continue;
        }
        let candidate = (deadline, opportunity.id.as_str(), evpi - loss);
        if best_wait.is_none_or(|best| (candidate.0, candidate.1) < (best.0, best.1)) {
            best_wait = Some(candidate);
        }
    }
    if let Some((deadline_ns, opportunity, value_bound)) = best_wait {
        return (
            Decision::WaitForCorroboration {
                opportunity: opportunity.to_owned(),
                deadline_ns,
                value_bound,
            },
            reasons,
        );
    }
    let mut best_probe: Option<(u64, &str)> = None;
    for probe in &query.probes {
        if !decision_relevant(
            query,
            assessment,
            threshold,
            &probe.failure_domains,
            probe.positive,
            probe.negative,
        ) {
            continue;
        }
        let spend = probe
            .cost
            .saturating_add(delay_loss(query, probe.latency_ns));
        if evpi <= spend {
            continue;
        }
        let value = evpi - spend;
        if best_probe.is_none_or(|best| {
            (value, std::cmp::Reverse(probe.id.as_str())) > (best.0, std::cmp::Reverse(best.1))
        }) {
            best_probe = Some((value, probe.id.as_str()));
        }
    }
    if let Some((value_bound, probe)) = best_probe {
        return (
            Decision::RequestObservation {
                probe: probe.to_owned(),
                value_bound,
            },
            reasons,
        );
    }
    if single_domain
        && let Some(urgent) = policy.urgent_single_domain_threshold
        && posterior.lo() >= urgent.saturating_add(threshold - policy.alert_threshold)
    {
        return (Decision::AlertSingleDomainUnconfirmed, reasons);
    }
    if policy.operator_confirmation_available && evpi > 0 {
        return (Decision::RequestOperatorConfirmation, reasons);
    }
    reasons.push(Reason::NoDecisionRelevantObservation);
    (Decision::HoldIndeterminate, reasons)
}

/// Fuses `query` and decides what happens next.
///
/// # Errors
///
/// [`FusionError::InvalidInput`] and [`FusionError::InvalidPolicy`] for a query outside its
/// contract, [`FusionError::Overflow`] if an exact sum leaves `i64` (impossible within the
/// validated bounds, checked anyway).
pub fn fuse(query: &FusionQuery) -> Result<FusionOutcome, FusionError> {
    query.validate()?;
    let Partition {
        clusters,
        excluded,
        uncalibrated,
    } = partition(query);
    let threshold = query
        .policy
        .alert_threshold
        .checked_add(query.policy.look_penalty_per_doubling * ceil_log2(query.looks))
        .ok_or(FusionError::Overflow("sequential alert threshold"))?;
    let assessment = assess(query.prior, clusters.iter().collect())?;
    // Uncalibrated observations may contradict the calibrated evidence. A low base rate is
    // likewise no observation of absence: neither can support a certified rejection.
    let uncertified_evidence = !excluded.is_empty() || !uncalibrated.is_empty();
    let (decision, mut reasons) = decide(query, &assessment, threshold, uncertified_evidence);
    if assessment.conflicted {
        reasons.push(Reason::ConflictingEvidence);
    }
    if !excluded.is_empty() {
        reasons.push(Reason::MissingObservations);
    }
    if !uncalibrated.is_empty() {
        reasons.push(Reason::UncalibratedEvidenceIgnored);
    }
    if threshold > query.policy.alert_threshold {
        reasons.push(Reason::OptionalStoppingCorrection);
    }
    reasons.sort_unstable();
    reasons.dedup();
    let mut counterfactuals = Vec::with_capacity(clusters.len());
    for removed in &clusters {
        let others = clusters
            .iter()
            .filter(|cluster| cluster.label != removed.label)
            .collect();
        let without = assess(query.prior, others)?;
        let (decision, _) = decide(query, &without, threshold, uncertified_evidence);
        counterfactuals.push(Counterfactual {
            removed_cluster: removed.label,
            posterior: without.posterior,
            decision,
        });
    }
    let posterior = assessment.posterior;
    let observable_gap = excluded
        .iter()
        .any(|(_, reason)| reason.starts_with("not_observable"))
        || matches!(query.coverage, Coverage::Gap { .. });
    let knowledge_state = if clusters.is_empty() {
        if observable_gap {
            "not_observable"
        } else {
            "unknown"
        }
    } else if assessment.conflicted {
        "conflicted"
    } else {
        "estimated"
    };
    let outcome = FusionOutcome {
        query_digest: query.digest(),
        policy_generation: query.policy.generation.clone(),
        probability_ppm: probability_ppm(posterior.lo(), posterior.hi()),
        supporting_clusters: assessment.support,
        contradicting_clusters: assessment.contra,
        knowledge_state,
        sequential_alert_threshold: threshold,
        decision,
        reasons,
        support_to_alert: (posterior.lo() < threshold).then(|| threshold - posterior.lo()),
        reduction_to_retain: (posterior.hi() >= query.policy.retain_threshold)
            .then(|| posterior.hi() - query.policy.retain_threshold + 1),
        counterfactuals,
        posterior,
        clusters,
        excluded,
        uncalibrated,
        decision_digest: fss_core::ContentDigest::sha256(b""),
    };
    Ok(outcome.seal())
}
