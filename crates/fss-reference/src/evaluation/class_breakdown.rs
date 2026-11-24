//! Class-specific event metrics at one caller-selected operating threshold.
//!
//! This is a projection of an existing full matching, not a second matching or a threshold
//! search. Classes cannot compete for a match in the event evaluator, so grouping the existing
//! outcomes preserves score ties, duplicate-alert penalties and neutral observations exactly.
//! Every class retains the entire corpus's observed duration, including negative clips.

use super::*;

/// Maximum number of distinct observed and explicitly declared classes in a breakdown.
pub const MAX_EVALUATION_CLASSES: usize = 256;

/// Fixed-threshold metrics for a class; threshold and exposure belong to the enclosing report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassOperatingPoint {
    /// Matched observable events at the shared threshold.
    pub true_positives: u64,
    /// Unmatched scored candidates at the shared threshold.
    pub false_positives: u64,
    /// Observable truth events not detected at the shared threshold.
    pub false_negatives: u64,
    /// Fraction of scored alerts that match.
    pub precision: Ratio,
    /// Fraction of observable truth events detected.
    pub recall: Ratio,
    /// Admission against the original budget and full exposure; None for zero exposure.
    pub within_budget: Option<bool>,
    /// Detection latency over matches at the shared threshold.
    pub time_to_detect: Option<TimeToDetectSummary>,
}

/// Metrics for one class, including truth-only, candidate-only and declared empty classes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassEvaluation {
    /// Exact, case-sensitive event class.
    pub class: String,
    /// Counts before applying the shared threshold.
    pub counts: EvaluationCounts,
    /// Per-class precision/recall curve, thresholds strictly descending.
    pub pr_curve: Vec<PrPoint>,
    /// Per-class step-wise AUPRC, undefined when no observable truth exists.
    pub auprc: PpmMetric,
    /// Metrics at the same threshold used by every other class.
    pub fixed_operating_point: ClassOperatingPoint,
}

/// Digest-bound class projection of a pooled evaluation, without changing its canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassBreakdown {
    /// Digest of the complete pooled evaluation and its input identities.
    pub report_digest: ContentDigest,
    /// One inclusive score threshold supplied before inspecting the evaluation.
    pub threshold_ppm: u32,
    /// Explicit class inventory in ascending order; observed classes are always included too.
    pub declared_classes: Vec<String>,
    /// Full corpus exposure, shared by every class (never filtered to positive clips).
    pub durations: ObservedDurations,
    /// Class metrics, ascending by exact class identifier.
    pub classes: Vec<ClassEvaluation>,
    /// Digest binding the parent, inventory, threshold, exposure and every class metric.
    pub digest: ContentDigest,
}

#[derive(Default)]
struct Accumulator {
    counts: EvaluationCounts,
    scores: BTreeMap<u32, (u64, u64)>,
    fixed_true_positives: u64,
    fixed_false_positives: u64,
    fixed_latencies: Vec<u64>,
}

fn checkpoint(cancelled: &dyn Fn() -> bool) -> Result<(), EvaluationError> {
    if cancelled() {
        Err(EvaluationError::Cancelled)
    } else {
        Ok(())
    }
}

fn add_class<'a>(
    classes: &mut BTreeMap<&'a str, Accumulator>,
    class: &'a str,
) -> Result<(), EvaluationError> {
    check_id("evaluation_class", class)?;
    if !classes.contains_key(class) {
        check_limit(
            EvaluationLimit::Classes,
            MAX_EVALUATION_CLASSES,
            classes.len() + 1,
        )?;
        classes.insert(class, Accumulator::default());
    }
    Ok(())
}

impl EvaluationReport {
    /// Project class metrics using the exact labels and candidates bound by this report.
    ///
    /// All observed classes are included. An optional declared inventory also exposes classes
    /// with no truths or candidates, whose recall and AUPRC remain explicitly undefined.
    /// Wrong input digests, malformed inventories and mismatched outcomes are refused.
    /// No threshold is selected or activated, and the pooled report is unchanged.
    pub fn by_class_at_threshold(
        &self,
        labels: &LabelSet,
        candidates: &CandidateSet,
        threshold_ppm: u32,
        declared_classes: &[String],
    ) -> Result<ClassBreakdown, EvaluationError> {
        self.by_class_at_threshold_cancellable(
            labels,
            candidates,
            threshold_ppm,
            declared_classes,
            &|| false,
        )
    }

    /// Same projection with cancellation at input, outcome, score and publication boundaries.
    ///
    /// There is no candidate-by-truth matching loop. Canonical sorts and hashes remain bounded
    /// indivisible operations under the existing input limits and the 256-class output limit.
    pub fn by_class_at_threshold_cancellable(
        &self,
        labels: &LabelSet,
        candidates: &CandidateSet,
        threshold_ppm: u32,
        declared_classes: &[String],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<ClassBreakdown, EvaluationError> {
        checkpoint(cancelled)?;
        if threshold_ppm > MAX_SCORE_PPM {
            return Err(EvaluationError::InvalidThreshold);
        }
        check_limit(EvaluationLimit::Classes, MAX_EVALUATION_CLASSES, declared_classes.len())?;
        check_limit(EvaluationLimit::Clips, MAX_EVALUATION_CLIPS, labels.clips.len())?;
        check_limit(
            EvaluationLimit::TruthEvents,
            MAX_EVALUATION_TRUTH_EVENTS,
            labels.events.len(),
        )?;
        check_limit(
            EvaluationLimit::Candidates,
            MAX_EVALUATION_CANDIDATES,
            candidates.candidates.len(),
        )?;
        let gap_count = labels.clips.iter().fold(0_usize, |count, clip| {
            count.saturating_add(clip.not_observable.len())
        });
        check_limit(
            EvaluationLimit::NotObservableIntervals,
            MAX_EVALUATION_NOT_OBSERVABLE_INTERVALS,
            gap_count,
        )?;
        if self.truth_outcomes.len() != labels.events.len()
            || self.candidate_outcomes.len() != candidates.candidates.len()
            || self.pr_curve.len() > candidates.candidates.len()
        {
            return Err(EvaluationError::InconsistentReport);
        }

        let mut classes = BTreeMap::new();
        let mut inventory: Vec<&str> = declared_classes.iter().map(String::as_str).collect();
        inventory.sort_unstable();
        for (index, class) in inventory.iter().enumerate() {
            checkpoint(cancelled)?;
            if index > 0 && inventory[index - 1] == *class {
                return Err(EvaluationError::DuplicateId {
                    field: "evaluation_class",
                    id: (*class).to_owned(),
                });
            }
            add_class(&mut classes, class)?;
        }
        let mut clips: Vec<&LabeledClip> = labels.clips.iter().collect();
        clips.sort_unstable_by(|a, b| a.clip_id.cmp(&b.clip_id));
        for clip in &clips {
            checkpoint(cancelled)?;
            check_id("clip_id", &clip.clip_id)?;
        }
        let mut events: Vec<&TruthEvent> = labels.events.iter().collect();
        events.sort_unstable_by(|a, b| a.event_id.cmp(&b.event_id));
        for event in &events {
            checkpoint(cancelled)?;
            check_id("event_id", &event.event_id)?;
            check_id("event_clip_id", &event.clip_id)?;
            if let Some(zone) = &event.zone {
                check_id("event_zone", zone)?;
            }
            add_class(&mut classes, &event.class)?;
        }
        let mut by_id: Vec<&EventCandidate> = candidates.candidates.iter().collect();
        by_id.sort_unstable_by(|a, b| a.candidate_id.cmp(&b.candidate_id));
        for candidate in &by_id {
            checkpoint(cancelled)?;
            check_id("candidate_id", &candidate.candidate_id)?;
            check_id("candidate_clip_id", &candidate.clip_id)?;
            if let Some(zone) = &candidate.zone {
                check_id("candidate_zone", zone)?;
            }
            add_class(&mut classes, &candidate.class)?;
        }
        if label_set_digest(&clips, &events)? != self.label_set_digest
            || candidate_set_digest(&by_id)? != self.candidate_set_digest
            || !self.verify_digest()
        {
            return Err(EvaluationError::InconsistentReport);
        }
        checkpoint(cancelled)?;

        for (index, (event, outcome)) in events.iter().zip(&self.truth_outcomes).enumerate() {
            checkpoint(cancelled)?;
            if event.event_id != outcome.event_id
                || (index > 0 && events[index - 1].event_id == event.event_id)
            {
                return Err(EvaluationError::InconsistentReport);
            }
            let state = classes
                .get_mut(event.class.as_str())
                .ok_or(EvaluationError::InconsistentReport)?;
            state.counts.truth_events += 1;
            match &outcome.disposition {
                TruthDisposition::NotObservable { .. } => {
                    state.counts.not_observable_truth_events += 1;
                }
                TruthDisposition::Missed => {
                    state.counts.observable_truth_events += 1;
                    state.counts.false_negatives += 1;
                }
                TruthDisposition::Detected { score_ppm, time_to_detect_ns, .. } => {
                    state.counts.observable_truth_events += 1;
                    if *score_ppm >= threshold_ppm {
                        state.fixed_latencies.push(*time_to_detect_ns);
                    }
                }
            }
        }
        for (index, (candidate, outcome)) in by_id.iter().zip(&self.candidate_outcomes).enumerate() {
            checkpoint(cancelled)?;
            if candidate.candidate_id != outcome.candidate_id
                || (index > 0 && by_id[index - 1].candidate_id == candidate.candidate_id)
            {
                return Err(EvaluationError::InconsistentReport);
            }
            let state = classes
                .get_mut(candidate.class.as_str())
                .ok_or(EvaluationError::InconsistentReport)?;
            state.counts.candidates += 1;
            let positive = match &outcome.disposition {
                CandidateDisposition::InsideNotObservable => {
                    state.counts.candidates_inside_not_observable += 1;
                    continue;
                }
                CandidateDisposition::MatchedNotObservableTruth { .. } => {
                    state.counts.candidates_matched_not_observable_truth += 1;
                    continue;
                }
                CandidateDisposition::TruePositive { event_id } => {
                    let event_index = events
                        .binary_search_by(|event| event.event_id.cmp(event_id))
                        .map_err(|_| EvaluationError::InconsistentReport)?;
                    let event = events[event_index];
                    if event.class != candidate.class
                        || event.clip_id != candidate.clip_id
                        || !matches!(
                            &self.truth_outcomes[event_index].disposition,
                            TruthDisposition::Detected { candidate_id, score_ppm, time_to_detect_ns }
                                if *candidate_id == candidate.candidate_id
                                    && *score_ppm == candidate.score_ppm
                                    && *time_to_detect_ns == candidate.detect_ns.saturating_sub(event.interval.start_ns)
                        )
                    {
                        return Err(EvaluationError::InconsistentReport);
                    }
                    true
                }
                CandidateDisposition::FalsePositive => false,
            };
            let score = state.scores.entry(candidate.score_ppm).or_default();
            if positive {
                state.counts.true_positives += 1;
                score.0 += 1;
                if candidate.score_ppm >= threshold_ppm {
                    state.fixed_true_positives += 1;
                }
            } else {
                state.counts.false_positives += 1;
                score.1 += 1;
                if candidate.score_ppm >= threshold_ppm {
                    state.fixed_false_positives += 1;
                }
            }
        }

        let mut projected = Vec::with_capacity(classes.len());
        for (class, state) in classes {
            checkpoint(cancelled)?;
            let positives = state.counts.observable_truth_events;
            if state.counts.true_positives + state.counts.false_negatives != positives
                || state.fixed_latencies.len() as u64 != state.fixed_true_positives
            {
                return Err(EvaluationError::InconsistentReport);
            }
            let mut pr_curve = Vec::with_capacity(state.scores.len());
            let mut tp = 0;
            let mut fp = 0;
            let mut sum_atto = 0_u128;
            for (score, (delta_tp, delta_fp)) in state.scores.iter().rev() {
                checkpoint(cancelled)?;
                tp += delta_tp;
                fp += delta_fp;
                pr_curve.push(PrPoint {
                    threshold_ppm: *score,
                    true_positives: tp,
                    false_positives: fp,
                    precision: Ratio::of(tp, tp + fp, UndefinedReason::NoScoredCandidates),
                    recall: Ratio::of(tp, positives, UndefinedReason::NoObservableTruthEvents),
                    within_false_alert_budget: self.policy.false_alert_budget.admits(fp, self.durations.observed_ns),
                });
                if positives > 0 {
                    sum_atto += u128::from(*delta_tp) * u128::from(tp) * ATTO_PER_UNIT
                        / (u128::from(positives) * u128::from(tp + fp));
                }
            }
            let auprc = if positives == 0 {
                PpmMetric::Undefined(UndefinedReason::NoObservableTruthEvents)
            } else {
                let ppm = ((sum_atto + ATTO_PER_PPM / 2) / ATTO_PER_PPM)
                    .min(u128::from(MAX_SCORE_PPM));
                PpmMetric::Defined(u32::try_from(ppm).unwrap_or(MAX_SCORE_PPM))
            };
            let fixed_tp = state.fixed_true_positives;
            let fixed_fp = state.fixed_false_positives;
            projected.push(ClassEvaluation {
                class: class.to_owned(),
                counts: state.counts,
                pr_curve,
                auprc,
                fixed_operating_point: ClassOperatingPoint {
                    true_positives: fixed_tp,
                    false_positives: fixed_fp,
                    false_negatives: positives.checked_sub(fixed_tp)
                        .ok_or(EvaluationError::InconsistentReport)?,
                    precision: Ratio::of(fixed_tp, fixed_tp + fixed_fp, UndefinedReason::NoScoredCandidates),
                    recall: Ratio::of(fixed_tp, positives, UndefinedReason::NoObservableTruthEvents),
                    within_budget: (self.durations.observed_ns > 0).then(|| {
                        self.policy.false_alert_budget.admits(fixed_fp, self.durations.observed_ns)
                    }),
                    time_to_detect: TimeToDetectSummary::from_values(state.fixed_latencies),
                },
            });
        }
        let total = projected.iter().fold(EvaluationCounts::default(), |mut sum, class| {
            let counts = class.counts;
            sum.truth_events += counts.truth_events;
            sum.observable_truth_events += counts.observable_truth_events;
            sum.not_observable_truth_events += counts.not_observable_truth_events;
            sum.candidates += counts.candidates;
            sum.candidates_inside_not_observable += counts.candidates_inside_not_observable;
            sum.candidates_matched_not_observable_truth += counts.candidates_matched_not_observable_truth;
            sum.true_positives += counts.true_positives;
            sum.false_positives += counts.false_positives;
            sum.false_negatives += counts.false_negatives;
            sum
        });
        if total != self.counts {
            return Err(EvaluationError::InconsistentReport);
        }
        let mut result = ClassBreakdown {
            report_digest: self.digest,
            threshold_ppm,
            declared_classes: inventory.into_iter().map(str::to_owned).collect(),
            durations: self.durations,
            classes: projected,
            digest: self.digest,
        };
        result.digest = result.compute_digest()?;
        checkpoint(cancelled)?;
        Ok(result)
    }
}

impl ClassBreakdown {
    /// Recompute the canonical class-projection digest.
    pub fn compute_digest(&self) -> Result<ContentDigest, EvaluationError> {
        let mut encoder = domain_encoder("class-breakdown/v1");
        encoder.digest(self.report_digest);
        encoder.u32(self.threshold_ppm);
        encoder.u64(self.declared_classes.len() as u64);
        for class in &self.declared_classes {
            encoder.text(class);
        }
        encode_u128(&mut encoder, self.durations.total_ns);
        encode_u128(&mut encoder, self.durations.not_observable_ns);
        encode_u128(&mut encoder, self.durations.observed_ns);
        encoder.u64(self.classes.len() as u64);
        for class in &self.classes {
            encoder.text(&class.class);
            let counts = &class.counts;
            for value in [
                counts.truth_events,
                counts.observable_truth_events,
                counts.not_observable_truth_events,
                counts.candidates,
                counts.candidates_inside_not_observable,
                counts.candidates_matched_not_observable_truth,
                counts.true_positives,
                counts.false_positives,
                counts.false_negatives,
            ] {
                encoder.u64(value);
            }
            encoder.u64(class.pr_curve.len() as u64);
            for point in &class.pr_curve {
                encode_point(&mut encoder, point);
            }
            match class.auprc {
                PpmMetric::Defined(value) => {
                    encoder.tag(1);
                    encoder.u32(value);
                }
                PpmMetric::Undefined(reason) => {
                    encoder.tag(0);
                    encoder.tag(reason.tag());
                }
            }
            let fixed = &class.fixed_operating_point;
            encoder.u64(fixed.true_positives);
            encoder.u64(fixed.false_positives);
            encoder.u64(fixed.false_negatives);
            fixed.precision.encode(&mut encoder);
            fixed.recall.encode(&mut encoder);
            encoder.tag(match fixed.within_budget {
                None => 0,
                Some(false) => 1,
                Some(true) => 2,
            });
            encode_ttd(&mut encoder, fixed.time_to_detect.as_ref());
        }
        finish_digest(encoder)
    }

    /// Whether the digest binds all fields of this class projection.
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.compute_digest().is_ok_and(|digest| digest == self.digest)
    }
}
