#![forbid(unsafe_code)]
//! Paired event outcomes at the predeclared threshold on one held-out corpus.

use fss_core::CanonicalEncoder;
use fss_reference::evaluation::{EvaluationReport, TruthDisposition};

use super::super::{Failure, Result, array, fixed_json, object, text};
use super::{Holdout, digest};

const SCHEMA: &str = "fss.evaluation.model_comparison.v1";

fn detected(disposition: &TruthDisposition, threshold: u32) -> Option<bool> {
    match disposition {
        TruthDisposition::Detected { score_ppm, .. } => Some(*score_ppm >= threshold),
        TruthDisposition::Missed => Some(false),
        TruthDisposition::NotObservable { .. } => None,
    }
}

impl Holdout {
    pub(crate) fn compare(
        &self,
        baseline: &EvaluationReport,
        challenger: &EvaluationReport,
    ) -> Result<String> {
        if baseline.label_set_digest != challenger.label_set_digest
            || baseline.policy != challenger.policy
            || baseline.identity.pipeline_generation != challenger.identity.pipeline_generation
            || baseline.identity.policy_generation != challenger.identity.policy_generation
            || baseline.truth_outcomes.len() != challenger.truth_outcomes.len()
        {
            return Err(Failure::new("evaluation.comparison.incompatible_reports"));
        }
        let old = baseline.at_threshold(self.threshold_ppm)?;
        let new = challenger.at_threshold(self.threshold_ppm)?;
        let mut gained = Vec::new();
        let mut lost = Vec::new();
        let (mut both, mut neither, mut unobservable) = (0_u64, 0_u64, 0_u64);
        // Evaluator output is canonical by truth ID. Candidate IDs belong to their own model.
        for (before, after) in baseline
            .truth_outcomes
            .iter()
            .zip(&challenger.truth_outcomes)
        {
            if before.event_id != after.event_id {
                return Err(Failure::new("evaluation.comparison.incompatible_reports"));
            }
            match (
                detected(&before.disposition, self.threshold_ppm),
                detected(&after.disposition, self.threshold_ppm),
            ) {
                (Some(false), Some(true)) => gained.push(text(&after.event_id)),
                (Some(true), Some(false)) => lost.push(text(&after.event_id)),
                (Some(true), Some(true)) => both += 1,
                (Some(false), Some(false)) => neither += 1,
                (None, None) => unobservable += 1,
                _ => return Err(Failure::new("evaluation.comparison.incompatible_reports")),
            }
        }
        let mut binding = CanonicalEncoder::new();
        binding.text(SCHEMA);
        binding.digest(self.manifest_digest);
        binding.digest(old.digest);
        binding.digest(new.digest);
        Ok(object(&[
            ("schema", text(SCHEMA)),
            (
                "baseline_model_generation",
                text(&baseline.identity.model_generation),
            ),
            (
                "challenger_model_generation",
                text(&challenger.identity.model_generation),
            ),
            ("manifest_digest", text(&self.manifest_digest.to_string())),
            ("baseline", fixed_json(&old)),
            ("challenger", fixed_json(&new)),
            ("detected_by_both", both.to_string()),
            ("missed_by_both", neither.to_string()),
            ("not_observable", unobservable.to_string()),
            ("gained_event_ids", array(gained)),
            ("lost_event_ids", array(lost)),
            ("digest", text(&digest(binding)?.to_string())),
        ]))
    }
}
