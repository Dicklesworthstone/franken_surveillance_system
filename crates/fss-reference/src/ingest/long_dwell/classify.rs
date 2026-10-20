#![forbid(unsafe_code)]
//! Attach the existing trained stage to an already complete native dwell scan.
//!
//! Checkpoints retain temporal computation only. Classification is a separate terminal stage
//! over qualifying episodes, using the original whole-scan resource reservation. It neither
//! rebuilds foreground/tracker state nor accepts caller-authored perception or model state.

use std::ops::Range;

use super::*;

/// Private source metadata plus a range inside the report's existing canonical analysis.
/// No extra trace, pixels, decoder state or classifier continuation is retained here.
#[derive(Debug)]
pub(super) struct ClassificationSource {
    pub(super) limits: LongDwellLimits,
    pub(super) manifest_digest: ContentDigest,
    pub(super) import_anchor: LedgerAnchor,
    pub(super) trace: Range<usize>,
}

impl LongDwellReport {
    /// Classify actual observations belonging to this complete, previously untrained scan.
    ///
    /// A resumed incremental scan can enter the same terminal stage as
    /// [`Self::analyze_with_detector`]. Only the selected native colour frames are decoded
    /// again; the foreground/tracker/dwell scan is not repeated. Classifier source, pixel and
    /// JPEG costs spend the remainder of the original scan's limits, with one inference
    /// allowance for all episodes. An already trained report cannot renew that allowance.
    /// Each call is a separately admitted terminal attempt: a refused attempt's classifier
    /// cost is not accumulated in this reusable temporal report. Callers account for retry
    /// work outside the report; its original temporal scan counters and limits never reset.
    ///
    /// Exact deployment, actor, authority basis, source custody, privacy and any requested
    /// health fence are checked before and after native classification, including zero
    /// candidates. Every refusal leaves this report unchanged. Successful replacement creates
    /// the same trained report and proposal identities as a whole-recording trained scan;
    /// those proposals require their own exact approval. This method stages and publishes
    /// nothing. Existing publication retains the exact model archive and cold replay recipe.
    pub fn classify_with_detector(
        &mut self,
        deployment: &ReferenceDeployment,
        detector: &LongDwellDetector<'_>,
        cx: &ReplayCx,
    ) -> Result<()> {
        checkpoint(cx, "long_dwell:classify")?;
        if self.detector.is_some() {
            return Err(WatchError::InvalidPlan(
                "completed dwell report already contains a detector stage",
            ));
        }
        let original = self.classification.as_ref().ok_or(WatchError::Conflict)?;
        let _ = super::super::long_watch::detector::LongWatchDetectorRecipe::new(
            detector.package,
            detector.config,
            detector.limits,
            &original.limits,
        )?;
        self.revalidate_derived_source(deployment, cx)?;
        let trace = self
            .analysis
            .get(original.trace.clone())
            .ok_or(WatchError::Conflict)?;
        let scan = ScanData {
            limits: original.limits,
            import_root: self.import_root,
            manifest_digest: original.manifest_digest,
            import_anchor: original.import_anchor.clone(),
            sensor: self.sensor.clone(),
            privacy: self.privacy.clone(),
            publication_guard: self.publication_guard.clone(),
            trace: trace.to_vec(),
            episodes: self
                .candidates
                .iter()
                .map(|candidate| candidate.episode.clone())
                .collect(),
            entries: Vec::new(),
            decoded: self.decoded,
            unreliable: self.unreliable,
            masked_zones: self.masked_zones,
            restarts: self.restarts,
            refusals: self.refusals.clone(),
            source_bytes: self.source_bytes,
            pixel_samples: self.pixel_samples,
            assignment_work: self.assignment_work,
            jpeg_work: self.jpeg_work,
            health: self.health.clone(),
            // This separately owned diagnostic is transferred only after every fallible
            // operation succeeds, so a refusal cannot consume it or alter its retention state.
            health_diagnostic: None,
            media_format: self.media_format.clone(),
        };
        let completed =
            run_native_detector(deployment, &self.plan, self.options, &scan, detector, cx)?;
        let mut classified = Self::from_scan(
            deployment,
            &self.plan,
            self.rule,
            self.options,
            scan,
            Some(completed),
            cx,
        )?;
        self.revalidate_derived_source(deployment, cx)?;
        checkpoint(cx, "long_dwell:classified")?;
        classified.health_diagnostic = self.health_diagnostic.take();
        *self = classified;
        Ok(())
    }
}

/// One implementation of temporal selection, whole-invocation admission and trained evidence
/// for direct analysis and terminal classification of a completed/resumed native report.
pub(super) fn run_native_detector(
    deployment: &ReferenceDeployment,
    plan: &WatchPlan,
    options: WatchOptions,
    scan: &ScanData,
    detector: &LongDwellDetector<'_>,
    cx: &ReplayCx,
) -> Result<super::super::long_watch::detector::Completed> {
    let selected = detector::select(scan, detector.config, cx)?;
    let mut allowance = super::super::long_watch::detector::AnalysisBudget::new(detector);
    let mut completed = super::super::long_watch::detector::run_selected(
        deployment,
        plan,
        options,
        scan,
        &scan.limits,
        detector,
        selected,
        &mut allowance,
        cx,
    )?;
    let _ = allowance.witness()?;
    completed.policy_json = completed.policy_json.replacen(
        "\"frame_selection\":\"whole_recording_entry_then_following_actual_matches\"",
        "\"frame_selection\":\"qualifying_dwell_episode_first_actual_matches_only\"",
        1,
    );
    Ok(completed)
}
