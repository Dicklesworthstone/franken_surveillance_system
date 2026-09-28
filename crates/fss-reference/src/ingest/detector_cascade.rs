#![forbid(unsafe_code)]
//! Context-bound detector cascade execution.
//!
//! The native engine remains responsible for decode, privacy projection, inference,
//! association and admission. Its per-frame memoization is private to an exact
//! invocation context: changing authority, interpretation, decoder ceilings, tracking
//! selections or recovery epochs cannot reuse an earlier frame result. In particular,
//! a newly committed privacy mask cannot inherit detections from the old mask.
//!
//! This is an in-process optimization, not a durable receipt or a grant of authority.
//! Every public entry point checks cancellation before consulting the engine.

use std::fmt;

use fss_core::{CanonicalEncoder, ContentDigest};

use super::detector_cascade_engine as engine;
pub use super::detector_cascade_engine::*;
use super::package_detect::PackageDetectLimits;
use super::recorded_watch::{MAX_WATCH_FRAMES, WatchLimits};
use super::rgb_detections::RgbDetectionContract;
use super::rgb_package::RgbDetectorPackage;
use crate::{ReferenceDeployment, ReplayCx, ScalarExecCx};

/// A verified detector package with authority- and input-scoped memoization.
/// The public API and evidence encoding are the native engine's existing API.
pub struct DetectorCascade<'a> {
    engine: engine::DetectorCascade<'a>,
    package: &'a RgbDetectorPackage,
    config: CascadeConfig,
    limits: PackageDetectLimits,
    scalar: &'a ScalarExecCx,
    basis: Option<ContentDigest>,
    retired_executions: usize,
}

impl fmt::Debug for DetectorCascade<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetectorCascade")
            .field("engine", &self.engine)
            .field("basis", &self.basis)
            .field("executed", &self.executed_inferences())
            .finish_non_exhaustive()
    }
}

/// The cascade's canonical policy JSON. The glob re-export names the engine's function, which
/// takes the engine type; callers hold this context-bound owner.
#[must_use]
pub fn cascade_policy_json(cascade: &DetectorCascade<'_>) -> String {
    engine::cascade_policy_json(&cascade.engine)
}

impl<'a> DetectorCascade<'a> {
    /// Bind a verified package to a validated, immutable cascade policy.
    pub fn new(
        package: &'a RgbDetectorPackage,
        config: CascadeConfig,
        limits: PackageDetectLimits,
        scalar: &'a ScalarExecCx,
    ) -> Result<Self, CascadeError> {
        Ok(Self {
            engine: engine::DetectorCascade::new(package, config, limits, scalar)?,
            package,
            config,
            limits,
            scalar,
            basis: None,
            retired_executions: 0,
        })
    }

    /// Native cascade identity; memoization never changes retained evidence bytes.
    #[must_use]
    pub fn digest(&self) -> ContentDigest {
        self.engine.digest()
    }

    /// Fixed native cascade policy digest.
    #[must_use]
    pub fn policy_digest() -> ContentDigest {
        engine::DetectorCascade::policy_digest()
    }

    /// Immutable cascade policy.
    #[must_use]
    pub fn config(&self) -> CascadeConfig {
        self.engine.config()
    }

    /// Verified package used by this instance.
    #[must_use]
    pub fn package(&self) -> &RgbDetectorPackage {
        self.engine.package()
    }

    /// Detector contract, including any explicit threshold override.
    #[must_use]
    pub fn contract(&self) -> &RgbDetectionContract {
        self.engine.contract()
    }

    /// Completed model executions across context changes; cache hits are excluded.
    #[must_use]
    pub fn executed_inferences(&self) -> usize {
        self.retired_executions
            .saturating_add(self.engine.executed_inferences())
    }

    /// A fresh per-analysis allowance, still shared across all cameras of that analysis.
    #[must_use]
    pub fn budget(&self) -> CascadeBudget {
        self.engine.budget()
    }

    /// Run selected frames without permitting recovery across a refused interval.
    pub fn run(
        &mut self,
        deployment: &ReferenceDeployment,
        source: CascadeSource<'_>,
        tracks: &[CascadeTrack],
        budget: &mut CascadeBudget,
        limits: &WatchLimits,
        cx: &ReplayCx,
    ) -> Result<CascadeOutcome, CascadeError> {
        self.run_recovered(
            deployment,
            RecoveredCascadeSource {
                source,
                decode_refusals: &[],
                tracking_restarts: &[],
            },
            tracks,
            budget,
            limits,
            cx,
        )
    }

    /// Run explicit recovery epochs, never reusing another invocation's context.
    pub fn run_recovered(
        &mut self,
        deployment: &ReferenceDeployment,
        source: RecoveredCascadeSource<'_>,
        tracks: &[CascadeTrack],
        budget: &mut CascadeBudget,
        limits: &WatchLimits,
        cx: &ReplayCx,
    ) -> Result<CascadeOutcome, CascadeError> {
        cx.checkpoint("detector_cascade:select")
            .map_err(|_| CascadeError::Cancelled)?;
        validate_shape(source, tracks)?;
        let basis = cache_basis(
            &deployment.current_anchor(),
            source,
            tracks,
            budget.remaining(),
            limits,
        );
        if self.basis != Some(basis) {
            self.reset_engine()?;
            self.basis = Some(basis);
        }
        let result = self
            .engine
            .run_recovered(deployment, source, tracks, budget, limits, cx);
        if result.is_err() {
            // A partially completed run is not a reusable successful invocation.
            self.basis = None;
        }
        result
    }

    fn reset_engine(&mut self) -> Result<(), CascadeError> {
        let next =
            engine::DetectorCascade::new(self.package, self.config, self.limits, self.scalar)?;
        self.retired_executions = self
            .retired_executions
            .saturating_add(self.engine.executed_inferences());
        self.engine = next;
        Ok(())
    }
}

/// Check size ceilings before formatting an untrusted request for an in-memory key.
fn validate_shape(
    source: RecoveredCascadeSource<'_>,
    tracks: &[CascadeTrack],
) -> Result<(), CascadeError> {
    if source.source.decoded_segments.len() > MAX_WATCH_FRAMES
        || source.decode_refusals.len() > MAX_WATCH_FRAMES
        || source.tracking_restarts.len() > MAX_WATCH_FRAMES
        || tracks.len() > MAX_WATCH_FRAMES
        || tracks
            .iter()
            .any(|track| track.selections.len() > MAX_CASCADE_FRAMES_PER_TRACK)
        || source
            .decode_refusals
            .iter()
            .any(|r| r.error_id.len() > 256)
    {
        return Err(CascadeError::InvalidConfig(
            "cascade cache input exceeds watch bounds",
        ));
    }
    if !matches!(source.source.media_format, "mjpeg" | "annexb" | "hevc") {
        return Err(CascadeError::InvalidConfig(
            "unsupported cascade media format",
        ));
    }
    Ok(())
}

/// Debug representations are intentionally process-local: this key is never exported,
/// persisted or used as an evidence identity. Encoding each part separately avoids
/// concatenation ambiguities and includes every field of the resource-ceiling structs.
fn cache_basis(
    authority: &impl fmt::Debug,
    source: RecoveredCascadeSource<'_>,
    tracks: &[CascadeTrack],
    remaining: usize,
    limits: &WatchLimits,
) -> ContentDigest {
    let mut e = CanonicalEncoder::new();
    e.text("fss.detector_cascade_process_cache.v1");
    e.text(&format!("{authority:?}"));
    e.text(&format!("{source:?}"));
    e.text(&format!("{tracks:?}"));
    e.u64(remaining as u64);
    e.text(&format!("{limits:?}"));
    ContentDigest::sha256(&e.finish())
}

#[cfg(test)]
mod tests {
    use super::super::recorded_decode::ComponentInterpretation;
    use super::*;

    fn source() -> RecoveredCascadeSource<'static> {
        RecoveredCascadeSource {
            source: CascadeSource {
                import_identity: ContentDigest::sha256(b"import"),
                import_root: ContentDigest::sha256(b"root"),
                interpretation: ComponentInterpretation::Grayscale,
                media_format: "mjpeg",
                first_segment: 0,
                decoded_segments: &[0, 1],
            },
            decode_refusals: &[],
            tracking_restarts: &[],
        }
    }

    fn key(source: RecoveredCascadeSource<'_>) -> ContentDigest {
        cache_basis(&"authority", source, &[], 2, &WatchLimits::default())
    }

    #[test]
    fn exact_context_is_repeatable() {
        assert_eq!(key(source()), key(source()));
    }

    #[test]
    fn authority_and_allowance_cannot_be_substituted() {
        let limits = WatchLimits::default();
        let original = key(source());
        assert_ne!(
            original,
            cache_basis(&"new privacy authority", source(), &[], 2, &limits)
        );
        assert_ne!(
            original,
            cache_basis(&"authority", source(), &[], 1, &limits)
        );
    }

    #[test]
    fn interpretation_import_root_and_decode_origin_are_bound() {
        let original = key(source());
        let mut changed = source();
        changed.source.interpretation = ComponentInterpretation::YCbCr;
        assert_ne!(original, key(changed));
        let mut changed = source();
        changed.source.import_root = ContentDigest::sha256(b"another root");
        assert_ne!(original, key(changed));
        let mut changed = source();
        changed.source.first_segment = 1;
        assert_ne!(original, key(changed));
    }

    #[test]
    fn recovery_epochs_and_display_order_are_bound() {
        let original = key(source());
        let mut changed = source();
        changed.tracking_restarts = &[1];
        assert_ne!(original, key(changed));
        let mut changed = source();
        changed.source.decoded_segments = &[1, 0];
        assert_ne!(original, key(changed));
    }

    #[test]
    fn tighter_resource_limits_do_not_inherit_success() {
        let mut limits = WatchLimits::default();
        limits.jpeg_work_units = 0;
        assert_ne!(
            key(source()),
            cache_basis(&"authority", source(), &[], 2, &limits)
        );
    }

    #[test]
    fn track_selections_are_bound() {
        let tracks = [CascadeTrack {
            track_id: 1,
            selections: vec![CascadeSelection {
                segment: 1,
                reason: SelectionReason::ZoneEntry,
                track_box: [10, 10, 4, 4],
            }],
        }];
        let limits = WatchLimits::default();
        assert_ne!(
            key(source()),
            cache_basis(&"authority", source(), &tracks, 2, &limits)
        );
        let before = cache_basis(&"authority", source(), &tracks, 2, &limits);
        let mut changed = tracks;
        changed[0].selections[0].track_box[0] = 11;
        assert_ne!(
            before,
            cache_basis(&"authority", source(), &changed, 2, &limits)
        );
    }

    #[test]
    fn oversized_requests_are_rejected_before_key_allocation() {
        let segments = vec![0; MAX_WATCH_FRAMES + 1];
        let mut changed = source();
        changed.source.decoded_segments = &segments;
        assert!(validate_shape(changed, &[]).is_err());
        assert!(validate_shape(source(), &[]).is_ok());
    }
}
