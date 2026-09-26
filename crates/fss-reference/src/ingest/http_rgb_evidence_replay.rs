#![forbid(unsafe_code)]
//! Cold restoration binds existing RGB evidence to a native original HTTP frame.
//! Loading bytes is not execution. Only actual native replay returns verified
//! detector output; temporal fingerprints require the existing tracker/zone owner
//! to reconstruct the original episode in order. No network or ledger write occurs.

use super::http_archive::{HttpArchiveError, HttpWireArchive, HttpWirePin, HttpWireScope};
use super::http_camera::rgb::http_rgb_exposure;
use super::http_rgb_evidence::{HttpRgbEvidenceLimits, HttpRgbEvidencePin};
use super::model_import::ImportBudget;
use super::privacy_mask::live::{MaskRefusal, SensorMask};
use super::rgb_archive::{
    RgbArchiveAuthority, RgbArchiveError, RgbArchiveOperation, restore_rgb_evidence,
};
use super::rgb_detections::RgbDetectionBudget;
use super::rgb_evidence::{
    ReplayedRgbEvidence, RgbEvidence, RgbEvidenceBudget, RgbEvidenceError, RgbReplayLimits,
};
use super::rgb_tracking::RgbZoneTracker;
use crate::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_codec_mjpeg::{DecodeBudget, http_mjpeg::HttpJpegFrame};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_geometry::{GeometryError, WorkBudget};
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint};

/// Original source selected by the caller, normally from HttpWireReplay. The tip
/// is independently known; it may include later reads than this result's prefix.
/// Neither this value nor possession of the frame authorizes original disclosure.
#[derive(Clone, Copy)]
pub struct HttpRgbEvidenceReplaySource<'a> {
    /// Current original-wire publisher, not the derived evidence deployment.
    pub publisher: &'a LocalRootPublisher,
    /// Exact source generation, receive-clock and original retention scope.
    pub scope: HttpWireScope,
    /// Independently retained current source tip; never implicitly follow latest.
    pub tip: HttpWirePin,
    /// Native source-mapped frame for this exact response-local ordinal.
    pub frame: &'a HttpJpegFrame,
    /// Current original-wire disclosure/deadline/cancellation authority.
    pub cancellation: &'a dyn PublishCancellation,
}
/// Refusal never yields replacement bytes, tensors, absence, or an upgraded mask.
#[derive(Debug)]
pub enum HttpRgbEvidenceReplayError {
    /// Invalid pin or mismatched source, numerical output or temporal history.
    Mismatch,
    /// The existing temporal owner has not completed both required stages.
    TemporalPending,
    /// Current disclosure/deadline/cancellation authority refused.
    Denied,
    /// Current original-wire custody could not be verified.
    Source(HttpArchiveError),
    /// Existing source-closed derived archive refused restoration.
    Archive(RgbArchiveError),
    /// Existing native source import/decode/inference/head replay refused.
    Evidence(RgbEvidenceError),
    /// Current sensor policy differs from the recorded generation.
    Privacy(MaskRefusal),
    /// Bounded source inventory/mapping work refused.
    Work(GeometryError),
}
impl std::fmt::Display for HttpRgbEvidenceReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Mismatch => "HTTP RGB replay source/result mismatch",
            Self::TemporalPending => "HTTP RGB temporal replay incomplete",
            Self::Denied => "HTTP RGB replay disclosure refused",
            Self::Source(_) => "HTTP RGB original custody refused",
            Self::Archive(_) => "HTTP RGB derived custody refused",
            Self::Evidence(_) => "HTTP RGB native evidence replay refused",
            Self::Privacy(_) => "HTTP RGB replay privacy generation refused",
            Self::Work(_) => "HTTP RGB replay source work refused",
        })
    }
}
impl std::error::Error for HttpRgbEvidenceReplayError {}
impl From<HttpArchiveError> for HttpRgbEvidenceReplayError {
    fn from(e: HttpArchiveError) -> Self {
        Self::Source(e)
    }
}
impl From<RgbArchiveError> for HttpRgbEvidenceReplayError {
    fn from(e: RgbArchiveError) -> Self {
        Self::Archive(e)
    }
}
impl From<RgbEvidenceError> for HttpRgbEvidenceReplayError {
    fn from(e: RgbEvidenceError) -> Self {
        Self::Evidence(e)
    }
}
impl From<GeometryError> for HttpRgbEvidenceReplayError {
    fn from(e: GeometryError) -> Self {
        Self::Work(e)
    }
}

/// A verified original-source binding and restored source envelope, NOT inference.
/// Restore and execution are separate so the evidence deployment can also supply
/// the sensor's immutable privacy authority without aliasing a mutable borrow.
pub struct RestoredHttpRgbEvidence {
    pin: HttpRgbEvidencePin,
    evidence: RgbEvidence,
}
/// Actual source-closed numerical recomputation, not a deserialized output claim.
pub struct ReplayedHttpRgbEvidence {
    pin: HttpRgbEvidencePin,
    replay: ReplayedRgbEvidence,
}
/// All four expected stage identities matched actual native reconstruction.
/// This is not durable publication, authenticated capture time or event authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedHttpRgbTemporalReplay {
    pin: HttpRgbEvidencePin,
}
impl VerifiedHttpRgbTemporalReplay {
    /// Exact independently selected source/result expectation that was checked.
    pub fn pin(self) -> HttpRgbEvidencePin {
        self.pin
    }
}

/// Re-read the exact original tip and source-closed derived graph. A historical
/// frame prefix must be a real member of that tip, not a rival or guessed root.
/// No decoded pixels or temporal mutation are produced by this function.
#[allow(clippy::too_many_arguments)]
pub fn restore_http_rgb_evidence(
    expected: HttpRgbEvidencePin,
    source: HttpRgbEvidenceReplaySource<'_>,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RgbArchiveAuthority,
    limits: HttpRgbEvidenceLimits,
    copy: &mut RgbEvidenceBudget,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RestoredHttpRgbEvidence, HttpRgbEvidenceReplayError> {
    validate(expected)?;
    authorize(expected, source.cancellation, authority, cx)?;
    let part = source.frame.part().receipt();
    if source.frame.head().wire != source.scope.stream
        || expected.ordinal != part.ordinal
        || expected.encoded != part.encoded_sha256
        || expected.wire.scope != source.tip.scope
        || expected.wire.reads > source.tip.reads
        || expected.wire.bytes > source.tip.bytes
        || source
            .frame
            .source_spans()
            .iter()
            .any(|s| s.wire_range[1] > expected.wire.bytes)
    {
        return Err(HttpRgbEvidenceReplayError::Mismatch);
    }
    let archive = HttpWireArchive::load(
        source.publisher,
        source.scope,
        source.tip,
        limits.source,
        source.cancellation,
        work,
    )?;
    // load() has checked the entire bounded inventory and its chain. Membership
    // is checked without replacing the historical per-result prefix with the tip.
    work.charge(source.tip.reads)?;
    if !archive.reads().any(|(pin, _)| pin == expected.wire) {
        return Err(HttpRgbEvidenceReplayError::Mismatch);
    }
    archive.verify_frame(source.publisher, source.frame, source.cancellation, work)?;
    if http_rgb_exposure(source.frame, work)? != expected.exposure {
        return Err(HttpRgbEvidenceReplayError::Mismatch);
    }
    let evidence = restore_rgb_evidence(
        deployment,
        expected.archive,
        limits.archive,
        authority,
        copy,
        work,
        cx,
    )?;
    work.charge(evidence.jpeg().len() as u64)?;
    if ContentDigest::sha256(evidence.jpeg()).bytes() != expected.encoded
        || evidence.mask_policy()? != expected.mask_policy
    {
        return Err(HttpRgbEvidenceReplayError::Mismatch);
    }
    authorize(expected, source.cancellation, authority, cx)?;
    Ok(RestoredHttpRgbEvidence {
        pin: expected,
        evidence,
    })
}
impl RestoredHttpRgbEvidence {
    /// Expected identities, not a claim that any numerical stage has run.
    pub fn pin(&self) -> HttpRgbEvidencePin {
        self.pin
    }
    /// Re-import/re-decode/re-execute with the existing native replay engine and
    /// compare its actual detector fingerprints against the independently saved pin.
    /// Current original disclosure and the named sensor's current policy are checked.
    /// Restored bytes are an authorized snapshot, not a timeless storage claim.
    #[allow(clippy::too_many_arguments)]
    pub fn replay(
        &self,
        privacy: SensorMask<'_>,
        limits: RgbReplayLimits,
        original: &dyn PublishCancellation,
        authority: &dyn RgbArchiveAuthority,
        copy: &mut RgbEvidenceBudget,
        import: &mut ImportBudget,
        decoder: &mut DecodeBudget<'_>,
        projection: &mut RgbDetectionBudget,
        cx: &ReplayCx,
        scalar: &ScalarExecCx,
    ) -> Result<ReplayedHttpRgbEvidence, HttpRgbEvidenceReplayError> {
        authorize(self.pin, original, authority, cx)?;
        let mask = privacy
            .resolve()
            .map_err(|e| HttpRgbEvidenceReplayError::Privacy(e.into()))?;
        if mask.policy_digest() != self.pin.mask_policy
            || mask.generation() != self.pin.mask_generation
        {
            return Err(HttpRgbEvidenceReplayError::Privacy(
                MaskRefusal::UnmaskedAccess,
            ));
        }
        let replay = self.evidence.replay(
            privacy, limits, copy, import, decoder, projection, cx, scalar,
        )?;
        let source = replay.admission().source();
        if replay.evidence_identity() != self.pin.archive.evidence
            || source.exposure != self.pin.exposure
            || source.encoded_sha256 != self.pin.encoded
            || source.capture != self.pin.archive.capture
            || replay.run().inference().identity().bytes() != self.pin.stages[0]
            || replay.run().report().digest().bytes() != self.pin.stages[1]
            || replay.run().mask_policy() != self.pin.mask_policy
        {
            return Err(HttpRgbEvidenceReplayError::Mismatch);
        }
        authorize(self.pin, original, authority, cx)?;
        Ok(ReplayedHttpRgbEvidence {
            pin: self.pin,
            replay,
        })
    }
}
impl ReplayedHttpRgbEvidence {
    /// Exact selected source/result pin whose numerical stages matched.
    pub fn pin(&self) -> HttpRgbEvidencePin {
        self.pin
    }
    /// Actual inference, head and preserved admission for the existing temporal owner.
    pub fn evidence(&self) -> &ReplayedRgbEvidence {
        &self.replay
    }
    /// Check actual reconstructed tracking and zones without mutating either stage.
    /// The caller must replay the same episode/configuration in original order.
    /// A mismatch does not reset history, retry association or manufacture an event.
    pub fn verify_temporal(
        &self,
        owner: &RgbZoneTracker,
    ) -> Result<VerifiedHttpRgbTemporalReplay, HttpRgbEvidenceReplayError> {
        let tracking = owner
            .tracking_report()
            .ok_or(HttpRgbEvidenceReplayError::TemporalPending)?;
        let zones = owner
            .zone_report()
            .ok_or(HttpRgbEvidenceReplayError::TemporalPending)?;
        if tracking.digest() != self.pin.stages[2] || zones.digest() != self.pin.stages[3] {
            return Err(HttpRgbEvidenceReplayError::Mismatch);
        }
        Ok(VerifiedHttpRgbTemporalReplay { pin: self.pin })
    }
}
fn validate(pin: HttpRgbEvidencePin) -> Result<(), HttpRgbEvidenceReplayError> {
    let valid = |d: ContentDigest| d.algorithm() == DigestAlgorithm::Sha256 && d.bytes() != [0; 32];
    if ![
        pin.archive.root,
        pin.archive.evidence,
        pin.archive.retention,
        pin.wire.scope,
        pin.wire.head,
    ]
    .into_iter()
    .all(valid)
        || pin.ordinal == 0
        || pin.wire.reads == 0
        || pin.wire.bytes == 0
        || pin.archive.capture[0] > pin.archive.capture[1]
        || [pin.exposure, pin.encoded]
            .into_iter()
            .chain(pin.stages)
            .any(|d| d == [0; 32])
        || pin.mask_policy.is_some() != pin.mask_generation.is_some()
        || pin.mask_policy.is_some_and(|p| !valid(p))
        || pin.mask_generation == Some(0)
    {
        return Err(HttpRgbEvidenceReplayError::Mismatch);
    }
    Ok(())
}
fn authorize(
    pin: HttpRgbEvidencePin,
    original: &dyn PublishCancellation,
    archive: &dyn RgbArchiveAuthority,
    cx: &ReplayCx,
) -> Result<(), HttpRgbEvidenceReplayError> {
    if cx.checkpoint("http-rgb-evidence:disclosure").is_err()
        || original.cancel_requested(PublishCutPoint::AfterChildrenVerified)
        || !archive.permits(
            RgbArchiveOperation::ReadOriginals,
            pin.archive.retention,
            pin.archive.evidence,
        )
    {
        return Err(HttpRgbEvidenceReplayError::Denied);
    }
    Ok(())
}
