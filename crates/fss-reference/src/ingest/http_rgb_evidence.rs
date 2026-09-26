#![forbid(unsafe_code)]
//! Live HTTP results cannot leave this owner before their source-closed detector
//! evidence is durably ledgered. This composes the existing recording and RGB
//! archive; it introduces no storage format, journal, worker or automatic event.
//!
//! Prepare with an actual `RgbEvidence::replay` of the held detector result. The
//! exact source, accepted admission, neural output and head result must match.
//! A saved pin is an expectation, not a successful publication or execution.
//! Temporal output is held and transferred with the original result, but the RGB
//! archive stores detector replay ingredients, NOT a temporal episode checkpoint.

use super::http_archive::{HttpArchiveLimits, HttpWireArchive, HttpWirePin};
use super::http_camera::rgb::custody::{HttpRgbWireCommit, HttpRgbWirePlan};
use super::http_camera::rgb::{
    HttpRgbBudgets, HttpRgbContext, HttpRgbOutput, HttpRgbReceipt, HttpRgbStep,
};
use super::http_recording::HttpRecordingAccess;
use super::http_replay::completion::HttpCompletionPin;
use super::http_rgb_recording::{
    HttpRgbRecording, HttpRgbRecordingError, HttpRgbRecordingRetirement, HttpRgbRecordingStep,
};
use super::rgb_archive::{
    PreparedRgbArchive, RgbArchiveAuthority, RgbArchiveError, RgbArchiveLimits,
    RgbArchiveOperation, RgbArchivePin, restore_rgb_evidence,
};
use super::rgb_detections::RgbDetectionBudget;
use super::rgb_evidence::{ReplayedRgbEvidence, RgbEvidence, RgbEvidenceBudget};
use super::rgb_inference::RgbRunLimits;
use super::rgb_tracking::{RgbFrameAdmission, pipeline::RgbZonePhase};
use crate::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use fss_core::ContentDigest;
use fss_geometry::WorkBudget;
use fss_publication::{LocalPublicationReceipt, LocalRootPublisher, RootLedgerReceipt};

/// Exact independently saved expectation. Public fields allow persistence, not
/// fabrication of an executed result: every operation compares the entire pin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpRgbEvidencePin {
    /// Existing original-model/JPEG/permission/recipe archive root and retention.
    pub archive: RgbArchivePin,
    /// Exact original-wire prefix present when this result was prepared.
    pub wire: HttpWirePin,
    /// Original HTTP/MIME mapped-source identity, not physical identity.
    pub exposure: [u8; 32],
    /// One-based part ordinal, not a camera timestamp.
    pub ordinal: u64,
    /// Hash of the complete original JPEG.
    pub encoded: [u8; 32],
    /// Actual inference, detection, tracking and zone fingerprints, in that order.
    /// The final two are expectations for temporal replay, NOT stored snapshots.
    pub stages: [[u8; 32]; 4],
    /// Applied policy, or the explicit no-policy marker.
    pub mask_policy: Option<ContentDigest>,
    /// Applied policy generation, absent exactly when the policy is absent.
    pub mask_generation: Option<u64>,
}
impl HttpRgbEvidencePin {
    fn new(archive: RgbArchivePin, wire: HttpWirePin, result: HttpRgbReceipt) -> Self {
        Self {
            archive,
            wire,
            exposure: result.exposure(),
            ordinal: result.ordinal(),
            encoded: result.encoded_sha256(),
            stages: [
                result.inference(),
                result.detections(),
                result.tracking(),
                result.zones(),
            ],
            mask_policy: result.mask_policy(),
            mask_generation: result.mask_generation(),
        }
    }
}

/// Whole-input bounds are fixed at attachment, not enlarged by a frame or retry.
#[derive(Clone, Copy, Debug)]
pub struct HttpRgbEvidenceLimits {
    /// Bounds for fresh verification of the original prefix before each boundary.
    pub source: HttpArchiveLimits,
    /// Existing source-closed RGB archive bounds.
    pub archive: RgbArchiveLimits,
}
/// Original-stream authority and derived-original retention/disclosure authority
/// are independent. Neither a saved pin nor a nonzero digest is a grant.
#[derive(Clone, Copy)]
pub struct HttpRgbEvidenceAccess<'a> {
    /// Existing live camera and original-wire storage authority.
    pub source: HttpRecordingAccess<'a>,
    /// Existing model/JPEG/permission archive authority.
    pub archive: &'a dyn RgbArchiveAuthority,
}
/// Refusals keep native results and prepared publication ownership intact.
#[derive(Debug)]
pub enum HttpRgbEvidenceError {
    /// No complete result or committed evidence exists at this boundary.
    NotReady,
    /// Wrong source, admission, replay, prepared pin or immutable retention scope.
    Mismatch,
    /// Existing original recording refused; no new source request is issued.
    Recording(HttpRgbRecordingError),
    /// Existing archive refused, including durable-but-unledgered outcomes.
    Archive(RgbArchiveError),
}
impl From<HttpRgbRecordingError> for HttpRgbEvidenceError {
    fn from(error: HttpRgbRecordingError) -> Self {
        Self::Recording(error)
    }
}
impl From<RgbArchiveError> for HttpRgbEvidenceError {
    fn from(error: RgbArchiveError) -> Self {
        Self::Archive(error)
    }
}
impl std::fmt::Display for HttpRgbEvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotReady => "HTTP RGB evidence boundary is not ready",
            Self::Mismatch => "HTTP RGB evidence binding mismatch",
            Self::Recording(_) => "HTTP RGB original recording refused",
            Self::Archive(_) => "HTTP RGB evidence archive refused",
        })
    }
}
impl std::error::Error for HttpRgbEvidenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Recording(error) => Some(error),
            Self::Archive(error) => Some(error),
            _ => None,
        }
    }
}

/// Failure returns the original recording unchanged, including its socket/work.
#[must_use]
pub struct HttpRgbEvidenceAttachFailure<'model, 'temporal> {
    /// Entire rejected owner; retirement remains available without another read.
    pub recording: HttpRgbRecording<'model, 'temporal>,
}
impl std::fmt::Debug for HttpRgbEvidenceAttachFailure<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HTTP RGB evidence requires an unanalysed, untransferred recording")
    }
}
impl std::fmt::Display for HttpRgbEvidenceAttachFailure<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
impl std::error::Error for HttpRgbEvidenceAttachFailure<'_, '_> {}

/// Exact plan stays owned after storage failure or late result-release denial.
#[must_use]
pub struct PendingHttpRgbEvidence {
    /// Independently retain before storage I/O; not a current custody proof.
    pub pin: HttpRgbEvidencePin,
    /// Existing source-closed publication plan for exact-key recovery.
    pub archive: PreparedRgbArchive,
    /// Historical successful root+ledger publication, not timeless authority.
    pub published: bool,
    result: HttpRgbReceipt,
}

/// Exclusive opt-in result durability. No mutable recording, unguarded output
/// transfer, archive replacement or live-owner extraction is exposed.
pub struct HttpRgbEvidenceRecording<'model, 'temporal> {
    recording: HttpRgbRecording<'model, 'temporal>,
    limits: HttpRgbEvidenceLimits,
    admission: Option<RgbFrameAdmission>,
    pending: Option<PendingHttpRgbEvidence>,
    last_delivered: Option<HttpRgbEvidencePin>,
}
impl<'model, 'temporal> HttpRgbEvidenceRecording<'model, 'temporal> {
    /// Attach before any analysis/transfer. A held raw read or first unanalysed
    /// frame is allowed; an already accepted admission cannot be reconstructed.
    #[allow(clippy::result_large_err)]
    pub fn attach(
        recording: HttpRgbRecording<'model, 'temporal>,
        limits: HttpRgbEvidenceLimits,
    ) -> Result<Self, HttpRgbEvidenceAttachFailure<'model, 'temporal>> {
        if recording.work().transferred != 0
            || recording.capture().phase() != RgbZonePhase::Ready
            || recording.capture().analysis().is_some()
            || recording.capture().camera().failure().is_some()
            || recording.prepared_completion().is_some()
        {
            return Err(HttpRgbEvidenceAttachFailure { recording });
        }
        Ok(Self {
            recording,
            limits,
            admission: None,
            pending: None,
            last_delivered: None,
        })
    }
    /// Read-only original owner and held native result; this is not a new grant.
    pub fn recording(&self) -> &HttpRgbRecording<'model, 'temporal> {
        &self.recording
    }
    /// Exact admission that actually reached an accepted native stage, including
    /// acceptance followed by an error. Corrected pre-acceptance retries replace nothing.
    pub fn accepted_admission(&self) -> Option<RgbFrameAdmission> {
        self.admission
    }
    /// Exact prepared result, known before any derived storage write.
    pub fn prepared(&self) -> Option<HttpRgbEvidencePin> {
        self.pending.as_ref().map(|p| p.pin)
    }
    /// Historical publication state only; transfer revalidates current storage.
    pub fn published(&self) -> Option<HttpRgbEvidencePin> {
        self.pending.as_ref().filter(|p| p.published).map(|p| p.pin)
    }
    /// Historical most recently transferred result's independent recovery pin.
    pub fn last_delivered(&self) -> Option<HttpRgbEvidencePin> {
        self.last_delivered
    }
    /// Existing source and result backpressure. ResultReady is not a durability claim.
    pub fn poll(
        &mut self,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpRgbRecordingStep, HttpRgbEvidenceError> {
        Ok(self.recording.poll(access)?)
    }
    /// Existing durable-before-parse original-read transaction, unchanged.
    pub fn commit_wire(
        &mut self,
        plan: HttpRgbWirePlan,
        publisher: &mut LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<HttpRgbWireCommit, HttpRgbEvidenceError> {
        Ok(self.recording.commit_wire(plan, publisher, access)?)
    }
    /// Save the exact admitted source/availability before returning a post-acceptance
    /// refusal. No later call can rewrite it or substitute another exposure.
    #[allow(clippy::too_many_arguments)]
    pub fn analyze(
        &mut self,
        context: HttpRgbContext<'_>,
        limits: RgbRunLimits,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
        budgets: HttpRgbBudgets<'_, '_>,
        cx: &ScalarExecCx,
    ) -> Result<HttpRgbStep, HttpRgbEvidenceError> {
        if self.admission.is_some() || self.pending.is_some() {
            return Err(HttpRgbEvidenceError::NotReady);
        }
        let admission = context.admission;
        let result = self
            .recording
            .analyze(context, limits, publisher, access, budgets, cx);
        if self.recording.capture().analysis().is_some() {
            self.admission = Some(admission);
        }
        Ok(result?)
    }
    /// Continue only accepted, unfinished native stages; never refill their budgets.
    #[allow(clippy::too_many_arguments)]
    pub fn resume(
        &mut self,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
        projection: &mut RgbDetectionBudget,
        temporal: &mut WorkBudget<'_>,
        linking: &mut WorkBudget<'_>,
        cx: &ScalarExecCx,
    ) -> Result<HttpRgbStep, HttpRgbEvidenceError> {
        if self.admission.is_none() {
            return Err(HttpRgbEvidenceError::NotReady);
        }
        Ok(self
            .recording
            .resume(publisher, access, projection, temporal, linking, cx)?)
    }

    /// Prepare the existing source-closed archive from an ACTUAL native replay of
    /// the held detector output. This never accepts a caller-authored tensor or
    /// inferred availability. It performs no filesystem writes or result transfer.
    /// Use RgbEvidence::capture on recording().capture().completed().detection_run()
    /// with accepted_admission(), then RgbEvidence::replay with the named sensor.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_evidence(
        &mut self,
        evidence: &RgbEvidence,
        replay: &ReplayedRgbEvidence,
        retention: ContentDigest,
        publisher: &LocalRootPublisher,
        access: HttpRgbEvidenceAccess<'_>,
        copy: &mut RgbEvidenceBudget,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<HttpRgbEvidencePin, HttpRgbEvidenceError> {
        let result = self
            .recording
            .capture()
            .completion()
            .ok_or(HttpRgbEvidenceError::NotReady)?;
        let admission = self.admission.ok_or(HttpRgbEvidenceError::NotReady)?;
        let actual = replay.admission();
        if actual.source() != admission.source()
            || actual.availability() != admission.availability()
            || actual.evidence() != admission.evidence()
            || replay.evidence_identity() != evidence.identity()
            || replay.run().inference().identity().bytes() != result.inference()
            || replay.run().report().digest().bytes() != result.detections()
            || replay.run().inference().source().exposure != result.exposure()
            || replay.run().inference().source().encoded_sha256 != result.encoded_sha256()
            || replay.run().mask_policy() != result.mask_policy()
        {
            return Err(HttpRgbEvidenceError::Mismatch);
        }
        if let Some(pending) = &self.pending {
            if pending.result != result
                || pending.pin.archive.evidence != evidence.identity()
                || pending.pin.archive.retention != retention
            {
                return Err(HttpRgbEvidenceError::Mismatch);
            }
        }
        if !access.archive.permits(
            RgbArchiveOperation::RetainOriginals,
            retention,
            evidence.identity(),
        ) {
            return Err(RgbArchiveError::Denied.into());
        }
        self.verify_current(result, publisher, access.source, work)?;
        if let Some(pending) = &self.pending {
            return Ok(pending.pin);
        }
        let archive = PreparedRgbArchive::new(
            evidence,
            replay,
            retention,
            self.limits.archive,
            copy,
            work,
            cx,
        )?;
        let pin = HttpRgbEvidencePin::new(archive.pin(), self.recording.pin(), result);
        self.pending = Some(PendingHttpRgbEvidence {
            pin,
            archive,
            published: false,
            result,
        });
        Ok(pin)
    }

    /// Durably publish originals and the canonical reachability batch before any
    /// result transfer. A root-only outcome is an error, not permission to release.
    /// Reopen a failed deployment and retry this SAME pin, without rerunning inference.
    /// No optional post-publication probe can conceal a successful commit.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_evidence(
        &mut self,
        expected: HttpRgbEvidencePin,
        publisher: &LocalRootPublisher,
        deployment: &mut ReferenceDeployment,
        access: HttpRgbEvidenceAccess<'_>,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<RootLedgerReceipt, HttpRgbEvidenceError> {
        let result = self.match_pending(expected)?;
        self.verify_current(result, publisher, access.source, work)?;
        let pending = self
            .pending
            .as_mut()
            .ok_or(HttpRgbEvidenceError::NotReady)?;
        let receipt = pending
            .archive
            .publish(deployment, access.archive, work, cx)?;
        pending.published = true;
        Ok(receipt)
    }

    /// Reopen and rehash the current committed derived graph, then transfer the
    /// actual held output and original frame under live camera/source authority.
    /// Read denial, tombstones, missing ledger or corruption keep both owners held.
    /// No native inference is rerun here: these are the still-owned live results.
    #[allow(clippy::too_many_arguments)]
    pub fn take_result(
        &mut self,
        expected: HttpRgbEvidencePin,
        publisher: &LocalRootPublisher,
        deployment: &mut ReferenceDeployment,
        access: HttpRgbEvidenceAccess<'_>,
        copy: &mut RgbEvidenceBudget,
        work: &mut WorkBudget<'_>,
        cx: &ReplayCx,
    ) -> Result<HttpRgbOutput, HttpRgbEvidenceError> {
        let result = self.match_pending(expected)?;
        if !self.pending.as_ref().is_some_and(|p| p.published) {
            return Err(HttpRgbEvidenceError::NotReady);
        }
        self.verify_current(result, publisher, access.source, work)?;
        restore_rgb_evidence(
            deployment,
            expected.archive,
            self.limits.archive,
            access.archive,
            copy,
            work,
            cx,
        )?;
        let output = self
            .recording
            .take_result(result, publisher, access.source)?;
        // Every fallible operation precedes native ownership transfer.
        self.pending = None;
        self.admission = None;
        self.last_delivered = Some(expected);
        Ok(output)
    }
    /// Source completion remains native HTTP/MIME completion, not an aggregate
    /// detector/temporal checkpoint. Retain EACH delivered evidence pin separately.
    pub fn commit_completion(
        &mut self,
        expected: HttpCompletionPin,
        publisher: &mut LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
    ) -> Result<LocalPublicationReceipt, HttpRgbEvidenceError> {
        if self.pending.is_some() || self.admission.is_some() {
            return Err(HttpRgbEvidenceError::NotReady);
        }
        Ok(self
            .recording
            .commit_completion(expected, publisher, access)?)
    }
    fn match_pending(
        &self,
        expected: HttpRgbEvidencePin,
    ) -> Result<HttpRgbReceipt, HttpRgbEvidenceError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or(HttpRgbEvidenceError::NotReady)?;
        if pending.pin != expected {
            return Err(HttpRgbEvidenceError::Mismatch);
        }
        Ok(pending.result)
    }
    fn verify_current(
        &mut self,
        result: HttpRgbReceipt,
        publisher: &LocalRootPublisher,
        access: HttpRecordingAccess<'_>,
        work: &mut WorkBudget<'_>,
    ) -> Result<(), HttpRgbEvidenceError> {
        if self.recording.capture().completion() != Some(result) {
            return Err(HttpRgbEvidenceError::Mismatch);
        }
        // A complete result already backpressures acquisition: this cannot read a
        // later source. Charge the existing whole-recording poll allowance as usual.
        if self.recording.poll(access)?
            != HttpRgbRecordingStep::Analysis(HttpRgbStep::ResultReady(result))
        {
            return Err(HttpRgbEvidenceError::NotReady);
        }
        let archive = HttpWireArchive::load(
            publisher,
            self.recording.scope(),
            self.recording.pin(),
            self.limits.source,
            access.storage,
            work,
        )
        .map_err(HttpRgbRecordingError::from)?;
        archive
            .verify_frame(
                publisher,
                self.recording
                    .capture()
                    .frame()
                    .ok_or(HttpRgbEvidenceError::NotReady)?,
                access.storage,
                work,
            )
            .map_err(HttpRgbRecordingError::from)?;
        Ok(())
    }
    /// Stop without network I/O; transfer all accepted computation and exact
    /// publication plans, including successful storage followed by denied delivery.
    pub fn retire(self) -> HttpRgbEvidenceRetirement {
        HttpRgbEvidenceRetirement {
            recording: self.recording.retire(),
            admission: self.admission,
            pending: self.pending,
            last_delivered: self.last_delivered,
        }
    }
}

/// Full recovery ownership. No failed publication is translated to an empty scene.
#[must_use]
pub struct HttpRgbEvidenceRetirement {
    /// Original source/processor work, wire publication plans and completion state.
    pub recording: HttpRgbRecordingRetirement,
    /// Accepted source/availability, even when analysis returned a late error.
    pub admission: Option<RgbFrameAdmission>,
    /// Exact source-closed plan and historical publication outcome still pending delivery.
    pub pending: Option<PendingHttpRgbEvidence>,
    /// Historical last result successfully transferred.
    pub last_delivered: Option<HttpRgbEvidencePin>,
}
