#![forbid(unsafe_code)]
//! Atomic in-memory application of an explicitly adjudicated partial assignment.
//! This owns derived track state, not evidence custody or identity/effect authority.

use super::{ContactTrack, TrackDisposition, TrackError, TrackReceipt, TrackSnapshot, TrackUpdate};
use crate::association::{AssociationError, MAX_ASSOCIATION_ITEMS};
use crate::association_hypotheses::{AssignmentLink, AssociationSelection};
use crate::{ContactObservation, ProjectionQuality, PropertyTwin, TrackingCamera};
use fss_core::ContentDigest;
use fss_geometry::{GeometryBasis, GeometryError, WorkBudget};
use std::collections::VecDeque;

/// Explicit owner decision. Sequence numbers start at one, with no accepted gaps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchOperation {
    /// Monotone operation number within the exact set session.
    pub sequence: u64,
    /// Nonzero retained adjudication record; a hash is not authentication.
    pub adjudication: [u8; 32],
}

/// No failed application changes any track, watermark, sequence or replay receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchError {
    /// Empty, duplicated, unseeded or incompatible initial membership, or invalid policy.
    InvalidInput,
    /// The twin, session, admitted camera, membership or source revision changed.
    BasisMismatch,
    /// Owner invalidation is latched; a new session is required.
    Invalidated,
    /// New operation is not exactly the next sequence number.
    Sequence,
    /// Old operation has left the bounded receipt cache; do not apply it again.
    ExpiredReplay,
    /// Same operation number has a different exact request or adjudication.
    ConflictingReplay,
    /// A camera exposure or source record is reused as a new batch.
    ReusedExposure,
    /// Allocation, byte or complete-output limit was exceeded.
    Limit,
    /// A selected source update could not be staged.
    Track(TrackError),
    /// Source freshness or assignment computation failed.
    Association(AssociationError),
}
impl From<TrackError> for BatchError {
    fn from(e: TrackError) -> Self {
        Self::Track(e)
    }
}
impl From<AssociationError> for BatchError {
    fn from(e: AssociationError) -> Self {
        Self::Association(e)
    }
}
impl From<GeometryError> for BatchError {
    fn from(e: GeometryError) -> Self {
        Self::Track(e.into())
    }
}
impl std::fmt::Display for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid track-set input",
            Self::BasisMismatch => "track-set basis mismatch",
            Self::Invalidated => "track-set session invalidated",
            Self::Sequence => "track-set operation sequence mismatch",
            Self::ExpiredReplay => "track-set replay receipt expired",
            Self::ConflictingReplay => "conflicting track-set replay",
            Self::ReusedExposure => "track-set source exposure reused",
            Self::Limit => "track-set resource limit exceeded",
            Self::Track(_) => "track-set source update failed",
            Self::Association(_) => "track-set association validation failed",
        })
    }
}
impl std::error::Error for BatchError {}

/// One committed in-memory transition, including unchanged and unmatched tracks.
/// This is not a durable ledger acknowledgement or physical-identity certificate.
#[derive(Debug, Eq, PartialEq)]
pub struct BatchReceipt {
    session: [u8; 32],
    operation: BatchOperation,
    request: [u8; 32],
    twin: [u8; 32],
    camera: u64,
    exposure: u64,
    frame_evidence: [u8; 32],
    capture: [u64; 2],
    one_to_one_basis: [u8; 32],
    links: Vec<AssignmentLink>,
    before: Vec<TrackReceipt>,
    after: Vec<TrackReceipt>,
    updates: Vec<TrackUpdate>,
    unmatched_tracks: Vec<u64>,
    unmatched_detections: Vec<u64>,
}
impl BatchReceipt {
    /// Exact owner-issued set session, never an authorization token.
    pub fn session(&self) -> [u8; 32] {
        self.session
    }
    /// Accepted sequence and explicit adjudication evidence.
    pub fn operation(&self) -> BatchOperation {
        self.operation
    }
    /// Fingerprint of the complete input graph, policy, selection and operation.
    pub fn request_digest(&self) -> [u8; 32] {
        self.request
    }
    /// Exact imported package, not only a reusable local geometry handle.
    pub fn twin_digest(&self) -> [u8; 32] {
        self.twin
    }
    /// Original source exposure identity within its camera.
    pub fn exposure(&self) -> (u64, u64) {
        (self.camera, self.exposure)
    }
    /// Source-frame evidence root, not a generated observation.
    pub fn frame_evidence(&self) -> [u8; 32] {
        self.frame_evidence
    }
    /// Source capture interval, not processing time.
    pub fn capture(&self) -> [u64; 2] {
        self.capture
    }
    /// Retained assumption under which the partial matching was checked.
    pub fn one_to_one_basis(&self) -> [u8; 32] {
        self.one_to_one_basis
    }
    /// Explicit chosen links; this module never ranks candidate assignments.
    pub fn links(&self) -> &[AssignmentLink] {
        &self.links
    }
    /// Full membership before the atomic update, in track-ID order.
    pub fn before(&self) -> &[TrackReceipt] {
        &self.before
    }
    /// Full membership after the atomic update, including untouched tracks.
    pub fn after(&self) -> &[TrackReceipt] {
        &self.after
    }
    /// Only the explicitly selected source updates, in track-ID order.
    pub fn updates(&self) -> &[TrackUpdate] {
        &self.updates
    }
    /// Unmatched tracks retain their old source state, not an observed disappearance.
    pub fn unmatched_tracks(&self) -> &[u64] {
        &self.unmatched_tracks
    }
    /// Unmatched detections are retained, not automatically converted to births/clutter.
    pub fn unmatched_detections(&self) -> &[u64] {
        &self.unmatched_detections
    }
    fn try_copy(&self) -> Result<Self, BatchError> {
        Ok(Self {
            session: self.session,
            operation: self.operation,
            request: self.request,
            twin: self.twin,
            camera: self.camera,
            exposure: self.exposure,
            frame_evidence: self.frame_evidence,
            capture: self.capture,
            one_to_one_basis: self.one_to_one_basis,
            links: copied(&self.links)?,
            before: copied(&self.before)?,
            after: copied(&self.after)?,
            updates: copied(&self.updates)?,
            unmatched_tracks: copied(&self.unmatched_tracks)?,
            unmatched_detections: copied(&self.unmatched_detections)?,
        })
    }
}

/// An exact retry returns its original receipt without replaying any track mutation.
#[derive(Debug, Eq, PartialEq)]
pub struct BatchUpdate {
    /// Original atomic transition, which may be older than the active set sequence.
    pub receipt: BatchReceipt,
    /// True only for an exact retained request retry.
    pub replayed: bool,
}

/// Exclusive owner of a fixed, already-seeded set of at most 32 source tracks.
///
/// There is no mutable per-track escape hatch. Membership/calibration changes need
/// an explicit new owner session. All fallible staging precedes one bounded commit
/// section; a cancellation arriving after its final poll does not interrupt it.
/// Process termination still loses this in-memory state: use source replay/custody.
pub struct ContactTrackSet {
    session: [u8; 32],
    geometry: GeometryBasis,
    twin: [u8; 32],
    tracks: Vec<ContactTrack>,
    sequence: u64,
    capacity: usize,
    receipts: VecDeque<BatchReceipt>,
    watermarks: Vec<Option<u64>>,
    invalidated: bool,
}
impl std::fmt::Debug for ContactTrackSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContactTrackSet")
            .field("tracks", &self.tracks.len())
            .field("sequence", &self.sequence)
            .field("invalidated", &self.invalidated)
            .finish_non_exhaustive()
    }
}
impl ContactTrackSet {
    /// Consume seeded active tracks with identical frozen camera registries and clock.
    /// Receipt capacity is 1..=256. Session uniqueness belongs to the canonical owner.
    pub fn new(
        twin: &PropertyTwin,
        session: [u8; 32],
        mut tracks: Vec<ContactTrack>,
        receipt_capacity: usize,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, BatchError> {
        budget.charge(0)?;
        if session == [0; 32]
            || tracks.is_empty()
            || tracks.len() > MAX_ASSOCIATION_ITEMS
            || !(1..=256).contains(&receipt_capacity)
        {
            return Err(BatchError::InvalidInput);
        }
        budget.charge(tracks.len() as u64 * 64)?;
        tracks.sort_by_key(|t| t.scope.track);
        let first = &tracks[0];
        for (i, track) in tracks.iter().enumerate() {
            track.snapshot(track.revision())?;
            if track.geometry != twin.basis()
                || track.twin_digest != twin.digest()
                || track.scope.clock != first.scope.clock
                || track.cameras != first.cameras
                || (i > 0 && tracks[i - 1].scope.track == track.scope.track)
            {
                return Err(BatchError::BasisMismatch);
            }
        }
        let mut watermarks = reserved(first.cameras.len())?;
        for camera in &first.cameras {
            let mut latest = None;
            for track in &tracks {
                budget.charge(1)?;
                let source = track.snapshot(track.revision())?.projection().observation();
                if source.camera == camera.camera {
                    latest =
                        Some(latest.map_or(source.capture[0], |t: u64| t.max(source.capture[0])));
                }
            }
            watermarks.push(latest);
        }
        let mut receipts = VecDeque::new();
        receipts
            .try_reserve_exact(receipt_capacity)
            .map_err(|_| BatchError::Limit)?;
        budget.charge(0)?;
        Ok(Self {
            session,
            geometry: twin.basis(),
            twin: twin.digest(),
            tracks,
            sequence: 0,
            capacity: receipt_capacity,
            receipts,
            watermarks,
            invalidated: false,
        })
    }
    /// Current accepted batch sequence; exact retries do not advance it.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Exact owner-issued set identity.
    pub fn session(&self) -> [u8; 32] {
        self.session
    }
    /// Read-only track access; no individual writer can race atomic publication.
    pub fn track(&self, id: u64) -> Option<&ContactTrack> {
        self.tracks
            .binary_search_by_key(&id, |t| t.scope.track)
            .ok()
            .map(|i| &self.tracks[i])
    }
    /// Active snapshots for the existing gate_contact_batch input; no state is copied.
    pub fn snapshots(
        &self,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Vec<TrackSnapshot<'_>>, BatchError> {
        budget.charge(0)?;
        if self.invalidated {
            return Err(BatchError::Invalidated);
        }
        let mut output = reserved(self.tracks.len())?;
        for track in &self.tracks {
            budget.charge(1)?;
            output.push(track.snapshot(track.revision())?);
        }
        Ok(output)
    }
    /// Last atomic acknowledgement remains readable for reconciliation after invalidation.
    pub fn last_receipt(&self) -> Option<&BatchReceipt> {
        self.receipts.back()
    }
    /// Latch invalidation on the entire set without requiring a compute allowance.
    pub fn invalidate(&mut self) {
        self.invalidated = true;
        for track in &mut self.tracks {
            track.invalidate();
        }
    }

    /// Apply an explicitly selected/adjudicated assignment to all chosen tracks or none.
    ///
    /// The complete graph source membership must equal this set, including unmatched
    /// tracks. Geometry compatibility is not identity authority. The caller retains
    /// the graph, alternative family and adjudication evidence in its existing ledger.
    pub fn apply_selection(
        &mut self,
        twin: &PropertyTwin,
        selection: &AssociationSelection<'_>,
        operation: BatchOperation,
        budget: &mut WorkBudget<'_>,
    ) -> Result<BatchUpdate, BatchError> {
        budget.charge(0)?;
        if self.invalidated {
            return Err(BatchError::Invalidated);
        }
        if twin.basis() != self.geometry
            || twin.digest() != self.twin
            || selection.graph().twin_digest() != self.twin
        {
            return Err(BatchError::BasisMismatch);
        }
        if operation.sequence == 0 || operation.adjudication == [0; 32] {
            return Err(BatchError::InvalidInput);
        }
        let request = binding::request(self.session, selection, operation, budget)?;
        if operation.sequence <= self.sequence {
            let old = self
                .receipts
                .iter()
                .find(|r| r.operation.sequence == operation.sequence)
                .ok_or(BatchError::ExpiredReplay)?;
            if old.request != request {
                return Err(BatchError::ConflictingReplay);
            }
            let receipt = old.try_copy()?;
            budget.charge(0)?;
            return Ok(BatchUpdate {
                receipt,
                replayed: true,
            });
        }
        if self.sequence.checked_add(1) != Some(operation.sequence) {
            return Err(BatchError::Sequence);
        }
        let frame = selection.graph().frame();
        let camera_index = self.tracks[0]
            .cameras
            .binary_search_by_key(&frame.camera.camera, |c| c.camera)
            .map_err(|_| BatchError::BasisMismatch)?;
        let camera = self.tracks[0].cameras[camera_index];
        if self.watermarks[camera_index].is_some_and(|t| frame.capture[0] <= t)
            || self.receipts.iter().any(|r| {
                r.frame_evidence == frame.evidence
                    || (r.camera == frame.camera.camera && r.exposure == frame.exposure)
            })
        {
            return Err(BatchError::ReusedExposure);
        }
        let snapshots = self.snapshots(budget)?;
        selection
            .graph()
            .check_current(twin, camera, &snapshots, budget)?;
        let mut before = reserved(snapshots.len())?;
        for snapshot in snapshots {
            before.push(snapshot.receipt());
        }
        let mut after = copied(&before)?;
        let observations = selection.observations(budget)?;
        let mut staged = reserved(observations.len())?;
        let mut updates = reserved(observations.len())?;
        for observation in observations {
            budget.charge(1)?;
            let index = self
                .tracks
                .binary_search_by_key(&observation.track, |t| t.scope.track)
                .map_err(|_| BatchError::BasisMismatch)?;
            let prepared = self.tracks[index].prepare_ingest(
                twin,
                observation,
                Some(operation.adjudication),
                budget,
            )?;
            if prepared.update.replayed {
                return Err(BatchError::ReusedExposure);
            }
            after[index] = prepared.update.receipt;
            updates.push(prepared.update);
            staged.push((index, prepared));
        }
        let assignment = selection.assignment();
        let receipt = BatchReceipt {
            session: self.session,
            operation,
            request,
            twin: self.twin,
            camera: camera.camera,
            exposure: frame.exposure,
            frame_evidence: frame.evidence,
            capture: frame.capture,
            one_to_one_basis: selection.policy().one_to_one_basis,
            links: copied(assignment.links())?,
            before,
            after,
            updates,
            unmatched_tracks: copied(assignment.unmatched_tracks())?,
            unmatched_detections: copied(assignment.unmatched_detections())?,
        };
        let remembered = receipt.try_copy()?;
        // Publication barrier: exclusive set ownership, checked indices, preallocated
        // receipt windows and no fallible operation/callback until every state is visible.
        budget.charge(0)?;
        for (index, prepared) in staged {
            self.tracks[index].apply_prepared(prepared);
        }
        self.watermarks[camera_index] = Some(frame.capture[0]);
        self.sequence = operation.sequence;
        if self.receipts.len() == self.capacity {
            self.receipts.pop_front();
        }
        self.receipts.push_back(remembered);
        Ok(BatchUpdate {
            receipt,
            replayed: false,
        })
    }
}

fn reserved<T>(count: usize) -> Result<Vec<T>, BatchError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| BatchError::Limit)?;
    Ok(result)
}
fn copied<T: Copy>(values: &[T]) -> Result<Vec<T>, BatchError> {
    let mut result = reserved(values.len())?;
    result.extend_from_slice(values);
    Ok(result)
}

mod binding;
