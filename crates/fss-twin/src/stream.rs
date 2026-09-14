#![forbid(unsafe_code)]
//! Incremental source-contact tracking over a frozen, owner-admitted property.
//!
//! No source is read here: the owner supplies authorized observations, camera
//! snapshots and a cancellation/work allowance. One instance tracks one anonymous
//! upstream identity. It does not associate people, activate calibration, or turn
//! missed detections into negative evidence.

use std::collections::VecDeque;
use fss_geometry::{GeometryBasis, GeometryError, WorkBudget};
use crate::{ContactObservation, ContactProjection, MotionFitOptions, ProjectionOptions,
    ProjectionQuality, PropertyTwin, TrackingCamera, TwinError, WorldMotion,
    fit_world_motion, project_contact};

/// Nonzero owner-resolved identities. Epoch changes when the owning session rebases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrackScope {
    /// Anonymous source track, not a personal identity.
    pub track: u64,
    /// Common capture-time basis, not the arrival clock.
    pub clock: u64,
    /// Owner-issued session generation; never reuse for changed admitted inputs.
    pub epoch: u64,
}

/// Bounded policy; dimensions are in source units and nanoseconds.
#[derive(Clone, Copy, Debug)]
pub struct TrackOptions {
    /// Contact projection bounds, applied to every observation.
    pub projection: ProjectionOptions,
    /// Maximum full capture-span of a motion pair, at most one hour.
    pub max_gap_ns: u64,
    /// Complete support-pair limit, 1..=256. This is not a top-k allowance.
    pub max_modes: usize,
    /// Recent idempotency receipts, 1..=4096. Older observations fail the watermark.
    pub receipt_capacity: usize,
}
impl Default for TrackOptions {
    fn default() -> Self {
        Self { projection: ProjectionOptions::default(), max_gap_ns: 30_000_000_000,
            max_modes: 64, receipt_capacity: 256 }
    }
}

/// What the accepted source observation permits, without inventing continuity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackDisposition {
    /// First usable support after startup or unsupported contact; no velocity yet.
    Seeded,
    /// A new source pair supports the retained motion hypotheses.
    MotionUpdated,
    /// Contact itself is hidden/unknown; the 2D observation is retained.
    ContactUnavailable,
    /// No support was found in the declared search volume; not physical absence.
    SupportUnavailable,
    /// Capture intervals overlap; no finite ordered velocity is inferred.
    TimeAmbiguous,
    /// The interval exceeds the configured continuity horizon; this is a new seed.
    Gap,
    /// A camera transition lacks owner-supplied association evidence.
    AssociationRequired,
}

/// Compact acknowledgement of one accepted observation. Not a durable fss/1 record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrackReceipt {
    /// Exact owner-resolved session identity.
    pub scope: TrackScope,
    /// Monotone accepted-update revision within that epoch.
    pub revision: u64,
    /// Original source evidence, not a generated forecast.
    pub evidence: [u8; 32],
    /// Meaning of the current tracking state.
    pub disposition: TrackDisposition,
    /// Conditional bounds, nominal geometry, or unknown contact.
    pub projection_quality: ProjectionQuality,
    /// Number of retained support hypotheses.
    pub supports: usize,
    /// Number of retained motion pairings; zero is not a stationary target.
    pub motion_modes: usize,
}

/// An exact retry returns its original receipt without replaying state changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrackUpdate {
    /// Original accepted acknowledgement, including its original revision.
    pub receipt: TrackReceipt,
    /// True for a cached exact retry; the current track may already be newer.
    pub replayed: bool,
}

/// Atomic update failures; the last accepted state is unchanged on error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackError {
    /// Invalid session policy or camera set.
    InvalidInput,
    /// Wrong twin, track, clock, camera or expected state revision.
    BasisMismatch,
    /// Same evidence/exposure was retried with different contents or association.
    ConflictingReplay,
    /// Not newer than the accepted lower-capture watermark and not a cached retry.
    LateObservation,
    /// Calibration/world/session was invalidated; a new owner epoch is required.
    Invalidated,
    /// No source observation has been accepted yet.
    Empty,
    /// Projection, motion, allocation, cancellation or deterministic work failure.
    Twin(TwinError),
}
impl From<TwinError> for TrackError {
    fn from(error: TwinError) -> Self { Self::Twin(error) }
}
impl From<GeometryError> for TrackError {
    fn from(error: GeometryError) -> Self { Self::Twin(error.into()) }
}
impl std::fmt::Display for TrackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid contact-track input",
            Self::BasisMismatch => "contact-track basis mismatch",
            Self::ConflictingReplay => "conflicting contact-track replay",
            Self::LateObservation => "contact observation precedes watermark",
            Self::Invalidated => "contact-track session invalidated",
            Self::Empty => "contact-track session has no observations",
            Self::Twin(_) => "contact-track computation failed",
        })
    }
}
impl std::error::Error for TrackError {}

struct Remembered {
    observation: ContactObservation,
    association: Option<[u8; 32]>,
    receipt: TrackReceipt,
}

/// Source-led incremental tracker; exclusive mutable access is its only local writer.
///
/// The bounded receipt window is not an evidence store. The owner retains source
/// custody and resolves persistent identities. Each accepted observation replaces
/// the current projection; hidden contact, temporal ambiguity and continuity gaps
/// clear usable motion rather than carrying an old velocity forward as observed.
pub struct ContactTrack {
    scope: TrackScope,
    geometry: GeometryBasis,
    twin_digest: [u8; 32],
    cameras: Vec<TrackingCamera>,
    options: TrackOptions,
    receipts: VecDeque<Remembered>,
    last: Option<ContactProjection>,
    motion: Option<WorldMotion>,
    receipt: Option<TrackReceipt>,
    invalidated: bool,
}
impl std::fmt::Debug for ContactTrack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContactTrack").field("revision", &self.revision())
            .field("invalidated", &self.invalidated).finish_non_exhaustive()
    }
}
impl ContactTrack {
    /// Freeze an already authorized camera set; changed calibration requires a new epoch.
    pub fn new(twin: &PropertyTwin, scope: TrackScope, cameras: &[TrackingCamera],
        options: TrackOptions, budget: &mut WorkBudget<'_>) -> Result<Self, TrackError> {
        budget.charge(0)?;
        let p = options.projection;
        if [scope.track, scope.clock, scope.epoch].contains(&0) || cameras.is_empty()
            || cameras.len() > 64 || options.max_gap_ns == 0
            || options.max_gap_ns > 3_600_000_000_000 || !(1..=256).contains(&options.max_modes)
            || !(1..=4096).contains(&options.receipt_capacity)
            || !(1..=128).contains(&p.max_hypotheses) || !p.near.is_finite()
            || !p.far.is_finite() || p.near <= 0.0 || p.far <= p.near || p.far > 1e9 {
            return Err(TrackError::InvalidInput);
        }
        for (i, camera) in cameras.iter().enumerate() {
            budget.charge(32 + i as u64)?;
            if camera.geometry != twin.basis() || camera.clock != scope.clock
                || [camera.camera, camera.calibration, camera.image_domain].contains(&0)
                || camera.validity[0] > camera.validity[1]
                || cameras[..i].iter().any(|other| other.camera == camera.camera) {
                return Err(TrackError::BasisMismatch);
            }
            if let Some(e) = camera.error {
                if e.centre.iter().chain(e.focal.iter()).chain(e.principal.iter())
                    .any(|v| !v.is_finite() || *v < 0.0 || *v > 1e12)
                    || !e.rotation_entry.is_finite() || !(0.0..=2.0).contains(&e.rotation_entry)
                    || (0..2).any(|a| e.focal[a] >= camera.intrinsics.focal_lengths()[a]) {
                    return Err(TrackError::InvalidInput);
                }
            }
        }
        let mut owned = Vec::new();
        owned.try_reserve_exact(cameras.len()).map_err(|_| TwinError::Limit)?;
        owned.extend_from_slice(cameras);
        owned.sort_by_key(|camera| camera.camera);
        let mut receipts = VecDeque::new();
        receipts.try_reserve_exact(options.receipt_capacity).map_err(|_| TwinError::Limit)?;
        budget.charge(0)?;
        Ok(Self { scope, geometry: twin.basis(), twin_digest: twin.digest(), cameras: owned,
            options, receipts, last: None, motion: None, receipt: None, invalidated: false })
    }
    /// Session generation; globally preventing epoch reuse belongs to the owner.
    pub fn scope(&self) -> TrackScope { self.scope }
    /// Zero before the first accepted input. Retries and failures do not increment it.
    pub fn revision(&self) -> u64 { self.receipt.map_or(0, |r| r.revision) }
    /// Last acknowledgement, available for reconciliation even after invalidation.
    pub fn last_receipt(&self) -> Option<TrackReceipt> { self.receipt }
    /// Stop all active reads and updates immediately; does not need spare work budget.
    /// Retained source references remain available to the owner for reconciliation.
    pub fn invalidate(&mut self) { self.invalidated = true; }

    /// Accept one source observation atomically. Failed computations never consume it.
    ///
    /// Inputs must arrive in increasing lower-capture-bound order. Exact cached
    /// retries can arrive later without rolling the track back. Evicted retries
    /// fail the watermark instead of being silently accepted a second time.
    pub fn ingest(&mut self, twin: &PropertyTwin, observation: ContactObservation,
        association: Option<[u8; 32]>, budget: &mut WorkBudget<'_>) -> Result<TrackUpdate, TrackError> {
        let prepared = self.prepare_ingest(twin, observation, association, budget)?;
        budget.charge(0)?;
        Ok(self.apply_prepared(prepared))
    }

    // Shared staging path: batch ownership prevents intervening writes. Preparation
    // performs every fallible operation without mutating the accepted track.
    fn prepare_ingest(&self, twin: &PropertyTwin, observation: ContactObservation,
        association: Option<[u8; 32]>, budget: &mut WorkBudget<'_>) -> Result<PreparedIngest, TrackError> {
        budget.charge(0)?;
        if self.invalidated { return Err(TrackError::Invalidated); }
        if twin.basis() != self.geometry || twin.digest() != self.twin_digest
            || observation.track != self.scope.track || observation.clock != self.scope.clock
            || association == Some([0; 32]) { return Err(TrackError::BasisMismatch); }
        for prior in &self.receipts {
            budget.charge(1)?;
            if prior.observation.evidence == observation.evidence
                || (prior.observation.camera == observation.camera
                    && prior.observation.exposure == observation.exposure) {
                if prior.observation != observation || prior.association != association {
                    return Err(TrackError::ConflictingReplay);
                }
                budget.charge(0)?;
                return Ok(PreparedIngest { update: TrackUpdate { receipt: prior.receipt, replayed: true },
                    replacement: None });
            }
        }
        if self.last.as_ref().is_some_and(|p| observation.capture[0] <= p.observation().capture[0]) {
            return Err(TrackError::LateObservation);
        }
        let camera = self.cameras.binary_search_by_key(&observation.camera, |c| c.camera)
            .map(|i| self.cameras[i]).map_err(|_| TrackError::BasisMismatch)?;
        let revision = self.revision().checked_add(1).ok_or(TwinError::Limit)?;
        let projected = project_contact(twin, camera, observation, self.options.projection, budget)?;
        let mut motion = None;
        let disposition = if projected.quality() == ProjectionQuality::ContactUnknown {
            TrackDisposition::ContactUnavailable
        } else if projected.hypotheses().is_empty() {
            TrackDisposition::SupportUnavailable
        } else if let Some(previous) = self.last.as_ref().filter(|p| !p.hypotheses().is_empty()) {
            let before = previous.observation();
            if observation.capture[0] <= before.capture[1] {
                TrackDisposition::TimeAmbiguous
            } else if observation.capture[1] - before.capture[0] > self.options.max_gap_ns {
                TrackDisposition::Gap
            } else if before.camera != observation.camera && association.is_none() {
                TrackDisposition::AssociationRequired
            } else {
                motion = Some(fit_world_motion(previous, &projected, MotionFitOptions {
                    max_gap_ns: self.options.max_gap_ns, max_modes: self.options.max_modes,
                    association }, budget)?);
                TrackDisposition::MotionUpdated
            }
        } else { TrackDisposition::Seeded };
        let receipt = TrackReceipt { scope: self.scope, revision, evidence: observation.evidence,
            disposition, projection_quality: projected.quality(), supports: projected.hypotheses().len(),
            motion_modes: motion.as_ref().map_or(0, |m| m.modes().len()) };
        budget.charge(0)?;
        Ok(PreparedIngest { update: TrackUpdate { receipt, replayed: false },
            replacement: Some(PreparedState { projected, motion,
                remembered: Remembered { observation, association, receipt } }) })
    }

    // Infallible publication only. Receipt capacity was reserved at construction;
    // no user callback, cancellation poll, allocation or I/O occurs here.
    fn apply_prepared(&mut self, prepared: PreparedIngest) -> TrackUpdate {
        if let Some(state) = prepared.replacement {
            if self.receipts.len() == self.options.receipt_capacity { self.receipts.pop_front(); }
            self.receipt = Some(state.remembered.receipt);
            self.receipts.push_back(state.remembered);
            self.last = Some(state.projected);
            self.motion = state.motion;
        }
        prepared.update
    }

    /// Borrow an exact active revision. A later mutation cannot coexist with this borrow.
    pub fn snapshot(&self, expected_revision: u64) -> Result<TrackSnapshot<'_>, TrackError> {
        if self.invalidated { return Err(TrackError::Invalidated); }
        let receipt = self.receipt.ok_or(TrackError::Empty)?;
        if expected_revision != receipt.revision { return Err(TrackError::BasisMismatch); }
        Ok(TrackSnapshot { receipt, projection: self.last.as_ref().ok_or(TrackError::Empty)?,
            motion: self.motion.as_ref(), cameras: &self.cameras })
    }
}

/// Active immutable view produced only by a revision-checked session read.
#[derive(Clone, Copy)]
pub struct TrackSnapshot<'a> {
    receipt: TrackReceipt,
    projection: &'a ContactProjection,
    motion: Option<&'a WorldMotion>,
    cameras: &'a [TrackingCamera],
}
impl<'a> TrackSnapshot<'a> {
    /// Exact source update and epoch to which derived outputs must bind.
    pub fn receipt(self) -> TrackReceipt { self.receipt }
    /// Latest source projection, including explicit unavailable-contact states.
    pub fn projection(self) -> &'a ContactProjection { self.projection }
    /// Source-pair motion only when the latest update established it.
    pub fn motion(self) -> Option<&'a WorldMotion> { self.motion }
    /// Frozen admitted camera set; no mutable calibration is read during prediction.
    pub fn cameras(self) -> &'a [TrackingCamera] { self.cameras }
}

struct PreparedState {
    projected: ContactProjection,
    motion: Option<WorldMotion>,
    remembered: Remembered,
}
struct PreparedIngest {
    update: TrackUpdate,
    replacement: Option<PreparedState>,
}

/// Atomic, explicitly adjudicated association updates across a frozen track set.
pub mod batch;
