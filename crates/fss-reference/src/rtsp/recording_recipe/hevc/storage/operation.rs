#![forbid(unsafe_code)]
//! Codec-pinned HEVC operator reconstruction: verify the complete program before publishing any output.
//!
//! All original source remains in the existing publisher. A result root is a derived receipt
//! for this exact reconstruction, never a camera EOF, canonical lineage or archive-index entry.

use super::super::{
    PlannedRecordingReplay, RecipeReplayFailure, RecipeReplayRetirement, RecipeReplayStep,
    RecordingRecipe, RecordingRecipeError, RecordingRecipeLimits,
};
use super::{RecipeStorageLimits, RecordingRecipePin, load_recording_recipe};
use crate::rtsp::datagram_archive::prefix::DatagramPrefix;
use crate::rtsp::datagram_archive::{
    DatagramArchive, DatagramArchiveError, DatagramArchiveLimits, DatagramPin, DatagramScope,
};
use crate::rtsp::datagram_reconstruction::hevc::recording::{
    HevcRecordingReplayRetirement as RecordingReplayRetirement,
    HevcRecordingReplayStep as RecordingReplayStep, HevcReplayBoundary,
};
use crate::rtsp::datagram_reconstruction::hevc::{HevcReplayBounds, HevcReplayStep};
use crate::rtsp::hevc_recording_capture::HevcCapturePoll as CapturePoll;
use crate::rtsp::hevc_recording_collector::HevcCollectionAdmission;
use crate::rtsp::recording::hevc::PreparedHevcRecording;
use crate::rtsp::recording::local::RecordingIoError;
use fss_core::{
    CanonicalDecoder, CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm,
};
use fss_object::ObjectManifest;
use fss_publication::{
    LocalPublicationReceipt, LocalPublicationState, LocalRootPublisher, PublishCancellation,
    SlotName,
};

// Exact first-party types, not alternate identities or an independent work-budget protocol.
pub use fss_geometry::WorkBudget;
pub use fss_packet::StreamKey;
mod publication;
pub use publication::{ReconstructionPublication, ReconstructionPublishFailure};

/// Immutable derived result family. Publication certifies neither continuous capture nor indexing.
pub const RECONSTRUCTION_RESULT_KIND: &str = "rtsp_hevc_recording_reconstruction_v1";

/// Independently accepted recipe identity and original source interpretation, not a read grant.
#[derive(Clone, Debug)]
pub struct RecipeSelection {
    /// Exact canonical recipe bytes, not a latest-revision lookup.
    pub recipe: ContentDigest,
    /// Exact source-closed recipe manifest.
    pub root: ContentDigest,
    /// Original connection, channel, clock and retention interpretation. No connection is opened.
    pub scope: DatagramScope,
}
/// Current whole-input/allocation ceilings. None is adopted from a stored program.
#[derive(Clone, Copy, Debug)]
pub struct RecipeLoadLimits {
    /// Whole current datagram inventory, including descendants outside the selected recipe.
    pub source: DatagramArchiveLimits,
    /// Complete recipe and componentwise configuration ceilings.
    pub recipe: RecordingRecipeLimits,
    /// Source-closure and current spool allocation bounds.
    pub storage: RecipeStorageLimits,
}

/// Fully verified source inventory and owned instructions, independent of the old process.
#[derive(Debug)]
pub struct LoadedRecordingRecipe {
    archive: DatagramPrefix,
    recipe: RecordingRecipe,
    pin: RecordingRecipePin,
    limits: RecipeLoadLimits,
}
impl LoadedRecordingRecipe {
    /// Read the exact pinned recipe header only to select a candidate source prefix, then use
    /// the ordinary complete source and recipe verifiers. The header never becomes authority.
    /// Valid descendants are verified but excluded from this recipe through a read-only prefix.
    /// Neither the selected source nor the live append history is changed.
    pub fn load(
        p: &LocalRootPublisher,
        selected: RecipeSelection,
        limits: RecipeLoadLimits,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, RecordingRecipeError> {
        limits.recipe.validate()?;
        let declaration = DatagramArchive::new(selected.scope.clone(), limits.source)?;
        limits.storage.check(p, &declaration)?;
        if [selected.recipe, selected.root]
            .iter()
            .any(|d| d.algorithm() != DigestAlgorithm::Sha256)
        {
            return Err(RecordingRecipeError::Mismatch);
        }
        let slot = super::slot(selected.recipe)?;
        if p.is_broken_slot(&slot)
            || p.root(&slot).is_none_or(|r| {
                r.root != selected.root || r.state != LocalPublicationState::Durable
            })
        {
            return Err(DatagramArchiveError::NotDurable.into());
        }
        let raw = super::object(
            p,
            selected.root,
            limits.storage.max_spool_object_bytes,
            cancel,
            budget,
        )?;
        let manifest = ObjectManifest::from_canonical_bytes(&raw)
            .map_err(|_| RecordingRecipeError::Mismatch)?;
        if manifest.root() != selected.root
            || manifest.kind() != super::RECORDING_RECIPE_KIND
            || manifest.metadata_digest() != Some(selected.recipe)
        {
            return Err(RecordingRecipeError::Mismatch);
        }
        let bytes = super::object(p, selected.recipe, limits.recipe.max_bytes, cancel, budget)?;
        // This is only a bounded bootstrap prefix of the existing format. The full decoder below
        // must still consume every byte, validate all fields, and reconstruct the exact child set.
        let mut d = CanonicalDecoder::new(&bytes);
        if d.text()? != super::super::DOMAIN || d.text()? != super::super::POLICY {
            return Err(RecordingRecipeError::Mismatch);
        }
        let source = DatagramPin {
            scope: d.digest()?,
            head: d.digest()?,
            datagrams: d.u64()?,
            payload_bytes: d.u64()?,
        };
        if source.scope != declaration.pin().scope
            || source.datagrams > limits.source.max_datagrams as u64
            || source.datagrams > limits.storage.max_source_roots as u64
            || source.payload_bytes > limits.source.max_payload_bytes
            || manifest.children().len() != source.datagrams as usize + 1
        {
            return Err(RecordingRecipeError::Mismatch);
        }
        drop(bytes);
        drop(raw);
        let archive =
            DatagramPrefix::recover(p, selected.scope, limits.source, source, cancel, budget)?;
        let pin = RecordingRecipePin {
            slot,
            root: selected.root,
            recipe: selected.recipe,
            source,
        };
        let recipe = load_recording_recipe(
            p,
            &pin,
            archive.archive(),
            limits.recipe,
            limits.storage,
            cancel,
            budget,
        )?;
        Ok(Self {
            archive,
            recipe,
            pin,
            limits,
        })
    }
    /// Independently selected identities, including the now fully verified source prefix.
    pub fn pin(&self) -> &RecordingRecipePin {
        &self.pin
    }
    /// The owned program; mutable timing overrides are not exposed.
    pub fn recipe(&self) -> &RecordingRecipe {
        &self.recipe
    }
    /// Full source head verified when this input was loaded, distinct from the selected prefix.
    /// This is historical observation metadata, not a latest-head query or recipe input.
    pub fn observed_source_head(&self) -> DatagramPin {
        self.archive.observed_head()
    }
    fn verify(
        &self,
        p: &LocalRootPublisher,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> Result<(), RecordingRecipeError> {
        // Keep the whole observed chain pinned within this attempt. In particular, a later
        // corrupt or rolled-back append is not hidden by the valid older recipe prefix.
        self.archive.revalidate(p, cancel, budget)?;
        let verified = load_recording_recipe(
            p,
            &self.pin,
            self.archive.archive(),
            self.limits.recipe,
            self.limits.storage,
            cancel,
            budget,
        )?;
        if verified.canonical_bytes() != self.recipe.canonical_bytes() {
            return Err(RecordingRecipeError::Mismatch);
        }
        Ok(())
    }
}

/// Current clock capability, not stored receive time or media DTS. None denotes unavailable time.
/// The cancellation capability separately enforces live authority/deadlines inside storage calls.
pub trait ReconstructionClock {
    /// Monotonic nanoseconds in the same current-operation epoch as HevcReplayBounds::deadline_ns.
    fn now_ns(&self) -> Option<u64>;
}
/// Complete-output bounds, checked in addition to native per-window construction bounds.
#[derive(Clone, Copy, Debug)]
pub struct ReconstructionLimits {
    /// Maximum completed windows held before publishing, in 1..=1024.
    pub max_windows: usize,
    /// Sum of held canonical recording bytes, in 1..=1 GiB.
    /// Native construction of the next window still uses the recipe's separately bounded workspace.
    pub max_output_bytes: u64,
    /// Complete publisher inventory/recovery scan, in 1..=262144; no silent partial inventory.
    pub max_scan_roots: usize,
}
impl Default for ReconstructionLimits {
    fn default() -> Self {
        Self {
            max_windows: 64,
            max_output_bytes: 64 * 1024 * 1024,
            max_scan_roots: 65_536,
        }
    }
}
impl ReconstructionLimits {
    fn validate(self, bounds: HevcReplayBounds) -> Result<(), ReconstructionError> {
        if !(1..=1024).contains(&self.max_windows)
            || !(1..=1_073_741_824).contains(&self.max_output_bytes)
            || !(1..=262_144).contains(&self.max_scan_roots)
            || !(1..=1_000_000).contains(&bounds.max_steps)
        {
            return Err(ReconstructionError::Limit);
        }
        Ok(())
    }
}

/// Payload/path-free operator error with original typed failures retained for API callers.
pub enum ReconstructionError {
    /// Source/recipe verification failed before or after computation.
    Recipe(Box<RecordingRecipeError>),
    /// Original native replay failure, including all its withheld ownership.
    Replay(Box<RecipeReplayFailure>),
    /// Original recording-publication error, including uncertain storage outcomes.
    Recording(Box<RecordingIoError>),
    /// Independent whole-output or step/scan capacity exhausted.
    Limit,
    /// The independently supplied current clock regressed.
    ClockReversed,
    /// Current time unavailable or the absolute deadline reached.
    Deadline,
    /// Native stop, missing terminal result, or inconsistent terminal accounting.
    Incomplete,
    /// A conflicting, malformed, broken or unaccounted output publication already exists.
    Conflict,
}
impl std::fmt::Debug for ReconstructionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Recipe(_) => "Recipe",
            Self::Replay(_) => "Replay",
            Self::Recording(_) => "Recording",
            Self::Limit => "Limit",
            Self::ClockReversed => "ClockReversed",
            Self::Deadline => "Deadline",
            Self::Incomplete => "Incomplete",
            Self::Conflict => "Conflict",
        })
    }
}
impl std::fmt::Display for ReconstructionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "reconstruction refused: {self:?}")
    }
}
impl std::error::Error for ReconstructionError {}
impl From<RecordingRecipeError> for ReconstructionError {
    fn from(e: RecordingRecipeError) -> Self {
        Self::Recipe(Box::new(e))
    }
}
impl From<RecordingIoError> for ReconstructionError {
    fn from(e: RecordingIoError) -> Self {
        Self::Recording(Box::new(e))
    }
}

/// Orthogonal observations; these counts are not a coverage or successful-decoding claim.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReconstructionSummary {
    /// Original RTP observations, including probation and retransmissions.
    pub rtp_observations: u64,
    /// Original RTCP observations.
    pub rtcp_observations: u64,
    /// RTCP observations that failed native syntax validation, not invented video gaps.
    pub invalid_rtcp: u64,
    /// Applied exact timing decisions, including unselected startup pictures.
    pub timings_applied: u64,
    /// Fully reconstructed windows, not necessarily published yet.
    pub windows: u64,
    /// Sum of canonical recording bytes, not physical incremental disk consumption.
    pub output_bytes: u64,
    /// Completed startup pictures not selected by the native IDR policy.
    pub unselected_pictures: u64,
    /// Packets released from active collection, including copies already represented in windows.
    /// This is not an omission count or an additional source-custody receipt.
    pub released_packets: u64,
    /// Source packets left in the collector after final prefix sealing.
    pub unsealed_packets: u64,
    /// Ordered-delivery packets still queued at prefix exhaustion.
    pub queued_packets: u64,
    /// Incomplete reconstructed NAL bytes, distinct from original-payload byte counts.
    pub fragment_bytes: u64,
    /// Completed NALs still awaiting assembly at prefix exhaustion.
    pub queued_nals: u64,
    /// A pending group was retired without a complete boundary; not a decoded-picture claim.
    pub incomplete_picture: bool,
    /// Number of original observations actually consumed; a real EOB may stop before the pin.
    pub observations_read: u64,
    /// Selected source observations after real EOB, retained in the independent source archive.
    pub remaining_datagrams: u64,
    /// Actual in-band EOB versus exhaustion of the selected source prefix. Neither means TCP EOF.
    pub end_of_bitstream: bool,
}

/// Every completed output survives a failed preparation. Source copies consumed during successful
/// steps remain recoverable through the exact original source pin; no stored bytes are deleted.
#[must_use]
pub struct ReconstructionFailure {
    /// Typed failure; nested errors retain their original detailed ownership.
    pub reason: ReconstructionError,
    /// Already reconstructed but never published windows.
    pub windows: Vec<PreparedHevcRecording>,
    /// Pending native ownership on a preparation failure.
    pub replay: Option<RecipeReplayRetirement>,
    /// Result withheld because a later bound/clock/cancellation check refused it.
    pub withheld: Option<Box<RecipeReplayStep>>,
    /// Terminal incomplete remainder, when native replay finished before the later failure.
    pub retained: Option<Box<RecordingReplayRetirement>>,
}
impl std::fmt::Debug for ReconstructionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReconstructionFailure")
            .field("reason", &self.reason)
            .field("windows", &self.windows.len())
            .field("withheld", &self.withheld.is_some())
            .field("retained", &self.retained.is_some())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for ReconstructionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.reason, f)
    }
}
impl std::error::Error for ReconstructionFailure {}

/// Predetermined complete-result route. It is not durable until the final publication succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconstructionPin {
    /// Deterministic result slot for the exact source-closed recipe.
    pub slot: SlotName,
    /// Complete graph of recipe, ordered outputs and summary metadata.
    pub root: ContentDigest,
}
/// Complete native execution, with bounded windows retained until explicit publication.
#[must_use]
pub struct PreparedReconstruction<'a> {
    loaded: &'a LoadedRecordingRecipe,
    windows: Vec<PreparedHevcRecording>,
    summary: ReconstructionSummary,
    retained: Box<RecordingReplayRetirement>,
    metadata: Vec<u8>,
    manifest: ObjectManifest,
    pin: ReconstructionPin,
    limits: ReconstructionLimits,
}
impl std::fmt::Debug for PreparedReconstruction<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedReconstruction")
            .field("pin", &self.pin)
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}
impl<'a> PreparedReconstruction<'a> {
    /// Run the whole fixed recipe policy without writing an output object or root. No partial
    /// program is publishable through this type. A native window is returned intact on refusal.
    pub fn prepare(
        loaded: &'a LoadedRecordingRecipe,
        p: &LocalRootPublisher,
        bounds: HevcReplayBounds,
        limits: ReconstructionLimits,
        clock: &dyn ReconstructionClock,
        cancel: &dyn PublishCancellation,
        budget: &mut WorkBudget<'_>,
    ) -> Result<Self, ReconstructionFailure> {
        let mut windows = Vec::new();
        let mut retained = None;
        let mut withheld = None;
        let mut replay = None;
        let mut last = 0;
        let result = (|| -> Result<_, ReconstructionError> {
            limits.validate(bounds)?;
            let now = tick(clock, &mut last, bounds.deadline_ns)?;
            loaded.verify(p, cancel, budget)?;
            replay = Some(PlannedRecordingReplay::new(
                &loaded.recipe,
                loaded.archive.archive(),
                loaded.limits.recipe,
                bounds,
                now,
            )?);
            let r = replay.as_mut().ok_or(ReconstructionError::Incomplete)?;
            let mut summary = ReconstructionSummary::default();
            for _ in 0..bounds.max_steps {
                let now = tick(clock, &mut last, bounds.deadline_ns)?;
                let step = r
                    .step(p, now, cancel, budget)
                    .map_err(|e| ReconstructionError::Replay(Box::new(e)))?;
                // Hold the produced value across post-computation deadline/cancellation refusal.
                withheld = Some(Box::new(step));
                tick(clock, &mut last, bounds.deadline_ns)?;
                super::probe(cancel, budget)?;
                let step = *withheld.take().ok_or(ReconstructionError::Incomplete)?;
                match step {
                    RecipeReplayStep::Replay(RecordingReplayStep::Capture(event)) => {
                        if let CapturePoll::Window(window) = *event {
                            let total = summary.output_bytes.checked_add(window.byte_len() as u64);
                            if windows.len() >= limits.max_windows
                                || total.is_none_or(|n| n > limits.max_output_bytes)
                                || windows.try_reserve(1).is_err()
                            {
                                withheld = Some(Box::new(RecipeReplayStep::Replay(
                                    RecordingReplayStep::Capture(Box::new(CapturePoll::Window(
                                        window,
                                    ))),
                                )));
                                return Err(ReconstructionError::Limit);
                            }
                            summary.output_bytes = total.ok_or(ReconstructionError::Limit)?;
                            windows.push(*window);
                            summary.windows += 1;
                        }
                    }
                    RecipeReplayStep::TimingApplied { outcome, .. } => {
                        summary.timings_applied += 1;
                        match outcome.admission {
                            HevcCollectionAdmission::Accepted { released, .. } => {
                                summary.released_packets += released.len() as u64;
                            }
                            HevcCollectionAdmission::AwaitingIdr { released } => {
                                summary.unselected_pictures += 1;
                                summary.released_packets += released.len() as u64;
                            }
                        }
                    }
                    RecipeReplayStep::PrefixFinalizing { seal } => {
                        summary.released_packets += seal.released.len() as u64;
                    }
                    RecipeReplayStep::Replay(RecordingReplayStep::Source(source)) => {
                        match *source {
                            HevcReplayStep::Rtp { .. } => summary.rtp_observations += 1,
                            HevcReplayStep::Rtcp { validation, .. } => {
                                summary.rtcp_observations += 1;
                                summary.invalid_rtcp += u64::from(validation.is_err());
                            }
                            _ => {}
                        }
                    }
                    RecipeReplayStep::Replay(RecordingReplayStep::FinishedPrefix {
                        retained: tail,
                    }) => {
                        retained = Some(tail);
                        break;
                    }
                    step @ (RecipeReplayStep::Ended
                    | RecipeReplayStep::Replay(RecordingReplayStep::Stopped { .. })) => {
                        withheld = Some(Box::new(step));
                        return Err(ReconstructionError::Incomplete);
                    }
                    _ => {}
                }
            }
            let tail = retained.as_ref().ok_or(ReconstructionError::Incomplete)?;
            summary.observations_read = r.observations_read();
            if r.timings_applied() != loaded.recipe.timings().len()
                || tail.source != loaded.pin.source
                || tail.interpretation != loaded.recipe.interpretation()
                || tail.observations_read != summary.observations_read
                || summary.observations_read > loaded.pin.source.datagrams
                || summary.rtp_observations + summary.rtcp_observations != summary.observations_read
                || tail.unoffered.is_some()
                || tail.withheld.is_some()
                || tail.withheld_timing.is_some()
                || tail.withheld_seal.is_some()
            {
                return Err(ReconstructionError::Incomplete);
            }
            summary.remaining_datagrams = loaded.pin.source.datagrams - summary.observations_read;
            let receiver = match tail.boundary {
                Some(HevcReplayBoundary::RetainedPrefix) => {
                    if summary.remaining_datagrams != 0 {
                        return Err(ReconstructionError::Incomplete);
                    }
                    let Some(HevcReplayStep::PrefixExhausted {
                        source, retired, ..
                    }) = tail.held_source.as_deref()
                    else {
                        return Err(ReconstructionError::Incomplete);
                    };
                    if *source != loaded.pin.source {
                        return Err(ReconstructionError::Incomplete);
                    }
                    retired
                }
                Some(HevcReplayBoundary::EndOfBitstream) => {
                    // A genuine EOB is NOT source-prefix exhaustion. Preserve unread observations
                    // and queued post-EOB NALs, without reinterpreting them as consumed frames.
                    summary.end_of_bitstream = true;
                    if tail.held_source.is_some() {
                        return Err(ReconstructionError::Incomplete);
                    }
                    tail.replay
                        .as_ref()
                        .and_then(|r| r.receiver.as_ref())
                        .ok_or(ReconstructionError::Incomplete)?
                }
                None => return Err(ReconstructionError::Incomplete),
            };
            if tail.replay.as_ref().is_some_and(|r| r.withheld.is_some()) {
                return Err(ReconstructionError::Incomplete);
            }
            summary.queued_packets = receiver.queue.packets as u64;
            summary.fragment_bytes = receiver.fragment.as_ref().map_or(0, |f| f.byte_len as u64);
            summary.queued_nals = tail.queued_nals.len() as u64;
            summary.incomplete_picture = tail.assembly.is_some();
            if let Some(capture) = &tail.capture {
                summary.unsealed_packets = capture.collection.sources.len() as u64;
                if capture.collection.ready.is_some()
                    || !capture.collection.pictures.is_empty()
                    || capture.event.is_some()
                {
                    return Err(ReconstructionError::Incomplete);
                }
            }
            let metadata = encode_summary(loaded, summary, &windows)?;
            let mut children = std::collections::BTreeSet::new();
            children.insert(loaded.pin.root);
            children.extend(windows.iter().map(|w| w.manifest().root()));
            let manifest = ObjectManifest::new(
                RECONSTRUCTION_RESULT_KIND,
                children,
                Some(ContentDigest::sha256(&metadata)),
            )
            .map_err(|_| ReconstructionError::Limit)?;
            if manifest.children().len() > p.limits().max_children
                || metadata.len() > p.limits().spool.max_object_bytes
                || manifest.canonical_bytes().len() > p.limits().spool.max_object_bytes
            {
                return Err(ReconstructionError::Limit);
            }
            let pin = ReconstructionPin {
                slot: route(loaded.pin.root, None)?,
                root: manifest.root(),
            };
            tick(clock, &mut last, bounds.deadline_ns)?;
            super::probe(cancel, budget)?;
            Ok((summary, metadata, manifest, pin))
        })();
        match result {
            Ok((summary, metadata, manifest, pin)) => match retained {
                Some(retained) => Ok(Self {
                    loaded,
                    windows,
                    summary,
                    retained,
                    metadata,
                    manifest,
                    pin,
                    limits,
                }),
                None => Err(ReconstructionFailure {
                    reason: ReconstructionError::Incomplete,
                    windows,
                    replay: replay.as_mut().and_then(PlannedRecordingReplay::cancel),
                    withheld,
                    retained: None,
                }),
            },
            Err(reason) => Err(ReconstructionFailure {
                reason,
                windows,
                replay: replay.as_mut().and_then(PlannedRecordingReplay::cancel),
                withheld,
                retained,
            }),
        }
    }
    /// Complete native outcome, not yet a publication receipt.
    pub fn summary(&self) -> ReconstructionSummary {
        self.summary
    }
    /// Exact source-closed input pin.
    pub fn recipe_pin(&self) -> &RecordingRecipePin {
        &self.loaded.pin
    }
    /// Predetermined completion identity to retain before attempting writes.
    pub fn pin(&self) -> &ReconstructionPin {
        &self.pin
    }
    /// All complete native recordings; no mutable override is exposed.
    pub fn windows(&self) -> &[PreparedHevcRecording] {
        &self.windows
    }
    /// Original incomplete tail and receiver accounting, even when zero windows were produced.
    pub fn retained(&self) -> &RecordingReplayRetirement {
        &self.retained
    }
    /// Deterministic original ordinal. Existing different roots are never overwritten.
    pub fn window_slot(&self, index: usize) -> Result<SlotName, ReconstructionError> {
        if index >= self.windows.len() {
            return Err(ReconstructionError::Limit);
        }
        route(self.loaded.pin.root, Some(index))
    }
}

fn tick(
    clock: &dyn ReconstructionClock,
    last: &mut u64,
    deadline: u64,
) -> Result<u64, ReconstructionError> {
    let now = clock.now_ns().ok_or(ReconstructionError::Deadline)?;
    if now < *last {
        return Err(ReconstructionError::ClockReversed);
    }
    if now >= deadline {
        return Err(ReconstructionError::Deadline);
    }
    *last = now;
    Ok(now)
}
fn route(
    recipe_root: ContentDigest,
    index: Option<usize>,
) -> Result<SlotName, ReconstructionError> {
    let text = recipe_root.to_text();
    let hex = text
        .strip_prefix("sha256:")
        .ok_or(ReconstructionError::Conflict)?;
    let suffix = index.map_or_else(|| "complete".to_owned(), |i| format!("w{i:08x}"));
    SlotName::parse(&format!("fsshrx1-{hex}-{suffix}")).map_err(|_| ReconstructionError::Conflict)
}
fn encode_summary(
    loaded: &LoadedRecordingRecipe,
    s: ReconstructionSummary,
    windows: &[PreparedHevcRecording],
) -> Result<Vec<u8>, ReconstructionError> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.hevc_recording_reconstruction_result.v1");
    e.digest(loaded.pin.root);
    e.digest(loaded.pin.recipe);
    e.digest(loaded.recipe.interpretation());
    e.digest(loaded.pin.source.scope);
    e.digest(loaded.pin.source.head);
    e.u64(loaded.pin.source.datagrams);
    e.u64(loaded.pin.source.payload_bytes);
    for n in [
        s.rtp_observations,
        s.rtcp_observations,
        s.invalid_rtcp,
        s.timings_applied,
        s.windows,
        s.output_bytes,
        s.unselected_pictures,
        s.released_packets,
        s.unsealed_packets,
        s.queued_packets,
        s.fragment_bytes,
        s.queued_nals,
        s.observations_read,
        s.remaining_datagrams,
    ] {
        e.u64(n);
    }
    e.bool(s.incomplete_picture);
    e.bool(s.end_of_bitstream);
    e.bool(false); // No capture-complete assertion, including empty input.
    for window in windows {
        e.digest(window.manifest().root());
        e.u64(window.byte_len() as u64);
    }
    e.finish_checked().map_err(|_| ReconstructionError::Limit)
}
