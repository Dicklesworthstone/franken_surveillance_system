#![forbid(unsafe_code)]
//! Explicitly authorized, ledgered publication of prepared FLV source evidence.
//! Known capture bounds must be independently established, not inferred from
//! network arrival or the camera's media clock. A separate unknown-time path
//! retains that uncertainty and makes no physical-time or coverage claim.
//! No implicit policy grants exist here.

use std::fmt;

use fss_core::{
    CanonicalDecoder, CanonicalEncode, CaptureInterval, ContentDigest, DigestAlgorithm, TimestampNs,
};
use fss_geometry::{GeometryError, WorkBudget};
use fss_object::ObjectManifest;
use fss_packet::extended_flv::stream::SearchMode;
use fss_publication::{
    PublishCancellation, PublishCutPoint, RootLedgerReceipt, RootLedgerState, SlotName,
};

use super::{
    av_evidence::{self, AudioConfigurationOrigin, PreparedAv, PreparedAvVideoOnly},
    av_recording,
    evidence::{DOMAIN, KIND, Prepared},
    source_evidence,
};
use crate::{ReferenceDeployment, ReplayCx, reference_deployment::ReplayCancellationBridge};

/// Dedicated metadata-only publication intent history.
pub mod journal;

/// Revalidated authority to retain original camera bytes under the exact scope.
pub trait RetainAuthority {
    /// This digest identifies a decision; the implementation must check current
    /// principal, policy, retention and capability rather than trusting the digest.
    fn permits(&self, retention: ContentDigest, root: ContentDigest) -> bool;
}

/// Current permission to disclose original camera bytes for one retained graph.
pub trait ReadAuthority {
    /// Implementations must revalidate the current principal, privacy and policy.
    fn permits(&self, retention: ContentDigest, root: ContentDigest) -> bool;
}

/// Immutable caller-retained identities needed to reopen one ledgered graph.
/// This pin is not a receipt and does not grant access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pin {
    /// Canonical manifest root.
    pub root: ContentDigest,
    /// Retention decision identity encoded into graph metadata.
    pub retention: ContentDigest,
    /// Caller-established physical capture interval encoded into graph metadata.
    pub capture: CaptureInterval,
}
impl Pin {
    /// Obtain a candidate pin only if physical capture bounds were supplied.
    pub fn from_plan(plan: &Prepared<'_>) -> Option<Self> {
        Some(Self {
            root: plan.manifest().root(),
            retention: plan.retention(),
            capture: plan.capture()?,
        })
    }
    /// Obtain an A/V graph pin only when physical capture bounds were supplied.
    pub fn from_av_plan(plan: &PreparedAv<'_>) -> Option<Self> {
        Some(Self {
            root: plan.manifest().root(),
            retention: plan.retention(),
            capture: plan.capture()?,
        })
    }

    fn slot(self) -> Result<SlotName, Error> {
        for digest in [self.root, self.retention] {
            if digest.algorithm() != DigestAlgorithm::Sha256
                || digest.is_laboratory()
                || digest.bytes() == [0; 32]
            {
                return Err(Error::Mismatch);
            }
        }
        if self.capture.earliest > self.capture.latest {
            return Err(Error::Mismatch);
        }
        slot_for_root(self.root)
    }
}

/// Identity of a graph whose physical capture time is explicitly unknown.
/// This is not a receipt or a grant, and cannot be converted to a known-time pin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownTimePin {
    /// Canonical manifest root.
    pub root: ContentDigest,
    /// Identity of the separately authorized retention decision.
    pub retention: ContentDigest,
}
impl UnknownTimePin {
    /// Obtain an unknown-time candidate only from a graph with no capture bounds.
    pub fn from_plan(plan: &Prepared<'_>) -> Option<Self> {
        plan.capture().is_none().then(|| Self {
            root: plan.manifest().root(),
            retention: plan.retention(),
        })
    }

    /// Obtain an unknown-time candidate from an A/V graph with no capture bounds.
    pub fn from_av_plan(plan: &PreparedAv<'_>) -> Option<Self> {
        plan.capture().is_none().then(|| Self {
            root: plan.manifest().root(),
            retention: plan.retention(),
        })
    }

    /// Obtain a video-only A/V candidate with explicitly unknown capture time.
    pub fn from_av_video_only_plan(plan: &PreparedAvVideoOnly<'_>) -> Option<Self> {
        plan.capture().is_none().then(|| Self {
            root: plan.manifest().root(),
            retention: plan.retention(),
        })
    }

    /// Candidate for one separately returned source record with unknown time.
    pub fn from_source_plan(plan: &source_evidence::Prepared<'_>) -> Self {
        Self {
            root: plan.manifest().root(),
            retention: plan.retention(),
        }
    }

    // Existing spool and policy checks use only root and retention. The full
    // range is an internal routing value, never returned as a physical bound.
    fn access_pin(self) -> Pin {
        Pin {
            root: self.root,
            retention: self.retention,
            capture: unknown_ledger_validity(),
        }
    }
}

fn unknown_ledger_validity() -> CaptureInterval {
    CaptureInterval {
        earliest: TimestampNs::MIN,
        latest: TimestampNs::MAX,
    }
}

/// Payload-free publication refusal. A storage failure can be indeterminate;
/// reconcile the exact same root and slot before trying a new publication.
#[derive(Debug)]
pub enum Error {
    /// The current original-byte policy denied retention.
    Denied,
    /// No independently justified capture bounds were provided.
    UnknownCapture,
    /// A source, graph, retention or publisher limit was exceeded.
    Limit,
    /// No durable, ledgered root matches the supplied pin.
    NotCommitted,
    /// A pending-intent journal must be reopened or does not name a candidate.
    RecoveryRequired,
    /// A deletion tombstone prohibits resurrection.
    Tombstoned,
    /// The operation's owner cancelled.
    Cancelled,
    /// A staged payload differed from its expected content address.
    Mismatch,
    /// Work accounting refused the operation.
    Work(GeometryError),
    /// Existing publication, ledger, or storage failure; it can be indeterminate.
    Storage(Box<dyn std::error::Error>),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Denied => "FLV original-byte retention denied",
            Self::UnknownCapture => "FLV physical capture bounds unavailable",
            Self::Limit => "FLV archive publication limit exceeded",
            Self::NotCommitted => "FLV archive root is not durably ledgered",
            Self::RecoveryRequired => "FLV pending source recovery requires an open intent",
            Self::Tombstoned => "FLV archive object tombstoned",
            Self::Cancelled => "FLV archive owner cancelled",
            Self::Mismatch => "FLV archive content mismatch",
            Self::Work(_) => "FLV archive work budget exhausted",
            Self::Storage(_) => "FLV archive storage or publication failed",
        })
    }
}
impl std::error::Error for Error {}
impl From<GeometryError> for Error {
    fn from(e: GeometryError) -> Self {
        Self::Work(e)
    }
}
fn storage<E: std::error::Error + 'static>(error: E) -> Error {
    Error::Storage(Box::new(error))
}

/// Bounds independent of bytes stored in the prepared evidence.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum configured spool object allocation; at most 64 MiB.
    pub maximum_spool_object_bytes: usize,
    /// Maximum ledger deltas inspected; at most 262,144.
    pub maximum_ledger_deltas: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            maximum_spool_object_bytes: 64 * 1024 * 1024,
            maximum_ledger_deltas: 65_536,
        }
    }
}

/// Deterministic immutable root slot. The returned name is not a receipt.
pub fn slot(plan: &Prepared<'_>) -> Result<SlotName, Error> {
    slot_for_root(plan.manifest().root())
}
fn slot_for_root(root: ContentDigest) -> Result<SlotName, Error> {
    let hex: String = root.bytes().iter().map(|b| format!("{b:02x}")).collect();
    SlotName::parse(&format!("uflv1-{hex}")).map_err(storage)
}

/// Stage exact source objects first, then publish and ledger the prepared root.
/// Retry the same plan after an indeterminate result. A successful return is
/// the underlying publisher's actual receipt, not an assertion of decode or
/// device authenticity. Individual spool objects are not encrypted here.
pub fn publish(
    plan: &Prepared<'_>,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RootLedgerReceipt, Error> {
    publish_graph(plan, deployment, authority, limits, work, cx)
}

/// Publish an A/V evidence graph under the same retention and ledger gates.
/// This does not establish synchronization, decoding, identity or coverage.
pub fn publish_av(
    plan: &PreparedAv<'_>,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RootLedgerReceipt, Error> {
    publish_graph(plan, deployment, authority, limits, work, cx)
}

/// Publish an explicitly unknown-time video graph. Its ledger validity covers
/// the entire representable timeline, not an inferred capture or receipt time.
/// This path does not journal intent or reconstruct source after a crash; retry
/// and reconcile the same root after any indeterminate publication.
pub fn publish_unknown_time(
    plan: &Prepared<'_>,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RootLedgerReceipt, Error> {
    publish_unknown_graph(plan, deployment, authority, limits, work, cx)
}

/// Publish an explicitly unknown-time A/V graph under the same authority and
/// recovery constraints as [`publish_unknown_time`].
pub fn publish_unknown_time_av(
    plan: &PreparedAv<'_>,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RootLedgerReceipt, Error> {
    publish_unknown_graph(plan, deployment, authority, limits, work, cx)
}

/// Failure in an anchored unknown-time publication. A failed write may
/// have taken effect; reconcile the exact pin and journal before proceeding.
#[derive(Debug)]
pub enum UnknownTimePublishError {
    /// The graph has known capture bounds or conflicts with a pending root.
    Candidate,
    /// Journal preparation or independent anchoring did not complete.
    BeforePublication(journal::Error),
    /// Source staging or root publication failed, possibly after an effect.
    Archive(Error),
    /// A receipt exists, but the journal or its anchor needs reconciliation.
    AfterPublication {
        /// Actual ledger receipt retained for reconciliation.
        receipt: Box<RootLedgerReceipt>,
        /// Journal or anchor refusal.
        source: journal::Error,
    },
}
impl fmt::Display for UnknownTimePublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Candidate => "unknown-time candidate conflicts with journal",
            Self::BeforePublication(_) => "unknown-time intent requires recovery",
            Self::Archive(_) => "unknown-time archive requires reconciliation",
            Self::AfterPublication { .. } => "unknown-time confirmation requires recovery",
        })
    }
}
impl std::error::Error for UnknownTimePublishError {}

/// Publish an already prepared unknown-time A/V graph with a separately
/// anchored intent and confirmation. The caller still owns the source, graph,
/// muxer reconstruction and independently retained keeper minimum. A failure
/// after intent preparation must be reconciled against this exact root.
pub fn publish_unknown_time_av_anchored(
    plan: &PreparedAv<'_>,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    journal: &mut journal::UnknownTimeJournal,
    keeper: &mut journal::UnknownTimeAnchorKeeper,
) -> Result<RootLedgerReceipt, UnknownTimePublishError> {
    let pin = UnknownTimePin::from_av_plan(plan).ok_or(UnknownTimePublishError::Candidate)?;
    publish_unknown_time_anchored(
        plan, pin, deployment, authority, limits, work, cx, journal, keeper,
    )
}

/// Publish a video-only A/V candidate with journaled intent and confirmation.
/// It records no audio samples, not audio absence or complete coverage. Any
/// uncertain outcome must be reconciled against the same root.
pub fn publish_unknown_time_av_video_only_anchored(
    plan: &PreparedAvVideoOnly<'_>,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    journal: &mut journal::UnknownTimeJournal,
    keeper: &mut journal::UnknownTimeAnchorKeeper,
) -> Result<RootLedgerReceipt, UnknownTimePublishError> {
    let pin =
        UnknownTimePin::from_av_video_only_plan(plan).ok_or(UnknownTimePublishError::Candidate)?;
    publish_unknown_time_anchored(
        plan, pin, deployment, authority, limits, work, cx, journal, keeper,
    )
}

/// Retain one separately returned source record using a dedicated unknown-time
/// journal and independent anchor. The source remains caller-owned on every
/// return; an indeterminate result must be reconciled against the same pin.
pub fn publish_unknown_time_source_anchored(
    plan: &source_evidence::Prepared<'_>,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    journal: &mut journal::UnknownTimeJournal,
    keeper: &mut journal::UnknownTimeAnchorKeeper,
) -> Result<RootLedgerReceipt, UnknownTimePublishError> {
    let pin = UnknownTimePin::from_source_plan(plan);
    publish_unknown_time_anchored(
        plan, pin, deployment, authority, limits, work, cx, journal, keeper,
    )
}

fn publish_unknown_time_anchored(
    plan: &impl Graph,
    pin: UnknownTimePin,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    journal: &mut journal::UnknownTimeJournal,
    keeper: &mut journal::UnknownTimeAnchorKeeper,
) -> Result<RootLedgerReceipt, UnknownTimePublishError> {
    if journal
        .pending()
        .or(journal.replay_pin())
        .is_some_and(|expected| expected != pin)
    {
        return Err(UnknownTimePublishError::Candidate);
    }
    keeper
        .preflight_publication(journal, pin, cx)
        .map_err(UnknownTimePublishError::BeforePublication)?;
    journal
        .prepare(pin, cx)
        .map_err(UnknownTimePublishError::BeforePublication)?;
    keeper
        .retain(journal, cx)
        .map_err(UnknownTimePublishError::BeforePublication)?;
    stage_graph(plan, deployment, authority, limits, work, cx, true, true)
        .map_err(UnknownTimePublishError::Archive)?;
    let receipt = publish_unknown_graph(plan, deployment, authority, limits, work, cx)
        .map_err(UnknownTimePublishError::Archive)?;
    if receipt.root != pin.root {
        return Err(UnknownTimePublishError::Archive(Error::Mismatch));
    }
    if let Err(source) = journal.confirm(pin, cx) {
        return Err(UnknownTimePublishError::AfterPublication {
            receipt: Box::new(receipt),
            source,
        });
    }
    if let Err(source) = keeper.retain(journal, cx) {
        return Err(UnknownTimePublishError::AfterPublication {
            receipt: Box::new(receipt),
            source,
        });
    }
    Ok(receipt)
}

/// Original source and initialization for an unknown-time A/V segment.
/// The caller keeps ownership of all borrowed originals on every outcome.
pub struct UnknownTimeAvSegment<'a> {
    /// Completed source-linked video segment.
    pub segment: &'a super::recording::Segment,
    /// Original video-configuration record.
    pub video_configuration: &'a fss_packet::extended_flv::stream::SourceRecord,
    /// Initialization tied to the video configuration.
    pub video_initialization: &'a fss_container::InitializationSegment,
    /// Initialization tied to the video and audio configurations.
    pub av_initialization: &'a fss_container::flv_av::Initialization,
    /// Explicitly classified audio-configuration provenance.
    pub audio: AvSegmentAudio<'a>,
    /// Identity of the separately authorized retention decision.
    pub retention: ContentDigest,
    /// Bounds for candidate evidence construction.
    pub evidence_limits: super::evidence::Limits,
}

/// A muxer exclusively bound to unknown-time publication. This wrapper does
/// not expose the internal full-range ledger routing value as capture time.
pub struct UnknownTimeMuxer {
    inner: av_recording::Muxer,
}
impl UnknownTimeMuxer {
    /// Transfer an idle, unbound muxer, or return it unchanged on refusal.
    pub fn new(inner: av_recording::Muxer) -> Result<Self, av_recording::Muxer> {
        if inner.pending_publication().is_some() || inner.publication_scope().is_some() {
            return Err(inner);
        }
        Ok(Self { inner })
    }

    /// Candidate requiring reconciliation, without a physical capture bound.
    pub fn pending(&self) -> Option<UnknownTimePin> {
        self.inner.pending_publication().map(|pin| UnknownTimePin {
            root: pin.root,
            retention: pin.retention,
        })
    }

    /// Remaining audio-frame allowance in the existing muxer epoch.
    pub fn remaining_audio_frames(&self) -> u64 {
        self.inner.remaining_audio_frames()
    }

    /// Extend the caller-authorized audio allowance without resetting clocks.
    /// A pending publication is refused by the underlying muxer.
    pub fn extend_audio_limit(
        &mut self,
        additional_frames: u64,
    ) -> Result<(), av_recording::Error> {
        self.inner.extend_audio_limit(additional_frames)
    }
}

/// Refusal by the unknown-time transactional segment owner.
#[derive(Debug)]
pub enum UnknownTimeSegmentError {
    /// Supplied audio provenance does not match the muxer.
    Binding,
    /// The muxer is already tied to another journal scope.
    JournalScope,
    /// A different candidate is awaiting reconciliation.
    PendingMismatch,
    /// Media derivation refused without advancing the muxer.
    Media(av_recording::Error),
    /// Video source evidence could not be prepared.
    Video(super::evidence::Error),
    /// A/V source evidence could not be prepared.
    AudioVideo(av_evidence::Error),
    /// Publication needs reconciliation against the retained exact input.
    Publication(UnknownTimePublishError),
}
impl fmt::Display for UnknownTimeSegmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Binding => "unknown-time A/V audio binding refused",
            Self::JournalScope => "unknown-time A/V journal scope refused",
            Self::PendingMismatch => "unknown-time A/V prior publication needs reconciliation",
            Self::Media(_) => "unknown-time A/V segment derivation refused",
            Self::Video(_) => "unknown-time video evidence refused",
            Self::AudioVideo(_) => "unknown-time A/V evidence refused",
            Self::Publication(_) => "unknown-time A/V publication needs reconciliation",
        })
    }
}
impl std::error::Error for UnknownTimeSegmentError {}

/// A committed unknown-time segment and its separately authorized read pin.
pub struct PublishedUnknownTimeAvSegment {
    /// Immutable unknown-time graph identity.
    pub pin: UnknownTimePin,
    /// Actual ledger receipt.
    pub receipt: RootLedgerReceipt,
    /// The graph profile; video-only does not establish audio absence.
    pub kind: UnknownTimeAvKind,
}

/// The source-checked derivative profile for one unknown-time segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownTimeAvKind {
    /// One or more AAC samples are mapped into this fragment.
    AudioVideo,
    /// No AAC sample was emitted; audio coverage remains unknown.
    VideoOnly,
}

/// Derive and publish one unknown-time segment under an anchored journal.
/// The muxer advances only after both publication and confirmation succeed;
/// on failure it retains the exact candidate fence for reconciliation.
pub fn publish_next_unknown_time_av_segment_anchored(
    input: &UnknownTimeAvSegment<'_>,
    muxer: &mut UnknownTimeMuxer,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    journal: &mut journal::UnknownTimeJournal,
    keeper: &mut journal::UnknownTimeAnchorKeeper,
) -> Result<PublishedUnknownTimeAvSegment, UnknownTimeSegmentError> {
    if !muxer.inner.bind_publication_scope(journal.scope()) {
        return Err(UnknownTimeSegmentError::JournalScope);
    }
    if let Some(expected) = journal.pending().or(journal.replay_pin()) {
        if muxer.pending().is_some_and(|proposed| proposed != expected) {
            return Err(UnknownTimeSegmentError::PendingMismatch);
        }
        muxer.inner.restore_publication_fence(expected.access_pin());
    }
    match (&input.audio, muxer.inner.source_binding()) {
        (AvSegmentAudio::SuppliedUnverified(_), None) => {}
        (AvSegmentAudio::InBand(bound), Some(binding)) => {
            let record = bound.record();
            if binding.epoch != bound.epoch()
                || binding.record_offset != record.offset()
                || binding.record_bytes != record.bytes().len()
                || binding.record_digest != ContentDigest::sha256(record.bytes())
                || binding.configuration_source != bound.source()
            {
                return Err(UnknownTimeSegmentError::Binding);
            }
        }
        _ => return Err(UnknownTimeSegmentError::Binding),
    }
    muxer
        .inner
        .with_fragment(
            input.av_initialization,
            input.segment,
            true,
            |fragment, pending| {
                let video = Prepared::new(
                    input.segment,
                    input.video_configuration,
                    input.video_initialization,
                    input.retention,
                    input.evidence_limits,
                )
                .map_err(UnknownTimeSegmentError::Video)?;
                if fragment.audio().is_empty() {
                    let plan = match &input.audio {
                        AvSegmentAudio::InBand(configuration) => PreparedAvVideoOnly::new(
                            &video,
                            configuration,
                            input.av_initialization,
                            fragment,
                            input.evidence_limits,
                        ),
                        AvSegmentAudio::SuppliedUnverified(configuration) => {
                            PreparedAvVideoOnly::new_with_unverified_audio_configuration(
                                &video,
                                configuration,
                                input.av_initialization,
                                fragment,
                                input.evidence_limits,
                            )
                        }
                    }
                    .map_err(UnknownTimeSegmentError::AudioVideo)?;
                    let pin = UnknownTimePin::from_av_video_only_plan(&plan)
                        .ok_or(UnknownTimeSegmentError::PendingMismatch)?;
                    if pending.is_some_and(|expected| expected != pin.access_pin()) {
                        return Err(UnknownTimeSegmentError::PendingMismatch);
                    }
                    *pending = Some(pin.access_pin());
                    let receipt = publish_unknown_time_av_video_only_anchored(
                        &plan, deployment, authority, limits, work, cx, journal, keeper,
                    )
                    .map_err(UnknownTimeSegmentError::Publication)?;
                    return Ok(PublishedUnknownTimeAvSegment {
                        pin,
                        receipt,
                        kind: UnknownTimeAvKind::VideoOnly,
                    });
                }
                let av = match &input.audio {
                    AvSegmentAudio::InBand(configuration) => PreparedAv::new(
                        &video,
                        configuration,
                        input.av_initialization,
                        fragment,
                        input.evidence_limits,
                    ),
                    AvSegmentAudio::SuppliedUnverified(configuration) => {
                        PreparedAv::new_with_unverified_audio_configuration(
                            &video,
                            configuration,
                            input.av_initialization,
                            fragment,
                            input.evidence_limits,
                        )
                    }
                }
                .map_err(UnknownTimeSegmentError::AudioVideo)?;
                let pin = UnknownTimePin::from_av_plan(&av)
                    .ok_or(UnknownTimeSegmentError::PendingMismatch)?;
                if pending.is_some_and(|expected| expected != pin.access_pin()) {
                    return Err(UnknownTimeSegmentError::PendingMismatch);
                }
                *pending = Some(pin.access_pin());
                let receipt = publish_unknown_time_av_anchored(
                    &av, deployment, authority, limits, work, cx, journal, keeper,
                )
                .map_err(UnknownTimeSegmentError::Publication)?;
                Ok(PublishedUnknownTimeAvSegment {
                    pin,
                    receipt,
                    kind: UnknownTimeAvKind::AudioVideo,
                })
            },
        )
        .map_err(|error| match error {
            av_recording::TransactionError::Media(error) => UnknownTimeSegmentError::Media(error),
            av_recording::TransactionError::Consumer(error) => error,
        })
}

/// Codec configuration with its explicit provenance for one publication.
pub enum AvSegmentAudio<'a> {
    /// Original non-provisional FLV configuration record and track claim.
    InBand(&'a fss_packet::extended_flv::aac_track::BoundConfiguration<'a>),
    /// Exact codec bytes supplied without an original configuration record.
    SuppliedUnverified(&'a fss_packet::extended_flv::aac::Configuration<'a>),
}

/// Original segment, decoder initialization, and caller-established policy and
/// capture bounds. The borrowed originals remain caller-owned on every outcome.
pub struct AvSegmentPublication<'a> {
    /// Completed source-linked video segment.
    pub segment: &'a super::recording::Segment,
    /// Original record containing the video configuration.
    pub video_configuration: &'a fss_packet::extended_flv::stream::SourceRecord,
    /// Initialization tied to the video configuration and segment.
    pub video_initialization: &'a fss_container::InitializationSegment,
    /// A/V initialization tied to the same video and audio configurations.
    pub av_initialization: &'a fss_container::flv_av::Initialization,
    /// Audio configuration and its retained or explicitly unverified source.
    pub audio: AvSegmentAudio<'a>,
    /// Identity of the separately authorized retention decision.
    pub retention: ContentDigest,
    /// Independently established physical capture bounds.
    pub capture: CaptureInterval,
    /// Bounds for candidate evidence construction.
    pub evidence_limits: super::evidence::Limits,
}

/// Refusal at a specific stage of segment derivation or archive publication.
/// An archive error can be indeterminate and requires exact-root reconciliation.
#[derive(Debug)]
pub enum AvSegmentPublishError {
    /// Audio provenance does not match the muxer's bound configuration.
    Binding,
    /// A journal-bound muxer cannot switch scopes or use an unjournaled path.
    JournalScope,
    /// The muxer refused the segment without advancing.
    Media(av_recording::Error),
    /// Video source evidence could not be prepared.
    Video(super::evidence::Error),
    /// A/V source evidence could not be prepared.
    AudioVideo(av_evidence::Error),
    /// A different root is still unresolved; neither root is authorized here.
    PendingMismatch {
        /// Root that must be reconciled before the owner can advance.
        expected: Pin,
        /// Root proposed by the current input.
        proposed: Pin,
    },
    /// Intent could not be durably prepared; its outcome can be indeterminate.
    JournalBefore {
        /// Exact proposed root.
        pin: Pin,
        /// Journal refusal or uncertain persistence result.
        source: journal::Error,
    },
    /// The intent exists but its separate anchor could not be retained.
    AnchorBefore {
        /// Exact proposed root; archive effects have not started in this call.
        pin: Pin,
        /// Retention of the journal prefix failed or is indeterminate.
        source: journal::Error,
    },
    /// The archive returned a receipt, but journaling confirmation failed.
    JournalAfterCommit {
        /// Exact published root.
        pin: Pin,
        /// Actual archive receipt retained for reconciliation.
        receipt: Box<RootLedgerReceipt>,
        /// Journal refusal or uncertain persistence result.
        source: journal::Error,
    },
    /// A receipt exists, but confirmation's separate anchor is unresolved.
    AnchorAfterCommit {
        /// Exact published root.
        pin: Pin,
        /// Actual archive receipt retained for reconciliation.
        receipt: Box<RootLedgerReceipt>,
        /// Retention of the confirmation prefix failed or is indeterminate.
        source: journal::Error,
    },
    /// Publication failed, possibly after an indeterminate effect. The exact
    /// pin identifies the root to reconcile; it grants no read authority.
    Archive {
        /// Exact candidate root and caller-supplied bounds for reconciliation.
        pin: Pin,
        /// Failure from the archive publication path.
        source: Error,
    },
}
impl fmt::Display for AvSegmentPublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Binding => "UniFi A/V audio binding refused",
            Self::JournalScope => "UniFi A/V publication journal scope refused",
            Self::Media(_) => "UniFi A/V segment derivation refused",
            Self::Video(_) => "UniFi video evidence preparation refused",
            Self::AudioVideo(_) => "UniFi A/V evidence preparation refused",
            Self::PendingMismatch { .. } => "UniFi A/V earlier publication requires reconciliation",
            Self::JournalBefore { .. } => "UniFi A/V publication intent requires recovery",
            Self::AnchorBefore { .. } => "UniFi A/V intent anchor requires recovery",
            Self::JournalAfterCommit { .. } => {
                "UniFi A/V publication confirmation requires recovery"
            }
            Self::AnchorAfterCommit { .. } => "UniFi A/V confirmation anchor requires recovery",
            Self::Archive { .. } => "UniFi A/V archive publication requires reconciliation",
        })
    }
}
impl std::error::Error for AvSegmentPublishError {}

/// A ledgered result and its exact root/capture pin.
pub struct PublishedAvSegment {
    /// Pin for independently authorized archive reads.
    pub pin: Pin,
    /// Actual ledger receipt, including committed versus already-ledgered.
    pub receipt: RootLedgerReceipt,
}

/// Derive and publish one segment before advancing the in-memory A/V muxer.
/// All source, identity, clock, retention and capture claims remain the
/// caller's responsibility. On error the segment and muxer remain usable for
/// reconciliation; an archive error or panic does not prove that no root was
/// staged or committed. Reconcile or retry the same exact input and root before
/// proceeding. This synchronous reference path is not a production async
/// persistence worker or a continuous recording service.
pub fn publish_next_av_segment(
    input: &AvSegmentPublication<'_>,
    muxer: &mut av_recording::Muxer,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<PublishedAvSegment, AvSegmentPublishError> {
    if muxer.publication_scope().is_some() {
        return Err(AvSegmentPublishError::JournalScope);
    }
    publish_next_av_segment_inner(
        input, muxer, deployment, authority, limits, work, cx, None, None,
    )
}

/// Publish with a separately owned intent journal. The journal records the
/// exact candidate before the archive effect and confirmation after its receipt.
/// The caller must independently retain journal anchors, source media and muxer
/// reconstruction state. This is synchronous reference I/O, not a running
/// recorder or a complete crash-recovery protocol.
pub fn publish_next_av_segment_journaled(
    input: &AvSegmentPublication<'_>,
    muxer: &mut av_recording::Muxer,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    journal: &mut journal::Journal,
) -> Result<PublishedAvSegment, AvSegmentPublishError> {
    if !muxer.bind_publication_scope(journal.scope()) {
        return Err(AvSegmentPublishError::JournalScope);
    }
    if let Some(expected) = journal.pending().or(journal.replay_pin()) {
        if let Some(proposed) = muxer.pending_publication() {
            if expected != proposed {
                return Err(AvSegmentPublishError::PendingMismatch { expected, proposed });
            }
        }
        muxer.restore_publication_fence(expected);
    }
    publish_next_av_segment_inner(
        input,
        muxer,
        deployment,
        authority,
        limits,
        work,
        cx,
        Some(journal),
        None,
    )
}

/// Publish while independently journaling each intent and confirmation prefix
/// before proceeding. Both stores need exclusive ownership and the keeper's
/// minimum must be independently retained; this does not reconstruct a muxer.
pub fn publish_next_av_segment_anchored(
    input: &AvSegmentPublication<'_>,
    muxer: &mut av_recording::Muxer,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    journal: &mut journal::Journal,
    keeper: &mut journal::AnchorKeeper,
) -> Result<PublishedAvSegment, AvSegmentPublishError> {
    if !muxer.bind_publication_scope(journal.scope()) {
        return Err(AvSegmentPublishError::JournalScope);
    }
    if let Some(expected) = journal.pending().or(journal.replay_pin()) {
        if let Some(proposed) = muxer.pending_publication() {
            if expected != proposed {
                return Err(AvSegmentPublishError::PendingMismatch { expected, proposed });
            }
        }
        muxer.restore_publication_fence(expected);
    }
    publish_next_av_segment_inner(
        input,
        muxer,
        deployment,
        authority,
        limits,
        work,
        cx,
        Some(journal),
        Some(keeper),
    )
}

fn publish_next_av_segment_inner(
    input: &AvSegmentPublication<'_>,
    muxer: &mut av_recording::Muxer,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    mut journal: Option<&mut journal::Journal>,
    mut keeper: Option<&mut journal::AnchorKeeper>,
) -> Result<PublishedAvSegment, AvSegmentPublishError> {
    match (&input.audio, muxer.source_binding()) {
        (AvSegmentAudio::SuppliedUnverified(_), None) => {}
        (AvSegmentAudio::InBand(bound), Some(binding)) => {
            let record = bound.record();
            if binding.epoch != bound.epoch()
                || binding.record_offset != record.offset()
                || binding.record_bytes != record.bytes().len()
                || binding.record_digest != ContentDigest::sha256(record.bytes())
                || binding.configuration_source != bound.source()
            {
                return Err(AvSegmentPublishError::Binding);
            }
        }
        _ => return Err(AvSegmentPublishError::Binding),
    }
    muxer
        .with_fragment(
            input.av_initialization,
            input.segment,
            false,
            |fragment, pending| {
                let video = Prepared::new_with_capture(
                    input.segment,
                    input.video_configuration,
                    input.video_initialization,
                    input.retention,
                    Some(input.capture),
                    input.evidence_limits,
                )
                .map_err(AvSegmentPublishError::Video)?;
                let av = match &input.audio {
                    AvSegmentAudio::InBand(configuration) => PreparedAv::new(
                        &video,
                        configuration,
                        input.av_initialization,
                        fragment,
                        input.evidence_limits,
                    ),
                    AvSegmentAudio::SuppliedUnverified(configuration) => {
                        PreparedAv::new_with_unverified_audio_configuration(
                            &video,
                            configuration,
                            input.av_initialization,
                            fragment,
                            input.evidence_limits,
                        )
                    }
                }
                .map_err(AvSegmentPublishError::AudioVideo)?;
                let pin = Pin {
                    root: av.manifest().root(),
                    retention: input.retention,
                    capture: input.capture,
                };
                if let Some(expected) = *pending {
                    if expected != pin {
                        return Err(AvSegmentPublishError::PendingMismatch {
                            expected,
                            proposed: pin,
                        });
                    }
                }
                // Establish the reconciliation fence before entering any archive
                // effect. It survives both ordinary errors and unwinding in this
                // process; it is not a durable crash-recovery journal.
                *pending = Some(pin);
                if let Some(journal) = journal.as_deref_mut() {
                    journal
                        .prepare(pin, cx)
                        .map_err(|source| AvSegmentPublishError::JournalBefore { pin, source })?;
                    if let Some(keeper) = keeper.as_deref_mut() {
                        keeper.retain(journal, cx).map_err(|source| {
                            AvSegmentPublishError::AnchorBefore { pin, source }
                        })?;
                    }
                    // Keep the complete source graph and its manifest in the
                    // verified spool before attempting root publication. A crash
                    // before this completes leaves an unresolved intent, not a
                    // claim that every source object is recoverable.
                    stage_graph(&av, deployment, authority, limits, work, cx, true, false)
                        .map_err(|source| AvSegmentPublishError::Archive { pin, source })?;
                }
                let receipt = publish_av(&av, deployment, authority, limits, work, cx)
                    .map_err(|source| AvSegmentPublishError::Archive { pin, source })?;
                if receipt.root != pin.root {
                    return Err(AvSegmentPublishError::Archive {
                        pin,
                        source: Error::Mismatch,
                    });
                }
                if let Some(journal) = journal.as_deref_mut() {
                    if let Err(source) = journal.confirm(pin, cx) {
                        return Err(AvSegmentPublishError::JournalAfterCommit {
                            pin,
                            receipt: Box::new(receipt),
                            source,
                        });
                    }
                    if let Some(keeper) = keeper.as_deref_mut() {
                        if let Err(source) = keeper.retain(journal, cx) {
                            return Err(AvSegmentPublishError::AnchorAfterCommit {
                                pin,
                                receipt: Box::new(receipt),
                                source,
                            });
                        }
                    }
                }
                Ok(PublishedAvSegment { pin, receipt })
            },
        )
        .map_err(|error| match error {
            av_recording::TransactionError::Media(error) => AvSegmentPublishError::Media(error),
            av_recording::TransactionError::Consumer(error) => error,
        })
}

trait Graph {
    fn manifest(&self) -> &ObjectManifest;
    fn capture(&self) -> Option<CaptureInterval>;
    fn retention(&self) -> ContentDigest;
    fn payloads(&self) -> Box<dyn Iterator<Item = &[u8]> + '_>;
}
impl Graph for Prepared<'_> {
    fn manifest(&self) -> &ObjectManifest {
        self.manifest()
    }
    fn capture(&self) -> Option<CaptureInterval> {
        self.capture()
    }
    fn retention(&self) -> ContentDigest {
        self.retention()
    }
    fn payloads(&self) -> Box<dyn Iterator<Item = &[u8]> + '_> {
        Box::new(self.payloads())
    }
}
impl Graph for PreparedAv<'_> {
    fn manifest(&self) -> &ObjectManifest {
        self.manifest()
    }
    fn capture(&self) -> Option<CaptureInterval> {
        self.capture()
    }
    fn retention(&self) -> ContentDigest {
        self.retention()
    }
    fn payloads(&self) -> Box<dyn Iterator<Item = &[u8]> + '_> {
        Box::new(self.payloads())
    }
}
impl Graph for PreparedAvVideoOnly<'_> {
    fn manifest(&self) -> &ObjectManifest {
        self.manifest()
    }
    fn capture(&self) -> Option<CaptureInterval> {
        self.capture()
    }
    fn retention(&self) -> ContentDigest {
        self.retention()
    }
    fn payloads(&self) -> Box<dyn Iterator<Item = &[u8]> + '_> {
        Box::new(self.payloads())
    }
}
impl Graph for source_evidence::Prepared<'_> {
    fn manifest(&self) -> &ObjectManifest {
        self.manifest()
    }
    fn capture(&self) -> Option<CaptureInterval> {
        None
    }
    fn retention(&self) -> ContentDigest {
        self.retention()
    }
    fn payloads(&self) -> Box<dyn Iterator<Item = &[u8]> + '_> {
        Box::new(self.payloads())
    }
}

struct RecoveredConfirmedAvGraph {
    manifest: ObjectManifest,
    retention: ContentDigest,
    children: Vec<Vec<u8>>,
}

struct ReplayRetainGate<'a> {
    read: &'a dyn ReadAuthority,
    retain: &'a dyn RetainAuthority,
}
impl RetainAuthority for ReplayRetainGate<'_> {
    fn permits(&self, retention: ContentDigest, root: ContentDigest) -> bool {
        self.read.permits(retention, root) && self.retain.permits(retention, root)
    }
}
impl Graph for RecoveredConfirmedAvGraph {
    fn manifest(&self) -> &ObjectManifest {
        &self.manifest
    }
    fn capture(&self) -> Option<CaptureInterval> {
        None
    }
    fn retention(&self) -> ContentDigest {
        self.retention
    }
    fn payloads(&self) -> Box<dyn Iterator<Item = &[u8]> + '_> {
        Box::new(self.children.iter().map(Vec::as_slice))
    }
}

/// A confirmed A/V graph could not be verified or its exact replay refused.
#[derive(Debug)]
pub enum ConfirmedAvReplayError {
    /// A verified prior confirmation, matching replay fence, and keeper are required.
    History,
    /// Current read authority, bounded graph readback, or source mapping failed.
    Readback(Error),
    /// Exact graph publication or its retained confirmation needs reconciliation.
    Publication(UnknownTimePublishError),
}
impl fmt::Display for ConfirmedAvReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::History => "confirmed A/V history requires reconciliation",
            Self::Readback(_) => "confirmed A/V graph readback refused",
            Self::Publication(_) => "confirmed A/V replay requires reconciliation",
        })
    }
}
impl std::error::Error for ConfirmedAvReplayError {}

/// Reconstruct and replay the exact *confirmed* unknown-time A/V graph from
/// retained objects after reopening its anchored journal.
///
/// Both read and retention authorities are rechecked. This verifies the
/// ledgered source mappings and every direct object before idempotently
/// publishing the same root. It refuses pending candidates and a lagging
/// keeper. Success clears only this in-memory replay fence; a later cold open
/// must verify again. It does not rebuild muxer clocks, establish source
/// identity, infer capture bounds, authorize a new connection, or prove
/// independent retention of the keeper or its anchors.
pub fn replay_confirmed_unknown_time_av_anchored(
    deployment: &mut ReferenceDeployment,
    read_authority: &dyn ReadAuthority,
    retain_authority: &dyn RetainAuthority,
    limits: Limits,
    object_limits: StagedAvLimits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    journal: &mut journal::UnknownTimeJournal,
    keeper: &mut journal::UnknownTimeAnchorKeeper,
) -> Result<RootLedgerReceipt, ConfirmedAvReplayError> {
    let pin = journal.confirmed().ok_or(ConfirmedAvReplayError::History)?;
    if journal.pending().is_some()
        || journal.replay_pin() != Some(pin)
        || journal.inner.is_fenced()
        || keeper.is_fenced()
        || keeper.target() != journal.anchor()
    {
        return Err(ConfirmedAvReplayError::History);
    }
    if !(1..=8192).contains(&object_limits.max_objects)
        || object_limits.max_object_bytes == 0
        || object_limits.max_object_bytes > deployment.publisher().limits().spool.max_object_bytes
        || !(1..=256 * 1024 * 1024).contains(&object_limits.max_total_bytes)
    {
        return Err(ConfirmedAvReplayError::Readback(Error::Limit));
    }
    let access = pin.access_pin();
    let root = read_part_bounded(
        deployment,
        access,
        pin.root,
        object_limits.max_object_bytes,
        read_authority,
        work,
        cx,
    )
    .map_err(ConfirmedAvReplayError::Readback)?;
    let manifest = ObjectManifest::from_canonical_bytes(&root)
        .map_err(storage)
        .map_err(ConfirmedAvReplayError::Readback)?;
    if manifest.root() != pin.root {
        return Err(ConfirmedAvReplayError::Readback(Error::Mismatch));
    }
    // Dispatch only by the digest-checked root kind, then verify the complete
    // ledgered source graph before replaying any effect. A read failure is
    // never interpreted as evidence of a different profile.
    match manifest.kind() {
        av_evidence::KIND => drop(
            read_unknown_time_av_clip(deployment, pin, read_authority, limits, work, cx)
                .map_err(ConfirmedAvReplayError::Readback)?,
        ),
        av_evidence::VIDEO_ONLY_KIND => drop(
            read_unknown_time_av_video_only_clip(deployment, pin, read_authority, limits, work, cx)
                .map_err(ConfirmedAvReplayError::Readback)?,
        ),
        _ => return Err(ConfirmedAvReplayError::Readback(Error::Mismatch)),
    }
    if manifest.children().len() > object_limits.max_objects
        || root.len() > object_limits.max_total_bytes
    {
        return Err(ConfirmedAvReplayError::Readback(Error::Limit));
    }
    let mut total = root.len();
    let mut children = Vec::new();
    children
        .try_reserve_exact(manifest.children().len())
        .map_err(|_| ConfirmedAvReplayError::Readback(Error::Limit))?;
    for digest in manifest.children() {
        let remaining = object_limits
            .max_total_bytes
            .checked_sub(total)
            .ok_or(ConfirmedAvReplayError::Readback(Error::Limit))?;
        let bytes = read_part_bounded(
            deployment,
            access,
            *digest,
            object_limits.max_object_bytes.min(remaining),
            read_authority,
            work,
            cx,
        )
        .map_err(ConfirmedAvReplayError::Readback)?;
        total = total
            .checked_add(bytes.len())
            .ok_or(ConfirmedAvReplayError::Readback(Error::Limit))?;
        if total > object_limits.max_total_bytes {
            return Err(ConfirmedAvReplayError::Readback(Error::Limit));
        }
        children.push(bytes);
    }
    if journal.pending().is_some()
        || journal.confirmed() != Some(pin)
        || journal.replay_pin() != Some(pin)
        || keeper.target() != journal.anchor()
    {
        return Err(ConfirmedAvReplayError::History);
    }
    let plan = RecoveredConfirmedAvGraph {
        manifest,
        retention: pin.retention,
        children,
    };
    let gate = ReplayRetainGate {
        read: read_authority,
        retain: retain_authority,
    };
    publish_unknown_time_anchored(
        &plan, pin, deployment, &gate, limits, work, cx, journal, keeper,
    )
    .map_err(ConfirmedAvReplayError::Publication)
}

fn publish_graph(
    plan: &impl Graph,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RootLedgerReceipt, Error> {
    let capture = plan.capture().ok_or(Error::UnknownCapture)?;
    stage_graph(plan, deployment, authority, limits, work, cx, false, false)?;
    let gate = Gate {
        plan,
        authority,
        cx,
    };
    deployment
        .ledgered_publisher()
        .publish_and_commit_cancellable(
            &slot_for_root(plan.manifest().root())?,
            plan.manifest(),
            capture,
            &gate,
        )
        .map_err(storage)
}

fn publish_unknown_graph(
    plan: &impl Graph,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RootLedgerReceipt, Error> {
    if plan.capture().is_some() {
        return Err(Error::Mismatch);
    }
    stage_graph(plan, deployment, authority, limits, work, cx, false, true)?;
    let gate = Gate {
        plan,
        authority,
        cx,
    };
    let receipt = deployment
        .ledgered_publisher()
        .publish_and_commit_cancellable(
            &slot_for_root(plan.manifest().root())?,
            plan.manifest(),
            unknown_ledger_validity(),
            &gate,
        )
        .map_err(storage)?;
    check_unknown_ledger_validity(deployment, plan.manifest().root(), &receipt.batch_id, work)?;
    Ok(receipt)
}

// Root publication can return an existing receipt. Recheck the actual
// ledger delta so a previously committed narrow interval is never silently
// represented as an unknown-time publication.
fn check_unknown_ledger_validity(
    deployment: &ReferenceDeployment,
    root: ContentDigest,
    batch_id: &fss_core::BatchId,
    work: &mut WorkBudget<'_>,
) -> Result<(), Error> {
    let object =
        fss_publication::root_reachability_object_id(&slot_for_root(root)?).map_err(storage)?;
    for batch in deployment.ledger().batches() {
        work.charge(1 + batch.deltas.len() as u64)?;
        if &batch.batch_id != batch_id {
            continue;
        }
        let mut matching = batch
            .deltas
            .iter()
            .filter(|delta| delta.object_id == object);
        let delta = matching.next().ok_or(Error::Mismatch)?;
        if matching.next().is_some()
            || delta.family != fss_publication::ROOT_REACHABILITY_FAMILY
            || delta.payload_digest != root
            || delta.validity != unknown_ledger_validity()
        {
            return Err(Error::Mismatch);
        }
        return Ok(());
    }
    Err(Error::Mismatch)
}

fn stage_graph(
    plan: &impl Graph,
    deployment: &mut ReferenceDeployment,
    authority: &dyn RetainAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    include_manifest: bool,
    allow_unknown: bool,
) -> Result<(), Error> {
    if !allow_unknown && plan.capture().is_none() {
        return Err(Error::UnknownCapture);
    }
    authorize(plan, authority, cx)?;
    if !(1024..=64 * 1024 * 1024).contains(&limits.maximum_spool_object_bytes)
        || !(1..=262_144).contains(&limits.maximum_ledger_deltas)
        || deployment.publisher().limits().spool.max_object_bytes
            > limits.maximum_spool_object_bytes
        || deployment.publisher().is_poisoned()
    {
        return Err(Error::Limit);
    }
    let mut deltas = 0usize;
    for batch in deployment.ledger().batches() {
        work.charge(1 + batch.deltas.len() as u64)?;
        deltas = deltas.checked_add(batch.deltas.len()).ok_or(Error::Limit)?;
        if deltas > limits.maximum_ledger_deltas {
            return Err(Error::Limit);
        }
    }
    work.charge(deployment.publisher().limits().spool.max_object_bytes as u64 * 4)?;
    for digest in plan
        .manifest()
        .children()
        .iter()
        .copied()
        .chain([plan.manifest().root()])
    {
        work.charge(deployment.publisher().limits().max_tombstones as u64 + 1)?;
        if deployment.publisher().tombstones().any(|v| *v == digest) {
            return Err(Error::Tombstoned);
        }
    }
    let object_ceiling = deployment.publisher().limits().spool.max_object_bytes;
    if plan.payloads().any(|bytes| bytes.len() > object_ceiling) {
        return Err(Error::Limit);
    }
    for bytes in plan.payloads() {
        authorize(plan, authority, cx)?;
        work.charge((bytes.len() as u64).checked_mul(3).ok_or(Error::Limit)?)?;
        if deployment.stage_payload(bytes).map_err(storage)? != ContentDigest::sha256(bytes) {
            return Err(Error::Mismatch);
        }
    }
    if include_manifest {
        authorize(plan, authority, cx)?;
        let bytes = plan.manifest().canonical_bytes();
        if bytes.len() > object_ceiling {
            return Err(Error::Limit);
        }
        work.charge((bytes.len() as u64).checked_mul(3).ok_or(Error::Limit)?)?;
        if deployment.stage_payload(&bytes).map_err(storage)? != plan.manifest().root() {
            return Err(Error::Mismatch);
        }
    }
    Ok(())
}

fn authorize(plan: &impl Graph, auth: &dyn RetainAuthority, cx: &ReplayCx) -> Result<(), Error> {
    cx.checkpoint("unifi-flv-archive:authority")
        .map_err(|_| Error::Cancelled)?;
    if !auth.permits(plan.retention(), plan.manifest().root()) {
        return Err(Error::Denied);
    }
    Ok(())
}
struct Gate<'a, G> {
    plan: &'a G,
    authority: &'a dyn RetainAuthority,
    cx: &'a ReplayCx,
}
impl<G: Graph> PublishCancellation for Gate<'_, G> {
    fn cancel_requested(&self, point: PublishCutPoint) -> bool {
        ReplayCancellationBridge(self.cx).cancel_requested(point)
            || !self
                .authority
                .permits(self.plan.retention(), self.plan.manifest().root())
    }
}

/// Read one direct child of an independently pinned, durably ledgered graph.
/// The root and metadata are verified before the requested object is disclosed.
/// This does not reconstruct the segment, replay its source mappings, prove
/// capture time, or authenticate the camera. Caller-selected limits cannot
/// expand the attached spool's configured maximum object allocation.
pub fn read_object(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    object: ContentDigest,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>, Error> {
    let (manifest, _) = open_graph(deployment, pin, authority, limits, work, cx)?;
    require_child(&manifest, object, work)?;
    read_part(deployment, pin, object, authority, work, cx)
}

/// Read a child of a ledgered A/V graph. This verifies the graph's authority,
/// content addresses and prefix, but does not replay media mappings or decode.
pub fn read_av_object(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    object: ContentDigest,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>, Error> {
    let (manifest, _) = open_graph_kind(
        deployment,
        pin,
        authority,
        limits,
        work,
        cx,
        av_evidence::KIND,
        av_evidence::DOMAIN,
    )?;
    require_child(&manifest, object, work)?;
    read_part(deployment, pin, object, authority, work, cx)
}

/// Read an authorized child of a ledgered unknown-time video graph. The
/// graph's unknown marker is checked before any child bytes are returned.
pub fn read_unknown_time_object(
    deployment: &mut ReferenceDeployment,
    pin: UnknownTimePin,
    object: ContentDigest,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>, Error> {
    read_unknown_time_object_kind(
        deployment, pin, object, authority, limits, work, cx, KIND, DOMAIN,
    )
}

/// Read an authorized child of a ledgered unknown-time A/V graph. This does
/// not establish camera identity, synchronization, decoding or coverage.
pub fn read_unknown_time_av_object(
    deployment: &mut ReferenceDeployment,
    pin: UnknownTimePin,
    object: ContentDigest,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>, Error> {
    read_unknown_time_object_kind(
        deployment,
        pin,
        object,
        authority,
        limits,
        work,
        cx,
        av_evidence::KIND,
        av_evidence::DOMAIN,
    )
}

/// Publication status of an authorized recovered source record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourcePublicationState {
    /// The exact root was published and committed to the ledger.
    Ledgered,
    /// The exact pending root and objects were staged, not proven published.
    Staged,
}

/// An authorized recovered source record and its untrusted connection claims.
pub struct RecoveredSource {
    /// Caller-supplied connection and generation, not authenticated identity.
    pub(super) key: fss_container::flv_avc::SourceKey,
    /// Caller-supplied camera claim, not an identity proof.
    pub(super) camera_claim: ContentDigest,
    /// Caller-supplied claim about why this record was returned separately.
    pub(super) disposition: super::recording::SourceDisposition,
    /// Original connection-relative offset.
    pub(super) offset: u64,
    /// Original parser boundary claim; it can remain provisional.
    pub(super) kind: fss_packet::extended_flv::stream::RecordKind,
    /// Exact original bytes, subject to the caller's disclosure policy.
    pub(super) bytes: Vec<u8>,
    pub(super) retention: ContentDigest,
    pub(super) metadata: Vec<u8>,
    pub(super) manifest: ObjectManifest,
    pub(super) state: SourcePublicationState,
}

impl RecoveredSource {
    /// Whether the source was ledgered or only verified as a staged candidate.
    pub fn publication_state(&self) -> SourcePublicationState {
        self.state
    }
    /// Caller-supplied connection and generation, not authenticated identity.
    pub fn key(&self) -> fss_container::flv_avc::SourceKey {
        self.key
    }
    /// Caller-supplied camera claim, not an identity proof.
    pub fn camera_claim(&self) -> ContentDigest {
        self.camera_claim
    }
    /// Caller-supplied claim about the source disposition.
    pub fn disposition(&self) -> super::recording::SourceDisposition {
        self.disposition
    }
    /// Original connection-relative offset.
    pub fn offset(&self) -> u64 {
        self.offset
    }
    /// Untrusted framing claim, including any provisional marker.
    pub fn kind(&self) -> fss_packet::extended_flv::stream::RecordKind {
        self.kind
    }
    /// Exact original bytes, subject to disclosure policy.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Reopen one ledgered standalone source record under current read authority.
/// The returned bytes and claims do not establish peer identity or capture time.
pub fn read_unknown_time_source(
    deployment: &mut ReferenceDeployment,
    pin: UnknownTimePin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecoveredSource, Error> {
    let access = pin.access_pin();
    let (manifest, metadata) = open_graph_kind_with_time(
        deployment,
        access,
        authority,
        limits,
        work,
        cx,
        source_evidence::KIND,
        source_evidence::DOMAIN,
        false,
    )?;
    recover_source_components(
        deployment,
        pin,
        manifest,
        metadata,
        authority,
        limits,
        work,
        cx,
        SourcePublicationState::Ledgered,
    )
}

/// Recover a fully staged pending record without claiming it was published.
/// The exact journal pin and independently anchored journal prefix are checked
/// before and after recovery; each digest-verified read rechecks authority.
pub fn read_staged_unknown_time_source(
    deployment: &ReferenceDeployment,
    journal: &journal::UnknownTimeJournal,
    keeper: &journal::UnknownTimeAnchorKeeper,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecoveredSource, Error> {
    if journal.inner.is_fenced() || keeper.is_fenced() || keeper.target() != journal.anchor() {
        return Err(Error::RecoveryRequired);
    }
    let pin = journal.pending().ok_or(Error::RecoveryRequired)?;
    let access = pin.access_pin();
    let _ = access.slot()?;
    if !(1024..=64 * 1024 * 1024).contains(&limits.maximum_spool_object_bytes)
        || deployment.publisher().limits().spool.max_object_bytes
            > limits.maximum_spool_object_bytes
        || deployment.publisher().is_poisoned()
    {
        return Err(Error::Limit);
    }
    let root = read_part(deployment, access, pin.root, authority, work, cx)?;
    let manifest = ObjectManifest::from_canonical_bytes(&root).map_err(storage)?;
    if manifest.root() != pin.root
        || manifest.kind() != source_evidence::KIND
        || manifest.children().len() != 2
    {
        return Err(Error::Mismatch);
    }
    let metadata_digest = manifest.metadata_digest().ok_or(Error::Mismatch)?;
    require_child(&manifest, metadata_digest, work)?;
    let metadata = read_part(deployment, access, metadata_digest, authority, work, cx)?;
    let recovered = recover_source_components(
        deployment,
        pin,
        manifest,
        metadata,
        authority,
        limits,
        work,
        cx,
        SourcePublicationState::Staged,
    )?;
    read_authorize(access, authority, cx)?;
    if journal.inner.is_fenced()
        || keeper.is_fenced()
        || journal.pending() != Some(pin)
        || keeper.target() != journal.anchor()
    {
        return Err(Error::RecoveryRequired);
    }
    Ok(recovered)
}

fn recover_source_components(
    deployment: &ReferenceDeployment,
    pin: UnknownTimePin,
    manifest: ObjectManifest,
    metadata: Vec<u8>,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    state: SourcePublicationState,
) -> Result<RecoveredSource, Error> {
    use super::recording::SourceDisposition;
    use fss_packet::extended_flv::stream::RecordKind;

    let access = pin.access_pin();
    work.charge((metadata.len() as u64).checked_mul(4).ok_or(Error::Limit)?)?;
    let mut decoder = CanonicalDecoder::new(&metadata);
    check_prefix_kind_with_time(&mut decoder, access, source_evidence::DOMAIN, false)?;
    let key = fss_container::flv_avc::SourceKey {
        connection: decoder.u64().map_err(storage)?,
        generation: decoder.u64().map_err(storage)?,
    };
    let camera_claim = decoder.digest().map_err(storage)?;
    if key.connection == 0
        || key.generation == 0
        || camera_claim.algorithm() != DigestAlgorithm::Sha256
        || camera_claim.is_laboratory()
        || camera_claim.bytes() == [0; 32]
    {
        return Err(Error::Mismatch);
    }
    let disposition = match decoder.u8().map_err(storage)? {
        0 => SourceDisposition::Header,
        1 => SourceDisposition::Configuration,
        2 => SourceDisposition::PreRoll,
        _ => return Err(Error::Mismatch),
    };
    let offset = decoder.u64().map_err(storage)?;
    let length = read_size(&mut decoder, limits.maximum_spool_object_bytes)?;
    if length == 0 || offset.checked_add(length as u64).is_none() {
        return Err(Error::Mismatch);
    }
    let digest = decoder.digest().map_err(storage)?;
    let kind = match decoder.u8().map_err(storage)? {
        0 => RecordKind::Header,
        1 => RecordKind::FirstTag {
            tag_kind: decoder.u8().map_err(storage)?,
            timestamp_ms: decoder.u32().map_err(storage)?,
        },
        2 => {
            let trailer_bytes = read_size(&mut decoder, length)?;
            if trailer_bytes >= length {
                return Err(Error::Mismatch);
            }
            RecordKind::Candidate {
                trailer_bytes,
                tag_kind: decoder.u8().map_err(storage)?,
                timestamp_ms: decoder.u32().map_err(storage)?,
                earlier_incomplete: decoder.bool().map_err(storage)?,
                provisional: decoder.bool().map_err(storage)?,
                policy: SearchMode::from_evidence_id(decoder.u8().map_err(storage)?)
                    .ok_or(Error::Mismatch)?,
            }
        }
        _ => return Err(Error::Mismatch),
    };
    decoder.ensure_finished().map_err(storage)?;
    if matches!(kind, RecordKind::Header) != matches!(disposition, SourceDisposition::Header)
        || (matches!(kind, RecordKind::Header) && offset != 0)
    {
        return Err(Error::Mismatch);
    }
    let metadata_digest = ContentDigest::sha256(&metadata);
    if digest == metadata_digest
        || manifest.metadata_digest() != Some(metadata_digest)
        || manifest.children().len() != 2
    {
        return Err(Error::Mismatch);
    }
    require_child(&manifest, metadata_digest, work)?;
    require_child(&manifest, digest, work)?;
    let bytes = read_part_bounded(deployment, access, digest, length, authority, work, cx)?;
    if bytes.len() != length {
        return Err(Error::Mismatch);
    }
    Ok(RecoveredSource {
        key,
        camera_claim,
        disposition,
        offset,
        kind,
        bytes,
        retention: pin.retention,
        metadata,
        manifest,
        state,
    })
}

fn read_unknown_time_object_kind(
    deployment: &mut ReferenceDeployment,
    pin: UnknownTimePin,
    object: ContentDigest,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    kind: &str,
    domain: &str,
) -> Result<Vec<u8>, Error> {
    let access = pin.access_pin();
    let (manifest, _) = open_graph_kind_with_time(
        deployment, access, authority, limits, work, cx, kind, domain, false,
    )?;
    require_child(&manifest, object, work)?;
    read_part(deployment, access, object, authority, work, cx)
}

fn require_child(
    manifest: &ObjectManifest,
    child: ContentDigest,
    work: &mut WorkBudget<'_>,
) -> Result<(), Error> {
    work.charge(u64::from(usize::BITS) + 1)?;
    if manifest.children().binary_search(&child).is_err() {
        return Err(Error::Mismatch);
    }
    Ok(())
}

/// Verified graph-local AAC configuration classification. An in-band record
/// and claimed epoch still do not authenticate the camera or shared epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvAudioConfiguration {
    /// Whether a source record was retained or the codec bytes were supplied.
    pub origin: AudioConfigurationOrigin,
    /// Content identity of the exact original configuration bytes.
    pub digest: ContentDigest,
    /// Claimed track-local epoch, present only with an in-band record.
    pub claimed_epoch: Option<u64>,
}

/// Reopen the A/V configuration classification and verify its bytes. For an
/// in-band configuration this also verifies the original FLV record and exact
/// byte range. This does not validate all mappings, identity or A/V timing.
pub fn read_av_audio_configuration(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<AvAudioConfiguration, Error> {
    read_av_audio_configuration_with_time(deployment, pin, authority, limits, work, cx, true)
}

fn read_av_audio_configuration_with_time(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    capture_known: bool,
) -> Result<AvAudioConfiguration, Error> {
    read_av_audio_configuration_profile(
        deployment,
        pin,
        authority,
        limits,
        work,
        cx,
        capture_known,
        false,
    )
}

fn read_av_audio_configuration_profile(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    capture_known: bool,
    video_only: bool,
) -> Result<AvAudioConfiguration, Error> {
    use fss_packet::extended_flv::{self, Parse, Tag, aac};

    let (kind, domain) = if video_only {
        (av_evidence::VIDEO_ONLY_KIND, av_evidence::VIDEO_ONLY_DOMAIN)
    } else {
        (av_evidence::KIND, av_evidence::DOMAIN)
    };
    let (manifest, metadata) = open_graph_kind_with_time(
        deployment,
        pin,
        authority,
        limits,
        work,
        cx,
        kind,
        domain,
        capture_known,
    )?;
    work.charge(metadata.len() as u64 * 4)?;
    let mut d = CanonicalDecoder::new(&metadata);
    check_prefix_kind_with_time(&mut d, pin, domain, capture_known)?;
    let video_root = d.digest().map_err(storage)?;
    require_child(&manifest, video_root, work)?;
    if video_only && (d.u8().map_err(storage)? != 0 || d.bool().map_err(storage)?) {
        return Err(Error::Mismatch);
    }
    let (origin, claimed_epoch, source) = match d.u8().map_err(storage)? {
        0 => {
            let epoch = d.u64().map_err(storage)?;
            let entry = record(&mut d, limits.maximum_spool_object_bytes)?;
            let start = d.u64().map_err(storage)?;
            let end = d.u64().map_err(storage)?;
            if epoch == 0 || start >= end {
                return Err(Error::Mismatch);
            }
            require_child(&manifest, entry.digest, work)?;
            (
                AudioConfigurationOrigin::InBand,
                Some(epoch),
                Some((entry, start..end)),
            )
        }
        1 => (AudioConfigurationOrigin::SuppliedUnverified, None, None),
        _ => return Err(Error::Mismatch),
    };
    let digest = d.digest().map_err(storage)?;
    require_child(&manifest, digest, work)?;
    let bytes = read_part_bounded(
        deployment,
        pin,
        digest,
        aac::MAX_SUPPORTED_CONFIGURATION_BYTES,
        authority,
        work,
        cx,
    )?;
    aac::Configuration::parse_explicit(&bytes).map_err(storage)?;
    if let Some((entry, range)) = source {
        let source_bytes = checked_record_bytes(deployment, pin, &entry, authority, work, cx)?;
        let (tag_offset, kind, timestamp) = entry.tag.ok_or(Error::Mismatch)?;
        let tag_bytes = source_bytes.get(tag_offset..).ok_or(Error::Mismatch)?;
        let Parse::Complete(tag) =
            Tag::parse(tag_bytes, extended_flv::Limits::default()).map_err(storage)?
        else {
            return Err(Error::Mismatch);
        };
        if kind != 8
            || tag.kind() != kind
            || tag.timestamp_ms() != timestamp
            || tag.wire_bytes().len() != tag_bytes.len()
        {
            return Err(Error::Mismatch);
        }
        let audio = aac::AudioTag::parse(tag, aac::Limits::default()).map_err(storage)?;
        if audio.packet_type() != aac::PacketType::Configuration || audio.body() != bytes {
            return Err(Error::Mismatch);
        }
        let body = audio.body_range();
        let start = entry
            .offset
            .checked_add(tag_offset as u64)
            .and_then(|offset| offset.checked_add(body.start as u64))
            .ok_or(Error::Limit)?;
        let end = entry
            .offset
            .checked_add(tag_offset as u64)
            .and_then(|offset| offset.checked_add(body.end as u64))
            .ok_or(Error::Limit)?;
        if range != (start..end) {
            return Err(Error::Mismatch);
        }
    }
    read_authorize(pin, authority, cx)?;
    Ok(AvAudioConfiguration {
        origin,
        digest,
        claimed_epoch,
    })
}

fn open_graph(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<(ObjectManifest, Vec<u8>), Error> {
    open_graph_kind(deployment, pin, authority, limits, work, cx, KIND, DOMAIN)
}

fn open_graph_kind(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    kind: &str,
    domain: &str,
) -> Result<(ObjectManifest, Vec<u8>), Error> {
    open_graph_kind_with_time(
        deployment, pin, authority, limits, work, cx, kind, domain, true,
    )
}

fn open_graph_kind_with_time(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    kind: &str,
    domain: &str,
    capture_known: bool,
) -> Result<(ObjectManifest, Vec<u8>), Error> {
    read_authorize(pin, authority, cx)?;
    if !(1024..=64 * 1024 * 1024).contains(&limits.maximum_spool_object_bytes)
        || !(1..=262_144).contains(&limits.maximum_ledger_deltas)
        || deployment.publisher().limits().spool.max_object_bytes
            > limits.maximum_spool_object_bytes
        || deployment.publisher().is_poisoned()
    {
        return Err(Error::Limit);
    }
    let mut count = 0usize;
    for batch in deployment.ledger().batches() {
        work.charge(1 + batch.deltas.len() as u64)?;
        count = count.checked_add(batch.deltas.len()).ok_or(Error::Limit)?;
        if count > limits.maximum_ledger_deltas {
            return Err(Error::Limit);
        }
    }
    work.charge(deployment.publisher().limits().spool.max_object_bytes as u64 * 4)?;
    match deployment
        .ledgered_publisher()
        .state(&pin.slot()?)
        .map_err(storage)?
    {
        RootLedgerState::Ledgered { root, batch_id, .. } if root == pin.root => {
            if !capture_known {
                check_unknown_ledger_validity(deployment, root, &batch_id, work)?;
            }
        }
        _ => return Err(Error::NotCommitted),
    }
    let root_bytes = read_part(deployment, pin, pin.root, authority, work, cx)?;
    let manifest = ObjectManifest::from_canonical_bytes(&root_bytes).map_err(storage)?;
    if manifest.root() != pin.root || manifest.kind() != kind {
        return Err(Error::Mismatch);
    }
    let metadata = manifest.metadata_digest().ok_or(Error::Mismatch)?;
    let metadata_bytes = read_part(deployment, pin, metadata, authority, work, cx)?;
    let mut decoder = CanonicalDecoder::new(&metadata_bytes);
    check_prefix_kind_with_time(&mut decoder, pin, domain, capture_known)?;
    Ok((manifest, metadata_bytes))
}

fn check_prefix_kind_with_time(
    decoder: &mut CanonicalDecoder<'_>,
    pin: Pin,
    domain: &str,
    capture_known: bool,
) -> Result<(), Error> {
    if decoder.text().map_err(storage)? != domain
        || decoder.digest().map_err(storage)? != pin.retention
        || decoder.bool().map_err(storage)? != capture_known
    {
        return Err(Error::Mismatch);
    }
    if !capture_known {
        return Ok(());
    }
    let capture = CaptureInterval::new(
        TimestampNs(decoder.i128().map_err(storage)?),
        TimestampNs(decoder.i128().map_err(storage)?),
    )
    .map_err(storage)?;
    if capture != pin.capture {
        return Err(Error::Mismatch);
    }
    Ok(())
}

fn read_authorize(pin: Pin, auth: &dyn ReadAuthority, cx: &ReplayCx) -> Result<(), Error> {
    cx.checkpoint("unifi-flv-archive:read-authority")
        .map_err(|_| Error::Cancelled)?;
    if !auth.permits(pin.retention, pin.root) {
        return Err(Error::Denied);
    }
    Ok(())
}
fn read_part(
    deployment: &ReferenceDeployment,
    pin: Pin,
    digest: ContentDigest,
    authority: &dyn ReadAuthority,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>, Error> {
    read_part_bounded(
        deployment,
        pin,
        digest,
        deployment.publisher().limits().spool.max_object_bytes,
        authority,
        work,
        cx,
    )
}

fn read_part_bounded(
    deployment: &ReferenceDeployment,
    pin: Pin,
    digest: ContentDigest,
    maximum_payload_bytes: usize,
    authority: &dyn ReadAuthority,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>, Error> {
    read_authorize(pin, authority, cx)?;
    if maximum_payload_bytes > deployment.publisher().limits().spool.max_object_bytes {
        return Err(Error::Limit);
    }
    work.charge(deployment.publisher().limits().max_tombstones as u64 + 1)?;
    if deployment
        .publisher()
        .tombstones()
        .any(|value| *value == digest)
    {
        return Err(Error::Tombstoned);
    }
    let read_bound = (fss_object::SPOOL_OBJECT_HEADER_LEN as u64)
        .checked_add(u64::try_from(maximum_payload_bytes).map_err(|_| Error::Limit)?)
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_mul(4))
        .ok_or(Error::Limit)?;
    work.charge(read_bound)?;
    let bytes = deployment
        .publisher()
        .spool()
        .read_bounded(digest, maximum_payload_bytes)
        .map_err(storage)?;
    if ContentDigest::sha256(&bytes) != digest {
        return Err(Error::Mismatch);
    }
    read_authorize(pin, authority, cx)?;
    Ok(bytes)
}

/// Explicit limits for verifying a pending A/V source graph.
#[derive(Clone, Copy, Debug)]
pub struct StagedAvLimits {
    /// Maximum manifest children, at most 8,192.
    pub max_objects: usize,
    /// Maximum bytes in one object, at most the archive spool limit.
    pub max_object_bytes: usize,
    /// Maximum combined verified manifest and child bytes, at most 256 MiB.
    pub max_total_bytes: usize,
}

/// A verified source-graph inventory, not a publication or camera receipt.
#[must_use]
pub struct StagedAvCandidate {
    pin: Pin,
    children: Vec<ContentDigest>,
    total_bytes: usize,
    object_limit: usize,
    source: StagedSourceIndex,
}

/// Verified pending unknown-time source graph, without a physical-time pin.
#[must_use]
pub struct StagedUnknownTimeAvCandidate {
    inner: StagedAvCandidate,
}
impl StagedUnknownTimeAvCandidate {
    /// Candidate root and retention decision, with capture time unknown.
    pub fn pin(&self) -> UnknownTimePin {
        UnknownTimePin {
            root: self.inner.pin.root,
            retention: self.inner.pin.retention,
        }
    }
    /// Verified direct object identities in canonical order.
    pub fn children(&self) -> &[ContentDigest] {
        self.inner.children()
    }
    /// Total verified bytes, including the manifest.
    pub fn total_bytes(&self) -> usize {
        self.inner.total_bytes()
    }
    /// Original video-configuration source record descriptor.
    pub fn configuration(&self) -> StagedSourceRecord {
        self.inner.configuration()
    }
    /// Original source records in claimed connection order.
    pub fn records(&self) -> &[StagedSourceRecord] {
        self.inner.records()
    }
    /// Duplicated boundary witnesses in claimed connection order.
    pub fn witness(&self) -> &[StagedSourceRecord] {
        self.inner.witness()
    }
}

/// One source object's claimed connection-relative position and exact digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StagedSourceRecord {
    /// Original connection-relative byte offset.
    pub offset: u64,
    /// Exact stored byte count, including any source trailer.
    pub length: usize,
    /// Digest address for authorized retrieval.
    pub digest: ContentDigest,
}

struct StagedSourceIndex {
    connection: u64,
    generation: u64,
    sequence: u32,
    configuration: StagedSourceRecord,
    records: Vec<StagedSourceRecord>,
    witness: Vec<StagedSourceRecord>,
}
impl StagedAvCandidate {
    /// Exact journaled candidate, including caller-supplied capture bounds.
    pub fn pin(&self) -> Pin {
        self.pin
    }
    /// Verified direct object identities in canonical order.
    pub fn children(&self) -> &[ContentDigest] {
        &self.children
    }
    /// Total verified payload bytes including the manifest.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }
    /// Unauthenticated caller-bound connection, generation and local fragment sequence.
    pub fn claimed_source(&self) -> (u64, u64, u32) {
        (
            self.source.connection,
            self.source.generation,
            self.source.sequence,
        )
    }
    /// Original video-configuration source record descriptor.
    pub fn configuration(&self) -> StagedSourceRecord {
        self.source.configuration
    }
    /// Original source records in claimed connection order.
    pub fn records(&self) -> &[StagedSourceRecord] {
        &self.source.records
    }
    /// Duplicated boundary witness records in claimed connection order.
    pub fn witness(&self) -> &[StagedSourceRecord] {
        &self.source.witness
    }
}

/// Verify that a still-pending journal root and every direct child are present
/// and digest-correct in the reopened spool. The caller must separately check
/// device identity, source-to-derivative semantics, capture time, publication
/// state, and muxer reconstruction. This is not an archive commit receipt.
pub fn verify_staged_av_candidate(
    deployment: &ReferenceDeployment,
    journal: &journal::Journal,
    authority: &dyn ReadAuthority,
    limits: StagedAvLimits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<StagedAvCandidate, Error> {
    verify_staged_av_candidate_with_time(deployment, journal, authority, limits, work, cx, true)
}

/// Verify an unknown-time journal's pending source graph without manufacturing
/// capture bounds or asserting that publication has completed.
pub fn verify_staged_unknown_time_av_candidate(
    deployment: &ReferenceDeployment,
    journal: &journal::UnknownTimeJournal,
    authority: &dyn ReadAuthority,
    limits: StagedAvLimits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<StagedUnknownTimeAvCandidate, Error> {
    Ok(StagedUnknownTimeAvCandidate {
        inner: verify_staged_av_candidate_with_time(
            deployment,
            &journal.inner,
            authority,
            limits,
            work,
            cx,
            false,
        )?,
    })
}

fn verify_staged_av_candidate_with_time(
    deployment: &ReferenceDeployment,
    journal: &journal::Journal,
    authority: &dyn ReadAuthority,
    limits: StagedAvLimits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    capture_known: bool,
) -> Result<StagedAvCandidate, Error> {
    if journal.is_fenced() {
        return Err(Error::RecoveryRequired);
    }
    let pin = journal.pending().ok_or(Error::RecoveryRequired)?;
    let _ = pin.slot()?;
    if !(1..=8192).contains(&limits.max_objects)
        || limits.max_object_bytes == 0
        || limits.max_object_bytes > deployment.publisher().limits().spool.max_object_bytes
        || !(1..=256 * 1024 * 1024).contains(&limits.max_total_bytes)
    {
        return Err(Error::Limit);
    }
    let root = read_part_bounded(
        deployment,
        pin,
        pin.root,
        limits.max_object_bytes,
        authority,
        work,
        cx,
    )?;
    let manifest = ObjectManifest::from_canonical_bytes(&root).map_err(storage)?;
    if manifest.root() != pin.root || manifest.kind() != av_evidence::KIND {
        return Err(Error::Mismatch);
    }
    if manifest.children().len() > limits.max_objects {
        return Err(Error::Limit);
    }
    let metadata = manifest.metadata_digest().ok_or(Error::Mismatch)?;
    if manifest.children().binary_search(&metadata).is_err() {
        return Err(Error::Mismatch);
    }
    let mut total_bytes = root.len();
    if total_bytes > limits.max_total_bytes {
        return Err(Error::Limit);
    }
    let mut lengths = Vec::new();
    lengths
        .try_reserve_exact(manifest.children().len())
        .map_err(|_| Error::Limit)?;
    for &digest in manifest.children() {
        let bytes = read_part_bounded(
            deployment,
            pin,
            digest,
            limits.max_object_bytes,
            authority,
            work,
            cx,
        )?;
        total_bytes = total_bytes.checked_add(bytes.len()).ok_or(Error::Limit)?;
        if total_bytes > limits.max_total_bytes {
            return Err(Error::Limit);
        }
        lengths.push((digest, bytes.len()));
        if digest == metadata {
            let mut decoder = CanonicalDecoder::new(&bytes);
            check_prefix_kind_with_time(&mut decoder, pin, av_evidence::DOMAIN, capture_known)?;
        }
    }
    let source = staged_source_index(
        deployment,
        pin,
        &manifest,
        &lengths,
        metadata,
        limits.max_object_bytes,
        authority,
        work,
        cx,
        capture_known,
    )?;
    read_authorize(pin, authority, cx)?;
    if journal.is_fenced() || journal.pending() != Some(pin) {
        return Err(Error::RecoveryRequired);
    }
    work.charge(u64::try_from(manifest.children().len()).map_err(|_| Error::Limit)?)?;
    let mut children = Vec::new();
    children
        .try_reserve_exact(manifest.children().len())
        .map_err(|_| Error::Limit)?;
    children.extend_from_slice(manifest.children());
    Ok(StagedAvCandidate {
        pin,
        children,
        total_bytes,
        object_limit: limits.max_object_bytes,
        source,
    })
}

fn staged_source_index(
    deployment: &ReferenceDeployment,
    pin: Pin,
    outer: &ObjectManifest,
    lengths: &[(ContentDigest, usize)],
    av_metadata: ContentDigest,
    object_limit: usize,
    authority: &dyn ReadAuthority,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    capture_known: bool,
) -> Result<StagedSourceIndex, Error> {
    let metadata = read_part_bounded(
        deployment,
        pin,
        av_metadata,
        object_limit,
        authority,
        work,
        cx,
    )?;
    let mut decoder = CanonicalDecoder::new(&metadata);
    check_prefix_kind_with_time(&mut decoder, pin, av_evidence::DOMAIN, capture_known)?;
    let video_root = decoder.digest().map_err(storage)?;
    if outer.children().binary_search(&video_root).is_err() {
        return Err(Error::Mismatch);
    }
    let video_bytes = read_part_bounded(
        deployment,
        pin,
        video_root,
        object_limit,
        authority,
        work,
        cx,
    )?;
    let video = ObjectManifest::from_canonical_bytes(&video_bytes).map_err(storage)?;
    if video.root() != video_root || video.kind() != KIND {
        return Err(Error::Mismatch);
    }
    for child in video.children() {
        work.charge(u64::from(usize::BITS) + 1)?;
        if outer.children().binary_search(child).is_err() {
            return Err(Error::Mismatch);
        }
    }
    let video_metadata = video.metadata_digest().ok_or(Error::Mismatch)?;
    if video.children().binary_search(&video_metadata).is_err() {
        return Err(Error::Mismatch);
    }
    let bytes = read_part_bounded(
        deployment,
        pin,
        video_metadata,
        object_limit,
        authority,
        work,
        cx,
    )?;
    let mut decoder = CanonicalDecoder::new(&bytes);
    check_prefix_kind_with_time(&mut decoder, pin, DOMAIN, capture_known)?;
    let connection = decoder.u64().map_err(storage)?;
    let generation = decoder.u64().map_err(storage)?;
    let sequence = decoder.u32().map_err(storage)?;
    if connection == 0 || generation == 0 || sequence == 0 {
        return Err(Error::Mismatch);
    }
    let configuration = record(&mut decoder, object_limit)?;
    work.charge(2 * (u64::from(usize::BITS) + 1))?;
    if video
        .children()
        .binary_search(&configuration.digest)
        .is_err()
        || staged_length(lengths, configuration.digest) != Some(configuration.length)
    {
        return Err(Error::Mismatch);
    }
    for _ in 0..2 {
        let digest = decoder.digest().map_err(storage)?;
        let length = read_size(&mut decoder, object_limit)?;
        work.charge(2 * (u64::from(usize::BITS) + 1))?;
        if length == 0
            || video.children().binary_search(&digest).is_err()
            || staged_length(lengths, digest) != Some(length)
        {
            return Err(Error::Mismatch);
        }
    }
    let count = read_size(&mut decoder, 8192)?;
    if count == 0 {
        return Err(Error::Mismatch);
    }
    work.charge(u64::try_from(count).map_err(|_| Error::Limit)?)?;
    let mut records = Vec::new();
    records.try_reserve_exact(count).map_err(|_| Error::Limit)?;
    let mut next = None;
    for _ in 0..count {
        let item = record(&mut decoder, object_limit)?;
        work.charge(2 * (u64::from(usize::BITS) + 1))?;
        if video.children().binary_search(&item.digest).is_err()
            || staged_length(lengths, item.digest) != Some(item.length)
            || next.is_some_and(|offset| offset != item.offset)
        {
            return Err(Error::Mismatch);
        }
        next = Some(
            item.offset
                .checked_add(item.length as u64)
                .ok_or(Error::Limit)?,
        );
        records.push(StagedSourceRecord {
            offset: item.offset,
            length: item.length,
            digest: item.digest,
        });
    }
    let witness_count = read_size(&mut decoder, 8192 - count)?;
    if witness_count == 0 {
        return Err(Error::Mismatch);
    }
    work.charge(u64::try_from(witness_count).map_err(|_| Error::Limit)?)?;
    let mut witness = Vec::new();
    witness
        .try_reserve_exact(witness_count)
        .map_err(|_| Error::Limit)?;
    for _ in 0..witness_count {
        let item = record(&mut decoder, object_limit)?;
        work.charge(2 * (u64::from(usize::BITS) + 1))?;
        if video.children().binary_search(&item.digest).is_err()
            || staged_length(lengths, item.digest) != Some(item.length)
            || next != Some(item.offset)
        {
            return Err(Error::Mismatch);
        }
        next = Some(
            item.offset
                .checked_add(item.length as u64)
                .ok_or(Error::Limit)?,
        );
        witness.push(StagedSourceRecord {
            offset: item.offset,
            length: item.length,
            digest: item.digest,
        });
    }
    Ok(StagedSourceIndex {
        connection,
        generation,
        sequence,
        configuration: StagedSourceRecord {
            offset: configuration.offset,
            length: configuration.length,
            digest: configuration.digest,
        },
        records,
        witness,
    })
}

fn staged_length(lengths: &[(ContentDigest, usize)], digest: ContentDigest) -> Option<usize> {
    lengths
        .binary_search_by_key(&digest, |(candidate, _)| *candidate)
        .ok()
        .map(|index| lengths[index].1)
}

/// Read one object from a previously verified pending graph, rechecking current
/// authority, journal state, membership, tombstones and the object's digest.
/// The returned bytes are original source or derivatives and require privacy
/// handling by the caller; no semantic mapping or publication is asserted.
pub fn read_staged_av_object(
    deployment: &ReferenceDeployment,
    journal: &journal::Journal,
    candidate: &StagedAvCandidate,
    digest: ContentDigest,
    authority: &dyn ReadAuthority,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>, Error> {
    if journal.is_fenced() || journal.pending() != Some(candidate.pin) {
        return Err(Error::RecoveryRequired);
    }
    if digest != candidate.pin.root && candidate.children.binary_search(&digest).is_err() {
        return Err(Error::Mismatch);
    }
    let root = read_part_bounded(
        deployment,
        candidate.pin,
        candidate.pin.root,
        candidate.object_limit,
        authority,
        work,
        cx,
    )?;
    let manifest = ObjectManifest::from_canonical_bytes(&root).map_err(storage)?;
    if manifest.root() != candidate.pin.root
        || manifest.kind() != av_evidence::KIND
        || manifest.children() != candidate.children.as_slice()
    {
        return Err(Error::Mismatch);
    }
    let bytes = read_part_bounded(
        deployment,
        candidate.pin,
        digest,
        candidate.object_limit,
        authority,
        work,
        cx,
    )?;
    if journal.is_fenced() || journal.pending() != Some(candidate.pin) {
        return Err(Error::RecoveryRequired);
    }
    Ok(bytes)
}

/// Read a verified pending unknown-time object under current authority. This
/// rechecks journal state and object integrity and does not assert publication.
pub fn read_staged_unknown_time_av_object(
    deployment: &ReferenceDeployment,
    journal: &journal::UnknownTimeJournal,
    candidate: &StagedUnknownTimeAvCandidate,
    digest: ContentDigest,
    authority: &dyn ReadAuthority,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>, Error> {
    read_staged_av_object(
        deployment,
        &journal.inner,
        &candidate.inner,
        digest,
        authority,
        work,
        cx,
    )
}

/// A recovered, source-checked AVC fragmented MP4. Its capture bounds are the
/// independently supplied bounds in the pin, not a clock inferred from video.
#[must_use]
pub struct RecoveredClip {
    bytes: Vec<u8>,
    capture: CaptureInterval,
    samples: usize,
    continuity: VideoContinuity,
}
impl RecoveredClip {
    /// Initialization segment followed by the validated media fragment.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Transfer the validated MP4 bytes to the authorized caller.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    /// Caller-supplied physical capture interval bound into the ledgered root.
    pub fn capture(&self) -> CaptureInterval {
        self.capture
    }
    /// Number of structurally validated AVC samples; not a decoder guarantee.
    pub fn samples(&self) -> usize {
        self.samples
    }
}
impl fmt::Debug for RecoveredClip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredClip")
            .field("bytes", &"<redacted>")
            .field("capture", &self.capture)
            .field("samples", &self.samples)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct StoredRecord {
    offset: u64,
    length: usize,
    digest: ContentDigest,
    tag: Option<(usize, u8, u32)>,
}

struct VideoContinuity {
    connection: u64,
    generation: u64,
    sequence: u32,
    first_decode: u64,
    end_decode: u64,
    records: Vec<StoredRecord>,
    lookahead: Vec<StoredRecord>,
}
struct StoredSample {
    start: usize,
    end: usize,
    decode: u64,
    composition: i128,
    duration: u32,
    idr: bool,
    first_nal: usize,
    end_nal: usize,
}
struct StoredNal {
    sample: usize,
    source_start: u64,
    source_end: u64,
    start: usize,
    end: usize,
}

fn read_size(decoder: &mut CanonicalDecoder<'_>, max: usize) -> Result<usize, Error> {
    let n = usize::try_from(decoder.u64().map_err(storage)?).map_err(|_| Error::Limit)?;
    if n > max {
        return Err(Error::Limit);
    }
    Ok(n)
}
fn record(decoder: &mut CanonicalDecoder<'_>, limit: usize) -> Result<StoredRecord, Error> {
    let offset = decoder.u64().map_err(storage)?;
    let length = read_size(decoder, limit)?;
    if length == 0 || offset.checked_add(length as u64).is_none() {
        return Err(Error::Mismatch);
    }
    let digest = decoder.digest().map_err(storage)?;
    let tag = match decoder.u8().map_err(storage)? {
        0 => None,
        1 => Some((
            0,
            decoder.u8().map_err(storage)?,
            decoder.u32().map_err(storage)?,
        )),
        2 => {
            let trailer = read_size(decoder, length)?;
            if trailer >= length {
                return Err(Error::Mismatch);
            }
            let kind = decoder.u8().map_err(storage)?;
            let timestamp = decoder.u32().map_err(storage)?;
            decoder.bool().map_err(storage)?;
            if decoder.bool().map_err(storage)? {
                return Err(Error::Mismatch);
            }
            if SearchMode::from_evidence_id(decoder.u8().map_err(storage)?).is_none() {
                return Err(Error::Mismatch);
            }
            Some((trailer, kind, timestamp))
        }
        _ => return Err(Error::Mismatch),
    };
    Ok(StoredRecord {
        offset,
        length,
        digest,
        tag,
    })
}
fn checked_record_bytes(
    deployment: &ReferenceDeployment,
    pin: Pin,
    entry: &StoredRecord,
    authority: &dyn ReadAuthority,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<Vec<u8>, Error> {
    let bytes = read_part_bounded(
        deployment,
        pin,
        entry.digest,
        entry.length,
        authority,
        work,
        cx,
    )?;
    if bytes.len() != entry.length {
        return Err(Error::Mismatch);
    }
    Ok(bytes)
}

fn fragment_sequence_matches(fragment: &[u8], sequence: u32) -> bool {
    fragment.get(8..20) == Some(b"\x00\x00\x00\x10mfhd\x00\x00\x00\x00")
        && fragment.get(20..24) == Some(sequence.to_be_bytes().as_slice())
}

/// Recover one ledgered segment, rechecking the graph, its source-object hashes,
/// original-to-fragment NAL byte mappings and the generated MP4's sample table.
/// The source framer's boundaries remain heuristic, capture time and device
/// identity are not independently proven here, and successful parsing is not
/// proof that a decoder can display the pictures. No data is returned on denial.
pub fn read_clip(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecoveredClip, Error> {
    let (manifest, metadata) = open_graph(deployment, pin, authority, limits, work, cx)?;
    recover_video_graph(
        deployment, pin, &manifest, &metadata, authority, limits, work, cx, true,
    )
}

/// Recover the independently source-checked video derivative nested in a
/// ledgered A/V graph. This returns video only, not the A/V fragment, and does
/// not validate audio mappings, synchronization, peer identity or capture time.
pub fn read_av_video_clip(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecoveredClip, Error> {
    let (_, _, video, video_metadata) =
        open_av_video_graph(deployment, pin, authority, limits, work, cx)?;
    recover_video_graph(
        deployment,
        pin,
        &video,
        &video_metadata,
        authority,
        limits,
        work,
        cx,
        true,
    )
}

/// Source-checked video recovered without a claim about physical capture time.
/// The connection and generation are caller-bound claims, not device identity.
#[must_use]
pub struct RecoveredUnknownTimeVideoClip {
    bytes: Vec<u8>,
    samples: usize,
    source: fss_container::flv_avc::SourceKey,
}

impl RecoveredUnknownTimeVideoClip {
    /// Video-only initialization and fragment after source and graph checks.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Number of structurally checked AVC samples, not a decoding guarantee.
    pub fn samples(&self) -> usize {
        self.samples
    }

    /// Caller-bound connection and generation, not authenticated identity.
    pub fn claimed_source(&self) -> fss_container::flv_avc::SourceKey {
        self.source
    }
}

impl fmt::Debug for RecoveredUnknownTimeVideoClip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredUnknownTimeVideoClip")
            .field("bytes", &"<redacted>")
            .field("samples", &self.samples)
            .finish_non_exhaustive()
    }
}

/// Recover the video derivative nested in an unknown-time A/V graph, checking
/// its retained original bytes and generated MP4 sample table. Audio mapping,
/// decoding, camera identity, capture time, and continuity remain separate.
pub fn read_unknown_time_av_video_clip(
    deployment: &mut ReferenceDeployment,
    pin: UnknownTimePin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecoveredUnknownTimeVideoClip, Error> {
    let access_pin = pin.access_pin();
    let (_, _, video, metadata) =
        open_av_video_graph_with_time(deployment, access_pin, authority, limits, work, cx, false)?;
    let clip = recover_video_graph(
        deployment, access_pin, &video, &metadata, authority, limits, work, cx, false,
    )?;
    Ok(RecoveredUnknownTimeVideoClip {
        bytes: clip.bytes,
        samples: clip.samples,
        source: fss_container::flv_avc::SourceKey {
            connection: clip.continuity.connection,
            generation: clip.continuity.generation,
        },
    })
}

fn open_av_video_graph(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<(ObjectManifest, Vec<u8>, ObjectManifest, Vec<u8>), Error> {
    open_av_video_graph_with_time(deployment, pin, authority, limits, work, cx, true)
}

fn open_av_video_graph_with_time(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    capture_known: bool,
) -> Result<(ObjectManifest, Vec<u8>, ObjectManifest, Vec<u8>), Error> {
    open_av_video_graph_profile(
        deployment,
        pin,
        authority,
        limits,
        work,
        cx,
        capture_known,
        false,
    )
}

fn open_av_video_graph_profile(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    capture_known: bool,
    video_only: bool,
) -> Result<(ObjectManifest, Vec<u8>, ObjectManifest, Vec<u8>), Error> {
    let (kind, domain) = if video_only {
        (av_evidence::VIDEO_ONLY_KIND, av_evidence::VIDEO_ONLY_DOMAIN)
    } else {
        (av_evidence::KIND, av_evidence::DOMAIN)
    };
    let (outer, metadata) = open_graph_kind_with_time(
        deployment,
        pin,
        authority,
        limits,
        work,
        cx,
        kind,
        domain,
        capture_known,
    )?;
    work.charge(metadata.len() as u64 * 4)?;
    let mut decoder = CanonicalDecoder::new(&metadata);
    check_prefix_kind_with_time(&mut decoder, pin, domain, capture_known)?;
    let video_root = decoder.digest().map_err(storage)?;
    work.charge(u64::from(usize::BITS) + 1)?;
    if outer.children().binary_search(&video_root).is_err() {
        return Err(Error::Mismatch);
    }
    let bytes = read_part(deployment, pin, video_root, authority, work, cx)?;
    let video = ObjectManifest::from_canonical_bytes(&bytes).map_err(storage)?;
    work.charge(
        (video.children().len() as u64)
            .checked_mul(u64::from(usize::BITS) + 1)
            .ok_or(Error::Limit)?,
    )?;
    if video.root() != video_root
        || video.kind() != KIND
        || video
            .children()
            .iter()
            .any(|child| outer.children().binary_search(child).is_err())
    {
        return Err(Error::Mismatch);
    }
    let digest = video.metadata_digest().ok_or(Error::Mismatch)?;
    let video_metadata = read_part(deployment, pin, digest, authority, work, cx)?;
    Ok((outer, metadata, video, video_metadata))
}

/// Evidence that retained AAC bodies match the writer-profile A/V sample table.
/// This is not audio decoding, independent clock alignment, source
/// authentication, or proof of continuous coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvAudioSourceMapping {
    /// Whether the codec configuration had a retained in-band source record.
    pub configuration_origin: AudioConfigurationOrigin,
    /// Number of matching AAC bodies.
    pub frames: usize,
    /// Caller-bound AAC sample clock at the first body.
    pub first_decode_ticks: u64,
    /// Exclusive end of the contiguous caller-bound AAC sample clock.
    pub end_decode_ticks: u64,
    /// Sample rate declared by the configuration, not independently measured.
    pub sample_rate: u32,
}

/// A/V bytes recovered after source-mapping and writer-profile checks.
/// Capture, identity, codec decoding and independent synchronization remain
/// separate claims; audio configuration provenance is exposed explicitly.
#[must_use]
pub struct RecoveredAvClip {
    bytes: Vec<u8>,
    capture: CaptureInterval,
    video_samples: usize,
    audio: AvAudioSourceMapping,
    initialization_len: usize,
    continuity: VideoContinuity,
}
impl RecoveredAvClip {
    /// Two-track initialization followed by its checked media fragment.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Transfer the authorized media bytes to the caller.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    /// Caller-supplied bounds encoded in the ledgered root.
    pub fn capture(&self) -> CaptureInterval {
        self.capture
    }
    /// Structurally checked video sample count, not a decode guarantee.
    pub fn video_samples(&self) -> usize {
        self.video_samples
    }
    /// Checked audio source mapping and configuration provenance.
    pub fn audio(&self) -> AvAudioSourceMapping {
        self.audio
    }
}
impl fmt::Debug for RecoveredAvClip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredAvClip")
            .field("bytes", &"<redacted>")
            .field("capture", &self.capture)
            .field("video_samples", &self.video_samples)
            .field("audio", &self.audio)
            .finish()
    }
}

/// A source-checked A/V derivative whose physical capture time is unknown.
/// No physical interval or temporal coverage is inferred from its ledger entry.
#[must_use]
pub struct RecoveredUnknownTimeAvClip {
    bytes: Vec<u8>,
    video_samples: usize,
    audio: AvAudioSourceMapping,
    source: fss_container::flv_avc::SourceKey,
    initialization_len: usize,
    continuity: VideoContinuity,
}
impl RecoveredUnknownTimeAvClip {
    /// Two-track initialization followed by the checked media fragment.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Transfer the authorized media bytes to the caller.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    /// Structurally checked video samples, not a decoder guarantee.
    pub fn video_samples(&self) -> usize {
        self.video_samples
    }
    /// Checked audio source mapping and configuration provenance.
    pub fn audio(&self) -> AvAudioSourceMapping {
        self.audio
    }
    /// Caller-bound connection and generation; this does not authenticate a camera.
    pub fn claimed_source(&self) -> fss_container::flv_avc::SourceKey {
        self.source
    }
}
impl fmt::Debug for RecoveredUnknownTimeAvClip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredUnknownTimeAvClip")
            .field("bytes", &"<redacted>")
            .field("video_samples", &self.video_samples)
            .field("audio", &self.audio)
            .finish()
    }
}

/// Owner-selected bounds for assembling checked A/V archive fragments.
#[derive(Clone, Copy, Debug)]
pub struct AvSequenceLimits {
    /// At most 32 independently authorized roots.
    pub max_fragments: usize,
    /// At most 128 MiB of returned initialization and fragment bytes.
    pub max_bytes: usize,
}

/// Per-root metadata retained alongside a recovered multi-fragment derivative.
#[derive(Clone, Copy, Debug)]
pub struct RecoveredAvPart {
    /// The exact independently ledgered root and caller-supplied capture bounds.
    pub pin: Pin,
    /// Number of structurally checked video samples.
    pub video_samples: usize,
    /// Source mapping and configuration provenance for this fragment.
    pub audio: AvAudioSourceMapping,
}

/// A bounded derivative assembled from independently verified A/V roots.
/// Contiguous local source and decode coordinates do not establish physical
/// capture continuity, camera identity, or synchronization.
#[must_use]
pub struct RecoveredAvSequence {
    bytes: Vec<u8>,
    parts: Vec<RecoveredAvPart>,
}
impl RecoveredAvSequence {
    /// One checked initialization followed by the checked media fragments.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Transfer the authorized derivative bytes to the caller.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    /// Ordered root identities and per-fragment provenance.
    pub fn parts(&self) -> &[RecoveredAvPart] {
        &self.parts
    }
}
impl fmt::Debug for RecoveredAvSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredAvSequence")
            .field("bytes", &"<redacted>")
            .field("parts", &self.parts)
            .finish()
    }
}

/// Read and join ordered, individually ledgered A/V fragments. This fails
/// closed on a missing root, access denial, changed initialization, sequence or
/// source discontinuity, or discontinuous audio/video decode clocks. Claimed
/// connection keys, media timestamps and supplied capture bounds are not an
/// independent camera identity, physical coverage, or A/V synchronization.
pub fn read_av_sequence(
    deployment: &mut ReferenceDeployment,
    pins: &[Pin],
    authority: &dyn ReadAuthority,
    limits: Limits,
    sequence_limits: AvSequenceLimits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecoveredAvSequence, Error> {
    if !(1..=32).contains(&sequence_limits.max_fragments)
        || !(1..=128 * 1024 * 1024).contains(&sequence_limits.max_bytes)
        || pins.is_empty()
        || pins.len() > sequence_limits.max_fragments
    {
        return Err(Error::Limit);
    }
    let mut bytes = Vec::new();
    let mut parts = Vec::new();
    parts
        .try_reserve_exact(pins.len())
        .map_err(|_| Error::Limit)?;
    let mut previous: Option<(VideoContinuity, AvAudioSourceMapping)> = None;
    let mut initialization_len = 0;
    for &pin in pins {
        let clip = read_av_clip(deployment, pin, authority, limits, work, cx)?;
        let init = clip
            .bytes
            .get(..clip.initialization_len)
            .ok_or(Error::Mismatch)?;
        let fragment = clip
            .bytes
            .get(clip.initialization_len..)
            .ok_or(Error::Mismatch)?;
        if let Some((last, audio)) = previous.as_ref() {
            let current = &clip.continuity;
            work.charge(u64::try_from(last.lookahead.len()).map_err(|_| Error::Limit)?)?;
            if last.connection != current.connection
                || last.generation != current.generation
                || last.sequence.checked_add(1) != Some(current.sequence)
                || last.end_decode != current.first_decode
                || !current.records.starts_with(&last.lookahead)
                || audio.end_decode_ticks != clip.audio.first_decode_ticks
                || audio.sample_rate != clip.audio.sample_rate
                || initialization_len != init.len()
                || bytes.get(..initialization_len) != Some(init)
            {
                return Err(Error::Mismatch);
            }
        } else {
            initialization_len = init.len();
            if init
                .len()
                .checked_add(fragment.len())
                .is_none_or(|n| n > sequence_limits.max_bytes)
            {
                return Err(Error::Limit);
            }
            work.charge(u64::try_from(init.len()).map_err(|_| Error::Limit)?)?;
            bytes
                .try_reserve_exact(init.len())
                .map_err(|_| Error::Limit)?;
            bytes.extend_from_slice(init);
        }
        if bytes
            .len()
            .checked_add(fragment.len())
            .is_none_or(|n| n > sequence_limits.max_bytes)
        {
            return Err(Error::Limit);
        }
        work.charge(u64::try_from(fragment.len()).map_err(|_| Error::Limit)?)?;
        bytes
            .try_reserve(fragment.len())
            .map_err(|_| Error::Limit)?;
        bytes.extend_from_slice(fragment);
        parts.push(RecoveredAvPart {
            pin,
            video_samples: clip.video_samples,
            audio: clip.audio,
        });
        previous = Some((clip.continuity, clip.audio));
    }
    // Recheck every root and its authority after assembly. These checks are
    // sequential observations, not a claim of an atomic multi-root snapshot.
    for &pin in pins {
        let _ = open_graph_kind(
            deployment,
            pin,
            authority,
            limits,
            work,
            cx,
            av_evidence::KIND,
            av_evidence::DOMAIN,
        )?;
    }
    Ok(RecoveredAvSequence { bytes, parts })
}

struct StoredAudioMapping {
    source: std::ops::Range<u64>,
    target: std::ops::Range<usize>,
    decode_ticks: u64,
    duration_ticks: u32,
}

/// Recheck every retained audio source tag against its emitted AAC body.
/// The A/V fragment remains in private memory and no media bytes are returned.
/// The generated initialization and audio fragment table are checked against
/// the writer's supported profile. A/V sync and decodability are not checked.
pub fn verify_av_audio_source_mapping(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<AvAudioSourceMapping, Error> {
    Ok(verify_av_graph(deployment, pin, authority, limits, work, cx)?.audio)
}

struct VerifiedAvGraph {
    audio: AvAudioSourceMapping,
    video_samples: usize,
    initialization_digest: ContentDigest,
    initialization_len: usize,
    fragment_digest: ContentDigest,
    fragment_len: usize,
    continuity: VideoContinuity,
}

/// Recover the two-track derivative after checking its retained video, audio
/// source ranges, configuration class and the supported writer-profile table.
/// This neither decodes the samples nor authenticates or synchronizes the camera.
/// No bytes are returned after policy revocation or content mismatch.
pub fn read_av_clip(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecoveredAvClip, Error> {
    read_av_clip_with_time(deployment, pin, authority, limits, work, cx, true)
}

/// Recover a source-checked A/V derivative without inventing capture bounds.
/// Audio configuration provenance and structural mappings are retained; this
/// does not establish device identity, decoding, coverage or synchronization.
pub fn read_unknown_time_av_clip(
    deployment: &mut ReferenceDeployment,
    pin: UnknownTimePin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecoveredUnknownTimeAvClip, Error> {
    let clip = read_av_clip_with_time(
        deployment,
        pin.access_pin(),
        authority,
        limits,
        work,
        cx,
        false,
    )?;
    Ok(RecoveredUnknownTimeAvClip {
        bytes: clip.bytes,
        video_samples: clip.video_samples,
        audio: clip.audio,
        initialization_len: clip.initialization_len,
        source: fss_container::flv_avc::SourceKey {
            connection: clip.continuity.connection,
            generation: clip.continuity.generation,
        },
        continuity: clip.continuity,
    })
}

/// A source-checked unknown-time segment with its actual stored profile.
#[must_use]
pub enum RecoveredUnknownTimeAv {
    /// The fragment includes mapped audio samples.
    AudioVideo(RecoveredUnknownTimeAvClip),
    /// The fragment has no emitted audio samples; coverage remains unknown.
    VideoOnly(RecoveredUnknownTimeAvVideoOnly),
}

impl RecoveredUnknownTimeAv {
    /// Caller-supplied connection and generation claim, not device identity.
    pub fn claimed_source(&self) -> fss_container::flv_avc::SourceKey {
        match self {
            Self::AudioVideo(clip) => clip.claimed_source(),
            Self::VideoOnly(clip) => clip.claimed_source(),
        }
    }
}

/// Recover either supported profile, using the digest-checked root kind to
/// select its full ledger and source verification. No error triggers fallback.
pub fn read_unknown_time_av_any(
    deployment: &mut ReferenceDeployment,
    pin: UnknownTimePin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecoveredUnknownTimeAv, Error> {
    let bound = limits
        .maximum_spool_object_bytes
        .min(deployment.publisher().limits().spool.max_object_bytes);
    let root = read_part_bounded(
        deployment,
        pin.access_pin(),
        pin.root,
        bound,
        authority,
        work,
        cx,
    )?;
    let manifest = ObjectManifest::from_canonical_bytes(&root).map_err(storage)?;
    if manifest.root() != pin.root {
        return Err(Error::Mismatch);
    }
    match manifest.kind() {
        av_evidence::KIND => {
            read_unknown_time_av_clip(deployment, pin, authority, limits, work, cx)
                .map(RecoveredUnknownTimeAv::AudioVideo)
        }
        av_evidence::VIDEO_ONLY_KIND => {
            read_unknown_time_av_video_only_clip(deployment, pin, authority, limits, work, cx)
                .map(RecoveredUnknownTimeAv::VideoOnly)
        }
        _ => Err(Error::Mismatch),
    }
}

/// One checked root in an unknown-time sequence. `None` does not establish
/// audio absence or coverage; it identifies a video-only derivative.
#[derive(Clone, Copy, Debug)]
pub struct RecoveredUnknownTimeAvPart {
    /// Exact separately authorized root.
    pub pin: UnknownTimePin,
    /// Structurally checked video samples.
    pub video_samples: usize,
    /// Checked audio mapping, if the derivative contains audio samples.
    pub audio: Option<AvAudioSourceMapping>,
}

/// A bounded sequence of independently checked unknown-time fragments.
#[must_use]
pub struct RecoveredUnknownTimeAvSequence {
    bytes: Vec<u8>,
    parts: Vec<RecoveredUnknownTimeAvPart>,
}
impl RecoveredUnknownTimeAvSequence {
    /// One checked initialization followed by the ordered media fragments.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Transfer the authorized media derivative.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    /// Ordered roots and their source-mapping claims.
    pub fn parts(&self) -> &[RecoveredUnknownTimeAvPart] {
        &self.parts
    }
}
impl fmt::Debug for RecoveredUnknownTimeAvSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredUnknownTimeAvSequence")
            .field("bytes", &"<redacted>")
            .field("parts", &self.parts)
            .finish()
    }
}

/// Join unknown-time roots only when their independently verified source and
/// video coordinates are contiguous and their initialization is identical.
/// A video-only root is allowed only as the first fragment; later audio roots
/// must have contiguous decode clocks. Every copied lookahead record must
/// exactly match the corresponding prefix of the following source records.
/// These checks do not establish physical time, camera identity, A/V sync or
/// audio coverage. Authorities are rechecked after assembly, not atomically.
pub fn read_unknown_time_av_sequence(
    deployment: &mut ReferenceDeployment,
    pins: &[UnknownTimePin],
    authority: &dyn ReadAuthority,
    limits: Limits,
    sequence_limits: AvSequenceLimits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecoveredUnknownTimeAvSequence, Error> {
    if !(1..=32).contains(&sequence_limits.max_fragments)
        || !(1..=128 * 1024 * 1024).contains(&sequence_limits.max_bytes)
        || pins.is_empty()
        || pins.len() > sequence_limits.max_fragments
    {
        return Err(Error::Limit);
    }
    let mut bytes = Vec::new();
    let mut parts = Vec::new();
    parts
        .try_reserve_exact(pins.len())
        .map_err(|_| Error::Limit)?;
    let mut previous: Option<(VideoContinuity, Option<AvAudioSourceMapping>)> = None;
    let mut initialization_len = 0;
    for &pin in pins {
        let (media, init_len, continuity, audio, video_samples) =
            match read_unknown_time_av_any(deployment, pin, authority, limits, work, cx)? {
                RecoveredUnknownTimeAv::AudioVideo(clip) => (
                    clip.bytes,
                    clip.initialization_len,
                    clip.continuity,
                    Some(clip.audio),
                    clip.video_samples,
                ),
                RecoveredUnknownTimeAv::VideoOnly(clip) => (
                    clip.bytes,
                    clip.initialization_len,
                    clip.continuity,
                    None,
                    clip.samples,
                ),
            };
        let init = media.get(..init_len).ok_or(Error::Mismatch)?;
        let fragment = media.get(init_len..).ok_or(Error::Mismatch)?;
        if let Some((last, last_audio)) = &previous {
            work.charge(u64::try_from(last.lookahead.len()).map_err(|_| Error::Limit)?)?;
            if audio.is_none()
                || last.connection != continuity.connection
                || last.generation != continuity.generation
                || last.sequence.checked_add(1) != Some(continuity.sequence)
                || last.end_decode != continuity.first_decode
                || !continuity.records.starts_with(&last.lookahead)
                || initialization_len != init.len()
                || bytes.get(..initialization_len) != Some(init)
                || last_audio.zip(audio).is_some_and(|(a, b)| {
                    a.end_decode_ticks != b.first_decode_ticks || a.sample_rate != b.sample_rate
                })
            {
                return Err(Error::Mismatch);
            }
        } else {
            initialization_len = init.len();
            if init
                .len()
                .checked_add(fragment.len())
                .is_none_or(|n| n > sequence_limits.max_bytes)
            {
                return Err(Error::Limit);
            }
            work.charge(u64::try_from(init.len()).map_err(|_| Error::Limit)?)?;
            bytes
                .try_reserve_exact(init.len())
                .map_err(|_| Error::Limit)?;
            bytes.extend_from_slice(init);
        }
        if bytes
            .len()
            .checked_add(fragment.len())
            .is_none_or(|n| n > sequence_limits.max_bytes)
        {
            return Err(Error::Limit);
        }
        work.charge(u64::try_from(fragment.len()).map_err(|_| Error::Limit)?)?;
        bytes
            .try_reserve(fragment.len())
            .map_err(|_| Error::Limit)?;
        bytes.extend_from_slice(fragment);
        parts.push(RecoveredUnknownTimeAvPart {
            pin,
            video_samples,
            audio,
        });
        previous = Some((continuity, audio));
    }
    for part in &parts {
        let (kind, domain) = if part.audio.is_some() {
            (av_evidence::KIND, av_evidence::DOMAIN)
        } else {
            (av_evidence::VIDEO_ONLY_KIND, av_evidence::VIDEO_ONLY_DOMAIN)
        };
        let _ = open_graph_kind_with_time(
            deployment,
            part.pin.access_pin(),
            authority,
            limits,
            work,
            cx,
            kind,
            domain,
            false,
        )?;
    }
    Ok(RecoveredUnknownTimeAvSequence { bytes, parts })
}

/// An authorized, source-checked video-only fragment under an A/V initialization.
/// It reports no emitted audio sample; audio coverage and capture time remain unknown.
#[must_use]
pub struct RecoveredUnknownTimeAvVideoOnly {
    bytes: Vec<u8>,
    samples: usize,
    source: fss_container::flv_avc::SourceKey,
    configuration_origin: AudioConfigurationOrigin,
    initialization_len: usize,
    continuity: VideoContinuity,
}
impl RecoveredUnknownTimeAvVideoOnly {
    /// Two-track initialization followed by a video-only media fragment.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Transfer authorized media bytes to the caller.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    /// Number of structurally verified video samples, not a decoder guarantee.
    pub fn video_samples(&self) -> usize {
        self.samples
    }
    /// Caller-supplied connection and generation claim, not device identity.
    pub fn claimed_source(&self) -> fss_container::flv_avc::SourceKey {
        self.source
    }
    /// Provenance of the AAC configuration, not proof of emitted audio.
    pub fn configuration_origin(&self) -> AudioConfigurationOrigin {
        self.configuration_origin
    }
}
impl fmt::Debug for RecoveredUnknownTimeAvVideoOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveredUnknownTimeAvVideoOnly")
            .field("bytes", &"<redacted>")
            .field("samples", &self.samples)
            .field("configuration_origin", &self.configuration_origin)
            .finish_non_exhaustive()
    }
}

/// Reopen a ledgered video-only A/V graph with explicitly unknown capture time.
/// Every source record in the owned segment is rechecked to contain no audio
/// tag; the copied lookahead is verified as part of the nested video graph but
/// remains on the next segment's side. This does not prove audio absence,
/// physical capture time, identity, synchronization, decoding or coverage.
pub fn read_unknown_time_av_video_only_clip(
    deployment: &mut ReferenceDeployment,
    pin: UnknownTimePin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<RecoveredUnknownTimeAvVideoOnly, Error> {
    use fss_packet::extended_flv::aac;
    let access = pin.access_pin();
    let configuration = read_av_audio_configuration_profile(
        deployment, access, authority, limits, work, cx, false, true,
    )?;
    let (outer, metadata, video, video_metadata) =
        open_av_video_graph_profile(deployment, access, authority, limits, work, cx, false, true)?;
    let verified_video = recover_video_graph(
        deployment,
        access,
        &video,
        &video_metadata,
        authority,
        limits,
        work,
        cx,
        false,
    )?;
    work.charge(metadata.len() as u64 * 4)?;
    let mut d = CanonicalDecoder::new(&metadata);
    check_prefix_kind_with_time(&mut d, access, av_evidence::VIDEO_ONLY_DOMAIN, false)?;
    if d.digest().map_err(storage)? != video.root()
        || d.u8().map_err(storage)? != 0
        || d.bool().map_err(storage)?
    {
        return Err(Error::Mismatch);
    }
    let config_record_end = match d.u8().map_err(storage)? {
        0 if configuration.origin == AudioConfigurationOrigin::InBand => {
            if Some(d.u64().map_err(storage)?) != configuration.claimed_epoch {
                return Err(Error::Mismatch);
            }
            let entry = record(&mut d, limits.maximum_spool_object_bytes)?;
            let _start = d.u64().map_err(storage)?;
            let _end = d.u64().map_err(storage)?;
            Some(
                entry
                    .offset
                    .checked_add(entry.length as u64)
                    .ok_or(Error::Limit)?,
            )
        }
        1 if configuration.origin == AudioConfigurationOrigin::SuppliedUnverified => None,
        _ => return Err(Error::Mismatch),
    };
    if d.digest().map_err(storage)? != configuration.digest {
        return Err(Error::Mismatch);
    }
    let initialization_digest = d.digest().map_err(storage)?;
    let initialization_len = read_size(&mut d, limits.maximum_spool_object_bytes)?;
    let fragment_digest = d.digest().map_err(storage)?;
    let fragment_len = read_size(&mut d, limits.maximum_spool_object_bytes)?;
    if d.u64().map_err(storage)? != 0
        || d.u64().map_err(storage)? != 0
        || initialization_len == 0
        || fragment_len == 0
        || outer
            .children()
            .binary_search(&initialization_digest)
            .is_err()
        || outer.children().binary_search(&fragment_digest).is_err()
    {
        return Err(Error::Mismatch);
    }
    d.ensure_finished().map_err(storage)?;
    let config_bytes = read_part_bounded(
        deployment,
        access,
        configuration.digest,
        aac::MAX_SUPPORTED_CONFIGURATION_BYTES,
        authority,
        work,
        cx,
    )?;
    let config = aac::Configuration::parse_explicit(&config_bytes).map_err(storage)?;
    let mut initialization = read_part_bounded(
        deployment,
        access,
        initialization_digest,
        initialization_len,
        authority,
        work,
        cx,
    )?;
    let fragment = read_part_bounded(
        deployment,
        access,
        fragment_digest,
        fragment_len,
        authority,
        work,
        cx,
    )?;
    if initialization.len() != initialization_len || fragment.len() != fragment_len {
        return Err(Error::Mismatch);
    }
    let mp4_limits = fss_container::Mp4Limits::default();
    work.charge(
        (verified_video.bytes().len() as u64)
            .checked_add(initialization.len() as u64)
            .and_then(|n| n.checked_add(fragment.len() as u64))
            .and_then(|n| n.checked_mul(4))
            .ok_or(Error::Limit)?,
    )?;
    fss_container::flv_av::verify_archived_initialization(
        verified_video.bytes(),
        &initialization,
        &config,
        mp4_limits,
    )
    .map_err(storage)?;
    work.charge(
        (video_metadata.len() as u64)
            .checked_mul(4)
            .ok_or(Error::Limit)?,
    )?;
    let mut v = CanonicalDecoder::new(&video_metadata);
    check_prefix_kind_with_time(&mut v, access, DOMAIN, false)?;
    let _connection = v.u64().map_err(storage)?;
    let _generation = v.u64().map_err(storage)?;
    let _sequence = v.u32().map_err(storage)?;
    let _configuration = record(&mut v, limits.maximum_spool_object_bytes)?;
    let _video_initialization_digest = v.digest().map_err(storage)?;
    let video_initialization_len = read_size(&mut v, limits.maximum_spool_object_bytes)?;
    let video_fragment_digest = v.digest().map_err(storage)?;
    let video_fragment_len = read_size(&mut v, limits.maximum_spool_object_bytes)?;
    let source_count = read_size(&mut v, 8192)?;
    if source_count == 0 {
        return Err(Error::Mismatch);
    }
    for index in 0..source_count {
        work.charge(1)?;
        let entry = record(&mut v, limits.maximum_spool_object_bytes)?;
        if index == 0 && config_record_end.is_some_and(|end| end > entry.offset) {
            return Err(Error::Mismatch);
        }
        // `recover_video_graph` already verifies each record and claimed kind.
        // Audio types cannot be silently omitted from this segment's derivative.
        if entry
            .tag
            .is_some_and(|(_, kind, _)| kind == 8 || kind == 10)
        {
            return Err(Error::Mismatch);
        }
    }
    let video_fragment = verified_video
        .bytes()
        .get(video_initialization_len..)
        .ok_or(Error::Mismatch)?;
    if video_fragment.len() != video_fragment_len
        || ContentDigest::sha256(video_fragment) != video_fragment_digest
    {
        return Err(Error::Mismatch);
    }
    fss_container::flv_av::verify_archived_video_only_fragment(
        video_fragment,
        &fragment,
        mp4_limits,
    )
    .map_err(storage)?;
    let total = initialization_len
        .checked_add(fragment_len)
        .filter(|n| *n <= 129 * 1024 * 1024)
        .ok_or(Error::Limit)?;
    work.charge((total as u64).checked_mul(2).ok_or(Error::Limit)?)?;
    initialization
        .try_reserve_exact(fragment.len())
        .map_err(|_| Error::Limit)?;
    initialization.extend_from_slice(&fragment);
    read_authorize(access, authority, cx)?;
    Ok(RecoveredUnknownTimeAvVideoOnly {
        bytes: initialization,
        samples: verified_video.samples(),
        source: fss_container::flv_avc::SourceKey {
            connection: verified_video.continuity.connection,
            generation: verified_video.continuity.generation,
        },
        configuration_origin: configuration.origin,
        initialization_len,
        continuity: verified_video.continuity,
    })
}

fn read_av_clip_with_time(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    capture_known: bool,
) -> Result<RecoveredAvClip, Error> {
    let verified =
        verify_av_graph_with_time(deployment, pin, authority, limits, work, cx, capture_known)?;
    let media_len = verified
        .initialization_len
        .checked_add(verified.fragment_len)
        .ok_or(Error::Limit)?;
    if media_len > 129 * 1024 * 1024 {
        return Err(Error::Limit);
    }
    let mut bytes = read_part_bounded(
        deployment,
        pin,
        verified.initialization_digest,
        verified.initialization_len,
        authority,
        work,
        cx,
    )?;
    let fragment = read_part_bounded(
        deployment,
        pin,
        verified.fragment_digest,
        verified.fragment_len,
        authority,
        work,
        cx,
    )?;
    if bytes.len() != verified.initialization_len || fragment.len() != verified.fragment_len {
        return Err(Error::Mismatch);
    }
    work.charge((media_len as u64).checked_mul(2).ok_or(Error::Limit)?)?;
    bytes
        .try_reserve_exact(fragment.len())
        .map_err(|_| Error::Limit)?;
    bytes.extend_from_slice(&fragment);
    read_authorize(pin, authority, cx)?;
    Ok(RecoveredAvClip {
        bytes,
        capture: pin.capture,
        video_samples: verified.video_samples,
        audio: verified.audio,
        initialization_len: verified.initialization_len,
        continuity: verified.continuity,
    })
}

fn verify_av_graph(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<VerifiedAvGraph, Error> {
    verify_av_graph_with_time(deployment, pin, authority, limits, work, cx, true)
}

fn verify_av_graph_with_time(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    capture_known: bool,
) -> Result<VerifiedAvGraph, Error> {
    use fss_packet::extended_flv::{self, Parse, Tag, aac};

    let configuration = read_av_audio_configuration_with_time(
        deployment,
        pin,
        authority,
        limits,
        work,
        cx,
        capture_known,
    )?;
    let (outer, metadata, video, video_metadata) =
        open_av_video_graph_with_time(deployment, pin, authority, limits, work, cx, capture_known)?;
    let verified_video = recover_video_graph(
        deployment,
        pin,
        &video,
        &video_metadata,
        authority,
        limits,
        work,
        cx,
        capture_known,
    )?;
    work.charge(metadata.len() as u64 * 4)?;
    let mut d = CanonicalDecoder::new(&metadata);
    check_prefix_kind_with_time(&mut d, pin, av_evidence::DOMAIN, capture_known)?;
    if d.digest().map_err(storage)? != video.root() {
        return Err(Error::Mismatch);
    }
    match d.u8().map_err(storage)? {
        0 if configuration.origin == AudioConfigurationOrigin::InBand => {
            if Some(d.u64().map_err(storage)?) != configuration.claimed_epoch {
                return Err(Error::Mismatch);
            }
            let _ = record(&mut d, limits.maximum_spool_object_bytes)?;
            let _ = d.u64().map_err(storage)?;
            let _ = d.u64().map_err(storage)?;
        }
        1 if configuration.origin == AudioConfigurationOrigin::SuppliedUnverified => {}
        _ => return Err(Error::Mismatch),
    }
    if d.digest().map_err(storage)? != configuration.digest {
        return Err(Error::Mismatch);
    }
    let initialization_digest = d.digest().map_err(storage)?;
    let initialization_len = read_size(&mut d, limits.maximum_spool_object_bytes)?;
    let fragment_digest = d.digest().map_err(storage)?;
    let fragment_len = read_size(&mut d, limits.maximum_spool_object_bytes)?;
    let video_shift = read_size(&mut d, fragment_len)?;
    work.charge(2 * (u64::from(usize::BITS) + 1))?;
    if initialization_len == 0
        || fragment_len == 0
        || outer
            .children()
            .binary_search(&initialization_digest)
            .is_err()
        || outer.children().binary_search(&fragment_digest).is_err()
    {
        return Err(Error::Mismatch);
    }
    let count = read_size(&mut d, 8192)?;
    if count == 0 || count > 4096 {
        return Err(Error::Mismatch);
    }
    if count.checked_mul(8).and_then(|n| n.checked_add(64)) != Some(video_shift) {
        return Err(Error::Mismatch);
    }
    let mut mappings = Vec::new();
    mappings
        .try_reserve_exact(count)
        .map_err(|_| Error::Limit)?;
    for _ in 0..count {
        let source = d.u64().map_err(storage)?..d.u64().map_err(storage)?;
        let target = read_size(&mut d, fragment_len)?..read_size(&mut d, fragment_len)?;
        let decode_ticks = d.u64().map_err(storage)?;
        let duration_ticks = d.u32().map_err(storage)?;
        if source.start >= source.end || target.start >= target.end || duration_ticks == 0 {
            return Err(Error::Mismatch);
        }
        mappings.push(StoredAudioMapping {
            source,
            target,
            decode_ticks,
            duration_ticks,
        });
    }
    d.ensure_finished().map_err(storage)?;
    let fragment = read_part_bounded(
        deployment,
        pin,
        fragment_digest,
        fragment_len,
        authority,
        work,
        cx,
    )?;
    if fragment.len() != fragment_len {
        return Err(Error::Mismatch);
    }
    let config_bytes = read_part_bounded(
        deployment,
        pin,
        configuration.digest,
        aac::MAX_SUPPORTED_CONFIGURATION_BYTES,
        authority,
        work,
        cx,
    )?;
    let config = aac::Configuration::parse_explicit(&config_bytes).map_err(storage)?;
    let initialization = read_part_bounded(
        deployment,
        pin,
        initialization_digest,
        initialization_len,
        authority,
        work,
        cx,
    )?;
    if initialization.len() != initialization_len {
        return Err(Error::Mismatch);
    }
    let mp4_limits = fss_container::Mp4Limits {
        max_samples: 4096,
        max_nals: 65_536,
        max_source_spans: 262_144,
        max_fragment_bytes: 128 * 1024 * 1024,
        max_initialization_bytes: 1024 * 1024,
    };
    work.charge(
        (verified_video.bytes().len() as u64)
            .checked_add(initialization.len() as u64)
            .and_then(|n| n.checked_mul(4))
            .ok_or(Error::Limit)?,
    )?;
    fss_container::flv_av::verify_archived_initialization(
        verified_video.bytes(),
        &initialization,
        &config,
        mp4_limits,
    )
    .map_err(storage)?;

    work.charge(video_metadata.len() as u64 * 4)?;
    let mut source = CanonicalDecoder::new(&video_metadata);
    check_prefix_kind_with_time(&mut source, pin, DOMAIN, capture_known)?;
    if source.u64().map_err(storage)? == 0
        || source.u64().map_err(storage)? == 0
        || source.u32().map_err(storage)? == 0
    {
        return Err(Error::Mismatch);
    }
    let _ = record(&mut source, limits.maximum_spool_object_bytes)?;
    let _ = source.digest().map_err(storage)?;
    let _ = read_size(&mut source, limits.maximum_spool_object_bytes)?;
    let video_fragment_digest = source.digest().map_err(storage)?;
    let video_fragment_len = read_size(&mut source, limits.maximum_spool_object_bytes)?;
    work.charge(u64::from(usize::BITS) + 1)?;
    if video
        .children()
        .binary_search(&video_fragment_digest)
        .is_err()
    {
        return Err(Error::Mismatch);
    }
    let video_fragment = read_part_bounded(
        deployment,
        pin,
        video_fragment_digest,
        video_fragment_len,
        authority,
        work,
        cx,
    )?;
    if video_fragment.len() != video_fragment_len {
        return Err(Error::Mismatch);
    }
    let mut container_mappings = Vec::new();
    container_mappings
        .try_reserve_exact(count)
        .map_err(|_| Error::Limit)?;
    for mapping in &mappings {
        container_mappings.push(fss_container::flv_av::AudioMapping {
            source: mapping.source.clone(),
            target: mapping.target.clone(),
            decode_ticks: mapping.decode_ticks,
            duration_ticks: u16::try_from(mapping.duration_ticks).map_err(|_| Error::Limit)?,
        });
    }
    work.charge(
        (video_fragment.len() as u64)
            .checked_add(fragment.len() as u64)
            .and_then(|n| n.checked_mul(4))
            .ok_or(Error::Limit)?,
    )?;
    fss_container::flv_av::verify_archived_fragment(
        &video_fragment,
        &fragment,
        &container_mappings,
        mp4_limits,
    )
    .map_err(storage)?;
    let source_count = read_size(&mut source, 8192)?;
    if source_count == 0 {
        return Err(Error::Mismatch);
    }
    let mut index = 0usize;
    let mut next_offset = None;
    let mut previous_target = None;
    let mut previous_tick = None;
    let mut previous_sender: Option<u32> = None;
    for _ in 0..source_count {
        let entry = record(&mut source, limits.maximum_spool_object_bytes)?;
        work.charge(u64::from(usize::BITS) + 1)?;
        if video.children().binary_search(&entry.digest).is_err()
            || next_offset.is_some_and(|offset| offset != entry.offset)
        {
            return Err(Error::Mismatch);
        }
        next_offset = Some(
            entry
                .offset
                .checked_add(entry.length as u64)
                .ok_or(Error::Limit)?,
        );
        let bytes = checked_record_bytes(deployment, pin, &entry, authority, work, cx)?;
        let Some((tag_offset, kind, timestamp)) = entry.tag else {
            let Parse::Complete(header) =
                extended_flv::Header::parse(&bytes, extended_flv::Limits::default())
                    .map_err(storage)?
            else {
                return Err(Error::Mismatch);
            };
            if header.wire_bytes().len() != bytes.len() {
                return Err(Error::Mismatch);
            }
            continue;
        };
        let tag_bytes = bytes.get(tag_offset..).ok_or(Error::Mismatch)?;
        let Parse::Complete(tag) =
            Tag::parse(tag_bytes, extended_flv::Limits::default()).map_err(storage)?
        else {
            return Err(Error::Mismatch);
        };
        if tag.wire_bytes().len() != tag_bytes.len()
            || tag.kind() != kind
            || tag.timestamp_ms() != timestamp
            || kind == 10
        {
            return Err(Error::Mismatch);
        }
        if kind != 8 {
            continue;
        }
        let audio = aac::AudioTag::parse(tag, aac::Limits::default()).map_err(storage)?;
        if audio.packet_type() != aac::PacketType::Raw {
            return Err(Error::Mismatch);
        }
        let mapping = mappings.get(index).ok_or(Error::Mismatch)?;
        let body = audio.body_range();
        let base = entry
            .offset
            .checked_add(tag_offset as u64)
            .ok_or(Error::Limit)?;
        let start = base.checked_add(body.start as u64).ok_or(Error::Limit)?;
        let end = base.checked_add(body.end as u64).ok_or(Error::Limit)?;
        if mapping.source != (start..end)
            || fragment.get(mapping.target.clone()) != Some(audio.body())
            || mapping.duration_ticks != u32::from(config.frame_samples())
            || previous_target.is_some_and(|end| end != mapping.target.start)
            || previous_tick.is_some_and(|end| end != mapping.decode_ticks)
            || previous_sender.is_some_and(|last| {
                let delta = timestamp.wrapping_sub(last);
                delta == 0 || delta >= (1 << 31)
            })
        {
            return Err(Error::Mismatch);
        }
        previous_target = Some(mapping.target.end);
        previous_tick = Some(
            mapping
                .decode_ticks
                .checked_add(u64::from(mapping.duration_ticks))
                .ok_or(Error::Limit)?,
        );
        previous_sender = Some(timestamp);
        index = index.checked_add(1).ok_or(Error::Limit)?;
    }
    if index != count {
        return Err(Error::Mismatch);
    }
    read_authorize(pin, authority, cx)?;
    Ok(VerifiedAvGraph {
        audio: AvAudioSourceMapping {
            configuration_origin: configuration.origin,
            frames: count,
            first_decode_ticks: mappings[0].decode_ticks,
            end_decode_ticks: previous_tick.ok_or(Error::Mismatch)?,
            sample_rate: config.sample_rate(),
        },
        video_samples: verified_video.samples(),
        initialization_digest,
        initialization_len,
        fragment_digest,
        fragment_len,
        continuity: verified_video.continuity,
    })
}

fn recover_video_graph(
    deployment: &mut ReferenceDeployment,
    pin: Pin,
    manifest: &ObjectManifest,
    metadata: &[u8],
    authority: &dyn ReadAuthority,
    limits: Limits,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
    capture_known: bool,
) -> Result<RecoveredClip, Error> {
    use fss_container::demux::{AvcMp4, DemuxLimits};
    use std::collections::BTreeSet;
    work.charge(metadata.len() as u64 * 4)?;
    let mut d = CanonicalDecoder::new(metadata);
    check_prefix_kind_with_time(&mut d, pin, DOMAIN, capture_known)?;
    let connection = d.u64().map_err(storage)?;
    let generation = d.u64().map_err(storage)?;
    let sequence = d.u32().map_err(storage)?;
    if connection == 0 || generation == 0 || sequence == 0 {
        return Err(Error::Mismatch);
    }
    let config = record(&mut d, limits.maximum_spool_object_bytes)?;
    let init_digest = d.digest().map_err(storage)?;
    let init_len = read_size(&mut d, limits.maximum_spool_object_bytes)?;
    let fragment_digest = d.digest().map_err(storage)?;
    let fragment_len = read_size(&mut d, limits.maximum_spool_object_bytes)?;
    let media_len = init_len.checked_add(fragment_len).ok_or(Error::Limit)?;
    if init_len == 0 || fragment_len == 0 || media_len > 128 * 1024 * 1024 {
        return Err(Error::Limit);
    }
    let mut children = BTreeSet::from([config.digest, init_digest, fragment_digest]);
    let source_count = read_size(&mut d, 8192)?;
    if source_count == 0 {
        return Err(Error::Mismatch);
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(source_count)
        .map_err(|_| Error::Limit)?;
    let mut total = config.length.checked_add(media_len).ok_or(Error::Limit)?;
    let mut next = None;
    for _ in 0..source_count {
        let item = record(&mut d, limits.maximum_spool_object_bytes)?;
        if next.is_some_and(|v| v != item.offset) {
            return Err(Error::Mismatch);
        }
        next = Some(
            item.offset
                .checked_add(item.length as u64)
                .ok_or(Error::Limit)?,
        );
        total = total.checked_add(item.length).ok_or(Error::Limit)?;
        children.insert(item.digest);
        records.push(item);
    }
    let witness_count = read_size(&mut d, 8192 - source_count)?;
    if witness_count == 0 {
        return Err(Error::Mismatch);
    }
    let mut witnesses = Vec::new();
    witnesses
        .try_reserve_exact(witness_count)
        .map_err(|_| Error::Limit)?;
    for _ in 0..witness_count {
        let item = record(&mut d, limits.maximum_spool_object_bytes)?;
        if next != Some(item.offset) {
            return Err(Error::Mismatch);
        }
        next = Some(
            item.offset
                .checked_add(item.length as u64)
                .ok_or(Error::Limit)?,
        );
        total = total.checked_add(item.length).ok_or(Error::Limit)?;
        children.insert(item.digest);
        witnesses.push(item);
    }
    if total > 256 * 1024 * 1024 {
        return Err(Error::Limit);
    }
    let count = read_size(&mut d, 4096)?;
    if count == 0 {
        return Err(Error::Mismatch);
    }
    let mut samples = Vec::new();
    samples.try_reserve_exact(count).map_err(|_| Error::Limit)?;
    for _ in 0..count {
        samples.push(StoredSample {
            start: read_size(&mut d, fragment_len)?,
            end: read_size(&mut d, fragment_len)?,
            decode: d.u64().map_err(storage)?,
            composition: d.i128().map_err(storage)?,
            duration: d.u32().map_err(storage)?,
            idr: d.bool().map_err(storage)?,
            first_nal: read_size(&mut d, 65_536)?,
            end_nal: read_size(&mut d, 65_536)?,
        });
    }
    let nal_count = read_size(&mut d, 65_536)?;
    if nal_count == 0 {
        return Err(Error::Mismatch);
    }
    let mut nals = Vec::new();
    nals.try_reserve_exact(nal_count)
        .map_err(|_| Error::Limit)?;
    for _ in 0..nal_count {
        nals.push(StoredNal {
            sample: read_size(&mut d, count - 1)?,
            source_start: d.u64().map_err(storage)?,
            source_end: d.u64().map_err(storage)?,
            start: read_size(&mut d, fragment_len)?,
            end: read_size(&mut d, fragment_len)?,
        });
    }
    if d.bool().map_err(storage)? {
        let start = d.u64().map_err(storage)?;
        let end = d.u64().map_err(storage)?;
        if start >= end {
            return Err(Error::Mismatch);
        }
    }
    d.ensure_finished().map_err(storage)?;
    children.insert(manifest.metadata_digest().ok_or(Error::Mismatch)?);
    if children
        .iter()
        .copied()
        .ne(manifest.children().iter().copied())
    {
        return Err(Error::Mismatch);
    }
    let config_bytes = checked_record_bytes(deployment, pin, &config, authority, work, cx)?;
    let (tag_offset, kind, timestamp) = config.tag.ok_or(Error::Mismatch)?;
    let tag_bytes = config_bytes.get(tag_offset..).ok_or(Error::Mismatch)?;
    let fss_packet::extended_flv::Parse::Complete(tag) = fss_packet::extended_flv::Tag::parse(
        tag_bytes,
        fss_packet::extended_flv::Limits::default(),
    )
    .map_err(storage)?
    else {
        return Err(Error::Mismatch);
    };
    if tag.wire_bytes().len() != tag_bytes.len()
        || tag.kind() != kind
        || tag.timestamp_ms() != timestamp
    {
        return Err(Error::Mismatch);
    }
    let source_config = fss_packet::extended_flv::avc::VideoTag::parse(tag)
        .map_err(storage)?
        .configuration(fss_packet::extended_flv::avc::Limits::default())
        .map_err(storage)?;
    let mut media = read_part_bounded(deployment, pin, init_digest, init_len, authority, work, cx)?;
    let fragment = read_part_bounded(
        deployment,
        pin,
        fragment_digest,
        fragment_len,
        authority,
        work,
        cx,
    )?;
    if media.len() != init_len || fragment.len() != fragment_len {
        return Err(Error::Mismatch);
    }
    if !fragment_sequence_matches(&fragment, sequence)
        || samples.windows(2).any(|pair| {
            pair[0].decode.checked_add(u64::from(pair[0].duration)) != Some(pair[1].decode)
        })
    {
        return Err(Error::Mismatch);
    }
    work.charge((media_len as u64).checked_mul(4).ok_or(Error::Limit)?)?;
    media
        .try_reserve_exact(fragment_len)
        .map_err(|_| Error::Limit)?;
    media.extend_from_slice(&fragment);
    let movie = AvcMp4::parse(&media, None, DemuxLimits::default()).map_err(storage)?;
    if movie.timescale() != 1000 || movie.nal_length_bytes() != 4 || movie.samples().len() != count
    {
        return Err(Error::Mismatch);
    }
    let mut source_sets = source_config.sps().chain(source_config.pps());
    for range in movie.parameter_sets() {
        let source = source_sets.next().ok_or(Error::Mismatch)?;
        if media.get(range.clone()) != Some(source.bytes()) {
            return Err(Error::Mismatch);
        }
    }
    if source_sets.next().is_some() {
        return Err(Error::Mismatch);
    }
    let mut nal_index = 0;
    for (index, (expected, actual)) in samples.iter().zip(movie.samples()).enumerate() {
        if expected.start >= expected.end
            || expected.first_nal != nal_index
            || expected.end_nal <= expected.first_nal
            || expected.end_nal > nals.len()
            || actual.source.start != init_len.checked_add(expected.start).ok_or(Error::Limit)?
            || actual.source.end != init_len.checked_add(expected.end).ok_or(Error::Limit)?
            || actual.decode_time != expected.decode
            || i128::from(actual.composition_offset) != expected.composition
            || actual.duration != expected.duration
            || actual.sync_sample != expected.idr
            || actual.contains_idr != expected.idr
        {
            return Err(Error::Mismatch);
        }
        let mut cursor = expected.start;
        for nal in &nals[expected.first_nal..expected.end_nal] {
            let prefix_end = cursor.checked_add(4).ok_or(Error::Limit)?;
            let prefix: [u8; 4] = fragment
                .get(cursor..prefix_end)
                .ok_or(Error::Mismatch)?
                .try_into()
                .map_err(|_| Error::Mismatch)?;
            if nal.sample != index
                || nal.start != prefix_end
                || nal.start >= nal.end
                || nal.end > expected.end
                || nal.source_start >= nal.source_end
                || u32::from_be_bytes(prefix) as usize != nal.end - nal.start
                || nal.source_end - nal.source_start != (nal.end - nal.start) as u64
            {
                return Err(Error::Mismatch);
            }
            cursor = nal.end;
        }
        if cursor != expected.end {
            return Err(Error::Mismatch);
        }
        nal_index = expected.end_nal;
    }
    if nal_index != nals.len() || !samples[0].idr {
        return Err(Error::Mismatch);
    }
    let mut index = 0;
    for entry in &records {
        let bytes = checked_record_bytes(deployment, pin, entry, authority, work, cx)?;
        let end = entry
            .offset
            .checked_add(entry.length as u64)
            .ok_or(Error::Limit)?;
        while let Some(nal) = nals.get(index) {
            if nal.source_start >= end {
                break;
            }
            let start = usize::try_from(
                nal.source_start
                    .checked_sub(entry.offset)
                    .ok_or(Error::Mismatch)?,
            )
            .map_err(|_| Error::Limit)?;
            let finish = usize::try_from(
                nal.source_end
                    .checked_sub(entry.offset)
                    .ok_or(Error::Mismatch)?,
            )
            .map_err(|_| Error::Limit)?;
            if bytes.get(start..finish) != fragment.get(nal.start..nal.end)
                || bytes.get(start..finish).is_none()
            {
                return Err(Error::Mismatch);
            }
            index += 1;
        }
    }
    if index != nals.len() {
        return Err(Error::Mismatch);
    }
    for entry in &witnesses {
        let _ = checked_record_bytes(deployment, pin, entry, authority, work, cx)?;
    }
    read_authorize(pin, authority, cx)?;
    Ok(RecoveredClip {
        bytes: media,
        capture: pin.capture,
        samples: count,
        continuity: VideoContinuity {
            connection,
            generation,
            sequence,
            first_decode: samples.first().ok_or(Error::Mismatch)?.decode,
            end_decode: samples
                .last()
                .ok_or(Error::Mismatch)?
                .decode
                .checked_add(u64::from(samples.last().ok_or(Error::Mismatch)?.duration))
                .ok_or(Error::Limit)?,
            records,
            lookahead: witnesses,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::{Error, fragment_sequence_matches, record};
    use crate::unifi_direct::evidence::encode_record;
    use fss_core::{CanonicalDecoder, CanonicalEncoder};
    use fss_packet::extended_flv::{
        Limits,
        stream::{Framer, Next, SearchMode},
    };

    #[test]
    fn archive_fragment_sequence_must_match_writer_header() {
        let mut header = [0u8; 24];
        header[8..20].copy_from_slice(b"\x00\x00\x00\x10mfhd\x00\x00\x00\x00");
        header[20..24].copy_from_slice(&7u32.to_be_bytes());
        assert!(fragment_sequence_matches(&header, 7));
        assert!(!fragment_sequence_matches(&header, 8));
        assert!(!fragment_sequence_matches(&header[..23], 7));
        header[12] ^= 1;
        assert!(!fragment_sequence_matches(&header, 7));
    }

    #[test]
    fn archive_record_accepts_av_flag_policy_and_rejects_unknown_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        fn tag(kind: u8, timestamp: u32, body: &[u8]) -> Vec<u8> {
            let len = body.len();
            let mut out = vec![
                kind,
                (len >> 16) as u8,
                (len >> 8) as u8,
                len as u8,
                (timestamp >> 16) as u8,
                (timestamp >> 8) as u8,
                timestamp as u8,
                (timestamp >> 24) as u8,
                0,
                0,
                0,
            ];
            out.extend_from_slice(body);
            out.extend_from_slice(&(11_u32 + len as u32).to_be_bytes());
            out
        }
        let mut wire = b"FLV\x01\x01\x00\x00\x00\x09\x00\x00\x00\x00".to_vec();
        wire.extend(tag(9, 0, b"video"));
        let mut trailer = [0; 16];
        trailer[11] = 1;
        wire.extend(trailer);
        wire.extend(tag(8, 40, b"audio"));
        let mut framer = Framer::with_mode(
            Limits::default(),
            1024,
            SearchMode::StructuredTrailer16AvFlag,
        )?;
        framer.append(0, &wire)?;
        framer.take()?;
        framer.take()?;
        let Next::Record(source) = framer.take()? else {
            return Err("missing source record".into());
        };
        let mut encoder = CanonicalEncoder::new();
        encode_record(&mut encoder, &source);
        let mut bytes = encoder.finish_checked()?;
        let parsed = record(&mut CanonicalDecoder::new(&bytes), 1024)?;
        assert_eq!(parsed.offset, source.offset());
        assert_eq!(parsed.length, source.bytes().len());
        assert_eq!(parsed.tag, Some((16, 8, 40)));
        *bytes.last_mut().ok_or("empty encoded record")? = 4;
        assert!(matches!(
            record(&mut CanonicalDecoder::new(&bytes), 1024),
            Err(Error::Mismatch)
        ));
        Ok(())
    }
}
