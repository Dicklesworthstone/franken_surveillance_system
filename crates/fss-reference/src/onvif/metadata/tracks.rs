#![forbid(unsafe_code)]
//! Retained ONVIF vendor-object tracklets over exact XML or recorded RTP source pins.
//!
//! This owner reconstructs the original sources twice under one cumulative allowance. It
//! returns derived cognition over vendor-claimed observations, never physical object identity,
//! camera coverage, trusted timestamps, calibrated geometry, an event, or effect authority.
//! Opening requires an existing deployment and does not reconcile pending effects. The usual
//! publisher recovery and exclusive lock still apply; this is not a forensic no-write mount.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm, LedgerAnchor, Plane,
    ProvenanceClass,
};
use fss_object::SpoolReadBudgetUsage;

use super::rtp::{self, RetainedRtpMetadata, RtpMetadataDocument};
use super::{MetadataError, RetainedMetadata, SourceBinding};
use crate::{ReferenceDeployment, ReferenceError, ReplayAdmission, ReplayCx};

/// Pure vendor-claim grouping. Its inputs alone do not authenticate custody.
pub mod contract;
pub use contract::{TrackError, TrackFrameInput, TrackLimits, TrackletReport, project_tracklets};

/// Completed source-verified grouping snapshot domain.
pub const RETAINED_TRACKLETS_SCHEMA: &str = "fss.onvif_retained_vendor_tracklets.v1";
/// Maximum independently supplied retained sources in one ordered request.
pub const MAX_TRACK_SOURCES: usize = 32;
/// Hard aggregate indexed stored-envelope read bound, across both complete source passes.
pub const MAX_TRACK_STORED_BYTES: u64 = 1024 * 1024 * 1024;
/// Hard aggregate indexed read-attempt bound, across both complete source passes.
pub const MAX_TRACK_INDEXED_READS: u64 = 65_536;
/// Hard cumulative conservative history, replay and projector work reservation.
pub const MAX_TRACK_WORK_UNITS: usize = 64 * 1024 * 1024;

/// An exact existing import identity and publication root. Order is caller-declared context;
/// a new pin always starts a new continuity segment, including two files from the same camera.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackSourcePin {
    /// Existing owner-supplied XML or native PullPoint source under its frozen interpretation.
    Xml {
        /// Immutable retained import identity.
        identity: ContentDigest,
        /// Required exact durable publication root.
        root: ContentDigest,
    },
    /// Existing RTP file or finite native RTSP metadata capture and its original source closure.
    Rtp {
        /// Immutable retained import identity.
        identity: ContentDigest,
        /// Required exact durable publication root.
        root: ContentDigest,
    },
}
impl TrackSourcePin {
    /// Immutable retained import identity.
    #[must_use]
    pub const fn identity(self) -> ContentDigest {
        match self {
            Self::Xml { identity, .. } | Self::Rtp { identity, .. } => identity,
        }
    }
    /// Required exact publication root.
    #[must_use]
    pub const fn root(self) -> ContentDigest {
        match self {
            Self::Xml { root, .. } | Self::Rtp { root, .. } => root,
        }
    }
    /// Stable source-owner discriminator, independent of native versus file acquisition.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Xml { .. } => "xml",
            Self::Rtp { .. } => "rtp",
        }
    }
}

/// One nonrenewing request allowance. Deployment opening retains its existing capacity bounds;
/// these indexed-read reservations start immediately after opening recovery, before hydration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrackReadLimits {
    /// Maximum ordered source pins; duplicate identities are refused rather than replayed twice.
    pub max_sources: usize,
    /// Stored envelopes, headers and trailing probes for all indexed reads in both passes.
    pub max_stored_bytes: u64,
    /// All indexed read attempts, including provenance and deletion-plan reads.
    pub max_indexed_reads: u64,
    /// Conservative ledger/replay/frame work plus each pure projection's full work allowance.
    pub max_work_units: usize,
    /// Per-projection shape/output bounds. Its work allowance is reserved anew from the SAME
    /// outer nonrenewing work balance before each projection; it is never replenished.
    pub projection: TrackLimits,
}
impl Default for TrackReadLimits {
    fn default() -> Self {
        Self {
            max_sources: MAX_TRACK_SOURCES,
            max_stored_bytes: 64 * 1024 * 1024,
            max_indexed_reads: 8192,
            max_work_units: 8 * 1024 * 1024,
            projection: TrackLimits::default(),
        }
    }
}
impl TrackReadLimits {
    /// Validate all hard caps without opening a deployment or reading a source.
    pub fn validate(&self) -> Result<(), RetainedTrackError> {
        if !(1..=MAX_TRACK_SOURCES).contains(&self.max_sources)
            || !(1..=MAX_TRACK_STORED_BYTES).contains(&self.max_stored_bytes)
            || !(1..=MAX_TRACK_INDEXED_READS).contains(&self.max_indexed_reads)
            || !(1..=MAX_TRACK_WORK_UNITS).contains(&self.max_work_units)
        {
            return Err(RetainedTrackError::Limit);
        }
        self.projection.validate()?;
        Ok(())
    }
}

/// Exact source attribution and completeness of one independently pinned input. Counts include
/// empty and rejected documents so a successful zero-row grouping cannot imply absent objects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackSourceReceipt {
    /// Original ordered request entry.
    pub pin: TrackSourcePin,
    /// Immutable owner/sensor/device/profile/parser/transport generation digest.
    pub scope: ContentDigest,
    /// Original XML digest or packet replay-file digest (not an RTP XML document digest).
    pub source_digest: ContentDigest,
    /// Native original observation digest, separate from its derived replay file.
    pub native_source_digest: Option<ContentDigest>,
    /// Exact existing XML projection or RTP source-mapping report digest.
    pub interpretation_digest: ContentDigest,
    /// Frozen XML parser generation. Legacy v1 sources remain event-only.
    pub parser_generation: &'static str,
    /// Existing acquisition mode; no acquisition is performed by this owner.
    pub source_mode: &'static str,
    /// Original publication authority, independent of the current query anchor.
    pub publication_anchor: LedgerAnchor,
    /// Number of retained complete XML candidates, including rejected candidates.
    pub documents: usize,
    /// Number of typed analytics frame occurrences supplied to grouping.
    pub analytics_frames: usize,
    /// Number of documents with no typed analytics frames, including rejected XML.
    pub empty_analytics_documents: usize,
    /// Number of retained XML candidates refused by the source's frozen parser.
    pub rejected_documents: usize,
    /// Documents containing uninterpreted source-level sections or event lifecycle claims.
    pub uninterpreted_documents: usize,
    /// Source acquisition/replay completion only; never physical coverage or identity evidence.
    pub source_processing_complete: bool,
}

/// Completed aggregate accounting. Reservations are conservative and never refunded; they are
/// not CPU timing measurements. Opening recovery and metadata/open syscalls are outside these
/// indexed byte/attempt counters, and remain bounded by the existing deployment-open contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrackReadUsage {
    /// Both source-validation passes, including closure, source and deletion-plan reads.
    pub indexed_reads: SpoolReadBudgetUsage,
    /// Reserved history/replay/frame/projector work across both passes.
    pub reserved_work_units: usize,
    /// Request's explicit maximum work balance.
    pub maximum_work_units: usize,
}

/// Complete refusal. No successful report or partial track set is returned.
#[derive(Debug)]
pub enum RetainedTrackError {
    /// Source pins, duplicate source identity, or source binding are invalid.
    InvalidRequest,
    /// An explicit count, indexed-read, work, or output allowance was exhausted.
    Limit,
    /// Pure grouping input/policy refused.
    Projection(TrackError),
    /// Original immutable source/root/ledger/deletion custody could not be re-established.
    Source(Box<MetadataError>),
    /// The complete existing deployment could not be opened with the supplied authority.
    Authority(Box<ReferenceError>),
    /// Source reconstruction, current anchor, or final projection changed between passes.
    Mismatch,
    /// Cooperative admission refused or cancellation was observed.
    Cancelled,
}
impl RetainedTrackError {
    /// Stable payload-free failure identity; never disclose a path or vendor label.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "onvif.tracks.invalid_request",
            Self::Limit => "onvif.tracks.limit",
            Self::Projection(error) => error.code(),
            Self::Source(error) => error.code(),
            Self::Authority(_) => "onvif.tracks.authority",
            Self::Mismatch => "onvif.tracks.mismatch",
            Self::Cancelled => "onvif.tracks.cancelled",
        }
    }
}
impl fmt::Display for RetainedTrackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for RetainedTrackError {}
impl From<TrackError> for RetainedTrackError {
    fn from(error: TrackError) -> Self {
        match error {
            TrackError::Cancelled => Self::Cancelled,
            TrackError::Limit | TrackError::BudgetExceeded => Self::Limit,
            error => Self::Projection(error),
        }
    }
}
impl From<MetadataError> for RetainedTrackError {
    fn from(error: MetadataError) -> Self {
        match error {
            MetadataError::Cancelled => Self::Cancelled,
            MetadataError::Limit => Self::Limit,
            MetadataError::Storage(fss_object::SpoolError::ReadBudgetExceeded { .. }) => {
                Self::Limit
            }
            error => Self::Source(Box::new(error)),
        }
    }
}
impl From<ReferenceError> for RetainedTrackError {
    fn from(error: ReferenceError) -> Self {
        Self::Authority(Box::new(error))
    }
}

type Result<T, E = RetainedTrackError> = std::result::Result<T, E>;

/// Source-verified derived cognition, released only after both full source passes agree.
#[derive(Debug)]
pub struct RetainedTracklets {
    report: TrackletReport,
    sources: Vec<TrackSourceReceipt>,
    authority_anchor: LedgerAnchor,
    limits: TrackReadLimits,
    usage: TrackReadUsage,
    digest: ContentDigest,
}
impl RetainedTracklets {
    /// Read exact pinned sources, project all admitted observations, and independently repeat
    /// the complete source reconstruction and grouping before release. The same nonrefillable
    /// indexed read and conservative work allowance covers both passes, including provenance
    /// and deletion checks. Every separate pin is a continuity barrier.
    ///
    /// Requires a complete existing deployment; never initializes one, publishes derived
    /// objects, acquires camera data, or reconciles pending effects. Standard opening recovery
    /// may perform publisher housekeeping under its exclusive lock.
    pub fn open(
        root: &Path,
        site_lineage: &str,
        pins: &[TrackSourcePin],
        limits: TrackReadLimits,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<Self> {
        Self::open_projected(root, site_lineage, pins, limits, cx, |_, _, _, _| {
            Ok::<(), RetainedTrackError>(())
        })
        .map(|(snapshot, ())| snapshot)
    }

    /// Run an owned cognitive projection inside both complete custody passes. The hook
    /// borrows only this pass's verified sources and uses the same nonrenewing allowance.
    /// All output must agree before the existing final authority and effect-store checks.
    pub(super) fn open_projected<A, T, F, E>(
        root: &Path,
        site_lineage: &str,
        pins: &[TrackSourcePin],
        limits: TrackReadLimits,
        cx: &ReplayCx<A>,
        mut extension: F,
    ) -> Result<(Self, T), E>
    where
        A: ReplayAdmission,
        T: Eq,
        E: From<RetainedTrackError> + From<MetadataError> + From<ReferenceError> + From<TrackError>,
        F: for<'a> FnMut(
            ProjectionInput<'a>,
            &ReferenceDeployment,
            &mut WorkBudget,
            &ReplayCx<A>,
        ) -> Result<T, E>,
    {
        limits.validate()?;
        if pins.is_empty() || pins.len() > limits.max_sources || cx.root_dir() != root {
            return Err(RetainedTrackError::InvalidRequest.into());
        }
        let mut identities = BTreeSet::new();
        for pin in pins {
            if !valid_digest(pin.identity())
                || !valid_digest(pin.root())
                || !identities.insert(pin.identity())
            {
                return Err(RetainedTrackError::InvalidRequest.into());
            }
        }
        checkpoint(cx, "onvif_tracks:open")?;
        let mut deployment = ReferenceDeployment::open_existing_without_effect_reconciliation(
            root,
            site_lineage,
            cx,
        )?;
        deployment
            .publisher_mut()
            .tighten_read_budget(limits.max_stored_bytes, limits.max_indexed_reads)
            .map_err(|_| RetainedTrackError::Limit)?;
        let authority_anchor = deployment.current_anchor().clone();
        let mut work = WorkBudget {
            maximum: limits.max_work_units,
            used: 0,
        };
        let (sources, report, projected) =
            read_projection(&deployment, pins, limits, &mut work, cx, &mut extension)?;
        checkpoint(cx, "onvif_tracks:revalidate")?;
        let (fresh_sources, fresh_report, fresh_projected) =
            read_projection(&deployment, pins, limits, &mut work, cx, &mut extension)?;
        if fresh_sources != sources || fresh_report != report || fresh_projected != projected {
            return Err(RetainedTrackError::Mismatch.into());
        }
        // Admission callbacks may themselves discover or change authority. No callback runs
        // after this final on-disk authority verification and before the snapshot is returned.
        checkpoint(cx, "onvif_tracks:complete")?;
        deployment
            .ledger()
            .verify_durable_head()
            .map_err(|_| RetainedTrackError::Mismatch)?;
        if deployment.current_anchor() != &authority_anchor
            || !deployment.effects().store_pin_is_current()
        {
            return Err(RetainedTrackError::Mismatch.into());
        }
        let usage = TrackReadUsage {
            indexed_reads: deployment.publisher().spool().read_budget_usage(),
            reserved_work_units: work.used,
            maximum_work_units: limits.max_work_units,
        };
        let digest = snapshot_digest(&sources, &report, &authority_anchor, limits, usage);
        Ok((
            Self {
                report,
                sources,
                authority_anchor,
                limits,
                usage,
                digest,
            },
            projected,
        ))
    }

    /// Complete grouping, including singletons and all accepted source-frame occurrences.
    #[must_use]
    pub fn report(&self) -> &TrackletReport {
        &self.report
    }
    /// Ordered exact source pins and retained processing limitations.
    #[must_use]
    pub fn sources(&self) -> &[TrackSourceReceipt] {
        &self.sources
    }
    /// Current authority snapshot against which all source deletion checks succeeded.
    #[must_use]
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.authority_anchor
    }
    /// Exact declared aggregate and projector bounds.
    #[must_use]
    pub const fn limits(&self) -> TrackReadLimits {
        self.limits
    }
    /// Shared cumulative accounting for both complete source-validation passes.
    #[must_use]
    pub const fn usage(&self) -> TrackReadUsage {
        self.usage
    }
    /// Snapshot identity binds source receipts, grouping, current authority and accounting.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// Grouping is derived cognition, never authority.
    #[must_use]
    pub const fn plane(&self) -> Plane {
        Plane::Cognition
    }
    /// Association itself is derived; the original leaves retain their vendor provenance.
    #[must_use]
    pub const fn provenance(&self) -> ProvenanceClass {
        ProvenanceClass::Derived
    }
    /// Every input observation remains a vendor claim after custody verification.
    #[must_use]
    pub const fn observation_provenance(&self) -> ProvenanceClass {
        ProvenanceClass::VendorClaimed
    }
}

/// Already reconstructed inputs borrowed by one bounded cognitive extension.
pub(super) struct ProjectionInput<'a> {
    pub sources: &'a [Source],
    pub receipts: &'a [TrackSourceReceipt],
    pub frames: &'a [TrackFrameInput<'a>],
    pub tracks: &'a TrackletReport,
}

pub(super) struct WorkBudget {
    maximum: usize,
    used: usize,
}
impl WorkBudget {
    pub(super) fn reserve(&mut self, amount: usize) -> Result<()> {
        self.used = self
            .used
            .checked_add(amount)
            .filter(|n| *n <= self.maximum)
            .ok_or(RetainedTrackError::Limit)?;
        Ok(())
    }
    pub(super) fn new(maximum: usize) -> Self {
        Self { maximum, used: 0 }
    }
    pub(super) const fn used(&self) -> usize {
        self.used
    }
    fn reader(&mut self, deployment: &ReferenceDeployment, pin: TrackSourcePin) -> Result<()> {
        self.source(deployment.ledger().batches(), pin)
    }
    pub(super) fn source(
        &mut self,
        batches: &[fss_core::EvidenceDeltaBatch],
        pin: TrackSourcePin,
    ) -> Result<()> {
        // Reserve before the source owner can scan. Six full (batch + delta) passes cover
        // deletion candidate/proof searches and the reverse publication search. Decoding and
        // sorting deletion-plan structures are independently bounded by their canonical byte
        // ceiling and this request's cumulative indexed read allowance.
        if batches.len() > super::MAX_HISTORY_BATCHES {
            return Err(RetainedTrackError::Limit);
        }
        self.reserve(batches.len())?;
        let mut deltas = 0_usize;
        for batch in batches {
            deltas = deltas
                .checked_add(batch.deltas.len())
                .ok_or(RetainedTrackError::Limit)?;
            if deltas > super::MAX_HISTORY_DELTAS {
                return Err(RetainedTrackError::Limit);
            }
        }
        let history = batches
            .len()
            .checked_add(deltas)
            .and_then(|n| n.checked_mul(6))
            .ok_or(RetainedTrackError::Limit)?;
        self.reserve(history)?;
        if matches!(pin, TrackSourcePin::Rtp { .. }) {
            // One replay plus a second bounded source-mapping traversal; wire/XML byte work is
            // separately constrained by the source owners and cumulative indexed byte balance.
            self.reserve(2 * (rtp::MAX_RECORDS + rtp::MAX_DOCUMENTS))?;
        }
        Ok(())
    }
}

pub(crate) enum Source {
    Xml(RetainedMetadata),
    Rtp(RetainedRtpMetadata),
}

fn read_projection<A, T, F, E>(
    deployment: &ReferenceDeployment,
    pins: &[TrackSourcePin],
    limits: TrackReadLimits,
    work: &mut WorkBudget,
    cx: &ReplayCx<A>,
    extension: &mut F,
) -> Result<(Vec<TrackSourceReceipt>, TrackletReport, T), E>
where
    A: ReplayAdmission,
    E: From<RetainedTrackError> + From<MetadataError> + From<ReferenceError> + From<TrackError>,
    F: for<'a> FnMut(
        ProjectionInput<'a>,
        &ReferenceDeployment,
        &mut WorkBudget,
        &ReplayCx<A>,
    ) -> Result<T, E>,
{
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(pins.len())
        .map_err(|_| RetainedTrackError::Limit)?;
    let mut total_frames = 0_usize;
    let mut total_objects = 0_usize;
    for pin in pins {
        checkpoint(cx, "onvif_tracks:source")?;
        work.reader(deployment, *pin)?;
        let source = match *pin {
            TrackSourcePin::Xml { identity, root } => Source::Xml(RetainedMetadata::open(
                deployment,
                identity,
                Some(root),
                cx,
            )?),
            TrackSourcePin::Rtp { identity, root } => Source::Rtp(RetainedRtpMetadata::open(
                deployment,
                identity,
                Some(root),
                cx,
            )?),
        };
        // Enforce aggregate shape capacity after each verified input and before reading the
        // next one. A small requested result cannot first accumulate every parsed source.
        let documents: Vec<_> = match &source {
            Source::Xml(value) => vec![value.document()],
            Source::Rtp(value) => value
                .documents()
                .iter()
                .filter_map(RtpMetadataDocument::document)
                .collect(),
        };
        work.reserve(documents.len())?;
        for document in documents {
            total_frames = total_frames
                .checked_add(document.analytics_frames.len())
                .ok_or(RetainedTrackError::Limit)?;
            if total_frames > limits.projection.max_frames {
                return Err(RetainedTrackError::Limit.into());
            }
            work.reserve(document.analytics_frames.len())?;
            for frame in &document.analytics_frames {
                total_objects = total_objects
                    .checked_add(frame.objects.len())
                    .ok_or(RetainedTrackError::Limit)?;
                if total_objects > limits.projection.max_objects {
                    return Err(RetainedTrackError::Limit.into());
                }
            }
        }
        sources.push(source);
    }
    project_loaded(
        deployment.site_lineage(),
        pins,
        &sources,
        limits,
        work,
        &|stage| checkpoint(cx, stage),
        |input, work| extension(input, deployment, work, cx),
    )
}

/// Shared deterministic frame mapping and grouping after an actual owner verifies each source.
/// Caller must enforce aggregate frame/object shape while accumulating source inputs.
pub(super) fn project_loaded<T, E>(
    site_lineage: &str,
    pins: &[TrackSourcePin],
    sources: &[Source],
    limits: TrackReadLimits,
    work: &mut WorkBudget,
    check: &dyn Fn(&'static str) -> Result<()>,
    extension: impl FnOnce(ProjectionInput<'_>, &mut WorkBudget) -> Result<T, E>,
) -> Result<(Vec<TrackSourceReceipt>, TrackletReport, T), E>
where
    E: From<RetainedTrackError> + From<MetadataError> + From<TrackError>,
{
    if sources.len() != pins.len() {
        return Err(RetainedTrackError::Mismatch.into());
    }
    let mut frames = Vec::new();
    let mut receipts = Vec::new();
    receipts
        .try_reserve_exact(pins.len())
        .map_err(|_| RetainedTrackError::Limit)?;
    for (pin, source) in pins.iter().copied().zip(sources) {
        check("onvif_tracks:frames")?;
        match source {
            Source::Xml(source) => {
                let scope = scope_digest(
                    site_lineage,
                    source.binding(),
                    source.parser_generation(),
                    None,
                );
                let document = source.document();
                let opaque = source_uninterpreted(document);
                for (frame_index, frame) in document.analytics_frames.iter().enumerate() {
                    append_frame(
                        &mut frames,
                        TrackFrameInput {
                            scope,
                            source_identity: pin.identity(),
                            source_root: pin.root(),
                            source_digest: source.source_digest(),
                            frame_digest: source.analytics_frame_digest(frame_index)?,
                            document_index: 0,
                            frame_index,
                            frame,
                            boundary_before: frame_index == 0,
                            uninterpreted_source: opaque,
                        },
                        limits,
                        work,
                    )?;
                }
                receipts.push(TrackSourceReceipt {
                    pin,
                    scope,
                    source_digest: source.source_digest(),
                    native_source_digest: None,
                    interpretation_digest: source.projection_digest(),
                    parser_generation: source.parser_generation(),
                    source_mode: source.source_mode(),
                    publication_anchor: source.authority_anchor().clone(),
                    documents: 1,
                    analytics_frames: document.analytics_frames.len(),
                    empty_analytics_documents: usize::from(document.analytics_frames.is_empty()),
                    rejected_documents: 0,
                    uninterpreted_documents: usize::from(opaque),
                    source_processing_complete: !document.has_unsupported_content(),
                });
            }
            Source::Rtp(source) => {
                let scope = scope_digest(
                    site_lineage,
                    source.binding(),
                    source.parser_generation(),
                    Some(source.config()),
                );
                let mut receipt = TrackSourceReceipt {
                    pin,
                    scope,
                    source_digest: source.source_digest(),
                    native_source_digest: source.native_source_digest(),
                    interpretation_digest: source.report_digest(),
                    parser_generation: source.parser_generation(),
                    source_mode: source.source_mode(),
                    publication_anchor: source.authority_anchor().clone(),
                    documents: source.documents().len(),
                    analytics_frames: 0,
                    empty_analytics_documents: 0,
                    rejected_documents: 0,
                    uninterpreted_documents: 0,
                    source_processing_complete: source.processing_complete(),
                };
                let mut previous: Option<&RtpMetadataDocument> = None;
                let mut barrier = true;
                // Any retained transport/acquisition loss conservatively disables linkage
                // between XML documents throughout this source; within each document its exact
                // typed frames remain useful. Stops never imply an unobserved closing tail.
                let clean_transport = source.processing_complete();
                for document in source.documents() {
                    work.reserve(1)?;
                    let Some(parsed) = document.document() else {
                        receipt.rejected_documents += 1;
                        receipt.empty_analytics_documents += 1;
                        barrier = true;
                        previous = Some(document);
                        continue;
                    };
                    let opaque = source_uninterpreted(parsed);
                    receipt.uninterpreted_documents += usize::from(opaque);
                    if parsed.analytics_frames.is_empty() {
                        receipt.empty_analytics_documents += 1;
                        barrier = true;
                        previous = Some(document);
                        continue;
                    }
                    let consecutive = clean_transport
                        && !barrier
                        && previous.is_some_and(|prior| adjacent_documents(prior, document));
                    // These accessors hash complete retained document buffers. Compute once
                    // per document, never once per frame or object occurrence.
                    let source_digest = document.source_digest();
                    let projection_digest = document
                        .projection_digest()
                        .ok_or(RetainedTrackError::Mismatch)?;
                    for (frame_index, frame) in parsed.analytics_frames.iter().enumerate() {
                        append_frame(
                            &mut frames,
                            TrackFrameInput {
                                scope,
                                source_identity: pin.identity(),
                                source_root: pin.root(),
                                source_digest,
                                frame_digest: rtp_frame_digest(
                                    pin,
                                    scope,
                                    source_digest,
                                    projection_digest,
                                    document.index(),
                                    frame_index,
                                ),
                                document_index: document.index(),
                                frame_index,
                                frame,
                                boundary_before: frame_index == 0 && !consecutive,
                                uninterpreted_source: opaque,
                            },
                            limits,
                            work,
                        )?;
                    }
                    receipt.analytics_frames += parsed.analytics_frames.len();
                    barrier = opaque;
                    previous = Some(document);
                }
                receipts.push(receipt);
            }
        }
    }
    check("onvif_tracks:project")?;
    // Reserve the full declared algorithm allowance before starting each projection. Both
    // passes consume the same outer balance even when the actual grouping happens to be cheap.
    work.reserve(
        usize::try_from(limits.projection.max_work_units).map_err(|_| RetainedTrackError::Limit)?,
    )?;
    let report = project_tracklets(&frames, limits.projection, || {
        check("onvif_tracks:group").is_ok()
    })?;
    let projected = extension(
        ProjectionInput {
            sources,
            receipts: &receipts,
            frames: &frames,
            tracks: &report,
        },
        work,
    )?;
    Ok((receipts, report, projected))
}

fn append_frame<'a>(
    frames: &mut Vec<TrackFrameInput<'a>>,
    frame: TrackFrameInput<'a>,
    limits: TrackReadLimits,
    work: &mut WorkBudget,
) -> Result<()> {
    if frames.len() >= limits.projection.max_frames {
        return Err(RetainedTrackError::Limit);
    }
    work.reserve(1 + frame.frame.objects.len())?;
    frames
        .try_reserve(1)
        .map_err(|_| RetainedTrackError::Limit)?;
    frames.push(frame);
    Ok(())
}

fn source_uninterpreted(document: &crate::onvif::wire::EventDocument) -> bool {
    // Event notifications can carry object deletion/merge/lifecycle semantics this projector
    // does not interpret, even when the event parser understands their structural containers.
    document.unsupported_sections != 0 || !document.notifications.is_empty()
}

fn adjacent_documents(prior: &RtpMetadataDocument, current: &RtpMetadataDocument) -> bool {
    prior.index().checked_add(1) == Some(current.index())
        && prior.provenance().fragments.last().is_some_and(|last| {
            last.sequence == current.provenance().boundary.sequence
                && last.record == current.provenance().boundary.record
                && last.source == current.provenance().boundary.source
        })
}

fn scope_digest(
    site: &str,
    binding: &SourceBinding,
    parser: &str,
    transport: Option<&rtp::RtpMetadataConfig>,
) -> ContentDigest {
    let mut encoded = CanonicalEncoder::new();
    encoded.text("fss.onvif_vendor_track_scope.v1");
    encoded.text(site);
    encoded.text(binding.sensor_id.as_str());
    encoded.digest(binding.device_generation);
    encoded.digest(binding.profile_generation);
    encoded.text(&binding.profile_token);
    encoded.text(parser);
    encoded.bool(transport.is_some());
    if let Some(config) = transport {
        encoded.text(rtp::REPLAY_GENERATION);
        encoded.bytes(&config.stream.ingress.to_be_bytes());
        encoded.u64(config.stream.generation);
        encoded.u32(config.stream.ssrc);
        encoded.u8(config.payload_type);
    }
    ContentDigest::sha256(&encoded.finish())
}

fn rtp_frame_digest(
    pin: TrackSourcePin,
    scope: ContentDigest,
    source_digest: ContentDigest,
    projection_digest: ContentDigest,
    document_index: usize,
    index: usize,
) -> ContentDigest {
    let mut encoded = CanonicalEncoder::new();
    encoded.text("fss.onvif_rtp_vendor_analytics_frame.v1");
    encoded.digest(pin.identity());
    encoded.digest(pin.root());
    encoded.digest(scope);
    encoded.digest(source_digest);
    encoded.digest(projection_digest);
    encoded.u64(document_index as u64);
    encoded.u64(index as u64);
    ContentDigest::sha256(&encoded.finish())
}

fn snapshot_digest(
    sources: &[TrackSourceReceipt],
    report: &TrackletReport,
    anchor: &LedgerAnchor,
    limits: TrackReadLimits,
    usage: TrackReadUsage,
) -> ContentDigest {
    let mut encoded = CanonicalEncoder::new();
    encoded.text(RETAINED_TRACKLETS_SCHEMA);
    anchor.encode_canonical(&mut encoded);
    encoded.digest(report.report_digest);
    encoded.u64(sources.len() as u64);
    for source in sources {
        encoded.text(source.pin.kind());
        encoded.digest(source.pin.identity());
        encoded.digest(source.pin.root());
        encoded.digest(source.scope);
        encoded.digest(source.source_digest);
        encoded.bool(source.native_source_digest.is_some());
        if let Some(native) = source.native_source_digest {
            encoded.digest(native);
        }
        encoded.digest(source.interpretation_digest);
        encoded.text(source.parser_generation);
        encoded.text(source.source_mode);
        source.publication_anchor.encode_canonical(&mut encoded);
        encoded.u64(source.documents as u64);
        encoded.u64(source.analytics_frames as u64);
        encoded.u64(source.empty_analytics_documents as u64);
        encoded.u64(source.rejected_documents as u64);
        encoded.u64(source.uninterpreted_documents as u64);
        encoded.bool(source.source_processing_complete);
    }
    encoded.u64(limits.max_sources as u64);
    encoded.u64(limits.max_stored_bytes);
    encoded.u64(limits.max_indexed_reads);
    encoded.u64(limits.max_work_units as u64);
    encoded.u64(usage.indexed_reads.used_bytes);
    encoded.u64(usage.indexed_reads.used_read_attempts);
    encoded.u64(usage.reserved_work_units as u64);
    ContentDigest::sha256(&encoded.finish())
}

fn valid_digest(digest: ContentDigest) -> bool {
    digest.algorithm() == DigestAlgorithm::Sha256 && digest.bytes() != [0; 32]
}
fn checkpoint(cx: &ReplayCx<impl ReplayAdmission>, stage: &'static str) -> Result<()> {
    super::checkpoint(cx, stage).map_err(Into::into)
}
