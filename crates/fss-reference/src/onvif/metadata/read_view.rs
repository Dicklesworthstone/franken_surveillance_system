#![forbid(unsafe_code)]
//! Exact, read-only ONVIF reconstruction and the existing finite cognitive projections.
//!
//! The caller owns verified deployment history. One real flat-closure reader and one work
//! balance cover both complete passes. No publisher, recovery, writer lock or directory scan
//! is acquired. This is a repeated bounded observation, not an atomic filesystem snapshot.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, DigestAlgorithm, EvidenceDeltaBatch,
};
use fss_object::SpoolIo;
use fss_publication::custody_audit::{
    CustodyAuditLimits,
    pinned_closure::{PinnedClosureError, PinnedClosureReader, PinnedClosureUsage},
};

use super::{
    MetadataError,
    lifecycle::{
        self, LifecycleDocumentReceipt, LifecycleLimits, LifecycleReadLimits, LifecycleReport,
        RetainedLifecycleError,
    },
    tracks::{
        self, RetainedTrackError, Source, TrackError, TrackLimits, TrackReadLimits, TrackSourcePin,
        TrackSourceReceipt, TrackletReport, WorkBudget,
    },
    zones::{ZoneError, ZoneLimits, ZonePolicy, ZoneReport, project_zones},
};
use crate::deletion::DeletionIndex;
use crate::onvif::wire::LifecycleParseLimits;

/// Select one interpretation; a zone policy is typed operator input, never an inferred basis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OnvifAnalysis {
    /// Complete finite vendor tracklet summaries.
    Tracks,
    /// Original runs plus additive vendor lifecycle relationships.
    Lifecycle,
    /// Original runs plus exact raw-coordinate zone observations.
    Zones(ZonePolicy),
}
impl OnvifAnalysis {
    /// Stable command and report discriminator.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tracks => "tracks",
            Self::Lifecycle => "lifecycle",
            Self::Zones(_) => "zones",
        }
    }
}

/// Separate exact filesystem and deterministic computation ceilings for one entire query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnvifReadLimits {
    /// All sources and both passes share these real read-only closure allowances.
    pub custody: CustodyAuditLimits,
    /// Ordered original source count, at most 32.
    pub max_sources: usize,
    /// Shared history/replay/projection/comparison work, never CPU time or a refillable pool.
    pub max_work_units: usize,
    /// Unchanged tracks-v1 policy.
    pub tracks: TrackLimits,
    /// Additive lifecycle policy.
    pub lifecycle: LifecycleLimits,
    /// Per-document additive parser ceiling.
    pub parse: LifecycleParseLimits,
    /// Exact vendor-zone projection policy.
    pub zones: ZoneLimits,
}
impl Default for OnvifReadLimits {
    fn default() -> Self {
        Self {
            custody: CustodyAuditLimits {
                max_catalogue_entries: 64,
                max_objects: 16_384,
                max_edges: 65_536,
                max_object_bytes: 8 * 1024 * 1024,
                max_read_bytes: 256 * 1024 * 1024,
                max_io_calls: 131_072,
            },
            max_sources: tracks::MAX_TRACK_SOURCES,
            max_work_units: 32 * 1024 * 1024,
            tracks: TrackLimits::default(),
            lifecycle: LifecycleLimits::default(),
            parse: LifecycleParseLimits::default(),
            zones: ZoneLimits::default(),
        }
    }
}
impl OnvifReadLimits {
    /// Reject widened or impossible policies before any source filesystem call.
    pub fn validate(&self, analysis: &OnvifAnalysis) -> Result<(), OnvifReadError> {
        let ceiling = Self::default();
        for (value, maximum) in [
            (self.max_sources, ceiling.max_sources),
            (self.max_work_units, tracks::MAX_TRACK_WORK_UNITS),
            (self.custody.max_catalogue_entries, 64),
            (self.custody.max_objects, 65_536),
            (self.custody.max_edges, 262_144),
            (self.custody.max_object_bytes, 8 * 1024 * 1024),
        ] {
            if value == 0 || value > maximum {
                return Err(OnvifReadError::InvalidRequest);
            }
        }
        if self.custody.max_read_bytes == 0
            || self.custody.max_read_bytes > 1024 * 1024 * 1024
            || self.custody.max_io_calls == 0
            || self.custody.max_io_calls > 1_000_000
        {
            return Err(OnvifReadError::InvalidRequest);
        }
        self.tracks.validate()?;
        self.lifecycle
            .validate()
            .map_err(RetainedLifecycleError::from)?;
        self.parse
            .validate()
            .map_err(RetainedLifecycleError::from)?;
        self.zones.validate()?;
        let extra = match analysis {
            OnvifAnalysis::Tracks => 0,
            OnvifAnalysis::Lifecycle => {
                if self.lifecycle.max_work_units <= self.tracks.max_work_units {
                    return Err(OnvifReadError::InvalidRequest);
                }
                self.lifecycle.max_work_units
            }
            OnvifAnalysis::Zones(policy) => {
                policy.validate()?;
                if self.zones.max_work_units <= self.tracks.max_work_units {
                    return Err(OnvifReadError::InvalidRequest);
                }
                self.zones.max_work_units
            }
        };
        if self
            .tracks
            .max_work_units
            .checked_add(extra)
            .and_then(|v| v.checked_mul(2))
            .is_none_or(|v| v > self.max_work_units as u64)
        {
            return Err(OnvifReadError::InvalidRequest);
        }
        Ok(())
    }

    fn track_read_limits(self) -> TrackReadLimits {
        TrackReadLimits {
            max_sources: self.max_sources,
            max_work_units: self.max_work_units,
            projection: self.tracks,
            ..TrackReadLimits::default()
        }
    }
}

/// Complete projected result, independently compared across both source passes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OnvifAnalysisResult {
    /// Original tracks are the selected interpretation.
    Tracks,
    /// Every lifecycle row and every original document disposition.
    Lifecycle {
        report: LifecycleReport,
        documents: Vec<LifecycleDocumentReceipt>,
        documents_digest: ContentDigest,
    },
    /// Complete zone cells, frame samples and observed transitions.
    Zones(ZoneReport),
}

/// Successful source observation. Digests are recomputed proofs, not new retained publications.
#[derive(Clone, Debug)]
pub struct OnvifReadResult {
    /// Every ordered source, including sources contributing zero analytics frames.
    pub sources: Vec<TrackSourceReceipt>,
    /// Original frozen tracks-v1 grouping and occurrence handles.
    pub tracks: TrackletReport,
    /// Requested additive interpretation.
    pub analysis: OnvifAnalysisResult,
    /// Entire selected flat object union for current deployment deletion checks.
    pub reference_digests: Vec<ContentDigest>,
    /// All actual archive reads/calls and both revalidation passes.
    pub read_usage: PinnedClosureUsage,
    /// Conservative work actually reserved from the one shared allowance.
    pub reserved_work_units: usize,
    /// Exact source/policy/limits identity; excludes transport JSON spelling.
    pub request_digest: ContentDigest,
    /// Complete result, source receipts and accounting identity.
    pub decision_digest: ContentDigest,
}

/// Whole-query refusal: no partial result, empty-success substitute or fallback owner.
#[derive(Debug)]
pub enum OnvifReadError {
    /// Invalid pins, duplicates, scope or limits.
    InvalidRequest,
    /// Original source reconstruction, publication witness or deletion refusal.
    Source(MetadataError),
    /// Exact read-only closure refusal.
    Custody(PinnedClosureError),
    /// Tracklet reconstruction or work bound refusal.
    Tracks(RetainedTrackError),
    /// Additive lifecycle refusal.
    Lifecycle(RetainedLifecycleError),
    /// Exact geometry or zone policy refusal.
    Zones(ZoneError),
    /// Reconstructed sources, interpretations or reference closure changed.
    Changed,
    /// Cooperative cancellation observed.
    Cancelled,
}
impl OnvifReadError {
    /// Stable, payload-free diagnostic identity.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "onvif.query.invalid_request",
            Self::Source(e) => e.code(),
            Self::Custody(e) => e.reason(),
            Self::Tracks(e) => e.code(),
            Self::Lifecycle(e) => e.code(),
            Self::Zones(e) => e.code(),
            Self::Changed => "onvif.query.changed",
            Self::Cancelled => "onvif.query.cancelled",
        }
    }
}
impl std::fmt::Display for OnvifReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for OnvifReadError {}
impl From<MetadataError> for OnvifReadError {
    fn from(e: MetadataError) -> Self {
        Self::Source(e)
    }
}
impl From<PinnedClosureError> for OnvifReadError {
    fn from(e: PinnedClosureError) -> Self {
        Self::Custody(e)
    }
}
impl From<RetainedTrackError> for OnvifReadError {
    fn from(e: RetainedTrackError) -> Self {
        Self::Tracks(e)
    }
}
impl From<TrackError> for OnvifReadError {
    fn from(e: TrackError) -> Self {
        Self::Tracks(e.into())
    }
}
impl From<RetainedLifecycleError> for OnvifReadError {
    fn from(e: RetainedLifecycleError) -> Self {
        Self::Lifecycle(e)
    }
}
impl From<ZoneError> for OnvifReadError {
    fn from(e: ZoneError) -> Self {
        Self::Zones(e)
    }
}

/// Validate ordered exact identities before opening any source capability.
pub(crate) fn validate_pins(pins: &[TrackSourcePin], maximum: usize) -> Result<(), OnvifReadError> {
    if pins.is_empty() || pins.len() > maximum {
        return Err(OnvifReadError::InvalidRequest);
    }
    let mut identities = BTreeSet::new();
    for pin in pins {
        if [pin.identity(), pin.root()]
            .iter()
            .any(|d| d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32])
            || !identities.insert(pin.identity())
        {
            return Err(OnvifReadError::InvalidRequest);
        }
    }
    Ok(())
}

#[derive(Eq, PartialEq)]
struct Pass {
    sources: Vec<TrackSourceReceipt>,
    tracks: TrackletReport,
    analysis: OnvifAnalysisResult,
    references: Vec<ContentDigest>,
}

/// Read only exact already-published flat closures under independently verified history.
#[allow(clippy::too_many_arguments)]
pub(crate) fn read_analysis(
    io: &dyn SpoolIo,
    archive_root: &Path,
    site: &str,
    batches: &[EvidenceDeltaBatch],
    deletions: &DeletionIndex,
    pins: &[TrackSourcePin],
    analysis: &OnvifAnalysis,
    limits: OnvifReadLimits,
    cancelled: &(impl Fn() -> bool + Sync),
) -> Result<OnvifReadResult, OnvifReadError> {
    limits.validate(analysis)?;
    validate_pins(pins, limits.max_sources)?;
    let request_digest = request_digest(site, pins, analysis, limits)?;
    let mut reader = PinnedClosureReader::new(io, archive_root, limits.custody, cancelled)?;
    let mut work = WorkBudget::new(limits.max_work_units);
    let first = read_pass(
        &mut reader,
        site,
        batches,
        deletions,
        pins,
        analysis,
        limits,
        &mut work,
        cancelled,
    )?;
    let second = read_pass(
        &mut reader,
        site,
        batches,
        deletions,
        pins,
        analysis,
        limits,
        &mut work,
        cancelled,
    )?;
    let analysis_bytes = match &first.analysis {
        OnvifAnalysisResult::Tracks => Some(0),
        OnvifAnalysisResult::Lifecycle {
            report, documents, ..
        } => report.encoded_bytes.checked_add(documents.len() * 1024),
        OnvifAnalysisResult::Zones(report) => Some(report.encoded_bytes),
    };
    let analysis_bytes = analysis_bytes.ok_or(RetainedTrackError::Limit)?;
    let comparison = first
        .tracks
        .encoded_bytes
        .checked_add(analysis_bytes)
        .and_then(|v| v.checked_add(first.sources.len() * 1024))
        .and_then(|v| v.checked_add(first.references.len() * 64))
        .and_then(|v| v.checked_mul(2))
        .ok_or(RetainedTrackError::Limit)?;
    work.reserve(comparison)?;
    if cancelled() {
        return Err(OnvifReadError::Cancelled);
    }
    if first != second {
        return Err(OnvifReadError::Changed);
    }
    drop(second);
    // Prepay only bounded pure commitment work before the final I/O/admission boundary.
    work.reserve(4096 + first.sources.len() * 1024 + first.references.len() * 64)?;
    let read_usage = reader.finish()?;
    let decision_digest = decision_digest(request_digest, &first, read_usage, work.used())?;
    Ok(OnvifReadResult {
        sources: first.sources,
        tracks: first.tracks,
        analysis: first.analysis,
        reference_digests: first.references,
        read_usage,
        reserved_work_units: work.used(),
        request_digest,
        decision_digest,
    })
}

#[allow(clippy::too_many_arguments)]
fn read_pass(
    reader: &mut PinnedClosureReader<'_>,
    site: &str,
    batches: &[EvidenceDeltaBatch],
    deletions: &DeletionIndex,
    pins: &[TrackSourcePin],
    analysis: &OnvifAnalysis,
    limits: OnvifReadLimits,
    work: &mut WorkBudget,
    cancelled: &dyn Fn() -> bool,
) -> Result<Pass, OnvifReadError> {
    let mut sources = Vec::new();
    let mut raw_xml = BTreeMap::new();
    let mut references = BTreeSet::new();
    let mut frames = 0_usize;
    let mut objects = 0_usize;
    for pin in pins {
        if cancelled() {
            return Err(OnvifReadError::Cancelled);
        }
        work.source(batches, *pin)?;
        let loaded =
            super::read_source::read_source(reader, site, batches, deletions, *pin, &|| {
                if cancelled() {
                    Err(MetadataError::Cancelled)
                } else {
                    Ok(())
                }
            })?;
        let documents: Vec<_> = match &loaded.source {
            Source::Xml(value) => vec![value.document()],
            Source::Rtp(value) => value
                .documents()
                .iter()
                .filter_map(|d| d.document())
                .collect(),
        };
        work.reserve(documents.len())?;
        for document in documents {
            frames = frames
                .checked_add(document.analytics_frames.len())
                .ok_or(RetainedTrackError::Limit)?;
            if frames > limits.tracks.max_frames {
                return Err(RetainedTrackError::Limit.into());
            }
            work.reserve(document.analytics_frames.len())?;
            for frame in &document.analytics_frames {
                objects = objects
                    .checked_add(frame.objects.len())
                    .ok_or(RetainedTrackError::Limit)?;
                if objects > limits.tracks.max_objects {
                    return Err(RetainedTrackError::Limit.into());
                }
            }
        }
        if let (OnvifAnalysis::Lifecycle, Source::Xml(source), Some(bytes)) =
            (analysis, &loaded.source, loaded.raw_xml)
        {
            raw_xml.insert(source.source_digest(), bytes);
        }
        references.extend(loaded.reference_digests);
        sources.push(loaded.source);
    }
    let check = |_: &'static str| {
        if cancelled() {
            Err(RetainedTrackError::Cancelled)
        } else {
            Ok(())
        }
    };
    let (receipts, tracks, projected) = tracks::project_loaded(
        site,
        pins,
        &sources,
        limits.track_read_limits(),
        work,
        &check,
        |input, work| -> Result<OnvifAnalysisResult, OnvifReadError> {
            match analysis {
                OnvifAnalysis::Tracks => Ok(OnvifAnalysisResult::Tracks),
                OnvifAnalysis::Lifecycle => {
                    let pass = lifecycle::project_verified_sources(
                        input,
                        work,
                        LifecycleReadLimits {
                            source: limits.track_read_limits(),
                            projection: limits.lifecycle,
                            parse: limits.parse,
                        },
                        &|_| {
                            if cancelled() {
                                Err(RetainedLifecycleError::Cancelled)
                            } else {
                                Ok(())
                            }
                        },
                        |digest, maximum| {
                            let bytes = raw_xml.get(&digest).ok_or(MetadataError::Custody)?;
                            if bytes.len() != maximum {
                                return Err(MetadataError::Custody);
                            }
                            Ok(Cow::Borrowed(bytes.as_slice()))
                        },
                    )?;
                    Ok(OnvifAnalysisResult::Lifecycle {
                        report: pass.report,
                        documents: pass.documents,
                        documents_digest: pass.documents_digest,
                    })
                }
                OnvifAnalysis::Zones(policy) => {
                    work.reserve(512)?;
                    work.reserve(
                        usize::try_from(limits.zones.max_work_units)
                            .map_err(|_| RetainedTrackError::Limit)?,
                    )?;
                    Ok(OnvifAnalysisResult::Zones(project_zones(
                        input.frames,
                        input.tracks,
                        policy,
                        limits.zones,
                        || !cancelled(),
                    )?))
                }
            }
        },
    )?;
    Ok(Pass {
        sources: receipts,
        tracks,
        analysis: projected,
        references: references.into_iter().collect(),
    })
}

fn request_digest(
    site: &str,
    pins: &[TrackSourcePin],
    analysis: &OnvifAnalysis,
    limits: OnvifReadLimits,
) -> Result<ContentDigest, OnvifReadError> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.onvif_read_view.request.v1");
    e.text(site);
    e.text(analysis.as_str());
    if let OnvifAnalysis::Zones(policy) = analysis {
        e.digest(policy.digest()?);
    }
    e.u64(pins.len() as u64);
    for pin in pins {
        e.text(pin.kind());
        e.digest(pin.identity());
        e.digest(pin.root());
    }
    for value in [
        limits.max_sources,
        limits.max_work_units,
        limits.custody.max_catalogue_entries,
        limits.custody.max_objects,
        limits.custody.max_edges,
        limits.custody.max_object_bytes,
        limits.tracks.max_frames,
        limits.tracks.max_objects,
        limits.tracks.max_tracklets,
        limits.tracks.max_output_bytes,
        limits.lifecycle.max_frames,
        limits.lifecycle.max_objects,
        limits.lifecycle.max_operations,
        limits.lifecycle.max_references,
        limits.lifecycle.max_output_bytes,
        limits.parse.max_frames,
        limits.parse.max_objects,
        limits.parse.max_operations,
        limits.parse.max_references,
        limits.zones.max_cells,
        limits.zones.max_frame_samples,
        limits.zones.max_transitions,
        limits.zones.max_output_bytes,
    ] {
        e.u64(value as u64);
    }
    for value in [
        limits.custody.max_read_bytes,
        limits.custody.max_io_calls,
        limits.tracks.max_work_units,
        limits.lifecycle.max_work_units,
        limits.parse.max_work_units,
        limits.zones.max_work_units,
        limits.tracks.max_vendor_gap_ns,
    ] {
        e.u64(value);
    }
    Ok(ContentDigest::sha256(
        &e.finish_checked()
            .map_err(|_| OnvifReadError::InvalidRequest)?,
    ))
}

fn decision_digest(
    request: ContentDigest,
    pass: &Pass,
    usage: PinnedClosureUsage,
    work: usize,
) -> Result<ContentDigest, OnvifReadError> {
    let mut e = CanonicalEncoder::new();
    e.text("fss.onvif_read_view.decision.v1");
    e.digest(request);
    e.digest(pass.tracks.report_digest);
    match &pass.analysis {
        OnvifAnalysisResult::Tracks => e.text("tracks"),
        OnvifAnalysisResult::Lifecycle {
            report,
            documents_digest,
            ..
        } => {
            e.text("lifecycle");
            e.digest(report.report_digest);
            e.digest(*documents_digest);
        }
        OnvifAnalysisResult::Zones(report) => {
            e.text("zones");
            e.digest(report.report_digest);
        }
    }
    e.u64(pass.sources.len() as u64);
    for s in &pass.sources {
        e.text(s.pin.kind());
        e.digest(s.pin.identity());
        e.digest(s.pin.root());
        e.digest(s.scope);
        e.digest(s.source_digest);
        e.bool(s.native_source_digest.is_some());
        if let Some(d) = s.native_source_digest {
            e.digest(d);
        }
        e.digest(s.interpretation_digest);
        e.text(s.parser_generation);
        e.text(s.source_mode);
        s.publication_anchor.encode_canonical(&mut e);
        for n in [
            s.documents,
            s.analytics_frames,
            s.empty_analytics_documents,
            s.rejected_documents,
            s.uninterpreted_documents,
        ] {
            e.u64(n as u64);
        }
        e.bool(s.source_processing_complete);
    }
    e.u64(pass.references.len() as u64);
    for d in &pass.references {
        e.digest(*d);
    }
    for n in [
        usage.read_bytes,
        usage.io_calls,
        usage.peak_reserved_read_bytes,
        usage.completed_roots as u64,
        usage.objects as u64,
        usage.edges as u64,
        usage.reference_checks as u64,
        work as u64,
    ] {
        e.u64(n);
    }
    Ok(ContentDigest::sha256(
        &e.finish_checked()
            .map_err(|_| OnvifReadError::InvalidRequest)?,
    ))
}
