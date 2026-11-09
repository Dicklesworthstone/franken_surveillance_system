#![forbid(unsafe_code)]
//! Source-verified additive vendor lifecycle interpretation over unchanged tracklets-v1.
//!
//! This owner borrows the verified XML/RTP sources inside both complete tracklet passes.
//! Source rereads, lifecycle parsing, relationship projection and receipt commitments debit
//! that SAME nonrenewing request allowance. It neither upgrades frozen retained generations
//! nor initializes a deployment, acquires data, publishes derived roots or reconciles effects.
//! Existing-store opening may still perform bounded publisher housekeeping under its lock.

use std::fmt;
use std::path::Path;

use fss_core::{CanonicalEncoder, ContentDigest, Plane, ProvenanceClass};

use super::tracks::{
    ProjectionInput, RetainedTrackError, RetainedTracklets, Source, TrackReadLimits, TrackSourcePin,
    WorkBudget,
};
use super::{Interpretation, MetadataError};
use crate::onvif::wire::{
    EventDocument, EventDocumentFormat, LIFECYCLE_PARSER_GENERATION, LifecycleDocument,
    LifecycleParseLimits, LifecycleWireError, lifecycle_parse_work_bound,
    parse_metadata_lifecycle_document,
};
use crate::{ReferenceDeployment, ReferenceError, ReplayAdmission, ReplayCx};

/// Pure source-linked relationships; original custody remains this owner's responsibility.
pub mod contract;
pub use contract::{
    LifecycleError, LifecycleFrameInput, LifecycleLimits, LifecycleReport, project_lifecycle,
};

/// Complete retained snapshot identity, separate from the unchanged tracklet report.
pub const RETAINED_LIFECYCLE_SCHEMA: &str = "fss.onvif_retained_vendor_lifecycle.v1";
/// Default shared history/replay/parser/projector allowance across both complete passes.
pub const DEFAULT_LIFECYCLE_READ_WORK_UNITS: usize = 32 * 1024 * 1024;
const DOCUMENT_RECEIPT_BYTES: usize = 1024;

/// One complete request's source, per-document parser and aggregate projection bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleReadLimits {
    /// Existing source custody, unchanged tracks-v1 policy and shared cumulative allowances.
    pub source: TrackReadLimits,
    /// Complete aggregate lifecycle relationship projection policy.
    pub projection: LifecycleLimits,
    /// Per-document parser bounds; a computed work quote may narrow, never widen this cap.
    pub parse: LifecycleParseLimits,
}
impl Default for LifecycleReadLimits {
    fn default() -> Self {
        Self {
            source: TrackReadLimits {
                max_work_units: DEFAULT_LIFECYCLE_READ_WORK_UNITS,
                ..TrackReadLimits::default()
            },
            projection: LifecycleLimits::default(),
            parse: LifecycleParseLimits::default(),
        }
    }
}
impl LifecycleReadLimits {
    /// Validate all policies before a deployment is opened or original source is read.
    pub fn validate(self) -> Result<(), RetainedLifecycleError> {
        self.source.validate()?;
        self.projection.validate()?;
        self.parse.validate()?;
        let minimum_work = self.source.projection.max_work_units
            .checked_add(self.projection.max_work_units)
            .and_then(|value| value.checked_mul(2))
            .ok_or(RetainedLifecycleError::Limit)?;
        if self.projection.max_work_units <= self.source.projection.max_work_units
            || minimum_work > self.source.max_work_units as u64
        {
            return Err(RetainedLifecycleError::Limit);
        }
        Ok(())
    }
}

/// Complete disposition of each original XML candidate or an explicit zero-document source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleDocumentState {
    /// The pinned RTP source yielded no complete XML candidate; no synthetic document exists.
    NoCompleteDocuments,
    /// Frozen event-v1 interpretation is preserved without discovering new analytics frames.
    FrozenEventsV1,
    /// The source's frozen parser accepted a SOAP event response rather than MetadataStream.
    NonAnalyticsSoap,
    /// The original frozen RTP XML parser rejected this complete retained candidate.
    RejectedXml,
    /// The additive parser accepted MetadataStream with no analytics frames.
    ParsedEmpty,
    /// The additive parser accepted every original analytics frame, including empty frames.
    Parsed,
}
impl LifecycleDocumentState {
    /// Closed report discriminator, without any claim of physical absence or coverage.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoCompleteDocuments => "no_complete_documents",
            Self::FrozenEventsV1 => "frozen_events_v1",
            Self::NonAnalyticsSoap => "non_analytics_soap",
            Self::RejectedXml => "rejected_xml",
            Self::ParsedEmpty => "parsed_empty",
            Self::Parsed => "parsed",
        }
    }
}

/// Every pinned source and XML occurrence remains visible even when it contributes no rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleDocumentReceipt {
    /// Ordered source position in the original request and verified snapshot.
    pub source_ordinal: usize,
    /// Exact source identity and durable publication root.
    pub pin: TrackSourcePin,
    /// Original complete XML occurrence; absent only for a zero-document RTP source.
    pub document_index: Option<usize>,
    /// Digest of original XML, not the enclosing RTP file; absent for a zero-document source.
    pub source_digest: Option<ContentDigest>,
    /// Original XML bytes; zero for a zero-document source.
    pub source_bytes: usize,
    /// Frozen retained parser generation, independent of the additive lifecycle generation.
    pub parser_generation: &'static str,
    /// Frozen container interpretation; absent for rejected XML and zero-document sources.
    pub format: Option<EventDocumentFormat>,
    /// Explicit parse/skip/empty disposition.
    pub state: LifecycleDocumentState,
    /// Original payload-free refusal, preserved only for rejected complete RTP XML.
    pub original_parse_error: Option<&'static str>,
    /// First paired tracks-v1 frame ordinal; also the insertion position for zero-frame rows.
    pub frame_start: usize,
    /// Number of paired original analytics frames in this document.
    pub frames: usize,
    /// Number of original Object occurrences, including those without Behaviour.
    pub objects: usize,
    /// Number of recognized ObjectTree operations, never coalesced.
    pub operations: usize,
    /// Number of operation endpoints, excluding the references in Object descriptions.
    pub references: usize,
    /// Source-level fields left outside the additive interpretation, including event sections.
    pub unsupported_sections: usize,
    /// Frames with uninterpreted lifecycle material; original analytics flags stay in snapshot.
    pub uninterpreted_frames: usize,
    /// Complete work quote reserved for this additive parse; zero for explicitly skipped rows.
    pub parse_work_units: u64,
}

/// Atomic refusal. No successful partial lifecycle report or detached source owner escapes.
#[derive(Debug)]
pub enum RetainedLifecycleError {
    /// Original source/authority/custody request failed under the existing tracklet owner.
    Source(Box<RetainedTrackError>),
    /// Independent bounded lifecycle projection refused its complete input.
    Projection(LifecycleError),
    /// Known lifecycle XML grammar refused its complete source document.
    Parse(LifecycleWireError),
    /// Aggregate shape, shared work, indexed reads or caller parse-work cap was exceeded.
    Limit,
    /// Original source and additive frame locators failed one-to-one alignment.
    Mismatch,
    /// Canonical bounded receipt commitment could not be completed.
    Encoding,
    /// Cooperative admission refused or cancellation was observed.
    Cancelled,
}
impl RetainedLifecycleError {
    /// Stable payload-free failure identity.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Source(error) => error.code(),
            Self::Projection(error) => error.code(),
            Self::Parse(error) => error.code(),
            Self::Limit => "onvif.lifecycle.limit",
            Self::Mismatch => "onvif.lifecycle.mismatch",
            Self::Encoding => "onvif.lifecycle.encoding",
            Self::Cancelled => "onvif.lifecycle.cancelled",
        }
    }
}
impl fmt::Display for RetainedLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for RetainedLifecycleError {}
impl From<RetainedTrackError> for RetainedLifecycleError {
    fn from(value: RetainedTrackError) -> Self {
        match value {
            RetainedTrackError::Limit => Self::Limit,
            RetainedTrackError::Cancelled => Self::Cancelled,
            value => Self::Source(Box::new(value)),
        }
    }
}
impl From<MetadataError> for RetainedLifecycleError {
    fn from(value: MetadataError) -> Self {
        RetainedTrackError::from(value).into()
    }
}
impl From<ReferenceError> for RetainedLifecycleError {
    fn from(value: ReferenceError) -> Self {
        RetainedTrackError::from(value).into()
    }
}
impl From<super::tracks::TrackError> for RetainedLifecycleError {
    fn from(value: super::tracks::TrackError) -> Self {
        RetainedTrackError::from(value).into()
    }
}
impl From<LifecycleError> for RetainedLifecycleError {
    fn from(value: LifecycleError) -> Self {
        match value {
            LifecycleError::Cancelled => Self::Cancelled,
            LifecycleError::Limit | LifecycleError::BudgetExceeded => Self::Limit,
            value => Self::Projection(value),
        }
    }
}
impl From<LifecycleWireError> for RetainedLifecycleError {
    fn from(value: LifecycleWireError) -> Self {
        match value {
            LifecycleWireError::Cancelled => Self::Cancelled,
            LifecycleWireError::Limit => Self::Limit,
            value => Self::Parse(value),
        }
    }
}

type Result<T, E = RetainedLifecycleError> = std::result::Result<T, E>;

/// Complete source-verified relationship snapshot, released after independent revalidation.
#[derive(Debug)]
pub struct RetainedLifecycle {
    snapshot: RetainedTracklets,
    report: LifecycleReport,
    documents: Vec<LifecycleDocumentReceipt>,
    limits: LifecycleReadLimits,
    digest: ContentDigest,
}
impl RetainedLifecycle {
    /// Reconstruct exact pinned sources twice with one cumulative allowance, apply the
    /// independent lifecycle parser only to retained analytics-v2 MetadataStream documents,
    /// and require both complete projections and receipts to agree before final authority checks.
    pub fn open(
        root: &Path,
        site_lineage: &str,
        pins: &[TrackSourcePin],
        limits: LifecycleReadLimits,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<Self> {
        limits.validate()?;
        let (snapshot, pass) = RetainedTracklets::open_projected(
            root,
            site_lineage,
            pins,
            limits.source,
            cx,
            |input, deployment, work, cx| project_sources(input, deployment, work, cx, limits),
        )?;
        // Only a fixed-size pure commitment follows the underlying owner's final authority
        // check. No admission callback, original source read, or effect occurs here.
        let mut encoded = CanonicalEncoder::new();
        encoded.text(RETAINED_LIFECYCLE_SCHEMA);
        encoded.digest(snapshot.digest());
        encoded.digest(pass.report.report_digest);
        encoded.digest(pass.documents_digest);
        let digest = ContentDigest::sha256(
            &encoded
                .finish_checked()
                .map_err(|_| RetainedLifecycleError::Encoding)?,
        );
        Ok(Self {
            snapshot,
            report: pass.report,
            documents: pass.documents,
            limits,
            digest,
        })
    }

    /// Unchanged tracks-v1 report, exact source receipts and aggregate accounting.
    #[must_use]
    pub fn snapshot(&self) -> &RetainedTracklets {
        &self.snapshot
    }
    /// Complete additive relationship projection; matching never joins original tracklets.
    #[must_use]
    pub fn report(&self) -> &LifecycleReport {
        &self.report
    }
    /// Every pinned source/document disposition, including empty, rejected and frozen inputs.
    #[must_use]
    pub fn documents(&self) -> &[LifecycleDocumentReceipt] {
        &self.documents
    }
    /// Exact caller-declared request policies.
    #[must_use]
    pub const fn limits(&self) -> LifecycleReadLimits {
        self.limits
    }
    /// Binds original snapshot, additive report, parser policy and every document receipt.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }
    /// The relationship interpretation remains cognition.
    #[must_use]
    pub const fn plane(&self) -> Plane {
        Plane::Cognition
    }
    /// Endpoint matching is a derivation, not authority.
    #[must_use]
    pub const fn provenance(&self) -> ProvenanceClass {
        ProvenanceClass::Derived
    }
    /// Every input observation and lifecycle declaration remains a vendor claim.
    #[must_use]
    pub const fn source_provenance(&self) -> ProvenanceClass {
        ProvenanceClass::VendorClaimed
    }
}

#[derive(Eq, PartialEq)]
struct Pass {
    report: LifecycleReport,
    documents: Vec<LifecycleDocumentReceipt>,
    documents_digest: ContentDigest,
}
struct ParsedDocument {
    receipt_index: usize,
    value: LifecycleDocument,
}

fn project_sources(
    input: ProjectionInput<'_>,
    deployment: &ReferenceDeployment,
    work: &mut WorkBudget,
    cx: &ReplayCx<impl ReplayAdmission>,
    limits: LifecycleReadLimits,
) -> Result<Pass> {
    if input.sources.len() != input.receipts.len() {
        return Err(RetainedLifecycleError::Mismatch);
    }
    if input.frames.len() > limits.projection.max_frames
        || input.tracks.occurrences.len() > limits.projection.max_objects
    {
        return Err(RetainedLifecycleError::Limit);
    }
    let mut documents = Vec::new();
    let mut parsed = Vec::new();
    let mut frame_start = 0;
    let mut operations = 0_usize;
    let mut references = 0_usize;
    for (source_ordinal, (source, original)) in
        input.sources.iter().zip(input.receipts).enumerate()
    {
        checkpoint(cx, "onvif_lifecycle:source")?;
        match source {
            Source::Xml(source) => {
                checkpoint(cx, "onvif_lifecycle:document")?;
                let mut receipt = receipt(
                    source_ordinal,
                    original.pin,
                    Some(0),
                    Some(source.source_digest()),
                    source.source_bytes(),
                    source.parser_generation(),
                    Some(source.document()),
                    frame_start,
                );
                if source.interpretation() == Interpretation::EventsV1 {
                    receipt.state = LifecycleDocumentState::FrozenEventsV1;
                    require_no_analytics(source.document())?;
                } else if source.document().format == EventDocumentFormat::PullMessages {
                    receipt.state = LifecycleDocumentState::NonAnalyticsSoap;
                    require_no_analytics(source.document())?;
                } else {
                    // Precharge the additive parse before the extra original XML read. That
                    // indexed read independently consumes the same installed spool byte cap.
                    let parse_limits = reserve_parse(source.source_bytes(), limits.parse, work)?;
                    let bytes = super::read(
                        deployment,
                        source.source_digest(),
                        source.source_bytes(),
                        cx,
                    )?;
                    if bytes.len() != source.source_bytes() {
                        return Err(RetainedLifecycleError::Mismatch);
                    }
                    let value = parse_metadata_lifecycle_document(&bytes, parse_limits, || {
                        checkpoint(cx, "onvif_lifecycle:parse").is_ok()
                    })?;
                    admit_parsed(
                        &input,
                        &mut receipt,
                        &value,
                        &mut frame_start,
                        &mut operations,
                        &mut references,
                        limits.projection,
                    )?;
                    push(
                        &mut parsed,
                        ParsedDocument {
                            receipt_index: documents.len(),
                            value,
                        },
                    )?;
                }
                push(&mut documents, receipt)?;
            }
            Source::Rtp(source) => {
                if source.documents().is_empty() {
                    checkpoint(cx, "onvif_lifecycle:document")?;
                    push(
                        &mut documents,
                        receipt(
                            source_ordinal,
                            original.pin,
                            None,
                            None,
                            0,
                            source.parser_generation(),
                            None,
                            frame_start,
                        ),
                    )?;
                }
                for document in source.documents() {
                    checkpoint(cx, "onvif_lifecycle:document")?;
                    // This accessor hashes the complete XML. Reserve and compute it once
                    // per document, including rejected and empty candidates, never per frame.
                    work.reserve(document.source_bytes())?;
                    let digest = document.source_digest();
                    let mut receipt = receipt(
                        source_ordinal,
                        original.pin,
                        Some(document.index()),
                        Some(digest),
                        document.source_bytes(),
                        source.parser_generation(),
                        document.document(),
                        frame_start,
                    );
                    match document.document() {
                        None => {
                            receipt.state = LifecycleDocumentState::RejectedXml;
                            receipt.original_parse_error = Some(
                                document
                                    .parse_error()
                                    .ok_or(RetainedLifecycleError::Mismatch)?,
                            );
                        }
                        Some(original)
                            if original.format == EventDocumentFormat::PullMessages =>
                        {
                            receipt.state = LifecycleDocumentState::NonAnalyticsSoap;
                            require_no_analytics(original)?;
                        }
                        Some(_) => {
                            let parse_limits =
                                reserve_parse(document.source_bytes(), limits.parse, work)?;
                            let value = parse_metadata_lifecycle_document(
                                document.source_xml(),
                                parse_limits,
                                || checkpoint(cx, "onvif_lifecycle:parse").is_ok(),
                            )?;
                            admit_parsed(
                                &input,
                                &mut receipt,
                                &value,
                                &mut frame_start,
                                &mut operations,
                                &mut references,
                                limits.projection,
                            )?;
                            push(
                                &mut parsed,
                                ParsedDocument {
                                    receipt_index: documents.len(),
                                    value,
                                },
                            )?;
                        }
                    }
                    push(&mut documents, receipt)?;
                }
            }
        }
    }
    if frame_start != input.frames.len() {
        return Err(RetainedLifecycleError::Mismatch);
    }
    let mut overlays = Vec::new();
    overlays
        .try_reserve_exact(input.frames.len())
        .map_err(|_| RetainedLifecycleError::Limit)?;
    for document in &parsed {
        let receipt = &documents[document.receipt_index];
        let source_digest = receipt
            .source_digest
            .ok_or(RetainedLifecycleError::Mismatch)?;
        for (offset, frame) in document.value.frames.iter().enumerate() {
            checkpoint(cx, "onvif_lifecycle:frame")?;
            overlays.push(LifecycleFrameInput {
                frame_ordinal: receipt.frame_start + offset,
                source_digest,
                frame,
                uninterpreted_source: document.value.unsupported_sections != 0,
            });
        }
    }
    checkpoint(cx, "onvif_lifecycle:project")?;
    work.reserve(
        usize::try_from(limits.projection.max_work_units)
            .map_err(|_| RetainedLifecycleError::Limit)?,
    )?;
    let report = project_lifecycle(
        input.frames,
        input.tracks,
        &overlays,
        limits.projection,
        || checkpoint(cx, "onvif_lifecycle:group").is_ok(),
    )?;
    let documents_digest = document_digest(&documents, limits.parse, work, cx)?;
    Ok(Pass {
        report,
        documents,
        documents_digest,
    })
}

fn reserve_parse(
    byte_len: usize,
    limits: LifecycleParseLimits,
    work: &mut WorkBudget,
) -> Result<LifecycleParseLimits> {
    let quote = lifecycle_parse_work_bound(byte_len).ok_or(RetainedLifecycleError::Limit)?;
    if quote > limits.max_work_units {
        return Err(RetainedLifecycleError::Limit);
    }
    work.reserve(usize::try_from(quote).map_err(|_| RetainedLifecycleError::Limit)?)?;
    Ok(LifecycleParseLimits {
        max_work_units: quote,
        ..limits
    })
}

fn require_no_analytics(document: &EventDocument) -> Result<()> {
    if !document.analytics_frames.is_empty() {
        return Err(RetainedLifecycleError::Mismatch);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn receipt(
    source_ordinal: usize,
    pin: TrackSourcePin,
    document_index: Option<usize>,
    source_digest: Option<ContentDigest>,
    source_bytes: usize,
    parser_generation: &'static str,
    original: Option<&EventDocument>,
    frame_start: usize,
) -> LifecycleDocumentReceipt {
    LifecycleDocumentReceipt {
        source_ordinal,
        pin,
        document_index,
        source_digest,
        source_bytes,
        parser_generation,
        format: original.map(|document| document.format),
        state: LifecycleDocumentState::NoCompleteDocuments,
        original_parse_error: None,
        frame_start,
        frames: 0,
        objects: 0,
        operations: 0,
        references: 0,
        unsupported_sections: original.map_or(0, |document| document.unsupported_sections),
        uninterpreted_frames: 0,
        parse_work_units: 0,
    }
}

#[allow(clippy::too_many_arguments)]
fn admit_parsed(
    input: &ProjectionInput<'_>,
    receipt: &mut LifecycleDocumentReceipt,
    value: &LifecycleDocument,
    frame_start: &mut usize,
    operations: &mut usize,
    references: &mut usize,
    limits: LifecycleLimits,
) -> Result<()> {
    let objects = value.frames.iter().try_fold(0_usize, |total, frame| {
        total
            .checked_add(frame.objects.len())
            .ok_or(RetainedLifecycleError::Limit)
    })?;
    let endpoints = value
        .reference_count
        .checked_sub(objects)
        .ok_or(RetainedLifecycleError::Mismatch)?;
    *operations = operations
        .checked_add(value.operation_count)
        .filter(|total| *total <= limits.max_operations)
        .ok_or(RetainedLifecycleError::Limit)?;
    *references = references
        .checked_add(endpoints)
        .filter(|total| *total <= limits.max_references)
        .ok_or(RetainedLifecycleError::Limit)?;
    let end = frame_start
        .checked_add(value.frames.len())
        .filter(|total| *total <= limits.max_frames && *total <= input.frames.len())
        .ok_or(RetainedLifecycleError::Limit)?;
    let source_digest = receipt
        .source_digest
        .ok_or(RetainedLifecycleError::Mismatch)?;
    for (offset, frame) in value.frames.iter().enumerate() {
        let source = &input.frames[*frame_start + offset];
        if source.source_identity != receipt.pin.identity()
            || source.source_root != receipt.pin.root()
            || source.source_digest != source_digest
            || Some(source.document_index) != receipt.document_index
            || source.frame_index != frame.frame_index
            || source.frame.utc_time != frame.utc_time
            || source.frame.source != frame.source
            || source.frame.objects.len() != frame.objects.len()
        {
            return Err(RetainedLifecycleError::Mismatch);
        }
        for (old, new) in source.frame.objects.iter().zip(&frame.objects) {
            if new.reference.object_id.as_deref() != Some(old.object_id.as_str()) {
                return Err(RetainedLifecycleError::Mismatch);
            }
        }
    }
    receipt.state = if value.frames.is_empty() {
        LifecycleDocumentState::ParsedEmpty
    } else {
        LifecycleDocumentState::Parsed
    };
    receipt.frames = value.frames.len();
    receipt.objects = objects;
    receipt.operations = value.operation_count;
    receipt.references = endpoints;
    receipt.unsupported_sections = value.unsupported_sections;
    receipt.uninterpreted_frames = value
        .frames
        .iter()
        .filter(|frame| frame.has_unsupported_content())
        .count();
    receipt.parse_work_units = value.work_units;
    *frame_start = end;
    Ok(())
}

fn document_digest(
    documents: &[LifecycleDocumentReceipt],
    limits: LifecycleParseLimits,
    work: &mut WorkBudget,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<ContentDigest> {
    let maximum = documents
        .len()
        .checked_mul(DOCUMENT_RECEIPT_BYTES)
        .and_then(|value| value.checked_add(512))
        .ok_or(RetainedLifecycleError::Limit)?;
    // Precharge complete bounded receipt encoding/hash plus the final fixed-size snapshot
    // hash, before allocation. No additional budget or callback is needed after final custody.
    work.reserve(
        maximum
            .checked_mul(2)
            .and_then(|value| value.checked_add(512))
            .ok_or(RetainedLifecycleError::Limit)?,
    )?;
    let mut encoded = CanonicalEncoder::new();
    encoded.text("fss.onvif_vendor_lifecycle_documents.v1");
    encoded.text(LIFECYCLE_PARSER_GENERATION);
    for limit in [
        limits.max_frames,
        limits.max_objects,
        limits.max_operations,
        limits.max_references,
    ] {
        encoded.u64(limit as u64);
    }
    encoded.u64(limits.max_work_units);
    encoded.u64(documents.len() as u64);
    for document in documents {
        checkpoint(cx, "onvif_lifecycle:receipt")?;
        if document.parser_generation.len() > 256
            || document
                .original_parse_error
                .is_some_and(|value| value.len() > 256)
        {
            return Err(RetainedLifecycleError::Limit);
        }
        encoded.u64(document.source_ordinal as u64);
        encoded.text(document.pin.kind());
        encoded.digest(document.pin.identity());
        encoded.digest(document.pin.root());
        encoded.bool(document.document_index.is_some());
        if let Some(index) = document.document_index {
            encoded.u64(index as u64);
        }
        encoded.bool(document.source_digest.is_some());
        if let Some(digest) = document.source_digest {
            encoded.digest(digest);
        }
        encoded.u64(document.source_bytes as u64);
        encoded.text(document.parser_generation);
        encoded.bool(document.format.is_some());
        if let Some(format) = document.format {
            encoded.text(match format {
                EventDocumentFormat::PullMessages => "pull_messages",
                EventDocumentFormat::MetadataStream => "metadata_stream",
            });
        }
        encoded.text(document.state.as_str());
        encoded.bool(document.original_parse_error.is_some());
        if let Some(error) = document.original_parse_error {
            encoded.text(error);
        }
        for count in [
            document.frame_start,
            document.frames,
            document.objects,
            document.operations,
            document.references,
            document.unsupported_sections,
            document.uninterpreted_frames,
        ] {
            encoded.u64(count as u64);
        }
        encoded.u64(document.parse_work_units);
    }
    let bytes = encoded
        .finish_checked()
        .map_err(|_| RetainedLifecycleError::Encoding)?;
    if bytes.len() > maximum {
        return Err(RetainedLifecycleError::Limit);
    }
    Ok(ContentDigest::sha256(&bytes))
}

fn push<T>(values: &mut Vec<T>, value: T) -> Result<()> {
    values
        .try_reserve(1)
        .map_err(|_| RetainedLifecycleError::Limit)?;
    values.push(value);
    Ok(())
}
fn checkpoint(cx: &ReplayCx<impl ReplayAdmission>, stage: &'static str) -> Result<()> {
    super::checkpoint(cx, stage).map_err(Into::into)
}
