#![forbid(unsafe_code)]
//! Source-closed import of recorded or natively acquired, uncompressed ONVIF metadata RTP.
//!
//! The original file recipe remains a finite owner-attributed import. A separate native
//! acquisition recipe also retains original negotiation and nanosecond packet observations.
//! The complete replay dump remains in custody, including probation, duplicate, malformed and unparsed
//! records. Every reconstructed document has exact original packet/payload spans and an
//! observed preceding marker. Recorder offsets drive only a frozen replay clock; neither they
//! nor RTP timestamps replace the independently declared owner receive interval.

mod record;
mod replay;

use std::{fmt, ops::Range};

use fss_core::{
    CanonicalEncode, ContentDigest, DigestAlgorithm, LedgerAnchor, Plane, ProvenanceClass, SensorId,
};
use fss_object::ObjectManifest;
use fss_packet::{OnvifMetadataLimits, OnvifMetadataReceiver, ReorderLimits, StreamKey};
use fss_publication::{LocalPublicationState, SlotName};

use super::{MetadataError, SourceBinding};
use crate::deletion::DeletionIndex;
use crate::onvif::wire::EventDocument;
use crate::rtsp::metadata_source::NativeMetadataSource;
use crate::{ReferenceDeployment, ReplayAdmission, ReplayCx};

/// New custody domain; the owner-file and native PullPoint recipes remain unchanged.
pub const RECIPE_DOMAIN: &str = "fss.onvif_metadata_rtpdump_import.v1";
/// Native acquisition is bound separately; the original file recipe is byte-identical.
pub const NATIVE_RECIPE_DOMAIN: &str = "fss.onvif_metadata_rtsp_import.v1";
/// Frozen packet reconstruction, timeline mapping and reporting interpretation.
pub const REPLAY_GENERATION: &str = "gen:fss1:onvif-metadata-rtpdump-v1";
/// Exact source byte ceiling, independent of packet and document limits.
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
/// Independent ceiling for original SDP, packet receive clocks and acquisition evidence.
pub const MAX_NATIVE_SOURCE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum complete record headers examined per import.
pub const MAX_RECORDS: usize = 16_384;
/// Maximum complete transport documents, including rejected XML.
pub const MAX_DOCUMENTS: usize = 64;
/// Last cancellable boundary before the batch root's authority publication.
pub const STAGE_RTP_METADATA_PUBLISH: &str = "onvif_rtp_metadata:publish";
const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROJECTION_BYTES: usize = 8 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 16 * 1024;

/// Independent finite-file work limits; a hit is retained as incomplete processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpMetadataImportLimits {
    /// Complete source allocation bound, at most eight MiB.
    pub max_input_bytes: usize,
    /// Complete source records examined, at most 16,384.
    pub max_records: usize,
    /// Marker-complete documents admitted, at most 64, including unsupported XML.
    pub max_documents: usize,
}
impl Default for RtpMetadataImportLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: MAX_INPUT_BYTES,
            max_records: MAX_RECORDS,
            max_documents: MAX_DOCUMENTS,
        }
    }
}

/// Exact owner pin and bounds, durably frozen before source interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpMetadataConfig {
    /// Owner ingress and stream generation plus explicitly selected SSRC.
    pub stream: StreamKey,
    /// Explicitly selected dynamic RTP payload type (96..=127).
    pub payload_type: u8,
    /// Original file and output count bounds.
    pub limits: RtpMetadataImportLimits,
    /// Existing packet parsing and sequence reorder bounds.
    pub reorder: ReorderLimits,
    /// Independent fixed lifetime, byte and fragment bounds for one XML document.
    pub metadata: OnvifMetadataLimits,
}
impl RtpMetadataConfig {
    /// Pure validation; no source read, ambient clock, authority or network effect.
    pub fn validate(&self) -> Result<(), MetadataError> {
        if !(1..=MAX_INPUT_BYTES).contains(&self.limits.max_input_bytes)
            || !(1..=MAX_RECORDS).contains(&self.limits.max_records)
            || !(1..=MAX_DOCUMENTS).contains(&self.limits.max_documents)
        {
            return Err(MetadataError::InvalidBinding);
        }
        OnvifMetadataReceiver::new(self.stream, self.payload_type, self.reorder, self.metadata)
            .map_err(|_| MetadataError::InvalidBinding)?;
        Ok(())
    }
}

/// One source record in arrival/file order, including records never admitted to reconstruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpMetadataRecord {
    /// Zero-based original file ordinal; this is not an RTP sequence.
    pub index: usize,
    /// Exact original record prefix and captured datagram range.
    pub span: Range<usize>,
    /// Exact original captured datagram range, excluding recorder prefix.
    pub packet_span: Range<usize>,
    /// Untrusted recorder-relative milliseconds, preserved without normalization.
    pub offset_ms: u32,
    /// Stable source/admission result, independent of XML validity.
    pub result: &'static str,
    /// Sequence classification before reconstruction, if the packet was admitted to tracking.
    pub sequence_class: Option<&'static str>,
    /// Extended sequence in the exact selected owner generation, when mapped.
    pub sequence: Option<u64>,
    /// Ordered reconstruction outcome, absent for unconsumed original packets.
    pub reconstruction: Option<&'static str>,
}

/// Payload-free incomplete processing or refusal, with retained source attribution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpMetadataIssue {
    /// Stable versioned reason, never camera-controlled text.
    pub reason: &'static str,
    /// Affected original arrival record when one triggered the result.
    pub record: Option<usize>,
    /// Exact affected original source envelope or terminal unprocessed suffix.
    pub source: Range<usize>,
    /// First affected extended sequence, where known.
    pub first_sequence: Option<u64>,
    /// Last affected extended sequence, where known; no absent tail is invented.
    pub last_sequence: Option<u64>,
    /// Reconstructed candidate bytes retired, never bytes removed from source custody.
    pub discarded_bytes: usize,
    /// Candidate fragments retired, independent of the inclusive sequence envelope.
    pub discarded_fragments: usize,
}

/// Original packet proving a document boundary, plus its exact immutable source range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpMetadataBoundary {
    /// Original arrival record ordinal.
    pub record: usize,
    /// Exact complete original record, including packet headers/extensions/padding.
    pub source: Range<usize>,
    /// Extended sequence of the observed preceding marker.
    pub sequence: u64,
    /// Uninterpreted timestamp on that marker.
    pub timestamp: u32,
    /// Untrusted recorder replay time, never local receive or capture time.
    pub replay_received_ns: u64,
}

/// One exact original packet/payload range in reconstructed sequence order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpMetadataFragment {
    /// Original arrival record ordinal; it may decrease after sequence reordering.
    pub record: usize,
    /// Original complete record range, including framing and datagram.
    pub source: Range<usize>,
    /// Exact copied payload range in the original file, excluding headers and padding.
    pub payload: Range<usize>,
    /// Corresponding range in the assembled document.
    pub document: Range<usize>,
    /// Extended sequence in the selected generation.
    pub sequence: u64,
    /// Original uninterpreted RTP timestamp; changes do not split an XML document.
    pub timestamp: u32,
    /// Original untrusted recorder replay time; may reverse after sequence ordering.
    pub replay_received_ns: u64,
}

/// Source proof of one marker-complete document; timestamps grant no source authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpDocumentProvenance {
    /// Preceding marker establishing a known start boundary.
    pub boundary: RtpMetadataBoundary,
    /// Exact fragments in reconstruction order, independently of original arrival order.
    pub fragments: Vec<RtpMetadataFragment>,
    /// Replay processing time at first ordered delivery.
    pub replay_started_ns: u64,
    /// Replay processing time at the closing marker.
    pub replay_completed_ns: u64,
}

/// Bounded retained-source processing report. It never certifies physical continuity or absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpMetadataReport {
    /// Exact complete original source length, including unparsed suffixes.
    pub input_bytes: usize,
    /// Every examined complete record in original arrival order.
    pub records: Vec<RtpMetadataRecord>,
    /// Every explicit gap, retirement, packet refusal, XML rejection or parser stop.
    pub issues: Vec<RtpMetadataIssue>,
    /// Stable terminal reason: clean EOF is separate from successful interpretation.
    pub end_reason: &'static str,
    /// Source bytes whose records were not processed after a terminal refusal.
    pub unprocessed_span: Option<Range<usize>>,
    /// All retained marker-complete documents, including rejected XML.
    pub complete_documents: usize,
    /// Complete documents accepted by the frozen vendor-cognition parser.
    pub usable_documents: usize,
    /// Marker-complete documents rejected by the frozen parser.
    pub rejected_documents: usize,
}
impl RtpMetadataReport {
    /// True only for clean bounded EOF with usable XML and no lost/refused selected content.
    /// Initial probation and discard through the first observed marker remain explicit records;
    /// this result applies only after that synchronization boundary, never before it.
    pub fn processing_complete(&self) -> bool {
        self.end_reason == "end_of_input"
            && self.usable_documents != 0
            && self.rejected_documents == 0
            && self.issues.is_empty()
            && self.unprocessed_span.is_none()
    }
}

/// One original-packet-derived XML candidate. Rejected XML remains retained without typed claims.
#[derive(Clone)]
pub struct RtpMetadataDocument {
    index: usize,
    bytes: Vec<u8>,
    projection: Option<Vec<u8>>,
    parsed: Option<EventDocument>,
    parse_error: Option<&'static str>,
    provenance: RtpDocumentProvenance,
}
impl RtpMetadataDocument {
    /// Zero-based complete transport-document occurrence; repeats are never coalesced.
    pub fn index(&self) -> usize {
        self.index
    }
    /// Digest of the exact assembled XML, a derivative of the original RTP payload spans.
    pub fn source_digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.bytes)
    }
    /// Exact XML byte length.
    pub fn source_bytes(&self) -> usize {
        self.bytes.len()
    }
    /// Deterministic vendor-cognition projection, absent for rejected XML.
    pub fn projection_digest(&self) -> Option<ContentDigest> {
        self.projection
            .as_ref()
            .map(|bytes| ContentDigest::sha256(bytes))
    }
    /// Parsed vendor claims, which may contain private values; apply disclosure policy.
    pub fn document(&self) -> Option<&EventDocument> {
        self.parsed.as_ref()
    }
    /// Stable payload-free parser refusal for retained marker-complete bytes.
    pub fn parse_error(&self) -> Option<&'static str> {
        self.parse_error
    }
    /// Exact packet and payload attribution, including the preceding boundary witness.
    pub fn provenance(&self) -> &RtpDocumentProvenance {
        &self.provenance
    }
}
impl fmt::Debug for RtpMetadataDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RtpMetadataDocument")
            .field("index", &self.index)
            .field("source_digest", &self.source_digest())
            .field("source_bytes", &self.bytes.len())
            .field("parse_error", &self.parse_error)
            .field("provenance", &self.provenance)
            .finish()
    }
}

/// One source-closed immutable batch, including zero-document and partial processing results.
#[derive(Clone)]
pub struct RetainedRtpMetadata {
    identity: ContentDigest,
    root: ContentDigest,
    recipe: record::Recipe,
    native_source: Option<NativeMetadataSource>,
    report: RtpMetadataReport,
    documents: Vec<RtpMetadataDocument>,
    anchor: LedgerAnchor,
}
impl fmt::Debug for RetainedRtpMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedRtpMetadata")
            .field("identity", &self.identity)
            .field("root", &self.root)
            .field("source_digest", &self.recipe.source)
            .field("documents", &self.documents.len())
            .field("end_reason", &self.report.end_reason)
            .finish()
    }
}
impl RetainedRtpMetadata {
    /// Immutable import identity, binding owner, source, limits and exact interpretation.
    pub const fn identity(&self) -> ContentDigest {
        self.identity
    }
    /// Exact root containing the replay file, recipe, report, every derivative and any native source.
    pub const fn publication_root(&self) -> ContentDigest {
        self.root
    }
    /// Digest of the complete replay packet file, not reconstructed XML. For native acquisition
    /// this is a deterministic millisecond projection; `native_source_digest` identifies originals.
    pub const fn source_digest(&self) -> ContentDigest {
        self.recipe.source
    }
    /// Exact replay packet file length, including the complete projected source prefix.
    pub const fn source_bytes(&self) -> usize {
        self.recipe.source_bytes
    }
    /// Digest of the canonical replay report and all document source mappings.
    pub const fn report_digest(&self) -> ContentDigest {
        self.recipe.report
    }
    /// Independent owner attribution and receive interval.
    pub fn binding(&self) -> &SourceBinding {
        &self.recipe.binding
    }
    /// Exact owner stream pin and bounds used for original and cold replay.
    pub fn config(&self) -> &RtpMetadataConfig {
        &self.recipe.config
    }
    /// Replay-file record outcomes and explicit processing boundaries. Native acquisition stops
    /// and projection omissions remain separate; use `processing_complete` for the whole result.
    pub fn report(&self) -> &RtpMetadataReport {
        &self.report
    }
    /// Every completed candidate, including parse refusals and duplicate occurrences.
    pub fn documents(&self) -> &[RtpMetadataDocument] {
        &self.documents
    }
    /// Original custody anchor, stable across exact retries and unrelated commits.
    pub fn authority_anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// Exact acquisition mode, bound by separate immutable recipe domains.
    pub const fn source_mode(&self) -> &'static str {
        if self.recipe.native_source.is_some() {
            "native_rtsp_tcp"
        } else {
            "owner_supplied_rtpdump"
        }
    }
    /// Meaning of the packet-file digest and replay report's millisecond clock.
    pub const fn source_representation(&self) -> &'static str {
        if self.recipe.native_source.is_some() {
            "derived_rtpdump_from_native_observations"
        } else {
            "original_owner_supplied_rtpdump"
        }
    }
    /// Original bounded acquisition evidence, including exact nanosecond packet observations.
    /// Its private route and SDP values require the caller's disclosure policy.
    pub fn native_source(&self) -> Option<&NativeMetadataSource> {
        self.native_source.as_ref()
    }
    /// Original canonical native source digest, separate from its replay-file projection.
    pub const fn native_source_digest(&self) -> Option<ContentDigest> {
        match self.recipe.native_source {
            Some((digest, _)) => Some(digest),
            None => None,
        }
    }
    /// Complete interpretation requires both bounded acquisition and packet replay to finish.
    /// It never certifies camera identity, trusted capture time, coverage or physical absence.
    pub fn processing_complete(&self) -> bool {
        self.report.processing_complete()
            && self
                .native_source
                .as_ref()
                .is_none_or(NativeMetadataSource::processing_complete)
    }
    /// Frozen XML interpretation, independently pinned from packet replay generation.
    pub const fn parser_generation(&self) -> &'static str {
        super::PARSER_GENERATION
    }
    /// Vendor labels are cognition, not authority.
    pub const fn plane(&self) -> Plane {
        Plane::Cognition
    }
    /// Source custody proves the bytes, not a camera's claims or authenticated origin.
    pub const fn provenance(&self) -> ProvenanceClass {
        ProvenanceClass::VendorClaimed
    }

    /// Reconstruct solely from retained original packet source under frozen bounds.
    /// Every source span, terminal refusal, XML projection, manifest and ledger link is checked.
    pub fn open(
        deployment: &ReferenceDeployment,
        identity: ContentDigest,
        expected_root: Option<ContentDigest>,
        cx: &ReplayCx<impl ReplayAdmission>,
    ) -> Result<Self, MetadataError> {
        super::admit(deployment, cx, "onvif_rtp_metadata:open")?;
        deployment
            .ledger()
            .verify_durable_head()
            .map_err(|_| MetadataError::Custody)?;
        if identity.algorithm() != DigestAlgorithm::Sha256 {
            return Err(MetadataError::InvalidBinding);
        }
        let deletions = DeletionIndex::read(deployment).map_err(|_| MetadataError::Custody)?;
        let slot = slot(identity)?;
        check_deleted(&deletions, identity, [identity])?;
        if deployment.publisher().is_broken_slot(&slot) {
            return Err(MetadataError::Custody);
        }
        let visible = deployment
            .publisher()
            .root(&slot)
            .ok_or(MetadataError::Unavailable)?;
        if visible.state != LocalPublicationState::Durable
            || expected_root.is_some_and(|expected| expected != visible.root)
        {
            return Err(MetadataError::Custody);
        }
        check_deleted(&deletions, identity, [visible.root])?;
        deployment
            .publisher()
            .require_durable_record(&slot)
            .map_err(|_| MetadataError::Custody)?;
        let encoded = super::read(deployment, identity, super::MAX_RECIPE_BYTES, cx)?;
        let recipe = record::decode(&encoded)?;
        if recipe.site != deployment.site_lineage() {
            return Err(MetadataError::Custody);
        }
        check_deleted(&deletions, identity, [recipe.source, recipe.report])?;
        let source = super::read(deployment, recipe.source, recipe.source_bytes, cx)?;
        if source.len() != recipe.source_bytes {
            return Err(MetadataError::Custody);
        }
        let native_source = if let Some((digest, length)) = recipe.native_source {
            check_deleted(&deletions, identity, [digest])?;
            let bytes = super::read(deployment, digest, length, cx)?;
            if bytes.len() != length || length > MAX_NATIVE_SOURCE_BYTES {
                return Err(MetadataError::Custody);
            }
            super::checkpoint(cx, "onvif_rtp_metadata:native_replay")?;
            let native =
                NativeMetadataSource::decode(&bytes).map_err(|_| MetadataError::Custody)?;
            validate_native_binding(&native, &recipe.binding, &recipe.config)
                .map_err(|_| MetadataError::Custody)?;
            if native
                .canonical_bytes()
                .map_err(|_| MetadataError::Custody)?
                != bytes
                || native.rtpdump().map_err(|_| MetadataError::Custody)? != source
            {
                return Err(MetadataError::Custody);
            }
            Some(native)
        } else {
            None
        };
        let replay = replay::analyze(&source, recipe.config, || {
            super::checkpoint(cx, "onvif_rtp_metadata:replay")
        })?;
        let report_bytes = record::report(&replay.report, &replay.documents)?;
        if ContentDigest::sha256(&report_bytes) != recipe.report
            || super::read(deployment, recipe.report, MAX_REPORT_BYTES, cx)? != report_bytes
        {
            return Err(MetadataError::Custody);
        }
        let manifest = manifest(identity, &recipe, &replay.documents)?;
        check_deleted(
            &deletions,
            identity,
            std::iter::once(manifest.root()).chain(manifest.children().iter().copied()),
        )?;
        if manifest.root() != visible.root
            || super::read(deployment, manifest.root(), MAX_MANIFEST_BYTES, cx)?
                != manifest.canonical_bytes()
        {
            return Err(MetadataError::Custody);
        }
        for document in &replay.documents {
            if super::read(
                deployment,
                document.source_digest(),
                document.bytes.len(),
                cx,
            )? != document.bytes
            {
                return Err(MetadataError::Custody);
            }
            if let Some(projection) = &document.projection {
                if super::read(
                    deployment,
                    ContentDigest::sha256(projection),
                    projection.len(),
                    cx,
                )? != *projection
                {
                    return Err(MetadataError::Custody);
                }
            }
        }
        let anchor = super::check_publication(deployment, &slot, &manifest, &recipe.binding, cx)?;
        deployment
            .publisher()
            .require_durable_record(&slot)
            .map_err(|_| MetadataError::Custody)?;
        deployment
            .ledger()
            .verify_durable_head()
            .map_err(|_| MetadataError::Custody)?;
        super::checkpoint(cx, "onvif_rtp_metadata:verified")?;
        Ok(Self {
            identity,
            root: manifest.root(),
            recipe,
            native_source,
            report: replay.report,
            documents: replay.documents,
            anchor,
        })
    }
}

/// Retain the complete original dump and a bounded deterministic replay, even when no usable XML
/// survives. A custody success is separate from `report().processing_complete()`. Exact retries
/// validate existing objects and resume publication; they never silently repair missing evidence.
pub fn retain(
    deployment: &mut ReferenceDeployment,
    source: &[u8],
    binding: SourceBinding,
    config: RtpMetadataConfig,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<RetainedRtpMetadata, MetadataError> {
    retain_inner(deployment, source, binding, config, None, cx)
}

/// Retain a finite native RTSP acquisition and its exact deterministic packet-file projection.
/// Original SDP and nanosecond packet observations share the same flat publication root as the
/// replay recipe, report and XML. No socket, credential lookup or network effect occurs here.
/// Partial/failed acquisitions still retain original evidence; completeness is independent.
pub fn retain_native(
    deployment: &mut ReferenceDeployment,
    native: &NativeMetadataSource,
    binding: SourceBinding,
    config: RtpMetadataConfig,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<RetainedRtpMetadata, MetadataError> {
    super::admit(deployment, cx, "onvif_rtp_metadata:native_admit")?;
    validate_native_binding(native, &binding, &config)?;
    let native_bytes = native
        .canonical_bytes()
        .map_err(|_| MetadataError::InvalidBinding)?;
    if native_bytes.len() > MAX_NATIVE_SOURCE_BYTES {
        return Err(MetadataError::Limit);
    }
    // Validate the durable interpretation before publishing its handle, not only on cold open.
    let durable_native =
        NativeMetadataSource::decode(&native_bytes).map_err(|_| MetadataError::Custody)?;
    validate_native_binding(&durable_native, &binding, &config)
        .map_err(|_| MetadataError::Custody)?;
    let source = native
        .rtpdump()
        .map_err(|_| MetadataError::InvalidBinding)?;
    if durable_native
        .rtpdump()
        .map_err(|_| MetadataError::Custody)?
        != source
    {
        return Err(MetadataError::Custody);
    }
    drop(durable_native);
    super::checkpoint(cx, "onvif_rtp_metadata:native_projected")?;
    retain_inner(
        deployment,
        &source,
        binding,
        config,
        Some((native, &native_bytes)),
        cx,
    )
}

fn retain_inner(
    deployment: &mut ReferenceDeployment,
    source: &[u8],
    binding: SourceBinding,
    config: RtpMetadataConfig,
    native: Option<(&NativeMetadataSource, &[u8])>,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<RetainedRtpMetadata, MetadataError> {
    super::admit(deployment, cx, "onvif_rtp_metadata:admit")?;
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(|_| MetadataError::Custody)?;
    if deployment.ledger().batches().len() >= super::MAX_HISTORY_BATCHES
        || super::history_work(deployment)? >= super::MAX_HISTORY_DELTAS
    {
        return Err(MetadataError::Limit);
    }
    binding.validate()?;
    config.validate()?;
    if !super::record::valid_label(deployment.site_lineage()) {
        return Err(MetadataError::InvalidBinding);
    }
    if source.len() > config.limits.max_input_bytes {
        return Err(MetadataError::Limit);
    }
    let replay = replay::analyze(source, config, || {
        super::checkpoint(cx, "onvif_rtp_metadata:replay")
    })?;
    let report_bytes = record::report(&replay.report, &replay.documents)?;
    let recipe = record::Recipe {
        site: deployment.site_lineage().to_owned(),
        binding,
        config,
        source: ContentDigest::sha256(source),
        source_bytes: source.len(),
        report: ContentDigest::sha256(&report_bytes),
        native_source: native.map(|(_, bytes)| (ContentDigest::sha256(bytes), bytes.len())),
    };
    let encoded = record::encode(&recipe)?;
    if record::decode(&encoded)? != recipe {
        return Err(MetadataError::Custody);
    }
    let identity = ContentDigest::sha256(&encoded);
    let slot = slot(identity)?;
    let manifest = manifest(identity, &recipe, &replay.documents)?;
    let manifest_bytes = manifest.canonical_bytes();
    let deletions = DeletionIndex::read(deployment).map_err(|_| MetadataError::Custody)?;
    check_deleted(
        &deletions,
        identity,
        std::iter::once(manifest.root()).chain(manifest.children().iter().copied()),
    )?;
    if deployment.publisher().is_broken_slot(&slot) {
        return Err(MetadataError::Custody);
    }
    let mut objects = vec![source, encoded.as_slice(), report_bytes.as_slice()];
    if let Some((_, bytes)) = native {
        objects.push(bytes);
    }
    for document in &replay.documents {
        objects.push(document.bytes.as_slice());
        if let Some(projection) = &document.projection {
            objects.push(projection.as_slice());
        }
    }
    if let Some(existing) = deployment.publisher().root(&slot) {
        if existing.root != manifest.root() {
            return Err(MetadataError::Custody);
        }
        if existing.state == LocalPublicationState::Durable {
            deployment
                .publisher()
                .require_durable_record(&slot)
                .map_err(|_| MetadataError::Custody)?;
        }
        for bytes in objects
            .iter()
            .copied()
            .chain(std::iter::once(manifest_bytes.as_slice()))
        {
            if super::read(deployment, ContentDigest::sha256(bytes), bytes.len(), cx)? != bytes {
                return Err(MetadataError::Custody);
            }
        }
        match super::check_publication(deployment, &slot, &manifest, &recipe.binding, cx) {
            Ok(_) | Err(MetadataError::Unavailable) => {}
            Err(error) => return Err(error),
        }
    } else {
        let object = format!("object:local-root:{}", slot.as_str());
        if deployment.ledger().batches().iter().any(|batch| {
            batch
                .deltas
                .iter()
                .any(|delta| delta.object_id.as_str() == object)
        }) {
            return Err(MetadataError::Custody);
        }
        super::checkpoint(cx, "onvif_rtp_metadata:stage")?;
        let staged = deployment.stage_and_publish(&slot, &objects, cx)?;
        if staged.manifest != manifest {
            return Err(MetadataError::Custody);
        }
    }
    super::checkpoint(cx, STAGE_RTP_METADATA_PUBLISH)?;
    let receipt =
        deployment.publish_and_commit(&slot, &manifest, recipe.binding.receive_interval, cx)?;
    let retained = RetainedRtpMetadata {
        identity,
        root: receipt.root,
        recipe,
        native_source: native.map(|(native, _)| native.clone()),
        report: replay.report,
        documents: replay.documents,
        anchor: receipt.anchor,
    };
    cx.checkpoint_post_commit("onvif_rtp_metadata:committed");
    Ok(retained)
}

fn validate_native_binding(
    native: &NativeMetadataSource,
    binding: &SourceBinding,
    config: &RtpMetadataConfig,
) -> Result<(), MetadataError> {
    binding.validate()?;
    config.validate()?;
    native
        .validate()
        .map_err(|_| MetadataError::InvalidBinding)?;
    let acquired = native.config();
    let ended_ns = native.ended_ns().ok_or(MetadataError::InvalidBinding)?;
    let earliest = acquired
        .receive_origin_ns
        .checked_add(i128::from(native.started_ns()))
        .ok_or(MetadataError::InvalidBinding)?;
    let latest = acquired
        .receive_origin_ns
        .checked_add(i128::from(ended_ns))
        .ok_or(MetadataError::InvalidBinding)?;
    if acquired.binding.key() != config.stream
        || acquired.payload_type != config.payload_type
        || binding.receive_interval.earliest.0 != earliest
        || binding.receive_interval.latest.0 != latest
    {
        return Err(MetadataError::InvalidBinding);
    }
    Ok(())
}

/// Lifecycle admission performs the same complete cold replay before exposing owner scope.
pub(crate) fn lifecycle_sensor(
    deployment: &ReferenceDeployment,
    identity: ContentDigest,
    cx: &ReplayCx<impl ReplayAdmission>,
) -> Result<SensorId, MetadataError> {
    Ok(RetainedRtpMetadata::open(deployment, identity, None, cx)?
        .binding()
        .sensor_id
        .clone())
}

fn slot(identity: ContentDigest) -> Result<SlotName, MetadataError> {
    SlotName::parse(&format!("onvif-rtp-metadata-{}", &identity.to_text()[7..]))
        .map_err(|_| MetadataError::InvalidBinding)
}
fn manifest(
    identity: ContentDigest,
    recipe: &record::Recipe,
    documents: &[RtpMetadataDocument],
) -> Result<ObjectManifest, MetadataError> {
    let mut children = vec![identity, recipe.source, recipe.report];
    if let Some((digest, _)) = recipe.native_source {
        children.push(digest);
    }
    for document in documents {
        children.push(document.source_digest());
        if let Some(projection) = document.projection_digest() {
            children.push(projection);
        }
    }
    children.sort_unstable();
    children.dedup();
    ObjectManifest::new(slot(identity)?.as_str(), children, None)
        .map_err(crate::ReferenceError::from)
        .map_err(Into::into)
}
fn check_deleted(
    deletions: &DeletionIndex,
    identity: ContentDigest,
    objects: impl IntoIterator<Item = ContentDigest>,
) -> Result<(), MetadataError> {
    let unit = format!("slot:onvif-rtp-metadata-{}", &identity.to_text()[7..]);
    super::check_deleted_for_unit(deletions, identity, &unit, objects)
}
