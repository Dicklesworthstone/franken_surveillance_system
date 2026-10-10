#![forbid(unsafe_code)]
//! An exact HTTP archive prefix becomes a locally self-contained retained MJPEG recording.
//!
//! Native HTTP/MIME parsing selects complete original JPEGs. Their concatenation is explicitly
//! a reconstructed media stream: the original response, wrappers, partial tail and exact maps
//! remain in the same publication closure. No capture clock, live continuity or EOF is invented.
//! Current sensor privacy masks are applied by existing retained decoders, after this byte-only
//! custody boundary. Original access and destination retention require independent live authority.

mod provenance;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fss_codec_mjpeg::{DecodeBudget, http_mjpeg::JpegWireSpan};
use fss_core::{
    BatchId, CanonicalEncode, CanonicalEncoder, CapsuleId, CaptureInterval, ClockBasis,
    ContentDigest, ContractError, DigestAlgorithm, EvidenceDelta, ObjectId, Plane, SensorCapsule,
    SensorId, SensorSourceBytesSpec, StreamId, TimestampNs,
};
use fss_geometry::WorkBudget;
use fss_object::ObjectManifest;
use fss_publication::{LocalRootPublisher, PublishCancellation, PublishCutPoint};

use super::file_adapter::{
    self, CaptureHint, FileImportManifest, FileIngestAdapter, FileIngestError, SegmentSpan,
};
use super::file_publication::FilePublicationPlan;
use super::http_archive::{HttpArchiveLimits, HttpWireArchive, HttpWirePin, HttpWireScope};
use super::http_replay::{HttpReplayAccess, HttpReplayLimits, HttpReplayStep, HttpWireReplay};
use crate::{ReferenceDeployment, ReplayCx};

pub(crate) use provenance::{verify_membership, verify_originals, verify_segment_budgeted};

/// Explicit adapter identity; old ADP-FILE imports keep their existing encoding and rules.
pub const ADAPTER: &str = "ADP-HTTP-MJPEG-ARCHIVE-001";
pub(crate) const GENERATION: &str = "gen:http-mjpeg-archive:v1:";
pub(crate) const DOMAIN: &str = "fss.http_mjpeg_import.v1";
/// Cooperative authority/cancellation checkpoint before every custody/publication boundary.
pub const STAGE_HTTP_IMPORT: &str = "http_import:source_custody";
/// A bounded recording selection, never a top-k frame list.
pub const MAX_FRAMES: usize = 4096;
/// Original and reconstructed streams each have an independent 64 MiB bound.
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_SPANS: usize = 65_536;
pub(crate) const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;
const CHUNK_BYTES: usize = 1024 * 1024;

/// Exact source selection and owner-declared destination camera/time binding.
#[derive(Clone, Debug)]
pub struct HttpImportRequest {
    /// Original response, generation, receive clock and retention-decision identities.
    pub source: HttpWireScope,
    /// Independently retained prefix; later source roots are refused, never followed.
    pub pin: HttpWirePin,
    /// Owner assertion connecting the response to a sensor; not remote authentication.
    pub sensor: SensorId,
    /// Owner-selected stream identity. Reconnects require a new source generation.
    pub stream: StreamId,
    /// Explicit ingest timestamp; source monotonic receive times are never converted to UTC.
    pub receive_time: TimestampNs,
    /// Optional recording timing assumptions, using the exact existing file-import semantics.
    pub capture_hint: Option<CaptureHint>,
    /// Independent selected-frame ceiling, at most 4096.
    pub max_frames: usize,
    /// Independent original and reconstructed byte ceiling, at most 64 MiB.
    pub max_bytes: u64,
}
impl HttpImportRequest {
    /// Deterministic request identity for exact approval. Includes every timing/budget input.
    pub fn digest(&self) -> Result<ContentDigest, HttpImportError> {
        if self.pin.scope != self.source.digest().map_err(source_error)?
            || self.pin.head.algorithm() != DigestAlgorithm::Sha256
            || self.pin.head.bytes() == [0; 32]
            || self.pin.reads == 0
            || self.pin.reads > 4096
            || self.pin.bytes == 0
            || self.pin.bytes > self.max_bytes
            || !(1..=MAX_FRAMES).contains(&self.max_frames)
            || !(1..=MAX_BYTES).contains(&self.max_bytes)
            || self.receive_time.0 < 0
        {
            return Err(HttpImportError::Invalid("source, time or bounds"));
        }
        if let Some(hint) = self.capture_hint {
            if hint.start_ns.0 < 0 || !hint.assumed_fps.is_finite() || hint.assumed_fps <= 0.0 {
                return Err(HttpImportError::Invalid("capture hint"));
            }
            FileIngestAdapter::compute_capture_interval(0, Some(&hint), self.receive_time)?;
        }
        let mut e = CanonicalEncoder::new();
        e.text("fss.http_mjpeg_import_request.v1");
        provenance::encode_scope(&mut e, self.source, self.pin);
        e.text(self.sensor.as_str());
        e.text(self.stream.as_str());
        e.i128(self.receive_time.0);
        e.bool(self.capture_hint.is_some());
        if let Some(hint) = self.capture_hint {
            e.i128(hint.start_ns.0);
            e.u64(hint.uncertainty_ns);
            e.u64(hint.assumed_fps.to_bits());
        }
        e.u64(self.max_frames as u64);
        e.u64(self.max_bytes);
        Ok(ContentDigest::sha256(&e.finish()))
    }
}

/// Independent permissions for original-byte disclosure and exact destination retention.
/// Callers must recheck current policy, deadline and revocation; no permissive default exists.
pub trait HttpImportAuthority {
    /// Permit the named source bytes to be copied into this deployment under its current policy.
    fn permit(&self, request: &HttpImportRequest, destination: &ReferenceDeployment) -> bool;
}

/// A complete local import does not imply that the camera response or physical scene completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpImportEnding {
    /// Original HTTP length/chunk framing AND MIME terminal delimiter were verified.
    ExplicitFramingComplete,
    /// Only the independently selected prefix exists; no socket EOF evidence was supplied.
    PinnedPrefix,
}
impl HttpImportEnding {
    /// Stable operator spelling, separate from import-publication completion.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExplicitFramingComplete => "explicit_framing_complete",
            Self::PinnedPrefix => "pinned_prefix",
        }
    }
}

/// Source, permission and custody failures remain explicit and carry no media/header text.
#[derive(Debug)]
pub enum HttpImportError {
    /// Invalid exact selection, timing assumption or independent resource ceiling.
    Invalid(&'static str),
    /// Native replay reached the exact selected ending without one complete original JPEG.
    /// This is neither an empty scene nor a claim that the original response completed.
    NoCompleteFrames,
    /// Current source/destination permission, cancellation or deadline refused.
    Denied,
    /// Archive/framing/origin verification refused; details contain no source bytes.
    Source(String),
    /// Existing retained import/publication owner refused.
    Import(Box<FileIngestError>),
}
impl HttpImportError {
    /// Stable registered error identity.
    pub fn stable_id(&self) -> &'static str {
        match self {
            Self::Invalid(_) | Self::NoCompleteFrames => "ERR-HTTP-IMPORT-REQUEST-001",
            Self::Denied => "ERR-HTTP-IMPORT-AUTHORITY-001",
            Self::Source(_) => "ERR-HTTP-IMPORT-SOURCE-001",
            Self::Import(_) => "ERR-HTTP-IMPORT-CUSTODY-001",
        }
    }
}
impl fmt::Display for HttpImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.stable_id())
    }
}
impl std::error::Error for HttpImportError {}
impl From<FileIngestError> for HttpImportError {
    fn from(e: FileIngestError) -> Self {
        Self::Import(Box::new(e))
    }
}
impl From<ContractError> for HttpImportError {
    fn from(e: ContractError) -> Self {
        FileIngestError::from(e).into()
    }
}
fn source_error(e: impl fmt::Debug) -> HttpImportError {
    HttpImportError::Source(format!("{e:?}"))
}
fn storage_error(e: impl Into<FileIngestError>) -> HttpImportError {
    HttpImportError::Import(Box::new(e.into()))
}
pub(crate) fn corrupt(reason: &str) -> FileIngestError {
    FileIngestError::CorruptSegment {
        detail: format!("HTTP import origin: {reason}"),
    }
}
pub(crate) fn checkpoint(cx: &ReplayCx) -> Result<(), FileIngestError> {
    cx.checkpoint(STAGE_HTTP_IMPORT)
        .map_err(|_| FileIngestError::CancellationRequested {
            stage: STAGE_HTTP_IMPORT,
        })
}

struct Access<'a> {
    authority: &'a dyn HttpImportAuthority,
    request: &'a HttpImportRequest,
    destination: &'a ReferenceDeployment,
    cx: &'a ReplayCx,
}
impl PublishCancellation for Access<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        checkpoint(self.cx).is_err() || !self.authority.permit(self.request, self.destination)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FrameOrigin {
    pub encoded: ContentDigest,
    pub bytes: u64,
    pub capture: CaptureInterval,
    pub spans: Vec<JpegWireSpan>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WireOrigin {
    pub root: ContentDigest,
    pub manifest: Vec<u8>,
    pub metadata: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Proof {
    pub source: HttpWireScope,
    pub pin: HttpWirePin,
    pub request: ContentDigest,
    pub sensor: SensorId,
    pub stream: StreamId,
    pub receive_time: TimestampNs,
    pub assumed_time: bool,
    pub ending: HttpImportEnding,
    pub roots: Vec<WireOrigin>,
    pub frames: Vec<FrameOrigin>,
}

/// Existing retained import plus source ending and exact origin proof identity.
#[derive(Debug)]
pub struct HttpImportReceipt {
    /// Source-closed recording identity consumed by existing watch, decode and inference APIs.
    pub import_identity: ContentDigest,
    /// Durable root of the existing file-import publication format.
    pub import_root: ContentDigest,
    /// Exact retained file-import metadata.
    pub manifest_digest: ContentDigest,
    /// Complete JPEGs retained in order, including duplicate source frames.
    pub frames: usize,
    /// `unknown` or the explicitly declared `operator_assumption`.
    pub capture_time_label: &'static str,
    /// Every original header and partial tail is retained, independent of this ending.
    pub ending: HttpImportEnding,
    /// Canonical origin proof, a leaf of the import's own publication closure.
    pub proof: ContentDigest,
    /// True only when the exact completed import was verified without new writes.
    pub reused: bool,
}

/// Execute one bounded native replay and publish its exact source-closed recording root last.
/// Independent whole-call budgets never refill per source read, frame or publication step.
pub fn import_http<'cx>(
    publisher: &LocalRootPublisher,
    destination: &mut ReferenceDeployment,
    request: &HttpImportRequest,
    authority: &dyn HttpImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'cx>,
    framing: &mut DecodeBudget<'cx>,
) -> Result<HttpImportReceipt, HttpImportError> {
    if cx.root_dir() != destination.root()
        || publisher.root_dir().starts_with(destination.root())
        || destination.root().starts_with(publisher.root_dir())
    {
        return Err(HttpImportError::Invalid(
            "distinct source and destination storage owners required",
        ));
    }
    let request_digest = request.digest()?;
    let mut payloads = BTreeMap::<ContentDigest, Vec<u8>>::new();
    let mut media = Vec::new();
    let mut frames = Vec::new();
    let (roots, ending) = {
        let access = Access {
            authority,
            request,
            destination,
            cx,
        };
        if access.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
            return Err(HttpImportError::Denied);
        }
        let archive = HttpWireArchive::load(
            publisher,
            request.source,
            request.pin,
            HttpArchiveLimits {
                maximum_reads: 4096,
                maximum_bytes: request.max_bytes,
                maximum_scan_roots: 65536,
                maximum_spool_object_bytes: 16 * 1024 * 1024,
            },
            &access,
            work,
        )
        .map_err(source_error)?;
        let mut roots = Vec::new();
        for (pin, wire) in archive.reads() {
            if access.cancel_requested(PublishCutPoint::AfterChildrenVerified) {
                return Err(HttpImportError::Denied);
            }
            let root_bytes = publisher.spool().read(pin.head).map_err(storage_error)?;
            let root = ObjectManifest::from_canonical_bytes(&root_bytes).map_err(storage_error)?;
            let metadata = root
                .metadata_digest()
                .ok_or(HttpImportError::Invalid("wire metadata"))?;
            for digest in root.children() {
                let bytes = publisher.spool().read(*digest).map_err(storage_error)?;
                work.charge(bytes.len() as u64).map_err(source_error)?;
                payloads.insert(*digest, bytes);
            }
            if !payloads.contains_key(&metadata)
                || !payloads.contains_key(&ContentDigest::new(DigestAlgorithm::Sha256, wire.sha256))
            {
                return Err(HttpImportError::Invalid("wire closure"));
            }
            roots.push(WireOrigin {
                root: pin.head,
                manifest: root_bytes.clone(),
                metadata: payloads
                    .get(&metadata)
                    .ok_or(HttpImportError::Invalid("wire metadata"))?
                    .clone(),
            });
            payloads.insert(pin.head, root_bytes);
        }
        let mut replay = HttpWireReplay::new(
            &archive,
            request.pin,
            HttpReplayLimits {
                // Permit parsing the terminal delimiter after an exactly full selection.
                // One bounded lookahead frame is refused below before transfer or publication.
                frames: request.max_frames as u64 + 1,
                ..HttpReplayLimits::default()
            },
        )
        .map_err(source_error)?;
        let mut ending = None;
        let mut spans_total = 0usize;
        for _ in 0..1_000_000 {
            let step = replay
                .step(HttpReplayAccess {
                    publisher,
                    cancellation: &access,
                    work,
                    framing,
                })
                .map_err(source_error)?;
            match step {
                HttpReplayStep::FrameReady => {
                    let receipt = replay
                        .pending_frame()
                        .ok_or(HttpImportError::Invalid("held frame"))?
                        .part()
                        .receipt();
                    if receipt.ordinal != frames.len() as u64 + 1
                        || frames.len() >= request.max_frames
                    {
                        return Err(HttpImportError::Invalid("frame sequence or limit"));
                    }
                    let frame = replay
                        .take_frame(
                            receipt.ordinal,
                            receipt.encoded_sha256,
                            HttpReplayAccess {
                                publisher,
                                cancellation: &access,
                                work,
                                framing,
                            },
                        )
                        .map_err(source_error)?;
                    let bytes = frame.part().bytes();
                    spans_total = spans_total
                        .checked_add(frame.source_spans().len())
                        .ok_or(HttpImportError::Invalid("span bound"))?;
                    if spans_total > MAX_SPANS
                        || media.len() as u64 + bytes.len() as u64 > request.max_bytes
                    {
                        return Err(HttpImportError::Invalid("media or span bound"));
                    }
                    work.charge(bytes.len() as u64).map_err(source_error)?;
                    media
                        .try_reserve(bytes.len())
                        .map_err(|_| HttpImportError::Invalid("media allocation"))?;
                    media.extend_from_slice(bytes);
                    frames.push(FrameOrigin {
                        encoded: ContentDigest::sha256(bytes),
                        bytes: bytes.len() as u64,
                        capture: FileIngestAdapter::compute_capture_interval(
                            frames.len(),
                            request.capture_hint.as_ref(),
                            request.receive_time,
                        )?,
                        spans: frame.source_spans().to_vec(),
                    });
                }
                HttpReplayStep::Complete => {
                    ending = Some(HttpImportEnding::ExplicitFramingComplete);
                    break;
                }
                HttpReplayStep::PrefixExhausted => {
                    ending = Some(HttpImportEnding::PinnedPrefix);
                    break;
                }
                _ => {}
            }
        }
        let ending = ending.ok_or(HttpImportError::Invalid("step limit"))?;
        if frames.is_empty() {
            return Err(HttpImportError::NoCompleteFrames);
        }
        (roots, ending)
    };
    let proof = Proof {
        source: request.source,
        pin: request.pin,
        request: request_digest,
        sensor: request.sensor.clone(),
        stream: request.stream.clone(),
        receive_time: request.receive_time,
        assumed_time: request.capture_hint.is_some(),
        ending,
        roots,
        frames,
    };
    publish(
        destination,
        request,
        authority,
        cx,
        work,
        proof,
        media,
        payloads,
    )
}

fn publish(
    destination: &mut ReferenceDeployment,
    request: &HttpImportRequest,
    authority: &dyn HttpImportAuthority,
    cx: &ReplayCx,
    work: &mut WorkBudget<'_>,
    proof: Proof,
    media: Vec<u8>,
    mut payloads: BTreeMap<ContentDigest, Vec<u8>>,
) -> Result<HttpImportReceipt, HttpImportError> {
    let proof_bytes = proof.encode()?;
    let proof_digest = ContentDigest::sha256(&proof_bytes);
    let identity = proof.identity()?;
    let hex = hex(identity);
    super::retained::refuse_deleted(destination, identity)?;
    let mut capsules = Vec::new();
    let mut segments = Vec::new();
    let mut offset = 0usize;
    for (index, origin) in proof.frames.iter().enumerate() {
        let end = offset
            .checked_add(origin.bytes as usize)
            .ok_or(HttpImportError::Invalid("offset"))?;
        let source = media
            .get(offset..end)
            .ok_or(HttpImportError::Invalid("media span"))?;
        let capsule = SensorCapsule::from_source_bytes(SensorSourceBytesSpec {
            capsule_id: CapsuleId::parse(format!("capsule:{hex}:{index:06}"))?,
            sensor_id: proof.sensor.clone(),
            stream_id: proof.stream.clone(),
            sequence: index as u64,
            capture: origin.capture,
            receive_time: proof.receive_time,
            clock_basis: ClockBasis::Estimated,
            source,
            frame_count: 1,
            gap_before: false,
        })?;
        segments.push(SegmentSpan {
            segment_index: index,
            offset: offset as u64,
            len: origin.bytes,
            segment_sha256: origin.encoded,
            capsule_id: capsule.capsule_id.clone(),
            gap_before: false,
        });
        let bytes = capsule.canonical_bytes();
        payloads.insert(ContentDigest::sha256(&bytes), bytes);
        capsules.push(capsule);
        offset = end;
    }
    let mut chunks = Vec::new();
    for bytes in media.chunks(CHUNK_BYTES) {
        let digest = ContentDigest::sha256(bytes);
        chunks.push(digest);
        payloads.insert(digest, bytes.to_vec());
    }
    let custody = ObjectManifest::new(
        "custody",
        chunks.iter().copied().collect::<BTreeSet<_>>(),
        None,
    )
    .map_err(storage_error)?;
    payloads.insert(custody.root(), custody.canonical_bytes());
    payloads.insert(proof_digest, proof_bytes);
    let mut manifest = FileImportManifest {
        input_sha256: ContentDigest::sha256(&media),
        input_bytes: media.len() as u64,
        format: "mjpeg".into(),
        detector_evidence: format!(
            "native_http_mime:reconstructed_jpeg_stream:original_wire_retained:{}",
            proof.ending.as_str()
        ),
        chunk_bytes: CHUNK_BYTES as u64,
        ordered_chunks: chunks,
        segment_spans: segments,
        omission_spans: Vec::new(),
        capsule_ids: capsules.iter().map(|c| c.capsule_id.clone()).collect(),
        limits_digest: proof.request,
        adapter_id: ADAPTER.into(),
        adapter_generation: format!("{GENERATION}{}", hex_digest(proof_digest)),
        part_roots: Vec::new(),
        capture_time_label: if proof.assumed_time {
            "operator_assumption"
        } else {
            "unknown"
        }
        .into(),
    };
    let publication = FilePublicationPlan::new(
        identity,
        payloads.keys().copied(),
        destination
            .limits()
            .manifest_children_max
            .min(destination.limits().batch_entries_max),
    )?;
    manifest.part_roots = publication.part_roots();
    let validity = CaptureInterval::new(
        capsules[0].capture.earliest,
        capsules
            .last()
            .ok_or(HttpImportError::Invalid("empty"))?
            .capture
            .latest,
    )?;
    let batch = BatchId::parse(format!("batch:file-import:{hex}:manifest"))?;
    let initial = EvidenceDelta {
        delta_id: format!("delta:file-import:{hex}:init"),
        family: "file_import".into(),
        object_id: ObjectId::parse(format!("object:file-import:{hex}"))?,
        prior_generation: None,
        new_generation: 1,
        validity,
        plane: Plane::Authority,
        payload_digest: custody.root(),
        witness_digest: None,
        operation_id: None,
    };
    let mut entries = vec![(initial, custody.root())];
    for capsule in &capsules {
        let digest = ContentDigest::sha256(&capsule.canonical_bytes());
        let delta = EvidenceDelta {
            delta_id: format!("delta:capsule:{}", capsule.capsule_id.as_str()),
            family: "sensor_capsule".into(),
            object_id: ObjectId::parse(format!("object:capsule:{}", capsule.capsule_id.as_str()))?,
            prior_generation: None,
            new_generation: 1,
            validity: capsule.capture,
            plane: Plane::Authority,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        };
        entries.push((delta, digest));
    }
    // A fixed one-entry partition keeps exact retries independent of deployment capacity.
    let batches = file_adapter::plan_capsule_batches(
        entries,
        1,
        destination.limits().journal_record_max_bytes as usize,
        destination.current_anchor(),
        &hex,
    )?;
    let root = publication.root_manifest(&manifest)?.root();
    let metadata = manifest.canonical_digest();
    let deltas = vec![
        EvidenceDelta {
            delta_id: format!("delta:file-import:{hex}:complete"),
            family: "file_import".into(),
            object_id: ObjectId::parse(format!("object:file-import:{hex}"))?,
            prior_generation: Some(1),
            new_generation: 2,
            validity,
            plane: Plane::Authority,
            payload_digest: metadata,
            witness_digest: Some(root),
            operation_id: None,
        },
        EvidenceDelta {
            delta_id: format!("delta:manifest:{hex}"),
            family: "file_import_manifest".into(),
            object_id: ObjectId::parse(format!("object:file-import-manifest:{hex}"))?,
            prior_generation: None,
            new_generation: 1,
            validity,
            plane: Plane::Authority,
            payload_digest: metadata,
            witness_digest: Some(root),
            operation_id: None,
        },
    ];
    let children = vec![metadata, root];
    guard(authority, request, destination, cx)?;
    let completed =
        file_adapter::retry::preflight(destination, &batches, &batch, identity, &manifest, cx)?;
    let receipt = |reused| HttpImportReceipt {
        import_identity: identity,
        import_root: root,
        manifest_digest: metadata,
        frames: proof.frames.len(),
        capture_time_label: if proof.assumed_time {
            "operator_assumption"
        } else {
            "unknown"
        },
        ending: proof.ending,
        proof: proof_digest,
        reused,
    };
    if completed.is_some() {
        publication.verify(destination, &manifest, cx)?;
        for (digest, expected) in &payloads {
            guard(authority, request, destination, cx)?;
            work.charge(expected.len() as u64).map_err(source_error)?;
            if destination
                .publisher()
                .spool()
                .read(*digest)
                .map_err(storage_error)?
                != *expected
            {
                return Err(HttpImportError::Invalid("completed custody differs"));
            }
        }
        return Ok(receipt(true));
    }
    publication.preflight_unstaged(
        destination,
        &manifest,
        validity,
        payloads.iter().map(|(d, b)| (*d, b.len())),
        cx,
    )?;
    file_adapter::check_commit_admission(
        destination,
        &batch,
        &deltas,
        &children,
        &publication,
        &batches,
        cx,
    )?;
    // A resumed part already exposes its original bytes as custody. Fresh archive input may
    // complete an unstaged suffix, but must never repair damage behind a visible prior root.
    let root_manifest = publication.root_manifest(&manifest)?;
    let metadata_bytes = manifest.canonical_bytes();
    for (slot, part) in publication
        .parts()
        .iter()
        .map(|p| (p.slot(), p.manifest()))
        .chain(std::iter::once((publication.slot(), &root_manifest)))
    {
        if destination
            .publisher()
            .root(slot)
            .is_some_and(|r| r.state != fss_publication::LocalPublicationState::Staged)
        {
            guard(authority, request, destination, cx)?;
            if destination
                .publisher()
                .spool()
                .read(part.root())
                .map_err(storage_error)?
                != part.canonical_bytes()
            {
                return Err(HttpImportError::Invalid("committed root differs"));
            }
            for digest in part.children() {
                guard(authority, request, destination, cx)?;
                let expected = if *digest == metadata {
                    &metadata_bytes
                } else {
                    payloads
                        .get(digest)
                        .ok_or(HttpImportError::Invalid("committed child membership"))?
                };
                work.charge(expected.len() as u64).map_err(source_error)?;
                if destination
                    .publisher()
                    .spool()
                    .read(*digest)
                    .map_err(storage_error)?
                    != *expected
                {
                    return Err(HttpImportError::Invalid("committed child differs"));
                }
            }
        }
    }
    for (digest, bytes) in &payloads {
        guard(authority, request, destination, cx)?;
        work.charge(bytes.len() as u64).map_err(source_error)?;
        let staged = destination
            .publisher_mut()
            .stage_object(bytes)
            .map_err(storage_error)?;
        if staged != *digest {
            return Err(HttpImportError::Invalid("staged identity"));
        }
        destination
            .publisher_mut()
            .verify_object(staged)
            .map_err(storage_error)?;
    }
    for planned in batches {
        guard(authority, request, destination, cx)?;
        file_adapter::append_planned_batch(
            destination,
            planned.batch_id,
            planned.deltas,
            planned.children,
            cx,
        )?;
    }
    guard(authority, request, destination, cx)?;
    publication.publish_guarded(destination, &manifest, validity, cx, &|current| {
        checkpoint(cx)?;
        if !authority.permit(request, current) {
            return Err(FileIngestError::CancellationRequested {
                stage: STAGE_HTTP_IMPORT,
            });
        }
        Ok(())
    })?;
    guard(authority, request, destination, cx)?;
    file_adapter::append_planned_batch(destination, batch, deltas, children, cx)?;
    // Completion is already durable; do not hide it behind a late optional read/cancel check.
    Ok(receipt(false))
}
fn guard(
    authority: &dyn HttpImportAuthority,
    request: &HttpImportRequest,
    destination: &ReferenceDeployment,
    cx: &ReplayCx,
) -> Result<(), HttpImportError> {
    checkpoint(cx)?;
    if !authority.permit(request, destination) {
        return Err(HttpImportError::Denied);
    }
    Ok(())
}
pub(crate) fn hex(d: ContentDigest) -> String {
    hex_digest(d)
}
fn hex_digest(d: ContentDigest) -> String {
    d.bytes().iter().map(|b| format!("{b:02x}")).collect()
}
