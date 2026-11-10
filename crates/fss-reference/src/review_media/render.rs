#![forbid(unsafe_code)]
//! Source-authenticated movie review materialization with current privacy screening.
//!
//! This read boundary neither grants recipient access nor publishes or exports anything.
//! The review owner authorizes media reads before entering it. It reuses the same native
//! decoders, selected-picture cache and rational movie timing as `fss-file export-movie`.
//! All prerequisite ranges must reach successful EOF. Output contains only screened luma,
//! in presentation order, with explicit edit/gap timing and no audio or invented pictures.

/// Shared bounded selected-picture cache; input pins alone do not authenticate source custody.
pub mod output;
/// Shared exact conversion from selected rational movie intervals to playback nanoseconds.
pub mod timing;

use std::cell::Cell;
use std::collections::BTreeMap;
use std::ops::Range;
use std::path::PathBuf;

use fss_container::demux::{MovieDecodeSpan, MovieSelectionLimits, VideoCodec};
use fss_container::matroska_gray::{MatroskaGrayError, TIMED_PROFILE, TimedGrayMatroskaConfig};
use fss_core::{
    CanonicalEncode, CanonicalEncoder, ContentDigest, ContractError, DigestAlgorithm, LedgerAnchor,
    SensorCapsule, SensorId, Sha256Hasher,
};

use crate::ingest::privacy_mask::{MaskBinding, PrivacyMaskError, current_mask, encode_marker};
use crate::ingest::recorded_decode::h264::{DecoderLimits, RecordedH264Range, RecordedH264Request};
use crate::ingest::recorded_decode::h265::{
    DecoderLimits as H265DecoderLimits, RecordedH265Range, RecordedH265Request,
};
use crate::ingest::recorded_decode::video_budget::{
    RecordedVideoDecodeBudget, VIDEO_DECODE_WORK_MODEL,
};
use crate::ingest::recorded_decode::{ComponentInterpretation, RecordedDecodeError};
use crate::ingest::retained::{
    MAX_MOVIE_ORIGIN_READ_BYTES, RetainedMovieSelection, SourceReadBudget,
};
use crate::ingest::{FileIngestError, RetainedFileImport, RetainedReadLimits};
use crate::{ReferenceDeployment, ReferenceError, ReplayCx};

use output::{FrameInput, MovieOutput, MovieOutputError, SourceBinding};
use timing::{MovieTiming, MovieTimingError};

/// Hard limit on complete canonical lineage receipts, independently of output media.
pub const MAX_REVIEW_RENDER_RECEIPT_BYTES: usize = 8 * 1024 * 1024;
/// Largest retained media payload admitted by this renderer.
pub const MAX_REVIEW_MEDIA_BYTES: u64 = 256 * 1024 * 1024;
/// Largest cumulative source-chunk allowance, including selection and revalidation reads.
pub const MAX_REVIEW_SOURCE_READ_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Conservative origin-replay reservation for one complete native source verification.
pub const ORIGIN_REVALIDATION_RESERVATION: u64 = MAX_MOVIE_ORIGIN_READ_BYTES;
/// Receipt domain; these bytes are derived provenance, never a recipient grant.
pub const REVIEW_RENDER_DOMAIN: &str = "fss.review_movie_render.v1";
const CHUNK: usize = 4096;
const MAX_SOURCE_DEPENDENCIES: usize = 65_536;

/// Independent owner-narrowable read, decode, storage and output ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReviewMovieLimits {
    /// Existing custody read limits; the complete original is bounded before allocation.
    pub read: RetainedReadLimits,
    /// Existing exact movie selector limits; at most 1024 aggregate prerequisite pictures.
    pub selection: MovieSelectionLimits,
    /// Cumulative conservative native-origin reservations; ordinary files consume zero.
    pub max_origin_read_bytes: u64,
    /// Cumulative complete-source and decoder chunk reads, never renewed for revalidation.
    pub max_decode_read_bytes: u64,
    /// Unique selected screened luma stored before output; repeated edits reuse it.
    pub max_cached_luma_bytes: u64,
    /// Complete Matroska bytes, including repeated presentation occurrences and headers.
    pub max_output_bytes: u64,
    /// Native encoded-byte plus coded-luma-capacity admission units over all decoder ranges.
    pub max_decode_work_units: u64,
    /// Maximum coded/visible dimension on either axis.
    pub max_dimension: u32,
    /// Maximum coded luma capacity per picture, independently of byte allowances.
    pub max_pixels: usize,
    /// Maximum slices per picture, additionally narrowed to the native decoder ceiling.
    pub max_slices_per_picture: u32,
}

impl Default for ReviewMovieLimits {
    fn default() -> Self {
        Self {
            read: RetainedReadLimits {
                max_source_bytes: fss_container::demux::MAX_MP4_INPUT_BYTES as u64,
                ..RetainedReadLimits::default()
            },
            selection: MovieSelectionLimits {
                max_decode_samples: output::MAX_MOVIE_FRAMES,
                ..MovieSelectionLimits::default()
            },
            max_origin_read_bytes: 3 * ORIGIN_REVALIDATION_RESERVATION,
            max_decode_read_bytes: 512 * 1024 * 1024,
            max_cached_luma_bytes: output::DEFAULT_LUMA_BYTES,
            max_output_bytes: 64 * 1024 * 1024,
            max_decode_work_units: 100_000_000,
            max_dimension: 4096,
            max_pixels: 4_194_304,
            max_slices_per_picture: 4096,
        }
    }
}

impl ReviewMovieLimits {
    /// Reject widened or zero bounds before any source read; no ceiling is silently increased.
    pub fn validate(&self) -> Result<(), ReviewRenderError> {
        self.selection
            .validate()
            .map_err(|_| ReviewRenderError::Limit)?;
        if self.selection.max_decode_samples > output::MAX_MOVIE_FRAMES
            || self.read.max_source_bytes == 0
            || self.read.max_source_bytes > fss_container::demux::MAX_MP4_INPUT_BYTES as u64
            || self.read.max_chunk_bytes == 0
            || self.read.max_chunk_bytes > crate::ingest::retained::MAX_RETAINED_PAYLOAD_BYTES
            || self.read.max_segment_bytes == 0
            || self.read.max_segment_bytes > crate::ingest::retained::MAX_RETAINED_PAYLOAD_BYTES
            || self.max_origin_read_bytes > 8 * ORIGIN_REVALIDATION_RESERVATION
            || !(1..=MAX_REVIEW_SOURCE_READ_BYTES).contains(&self.max_decode_read_bytes)
            || !(1..=output::MAX_LUMA_BYTES).contains(&self.max_cached_luma_bytes)
            || !(1..=MAX_REVIEW_MEDIA_BYTES).contains(&self.max_output_bytes)
            || self.max_decode_work_units == 0
            || self.max_decode_work_units > 16_000_000_000
            || !(1..=4096).contains(&self.max_dimension)
            || !(256..=4_194_304).contains(&self.max_pixels)
            || self.max_slices_per_picture == 0
            || self.max_slices_per_picture > 4096
        {
            return Err(ReviewRenderError::Limit);
        }
        Ok(())
    }
}

impl CanonicalEncode for ReviewMovieLimits {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        for value in [
            self.read.max_source_bytes,
            self.read.max_chunk_bytes,
            self.read.max_segment_bytes,
            self.selection.max_work as u64,
            self.selection.max_rows as u64,
            self.selection.max_decode_samples as u64,
            self.selection.max_source_bytes,
            self.selection.max_annex_b_bytes,
            self.max_origin_read_bytes,
            self.max_decode_read_bytes,
            self.max_cached_luma_bytes,
            self.max_output_bytes,
            self.max_decode_work_units,
            u64::from(self.max_dimension),
            self.max_pixels as u64,
            u64::from(self.max_slices_per_picture),
        ] {
            e.u64(value);
        }
    }
}

/// One exact retained import and half-open movie-clock interval; this is not a UTC query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewMovieRequest {
    /// Completed source import; paths and an implicit latest recording are not admitted.
    pub import_identity: ContentDigest,
    /// Inclusive tick in the source movie timescale.
    pub movie_start_tick: u64,
    /// Exclusive tick in the source movie timescale.
    pub movie_end_tick: u64,
    /// Full rendering allowances, bound into the retained receipt and owning approval.
    pub limits: ReviewMovieLimits,
}

impl ReviewMovieRequest {
    /// Validate all declarations before source or authority access.
    pub fn validate(&self) -> Result<(), ReviewRenderError> {
        self.limits.validate()?;
        if self.import_identity.algorithm() != DigestAlgorithm::Sha256
            || self.import_identity.is_laboratory()
            || self.import_identity.bytes() == [0; 32]
            || self.movie_start_tick >= self.movie_end_tick
        {
            return Err(ReviewRenderError::InvalidRequest);
        }
        Ok(())
    }

    /// Exact interval passed to the existing authenticated movie selector.
    pub fn interval(&self) -> Range<u64> {
        self.movie_start_tick..self.movie_end_tick
    }

    /// Bounded versioned request identity; no authorization is implied.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.canonical_bytes())
    }

    /// Exact bounded request encoding used by the review owner's prepared approval.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut e = CanonicalEncoder::new();
        e.text("fss.review_movie_request.v1");
        self.encode_canonical(&mut e);
        e.finish()
    }
}

impl CanonicalEncode for ReviewMovieRequest {
    fn encode_canonical(&self, e: &mut CanonicalEncoder) {
        e.digest(self.import_identity);
        e.u64(self.movie_start_tick);
        e.u64(self.movie_end_tick);
        self.limits.encode_canonical(e);
    }
}

/// Complete refusal; no partial media or successful receipt is returned.
#[derive(Debug)]
pub enum ReviewRenderError {
    /// Request, source-frame or privacy identities disagree.
    InvalidRequest,
    /// A hard or owner-supplied bound was exhausted.
    Limit,
    /// The source, authority, principal or exact privacy generation changed.
    Stale,
    /// Owner cancellation was observed before releasing output.
    Cancelled,
    /// Existing source custody or native-origin replay refused.
    Source(Box<FileIngestError>),
    /// Existing native picture decoding refused.
    Decode(Box<RecordedDecodeError>),
    /// Current privacy policy was invalid or unavailable.
    Privacy(Box<PrivacyMaskError>),
    /// Selected picture cache refused inconsistent or missing frames.
    Output(MovieOutputError),
    /// Exact rational intervals cannot be represented by the timed profile.
    Timing(MovieTimingError),
    /// Native Matroska framing refused the requested shape or interval.
    Container(MatroskaGrayError),
    /// Durable authority could not be verified.
    Authority(Box<ReferenceError>),
    /// Canonical encoding exceeded its contract.
    Contract(ContractError),
}

impl std::fmt::Display for ReviewRenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest => f.write_str("invalid movie review request or source binding"),
            Self::Limit => f.write_str("movie review allowance exceeded"),
            Self::Stale => f.write_str("movie review source, privacy or authority is stale"),
            Self::Cancelled => f.write_str("movie review cancelled"),
            Self::Source(e) => write!(f, "movie review source: {e}"),
            Self::Decode(e) => write!(f, "movie review decode: {e}"),
            Self::Privacy(e) => write!(f, "movie review privacy: {e}"),
            Self::Output(e) => e.fmt(f),
            Self::Timing(e) => e.fmt(f),
            Self::Container(e) => e.fmt(f),
            Self::Authority(e) => write!(f, "movie review authority: {e}"),
            Self::Contract(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for ReviewRenderError {}
impl From<FileIngestError> for ReviewRenderError {
    fn from(value: FileIngestError) -> Self {
        Self::Source(Box::new(value))
    }
}
impl From<RecordedDecodeError> for ReviewRenderError {
    fn from(value: RecordedDecodeError) -> Self {
        Self::Decode(Box::new(value))
    }
}
impl From<PrivacyMaskError> for ReviewRenderError {
    fn from(value: PrivacyMaskError) -> Self {
        Self::Privacy(Box::new(value))
    }
}
impl From<MovieOutputError> for ReviewRenderError {
    fn from(value: MovieOutputError) -> Self {
        Self::Output(value)
    }
}
impl From<MovieTimingError> for ReviewRenderError {
    fn from(value: MovieTimingError) -> Self {
        Self::Timing(value)
    }
}
impl From<MatroskaGrayError> for ReviewRenderError {
    fn from(value: MatroskaGrayError) -> Self {
        Self::Container(value)
    }
}
impl From<ContractError> for ReviewRenderError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

struct FrameProof {
    capsule_digest: ContentDigest,
    decoder: ContentDigest,
    receipt: ContentDigest,
    bytes: Vec<u8>,
}

struct ReadBudget {
    source: SourceReadBudget,
    maximum_origin: u64,
    origin_reserved: Cell<u64>,
}

impl ReadBudget {
    fn select(
        &self,
        retained: &RetainedFileImport,
        deployment: &ReferenceDeployment,
        request: &ReviewMovieRequest,
        cx: &ReplayCx,
    ) -> Result<RetainedMovieSelection, ReviewRenderError> {
        // Reserve before reading. Failed reads and validation do not restore allowances.
        self.source.reserve(retained.manifest().input_bytes)?;
        let native = retained.manifest().adapter_id != crate::ingest::ADP_FILE_ROW_ID;
        let origin = if native {
            ORIGIN_REVALIDATION_RESERVATION
        } else {
            0
        };
        let next = self
            .origin_reserved
            .get()
            .checked_add(origin)
            .filter(|next| *next <= self.maximum_origin)
            .ok_or(ReviewRenderError::Limit)?;
        self.origin_reserved.set(next);
        Ok(retained.select_movie_interval_with_origin_limit(
            deployment,
            request.interval(),
            request.limits.read,
            request.limits.selection,
            origin,
            cx,
        )?)
    }
}

/// Opaque, fully screened materialization. It grants neither retention nor recipient delivery.
pub struct RenderedReviewMovie {
    request: ReviewMovieRequest,
    root: PathBuf,
    principal: String,
    anchor: LedgerAnchor,
    selected: RetainedMovieSelection,
    retained: RetainedFileImport,
    sensor: SensorId,
    privacy: MaskBinding,
    dependencies: Vec<ContentDigest>,
    dimensions: [u32; 2],
    frames: usize,
    duration_ns: u64,
    lineage: ContentDigest,
    media: Vec<u8>,
    media_digest: ContentDigest,
    receipt: Vec<u8>,
    receipt_digest: ContentDigest,
    decode_work: u64,
    reads: ReadBudget,
}

impl std::fmt::Debug for RenderedReviewMovie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RenderedReviewMovie")
            .field("frames", &self.frames)
            .field("media_bytes", &self.media.len())
            .finish_non_exhaustive()
    }
}

impl RenderedReviewMovie {
    /// Screened grayscale Matroska bytes. The owner still must authorize any disclosure.
    pub fn bytes(&self) -> &[u8] {
        &self.media
    }
    /// Exact complete media identity.
    pub fn media_digest(&self) -> ContentDigest {
        self.media_digest
    }
    /// Selected occurrence, native frame and source transformation identity.
    pub fn lineage_digest(&self) -> ContentDigest {
        self.lineage
    }
    /// Complete bounded canonical source, timing, mask and transformation provenance.
    pub fn receipt_bytes(&self) -> &[u8] {
        &self.receipt
    }
    /// Identity of `receipt_bytes()`.
    pub fn receipt_digest(&self) -> ContentDigest {
        self.receipt_digest
    }
    /// Exact source-backed selection, including explicit gaps and capture-time label.
    pub fn selection(&self) -> &RetainedMovieSelection {
        &self.selected
    }
    /// Exact completed source root, useful as a retention/deletion dependency.
    pub fn source_import_root(&self) -> ContentDigest {
        self.selected.import_root
    }
    /// Sorted original root, manifest, parts, chunks, capsule and mask dependencies.
    pub fn source_dependency_digests(&self) -> &[ContentDigest] {
        &self.dependencies
    }
    /// Actual mask generation applied before pixels entered the cache.
    pub fn privacy(&self) -> &MaskBinding {
        &self.privacy
    }
    /// The source sensor authenticated by native frame capsules.
    pub fn sensor(&self) -> &SensorId {
        &self.sensor
    }
    /// Historical source-completion anchor, distinct from current authority.
    pub fn source_anchor(&self) -> &LedgerAnchor {
        &self.selected.authority_anchor
    }
    /// Exact authority anchor validated before the result was released.
    pub fn anchor(&self) -> &LedgerAnchor {
        &self.anchor
    }
    /// Principal of the source-read context, not a remote recipient grant.
    pub fn principal(&self) -> &str {
        &self.principal
    }
    /// Unchanged native screened luma dimensions.
    pub fn dimensions(&self) -> [u32; 2] {
        self.dimensions
    }
    /// Complete presentation occurrence count; repeated edits count separately.
    pub fn frames(&self) -> usize {
        self.frames
    }
    /// Requested movie interval duration; leading and trailing gaps remain included.
    pub fn duration_ns(&self) -> u64 {
        self.duration_ns
    }
    /// Native decode admission consumed across the complete prerequisite ranges.
    pub fn decode_work_units(&self) -> u64 {
        self.decode_work
    }
    /// Cumulative source read reservations, including final revalidation and later calls.
    pub fn decode_source_bytes(&self) -> u64 {
        self.reads.source.used()
    }
    /// Conservative origin-replay reservations, including later revalidation calls.
    pub fn origin_read_bytes_reserved(&self) -> u64 {
        self.reads.origin_reserved.get()
    }
    /// Move media and canonical receipt to the already-authorized publication owner.
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.media, self.receipt)
    }

    /// Reopen and rehash the complete source and native origin without refilling allowances.
    /// Authority, principal, context root, deletion and exact privacy generation must remain.
    /// Call before publication if other work has occurred since `render_movie` returned.
    pub fn revalidate(
        &self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<(), ReviewRenderError> {
        checkpoint(cx, "review_movie:revalidate")?;
        self.check_context(deployment, cx)?;
        let retained = RetainedFileImport::open(
            deployment,
            self.request.import_identity,
            self.request.limits.read,
            cx,
        )?;
        if retained != self.retained || current_mask(deployment, &self.sensor)? != self.privacy {
            return Err(ReviewRenderError::Stale);
        }
        let selected = self
            .reads
            .select(&retained, deployment, &self.request, cx)?;
        if selected != self.selected {
            return Err(ReviewRenderError::Stale);
        }
        checkpoint(cx, "review_movie:revalidate_complete")?;
        self.check_context(deployment, cx)?;
        let current = RetainedFileImport::open(
            deployment,
            self.request.import_identity,
            self.request.limits.read,
            cx,
        )?;
        if current != self.retained || current_mask(deployment, &self.sensor)? != self.privacy {
            return Err(ReviewRenderError::Stale);
        }
        checkpoint(cx, "review_movie:release")
    }

    fn check_context(
        &self,
        deployment: &ReferenceDeployment,
        cx: &ReplayCx,
    ) -> Result<(), ReviewRenderError> {
        if cx.root_dir() != self.root
            || deployment.root() != self.root
            || cx.io_authority().principal() != self.principal
            || deployment.current_anchor() != &self.anchor
        {
            return Err(ReviewRenderError::Stale);
        }
        verify_head(deployment)
    }
}

fn checkpoint(cx: &ReplayCx, stage: &'static str) -> Result<(), ReviewRenderError> {
    cx.checkpoint(stage)
        .map_err(|_| ReviewRenderError::Cancelled)
}

fn cache_checkpoint(cx: &ReplayCx) -> Result<(), MovieOutputError> {
    cx.checkpoint("review_movie:cache")
        .map_err(|_| MovieOutputError::Cancelled)
}

fn verify_head(deployment: &ReferenceDeployment) -> Result<(), ReviewRenderError> {
    deployment
        .ledger()
        .verify_durable_head()
        .map_err(ReferenceError::from)
        .map_err(|e| ReviewRenderError::Authority(Box::new(e)))
}

/// Materialize one authorized exact-source movie interval, without writing or publishing.
///
/// The calling review owner is responsible for media-read/prepare authority. Empty selections,
/// unsupported native codecs, missing output pictures, mismatched masks and late failures refuse
/// the whole operation. Memory contains at most the admitted unique luma, output and native
/// decoder/source buffers; complete media size is checked before allocating its output buffer.
pub(crate) fn render_movie(
    deployment: &ReferenceDeployment,
    request: &ReviewMovieRequest,
    cx: &ReplayCx,
) -> Result<RenderedReviewMovie, ReviewRenderError> {
    request.validate()?;
    checkpoint(cx, "review_movie:begin")?;
    if cx.root_dir() != deployment.root() {
        return Err(ReviewRenderError::Stale);
    }
    verify_head(deployment)?;
    let anchor = deployment.current_anchor().clone();
    let retained =
        RetainedFileImport::open(deployment, request.import_identity, request.limits.read, cx)?;
    let reads = ReadBudget {
        source: SourceReadBudget::new(request.limits.max_decode_read_bytes),
        maximum_origin: request.limits.max_origin_read_bytes,
        origin_reserved: Cell::new(0),
    };
    let selected = reads.select(&retained, deployment, request, cx)?;
    let mut output = MovieOutput::new(
        &selected.selection,
        SourceBinding {
            import_identity: selected.import_identity,
            import_root: selected.import_root,
            manifest_digest: selected.manifest_digest,
            input_sha256: selected.input_sha256,
            track_id: selected.track_id,
            codec: selected.codec,
        },
        request.limits.max_cached_luma_bytes,
    )?;
    let timing = MovieTiming::new(&selected.selection, &mut || {
        cx.checkpoint("review_movie:timing")
            .map_err(|_| MovieTimingError::Cancelled)
    })?;
    let mut native_budget = RecordedVideoDecodeBudget::new(request.limits.max_decode_work_units);
    let mut proofs = BTreeMap::new();
    let mut proof_bytes = 0_usize;
    let mut privacy = None;
    let mut sensor = None;
    let mut decoded_frames = 0_u64;
    for span in &selected.selection.decode_spans {
        checkpoint(cx, "review_movie:decode_span")?;
        decoded_frames = decoded_frames
            .checked_add(decode_span(
                deployment,
                request,
                &selected,
                span,
                &mut output,
                &mut proofs,
                &mut proof_bytes,
                &mut privacy,
                &mut sensor,
                &mut native_budget,
                &reads.source,
                cx,
            )?)
            .ok_or(ReviewRenderError::Limit)?;
    }
    let complete = output.finish(&mut || cache_checkpoint(cx))?;
    let privacy = privacy.ok_or(ReviewRenderError::InvalidRequest)?;
    let sensor = sensor.ok_or(ReviewRenderError::InvalidRequest)?;
    if timing.frames() != complete.frames() {
        return Err(ReviewRenderError::InvalidRequest);
    }
    let dimensions = complete
        .frame(0)
        .ok_or(ReviewRenderError::InvalidRequest)?
        .dimensions;
    let config = TimedGrayMatroskaConfig::new(dimensions, timing.duration_ns())?;
    let initialization = config.initialization()?;
    let mut media_bytes = initialization.bytes().len() as u64;
    for ordinal in 0..complete.frames() {
        checkpoint(cx, "review_movie:quote_output")?;
        let frame = complete
            .frame(ordinal)
            .ok_or(ReviewRenderError::InvalidRequest)?;
        if frame.dimensions != dimensions {
            return Err(ReviewRenderError::InvalidRequest);
        }
        let interval = timing
            .frame(ordinal)
            .ok_or(ReviewRenderError::InvalidRequest)?;
        let framing = config.frame(ordinal as u64, interval.start_ns, interval.end_ns)?;
        media_bytes = media_bytes
            .checked_add(framing.prefix().len() as u64)
            .and_then(|n| n.checked_add(frame.pixels().len() as u64))
            .filter(|n| *n <= request.limits.max_output_bytes)
            .ok_or(ReviewRenderError::Limit)?;
    }
    let mut media = Vec::new();
    media
        .try_reserve_exact(usize::try_from(media_bytes).map_err(|_| ReviewRenderError::Limit)?)
        .map_err(|_| ReviewRenderError::Limit)?;
    let mut hash = Sha256Hasher::new();
    append(&mut media, &mut hash, initialization.bytes(), cx)?;
    for ordinal in 0..complete.frames() {
        let frame = complete
            .frame(ordinal)
            .ok_or(ReviewRenderError::InvalidRequest)?;
        let interval = timing
            .frame(ordinal)
            .ok_or(ReviewRenderError::InvalidRequest)?;
        let framing = config.frame(ordinal as u64, interval.start_ns, interval.end_ns)?;
        if framing.payload_bytes() != frame.pixels().len() {
            return Err(ReviewRenderError::InvalidRequest);
        }
        append(&mut media, &mut hash, framing.prefix(), cx)?;
        append(&mut media, &mut hash, frame.pixels(), cx)?;
    }
    if media.len() as u64 != media_bytes {
        return Err(ReviewRenderError::InvalidRequest);
    }
    let media_digest = ContentDigest::new(DigestAlgorithm::Sha256, hash.finalize()?);
    let dependencies = source_dependencies(&retained, &privacy, &proofs)?;
    let mut rendered = RenderedReviewMovie {
        request: request.clone(),
        root: deployment.root().to_path_buf(),
        principal: cx.io_authority().principal().to_owned(),
        anchor,
        selected,
        retained,
        sensor,
        privacy,
        dependencies,
        dimensions,
        frames: complete.frames(),
        duration_ns: timing.duration_ns(),
        lineage: complete.lineage_digest(),
        media,
        media_digest,
        receipt: Vec::new(),
        receipt_digest: ContentDigest::sha256(&[]),
        decode_work: native_budget.used(),
        reads,
    };
    // A completed cache is insufficient: rehash every original and recheck current authority.
    rendered.revalidate(deployment, cx)?;
    rendered.receipt = receipt(&rendered, &complete, &timing, &proofs, decoded_frames, cx)?;
    rendered.receipt_digest = ContentDigest::sha256(&rendered.receipt);
    checkpoint(cx, "review_movie:receipt_complete")?;
    rendered.check_context(deployment, cx)?;
    if current_mask(deployment, &rendered.sensor)? != rendered.privacy {
        return Err(ReviewRenderError::Stale);
    }
    checkpoint(cx, "review_movie:release_complete")?;
    Ok(rendered)
}

fn append(
    out: &mut Vec<u8>,
    hash: &mut Sha256Hasher,
    bytes: &[u8],
    cx: &ReplayCx,
) -> Result<(), ReviewRenderError> {
    for chunk in bytes.chunks(CHUNK) {
        checkpoint(cx, "review_movie:output")?;
        out.extend_from_slice(chunk);
        hash.update(chunk);
    }
    Ok(())
}

fn check_source(
    retained: &RetainedFileImport,
    selected: &RetainedMovieSelection,
) -> Result<(), ReviewRenderError> {
    if retained.import_identity() != selected.import_identity
        || retained.import_root() != selected.import_root
        || retained.manifest_digest() != selected.manifest_digest
        || retained.manifest().input_sha256 != selected.input_sha256
    {
        return Err(ReviewRenderError::Stale);
    }
    Ok(())
}

fn bind_privacy(
    value: &MaskBinding,
    privacy: &mut Option<MaskBinding>,
) -> Result<(), ReviewRenderError> {
    if let Some(expected) = privacy {
        if expected != value {
            return Err(ReviewRenderError::Stale);
        }
    } else {
        *privacy = Some(value.clone());
    }
    Ok(())
}

fn segment_in_span(segment: u64, span: &MovieDecodeSpan) -> Result<usize, ReviewRenderError> {
    let segment = usize::try_from(segment).map_err(|_| ReviewRenderError::InvalidRequest)?;
    let end = span
        .first_sample
        .checked_add(span.sample_count)
        .ok_or(ReviewRenderError::Limit)?;
    if !(span.first_sample..end).contains(&segment) {
        return Err(ReviewRenderError::InvalidRequest);
    }
    Ok(segment)
}

fn bind_frame(
    sensor: &mut Option<SensorId>,
    capsule: &SensorCapsule,
    privacy: &Option<MaskBinding>,
    binding: ContentDigest,
) -> Result<(), ReviewRenderError> {
    if let Some(expected) = sensor {
        if expected != &capsule.sensor_id {
            return Err(ReviewRenderError::InvalidRequest);
        }
    } else {
        *sensor = Some(capsule.sensor_id.clone());
    }
    if privacy.as_ref().is_none_or(|p| p.digest() != binding) {
        return Err(ReviewRenderError::Stale);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decode_span(
    deployment: &ReferenceDeployment,
    request: &ReviewMovieRequest,
    selected: &RetainedMovieSelection,
    span: &MovieDecodeSpan,
    output: &mut MovieOutput<'_>,
    proofs: &mut BTreeMap<usize, FrameProof>,
    proof_bytes: &mut usize,
    privacy: &mut Option<MaskBinding>,
    sensor: &mut Option<SensorId>,
    budget: &mut RecordedVideoDecodeBudget,
    source_budget: &SourceReadBudget,
    cx: &ReplayCx,
) -> Result<u64, ReviewRenderError> {
    let limits = request.limits;
    macro_rules! consume {
        ($range:expr) => {{
            let mut range = $range;
            check_source(range.retained(), selected)?;
            bind_privacy(range.mask(), privacy)?;
            while let Some(frame) = range.next_frame_with_budget(deployment, budget, cx)? {
                let segment = segment_in_span(frame.segment_index(), span)?;
                if output.wants(segment) {
                    let receipt = frame.receipt();
                    bind_frame(sensor, receipt.capsule(), privacy, receipt.mask_binding())?;
                    output.insert(
                        FrameInput {
                            segment,
                            dimensions: frame.dimensions(),
                            pixels: frame.pixels(),
                            luma_sha256: receipt.luma_sha256().bytes(),
                            decode_receipt: receipt.digest(),
                        },
                        &mut || cache_checkpoint(cx),
                    )?;
                    let bytes = receipt.encoded();
                    *proof_bytes = proof_bytes
                        .checked_add(bytes.len())
                        .filter(|n| *n <= MAX_REVIEW_RENDER_RECEIPT_BYTES)
                        .ok_or(ReviewRenderError::Limit)?;
                    proofs.insert(
                        segment,
                        FrameProof {
                            capsule_digest: receipt.capsule_digest(),
                            decoder: receipt.decoder_identity(),
                            receipt: receipt.digest(),
                            bytes,
                        },
                    );
                }
            }
            range.decoded()
        }};
    }
    Ok(match selected.codec {
        VideoCodec::Avc => consume!(RecordedH264Range::open_with_budgets(
            deployment,
            RecordedH264Request {
                import_identity: request.import_identity,
                first_segment: span.first_sample,
                segment_count: span.sample_count,
                interpretation: ComponentInterpretation::YCbCr,
                read_limits: limits.read,
                decoder_limits: DecoderLimits {
                    max_width: limits.max_dimension,
                    max_height: limits.max_dimension,
                    max_macroblocks: (limits.max_pixels / 256) as u32,
                    max_pictures: span.sample_count as u64,
                    max_nal_bytes: limits.read.max_segment_bytes.min(16 * 1024 * 1024) as usize,
                    max_slices_per_picture: limits
                        .max_slices_per_picture
                        .min(DecoderLimits::default().max_slices_per_picture),
                    ..DecoderLimits::default()
                },
            },
            source_budget,
            budget,
            cx
        )?),
        VideoCodec::Hevc => consume!(RecordedH265Range::open_with_budgets(
            deployment,
            RecordedH265Request {
                import_identity: request.import_identity,
                first_segment: span.first_sample,
                segment_count: span.sample_count,
                interpretation: ComponentInterpretation::YCbCr,
                read_limits: limits.read,
                decoder_limits: H265DecoderLimits {
                    max_width: limits.max_dimension,
                    max_height: limits.max_dimension,
                    max_luma_samples: limits.max_pixels as u64,
                    max_pictures: span.sample_count as u64,
                    max_nal_bytes: limits.read.max_segment_bytes.min(16 * 1024 * 1024) as usize,
                    max_slices_per_picture: limits
                        .max_slices_per_picture
                        .min(H265DecoderLimits::default().max_slices_per_picture),
                    ..H265DecoderLimits::default()
                },
            },
            source_budget,
            budget,
            cx
        )?),
    })
}

fn source_dependencies(
    retained: &RetainedFileImport,
    privacy: &MaskBinding,
    proofs: &BTreeMap<usize, FrameProof>,
) -> Result<Vec<ContentDigest>, ReviewRenderError> {
    let manifest = retained.manifest();
    let count = manifest
        .ordered_chunks
        .len()
        .checked_add(manifest.part_roots.len())
        .and_then(|n| n.checked_add(proofs.len()))
        .and_then(|n| n.checked_add(3))
        .filter(|n| *n <= MAX_SOURCE_DEPENDENCIES)
        .ok_or(ReviewRenderError::Limit)?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| ReviewRenderError::Limit)?;
    values.extend([retained.import_root(), retained.manifest_digest()]);
    values.extend_from_slice(&manifest.ordered_chunks);
    values.extend_from_slice(&manifest.part_roots);
    values.extend(proofs.values().map(|proof| proof.capsule_digest));
    if let Some(policy) = privacy.policy_digest() {
        values.push(policy);
    }
    values.sort_unstable();
    values.dedup();
    Ok(values)
}

fn receipt(
    rendered: &RenderedReviewMovie,
    complete: &output::CompleteMovieOutput,
    timing: &MovieTiming,
    proofs: &BTreeMap<usize, FrameProof>,
    decoded_frames: u64,
    cx: &ReplayCx,
) -> Result<Vec<u8>, ReviewRenderError> {
    let mut e = CanonicalEncoder::new();
    e.text(REVIEW_RENDER_DOMAIN);
    e.u32(1);
    e.text(TIMED_PROFILE);
    e.digest(ContentDigest::sha256(include_bytes!("render.rs")));
    e.digest(ContentDigest::sha256(include_bytes!("render/timing.rs")));
    rendered.request.encode_canonical(&mut e);
    e.text(&rendered.principal);
    // The current authority head is checked at every release, but is not a source-transform
    // input. The owning review record binds it separately. This receipt must remain stable
    // when crash recovery verifies identical bytes after their own root-reachability append.
    rendered.selected.authority_anchor.encode_canonical(&mut e);
    e.digest(rendered.selected.import_root);
    e.digest(rendered.selected.manifest_digest);
    e.digest(rendered.selected.input_sha256);
    e.u64(rendered.selected.input_bytes);
    e.text(&rendered.selected.source_adapter_id);
    e.text(&rendered.selected.source_adapter_generation);
    e.text(&rendered.selected.capture_time_label);
    e.text(rendered.sensor.as_str());
    e.digest(rendered.privacy.digest());
    encode_marker(&mut e, rendered.privacy.policy_digest());
    match rendered.privacy.generation() {
        None => e.u8(0),
        Some(generation) => {
            e.u8(1);
            e.u64(generation);
        }
    }
    e.digest(rendered.lineage);
    e.digest(rendered.media_digest);
    e.u64(rendered.media.len() as u64);
    e.u32(rendered.dimensions[0]);
    e.u32(rendered.dimensions[1]);
    e.u64(rendered.duration_ns);
    e.u64(rendered.frames as u64);
    e.u64(complete.unique_frames() as u64);
    e.u64(complete.luma_bytes());
    e.u64(decoded_frames);
    e.text(VIDEO_DECODE_WORK_MODEL);
    e.u64(rendered.decode_work);
    e.u64(rendered.reads.source.used());
    e.u64(rendered.reads.origin_reserved.get());
    e.u64(rendered.dependencies.len() as u64);
    let mut bytes = Vec::new();
    append_receipt(&mut bytes, &e.finish_checked()?)?;
    for dependency in &rendered.dependencies {
        checkpoint(cx, "review_movie:receipt_dependency")?;
        let mut e = CanonicalEncoder::new();
        e.digest(*dependency);
        append_receipt(&mut bytes, &e.finish_checked()?)?;
    }
    let mut e = CanonicalEncoder::new();
    e.u64(proofs.len() as u64);
    append_receipt(&mut bytes, &e.finish_checked()?)?;
    for (segment, proof) in proofs {
        checkpoint(cx, "review_movie:receipt_frame")?;
        let mut e = CanonicalEncoder::new();
        e.u64(*segment as u64);
        e.digest(proof.capsule_digest);
        e.digest(proof.decoder);
        e.digest(proof.receipt);
        // The sealed native receipt already embeds the complete canonical source capsule.
        // Append its length and bytes separately so an oversized combined receipt never
        // allocates beyond its hard bound merely to discover that it must refuse.
        e.u64(proof.bytes.len() as u64);
        append_receipt(&mut bytes, &e.finish_checked()?)?;
        append_receipt(&mut bytes, &proof.bytes)?;
    }
    let mut e = CanonicalEncoder::new();
    e.u64(complete.frames() as u64);
    append_receipt(&mut bytes, &e.finish_checked()?)?;
    for ordinal in 0..complete.frames() {
        checkpoint(cx, "review_movie:receipt_occurrence")?;
        let frame = complete
            .frame(ordinal)
            .ok_or(ReviewRenderError::InvalidRequest)?;
        let interval = timing
            .frame(ordinal)
            .ok_or(ReviewRenderError::InvalidRequest)?;
        let mut e = CanonicalEncoder::new();
        e.u64(frame.segment as u64);
        e.u64(interval.start_ns);
        e.u64(interval.end_ns);
        e.digest(ContentDigest::new(
            DigestAlgorithm::Sha256,
            frame.luma_sha256,
        ));
        append_receipt(&mut bytes, &e.finish_checked()?)?;
    }
    Ok(bytes)
}

fn append_receipt(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ReviewRenderError> {
    out.len()
        .checked_add(bytes.len())
        .filter(|n| *n <= MAX_REVIEW_RENDER_RECEIPT_BYTES)
        .ok_or(ReviewRenderError::Limit)?;
    out.try_reserve_exact(bytes.len())
        .map_err(|_| ReviewRenderError::Limit)?;
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
#[path = "render/tests.rs"]
mod tests;
