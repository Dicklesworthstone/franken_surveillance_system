#![forbid(unsafe_code)]
//! Bounded materialization of movie-time presentation occurrences from screened native frames.
//!
//! The caller authenticates `MovieSelection`, supplies sealed native frame pins, and consumes
//! every quoted decode span through successful EOF before calling `finish`. This helper owns
//! only selected luma and metadata; it has no filesystem, source-custody or effect authority.
//! Original segment indices identify cached frames. Presentation occurrences retain edit order
//! and repetition without copying their pixels again. Any insertion refusal fences completion.

use fss_container::demux::{
    MAX_ANNEX_B_BYTES, MAX_MP4_INPUT_BYTES, MAX_MP4_SAMPLES, MovieGapKind, MovieInterval,
    MovieSelection, MovieSelectionLimits, VideoCodec,
};
use fss_core::{ContentDigest, DigestAlgorithm, Sha256Hasher};
use std::ops::Range;

/// Maximum presentation occurrences and aggregate prerequisite pictures.
pub const MAX_MOVIE_FRAMES: usize = 1024;
/// Default storage allowance for unique selected screened luma.
pub const DEFAULT_LUMA_BYTES: u64 = 64 * 1024 * 1024;
/// Hard storage ceiling for unique selected screened luma.
pub const MAX_LUMA_BYTES: u64 = 256 * 1024 * 1024;
/// Versioned identity domain of the exact movie selection and native frame lineage.
pub const LINEAGE_DOMAIN: &str = "fss.file_movie_output.v1";
const MAX_DIMENSION: u32 = 4096;
const MAX_PIXELS: usize = 4_194_304;
const CHUNK: usize = 4096;
const IMPLEMENTATION: &[u8] = include_bytes!("output.rs");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A complete materialization refusal; no partial completed cache is released.
pub enum MovieOutputError {
    /// Source pins or the exact selection partition are inconsistent.
    InvalidPlan,
    /// A native hard ceiling or caller allowance was exceeded.
    Limit,
    /// A selected original picture was supplied more than once.
    Duplicate,
    /// At least one selected original picture was never supplied.
    Missing,
    /// Native dimensions, pixel digest or receipt identity did not match.
    InvalidFrame,
    /// The owner cancellation checkpoint refused further work.
    Cancelled,
    /// An earlier insertion refused and permanently fenced this cache.
    Fenced,
}

impl std::fmt::Display for MovieOutputError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::InvalidPlan => "invalid bounded movie output plan",
            Self::Limit => "movie output allowance exceeded",
            Self::Duplicate => "duplicate selected movie frame",
            Self::Missing => "selected movie frame was not decoded",
            Self::InvalidFrame => "movie frame does not match its shape or sealed pins",
            Self::Cancelled => "movie output cancelled",
            Self::Fenced => "movie output fenced after an earlier refusal",
        })
    }
}
impl std::error::Error for MovieOutputError {}

#[derive(Clone, Copy, Debug)]
/// Authenticated original-source coordinates supplied by the custody owner.
pub struct SourceBinding {
    /// Completed original import identity.
    pub import_identity: ContentDigest,
    /// Completed original import object-graph root.
    pub import_root: ContentDigest,
    /// Exact retained file manifest identity.
    pub manifest_digest: ContentDigest,
    /// Digest of the complete original source bytes.
    pub input_sha256: ContentDigest,
    /// Source movie track identifier.
    pub track_id: u32,
    /// Native codec of the retained source track.
    pub codec: VideoCodec,
}

/// One already-screened native picture; this helper itself has no privacy authority.
pub struct FrameInput<'a> {
    /// Original source sample index, independent of display order.
    pub segment: usize,
    /// Unchanged native luma dimensions.
    pub dimensions: [u32; 2],
    /// Screened native luma, exactly width times height bytes.
    pub pixels: &'a [u8],
    /// Native receipt's digest of the screened luma.
    pub luma_sha256: [u8; 32],
    /// Sealed native frame receipt binding source, pixels and applied privacy policy.
    pub decode_receipt: ContentDigest,
}

/// One verified unique selected picture, reused by repeated presentation occurrences.
pub struct CachedFrame {
    /// Original source sample index.
    pub segment: usize,
    /// Unchanged native luma dimensions.
    pub dimensions: [u32; 2],
    /// Verified SHA-256 of the owned screened pixels.
    pub luma_sha256: [u8; 32],
    /// Native frame receipt identity provided by the custody owner.
    pub decode_receipt: ContentDigest,
    pixels: Vec<u8>,
}

impl CachedFrame {
    /// Verified screened luma; disclosure remains the caller's authority decision.
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }
}

struct Slot {
    segment: usize,
    frame: Option<CachedFrame>,
}

/// Bounded selected-picture cache whose successful completion requires every selected picture.
pub struct MovieOutput<'a> {
    selection: &'a MovieSelection,
    source: SourceBinding,
    slots: Vec<Slot>,
    occurrences: Vec<usize>,
    maximum: u64,
    luma_bytes: u64,
    failed: bool,
}

impl<'a> MovieOutput<'a> {
    /// Validate exact selection coverage and reserve bounded picture metadata.
    pub fn new(
        selection: &'a MovieSelection,
        source: SourceBinding,
        maximum_luma_bytes: u64,
    ) -> Result<Self, MovieOutputError> {
        if maximum_luma_bytes == 0 || maximum_luma_bytes > MAX_LUMA_BYTES {
            return Err(MovieOutputError::Limit);
        }
        if source.track_id == 0
            || [
                source.import_identity,
                source.import_root,
                source.manifest_digest,
                source.input_sha256,
            ]
            .into_iter()
            .any(|pin| !valid_pin(pin))
        {
            return Err(MovieOutputError::InvalidPlan);
        }
        let (segments, occurrences) = validate(selection)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(segments.len())
            .map_err(|_| MovieOutputError::Limit)?;
        for segment in segments {
            slots.push(Slot {
                segment,
                frame: None,
            });
        }
        Ok(Self {
            selection,
            source,
            slots,
            occurrences,
            maximum: maximum_luma_bytes,
            luma_bytes: 0,
            failed: false,
        })
    }

    /// Whether an original picture belongs to at least one selected presentation occurrence.
    pub fn wants(&self, segment: usize) -> bool {
        self.slots
            .binary_search_by_key(&segment, |slot| slot.segment)
            .is_ok()
    }

    /// Verify and copy one screened native picture; any refusal fences this cache.
    pub fn insert(
        &mut self,
        input: FrameInput<'_>,
        checkpoint: &mut impl FnMut() -> Result<(), MovieOutputError>,
    ) -> Result<(), MovieOutputError> {
        if self.failed {
            return Err(MovieOutputError::Fenced);
        }
        let result = self.insert_inner(input, checkpoint);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn insert_inner(
        &mut self,
        input: FrameInput<'_>,
        checkpoint: &mut impl FnMut() -> Result<(), MovieOutputError>,
    ) -> Result<(), MovieOutputError> {
        checkpoint()?;
        let index = self
            .slots
            .binary_search_by_key(&input.segment, |slot| slot.segment)
            .map_err(|_| MovieOutputError::InvalidFrame)?;
        if self.slots[index].frame.is_some() {
            return Err(MovieOutputError::Duplicate);
        }
        let [width, height] = input.dimensions;
        let count = u64::from(width) * u64::from(height);
        if width == 0
            || height == 0
            || width > MAX_DIMENSION
            || height > MAX_DIMENSION
            || count > MAX_PIXELS as u64
            || count != input.pixels.len() as u64
            || !valid_pin(input.decode_receipt)
        {
            return Err(MovieOutputError::InvalidFrame);
        }
        let total = self
            .luma_bytes
            .checked_add(count)
            .filter(|total| *total <= self.maximum)
            .ok_or(MovieOutputError::Limit)?;
        // Admit the entire unique frame before allocating or hashing any of its pixels.
        let mut pixels = Vec::new();
        pixels
            .try_reserve_exact(input.pixels.len())
            .map_err(|_| MovieOutputError::Limit)?;
        let mut hash = Sha256Hasher::new();
        for chunk in input.pixels.chunks(CHUNK) {
            checkpoint()?;
            hash.update(chunk);
            pixels.extend_from_slice(chunk);
        }
        if hash
            .finalize()
            .map_err(|_| MovieOutputError::InvalidFrame)?
            != input.luma_sha256
        {
            return Err(MovieOutputError::InvalidFrame);
        }
        checkpoint()?;
        self.slots[index].frame = Some(CachedFrame {
            segment: input.segment,
            dimensions: input.dimensions,
            pixels,
            luma_sha256: input.luma_sha256,
            decode_receipt: input.decode_receipt,
        });
        self.luma_bytes = total;
        Ok(())
    }

    /// Invoke only after every native range reaches successful EOF, including unselected tail.
    /// Cached selected pixels alone do not prove that the owner's source traversal succeeded.
    /// Complete the selection and lineage after the owner has verified every decoder's EOF.
    pub fn finish(
        self,
        checkpoint: &mut impl FnMut() -> Result<(), MovieOutputError>,
    ) -> Result<CompleteMovieOutput, MovieOutputError> {
        if self.failed {
            return Err(MovieOutputError::Fenced);
        }
        checkpoint()?;
        if self.slots.iter().any(|slot| slot.frame.is_none()) {
            return Err(MovieOutputError::Missing);
        }
        let lineage = self.lineage(checkpoint)?;
        checkpoint()?;
        Ok(CompleteMovieOutput {
            slots: self.slots,
            occurrences: self.occurrences,
            luma_bytes: self.luma_bytes,
            lineage,
        })
    }

    fn lineage(
        &self,
        checkpoint: &mut impl FnMut() -> Result<(), MovieOutputError>,
    ) -> Result<ContentDigest, MovieOutputError> {
        // Source identity changes when this exact materialization implementation changes.
        let mut implementation = Sha256Hasher::new();
        for chunk in IMPLEMENTATION.chunks(CHUNK) {
            checkpoint()?;
            implementation.update(chunk);
        }
        let implementation = implementation
            .finalize()
            .map_err(|_| MovieOutputError::Limit)?;
        let mut hash = Sha256Hasher::new();
        hash.update(LINEAGE_DOMAIN.as_bytes());
        hash.update(&[0]);
        hash.update(&implementation);
        for pin in [
            self.source.import_identity,
            self.source.import_root,
            self.source.manifest_digest,
            self.source.input_sha256,
        ] {
            hash.update(&pin.bytes());
        }
        hash.update(&self.source.track_id.to_le_bytes());
        hash.update(&[match self.source.codec {
            VideoCodec::Avc => 1,
            VideoCodec::Hevc => 2,
        }]);
        let selection = self.selection;
        hash.update(&selection.query.start.to_le_bytes());
        hash.update(&selection.query.end.to_le_bytes());
        hash.update(&selection.movie_timescale.to_le_bytes());
        hash.update(&selection.media_timescale.to_le_bytes());
        hash.update(&(selection.work as u64).to_le_bytes());
        hash.update(&selection.sample_bytes.to_le_bytes());
        hash.update(&selection.decode_bytes.to_le_bytes());
        hash.update(&selection.annex_b_bytes.to_le_bytes());
        hash.update(&(selection.edits.len() as u64).to_le_bytes());
        for edit in &selection.edits {
            checkpoint()?;
            option_index(&mut hash, edit.edit_index);
            interval(&mut hash, &edit.interval);
            match edit.media_time {
                None => hash.update(&[0]),
                Some(time) => {
                    hash.update(&[1]);
                    hash.update(&time.to_le_bytes());
                }
            }
        }
        hash.update(&(selection.gaps.len() as u64).to_le_bytes());
        for gap in &selection.gaps {
            checkpoint()?;
            hash.update(&[match gap.kind {
                MovieGapKind::EmptyEdit => 1,
                MovieGapKind::Unrepresented => 2,
            }]);
            interval(&mut hash, &gap.interval);
        }
        hash.update(&(selection.decode_spans.len() as u64).to_le_bytes());
        for span in &selection.decode_spans {
            checkpoint()?;
            hash.update(&(span.first_sample as u64).to_le_bytes());
            hash.update(&(span.sample_count as u64).to_le_bytes());
            hash.update(&span.source_bytes.to_le_bytes());
            hash.update(&span.annex_b_bytes.to_le_bytes());
            hash.update(&(span.requested_samples.len() as u64).to_le_bytes());
            for sample in &span.requested_samples {
                checkpoint()?;
                hash.update(&(*sample as u64).to_le_bytes());
            }
        }
        hash.update(&(selection.samples.len() as u64).to_le_bytes());
        for (ordinal, sample) in selection.samples.iter().enumerate() {
            checkpoint()?;
            let frame = self
                .slots
                .get(self.occurrences[ordinal])
                .and_then(|slot| slot.frame.as_ref())
                .ok_or(MovieOutputError::Missing)?;
            hash.update(&(ordinal as u64).to_le_bytes());
            hash.update(&(sample.sample_index as u64).to_le_bytes());
            option_index(&mut hash, sample.edit_index);
            hash.update(&(sample.source.start as u64).to_le_bytes());
            hash.update(&(sample.source.end as u64).to_le_bytes());
            interval(&mut hash, &sample.interval);
            hash.update(&frame.dimensions[0].to_le_bytes());
            hash.update(&frame.dimensions[1].to_le_bytes());
            hash.update(&(frame.pixels.len() as u64).to_le_bytes());
            hash.update(&frame.luma_sha256);
            hash.update(&frame.decode_receipt.bytes());
        }
        hash.update(&(self.slots.len() as u64).to_le_bytes());
        hash.update(&self.luma_bytes.to_le_bytes());
        hash.finalize()
            .map(|bytes| ContentDigest::new(DigestAlgorithm::Sha256, bytes))
            .map_err(|_| MovieOutputError::Limit)
    }
}

/// Complete validated presentation order backed by one copy of each unique screened picture.
pub struct CompleteMovieOutput {
    slots: Vec<Slot>,
    occurrences: Vec<usize>,
    luma_bytes: u64,
    lineage: ContentDigest,
}

impl CompleteMovieOutput {
    /// Picture for one presentation occurrence, including repeated edits.
    pub fn frame(&self, occurrence: usize) -> Option<&CachedFrame> {
        self.slots
            .get(*self.occurrences.get(occurrence)?)?
            .frame
            .as_ref()
    }
    /// Number of selected presentation occurrences.
    pub fn frames(&self) -> usize {
        self.occurrences.len()
    }
    /// Number of unique original pictures held by this cache.
    pub fn unique_frames(&self) -> usize {
        self.slots.len()
    }
    /// Total stored unique luma bytes; repetitions add no cache storage.
    pub fn luma_bytes(&self) -> u64 {
        self.luma_bytes
    }
    /// Source, selection, gap and native-frame transformation identity.
    pub fn lineage_digest(&self) -> ContentDigest {
        self.lineage
    }
}

fn valid_pin(pin: ContentDigest) -> bool {
    pin.algorithm() == DigestAlgorithm::Sha256 && !pin.is_laboratory() && pin.bytes() != [0; 32]
}

fn interval(hash: &mut Sha256Hasher, value: &MovieInterval) {
    hash.update(&value.start_numerator.to_le_bytes());
    hash.update(&value.end_numerator.to_le_bytes());
    hash.update(&value.denominator.to_le_bytes());
}

fn option_index(hash: &mut Sha256Hasher, value: Option<usize>) {
    match value {
        None => hash.update(&[0]),
        Some(index) => {
            hash.update(&[1]);
            hash.update(&(index as u64).to_le_bytes());
        }
    }
}

fn validate(selection: &MovieSelection) -> Result<(Vec<usize>, Vec<usize>), MovieOutputError> {
    let invalid = MovieOutputError::InvalidPlan;
    if selection.query.start >= selection.query.end
        || selection.movie_timescale == 0
        || selection.media_timescale == 0
    {
        return Err(invalid);
    }
    if selection.samples.is_empty()
        || selection.samples.len() > MAX_MOVIE_FRAMES
        || selection.decode_spans.is_empty()
        || selection.decode_spans.len() > MAX_MOVIE_FRAMES
    {
        return Err(MovieOutputError::Limit);
    }
    let defaults = MovieSelectionLimits::default();
    let rows = selection
        .samples
        .len()
        .checked_add(selection.edits.len())
        .and_then(|n| n.checked_add(selection.gaps.len()))
        .and_then(|n| n.checked_add(selection.decode_spans.len()))
        .ok_or(MovieOutputError::Limit)?;
    if rows > defaults.max_rows || selection.work > defaults.max_work {
        return Err(MovieOutputError::Limit);
    }
    let denominator = selection.media_timescale;
    let query_start = u128::from(selection.query.start) * u128::from(denominator);
    let query_end = u128::from(selection.query.end) * u128::from(denominator);
    let valid_interval = |interval: &MovieInterval| {
        interval.denominator == denominator
            && interval.start_numerator < interval.end_numerator
            && interval.start_numerator >= query_start
            && interval.end_numerator <= query_end
    };
    if selection.edits.is_empty()
        || selection
            .edits
            .iter()
            .any(|edit| !valid_interval(&edit.interval))
        || selection.edits.windows(2).any(|pair| {
            pair[0].edit_index >= pair[1].edit_index
                || pair[0].interval.end_numerator > pair[1].interval.start_numerator
        })
        || (selection.edits.len() > 1
            && selection.edits.iter().any(|edit| edit.edit_index.is_none()))
    {
        return Err(invalid);
    }
    if selection
        .gaps
        .iter()
        .any(|gap| !valid_interval(&gap.interval))
        || selection
            .gaps
            .windows(2)
            .any(|pair| pair[0].interval.end_numerator > pair[1].interval.start_numerator)
        || selection
            .samples
            .windows(2)
            .any(|pair| pair[0].interval.end_numerator > pair[1].interval.start_numerator)
    {
        return Err(invalid);
    }
    let mut segments = Vec::new();
    segments
        .try_reserve_exact(selection.samples.len())
        .map_err(|_| MovieOutputError::Limit)?;
    for sample in &selection.samples {
        if sample.sample_index >= MAX_MP4_SAMPLES
            || sample.source.start >= sample.source.end
            || sample.source.end > MAX_MP4_INPUT_BYTES
            || !valid_interval(&sample.interval)
        {
            return Err(invalid);
        }
        let edit = selection
            .edits
            .binary_search_by_key(&sample.edit_index, |edit| edit.edit_index)
            .ok()
            .and_then(|index| selection.edits.get(index))
            .ok_or(invalid)?;
        if edit.media_time.is_none()
            || sample.interval.start_numerator < edit.interval.start_numerator
            || sample.interval.end_numerator > edit.interval.end_numerator
        {
            return Err(invalid);
        }
        segments.push(sample.sample_index);
    }
    segments.sort_unstable();
    segments.dedup();
    let mut occurrences = Vec::new();
    occurrences
        .try_reserve_exact(selection.samples.len())
        .map_err(|_| MovieOutputError::Limit)?;
    let mut sources: Vec<Option<Range<usize>>> = Vec::new();
    sources
        .try_reserve_exact(segments.len())
        .map_err(|_| MovieOutputError::Limit)?;
    sources.resize_with(segments.len(), || None);
    let mut sample_bytes = 0_u64;
    for sample in &selection.samples {
        let index = segments
            .binary_search(&sample.sample_index)
            .map_err(|_| invalid)?;
        if let Some(prior) = &sources[index] {
            if prior != &sample.source {
                return Err(invalid);
            }
        } else {
            sample_bytes = sample_bytes
                .checked_add(sample.source.len() as u64)
                .ok_or(invalid)?;
            sources[index] = Some(sample.source.clone());
        }
        occurrences.push(index);
    }
    if sample_bytes != selection.sample_bytes {
        return Err(invalid);
    }
    let mut requested = Vec::new();
    requested
        .try_reserve_exact(segments.len())
        .map_err(|_| MovieOutputError::Limit)?;
    let mut previous_end = 0;
    let mut decoded = 0_usize;
    let mut decode_bytes = 0_u64;
    let mut annex_b_bytes = 0_u64;
    for span in &selection.decode_spans {
        let end = span
            .first_sample
            .checked_add(span.sample_count)
            .ok_or(invalid)?;
        decoded = decoded
            .checked_add(span.sample_count)
            .ok_or(MovieOutputError::Limit)?;
        if decoded > MAX_MOVIE_FRAMES {
            return Err(MovieOutputError::Limit);
        }
        if span.sample_count == 0
            || span.first_sample < previous_end
            || end > MAX_MP4_SAMPLES
            || span.requested_samples.is_empty()
            || span.requested_samples.len() > span.sample_count
            || span
                .requested_samples
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || span.source_bytes == 0
            || span.annex_b_bytes == 0
        {
            return Err(invalid);
        }
        previous_end = end;
        let mut selected_bytes = 0_u64;
        for sample in &span.requested_samples {
            if *sample < span.first_sample || *sample >= end {
                return Err(invalid);
            }
            let index = segments.binary_search(sample).map_err(|_| invalid)?;
            selected_bytes = selected_bytes
                .checked_add(sources[index].as_ref().ok_or(invalid)?.len() as u64)
                .ok_or(invalid)?;
            if requested.len() >= segments.len() {
                return Err(invalid);
            }
            requested.push(*sample);
        }
        if selected_bytes > span.source_bytes {
            return Err(invalid);
        }
        decode_bytes = decode_bytes.checked_add(span.source_bytes).ok_or(invalid)?;
        annex_b_bytes = annex_b_bytes
            .checked_add(span.annex_b_bytes)
            .ok_or(invalid)?;
    }
    if rows
        .checked_add(requested.len())
        .is_none_or(|n| n > defaults.max_rows)
        || decode_bytes > MAX_MP4_INPUT_BYTES as u64
        || annex_b_bytes > MAX_ANNEX_B_BYTES as u64
    {
        return Err(MovieOutputError::Limit);
    }
    if requested != segments
        || decode_bytes != selection.decode_bytes
        || annex_b_bytes != selection.annex_b_bytes
    {
        return Err(invalid);
    }
    // Sample occurrences and declared gaps must partition the complete requested interval.
    let (mut sample, mut gap, mut cursor) = (0, 0, query_start);
    while sample < selection.samples.len() || gap < selection.gaps.len() {
        let take_sample = gap == selection.gaps.len()
            || (sample < selection.samples.len()
                && selection.samples[sample].interval.start_numerator
                    < selection.gaps[gap].interval.start_numerator);
        let next = if take_sample {
            let interval = &selection.samples[sample].interval;
            sample += 1;
            interval
        } else {
            let interval = &selection.gaps[gap].interval;
            gap += 1;
            interval
        };
        if next.start_numerator != cursor {
            return Err(invalid);
        }
        cursor = next.end_numerator;
    }
    if cursor != query_end {
        return Err(invalid);
    }
    Ok((segments, occurrences))
}
