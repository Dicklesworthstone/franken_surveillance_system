#![forbid(unsafe_code)]
//! Finite MJPEG AVI files with exact original frame ranges and rational stream time.
//!
//! The admitted RIFF profile has one video stream, one `movi` list, optional
//! interleaved audio and `rec ` lists. Stream order defines presentation order.
//! Index-directed playback, multiple RIFF/AVIX segments, dropped frames, palette
//! changes and interlaced layouts refuse. The file importer additionally verifies
//! one complete JPEG framing span per selected chunk before retaining capsules.
//! Container timing is media time. It never establishes a source capture clock.

use std::ops::Range;

use crate::demux::{DemuxError, DemuxLimits};

/// One compressed video sample, borrowed from the original AVI recording.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AviSample {
    /// Zero-based video sample index, independent of interleaved audio chunks.
    pub index: usize,
    /// Exact JPEG bytes, excluding the RIFF chunk header and word-alignment padding.
    pub source: Range<usize>,
    /// Presentation tick in the stream's `scale / rate` seconds time base.
    pub presentation_tick: u64,
}

/// A bounded source-preserving index. Parsing does not decode JPEG pixels.
#[derive(Debug)]
pub struct AviMjpeg<'a> {
    source: &'a [u8],
    samples: Vec<AviSample>,
    dimensions: [u32; 2],
    scale: u32,
    rate: u32,
}

#[derive(Clone)]
struct Chunk {
    kind: [u8; 4],
    body: Range<usize>,
}

struct Reader<'a, 'c> {
    source: &'a [u8],
    limits: DemuxLimits,
    chunks: usize,
    check: &'c mut dyn FnMut() -> Result<(), DemuxError>,
}

impl Reader<'_, '_> {
    fn chunks(&mut self, range: Range<usize>) -> Result<Vec<Chunk>, DemuxError> {
        let mut at = range.start;
        let mut chunks = Vec::new();
        while at < range.end {
            (self.check)()?;
            self.chunks += 1;
            if self.chunks > self.limits.maximum_boxes {
                return Err(DemuxError::Limit);
            }
            let header = self
                .source
                .get(at..range.end)
                .filter(|bytes| bytes.len() >= 8)
                .ok_or(DemuxError::Truncated)?;
            let size = word(header, 4)? as usize;
            let start = at.checked_add(8).ok_or(DemuxError::Limit)?;
            let end = start.checked_add(size).ok_or(DemuxError::Limit)?;
            at = end.checked_add(size & 1).ok_or(DemuxError::Limit)?;
            if at > range.end {
                return Err(DemuxError::Truncated);
            }
            chunks.try_reserve(1).map_err(|_| DemuxError::Limit)?;
            chunks.push(Chunk {
                kind: header[..4].try_into().map_err(|_| DemuxError::Layout)?,
                body: start..end,
            });
        }
        Ok(chunks)
    }

    fn body(&self, chunk: &Chunk) -> &[u8] {
        &self.source[chunk.body.clone()]
    }

    fn list(&self, chunk: &Chunk, kind: &[u8; 4]) -> bool {
        chunk.kind == *b"LIST" && self.body(chunk).get(..4) == Some(kind)
    }

    fn samples(
        &mut self,
        chunks: &[Chunk],
        stream: u8,
        audio_streams: u64,
        start: u32,
        in_record: bool,
        output: &mut Vec<AviSample>,
    ) -> Result<(), DemuxError> {
        for chunk in chunks {
            (self.check)()?;
            if chunk.kind == *b"LIST" {
                if in_record || !self.list(chunk, b"rec ") {
                    return Err(DemuxError::Unsupported);
                }
                let children = self.chunks(chunk.body.start + 4..chunk.body.end)?;
                self.samples(&children, stream, audio_streams, start, true, output)?;
                continue;
            }
            if matches!(&chunk.kind, b"JUNK" | b"idx1")
                || (&chunk.kind[..2] == b"ix"
                    && chunk.kind[2..].iter().all(u8::is_ascii_digit))
            {
                continue;
            }
            if !chunk.kind[..2].iter().all(u8::is_ascii_digit) {
                return Err(DemuxError::Unsupported);
            }
            let chunk_stream = (chunk.kind[0] - b'0') * 10 + chunk.kind[1] - b'0';
            if chunk_stream != stream {
                if chunk_stream >= 64
                    || audio_streams & (1_u64 << chunk_stream) == 0
                    || chunk.kind[2..] != *b"wb"
                {
                    return Err(DemuxError::TrackSelection);
                }
                continue;
            }
            if chunk.kind[2..] != *b"dc" {
                return Err(DemuxError::Unsupported);
            }
            let jpeg = self.body(chunk);
            if !jpeg.starts_with(&[0xff, 0xd8]) || !jpeg.ends_with(&[0xff, 0xd9]) {
                return Err(DemuxError::Layout);
            }
            if output.len() >= self.limits.maximum_samples
                || output.len() >= self.limits.maximum_table_entries
            {
                return Err(DemuxError::Limit);
            }
            let presentation_tick = u64::from(start)
                .checked_add(output.len() as u64)
                .ok_or(DemuxError::Timeline)?;
            output.try_reserve(1).map_err(|_| DemuxError::Limit)?;
            output.push(AviSample {
                index: output.len(),
                source: chunk.body.clone(),
                presentation_tick,
            });
        }
        Ok(())
    }
}

impl<'a> AviMjpeg<'a> {
    /// Index one complete classic RIFF AVI file. Counts and timing must agree.
    pub fn parse(source: &'a [u8], limits: DemuxLimits) -> Result<Self, DemuxError> {
        Self::parse_with_checkpoint(source, limits, &mut || Ok(()))
    }

    /// Index with cancellation at every RIFF chunk and selected sample boundary.
    ///
    /// Source, sample, track, chunk and table-entry ceilings use `DemuxLimits`.
    /// The metadata allowance bounds every byte outside selected JPEG payloads,
    /// including opaque audio and indexes. NAL and Annex-B ceilings are unused.
    pub fn parse_with_checkpoint(
        source: &'a [u8],
        limits: DemuxLimits,
        check: &mut dyn FnMut() -> Result<(), DemuxError>,
    ) -> Result<Self, DemuxError> {
        limits.validate()?;
        check()?;
        if source.len() > limits.maximum_input_bytes {
            return Err(DemuxError::Limit);
        }
        if source.get(..4) != Some(b"RIFF") || source.get(8..12) != Some(b"AVI ") {
            return Err(DemuxError::Unsupported);
        }
        let end = usize::try_from(word(source, 4)?)
            .ok()
            .and_then(|size| size.checked_add(8))
            .ok_or(DemuxError::Limit)?;
        if end > source.len() {
            return Err(DemuxError::Truncated);
        }
        if end != source.len() || end < 12 {
            return Err(DemuxError::Unsupported);
        }
        let mut reader = Reader {
            source,
            limits,
            chunks: 1,
            check,
        };
        let top = reader.chunks(12..end)?;
        let headers = unique(top.iter().filter(|chunk| reader.list(chunk, b"hdrl")))?;
        let movie = unique(top.iter().filter(|chunk| reader.list(chunk, b"movi")))?;
        if headers.body.end > movie.body.start {
            return Err(DemuxError::Layout);
        }
        let header_chunks = reader.chunks(headers.body.start + 4..headers.body.end)?;
        let main = unique(header_chunks.iter().filter(|chunk| chunk.kind == *b"avih"))?;
        let main = reader.body(&main);
        if main.len() != 56 {
            return Err(DemuxError::Layout);
        }
        // AVIF_MUSTUSEINDEX changes presentation order; physical order cannot substitute.
        if word(main, 12)? & 0x20 != 0 {
            return Err(DemuxError::Unsupported);
        }
        let canvas = [word(main, 32)?, word(main, 36)?];
        let declared_frames = word(main, 16)?;
        let declared_streams = word(main, 24)?;
        let streams: Vec<_> = header_chunks
            .iter()
            .filter(|chunk| reader.list(chunk, b"strl"))
            .cloned()
            .collect();
        if streams.is_empty()
            || streams.len() > limits.maximum_tracks
            || streams.len() as u64 != u64::from(declared_streams)
        {
            return Err(DemuxError::TrackSelection);
        }
        let mut selected = None;
        let mut audio_streams = 0_u64;
        for (index, stream) in streams.iter().enumerate() {
            let chunks = reader.chunks(stream.body.start + 4..stream.body.end)?;
            let header = unique(chunks.iter().filter(|chunk| chunk.kind == *b"strh"))?;
            let header = reader.body(&header);
            if header.len() != 56 {
                return Err(DemuxError::Layout);
            }
            if &header[..4] == b"auds" {
                audio_streams |= 1_u64 << index;
                continue;
            }
            if &header[..4] != b"vids" {
                return Err(DemuxError::Unsupported);
            }
            if selected.is_some() {
                return Err(DemuxError::TrackSelection);
            }
            if &header[4..8] != b"MJPG"
                || word(header, 8)? != 0
                || word(header, 16)? != 0
                || word(header, 44)? != 0
                || chunks.iter().any(|chunk| chunk.kind == *b"strd")
            {
                return Err(DemuxError::Unsupported);
            }
            let scale = word(header, 20)?;
            let rate = word(header, 24)?;
            let start = word(header, 28)?;
            let count = word(header, 32)?;
            if scale == 0 || rate == 0 || count == 0 || count != declared_frames {
                return Err(DemuxError::Timeline);
            }
            let format = unique(chunks.iter().filter(|chunk| chunk.kind == *b"strf"))?;
            let format = reader.body(&format);
            if format.len() != 40
                || word(format, 0)? != 40
                || format[12..16] != [1, 0, 24, 0]
                || &format[16..20] != b"MJPG"
            {
                return Err(DemuxError::Unsupported);
            }
            let dimensions = [word(format, 4)?, word(format, 8)?];
            if dimensions.iter().any(|value| !(1..=65_535).contains(value)) {
                return Err(DemuxError::Unsupported);
            }
            if dimensions != canvas {
                return Err(DemuxError::Layout);
            }
            // rcFrame is a destination rectangle, not inert codec metadata.
            let rectangle = &header[48..56];
            let extent = dimensions[0] | (dimensions[1] << 16);
            if rectangle != [0; 8]
                && (dimensions.iter().any(|value| *value > i16::MAX as u32)
                    || word(header, 48)? != 0 || word(header, 52)? != extent)
            {
                return Err(DemuxError::Unsupported);
            }
            let mut properties = chunks.iter().filter(|chunk| chunk.kind == *b"vprp");
            if let Some(properties_chunk) = properties.next() {
                if properties.next().is_some() {
                    return Err(DemuxError::DuplicateBox(*b"vprp"));
                }
                identity_properties(reader.body(properties_chunk), dimensions)?;
            }
            selected = Some((index as u8, dimensions, scale, rate, start, count));
        }
        let (stream, dimensions, scale, rate, start, count) =
            selected.ok_or(DemuxError::TrackSelection)?;
        if count as usize > limits.maximum_samples || count as usize > limits.maximum_table_entries {
            return Err(DemuxError::Limit);
        }
        let chunks = reader.chunks(movie.body.start + 4..movie.body.end)?;
        let mut samples = Vec::new();
        reader.samples(&chunks, stream, audio_streams, start, false, &mut samples)?;
        if samples.len() as u64 != u64::from(count) {
            return Err(DemuxError::Timeline);
        }
        let frame_bytes = samples.iter().try_fold(0_usize, |sum, sample| {
            sum.checked_add(sample.source.len()).ok_or(DemuxError::Limit)
        })?;
        if source.len() - frame_bytes > limits.maximum_metadata_bytes {
            return Err(DemuxError::Limit);
        }
        (reader.check)()?;
        Ok(Self {
            source,
            samples,
            dimensions,
            scale,
            rate,
        })
    }

    /// Exact original RIFF bytes, including opaque audio, metadata and indexes.
    pub fn source(&self) -> &'a [u8] {
        self.source
    }

    /// Video samples in the file's declared presentation order.
    pub fn samples(&self) -> &[AviSample] {
        &self.samples
    }

    /// Width and height declared by the video stream's BITMAPINFOHEADER.
    pub const fn dimensions(&self) -> [u32; 2] {
        self.dimensions
    }

    /// Seconds per stream tick, as an exact positive numerator and denominator.
    pub const fn time_base(&self) -> (u32, u32) {
        (self.scale, self.rate)
    }
}

// Admit only progressive, square-pixel, full-frame vprp geometry. The target
// refresh value is presentation-device metadata, not the stream sample clock.
fn identity_properties(body: &[u8], [width, height]: [u32; 2]) -> Result<(), DemuxError> {
    if body.len() != 68 {
        return Err(DemuxError::Unsupported);
    }
    let aspect = word(body, 20)?;
    let numerator = aspect >> 16;
    let denominator = aspect & 0xffff;
    if numerator == 0
        || denominator == 0
        || u64::from(numerator) * u64::from(height)
            != u64::from(denominator) * u64::from(width)
    {
        return Err(DemuxError::Unsupported);
    }
    for (offset, expected) in [
        (0, 0), (4, 0), (12, width), (16, height),
        (24, width), (28, height), (32, 1),
        (36, height), (40, width), (44, height), (48, width),
        (52, 0), (56, 0), (60, 0), (64, 0),
    ] {
        if word(body, offset)? != expected {
            return Err(DemuxError::Unsupported);
        }
    }
    Ok(())
}

fn unique<'a>(mut chunks: impl Iterator<Item = &'a Chunk>) -> Result<Chunk, DemuxError> {
    let value = chunks.next().ok_or(DemuxError::Layout)?;
    if chunks.next().is_some() {
        return Err(DemuxError::DuplicateBox(value.kind));
    }
    Ok(value.clone())
}

fn word(bytes: &[u8], at: usize) -> Result<u32, DemuxError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or(DemuxError::Truncated)?
            .try_into()
            .map_err(|_| DemuxError::Truncated)?,
    ))
}
