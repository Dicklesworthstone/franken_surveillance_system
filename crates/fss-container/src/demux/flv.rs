#![forbid(unsafe_code)]
//! Strict standard AVC FLV indexing with original sample and NAL ranges.
//!
//! This is a finite file reader, not the extended-FLV stream recovery heuristic. Every
//! tag must have its exact back-reference and remain inside the original file. Audio
//! and script tags are retained as opaque structure. The first video tag configures
//! one immutable AVC description; repeated descriptions must be byte-identical.

use std::ops::Range;

use fss_packet::extended_flv::{self, Header, Parse, Tag, avc};

use super::{DemuxError, DemuxLimits, Reader, reader::BoxRef, tables};

/// One length-prefixed AVC tag body in original file order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlvSample {
    /// Zero-based video sample ordinal, not a physical capture sequence.
    pub index: usize,
    /// Exact length-prefixed AVC bytes in the original FLV file.
    pub source: Range<usize>,
    /// Original complete tag, including header, AVC prefix and previous-tag size.
    pub tag: Range<usize>,
    /// Observed FLV decoding coordinate in milliseconds. Wrapping is not inferred.
    pub decode_time_ms: u32,
    /// Observed signed presentation-minus-decode offset in milliseconds.
    pub composition_offset_ms: i32,
    /// Difference to the next observed decoding coordinate. The last sample is unknown.
    /// This does not establish exposure duration, source continuity or scene coverage.
    pub duration_ms: Option<u32>,
    /// Sender's frame-type assertion, independently checked against IDR NAL presence.
    pub keyframe: bool,
    /// Whether an IDR slice NAL is present, not a native decoding proof.
    pub contains_idr: bool,
    /// Exact NAL payload ranges in source order, excluding their length fields.
    pub nals: Vec<Range<usize>>,
}
impl FlvSample {
    /// Exact signed presentation coordinate on the FLV media clock, never UTC.
    #[must_use]
    pub fn presentation_time_ms(&self) -> i64 {
        i64::from(self.decode_time_ms) + i64::from(self.composition_offset_ms)
    }
}

/// Complete source regions that tile the file: header, then each original tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlvTag {
    /// Original half-open source range.
    pub range: Range<usize>,
    /// Stable structural label, without interpreting audio or script payloads.
    pub name: &'static str,
}

/// Source-preserving AVC FLV index. No media bytes, decoding or effects are produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlvVideo {
    length: usize,
    parameters: Vec<Range<usize>>,
    samples: Vec<FlvSample>,
    tags: Vec<FlvTag>,
}
impl FlvVideo {
    /// Parse the complete file under independent source, tag, metadata, sample and NAL bounds.
    /// `maximum_boxes` bounds FLV tags plus the file header; `maximum_metadata_bytes` bounds
    /// every byte outside selected sample bodies, including opaque audio and script payloads.
    /// No torn-tail recovery, timestamp unwrapping, parameter changes or vendor tags are admitted.
    pub fn parse(source: &[u8], limits: DemuxLimits) -> Result<Self, DemuxError> {
        Self::parse_with_checkpoint(source, limits, &mut || Ok(()))
    }

    /// Complete-file parse with cooperative checkpoints before framing and every NAL.
    /// Any refusal discards the complete index; no partial success is returned.
    pub fn parse_with_checkpoint(
        source: &[u8],
        limits: DemuxLimits,
        check: &mut dyn FnMut() -> Result<(), DemuxError>,
    ) -> Result<Self, DemuxError> {
        limits.validate()?;
        if source.len() > limits.maximum_input_bytes {
            return Err(DemuxError::Limit);
        }
        let mut reader = Reader::new(source, limits, check);
        visit(&mut reader)?;
        let prefix = source.get(..9).ok_or(DemuxError::Truncated)?;
        if prefix[4] & !5 != 0 {
            return Err(DemuxError::Layout);
        }
        let framing = extended_flv::Limits {
            max_payload: limits.maximum_input_bytes.min(4 * 1024 * 1024),
            max_trailer: 0,
            max_header: limits.maximum_metadata_bytes.clamp(9, 4096),
        };
        let header = match Header::parse(source, framing).map_err(framing_error)? {
            Parse::Complete(header) => header,
            Parse::NeedMore => return Err(DemuxError::Truncated),
        };
        if header.flags() & 1 == 0 {
            return Err(DemuxError::Unsupported);
        }
        let mut at = header.wire_bytes().len();
        let mut metadata = at;
        if metadata > limits.maximum_metadata_bytes {
            return Err(DemuxError::Limit);
        }
        let mut tags = vec![FlvTag {
            range: 0..at,
            name: "header",
        }];
        let mut configuration: Option<Range<usize>> = None;
        let mut length = 0;
        let mut parameters = Vec::new();
        let mut samples: Vec<FlvSample> = Vec::new();
        let mut ended = false;
        while at < source.len() {
            visit(&mut reader)?;
            let remaining = &source[at..];
            let tag_header = remaining.get(..11).ok_or(DemuxError::Truncated)?;
            let kind = tag_header[0];
            if kind & 0xc0 != 0 || tag_header[8..11] != [0; 3] {
                return Err(DemuxError::Layout);
            }
            if kind & 0x20 != 0 || !matches!(kind, 8 | 9 | 18) {
                return Err(DemuxError::Unsupported);
            }
            if kind == 8 && header.flags() & 4 == 0 {
                return Err(DemuxError::Layout);
            }
            let tag = match Tag::parse(remaining, framing).map_err(framing_error)? {
                Parse::Complete(tag) => tag,
                Parse::NeedMore => return Err(DemuxError::Truncated),
            };
            let end = at
                .checked_add(tag.wire_bytes().len())
                .ok_or(DemuxError::Limit)?;
            let mut selected_bytes = 0;
            if kind == 9 {
                if ended {
                    return Err(DemuxError::Layout);
                }
                let video = avc::VideoTag::parse(tag).map_err(|error| match error {
                    avc::Error::UnsupportedVideo => DemuxError::Unsupported,
                    _ => DemuxError::Nal,
                })?;
                if !matches!(video.frame_type(), 1 | 2) {
                    return Err(DemuxError::Unsupported);
                }
                let body = video.body_range();
                let body = at + body.start..at + body.end;
                match video.packet_type() {
                    avc::PacketType::Configuration => {
                        if video.frame_type() != 1 || video.composition_offset_ms() != 0 {
                            return Err(DemuxError::Layout);
                        }
                        if let Some(first) = &configuration {
                            if source[first.clone()] != source[body.clone()] {
                                return Err(DemuxError::Unsupported);
                            }
                        } else {
                            (length, parameters) = tables::avc_configuration(
                                &mut reader,
                                &BoxRef {
                                    kind: *b"avcC",
                                    start: body.start,
                                    body: body.clone(),
                                },
                            )?;
                            configuration = Some(body);
                        }
                    }
                    avc::PacketType::NalUnits => {
                        if configuration.is_none() {
                            return Err(DemuxError::MissingBox(*b"avcC"));
                        }
                        if samples.len() >= limits.maximum_samples {
                            return Err(DemuxError::Limit);
                        }
                        reader.entries(1)?;
                        let mut sample = FlvSample {
                            index: samples.len(),
                            source: body.clone(),
                            tag: at..end,
                            decode_time_ms: video.timestamp_ms(),
                            composition_offset_ms: video.composition_offset_ms(),
                            duration_ms: None,
                            keyframe: video.frame_type() == 1,
                            contains_idr: false,
                            nals: Vec::new(),
                        };
                        let mut picture = false;
                        tables::nals(source, body.clone(), length, &mut |range| {
                            reader.checkpoint()?;
                            reader.nals = reader
                                .nals
                                .checked_add(1)
                                .filter(|count| *count <= limits.maximum_nals)
                                .ok_or(DemuxError::Limit)?;
                            let bytes = &source[range.clone()];
                            let kind = tables::nal_kind(bytes)?;
                            if matches!(kind, 7 | 8 | 13)
                                && !parameters
                                    .iter()
                                    .any(|parameter| source[parameter.clone()] == *bytes)
                            {
                                return Err(DemuxError::Unsupported);
                            }
                            picture |= matches!(kind, 1 | 5);
                            sample.contains_idr |= kind == 5;
                            sample.nals.push(range);
                            Ok(())
                        })?;
                        if !picture || sample.keyframe != sample.contains_idr {
                            return Err(DemuxError::Nal);
                        }
                        if let Some(previous) = samples.last_mut() {
                            previous.duration_ms = Some(
                                sample
                                    .decode_time_ms
                                    .checked_sub(previous.decode_time_ms)
                                    .filter(|duration| *duration != 0)
                                    .ok_or(DemuxError::Timeline)?,
                            );
                        }
                        selected_bytes = body.len();
                        samples.push(sample);
                    }
                    avc::PacketType::EndOfSequence => {
                        if configuration.is_none()
                            || samples.is_empty()
                            || !body.is_empty()
                            || video.frame_type() != 1
                            || video.composition_offset_ms() != 0
                        {
                            return Err(DemuxError::Layout);
                        }
                        // An end marker is not another observed picture or a duration witness.
                        ended = true;
                    }
                }
            }
            metadata = metadata
                .checked_add(end - at - selected_bytes)
                .filter(|bytes| *bytes <= limits.maximum_metadata_bytes)
                .ok_or(DemuxError::Limit)?;
            tags.push(FlvTag {
                range: at..end,
                name: match kind {
                    8 => "audio",
                    9 => "video",
                    _ => "script",
                },
            });
            at = end;
        }
        if configuration.is_none() || samples.is_empty() {
            return Err(DemuxError::TrackSelection);
        }
        reader.checkpoint()?;
        Ok(Self {
            length,
            parameters,
            samples,
            tags,
        })
    }

    /// Original AVC sample length-field width, one, two or four bytes.
    #[must_use]
    pub fn nal_length_bytes(&self) -> usize {
        self.length
    }
    /// Exact original configuration SPS/PPS and optional SPS-extension ranges.
    #[must_use]
    pub fn parameter_sets(&self) -> &[Range<usize>] {
        &self.parameters
    }
    /// Complete decoding-order video sample index.
    #[must_use]
    pub fn samples(&self) -> &[FlvSample] {
        &self.samples
    }
    /// Complete file tiling, including unselected audio/script bytes.
    #[must_use]
    pub fn tags(&self) -> &[FlvTag] {
        &self.tags
    }
}

fn visit(reader: &mut Reader<'_, '_>) -> Result<(), DemuxError> {
    reader.checkpoint()?;
    reader.boxes = reader
        .boxes
        .checked_add(1)
        .filter(|count| *count <= reader.limits.maximum_boxes)
        .ok_or(DemuxError::Limit)?;
    reader.entries(1)
}

fn framing_error(error: extended_flv::Error) -> DemuxError {
    match error {
        extended_flv::Error::PayloadLimit | extended_flv::Error::InvalidLimits => DemuxError::Limit,
        extended_flv::Error::InvalidTagKind => DemuxError::Unsupported,
        _ => DemuxError::Layout,
    }
}

#[cfg(test)]
mod tests;
