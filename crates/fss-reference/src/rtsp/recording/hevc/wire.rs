#![forbid(unsafe_code)]

use super::*;
use fss_core::{CanonicalDecoder, CanonicalEncoder, SensorId, StreamId};
use fss_packet::{H265SourceSpan, hevc::HevcBoundary};

const SCHEMA: &str = "fss.hevc_recording_window.index.v1";
const MAX_INDEX_BYTES: usize = 2 * 1024 * 1024;

pub(super) fn encode(index: &Index) -> Result<Vec<u8>> {
    if index.samples.is_empty() || index.samples.len() > MAX_RECORDING_SAMPLES
        || index.mappings.is_empty() || index.mappings.len() > MAX_RECORDING_MAPPINGS
        || index.source_only_nals > MAX_HEVC_LOOKAHEAD_NALS
    { return Err(RecordingError::Limit); }
    let spans = index.mappings.iter().try_fold(0_usize, |count, m| count.checked_add(m.sources.len()))
        .ok_or(RecordingError::Limit)?;
    if spans > MAX_RECORDING_MAPPINGS { return Err(RecordingError::Limit); }
    let mut e = CanonicalEncoder::new();
    e.text(SCHEMA); e.text(index.scope.sensor.as_str()); e.text(index.scope.stream.as_str());
    e.u64(index.scope.generation); e.digest(index.scope.anchor); e.digest(index.scope.receive_clock);
    e.u32(index.ssrc); e.u32(u32::from(index.payload_type)); e.u32(index.time_scale);
    e.digest(index.source); e.digest(index.initialization); e.digest(index.media);
    for parameter in &index.parameters { range(&mut e, parameter); }
    e.u64(index.source_only_nals as u64);
    e.u64(index.samples.len() as u64);
    for s in &index.samples {
        range(&mut e, &s.range); e.u64(s.decode_time); e.u64(s.presentation_time);
        e.u32(s.duration); e.u32(s.rtp_timestamp); e.bool(s.idr);
        e.u64(boundary(s.boundary)); range(&mut e, &s.mappings);
    }
    e.u64(index.mappings.len() as u64);
    for m in &index.mappings {
        e.u64(m.sample as u64); e.u64(m.nal as u64); range(&mut e, &m.range);
        e.u64(m.sources.len() as u64);
        for source in &m.sources {
            e.u64(source.sequence); range(&mut e, &source.wire_range); range(&mut e, &source.nal_range);
            e.bool(source.fragment_header_range.is_some());
            if let Some(r) = &source.fragment_header_range { range(&mut e, r); }
        }
    }
    let bytes = e.finish_checked().map_err(|_| RecordingError::Malformed)?;
    if bytes.len() > MAX_INDEX_BYTES { return Err(RecordingError::Limit); }
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Index> {
    if bytes.len() > MAX_INDEX_BYTES { return Err(RecordingError::Limit); }
    let mut d = Decoder(CanonicalDecoder::new(bytes));
    if d.text()? != SCHEMA { return Err(RecordingError::Malformed); }
    let sensor = SensorId::parse(d.text()?).map_err(|_| RecordingError::Scope)?;
    let stream = StreamId::parse(d.text()?).map_err(|_| RecordingError::Scope)?;
    let generation = d.u64()?;
    let anchor = d.digest()?; let receive_clock = d.digest()?;
    let ssrc = d.u32()?;
    let payload_type = u8::try_from(d.u32()?).map_err(|_| RecordingError::Scope)?;
    if generation == 0 || payload_type > 127 { return Err(RecordingError::Scope); }
    let time_scale = d.u32()?;
    let source = d.digest()?; let initialization = d.digest()?; let media = d.digest()?;
    let parameters = [d.range()?, d.range()?, d.range()?];
    let source_only_nals = d.count(MAX_HEVC_LOOKAHEAD_NALS)?;
    let count = d.count(MAX_RECORDING_SAMPLES)?;
    if count == 0 { return Err(RecordingError::Malformed); }
    let mut samples = bounded_vec(count, MAX_RECORDING_SAMPLES)?;
    for _ in 0..count {
        samples.push(HevcSampleMapping { range: d.range()?, decode_time: d.u64()?,
            presentation_time: d.u64()?, duration: d.u32()?, rtp_timestamp: d.u32()?,
            idr: d.boolean()?, boundary: decode_boundary(d.u64()?)?, mappings: d.range()? });
    }
    let count = d.count(MAX_RECORDING_MAPPINGS)?;
    if count == 0 { return Err(RecordingError::Malformed); }
    let mut mappings = bounded_vec(count, MAX_RECORDING_MAPPINGS)?;
    let mut remaining = MAX_RECORDING_MAPPINGS;
    for _ in 0..count {
        let sample = d.count(MAX_RECORDING_SAMPLES)?;
        let nal = d.count(MAX_RECORDING_MAPPINGS)?;
        let output_range = d.range()?;
        let count = d.count(remaining)?;
        if count == 0 { return Err(RecordingError::Source); }
        remaining -= count;
        let mut sources = bounded_vec(count, MAX_RECORDING_MAPPINGS)?;
        for _ in 0..count {
            sources.push(H265SourceSpan { sequence: d.u64()?, wire_range: d.range()?, nal_range: d.range()?,
                fragment_header_range: if d.boolean()? { Some(d.range()?) } else { None } });
        }
        mappings.push(HevcNalMapping { sample, nal, range: output_range, sources });
    }
    d.0.ensure_finished().map_err(|_| RecordingError::Malformed)?;
    Ok(Index { scope: RecordingScope { sensor, stream, generation, anchor, receive_clock },
        ssrc, payload_type, time_scale, source, initialization, media, parameters,
        source_only_nals, samples, mappings })
}

fn range(e: &mut CanonicalEncoder, r: &Range<usize>) { e.u64(r.start as u64); e.u64(r.end as u64); }
fn boundary(value: HevcBoundary) -> u64 {
    match value {
        HevcBoundary::NextFirstSlice => 1, HevcBoundary::NextAccessUnitPrefix => 2,
        HevcBoundary::AccessUnitDelimiter => 3, HevcBoundary::EndOfSequence => 4,
        HevcBoundary::EndOfBitstream => 5, HevcBoundary::EndOfInputUnverified => 6,
    }
}
fn decode_boundary(code: u64) -> Result<HevcBoundary> {
    match code {
        1 => Ok(HevcBoundary::NextFirstSlice), 2 => Ok(HevcBoundary::NextAccessUnitPrefix),
        3 => Ok(HevcBoundary::AccessUnitDelimiter), 4 => Ok(HevcBoundary::EndOfSequence),
        5 => Ok(HevcBoundary::EndOfBitstream), 6 => Ok(HevcBoundary::EndOfInputUnverified),
        _ => Err(RecordingError::Malformed),
    }
}
struct Decoder<'a>(CanonicalDecoder<'a>);
impl<'a> Decoder<'a> {
    fn text(&mut self) -> Result<&'a str> { self.0.text().map_err(|_| RecordingError::Malformed) }
    fn u32(&mut self) -> Result<u32> { self.0.u32().map_err(|_| RecordingError::Malformed) }
    fn u64(&mut self) -> Result<u64> { self.0.u64().map_err(|_| RecordingError::Malformed) }
    fn boolean(&mut self) -> Result<bool> { self.0.bool().map_err(|_| RecordingError::Malformed) }
    fn digest(&mut self) -> Result<ContentDigest> { self.0.digest().map_err(|_| RecordingError::Malformed) }
    fn count(&mut self, max: usize) -> Result<usize> {
        let n = usize::try_from(self.u64()?).map_err(|_| RecordingError::Limit)?;
        if n > max { return Err(RecordingError::Limit); }
        Ok(n)
    }
    fn range(&mut self) -> Result<Range<usize>> {
        let start = self.count(MAX_RECORDING_BYTES)?; let end = self.count(MAX_RECORDING_BYTES)?;
        if start > end { return Err(RecordingError::Malformed); }
        Ok(start..end)
    }
}
